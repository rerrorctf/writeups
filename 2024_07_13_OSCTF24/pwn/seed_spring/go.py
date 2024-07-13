#!/usr/bin/env python3

from pwn import *
import ctypes

#context.log_level = "debug"
elf = ELF("./seed_spring", checksec=False)
context.binary = elf

libc = ctypes.CDLL("/lib/x86_64-linux-gnu/libc.so.6")

#p = elf.process()
#p = elf.debug(gdbscript="")
p = remote("34.125.199.248", 2534)

now = libc.time(0)
libc.srand(now)

p.readuntil(b"How high will you fly?\n\n")

for i in range(30):
    p.sendlineafter(b"Guess the height: ", str(libc.rand() & 0xf).encode())

p.interactive() # OSCTF{th1s_w4snt_phys1cs_lm4o}
