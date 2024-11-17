#!/usr/bin/env python3

from pwn import *

#context.log_level = "debug"
elf = ELF("./secure_bank", checksec=False)
context.binary = elf

#p = elf.process()
#p = elf.debug(gdbscript="")
p = remote("securebank.ctf.intigriti.io", 1335)

p.sendline(str(0x539).encode())

p.sendline(str(0x568720).encode())

p.readuntil(b"your flag: ")

print(p.readline()[:-2].decode()) # INTIGRITI{pfff7_wh47_2f4?!}
