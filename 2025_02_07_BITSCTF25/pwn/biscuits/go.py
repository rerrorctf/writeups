#!/usr/bin/env python3

from pwn import *
import ctypes
import struct

#context.log_level = "debug"
elf = ELF("./main", checksec=False)
context.binary = elf

cookies = elf.read(elf.sym["cookies"], 0x500)

# sha256: e7a914a33fd4f6d25057b8d48c7c5f3d55ab870ec4ee27693d6c5f3a532e6226 
libc = ctypes.CDLL("/lib/x86_64-linux-gnu/libc.so.6")

#p = elf.process()
#p = elf.debug(gdbscript="")
p = remote("20.244.40.210", 6000)

now = libc.time(0)
libc.srand(now)

for i in range(100):
    idx = libc.rand() % 100
    cookie = struct.unpack("<Q", cookies[idx * 8: (idx * 8) + 8])[0]
    p.sendlineafter(b"Guess the cookie: ", elf.read(cookie, 64))

p.readuntil(b"Flag: ")

# BITSCTF{7h4nk5_f0r_4ll_0f_th3_c00ki3s_1_r34lly_enjoy3d_th3m_d31fa51e}
print(p.readuntil(b"}").decode())
