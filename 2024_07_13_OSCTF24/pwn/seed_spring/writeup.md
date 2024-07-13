https://ctftime.org/event/2416

# seed_spring (pwn)

RANDOMisation successful: Your mission is to jump on the sPRiNG and see how high you can soar. With 30 levels of increasing complexity, you'll need to master the laws of PHYSICS and TIME to reach new heights. Can you crack the code and defy gravity? Let the experiment begin!

nc 34.125.199.248 2534

## Solution

1) seed local srand with same time
2) generate same prng sequence

```python
#!/usr/bin/env python3

from pwn import *
import ctypes

#context.log_level = "debug"
elf = ELF("./seed_spring", checksec=False)
context.binary = elf

libc = ctypes.CDLL("/lib/x86_64-linux-gnu/libc.so.6")

#p = elf.process()
#p = elf.debug(gdbscript="")
p = remote("34.125.199.248", 2534)

now = libc.time(0)
libc.srand(now)

p.readuntil(b"How high will you fly?\n\n")

for i in range(30):
    p.sendlineafter(b"Guess the height: ", str(libc.rand() & 0xf).encode())

p.interactive() # OSCTF{th1s_w4snt_phys1cs_lm4o}
```

## Flag
`OSCTF{th1s_w4snt_phys1cs_lm4o}`

smiley 2024/07/13
