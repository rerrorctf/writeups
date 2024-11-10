https://ctftime.org/event/2512

# HMAC (crypto)

There’s a secret message being HMAC-protected, but the implementation has a serious flaw. Can you recover the secret message using a side-channel attack?

SRC: https://gist.github.com/AndyNovo/91e3c51ef47980d32ad1cde26b917ac4

 nc 0.cloud.chals.io 11320

## Analysis

We can see from the following code that each correct byte has an artificial timing delay added:

```python
# Compare two byte arrays. Take variable time depending on how many bytes are equal.
def insecure_compare(a, b):
    if len(a) != len(b):
        return False
    for i in range(len(a)):
        if a[i] != b[i]:
            return False
        # Simulate time delay per byte comparison
        time.sleep(0.05)
    return True
```

We can use this to detect correct bytes by observing this timing sidechannel.

## Solution

```python
#!/usr/bin/env python3

from pwn import *
import time

context.log_level = "WARNING"

known_bytes = bytes.fromhex("f21928fd469f")

for x in range(20-len(known_bytes)):
    times = []

    for i in range(0x100):
        s = known_bytes + p8(i)
        s += (20 - len(s)) * b"\x00"
        s = s.hex().encode()

        t_avg = 0
        for j in range(4):
            with remote("0.cloud.chals.io", 11320) as p:
            #with process(["python3", "./dist.py"]) as p:
                p.readuntil(b"Enter your McGuess (hex):\n>")
                n = time.perf_counter()
                p.sendline(s)
                p.readline()
                t_avg += time.perf_counter() - n

        t_avg /= 4
        times.append(t_avg)

    best_time = -1.0
    best_index = -1
    for i in range(0x100):
        if times[i] > best_time:
            best_time = times[i]
            best_index = i

    known_bytes += p8(best_index)
    print(best_index, best_time, known_bytes.hex())

p = remote("0.cloud.chals.io", 11320)
p.sendlineafter(b"Enter your McGuess (hex):\n>", known_bytes.hex().encode())
p.interactive() # UDCTF{B4d_T1miN6}
```

## Flag
`UDCTF{B4d_T1miN6}`

smiley 2024/11/10
