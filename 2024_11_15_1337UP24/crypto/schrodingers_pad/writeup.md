https://ctftime.org/event/2446

# Schrödinger's Pad (crypto)

Everyone knows you can't reuse a OTP, but throw in a cat and a box.. Maybe it's secure?

nc pad.ctf.intigriti.io 1348

## Analysis

A One Time Pad (OTP) involves xor the plaintext with a keystream that must be reused.

We can see that the server performs OTP on the flag and our input with the same keystream.

Before the ciphertext is returned to us the server performs one of two transformations on it.

### Alive

In the case that "the cat is alive"

```python
for i in range(len(c)):
    c[i] = ((c[i] << 1) & 0xFF) ^ 0xAC
```

We can see that, in theory, information here is lost by this transformation - specifically the top bit of each byte of the ciphertext.

In reality its not really lost because the top bit of all bytes of the plaintext and the keystream are known to be `0` because they come from a subset of ascii printables.

This transformation can be undone as follows:

```python
for i in range(len(c)):
    c[i] ^= 0xAC
    c[i] = c[i] >> 1
```

### Dead

In the case that "the cat is dead"

```python
for i in range(len(c)):
    c[i] = ((c[i] >> 1) | (c[i] << 7)) & 0xFF
    c[i] ^= 0xCA
```

This transformation can be undone as follows:

```python
for i in range(len(c)):
    c[i] ^= 0xCA
    c[i] = ((c[i] << 1) | (c[i] >> 7)) & 0xFF
```

## Solution

1) Undo the `alive` or `dead` transformation to recover the output of the OTP
2) `xor(known_plaintext, ciphertext)` to recover the keystream
2) `xor(keystream, encrypted_flag)` to recover the flag

```python
#!/usr/bin/env python3

from pwn import *

#context.log_level = "debug"
p = remote("pad.ctf.intigriti.io", 1348)

p.readuntil(b": ")

flag = bytes.fromhex(p.readline().decode())

known_plaintext = b"A" * 160
p.sendlineafter(b"yourself?\n", known_plaintext)

p.readuntil(b"state=")
state = p.readuntil(b"): ")[:-3]

ciphertext = bytearray(bytes.fromhex(p.readline().decode()))

if state == b"alive":
    for i in range(len(ciphertext)):
        ciphertext[i] ^= 0xAC
        ciphertext[i] = ciphertext[i] >> 1

if state == b"dead":
    for i in range(len(ciphertext)):
        ciphertext[i] ^= 0xCA
        ciphertext[i] = ((ciphertext[i] << 1) | (ciphertext[i] >> 7)) & 0xFF

keystream = xor(known_plaintext, ciphertext)
flag = xor(keystream, flag).decode()[37:61]
print(flag) # INTIGRITI{d34d_0r_4l1v3}
```

## Flag
`INTIGRITI{d34d_0r_4l1v3}`

smiley 2024/11/16
