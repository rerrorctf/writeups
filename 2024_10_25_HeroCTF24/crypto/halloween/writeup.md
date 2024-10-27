https://ctftime.org/event/2496

# Halloween (crypto)

Boo! Do you believe in ghosts ? I sure don't.

nc crypto.heroctf.fr 9001

## Analysis

We can see from `chall.py` that everything about the setup appears normal:

```python
import gostcrypto
import os

with open("flag.txt", "rb") as f:
    flag = f.read()

key, iv = os.urandom(32), os.urandom(8)
cipher = gostcrypto.gostcipher.new(
    "kuznechik", key, gostcrypto.gostcipher.MODE_CTR, init_vect=iv
)

print(f"It's almost Halloween, time to get sp00{cipher.encrypt(flag).hex()}00ky 👻!")
```

Notably the cipher is initialized in counter mode.

When looking to exploit counter mode the first thing that should come to mind is nonce-reuse. This is because if we can recover two ciphertexts xored with the same nonce and counter we can recover the keystream.

`chall.py` ends with the following code:

```python
while True:
    print(cipher.encrypt(bytes.fromhex(input())).hex())
```

This strongly suggests we can recover the flag with some chosen plaintext.

Interestingly the loop is unbounded and there is no sign from the provided `Dockerfile` that we'll be cut off earlier than we choose.

`kuznechik` uses an 8 byte iv and an 8 byte counter and so this suggests `2^64` work to cause the counter to wrap.

However if we look at the implementation of the counter increment we can see that it will wrap after only 256 blocks:

https://github.com/drobotun/gostcrypto/blob/1590311620d6d03d1d8e1b6abe1966da4c8550ed/gostcrypto/gostcipher/gost_34_13_2015.py#L841

Here is pseudo-code adapted from the linked code:

```python
block_size = 16
init_vect = os.urandom(8)
init_vect = bytearray(init_vect)
counter = init_vect + b'\x00' * (block_size // 2)
counter = bytearray(counter)

def inc_ctr(ctr: bytearray) -> bytearray:
    internal = 0
    bit = bytearray(block_size)
    bit[block_size - 1] = 0x01
    for i in range(block_size):
        internal = ctr[i] + bit[i] + (internal << 8)
        ctr[i] = internal & 0xff
    return ctr
```

We can clearly see that `ctr[i] = internal & 0xff` prevents the value ever exceeding 0xff.

If we run `inc_ctr` in a loop 256 times we see that the counter will wrap:

```python
...
a260684ef15502de00000000000000fa
a260684ef15502de00000000000000fb
a260684ef15502de00000000000000fc
a260684ef15502de00000000000000fd
a260684ef15502de00000000000000fe
a260684ef15502de00000000000000ff
a260684ef15502de0000000000000000
```

### Fixing The Bug

An alternative way to implement the wrapping with the `struct` module might look like this:

```python
def inc_ctr(ctr: bytearray) -> bytearray:
    c = struct.unpack('>Q', ctr[-8:])[0]
    ctr[-8:] = struct.pack('>Q', (c - 1) & 0xffffffffffffffff)
    return ctr
```

If we run `inc_ctr` in a loop 256 times we see that the counter no longer wrap:

```python
...
7ba1af8a34da057300000000000000fa
7ba1af8a34da057300000000000000fb
7ba1af8a34da057300000000000000fc
7ba1af8a34da057300000000000000fd
7ba1af8a34da057300000000000000fe
7ba1af8a34da057300000000000000ff
7ba1af8a34da05730000000000000100
```

## Solution

1) Capture the encrypted flag taking care to extract only the hex characters associated with the ciphertext from the line
2) Encrypt a known plaintext, shown here `b"A" * 77`, and capture the ciphertext for the 257th block
    - Note: see above for an explanation of why the counter wraps and only has 256 unique values as a result
3) xor the two ciphertexts together to recover the keystream used to encrypt the flag
4) xor the encrypted flag with the keystream to recover the flag

```python
#!/usr/bin/env python3

from pwn import *

#context.log_level = "debug"
p = remote("crypto.heroctf.fr", 9001)

c1 = p.readline().decode()[39:(77*2)+39]

p1 = b"A" * 77
for i in range(0x100):
    p.sendline(p1.hex().encode())
    c2 = p.readline().decode()

key_stream = xor(bytes.fromhex(c1), bytes.fromhex(c2))
flag = xor(key_stream, p1).decode()
print(flag) # Hero{5p00ky_5c4ry_fl4w3d_cryp70_1mpl3m3n74710ns_53nd_5h1v3r5_d0wn_y0ur_5p1n3}
```

## Flag
`Hero{5p00ky_5c4ry_fl4w3d_cryp70_1mpl3m3n74710ns_53nd_5h1v3r5_d0wn_y0ur_5p1n3}`

smiley 2024/10/26
