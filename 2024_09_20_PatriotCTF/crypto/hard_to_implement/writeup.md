https://ctftime.org/event/2426/

# Hard to Implement (crypto)

I have a flag for you. We should talk more over my secure communications channel.

nc chal.competitivecyber.club 6001

## Analysis

The remote encrypts our chosen plaintext along with the flag using AES_128_ECB as follows:

```python
def encrypt(key,plaintext):
	cipher = AES.new(key, AES.MODE_ECB)
	pt = pad(plaintext + flag.encode(), 16)
	return cipher.encrypt(pt).hex()
```

Because control the prefix, here called plaintext, we can decrypt the flag one byte a time.

This works because we can compute all possible permutations of the last byte within a block and then align the flag such that its first byte appears in the last byte along with the same prefix.

In this pseudocode we compute all the permutations and note the ciphertext:

```python
for i in range(256):
    if AES_128_ECB(b"A" * 15 + bytes([i])) == AES_128_ECB(b"A" * 15 + flag[0]):
        #
```

When we allow the first byte of the flag to be the last byte of the block, by specifying a prefix of only 15 bytes, we'll get back a ciphertext that is identical to one of the 256 possible ciphertexts.

We can repeat this process for each byte of the secret suffix.

You can read more about this attack here https://cryptopals.com/sets/2/challenges/12.

## Solution

Note: the final for loop is written with an unclear idea of how large the final flag is.

```python
#!/usr/bin/env python3

from pwn import *
from string import printable

#context.log_level = "debug"
p = remote("chal.competitivecyber.club", 6001)

def encrypt(plaintext):
    p.sendafter(b"> ", plaintext)
    p.readuntil(b"> ")
    return bytes.fromhex(p.readline().decode())

def get_next_byte(flag):
    prefix_len = (16 - (1 + len(flag))) % 16
    prefix = b'A' * prefix_len
    length = prefix_len + len(flag) + 1
    ciphertext = encrypt(prefix)
    for c in printable:
        fake = encrypt(prefix + flag + bytes([ord(c)]))
        if fake[:length] == ciphertext[:length]:
            return bytes([ord(c)])
    return b''

flag = b""
for i in range(32):
    flag += get_next_byte(flag)
    print(flag.decode()) # pctf{ab8zf58}
```

## Flag
`pctf{ab8zf58}`

smiley 2024/09/21
