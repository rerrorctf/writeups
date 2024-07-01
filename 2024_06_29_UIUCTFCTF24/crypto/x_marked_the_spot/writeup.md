https://ctftime.org/event/2275

# X Marked the Spot (crypto)

A perfect first challenge for beginners. Who said pirates can't ride trains...

## Solution

The flag is xored with the key.

We know that the flag format is `uiuctf{.+}`.

This means we can recover the first 7 bytes of the keystream by xoring it with `uiuctf{`.

We can obtain the final byte of the keystream two ways:

1) Notice that the length of the ciphertext, and therefore the plaintext, is a multiple of 8. This means that the 8th byte of the key was used to encrypt `"}"`
2) Simply try all possible values for the final byte of the key, optionally limiting this to `string.printable`, and look for a plaintext that ends with `"}"`

```python
import struct
from itertools import cycle

with open("ct", "rb") as file:
    ct = file.read()

key = b""
for i, c in enumerate("uiuctf{"):
    key += struct.pack("B", ct[i] ^ ord(c))

key += struct.pack("B", ct[-1] ^ ord("}"))

pt = bytes(x ^ y for x, y in zip(ct, cycle(key)))

print(pt.decode())
```

## Flag
`uiuctf{n0t_ju5t_th3_st4rt_but_4l50_th3_3nd!!!!!}`

smiley 2024/06/30
