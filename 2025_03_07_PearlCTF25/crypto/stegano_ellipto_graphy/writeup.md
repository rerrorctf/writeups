https://ctftime.org/event/2647

# stegano_ellipto_graphy (crypto)

My friend e4stw1nd’s girlfriend keeps sending and receiving images along with a number to her best friend. He insists she’s loyal, but I don’t think so. One day, I hacked into her best friend’s laptop and found this code—but some parts are redacted. Can you complete it and prove him wrong?

## Analysis

We can see the main vulnerability is in the generation of `shared_key`:

```python
def encrypt_message(message, public_key):
    
    shared_key_point = curve.multiply(public_key[0], g)
    shared_key = shared_key_point[0]  
```

Specifically the the `public_key` is used with `g` to generated the shared symmetric key.

We are given a value in a file called `key`. If this is the private key we can reconstruct the shared symmetric key.

## Solution

1) Extract the least significant bit of each pixel in the image
2) Reconstruct the ciphertext
3) Compute the public key (this is used to generate a shared symmetric key)
4) Decrypt the ciphertext using the same method as encryption.

```python
#!/usr/bin/env python3

from pwn import *
import hashlib
import os
from PIL import Image
import numpy as np

class ECC:
    def __init__(self, p, a, b, g, n):
        self.p = p
        self.a = a
        self.b = b
        self.g = g
        self.n = n

    def add(self, P, Q):
        if P == (0, 0):  
            return Q
        if Q == (0, 0):  
            return P
        if P[0] == Q[0] and P[1] != Q[1]:  
            return (0, 0)

        if P != Q:
            lambd = (Q[1] - P[1]) * pow(Q[0] - P[0], -1, self.p) % self.p
        else:
            if 2 * P[1] % self.p == 0:
                raise ValueError("Point doubling failed: 2 * P[1] is not invertible.")
            lambd = (3 * P[0] ** 2 + self.a) * pow(2 * P[1], -1, self.p) % self.p

        x_r = (lambd ** 2 - P[0] - Q[0]) % self.p
        y_r = (lambd * (P[0] - x_r) - P[1]) % self.p
        return (x_r, y_r)

    def multiply(self, k, P):
        R = (0, 0)
        for i in bin(k)[2:]:
            R = self.add(R, R)
            if i == "1":
                R = self.add(R, P)
        return R

# the elliptic curve is basically https://neuromancer.sk/std/secg/secp256k1
# ...but with a different point g

p = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f
a = 0
b = 7
g = (55066263022277343669578718895168534326250603453732580969419399252653644613,
     93807190528502704734438820432045625694355265803661227653698390517638372054)
n = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141

curve = ECC(p, a, b, g, n)

# this should work to decrypt the message too...
# ...note how only public information is required

def encrypt_message(message, public_key):
    shared_key_point = curve.multiply(public_key[0], g)
    shared_key = shared_key_point[0]  

    shared_key_bytes = b""
    while len(shared_key_bytes) < len(message):
        shared_key_bytes += hashlib.sha256((str(shared_key) + str(len(shared_key_bytes))).encode()).digest()

    encrypted_message = bytes([m ^ k for m, k in zip(message, shared_key_bytes)])
    return encrypted_message

# extract the lsb to recover the ciphertext...

data_bin = ""
flat_img = np.array(Image.open("./out.png")).flatten()
for pixel in flat_img:
    data_bin += str(pixel & 0x1)

ciphertext = b""
ciphertext_len = int(data_bin[:16], 2)
data_bin = data_bin[16:16+(ciphertext_len*8)]
for i in range(0, ciphertext_len*8, 8):
    ciphertext += p8(int(data_bin[i:i+8], 2))

# we know the private key from the provided key file...

private_key = 6558684506371667866903020874921700400259832463896378794735041574848246323110
public_key = curve.multiply(private_key, g)

flag = encrypt_message(ciphertext, public_key).decode()
print(flag) # pearl{babe_he's_not_home_U_know_the_drill}
```

## Flag
`pearl{babe_he's_not_home_U_know_the_drill}`

smiley 2025/03/07
