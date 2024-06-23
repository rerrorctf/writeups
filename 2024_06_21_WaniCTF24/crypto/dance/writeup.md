https://ctftime.org/event/2377

# dance (crypto)

step by step

## Analysis

In the provided `chall.py` we can see a server that allows users to perform encryption.

In order to perform encryption a user must first login.

In order to login a user must simply provide their username.

A token will computed for their session based on the following:
1) Their username
2) The number of minutes that have elapsed this hour
3) The number of seconds that have elapsed this minute

The token is used to derived a key and a nonce for an encryption function that is provided in the file `mycipher.py`.

We are also provided with the username used. At this point we can safely say that we can bruteforce all key/nonce pairs.

We can see that the cipher in question is ChaCha.

We can tell that this is ChaCha and not Salsa by quarter round:

```python
def __quarter_round(self, a: F2_32, b: F2_32, c: F2_32, d: F2_32):
    a += b; d ^= a; d <<= 16
    c += d; b ^= c; b <<= 12
    a += b; d ^= a; d <<= 8
    c += d; b ^= c; b <<= 7
    return a, b, c, d
```

Whereas a Salsa quarter round would look more like:

```c
#define ROTL(a,b) (((a) << (b)) | ((a) >> (32 - (b))))
#define QR(a, b, c, d)(  \
	b ^= ROTL(a + d, 7), \
	c ^= ROTL(b + a, 9), \
	d ^= ROTL(c + b,13), \
	a ^= ROTL(d + c,18))
```

We can determine the number of rounds by counting the number of quarter rounds:

```python
for _ in range(10):
    self.__Qround(0, 4, 8, 12)
    self.__Qround(1, 5, 9, 13)
    self.__Qround(2, 6, 10, 14)
    self.__Qround(3, 7, 11, 15)
    self.__Qround(0, 5, 10, 15)
    self.__Qround(1, 6, 11, 12)
    self.__Qround(2, 7, 8, 13)
    self.__Qround(3, 4, 9, 14)
```

`10 * 8 = 80` quater rounds so `80 / 4 = 20` rounds.

Therefore this is ChaCha20. However, what matters here is that ChaCha20 is a stream cipher.

If we can recover the keystream used to perform the original encryption we can simply xor it with the encrypted data to recover the flag.

To do this we will recover the keystream from a known plaintext for all possible key / nonce pairs and then try to decrypt the flag with each keystream.

## Solution

1) Reconstuct all possible tokens using:
    - The given username `gureisya`
    - The fact that there are only 60 possible values for minutes and seconds
2) Encrypt a known plaintext with each possible token
3) Recover the key stream from the known ciphertext by xoring it with the known plaintext
4) Attempt to decrypt the encrypted flag with the recovered keystream

```python
#!/usr/bin/env python3

import hashlib

from mycipher import MyCipher

username = 'gureisya'
known_ciphertext = b"\x06\x1f\xf0\x6d\xa6\xfb\xf8\xef\xcd\x2c\xa0\xc1\xd3\xb2\x36\xae\xde\x3f\x5d\x4b\x6e\x8e\xa2\x41\x79"

def make_token(data1: str, data2: str):
    sha256 = hashlib.sha256()
    sha256.update(data1.encode())
    right = sha256.hexdigest()[:20]
    sha256.update(data2.encode())
    left = sha256.hexdigest()[:12]
    token = left + right
    return token

def try_token(token: str):
    sha256 = hashlib.sha256()
    sha256.update(token.encode())
    key = sha256.hexdigest()[:32]
    nonce = token[:12]
    cipher = MyCipher(key.encode(), nonce.encode())
    plaintext = b"A" * len(known_ciphertext)
    ciphertext = cipher.encrypt(plaintext)
    keystream = b""
    for i in range(len(known_ciphertext)):
        keystream += (ord("A") ^ ciphertext[i]).to_bytes(1, byteorder="big")
    flag = b""
    for i in range(len(known_ciphertext)):
        flag += (keystream[i] ^ known_ciphertext[i]).to_bytes(1, byteorder="big")
    if flag[:4] == b"FLAG":
        print(flag.decode())

for minutes in range(1, 61):
    for sec in range(1, 61):
        for r in range(0, 11):
            data1 = f'user: {username}, {minutes}:{sec}'
            data2 = f'{username}'+str(r)
            try_token(make_token(data1, data2))
```

## Flag
`FLAG{d4nc3_l0b0t_d4nc3!!}`

smiley 2024/06/21
