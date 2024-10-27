https://ctftime.org/event/2496

# Paranoia (crypto)

I always feel that somebody's watching me

And I have found a way to keep my privacy (oh, oh)

## Analysis

We can see from the following code that data is encrypted twice. Once with AES and then again with SM4:

```python
data = self.__encrypt(AES, data, self.keys[0])
data = self.__encrypt(SM4, data, self.keys[1])
```

You might be tempted to think this doubles the security of the encryption but in reality it only very slightly increases the amount of work required by a bruteforce search.

This is because of the https://en.wikipedia.org/wiki/Meet-in-the-middle_attack which I will summarise in the next section.

Before that however we should note the following:

```python
# To comply with cryptography export regulations,
# 6 bytes = 2**48 bits, should be bruteforce-proof anyway
for n, k in enumerate(keys):
    print(f"k{n} = {k[3:]}")
```

A 3 byte bruteforce is very doable and a 6 byte bruteforce is not. Therefore our best hope is to deploy the meet in the middle attack to do around 2^12 work to recover both keys.

The last component we need is a known plaintext/ciphertext pair:

```python
print("pt_banner =", banner)
print("ct_banner =", paranoia.encrypt(banner))
```

### Meet In The Middle Attack

To perform the meet in the middle attack we perform the following steps:

1) Collect a known plaintext and ciphertext pair
2) Encrypt the known plaintext with all possible keys for the first cipher
3) Decrypt the known ciphertext with all possible keys for the second cipher
4) Check if any ciphertext produced step 2 is also produced by step 3
5) Consider each key pair that produces a matching ciphertext a candidate key pair
6) For each candidate key pair test if you can produce the known ciphertext with the known plaintext

## Solution

```python
#!/usr/bin/env python3

from cryptography.hazmat.primitives.ciphers.algorithms import AES, SM4
from cryptography.hazmat.primitives.ciphers import Cipher, modes
from struct import pack

def pad(data: bytes, bs: int) -> bytes:
    return data + (chr(bs - len(data) % bs) * (bs - len(data) % bs)).encode()

pt_banner = b"I don't trust governments, thankfully I've found smart a way to keep my data secure."
padded_pt_banner = pad(pt_banner, 16)
ct_banner = b"\xd5\xae\x14\x9de\x86\x15\x88\xe0\xdc\xc7\x88{\xcfy\x81\x91\xbaH\xb6\x06\x02\xbey_0\xa5\x8a\xf6\x8b?\x9c\xc9\x92\xac\xdeb=@\x9bI\xeeY\xa0\x8d/o\xfa%)\xfb\xa2j\xd9N\xf7\xfd\xf6\xc2\x0b\xc3\xd2\xfc\te\x99\x9aIG\x01_\xb3\xf4\x0fG\xfb\x9f\xab\\\xe0\xcc\x92\xf5\xaf\xa2\xe6\xb0h\x7f}\x92O\xa6\x04\x92\x88"
enc_flag = b"\xaf\xe0\xb8h=_\xb0\xfbJ0\xe6l\x8c\xf2\xad\x14\xee\xccw\xe9\xff\xaa\xb2\xe9c\xa4\xa0\x95\x81\xb8\x03\x93\x7fg\x00v\xde\xba\xfe\xb92\x04\xed\xc4\xc7\x08\x8c\x96C\x97\x07\x1b\xe8~':\x91\x08\xcf\x9e\x81\x0b\x9b\x15"
k0 = b'C\xb0\xc0f\xf3\xa8\n\xff\x8e\x96g\x03"'
k1 = b"Q\x95\x8b@\xfbf\xba_\x9e\x84\xba\x1a7"

enc_k0p = {}
for i in range(0x1000000):
    k0p =  pack(">I", i)[1:] + k0
    cipher = Cipher(AES(k0p), modes.ECB())
    encryptor = cipher.encryptor()
    enc_k0p[encryptor.update(padded_pt_banner) + encryptor.finalize()] = i

dec_k1p = []
for i in range(0x1000000):
    k1p = pack(">I", i)[1:] + k1
    cipher = Cipher(SM4(k1p), modes.ECB())
    decryptor = cipher.decryptor()
    dec_k1p.append(decryptor.update(ct_banner) + decryptor.finalize())

for i in range(len(dec_k1p)):
    if dec_k1p[i] in enc_k0p:
        k1p = pack(">I", i)[1:] + k1
        cipher = Cipher(SM4(k1p), modes.ECB())
        decryptor = cipher.decryptor()
        flag = decryptor.update(enc_flag) + decryptor.finalize()

        k0p =  pack(">I", enc_k0p[dec_k1p[i]])[1:] + k0
        cipher = Cipher(AES(k0p), modes.ECB())
        decryptor = cipher.decryptor()
        flag = decryptor.update(flag) + decryptor.finalize()

        print(flag) # Hero{p4r4n014_p4r4n014_3v3ryb0dy_5_c0m1n6_70_637_m3!}
```

## Flag
`Hero{p4r4n014_p4r4n014_3v3ryb0dy_5_c0m1n6_70_637_m3!}`

smiley 2024/10/27
