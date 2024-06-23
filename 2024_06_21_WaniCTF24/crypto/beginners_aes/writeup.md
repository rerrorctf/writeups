https://ctftime.org/event/2377

# beginners_aes (crypto)

AES is one of the most important encryption methods in our daily lives.

## Solution

We are given the following python:

```python
# https://pycryptodome.readthedocs.io/en/latest/src/cipher/aes.html
from Crypto.Util.Padding import pad
from Crypto.Cipher import AES
from os import urandom
import hashlib

key = b'the_enc_key_is_'
iv = b'my_great_iv_is_'
key += urandom(1)
iv += urandom(1)

cipher = AES.new(key, AES.MODE_CBC, iv)
FLAG = b'FLAG{This_is_a_dummy_flag}'
flag_hash = hashlib.sha256(FLAG).hexdigest()

msg = pad(FLAG, 16)
enc = cipher.encrypt(msg)

print(f'enc = {enc}') # bytes object
print(f'flag_hash = {flag_hash}') # str object
```

And the following output:

```
enc = b'\x16\x97,\xa7\xfb_\xf3\x15.\x87jKRaF&"\xb6\xc4x\xf4.K\xd77j\xe5MLI_y\xd96\xf1$\xc5\xa3\x03\x990Q^\xc0\x17M2\x18'
flag_hash = 6a96111d69e015a07e96dcd141d31e7fc81c4420dbbef75aef5201809093210e
```

We can see there the key possible space is very small with only 256 possible keys and 256 possible ivs there are only 65536 possible ways to encrypt.

To decrypt we simply try them all using the provided flag hash to easily determine when we reach the correct solution.

```python
#!/usr/bin/env python3

import hashlib

from Crypto.Util.Padding import unpad
from Crypto.Cipher import AES

enc = b'\x16\x97,\xa7\xfb_\xf3\x15.\x87jKRaF&"\xb6\xc4x\xf4.K\xd77j\xe5MLI_y\xd96\xf1$\xc5\xa3\x03\x990Q^\xc0\x17M2\x18'
flag_hash = "6a96111d69e015a07e96dcd141d31e7fc81c4420dbbef75aef5201809093210e"

def decrypt(key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    flag = unpad(cipher.decrypt(enc), 16)
    if hashlib.sha256(flag).hexdigest() == flag_hash:
        print(flag.decode())

for i in range(0x100):
    for j in range(0x100):
        key = b'the_enc_key_is_'
        iv = b'my_great_iv_is_'
        key += i.to_bytes(1, byteorder="big")
        iv += j.to_bytes(1, byteorder="big")
        try:
            decrypt(key, iv)
        except:
            pass
```

## Flag
`FLAG{7h3_f1r57_5t3p_t0_Crypt0!!}`

smiley 2024/06/21
