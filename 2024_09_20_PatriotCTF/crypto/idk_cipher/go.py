#!/usr/bin/env python3

from base64 import b64decode
from struct import pack

key = b"secretkey"
ciphertext = b64decode(b"QRVWUFdWEUpdXEVGCF8DVEoYEEIBBlEAE0dQAURFD1I=")

x = b""
key_idx = 0

for i in range(0, len(ciphertext), 2):
    x += pack("B", ciphertext[i] ^ key[key_idx])
    key_idx = (key_idx + 1) % len(key)

y = b""
key_idx = 0

for i in range(1, len(ciphertext), 2):
    y += pack("B", ciphertext[i] ^ key[key_idx])
    key_idx = (key_idx + 1) % len(key)

flag = b"pctf{" + x + y[::-1] + b"}"

print(flag.decode()) # pctf{234c81cf3cd2a50d91d5cc1a1429855f}
