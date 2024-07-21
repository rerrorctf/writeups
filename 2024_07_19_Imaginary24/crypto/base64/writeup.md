https://ctftime.org/event/2396

# base64 (crypto)

yet another base64 decoding challenge

https://cybersharing.net/s/8c2a3e4e78a0161f

## Analysis

We are given the following code:

```python
from Crypto.Util.number import bytes_to_long

q = 64

flag = open("flag.txt", "rb").read()
flag_int = bytes_to_long(flag)

secret_key = []
while flag_int:
    secret_key.append(flag_int % q)
    flag_int //= q

print(f"{secret_key = }")
```

We are also given the output in a file called out.txt.

This code operates on groups of 6 bits each of which have 64 possible values. It represents each of those with a decimal value from 0 to 65.

A typical base64 encoder would represent these 64 values using an alphabet that allows all values to represented with one byte.

## Solution

To solve we simply invert the operation:

```python
#!/usr/bin/env python3

q = 64

secret_key = [10, 52, 23, 14, 52, 16, 3, 14, 37, 37, 3, 25,
              50, 32, 19, 14, 48, 32, 35, 13, 54, 12, 35, 12,
              31, 29, 7, 29, 38, 61, 37, 27, 47, 5, 51, 28,
              50, 13, 35, 29, 46, 1, 51, 24, 31, 21, 54, 28,
              52, 8, 54, 30, 38, 17, 55, 24, 41, 1]

flag_int = 0
for i in range(len(secret_key)-1, -1, -1):
    flag_int = flag_int * q + secret_key[i]

flag = flag_int.to_bytes((len(secret_key) * 3) // 4, byteorder="big")

print(flag.decode()) # ictf{b4se_c0nv3rs1on_ftw_236680982d9e8449}
```

Note that to recover the number of bytes that a quantity of base64 characters represents you do the following:

`(len(base64_data) * 3) // 4`

## Flag
`ictf{b4se_c0nv3rs1on_ftw_236680982d9e8449}`

smiley 2024/07/21
