https://ctftime.org/event/2238/

# Criminal ~ CRY

It would be a crime for me to just give you the flag, so I'll encrypt it first before sending it. I'll even compress it to make it faster to transmit!

Note: the flag matches the regex gigem{[a-z_]+} (the curly braces are not quantifiers).

## Solution

This task is based on the https://en.wikipedia.org/wiki/CRIME vuln from 2012.

The idea is that when you compress data prior to encryption the length of the ciphertext can be used to determine the plaintext.

We can see from the following code that the size of the compressed result is smaller when the suffix matches the prefix:

```
>>> import zlib
>>> len(zlib.compress(b"gigem{a" + b"gigem{a"))
17
>>> len(zlib.compress(b"gigem{a" + b"gigem{b"))
18
>>> len(zlib.compress(b"gigem{a" + b"gigem{c"))
18
>>> len(zlib.compress(b"gigem{a" + b"gigem{d"))
18
```

We can use this to determine the flag, character by character, by observing which suffix produces the smallest resulting ciphertext:

```
from pwn import *
from base64 import b64decode

io = remote("tamuctf.com", 443, ssl=True, sni="criminal")

alphabet = []
for i in range(0, 26):
    alphabet += chr(ord('a') + i)
alphabet += '_'

flag = b"gigem{"

while True:
    smallest_size = 42069
    best_letter = ''
    for l in alphabet:
        io.readuntil(b"Append whatever you want to the flag: ")
        io.sendline(flag + l.encode())
        size = len(b64decode(io.readline().decode()))
        if size < smallest_size:
            smallest_size = size
            best_letter = l
    flag += best_letter.encode()
    print(flag)
```

## Flag
`gigem{foiled_again}`
