https://ctftime.org/event/2573

# Rock my Password (crypto)

I've come up with an extremely secure(tm) way to store my password, noone will be able to reverse it! I've hashed it with md5 100 times, then sha256 100 times, then sha512 100 times! There's no way you're going to be able to undo it >:3 I'll even tell you it was in the RockYou database, and the password is 10 characters long, that's how confident I am!

The flag is in the format: swampCTF{RockYouPassword}

As a reminder, please don't flood our infrastructure with guesses.

Hashed Password (Flag): f600d59a5cdd245a45297079299f2fcd811a8c5461d979f09b73d21b11fbb4f899389e588745c6a9af13749eebbdc2e72336cc57ccf90953e6f9096996a58dcc

Note: The entire flag (swampCTF{rockyoupassword}) was hashed to get the provided hash, not just rockyoupassword

## SecLists

I use the following repo which contains a compressed version of the rockyou.txt list:

https://github.com/danielmiessler/SecLists

## Solution

```python
#!/usr/bin/env python3

from hashlib import md5, sha256, sha512

flag_hash = bytes.fromhex("f600d59a5cdd245a45297079299f2fcd811a8c5461d979f09b73d21b11fbb4f899389e588745c6a9af13749eebbdc2e72336cc57ccf90953e6f9096996a58dcc")

f = open("/opt/SecLists/Passwords/Leaked-Databases/rockyou.txt", "r")

for i in range(14344391):
    try:
        p = f.readline().strip().encode()
    except:
        continue

    if len(p) != 10:
        continue

    flag = b"swampCTF{" + p + b"}" 
    h = flag

    for j in range(100):
        h = md5(h).digest()

    for j in range(100):
        h = sha256(h).digest()

    for j in range(100):
        h = sha512(h).digest()

    if h == flag_hash:
        print(flag.decode()) # swampCTF{secretcode}
        break
```

## Flag
`swampCTF{secretcode}`

smiley 2025/03/29
