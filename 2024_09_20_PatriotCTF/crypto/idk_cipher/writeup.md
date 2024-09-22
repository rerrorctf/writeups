https://ctftime.org/event/2426/

# idk cipher (crypto)

I spent a couple of hours with ???; now I am the world's best cryptographer!!! note: the flag contents will just random chars-- not english/leetspeak

Cipher Text: QRVWUFdWEUpdXEVGCF8DVEoYEEIBBlEAE0dQAURFD1I=

Please wrap the flag with pctf{}.

## Analysis

1) We can see that the ciphertext is emitted in pairs where each pair
2) The pairs are formed using the input and the input reversed
3) The plaintext is xored with bytes of the key

## Solution

1) Permute the ciphertext such that the byte order matches that of the original plaintext
2) Apply they key with xor - repeating the key as it is exhausted

```python
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
```

### Note

I found the following part of the task needlessly confusing:

```python
# WARNING: This is a secret key. Do not expose it.
srt_key = 'secretkey' # // TODO: change the placeholder
```

You are supposed to realise or guess that this is the actual key and not a placeholder.

Given that there is no form of offline integrity check possible within the task itself this is especially bad.

Granted, you are told that `the flag contents will just random chars`. So you can at least assume that a non-printable byte is wrong.

## Flag
`pctf{234c81cf3cd2a50d91d5cc1a1429855f}`

smiley 2024/09/21
