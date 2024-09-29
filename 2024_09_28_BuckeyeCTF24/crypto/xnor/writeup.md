https://ctftime.org/event/2449

# xnor (crypto)

XNOR! Its like XOR, but its actually the complete opposite.

## Analysis

We are given a the result of encrypting both a known plaintext and a flag with the same key. The method of encryption is to apply the xnor operation to each bit.

## Solution

1) Recover the key by xnoring the encrypted message with the known plaintext
2) Recover the flag by xnoring the encrypted flag with the key

```python
#!/usr/bin/env python3

from xnor import *

message  = b'Blue is greener than purple for sure!'
message_enc = bytes.fromhex("fe9d88f3d675d0c90d95468212b79e929efffcf281d04f0cfa6d07704118943da2af36b9f8")
key = xnor_bytes(message_enc, message)

flag_enc = bytes.fromhex("de9289f08d6bcb90359f4dd70e8d95829fc8ffaf90ce5d21f96e3d635f148a68e4eb32efa4")
flag = xnor_bytes(flag_enc, key)

print(flag.decode()) # bctf{why_xn0r_y0u_b31ng_so_3xclu51v3}
```

## Flag
`bctf{why_xn0r_y0u_b31ng_so_3xclu51v3}`

smiley 2024/09/28
