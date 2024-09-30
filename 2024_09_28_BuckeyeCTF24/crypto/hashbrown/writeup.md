https://ctftime.org/event/2449

# hashbrown (crypto)

I made fresh hashbrowns fresh hash function.

nc challs.pwnoh.io 13419

## Analysis

In `hash` we can see that the output of the previous aes encryption is used as the key for the following block.

We can see that the the final aes encryption output is returned as a signature.

This means that we can continue hashing with a known signature and message by using the signature as the key and appending to the message.

We have to take care to deal with the padding in `pad` correctly when presenting a message a message to be verified and when extending a hash output. In particular the verifier will add padding to whatever message we give it and therefore we need to present an unpadded but extended message and encrypt a padded and extended message. We must also take care to preserve the padding that would have been added to the original message.

## Solution

1) Create a block containing the checked string "french fry"
2) Make a padded variant of the new block
3) Collect the original message and extended it with both the padded and unpadded french fry block
4) Collect the signature and then forge a new signature

```python
#!/usr/bin/env python3

from pwn import *
from Crypto.Cipher import AES

#context.log_level = "debug"
p = remote("challs.pwnoh.io", 13419)

p.readuntil(b"hex:\n")
message = bytes.fromhex(p.readline().decode())
message += b"_" * (16 - len(message) % 16)

p.readuntil(b"Signature:\n")
key = bytes.fromhex(p.readline().decode()[-33:-1])

french_fry = b"french fry"
padded_french_fry = french_fry + (b"_" * (16 - len(french_fry) % 16))

p.sendlineafter(b"> ", (message + french_fry).hex().encode())

forgery = AES.new(key, AES.MODE_ECB).encrypt(padded_french_fry)
p.sendlineafter(b"> ", forgery.hex().encode())

p.readuntil(b"flag:\n")

# bctf{e7ym0l0gy_f4c7_7h3_w0rd_hash_c0m35_fr0m_7h3_fr3nch_hacher_wh1ch_m34n5_t0_h4ck_0r_ch0p}
print(p.readline().decode()[:-1])
```

## Flag
`bctf{e7ym0l0gy_f4c7_7h3_w0rd_hash_c0m35_fr0m_7h3_fr3nch_hacher_wh1ch_m34n5_t0_h4ck_0r_ch0p}`

smiley 2024/09/28
