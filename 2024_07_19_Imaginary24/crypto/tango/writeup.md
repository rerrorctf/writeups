https://ctftime.org/event/2396

# tango (crypto)

Let's dance!

https://cybersharing.net/s/d0f066f686795481

nc tango.chal.imaginaryctf.org 1337

## Analysis

1) The use of Salsa20, a stream cipher, without a suitable mac allows us to alter the ciphertext
2) The nonce embedded in the json structure, which has no realation to the cipher nonce, isn't checked
3) We know most, but not all, of the plaintext used in `encrypt_command`
4) We can recover a good chunk of the keystream and use it to encrypt our own shorter json structure

## Solution

```python
#!/usr/bin/env python3

import json

from pwn import *
from zlib import crc32

#context.log_level = "debug"
#p = process(["python3", "./server.py"])
p = remote("tango.chal.imaginaryctf.org", 1337)

p.sendlineafter(b"> ", b"E")
p.sendlineafter(b"Your command: ", b"fla")
p.readuntil(b"Your encrypted packet is: ")
encrypted_packet = bytes.fromhex(p.readline().decode()[:-1])

nonce = encrypted_packet[:8]
ciphertext = encrypted_packet[12:]

known_plaintext = json.dumps({'user': 'user', 'command': 'fla', 'nonce': "ffffffffffffffff" }).encode('ascii')

keystream = b""
for i in range(len(known_plaintext)):
    keystream += p8(known_plaintext[i] ^ ciphertext[i])

chosen_plaintext = json.dumps({'user': 'root', 'command': 'flag'}).encode('ascii')
checksum = crc32(chosen_plaintext).to_bytes(length=4, byteorder="big")

crafted_packet = nonce
crafted_packet += checksum
for i in range(len(chosen_plaintext)):
    crafted_packet += p8(chosen_plaintext[i] ^ keystream[i])

p.sendlineafter(b"> ", b"R")
p.sendlineafter(b"Your encrypted packet (hex): ", crafted_packet.hex().encode())

log.success(p.readline().decode()) # ictf{F0xtr0t_L1m4_4lph4_G0lf}
```

## Flag
`ictf{F0xtr0t_L1m4_4lph4_G0lf}`

smiley 2024/07/21
