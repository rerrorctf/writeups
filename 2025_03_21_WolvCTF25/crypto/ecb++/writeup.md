https://ctftime.org/event/2579 

# ECB++ (crypto)

I made an encryption machine! I was so nice that it even gives out gifts together with the encrypted text!

nc ecbpp.kctf-453514-codelab.kctf.cloud 1337

## Analysis

We can see that we are given an ECB encryption oracle with an attack controlled prefix:

```python
def encrypt(message):
    global flag
    message = message.encode()
    message += flag.encode()
    key = random.getrandbits(256)
    key = key.to_bytes(32,'little')
    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext = cipher.encrypt(pad(message, AES.block_size))
    return(ciphertext.hex())
```

However unlike typical ECB encryption oracles every single message is encrypted under a new random key.

This means that in order to perform byte-at-a-time plaintext recovery we need to encrypt all the inputs for our dictionary of known plaintext to ciphertext pairs along with our query plaintext in a single pass.

Here's an example WHICH DOESN'T WORK of the more typical byte-at-time ECB attack:

```python
# this DOESN'T work because the key changes each time..

def ecb_byte_at_a_time(known_pt=""):
    known_pt = ("A" * 16) + known_pt

    def enc(pt):
        p.sendline(b"Y")
        p.sendlineafter(b"message:", pt)
        p.readuntil(b"Your message is: ")
        ct = bytes.fromhex(p.readline().decode())
        return ct

    for i in range(MAX_FLAG_LEN):
        padding = 15 - (i % 16)
        pt = "A" * padding
        ct = enc(pt)

        dict_cts = {}
        for c in ALPHABET:
            dict_known_pt = known_pt[len(known_pt)-16+1:len(known_pt)]
            dict_pt = dict_known_pt + c
            dict_cts[c] = enc(dict_pt)

        block_to_attack = (padding + i) // 16
        ct_block_to_attack = ct[block_to_attack * 16: (block_to_attack + 1) * 16]

        for c in ALPHABET:
            match = True
            for j in range(16):
                if ct_block_to_attack[j] != dict_cts[c][j]:
                    match = False
                    break

            if match:
                known_pt += c
                print(f"{known_pt[16:]}")
                break

        if "}" in known_pt:
            return known_pt[16:]
```

Recall that this doesn't work because each call to `enc` assumes the same key is used to encrypt our chosen plaintext.

## Solution

1) For each byte of the flag send along every possible character from our alphabet as the last byte in a block followed by a query which places the next unknown byte in the 16th byte of a block
2) Compare the ciphertext for the block containing the unknown character against the outputs for our known-plaintext/ciphertext pairs

```python
#!/usr/bin/env python3

import string
from pwn import *

#context.log_level = "debug"

MAX_FLAG_LEN = 90

# we're not given an alphabet so pick a sensible one...
ALPHABET = string.ascii_letters + string.digits + "-_}{@!?$%^&*()~#/"

#p = process(["venv/bin/python3", "./chal.py"])
p = remote("ecbpp.kctf-453514-codelab.kctf.cloud", 1337)

p.readline()
p.readline()

def ecb_byte_at_a_time(known_pt=""):
    known_pt = known_pt

    def enc(pt):
        p.sendline(b"Y")
        p.sendlineafter(b"message:", pt.encode())
        p.readuntil(b"Your message is:  ")
        ct = bytes.fromhex(p.readline().decode())
        return ct

    for i in range(MAX_FLAG_LEN):
        padding = 15 - (i % 16)

        pt = ""
        for c in ALPHABET:
            pt += ("A" * padding) + known_pt + c

        dict_block_sizes = len(("A" * padding) + known_pt + "A")
        prefix_len = len(pt)

        pt += "A" * padding
        ct = enc(pt)

        dict_cts = {}
        for j in range(len(ALPHABET)):
            c = ALPHABET[j]
            dict_cts[c] = ct[j*dict_block_sizes:(j+1)*dict_block_sizes][-16:]

        ct = ct[len(ALPHABET)*dict_block_sizes:]

        block_to_attack = (padding + i) // 16
        ct_block_to_attack = ct[block_to_attack * 16: (block_to_attack + 1) * 16]

        for c in ALPHABET:
            match = True
            for j in range(16):
                if ct_block_to_attack[j] != dict_cts[c][j]:
                    match = False
                    break

            if match:
                known_pt += c
                #print(f"{known_pt}")
                break

    return known_pt

flag = ecb_byte_at_a_time(known_pt="wctf{")
print(flag) # wctf{1_m4d3_th15_fl4G_r34lly_l0ng_s0_th4t_y0u_w0ulD_h4v3_t0_d34L_w1th_muL7iPl3_bl0cKs_L0L}
```

## Flag
`wctf{1_m4d3_th15_fl4G_r34lly_l0ng_s0_th4t_y0u_w0ulD_h4v3_t0_d34L_w1th_muL7iPl3_bl0cKs_L0L}`

smiley 2025/03/22
