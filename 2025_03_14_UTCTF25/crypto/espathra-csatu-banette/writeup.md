https://ctftime.org/event/2641

# Espathra-Csatu-Banette (crypto)

Everyone keeps telling me how ECB isn't meta-viable and that I should stop playing it to tournaments. Well, I love ECB so I've added some new tech that should hopefully get me some better results!

nc challenge.utctf.live 7150

## Analysis

We are provided with the following code in `main.py`:

```python
#!/usr/bin/env python3

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
key = open("/src/key", "rb").read()
secret = open("/src/flag.txt", "r").read()
cipher = AES.new(key, AES.MODE_ECB)

while 1:
    print('Enter text to be encrypted: ', end='')
    x = input()
    chksum = sum(ord(c) for c in x) % (len(x)+1)
    pt = x[:chksum] + secret + x[chksum:]
    ct = cipher.encrypt(pad(pt.encode('utf-8'), AES.block_size))
    print(hex(int.from_bytes(ct, byteorder='big')))
```

We can see that we have an ECB encryption oracle.

However the flag conditionally prefixed and suffixed with attacker controlled input.

This is vulnerable to the ECB byte at a time attack.

For more information on this attack see https://www.cryptopals.com/sets/2/challenges/12.

We just need to make sure that we can control `pt` such that `pt = attacker_prefx + secret + ...`:

```python
# make_plaintext ensures that our prefix is appended to the flag...
# ...by adding a suffix such that:
# chksum = sum(ord(c) for c in x) % (len(x)+1)
# assert(chksum == len(prefix))
#
# which makes:
# pt = x[:chksum] + secret + x[chksum:]
#
# become:
# pt = prefix + secret + suffix
#
# we can ignore the suffix and so this becomes:
# pt = prefix + secret
# ...which is the standard form for ecb byte-at-a-time decryption

def make_plaintext(prefix):
    attempt = 0
    x = prefix
    while True:
        if sum(ord(c) for c in x) % (len(x)+1) == len(prefix):
            return x
        x = prefix + string.ascii_letters[attempt]
        attempt += 1

```

### Testing Locally

In order to easily test locally I used `p = process(["venv/bin/python3", "./main2.py"])` along with the following modified version of `main.py`:

```python
#!/usr/bin/env python3

import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

key = os.urandom(16)
secret = "utflag{an_example_of_what_the_flag_might_be!!}"
cipher = AES.new(key, AES.MODE_ECB)

while 1:
    print('Enter text to be encrypted: ', end='')
    x = input()
    chksum = sum(ord(c) for c in x) % (len(x)+1)
    pt = x[:chksum] + secret + x[chksum:]
    ct = cipher.encrypt(pad(pt.encode('utf-8'), AES.block_size))
    print(hex(int.from_bytes(ct, byteorder='big')))
```

This is helpful because testing against the remote can be very slow and error prone.

## Solution

```python
#!/usr/bin/env python3

import string
from pwn import *

MAX_FLAG_LEN = 128

#context.log_level = "debug"

#p = process(["venv/bin/python3", "./main2.py"])
p = remote("challenge.utctf.live", 7150)

# make_plaintext ensures that our prefix is appended to the flag...
# ...by adding a suffix such that:
# chksum = sum(ord(c) for c in x) % (len(x)+1)
# assert(chksum == len(prefix))
#
# which makes:
# pt = x[:chksum] + secret + x[chksum:]
#
# become:
# pt = prefix + secret + suffix
#
# we can ignore the suffix and so this becomes:
# pt = prefix + secret
# ...which is the standard form for ecb byte-at-a-time decryption

def make_plaintext(prefix):
    attempt = 0
    x = prefix
    while True:
        if sum(ord(c) for c in x) % (len(x)+1) == len(prefix):
            return x
        x = prefix + string.ascii_letters[attempt]
        attempt += 1

# note that if your connection dies before you know the entire flag...
# ... you can add what you know to known_pt to save yourself some time
# e.g. ecb_byte_at_a_time(known_pt="utflag{st0p_")...
# ... continues discovery after the _

def ecb_byte_at_a_time(known_pt=""):
    known_pt = ("A" * 16) + known_pt

    # we're not given an alphabet so pick a sensible one...
    alphabet = string.ascii_letters + string.digits + "_!?}{"

    def read_ct():
        ct = int(p.readline().decode(), 16)
        ct = ct.to_bytes(length=(ct.bit_length()+7)//8, byteorder="big")
        return ct

    for i in range(MAX_FLAG_LEN):
        padding = 15 - (i % 16)
        pt = make_plaintext("A" * padding)
        p.sendlineafter(b"to be encrypted: ", pt.encode())
        ct = read_ct()

        dict_cts = {}
        for c in alphabet:
            dict_known_pt = known_pt[len(known_pt)-16+1:len(known_pt)]
            dict_pt = make_plaintext(dict_known_pt + c)
            p.sendlineafter(b"to be encrypted: ", dict_pt.encode())
            dict_cts[c] = read_ct()

        block_to_attack = (padding + i) // 16
        ct_block_to_attack = ct[block_to_attack * 16: (block_to_attack + 1) * 16]

        for c in alphabet:
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

flag = ecb_byte_at_a_time(known_pt="utflag{")
print(flag) # utflag{st0p_r0ll1ng_y0ur_0wn_crypt0!!}

```

## Flag
`utflag{st0p_r0ll1ng_y0ur_0wn_crypt0!!}`

smiley 2025/03/15
