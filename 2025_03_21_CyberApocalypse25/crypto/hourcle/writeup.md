https://ctftime.org/event/2674

# Hourcle (crypto)

A powerful enchantment meant to obscure has been carelessly repurposed, revealing more than it conceals. A fool sought security, yet created an opening for those who dare to peer beyond the illusion. Can you exploit the very spell meant to guard its secrets and twist it to your will?

## Analysis

We are given the following oracle:

```python
def encrypt_creds(user):
    padded = pad((user + password).encode(), 16)
    IV = os.urandom(16)
    cipher = AES.new(KEY, AES.MODE_CBC, iv=IV)
    ciphertext = cipher.decrypt(padded)
    return ciphertext
```

Note how we are decrypting here in CBC mode despite the function name `encrypt_creds`.

Because we partially control the "ciphertext" (that is the padded `user + password` input to AES) in this context we can recover the "plaintext" (that is the garbled output of decrypting the padded `user + password` input under a random key) by xoring it with the known "ciphertext" of the previous block.

If this is complex to visualise in your head try to image the process when looking at an image like this one https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#/media/File:CBC_decryption.svg.

Here the "Ciphertext" in the image is the padded `user + password` and you can clearly see that if you know the value of "Ciphertext" from the previous block that you can xor it with the "Plaintext" to recover the actual bytes output by AES.

This won't work on the first block due to the random and unknown initialization vector. But it will work on all later blocks.

With the AES raw output recovered this then becomes an ECB encryption oracle with a twist and is subject to the well known ECB byte-at-a-time attack.

For more information on the ECB byte-at-a-time attack see https://cryptopals.com/sets/2/challenges/12.

In this case our goal is not to directly recover the flag but to recover the password which we can then use to ask for the flag to be printed.

### On Brutish Behaviour

Note that the password is 20 characters. This means that we can recover 16 characters of the password without crossing an AES block.

I found that for some reason I couldn't reliably extend by attack across the block boundary.

If someone reading this knows how to do that _please do let me know_.

So instead what I found was that sometimes (I suppose around 1 in 256 times) I would be able to correctly recover 17 characters of the password which meant *only* a ~18 bit bruteforce for the rest of the password.

Note that its less than 3 bytes due to the constrained alphabet.

```python
>>> import string; import math;
>>> math.log2(len(string.ascii_letters+string.digits)**3)
17.862588931160627
```

I can't decide if this is intended or not after all its possible to solve the task this way.

For example why is the password 20 characters and so close to being trivially bruteforceable if you are supposed to make a robust attack capable of multi-block recovery and not say 64 or 128? If you are supposed to recover 2 or more blocks making 64 or more characters wouldn't make the attack much slower.

In the end I opted to first search for the case where I recoverd a 17 character password and then bruteforce the last 3 characters.

## Solution

```python
#!/usr/bin/env python3

import string
from pwn import *

#context.log_level = "debug"

ALPHABET = string.ascii_letters + string.digits

def ecb_byte_at_a_time(known_pt=""):
    known_pt = ("A" * 16) + known_pt

    def enc(username):
        p.sendlineafter(b"traveler :: ", b"1")
        p.sendlineafter(b"archives :: ", (b"A" * 16) + username.encode())
        p.readuntil(b"encrypted scrolls: ")
        creds = bytes.fromhex(p.readline().decode())
        return xor((b"A" * 16) + username.encode(), creds[16:])

    for i in range(17):
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

    return known_pt[16:]

while True:
    #with remote("94.237.54.190", 30607) as p:
    with process(["venv/bin/python3", "./server.py"]) as p:
        password = ecb_byte_at_a_time()
        print(f"{password = }")
        print(f"{len(password) = }")

        if len(password) < 17:
            continue

        while True:
            for i in ALPHABET:
                for j in ALPHABET:
                    for k in ALPHABET:
                        proposed_password = password + i + j + k
                        p.sendlineafter(b"traveler :: ", b"2")
                        p.sendlineafter(b"Sanctum :: ", proposed_password.encode())
                        line = p.readline()
                        if b"[-] You salt not pass!" not in line:
                            print(line)
                            p.interactive()

# HTB{encrypting_with_CBC_decryption_is_as_insecure_as_ECB___they_also_both_fail_the_penguin_test_a4fb14b547cd88d205bda23590ca29f9}
```

## Flag
`HTB{encrypting_with_CBC_decryption_is_as_insecure_as_ECB___they_also_both_fail_the_penguin_test_a4fb14b547cd88d205bda23590ca29f9}`

smiley 2025/03/22
