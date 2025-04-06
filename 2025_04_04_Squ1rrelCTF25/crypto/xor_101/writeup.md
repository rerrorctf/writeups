https://ctftime.org/event/2708

# xor 101 (crypto)

My bike lock has 13 digits, you might have to dig around! 434542034a46505a4c516a6a5e496b5b025b5f6a46760a0c420342506846085b6a035f084b616c5f66685f616b535a035f6641035f6b7b5d765348

The flag format is squ1rrel{inner_flag_contents}. hint: the inner flag contents only include letters, digits, or underscores.

## Analysis

We are told that the key is a string of 13 ascii digits.

We know that the flag format is 9 characters long `squ1rrel{` so we can recover the first 9 characters of the key.

From there we can simply bruteforce the remainder of the key. Note that this is not even a 32-bit bruteforce, which is already very doable, but around a 14-bit due to the constrained alphabet we know that there are 4 more numbers each of which has one of 10 values:

```python
>>> import math
>>> math.log2(10**4)
13.287712379549449
```

Unfortunately there are about 20 valid solutions even the constraints of the task, unless I missed one, so I just picked the most reasonable looking answer printed by the following script.

## Solution

```python
#!/usr/bin/env python3

import string
from pwn import *

# My bike lock has 13 digits, you might have to dig around!
c = bytes.fromhex("434542034a46505a4c516a6a5e496b5b025b5f6a46760a0c420342506846085b6a035f084b616c5f66685f616b535a035f6641035f6b7b5d765348")

# The flag format is squ1rrel{inner_flag_contents}.
# hint: the inner flag contents only include letters, digits, or underscores.

ALPHABET = (string.ascii_letters + string.digits + "{}_").encode()

known_plaintext = b"squ1rrel{"
known_keystream = xor(known_plaintext, c[:len(known_plaintext)])

for i in range(10000):
    potential_keystream = known_keystream + f"{i:04}".encode()
    potential_plaintext = xor(potential_keystream, c)
    valid = True
    for j in range(len(potential_plaintext)):
        if potential_plaintext[j] not in ALPHABET:
            valid = False
            break
    if valid:
        print(potential_plaintext) # squ1rrel{iS_my_l0ck_pA25w0rd_t0o_5h0rT_oR_mY_fl4g_t0o_LoNg}
```

## Flag
`squ1rrel{iS_my_l0ck_pA25w0rd_t0o_5h0rT_oR_mY_fl4g_t0o_LoNg}`

smiley 2025/04/05
