https://ctftime.org/event/2377

# replacement (crypto)

No one can read my diary!

## Analysis

We are given the following python code:

```python
from secret import cal
import hashlib

enc = []
for char in cal:
    x = ord(char)
    x = hashlib.md5(str(x).encode()).hexdigest()
    enc.append(int(x, 16))
        
with open('my_diary_11_8_Wednesday.txt', 'w') as f:
    f.write(str(enc))
```

We can see that each character is stored as the md5 hash of its order.

## Solution

1) Make a lookup table for all possible characters keyed with the md5 hash of their order
2) Lookup the character for each md5 hash in the ciphertext 

```python
#!/usr/bin/env python3

import string
import hashlib
import re

lookup_table = {}

for char in string.printable:
    h = hashlib.md5(str(ord(char)).encode()).hexdigest()
    lookup_table[int(h, 16)] = char

with open("./my_diary_11_8_Wednesday.txt", "r") as f:
    ciphertext = eval(f.read())

flag = ""
for char in ciphertext:
    flag += lookup_table[char]

print(re.findall(r'FLAG{.+}', flag)[0])
```

## Flag
`FLAG{13epl4cem3nt}`

smiley 2024/06/21
