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

print(re.findall(r'FLAG{.+}', flag)[0]) # FLAG{13epl4cem3nt}
