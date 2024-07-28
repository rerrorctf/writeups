#!/usr/bin/env python3

from pwn import *

from binascii import unhexlify

with open("./enc.txt", "r") as f:
    enc = f.read()

letters = []
for i in range(0, len(enc), 5):
    letters.append(enc[i:i+5])

def FLAG_KILLER(value):
    index = 0
    temp = []
    output = 0
    while value > 0:
        temp.append(2 - (value % 4) if value % 2 != 0 else 0)
        value = (value - temp[index])/2
        index += 1
    temp = temp[::-1]
    for index in range(len(temp)):
        output += temp[index] * 3 ** (len(temp) - index - 1)
    return output

flag = 0

for i in range(len(letters)):
    for j in range(0x1000):
        if (FLAG_KILLER(j) == int(letters[i], 16)):
            flag = (flag << 12) + j

flag = unhexlify(hex(flag)[2:] + "0")[:-2] + b"}"

print(flag.decode()) # DEAD{263f871e880e9dc7d2401000304fc60e98c7c588}