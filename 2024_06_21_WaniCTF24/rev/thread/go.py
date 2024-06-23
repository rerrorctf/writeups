#!/usr/bin/env python3

from pwn import *
from z3 import *

N = 45

output = [
    0xa8, 0x8a, 0xbf, 0xa5, 0x2fd, 0x59, 0xde, 0x24,
    0x65, 0x10f, 0xde, 0x23, 0x15d, 0x42, 0x2c, 0xde,
    0x09, 0x65, 0xde, 0x51, 0xef, 0x13f, 0x24, 0x53,
    0x15d, 0x48, 0x53, 0xde, 0x09, 0x53, 0x14b, 0x24,
    0x65, 0xde, 0x36, 0x53, 0x15d, 0x12, 0x4a, 0x124,
    0x3f, 0x5f, 0x14e, 0xd5, 0x0b
]

input = []
for i in range(N):
    input.append(BitVec(f"{i}", 32))

s = Solver()

for i in range(N):
    x = input[i]
    op = 0
    while op < 3:
        new_op = (op + i) % 3
        if new_op == 0:
            x *= 3
        if new_op == 1:
            x += 5
        if new_op == 2:
            x ^= 0x7f
        op = op + 1
    s.add(x == output[i])

s.check()
model = s.model()

flag = ""
for i in range(len(output)):
    flag += chr(int(str(model[input[i]])))

print(flag)

p = process("./thread")

p.sendline(flag.encode())

print(p.readline().decode())
