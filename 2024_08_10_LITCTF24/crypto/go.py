#!/usr/bin/env python3

from pwn import *
from math import gcd

def modinv(a, m):
    return pow(a, -1, m)

#context.log_level = "debug"

#p = remote("litctf.org", 31783)
p = process(["python3", "./chal.py"])

p.readuntil(b"CT = ")
flag_ciphertext = int(p.readline())

p.sendlineafter(b"Plaintext: ", str(-1).encode())
p.readuntil(b"CT = ")
n = int(p.readline()) + 1

m1 = 21
p.sendlineafter(b"Plaintext: ", str(m1).encode())
p.readuntil(b"CT = ")
c1 = int(p.readline())

m2 = 22
p.sendlineafter(b"Plaintext: ", str(m2).encode())
p.readuntil(b"CT = ")
c2 = int(p.readline())

# sometimes we get e * 2 instead of e
e = gcd(m1 - c1, m2 - c2)
d = modinv(e, (e - 1) * ((n // e) - 1))

# so.. sometimes this doesn't work
flag = pow(flag_ciphertext, d, n)
flag = flag.to_bytes(length=(flag.bit_length() + 7) // 8, byteorder="big")

log.success(flag.decode())

