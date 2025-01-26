#!/usr/bin/env python3

from pwn import *
from hashlib import sha1
from json import loads

# https://neuromancer.sk/std/nist/P-256
p = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
a = 0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc
G = (0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296, 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5)
n = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551

def inverse(x, n):
    return pow(x, -1, n)

def point_addition_slope(P, Q, p):
    y = Q[1] - P[1]
    x = Q[0] - P[0]
    x_inverse = inverse(x, p)
    return (y * x_inverse) % p

def point_doubling_slope(P, a, p):
    y = (3 * P[0] * P[0]) + a % p
    x = 2 * P[1] % p
    x_inverse = inverse(x, p)
    return (y * x_inverse) % p

def point_addition(P, Q, a, p):
    if P != Q:
        s = point_addition_slope(P, Q, p)
    else:
        s = point_doubling_slope(P, a, p)
    x = ((s * s) - P[0] - Q[0]) % p
    y = ((s * (P[0] - x)) - P[1]) % p
    return (x, y)

def point_multiplication(P, d, a, p):
    T = P
    for i in range(d.bit_length() - 2, -1, -1):
        T = point_addition(T, T, a, p)
        if (d >> i) & 1:
            T = point_addition(T, P, a, p)
    return T

#context.log_level = "debug"
rem = remote("5964a8b3-1650-4a65-aa38-8f6f1563d535.x3c.tf", 31337, ssl=True)

rem.sendlineafter(b"(sign/mvm): ", b"sign")

sig = loads(rem.readline().decode())
r, s = int(sig["r"], 16), int(sig["s"], 16)

k = 0
for i in range(1, 2**18):
    maybe_r = point_multiplication(G, i, a, p)[0]
    if maybe_r == r:
        k = i
        break

z = int.from_bytes(sha1("hardcoded cuz reasons".encode()).digest()) % n
maybe_d = (((s * k) - z) * inverse(r, n)) % n
assert(r == point_multiplication(G, k, a, p)[0])
assert(s == ((pow(k, -1, n) * (z + r * maybe_d)) % n))

z = int.from_bytes(sha1("mvm mvm mvm".encode()).digest()) % n
r = point_multiplication(G, k, a, p)[0]
s = (pow(k, -1, n) * (z + r * maybe_d)) % n

rem.sendlineafter(b"(sign/mvm): ", b"mvm")
rem.sendlineafter(b"r: ", hex(r).encode())
rem.sendlineafter(b"s: ", hex(s).encode())

flag = loads(rem.readline().decode())["flag"]
print(flag) # MVM{why_k_no_v3wwy_much_se3uw3????}
