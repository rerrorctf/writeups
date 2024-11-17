#!/usr/bin/env python3

from pwn import *

#context.log_level = "debug"
p = remote("krsa.ctf.intigriti.io", 1346)
#p = process(["python3", "./kRSA.py"])

p.readuntil(b"n=")
n = int(p.readline().decode())

p.readuntil(b"e=")
e = int(p.readline().decode())

p.readuntil(b"ck=")
ck = int(p.readline().decode())

def recover_k(c, e, n):
    A = {}
    for i in range(1, 0xffff):
        x = (pow(pow(i, -1, n), e, n) * c) % n
        A[x] = i

    for j in range(1, 0xfffff):
        y = pow(j, e, n)
        if y in A:
            i = A[y]
            return i * j

k = recover_k(ck, e, n)

p.sendlineafter(b"Secret key ? ", str(k).encode())

p.interactive() # INTIGRITI{w3_sh0uld_m33t_1n_th3_m1ddl3}
