#!/usr/bin/env python3

from pwn import *

#context.log_level = "debug"
p = remote("chals.bitskrieg.in", 7000)

p.readuntil(b"n = ")
n = int(p.readline().decode())

p.readuntil(b"e = ")
e = int(p.readline().decode())

p.readuntil(b"ct = ")
c = int(p.readline().decode())

c2 = (pow(2, e, n) * c) % n
p.sendlineafter(b"Ciphertext (int):", str(c2).encode())

p.readuntil(b"seek : ")
m = int(p.readline().decode()) // 2
flag = m.to_bytes(length=(m.bit_length() + 7) // 8).decode()

# BITSCTF{r54_0r4acl3_h4s_g0t_t0_b3_0n3_0f_7h3_3as13st_crypt0_1n_my_0p1n10n_74b15203}
print(flag) 
