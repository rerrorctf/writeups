#!/usr/bin/env python3

from pwn import *

#context.log_level = "debug"
p = remote("crypto.heroctf.fr", 9001)

c1 = p.readline().decode()[39:(77*2)+39]

p1 = b"A" * 77
for i in range(0x100):
    p.sendline(p1.hex().encode())
    c2 = p.readline().decode()

key_stream = xor(bytes.fromhex(c1), bytes.fromhex(c2))
flag = xor(key_stream, p1).decode()
print(flag) # Hero{5p00ky_5c4ry_fl4w3d_cryp70_1mpl3m3n74710ns_53nd_5h1v3r5_d0wn_y0ur_5p1n3}
