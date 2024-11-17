#!/usr/bin/env python3

from pwn import *

#context.log_level = "debug"
p = remote("pad.ctf.intigriti.io", 1348)

p.readuntil(b": ")

flag = bytes.fromhex(p.readline().decode())

known_plaintext = b"A" * 160
p.sendlineafter(b"yourself?\n", known_plaintext)

p.readuntil(b"state=")
state = p.readuntil(b"): ")[:-3]

ciphertext = bytearray(bytes.fromhex(p.readline().decode()))

if state == b"alive":
    for i in range(len(ciphertext)):
        ciphertext[i] ^= 0xAC
        ciphertext[i] = ciphertext[i] >> 1

if state == b"dead":
    for i in range(len(ciphertext)):
        ciphertext[i] ^= 0xCA
        ciphertext[i] = ((ciphertext[i] << 1) | (ciphertext[i] >> 7)) & 0xFF

keystream = xor(known_plaintext, ciphertext)
flag = xor(keystream, flag).decode()[37:61]
print(flag) # INTIGRITI{d34d_0r_4l1v3}
