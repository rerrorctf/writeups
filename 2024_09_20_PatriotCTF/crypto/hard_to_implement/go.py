#!/usr/bin/env python3

from pwn import *
from string import printable

#context.log_level = "debug"
p = remote("chal.competitivecyber.club", 6001)

def encrypt(plaintext):
    p.sendafter(b"> ", plaintext)
    p.readuntil(b"> ")
    return bytes.fromhex(p.readline().decode())

def get_next_byte(flag):
    prefix_len = (16 - (1 + len(flag))) % 16
    prefix = b'A' * prefix_len
    length = prefix_len + len(flag) + 1
    ciphertext = encrypt(prefix)
    for c in printable:
        fake = encrypt(prefix + flag + bytes([ord(c)]))
        if fake[:length] == ciphertext[:length]:
            return bytes([ord(c)])
    return b''

flag = b""
for i in range(32):
    flag += get_next_byte(flag)
    print(flag.decode()) # pctf{ab8zf58}
