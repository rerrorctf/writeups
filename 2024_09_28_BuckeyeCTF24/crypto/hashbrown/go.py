#!/usr/bin/env python3

from pwn import *
from Crypto.Cipher import AES

#context.log_level = "debug"
p = remote("challs.pwnoh.io", 13419)

p.readuntil(b"hex:\n")
message = bytes.fromhex(p.readline().decode())
message += b"_" * (16 - len(message) % 16)

p.readuntil(b"Signature:\n")
key = bytes.fromhex(p.readline().decode()[-33:-1])

french_fry = b"french fry"
padded_french_fry = french_fry + (b"_" * (16 - len(french_fry) % 16))

p.sendlineafter(b"> ", (message + french_fry).hex().encode())

forgery = AES.new(key, AES.MODE_ECB).encrypt(padded_french_fry)
p.sendlineafter(b"> ", forgery.hex().encode())

p.readuntil(b"flag:\n")

# bctf{e7ym0l0gy_f4c7_7h3_w0rd_hash_c0m35_fr0m_7h3_fr3nch_hacher_wh1ch_m34n5_t0_h4ck_0r_ch0p}
print(p.readline().decode()[:-1])
