#!/usr/bin/env python3

from pwn import *

enc_flag = bytes.fromhex("a850d725cb56b0de4fcb40de72a4df56a72ec06cafa75ecb41f51c95")

key = xor(b"FMCTF{", enc_flag[:6]) + xor(b"}", enc_flag[-1:])

flag = xor(enc_flag, key)

print(flag.decode()) # FMCTF{X0R_1S_L1K3_MAGIC_0x1}
