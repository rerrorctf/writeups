#!/usr/bin/env python3

from pwn import *
from os import system

# https://github.com/brimstone/fastcoll

system("./fastcoll -o msg1.bin msg2.bin")

m1 = open("msg1.bin", "rb").read().hex()
m2 = open("msg2.bin", "rb").read().hex()

p = remote("md5-01.chal.perfect.blue", 1337)

p.sendlineafter(b"m1 > ", m1.encode())
p.sendlineafter(b"m2 > ", m2.encode())

p.interactive()
