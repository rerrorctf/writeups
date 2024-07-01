#!/usr/bin/env python3

from pwn import *

traces = []

for i in range(6):
    with remote("without-a-trace.chal.uiuc.tf", 1337, ssl=True) as p:
        if i == 1:
             p.sendlineafter(b"u1 = ", b"2")
        else:
            p.sendlineafter(b"u1 = ", b"1")

        if i == 2:
             p.sendlineafter(b"u2 = ", b"2")
        else:
            p.sendlineafter(b"u2 = ", b"1")

        if i == 3:
             p.sendlineafter(b"u3 = ", b"2")
        else:
            p.sendlineafter(b"u3 = ", b"1")

        if i == 4:
             p.sendlineafter(b"u4 = ", b"2")
        else:
            p.sendlineafter(b"u4 = ", b"1")

        if i == 5:
             p.sendlineafter(b"u5 = ", b"2")
        else:
            p.sendlineafter(b"u5 = ", b"1")

        p.readuntil(b"Have fun: ")
        trace = int(p.readline().decode())

        traces.append(trace)

flag = b""
for i in range(5):
    flag += (traces[i + 1] - traces[0]).to_bytes(length=5, byteorder="big")

print(flag.decode()) # uiuctf{tr4c1ng_&&_mult5!}
