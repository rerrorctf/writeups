#!/usr/bin/env python3

from pwn import *
import time

context.log_level = "WARNING"

known_bytes = bytes.fromhex("f21928fd469f")

for x in range(20-len(known_bytes)):
    times = []

    for i in range(0x100):
        s = known_bytes + p8(i)
        s += (20 - len(s)) * b"\x00"
        s = s.hex().encode()

        t_avg = 0
        for j in range(4):
            with remote("0.cloud.chals.io", 11320) as p:
            #with process(["python3", "./dist.py"]) as p:
                p.readuntil(b"Enter your McGuess (hex):\n>")
                n = time.perf_counter()
                p.sendline(s)
                p.readline()
                t_avg += time.perf_counter() - n

        t_avg /= 4
        times.append(t_avg)

    best_time = -1.0
    best_index = -1
    for i in range(0x100):
        if times[i] > best_time:
            best_time = times[i]
            best_index = i

    known_bytes += p8(best_index)
    print(best_index, best_time, known_bytes.hex())

p = remote("0.cloud.chals.io", 11320)
p.sendlineafter(b"Enter your McGuess (hex):\n>", known_bytes.hex().encode())
p.interactive() # UDCTF{B4d_T1miN6}
