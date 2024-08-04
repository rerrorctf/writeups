#!/usr/bin/env python3

with open("task.txt", "r") as f:
    c = f.read()

c = c.replace(" ", "")
c = c.replace("\n", "")

c = c.replace("A", "0")
c = c.replace("C", "1")
c = c.replace("G", "2")
c = c.replace("T", "3")

flag = ""

for i in range(0, len(c), 4):
    flag += chr(int(c[i:i+4], 4))

print(flag) # TFCCTF{1_w1ll_g3t_th1s_4s_4_t4tt00_V3ry_s00n}