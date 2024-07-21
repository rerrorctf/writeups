#!/usr/bin/env python3

q = 64

secret_key = [10, 52, 23, 14, 52, 16, 3, 14, 37, 37, 3, 25,
              50, 32, 19, 14, 48, 32, 35, 13, 54, 12, 35, 12,
              31, 29, 7, 29, 38, 61, 37, 27, 47, 5, 51, 28,
              50, 13, 35, 29, 46, 1, 51, 24, 31, 21, 54, 28,
              52, 8, 54, 30, 38, 17, 55, 24, 41, 1]

flag_int = 0
for i in range(len(secret_key)-1, -1, -1):
    flag_int = flag_int * q + secret_key[i]

flag = flag_int.to_bytes((len(secret_key) * 3) // 4, byteorder="big")

print(flag.decode()) # ictf{b4se_c0nv3rs1on_ftw_236680982d9e8449}
