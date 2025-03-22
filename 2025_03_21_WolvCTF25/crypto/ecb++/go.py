#!/usr/bin/env python3

import string
from pwn import *

#context.log_level = "debug"

MAX_FLAG_LEN = 90

# we're not given an alphabet so pick a sensible one...
ALPHABET = string.ascii_letters + string.digits + "-_}{@!?$%^&*()~#/"

#p = process(["venv/bin/python3", "./chal.py"])
p = remote("ecbpp.kctf-453514-codelab.kctf.cloud", 1337)

p.readline()
p.readline()

def ecb_byte_at_a_time(known_pt=""):
    known_pt = known_pt

    def enc(pt):
        p.sendline(b"Y")
        p.sendlineafter(b"message:", pt.encode())
        p.readuntil(b"Your message is:  ")
        ct = bytes.fromhex(p.readline().decode())
        return ct

    for i in range(MAX_FLAG_LEN):
        padding = 15 - (i % 16)

        pt = ""
        for c in ALPHABET:
            pt += ("A" * padding) + known_pt + c

        dict_block_sizes = len(("A" * padding) + known_pt + "A")
        prefix_len = len(pt)

        pt += "A" * padding
        ct = enc(pt)

        dict_cts = {}
        for j in range(len(ALPHABET)):
            c = ALPHABET[j]
            dict_cts[c] = ct[j*dict_block_sizes:(j+1)*dict_block_sizes][-16:]

        ct = ct[len(ALPHABET)*dict_block_sizes:]

        block_to_attack = (padding + i) // 16
        ct_block_to_attack = ct[block_to_attack * 16: (block_to_attack + 1) * 16]

        for c in ALPHABET:
            match = True
            for j in range(16):
                if ct_block_to_attack[j] != dict_cts[c][j]:
                    match = False
                    break

            if match:
                known_pt += c
                #print(f"{known_pt}")
                break

    return known_pt

flag = ecb_byte_at_a_time(known_pt="wctf{")
print(flag) # wctf{1_m4d3_th15_fl4G_r34lly_l0ng_s0_th4t_y0u_w0ulD_h4v3_t0_d34L_w1th_muL7iPl3_bl0cKs_L0L}
