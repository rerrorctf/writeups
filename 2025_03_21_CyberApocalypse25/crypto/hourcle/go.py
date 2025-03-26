#!/usr/bin/env python3

import string
from pwn import *

#context.log_level = "debug"

ALPHABET = string.ascii_letters + string.digits

def ecb_byte_at_a_time(known_pt=""):
    known_pt = ("A" * 16) + known_pt

    def enc(username):
        p.sendlineafter(b"traveler :: ", b"1")
        p.sendlineafter(b"archives :: ", (b"A" * 16) + username.encode())
        p.readuntil(b"encrypted scrolls: ")
        creds = bytes.fromhex(p.readline().decode())
        return xor((b"A" * 16) + username.encode(), creds[16:])

    for i in range(17):
        padding = 15 - (i % 16)
        pt = "A" * padding
        ct = enc(pt)

        dict_cts = {}
        for c in ALPHABET:
            dict_known_pt = known_pt[len(known_pt)-16+1:len(known_pt)]
            dict_pt = dict_known_pt + c
            dict_cts[c] = enc(dict_pt)

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
                print(f"{known_pt[16:]}")
                break

    return known_pt[16:]

while True:
    #with remote("94.237.54.190", 30607) as p:
    with process(["venv/bin/python3", "./server.py"]) as p:
        password = ecb_byte_at_a_time()
        print(f"{password = }")
        print(f"{len(password) = }")

        if len(password) < 17:
            continue

        while True:
            for i in ALPHABET:
                for j in ALPHABET:
                    for k in ALPHABET:
                        proposed_password = password + i + j + k
                        p.sendlineafter(b"traveler :: ", b"2")
                        p.sendlineafter(b"Sanctum :: ", proposed_password.encode())
                        line = p.readline()
                        if b"[-] You salt not pass!" not in line:
                            print(line)
                            p.interactive()

# HTB{encrypting_with_CBC_decryption_is_as_insecure_as_ECB___they_also_both_fail_the_penguin_test_a4fb14b547cd88d205bda23590ca29f9}
