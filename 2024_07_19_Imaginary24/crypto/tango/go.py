#!/usr/bin/env python3

import json

from pwn import *
from zlib import crc32

#context.log_level = "debug"
#p = process(["python3", "./server.py"])
p = remote("tango.chal.imaginaryctf.org", 1337)

p.sendlineafter(b"> ", b"E")
p.sendlineafter(b"Your command: ", b"fla")
p.readuntil(b"Your encrypted packet is: ")
encrypted_packet = bytes.fromhex(p.readline().decode()[:-1])

nonce = encrypted_packet[:8]
ciphertext = encrypted_packet[12:]

known_plaintext = json.dumps({'user': 'user', 'command': 'fla', 'nonce': "ffffffffffffffff" }).encode('ascii')

keystream = b""
for i in range(len(known_plaintext)):
    keystream += p8(known_plaintext[i] ^ ciphertext[i])

chosen_plaintext = json.dumps({'user': 'root', 'command': 'flag'}).encode('ascii')
checksum = crc32(chosen_plaintext).to_bytes(length=4, byteorder="big")

crafted_packet = nonce
crafted_packet += checksum
for i in range(len(chosen_plaintext)):
    crafted_packet += p8(chosen_plaintext[i] ^ keystream[i])

p.sendlineafter(b"> ", b"R")
p.sendlineafter(b"Your encrypted packet (hex): ", crafted_packet.hex().encode())

log.success(p.readline().decode()) # ictf{F0xtr0t_L1m4_4lph4_G0lf}
