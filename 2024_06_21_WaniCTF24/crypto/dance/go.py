#!/usr/bin/env python3

import hashlib

from mycipher import MyCipher

username = 'gureisya'
known_ciphertext = b"\x06\x1f\xf0\x6d\xa6\xfb\xf8\xef\xcd\x2c\xa0\xc1\xd3\xb2\x36\xae\xde\x3f\x5d\x4b\x6e\x8e\xa2\x41\x79"

def make_token(data1: str, data2: str):
    sha256 = hashlib.sha256()
    sha256.update(data1.encode())
    right = sha256.hexdigest()[:20]
    sha256.update(data2.encode())
    left = sha256.hexdigest()[:12]
    token = left + right
    return token

def try_token(token: str):
    sha256 = hashlib.sha256()
    sha256.update(token.encode())
    key = sha256.hexdigest()[:32]
    nonce = token[:12]
    cipher = MyCipher(key.encode(), nonce.encode())
    plaintext = b"A" * len(known_ciphertext)
    ciphertext = cipher.encrypt(plaintext)
    keystream = b""
    for i in range(len(known_ciphertext)):
        keystream += (ord("A") ^ ciphertext[i]).to_bytes(1, byteorder="big")
    flag = b""
    for i in range(len(known_ciphertext)):
        flag += (keystream[i] ^ known_ciphertext[i]).to_bytes(1, byteorder="big")
    if flag[:4] == b"FLAG":
        print(flag.decode()) # FLAG{d4nc3_l0b0t_d4nc3!!}

for minutes in range(1, 61):
    for sec in range(1, 61):
        for r in range(0, 11):
            data1 = f'user: {username}, {minutes}:{sec}'
            data2 = f'{username}'+str(r)
            try_token(make_token(data1, data2))
