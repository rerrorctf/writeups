#!/usr/bin/env python3

import hashlib

from Crypto.Util.Padding import unpad
from Crypto.Cipher import AES

enc = b'\x16\x97,\xa7\xfb_\xf3\x15.\x87jKRaF&"\xb6\xc4x\xf4.K\xd77j\xe5MLI_y\xd96\xf1$\xc5\xa3\x03\x990Q^\xc0\x17M2\x18'
flag_hash = "6a96111d69e015a07e96dcd141d31e7fc81c4420dbbef75aef5201809093210e"

def decrypt(key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    flag = unpad(cipher.decrypt(enc), 16)
    if hashlib.sha256(flag).hexdigest() == flag_hash:
        print(flag.decode()) # FLAG{7h3_f1r57_5t3p_t0_Crypt0!!}

for i in range(0x100):
    for j in range(0x100):
        key = b'the_enc_key_is_'
        iv = b'my_great_iv_is_'
        key += i.to_bytes(1, byteorder="big")
        iv += j.to_bytes(1, byteorder="big")
        try:
            decrypt(key, iv)
        except:
            pass
