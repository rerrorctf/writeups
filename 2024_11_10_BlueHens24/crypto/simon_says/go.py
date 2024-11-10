#!/usr/bin/env python3

from pwn import *

with open("ciphers.txt", "r") as f:
    ciphers = f.readlines()

flag = bytes.fromhex("9026f1429c2119b8 e4c4b164dbae0938 7860641d0840662a a5e9c3299c4645f7")

keystream = xor(flag[:6], b"udctf{")
print(keystream.hex()) # e5429236fa5a ? 4b ? cd
keystream += b"\x4b\xcd"

for i in range(1, 17):
    for j in range(48):
        try:
            fragment = xor(keystream, bytes.fromhex(ciphers[i][j*16:(j+1)*16])).decode("ascii")
            #print(i, j, fragment.encode())
        except:
            pass

#for x in range(0x10000):
#    for i in range(1, 16):
#        for j in range(32):
#            try:
#                fragment = xor(keystream + p16(x), bytes.fromhex(ciphers[i][j*16:(j+1)*16])).decode("ascii")
#                print(i, j, fragment)
#            except:
#                pass
    #print((keystream + p16(x)).hex())

#i = 10
#j = 7
#for x in range(0x100):
#    try:
#        fragment = xor(keystream + p16(x), bytes.fromhex(ciphers[i][j*16:(j+1)*16]))
        #if b"anythin" in fragment:
        #    print(fragment)
        #    print((keystream + p16(x)).hex())
#    except:
#        pass

# 13 4 arhit ecture??
# 6 11 b're reass'
#i = 13
#j = 5
#keystream2 = xor(b"ecture", bytes.fromhex(ciphers[i][j*16:(j+1)*16])[:6])

i = 16
j = 2
keystream2 = xor(b"d lately", bytes.fromhex(ciphers[i][j*16:(j+1)*16])[:8])

for i in range(1, 17):
    for j in range(48):
        try:
            fragment = xor(keystream2, bytes.fromhex(ciphers[i][j*16:(j+1)*16])[:8]).decode("ascii")
            #print(i, j, fragment.encode())
        except:
            pass

i = 13
j = 6
keystream3 = xor(b"r design", bytes.fromhex(ciphers[i][j*16:(j+1)*16])[:8])

for i in range(1, 17):
    for j in range(48):
        try:
            fragment = xor(keystream3, bytes.fromhex(ciphers[i][j*16:(j+1)*16])[:8]).decode("ascii")
            #print(i, j, fragment.encode())
        except:
            pass

i = 10
j = 10
keystream4 = xor(b"ttractiv", bytes.fromhex(ciphers[i][j*16:(j+1)*16])[:8])

for i in range(1, 17):
    for j in range(48):
        try:
            fragment = xor(keystream4, bytes.fromhex(ciphers[i][j*16:(j+1)*16])[:8]).decode("ascii")
            print(i, j, fragment.encode())
        except:
            pass

known_plaintext = b'e noticed lately that the parano'
keystream = xor(known_plaintext, bytes.fromhex(ciphers[16][16:16*4]))
print(xor(keystream, flag)) # udctf{Rul3sEqualB0r3dom}
