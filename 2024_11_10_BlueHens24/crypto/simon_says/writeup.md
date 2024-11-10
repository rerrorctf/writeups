https://ctftime.org/event/2512

# Simon Says (crypto)

## Analysis

We can see that the cipher in ctr mode, in `simon_ctf.py`, uses the same nonce for every ciphertext.

The way that this implementation of simon deals with nonces and counters is simply to increment them for each block.

This means that each ciphertext shares all but the first block of the previous ciphertext's keystream.

This means that the flag's keystream is the same as blocks 2 through 5 in the last ciphertext's keystream.

Now we know that all ciphertext's effectively share a keystream we can use the known plaintext in the format to recover a 6 byte portion of the keystream for every ciphertext.

From here we can expand the keystream manually, this is what I did, or probably through some kind of statistical model.

## Solution

1) Recover 6 bytes of the keystream with the known plaintext / flag format
2) Gradually expand the keystream by trial and error by observing the english language words revealed by the known keystream

Note: this script is not very clean but I thought it was best to show it as It ended up to help explain the steps of the process I took.

```python
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
```

### Recovered Plaintext

Here is the plaintext I recovered from my notes. I gradually built this up as I tested out different possible keystream expansions.

```
1 16 b'very par'  1 17 b't of you'  1 18 b'r body, '  1 19 b'be full '
2 15 b'vable or'  2 16 b' achieva'  2 17 b'ble. Win'  2 18 b'ners can'
3 14 b'a way to'  3 15 b' succeed'  3 16 b'. Simila'  3 17 b'rly, whe'
4 13 b'brain, m'  4 14 b'uscles, '  4 15 b'nerves, '  4 16 b'every pa'
5 12 b'have to '  5 13 b'trust th'  5 14 b'at the d'  5 15 b'ots will'
6 11 b're reass'  6 12 b'embling '  6 13 b'were dis'  6 14 b'assemble'
7 10 b'ad of im'  7 11 b'agining '  7 12 b'that our'  7 13 b' main ta'
8 9  b'water an'  8 10 b'd see it'  8 11 b' as half'  8 12 b' empty. '
9 8  b'r would '  9 9  b'ever con'  9 10 b'sent to '  9 11 b'write a '
10 7 b' anythin'  10 8 b'g.  One '  10 9 b'of the a' 10 10 b'ttractiv'
11 6 b' are ver'  11 7 b'y wrong.'  11 8 b'  Your k' 11 9  b'nowledge'
13 4 b'l archit'  13 5 b'ecture o'  13 6 b'r design' 13 7  b' in mind'
14 3 b've been '  14 4 b'asked, '   
15 2 b'rk hard '  15 3 b'to make '  15 4 b'Ruby per' 15 5 b'fect for'
16 1 b'e notice'  16 2 b'd lately'  16 3 b' that th' 16 4 b'e parano'
     b'udctf{??'       b'????????'       b'????????'      b'????????'
```

## Flag
`udctf{Rul3sEqualB0r3dom}`

smiley 2024/11/10
