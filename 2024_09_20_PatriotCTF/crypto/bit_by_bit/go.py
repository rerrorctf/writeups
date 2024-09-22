#!/usr/bin/env python3

from re import findall

freq = {
    ord('a'): 0.08167, ord('A'): 0.08167,
    ord('b'): 0.01492, ord('B'): 0.01492,
    ord('c'): 0.02782, ord('C'): 0.02782,
    ord('d'): 0.04253, ord('D'): 0.04253,
    ord('e'): 0.12702, ord('E'): 0.12702,
    ord('f'): 0.02228, ord('F'): 0.02228,
    ord('g'): 0.02015, ord('G'): 0.02015,
    ord('h'): 0.06094, ord('H'): 0.06094,
    ord('i'): 0.06966, ord('I'): 0.06966,
    ord('j'): 0.00153, ord('J'): 0.00153,
    ord('k'): 0.00772, ord('K'): 0.00772,
    ord('l'): 0.04025, ord('L'): 0.04025,
    ord('m'): 0.02406, ord('M'): 0.02406,
    ord('n'): 0.06749, ord('N'): 0.06749,
    ord('o'): 0.07507, ord('O'): 0.07507,
    ord('p'): 0.01929, ord('P'): 0.01929,
    ord('q'): 0.00095, ord('Q'): 0.00095,
    ord('r'): 0.05987, ord('R'): 0.05987,
    ord('s'): 0.06327, ord('S'): 0.06327,
    ord('t'): 0.09056, ord('T'): 0.09056,
    ord('u'): 0.02758, ord('U'): 0.02758,
    ord('v'): 0.00978, ord('V'): 0.00978,
    ord('w'): 0.02360, ord('W'): 0.02360,
    ord('x'): 0.00150, ord('X'): 0.00150,
    ord('y'): 0.01974, ord('Y'): 0.01974,
    ord('z'): 0.00074, ord('Z'): 0.00074,
    ord(' '): 0.13000
}

with open("out.txt", "r") as f:
    ciphertext = bytes.fromhex(f.read())

chunks = [ciphertext[i:i+16] for i in range(0, len(ciphertext), 16)]

key = bytearray(16)

for i in range(0, 16):
    best_b = 0
    high_score = -1.0
    for j in range(256):
        key[i] = j
        score = 0.0
        for chunk in chunks:
            c = int.from_bytes(chunk)
            k = int.from_bytes(key)
            b = int(c ^ k).to_bytes(length=16, byteorder="big")[i]
            try:
                score += freq[b]
            except:
                pass
        if score > high_score:
            best_b = j
            high_score = score
    key[i] = best_b

# fix the last byte of the key based on known plaintext in this chunk
# this block ends with "pctf" which is part of the known flag format
key[15] = (chunks[28][15] ^ (ord("f"))) - 29

plaintext = b""
for i in range(len(chunks)):
    c = int.from_bytes(chunks[i])
    k = (int.from_bytes(key) + i + 1)
    plaintext += int(c ^ k).to_bytes(length=16, byteorder="big")

plaintext = plaintext.decode("utf-8", "ignore")

flag = findall("pctf{.+}", plaintext)[0]
print(flag) # pctf{4_th3_tw0_t1m3_4a324510356}
