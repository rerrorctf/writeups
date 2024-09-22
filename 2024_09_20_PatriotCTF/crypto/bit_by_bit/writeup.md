https://ctftime.org/event/2426/

# Bit by Bit (crypto)

I heard one-time pads are unbreakable.

## Analysis

We can see from `transmit.py` that the plaintext is encrypted with a modified repeating key xor. The modification is to add one to the key each time it is used.

We are supposed to imagine that the person encrypting believes this is equivalent to a one time pad. The key difference here being that parts of the key stream are reused.

We can recover the key using frequency analysis because the plaintext happens to be English prose with a flag embedded.

You can get a hint that this is English simply by unhexing the ciphertext and noting that the key used to encrypt each 16 byte chunk was itself only 96 bits long meaning that the first 4 bytes of each block of the ciphertext are visible in the clear. From this we can clearly make out english language words in part or in whole.

## Solution

1) Score each byte of the key based on an English frequency scoring metric
2) Adjust the final byte based on some known plaintext to account for the addition of the iv

```python
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
```

## Flag
`pctf{4_th3_tw0_t1m3_4a324510356}`

smiley 2024/09/22
