from pwn import *
import os
f=open("poems.txt","r")
lngstr=f.read()
f.close()
lines = lngstr.split("\n")
lines = list(filter(lambda x: len(x) > 30, lines))
import random
winners = [random.choice(lines) for _ in range(10)]
def simple(ltr):
    return ltr.isalpha() or ltr == " "

pts = ["".join(filter(simple, x)).strip().lower() for x in winners] + ["udctf{placeholder_flag_here}"]
key = os.urandom(100)
cts = [xor(x.encode(),key[:len(x)]).hex() for x in pts]
print(cts)