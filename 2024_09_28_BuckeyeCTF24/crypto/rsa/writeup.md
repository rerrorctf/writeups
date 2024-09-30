https://ctftime.org/event/2449

# rsa (crypto)

https://en.wikipedia.org/wiki/RSA_(cryptosystem)

## Analysis

We are given a 256 bit modulus. This can be factored into `p` and `q` quite quickly or looked up online.

## Solution

```python
#!/usr/bin/env python3

e = 65537
n = 66082519841206442253261420880518905643648844231755824847819839195516869801231
c = 19146395818313260878394498164948015155839880044374872805448779372117637653026

# https://factordb.com/index.php?query=66082519841206442253261420880518905643648844231755824847819839195516869801231
#
# can also factor with sage in ~3 minutes on my machine
# sage: n = 66082519841206442253261420880518905643648844231755824847819839195516869801231
# sage: n.factor()
# 213055785127022839309619937270901673863 * 310165339100312907369816767764432814137

p = 213055785127022839309619937270901673863
q = 310165339100312907369816767764432814137
assert((p * q) == n)

phi = (p - 1) * (q - 1)
d = pow(e, -1, phi)

m = pow(c, d, n)
flag = m.to_bytes(length=(m.bit_length() + 7) // 8, byteorder="big").decode()
print(flag) # bctf{f4c70r1z3_b3773r_4d3b35e4}
```

## Flag
`bctf{f4c70r1z3_b3773r_4d3b35e4}`

smiley 2024/09/28
