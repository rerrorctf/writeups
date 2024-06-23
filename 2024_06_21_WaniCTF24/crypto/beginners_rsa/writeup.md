https://ctftime.org/event/2377

# beginners_rsa (crypto)

Do you know RSA?

## Solution

We are giving the following python code:

```python
from Crypto.Util.number import *

p = getPrime(64)
q = getPrime(64)
r = getPrime(64)
s = getPrime(64)
a = getPrime(64)
n = p*q*r*s*a
e = 0x10001

FLAG = b'FLAG{This_is_a_fake_flag}'
m = bytes_to_long(FLAG)
enc = pow(m, e, n)
print(f'n = {n}')
print(f'e = {e}')
print(f'enc = {enc}')
```

And the following text output:

```
n = 317903423385943473062528814030345176720578295695512495346444822768171649361480819163749494400347
e = 65537
enc = 127075137729897107295787718796341877071536678034322988535029776806418266591167534816788125330265
```

In order to solve this task we must:
1) Factor n into p, q, r, s, a
2) Compute phi(n)
3) Compute d
4) Decrypt the value of enc

```python
#!/usr/bin/env python3

n = 317903423385943473062528814030345176720578295695512495346444822768171649361480819163749494400347
e = 65537
enc = 127075137729897107295787718796341877071536678034322988535029776806418266591167534816788125330265

# n is factored with sage
# sage: n = 317903423385943473062528814030345176720578295695512495346444822768171649361480819163749494400347
# sage: n.factor()
# 9953162929836910171 * 11771834931016130837 * 12109985960354612149 * 13079524394617385153 * 17129880600534041513

p = 9953162929836910171
q = 11771834931016130837
r = 12109985960354612149
s = 13079524394617385153
a = 17129880600534041513

assert((p*q*r*s*a) == n)

phi = (p-1)*(q-1)*(r-1)*(s-1)*(a-1)

d = pow(e, -1, phi)

m = pow(enc, d, n)

print(m.to_bytes(20, byteorder="big").decode())
```

## Flag
`FLAG{S0_3a5y_1254!!}`

smiley 2024/06/21
