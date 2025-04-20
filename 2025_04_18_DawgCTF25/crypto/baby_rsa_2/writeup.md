https://ctftime.org/event/2651

# Baby RSA 2 (crypto)

## Analysis

We can see from the provided code that `N` is used in the context of two distinct key pairs:

```python
p = getPrime(512)
q = getPrime(512)
N = p * q

e_priv = 0x10001
phi = (p - 1) * (q - 1)

d_priv = inverse(e_priv, phi)

m = bytes_to_long(flag)
c = pow(m, e_priv, N)

e_pub = getPrime(16)
d_pub = inverse(e_pub, phi) 

print(f"e = {e_pub}")
print(f"d = {d_pub}")
print(f"N = {N}")
print(f"c = {c}")
```

1) `e` = `0x10001` and `d` is kept private
    - This key pair is used to encrypt the flag
2) `e` = `getPrime(16)` = `58271` and `d` = `16314065939355844497428646964774413938010062495984944007868244761330321449198604198404787327825341236658059256072790190934480082681534717838850610633320375625893501985237981407305284860652632590435055933317638416556532857376955427517397962124909869006289022084571993305966362498048396739334756594170449299859`

When we given both `e` and `d` for a given `N` we can factor `N` as follows:

```python
# https://www.di-mgt.com.au/rsa_factorize_n.html
def factor_n_given_d_and_e(N, d, e):
    k = (d * e) - 1
    t = 0
    x = 0
    while True:
        g = random.randint(2, N - 1)
        t = k
        while (t % 2) == 0:
            t //= 2
            x = pow(g, t, N)
            y = math.gcd(x - 1, N)
            if (x > 1) and (y > 1):
                p = y
                q = N // y
                return p, q
````

This means that, although we are not given the `d` which can be used to directly decrypt the ciphertext, we can compute `phi` which is common to all key pairs using this modulus `N` and from that compute `d` for any given value of `e`.

## Solution

```python
#!/usr/bin/env python3

import random
import math

e = 58271
d = 16314065939355844497428646964774413938010062495984944007868244761330321449198604198404787327825341236658059256072790190934480082681534717838850610633320375625893501985237981407305284860652632590435055933317638416556532857376955427517397962124909869006289022084571993305966362498048396739334756594170449299859
N = 119082667712915497270407702277886743652985638444637188059938681008077058895935345765407160513555112013190751711213523389194925328565164667817570328474785391992857634832562389502866385475392702847788337877472422435555825872297998602400341624700149407637506713864175123267515579305109471947679940924817268027249
c = 107089582154092285354514758987465112016144455480126366962910414293721965682740674205100222823439150990299989680593179350933020427732386716386685052221680274283469481350106415150660410528574034324184318354089504379956162660478769613136499331243363223860893663583161020156316072996007464894397755058410931262938

# https://www.di-mgt.com.au/rsa_factorize_n.html
def factor_n_given_d_and_e(N, d, e):
    k = (d * e) - 1
    t = 0
    x = 0
    while True:
        g = random.randint(2, N - 1)
        t = k
        while (t % 2) == 0:
            t //= 2
            x = pow(g, t, N)
            y = math.gcd(x - 1, N)
            if (x > 1) and (y > 1):
                p = y
                q = N // y
                return p, q

p, q = factor_n_given_d_and_e(N, d, e)
assert((p * q) == N)

phi = (p - 1) * (q - 1)
d = pow(0x10001, -1, phi)
m = pow(c, d, N)

flag = m.to_bytes(length=(m.bit_length() + 7) // 8, byteorder="big")
print(flag.decode()) # DawgCTF{kn0w1ng_d_1s_kn0w1ng_f4ct0rs}
```

## Flag
`DawgCTF{kn0w1ng_d_1s_kn0w1ng_f4ct0rs}`

smiley 2025/04/19
