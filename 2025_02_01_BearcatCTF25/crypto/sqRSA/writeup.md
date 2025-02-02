https://ctftime.org/event/2596

# sqRSA (crypto)

Im having trouble with this RSA stuff. I think I'm doing it right but it keeps giving me an error! Can you get my program to work?

## Analysis

We can see that sqRSA.py implements the https://en.wikipedia.org/wiki/Rabin_cryptosystem:

```python
e = 2
p = getPrime(512)
q = getPrime(512)
n = p*q

print(f'{e = }')
print(f'{p = }')
print(f'{q = }')
print(f'{n = }')

m = bytes_to_long(pad(FLAG,100))
c = pow(m, e, n)
```

In order to decrypt `c` we must implement the Rabin cryptosystem's decryption.

## Solution

```python
#!/usr/bin/env python3

def legendre_symbol(a, p):
    ls = pow(a, (p - 1) // 2, p)
    return -1 if ls == p - 1 else ls

def square_root_modulo_p(a, p):
    if legendre_symbol(a, p) != 1:
        return 0
    elif a == 0:
        return 0
    elif p == 2:
        return p
    elif p % 4 == 3:
        return pow(a, (p + 1) // 4, p)

    s = p - 1
    e = 0
    while s % 2 == 0:
        s //= 2
        e += 1

    n = 2
    while legendre_symbol(n, p) != -1:
        n += 1

    x = pow(a, (s + 1) // 2, p)
    b = pow(a, s, p)
    g = pow(n, s, p)
    r = e

    while True:
        t = b
        m = 0
        for m in range(r):
            if t == 1:
                break
            t = pow(t, 2, p)

        if m == 0:
            return x

        gs = pow(g, 2 ** (r - m - 1), p)
        g = (gs * gs) % p
        x = (x * gs) % p
        b = (b * g) % p
        r = m

def extended_euclidian_algorithm(r0, r1):
    s0 = 1
    s1 = 0
    t0 = 0
    t1 = 1
    i = 1
    while True:
        i = i + 1
        r = r0 % r1
        if r == 0:
            break
        q = (r0 - r) // r1
        s = s0 - (q * s1)
        t = t0 - (q * t1)
        r0 = r1
        r1 = r
        s0 = s1
        s1 = s
        t0 = t1
        t1 = t
    return r1, s1, t1

e = 2
p = 8946541176074654913817717054410771331419218032593785296134838490312525894218240553305396599307555077734655624876704161811830296918000348456470769765921767
q = 8932929811422923151480388874853984777290071075825590049173830382535883452482114410463430296988680318519251836647527145507992221700683938654669731212502879
n = 79918824380879984230214478212107859789970760434299554608805294793725784734356035450441094355662829397276452220713697299759466084320223642049726452788651518853937184518959195516619507938497758925978032369947277889352888108330331269331130005097469138112607532759174992940835608455793923500626923539208576267193
c = 17349894155329354363328734000800652637346887108866919240446747423455120556394923514564284438906649577094462846372316919957176356395706169922421515974398971844608693078173465906525109301576180786133798467234128571459625488335621909834995712400917418963473920470534646258784866422718709370743346105151573384808

# code adapted from https://asecuritysite.com/encryption/rabin2

r = square_root_modulo_p(c, p)
s = square_root_modulo_p(c, q)
gcd, yp, yq = extended_euclidian_algorithm(p, q)
x = (r * yq * q + s * yp * p) % n
y = (r * yq * q - s * yp * p) % n
lst = [x, n - x, y, n - y]

for i in lst:
    binary = bin(i)
    append = binary[-16:]
    binary = binary[:-16]
    if append == binary[-16:]:
        string = bin(i)
        string = string[:-16]
        plaintext = int(string, 2)
        flag = plaintext.to_bytes(length=(plaintext.bit_length() + 7) // 8)
        print(flag) # BCCTF{Don7_b3_4_squArE_ac6c54f792c90a69b8}
```

## Flag
`BCCTF{Don7_b3_4_squArE_ac6c54f792c90a69b8}`

smiley 2025/02/02
