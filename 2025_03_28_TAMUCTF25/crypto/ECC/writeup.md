https://ctftime.org/event/2681

# ECC (crypto)

Can you get the secret key from the following two signed messages?

1st Message: The secp256r1 curve was used.
2nd Message: k value may have been re-used.

1st Signature r value: 91684750294663587590699225454580710947373104789074350179443937301009206290695

1st Signature s value: 8734396013686485452502025686012376394264288962663555711176194873788392352477

2nd Signature r value: 91684750294663587590699225454580710947373104789074350179443937301009206290695

2nd Signature s value: 96254287552668750588265978919231985627964457792323178870952715849103024292631

The flag is the secret key used to sign the messages. It will be in the flag format.

## Analysis

### Both r Values are the Same

Note that the two signatures share the same `r` values. This is an additional clue that the two signatures were performed with the same value of `k`. To understand why let's review the way we calculate `r`:

```python
r = point_multiplication(G, k, a, p)[0]
```

We can make two related observations here:

1) The only secret value used to compute `r` is `k`
2) When `k` is reused, for a given curve, we'll always get the same values for `r` regardless of the message being signed

### Recovering the Value of k

When `k` is reused between two messages `h1` and `h2` you can recover `k` as follows:

```python
k = (h1 - h2) * pow((s1 - s2), -1, n) % n
```

### Recovering the Value of d

When we know the value of `k` used to perform a signature we can potentially recover `d` as follows:

```python
maybe_d = (((s1 * k) - h1) * pow(r1, -1, n)) % n
```

Just check that you can recompute the same signature with the candidate `d`:

```python
assert(r1 == point_multiplication(G, k, a, p)[0])
assert(s1 == ((pow(k, -1, n) * (h1 + r1 * int(maybe_d))) % n))
```

## Solution

1) Recover the value of `k`
2) Recover the value of `d`

```python
#!/usr/bin/env python3

from hashlib import sha256

# https://neuromancer.sk/std/secg/secp256r1
p = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
a = 0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc
G = (0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296, 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5)
n = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551

def inverse(x, n):
    return pow(x, -1, n)

def point_addition_slope(P, Q, p):
    y = Q[1] - P[1]
    x = Q[0] - P[0]
    x_inverse = inverse(x, p)
    return (y * x_inverse) % p

def point_doubling_slope(P, a, p):
    y = (3 * P[0] * P[0]) + a % p
    x = 2 * P[1] % p
    x_inverse = inverse(x, p)
    return (y * x_inverse) % p

def point_addition(P, Q, a, p):
    if P != Q:
        s = point_addition_slope(P, Q, p)
    else:
        s = point_doubling_slope(P, a, p)
    x = ((s * s) - P[0] - Q[0]) % p
    y = ((s * (P[0] - x)) - P[1]) % p
    return (x, y)

def point_multiplication(P, d, a, p):
    T = P
    for i in range(d.bit_length() - 2, -1, -1):
        T = point_addition(T, T, a, p)
        if (d >> i) & 1:
            T = point_addition(T, P, a, p)
    return T

h1 = int.from_bytes(sha256(b"The secp256r1 curve was used.").digest())
h2 = int.from_bytes(sha256(b"k value may have been re-used.").digest())

r1 = 91684750294663587590699225454580710947373104789074350179443937301009206290695
s1 = 8734396013686485452502025686012376394264288962663555711176194873788392352477

r2 = 91684750294663587590699225454580710947373104789074350179443937301009206290695
s2 = 96254287552668750588265978919231985627964457792323178870952715849103024292631

k = (h1 - h2) * pow((s1 - s2), -1, n) % n
maybe_d = (((s1 * k) - h1) * pow(r1, -1, n)) % n
assert(r1 == point_multiplication(G, k, a, p)[0])
assert(s1 == ((pow(k, -1, n) * (h1 + r1 * int(maybe_d))) % n))

flag = maybe_d.to_bytes(length=(maybe_d.bit_length() + 7) // 8, byteorder="big")
print(flag.decode()) # gigem{r3u51n6_k_0n_516n47ur35}
```

## Flag
`gigem{r3u51n6_k_0n_516n47ur35}`

smiley 2025/03/29
