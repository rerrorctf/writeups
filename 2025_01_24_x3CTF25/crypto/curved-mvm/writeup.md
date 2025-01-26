https://ctftime.org/event/2467

# curved-mvm (crypto)

mvm cwypto chall for funny users.

## Analysis

We can see from `fast.py` that we can do up to two operations. Each time choosing one of the following:

1) Request an ECDSA-P256 signature be performed over the sha1 hash of "hardcoded cuz reasons"
2) Verify that an ECDSA-PS256 signature over the sha1 hash of "mvm mvm mvm" is valid

There is a bug in the signature code, i.e. `sign_msg`, that allows us to recover the private number `d`.

The bug is caused by selecting a `k`, or nonce, that is not uniformly random throughout the entire space represented by the order of the group also known as `n` or sometimes `q`.

```python
def sign_msg(msg: str):
    z = int.from_bytes(sha1(msg.encode()).digest()) % n
    k = (randbits(K_SIZE) + 2) % n
    R = k * P256.G
    r = R.x % n
    s = (pow(k, -1, n) * (z + r * SECRET_KEY)) % n
    return {"r": hex(r), "s": hex(s)}
```

Because we can recover `d` given such a signature; our solution will first request such a signature with the `sign` option and then use it recover `d` before providing a forged signature to the `mvm` option in order to get the flag.

### How Does The Attack Work?

_feel free to skip this section if you already know how it works_

Because the number of total possible values for `k` is small, specifically there are 2^18 possible values for `k`, we can easily iterate through all of them. This particular attack would not be possible if `k` was chosen uniformly at random from the range `[1, n)` or if the total number of possible values was much larger.

Note: while some attacks on ECDSA exploit a bias in `k`, or nonce, selection of as little as 1 bit, and there is very much a strong 238 bit bias here, this particular attack is simpler and does not directly exploit this bias e.g. it would also be applicable on a curve with a small enough order where no bias is present in the selection of `k`.

To start we simply try all possible values of k, hoping to discover the value that was selected randomly by the remote, looking for a value that produces the same `r` as is a part of the signature:

```python
k = 0
for i in range(1, 2**18):
    maybe_r = point_multiplication(G, i, a, p)[0]
    if maybe_r == r:
        k = i
        break
```

Note: because we're using ECDSA here we use elliptic curve point multiplication to have `k` applications of the group operator but this also works for DSA but instead you would use modular exponentiation to produce candidate `r` values.

Once you have a likely `k` you can use it to recover `d` as follows:

First observe how `d`, here given as `SECRET_KEY`, is used during signature generation:

```python
s = (pow(k, -1, n) * (z + r * SECRET_KEY)) % n
```

Using algebra we can rearrange this expression to solve for `d`, or `SECRET_KEY`, as follows:

```python
maybe_d = (((s * k) - z) * inverse(r, n)) % n
```

This works even if `d` is selected uniformly at random from the range `[1, n)` as long as `k` has a small enough set of possible values for us to test them all in a reasonable amount of time.

Once we have a likely value for `d` we can test it out by recomputing `r` and `s` and comparing the values we get to the original values for `r` and `s`:

```python
assert(r == point_multiplication(G, k, a, p)[0])
assert(s == ((pow(k, -1, n) * (z + r * maybe_d)) % n))
```

If these asserts pass it is very likely that we have recorved the exact value for `d` that the remote has. This means that we can now sign whatever we like:

```python
z = int.from_bytes(sha1("mvm mvm mvm".encode()).digest()) % n
r = point_multiplication(G, k, a, p)[0]
s = (pow(k, -1, n) * (z + r * maybe_d)) % n
```

If you want more details about ECDSA check out the wikipedia article https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm

If you want more details about this attack and another example of the same kind of challenge, albeit with DSA not ECDSA, see https://www.cryptopals.com/sets/6/challenges/43

## Solution

1) Request a weak signature where `k` is drawn from `[2, (2^18)+2)`
2) Test all possible values of `k` to recover `d`
3) Use `d` to forge a signature for the string `mvm mvm mvm`

```python
#!/usr/bin/env python3

from pwn import *
from hashlib import sha1
from json import loads

# https://neuromancer.sk/std/nist/P-256
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

#context.log_level = "debug"
rem = remote("5964a8b3-1650-4a65-aa38-8f6f1563d535.x3c.tf", 31337, ssl=True)

rem.sendlineafter(b"(sign/mvm): ", b"sign")

sig = loads(rem.readline().decode())
r, s = int(sig["r"], 16), int(sig["s"], 16)

k = 0
for i in range(1, 2**18):
    maybe_r = point_multiplication(G, i, a, p)[0]
    if maybe_r == r:
        k = i
        break

z = int.from_bytes(sha1("hardcoded cuz reasons".encode()).digest()) % n
maybe_d = (((s * k) - z) * inverse(r, n)) % n
assert(r == point_multiplication(G, k, a, p)[0])
assert(s == ((pow(k, -1, n) * (z + r * maybe_d)) % n))

z = int.from_bytes(sha1("mvm mvm mvm".encode()).digest()) % n
r = point_multiplication(G, k, a, p)[0]
s = (pow(k, -1, n) * (z + r * maybe_d)) % n

rem.sendlineafter(b"(sign/mvm): ", b"mvm")
rem.sendlineafter(b"r: ", hex(r).encode())
rem.sendlineafter(b"s: ", hex(s).encode())

flag = loads(rem.readline().decode())["flag"]
print(flag) # MVM{why_k_no_v3wwy_much_se3uw3????}
```

## Flag
`MVM{why_k_no_v3wwy_much_se3uw3????}`

smiley 2025/01/25
