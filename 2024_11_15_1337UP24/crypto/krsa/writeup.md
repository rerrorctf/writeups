https://ctftime.org/event/2446

# kRSA (crypto)

RSA-2048 is considered secure and SSL/TLS often use it for key exchange. So this custom protocol between Alice and Bob should be pretty secure right?

nc krsa.ctf.intigriti.io 1346

## Analysis

Unpadded/Unarmored RSA is subject to the meet in the middle attack.

The weakness here is related to the limited input space, i.e. the possible values for `k`, as a opposed to size of the modulus.

In this case our maximum value of `k` is 32 bits all set. We can recover `k` in about `2 * 2^(32/2)` steps.

Note: this attack does not scale easily to 64 bits ( but it is possible ) much less so to 128 bits.

### How does it work?

The basis of this attack is the realisation that for any `k`, where `k ∈ [0, 2^32)`, `k` can _probably_ be expressed as the product of two numbers `i` and `j` where `i, j ∈ [0, 2^(32/2))`.

This means that if we can divide `k` by all possible values of `i` we have all possible values of `j`.

There is one small problem though. We don't know `k` only `c`.

We overcome this by exploiting the fact that ciphertext multiplication in the RSA cryptosystem is homomorphic.

This means that if `k = i * j` then `pow(k, e, n) == c == pow(i, e, n) * pow(j, e, n)` and that `pow(k, e, n) * pow(pow(i, -1, n), e, n) == pow(j, e, n)`.

So we start by storing for each `i ∈ [0, 2^(32/2))` the result of `c * pow(pow(i, -1, n), e, n) % n`. This is our list of candidate encryptions of `j`. We do this in a hashtable for quick lookup.

```python
A = {}
for i in range(1, 0xffff):
    x = (pow(pow(i, -1, n), e, n) * c) % n
    A[x] = i
```

Next for each `j ∈ [0, 2^(32/2))` we compute `y = pow(j, e, n)` and we check if `y` is in our hashtable. If it is we have an `i` and a `j` that we can multiply to produce the original value of `k` and we can check this as follows:

`pow(i * j, e, n) == pow(i, e, n) * pow(j, e, n) == c`

This allows us to check for a given value if the product of `i` and that value could produce `c` as follows:

```python
for j in range(1, 0xffff):
    y = pow(j, e, n)
    if y in A:
        i = A[y]
        return i * j
```

See these answers for more information:

https://crypto.stackexchange.com/questions/2195/is-rsa-padding-needed-for-single-recipient-one-time-unique-random-message/2196#2196

https://crypto.stackexchange.com/questions/109034/time-memory-tradeoffs-in-rsa-meet-in-the-middle-attack

#### Note

In practice I found increasing the scope of `j` by 4 bits such that `j ∈ [0, 2^20)` almost always catches the case where the factorization of `k` cannot be expressed by two 16-bit numbers. This is ok as it doesn't increase the amount of work to be done. If anyone can explain to me why this is the case I would be curious to know why as most things seem to assume you can split the key space into two equal chunks.

## Solution

```python
#!/usr/bin/env python3

from pwn import *

#context.log_level = "debug"
p = remote("krsa.ctf.intigriti.io", 1346)
#p = process(["python3", "./kRSA.py"])

p.readuntil(b"n=")
n = int(p.readline().decode())

p.readuntil(b"e=")
e = int(p.readline().decode())

p.readuntil(b"ck=")
ck = int(p.readline().decode())

def recover_k(c, e, n):
    A = {}
    for i in range(1, 0xffff):
        x = (pow(pow(i, -1, n), e, n) * c) % n
        A[x] = i

    for j in range(1, 0xfffff):
        y = pow(j, e, n)
        if y in A:
            i = A[y]
            return i * j

k = recover_k(ck, e, n)

p.sendlineafter(b"Secret key ? ", str(k).encode())

p.interactive() # INTIGRITI{w3_sh0uld_m33t_1n_th3_m1ddl3}
 ```

## Flag
`INTIGRITI{w3_sh0uld_m33t_1n_th3_m1ddl3}`

smiley 2024/11/16
