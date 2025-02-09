https://ctftime.org/event/2607

# Baby Crypto (crypto)

I do not think it gets easier than this...

nc chals.bitskrieg.in 7000

## Analysis

Note: there is no source code provided for this task...

Upon connecting to the remote we are given three values `n`, `e` and `ct`.

It is a reasonable guess that `ct` is ciphertext representing the flag produced using the RSA cryptosystem.

Example pseudocode:

```python
ct = pow(int.from_bytes(b"flag{example}", byteorder="big"), e, n)
```

Then we are given the prompt `Ciphertext (int):`.

It is a reasonable guess if we provide an ascii string representation of a base 10 integer that the remote will attempt to decrypt it using the factors of `n`.

Example pseudocode:

```python
m = pow(ct, d, n)
```

We can attempt to confirm this by passing back `ct` and seeing what happens:

```bash
$ nc chals.bitskrieg.in 7000
n = 169274229517675614337157564805648293002951113909832970215498133664065313932065372954187785050646167032778253726263004932574588765992236845202718837229671603176674615643249208987776456248248171397140773566964414202853296955826987797739121532175135538870432653514985037104309262177353490186456071322829970253333
e = 65537
ct = 76195713621264293453133312523016291719188264509499278697451736104581734533008715911398859363782541388201784085725943727138434532368425922946357077630683729238220101990054670852921370822841236634664941428206570107670266044837640475653564798143906353625109954062037483267805620901019069452883557516088571624481

Ciphertext (int): 76195713621264293453133312523016291719188264509499278697451736104581734533008715911398859363782541388201784085725943727138434532368425922946357077630683729238220101990054670852921370822841236634664941428206570107670266044837640475653564798143906353625109954062037483267805620901019069452883557516088571624481
Oracle Response: NO, it is not THAT simple!!
```

So we cannot directly decrypt the flag ciphertext.

Also it is worth nothing that the remote uses the term "Oracle" to describe its response. In cryptology an Oracle typically refers to something that we can provide input to and get a response from and it is strongly implied that we can learn something in the process.

So what kind of oracle is this? It appears to be a decryption oracle - that is it just decrypts the ciphertext you give it - that won't allow you to decrypt the ciphertext of the flag itself.

What happens if we provide another number?

```bash
$ nc chals.bitskrieg.in 7000
n = 164179407168765594818378256268127857495257881210918746024483206933055053832449852056746801299056911870956126688273778174632983646819651801686991024932625794779328050932909742945504389741348911482748495909863198042059162612531661822329423644316896313830188203046392023675886784355634689847933696232888095903393
e = 65537
ct = 41061112994932206385742149334755246940517246234194936471197475110009430957764797959206224988002780570739882115815578510011546878948545671305516795660789733255661689542659085351709847922680741927522352596908773675745564088168479804569580210235681131915901192427115405868029912988434447484170148549946632013597

Ciphertext (int): 6969 
Oracle Response: Well, here is the answer that you seek : 96216000488349438629998336810268932405714575548834633748205942660847407502618756523840070661702449716999240833091990489219403169276320742288775838836430470334626893347911985730993558369720608623319927588007711770162608052149778989141120783948594823466481002438031286393137583198696892664134623526852198759187
```

At this point the problem is a little more clear. We a given `n`, `e`, `ct` and then we must supply another chosen ciphertext and then we probably get back the plaintext for this chosen ciphertext and then finally we must use only these values to decrypt the flag itself.

Its worth pointing out that this wouldn't be possible if the remote uses https://en.wikipedia.org/wiki/Optimal_asymmetric_encryption_padding. I'm not sure if there is any way for us to confirm that the ciphertext we are given is unpadded or if we have to just assume so.

In order to recover the flag we will exploit the fact that the RSA cryptosystem is partially homomorphic.

### Homomorphic Encryption Background

_feel free this skip this if you already know the material_

Here is a basic example of the RSA cryptosystem's homomorphic multiplication:

```python
#!/usr/bin/env python3

p = 67
q = 71
n = p*q

e = 65537
d = pow(e, -1, (p-1)*(q-1))

# here we multiply the ciphertext of 2 with itself mod n
print((pow(2, e, n) * pow(2, e, n)) % n) # 888

# when we decrypt the result we also get the product of the plaintext
print(pow(888, d, n)) # => 4
```

Here is another example where we pretend that we only know the ciphertext of the value `secret`:

```python
#!/usr/bin/env python3

p = 67
q = 71
n = p*q

e = 65537
d = pow(e, -1, (p-1)*(q-1))

secret = 3 # we don't know this
secret_c = pow(secret, e, n)

# here we multiply the ciphertext of secret with 2
print((pow(2, e, n) * secret_c) % n) # 1932

# when we divide the result by 2 we get the secret
print(pow(((pow(2, e, n) * secret_c) % n), d, n) // 2) # => 3
```

We can see that by dividing the result of the decryption of the product of ciphertext of `secret` and of `2` by `2` that we get the `secret` value back.

Now of course in this example we could just decrypt `secret` too... But if you recall in this task the remote specifically forbids you from decrypting the flag's ciphertext directly.

For more information on homomorphic encryption: https://en.wikipedia.org/wiki/Homomorphic_encryption#Partially_homomorphic_cryptosystems

For an example of a more advanced attack that exploits RSA being a partially homomorphic cryptosystem: https://github.com/dmur1/writeups/blob/1f55de174d22e786f6dec50cce40651eb4b526ea/2024_11_15_1337UP24/crypto/krsa/writeup.md

## Solution

1) Encrypt the number `2` with the given `e` and `n` values
2) Multiple `2^e % n` by the given ciphertext (`c`) to produce another ciphertext (`c2`)
    - This is an example of homomorphic encryption with the RSA cryptosystem
3) Request that the remote decrypt the result of the homomorphic encryption (`c2`)
    - This will give us the plaintext of the flag, as an integer, multiplied by `2`
4) Divide the value by `2` to recover the flag

```python
#!/usr/bin/env python3

from pwn import *

#context.log_level = "debug"
p = remote("chals.bitskrieg.in", 7000)

p.readuntil(b"n = ")
n = int(p.readline().decode())

p.readuntil(b"e = ")
e = int(p.readline().decode())

p.readuntil(b"ct = ")
c = int(p.readline().decode())

c2 = (pow(2, e, n) * c) % n
p.sendlineafter(b"Ciphertext (int):", str(c2).encode())

p.readuntil(b"seek : ")
m = int(p.readline().decode()) // 2
flag = m.to_bytes(length=(m.bit_length() + 7) // 8).decode()

# BITSCTF{r54_0r4acl3_h4s_g0t_t0_b3_0n3_0f_7h3_3as13st_crypt0_1n_my_0p1n10n_74b15203}
print(flag) 
```

## Flag
`BITSCTF{r54_0r4acl3_h4s_g0t_t0_b3_0n3_0f_7h3_3as13st_crypt0_1n_my_0p1n10n_74b15203}`

smiley 2025/02/08
