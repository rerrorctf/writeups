https://ctftime.org/event/2423

# Biased Election (crypto)

We heard rumors that someone might rig the upcoming elections. We managed to place a backdoor in one of their messaging systems. See what you can make out of it, the world counts on you.

## Analysis

We are given the file `server.py`.

This code allows us to collect up to 11 signatures. It is perhaps worth nothing that it may have been the author's intention to allow only up to 10 signatures to be collected. This does not make the attack much easier nor much more consistent.

We can see by testing the output of `the_random` that has a bit length of around 160 bits. Viewed another way, this is 96 bit bias towards 0 in a bit string of 256 bits. 

``` python
>>> import server
>>> print(server.the_random().bit_length())
160
>>> print(server.the_random().bit_length())
159
>>> print(server.the_random().bit_length())
158
>>> print(server.the_random().bit_length())
160
>>> print(server.the_random().bit_length())
159
```

We are required to provide the ECDSA private key, typically referred to as `d`, in order to get the flag.

## Attack

It is possible to recover the ECDSA private key d when an rng is used with even a slight bias. The larger the bias, in this case the bias is very large, the less signatures you need but even small biases make it plausible to perform private key recovery from signatures.

This attack is explained well and in great depth in the following resources:
- [Key-Recovery Attacks on ECDSA with Biased Nonces](https://www.cryptopals.com/sets/8/challenges/62.txt)
- [ECDSA Handle With Care - Trail of Bits](https://blog.trailofbits.com/2020/06/11/ecdsa-handle-with-care/)
- [Biased Nonce Sense Lattice attacks against weak ECDSA signatures in the wild (YouTube)](https://www.youtube.com/watch?v=6ssTlSSIJQE)
- [Biased Nonce Sense: Lattice Attacks against Weak ECDSA Signatures in Cryptocurrencies (paper)](https://eprint.iacr.org/2019/023.pdf)

### PuTTY CVE

As a side note it was recently disclosed that PuTTY before 0.81 was potentially vulnerable to this attack albeit with NIST's P-521 curve and a `521 - 512 => 9` bit bias.

https://nvd.nist.gov/vuln/detail/CVE-2024-31497

You can find a nice writeup of this particular issue [here](https://ericrafaloff.com/biased-nonce-generation-in-putty-for-nist-p-521-keys/).

## Solution

I had a lot of issues getting sage and pwntools in the same python script. This used to work but it seems it doesn't anymore.

The easiest way for me to access a working sage session is to use the `sage` command in `ret` https://github.com/rerrorctf/ret?tab=readme-ov-file#-sage.

Due to the aforementioned issues using sage nicely with python the following is the best workflow I could come up with:

1) Run `go.py` to collect as many signatures as we can, this happens to be 11, then parse and then print them as 3 python arrays `hs`, `rs` and `ss`
2) Copy paste those 3 python arrays into another file called `go-sage.py`, shown below, which actually performs the lattice basis reduction
3) Copy the recovered key from sage into the waiting shell to get the flag

```python
from pwn import *

order = 115792089210356248762697446949407573529996955224135760342422259061068512044369 #G.order()

#context.log_level = "debug"
#p = process(["python3", "server.py"])
p = remote("challs.tfcctf.com", 30646)

p.readline() # What do you want to do?
p.readline() # 1. Listen in on conversation
p.readline() # 2. Submit the info you found
p.readline() # 3. Get pubkey

def collect_signatures():
    hs = []
    rs = []
    ss = []
    for i in range(11):
        p.sendline(b"1")
        line = p.readline().decode()
        line = line.replace(",", "")
        line = line.replace("'", "")
        line = line.replace("}", "")
        line = line.split(" ")
        hsh = int(line[1], 10)
        r = int(line[3], 16)
        s = int(line[5], 16)
        hs.append(hsh)
        rs.append(r)
        ss.append(s)
    return hs, rs, ss

hs, rs, ss = collect_signatures()

print(f"{hs = }")
print(f"{rs = }")
print(f"{ss = }")

# use sage to recover private key d

p.sendline(b"2")

p.readuntil(b"Key? ")

# paste the 2nd value
# e.g. 30074281352231076024531614267798461182783011404334876390885601752600165860912

p.interactive() # TFCCTF{c0Ngr47s_y0u_s4v3d_th3_3lect1Ons}
```

Note that the remote returns the hashes in base 10 and the r and s values in base 16.

```python
order = 115792089210356248762697446949407573529996955224135760342422259061068512044369

# replace hs, rs and ss with the output of go.py

hs = []
rs = []
ss = []

def modinv(a, m):
    return a.inverse_mod(m)

def recover_private_key(hs, rs, ss):
    num_messages = len(hs)

    last_h = hs[-1]
    last_r = rs[-1]
    last_s = ss[-1]

    last_r_last_s_inv = last_r * modinv(last_s, order)
    last_h_last_s_inv = last_h * modinv(last_s, order)

    matrix = Matrix(QQ, num_messages + 2, num_messages + 2)

    for i in range(num_messages):
        matrix[i, i] = order

    for i in range(num_messages):
        x0 = (rs[i] * modinv(ss[i], order)) - last_r_last_s_inv
        x1 = (hs[i] * modinv(ss[i], order)) - last_h_last_s_inv
        matrix[num_messages + 0, i] = x0
        matrix[num_messages + 1, i] = x1

    matrix[num_messages + 0, i + 1] = 2**(256 - 96) // order
    matrix[num_messages + 0, i + 2] = 0
    matrix[num_messages + 1, i + 1] = 0
    matrix[num_messages + 1, i + 2] = 2**(256 - 96)

    new_matrix = matrix.LLL(early_red=True, use_siegel=True)

    keys = []
    for row in new_matrix:
        diff = row[0]
        key = ((last_s * hs[0]) - (ss[0] * last_h) - (ss[0] * last_s * diff))
        key *= modinv((last_r * ss[0]) - (rs[0] * last_s), order)
        key = key % order
        if key not in keys:
            keys.append(key)

    return keys

keys = recover_private_key(hs, rs, ss)

print(keys[1]) # use 2nd value
```

Note that `- 96` refers to the bias in the top bits of the nonces discussed earlier.

## Flag
`TFCCTF{c0Ngr47s_y0u_s4v3d_th3_3lect1Ons}`

smiley 2024/08/03
