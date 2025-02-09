https://ctftime.org/event/2607

# Alice n Bob in Wonderland (crypto)

However secure a communication be, people want it to be more secure.

Alice and Bob are communicating over a secure channel about some secret operation. Your task is to break their scheme and retrieve the key.

Also I do not know if this is going to be relevant, but the first message in they send every time they start their conversation, they start with Glory to the RedHawk.

nc chals.bitskrieg.in 7002

## Analysis

There are two inter-related weaknesses we need to exploit to solve this challenge:

The first relates to how `random.seed` is called and how `random.randint` is used:

```python
aes_key = shared_secret[:16]
iv = shared_secret[16:]
random.seed(int(iv.hex(),16))
```

By seeding `random` with the IV that is used during encryption it opens the door for us to produce the same stream of random numbers if we can recover the IV.

The second relates to how `k` values are chosen for ECDSA-SECP256k1-SHA-2-256 signatures:

```python
k = random.randint(1, SECP256k1.order - 1)  
signature = private_key.sign(message,hashfunc=hashlib.sha256 ,k=k)
```

By choosing `k` values in way that is predictable, if we can recover the IV, it opens the door for us to recover the private key used to perform the signatures.

### AES CBC IV Recovery

One of the ways to recover the IV, when its not provided directly with the ciphertext as normal, is to exploit the effect that repeated ciphertext blocks that are interleaved with zeroes has on the resulting plaintext: 

```python
#!/usr/bin/env python3

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

key = b"A" * 16
iv = b"B" * 16
print(f"{iv.hex() = }")

cipher = AES.new(key, AES.MODE_CBC, iv)
ciphertext = cipher.encrypt(pad((b"C" * 16) * 3, AES.block_size))

cipher = AES.new(key, AES.MODE_CBC, iv)
plaintext = cipher.decrypt(ciphertext[:16] + (b"\x00" * 16) + ciphertext)

iv = xor(plaintext[:16], plaintext[32:48])
print(f"{iv.hex() = }") # iv.hex() = '42424242424242424242424242424242'
```

This works because the first block of plaintext is xored with the iv and the third block, being a copy of the first, results in the same plaintext but xored with all zeroes from the second ciphertext block:

```
C1 = ...
C2 = b"\x00" * 16
C3 = C1
C4 = ...

if C1 == C3 then... P1 == P3

P1 ^ IV = AES-DEC(C1, K)
P2 ^ C1 = AES-DEC(C2, K)
P3 ^ C2 = AES-DEC(C3, K)

if C2 = b"\x00" * 16 then P3 ^ C2 == P3 == P1

IV = AES-DEC(C1, K) ^ AES-DEC(C3, K) = (P1 ^ IV) ^ (P3 ^ C2) = (P1 ^ IV) ^ P3
```

If you want to read more about this concept see https://cedricvanrompay.gitlab.io/cryptopals/challenges/27.html

### ECDSA Private Key Recovery From Known K

We can recover the values of `k` used by the signatures by seeding `random.seed` using the same value as the remote:

```python
seed(int(iv.hex(), 16))
k = randint(1, SECP256k1.order - 1)
k = randint(1, SECP256k1.order - 1) # bob's first signature uses the 2nd k
```

Once you have a likely `k` you can use it to recover `d` as follows:

First observe how `d` is generally used during signature generation:

```python
s = (pow(k, -1, n) * (z + r * d)) % SECP256k1.order
```

Using algebra we can rearrange this expression to solve for `d` as follows:

```python
r = int.from_bytes(bobs_first_signature[:32])
s = int.from_bytes(bobs_first_signature[32:])
z = int.from_bytes(sha256(b"Glory to the RedHawk").digest()) % SECP256k1.order

maybe_d = (((s * k) - z) * pow(r, -1, SECP256k1.order)) % SECP256k1.order
```

This works even if `d` is selected uniformly at random from the range `[1, n)` as long as `k` is known.

This then lets us create a private key from d using the `ecdsa` library as follows:

```python
bob_private_key = SigningKey.from_secret_exponent(maybe_d, curve=SECP256k1)
```

If you want more details about this attack and another example of the same kind of challenge, albeit with DSA not ECDSA, see https://www.cryptopals.com/sets/6/challenges/43

If you want to read more about this concept see https://github.com/rerrorctf/writeups/blob/main/2025_01_24_x3CTF25/crypto/curved-mvm/writeup.md#how-does-the-attack-work

## Solution

```python
#!/usr/bin/env python3

from pwn import *
from random import seed, randint
from hashlib import sha256
from ecdsa import VerifyingKey, SigningKey, SECP256k1
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

#context.log_level = "debug"

p = remote("chals.bitskrieg.in", 7002)

p.readuntil(b"Alice's public key: ")
alice_public_key = bytes.fromhex(p.readline().decode())
alice_public_key = VerifyingKey.from_string(alice_public_key, curve=SECP256k1)

p.readuntil(b"Bob's public key: ")
bob_public_key = bytes.fromhex(p.readline().decode())
bob_public_key = VerifyingKey.from_string(bob_public_key, curve=SECP256k1)

# pass the first 4 messages between alice and bob...
# ... take note of the first pair from alice and the first signature from bob

p.readuntil(b"Ciphertext: ")
ciphertext = bytes.fromhex(p.readline().decode())
p.readuntil(b"Signature: ")
signature = bytes.fromhex(p.readline().decode())
p.sendlineafter(b"Ciphertext (hex): ", ciphertext.hex().encode())
p.sendlineafter(b"Signature (hex): ", signature.hex().encode())

alices_first_ciphertext = ciphertext
alices_first_signature = signature

p.readuntil(b"Ciphertext: ")
ciphertext = bytes.fromhex(p.readline().decode())
p.readuntil(b"Signature: ")
signature = bytes.fromhex(p.readline().decode())
p.sendlineafter(b"Ciphertext (hex): ", ciphertext.hex().encode())
p.sendlineafter(b"Signature (hex): ", signature.hex().encode())

bobs_first_signature = signature

p.readuntil(b"Ciphertext: ")
ciphertext = bytes.fromhex(p.readline().decode())
p.readuntil(b"Signature: ")
signature = bytes.fromhex(p.readline().decode())
p.sendlineafter(b"Ciphertext (hex): ", ciphertext.hex().encode())
p.sendlineafter(b"Signature (hex): ", signature.hex().encode())

p.readuntil(b"Ciphertext: ")
ciphertext = bytes.fromhex(p.readline().decode())
p.readuntil(b"Signature: ")
signature = bytes.fromhex(p.readline().decode())
p.sendlineafter(b"Ciphertext (hex): ", ciphertext.hex().encode())
p.sendlineafter(b"Signature (hex): ", signature.hex().encode())

# this message is at least 3 blocks long so we can easily reuse it to recover the iv
# ... note that the signature here doesn't match what we send and that's ok

p.readuntil(b"Ciphertext: ")
ciphertext = bytes.fromhex(p.readline().decode())
p.readuntil(b"Signature: ")
signature = bytes.fromhex(p.readline().decode())

ciphertext_to_compute_iv = ciphertext[:16] + (b"\x00" * 16) + ciphertext

p.sendlineafter(b"Ciphertext (hex): ", ciphertext_to_compute_iv.hex().encode())
p.sendlineafter(b"Signature (hex): ", signature.hex().encode())

p.readuntil(b"found:\n")
plaintext = bytes.fromhex(p.readline().decode())
iv = xor(plaintext[:16], plaintext[32:48])

# to finish the conversation after we provided an invalid signature...
# ... send a valid ciphertext / signature pair from alice that we saved earlier

p.sendlineafter(b"Ciphertext (hex): ", alices_first_ciphertext.hex().encode())
p.sendlineafter(b"Signature (hex): ", alices_first_signature.hex().encode())

# now we can seed random and recover k...
# ... and then use that to recover bob's private key

r = int.from_bytes(bobs_first_signature[:32])
s = int.from_bytes(bobs_first_signature[32:])
z = int.from_bytes(sha256(b"Glory to the RedHawk").digest()) % SECP256k1.order

seed(int(iv.hex(), 16))
k = randint(1, SECP256k1.order - 1)
k = randint(1, SECP256k1.order - 1) # bob's first signature uses the 2nd k

maybe_d = (((s * k) - z) * pow(r, -1, SECP256k1.order)) % SECP256k1.order

bob_private_key = SigningKey.from_secret_exponent(maybe_d, curve=SECP256k1)

# now we have bob's private key...
# ... we can compute the shared secret and then the aes key

shared_point = bob_private_key.privkey.secret_multiplier * alice_public_key.pubkey.point
shared_secret_bytes = shared_point.to_bytes()
shared_secret = sha256(shared_secret_bytes).digest()

assert(shared_secret[16:] == iv)
aes_key = shared_secret[:16]

# now we have the iv, aes key and bob's private key...
# ... we can encrypt the chosen plaintext and forge a signature from bob for it

chosen_plaintext = b"Can I have the key again, I think I forgot where I kept the key."
cipher = AES.new(aes_key, AES.MODE_CBC, iv)
ciphertext = cipher.encrypt(pad(chosen_plaintext, AES.block_size))
signature = bob_private_key.sign(chosen_plaintext,hashfunc=sha256 ,k=69)
p.sendlineafter(b"Ciphertext (hex): ", ciphertext.hex().encode())
p.sendlineafter(b"Signature (hex): ", signature.hex().encode())

# then alice should send us the flag encrypted...
# ... along with a signature that we can ignore

p.readuntil(b"Ciphertext: ")
flag_ciphertext = bytes.fromhex(p.readline().decode())
p.readuntil(b"Signature: ")
flag_signature = bytes.fromhex(p.readline().decode())
cipher = AES.new(aes_key, AES.MODE_CBC, iv)
plaintext = unpad(cipher.decrypt(flag_ciphertext), AES.block_size)
flag = plaintext[59:].decode()
print(flag) # BITSCTF{7h1s_w45_0n3_of_th3_c00l3s7_m155i0ns_1_h4v3_3v3r_s33n_b14dae74}
```

## Flag
`BITSCTF{7h1s_w45_0n3_of_th3_c00l3s7_m155i0ns_1_h4v3_3v3r_s33n_b14dae74}`

smiley 2025/02/08
