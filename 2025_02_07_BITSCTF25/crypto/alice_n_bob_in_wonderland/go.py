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
