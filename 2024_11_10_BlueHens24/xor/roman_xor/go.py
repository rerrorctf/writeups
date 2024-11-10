#!/usr/bin/env python3

from pwn import *

cts = [
  '43794c9c8faa2cff24edc8afe507a13f62837c7e166f428cab5aff893225ff19104bc8754c1c09', 
  '5d315e8786e62cf763e9d4afe80ca13b649a717e11615986b642f3952f76b71b0342c4', 
  '46785a8bcae62aeb60a5deeef107a1256ed7792752695886ff50f5886171ff1717', 
  '5d315e819fe621b966e08dfae906e43a78837b31162e5e8cff46e8953275f20a0d5ad23d4712144c', 
  '557f4dce9ee220b967e4dfffe616e9216a9934291b7d5690bb45ba922e6afc', 
  '55315a868fef35f16beac6afe810a1206a81717e1e6b5690b152ba953462ff0c424acd6e0307055a81b93590c1fe', 
  '557d489dcafd2df870a5cfe0e816f268628334291b7a5fc2aa58f99f3276f616160fc27c5116', 
  '557f4dce8bee21fc24f1c5eaa712ee3f6e853431142e448db216fb9e2b70e5110c48816b46011e5a', 
  '407e099783ef29fd24edc4fca704f33d6283343f1c6a178ab645ba962464f1581147c0714f530350d5f53690dee6', 
  '40785ace93e530b970edccfba711e0312b9e607e1c6143c2b616e3953425f317425bc9780317085ac5a6', 
  '41754a9a8cf13da976dac4e1d810b1253f994b6f47514387b106e8a57175a40a0370d22c4d14084d9ea8']

keystream = xor(b"udctf{", bytes.fromhex(cts[-1])[:6])
keystream = xor(b"i would", bytes.fromhex(cts[3])[:7])
keystream = xor(b"to yield ", bytes.fromhex(cts[-3])[:9])
keystream = xor(b"i willingly ", bytes.fromhex(cts[1])[:12])
keystream = xor(b"i would be un", bytes.fromhex(cts[3])[:13])
keystream = xor(b"rise lord save ", bytes.fromhex(cts[2])[:15])
keystream = xor(b"i would be under", bytes.fromhex(cts[3])[:16])
keystream = xor(b"to yield his fruit", bytes.fromhex(cts[8])[:18])
keystream = xor(b"where if he be with", bytes.fromhex(cts[0])[:19])
keystream = xor(b"i would be understood ", bytes.fromhex(cts[3])[:22])
keystream = xor(b"to yield his fruit and ", bytes.fromhex(cts[8])[:23])
keystream = xor(b"rise lord save me my god", bytes.fromhex(cts[2])[:25])
keystream = xor(b"where if he be with dauntless ", bytes.fromhex(cts[0])[:30])
keystream = xor(b"i willingly on some conditions ", bytes.fromhex(cts[1])[:31])
keystream = xor(b"alas what boots it with uncessant ", bytes.fromhex(cts[6])[:34])
keystream = xor(b"i would be understood in prosperous", bytes.fromhex(cts[3])[:35])

# Blind mouthes! that scarce themselves know how to hold A Sheep-hook, or have learn'd ought els the least [ 120 ] That to the faithfull Herdmans art belongs! What recks it them? What need they?

keystream = xor(b"a sheephook or have learnd ought els the least", bytes.fromhex(cts[5])[:46])

for i in range(len(cts)):
    ct = bytes.fromhex(cts[i])
    print(i, xor(ct, keystream))

flac_enc = bytes.fromhex(cts[-1])
flag = xor(flac_enc, keystream[:len(flac_enc)]).decode()
print(flag) # udctf{x0r_in_r0m4n_15_ten0r_0p3ra_s1nger?}
