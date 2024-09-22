#!/usr/bin/env python3

from Crypto.Util.number import *
from Crypto.PublicKey import RSA
from cryptography.hazmat.primitives import serialization
from os import system
import random

# critically important to use this version or getPrime might not return 
# the same p and q as were used in the task!
#
# $ pip3 install --force-reinstall -v "pycryptodome==3.10.4"
#

public_key = serialization.load_pem_public_key(
    """
    -----BEGIN PUBLIC KEY-----
    MIHdMA0GCSqGSIb3DQEBAQUAA4HLADCBxwKBgQCMdauT2revYJrutp7eqQfrMkse
    TqfgRdLlMddaVRxiG04qJneVtpzkeLQTZqniJWx5YsUwMDeISeQjmVkr2a+Ob9S8
    +xsqVQ0XTW3xPjwKaZhW8jXAlX13ClhAxk1FvPbl6ASsPGUMX6gRSXArRYFx3Kev
    C9xng/ZKEhsC5FzBBwJBALKsZCm9FGHXvyJChFDt7vDZUCyU1jbOgS9EhNz+HrrU
    K9OCgOoZGfcjIHAcrM+w4AdF48NQELqttmKlcko6ock=
    -----END PUBLIC KEY-----
    """.encode()
)

known_n = public_key.public_numbers().n
known_e = public_key.public_numbers().e

# $ stat public_key.pem 
#  File: public_key.pem
#  Size: 356       	Blocks: 8          IO Block: 4096   regular file
#Device: 252,0	Inode: 109599763   Links: 1
#Access: (0644/-rw-r--r--)  Uid: ( 1000/    user)   Gid: ( 1000/    user)
#Access: 2024-09-21 10:40:57.326332769 +0100
#Modify: 2024-08-18 23:07:49.000000000 +0100
#Change: 2024-09-21 10:40:57.299331566 +0100
# Birth: 2024-09-21 10:40:57.299331566 +0100

# $ date -u -d "2024-08-18 23:07:49.000000000 +0100" +%s
# 1724018869

start_time = 1724018869

while True:
    random.seed(start_time)
    p, q = getPrime(512, random.randbytes), getPrime(512, random.randbytes)
    n = p*q
    if n == known_n:
        break
    start_time -= 1

e = known_e
phi = (p-1)*(q-1)
d = pow(e, -1, phi)

key = RSA.construct((n, e, d, p, q))

with open("private_key.pem", "wb") as f:
    f.write(key.export_key("PEM"))

system("openssl pkeyutl -decrypt -inkey private_key.pem -in flag.enc") # CACI{T!ME_T0_S33D}
