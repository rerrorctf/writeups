#!/usr/bin/env python3

from pwn import *
import requests

url = "https://i8fgyps3o2.execute-api.us-east-1.amazonaws.com/default/ctrmode?pt=00"
response = requests.get(url)
data = response.json()
probiv = data["probiv"] # GPEq6Sqzy6dLmeM
flagenc = data["flagenc"]
log.success(data)

iv = unhex(probiv) + b"\x00" + unhex(probiv) + b"\x01" + unhex(probiv) + b"\x02" + unhex(probiv) + b"\x03" 

url = "https://i8fgyps3o2.execute-api.us-east-1.amazonaws.com/default/ctrmode?pt=" + iv.hex()
response = requests.get(url)
data = response.json()
ciphertext = data["ciphertext"]
log.success(data)

flag = xor(bytes.fromhex(ciphertext), bytes.fromhex(flagenc))[:50].decode()
print(flag) # UDCTF{th3r3_15_n0_sp00n_y0uv3_alr34dy_d3c1d3d_NE0}
