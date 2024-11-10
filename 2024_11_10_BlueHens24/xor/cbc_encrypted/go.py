#!/usr/bin/env python3

from pwn import *
import requests

url = "https://vbbfgwcc6dnuzlawkslmxvlni40zkayu.lambda-url.us-east-1.on.aws/"
response = requests.get(url)
data = response.json()
token = data["token"]
iv = bytes.fromhex(data["iv"])
log.success(data)

known_plaintext = b'{"role":"guest",'
wanted_plaintext = b'{"role":"admin",'
iv = xor(xor(iv, known_plaintext), wanted_plaintext)

url = "https://vbbfgwcc6dnuzlawkslmxvlni40zkayu.lambda-url.us-east-1.on.aws/?token=" + token + "&iv=" + iv.hex()
response = requests.get(url)
data = response.json()
flag = data["flag"]
log.success(flag) # udctf{1v_m4n1pul4t10n_FTW_just_anoth3r_x0R_4pplic4tion}
