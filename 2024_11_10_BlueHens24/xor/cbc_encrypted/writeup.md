https://ctftime.org/event/2512

# CBC Encrypted? (xor)

https://gist.github.com/AndyNovo/84580af56a6294ed2576366018dc557c

https://vbbfgwcc6dnuzlawkslmxvlni40zkayu.lambda-url.us-east-1.on.aws/

## Analysis

We can see from the following part of `cbcfun_lambda.py` that cbc is used without integrity:

```python
ct=bytes.fromhex(event["queryStringParameters"]["token"])
iv=bytes.fromhex(event["queryStringParameters"]["iv"])
cipher = AES.new(os.environ["secretkey"].encode(), AES.MODE_CBC, iv=iv)
pt = cipher.decrypt(ct)
flag = os.environ["flag"]

try:
    token = json.loads(pt)
    if (token['role'] == 'admin'):
        return {
            'statusCode': 200,
            'body': json.dumps({"flag": flag})
        }
    else:
        return {
            'statusCode': 401,
            'body': json.dumps({"flag": "unauthorized"})
        }
```

You can read more about cbc decryption here:

https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_block_chaining_(CBC)

## Solution

1) Get an iv/ciphertext pair for the known plaintext `{"role":"guest","username":"johndoe","id":"123"}`
2) XOR the known plaintext with the iv to get the output of the cipher for the first block
3) XOR the output of the cipher for the first block with the wanted_plaintext
    - This alters the outcome of decryption to produce our wanted plaintext

```python
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
```

## Flag
`udctf{1v_m4n1pul4t10n_FTW_just_anoth3r_x0R_4pplic4tion}`

smiley 2024/11/10
