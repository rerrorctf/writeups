https://ctftime.org/event/2512

# CTR Mode Is Just XOR (xor)

https://gist.github.com/AndyNovo/23d509307fc55fcebae1fd522ed04295

This series of problems is called the XOR SCHOOL. For whatever reason I just love xor problems and over the years there are many that have charmed my soul. This sequence is an homage to the many many ways that xor shows up in CTFs. I hope you can see some of the beauty that I see through them. -ProfNinja

https://i8fgyps3o2.execute-api.us-east-1.amazonaws.com/default/ctrmode\?pt\=00 

## Analysis

We can see from the code in `lambda.py` that we are given the ability to encrypt whatever we want under the same secret key in ECB mode:

```python
yourcipher = AES.new(os.environ["secretkey"].encode(), AES.MODE_ECB)
    try:
        encrypted = yourcipher.encrypt(padded)
```

We can also see that we are given the same nonce as is used to encrypt the flag in CTR mode:

```python
return {
        'statusCode': 200,
        'body': json.dumps({"ciphertext": encrypted.hex(), "probiv": probiv.encode().hex(), "flagenc": pct.hex()})
    }
```

If we encrypt this nonce in ECB mode, taking are to increment it for each block, we can produce the same keystream that the CTR mode cipher used to encrypt the flag.

## Solution

1) Collect an iv/ciphertext pair
2) Use the iv to construct a series of 4 blocks consisting of the iv and a 1 byte sequential counter
3) Encrypt this to recover the keystream
4) Decrypt the ciphertext we recovered in step 1

```python
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
```

## Flag
`UDCTF{th3r3_15_n0_sp00n_y0uv3_alr34dy_d3c1d3d_NE0}`

smiley 2024/11/10
