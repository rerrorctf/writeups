#!/usr/bin/env python3

import requests
import string

def guess_big(w):
    REMOTE = (
        "https://55nlig2es7hyrhvzcxzboyp4xe0nzjrc.lambda-url.us-east-1.on.aws/?payload="
        + w
    )
    res = requests.get(REMOTE)
    print(bytes.fromhex(w), res.text, flush=True)
    print("---", flush=True)
    return res.json()

flag = b"udctf{"
for _ in range(64):
    for c in string.ascii_letters + string.digits + string.punctuation:
        c = c.encode()
        j = guess_big((flag + c).hex())["sniffed"]

        if j < 68:
            max = j
            flag = flag + c
            break
    print(f"DEBUGPRINT[12]: lab1.py:49: flag={flag}")
