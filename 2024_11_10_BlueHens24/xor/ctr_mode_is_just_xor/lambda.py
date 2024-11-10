#LIVE AT https://i8fgyps3o2.execute-api.us-east-1.amazonaws.com/default/ctrmode?pt=00

import json
import os
import sys
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


def lambda_handler(event, context):
    pt=bytes.fromhex(event["queryStringParameters"]["pt"])
    padded = pad(pt, 16)

    probiv = os.environ["probiv"]
    flag = os.environ["flag"]
    padflag = pad(flag.encode(), 16)
    flagcipher = AES.new(os.environ["secretkey"].encode(), AES.MODE_CTR, nonce=probiv.encode())
    pct = flagcipher.encrypt(padflag)

    yourcipher = AES.new(os.environ["secretkey"].encode(), AES.MODE_ECB)
    try:
        encrypted = yourcipher.encrypt(padded)
    except ValueError as e:
        return {'statusCode': 500, "error": str(e)}

    return {
        'statusCode': 200,
        'body': json.dumps({"ciphertext": encrypted.hex(), "probiv": probiv.encode().hex(), "flagenc": pct.hex()})
    }
