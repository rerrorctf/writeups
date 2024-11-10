#endpoint: https://vbbfgwcc6dnuzlawkslmxvlni40zkayu.lambda-url.us-east-1.on.aws/

import json
import os
import sys
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


def lambda_handler(event, context):
    if ("queryStringParameters" in event) and ("token" in event["queryStringParameters"]):
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

        except ValueError as e:
            return {'statusCode': 401, "error": str(e)}
    else:
        iv = os.urandom(16)
        cipher = AES.new(os.environ["secretkey"].encode(), AES.MODE_CBC, iv=iv)
        pt=b'{"role":"guest","username":"johndoe","id":"123"}'
        ct = cipher.encrypt(pt)
        return {
            'statusCode': 200,
            'body': json.dumps({"token": ct.hex(), "iv": iv.hex()})
        }