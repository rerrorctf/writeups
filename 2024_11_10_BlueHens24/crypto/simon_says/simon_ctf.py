# See https://pypi.org/project/simonspeckciphers/ for implementation
from simon import SimonCipher

import secrets
import string
from Crypto.Util.number import bytes_to_long, long_to_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.Util.strxor import strxor

KEY_SIZE = 128
BLOCK_SIZE = 64
# Number of ciphertexts
NUM_ENTRIES = 16 

key = secrets.randbits(KEY_SIZE)
nonce = secrets.randbits(2*BLOCK_SIZE)

print(nonce)
counter = 0

with open("quotes.txt") as qf: #read quote file
    for _qi in range(NUM_ENTRIES):
        ql = next(qf).strip() #read quote line
        assert ql.isprintable()
        ql = pad(ql.encode("utf-8"), BLOCK_SIZE//8)
        assert ((len(ql) % (BLOCK_SIZE//8)) == 0)
        
        # encrypt the message
        my_simon = SimonCipher(key,  key_size=KEY_SIZE, block_size=BLOCK_SIZE, mode='CTR', init=nonce, counter=counter)
        ctxt = b""
        for i in range(0, len(ql), (BLOCK_SIZE//8)):
            ctxt_int = my_simon.encrypt(bytes_to_long(ql[i: i+ (BLOCK_SIZE//8)]))
            ctxt += long_to_bytes(ctxt_int)
        print(ctxt.hex())
        nonce += 1

flag = "udctf{REDACTED}"
ctxt = b""
flag = pad(flag.encode("utf-8"), BLOCK_SIZE//8)
my_simon = SimonCipher(key,  key_size=KEY_SIZE, block_size=BLOCK_SIZE, mode='CTR', init=nonce, counter=counter)
for i in range(0, len(flag), BLOCK_SIZE//8):
    ctxt_int = my_simon.encrypt(bytes_to_long(flag[i : i+(BLOCK_SIZE//8)]))
    ctxt += long_to_bytes(ctxt_int)

print(ctxt.hex())