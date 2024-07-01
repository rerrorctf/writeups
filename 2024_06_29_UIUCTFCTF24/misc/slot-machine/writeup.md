https://ctftime.org/event/2275

# slot-machine (misc)

hash with a lot of zeroes

## Solution

the challenge let you choose a hash and a length
if you win you get length bytes of the flag
winning here is just satisfying `len(set(hash[:length])) == 1:`
so we need a hash with a lot of repeated bytes
then we google bitcoin lowest block number and manually get the hash from it

```python
import requests
import json
import hashlib

block={}

#inputs values (from https://www.blockchain.com/explorer/blocks/btc/756951)
block['blocknumber']=756951
block['version']='20400000'
block['hashPrevBlock']='000000000000000000050da0da9451c2e1306db4ddb5acc965fc1016678d9154'
block['hashMerkleRoot']='62c46f1efadf6e39b7463e5362bb552cba98f74a80a58378ff5194c7b058005a'
block['time']=1664846893
block['bits']=386464174
block['nonce']=3240300428

#prepare values
block['versionprepared']=bytes.fromhex(block['version'])[::-1].hex()
block['hashPrevBlockprepared']=bytes.fromhex(block['hashPrevBlock'])[::-1].hex()
block['hashMerkleRootprepared']=bytes.fromhex(block['hashMerkleRoot'])[::-1].hex()
block['timeprepared']=int(block['time']).to_bytes(4, byteorder='little').hex()
block['bitsprepared']=int(block['bits']).to_bytes(4, byteorder='little').hex()
block['nonceprepared']=int(block['nonce']).to_bytes(4, byteorder='little').hex()

#concatentate prepared values to create input to double sha256 hash function
block['hashinput']=block['versionprepared'] + block['hashPrevBlockprepared'] + block['hashMerkleRootprepared'] + block['timeprepared'] + block['bitsprepared'] + block['nonceprepared']

#double sha256 hash
d1 = hashlib.sha256(bytes.fromhex(block['hashinput'])).digest()

print(d1[::-1].hex())
```

```python
#!/usr/bin/env python3

from pwn import *

p = remote("slot-machine.chal.uiuc.tf", 1337, ssl=True)
p.sendline("93ccd10e30712e566e0bc0189c791e609b11fc17190b00eb50d6fa8b4909b2f5")
p.sendline("24")
p.interactive()
```

## Flag
`uiuctf{keep_going!_3cyd}`

shafouz 2024/06/30
