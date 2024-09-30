#!/usr/bin/env python3

from xnor import *

message  = b'Blue is greener than purple for sure!'
message_enc = bytes.fromhex("fe9d88f3d675d0c90d95468212b79e929efffcf281d04f0cfa6d07704118943da2af36b9f8")
key = xnor_bytes(message_enc, message)

flag_enc = bytes.fromhex("de9289f08d6bcb90359f4dd70e8d95829fc8ffaf90ce5d21f96e3d635f148a68e4eb32efa4")
flag = xnor_bytes(flag_enc, key)

print(flag.decode()) # bctf{why_xn0r_y0u_b31ng_so_3xclu51v3}
