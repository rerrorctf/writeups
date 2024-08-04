#!/usr/bin/env python3

from pwn import *

order = 115792089210356248762697446949407573529996955224135760342422259061068512044369 #G.order()

#context.log_level = "debug"
#p = process(["python3", "server.py"])
p = remote("challs.tfcctf.com", 30646)

p.readline() # What do you want to do?
p.readline() # 1. Listen in on conversation
p.readline() # 2. Submit the info you found
p.readline() # 3. Get pubkey

def collect_signatures():
    hs = []
    rs = []
    ss = []
    for i in range(11):
        p.sendline(b"1")
        line = p.readline().decode()
        line = line.replace(",", "")
        line = line.replace("'", "")
        line = line.replace("}", "")
        line = line.split(" ")
        hsh = int(line[1], 10)
        r = int(line[3], 16)
        s = int(line[5], 16)
        hs.append(hsh)
        rs.append(r)
        ss.append(s)
    return hs, rs, ss

hs, rs, ss = collect_signatures()

print(f"{hs = }")
print(f"{rs = }")
print(f"{ss = }")

# use sage to recover private key d

p.sendline(b"2")

p.readuntil(b"Key? ")

# paste the 2nd value
# e.g. 30074281352231076024531614267798461182783011404334876390885601752600165860912

p.interactive() # TFCCTF{c0Ngr47s_y0u_s4v3d_th3_3lect1Ons}
