import struct
from itertools import cycle

with open("ct", "rb") as file:
    ct = file.read()

key = b""
for i, c in enumerate("uiuctf{"):
    key += struct.pack("B", ct[i] ^ ord(c))

key += struct.pack("B", ct[-1] ^ ord("}"))

pt = bytes(x ^ y for x, y in zip(ct, cycle(key)))

print(pt.decode()) # uiuctf{n0t_ju5t_th3_st4rt_but_4l50_th3_3nd!!!!!}
