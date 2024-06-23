#!/usr/bin/env python3

from pwn import *

elf = ELF("./chal_home", checksec=False)
context.binary = elf

p = elf.debug(gdbscript=
"""
set context-sections ''
break main
continue
nextret
search -t bytes FLAG{
""")

p.interactive() # FLAG{How_did_you_get_here_4VKzTLibQmPaBZY4}
