#!/usr/bin/env python3

from pwn import *
import time

#context.log_level = "debug"
elf = ELF("./main", checksec=False)
context.binary = elf

# first determine the correct length
# as long as the first character is correct it will take longer
# we know the first character from the flag format TFCCTF{.+}

flag = b""
length = 0
best_length_time = 0

for i in range(50):
    start_time = time.time()
    
    with elf.process(argv=[flag], level="CRITICAL") as p:
        p.readall()

    end_time = time.time()
    elapsed_time = end_time - start_time

    if elapsed_time > best_length_time:
        length = len(flag)
        best_length_time = elapsed_time

    flag += b"T"

log.success(f"flag length: {length}")

# now determine the rest of the flag skipping the known prefix

flag = bytearray(b"TFCCTF{" + (b"T" * (length - 7)))

for i in range(7, length):
    best_char = b"\x00"
    best_char_time = 0
    for c in string.printable:
        flag[i] = ord(c)
        start_time = time.time()
    
        with elf.process(argv=[flag], level="CRITICAL") as p:
            p.readall()

        end_time = time.time()
        elapsed_time = end_time - start_time

        if elapsed_time > best_char_time:
            best_char = c
            best_char_time = elapsed_time

    flag[i] = ord(best_char)
    log.info(f"{flag =}")

log.success(f"{flag = }")
