https://ctftime.org/event/2377

# home (rev)

FLAGを処理してくれる関数は難読化しちゃいました。読みたくは……ないですね！

The function that processes the FLAG has been obfuscated. You don't want to read it... do you?

## Analysis

`main` @ `0x00101977`

- We can see some anti-debugging code at the start of this function
- At the end of the function is a call to `constructFlag`. It is likely that this places the flag in memory somewhere.

`constructFlag` @ `0x001011b0`

- We can see a lot of code here that would be quite complicated to reverse
- At the end of the function the code prints `Processing Completed!`
- It seems likely that after this function returns the flag is present somewhere in memory

## Solution

1) Patch the binary with ghidra to `JMP` straight to `constructFlag`
2) Break with pwndbg at the end of `main`
3) Search memory for the sequence of bytes `FLAG{`
4) Find the flag on the stack

To patch the binary with ghidra:

1) Open `chal_home` with ghidra
2) Navigate to the `main` function @ `0x00101977`
3) Note the address of the code that calls `constructFlag` as `0x00101a0c`
4) Right mouse click on the instruction @ `0x001019a1`, just prior to the debugger checks, and select Patch instruction
5) Change the mnemonic to `JMP` and the argument to `0x001019a1`. Note that `JMP` must be in uppercase and `0x001019a1` must start with `0x` where `x` is lowercase
6) Using the file menu select Export Program
7) Select Original File as the format
8) Export the file overwriting the original file

Now if we run the newly patched binary with pwndbg and break at `main` we see the following:

```
 ► 0x55555555597f <main+8>      sub    rsp, 0x410                   RSP => 0x7fffffffd3e0 (0x7fffffffd7f0 - 0x410)
   0x555555555986 <main+15>     mov    rax, qword ptr fs:[0x28]
   0x55555555598f <main+24>     mov    qword ptr [rbp - 8], rax
   0x555555555993 <main+28>     xor    eax, eax                     EAX => 0
   0x555555555995 <main+30>     lea    rax, [rbp - 0x410]
   0x55555555599c <main+37>     mov    esi, 0x400                   ESI => 0x400
   0x5555555559a1 <main+42>     jmp    main+149                    <main+149>
    ↓
   0x555555555a0c <main+149>    mov    eax, 0                 EAX => 0
   0x555555555a11 <main+154>    call   constructFlag               <constructFlag>
 
   0x555555555a16 <main+159>    jmp    main+194                    <main+194>
```

As you can see we simply `JMP` at `0x0x5555555559a1` directly to `constructFlag`.

Finally we can place a breakpoint after the call to `constructFlag` and then use the `search -t bytes` command to find the flag in memory.

Here is a pwntools script that automates the usage of pwndbg for this task:

```python
#!/usr/bin/env python3

from pwn import *

elf = ELF("./chal_home", checksec=False)
context.binary = elf

p = elf.debug(gdbscript=
"""
set context-sections ''
break main
continue
nextret
search -t bytes FLAG{
""")

p.interactive() # FLAG{How_did_you_get_here_4VKzTLibQmPaBZY4}
```

## Flag
`FLAG{How_did_you_get_here_4VKzTLibQmPaBZY4}`

smiley 2024/06/23
