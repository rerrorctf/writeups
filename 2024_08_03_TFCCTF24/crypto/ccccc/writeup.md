https://ctftime.org/event/2423

# ccccc (crypto)

CCCCC CCCCC CCCCC CCCCC CCCCC CCCCC CCCCC CCCCC CCCCC CCCCC CCCCC CCCCC

CCCCC CCCCC CCCCC

## Solution

1) Remove the `c` characters from every other index
2) Unhex to recover the flag

```python
#!/usr/bin/env python3

from binascii import unhexlify

with open("ccccc.txt", "r") as f:
    c = f.read()

flag = ""
for i in range(0, len(c), 2):
    flag += c[i]

flag = unhexlify(flag)[:-1].decode()

print(flag) # TFCCTF{cshout_cout_ct0_cmy_cb0y_c4nd_cmy_cdog_cand_cmy_cc47}
```

## Flag
`TFCCTF{cshout_cout_ct0_cmy_cb0y_c4nd_cmy_cdog_cand_cmy_cc47}`

smiley 2024/08/03
