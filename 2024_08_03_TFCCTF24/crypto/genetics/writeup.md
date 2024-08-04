https://ctftime.org/event/2423

# Genetics (crypto)

I just took a quick look at my DNA. I feel like I was created for this CTF.

CCCA CACG CAAT CAAT CCCA CACG CTGT ATAC CCTT CTCT ATAC CGTA CGTA CCTT CGCT ATAT CTCA CCTT CTCA CGGA ATAC CTAT CCTT ATCA CTAT CCTT ATCA CCTT CTCA ATCA CTCA CTCA ATAA ATAA CCTT CCCG ATAT CTAG CTGC CCTT CTAT ATAA ATAA CGTG CTTC

## Analysis

The given text appears similar to the most common [DNA digital data store encoding](https://en.wikipedia.org/wiki/DNA_digital_data_storage).

This is a base 4 encoding.

## Solution

1) Convert the letter symbols to number symbols
2) Convert the numbers to base 10 from base 4

```python
#!/usr/bin/env python3

with open("task.txt", "r") as f:
    c = f.read()

c = c.replace(" ", "")
c = c.replace("\n", "")

c = c.replace("A", "0")
c = c.replace("C", "1")
c = c.replace("G", "2")
c = c.replace("T", "3")

flag = ""

for i in range(0, len(c), 4):
    flag += chr(int(c[i:i+4], 4))

print(flag) # TFCCTF{1_w1ll_g3t_th1s_4s_4_t4tt00_V3ry_s00n}
```

## Flag
`TFCCTF{1_w1ll_g3t_th1s_4s_4_t4tt00_V3ry_s00n}`

smiley 2024/08/03
