https://ctftime.org/event/2512

# XOR Without XOR (xor)

This is how XOR makes me feel.

## Analysis

```python
>>> flag = 'u_cnfrj_sr_b_34}yd1tt{0upt04lbmb'
>>> flag*32
'u_cnfrj_sr_b_34}yd1tt{0upt04lbmbu_cnfrj_sr_b_34}yd1tt{0upt04lbmbu_cnfrj_sr_b_34}yd1tt{0upt04lbmbu_cnfrj_sr_b_34}yd1tt{0upt04lbmbu_cnfrj_sr_b_34}yd1tt{0upt04lbmbu_cnfrj_sr_b_34}yd1tt{0upt04lbmbu_cnfrj_sr_b_34}yd1tt{0upt04lbmbu_cnfrj_sr_b_34}yd1tt{0upt04lbmbu_cnfrj_sr_b_34}yd1tt{0upt04lbmbu_cnfrj_sr_b_34}yd1tt{0upt04lbmbu_cnfrj_sr_b_34}yd1tt{0upt04lbmbu_cnfrj_sr_b_34}yd1tt{0upt04lbmbu_cnfrj_sr_b_34}yd1tt{0upt04lbmbu_cnfrj_sr_b_34}yd1tt{0upt04lbmbu_cnfrj_sr_b_34}yd1tt{0upt04lbmbu_cnfrj_sr_b_34}yd1tt{0upt04lbmbu_cnfrj_sr_b_34}yd1tt{0upt04lbmbu_cnfrj_sr_b_34}yd1tt{0upt04lbmbu_cnfrj_sr_b_34}yd1tt{0upt04lbmbu_cnfrj_sr_b_34}yd1tt{0upt04lbmbu_cnfrj_sr_b_34}yd1tt{0upt04lbmbu_cnfrj_sr_b_34}yd1tt{0upt04lbmbu_cnfrj_sr_b_34}yd1tt{0upt04lbmbu_cnfrj_sr_b_34}yd1tt{0upt04lbmbu_cnfrj_sr_b_34}yd1tt{0upt04lbmbu_cnfrj_sr_b_34}yd1tt{0upt04lbmbu_cnfrj_sr_b_34}yd1tt{0upt04lbmbu_cnfrj_sr_b_34}yd1tt{0upt04lbmbu_cnfrj_sr_b_34}yd1tt{0upt04lbmbu_cnfrj_sr_b_34}yd1tt{0upt04lbmbu_cnfrj_sr_b_34}yd1tt{0upt04lbmbu_cnfrj_sr_b_34}yd1tt{0upt04lbmb'
>>> (flag*32)[::17]
'udctf{just_4_b4by_1ntr0_pr0bl3m}udctf{just_4_b4by_1ntr0_pr0bl'
>>> (flag*32)[::17][:32]
'udctf{just_4_b4by_1ntr0_pr0bl3m}'
```

## Solution

```python
#!/usr/bin/env python3

from pwn import *

flag = 'u_cnfrj_sr_b_34}yd1tt{0upt04lbmb'
print((flag*32)[::17][:32]) # udctf{just_4_b4by_1ntr0_pr0bl3m}
```

## Flag
`udctf{just_4_b4by_1ntr0_pr0bl3m}`

smiley 2024/11/10
