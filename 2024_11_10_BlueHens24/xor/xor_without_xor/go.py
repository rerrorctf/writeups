#!/usr/bin/env python3

from pwn import *

flag = 'u_cnfrj_sr_b_34}yd1tt{0upt04lbmb'
print((flag*32)[::17][:32]) # udctf{just_4_b4by_1ntr0_pr0bl3m}
