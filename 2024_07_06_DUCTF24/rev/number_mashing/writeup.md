https://ctftime.org/event/2284

# number mashing (crypto)

Mash your keyboard numpad in a specific order and a flag might just pop out!

nc 2024.ductf.dev 30014

## Analysis

The code in the binary roughly decompiles to the following:

```c
int x, y;
scanf("%d %d", &x, &y);
assert(x != 0 && y != 0 && y != 1);
assert(x == (x / y));
```

## Solution

1) Use z3 to solve the for the constraints in the binary
2) Supply the inputs that satisfy the model
3) Wonder if the task was actually trying to teach you something about numbers work

```python
#!/usr/bin/env python3

from pwn import *
from z3 import *

x = BitVec('x', 32) # local_11c
y = BitVec('y', 32) # local_118

s = Solver()

s.add(x != 0)
s.add(y != 0)
s.add(y != 1)
s.add(x == (x / y))

s.check()
m = s.model()

p = remote("2024.ductf.dev", 30014)

p.sendline(f"{m[x].as_long()} {m[y].as_long()}".encode()) # 2147483648 4294967295

p.interactive() # DUCTF{w0w_y0u_just_br0ke_math!!}
```

## Flag
`DUCTF{w0w_y0u_just_br0ke_math!!}`

smiley 2024/07/06
