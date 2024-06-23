https://ctftime.org/event/2377

#  Thread (rev)

ワ...ワァ...!?

## Analysis

`0x00101415` or `main`:
- Reads 45 characters of input
    - This is the flag
- Widens each char to 4 bytes and writes it to `0x00104140`
    - Such that we have something like `F 0 0 0 L 0 0 0 A 0 0 0` and so on
- Spawns 45 threads, one for each character of the flag
- Compares the array at `0x0x00104140` to the one at `0x00104020`
    - If they are the same the flag we input was correct

`0x00101289`:
- The thread func used by each of the 45 threads
- Each thread works within the same mutex
- Performs one of three operations on each loop
    - If `0` then `* 3`
    - If `1` then `+ 5`
    - If `2` then `^ 0x7f`
- The code uses a value in the array at `0x00104200` for each thread that is initialy zero to influence the operation selection

In summary the operation selection for each thread is roughly as follows:

```c
#include <stdio.h>

int current_op[45];

int main() {
    for (int i = 0; i < 45; i++) {
        printf("[%d] ", i);

        int loop = 0;
        while (loop < 3) {
            int op = (current_op[i] + i) % 3;
            printf(" %d", op);
            current_op[i] = current_op[i] + 1;
            loop = current_op[i];
        }

        printf("\n");
    }

    return 0;
}
```

## Solution

1) Extract the output from `0x0x00104020`
2) Reconstruct the order of operations taken by each thread for each character
3) Specify those operations as a series of z3 constraints resulting in the corresponding value in the output array

```python
#!/usr/bin/env python3

from pwn import *
from z3 import *

N = 45

output = [
    0xa8, 0x8a, 0xbf, 0xa5, 0x2fd, 0x59, 0xde, 0x24,
    0x65, 0x10f, 0xde, 0x23, 0x15d, 0x42, 0x2c, 0xde,
    0x09, 0x65, 0xde, 0x51, 0xef, 0x13f, 0x24, 0x53,
    0x15d, 0x48, 0x53, 0xde, 0x09, 0x53, 0x14b, 0x24,
    0x65, 0xde, 0x36, 0x53, 0x15d, 0x12, 0x4a, 0x124,
    0x3f, 0x5f, 0x14e, 0xd5, 0x0b
]

input = []
for i in range(N):
    input.append(BitVec(f"{i}", 32))

s = Solver()

for i in range(N):
    x = input[i]
    op = 0
    while op < 3:
        new_op = (op + i) % 3
        if new_op == 0:
            x *= 3
        if new_op == 1:
            x += 5
        if new_op == 2:
            x ^= 0x7f
        op = op + 1
    s.add(x == output[i])

s.check()
model = s.model()

flag = ""
for i in range(len(output)):
    flag += chr(int(str(model[input[i]])))

print(flag)

p = process("./thread")

p.sendline(flag.encode())

print(p.readline().decode())
```

## Flag
`FLAG{c4n_y0u_dr4w_4_1ine_be4ween_4he_thread3}`

smiley 2024/06/22
