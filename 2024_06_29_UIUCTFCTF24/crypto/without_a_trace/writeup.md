https://ctftime.org/event/2275

# Without a Trace (crypto)

Gone with the wind, can you find my flag?

ncat --ssl without-a-trace.chal.uiuc.tf 1337

## Solution

The task works something like this:

1) The flag is broken up into 5 numbers along the diagonal of one matrix.
2) The user supplied matrix is multiplied by the flag matrix
3) The server turns to us the sum of the elements along the diagonal, also known as the trace

The soultion works like this:

1) Recognise that if we supply the identiy matrix, that is the matrix with 1s along the diagonal, that we get back the sum of the 5 elements that flag was broken up into
2) Recognise that if we double just one of these values, by supplying a matrix where 4 of the elements are 1 and one is 2, we can subtract the initial trace to recover that section of the flag.
3) Collect five such traces and subtract the initial trace from each to recover the flag.

```python
#!/usr/bin/env python3

from pwn import *

traces = []

for i in range(6):
    with remote("without-a-trace.chal.uiuc.tf", 1337, ssl=True) as p:
        if i == 1:
             p.sendlineafter(b"u1 = ", b"2")
        else:
            p.sendlineafter(b"u1 = ", b"1")

        if i == 2:
             p.sendlineafter(b"u2 = ", b"2")
        else:
            p.sendlineafter(b"u2 = ", b"1")

        if i == 3:
             p.sendlineafter(b"u3 = ", b"2")
        else:
            p.sendlineafter(b"u3 = ", b"1")

        if i == 4:
             p.sendlineafter(b"u4 = ", b"2")
        else:
            p.sendlineafter(b"u4 = ", b"1")

        if i == 5:
             p.sendlineafter(b"u5 = ", b"2")
        else:
            p.sendlineafter(b"u5 = ", b"1")

        p.readuntil(b"Have fun: ")
        trace = int(p.readline().decode())

        traces.append(trace)

flag = b""
for i in range(5):
    flag += (traces[i + 1] - traces[0]).to_bytes(length=5, byteorder="big")

print(flag.decode()) # uiuctf{tr4c1ng_&&_mult5!}
```

## Flag
`uiuctf{tr4c1ng_&&_mult5!}`

smiley 2024/06/30
