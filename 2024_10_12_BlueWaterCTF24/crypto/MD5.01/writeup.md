https://ctftime.org/event/2479

# MD5.01 (CRYPTO)

Wow, MD5 is vulnerable! Check this paper: https://eprint.iacr.org/2004/199.pdf.

nc md5-01.chal.bw.ctf.ing 1337

## Analysis

We can see from reading `main.py` that it wants two different inputs that produce the same return value from `md5`.

This function appears to implement the MD5 hash function.

Testing this you can observe that the results do not match those of `md5sum`.

I compared the provided source code in `main.py` to the wikipedia article on MD5 manually and spotted the difference in `II` this way.

However you could also have spotted it by using a differ utility and the provided url:

```diff
$ diff main.py rossetacode.py 
3d2
< # MD5 Implementation from https://rosettacode.org/wiki/MD5/Implementation#Python
16c15
<             16*[lambda b, c, d: c ^ (~b | d)]
---
>             16*[lambda b, c, d: c ^ (b | ~d)]
```

### Note

At the time of writing the code on https://rosettacode.org/wiki/MD5/Implementation#Python does not contain this bug. It is likely that this change was made by the ctf task author although I have no way of knowning either way.

## Producing a Collision

Most people know that MD5 is broken however you cannot simply provide random input and hope for an MD5 collision as the probability of this working is far too low.

Instead you need to implement one of the published attacks that lower the complexity of producing a collision.

There are quite a few pieces of software that will do this for you, and probably a few handy websites too, however the MD5 used by `main.py` is not standard.

Therefore we need to either write something from scratch or modify an existing piece of software to compute the MD5 algorithm in the same way as `main.py`.

## hashclash

Initially I found this project on github:

https://github.com/cr-marcstevens/hashclash

I was able to produce a collision after a few minutes.

However when I tried to modify the source code to have the `~b` change from `main.py` I couldn't quite get it to work.

## fastcoll

I found a copy of something called `fastcoll` on github here:

https://github.com/brimstone/fastcoll

This is much simpler than hashclash and I felt it was more likely I would be able to modify the MD5 implementation to match.

### Patch

I made the following patch:

```diff
diff --git a/main.hpp b/main.hpp
index fd972e4..2e46061 100644
--- a/main.hpp
+++ b/main.hpp
...
@@ -71,7 +71,7 @@ inline uint32 GG(uint32 b, uint32 c, uint32 d)
 inline uint32 HH(uint32 b, uint32 c, uint32 d) 
 {      return b ^ c ^ d; }
 inline uint32 II(uint32 b, uint32 c, uint32 d) 
-{      return c ^ (b | ~d); }
+{      return c ^ (~b | d); }
```

This worked! `fastcoll` reported a collision, and wrote the output to two files, but `md5sum` showed that this was not a valid MD5 collision:

```bash
$ ./fastcoll -o msg1.bin msg2.bin
...
$ md5sum msg*
261c1f9d3a120d23b955b42dc0535876  msg1.bin
8cfd91324404eb789cf7fdcb5142f83a  msg2.bin
```

#### Note

I also commented out some of the boost timer code rather than trying to get it working as that was simpler.

## Solution

1) Use the patched version of `fastcoll` to produce a collision
2) Send the colliding inputs as hex strings to the remote

```python
#!/usr/bin/env python3

from pwn import *
from os import system

system("./fastcoll -o msg1.bin msg2.bin")

m1 = open("msg1.bin", "rb").read().hex()
m2 = open("msg2.bin", "rb").read().hex()

p = remote("md5-01.chal.perfect.blue", 1337)

p.sendlineafter(b"m1 > ", m1.encode())
p.sendlineafter(b"m2 > ", m2.encode())

p.interactive()
```

## Flag
`bwctf{i_never_said_its_the_same_md5_function_:)}`

smiley 2024/10/13
