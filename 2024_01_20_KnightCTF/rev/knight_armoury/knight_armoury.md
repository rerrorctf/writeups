https://ctftime.org/event/2209/

Knight Armoury

In a realm where magic and technology merge, lies the Knight Armoury, home to the legendary "Sword of Bytes." Forged by Knight Squad, this digital sword holds immense power. Your mission: reverse the ancient binary guarding the Armoury and claim the sword to become the protector of the digital kingdom. Only the wisest and most skilled in reverse engineering can succeed. Are you ready to embark on this epic journey?

Solution

```
pwndbg> n
0x0000000000401cf4 in ?? ()
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
──────────────────────────────────────────────────────────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]───────────────────────────────────────────────────────────────────────────────
*RAX  0x0
 RBX  0x7fffffffdf78 —▸ 0x7fffffffe2ff ◂— 'SHELL=/bin/bash'
*RCX  0x59
 RDX  0x0
 RDI  0x7fffffffdde0 ◂— 0x74736574 /* 'test' */
*RSI  0x4c20b0 ◂— 'YqCqAdywxj'
 R8   0x0
 R9   0xa
 R10  0xffffffffffffffff
 R11  0x0
 R12  0x7fffffffdf68 —▸ 0x7fffffffe2da ◂— '/home/knight2024/Downloads/knight_armoury'
 R13  0x1
 R14  0x4be2e8 —▸ 0x401800 ◂— endbr64 
 R15  0x1
 RBP  0x7fffffffde50 ◂— 0x1
 RSP  0x7fffffffdde0 ◂— 0x74736574 /* 'test' */
*RIP  0x401cf4 ◂— test eax, eax
───────────────────────────────────────────────────────────────────────────────────────[ DISASM / x86-64 / set emulate on ]────────────────────────────────────────────────────────────────────────────────────────
   0x401cde    mov    eax, 0
   0x401ce3    call   0x405040                      <0x405040>
 
   0x401ce8    lea    rax, [rbp - 0x70]
   0x401cec    mov    rdi, rax
   0x401cef    call   0x401a5e                      <0x401a5e>
 
 ► 0x401cf4    test   eax, eax
   0x401cf6    je     0x401d6d                      <0x401d6d>
    ↓
   0x401d6d    lea    rax, [rip + 0x92695]
   0x401d74    mov    rdi, rax
   0x401d77    call   0x412830                      <0x412830>
 
   0x401d7c    mov    eax, 0
```

If we breakpoint on `test eax, eax` which is the return address of `call  0x401a5e`; just a little bit later after we are prompted for the `pass key`, we can see some weird string at $RSI register `*RSI  0x4c20b0 ◂— 'YqCqAdywxj'`

`YqCqAdywxj` is the the correct pass key and we can supply that as input to retrieve the flag.

flag: `KCTF{kN1gHT_aRm0uRy_aCC3ss_GranTed}`
