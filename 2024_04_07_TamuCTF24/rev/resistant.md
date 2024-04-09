https://ctftime.org/event/2238/

<h1> Resistant ~ Rev </h1>

<p>All these RE challenges are just too easy! So what happens when the binary fights back?</p>

<h1>Reversing part</h1>

<p>In this challenge we are given 64 bit ELF binary. If we run this binary it will prompt us for a password. Disassembling it in IDA we can see some interesting decompiled C code.</p>

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  setvbuf(stdin, 0LL, 2, 0LL);
  setvbuf(stdout, 0LL, 2, 0LL);
  setvbuf(stderr, 0LL, 2, 0LL);
  prctl(4, 0LL);
  if ( (unsigned __int8)check_debug() != 1 )
  {
    mprotect((void *)((unsigned __int64)&auth & 0xFFFFFFFFFFFFF000LL), auth_len + ((unsigned __int64)&auth & 0xFFF), 7);// rwx
    decrypt_func(&auth, (unsigned int)auth_len);
    mprotect((void *)((unsigned __int64)&auth & 0xFFFFFFFFFFFFF000LL), auth_len + ((unsigned __int64)&auth & 0xFFF), 5);// rx
    ((void (*)(void))auth)();
    ptrace(PTRACE_KILL, 0LL, 0LL, 0LL);
  }
  return 0;
}
```

<p> This already looked interesting, first we have:</p>

The `prctl(4, 0LL)` system call , with two arguments 4 and 0; 4 stands for `PR_SET_DUMPABLE` , when `PR_SET_DUMPABLE` is set to 0 this means it will be non-dumpable, e.g if process crashes no core dump file is generated.
If we take a look at that `check_debug()` function, we can see that there are some more anti-debugging techniques.

```c
__int64 check_debug()
{
  if ( ptrace(PTRACE_TRACEME, 0LL, 0LL, 0LL) )
  {
    fwrite("Debugger detected!\n", 1uLL, 0x13uLL, stderr);
    ptrace(PTRACE_KILL, 0LL, 0LL, 0LL);
    exit(0);
  }
  return 0LL;
}
```

The process calls `ptrace()` with the `PTRACE_TRACEME` flag, which is a request to allow the process to be traced, since there was `prctl(4,0)` before check_debug(), any subsequent call to `ptrace` would fail because the process is not dumpable. It will reach `exit(0)` and end the process - so all in all this would "prevent" us from attaching debugger.

If we get back to the `main()` function we can see there are calls to `mprotect()` for setting up permissions of the page(s) where `.auth` section is located to `rwx` and later to `rw`. In between those two calls we have a call to `decrypt_func(&auth, auth_len)` which takes an address of a section and its length and it does byte XORing against 16 bytes `func_key`.

```c
__int64 __fastcall decrypt_func(__int64 a1, int a2)
{
  __int64 result; // rax
  unsigned __int64 i; // [rsp+14h] [rbp-8h]

  for ( i = 0LL; ; ++i )
  {
    result = a2;
    if ( i >= a2 )
      break;
    *(_BYTE *)(a1 + i) ^= func_key[i & 0xF];
  }
  return result;
}
```

Checking what is at `auth` in IDA View:

```.auth:00000000000017F9 ; __unwind {
.auth:00000000000017F9                 cmp     [rsi], edx
.auth:00000000000017FB                 scasb
.auth:00000000000017FD                 and     eax, 703CAD7Bh
.auth:0000000000001802                 fcmovnu st, st(1)
.auth:0000000000001804                 insd
.auth:0000000000001805                 mov     bh, 53h ; 'S'
.auth:0000000000001805 ; ---------------------------------------------------------------------------
.auth:0000000000001807                 db 9Ah
.auth:0000000000001808                 dq 0A9C9950E4C166CFBh, 450C1966B801ACF4h, 9E13BFDA7F168B6Ch
.auth:0000000000001820                 dq 2A3E1B21DF94A9B0h, 1434D5037D0BE5B3h, 20337F4C7ECE3E73h
.auth:0000000000001838                 dq 4ADEE8E43023826Eh, 522E1B2192D69DF4h, 21F86D4C085BE1B3h
.auth:0000000000001850                 dq 727B9269522BD335h, 0C9BDE0033AA195CFh, 5CF2DA6952930406h
.auth:0000000000001868                 dq 9086854BC55E6C44h, 9A5C0D7CD9DBEB43h, 96079232C0D324FBh
. . .

.auth:00000000000019B0 ; } // starts at 17F9
.auth:00000000000019B0 _auth           ends
```
Could make an assumption that those are encrypted opcodes that will be decrypted at the runtime by that `decrypt_func()`, however there was another similar section called `.dec`. 

Checking strings didn't give me any XREF's so I was assuming that those strings are part of encrypted code either in `.auth` or `.dec` section.

<h1>Solution</h1>

There are multiple ways of bypassing this anti debugging technique, patching was most straight forward. Did it straight inside the gdb by changing instruction in `check_debug()` 

`jz      short loc_141B`

We will bypass the check and go into the branch where there is no `exit()` syscall. From ths point its straight forward gdb grind. At one point decrypted auth code is calling `memcmp()`

``` ► 0x55555555591e <auth+293>    call   memcmp@plt                <memcmp@plt>
        s1: 0x7fffffffdd90 ◂— xor byte ptr [rbp + r10*2 + 0x72], r14b /* 0x6d304d725574304e; 'N0tUrM0msP4sswd!AAAAAA\n' */
        s2: 0x7fffffffdda0 ◂— or al, byte ptr [r8] /* 0xa414141414141; 'AAAAAA\n' */
```

My input was just `AAAAAA`, but that `N0tUrM0msP4sswd!` was worth a check, since we were supposed to check this remotely it seems it actually gave a flag:

```[+] Opening connection to tamuctf.com on port 443: Done
[DEBUG] Sent 0x11 bytes:
    b'N0tUrM0msP4sswd!\n'
[+] Receiving all data: Done (51B)
[DEBUG] Received 0x10 bytes:
    b'Input password: '
[DEBUG] Received 0x23 bytes:
    b'gigem{a_b4ttl3_4_th3_hist0ry_b00ks}'
[*] Closed connection to tamuctf.com port 443
```

<b>Flag: gigem{a_b4ttl3_4_th3_hist0ry_b00ks} </b>


Author: https://github.com/0xhebi