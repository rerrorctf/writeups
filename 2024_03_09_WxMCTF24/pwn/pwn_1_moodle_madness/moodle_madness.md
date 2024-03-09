https://ctftime.org/event/2179/

# WxMCTF '24 Pwn 1 - Moodle Madness - PWN

It recently came to light from an anonymous source that "Moodle," the math assignment program made famous by Ms. Gugoiu, has an exploit to see the answers to questions. Buddhathe18th, always reluctant to do homework, decided to investigate this exploit himself for the notorious 3.2 STACK Part 2 Challenge. He vaguely recalls that it involves inputting a string into the answer box, but with 1 hour left, he needs some help. Could you help him find the exploit?

## Solution

```
$ file ./moodle 
./moodle: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=29daf9cad61702f11a472b1cd65d493b239e3d83, for GNU/Linux 3.2.0, not stripped
```

`d2f6c75e13375d754e8ee747958664cfe4725252c526a9cc048bd54666722075  ./moodle`

```
$ strings ./moodle 
cmxw    H
m{ft    H
ld00    H    
4m_3    H
r3t5    H  
dn1m    H  
}!!!    H
```

## Flag
`wxmctf{m00dl3_m45t3rm1nd!!!}`
