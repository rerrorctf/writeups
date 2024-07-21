https://ctftime.org/event/2396

# starship (misc)

We've gotten console access to the rogue ship, but there isn't much time left. Hopefully you can figure out how to destroy it... before it's too late

https://cybersharing.net/s/79c7e323d8f328f0

nc starship.chal.imaginaryctf.org 1337

## Analysis

We can see from analysis of `main.py` that the goal is to have the model change its classification of two elements from `enemy` to `friendly`.

We have the ability to insert one new element into the dataset and to retrain the model.

Because the model uses a `KNeighborsClassifier` we achieve this by inserting a new neighbour, that is classified as friendly, between the incoming elements. The model will then predict that the incoming elements are friendly.

Crucially option `4`, namely `check incoming objects`, gives us the raw data for the incoming elements. We can use this construct a new friendly element that is halfway between them.

### What's a KNeighborsClassifier anyway?

A k neighbor classifier attempts to find k elements, in this case 3, that are nearest a point in order to determine what its classification should be.

For example imagine you have a data set of `x, y` coordinates some are `good` and some are `bad`. A `KNeighborsClassifier` trained on this data set will allow you predict whether a element that is not in the data set is `good` or `bad` based on the nearest `n_neighbors=3` points in the data set.

```
10 |                                * (8,10) Good
9  |      * (2,9) Bad
8  |                                    * (9, 8) Good
7  |
6  |
5  |                   * (5,5) Bad
4  |
3  |
2  |   * (1, 2) Bad
1  |
0  |-----------------------------------------
   0   1   2   3   4   5   6   7   8   9   10
```

We can see here how a point near the upper right of the graph would be classified as `good` based on the prevailing classification of its neighbours.

Equally we can see how the insertion of a `bad` point at, for example, `(10,10)` would likely change the classification of points in this region when the model is trained on that dataset and then used to predict the classification.

The dataset used in this challange has more than 2 dimensions but the principle is the same.

## Solution

```python
#!/usr/bin/env python3

from pwn import *

#context.log_level = "debug"
p = remote("starship.chal.imaginaryctf.org", 1337)

p.sendlineafter(b"> ", b"4")

p.readuntil(b"target 1: ")

target1 = p.readline().decode().split("|")[0][:-1].split(",")

p.readuntil(b"target 2: ")

target2 = p.readline().decode().split("|")[0][:-1].split(",")

between = ""
for i in range(9):
    between += f"{(int(target1[i]) + int(target2[i])) // 2},"
between += "friendly"

p.sendlineafter(b"> ", b"42")
p.sendlineafter(b"enter data: ", between.encode())

p.sendlineafter(b"> ", b"2")

p.sendlineafter(b"> ", b"4")

p.readline()
p.readline()

log.success(p.readline().decode()) # ictf{m1ssion_succ3ss_8fac91385b77b026}
```

## Flag
`flag: ictf{m1ssion_succ3ss_8fac91385b77b026}`

smiley 2024/07/21
