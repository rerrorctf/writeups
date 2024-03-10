https://ctftime.org/event/2179/

# crypto 3 - racing

Played a few rounds didnt fully understand.
They way it works is you input a number from 0 to 5 and them stuff happens.

What caught my attention was what the challenge printed.
```
['C0', 'Y0', 'C1', 'Y1', 'C2', 'Y2', 'C3', 'Y3', 'C4', 'Y4', 'C5', 'Y5'] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] []
['C0', 'Y0', 'C1', 'Y1', 'C2', 'Y2', 'C3', 'Y3', 'Y4', 'C5', 'Y5'] [] [] [] [] [] ['C4'] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] []
1
['C0', 'Y0', 'C1', 'C2', 'Y2', 'C3', 'Y3', 'Y4', 'C5', 'Y5'] ['Y1'] [] [] [] [] ['C4'] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] []
['Y0', 'C1', 'C2', 'Y2', 'C3', 'Y3', 'Y4', 'C5', 'Y5'] ['Y1'] [] ['C0'] [] [] ['C4'] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] [] []
```
It reminded of one of the examples on:
https://www.atredis.com/blog/2023/12/4/a-libAFL-introductory-workshop

You solve a maze using libAFL and its pretty cool to look at. 
Kinda like game of life, you just keeping staring at it try paths out.

So if the game is simple enough you could probably do the same and use stdout to guide the fuzzer.
First what I did was simplify the game to make it easier for the fuzzer.
1. Instead of calling input() a bunch of times just sent it all together once.
2. Parsing the board and deriving how far you got from that was too hard.
  - so remove all that and just print the scores after each round
3. Needed to tell the fuzzer when I found the answer
  - Could do something with stdout or stderr but libAFL has the `CrashFeedback`
  - so just send a SIGSEGV when we find the flag

full changes:
```diff
1c1,2
< import os
---
> #!/usr/bin/env -S python3
> import os, sys, signal
29a31,34
> inp = input()
> inp = inp.rstrip().split(" ")
> __next = 0
> print(inp, file=sys.stderr, flush=True)
31c36
<     printBoard(cpuPlayers, yourPlayers)
---
>     # printBoard(cpuPlayers, yourPlayers)
44c49
<     printBoard(cpuPlayers, yourPlayers)
---
>     # printBoard(cpuPlayers, yourPlayers)
46c51,61
<     x = int(input())
---
>     try:
>         x = int(inp[__next])
> 
>         __next += 1
>         cpu = str(6-cpuPlayers.count(None))
>         player = str(6-yourPlayers.count(None))
>         print(cpu + "|" + player, flush=True)
>         # print(f"{yourScore}|{cpuScore}", file=sys.stderr)
>     except IndexError as e:
>         break
> 
58a74,77
> cpu = cpuScore
> player = yourScore
> print(str(cpu) + "|" + str(player), flush=True)
> print("cpuScore: " + str(cpu) + " | " + "yourScore: " + str(player), file=sys.stderr, flush=True)
60d78
<     print("Congrats on winning! here's your flag")
61a80,81
>     pid = os.getpid()
>     os.kill(pid, signal.SIGSEGV)
```

on the libAFL side I took the code from the maze solver and just changed it.
after a lot of trial and error I got to:
- https://gist.github.com/shafouz/1d2f96289419970c878d84b6bafd35d7

There is a lot of setup in this code. The parts that actually matter are `is_interesting()` and `mutate()`.
These are the from the libAFL interface. 
- mutate() allow the user to control how the input is mutated an is_interesting() processes infomation
and reduces that to a simple yes or no question.

on the code `mutate()` was making sure that the input was only in the form: `num num ...` and 
`is_interesting()` was:
1. Reading stdout from the program.
2. Checking if the cpu score on the last line (final score) was less than 2.
- the idea behind that is given that the final check for the flag needed: `player == 6 and cpu == 0` and
both cpu and player started with 6 points, a lower cpu score would increase the player chance of winning.
  
And it found a solution relatively fast even with 10execs/s.
But it wasn't consistent and when I was trying locally it was not working.
But them I did:
```bash
while true; do echo '2 0 3 3 5 0 2 5 5 4 4 2 3 4 4 2 5 4 2 5 0 4 4 1 4 0 1 1 3 0 5 0 0 1 5 0 5 4 0 5 3 1 4 1 0 5 5 1 1 5 1 5 5 0 0 4 0 1 1 0 1 4 4 3 2 0 1 1 3 3 0 5 3 5 4 0 5 3 5 4 2 5 1 2 2 1 1 1 5 1 3 3 3 5 0 0 3 4 1' | sed 's# #\n#g' | nc 6344f81.678470.xyz 31626 &>> log.txt; done
```

and it worked:
wxmctf{u_won_the_r4c3_0mgGG!!}

https://aflplus.plus/libafl-book/
