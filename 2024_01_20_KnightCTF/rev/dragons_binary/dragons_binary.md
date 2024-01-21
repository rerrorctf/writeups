https://ctftime.org/event/2209/

# Dragon's Binary

In the mystical land of Eldoria, a fierce dragon had captured the kingdom's most precious treasure, hiding it behind a magical binary. The bravest knight of the realm, Sir Emeric, known for both sword and wit, embarked on a quest to retrieve the treasure. To succeed, he must reverse the dragon's binary. As Sir Emeric's trusted apprentice in "Dragon's Binary" you are tasked with solving the cipher to reveal the hidden treasure and help vanquish the dragon's spell. Your journey is filled with mystery and danger, where only the sharpest mind can prevail.

Right Passcode is the flag.

## Solution

`0a20080976101999dbaba015dc31eed4cfc3fb05866c100653d4d110ea34f391  dragon.binary`

```
; 0x6e49654d74656c is "letMeIn"
004019a6 MOV RAX,0x6e49654d74656c
; set local_50 equal to "letMeIn"
004019b0 MOV qword ptr [RBP + local_50],RAX
```

We can simply pass `"letMeIn"` to the binary.

```
$ echo -n "letMeIn" | ./dragon.binary 
            / \  //\
    |\___/|      /   \//  \
    /O  O  \__  /    //  | \ \ 
   /     /  \/_/    //   |  \  \  
  @___@'    \/_   //    |   \   \ 
     |       \/_ //     |    \    \ 
     |        \///      |     \     \ 
    _|_ /   )  //       |      \     _\ 
  '/,_ _ _/  ( ; -.    |    _ _\.-~        .-~~~^-.
  ,( -} . ~ .^-     `-.|.-~-.           .~         `.
    `~-'            /  \      ~-. _ .-~      .-~^-.  \
                   (    \`-._ _.-~                 ~-. _ _.-~
                    \.-~    ~                      ~-._ _.-~
                     /.-~                            ~-.
                    \_ _ _.-~                        /\ 
                            ~-._                   _.-~
Dragon's Binary

Enter the passcode: Passcode is correct.
```

## Flag
`KCTF{letMeIn}`
