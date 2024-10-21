https://ctftime.org/event/2485

# Adventure Cipher (crypto)

Can you crack Sir Alaric's message?

Note: The alphabet is abcdefghijklmnopqrstuvwxyz_<space>{} (where <space> is " ")

## Analysis

Inside `letter.txt` we can see a lot of capitalized words repeating.

We can see that there are 30 unique words within the letter with the following code:

```python
from string import ascii_uppercase

with open("letter.txt", "r") as f:
    letter = f.read()

words = {}

for word in letter.split(" "):
    if len(word) < 1:
        continue
    if word[0] not in ascii_uppercase:
        continue
    words[word] = words.get(word, 0) + 1

sorted_words = sorted(words, key=words.get, reverse=True)
print(len(sorted_words)) # 30
```

This matches the number of symbols in the given alphabet i.e. 26 letters + _ + space + { + } gives us 30 symbols.

At this point it seems likely that each word within the letter relates to one of these 30 symbols.

With the following code we can see which words occur most frequently:

```python
from string import ascii_uppercase

with open("letter.txt", "r") as f:
    letter = f.read()

words = {}

for word in letter.split(" "):
    if len(word) < 1:
        continue
    if word[0] not in ascii_uppercase:
        continue
    words[word] = words.get(word, 0) + 1

sorted_words = sorted(words, key=words.get, reverse=True)

for word in sorted_words:
    print(word, words[word])
```

This prints the following output:

```
Ridge 701
Pilgrimage 421
Escapade 329
Voyage 295
Wanderlust 231
Venture 230
Exploration 224
Adventure 199
Wander 198
Pathway 190
Trek 150
Quest 146
Migration 109
Expedition 82
Pursuit 78
Trail 74
Journey 72
Passage 69
Odyssey 69
Traverse 53
Travel 51
Field 33
Crossing 21
Survivor 11
Roaming 6
Sojourn 4
Bridge 4
Discovery 2
River 1
Valley 1
```

We can make the following observerations from this data:

1) `Ridge` likely relates to the the space symbol
    - This is because in English we expect the space symbol to occur around twice as often as the most frequent letter
2) `River` and `Valley` are likely `{` and `}` although we do not know which is which yet
    - This is because we know the letter contains a flag of the format `sun{.+}` and it is possible but unlikely for these characters to occur elswhere in the plaintext
3) `Pilgrimage` is quite likely to be the letter `e`
    - This is because `e` is the most commonly occurring letter in English

Going back to `letter.txt` we can see that `River` occurs before `Valley`. This means that `River` is most likely `{` and `Valley` is most likely `}`.

We can make an interesting observation that `Bridge` only occurs within `River` and `Valley` - that is within the flag - it seems likely that this is `_` as a result. I think it is reasonable to conclude that `_` is quite unlikely to occur in a letter outside of a flag.

We can also assume, since we know the flag format is `sun{.+}` that the three words before `River`, namely `Venture`, `Migration` and `Exploration`, correspond to `s`, `u` and `n`.

At this point we have a strong guess for 7 of the 30 symbols.

In order to progress further I performed bigram frequency analysis. That is looking at the frequency of pairs of symbols in the ciphertext and relating them to pairs of letters in English.

```python
bigrams = {}

prev_word = ""
for word in letter.split(" "):
    if len(word) < 1:
        continue
    if word[0] not in ascii_uppercase:
        continue
    if word == "Ridge":
        continue

    if prev_word != "":
        bigram = prev_word + " " + word
        bigrams[bigram] = bigrams.get(bigram, 0) + 1

    prev_word = word

sorted_bigrams = sorted(bigrams, key=bigrams.get, reverse=True)

freq_bigrams = ["th", "he", "in", "er", "an", "re", "on", "at", "en", "nd"]

for bigram, letters in zip(sorted_bigrams[:len(freq_bigrams)], freq_bigrams):
    print(bigram, letters)
```

This makes it easier to assign `t` to `Escapade` and `h` to `Adventure` as this forms the word `the` at the start of various paragraphs and sentences within the interim plaintext.

The goal now is to try to fill in all of the 2 and 3 letter words such that they make sense and to snag any obvious words with unusual letters.

I quickly noticed the word `esteemed` without `m` and `d` at the start of the letter. This allowed me to bind `m` and `d` with some confidence.

At this point I simply worked through the rest of the symbols assigning reasonable guesses and checking if the resulting plaintext made more sense until I had assigned each symbol a letter of the alphabet.

## Solution

```python
#!/usr/bin/env python3

from pwn import *
from string import ascii_uppercase
from re import search

with open("letter.txt", "r") as f:
    letter = f.read()

words = {}

for word in letter.split(" "):
    if len(word) < 1:
        continue
    if word[0] not in ascii_uppercase:
        continue
    words[word] = words.get(word, 0) + 1

sorted_words = sorted(words, key=words.get, reverse=True)

freq = "etaoinshrdlcumwfgypbvkjxqz"

#for x, y in zip(sorted_words, freq):
#    print(x, y)

bigrams = {}

prev_word = ""
for word in letter.split(" "):
    if len(word) < 1:
        continue
    if word[0] not in ascii_uppercase:
        continue
    if word == "Ridge":
        continue

    if prev_word != "":
        bigram = prev_word + " " + word
        bigrams[bigram] = bigrams.get(bigram, 0) + 1

    prev_word = word

sorted_bigrams = sorted(bigrams, key=bigrams.get, reverse=True)

freq_bigrams = ["th", "he", "in", "er", "an", "re", "on", "at", "en", "nd"]

#for bigram, letters in zip(sorted_bigrams[:len(freq_bigrams)], freq_bigrams):
#    print(bigram, letters)

# known plaintext
letter = letter.replace("Bridge", "_") # Bridge occurs only within River and Valley
letter = letter.replace(" Venture", " s")
letter = letter.replace("Migration", "u")
letter = letter.replace("Exploration", "n")
letter = letter.replace("River", "{") # River occurs before valley
letter = letter.replace("Valley", "}") # Valley occurs after River

# Ridge is most likely space as it occurs twice as frequently as e
letter = letter.replace("Ridge", "/")

# reasonable guesses
letter = letter.replace("Escapade", "t")
letter = letter.replace("Adventure", "h")
letter = letter.replace("Pilgrimage", "e")
letter = letter.replace("Wanderlust", "i")
letter = letter.replace("Wander", "o")
letter = letter.replace("Passage", "m")
letter = letter.replace("Travel", "y")
letter = letter.replace("Quest", "d")
letter = letter.replace("Trail", "f")
letter = letter.replace("Voyage", "a")
letter = letter.replace("Field", "v")
letter = letter.replace("Crossing", "k")
letter = letter.replace("Pathway", "r")
letter = letter.replace("Journey", "g")
letter = letter.replace("Traverse", "p")
letter = letter.replace("Trek", "l")
letter = letter.replace("Expedition", "c")
letter = letter.replace("Odyssey", "b")
letter = letter.replace("Pursuit", "w")
letter = letter.replace("Sojourn", "j")
letter = letter.replace("Survivor", "z")
letter = letter.replace("Roaming", "x")
letter = letter.replace("Discovery", "q")

flag = search(r"s u n {.+}", letter).group().replace(" ", "")
print(flag) # sun{the_almighty_alaric_and_blaze}
```

## Flag
`sun{the_almighty_alaric_and_blaze}`

smiley 2024/10/20
