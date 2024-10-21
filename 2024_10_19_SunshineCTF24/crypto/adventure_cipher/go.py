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

# resonable guesses
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
