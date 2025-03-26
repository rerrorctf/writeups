https://ctftime.org/event/2674

# Traces (crypto)

Long ago, a sacred message was sealed away, its meaning obscured by the overlapping echoes of its own magic. The careless work of an enchanter has left behind a flaw—a weakness hidden within repetition. With keen eyes and sharper wits, can you untangle the whispers of the past and restore the lost words?

## Analysis

We can see from the following code that this code encrypts messages using AES in CTR mode but with nonce reuse:

```python
def output_message(self, msg):
    enc_body = self.encrypt(msg.encode()).hex()
    print(enc_body, flush=True)
    sleep(0.001)

def encrypt(self, msg):
    encrypted_message = AES.new(self.key, AES.MODE_CTR, counter=Counter.new(128)).encrypt(msg)
    return encrypted_message
```

This means that if we have any known plaintext for any of the given ciphertext that we can recover a portion of the keystream for all of the ciphertexts.

The task presents something like an IRC server.

Join "#general" and you will see a bunch of ciphertext encrypted with `encrypt`.

We can see from the following code that before people can talk in a channel they must provide "!nick " followed by their nickname:

```python
warn('You must set your channel nickname in your first message at any channel. Format: "!nick <nickname>"')
```

This means that if we know the nickname that a user input that we have a good chunk of known plaintext.

We can see from the output that user "Runeblight" has the longest name and they wrote something in the third message. If we guess that its "!nick Runeblight" we can then try to recover the first 16 bytes of the keystream as follows:

```python
p.readuntil(b"<Runeblight> : ")
c = bytes.fromhex(p.readline().decode())
k = xor(b"!nick Runeblight", cc)
print(f"{k.hex() = }")
```

If this guess was correct - which it is - we can now recover the first 16 bytes of plaintext from every message for which we have ciphertext.

The keystream can now be extended by crib dragging. That is by making educated guesses about the plaintext of messages and trialing them in keystream recover we can slowly extend our keystream.

For example if we saw a message like "I'll com" we can guess that the plaintext is actually "I'll compare " and if we guessed correctly we can recover an additional 5 bytes of the keystream.

If you guess incorrectly its very likely that most of the other messages will look nonsensical (or contain non-printable bytes in the resulting plaintext in the context of ascii strings in a chat app).

For more information on crib dragging (and known-plaintext attacks in general) see https://en.wikipedia.org/wiki/Known-plaintext_attack.

## Solution

1) Join #general and read a bunch of ciphertexts
2) Recover the start of the keystream by using known-plaintext
3) Crib drag to extend the keystream
4) Recover the password from one of the messages
5) Use the password to join #secret
6) Crib drag to extend the keystream
7) Recover the flag from one of the messages

```python
#!/usr/bin/env python3

from pwn import *

#context.log_level = "debug"

#p = elf.process(["venv/bin/python3", "./server.py"])
p = remote("83.136.250.101", 30375)

p.sendline(b"join #general")

p.readuntil(b"<Doomfang> : ")
c1 = bytes.fromhex(p.readline().decode())
k1 = xor(b"!nick Doomfang", c1)
print(f"{k1.hex() = }")

p.readuntil(b"<Stormbane> : ")
c2 = bytes.fromhex(p.readline().decode())
k2 = xor(b"!nick Stormbane", c2)
print(f"{k2.hex() = }")

p.readuntil(b"<Runeblight> : ")
c3 = bytes.fromhex(p.readline().decode())
k3 = xor(b"!nick Runeblight", c3)
print(f"{k3.hex() = }")

cs = []

for i in range(18):
    p.readuntil(b" : ")
    c = bytes.fromhex(p.readline().decode())
    cs.append(c)

known_plaintext = b"I'll compare the latest data with "
known_plaintext = b"Hold on. I\'m seeing strange signals from "
known_plaintext = b"Agreed. Move all talks to the private room "
known_plaintext = b"Here is the passphrase for our secure channel "
known_plaintext = b"Got it. Only share it with our most trusted allies "
known_plaintext = b"Understood. Has there been any sign of them regrouping since"
known_plaintext = b"We've got a new tip about the rebels. Let's keep our chat private."
known_plaintext = b"This channel is not safe for long talks. Let's switch to our private room"
known_plaintext = b"Agreed. Move all talks to the private room. Runeblight, please clear the logs"
known_plaintext = b"Not yet, but I'm checking some unusual signals. If they sense us, we might have "
known_plaintext = b"Understood. I'm disconnecting now. If they have seen us, we must disappear immediately."

k4 = xor(known_plaintext, cs[14])

for i in range(len(cs)):
    c = cs[i]
    ##print(i, c.hex())
    #print(i, xor(c, k4[:len(c)]))

password = xor(k4[:len(cs[4])], cs[4])[47:]
print(f"{password = }")

p.sendline(b"!nick smiley")

p.sendline(b"!leave")

p.clean()

###

p.sendline(b"join #secret " + password)

p.readuntil(b"<Runeblight> : ")
c3 = bytes.fromhex(p.readline().decode())
k3 = xor(b"!nick Runeblight", c3)
print(f"{k3.hex() = }")

cs2 = []

for i in range(13):
    p.readuntil(b" : ")
    c = bytes.fromhex(p.readline().decode())
    cs2.append(c)

known_plaintext = b"Exactly. And even if "
known_plaintext = b"I'm already cross-checking "
known_plaintext = b"Agreed. The enemy's scouts grow more persistent. If they catch even a whisper of our designs, they "
known_plaintext = b"We should end this meeting and move to a more secure sanctum. If their mages or spies are closing in "
known_plaintext = b"Yes, but we must treat it only as a last resort. If we activate it too soon, we risk revealing its location "
known_plaintext = b"We should keep our planning here. The outer halls are not secure, and too many eyes watch the open channels"
known_plaintext = b"I've been studying the traces left behind by our previous incantations, and something feels wrong. Our network "
known_plaintext = b"We should end this meeting and move to a more secure sanctum. If their mages or spies are closing in, they may"
known_plaintext = b"Good. No record of it must exist in the written tomes. I will ensure all traces are erased, and it shall never "
known_plaintext = b"I'm already cross-checking our spellwork against the ancient records. If this beacon was part of an older enchantment "
known_plaintext = b"We should end this meeting and move to a more secure sanctum. If their mages or spies are closing in, they may intercept our "
known_plaintext = b"Exactly. And even if we remain unseen for now, we need contingency plans. If the Council fortifies its magical barriers, we could lose access "
known_plaintext = b"Good. No record of it must exist in the written tomes. I will ensure all traces are erased, and it shall never be spoken of openly. If the enemy " # 7
known_plaintext = b"Agreed. The more we discuss it, the greater the risk. Every moment we delay, the Council strengthens its defenses. We must act soon before our window of opportunity closes" # 8
known_plaintext = b"We cannot afford hesitation. If this is a breach, then the High Council's forces may already be on our trail. Even the smallest mistake could doom our entire campaign. We must " # 4
known_plaintext = b"I'm already cross-checking our spellwork against the ancient records. If this beacon was part of an older enchantment, I'll find proof. But if it is active now, then we have a problem " # 3

k4 = xor(known_plaintext, cs2[3])

for i in range(len(cs2)):
    c = cs2[i]
    print(i, xor(c, k4)[:len(c)])

flag = xor(k4, cs2[6])[127:127+53]
print(flag.decode()) # HTB{Crib_Dragging_Exploitation_With_Key_Nonce_Reuse!}
```

## Flag
`HTB{Crib_Dragging_Exploitation_With_Key_Nonce_Reuse!}`

smiley 2025/03/22
