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
