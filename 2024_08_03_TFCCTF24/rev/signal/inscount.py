#!/usr/bin/env python3

import string
from pwn import *

PIN             = "/opt/pin/pin"
INSCOUNT2_MT_SO = "/opt/pin/source/tools/SimpleExamples/obj-intel64/inscount2_mt.so"
BINARY          = "./signal"

flag = b""
#flag = b"b11e800000b27dcf82e70c4bad63a3eb"

while True:
	highest_count = 0
	best_byte = b"\x00"
	for c in "10fedcba98765432":
		b = c.encode()
		with process(argv=[PIN, "-t", INSCOUNT2_MT_SO, "--", BINARY, flag + b], level="CRITICAL") as p:
			lines = p.recvall().split(b"\n")

			count = 0
			for line in lines:
				if b"Count[" in line:
					count += int(line.split(b" = ")[1])

			if count > highest_count:
				highest_count = count
				best_byte = b
	flag += best_byte
	log.success(flag.decode())
