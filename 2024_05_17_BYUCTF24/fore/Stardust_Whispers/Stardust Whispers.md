<h1>Stardust Whispers ~ Forensics</h1>

<h2>Solutions</h2>

<p>In this challenge we were given .pcapng file that we were supposed to analyse. There are http requests for getting 9 different images which are shown below - however this was distraction and extracting them didn't give us the flag </p>

```
GET /one.jpeg HTTP/1.1
User-Agent: Wget/1.19.4 (linux-gnu)
Accept: */*
Accept-Encoding: identity
Host: 192.168.1.5:8888
Connection: Keep-Alive

HTTP/1.0 200 OK
Server: SimpleHTTP/0.6 Python/3.8.5
Date: Wed, 22 Nov 2023 04:58:21 GMT
Content-type: image/jpeg
Content-Length: 9575
Last-Modified: Wed, 22 Nov 2023 04:47:15 GMT

......JFIF...............
...
```

<p> However I saw some strange pattern in ICMP requests </p>

```
0000   00 50 56 01 61 9c 00 50 56 01 61 98 08 00 45 00   .PV.a..PV.a...E.
0010   00 54 bd 56 40 00 40 01 ab 95 c0 a8 01 05 08 08   .T.V@.@.........
0020   08 08 08 00 c9 e7 15 d9 00 27 22 8a 5d 65 00 00   .........'".]e..
0030   00 00 ce 55 0b 00 00 00 00 00 10 11 12 13 14 15   ...U............
0040   16 17 18 19 1a 1b 1c 1d 1e 1f 20 21 22 23 24 25   .......... !"#$%
0050   26 27 28 29 2a 2b 2c 2d 2e 2f 30 31 32 33 34 35   &'()*+,-./012345
0060   36 37                                             67
```

<p>I decided to dump the packages first and that was yielding me already some base64 string, and then I adjusted the script to confirm the result </p>


```python
import pyshark
import binascii
import base64

def extract_icmp_payloads(pcap_file):
    payloads = []
    capture = pyshark.FileCapture(pcap_file, display_filter="icmp")
    for packet in capture:
        if 'ICMP' in packet:
            try:
                icmp_layer = packet.icmp
                if hasattr(icmp_layer, 'data'):
                    payload = icmp_layer.data.binary_value
                    if payload not in payloads:  # Avoid duplicate payloads
                        payloads.append(payload)
                        hex_payload = binascii.hexlify(payload)
                        print(f'Timestamp: {packet.sniff_time}, Hex Payload: {hex_payload.decode()}')
            except AttributeError:
                continue
    capture.close()
    return payloads

def decode_and_concatenate_payloads(payloads):
    concatenated_payload = b''.join(payloads)
    print(f'Concatenated Payload (hex): {binascii.hexlify(concatenated_payload).decode()}')
    
    try:
        base64_data = concatenated_payload.decode('ascii')
        ascii_data = base64.b64decode(base64_data).decode('ascii')
        print(f'Base64 to ASCII: {ascii_data}')
    except (binascii.Error, UnicodeDecodeError) as e:
        print(f'Failed to decode as Base64 to ASCII: {e}')

    try:
        hex_data = binascii.hexlify(concatenated_payload).decode('ascii')
        ascii_data = bytes.fromhex(hex_data).decode('ascii')
        print(f'Hex to ASCII: {ascii_data}')
    except (binascii.Error, UnicodeDecodeError, ValueError) as e:
        print(f'Failed to decode as Hex to ASCII: {e}')

def find_base64_like_payload(payloads):
    base64_payloads = []
    for payload in payloads:
        try:
            base64_data = payload.decode('ascii')
            if all(c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=' for c in base64_data):
                print(f'Potential Base64 Payload: {base64_data}')
                base64_payloads.append(payload)
        except UnicodeDecodeError:
            continue
    return base64_payloads

def main():
    pcap_file = 'fun.pcapng'
    
    payloads = extract_icmp_payloads(pcap_file)
    
    if not payloads:
        print("No ICMP payloads extracted.")
    else:
        print(f"Extracted {len(payloads)} payloads.")
        base64_like_payloads = find_base64_like_payload(payloads)
        if base64_like_payloads:
            print(f'Found {len(base64_like_payloads)} Base64-like payload(s).')
            decode_and_concatenate_payloads(base64_like_payloads)
        else:
            print("No Base64-like payload found.")

if __name__ == "__main__":
    main()
```

Result was:

```Potential Base64 Payload: e3RzaF9BZV9uX19pbm9tbm1hdGVkZW59dWVoZGUK
Found 1 Base64-like payload(s).
Concatenated Payload (hex): 6533527a614639425a56397558313970626d3974626d31686447566b5a5735396457566f5a47554b
Base64 to ASCII: {tsh_Ae_n__inomnmateden}uehde

Hex to ASCII: e3RzaF9BZV9uX19pbm9tbm1hdGVkZW59dWVoZGUK
```

That didn't seem like a proper flag `{tsh_Ae_n__inomnmateden}uehde`

I read a quote from docx hint

> As they neared the Hutt-controlled planet of Tatooine, Leia reminded her friend of the essential component of their plan: “Chani,” she said, “remember the silent language of message packets traveling through the galactic network. It’s our path to infiltrating Jabba’s fortress undetected. The key is 4. If you remember your training, think of the database of exploits and the number 18581.”
Chani nodded, her eyes alight with determination. They would pose as traders, their stillsuits concealing vibroblades. Together they wove a web of deception as they skillfully isolated their target within the bustling cantina’s noise. Finally the trap was set. In a final showdown, they fought side by side—Chani’s crysknife clashing with Jabba’s guards, Leia using the Force to disarm her foes. At long last, the Sapho juice was theirs, though they had to change the final ‘K’ to ‘=’ in order to decipher their mission.

I tried replacing `K to =` but that didn't give me the flag, `key = 4` was making me thinking that this is some sort of encryption...

Hanging in cyberchef it happens that it was <a href="https://en.wikipedia.org/wiki/Rail_fence_cipher">Rail Fence Cipher</a> - putting key as `4` and base64 decoded input from `e3RzaF9BZV9uX19pbm9tbm1hdGVkZW59dWVoZGU=` would give us `{Amunet_means_the_hidden_one}` and we have to just prepend `byuctf` which was described in the description of the task:

<b>Flag: byuctf{Amunet_means_the_hidden_one}</b> 

<b>author:</b> [0xhebi](https://github.com/0xhebi)