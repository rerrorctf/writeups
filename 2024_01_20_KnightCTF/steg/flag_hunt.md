https://ctftime.org/event/2209/

# Flag Hunt

Hunt your way through the challenge and Capture The hidden Flag!!!     

## Solution

`c43922c6a54b1c9cb952b39d57a33f12649b1643080a69605a90cf625ddf6693  chall.zip`

Attempting to unzip the file requires a password.

We can crack the .zip password with `fcrackzip`:

```
$ fcrackzip --use-unzip --dictionary --init-password ./rockyou.txt ./chall.zip


PASSWORD FOUND!!!!: pw == zippo123
```

Unzipping the archive we see that it is mostly .jpg files with 3 non-.jpg files.

```
623ae1290b066e9e624b76b3f3b78ff2e3ed7bc705a79712bb7fcb198d50bb05  key.wav
e3958afaf1fc3ba1160bffbf9b05e26fe93d87e17a5622edf62fe8dbb89f65e3  n0t3.txt
6cb616f52831ec2b894d47ec740e00102b057f37210ec51b9c3edcaebca5c155  nooope_not_here_gotta_try_harder.txt
```

Most of the image files have the following sha256 hash:

```
a534153c1d076fc192540a2be9e7ba24895bd1a8051b0a041136a015f9a84bc9
```

However `img725.jpg` has a different sha256 hash:

```                                                                                           
98603f28780e5dc0ab08e857a4b03bf8ba050f0a8759f559933fcb1cfd6c4c7f
```

`key.wav` contains the sound of morse code.

I converted it to text with the help of `https://capitalizemytitle.com/morse-code-translator/`:

```
-- --- .-. ... . -.-. --- -.. . - --- - .... . .-. . ... -.-. ..- . -.-.-- -.-.--
MORSECODETOTHERESCUE!!
```

We can see a hint to use lowercase in `n0t3.txt`:

```
$ cat n0t3.txt                                                                                                                                
The flag is here somewhere. Keep Searching..

Tip: Use lowercase only
```

We can attempt to see if the unusual .jpg contains anything with `steghide`:

```
$ steghide info ./img725.jpg -p morsecodetotherescue\!\!                
"img725.jpg":
  format: jpeg
  capacity: 8.0 KB
  embedded file "flag.txt":
    size: 47.0 Byte
    encrypted: rijndael-128, cbc
    compressed: yes
```

We can extract the embedded file `flag.txt` as follows:

```
$ steghide extract --stegofile ./img725.jpg -p morsecodetotherescue\!\!
wrote extracted data to "flag.txt".
```
         
## Flag
`KCTF{3mb3d_53cr37_4nd_z1pp17_4ll_up_ba6df32ce}`
