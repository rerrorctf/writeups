import secrets
import hmac
import time

# Compare two byte arrays. Take variable time depending on how many bytes are equal.
def insecure_compare(a, b):
    if len(a) != len(b):
        return False
    for i in range(len(a)):
        if a[i] != b[i]:
            return False
        # Simulate time delay per byte comparison
        time.sleep(0.05)
    return True

# Simulate the timing attack by measuring the time it takes to compare bytes of the MAC.
def verify_hmac(user_hmac_hex):
    try:
        user_hmac = bytes.fromhex(user_hmac_hex)
    except ValueError:
        print("Invalid HMAC format. Please enter a hex string.")
        return False

    # Calculate the expected HMAC for the hidden flag message
    expected_hmac = hmac.new(key, flag, digestmod="sha1").digest()
    print(expected_hmac.hex())
    
    # Compare user-provided HMAC to the expected one with timing leak
    if insecure_compare(expected_hmac, user_hmac):
        return True
    else:
        return False



flag = b"UDCTF{REDACTED}"
key = b"REDACTED"
    
def main():
    print("Can you recover the secret message using a side-channel attack?\n")
    s=input("Enter your McGuess (hex):\n>")
    answer = verify_hmac(s)
    print("Warning... this challenge might test your patience as well...")
    # Recover a valid tag
    if (answer):
        print("Here's the flag: %s" % (flag.decode()))
        exit()
    else:
        print("Nope.")
        exit()

if __name__ == "__main__":
    main()