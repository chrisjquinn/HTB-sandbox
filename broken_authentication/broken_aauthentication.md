# Broken Authentication

## Intro stuff

Recalling the three domains of authentication (knows,is,has) and the module works on form based HTTP authentication. It is authentication not authorization. 

CIRT has a db for [default passwords](https://www.cirt.net/passwords). SecLists has a good list based on cirt.net. Good idea to check both lists. 

SCADA also put the hardcoded passwords list into github. See [SCADAPASS](https://github.com/scadastrangelove/SCADAPASS)

## Default Credentials
As a warm up they have a [python file]() and [PHP File](). It was fiddly getting the first part done, as the python script they gave was not built for the box that was running. Changing this worked. It is also a simple script too that you could build. Solved doing a search and using the default credentials for the advantech HMI webacess etc.

## Weak Bruteforce Protections
Many of them, but two listed on HTB are CAPTCHA and Rate Limits. 

### CAPTCHA
CAPTCHA comes in many flavors, some are quite stupid too once we look into the HTML. E.g. the result could be in its own form or jpg tag:

```html
<img id="7xefD6" src="captcha.jpg">
```

as an attacker, read the page source. 


### Rate Limiting
See in the HTML a warning with how many seconds. You deal with RLs in assassin by handling the 429s. Another python file has been supplied by HTB to deal with this, does a `time.sleep()`

### Other weak protections - IP
On the second part of the question it was fiddly from the python file provided. Edits were done to change the URL, form parameters and add in a header of:
```python
headers = {
  "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.96 Safari/537.36",
  "X-Forwarded-For": "127.0.0.1"
}
```

And then worked, simply adding in this header. No usr/auth really needed to attempt


## Brute Forcing Usernames
Username enumeration overlooked - it is treated like a public account, like an email, people think it is used to communicate with others. 

There is a trade-off in UX vs. security when revealing if a username already exists, allows for attack. 

### User Unknown Attack
You could carry out a bruteforce attack when the difference of an unknown vs. known username in the errors spat out on the page. wfuzz can then run a string match using the `-hs` flag:

```bash
wfuzz -c -z file,/opt/useful/SecLists/Usernames/top-usernames-shortlist.txt -d "Username=FUZZ&Password=dummypass" --hs "Unknown username" http://brokenauthentication.hackthebox.eu/user_unknown.php
```

### Username Existence Interference
This is where there might be no explicit error message, but might be able to infer via another subtle way. Say, the form input has changed to be pre-filled when we tried `admin` for a username. There may also be cookies getting set in the browser. Inspect HTTP headers and the source code.

Question 2 shown this in the source code response where `wronguser` was in the source code, but `validuser` was shown when we tried the username of `ansible`

### Timing Attack
Some web apps have flaws by design, one is where username and password are checked sequentially. Example given by HTB is some php:

```php
<?php
// connect to database
$db = mysqli_connect("localhost", "dbuser", "dbpass", "dbname");

// retrieve row data for user
$result = $db->query('SELECT * FROM users WHERE username="'.safesql($_POST['user']).'" AND active=1');

// $db->query() replies True if there are at least a row (so a user), and False if there are no rows (so no users)
if ($result) {
  // retrieve a row. don't use this code if multiple rows are expected
  $row = mysqli_fetch_row($result);

  // hash password using custom algorithm
  $cpass = hash_password($_POST['password']);
  
  // check if received password matches with one stored in the database
  if ($cpass === $row['cpassword']) {
	echo "Welcome $row['username']";
  } else {
    echo "Invalid credentials.";
  } 
} else {
  echo "Invalid credentials.";
}
?>
```


Question 3 in the excercise is a timing attack. Will run locally using the file of `timing.py`. It was quite robust, so running it a few times helped figure out which one to try. 

### Enumerate through Password Reset
Differences in the messaging when requesting a password reset will give us clues e.g. "You should recieve a message shortly" vs. "Username unknown"

### Enumerate through Registration Form
Copy-pasted, quite interesting:
> One interesting feature of email addresses that many people do not know or do not have ready in mind while testing is sub-addressing. This extension, defined at [RFC5233](https://datatracker.ietf.org/doc/html/rfc5233), says that any +tag in the left part of an email address should be ignored by the Mail Transport Agent (MTA) and used as a tag for sieve filters. This means that writing to an email address like student+htb@hackthebox.eu will deliver the email to student@hackthebox.eu and, if filters are supported and properly configured, will be placed in folder htb. Very few web applications respect this RFC, which leads to the possibility of registering almost infinite users by using a tag and only one actual email address.


## Brute Forcing Passwords
Links to the top most passwords and a [table](https://en.wikipedia.org/wiki/List_of_the_most_common_passwords#SplashData). Credential Stuffing - taking stolen creds and trying to login to other services on the basis that they are reused. 

### Policy Inference
Knowing the compliant search space means we can test compliant passwords. This can be scoped when registering a new user or on the 'forgot password' flow. 

If we have no disclosure, then we can start with a complex password and then work down the families, making a matrix. 

Tried Password  Lower Upper Digit Special >=8chars  >=20chars
Yes/No  qwerty  X         
Yes/No  Qwerty  X X       
Yes/No  Qwerty1 X X X     
Yes/No  Qwertyu1  X X X   X 
Yes/No  Qwert1! X X X X   
Yes/No  Qwerty1!  X X X X X 
Yes/No  QWERTY1   X X     
Yes/No  QWERT1!   X X X   
Yes/No  QWERTY1!    X X X X 
Yes/No  Qwerty! X X   X   
Yes/No  Qwertyuiop12345!@#$%  X X X X X X

We can then find out what the brute-force space is and tailor a list from a big one, like `rockyou.txt`. `grep` comes in handy here:
```bash
grep '[[:upper:]]' rockyou.txt | grep '[[:lower:]]' | grep -E '^.{8,12}$'
```
Will find ones with at least one uppercase, one lowercase (at least one) and a lenfth of 8 & 12 characters using the extended regular expressions. 


Excercise, using rockyou-50.txt. 
Used burp to run the various passwords, I think I could have also used wfuzz or FUFF too here. It was from using the type of `batteringram` in burp that repeated the same payload positions. I guess FUFF is better here for combining different keywords. 


Looks like `Qwerty1` - actually `QWERT1` worked which is the smallest search space and we can run a filter on:
1. At least 6 letters
2. All upper letters, no lowercase
3. 1 Number


Using wfuzz then shown that there is some login failures. So, lets use the python file. Edited the python file, but it did not manage to catch `ANGEL1` for some reason. It was achieved through some chatgpt along with trying a couple on my own in burp repeater. Luckily, there were only a few shown. 

Grep to created the filtered file was:
```bash
grep -E '\b[A-Z]+[0-9]+[A-Z0-9]*\b` rockyou.txt > rockyou-filt.txt
```


## Predictable Reset Token
When an application sends for a reset of password token, sometimes there are security questions, but the token is sent to some sort of ID. Token generation should be robust, frameworks have been built for this purpose. Devs introduce their own which can have logic flaws.


### Weak Token Generation
Some apps use predictable or known values, which is not needed to validate a user. We could try to brute force any weak hash using known combos of time_username or time_email. This shitty php code for example:

```php
<?php
function generate_reset_token($username) {
  $time = intval(microtime(true) * 1000);
  $token = md5($username . $time);
  return $token;
}
```

It is similar to the CVE-2016-0783 vulnerability. Easy to spot, attacker knows a vald username can get the server time by reading the `Date header` in the HTTP response. HTB gave an example where the token is generated from an epoch timestamp. File `reset_token_time.py` we could gain some confidence in creating and brute forcing a time based token. Bear in mind a reverse proxy could be stripping stuff, we can infer from an email header, last login time, in-app message etc. Some never invalidate or expire tokens.

### Short Tokens
Normally to help mobile users. No need, links do the job. A GET call can do the job e.g. `https://127.0.0.1/reset.php?token=any_random_sequence`. 

`wfuzz` could be used to brute force:
```bash
wfuzz -z range,00000-99999 --ss "Valid" "https://brokenauthentication.hackthebox.eu/token.php?user=admin&token=FUZZ"
```
This is where a success has a message of "Valid" and we just are trying 5 digit keys. You could also do `-hs "Invalid"` to filter out. Might cause DoS and it is very loud. 


### Weak Cryptography
Rolling own crypto is a dangerous idea. Devs can easily lean on security thorough obscurity. [F-Secure article](https://labs.withsecure.com/advisories/opencart-predictable-password-reset-tokens). Realised the `mt_rand()` PHP function is vulnerable to lack of entropy. PoCs:
- https://github.com/GeorgeArgyros/Snowflake
- https://download.openwall.net/pub/projects/php_mt_seed/

### Reset token as a temp password
By design, they should be invalidated as soon as the user logs in anfd changes it. By thorough as possible. The algo generating the temp password could also be predictable e.g. `mt_rand()`, `md5(username)`.

Getting the first question was actually trickier than I thought, as it was using a known vulnerability. Question was confusing as well. `token_tracker.py` figured it out, from pasting in the printed token. Some better logic could have sped it up.

Question 2 was easy to figure out but was just fiddly by using cyberchef having hex deliminators of spaces, when it should be None!



## Authentication Credentials Handling

## Guessable Answers
An easy one really, security questions can be guessed. Used ChatGPT to enumerate 100 colours to then brute force one of the questions. Could have done the same for pizza flavours.

## Username Injection
The excercise abuses logic if the `userid` field is supplied in the POST request. It was actually easier than expected, as it was just adding this to the POST request and then making sure the password of `htbuser` was used. I changed the password for `htbuser`, so I had to make sure it was the correct one
















