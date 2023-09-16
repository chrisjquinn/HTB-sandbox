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

 


`















