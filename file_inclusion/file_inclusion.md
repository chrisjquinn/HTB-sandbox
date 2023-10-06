# File Inclusion

## Intro
Putting parameters for functionality needs to be securely coded. If not, an attacker can use them to display contents of local files on the server, which is the [LFI vulnerability](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_Local_File_Inclusion). 

Most common place we find it is within templating engines. Think of a static header, nav bar and footer, with the dynamic crap in the middle. `/index.php?page=about` gives an idea of `index.php` being the static big and `about` being the dynamic. Maybe it is a local file called `about.php`. LFI vulns lead to source code disclosure, data exposurem RCE under certain conditions. Leaking source code can lead to other vulnerabilities being found. Data can be used for further exploit (or sheer exfiltration)

### Examples
Happens in `PHP, NodeJS, Java & .NET`. All have different approaches to including local files. The common thing is loading a file from a specified path.

#### PHP
We may use the function `include()` to load local or remote file. If the path is from a user submitted parameter, like a GET param, and theres no sanitization, then leads to LFI. E.g:
```php
if (isset($_GET['language'])) {
    include($_GET['language']);
}
```
Above: *if there is the language param populated, then include the value*. Not exclusive to the `include()` func, there are others too like `require()`. Module will mainly focus on PHP web apps running on a linux back-end.

#### NodeJS
```js
if(req.query.language) {
    fs.readFile(path.join(__dirname, req.query.language), function (err, data) {
        res.write(data);
    });
}
```
and using the `render()` function from express:
```js
app.get("/about/:language", function(req, res) {
    res.render(`/${req.params.language}/about.html`);
});
```
to determine which directory to load the about page - `/en/about.html` , `/fr/about.html` etc. But the param is `/about/en` in the web request, compared to a `?` param. 

#### Java
Using `include`:
```jsp
<c:if test="${not empty param.language}">
    <jsp:include file="<%= request.getParameter('language') %>" />
</c:if>
```

#### .NET
```cs
@if (!string.IsNullOrEmpty(HttpContext.Request.Query['language'])) {
    <% Response.WriteFile("<% HttpContext.Request.Query['language'] %>"); %> 
}
```
`@Html.Partial()` function may also be sued to render the specified file as follows:
```cs
@Html.Partial(HttpContext.Request.Query['language'])
```
and the `include` function may be used to render local files or remote URLs:
```cs
<!--#include file="<% HttpContext.Request.Query['language'] %>"-->
```

### Read v Execute
**Function	| Read Content |	Execute	|	Remote URL**

**PHP**			
include()/include_once()	✅	✅	✅
require()/require_once()	✅	✅	❌
file_get_contents()	✅	❌	✅
fopen()/file()	✅	❌	❌
NodeJS			
fs.readFile()	✅	❌	❌
fs.sendFile()	✅	❌	❌
res.render()	✅	✅	❌

**Java**		
include	✅	❌	❌
import	✅	✅	✅

**.NET**			
@Html.Partial()	✅	❌	❌
@Html.RemotePartial()	✅	❌	✅
Response.WriteFile()	✅	❌	❌
include	✅	✅	✅

Good to note for the level of exploit if you found what function is being used.

## File Disclosure

### LFI

#### Basic LFI
Excercise has a drop down where we can choose a language. The language can be seen in the url of `?language=es.php`, change to a file such as `/etc/passwd`. Showed output in the excercide but not the actual box. But, many devs will prepend the user param to a relative directory, so try to escape with lots of `../../../../`. Doing this on the box shows the `/etc/passwd` file. Guide shown some errors when trying to do absolute path, which is helpful. 

> Tip: Try to find the minimum number of escapes `../` that works and use it. For `/var/www/html` we will need 3. 

Prefix and appended parts, say a prefix of `_lang` might break LFI or a suffix of `.php` do the same, as there is no `/etc/passwd.php`. 


#### Second order attacks
More advanced type of LFI. Web app may allow us to download our avatar through a URL like `profile/$username/avatar.png`. Craft a malicious LFI username like `../../../etc/passwd` then it may be possible to change the file being pulled to another local file on the server. It is called second-order because it is poisoning a database entry with a malicious LFI payload. Then another functionality would utilize the payload to perform the attack (i.e. download the avatar based on username value). 

### Basic Bypasses
Web app might have some protection against basic LFI. 

#### Non-recursive path traversal filters
Simple protection is a search and replace filter, say:
```php
$language = str_replace('../', '', $_GET['language']);
```
That removes escapes. How to get around? `..//` becomes `../`, so there you go. Can also do `..././` or `....\/` and several others. In some cases, escaping the forward slash character may also work to avoid path traversal filters, or adding extra forward slashes.


#### Encoding
Say a filter removes all dots and slashes. URL encode to `%2e%2e%2f`. Double encode. Refer to the command injections module for more. 

#### Approved Paths
Might have a regex filter on the web app. E.g. only allow paths under the `/languages` directory:
```php
if(preg_match('/^\.\/languages\/.+$/', $_GET['language'])) {
    include($_GET['language']);
} else {
    echo 'Illegal path specified!';
}
```
To find the approved path, examine requests sent by the existing forms, fuzz web directories under the same path and try different ones until we get a match. To bypass, prepend approved path and then traverse. Combine techniques too. 

#### Appended extension
Might not be able to bypass extension in the more modern versions of php. Reading the php files still useful. Couple of techniques we can use, but for obsolete versions before 5.4. 

Path Truncation
Earlier versions of PHP strings had a length of 4096 chars, likely due to limits of 32-bit systems. Anything longer gets truncated and anything after gets ignored. PHP also used to remove trailing slashes and single dots in path names, so `/etc/passwd/.` becomes `/etc/passwd`. Combine both to create a long string that evaluates to a correct path, that way the truncation kicks off the extension of `.php`. Making a bunch via bash:
```bash
Chris-113@htb[/htb]$ echo -n "non_existing_directory/../../../etc/passwd/" && for i in {1..2048}; do echo -n "./"; done
non_existing_directory/../../../etc/passwd/./././<SNIP>././././
```

Null Bytes
PHP <5.5 were vulnerable to nul byte injection. Which means adding the null byte `%00` at the end of the string would terminate the string and not consider anything after. `/etc/passwd%00` means it would add `.php` at the end, but the null byte stops it. 

Excercise was found by using escapes via `....//`
