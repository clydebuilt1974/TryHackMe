# Protocols and Servers
## Telnet
* Application layer protocol used to connect to a virtual terminal of another computer.
* Relatively simple protocol.
* User is asked for a username and password when they connect.
* This communication between the Telnet client and the Telnet server is not encrypted.
  * Easy target for attackers.
* Telnet server listens for incoming connections on port TCP/23.
```
telnet 10.10.249.0

Trying 10.10.249.0...
Connected to 10.10.249.0.
Escape character is '^]'.
Ubuntu 20.04.3 LTS
```
* User is asked to provide their login name (username).
* Then, he is asked for the password
  * The password is not shown on the screen but is displayed below for demonstration purposes.
```
bento login: frank
Password: D2xc9CgD
```
* User is greeted with a welcome message once the system checks the login credentials.
```
Welcome to Ubuntu 20.04.3 LTS (GNU/Linux 5.4.0-84-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Fri 01 Oct 2021 12:24:56 PM UTC

  System load:  0.05              Processes:              243
  Usage of /:   45.7% of 6.53GB   Users logged in:        1
  Memory usage: 15%               IPv4 address for ens33: MACHINE_IP
  Swap usage:   0%

 * Super-optimized for small spaces - read how we shrank the memory
   footprint of MicroK8s to make it the smallest full K8s around.

   https://ubuntu.com/blog/microk8s-memory-optimisation

0 updates can be applied immediately.

*** System restart required ***
Last login: Fri Oct  1 12:17:25 UTC 2021 from meiyo on pts/3
You have mail.
```
* Remote server grants a command prompt
* `$` indicates that this is not a root terminal.
```
frank@bento:~$
```
* No longer considered a secure option as anyone capturing the network traffic will be able to discover usernames and passwords which would grant them access to the remote system.
* The secure alternative is SSH.

## Hypertext Transfer Protocol (HTTP)
* Protocol used to transfer web pages.
* Web browser connects to the webserver and uses HTTP to request HTML pages and images among other files and submit forms and upload various files.
* HTTP sends and receives data as cleartext (not encrypted).
* Telnet (or Netcat) can communicate with a web server and act as a 'web browser'.
  * Need to input the HTTP-related commands instead of the web browser doing this.
* Use telnet to request a file from the webserver.
1. Connect to port 80 using `telnet 10.10.249.0 80`.
2. Type `GET /index.html HTTP/1.1` to retrieve the page index.html or `GET / HTTP/1.1` to retrieve the default page.
3. Provide some value for the host like `host: telnet` and hit the Enter/Return key twice.
```
telnet 10.10.249.0 80

Trying 10.10.249.0...
Connected to 10.10.249.0.
Escape character is '^]'.
GET /index.html HTTP/1.1
host: telnet

HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Wed, 15 Sep 2021 08:56:20 GMT
Content-Type: text/html
Content-Length: 234
Last-Modified: Wed, 15 Sep 2021 08:53:59 GMT
Connection: keep-alive
ETag: "6141b4a7-ea"
Accept-Ranges: bytes

<!DOCTYPE html>
<html lang="en">
<head>
  <title>Welcome to my Web Server</title>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
</head>
<body>
  <h1>Coming Soon<h1>
</body>
</html>
```
* Web server will 'serve' specific set of files to the requesting web browser.
* Three popular choices for HTTP servers.
  * [Apache](https://www.apache.org/)
  * [Internet Information Services (IIS)](https://www.iis.net/)
  * [nginx](https://nginx.org/)
* Apache and Nginx are free and open-source software.
* IIS is closed source software and requires paying for a licence.
* Most popular web browsers.
  * Chrome by Google
  * Edge by Microsoft
  * Firefox by Mozilla
  * Safari by Apple.

## File Transfer Protocol (FTP)
* Developed to make transfer of files between different computers with different systems efficient.
* Sends and receives data as cleartext.
* Can use Telnet (or Netcat) to communicate with an FTP server and act as an FTP client.
* FTP servers listen on port 21 by default.
* There are two modes for FTP.
  * Active: where the data is sent over a separate channel originating from the FTP server’s port 20.
  * Passive: where the data is sent over a separate channel originating from an FTP client’s port above port number 1023.
* Cannot transfer a file using a simple client such as Telnet because FTP creates a separate connection for file transfer.
```
telnet 10.10.249.0 21

Trying 10.10.249.0...
Connected to 10.10.249.0.
Escape character is '^]'.
220 (vsFTPd 3.0.3)
```
* Provide the username with the command `USER frank`.
```
USER frank
331 Please specify the password.
```
* Provide the password with the command `PASS D2xc9CgD`.
```
PASS D2xc9CgD
230 Login successful.
```
* The `SYST` command shows the System Type of the target (UNIX in this case).
```
SYST
215 UNIX Type: L8
```
* `PASV` switches the mode to passive.
```
PASV
227 Entering Passive Mode (10,10,0,148,78,223).
```
* `TYPE A` switches the file transfer mode to ASCII.
* `TYPE I` switches the file transfer mode to binary.
```
TYPE A
200 Switching to ASCII mode.
```
* `STAT` can provide some added information.
```
STAT          
211-FTP server status:
     Connected to ::ffff:10.10.0.1
     Logged in as frank
     TYPE: ASCII
     No session bandwidth limit
     Session timeout in seconds is 300
     Control connection is plain text
     Data connections will be plain text
     At session startup, client count was 1
     vsFTPd 3.0.3 - secure, fast, stable
211 End of status
QUIT
221 Goodbye.
Connection closed by foreign host.      
```
* FTP client will initiate a connection to an FTP server that listens on port 21 by default.
* All commands are sent over the control channel.
* Another TCP connection will be established between them once the client requests a file.
* Use an actual FTP client to download a text file.
```
ftp 10.10.249.0

Connected to 10.10.249.0.
220 (vsFTPd 3.0.3)
Name: frank
331 Please specify the password.
Password: D2xc9CgD
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
```
* Use `ls` to list the files and learn the file name.
```
ftp> ls
227 Entering Passive Mode (10,20,30,148,201,180).
150 Here comes the directory listing.
-rw-rw-r--    1 1001     1001         4006 Sep 15 10:27 README.txt
226 Directory send OK.
```
* Switch to `ascii` since it is a text file (not binary).
```
ftp> ascii
200 Switching to ASCII mode.
```
* `get FILENAME` made the client and server establish another channel for file transfer.
```
ftp> get README.txt
local: README.txt remote: README.txt
227 Entering Passive Mode (10,10,0,148,125,55).
150 Opening BINARY mode data connection for README.txt (4006 bytes).
WARNING! 9 bare linefeeds received in ASCII mode
File may not have transferred correctly.
226 Transfer complete.
4006 bytes received in 0.000269 secs (14892.19 Kbytes/sec)
ftp> exit
221 Goodbye.
```     
* FTP servers and FTP clients use the FTP protocol.
* Examples of FTP server software.
  * [vsftpd](https://security.appspot.com/vsftpd.html)
  * [ProFTPD](http://www.proftpd.org/)
  * [uFTP](https://www.uftpserver.com/)
  * [FileZilla](https://filezilla-project.org/)
* Some web browsers also support FTP protocol.
* FTP traffic can be an easy target for attackers because the login credentials along with the commands and files are sent in cleartext.

## Simple Mail Transfer Protocol (SMTP)
* Email is one of the most used services on the Internet.
* Mail Submission Agent (MSA) 
  * Receives messages from MUAs.
  * Checks for any errors before transferring them to the MTA.
    * MSA and MTA are commonly hosted on the same server.
* Mail Transfer Agent (MTA) 
  * Sends email message to the MTA of the recipient.
  * Typically also functions as MDA
* Mail Delivery Agent (MDA)
  * Recipients collect email from MDA using MUAs.
* Mail User Agent (MUA)
  * An email client.
  * Connects to MSA to send messages.

* Need to rely on email protocols to talk with an MTA and an MDA.
  * Simple Mail Transfer Protocol (SMTP)
    * Used to communicate with an MTA server.
    * Listens on port 25 by default.
    * Uses cleartext.
      * Can use a basic Telnet client to connect to an SMTP server and act as an email client (MUA) sending a message.
  * Post Office Protocol version 3 (POP3) or Internet Message Access Protocol (IMAP).
```
telnet 10.10.249.0 25

Trying 10.10.249.0...
Connected to 10.10.249.0.
Escape character is '^]'.
220 bento.localdomain ESMTP Postfix (Ubuntu)
```
* Issue `helo hostname` and then start typing the email.
```
helo telnet
250 bento.localdomain
```
* Issue `mail from:`, `rcpt to:` to indicate the sender and the recipient.
```
mail from: 
250 2.1.0 Ok
rcpt to: 
250 2.1.5 Ok
```
* Issue the command `data` and type the message.
```
data
354 End data with .
subject: Sending email with Telnet
Hello Frank,
I am just writing to say hi!
```
* Issue `<CR><LF>.<CR><LF>` (or Enter . Enter to put it in simpler terms).
```           
.
```
* The SMTP server now queues the message.
```
250 2.0.0 Ok: queued as C3E7F45F06
quit
221 2.0.0 Bye
Connection closed by foreign host.
```   
## Post Office Protocol 3 (POP3)
* Protocol used to download the email messages from a Mail Delivery Agent (MDA) server.
* The mail client connects to the POP3 server, authenticates, downloads the new email messages before (optionally) deleting them.nt.
* POP3 default port is TCP/110.
```
telnet 10.10.249.0 110

Trying 10.10.249.0...
Connected to 10.10.249.0.
Escape character is '^]'.
+OK 10.10.249.0 Mail Server POP3 Wed, 15 Sep 2021 11:05:34 +0300
```
* Authentication is required to access the email messages.
* User authenticates by providing username `USER frank` and password `PASS D2xc9CgD`.
```
USER frank
+OK frank
PASS D2xc9CgD
+OK 1 messages (179) octets
```
* Positive response to `STAT` has the format `+OK nn mm`.
  * `nn` is the number of email messages in the inbox.
  * `mm` is the size of the inbox in octets (byte).
```
STAT
+OK 1 179
```
* The command `LIST` provided a list of new messages on the server.
```
LIST
+OK 1 messages (179) octets
1 179
.
```
* `RETR 1` retrieved the first message in the list.
```
RETR 1
+OK
From: Mail Server 
To: Frank 
subject: Sending email with Telnet
Hello Frank,
I am just writing to say hi!
.
QUIT
+OK 10.10.249.0 closing connection
Connection closed by foreign host.
```
* Commands are sent in cleartext.
* Any third party watching the network traffic can steal the login credentials.
* MUA deletes the mail message after it downloads it by default.
* Consider IMAP to keep all mailboxes synchronised.

## Internet Message Access Protocol (IMAP)
* More sophisticated than POP3.
* IMAP makes it possible to keep email synchronised across multiple mail clients.
* Marking an email message as read when checking email on your smartphone will save the change on the IMAP server (MDA) and replicate on other devices when the inbox is syncronised.
```
telnet 10.10.249.0 143

Trying 10.10.249.0...
Connected to 10.10.249.0.
Escape character is '^]'.
* OK [CAPABILITY IMAP4rev1 UIDPLUS CHILDREN NAMESPACE THREAD=ORDEREDSUBJECT THREAD=REFERENCES SORT QUOTA IDLE ACL ACL2=UNION STARTTLS ENABLE UTF8=ACCEPT] Courier-IMAP ready. Copyright 1998-2018 Double Precision, Inc.  See COPYING for distribution information.
```
* Authenticate using `LOGIN username password`.
* IMAP requires each command to be preceded by a random string (c1, c2) to be able to track the reply.
```
c1 LOGIN frank D2xc9CgD
* OK [ALERT] Filesystem notification initialization error -- contact your mail administrator (check for configuration errors with the FAM/Gamin library)
c1 OK LOGIN Ok.
```
* Listed the mail folders using `LIST "" "*"`.
```
c2 LIST "" "*"
* LIST (\HasNoChildren) "." "INBOX.Trash"
* LIST (\HasNoChildren) "." "INBOX.Drafts"
* LIST (\HasNoChildren) "." "INBOX.Templates"
* LIST (\HasNoChildren) "." "INBOX.Sent"
* LIST (\Unmarked \HasChildren) "." "INBOX"
c2 OK LIST completed
```
* Check if there are any new messages in the inbox using `EXAMINE INBOX`.
```
c3 EXAMINE INBOX
* FLAGS (\Draft \Answered \Flagged \Deleted \Seen \Recent)
* OK [PERMANENTFLAGS ()] No permanent flags permitted
* 0 EXISTS
* 0 RECENT
* OK [UIDVALIDITY 631694851] Ok
* OK [MYRIGHTS "acdilrsw"] ACL
c3 OK [READ-ONLY] Ok
c4 LOGOUT
* BYE Courier-IMAP server shutting down
c4 OK LOGOUT completed
Connection closed by foreign host.
```
* Login credentials sent in cleartext.
* Anyone watching the network traffic would be able to know Frank’s username and password.

## Sniffing Attacks
* Refers to using a network packet capture tool to collect information about the target.
* Data exchanged can be captured (private messages and login credentials) by a third party to analyse when a protocol communicates in cleartext.
* Can be conducted using an Ethernet (802.3) network card provided that the user has proper permissions (`root` permissions on Linux and administrator privileges on MS Windows).
1. Tcpdump is a free open source command-line interface (CLI) program.
2. Wireshark is a free open source graphical user interface (GUI) program.
3. Tshark is a CLI alternative to Wireshark.
* Consider a user checking his email messages using POP3.
* Use Tcpdump to attempt to capture the username and password.
  * `sudo tcpdump port 110 -A`.
    * Need `sudo` as packet captures require root privileges.
    * Limit the number of captured and displayed packets to those exchanged with the POP3 server using `port 110`.
    * Display the contents of the captured packets in ASCII format using `-A`.
* Requires access to the network traffic.
  * Wiretap.
  * Switch with port mirroring.
* Can also ccess the traffic exchanged if a successful Man-in-the-Middle (MITM) attack is launched.
```
sudo tcpdump port 110 -A

[...]
09:05:15.132861 IP 10.20.30.1.58386 > 10.20.30.148.pop3: Flags [P.], seq 1:13, ack 19, win 502, options [nop,nop,TS val 423360697 ecr 3958275530], length 12
E..@.V@.@.g.
...
......n......"............
.;....}.USER frank

09:05:15.133465 IP 10.20.30.148.pop3 > 10.20.30.1.58386: Flags [.], ack 13, win 510, options [nop,nop,TS val 3958280553 ecr 423360697], length 0
E..4..@.@.O~
...
....n....".........?P.....
...i.;..
09:05:15.133610 IP 10.20.30.148.pop3 > 10.20.30.1.58386: Flags [P.], seq 19:43, ack 13, win 510, options [nop,nop,TS val 3958280553 ecr 423360697], length 24
E..L..@.@.Oe
...
....n....".........<-.....
...i.;..+OK Password required.

09:05:15.133660 IP 10.20.30.1.58386 > 10.20.30.148.pop3: Flags [.], ack 43, win 502, options [nop,nop,TS val 423360698 ecr 3958280553], length 0
E..4.W@.@.g.
...
......n......".....??.....
.;.....i
09:05:22.852695 IP 10.20.30.1.58386 > 10.20.30.148.pop3: Flags [P.], seq 13:28, ack 43, win 502, options [nop,nop,TS val 423368417 ecr 3958280553], length 15
E..C.X@.@.g.
...
......n......".....6......
.<.....iPASS D2xc9CgD
[...]     
```
* First packet explicitly displays `USER frank` while the last packet reveals the password `PASS D2xc9CgD`.
* Could also use Wireshark to achieve the same results.
  * Enter `pop` in the filter field.
  * Can now see a username and password were captured.
* Any protocol that uses cleartext communication is susceptible to this kind of attack.
* Only requirement is to have access to a system between the two communicating systems.
* Mitigation lies in adding an encryption layer on top of any network protocol.
  * Transport Layer Security (TLS) has been added to HTTP, FTP, SMTP, POP3, IMAP and many others. 
  * Telnet has been replaced by the secure alternative Secure Shell (SSH).

## Man-in-the-Middle (MITM) Attacks
* Occurs when a victim (A) believes they are communicating with a legitimate destination (B) but is unknowingly communicating with an attacker (E).
  * A requests the transfer of £20 to M.
  * E altered this message and replaced the original value with a new one of £2000.
  * B received the modified message and acted on it.
* Relatively simple to carry out if the two parties do not confirm the authenticity and integrity of each message.
* Mitigation against this attack requires the use of cryptography.
  * Proper authentication along with encryption or signing of the exchanged messages.
  * Transport Layer Security (TLS) protects from MITM attacks with the help of Public Key Infrastructure (PKI) and trusted root certificates.

## Transport Layer Security (TLS)
* Standard solution to protect the confidentiality and integrity of exchanged packets.
* Can protect against password sniffing and MITM attacks.
* SSL (Secure Sockets Layer) started when the world wide web started to see new applications such as online shopping and sending payment information.
* Netscape introduced SSL in 1994 with SSL 3.0 being released in 1996.
* TLS (Transport Layer Security) protocol was introduced in 1999.
* Encryption can be added to protocols via the presentation layer of the ISO/OSI model.
* Data will then be presented in an encrypted format (ciphertext) instead of its original form.
* TLS is more secure than SSL and it has practically replaced it.
  * Expect all modern servers to be using TLS.
* Existing cleartext protocol can be upgraded to use encryption via SSL/TLS.

| Protocol | Default Port | Secured Protocol | Default Port with TLS
| --- | --- | --- | ---
| HTTP | 80 | HTTPS | 443
| FTP | 21 | FTPS | 990
| SMTP | 25 | SMTPS | 465
| POP3 | 110 | POP3S | 995
| IMAP | 143 | IMAPS | 993

* HTTPS steps.
1. Establish a TCP connection
2. Establish SSL/TLS connection
3. Send GET and POST HTTP requests to the webserver
* Client needs to perform the proper handshake with the server to establish an SSL/TLS connection.
* SSL connection establishment based on [RFC 6101](https://datatracker.ietf.org/doc/html/rfc6101).
1. Client sends a 'ClientHello' to the server to indicate its capabilities such as supported algorithms.
2. Server responds with a 'ServerHello' indicating the selected connection parameters.
   * Server provides its certificate if server authentication is required.
     * Certificate is a digital file to identify itself.
     * Usually digitally signed by a third party.
   * Might send additional information necessary to generate master key in its 'ServerKeyExchange' message.
   * Sends 'ServerHelloDone' message to indicate that server is done with the negotiation.
3. Client responds with 'ClientKeyExchange' which contains additional information required to generate the master key.
   * Switches to use encryption and informs the server using the 'ChangeCipherSpec' message.
4. Server switches to use encryption as well and informs the client in the 'ChangeCipherSpec' message.
* Client was able to agree on a secret key with a server that has a public certificate.
  * Secret key was securely generated so that a third party monitoring the channel wouldn’t be able to discover it.
  * Further communication between the client and the server is encrypted using the generated key.
* SSL/TLS relies on public certificates signed by trusted certificate authorities to be effective when browsing the web over HTTPS.
  * Browser expects the web server to provide a signed certificate from a trusted certificate authority.
  * MITM attack cannot occur.
  * Browser will automatically ensure that the communication is secure thanks to the server’s certificate.
    * To whom is the certificate issued? That is the name of the company that will use this certificate.
    * Who issued the certificate? This is the certificate authority that issued this certificate.
   * Validity period. Do not want to use a certificate that has expired.

## Secure Shell (SSH)
* Created to provide a secure way for remote system administration.
1. Identity of the remote server can be confirmed.
2. Exchanged messages are encrypted and can only be decrypted by the intended recipient.
3. Both sides can detect any modification in the messages.
* Above three points are ensured by cryptography.
  * Part of confidentiality and integrity.
  * Made possible through the proper use of different encryption algorithms.
* SSH server listens on port 22 by default.
* SSH client can authenticate to server in two ways.
  * Username and a password.
  * Private and public key (after the SSH server is configured to recognise the corresponding public key).
```
ssh mark@10.10.158.132

mark@10.10.158.132's password: XBtc49AB

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Mon Sep 20 13:53:17 2021
mark@debian8:~$
```
* SSH is very reliable for remote administration because all commands executed on the remote system will be sent over an encrypted channel.
* Need to confirm the fingerprint of the SSH server’s public key to avoid man-in-the-middle (MITM) attacks if this is the first time connecting to the system.
  * Do not usually have a third party to check if the public key is valid so this must be done manually.
* Use SSH to transfer files using SCP (Secure Copy Protocol) based on the SSH protocol.
  * `scp mark@10.10.158.132:/home/mark/archive.tar.gz ~`.
    * Copies a file named `archive.tar.gz` from the remote system located in the `/home/mark` directory to `~`.
      * `~` is root of the home directory of the currently logged-in user.
  * `scp backup.tar.bz2 mark@10.10.158.132:/home/mark/`.
    * Copies the file `backup.tar.bz2` from the local system to the directory `/home/mark/` on the remote system.
```
scp document.txt mark@10.10.158.132:/home/mark

mark@10.10.158.132's password: 
document.txt                                        100% 1997KB  70.4MB/s   00:00       
```
* FTP could be secured using SSL/TLS by using the FTPS protocol which uses port 990.
* FTP can also be secured using the SSH protocol which is the SFTP protocol.
  * By default this service listens on port 22 like SSH.

## Password Attacks
* Many protocols require authentication.
  * This is proving who an identity claims to be.
* In the POP3 example below the user is identified as the user frank and the server authenticated us because the correct password was provided.
  * The password is one way to authenticate.
```
telnet 10.10.158.132 110

Trying 10.10.158.132...
Connected to 10.10.158.132.
Escape character is '^]'.
+OK 10.10.158.132 Mail Server POP3 Wed, 15 Sep 2021 11:05:34 +0300 
USER frank
+OK frank
PASS D2xc9CgD
+OK 1 messages (179) octets
STAT
+OK 1 179
LIST
+OK 1 messages (179) octets
1 179
.
RETR 1
+OK
From: Mail Server 
To: Frank 
subject: Sending email with Telnet
Hello Frank,
I am just writing to say hi!
.
QUIT
+OK 10.10.158.132 closing connection
Connection closed by foreign host.    
```
* Authentication can be achieved through one of the following (or a combination of two).
  * Something you know.
    * Password, PIN code.
  * Something you have.
    * SIM card, RFID card, or USB dongle.
  * Something you are.
    * Fingerprint and iris.
* Password attack approaches.
  * Password Guessing.
    * Guessing a password requires some knowledge of the target such as their pet’s name and birth year.
  * Dictionary Attack.
    * Expands on password guessing and attempts to include all valid words in a dictionary or a wordlist.
  * Brute Force Attack.
    * Exhaustive and time-consuming.
    * Attackers can go as far as trying all possible character combinations which grows fast (exponential growth with the number of characters).
* Choice of word list should depend on knowledge of the target.
  * French user might use a French word instead of an English one.
    * French word list might be more promising.
* [Hydra](https://github.com/vanhauser-thc/thc-hydra)
  * Automated means of trying common passwords or entries from a word list.
  * Supports many protocols including FTP, POP3, IMAP, SMTP, SSH, and all methods related to HTTP.
* General command-line syntax is: `hydra -l username -P wordlist.txt server service`.
  * `-l username`
    * i.e. login name of the target.
  * `-P wordlist.txt` is text file containing the list of passwords to try with the provided username.
  * `server` is hostname or IP address of the target server.
  * `service` indicates the service against to launch the dictionary attack.
* `hydra -l mark -P /usr/share/wordlists/rockyou.txt 10.10.158.132 ftp` will use mark as the username as it iterates over the provided passwords against the FTP server.
* `hydra -l mark -P /usr/share/wordlists/rockyou.txt ftp://10.10.158.132` is identical to the previous example.
   * `10.10.158.132 ftp` is the same as `ftp://10.10.158.132`.
* `hydra -l frank -P /usr/share/wordlists/rockyou.txt 10.10.158.132 ssh` will use frank as the user name as it tries to login via SSH using the different passwords.
* Extra optional arguments.
  * `-s PORT` to specify a non-default port for the service in question.
  * `-V` or `-vV` for verbose forces Hydra to show the username and password combinations that are being tried.
    * This verbosity is very convenient to see progress.
  * `-t n` where `n` is the number of parallel connections to the target.
    * `-t 16` will create 16 threads used to connect to the target.
  * `-d` for debugging, to get more detailed information.
    * Debugging output can save much frustration.
* Issue `CTRL-C` to end the process once the password is found.
* Attacks against login systems can be carried out efficiently using a tool such as THC Hydra combined with a suitable word list.
* Mitigation against these attacks can be sophisticated and depends on the target system.
  * Password Policy enforces minimum complexity constraints on the passwords set by the user.
  * Account Lockout locks the account after a certain number of failed attempts.
  * Throttling Authentication Attempts delays the response to a login attempt.
    * A couple of seconds of delay is tolerable for someone who knows the password, but they can severely hinder automated tools.
  * Using CAPTCHA requires solving a question difficult for machines.
    * This works well if the login page is via a graphical user interface (GUI).
    * CAPTCHA stands for 'Completely Automated Public Turing test to tell Computers and Humans Apart'.
  * Requiring the use of a public certificate for authentication.
    * This approach works well with SSH.
  * Two-Factor Authentication asks the user to provide a code available via other means such as email, smartphone app or SMS.
  * There are many other approaches that are more sophisticated or might require some established knowledge about the user, such as IP-based geolocation.
  * Using a combination of the above approaches is an excellent approach to protect against password attacks.

## Summary

| Protocol | TCP Port | Application(s) | Data Security
| --- | --- | --- | ---
| FTP | 21 | File Transfer | Cleartext
| FTPS | 990 | File Transfer | Encrypted
| HTTP | 80 | World Wide Web | Cleartext
| HTTPS | 443 | World Wide Web | Encrypted
| IMAP | 143 | Email (MDA) | Cleartext
| IMAPS | 993 | Email (MDA) | Encrypted
| POP3 | 110 | Email (MDA) | Cleartext
| POP3S | 995 | Email (MDA) | Encrypted
| SFTP | 22 | File Transfer | Encrypted
| SSH | 22 | Remote Access and File Transfer | Encrypted
| SMTP | 25 | Email (MTA) | Cleartext
| SMTPS | 465 | Email (MTA) | Encrypted
| Telnet | 23 | Remote Access | Cleartext

| Hydra Option | Explanation
| --- | ---
| `-l username` | Provide the login name
| `-P WordList.txt` | Specify the password list to use
| `server service` | Set the server address and service to attack
| `-s PORT` |  Use in case of non-default service port number
| `-V` or `-vV` | Show the username and password combinations being tried
| `-d` | Display debugging output if the verbose output is not helping
