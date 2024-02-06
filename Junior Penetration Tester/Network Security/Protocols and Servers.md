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
* The $ indicates that this is not a root terminal.
```
frank@bento:~$
```
* Not a reliable protocol for remote administration as all the data is sent in cleartext.
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
File Transfer Protocol (FTP) was developed to make the transfer of files between different computers with different systems efficient.
FTP also sends and receives data as cleartext; therefore, we can use Telnet (or Netcat) to communicate with an FTP server and act as an FTP client. In the example below, we carried out the following steps:
We connected to an FTP server using a Telnet client. Since FTP servers listen on port 21 by default, we had to specify to our Telnet client to attempt connection to port 21 instead of the default Telnet port.
We needed to provide the username with the command USER frank.
Then, we provided the password with the command PASS D2xc9CgD.
Because we supplied the correct username and password, we got logged in.
A command like STAT can provide some added information. The SYST command shows the System Type of the target (UNIX in this case). PASV switches the mode to passive. It is worth noting that there are two modes for FTP:
Active: In the active mode, the data is sent over a separate channel originating from the FTP server’s port 20.
Passive: In the passive mode, the data is sent over a separate channel originating from an FTP client’s port above port number 1023.
The command TYPE A switches the file transfer mode to ASCII, while TYPE I switches the file transfer mode to binary. However, we cannot transfer a file using a simple client such as Telnet because FTP creates a separate connection for file transfer.
telnet 10.10.249.0 21

Trying 10.10.249.0...
Connected to 10.10.249.0.
Escape character is '^]'.
220 (vsFTPd 3.0.3)
USER frank
331 Please specify the password.
PASS D2xc9CgD
230 Login successful.
SYST
215 UNIX Type: L8
PASV
227 Entering Passive Mode (10,10,0,148,78,223).
TYPE A
200 Switching to ASCII mode.
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
The image below shows how an actual file transfer would be conducted using FTP. To keep things simple in this figure, let’s only focus on the fact that the FTP client will initiate a connection to an FTP server, which listens on port 21 by default. All commands will be sent over the control channel. Once the client requests a file, another TCP connection will be established between them. (The details of establishing the data connection/channel is beyond the scope of this room.)

Considering the sophistication of the data transfer over FTP, let’s use an actual FTP client to download a text file. We only needed a small number of commands to retrieve the file. After logging in successfully, we get the FTP prompt, ftp>, to execute various FTP commands. We used ls to list the files and learn the file name; then, we switched to ascii since it is a text file (not binary). Finally, get FILENAME made the client and server establish another channel for file transfer.
ftp 10.10.249.0

Connected to 10.10.249.0.
220 (vsFTPd 3.0.3)
Name: frank
331 Please specify the password.
Password: D2xc9CgD
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
227 Entering Passive Mode (10,20,30,148,201,180).
150 Here comes the directory listing.
-rw-rw-r--    1 1001     1001         4006 Sep 15 10:27 README.txt
226 Directory send OK.
ftp> ascii
200 Switching to ASCII mode.
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
FTP servers and FTP clients use the FTP protocol. There are various FTP server software that you can select from if you want to host your FTP file server. Examples of FTP server software include:
vsftpd
ProFTPD
uFTP
For FTP clients, in addition to the console FTP client commonly found on Linux systems, you can use an FTP client with GUI such as FileZilla. Some web browsers also support FTP protocol.
Because FTP sends the login credentials along with the commands and files in cleartext, FTP traffic can be an easy target for attackers.
Simple Mail Transfer Protocol (SMTP)
Email is one of the most used services on the Internet. There are various configurations for email servers; for instance, you may set up an email system to allow local users to exchange emails with each other with no access to the Internet. However, we will consider the more general setup where different email servers connect over the Internet.
Email delivery over the Internet requires the following components:
Mail Submission Agent (MSA)
Mail Transfer Agent (MTA)
Mail Delivery Agent (MDA)
Mail User Agent (MUA)
The above four terms may look cryptic, but they are more straightforward than they appear. We will explain these terms using the figure below.

The figure shows the following five steps that an email needs to go through to reach the recipient’s inbox:
A Mail User Agent (MUA), or simply an email client, has an email message to be sent. The MUA connects to a Mail Submission Agent (MSA) to send its message.
The MSA receives the message, checks for any errors before transferring it to the Mail Transfer Agent (MTA) server, commonly hosted on the same server.
The MTA will send the email message to the MTA of the recipient. The MTA can also function as a Mail Submission Agent (MSA).
A typical setup would have the MTA server also functioning as a Mail Delivery Agent (MDA).
The recipient will collect its email from the MDA using their email client.
If the above steps sound confusing, consider the following analogy:
You (MUA) want to send postal mail.
The post office employee (MSA) checks the postal mail for any issues before your local post office (MTA) accepts it.
The local post office checks the mail destination and sends it to the post office (MTA) in the correct country.
The post office (MTA) delivers the mail to the recipient mailbox (MDA).
The recipient (MUA) regularly checks the mailbox for new mail. They notice the new mail, and they take it.
In the same way, we need to follow a protocol to communicate with an HTTP server, and we need to rely on email protocols to talk with an MTA and an MDA. The protocols are:
Simple Mail Transfer Protocol (SMTP)
Post Office Protocol version 3 (POP3) or Internet Message Access Protocol (IMAP)
Simple Mail Transfer Protocol (SMTP) is used to communicate with an MTA server. Because SMTP uses cleartext, where all commands are sent without encryption, we can use a basic Telnet client to connect to an SMTP server and act as an email client (MUA) sending a message.
SMTP server listens on port 25 by default. To see basic communication with an SMTP server, we used Telnet to connect to it. Once connected, we issue helo hostname and then start typing our email.
telnet 10.10.249.0 25

Trying 10.10.249.0...
Connected to 10.10.249.0.
Escape character is '^]'.
220 bento.localdomain ESMTP Postfix (Ubuntu)
helo telnet
250 bento.localdomain
mail from: 
250 2.1.0 Ok
rcpt to: 
250 2.1.5 Ok
data
354 End data with .
subject: Sending email with Telnet
Hello Frank,
I am just writing to say hi!             
.
250 2.0.0 Ok: queued as C3E7F45F06
quit
221 2.0.0 Bye
Connection closed by foreign host.       
After helo, we issue mail from:, rcpt to: to indicate the sender and the recipient. When we send our email message, we issue the command data and type our message. We issue <CR><LF>.<CR><LF> (or Enter . Enter to put it in simpler terms). The SMTP server now queues the message.
Generally speaking, we don’t need to memorise SMTP commands. The console output above aims to help better explain what a typical mail client does when it uses SMTP.
Post Office Protocol 3 (POP3)
Post Office Protocol version 3 (POP3) is a protocol used to download the email messages from a Mail Delivery Agent (MDA) server, as shown in the figure below. The mail client connects to the POP3 server, authenticates, downloads the new email messages before (optionally) deleting them.

The example below shows what a POP3 session would look like if conducted via a Telnet client. First, the user connects to the POP3 server at the POP3 default port 110. Authentication is required to access the email messages; the user authenticates by providing his username USER frank and password PASS D2xc9CgD. Using the command STAT, we get the reply +OK 1 179; based on RFC 1939, a positive response to STAT has the format +OK nn mm, where nn is the number of email messages in the inbox, and mm is the size of the inbox in octets (byte). The command LIST provided a list of new messages on the server, and RETR 1 retrieved the first message in the list. We don’t need to concern ourselves with memorising these commands; however, it is helpful to strengthen our understanding of such protocol.
telnet 10.10.249.0 110

Trying 10.10.249.0...
Connected to 10.10.249.0.
Escape character is '^]'.
+OK 10.10.249.0 Mail Server POP3 Wed, 15 Sep 2021 11:05:34 +0300 
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
+OK 10.10.249.0 closing connection
Connection closed by foreign host.

The example above shows that the commands are sent in cleartext. Using Telnet was enough to authenticate and retrieve an email message. As the username and password are sent in cleartext, any third party watching the network traffic can steal the login credentials.
In general, your mail client (MUA) will connect to the POP3 server (MDA), authenticate, and download the messages. Although the communication using the POP3 protocol will be hidden behind a sleek interface, similar commands will be issued, as shown in the Telnet session above.
Based on the default settings, the mail client deletes the mail message after it downloads it. The default behaviour can be changed from the mail client settings if you wish to download the emails again from another mail client. Accessing the same mail account via multiple clients using POP3 is usually not very convenient as one would lose track of read and unread messages. To keep all mailboxes synchronised, we need to consider other protocols, such as IMAP.
Internet Message Access Protocol (IMAP)
Internet Message Access Protocol (IMAP) is more sophisticated than POP3. IMAP makes it possible to keep your email synchronised across multiple devices (and mail clients). In other words, if you mark an email message as read when checking your email on your smartphone, the change will be saved on the IMAP server (MDA) and replicated on your laptop when you synchronise your inbox.
Let’s take a look at sample IMAP commands. In the console output below, we use Telnet to connect to the IMAP server’s default port, and then we authenticate using LOGIN username password. IMAP requires each command to be preceded by a random string to be able to track the reply. So we added c1, then c2, and so on. Then we listed our mail folders using LIST "" "*", before checking if we have any new messages in the inbox using EXAMINE INBOX. We don’t need to memorise these commands; however, we are simply providing the example below to give a vivid image of what happens when the mail client communicates with an IMAP server.
telnet 10.10.249.0 143

Trying 10.10.249.0...
Connected to 10.10.249.0.
Escape character is '^]'.
* OK [CAPABILITY IMAP4rev1 UIDPLUS CHILDREN NAMESPACE THREAD=ORDEREDSUBJECT THREAD=REFERENCES SORT QUOTA IDLE ACL ACL2=UNION STARTTLS ENABLE UTF8=ACCEPT] Courier-IMAP ready. Copyright 1998-2018 Double Precision, Inc.  See COPYING for distribution information.
c1 LOGIN frank D2xc9CgD
* OK [ALERT] Filesystem notification initialization error -- contact your mail administrator (check for configuration errors with the FAM/Gamin library)
c1 OK LOGIN Ok.
c2 LIST "" "*"
* LIST (\HasNoChildren) "." "INBOX.Trash"
* LIST (\HasNoChildren) "." "INBOX.Drafts"
* LIST (\HasNoChildren) "." "INBOX.Templates"
* LIST (\HasNoChildren) "." "INBOX.Sent"
* LIST (\Unmarked \HasChildren) "." "INBOX"
c2 OK LIST completed
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
It is clear that IMAP sends the login credentials in cleartext, as we can see in the command LOGIN frank D2xc9CgD. Anyone watching the network traffic would be able to know Frank’s username and password.
Summary
It is good to remember the default port number for common protocols. Below is a summary of the protocols we covered, sorted in alphabetical order, along with their default port numbers.
Protocol
TCP Port
Application(s)
Data Security
FTP
21
File Transfer
Cleartext
HTTP
80
World Wide Web
Cleartext
IMAP
143
Email (MDA)
Cleartext
POP3
110
Email (MDA)
Cleartext
SMTP
25
Email (MTA)
Cleartext
Telnet
23
Remote Access
Cleartext

Protocols and Servers 2
Learn about attacks against passwords and cleartext traffic; explore options for mitigation via SSH and SSL/TLS.
Introduction
Servers implementing the protocols discussed in the previous section are subject to different kinds of attacks. To name a few, consider:
Sniffing Attack (Network Packet Capture)
Man-in-the-Middle (MITM) Attack
Password Attack (Authentication Attack)
Vulnerabilities
From a security perspective, we always need to think about what we aim to protect; consider the security triad: Confidentiality, Integrity, and Availability (CIA). Confidentiality refers to keeping the contents of the communications accessible to the intended parties. Integrity is the idea of assuring any data sent is accurate, consistent, and complete when reaching its destination. Finally, availability refers to being able to access the service when we need it. Different parties will put varying emphasis on these three. For instance, confidentiality would be the highest priority for an intelligence agency. Online banking will put more emphasis on the integrity of transactions. Availability is of the highest importance for any platform making money by serving ads.
Knowing that we are protecting the Confidentiality, Integrity, and Availability (CIA), an attack aims to cause Disclosure, Alteration, and Destruction (DAD). The figures below reflect this.

These attacks directly affect the security of the system. For instance, network packet capture violates confidentiality and leads to the disclosure of information. A successful password attack can also lead to disclosure. On the other hand, a Man-in-the-Middle (MITM) attack breaks the system’s integrity as it can alter the communicated data. We will focus on these three attacks in this room as these attacks are integral to the protocol design and server implementation.
Vulnerabilities are of a broader spectrum, and exploited vulnerabilities have different impacts on the target systems. For instance, exploiting a Denial of Service (DoS) vulnerability can affect the system’s availability, while exploiting a Remote Code Execution (RCE) vulnerability can lead to more severe damages. It is important to note that a vulnerability by itself creates a risk; damage can occur only when the vulnerability is exploited.
This room will focus on how a protocol can be upgraded or replaced to protect against disclosure and alteration, i.e. protecting the confidentiality and integrity of the transmitted data. We will be recommending other modules that cover additional topics.
Moreover, we introduce Hydra to find weak passwords.
Sniffing Attack
Sniffing attack refers to using a network packet capture tool to collect information about the target. When a protocol communicates in cleartext, the data exchanged can be captured by a third party to analyse. A simple network packet capture can reveal information, such as the content of private messages and login credentials, if the data isn't encrypted in transit.
A sniffing attack can be conducted using an Ethernet (802.3) network card, provided that the user has proper permissions (root permissions on Linux and administrator privileges on MS Windows). There are many programs available to capture network packets. We consider the following:
Tcpdump is a free open source command-line interface (CLI) program that has been ported to work on many operating systems.
Wireshark is a free open source graphical user interface (GUI) program available for several operating systems, including Linux, macOS and MS Windows.
Tshark is a CLI alternative to Wireshark.
There are several specialised tools for capturing passwords and even complete messages; however, this can still be achieved by Tcpdump and Wireshark with some added effort.
Consider a user checking his email messages using POP3. First, we are going to use Tcpdump to attempt to capture the username and password. In the terminal output below, we used the command sudo tcpdump port 110 -A. Before explaining this command, we should mention that this attack requires access to the network traffic, for example, via a wiretap or a switch with port mirroring. Alternatively, we can access the traffic exchanged if we launch a successful Man-in-the-Middle (MITM) attack.
We need sudo as packet captures require root privileges. We wanted to limit the number of captured and displayed packets to those exchanged with the POP3 server. We know that POP3 uses port 110, so we filtered our packets using port 110. Finally, we wanted to display the contents of the captured packets in ASCII format, so we added -A.
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
In the terminal output above, we have removed the unimportant packets to help you better focus on the ones that matter. In particular, the username and password were each sent in their own packet. The first packet explicitly displays “USER frank”, while the last packet reveals the password “PASS D2xc9CgD”.
We could also use Wireshark to achieve the same results. In the Wireshark window below, we can see that we have entered pop in the filter field. Now that we've filtered just the traffic we're interested in, we can see a username and password were captured.

In brief, any protocol that uses cleartext communication is susceptible to this kind of attack. The only requirement for this attack to succeed is to have access to a system between the two communicating systems. This attack requires attention; the mitigation lies in adding an encryption layer on top of any network protocol. In particular, Transport Layer Security (TLS) has been added to HTTP, FTP, SMTP, POP3, IMAP and many others. For remote access, Telnet has been replaced by the secure alternative Secure Shell (SSH).
Man-in-the-Middle (MITM) Attack
A Man-in-the-Middle (MITM) attack occurs when a victim (A) believes they are communicating with a legitimate destination (B) but is unknowingly communicating with an attacker (E). In the figure below, we have A requesting the transfer of $20 to M; however, E altered this message and replaced the original value with a new one. B received the modified message and acted on it.

This attack is relatively simple to carry out if the two parties do not confirm the authenticity and integrity of each message. In some cases, the chosen protocol does not provide secure authentication or integrity checking; moreover, some protocols have inherent insecurities that make them susceptible to this kind of attack.
Any time you browse over HTTP, you are susceptible to a MITM attack, and the scary thing is that you cannot recognize it. Many tools would aid you in carrying out such an attack, such as Ettercap and Bettercap.
MITM can also affect other cleartext protocols such as FTP, SMTP, and POP3. Mitigation against this attack requires the use of cryptography. The solution lies in proper authentication along with encryption or signing of the exchanged messages. With the help of Public Key Infrastructure (PKI) and trusted root certificates, Transport Layer Security (TLS) protects from MITM attacks.
Transport Layer Security (TLS)
In this task, we learn about a standard solution to protect the confidentiality and integrity of the exchanged packets. The following approach can protect against password sniffing and MITM attacks.
SSL (Secure Sockets Layer) started when the world wide web started to see new applications, such as online shopping and sending payment information. Netscape introduced SSL in 1994, with SSL 3.0 being released in 1996. But eventually, more security was needed, and the TLS (Transport Layer Security) protocol was introduced in 1999. Before we explain what TLS and SSL provide, let’s see how they fit the networking model.
The common protocols we have covered so far send the data in cleartext; this makes it possible for anyone with access to the network to capture, save and analyse the exchanged messages. The image below shows the ISO/OSI network layers. The protocols we have covered so far in this room are on the application layer. Consider the ISO/OSI model; we can add encryption to our protocols via the presentation layer. Consequently, data will be presented in an encrypted format (ciphertext) instead of its original form.

Because of the close relation between SSL and TLS, one might be used instead of the other. However, TLS is more secure than SSL, and it has practically replaced SSL. We could have dropped SSL and just written TLS instead of SSL/TLS, but we will continue to mention the two to avoid any ambiguity because the term SSL is still in wide use. However, we can expect all modern servers to be using TLS.
An existing cleartext protocol can be upgraded to use encryption via SSL/TLS. We can use TLS to upgrade HTTP, FTP, SMTP, POP3, and IMAP, to name a few. The following table lists the protocols we have covered and their default ports before and after the encryption upgrade via SSL/TLS. The list is not exhaustive; however, the purpose is to help us better understand the process.
Protocol
Default Port
Secured Protocol
Default Port with TLS
HTTP
80
HTTPS
443
FTP
21
FTPS
990
SMTP
25
SMTPS
465
POP3
110
POP3S
995
IMAP
143
IMAPS
993

Considering the case of HTTP. Initially, to retrieve a web page over HTTP, the web browser would need at least perform the following two steps:
Establish a TCP connection with the remote web server
Send HTTP requests to the web server, such as GET and POST requests.
HTTPS requires an additional step to encrypt the traffic. The new step takes place after establishing a TCP connection and before sending HTTP requests. This extra step can be inferred from the ISO/OSI model in the image presented earlier. Consequently, HTTPS requires at least the following three steps:
Establish a TCP connection
Establish SSL/TLS connection
Send HTTP requests to the webserver
To establish an SSL/TLS connection, the client needs to perform the proper handshake with the server. Based on RFC 6101, the SSL connection establishment will look like the figure below.

After establishing a TCP connection with the server, the client establishes an SSL/TLS connection, as shown in the figure above. The terms might look complicated depending on your knowledge of cryptography, but we can simplify the four steps as:
The client sends a ClientHello to the server to indicate its capabilities, such as supported algorithms.
The server responds with a ServerHello, indicating the selected connection parameters. The server provides its certificate if server authentication is required. The certificate is a digital file to identify itself; it is usually digitally signed by a third party. Moreover, it might send additional information necessary to generate the master key, in its ServerKeyExchange message, before sending the ServerHelloDone message to indicate that it is done with the negotiation.
The client responds with a ClientKeyExchange, which contains additional information required to generate the master key. Furthermore, it switches to use encryption and informs the server using the ChangeCipherSpec message.
The server switches to use encryption as well and informs the client in the ChangeCipherSpec message.
If this still sounds sophisticated, don’t worry; we only need the gist of it. A client was able to agree on a secret key with a server that has a public certificate. This secret key was securely generated so that a third party monitoring the channel wouldn’t be able to discover it. Further communication between the client and the server will be encrypted using the generated key.
Consequently, once an SSL/TLS handshake has been established, HTTP requests and exchanged data won’t be accessible to anyone watching the communication channel.
As a final note, for SSL/TLS to be effective, especially when browsing the web over HTTPS, we rely on public certificates signed by certificate authorities trusted by our systems. In other words, when we browse to TryHackMe over HTTPS, our browser expects the TryHackMe web server to provide a signed certificate from a trusted certificate authority, as per the example below. This way, our browser ensures that it is communicating with the correct server, and a MITM attack cannot occur.

In the figure above, we can see the following information:
To whom is the certificate issued? That is the name of the company that will use this certificate.
Who issued the certificate? This is the certificate authority that issued this certificate.
Validity period. You don’t want to use a certificate that has expired, for instance.
Luckily, we don’t have to check the certificate manually for every site we visit; our web browser will do it for us. Our web browser will ensure that we are talking with the correct server and ensure that our communication is secure, thanks to the server’s certificate.
Secure Shell (SSH)
Secure Shell (SSH) was created to provide a secure way for remote system administration. In other words, it lets you securely connect to another system over the network and execute commands on the remote system. Put simply, the “S” in SSH stands for secure, which can be summarised simply as:
You can confirm the identity of the remote server
Exchanged messages are encrypted and can only be decrypted by the intended recipient
Both sides can detect any modification in the messages
The above three points are ensured by cryptography. In more technical terms, they are part of confidentiality and integrity, made possible through the proper use of different encryption algorithms.
To use SSH, you need an SSH server and an SSH client. The SSH server listens on port 22 by default. The SSH client can authenticate using:
A username and a password
A private and public key (after the SSH server is configured to recognize the corresponding public key)
On Linux, macOS, and MS Windows builds after 2018, you can connect to an SSH server using the following command ssh username@10.10.158.132. This command will try to connect to the server of IP address 10.10.158.132 with the login name username. If an SSH server is listening on the default port, it will ask you to provide the password for username. Once authenticated, the user will have access to the target server’s terminal. The terminal output below is an example of using SSH to access a Debian Linux server.
ssh mark@10.10.158.132

mark@10.10.158.132's password: XBtc49AB

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Mon Sep 20 13:53:17 2021
mark@debian8:~$
In the example above, we issued the command ssh mark@10.10.158.132. Then, once we entered the correct password, we got access to the remote system’s terminal. SSH is very reliable for remote administration because our username and password were sent encrypted; moreover, all commands we execute on the remote system will be sent over an encrypted channel.
Note that if this is the first time we connect to this system, we will need to confirm the fingerprint of the SSH server’s public key to avoid man-in-the-middle (MITM) attacks. As explained earlier, MITM takes place when a malicious party, E, situates itself between A and B, and communicates with A, pretending to be B, and communicates with B pretending to be A, while A and B think that they are communicating directly with each other. In the case of SSH, we don’t usually have a third party to check if the public key is valid, so we need to do this manually. This attack is shown in the image below.

We can use SSH to transfer files using SCP (Secure Copy Protocol) based on the SSH protocol. An example of the syntax is as follows: scp mark@10.10.158.132:/home/mark/archive.tar.gz ~. This command will copy a file named archive.tar.gz from the remote system located in the /home/mark directory to ~, i.e., the root of the home directory of the currently logged-in user.
Another example syntax is scp backup.tar.bz2 mark@10.10.158.132:/home/mark/. This command will copy the file backup.tar.bz2 from the local system to the directory /home/mark/ on the remote system.
scp document.txt mark@10.10.158.132:/home/mark

mark@10.10.158.132's password: 
document.txt                                        100% 1997KB  70.4MB/s   00:00       
As a closing note, FTP could be secured using SSL/TLS by using the FTPS protocol which uses port 990. It is worth mentioning that FTP can also be secured using the SSH protocol which is the SFTP protocol. By default this service listens on port 22, just like SSH.
Password Attack
We discussed network packet captures and MITM attacks as well as how these attacks can be mitigated using TLS and SSH. The third type of attack that we will cover is a password attack.
Many protocols require you to authenticate. Authentication is proving who you claim to be. When we are using protocols such as POP3, we should not be given access to the mailbox before verifying our identity. In the POP3 example below, we are identified as the user frank, and the server authenticated us because we provided the correct password. In other words, the password is one way to authenticate.
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
Authentication, or proving your identity, can be achieved through one of the following, or a combination of two:
Something you know, such as password and PIN code.
Something you have, such as a SIM card, RFID card, and USB dongle.
Something you are, such as fingerprint and iris.
This task will focus on attacks against passwords, i.e. something the target knows. If you revisit the communication with several previous servers using protocols such as Telnet, SSH, POP3, and IMAP, we always need a password to gain access. Based on the 150 million usernames and passwords leaked from the Adobe breach in 2013, the top ten passwords are:
123456
123456789
password
adobe123
12345678
qwerty
1234567
111111
photoshop
123123
Only two passwords are related to Adobe and its products, but the rest are generic. You might think that this has changed over the past decade; however, 123456, 1234567, 12345678, and 123456789 are still common choices for many users. Others haven’t realised yet that qwerty is not secret, and it is used by many as their password.
Attacks against passwords are usually carried out by:
Password Guessing: Guessing a password requires some knowledge of the target, such as their pet’s name and birth year.
Dictionary Attack: This approach expands on password guessing and attempts to include all valid words in a dictionary or a wordlist.
Brute Force Attack: This attack is the most exhaustive and time-consuming where an attacker can go as far as trying all possible character combinations, which grows fast (exponential growth with the number of characters).
Let’s focus on dictionary attacks. Over time, hackers have compiled list after list containing leaked passwords from data breaches. One example is RockYou’s list of breached passwords, which you can find on the AttackBox at /usr/share/wordlists/rockyou.txt. The choice of the word list should depend on your knowledge of the target. For instance, a French user might use a French word instead of an English one. Consequently, a French word list might be more promising.
We want an automated way to try the common passwords or the entries from a word list; here comes THC Hydra. Hydra supports many protocols, including FTP, POP3, IMAP, SMTP, SSH, and all methods related to HTTP. The general command-line syntax is: hydra -l username -P wordlist.txt server service where we specify the following options:
-l username: -l should precede the username, i.e. the login name of the target.
-P wordlist.txt: -P precedes the wordlist.txt file, which is a text file containing the list of passwords you want to try with the provided username.
server is the hostname or IP address of the target server.
service indicates the service which you are trying to launch the dictionary attack.
Consider the following concrete examples:
hydra -l mark -P /usr/share/wordlists/rockyou.txt 10.10.158.132 ftp will use mark as the username as it iterates over the provided passwords against the FTP server.
hydra -l mark -P /usr/share/wordlists/rockyou.txt ftp://10.10.158.132 is identical to the previous example. 10.10.158.132 ftp is the same as ftp://10.10.158.132.
hydra -l frank -P /usr/share/wordlists/rockyou.txt 10.10.158.132 ssh will use frank as the user name as it tries to login via SSH using the different passwords.
There are some extra optional arguments that you can add:
-s PORT to specify a non-default port for the service in question.
-V or -vV, for verbose, makes Hydra show the username and password combinations that are being tried. This verbosity is very convenient to see the progress, especially if you are still not confident of your command-line syntax.
-t n where n is the number of parallel connections to the target. -t 16 will create 16 threads used to connect to the target.
-d, for debugging, to get more detailed information about what’s going on. The debugging output can save you much frustration; for instance, if Hydra tries to connect to a closed port and timing out, -d will reveal this right away.
Once the password is found, you can issue CTRL-C to end the process. In TryHackMe tasks, we expect any attack to finish within less than five minutes; however, the attack would usually take longer in real-life scenarios. Options for verbosity or debugging can be pretty helpful if you want Hydra to update you about its progress.
In summary, attacks against login systems can be carried out efficiently using a tool, such as THC Hydra combined with a suitable word list. Mitigation against such attacks can be sophisticated and depends on the target system. A few of the approaches include:
Password Policy: Enforces minimum complexity constraints on the passwords set by the user.
Account Lockout: Locks the account after a certain number of failed attempts.
Throttling Authentication Attempts: Delays the response to a login attempt. A couple of seconds of delay is tolerable for someone who knows the password, but they can severely hinder automated tools.
Using CAPTCHA: Requires solving a question difficult for machines. It works well if the login page is via a graphical user interface (GUI). (Note that CAPTCHA stands for Completely Automated Public Turing test to tell Computers and Humans Apart.)
Requiring the use of a public certificate for authentication. This approach works well with SSH, for instance.
Two-Factor Authentication: Ask the user to provide a code available via other means, such as email, smartphone app or SMS.
There are many other approaches that are more sophisticated or might require some established knowledge about the user, such as IP-based geolocation.
Using a combination of the above approaches is an excellent approach to protect against password attacks.
Summary
This room covered various protocols, their usage, and how they work under the hood. Three common attacks are:
Sniffing Attack
MITM Attack
Password Attack
For each of the above, we focused both on the attack details and the mitigation steps. Note that many other attacks can be conducted against specific servers and protocols. 
It is good to remember the default port number for common protocols. For convenience, the services we covered are listed in the following table sorted by alphabetical order.
Protocol
TCP Port
Application(s)
Data Security
FTP
21
File Transfer
Cleartext
FTPS
990
File Transfer
Encrypted
HTTP
80
World Wide Web
Cleartext
HTTPS
443
World Wide Web
Encrypted
IMAP
143
Email (MDA)
Cleartext
IMAPS
993
Email (MDA)
Encrypted
POP3
110
Email (MDA)
Cleartext
POP3S
995
Email (MDA)
Encrypted
SFTP
22
File Transfer
Encrypted
SSH
22
Remote Access and File Transfer
Encrypted
SMTP
25
Email (MTA)
Cleartext
SMTPS
465
Email (MTA)
Encrypted
Telnet
23
Remote Access
Cleartext

Hydra remains a very efficient tool that you can launch from the terminal to try the different passwords. We summarise its main options in the following table.
Option
Explanation
-l username
Provide the login name
-P WordList.txt
Specify the password list to use
server service
Set the server address and service to attack
-s PORT
Use in case of non-default service port number
-V or -vV
Show the username and password combinations being tried
-d
Display debugging output if the verbose output is not helping



