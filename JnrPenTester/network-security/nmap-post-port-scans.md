# Nmap Post Port Scans

### **Nmap Post Port Scans** <a href="#zgbpb3y0zy3t" id="zgbpb3y0zy3t"></a>

### **Service Detection** <a href="#v69a83r9asc3" id="v69a83r9asc3"></a>

* Probe available ports to detect the running service.
  * Essential piece of information to learn if there are any known vulnerabilities of the service.
* Add -sV to Nmap command to collect and determine service and version information for open ports.
* Control intensity with --version-intensity LEVEL.
  * Level ranges between 0 (the lightest) and 9 (most complete).
    * \-sV --version-light has an intensity of 2.
    * \-sV --version-all has an intensity of 9.
* Using -sV will force Nmap to proceed with the TCP 3-way handshake and establish the connection.
  * Necessary because Nmap cannot discover the version without establishing a connection fully and communicating with the listening service.
  * Stealth SYN scan -sS is not possible with-sV.
* Adding -sV leads to a new column in the output showing the version for each detected service.

sudo nmap -sV 10.10.32.254

Starting Nmap 7.60 ( https://nmap.org ) at 2021-09-10 05:03 BST

Nmap scan report for 10.10.32.254

Host is up (0.0040s latency).

Not shown: 995 closed ports

PORT STATE SERVICE VERSION

22/tcp open ssh OpenSSH 6.7p1 Debian 5+deb8u8 (protocol 2.0)

25/tcp open smtp Postfix smtpd

80/tcp open http nginx 1.6.2

110/tcp open pop3 Dovecot pop3d

111/tcp open rpcbind 2-4 (RPC #100000)

MAC Address: 02:A0:E7:B5:B6:C5 (Unknown)

Service Info: Host: debra2.thm.local; OS: Linux; CPE: cpe:/o:linux:linux\_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .

Nmap done: 1 IP address (1 host up) scanned in 8.40 seconds

* Many Nmap options require root privileges.
* Need to use sudo as in the example above unless you are running Nmap as root.

### **OS Detection and Traceroute** <a href="#id-1yjjt55i80as" id="id-1yjjt55i80as"></a>

#### **OS Detection** <a href="#zfb0tqndthnq" id="zfb0tqndthnq"></a>

* Nmap can detect the Operating System (OS) based on its behaviour and any telltale signs in its responses.
* OS detection enabled using -O.
  * Uppercase O as in OS.

sudo nmap -sS -O 10.10.193.9

Starting Nmap 7.60 ( https://nmap.org ) at 2021-09-10 05:04 BST

Nmap scan report for 10.10.193.9

Host is up (0.00099s latency).

Not shown: 994 closed ports

PORT STATE SERVICE

22/tcp open ssh

25/tcp open smtp

80/tcp open http

110/tcp open pop3

111/tcp open rpcbind

143/tcp open imap

MAC Address: 02:A0:E7:B5:B6:C5 (Unknown)

Device type: general purpose

Running: Linux 3.X

OS CPE: cpe:/o:linux:linux\_kernel:3.13

OS details: Linux 3.13

Network Distance: 1 hop

OS detection performed. Please report any incorrect results at https://nmap.org/submit/ .

Nmap done: 1 IP address (1 host up) scanned in 3.91 seconds

* OS detection is very convenient but many factors might affect its accuracy.
  * Nmap needs to find at least one open and one closed port on the target to make a reliable guess.
  * Guest OS fingerprints might get distorted due to the rising use of virtualization and similar technologies.
* Always take the OS version as a best guess.

#### **Traceroute** <a href="#kkhyw71nw396" id="kkhyw71nw396"></a>

* Add --traceroute to Nmap to find the routers between source and target.
* Nmap’s traceroute works slightly differently than the traceroute command found on Linux and macOS or tracert found on MS Windows.
  * Standard traceroute starts with a packet of low TTL (Time to Live) and keeps increasing until it reaches the target.
  * Nmap’s traceroute starts with a packet of high TTL and keeps decreasing.

sudo nmap -sS --traceroute 10.10.193.9

Starting Nmap 7.60 ( https://nmap.org ) at 2021-09-10 05:05 BST

Nmap scan report for 10.10.193.9

Host is up (0.0015s latency).

Not shown: 994 closed ports

PORT STATE SERVICE

22/tcp open ssh

25/tcp open smtp

80/tcp open http

110/tcp open pop3

111/tcp open rpcbind

143/tcp open imap

MAC Address: 02:A0:E7:B5:B6:C5 (Unknown)

TRACEROUTE

HOP RTT ADDRESS

1 1.48 ms MACHINE\_IP

Nmap done: 1 IP address (1 host up) scanned in 1.59 seconds

* Many routers are configured not to send ICMP Time-to-Live exceeded that would prevent the discovery of their IP addresses.

### **Nmap Scripting Engine (NSE)** <a href="#id-5h4wo5nehqta" id="id-5h4wo5nehqta"></a>

* A script is a piece of code that does not need to be compiled.
  * It remains in its original human-readable form and does not need to be converted to machine language.
* Scripts provide additional / custom functionality that did not exist via the built-in commands.
* Nmap provides support for scripts using the Lua language.
  * Nmap Scripting Engine (NSE) is a Lua interpreter that allows Nmap to execute Nmap scripts written in Lua language.
* Nmap default installation can easily contain close to 600 scripts.
  * Nmap installation folder at /usr/share/nmap/scripts contains hundreds of scripts conveniently named starting with the protocol they target.
* Run the scripts in the default category using --script=default or adding -sC.

| **Script Category** | **Description**                                                        |
| ------------------- | ---------------------------------------------------------------------- |
| auth                | Authentication related scripts                                         |
| broadcast           | Discover hosts by sending broadcast messages                           |
| brute               | Performs brute-force password auditing against logins                  |
| default             | Default scripts, same as -sC                                           |
| discovery           | Retrieve accessible information, such as database tables and DNS names |
| dos                 | Detects servers vulnerable to Denial of Service (DoS)                  |
| exploit             | Attempts to exploit various vulnerable services                        |
| external            | Checks using a third-party service, such as Geoplugin and Virustotal   |
| fuzzer              | Launch fuzzing attacks                                                 |
| intrusive           | Intrusive scripts such as brute-force attacks and exploitation         |
| malware             | Scans for backdoors                                                    |
| safe                | Safe scripts that won’t crash the target                               |
| version             | Retrieve service versions                                              |
| vuln                | Checks for vulnerabilities or exploit vulnerable services              |

* Some scripts belong to more than one category.
* Crucial to be careful when selecting scripts to run to prevent services crashing or inadvertently exploiting them.

sudo nmap -sS -sC 10.10.161.170

Starting Nmap 7.60 ( https://nmap.org ) at 2021-09-10 05:08 BST

Nmap scan report for ip-10-10-161-170.eu-west-1.compute.internal (10.10.161.170)

Host is up (0.0011s latency).

Not shown: 994 closed ports

PORT STATE SERVICE

22/tcp open ssh

\| ssh-hostkey:

\| 1024 d5:80:97:a3:a8:3b:57:78:2f:0a:78:ae:ad:34:24:f4 (DSA)

\| 2048 aa:66:7a:45:eb:d1:8c:00:e3:12:31:d8:76:8e:ed:3a (RSA)

\| 256 3d:82:72:a3:07:49:2e:cb:d9:87:db:08:c6:90:56:65 (ECDSA)

|\_ 256 dc:f0:0c:89:70:87:65:ba:52:b1:e9:59:f7:5d:d2:6a (EdDSA)

25/tcp open smtp

|\_smtp-commands: debra2.thm.local, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN,

\| ssl-cert: Subject: commonName=debra2.thm.local

\| Not valid before: 2021-08-10T12:10:58

|\_Not valid after: 2031-08-08T12:10:58

|\_ssl-date: TLS randomness does not represent time

80/tcp open http

|\_http-title: Welcome to nginx on Debian!

110/tcp open pop3

|\_pop3-capabilities: RESP-CODES CAPA TOP SASL UIDL PIPELINING AUTH-RESP-CODE

111/tcp open rpcbind

\| rpcinfo:

\| program version port/proto service

\| 100000 2,3,4 111/tcp rpcbind

\| 100000 2,3,4 111/udp rpcbind

\| 100024 1 38099/tcp status

|\_ 100024 1 54067/udp status

143/tcp open imap

|\_imap-capabilities: LITERAL+ capabilities IMAP4rev1 OK Pre-login ENABLE have LOGINDISABLEDA0001 listed SASL-IR ID more post-login LOGIN-REFERRALS IDLE

MAC Address: 02:A0:E7:B5:B6:C5 (Unknown)

Nmap done: 1 IP address (1 host up) scanned in 2.21 seconds

* Can also specify the script by name.
  * \--script 'SCRIPT-NAME'.
  * Pattern such as --script "ftp\*".
    * This would include ftp-brute.
* Open the script file with a text reader if unsure what a script does.
* Some scripts are pretty intrusive.
* Some scripts might be for a specific server and if chosen at random will waste time with no benefit.
* Make sure that there is written authorisation to launch such tests on the target server.

sudo nmap -sS -n --script "http-date" 10.10.34.180

Starting Nmap 7.60 ( https://nmap.org ) at 2021-09-10 08:04 BST

Nmap scan report for 10.10.34.180

Host is up (0.0011s latency).

Not shown: 994 closed ports

PORT STATE SERVICE

22/tcp open ssh

25/tcp open smtp

80/tcp open http

|\_http-date: Fri, 10 Sep 2021 07:04:26 GMT; 0s from local time.

110/tcp open pop3

111/tcp open rpcbind

143/tcp open imap

MAC Address: 02:44:87:82:AC:83 (Unknown)

Nmap done: 1 IP address (1 host up) scanned in 1.78 seconds

* Can write custom scripts or download Nmap scripts from the Internet.
  * Downloading and using a Nmap script from the Internet holds a certain level of risk.

### **Saving the Output** <a href="#binvojixj883" id="binvojixj883"></a>

* Save the results in a file whenever an Nmap scan is run.
* Selecting and adopting a good naming convention for the filenames is also crucial.
  * Number of files can quickly grow and hinder the ability to find a previous scan result.
* Four main formats.

1. Normal
2. Grepable (grepable)
3. XML
4. Script Kiddie
   * This format is not recommended.

#### **Normal** <a href="#id-3fo9xrv7y8rm" id="id-3fo9xrv7y8rm"></a>

* Similar to the screen output when scanning a target.
* Save in normal format using -oN FILENAME.
  * N stands for normal.

cat 10.10.99.102\_scan.nmap

\# Nmap 7.60 scan initiated Fri Sep 10 05:14:19 2021 as: nmap -sS -sV -O -oN 10.10.99.102\_scan 10.10.99.102

Nmap scan report for 10.10.99.102

Host is up (0.00086s latency).

Not shown: 994 closed ports

PORT STATE SERVICE VERSION

22/tcp open ssh OpenSSH 6.7p1 Debian 5+deb8u8 (protocol 2.0)

25/tcp open smtp Postfix smtpd

80/tcp open http nginx 1.6.2

110/tcp open pop3 Dovecot pop3d

111/tcp open rpcbind 2-4 (RPC #100000)

143/tcp open imap Dovecot imapd

MAC Address: 02:A0:E7:B5:B6:C5 (Unknown)

Device type: general purpose

Running: Linux 3.X

OS CPE: cpe:/o:linux:linux\_kernel:3.13

OS details: Linux 3.13

Network Distance: 1 hop

Service Info: Host: debra2.thm.local; OS: Linux; CPE: cpe:/o:linux:linux\_kernel

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .

\# Nmap done at Fri Sep 10 05:14:28 2021 -- 1 IP address (1 host up) scanned in 9.99 seconds

#### **Grepable** <a href="#id-9l1kyur1ykwo" id="id-9l1kyur1ykwo"></a>

* Grep stands for Global Regular Expression Printer.
* Makes filtering the scan output for specific keywords or terms efficient.
* Save the scan result using -oG FILENAME.

cat 10.10.99.102\_scan.gnmap

\# Nmap 7.60 scan initiated Fri Sep 10 05:14:19 2021 as: nmap -sS -sV -O -oG 10.10.99.102\_scan 10.10.99.102

Host: 10.10.99.102 Status: Up

Host: 10.10.99.102 Ports: 22/open/tcp//ssh//OpenSSH 6.7p1 Debian 5+deb8u8 (protocol 2.0)/, 25/open/tcp//smtp//Postfix smtpd/, 80/open/tcp//http//nginx 1.6.2/, 110/open/tcp//pop3//Dovecot pop3d/, 111/open/tcp//rpcbind//2-4 (RPC #100000)/, 143/open/tcp//imap//Dovecot imapd/ Ignored State: closed (994) OS: Linux 3.13 Seq Index: 257 IP ID Seq: All zeros

\# Nmap done at Fri Sep 10 05:14:28 2021 -- 1 IP address (1 host up) scanned in 9.99 seconds

* An example use of grep is grep KEYWORD TEXT\_FILE.
  * Displays all the lines containing the provided keyword.

#### **XML** <a href="#bhlnzqh4cxsi" id="bhlnzqh4cxsi"></a>

* Save the scan results in XML format using -oX FILENAME.
* Most convenient to process output in other programs.
* Save the scan output in all three formats using -oA FILENAME to combine -oN, -oG, and -oX for normal, grepable, and XML.

#### **Script Kiddie** <a href="#iqmxdw3irjom" id="iqmxdw3irjom"></a>

* This format is useless if needing to search the output for any interesting keywords or keep the results for future reference.
* Can use it to save the output of the scan nmap -sS 127.0.0.1 -oS FILENAME and look 31337 in front of friends who are not tech-savvy.

cat 10.10.99.102\_scan.kiddie

$tart!ng nMaP 7.60 ( httpz://nMap.0rG ) at 2021-09-10 05:17 B$T

Nmap scan rEp0rt f0r |p-10-10-161-170.EU-w3$t-1.C0mputE.intErnaL (10.10.161.170)

HOSt !s uP (0.00095s LatEncy).

N0T $H0wn: 994 closed pOrtS

PoRT st4Te SeRViC3 VERS1on

22/tcp Open ssH Op3n\$$H 6.7p1 Deb|an 5+dEb8u8 (pr0t0COl 2.0)

25/tCp Op3n SmTp P0$Tf!x Smtpd

80/tcp 0p3n http Ng1nx 1.6.2

110/tCP 0pen pOP3 d0v3coT P0p3D

111/TcP op3n RpcbInd 2-4 (RPC #100000)

143/Tcp opEn Imap Dovecot 1mApd

mAC 4Ddr3sz: 02:40:e7:B5:B6:c5 (Unknown)

Netw0rk d!stanc3: 1 h0p

$3rv1c3 InFO: Ho$t: dEBra2.thM.lOcal; 0s: Linux; cPe: cP3:/0:linux:l|nux\_k3rnel

0S and servIc3 D3tEcti0n pErf0rm3d. Plea$e r3p0rt any !nc0RrecT rE$ultz at hTtpz://nmap.0rg/$ubmit/ .

Nmap d0nE: 1 |P addr3SS (1 hoSt up) $CaNnEd !n 21.80 s3c0Ndz

### **Summary** <a href="#ch7ybblvm29e" id="ch7ybblvm29e"></a>

| **Option**              | **Meaning**                                     |
| ----------------------- | ----------------------------------------------- |
| -sV                     | determine service/version info on open ports    |
| -sV --version-light\`   | try the most likely probes (2)                  |
| -sV --version-all\`     | try all available probes (9)                    |
| -O                      | detect OS                                       |
| --traceroute            | run traceroute to target                        |
| --script=SCRIPTS        | Nmap scripts to run                             |
| -sC or --script=default | run default scripts                             |
| -A                      | equivalent to -sV -O -sC --traceroute           |
| -oN                     | save output in normal format                    |
| -oG                     | save output in grepable format                  |
| -oX                     | save output in XML format                       |
| -oA                     | save output in normal, XML and Grepable formats |

* [Nmap cheat sheet](https://cdn.comparitech.com/wp-content/uploads/2019/06/Nmap-Cheat-Sheet.pdf).
