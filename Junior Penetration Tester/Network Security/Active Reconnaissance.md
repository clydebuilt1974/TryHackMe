# Active Reconnaissance
* **Do not engage in active reconnaissance work before getting signed legal authorisation from the client**.
* Active reconnaissance requires some kind of contact to be made with the target.
  * Social engineering.
  * Direct connection to a target system.
    * A connection might leave information in the logs.
      * Hide active reconnaissance as regular client activity.
        * No one should suspect a browser connected to a target web server among hundreds of other legitimate users.

## Web Browser
* TCP/80 by default when a website is accessed over HTTP.
* TCP/443 by default when accessed over HTTPS.
* Can use custom ports to access a service.
  * `https://127.0.0.1:8834/` will connect to 127.0.0.1 (localhost) at port 8834 via HTTPS protocol.
* Developer Tools allow inspection of things that the browser has received and exchanged with the remote server.
  * View and modify JavaScript (JS) files.
  * Inspect cookies set on the system.
  * Discover the folder structure of the site content.
* Add-ons for Firefox and Chrome can help in penetration testing.
  * **FoxyProxy** quickly changes the proxy server being using to access the target website.
    * Convenient when using a tool such as Burp Suite.
    * Get FoxyProxy for Firefox from [here](https://addons.mozilla.org/en-US/firefox/addon/foxyproxy-standard).
  * **User-Agent Switcher and Manager** pretends to access a webpage from a different OS or different web browser.
    * Pretend to browse a site using an iPhone when accessing it from Mozilla Firefox.
    * Download User-Agent Switcher and Manager for Firefox [here](https://addons.mozilla.org/en-US/firefox/addon/user-agent-string-switcher).
  * **Wappalyzer** provides insights about the technologies used on the visited websites.
  * Get Wappalyzer for Firefox [here](https://addons.mozilla.org/en-US/firefox/addon/wappalyzer).

## Ping
* Sends an ICMP Echo Request (type 8) packet to a remote system and the remote system sends back an ICMP Echo Reply (type 0).
  * Checks whether the remote system is online and that the network is working between the two systems.
* Use to ensure that a target system is online before time is spent carrying out more detailed scans to discover the running operating system and services.
```
ping 10.10.10.10
```
```
ping example.com
```
* System must be able to resolve example.com before sending the ICMP Echo Request packet.
* `ping -c 10 10.10.190.23` sends ten packets on Linux.
  * CTRL+c forces ping to stop if count is not specified.
  * Equivalent to `ping -n 10 10.10.190.23` on Windows.
* Ping falls under the protocol ICMP (Internet Control Message Protocol).
* There are a few explanations that could explain why a ping reply is not received.
  * Destination is not responsive.
    * Possibly still booting up.
    * Turned off.
    * OS has crashed.
  * Destination is unplugged from the network.
  * Faulty network device across the path.
  * A firewall is configured to block such packets.
    * Firewall might be software running on the remote system or a network appliance.
    * Note that MS Windows firewall blocks ping by default.
  * Source system is unplugged from the network.

## Traceroute
* Traces the route taken by the packets from source system to another host.
* On Linux and macOS use `traceroute MACHINE_IP`.
* On MS Windows use `tracert MACHINE_IP`. 
* Purpose is to find the IP addresses of the routers (or hops) that a packet traverses.  
* Route taken by the packets may change as many routers use dynamic routing protocols that adapt to network changes.
* Relies on ICMP to 'trick' the routers into revealing their IP addresses.
  * Uses a small Time To Live (TTL) in the IP header field.
    * TTL indicates the maximum number of routers/hops that a packet can pass through before being dropped.
  * When a router receives a packet it decrements the TTL by one before passing it to the next router.
  * If TTL reaches 0 it is dropped and an ICMP Time-to-Live exceeded in-transit error message is sent to the original sender.
    * Some routers are configured not to send such ICMP messages when discarding a packet.
* Traceroute will start by sending UDP datagrams within IP packets of TTL=1 on Linux.
  * First router encounters TTL=0 and sends an ICMP Time-to-Live exceeded back.
    * TTL of 1 will reveal the IP address of the first router.
  * Another packet is sent with TTL=2.
    * This packet will be dropped at the second router.
  * And so on.
* The number of hops/routers between source and target system depends on the time when traceroute is run.
  * There is no guarantee that the packets will always follow the same route even if on the same network or if the traceroute command is repeated within a short time.
* Some routers return a public IP address.
  * A few of these routers might be examined based on the scope of the intended penetration testing.
* Some routers do not return a reply.

## Telnet
The TELNET (Teletype Network) protocol was developed in 1969 to communicate with a remote system via a command-line interface (CLI). Hence, the command telnet uses the TELNET protocol for remote administration. The default port used by telnet is 23. From a security perspective, telnet sends all the data, including usernames and passwords, in cleartext. Sending in cleartext makes it easy for anyone, who has access to the communication channel, to steal the login credentials. The secure alternative is SSH (Secure SHell) protocol.
However, the telnet client, with its simplicity, can be used for other purposes. Knowing that telnet client relies on the TCP protocol, you can use Telnet to connect to any service and grab its banner. Using telnet 10.10.190.23 PORT, you can connect to any service running on TCP and even exchange a few messages unless it uses encryption.
Let’s say we want to discover more information about a web server, listening on port 80. We connect to the server at port 80, and then we communicate using the HTTP protocol. You don’t need to dive into the HTTP protocol; you just need to issue GET / HTTP/1.1. To specify something other than the default index page, you can issue GET /page.html HTTP/1.1, which will request page.html. We also specified to the remote web server that we want to use HTTP version 1.1 for communication. To get a valid response, instead of an error, you need to input some value for the host host: example and hit enter twice. Executing these steps will provide the requested index page.
telnet 10.10.190.23 80

Trying 10.10.190.23...
Connected to 10.10.190.23.
Escape character is '^]'.
GET / HTTP/1.1
host: telnet

HTTP/1.1 200 OK
Server: nginx/1.6.2
Date: Tue, 17 Aug 2021 11:13:25 GMT
Content-Type: text/html
Content-Length: 867
Last-Modified: Tue, 17 Aug 2021 11:12:16 GMT
Connection: keep-alive
ETag: "611b9990-363"
Accept-Ranges: bytes
...      
Of particular interest for us is discovering the type and version of the installed web server, Server: nginx/1.6.2. In this example, we communicated with a web server, so we used basic HTTP commands. If we connect to a mail server, we need to use proper commands based on the protocol, such as SMTP and POP3.
Netcat
Netcat or simply nc has different applications that can be of great value to a pentester. Netcat supports both TCP and UDP protocols. It can function as a client that connects to a listening port; alternatively, it can act as a server that listens on a port of your choice. Hence, it is a convenient tool that you can use as a simple client or server over TCP or UDP.
First, you can connect to a server, as you did with Telnet, to collect its banner using nc 10.10.190.23 PORT, which is quite similar to our previous telnet 10.10.190.23 PORT. Note that you might need to press SHIFT+ENTER after the GET line.
nc 10.10.190.23 80

GET / HTTP/1.1
host: netcat

HTTP/1.1 200 OK
Server: nginx/1.6.2
Date: Tue, 17 Aug 2021 11:39:49 GMT
Content-Type: text/html
Content-Length: 867
Last-Modified: Tue, 17 Aug 2021 11:12:16 GMT
Connection: keep-alive
ETag: "611b9990-363"
Accept-Ranges: bytes
...       
In the terminal shown above, we used netcat to connect to 10.10.190.23 port 80 using nc 10.10.190.23 80. Next, we issued a get for the default page using GET / HTTP/1.1; we are specifying to the target server that our client supports HTTP version 1.1. Finally, we need to give a name to our host, so we added on a new line, host: netcat; you can name your host anything as this has no impact on this exercise.
Based on the output Server: nginx/1.6.2 we received, we can tell that on port 80, we have Nginx version 1.6.2 listening for incoming connections.
You can use netcat to listen on a TCP port and connect to a listening port on another system.
On the server system, where you want to open a port and listen on it, you can issue nc -lp 1234 or better yet, nc -vnlp 1234, which is equivalent to nc -v -l -n -p 1234. The exact order of the letters does not matter as long as the port number is preceded directly by -p.
option
meaning
-l
Listen mode
-p
Specify the Port number
-n
Numeric only; no resolution of hostnames via DNS
-v
Verbose output (optional, yet useful to discover any bugs)
-vv
Very Verbose (optional)
-k
Keep listening after client disconnects

Notes:
the option -p should appear just before the port number you want to listen on.
the option -n will avoid DNS lookups and warnings.
port numbers less than 1024 require root privileges to listen on.
On the client-side, you would issue nc 10.10.190.23 PORT_NUMBER. Here is an example of using nc to echo. After you successfully establish a connection to the server, whatever you type on the client-side will be echoed on the server-side and vice versa.
Consider the following example. On the server-side, we will listen on port 1234. We can achieve this with the command nc -vnlp 1234 (same as nc -lvnp 1234). In our case, the listening server has the IP address 10.10.190.23, so we can connect to it from the client-side by executing nc 10.10.190.23 1234. This setup would echo whatever you type on one side to the other side of the TCP tunnel. You can find a recording of the process below. Note that the listening server is on the left side of the screen.
Putting It All Together
In this room, we have covered many various tools. It is easy to put a few of them together via a shell script to build a primitive network and system scanner. You can use traceroute to map the path to the target, ping to check if the target system responds to ICMP Echo, and telnet to check which ports are open and reachable by attempting to connect to them. Available scanners do this at much more advanced and sophisticated levels, as we will see in the next four rooms with nmap.
Command
Example
ping
ping -c 10 10.10.190.23 on Linux or macOS
ping
ping -n 10 10.10.190.23 on MS Windows
traceroute
traceroute 10.10.190.23 on Linux or macOS
tracert
tracert 10.10.190.23 on MS Windows
telnet
telnet 10.10.190.23 PORT_NUMBER
netcat as client
nc 10.10.190.23 PORT_NUMBER
netcat as server
nc -lvnp PORT_NUMBER

Although these are fundamental tools, they are readily available on most systems. In particular, a web browser is installed on practically every computer and smartphone and can be an essential tool in your arsenal for conducting reconnaissance without raising alarms.
Operating System
Developer Tools Shortcut
Linux or MS Windows
Ctrl+Shift+I
macOS
Option + Command + I

