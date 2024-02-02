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
* On Linux and macOS use `traceroute TARGET_IP`.
* On MS Windows use `tracert TARGET_IP`. 
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
* TELNET (Teletype Network) protocol was developed in 1969 to communicate with a remote system via a command-line interface (CLI).
* `telnet` uses the TELNET protocol for remote administration.
* Default port used by telnet is TCP/23.
* `telnet` sends all the data including usernames and passwords in cleartext.
  * Sending in cleartext makes it easy for anyone who has access to the communication channel to steal login credentials.
* Secure alternative is SSH (Secure SHell) protocol.
* Use Telnet to connect to any service and grab its banner.
* `telnet TARGET_IP PORT` can connect to any service running on TCP and even exchange a few messages unless it uses encryption.
```
telnet 10.10.190.23 80

Trying 10.10.190.23...
Connected to 10.10.190.23.
Escape character is '^]'.
```
* Request to use HTTP version 1.1 for communication.
* `GET /page.html HTTP/1.1` to specify something other than the default index page.
```
GET / HTTP/1.1
```
* To get a valid response instead of an error input a value for the host `host: telnet` and hit enter twice.
```
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
```    
* Type and version of the installed web server is discovered `Server: nginx/1.6.2`.
* Need to use proper commands based on the protocol such as SMTP and POP3 when connecting to a mail server.

## Netcat
* Netcat (`nc`) has different applications that can be of great value to a pentester.
* Supports both TCP and UDP protocols.
* Can function as a client that connects to a listening port or can act as a server that listens on a port of choice.
  * Convenient tool to use as a simple client or server over TCP or UDP.
* `nc TARGET_IP PORT` to connect to a server to collect its banner.
```
nc 10.10.190.23 80
```
* Issue a get for the default page.
* Specify to the target server that the client supports HTTP version 1.1.
```
GET / HTTP/1.1
```
* May need to press SHIFT+ENTER after the GET line.
* Give a name to the host.
```
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
```   
* Netcat can be used to listen on a TCP port and connect to a listening port on another system.
  * `nc -vnlp PORT_NUMBER` on the *server-side* system where a port should be opened and listened on.
    * Exact order of the letters does not matter as long as the port number is preceded directly by `-p`.
* Connect to listening server from the client-side using `nc SERVER_IP PORT_NUMBER`.
* This setup will echo whatever is typed on one side to the other side of the TCP tunnel.

| Option | Meaning
| --- | ---
| `-l` | Listen mode
| `-p` | Specify the Port number
| `-n` | Numeric only; no resolution of hostnames via DNS
| -v | Verbose output (optional, yet useful to discover any bugs)
| -vv | Very Verbose (optional)
| -k | Keep listening after client disconnects

* Notes:
  * `-p` should appear just before the port number to listen on.
  * '-n' will avoid DNS lookups and warnings.
  * port numbers less than 1024 require root privileges to listen on.

## Putting It All Together

| Command | Example
| --- | ---
| `ping` | `ping -c 10 10.10.190.23` on Linux or macOS
| `ping` | `ping -n 10 10.10.190.23` on MS Windows
| `traceroute` | `traceroute 10.10.190.23` on Linux or macOS
| `tracert` | `tracert 10.10.190.23` on MS Windows
| `telnet` | `telnet 10.10.190.23 PORT_NUMBER`
| netcat as client |  `nc 10.10.190.23 PORT_NUMBER`
| netcat as server | `nc -lvnp PORT_NUMBER`

| Operating System | Developer Tools Shortcut
| --- | ---
| Linux or MS Windows | `Ctrl+Shift+I`
| macOS | `Option + Command + I`
