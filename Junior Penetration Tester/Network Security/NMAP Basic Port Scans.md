# Nmap Basic Port Scans
## TCP and UDP Ports
* TCP or UDP ports identify network services running on a host.
  * Providing time.
  * Responding to DNS queries.
  * Serving web pages.
* No more than one service can listen on any TCP or UDP port (on the same IP address).
  * HTTP server would bind to TCP port 80 by default.
    * If the HTTP server supports SSL/TLS it would listen on TCP port 443.
* Ports are classified in two states:
1. Open port indicates that there is some service listening on that port.
2. Closed port indicates that there is no service listening on that port.
* Consider the impact of firewalls.
  * Port might be open but a firewall might be blocking the packets.
  * Nmap considers six states due to firewall filtering:
    
| State | Meaning
| --- | ---
| Open | A service is listening on the specified port.
| Closed | No service is listening on the specified port although the port is accessible.  Port is reachable and is not blocked by a firewall or other security appliances/programs.
| Filtered | Nmap cannot determine if the port is open or closed because the port is not accessible.  Usually due to a firewall preventing Nmap from reaching that port.
| Unfiltered | Nmap cannot determine if the port is open or closed although the port is accessible. This state is encountered when using an ACK scan `-sA`.
| Open Filtered | Nmap cannot determine whether the port is open or filtered.
| Closed Filtered | Nmap cannot decide whether a port is closed or filtered.

## TCP Flags
* Nmap supports different types of TCP port scans.
* TCP header is the first 24 bytes of a TCP segment.
* TCP header defined in [RFC 793](https://datatracker.ietf.org/doc/html/rfc793.html).

![TCP Header](https://upload.wikimedia.org/wikipedia/commons/c/c8/Ntwk_tcp_header123.jpg?20091215232927)

* In the first row is source TCP port number and the destination port number.
* Port number is allocated 16 bits (2 bytes).
* In the second and third rows is the sequence number and the acknowledgement number.
* Each row has 32 bits (4 bytes) allocated with six rows total making up 24 bytes.
* Setting a flag bit means setting its value to 1.
* TCP header flags.
  * URG: Urgent flag indicates that the urgent pointer filed is significant.
    * Urgent pointer indicates that the incoming data is urgent and that a TCP segment with the URG flag set is processed immediately without consideration of having to wait on previously sent TCP segments.
  * ACK: Acknowledgement flag indicates that the acknowledgement number is significant.
    * Used to acknowledge the receipt of a TCP segment.
  * PSH: Push flag asks TCP to pass the data to the application promptly.
  * RST: Reset flag is used to reset the connection.
    * Another device such as a firewall may send a Reset to tear a TCP connection.
    * Also used when data is sent to a host and there is no service on the receiving end to answer.
  * SYN: Synchronise flag is used to initiate a TCP 3-way handshake and synchronise sequence numbers with the other host.
    * Sequence number should be set randomly during TCP connection establishment.
  * FIN: The sender has no more data to send.

## TCP Connect Scan
* Works by completing the TCP 3-way handshake.
* Connection is torn as soon as its state is confirmed by sending a RST/ACK.
* Run TCP connect scan using `-sT`.
* Important to note that a TCP connect scan is the only possible option to discover open TCP ports if Nmap is not run as a privileged user (`root` or `sudoer`).
* Nmap will attempt to connect to the 1000 most common ports by default.
* Closed TCP port responds to a SYN packet with RST/ACK to indicate that it is not open.
```
nmap -sT 10.10.190.11

Starting Nmap 7.60 ( https://nmap.org ) at 2021-08-30 09:53 BST
Nmap scan report for 10.10.190.11
Host is up (0.0024s latency).
Not shown: 995 closed ports
PORT    STATE SERVICE
22/tcp  open  ssh
25/tcp  open  smtp
80/tcp  open  http
111/tcp open  rpcbind
143/tcp open  imap
MAC Address: 02:45:BF:8A:2D:6B (Unknown)

Nmap done: 1 IP address (1 host up) scanned in 0.40 seconds      
```
* Use `-F` to enable fast mode and decrease the number of scanned ports from 1000 to 100 most common ports.
* Use `-r` option to scan the ports in consecutive order instead of random order.
  * Useful when testing whether ports open in a consistent manner.
  * For instance when a target boots up.

## TCP SYN Scan
* Unprivileged users are limited to TCP connect scans.
* Default scan mode for a privileged (root or sudoer) user is SYN scan.
* SYN scan does not need to complete the TCP 3-way handshake.
  * Nmap sends an RST packet once a SYN/ACK packet is received.
  * This decreases the chances of the scan being logged because we didn’t establish a TCP connection.
* Use this scan type by using the `-sS` option.
```
sudo nmap -sS 10.10.190.11

Starting Nmap 7.60 ( https://nmap.org ) at 2021-08-30 09:53 BST
Nmap scan report for 10.10.190.11
Host is up (0.0073s latency).
Not shown: 994 closed ports
PORT    STATE SERVICE
22/tcp  open  ssh
25/tcp  open  smtp
80/tcp  open  http
110/tcp open  pop3
111/tcp open  rpcbind
143/tcp open  imap
MAC Address: 02:45:BF:8A:2D:6B (Unknown)

Nmap done: 1 IP address (1 host up) scanned in 1.60 seconds
```

## UDP Scan
* UDP is a connectionless protocol.
* Does not require any handshake for connection establishment.
* Cannot guarantee that a service listening on a UDP port would respond to Nmap packets.
* Cannot expect any reply in return if a UDP packet is sent to an open UDP port.
  * UDP ports that do not generate any response are the ones that Nmap will state as open.
* If a UDP packet is sent to a closed port an ICMP packet of type 3, destination unreachable, and code 3, port unreachable is returned.
* Select UDP scan using the `-sU` option.
```
sudo nmap -sU 10.10.145.131

Starting Nmap 7.60 ( https://nmap.org ) at 2021-08-30 09:54 BST
Nmap scan report for 10.10.145.131
Host is up (0.00061s latency).
Not shown: 998 closed ports
PORT    STATE         SERVICE
68/udp  open|filtered dhcpc
111/udp open          rpcbind
MAC Address: 02:45:BF:8A:2D:6B (Unknown)

Nmap done: 1 IP address (1 host up) scanned in 1085.05 seconds
```
* A new service has been installed on the target since the last scan.
* Use the terminal on the attacking machine to execute `nmap -sU -F -v 10.10.145.131`.
```
Starting Nmap 7.60 ( https://nmap.org ) at 2023-12-15 11:11 GMT
Initiating ARP Ping Scan at 11:11
Scanning 10.10.15.253 [1 port]
Completed ARP Ping Scan at 11:11, 0.22s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 11:11
Completed Parallel DNS resolution of 1 host. at 11:11, 0.00s elapsed
Initiating UDP Scan at 11:11
Scanning ip-10-10-15-253.eu-west-1.compute.internal (10.10.15.253) [100 ports]
Increasing send delay for 10.10.15.253 from 0 to 50 due to max_successful_tryno increase to 4
Increasing send delay for 10.10.15.253 from 50 to 100 due to max_successful_tryno increase to 5
Increasing send delay for 10.10.15.253 from 100 to 200 due to max_successful_tryno increase to 6
Increasing send delay for 10.10.15.253 from 200 to 400 due to max_successful_tryno increase to 7
Increasing send delay for 10.10.15.253 from 400 to 800 due to 11 out of 18 dropped probes since last increase.
UDP Scan Timing: About 42.78% done; ETC: 11:13 (0:00:41 remaining)
Discovered open port 53/udp on 10.10.15.253
Discovered open port 111/udp on 10.10.15.253
Completed UDP Scan at 11:13, 98.56s elapsed (100 total ports)
Nmap scan report for ip-10-10-15-253.eu-west-1.compute.internal (10.10.15.253)
Host is up (0.00046s latency).
Not shown: 97 closed ports
PORT	STATE     	SERVICE
53/udp  open      	domain
68/udp  open|filtered dhcpc
111/udp open      	rpcbind
MAC Address: 02:E0:4A:AF:D7:05 (Unknown)

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 98.92 seconds
       	Raw packets sent: 210 (7.134KB) | Rcvd: 108 (6.745KB)
```

## Fine-Tuning Scope and Performance
* Specify the ports to scan instead of the default 1000 ports.
  * port list: `-p22,80,443`.
  * port range: `-p1-1023` will scan all ports between 1 and 1023 inclusive.
    * `-p20-25` will scan ports between 20 and 25 inclusive.
* Scan of all 65535 ports using `-p-`.
* Scan the most common 100 ports using `-F`.
* `--top-ports 10` will check the ten most common ports.
* Control the scan timing using `-T<0-5>`.
  * Six scan timing templates available.
    * Paranoid (0)
      * `-T0` scans one port at a time and waits 5 minutes between sending each probe.
    * Sneaky (1)
      * Often used during real engagements where stealth is important.
    * Polite (2)
    * Normal (3)
      * Default timing.
    * Aggressive (4)
      * Often used during CTFs and when learning to scan on practice targets.
    * Insane (5)
      *  Can affect the accuracy of the scan results due to the increased likelihood of packet loss.
  * Use `-T0` or `-T1` to avoid IDS alerts.
* Control packet rate using `--min-rate <number>` and `--max-rate <number>`.
  * `--max-rate 10` or `--max-rate=10` ensures that the scanner is not sending more than ten packets per second.
* Control probing parallelisation using `--min-parallelism <numprobes>` and `--max-parallelism <numprobes>`.
  * Nmap probes the targets to discover which hosts are live and which ports are open.
  * Probing parallelisation specifies the number of such probes that can be run in parallel.
  * `--min-parallelism=512` pushes Nmap to maintain at least 512 probes in parallel.

## Summary

| Port Scan Type | Example Command
| --- | ---
| TCP Connect Scan | `nmap -sT 10.10.15.253`
| TCP SYN Scan | `sudo nmap -sS 10.10.15.253`
| UDP Scan | `sudo nmap -sU 10.10.15.253`

| Option | Purpose
| --- | ---
| `-p-` | all ports
| `-p1-1023`  | scan ports 1 to 1023
| `-F` | 100 most common ports
| `-r` | scan ports in consecutive order
| `-T<0-5>` | `-T0` being the slowest and T5 the fastest
| `--max-rate 50` | rate <= 50 packets/sec
| `--min-rate 15` |  rate >= 15 packets/sec
| `--min-parallelism 100` | at least 100 probes in parallel
