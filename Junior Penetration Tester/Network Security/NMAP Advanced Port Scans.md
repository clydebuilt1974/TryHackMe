# Nmap Advanced Port Scans
## TCP Null Scan, FIN Scan, and Xmas Scan
### Null Scan
* All six flag bits are set to zero.
* Choose this scan using `-sN`.
* TCP packet with no flags set will not trigger any response when it reaches an open port.
* Lack of reply indicates that either the port is open or a firewall is blocking the packet.
* Expect the target server to respond with an RST packet if the port is closed.
  * Use the lack of RST response to determine that the ports that are either open or filtered.
```
sudo nmap -sN 10.10.203.206

Starting Nmap 7.60 ( https://nmap.org ) at 2021-08-30 10:30 BST
Nmap scan report for 10.10.203.206
Host is up (0.00066s latency).
Not shown: 994 closed ports
PORT    STATE         SERVICE
22/tcp  open|filtered ssh
25/tcp  open|filtered smtp
80/tcp  open|filtered http
110/tcp open|filtered pop3
111/tcp open|filtered rpcbind
143/tcp open|filtered imap
MAC Address: 02:45:BF:8A:2D:6B (Unknown)

Nmap done: 1 IP address (1 host up) scanned in 96.50 seconds
```
* Note that many Nmap options require root privileges.
  * Use `sudo` using the `-sN` option unless running Nmap as `root`.

### FIN Scan
* Sends TCP packet with FIN flag set.
* Choose this scan type using `-sF`.
* No response will be sent if the TCP port is open.
  * Nmap cannot be sure if the port is open or if a firewall is blocking (filtering) the traffic related to this TCP port.
* Target system should respond with a RST if the port is closed.
  * Some firewalls will 'silently' drop the traffic without sending an RST.
```
sudo nmap -sF 10.10.203.206

Starting Nmap 7.60 ( https://nmap.org ) at 2021-08-30 10:32 BST
Nmap scan report for 10.10.203.206
Host is up (0.0018s latency).
Not shown: 994 closed ports
PORT    STATE         SERVICE
22/tcp  open|filtered ssh
25/tcp  open|filtered smtp
80/tcp  open|filtered http
110/tcp open|filtered pop3
111/tcp open|filtered rpcbind
143/tcp open|filtered imap
MAC Address: 02:45:BF:8A:2D:6B (Unknown)

Nmap done: 1 IP address (1 host up) scanned in 96.52 seconds
```

### Xmas Scan
* Gets its name after Christmas tree lights.
* Sets the FIN, PSH, and URG flags simultaneously.
* Select with the option `-sX`.
* Like the Null and FIN scan it means that the port is closed if an RST packet is received.
* Otherwise it will be reported as open|filtered.
```
sudo nmap -sX 10.10.203.206

Starting Nmap 7.60 ( https://nmap.org ) at 2021-08-30 10:34 BST
Nmap scan report for 10.10.203.206
Host is up (0.00087s latency).
Not shown: 994 closed ports
PORT    STATE         SERVICE
22/tcp  open|filtered ssh
25/tcp  open|filtered smtp
80/tcp  open|filtered http
110/tcp open|filtered pop3
111/tcp open|filtered rpcbind
143/tcp open|filtered imap
MAC Address: 02:45:BF:8A:2D:6B (Unknown)

Nmap done: 1 IP address (1 host up) scanned in 84.85 seconds      
```
* One scenario where these three scan types can be efficient is when scanning a target behind a stateless (non-stateful) firewall.
  * A stateless firewall will check if the incoming packet has the SYN flag set to detect a connection attempt.
  * Using a flag combination that does not match the SYN packet makes it possible to deceive the firewall and reach the system behind it.
    * Stateful firewalls will practically block all such crafted packets and render this kind of scan useless.

## TCP Maimon Scan
* Uriel Maimon first described this scan in 1996.
* FIN and ACK bits are set.
* Most target systems respond with an RST packet regardless of whether the TCP port is open.
  * Will not be able to discover the open ports.
  * Certain BSD-derived systems drop the packet if it is an open port.
    *  This exposes the open ports.
* This scan won’t work on most targets encountered in modern networks.
* Use this scan with the `-sM` option.
```
sudo nmap -sM 10.10.252.27

Starting Nmap 7.60 ( https://nmap.org ) at 2021-08-30 10:36 BST
Nmap scan report for ip-10-10-252-27.eu-west-1.compute.internal (10.10.252.27)
Host is up (0.00095s latency).
All 1000 scanned ports on ip-10-10-252-27.eu-west-1.compute.internal (10.10.252.27) are closed
MAC Address: 02:45:BF:8A:2D:6B (Unknown)

Nmap done: 1 IP address (1 host up) scanned in 1.61 seconds     
```

## TCP ACK, Window, and Custom Scan
### TCP ACK Scan
* Let’s start with the TCP ACK scan. As the name implies, an ACK scan will send a TCP packet with the ACK flag set.
* Use the -sA option to choose this scan.
* As we show in the figure below, the target would respond to the ACK with RST regardless of the state of the port.
* This behaviour happens because a TCP packet with the ACK flag set should be sent only in response to a received TCP packet to acknowledge the receipt of some data, unlike our case.
* Hence, this scan won’t tell us whether the target port is open in a simple setup.
* In the following example, we scanned the target VM before installing a firewall on it.
* As expected, we couldn’t learn which ports were open.
```
sudo nmap -sA 10.10.221.216

Starting Nmap 7.60 ( https://nmap.org ) at 2021-08-30 10:37 BST
Nmap scan report for 10.10.221.216
Host is up (0.0013s latency).
All 1000 scanned ports on 10.10.221.216 are unfiltered
MAC Address: 02:45:BF:8A:2D:6B (Unknown)

Nmap done: 1 IP address (1 host up) scanned in 1.68 seconds      
```
* This kind of scan would be helpful if there is a firewall in front of the target.
* Consequently, based on which ACK packets resulted in responses, you will learn which ports were not blocked by the firewall.
* In other words, this type of scan is more suitable to discover firewall rule sets and configuration.
* After setting up the target 10.10.221.216 with a firewall, we repeated the ACK scan.
* This time, we received some interesting results. As seen in the console output below, we have three ports that aren't being blocked by the firewall.
* This result indicates that the firewall is blocking all other ports except for these three ports.
```
sudo nmap -sA 10.10.221.216

Starting Nmap 7.60 ( https://nmap.org ) at 2021-09-07 11:34 BST
Nmap scan report for 10.10.221.216
Host is up (0.00046s latency).
Not shown: 997 filtered ports
PORT    STATE      SERVICE
22/tcp  unfiltered ssh
25/tcp  unfiltered smtp
80/tcp  unfiltered http
MAC Address: 02:78:C0:D0:4E:E9 (Unknown)

Nmap done: 1 IP address (1 host up) scanned in 15.45 seconds
```
### Window Scan
* Almost the same as the ACK scan.
  * Examines the TCP Window field of the RST packets returned.
* Can reveal that the port is open on specific systems.
* Select this scan type using `-sW`.
* Expect to get an RST packet in reply to the “uninvited” ACK packets regardless of whether the port is open or closed.
```
sudo nmap -sW 10.10.252.27

Starting Nmap 7.60 ( https://nmap.org ) at 2021-08-30 10:38 BST
Nmap scan report for 10.10.252.27
Host is up (0.0011s latency).
All 1000 scanned ports on ip-10-10-252-27.eu-west-1.compute.internal (10.10.252.27) are closed
MAC Address: 02:45:BF:8A:2D:6B (Unknown)

Nmap done: 1 IP address (1 host up) scanned in 1.60 seconds  
```
* Repeating the TCP window scan against a server behind a firewall can provide more satisfying results.
  * TCP window scan pointed out that three ports are detected as closed.
    * This is in contrast with the ACK scan that labelled the same three ports as unfiltered.
* Ports responded differently indicating that the firewall does not block them.
```
sudo nmap -sW 10.10.252.27

Starting Nmap 7.60 ( https://nmap.org ) at 2021-09-07 11:39 BST
Nmap scan report for 10.10.252.27
Host is up (0.00040s latency).
Not shown: 997 filtered ports
PORT    STATE  SERVICE
22/tcp  closed ssh
25/tcp  closed smtp
80/tcp  closed http
MAC Address: 02:78:C0:D0:4E:E9 (Unknown)

Nmap done: 1 IP address (1 host up) scanned in 14.84 seconds      
```
### Custom Scan
* Use `--scanflags` to experiment with a new TCP flag combination.
  * Set SYN, RST, and FIN simultaneously using `--scanflags RSTSYNFIN`.
* Need to know how the different ports will behave to interpret the results in different scenarios correctly.
* Just because a firewall is not blocking a specific port it does not mean that a service is listening on that port.
  * ACK and window scans expose the firewall rules not the services.

### Spoofing and Decoys
* Scan a target system using a spoofed IP address and even a spoofed MAC address.
* Only beneficial in a situation where capturing the response is guaranteed.
  * No response would be routed back if scanning a target from some random network using a spoofed IP address.
* Scanning with a spoofed IP address uses three steps.
1. Attacker sends a packet with a spoofed source IP address to the target machine.
2. Target machine replies to the spoofed IP address as the destination.
3. Attacker captures the replies to figure out open ports.
* Issue `nmap -e NET_INTERFACE -Pn -S SPOOFED_IP 10.10.221.216`.
  * Specify the network interface to receive ping replies using `-e`.
  * Explicitly disable ping scan using `-Pn`.
* This scan will be useless if the attacker system cannot monitor the network for responses.
* Spoof source MAC address as when on the same subnet as the target machine.
  * Use `--spoof-mac SPOOFED_MAC`.
* Address spoofing is only possible if the attacker and the target machine are on the same Ethernet (802.3) network or same WiFi (802.11).
* Attacker might resort to using decoys to make it more challenging to be pinpointed.
  * Make the scan appear to be coming from many IP addresses so that the attacker’s IP address would be lost among them.
* Launch a decoy scan by specifying a specific or random IP address after `-D`.
  * `nmap -D 10.10.0.1,10.10.0.2,ME 10.10.221.216` will make the scan of 10.10.221.216 appear as coming from the IP addresses 10.10.0.1, 10.10.0.2, and then ME to indicate that 'real' IP address should appear in the third order.
  * `nmap -D 10.10.0.1,10.10.0.2,RND,RND,ME 10.10.221.216` assign the the third and fourth source IP addresses randomly while the fifth source is going to be the attacker’s IP address.

## Fragmented Packets
### Firewall
* Piece of software or hardware that permits packets to pass through or blocks them.
* Functions based on firewall rules.
  * Summarised as blocking all traffic with exceptions or allowing all traffic with exceptions.
* Traditional firewall inspects the IP header and the transport layer header.
* More sophisticated firewalls also try to examine the data carried by the transport layer.

### IDS
* Intrusion detection system (IDS) inspects network packets for select behavioural patterns or specific content signatures.
* Raises an alert whenever a malicious rule is met.
* Inspects data contents in the transport layer and checks if it matches any malicious patterns.

### Fragmented Packets
* Nmap provides the option `-f` to fragment packets.
* IP data will be divided into 8 bytes or less.
* Adding another `-f` (`-f` -`f` or `-ff`) will split the data into 16 byte-fragments instead of 8.
* Can change the default value by using the `--mtu`.
  * Always choose a multiple of 8.
![IP Header](https://upload.wikimedia.org/wikipedia/commons/thumb/8/88/IPv4_Header.svg/1022px-IPv4_Header.svg.png?20111002121853)
* Source address takes 32 bits (4 bytes) on the fourth row.
* Destination address takes another 4 bytes on the fifth row.
* IP uses the identification (ID) and fragment offset to aid in the reassembly on the recipient side.
* Can increase the size of the packets to make them look innocuous using `--data-length NUM`.
  * NUM specifies the number of bytes to append to the packets.

### Idle/Zombie Scan
* Spoofing the source IP address can be a great approach to scanning stealthily.
* However, spoofing will only work in specific network setups.
* It requires you to be in a position where you can monitor the traffic.
* Considering these limitations, spoofing your IP address can have little use; however, we can give it an upgrade with the idle scan.
* The idle scan, or zombie scan, requires an idle system connected to the network that you can communicate with.
* Practically, Nmap will make each probe appear as if coming from the idle (zombie) host, then it will check for indicators whether the idle (zombie) host received any response to the spoofed probe.
* This is accomplished by checking the IP identification (IP ID) value in the IP header. You can run an idle scan using nmap -sI ZOMBIE_IP 10.10.221.216, where ZOMBIE_IP is the IP address of the idle host (zombie).
* The idle (zombie) scan requires the following three steps to discover whether a port is open:
* Trigger the idle host to respond so that you can record the current IP ID on the idle host.
* Send a SYN packet to a TCP port on the target.
* The packet should be spoofed to appear as if it was coming from the idle host (zombie) IP address.
* Trigger the idle machine again to respond so that you can compare the new IP ID with the one received earlier.
* Let’s explain with figures.
* In the figure below, we have the attacker system probing an idle machine, a multi-function printer.
* By sending a SYN/ACK, it responds with an RST packet containing its newly incremented IP ID.
* The attacker will send a SYN packet to the TCP port they want to check on the target machine in the next step.
* However, this packet will use the idle host (zombie) IP address as the source.
* Three scenarios would arise. In the first scenario, shown in the figure below, the TCP port is closed; therefore, the target machine responds to the idle host with an RST packet.
* The idle host does not respond; hence its IP ID is not incremented.
* In the second scenario, as shown below, the TCP port is open, so the target machine responds with a SYN/ACK to the idle host (zombie).
* The idle host responds to this unexpected packet with an RST packet, thus incrementing its IP ID.
* In the third scenario, the target machine does not respond at all due to firewall rules.
* This lack of response will lead to the same result as with the closed port; the idle host won’t increase the IP ID.
* For the final step, the attacker sends another SYN/ACK to the idle host.
* The idle host responds with an RST packet, incrementing the IP ID by one again.
* The attacker needs to compare the IP ID of the RST packet received in the first step with the IP ID of the RST packet received in this third step.
* If the difference is 1, it means the port on the target machine was closed or filtered.
* However, if the difference is 2, it means that the port on the target was open.
* It is worth repeating that this scan is called an idle scan because choosing an idle host is indispensable for the accuracy of the scan.
* If the “idle host” is busy, all the returned IP IDs would be useless.

## Getting More Details
* You might consider adding --reason if you want Nmap to provide more details regarding its reasoning and conclusions.
* Consider the two scans below to the system; however, the latter adds --reason.
```
sudo nmap -sS 10.10.252.27

Starting Nmap 7.60 ( https://nmap.org ) at 2021-08-30 10:39 BST
Nmap scan report for ip-10-10-252-27.eu-west-1.compute.internal (10.10.252.27)
Host is up (0.0020s latency).
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
```       
sudo nmap -sS --reason 10.10.252.27

Starting Nmap 7.60 ( https://nmap.org ) at 2021-08-30 10:40 BST
Nmap scan report for ip-10-10-252-27.eu-west-1.compute.internal (10.10.252.27)
Host is up, received arp-response (0.0020s latency).
Not shown: 994 closed ports
Reason: 994 resets
PORT    STATE SERVICE REASON
22/tcp  open  ssh     syn-ack ttl 64
25/tcp  open  smtp    syn-ack ttl 64
80/tcp  open  http    syn-ack ttl 64
110/tcp open  pop3    syn-ack ttl 64
111/tcp open  rpcbind syn-ack ttl 64
143/tcp open  imap    syn-ack ttl 64
MAC Address: 02:45:BF:8A:2D:6B (Unknown)

Nmap done: 1 IP address (1 host up) scanned in 1.59 seconds
```
* Providing the --reason flag gives us the explicit reason why Nmap concluded that the system is up or a particular port is open.
* In this console output above, we can see that this system is considered online because Nmap “received arp-response.”
* On the other hand, we know that the SSH port is deemed to be open because Nmap received a “syn-ack” packet back.
* For more detailed output, you can consider using -v for verbose output or -vv for even more verbosity.
```
sudo nmap -sS -vv 10.10.252.27

Starting Nmap 7.60 ( https://nmap.org ) at 2021-08-30 10:41 BST
Initiating ARP Ping Scan at 10:41
Scanning 10.10.252.27 [1 port]
Completed ARP Ping Scan at 10:41, 0.22s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 10:41
Completed Parallel DNS resolution of 1 host. at 10:41, 0.00s elapsed
Initiating SYN Stealth Scan at 10:41
Scanning ip-10-10-252-27.eu-west-1.compute.internal (10.10.252.27) [1000 ports]
Discovered open port 22/tcp on 10.10.252.27
Discovered open port 25/tcp on 10.10.252.27
Discovered open port 80/tcp on 10.10.252.27
Discovered open port 110/tcp on 10.10.252.27
Discovered open port 111/tcp on 10.10.252.27
Discovered open port 143/tcp on 10.10.252.27
Completed SYN Stealth Scan at 10:41, 1.25s elapsed (1000 total ports)
Nmap scan report for ip-10-10-252-27.eu-west-1.compute.internal (10.10.252.27)
Host is up, received arp-response (0.0019s latency).
Scanned at 2021-08-30 10:41:02 BST for 1s
Not shown: 994 closed ports
Reason: 994 resets
PORT    STATE SERVICE REASON
22/tcp  open  ssh     syn-ack ttl 64
25/tcp  open  smtp    syn-ack ttl 64
80/tcp  open  http    syn-ack ttl 64
110/tcp open  pop3    syn-ack ttl 64
111/tcp open  rpcbind syn-ack ttl 64
143/tcp open  imap    syn-ack ttl 64
MAC Address: 02:45:BF:8A:2D:6B (Unknown)

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 1.59 seconds
           Raw packets sent: 1002 (44.072KB) | Rcvd: 1002 (40.092KB)    
```
* If `-vv` does not satisfy your curiosity, you can use -d for debugging details or -dd for even more details.
* You can guarantee that using -d will create an output that extends beyond a single screen.

## Summary

| Port Scan Type | Example Command
| --- | ---
| TCP Null Scan | `sudo nmap -sN 10.10.21.218`
| TCP FIN Scan | `sudo nmap -sF 10.10.21.218`
| TCP Xmas Scan | `sudo nmap -sX 10.10.21.218`
| TCP Maimon Scan | `sudo nmap -sM 10.10.21.218`
| TCP ACK Scan | `sudo nmap -sA 10.10.21.218`
| TCP Window Scan | `sudo nmap -sW 10.10.21.218`
| Custom TCP Scan | `sudo nmap --scanflags URGACKPSHRSTSYNFIN 10.10.21.218`
| Spoofed Source IP | `sudo nmap -S SPOOFED_IP 10.10.21.218`
| Spoofed MAC Address | `--spoof-mac SPOOFED_MAC`
| Decoy Scan | `nmap -D DECOY_IP,ME 10.10.21.218`
| Idle (Zombie) Scan | `sudo nmap -sI ZOMBIE_IP 10.10.21.218`
| Fragment IP data into 8 bytes | `-f` 
| Fragment IP data into 16 bytes | `-ff`

| Option | Purpose
| --- | ---
| `--source-port PORT_NUM` | specify source port number
| `--data-length NUM` | append random data to reach given length

* These scan types rely on setting TCP flags in unexpected ways to prompt ports for a reply.
* Null, FIN, and Xmas scans provoke a response from closed ports, while Maimon, ACK, and Window scans provoke a response from open and closed ports.

| Option | Purpose
| --- | ---
| `--reason` |  explains how Nmap made its conclusion
| `-v` |  verbose
| `-vv` | very verbose
| `-d` | debugging
| `-dd` |  more details for debugging
