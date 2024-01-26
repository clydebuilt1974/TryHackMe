# Passive Reconnaissance
## Passive Versus Active Recon
* Before the dawn of computer systems and networks, in the Art of War, Sun Tzu taught:
> If you know the enemy and know yourself, your victory will not stand in doubt.
  * If playing the role of an attacker, information about the target must be gathered.
  * If playing the role of a defender, knowing what the adversary can discover is important.
* Reconnaissance (recon) can be defined as a preliminary survey to gather information about a target.
* It is the first step in The [Unified Kill Chain](https://www.unifiedkillchain.com/) to gain an initial foothold on a system.
  * Reconnaissance is divided into:
    * Passive Reconnaissance.
    * Active Reconnaissance.
* Passive reconnaissance is reliant on publicly available knowledge.
  * Knowledge that can be accessed from publicly available resources without directly engaging with the target.
* Passive reconnaissance activities include many activitiese:
  * Looking up DNS records of a domain from a public DNS server.
  * Checking job ads related to the target website.
  * Reading news articles about the target company.
* Active reconnaissance cannot be achieved so discreetly.
  * It requires direct engagement with the target.
* Examples of active reconnaissance activities:
  * Connecting to one of the company servers such as HTTP, FTP, and SMTP.
  * Calling the company in an attempt to get information (social engineering).
  * Entering company premises pretending to be a repairman.
* Considering the invasive nature of active reconnaissance, a person can quickly get into legal trouble unless they obtain proper legal authorisation.

## `whois`
* Request and response protocol that follows the [RFC 3912](https://www.ietf.org/rfc/rfc3912.txt) specification.
  * WHOIS server listens on TCP port 43 for incoming requests.
  * Domain registrar is responsible for maintaining the WHOIS records for the domain names it is leasing.
  * WHOIS server replies with various information related to the domain requested.
* Of particular interest:
  * Registrar: via which registrar was the domain name registered?
  * Contact info of registrant: the name, organisation, address, phone, among other things. (unless made hidden via a privacy service)
  * Creation, update, and expiration dates: when was the domain name first registered?
    * When was it last updated?
    * When does it need to be renewed?
  * Name Server: which server to ask to resolve the domain name?
* To get this information, use a whois client or an online service.
  * Many online services provide whois information.
    * It is generally faster and more convenient to use a local whois client.
  * Using a Linux machine, such as Parrot or Kali, can easily access the whois client on the terminal.
  * The syntax is `whois DOMAIN_NAME`, where `DOMAIN_NAME` is the domain about of interest.
```
whois tryhackme.com

[Querying whois.verisign-grs.com]
[Redirected to whois.namecheap.com]
[Querying whois.namecheap.com]
[whois.namecheap.com]
Domain name: tryhackme.com
Registry Domain ID: 2282723194_DOMAIN_COM-VRSN
Registrar WHOIS Server: whois.namecheap.com
Registrar URL: http://www.namecheap.com
Updated Date: 2021-05-01T19:43:23.31Z
Creation Date: 2018-07-05T19:46:15.00Z
Registrar Registration Expiration Date: 2027-07-05T19:46:15.00Z
Registrar: NAMECHEAP INC
Registrar IANA ID: 1068
Registrar Abuse Contact Email: abuse@namecheap.com
Registrar Abuse Contact Phone: +1.6613102107
Reseller: NAMECHEAP INC
Domain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited
Registry Registrant ID: 
Registrant Name: Withheld for Privacy Purposes
Registrant Organization: Privacy service provided by Withheld for Privacy ehf
[...]
URL of the ICANN WHOIS Data Problem Reporting System: http://wdprs.internic.net/
>>> Last update of WHOIS database: 2021-08-25T14:58:29.57Z <<<
```
* For more information on Whois status codes, visit [https://icann.org/epp](https://icann.org/epp).
* Can see plenty of information:
  * Redirection to `whois.namecheap.com` to get the information.
    * `namecheap.com` is maintaining the WHOIS record for this domain name.
  * Creation date along with the last-update date and expiration date.
* Information about the registrar and the registrant.
  * Registrant’s name and contact information appear unless they are using some privacy service.
  * Domain name servers to query if there are any DNS records to look up.
* Information collected can be inspected to find new attack surfaces, such as social engineering or technical attacks.
  * For instance, depending on the scope of the penetration test, consider an attack against the email server of the admin user or the DNS servers, assuming they are owned by the client and fall within the scope of the penetration test.
* Note that due to automated tools abusing WHOIS queries to harvest email addresses, many WHOIS services take measures against this.
  * They might redact email addresses.
  * Many registrants subscribe to privacy services to avoid their email addresses being harvested by spammers and keep their information private.

## `nslookup` and `dig`
Find the IP address of a domain name using nslookup, which stands for Name Server Look Up. You need to issue the command nslookup DOMAIN_NAME, for example, nslookup tryhackme.com. Or, more generally, you can use nslookup OPTIONS DOMAIN_NAME SERVER. These three main parameters are:
OPTIONS contains the query type as shown in the table below. For instance, you can use A for IPv4 addresses and AAAA for IPv6 addresses.
DOMAIN_NAME is the domain name you are looking up.
SERVER is the DNS server that you want to query. You can choose any local or public DNS server to query. Cloudflare offers 1.1.1.1 and 1.0.0.1, Google offers 8.8.8.8 and 8.8.4.4, and Quad9 offers 9.9.9.9 and 149.112.112.112. There are many more public DNS servers that you can choose from if you want alternatives to your ISP’s DNS servers.
Query type
Result
A
IPv4 Addresses
AAAA
IPv6 Addresses
CNAME
Canonical Name
MX
Mail Servers
SOA
Start of Authority
TXT
TXT Records

For instance, nslookup -type=A tryhackme.com 1.1.1.1 (or nslookup -type=a tryhackme.com 1.1.1.1 as it is case-insensitive) can be used to return all the IPv4 addresses used by tryhackme.com.
nslookup -type=A tryhackme.com 1.1.1.1

Server:		1.1.1.1
Address:	1.1.1.1#53

Non-authoritative answer:
Name:	tryhackme.com
Address: 172.67.69.208
Name:	tryhackme.com
Address: 104.26.11.229
Name:	tryhackme.com
Address: 104.26.10.229
The A and AAAA records are used to return IPv4 and IPv6 addresses, respectively. This lookup is helpful to know from a penetration testing perspective. In the example above, we started with one domain name, and we obtained three IPv4 addresses. Each of these IP addresses can be further checked for insecurities, assuming they lie within the scope of the penetration test.
Let’s say you want to learn about the email servers and configurations for a particular domain. You can issue nslookup -type=MX tryhackme.com. Here is an example:
nslookup -type=MX tryhackme.com

Server:		127.0.0.53
Address:	127.0.0.53#53

Non-authoritative answer:
tryhackme.com	mail exchanger = 5 alt1.aspmx.l.google.com.
tryhackme.com	mail exchanger = 1 aspmx.l.google.com.
tryhackme.com	mail exchanger = 10 alt4.aspmx.l.google.com.
tryhackme.com	mail exchanger = 10 alt3.aspmx.l.google.com.
tryhackme.com	mail exchanger = 5 alt2.aspmx.l.google.com.      
We can see that tryhackme.com’s current email configuration uses Google. Since MX is looking up the Mail Exchange servers, we notice that when a mail server tries to deliver email @tryhackme.com, it will try to connect to the aspmx.l.google.com, which has order 1. If it is busy or unavailable, the mail server will attempt to connect to the next in order mail exchange servers, alt1.aspmx.l.google.com or alt2.aspmx.l.google.com.
Google provides the listed mail servers; therefore, we should not expect the mail servers to be running a vulnerable server version. However, in other cases, we might find mail servers that are not adequately secured or patched.
Such pieces of information might prove valuable as you continue the passive reconnaissance of your target. You can repeat similar queries for other domain names and try different types, such as -type=txt. Who knows what kind of information you might discover along your way!
For more advanced DNS queries and additional functionality, you can use dig, the acronym for “Domain Information Groper,” if you are curious. Let’s use dig to look up the MX records and compare them to nslookup. We can use dig DOMAIN_NAME, but to specify the record type, we would use dig DOMAIN_NAME TYPE. Optionally, we can select the server we want to query using dig @SERVER DOMAIN_NAME TYPE.
SERVER is the DNS server that you want to query.
DOMAIN_NAME is the domain name you are looking up.
TYPE contains the DNS record type, as shown in the table provided earlier.
dig tryhackme.com MX

; <<>> DiG 9.16.19-RH <<>> tryhackme.com MX
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 27880
;; flags: qr rd ra; QUERY: 1, ANSWER: 5, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 65494
;; QUESTION SECTION:
;tryhackme.com.   		 IN    MX

;; ANSWER SECTION:
tryhackme.com.   	 300    IN    MX    5 alt2.aspmx.l.google.com.
tryhackme.com.   	 300    IN    MX    1 aspmx.l.google.com.
tryhackme.com.   	 300    IN    MX    10 alt3.aspmx.l.google.com.
tryhackme.com.   	 300    IN    MX    10 alt4.aspmx.l.google.com.
tryhackme.com.   	 300    IN    MX    5 alt1.aspmx.l.google.com.

;; Query time: 3 msec
;; SERVER: 127.0.0.53#53(127.0.0.53)
;; WHEN: Thu Dec 07 13:32:38 GMT 2023
;; MSG SIZE  rcvd: 157
A quick comparison between the output of nslookup and dig shows that dig returned more information, such as the TTL (Time To Live) by default. If you want to query a 1.1.1.1 DNS server, you can execute dig @1.1.1.1 tryhackme.com MX.
DNSDumpster
DNS lookup tools, such as nslookup and dig, cannot find subdomains on their own. The domain you are inspecting might include a different subdomain that can reveal much information about the target. For instance, if tryhackme.com has the subdomains wiki.tryhackme.com and webmail.tryhackme.com, you want to learn more about these two as they can hold a trove of information about your target. There is a possibility that one of these subdomains has been set up and is not updated regularly. Lack of proper regular updates usually leads to vulnerable services. But how can we know that such subdomains exist?
We can consider using multiple search engines to compile a list of publicly known subdomains. One search engine won’t be enough; moreover, we should expect to go through at least tens of results to find interesting data. After all, you are looking for subdomains that are not explicitly advertised, and hence it is not necessary to make it to the first page of search results. Another approach to discover such subdomains would be to rely on brute-forcing queries to find which subdomains have DNS records.
To avoid such a time-consuming search, one can use an online service that offers detailed answers to DNS queries, such as DNSDumpster. If we search DNSDumpster for tryhackme.com, we will discover the subdomain blog.tryhackme.com, which a typical DNS query cannot provide. In addition, DNSDumpster will return the collected DNS information in easy-to-read tables and a graph. DNSDumpster will also provide any collected information about listening servers.
We will search for tryhackme.com on DNSDumpster to give you a glimpse of the expected output. Among the results, we got a list of DNS servers for the domain we are looking up. DNSDumpster also resolved the domain names to IP addresses and even tried to geolocate them. We can also see the MX records; DNSDumpster resolved all five mail exchange servers to their respective IP addresses and provided more information about the owner and location. Finally, we can see TXT records. Practically a single query was enough to retrieve all this information.

DNSDumpster will also represent the collected information graphically. DNSDumpster displayed the data from the table earlier as a graph. You can see the DNS and MX branching to their respective servers and also showing the IP addresses.

There is currently a beta feature that allows you to export the graph as well. You can manipulate the graph and move blocks around if needed.

Shodan.io
When you are tasked to run a penetration test against specific targets, as part of the passive reconnaissance phase, a service like Shodan.io can be helpful to learn various pieces of information about the client’s network, without actively connecting to it. Furthermore, on the defensive side, you can use different services from Shodan.io to learn about connected and exposed devices belonging to your organisation.
Shodan.io tries to connect to every device reachable online to build a search engine of connected “things” in contrast with a search engine for web pages. Once it gets a response, it collects all the information related to the service and saves it in the database to make it searchable. Consider the saved record of one of tryhackme.com’s servers.

This record shows a web server; however, as mentioned already, Shodan.io collects information related to any device it can find connected online. Searching for tryhackme.com on Shodan.io will display at least the record shown in the screenshot above. Via this Shodan.io search result, we can learn several things related to our search, such as:
IP address
hosting company
geographic location
server type and version
You may also try searching for the IP addresses you have obtained from DNS lookups. These are, of course, more subject to change. On their help page, you can learn about all the search options available at Shodan.io, and you are encouraged to join TryHackMe’s Shodan.io.
Summary
In this room, we focused on passive reconnaissance. In particular, we covered command-line tools, whois, nslookup, and dig. We also discussed two publicly available services DNSDumpster and Shodan.io. The power of such tools is that you can collect information about your targets without directly connecting to them. Moreover, the trove of information you may find using such tools can be massive once you master the search options and get used to reading the results.
Purpose
Command Line Example
Lookup WHOIS record
whois tryhackme.com
Lookup DNS A records
nslookup -type=A tryhackme.com
Lookup DNS MX records at DNS server
nslookup -type=MX tryhackme.com 1.1.1.1
Lookup DNS TXT records
nslookup -type=TXT tryhackme.com
Lookup DNS A records
dig tryhackme.com A
Lookup DNS MX records at DNS server
dig @1.1.1.1 tryhackme.com MX
Lookup DNS TXT records
dig tryhackme.com TXT
