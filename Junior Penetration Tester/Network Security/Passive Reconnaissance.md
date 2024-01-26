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

| Purpose | Command Line Example
| --- | ---
| Lookup WHOIS record | `whois tryhackme.com`

## `nslookup` and `dig`
* Find the IP address of a domain name using `nslookup`, which stands for Name Server Look Up.
  * Need to issue the command `nslookup DOMAIN_NAME`, for example, `nslookup tryhackme.com`.
  * Can use `nslookup OPTIONS DOMAIN_NAME SERVER`.
  * Three main parameters:
    * `OPTIONS` contains the query type as shown in the table below.
      * For instance, use A for IPv4 addresses and AAAA for IPv6 addresses.
    * `DOMAIN_NAME` is the domain name being looked up.
    * `SERVER` is the DNS server to query.
      * Can choose any local or public DNS server to query.
      * Cloudflare offers 1.1.1.1 and 1.0.0.1, Google offers 8.8.8.8 and 8.8.4.4, and Quad9 offers 9.9.9.9 and 149.112.112.112.
      * There are [many more public DNS servers](https://duckduckgo.com/?q=public+dns) to choose from if alternatives to the ISP’s DNS servers are required.

| Query type | Result
| --- | ---
| A | IPv4 Addresses
| AAAA | IPv6 Addresses
| CNAME | Canonical Name
| MX | Mail Servers
| SOA | Start of Authority
| TXT | TXT Records

* For instance, `nslookup -type=A tryhackme.com 1.1.1.1` (or `nslookup -type=a tryhackme.com 1.1.1.1` as it is case-insensitive) can be used to return all the IPv4 addresses used by `tryhackme.com`.
```
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
```
* A and AAAA records are used to return IPv4 and IPv6 addresses, respectively.
  * This lookup is helpful to know from a penetration testing perspective.
    * The example above started with one domain name, and obtained three IPv4 addresses.
    * Each of these IP addresses can be further checked for insecurities, assuming they lie within the scope of the penetration test.
* To learn about the email servers and configurations for a particular domain, issue `nslookup -type=MX tryhackme.com`.
  * Here is an example:
```
nslookup -type=MX tryhackme.com

Server:		127.0.0.53
Address:	127.0.0.53#53

Non-authoritative answer:
tryhackme.com	mail exchanger = 5 alt1.aspmx.l.google.com.
tryhackme.com	mail exchanger = 1 aspmx.l.google.com.
tryhackme.com	mail exchanger = 10 alt4.aspmx.l.google.com.
tryhackme.com	mail exchanger = 10 alt3.aspmx.l.google.com.
tryhackme.com	mail exchanger = 5 alt2.aspmx.l.google.com.
``` 
* Can see that tryhackme.com’s current email configuration uses Google.
  * Since MX is looking up the Mail Exchange servers, notice that when a mail server tries to deliver email `@tryhackme.com`, it will try to connect to the `aspmx.l.google.com`, which has order 1.
  * If it is busy or unavailable, the mail server will attempt to connect to the next in order mail exchange servers, `alt1.aspmx.l.google.com` or `alt2.aspmx.l.google.com`.
* Google provides the listed mail servers; therefore, the mail servers are not expected to be running a vulnerable server version.
  * Mail servers may be found that are not adequately secured or patched.
* Such pieces of information might prove valuable as the passive reconnaissance of the target continues.
  * Can repeat similar queries for other domain names and try different types, such as `-type=txt`.

| Purpose | Command Line Example
| --- | ---
| Lookup DNS A records | `nslookup -type=A tryhackme.com`
| Lookup DNS MX records at DNS server | `nslookup -type=MX tryhackme.com 1.1.1.1`
| Lookup DNS TXT records | `nslookup -type=TXT tryhackme.com`
 
* For more advanced DNS queries and additional functionality, use `dig`, the acronym for 'Domain Information Groper'.
  * Use `dig` to look up the MX records and compare them to `nslookup`.
  * Can use `dig DOMAIN_NAME`, but to specify the record type, use `dig DOMAIN_NAME TYPE`.
  * Optionally, select the server to query using `dig @SERVER DOMAIN_NAME TYPE`.
    * `SERVER` is the DNS server to query.
    * `DOMAIN_NAME` is the domain name being looked up.
    * `TYPE` contains the DNS record type, as shown in the table provided earlier.
```
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
```
* A quick comparison between the output of `nslookup` and `dig` shows that `dig` returned more information, such as the TTL (Time To Live) by default.
  * To query a 1.1.1.1 DNS server, execute `dig @1.1.1.1 tryhackme.com MX`.

| Purpose | Command Line Example
| --- | ---
| Lookup DNS A records | `dig tryhackme.com A`
| Lookup DNS MX records at DNS server | `dig @1.1.1.1 tryhackme.com MX`
| Lookup DNS TXT records | `dig tryhackme.com TXT`

## [DNSDumpster](https://dnsdumpster.com/)
* DNS lookup tools, such as nslookup and dig, cannot find subdomains on their own.
  * The domain being inspecting might include a different subdomain that can reveal much information about the target.
    * For instance, if `tryhackme.com` has the subdomains `wiki.tryhackme.com` and `webmail.tryhackme.com`, it is prudent to learn more about these two as they can hold a trove of information about the target.
    * There is a possibility that one of these subdomains has been set up and is not updated regularly.
      * Lack of proper regular updates usually leads to vulnerable services.

* Consider using multiple search engines to compile a list of publicly known subdomains.
  * Should expect to go through at least tens of results to find interesting data.
  * Looking for subdomains that are not explicitly advertised, and hence it is not necessary to make it to the first page of search results.
  * Another approach to discover such subdomains would be to rely on brute-forcing queries to find which subdomains have DNS records.

* To avoid such a time-consuming search, use an online service that offers detailed answers to DNS queries, such as DNSDumpster.
  * Searching DNSDumpster for `tryhackme.com` discovers the subdomain `blog.tryhackme.com`, which a typical DNS query cannot provide.
  * DNSDumpster will return the collected DNS information in easy-to-read tables and a graph.
  * DNSDumpster will also provide any collected information about listening servers.
  * Among the results, is a list of DNS servers for the domain.
  * DNSDumpster also resolved the domain names to IP addresses and even tried to geolocate them.
  * DNSDumpster also returned the MX records.
    * Resolved all five mail exchange servers to their respective IP addresses and provided more information about the owner and location.
  * DNSDumpster also returned TXT records.
  * Practically a single query was enough to retrieve all this information.
* DNSDumpster will also represent the collected information graphically.

## [Shodan.io](https://www.shodan.io/)
* When tasked to run a penetration test against specific targets, as part of the passive reconnaissance phase, a service like Shodan.io can be helpful to learn various pieces of information about the client’s network, without actively connecting to it.
  * On the defensive side, the different services from Shodan.io can be used to learn about connected and exposed devices belonging to the organisation.
* Shodan.io tries to connect to every device reachable online to build a search engine of connected “things” in contrast with a search engine for web pages.
  * Once it gets a response, it collects all the information related to the service and saves it in the database to make it searchable.
* Searching for `tryhackme.com` on Shodan.io will display at least one record:
  * IP address
  * hosting company
  * geographic location
  * server type and version
* Can also search for IP addresses obtained from DNS lookups.
* Learn about all the search options available at Shodan.io on their [help page](https://help.shodan.io/the-basics/search-query-fundamentals).
