# Burp Suite: Intruder
## What is Intruder?
* Burp Suite's built-in fuzzing tool.
* Allows for automated request modification and repetitive testing with variations in input values.
* Uses a captured request (often from the Proxy module) to send multiple requests with slightly altered values based on user-defined configurations:
  * Brute-force login forms by substituting username and password fields with values from a wordlist.
  * Perform fuzzing attacks using wordlists to test subdirectories, endpoints, or virtual hosts.
* Functionality is comparable to command-line tools like `Wfuzz` or `ffuf`.
* Important to note that Intruder is rate-limited within Burp Community Edition.
  * Significantly reduces its speed compared to Burp Professional.
  * Limitation often leads security practitioners to rely on other tools for fuzzing and brute-forcing.

## The Intruder interface:
* Initial view presents a simple interface where the target can be selcted.
  * This field will already be populated if a request has been sent from the Proxy (using Ctrl + I or right-clicking and selecting "Send to Intruder").
* Four sub-tabs:
  * **Positions**: Allows attack type selection and configuration of where to insert the payloads in the request template.
  * **Payloads**: Select values to insert into the positions defined in the Positions tab.
      * Various payload options, such as loading items from a wordlist.
        * The way these payloads are inserted into the template depends on the attack type chosen in the Positions tab.
      * Enables the modification of Intruder's behaviour regarding payloads:
        * Defining pre-processing rules for each payload (e.g., adding a prefix or suffix.
        * Performing match and replace.
        * Skipping payloads based on a defined regex).
  * **Resource Pool**: Not particularly useful in the Burp Community Edition.
     * Without access to these automated tasks it is of limited importance.
     * Allows for resource allocation among various automated tasks in Burp Professional.
  * **Settings**: Allows configuration of attack behaviour.
    * Primarily deals with how Burp handles results and the attack itself.
      * For instance, flag requests containing specific text or define Burp's response to redirect (3xx) responses.
* The term "fuzzing" refers to the process of testing functionality or existence by applying a set of data to a parameter.
  * For example, fuzzing for endpoints in a web application involves taking each word in a wordlist and appending it to a request URL (e.g., `http://MACHINE_IP/WORD_GOES_HERE`) to observe the server's response.

## Positions
* First step is to examine the positions within the request where payloads might be introduced when using Intruder to perform an attack.
* In the Positions tab:
  * Burp Suite automatically attempts to identify the most probable positions where payloads can be inserted.
    * These positions are highlighted in green and enclosed by section marks `§`.
  * Right-hand side of the interface displays `Add §`, `Clear §`, and `Auto §` buttons.
    * `Add §` defines new positions manually by highlighting them within the request editor and then clicking the button.
    * `Clear §` button removes all defined positions, providing a blank canvas where to custom positions can be defined.
    * `Auto §` button automatically attempts to identify the most likely positions based on the request.
       * This feature is helpful if the default positions were previously cleared.

## Payloads
* In the **Payloads** tab, payloads for the attack can be created, assigned, and configured.
* This sub-tab is divided into four sections:
  * **Payload Sets**: Selects the position to configure a payload set and select the type of payload to use.
      * Dropdown will have only one option regardless of the number of defined positions when using attack types that allow only a single payload set (Sniper or Battering Ram).
      * One item in the dropdown for each position when using attack types that require multiple payload sets (Pitchfork or Cluster Bomb).
      * Follow a top-to-bottom, left-to-right order when assigning numbers dropdown for multiple positions.
        * For example, with two positions (`username=§pentester§&password=§Expl01ted§`) the first item in the payload set dropdown would refer to the username field, and the second item would refer to the password field.
* **Payload settings**: Provides options specific to the selected payload type for the current payload set.
    * For example, when using the 'Simple list' payload type, payloads can be manually added or removed to/from the set using the **Add** text box, **Paste** lines, or **Load** payloads from a file.
      * **Remove** button removes the currently selected line.
      * **Clear** button clears the entire list.
      * Be cautious with loading huge lists as it may cause Burp to crash.
    * Each payload type will have its own set of options and functionality.
* **Payload Processing**: Defines rules to be applied to each payload in the set before it is sent to the target.
    * For example, capitalise every word, skip payloads that match a regex pattern, or apply other transformations or filtering.
* **Payload Encoding**: Customises the encoding options for the payloads.
    * Burp Suite applies URL encoding by default to ensure the safe transmission of payloads.
      * Override the default URL encoding options by modifying the list of characters to be encoded or unchecking the "URL-encode these characters" checkbox.
* These sections allow the creation and customisation of payload sets to suit the specific requirements of the attacks.
  * This level of control allows the fine tuning of payloads for effective testing and exploitation.

## Sniper
* Default attack type and most commonly used attack type in Burp Suite Intruder.
* Particularly effective for single-position attacks, such as password brute-force or fuzzing for API endpoints.
* Set of payloads provided in a Sniper attack.
  * Can be a wordlist or a range of numbers.
  * Intruder inserts each payload into each defined position in the request.
* Example template:
```
POST /support/login/ HTTP/1.1
Host: 10.10.225.178
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:80.0) Gecko/20100101 Firefox/80.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 37
Origin: http://10.10.225.178
Connection: close
Referer: http://10.10.225.178/support/login/
Upgrade-Insecure-Requests: 1

username=§pentester§&password=§Expl01ted§             
```
* Two positions are defined for the `username` and `password` body parameters.
* Intruder takes each payload from the payload set and substitutes it into each defined position in turn.
* Intruder would generate six requests assuming a wordlist with three words is used (`burp`, `suite`, and `intruder`):

|  Request Number | Request Body
| --- | ---
| 1 | `username=burp&password=Expl01ted`
| 2 | `username=suite&password=Expl01ted`
| 3 | `username=intruder&password=Expl01ted`
| 4 | `username=pentester&password=burp`
| 5 | `username=pentester&password=suite`
| 6 | `username=pentester&password=intruder`

* Intruder starts with the first position (`username`) and substitutes each payload into it, then moves to the second position (`password`) and performs the same substitution with the payloads.
* The total number of requests made by Sniper can be calculated as requests = numberOfWords * numberOfPositions.
* Sniper attack type is beneficial when tests are performws with single-position attacks, utilising different payloads for each position.
* It allows for precise testing and analysis of different payload variations.

## Battering Ram
* Places the same payload in every position simultaneously, rather than substituting each payload into each position in turn.
* Example template:
```
POST /support/login/ HTTP/1.1
    Host: 10.10.225.178
    User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:80.0) Gecko/20100101 Firefox/80.0
    Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
    Accept-Language: en-US,en;q=0.5
    Accept-Encoding: gzip, deflate
    Content-Type: application/x-www-form-urlencoded
    Content-Length: 37
    Origin: http://10.10.225.178
    Connection: close
    Referer: http://10.10.225.178/support/login/
    Upgrade-Insecure-Requests: 1
    
    username=§pentester§&password=§Expl01ted§             
```
* Using the Battering Ram attack type with the same wordlist from before (`burp`, `suite`, and `intruder`), Intruder would generate three requests:

| Request Number | Request Body
| --- | ---
| 1 | `username=burp&password=burp`
| 2 | `username=suite&password=suite`
| 3 | `username=intruder&password=intruder`

* Each payload from the wordlist is inserted into every position for each request made.
* In a Battering Ram attack, the same payload is thrown at every defined position simultaneously, providing a brute-force-like approach to testing.
* The Battering Ram attack type is useful when testing the same payload against multiple positions at once without the need for sequential substitution.

## Pitchfork
* Similar to having multiple Sniper attacks running simultaneously.
* Pitchfork utilises one payload set per position (up to a maximum of 20) and iterates through them all simultaneously.
* Revisit the Battering Ram brute-force example, but this time with two wordlists:
  * The first wordlist contains usernames `joel`, `harriet`, and `alex`.
  * The second wordlist contains passwords `J03l`, `Emma1815`, and `Sk1ll`.
* Use these two lists to perform a Pitchfork attack on the login form.
* Each request made during the attack would look like this:

| Request Number | Request Body
| --- | --- 
| 1 | `username=joel&password=J03l`
| 2 | `username=harriet&password=Emma1815`
| 3 | `username=alex&password=Sk1ll`

* Pitchfork takes the first item from each list and substitutes them into the request, one per position.
* Repeats the process for the next request by taking the second item from each list and substituting it into the template.
* Continues this iteration until one or all of the lists run out of items.
* Note that Intruder stops testing as soon as one of the lists is complete.
  * It is ideal for the payload sets to have the same length.
* Pitchfork attack type is especially useful when conducting credential-stuffing attacks or when multiple positions require separate payload sets.
* Allows for simultaneous testing of multiple positions with different payloads.

## Cluster Bomb
* Allows multiple payload sets tpo be chosen, one per position (up to a maximum of 20).
* Iterates through each payload set individually ensuring that every possible combination of payloads is tested.
* Assume there are three users and three passwords, but the mappings are unknown.
  * In this case use a Cluster bomb attack to try every combination of values.
  * The request table for the `username` and `password` positions would look like this:

| Request Number | Request Body
| --- | ---
| 1 | `username=joel&password=J03l`
| 2 | `username=harriet&password=J03l`
| 3 | `username=alex&password=J03l`
| 4 | `username=joel&password=Emma1815`
| 5 | `username=harriet&password=Emma1815`
| 6 | `username=alex&password=Emma1815`
| 7 | `username=joel&password=Sk1ll`
| 8 | `username=harriet&password=Sk1ll`
| 9 | `username=alex&password=Sk1ll`

* Cluster bomb attack type iterates through every combination of the provided payload sets.
  * It tests every possibility by substituting each value from each payload set into the corresponding position in the request.
* Cluster bomb attacks can generate a significant amount of traffic as it tests every combination.
* The number of requests made by a Cluster bomb attack can be calculated by multiplying the number of lines in each payload set together.
* Important to be cautious when using this attack type, especially when dealing with large payload sets.
* Execution of a Cluster bomb attack with a moderately sized payload set can take a significantly longer time when using Burp Community and its Intruder rate-limiting.
* Particularly useful for credential brute-forcing scenarios where the mapping between usernames and passwords is unknown.

## Introduction to Attack Types
* Positions tab of Intruder has a dropdown menu for selecting the attack type.
* Intruder offers four attack types, each serving a specific purpose:
  * **Sniper**: default attack type and most commonly used option.
      * It cycles through the payloads, inserting one payload at a time into each position defined in the request.
      * Sniper attacks iterate through all the payloads in a linear fashion, allowing for precise and focused testing.
  * **Battering ram**: Differs from Sniper in that it sends all payloads simultaneously, each payload inserted into its respective position.
      * This attack type is useful when testing for race conditions or when payloads need to be sent concurrently.
  * **Pitchfork**: Enables the simultaneous testing of multiple positions with different payloads.
      * Allows the tester to define multiple payload sets, each associated with a specific position in the request.
      * Effective when there are distinct parameters that need separate testing.
  * **Cluster bomb**: Combines the Sniper and Pitchfork approaches.
      * Performs a Sniper-like attack on each position but simultaneously tests all payloads from each set.
      * Useful when multiple positions have different payloads, and we want to test them all together.
* Each attack type has its advantages and is suitable for different testing scenarios.

## Practical Example
* Attempt to gain access to a support portal located at `http://website.thm/support/login`.
* This portal follows a typical login structure.
* Inspecting the source code shows that no protective measures have been implemented:
```
<from method="POST">
 <div class="form-floating mb-3">
  <input class="form-control" type="text" name="username" placeholder="Username" required>
  <label for="username">Username</label>
 </div>
 <div class="form-floating mb-3">
  <input class="form-control" type="password" name="password" placeholder="Password" required>
  <label for="password">Password</label>
 </div>
 <div class="d-grid"><button class="btn btn-primary btn-lg" type="submit"><Login!</button></div>
</form>
```
* `EmployeeCreds.zip` contains a collection of leaked credentials belonging to employees (usernames.txt and passwords.txt).
> Approximately three months ago, Bastion Hosting fell victim to a cyber attack, compromising employee usernames, email addresses, and plaintext passwords. While the affected employees were instructed to change their passwords promptly, there is a possibility that some disregarded this advice.
* Leverage a credential-stuffing attack instead of a straightforward brute-force.
* Navigate to `http://website.thm/support/login`.
* Activate the Burp Proxy and attempt to log in, capturing the request in the proxy.
  * Any credentials will suffice for this step.
* Send the captured request from the Proxy to Intruder by right-clicking and selecting "Send to Intruder" or using Ctrl + I.
* In the "Positions" sub-tab, ensure that only the username and password parameters are selected.
* Clear any additional selections, such as session cookies.
* Set the Attack type to "Pitchfork."
* Move to the "Payloads" sub-tab.
* Two payload sets available for the `username` and `password` fields.
* In the first payload set (for usernames), go to "Payload settings," choose "Load," and select the `usernames.txt` list.
* Repeat the same process for the second payload set (for passwords) using the `passwords.txt` list.
* Click the Start Attack button to begin the credential-stuffing attack.
  * A warning about rate-limiting may appear; click OK to proceed.
  * The attack will take a few minutes to complete in Burp Community.
* Once the attack starts, a new window will display the results of the requests.
* Need to identify which one(s) were successful as Burp sent 100 requests.
* Use the response length to distinguish them since the response status codes are not differentiating successful and unsuccessful attempts (all are 302 redirects).
* Click on the header for the "Length" column to sort the results by byte length.
* Look for the request with a shorter response length, indicating a successful login attempt.
* To confirm the successful login attempt, use the credentials from the request with the shorter response length to log in.

## Practical Challenge
* Having gained access to the support system, explore its functionalities and see what actions can be performed.
* Upon accessing the home interface, there is a table displaying various tickets.
* Clicking on any row redirects to a page where the complete ticket can be viewed.
* By examining the URL structure, these pages are numbered in the following format: `http://website.thm/support/ticket/NUMBER`
* The numbering system indicates that the tickets are assigned integer identifiers rather than complex and hard-to-guess IDs.
* This information is significant because it suggests two possible scenarios:
  * **Access Control**: The endpoint may be properly configured to restrict access only to tickets assigned to our current user.
      * In this case, we can only view tickets associated with our account.
  * **IDOR Vulnerability**: The endpoint may lack appropriate access controls, leading to a vulnerability known as Insecure Direct Object References (IDOR).
      * Could potentially exploit the system and read all existing tickets, regardless of the assigned user.
* To investigate further, utilise the Intruder tool to fuzz the `/support/ticket/NUMBER` endpoint.
* This approach will help to determine whether the endpoint has been correctly configured or if an IDOR vulnerability is present.
* Note: need to capture a request while being logged in.
1. Click on a ticket and Send the Request via BURP proxy.
2. Send the captured Request to Intruder
3. Add a Position around the ticket integer identifier
```
GET /support/ticket/§78§ HTTP/1.1
```
* Move to Payloads sub tab
* Select Numbers as the Payload type
* Change the Number range From 1 To 100 to fuzz the endpoint.
* Start the Attack.
* Sort the results table by Status code.
  * Status code `200` means that the request was successful
* Sequentially change the ticket integer identifier in the browser to view the tickets where the Status code was `200` to find the flag.

## Extra Mile Challenge
* A more challenging variant of the credential-stuffing attack where additional measures have been implemented to make brute-forcing more difficult.
### Catching the Request
* Begin by capturing a request to http://website.thm/admin/login/ and reviewing the response.
* Example of the response:
```
Set-Cookie: session=eyJpZCI6IjUwN2E1OGZkLTFkM2QtNDFhNS1iYmEzLThmNDVhOTRlYjFiMSIsImMiOjE3MDYyNjk4OTg2NjgsInMiOjEsInIiOjAsInNiIjowLCJzciI6MCwic2UiOjAsImZzIjowLCJzcCI6MH0=;
```
* Page source code:
```
<input type="hidden" name="loginToken" value="4147fc4045clbe8ab6aclabe1b593e69">
```
* In the response there is now a session cookie set alongside the username and password field, as well as a CSRF (Cross-Site Request Forgery) token in the form as a hidden field.
* Refreshing the page reveals that both the session cookie and the loginToken change with each request.
  * This means that for every login attempt the valid values for the session cookie and the loginToken need to be extracted.
* Use Burp Macros to define a repeated set of actions (macro) to be executed before each request.
* This macro will extract unique values for the session cookie and loginToken, replacing them in every subsequent request of our attack.
### Tutorial
1. Navigate to `http://website.thm/admin/login/`.
   * Activate Intercept in the Proxy module and attempt to log in.
   * Capture the request and send it to Intruder.
2. Configure the positions the same way as per brute-forcing the support login:
   * Set the attack type to 'Pitchfork'.
   * Clear all predefined positions and select only the `username` and `password` form fields.
   * The macro will handle the other two positions.
3. Switch over to the Payloads tab and load in the same `username` and `password` wordlists used for the support login attack.
4. Now need to find a way to grab the ever changing loginToken and session cookie.
   * 'Recursive grep' will not work here due to the redirect response so this cannot be done entirely within Intruder.
   * Will need to build a macro instead.
     * Macros allow the same set of actions to be performed repeatedly.
   * Need to send a `GET` request to `/admin/login/`:
   * To do this. switch over to the main 'Settings' tab at the top-right.
   * Click on the 'Sessions' category.
   * Scroll down to the bottom of the category to the 'Macros' section and click the Add button.
   * The menu that appears will show the request history.
     * If there is not a `GET` request to `http://website.thm/admin/login/` in the list already, navigate to this location in the browser to see a suitable request appear in the list.
   * With the request selected, click OK.
   * Give the macro a suitable name, then click OK again to finish the process.
5. Now need to set Session Handling rules that define how the macro should be used.
   * In the "Sessions" category of the main settings, scroll up to the "Session Handling Rules" section and choose to Add a new rule.
   * A new window pops up with 'Details' and 'Scope' tabs.
     * Fill in an appropriate description in the Details tab, then switch to the Scope tab:
       * Deselect every checkbox other than Intruder in the 'Tools Scope' section.
         * Do not need this rule to apply anywhere else.
       * Choose 'Use suite scope' in the 'URL Scope' section.
         * This will set the macro to only operate on sites that have been added to the global scope.
       * If a global scope has not been set, keep the 'Use custom scope' option as default and add http://website.thm/ to the scope in this section.
6. Switch back over to the Details tab and look at the 'Rule Actions' section:
   * Click the Add button.
     * Dropdown menu will appear with a list of actions we can add.
       * Select 'Run a Macro'.
         * In the new window that appears, select the macro created earlier.
7. The macro will now overwrite all of the parameters in Intruder requests before they are sent.
   * This means that the loginTokens and session cookies will get added straight into the requests.
   * Restrict which parameters and cookies are being updated before the attack is started:
     * Select 'Update only the following parameters and headers', then click the Edit button next to the input box below the radio button.
       * In the 'Enter a new item' text field, type "loginToken". Press Add, then Close
     * Select 'Update only the following cookies', then click the relevant Edit button.
       * Enter 'session' in the "Enter a new item" text field. Press Add, then Close.
     * Press OK to confirm the action.
9. Click OK to finish.
10. Now have a macro defined that will substitute in the CSRF token and session cookie.
   * All that's left to do is switch back to Intruder and start the attack.
   * Should be getting `302` status code responses for every request in this attack.
     * Macro is not working properly if `403` errors are received.
11. Response codes are all the same (302 Redirects) as with the support login credential stuffing attack carried out previously.
    * Order the responses by length to find the valid credentials.
    * Results won't be quite clear-cut as will be quite a few different response lengths.
      * The response that indicates a successful login should still stand out as being significantly shorter.
12. Use the credentials just found to log in (may need to refresh the login page before entering the credentials).
