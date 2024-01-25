# Burp Suite: Repeater
## What is Repeater?
* Enables the modification and resending of intercepted requests to a target of choice.
* Allows requests captured in the Burp Proxy to be manipulated, sending them repeatedly as needed.
* Can manually create requests from scratch, similar to using a command-line tool like cURL.
* The ability to edit and resend requests multiple times makes Repeater invaluable for manual exploration and testing of endpoints.
* Provides a user-friendly graphical interface for crafting request payloads and offers various views of the response, including a rendering engine for a graphical representation.
* Interface consists of six main sections:
  * **Request List**: Located at the top left of the tab, it displays the list of Repeater requests.
    * Multiple requests can be managed simultaneously, and each new request sent to Repeater will appear here.
  * **Request Controls**: Positioned directly beneath the request list, these controls allow a request to be sent, a hanging request to be cancelled, and navigation through the request history.
  * **Request and Response View**: Occupying the majority of the interface, this section displays the Request and Response views.
    * The request can be edited in the Request view and then forward it, while the corresponding response will be shown in the Response view.
  * **Layout Options**: Located at the top-right of the Request/Response view, these options enable the layout of the Request and Response views to be customised.
    * The default setting is a side-by-side (horizontal) layout, but a vertical layout may be chosen or they can be combined in separate tabs.
  * **Inspector**: Positioned on the right-hand side, the Inspector allows the analysis and modification of requests in a more intuitive manner than using the raw editor.
  * **Target**: Situated above the Inspector, the Target field specifies the IP address or domain to which the requests are sent.
    * When requests are sent to Repeater from other Burp Suite components, this field is automatically populated.
## Basic Usage
* While manual request crafting is an option, it is more common to capture a request using the Proxy module and subsequently transmit it to Repeater for further editing and resending.
* Once a request has been captured in the Proxy module, it can be sent to Repeater by either right-clicking on the request and selecting Send to Repeater, or by utilising the keyboard shortcut Ctrl + R.
* The captured request is now accessible in the Request view.
* Both the Target and Inspector sections display relevant information, albeit a response is currently lacking.
* Upon clicking the Send button, the Response view populates.
* Should any aspect of the request need to be modified, simply type within the Request view and press Send once again.
* This action will update the Response view on the right accordingly.
  * For instance, altering the Connection header to "open" instead of "close" yields a response with a Connection header containing the value "keep-alive":
* The history buttons situated to the right of the Send button can be used to navigate through the modification history, allowing movement forward or backwards as needed.
## Message Analysis Toolbar
* Repeater provides various request and response presentation options, ranging from hexadecimal output to a fully rendered page.
* To explore these options, refer to the section located above the response box, where the following four view buttons are available:
  * **Pretty**: This is the default option, which takes the raw response and applies slight formatting enhancements to improve readability.
  * **Raw**: This option displays the unmodified response directly received from the server without any additional formatting.
  * **Hex**: By selecting this view, the response can be examined in a byte-level representation, which is particularly useful when dealing with binary files.
  * **Render**: The render option allows visualisation of the page as it would appear in a web browser.
      * While not commonly utilised in Repeater, as the focus is usually on the source code, it still offers a valuable feature.
* For most scenarios, the **Pretty** option is generally sufficient.
* Adjacent to the view buttons, on the right-hand side, are the **Show non-printable characters** button (\n).
  * This functionality enables the display of characters that may not be visible with the **Pretty** or **Raw** options.
    * For example, each line in the response typically ends with the characters `\r\n`, representing a carriage return followed by a new line.
    * These characters play an important role in the interpretation of HTTP headers.
  * While not mandatory for most tasks, this option can prove advantageous in certain situations.

## Inspector
* Supplementary feature to the Request and Response views in the Repeater module.
* Also used to obtain a visually organised breakdown of requests and responses, as well as for experimenting to see how changes made using the higher-level Inspector affect the equivalent raw versions.
* Can be utilised both in the Proxy and Repeater module.
  * In both instances, it is situated on the far-right side of the window, presenting a list of components within the request and response.
  * Among these components, the sections pertaining to the request can typically be modified, enabling the addition, editing, and removal of items.
    * For instance, in the Request Attributes section, we can alter elements related to the location, method, and protocol of the request.
    * This includes modifying the desired resource to retrieve, changing the HTTP method from GET to another variant, or switching the protocol from HTTP/1 to HTTP/2.
* Other sections available for viewing and/or editing include:
  * **Request Query Parameters**: These refer to data sent to the server via the URL.
      * For example, in a `GET` request like `https://admin.tryhackme.com/?redirect=false`, the query parameter `redirect` has a value of `false`.
  * **Request Body Parameters**: Similar to query parameters, but specific to POST requests.
      * Any data sent as part of a POST request will be displayed in this section, allowing the modification of the parameters before resending.
  * **Request Cookies**: This section contains a modifiable list of cookies sent with each request.
  * **Request Headers**: It enables the viewing, accessing, and modification (including adding or removing) of any headers sent with our requests.
      * Editing these headers can be valuable when examining how a web server responds to unexpected headers.
  * **Response Headers**: This section displays the headers returned by the server in response to the request.
      * It cannot be modified, as the attacker has no control over the headers returned by the server.
      * Note that this section becomes visible only after sending a request and receiving a response.
* While the textual representation of these components can be found within the Request and Response views, Inspector's tabular format provides a convenient way to visualise and interact with them.

### Repeater Challenge
* The objective is to identify and exploit a Union SQLi vulnerability present in the `ID` parameter of the `/about/ID` endpoint.
* The task is to launch an attack to retrieve the notes about the CEO stored in the database by leveraging this vulnerability.
* Capture a request to `http://website.thm/about/2` in the Burp Proxy.
* Send it to Repeater with Ctrl + R or by right-clicking and choosing 'Send to Repeater'.
* Add a single apostrophe `'` after the `/about/2 at the end of the path.
* Send the request.
* The server responds with a '500 Internal Server Error', indicating that the query was successfully broken.
  * This validates that a simple SQLi is present.
* The body of the server's response contains an overly verbose error message that shows the query:
```
<h2>
 <code>
  Invalid statement: <code>
   SELECT firstName, lastName,
    pfpLink, role, bio FROM
   people WHERE id = 2'
  </code>
 </code>
</h2>
```
* This is an extremely useful error message that the server should absolutely not be sending, but the fact that it has makes things significantly more straightforward.
* The message states a couple of things that will be invaluable when exploiting this vulnerability:
  * The database table we are selecting from is called `people`.
  * The query selects five columns from the table `firstName`, `lastName`, `pfpLink`, `role`, and `bio`.
* With this information, the query column number and table name enumeration steps can be skipped.
* Still need to find the name of the target column.
* Use a union query to select the column names for the `people` table from the `columns` table in the `information_schema` default database:
```
/about/-1 UNION ALL SELECT column_name,null,null,null,null FROM information_schema.columns WHERE table_name="people"
```
* This creates a union query and selects the target, then four null columns (to avoid the query erroring out).
  * The selected `ID` is changed from `2` to an invalid number; `-1`.
    * Ensures that nothing is retrieved with the original (legitimate) query.
    * First row returned from the database will be the desired response from the injected query.
* The returned response shows that the first column name `id` has been inserted into the page title:
```
<title>
 About | id None
</title>
```
* We have successfully pulled the first column name out of the database, but we now have a problem.
* The page is only displaying the first matching item — we need to see all of the matching items.
* Fortunately, we can use our SQLi to group the results. We can still only retrieve one result at a time, but by using the group_concat() function, we can amalgamate all of the column names into a single output:
```
/about/-1 UNION ALL SELECT group_concat(column_name),null,null,null,null FROM information_schema.columns WHERE table_name="people"
```
* We have successfully identified eight columns in this table: id, firstName, lastName, pfpLink, role, shortRole, bio, and notes.
* Considering our task, it seems a safe bet that our target column is notes.
* Finally, we are ready to take the flag from this database — we have all of the information that we need:
* The name of the table: people.
* The name of the target column: notes.
* The ID of the CEO is 1; this can be found simply by clicking on Jameson Wolfe's profile on the /about/ page and checking the ID in the URL.
* Let's craft a query to extract this flag:
```
-1 UNION ALL SELECT notes,null,null,null,null FROM people WHERE id = 1
``
