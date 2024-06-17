# Other Burp Modules

### **Burp Suite: Other Modules** <a href="#oezx6s20e3gn" id="oezx6s20e3gn"></a>

* Decoder, Comparer, Sequencer, and Organizer tools facilitate operations with encoded text, enable comparison of data sets, allow the analysis of randomness within captured tokens, and help you store and annotate copies of HTTP messages that may want to be revisited later.
* Although these tasks appear straightforward, accomplishing them within Burp Suite can substantially save time.

### **Decoder: Overview** <a href="#id-4r7367pdc9zf" id="id-4r7367pdc9zf"></a>

* Gives user data manipulation capabilities.
* Not only decodes data intercepted during an attack but also provides the function to encode data, prepping it for transmission to the target.
* Allows creation of hashsums of data, as well as providing a Smart Decode feature, which attempts to decode provided data recursively until it is back to being plaintext (like the "Magic" function of Cyberchef).
* To access the Decoder, navigate to the Decoder tab from the top menu to view the available options:
  * The left input field serves as the workspace for entering or pasting data that requires encoding or decoding.
    * Consistent with other modules of Burp Suite, data can be moved to this area from different parts of the framework via the Send to Decoder option upon right-clicking.
  * At the top of the list on the right, there's an option to treat the input as either text or hexadecimal byte values.
  * Below this are dropdown menus are present to encode, decode, or hash the input.
  * The Smart Decode feature, located at the end, attempts to auto-decode the input.
* Upon entering data into the input field, the interface replicates itself to present the output of our operation.
* Can then choose to apply further transformations using the same options.

### **Decoder: Encoding/Decoding** <a href="#c5rwtj9rnbm7" id="c5rwtj9rnbm7"></a>

* These are identical whether the decoding or encoding menu is chosen:
  * **Plain**: refers to the raw text before any transformations are applied.
  * **URL**: utilised to ensure the safe transfer of data in the URL of a web request.
    * Involves substituting characters for their ASCII character code in hexadecimal format, preceded by a percentage symbol %.
    * This method is vital for any type of web application testing.
      * For instance, encoding the forward-slash character /, whose ASCII character code is 47, converts it to 2F in hexadecimal, thus becoming %2F in URL encoding.
        * The Decoder can be used to verify this by typing a forward slash in the input box, then selecting Encode as -> URL.
  * **HTML**: replaces special characters with an ampersand &, followed by either a hexadecimal number or a reference to the character being escaped, and ending with a semicolon ;.
    * This method ensures the safe rendering of special characters in HTML and helps prevent attacks such as XSS.
    * HTML option in Decoder allows any character to be encoded into its HTML escaped format or decode captured HTML entities.
      * For instance, to decode a previously discussed quotation mark, input the encoded version and choose Decode as -> HTML.
  * **Base64**: converts any data into an ASCII-compatible format.
  * **ASCII Hex**: transitions data between ASCII and hexadecimal representations.
    * For instance, the word ASCII can be converted into the hexadecimal number 4153434949.
    * Each character is converted from its numeric ASCII representation into hexadecimal.
  * **Hex, Octal, and Binary**: apply solely to numeric inputs, converting between decimal, hexadecimal, octal (base eight), and binary representations.
  * **Gzip**: compresses data, reducing file and page sizes before browser transmission.
    * Faster load times are highly desirable for developers looking to enhance their SEO score and avoid user inconvenience.
    * Decoder facilitates the manual encoding and decoding of gzip data, although it often isn't valid ASCII/Unicode.
* Methods can be stacked.
  * For example, a phrase ('Burp Suite Decoder') could be converted to ASCII Hex and then to octal.
* In combination, these methods grant substantial control over the data being encoding or decoding.
* Each encoding/decoding method is colour-coded, enabling swift identification of the applied transformation.

#### **Hex Format** <a href="#id-3mv3sy1et5pn" id="id-3mv3sy1et5pn"></a>

* There are times when byte-by-byte input editing is necessary.
* This is where 'Hex View' proves useful (selectable above the decoding options).
* Enables viewing and altering of data in hexadecimal byte format, a vital tool when working with binary files or other non-ASCII data.

#### **Smart Decode** <a href="#ub9vcttiz20q" id="ub9vcttiz20q"></a>

* Tries to auto-decode encoded text.
  * For instance \&#x42;\&#x75;\&#x72;\&#x70;\&#x20;\&#x53;\&#x75;\&#x69;\&#x74;\&#x65 is automatically recognized as HTML encoded and is accordingly decoded.
* While not perfect, this feature can be a quick solution for decoding unknown data chunks.

#### **Decoder: Hashing** <a href="#id-4145cbflrp11" id="id-4145cbflrp11"></a>

* Decoder also offers the ability to generate hashsums for data.

**Theory**

* Hashing is a one-way process that transforms data into a unique signature.
* For a function to qualify as a hashing algorithm, the output it generates must be irreversible.
* A proficient hashing algorithm ensures that every data input will generate a completely unique hash.
  * For instance, using the MD5 algorithm to produce a hashsum for the text MD5sum returns 4ae1a02de5bd02a5515f583f4fca5e8c.
    * Using the same algorithm for MD5SUM yields an entirely different hash despite the close resemblance of the input 13b436b09172400c9eb2f69fbd20adad.
* Hashes are commonly used to verify the integrity of files and documents, as even a tiny alteration to the file significantly changes the hashsum.
* MD5 algorithm is deprecated and should not be used for contemporary applications.
* Hashes are used to securely store passwords since the one-way hashing process makes the passwords relatively secure, even if the database is compromised.
* When a user creates a password, the application hashes and stores it.
* During login, the application hashes the submitted password and compares it against the stored hash; if they match, the password is correct.
* Using this method, an application never needs to store the original (plaintext) password.

**Hashing in Decoder**

* Allows creation of hashsums for data directly within Burp Suite.
* Click on the Hash dropdown menu and select an algorithm from the list.
  * Note: The list is significantly longer than the encoding/decoding algorithms.
  * It is worth scrolling through to see the many available hashing algorithms.
* Enter 'MD5sum' into the input box, then scroll down the list until we find 'MD5'.
  * Applying this automatically moved into the Hex view.
* A hashing algorithm's output does not yield pure ASCII/Unicode text.
  * Customary to convert the algorithm's output into a hexadecimal string.
  * This is the "hash" form.

### **Comparer: Overview** <a href="#id-5i1kjf9gn9zt" id="id-5i1kjf9gn9zt"></a>

* Compares two pieces of data, either by ASCII words or by bytes.
* The interface is divided into three main sections:
  * On the left are the items to be compared.
    * When data is loaded into Comparer, it appears as rows in these tables.
    * Select two datasets to compare.
  * On the upper right are options for pasting data from the clipboard (Paste), loading data from a file (Load), removing the current row (Remove), and clearing all datasets (Clear).
  * On the lower right is the option to compare the datasets by either words or bytes.
* Can also load data into Comparer from other modules by right-clicking and choosing Send to Comparer.
* Pop-up window shows the comparison once at least 2 datasets have been added to compare.
  * Window has three distinct sections:
    * Compared data occupies most of the window.
      * Can be viewed in either text or hex format.
      * Initial format depends on whether the compare is by words or bytes in the previous window.
        * This can be overridden by using the buttons above the comparison boxes.
  * Comparison key is at the bottom left, showing which colours represent modified, deleted, and added data between the two datasets.
  * Sync views checkbox is at the bottom right of the window.
    * When selected, it ensures that both sets of data will sync formats.
    * If one of them is changed into Hex view, the other will adjust to match.
  * The window title displays the total number of differences found.

#### **Comparer: Example** <a href="#jy8ng7koebxw" id="jy8ng7koebxw"></a>

* There are many situations where being able to quickly compare two (potentially very large) pieces of data can come in handy.
  * For example, comparing two responses with different lengths to see where the differences lie and whether the differences indicate a successful login when performing a login bruteforce or credential stuffing attack with Intruder.

#### **Practical Comparer Example** <a href="#id-30oiewgp2ud1" id="id-30oiewgp2ud1"></a>

* Navigate to[ http://website.thm/support/login](http://website.thm/support/login)
* Try to log in with an invalid username and password and capture the request in the Burp Proxy.
* Send the request to Repeater with Ctrl + R (or Mac equivalent) or by right-clicking on the request in the Proxy module and choosing Send to Repeater.
* Send the request, then right-click on the response and choose Send to Comparer.
* In the Repeater tab, change the credentials to:

Username: support\_admin

Password: w58ySK4W

* Send the request again, then pass the new response to Comparer.
* Compare the two responses by word to identify the main differences.

### **Sequencer: Overview** <a href="#i9eahs599kyg" id="i9eahs599kyg"></a>

* Evaluates the entropy, or randomness, of 'tokens'.
  * Tokens are strings used to identify something and should ideally be generated in a cryptographically secure manner.
* Tokens could be session cookies or Cross-Site Request Forgery (CSRF) tokens used to protect form submissions.
* If the tokens aren't generated securely, then prediction of upcoming token values should be possible.
* Two main ways to perform token analysis with Sequencer:
  * **Live Capture**: is the more common method and is the default sub-tab for Sequencer.
    * Allows passing of a request that will generate a token to Sequencer for analysis.
      * For instance, pass a POST request to a login endpoint to Sequencer, knowing that the server will respond with a cookie.
    * With the request passed in, Sequencer can be instructed to start a live capture.
    * Will then automatically make the same request thousands of times, storing the generated token samples for analysis.
    * After collecting enough samples, we stop the Sequencer and allow it to analyse the captured tokens.
* **Manual Load**: allows the loading of a list of pre-generated token samples directly into Sequencer for analysis.
  * Do not need to make thousands of requests to the target, which can be noisy and resource-intensive.
  * Does require that there is a large list of pre-generated tokens.

#### **Sequencer: Live Capture** <a href="#atfshqditczi" id="atfshqditczi"></a>

* Use Sequencer's live capture for entropy analysis on the anti-bruteforce token used in the admin login form.
* Capture a request to http://website.thm/admin/login/ in the Proxy.
* Right-click on the request and select **Send to Sequencer**.
* In the 'Token Location Within Response' section, select the **Form field** radio button and choose the loginToken from the dropdown menu.
* Leave all other options at their default values and click on the **Start live capture** button.
* A new window will pop up indicating that a live capture is in progress and displaying the number of tokens captured so far.
* Wait until a sufficient number of tokens are captured (approximately 10,000 should suffice).
  * The more tokens we have, the more precise the analysis will be.
* Once around 10,000 tokens are captured, click on **Pause** and then select the **Analyze now** button.
* Note that there is also a button to **Stop** the capture.
  * By opting to pause, the option is still available to resume the capture later if the report does not have enough samples to accurately calculate the token's entropy.
* Could have also selected the 'Auto analyse' checkbox if periodic updates on the analysis was required.
  * This option tells Burp to perform the entropy analysis after every 2000 requests, providing frequent updates that will become increasingly accurate as more samples are loaded into Sequencer.
* Could now choose to copy or save the captured tokens for further analysis at a later time.
* Burp will analyse the token's entropy and generate a report after clicking the **Analyze now** button.

#### **Sequencer: Analysis** <a href="#q1zkatguvf78" id="q1zkatguvf78"></a>

* The generated entropy analysis report is split into four primary sections:
  * The first of these is the **Summary** of the results.
    * The summary gives us the following:
      * **Overall result**: providing a broad assessment of the security of the token generation mechanism.
        * In this exapmle, the level of entropy indicates that the tokens are likely securely generated.
      * **Effective entropy**: measures the randomness of the tokens.
        * The effective entropy of 117 bits is relatively high, indicating that the tokens are sufficiently random and, therefore, secure against prediction or brute force attacks.
      * **Reliability**: measure the cofidence in the accuracy of the results.
        * The significance level of 1% implies that there is 99% confidence in the accuracy.

This level of confidence is high, providing assurance in the accuracy of the effective entropy estimation.

*
  *
    *
      * **Sample**: provides details about the token samples analysed during the entropy testing process, including the number of tokens and their characteristics.
* While the summary report often provides enough information to assess the security of the token generation process, it's important to remember that further investigation may be necessary in some cases.
* The **Character-level** and **Bit-level** analysis can provide more detailed insights into the randomness of the tokens, especially when the summary results raise potential concerns.
* The entropy report can provide a strong indicator of the security of the token generation mechanism, there needs to be more definitive proof.
* Other factors could also impact the security of the tokens, and the nature of probability and statistics means there's always a degree of uncertainty.
* Howver, An effective entropy of 117 bits with a significance level of 1% suggests a robustly secure token generation process.

### **Organiser: Overview** <a href="#y1jras3zyi3z" id="y1jras3zyi3z"></a>

* Designed to help store and annotate copies of HTTP requests that may want to be revisited later.
* Can be particularly useful for organising your penetration testing workflow.
* Key Features:
  1. Store requests that to investigate later, save requests already identified as interesting, or save requests to add to a report later.
  2. Send HTTP requests to Burp Organizer from other Burp Modules such as **Proxy** or **Repeater**.
     * Can do this by right-clicking the request and selecting **Send to Organizer** or using the default hotkey Ctrl + O.
     * Each HTTP request send to Organizer is a read-only copy of the original request saved at the point it was sent to Organizer.
* Requests are stored in a table, which contains columns such as:
  1. Request index number.
  2. Time the request was made.
  3. Workflow status.
  4. Burp tool that the request was sent from.
  5. HTTP method.
  6. Server hostname.
  7. URL file path.
  8. URL query string.
  9. Number of parameters in the request.
  10. HTTP status code of the response.
  11. Length of the response in bytes.
  12. Any notes made.
* To view the request and response:
  1. Click on any Organizer item.
  2. The request and response are both read-only.
     * Search within the request or response, select the request, and then use the search bar below the request.

### **Conclusion** <a href="#id-9a6xot6af178" id="id-9a6xot6af178"></a>

* Decoder allows the encoding and decoding of data, making it easier to read and understand the information being transferred.
* Comparer enables the spotting of differences between two datasets, which can be pivotal in identifying vulnerabilities or anomalies.
* Sequencer helps in performing entropy analysis on tokens, providing insights into the randomness of their generation and, consequently, their security level.
* Organiser enables storing and annotating of copies of HTTP requests that may need to be revisited later.
