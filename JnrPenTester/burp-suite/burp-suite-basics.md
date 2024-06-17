# Burp Suite Basics

### **Burp Suite: The Basics** <a href="#h1fceptwtj83" id="h1fceptwtj83"></a>

### **What is Burp Suite?** <a href="#id-3ud7si9fr7yb" id="id-3ud7si9fr7yb"></a>

* Java-based framework designed to serve as a comprehensive solution for conducting web application penetration testing.
* Has become the industry standard tool for hands-on security assessments of web and mobile applications, including those that rely on application programming interfaces (APIs).
* Captures and enables manipulation of all the HTTP/HTTPS traffic between a browser and a web server.
  * This fundamental capability forms the backbone of the framework.
* By intercepting requests, users have the flexibility to route them to various components within the Burp Suite framework.
* Having the ability to intercept, view, and modify web requests before they reach the target server or even manipulate responses before they are received by our browser makes Burp Suite an invaluable tool for manual web application testing.
* Burp Suite Community Edition id freely accessible for non-commercial use within legal boundaries.
* Burp Suite Professional is an unrestricted version of Burp Suite Community that comes with features such as:
  * An automated vulnerability scanner.
  * A fuzzer/brute-forcer that isn't rate limited.
  * Saving projects for future use and report generation.
  * A built-in API to allow integration with other tools.
  * Unrestricted access to add new extensions for greater functionality.
  * Access to the Burp Suite Collaborator (effectively providing a unique request catcher self-hosted or running on a Portswigger-owned server).
  * Highly potent tool, making it a preferred choice for professionals in the field.
* Burp Suite Enterprise in contrast to the community and professional editions is primarily utilised for continuous scanning.
  * Features an automated scanner that periodically scans web applications for vulnerabilities, similar to how tools like Nessus perform automated infrastructure scanning.
  * Unlike the other editions, Burp Suite Enterprise resides on a server and constantly scans the target web applications for potential vulnerabilities.

### **Features of Burp Suite Community Edition** <a href="#psvnfolq7h8s" id="psvnfolq7h8s"></a>

#### **Proxy** <a href="#t401ed276g98" id="t401ed276g98"></a>

* Enables interception and modification of requests and responses while interacting with web applications.

#### **Repeater** <a href="#bbt67quho89q" id="bbt67quho89q"></a>

* Allows for capturing, modifying, and resending the same request multiple times.
* Functionality is particularly useful when crafting payloads through trial and error (e.g., in SQLi - Structured Query Language Injection) or testing the functionality of an endpoint for vulnerabilities.

#### **Intruder** <a href="#wj7k7arbf3bd" id="wj7k7arbf3bd"></a>

* Allows for spraying endpoints with requests despite rate limitations.
* Commonly utilised for brute-force attacks or fuzzing endpoints.

#### **Decoder** <a href="#r20ee75mcnco" id="r20ee75mcnco"></a>

* Offers a valuable service for data transformation.
* Can decode captured information or encode payloads before sending them to the target.
* While alternative services exist for this purpose, leveraging Decoder within Burp Suite can be highly efficient.

#### **Comparer** <a href="#f5top7nshk2o" id="f5top7nshk2o"></a>

* Enables the comparison of two pieces of data at either the word or byte level.
* While not exclusive to Burp Suite, the ability to send potentially large data segments directly to a comparison tool with a single keyboard shortcut significantly accelerates the process.

#### **Sequencer** <a href="#t4h8emoif26y" id="t4h8emoif26y"></a>

* Typically employed when assessing the randomness of tokens, such as session cookie values or other supposedly randomly generated data.
* If the algorithm used for generating these values lacks secure randomness, it can expose avenues for devastating attacks.

#### **Extensions** <a href="#w2183icf5bjy" id="w2183icf5bjy"></a>

* Beyond the built-in features, the Java codebase of Burp Suite facilitates the development of extensions to enhance the framework's functionality.
  * These extensions can be written in Java, Python (using the Java Jython interpreter), or Ruby (using the Java JRuby interpreter).
* The Burp Suite Extender module allows for quick and easy loading of extensions into the framework, while the marketplace, known as the BApp Store, enables downloading of third-party modules.
* While certain extensions may require a professional licence for integration, there are still a considerable number of extensions available for Burp Community.
  * For instance, the Logger++ module can extend the built-in logging functionality of Burp Suite.

### **Installation** <a href="#h2xpe3me9dpv" id="h2xpe3me9dpv"></a>

#### **Downloads** <a href="#g0l2ixnibbnr" id="g0l2ixnibbnr"></a>

* To download the latest version of Burp Suite for other systems, click[ this](https://portswigger.net/burp/releases/) button to go to the download page.
* Burp Suite comes pre-installed with **Kali Linux**.
  * In case it is missing on the Kali installation, it can easily be installed from the Kali apt repositories.
* **Linux, macOS, and Windows**: PortSwigger provides dedicated installers for Burp Suite Community and Burp Suite Professional on the Burp Suite downloads page.
  * Choose your operating system from the dropdown menu and select **Burp Suite Community Edition**.
  * Click the **Download** button to initiate the download.

#### **Installation** <a href="#e2jpnns1viwu" id="e2jpnns1viwu"></a>

* On Windows, run the executable file, while on Linux, execute the script from the terminal (with or without sudo).
  * If sudo is not used during installation on Linux, Burp Suite will be installed in the home directory at \~/BurpSuiteCommunity/BurpSuiteCommunity and will not be added to the PATH.
* The installation wizard provides clear instructions and it is generally safe to accept the default settings.

### **The Dashboard** <a href="#id-4if2clcwp2ll" id="id-4if2clcwp2ll"></a>

* Once Burp Suite is launched and the terms and conditions are accepted, a project type will need to be selected.
  * In Burp Suite Community, the options are limited so click **Next** to proceed.
* The next window allows the configuration for Burp Suite to be chosen.
  * It is generally recommended to keep the default settings, which are suitable for most situations.
* Click **Start Burp** to open the main Burp Suite interface.
  * Upon opening Burp Suite for the first time, a screen with training options may be encountered.
    * It is highly recommended to go through these training materials.
* If the training screen is not displayed (or in subsequent sessions) the **Burp Dashboard** will be presented.
* There are question mark icons throughout the various tabs and windows of Burp Suite.
  * Clicking on these opens a new window with helpful information specific to that section.
  * These are invaluable when assistance or clarification is needed on a particular feature, so make sure to utilise them effectively.
* The Burp Dashboard is divided into four quadrants, as labelled in counter-clockwise order starting from the top left.

#### **Tasks Section** <a href="#id-3hbd2f6nic3j" id="id-3hbd2f6nic3j"></a>

* Allows the definition of background tasks that Burp Suite will perform while the application is used.
* Burp Suite Professional offers additional features like on-demand scans.

#### **Event log Section** <a href="#id-1vn8rutejshs" id="id-1vn8rutejshs"></a>

* Provides information about the actions performed by Burp Suite, such as starting the proxy, as well as details about connections made through Burp.

#### **Issue Activity Section** <a href="#w2uheu7msvmd" id="w2uheu7msvmd"></a>

* Specific to Burp Suite Professional.
* Displays vulnerabilities identified by the automated scanner, ranked by severity and filterable based on the certainty of the vulnerability.

#### **Advisory Section** <a href="#id-4su47aow71ck" id="id-4su47aow71ck"></a>

* Provides more detailed information about the identified vulnerabilities, including references and suggested remediations.
* This information can be exported into a report.
* In Burp Suite Community, this section may not show any vulnerabilities.

### **Navigation** <a href="#cbjka2o5ox2i" id="cbjka2o5ox2i"></a>

* Primarily done through the top menu bars, which allow switching between modules and access various sub-tabs within each module.
* Sub-tabs appear in a second menu bar directly below the main menu bar.

#### **Module Selection** <a href="#h0o7vdhlwfp8" id="h0o7vdhlwfp8"></a>

* Top row of the menu bar displays the available modules in Burp Suite.
* Each module can be clicked on to switch between them.

#### **Sub-Tabs** <a href="#id-1ohnnz7nijo5" id="id-1ohnnz7nijo5"></a>

* If a selected module has multiple sub-tabs, they can be accessed through the second menu bar that appears directly below the main menu bar.
* Sub-tabs often contain module-specific settings and options.

#### **Detaching Tabs** <a href="#aen6u6w2ytsz" id="aen6u6w2ytsz"></a>

* To view multiple tabs separately, detach them into separate windows.
  * To do this, go to the Window option in the application menu above the Module Selection bar.
    * From there, choose the "Detach" option, and the selected tab will open in a separate window.
* Detached tabs can be reattached using the same method.
* Keyboard shortcuts are provided for quick navigation to key tabs:

| **Shortcut**     | **Tab**      |
| ---------------- | ------------ |
| Ctrl + Shift + D | Dashboard    |
| Ctrl + Shift + T | Target tab   |
| Ctrl + Shift + P | Proxy tab    |
| Ctrl + Shift + I | Intruder tab |
| Ctrl + Shift + R | Repeater tab |

### **Options** <a href="#id-8db49c7svai0" id="id-8db49c7svai0"></a>

#### **Global Settings** <a href="#bn6ayre6mn08" id="bn6ayre6mn08"></a>

* Affect the entire Burp Suite installation and are applied every time you start the application.
* Provide a baseline configuration for your Burp Suite environment.

#### **Project Settings** <a href="#id-3rw7obnsw413" id="id-3rw7obnsw413"></a>

* Specific to the current project and apply only during the session.
* Burp Suite Community Edition does not support saving projects, so any project-specific options will be lost when you close Burp.
* To access the settings, click on the **Settings** button in the top navigation bar.
* This will open a separate settings window.
* There is a menu on the left-hand side in the Settings window.
* This menu allows switching between different types of settings including:
  * **Search**: Enables searching for specific settings using keywords.
  * **Type filter**: Filters the settings for User and Project options.
  * **User settings**: Shows settings that affect the entire Burp Suite installation.
  * **Project settings**: Displays settings specific to the current project.
  * **Categories**: Allows selecting settings by category.
* Many tools within Burp Suite provide shortcuts to specific categories of settings.
  * For example, the Proxy module includes a Proxy settings button that opens the settings window directly to the relevant proxy section.
* The search feature on the settings page is a valuable addition, allowing the quick search for settings using keywords.

### **Introduction to the Burp Proxy** <a href="#id-7rxi6lsujrcw" id="id-7rxi6lsujrcw"></a>

* Fundamental and crucial tool within Burp Suite.
* Enables the capture of requests and responses between the user and the target web server.
* Intercepted traffic can be manipulated, sent to other tools for further processing, or explicitly allowed to continue to its destination.

#### **Key Points to Understand About the Burp Proxy** <a href="#id-6q5mod7o0k9b" id="id-6q5mod7o0k9b"></a>

* **Intercepting Requests**: When requests are made through the Burp Proxy, they are intercepted and held back from reaching the target server.
  * The requests appear in the Proxy tab, allowing for further actions such as forwarding, dropping, editing, or sending them to other Burp modules.
  * To disable the intercept and allow requests to pass through the proxy without interruption, click the Intercept is on button.
* **Taking Control**: The ability to intercept requests empowers testers to gain complete control over web traffic, making it invaluable for testing web applications.
* **Capture and Logging**: Burp Suite captures and logs requests made through the proxy by default, even when the interception is turned off.
  * This logging functionality can be helpful for later analysis and review of prior requests.
* **WebSocket Support**: Burp Suite also captures and logs WebSocket communication, providing additional assistance when analysing web applications.
* **Logs and History**: The captured requests can be viewed in the HTTP history and WebSockets history sub-tabs, allowing for retrospective analysis and sending the requests to other Burp modules as needed.
* Proxy-specific options can be accessed by clicking the **Proxy settings** button.
  * These options provide extensive control over the Proxy’s behaviour and functionality.

#### **Some Notable Features in the Proxy Settings** <a href="#id-7x9a9vc7o4e3" id="id-7x9a9vc7o4e3"></a>

* **Response Interception**: By default, the proxy does not intercept server responses unless explicitly requested on a per-request basis.
  * The "Intercept responses based on the following rules" checkbox, along with the defined rules, allows for a more flexible response interception.
* **Match and Replace**: This section in the Proxy settings enables the use of regular expressions (regex) to modify incoming and outgoing requests.
  * This feature allows for dynamic changes, such as modifying the user agent or manipulating cookies.

### **Connecting through the Proxy (FoxyProxy)** <a href="#m681dhlgrb13" id="m681dhlgrb13"></a>

* To use the Burp Suite Proxy, the local web browser must be configured to redirect traffic through Burp Suite.
* These instructions are specific to Firefox.
  * **Install FoxyProxy**: Download and install the[ FoxyProxy Basic extension](https://addons.mozilla.org/en-US/firefox/addon/foxyproxy-basic/).
  * **Access FoxyProxy Options**: Once installed, a button will appear at the top right of the Firefox browser.
    * Click on the FoxyProxy button to access the FoxyProxy options pop-up.
  * **Create Burp Proxy Configuration**: In the FoxyProxy options pop-up, click the **Options** button.
    * This will open a new browser tab with the FoxyProxy configurations.
    * Click the **Add** button to create a new proxy configuration.
* **Add Proxy Details**: On the **Add Proxy** page, fill in the following values:
  * Title: Burp (or any preferred name)
  * Proxy IP: 127.0.0.1
  * Port: 8080
* **Save Configuration**: Click **Save** to save the Burp Proxy configuration.
* **Activate Proxy Configuration**: Click on the FoxyProxy icon at the top-right of the Firefox browser and select the Burp configuration.
  * This will redirect your browser traffic through 127.0.0.1:8080.
* **Enable Proxy Intercept in Burp Suite**: Switch to Burp Suite and ensure that Intercept is turned on in the **Proxy** tab.
* **Test the Proxy**: Open Firefox and try accessing a website.
  * The browser will hang, and the proxy will populate with the HTTP request.

**Remember the following**:

* When the proxy configuration is active, and the intercept is switched on in Burp Suite, the browser will hang whenever a request is made.
* Be cautious not to leave the intercept switched on unintentionally, as it can prevent the browser from making any requests.
* Right-clicking on a request in Burp Suite performs various actions, such as forwarding, dropping, sending to other tools, or selecting options from the right-click menu.

### **Site Map and Issue Definitions** <a href="#h6iu9pr351qc" id="h6iu9pr351qc"></a>

* **Target** tab in Burp Suite consists of three tabs and provides more than just control over the scope of our testing.
  * **Site map**: This sub-tab maps out the targeted web applications in a tree structure.
    * Every page visited while the proxy is active will be displayed on the site map.
    * This feature enables automatic generation of a site map by simply browsing the web application.
    * In Burp Suite Professional, the site map can also be used to perform automated crawling of the target, exploring links between pages and mapping out as much of the site as possible.
    * Even with Burp Suite Community, the site map ca nstill be utilised to accumulate data during the initial enumeration steps.
    * It is particularly useful for mapping out APIs, as any API endpoints accessed by the web application will be captured in the site map.
  * **Issue definitions**: Although Burp Community does not include the full vulnerability scanning functionality available in Burp Suite Professional, there is still access to a list of all the vulnerabilities that the scanner looks for.
    * This section provides an extensive list of web vulnerabilities, complete with descriptions and references.
    * This resource can be valuable for referencing vulnerabilities in reports or assisting in describing a particular vulnerability that may have been identified during manual testing.
  * **Scope settings**: This setting allows control over the target scope in Burp Suite.
    * It enables the inclusion or exclusion of specific domains/IPs to define the scope of the testing.
    * By managing the scope, the focus is on the web applications being specifically targeting and avoids capturing unnecessary traffic.

### **The Burp Suite Browser** <a href="#g0odas2ak19n" id="g0odas2ak19n"></a>

* Burp Suite includes a built-in Chromium browser that is pre-configured to use the proxy without any of the modifications.
  * To start the Burp Browser, click the Open Browser button in the proxy tab.
  * A Chromium window will pop up, and any requests made in this browser will go through the proxy.
  * There are many settings related to the Burp Browser in the project options and user options settings.
* If Burp Suite is being run on Linux as the root user, an error preventing the Burp Browser from starting due to the inability to create a sandbox environment may be encountered.
  * There are two simple solutions to this:
    * **Smart option**: Create a new user and run Burp Suite under a low-privilege account to allow the Burp Browser to run without issues.
    * **Easy option**: Go to Settings -> Tools -> Burp's browser and check the Allow Burp's browser to run without a sandbox option.
      * Enabling this option will allow the browser to start without a sandbox.
      * However, this option is disabled by default for security reasons.
        * Exercise caution if it is enabled, as compromising the browser could grant an attacker access to the entire machine.

### **Scoping and Targeting** <a href="#id-3a3nl1c88m9u" id="id-3a3nl1c88m9u"></a>

* One of the most important aspects of using the Burp Proxy.
* Capturing and logging all of the traffic can quickly become overwhelming and inconvenient, especially when the focus is on specific web applications.
* By setting a scope for the project, what gets proxied and logged in Burp Suite can be defined.
* Burp Suite can be restricted to target only the specific web application(s) to test:
  * Switch to the Target tab, right-click on the target from the list on the left, and select Add To Scope.
  * Burp will then prompt to choose whether to stop logging anything that is not in scope.
    * In most cases select yes.
* To check the scope, switch to the **Scope** settings sub-tab within the **Target** tab.
  * The Scope settings window allows control over the target scope by including or excluding domains/IPs.
  * This section is powerful.
* Even if logging is disabled for out-of-scope traffic, the proxy will still intercept everything.
  * To prevent this, go to the **Proxy settings** sub-tab and select **And URL Is in target scope** from the **Intercept Client Requests** section.
    * Enabling this option ensures that the proxy completely ignores any traffic that is not within the defined scope, resulting in a cleaner traffic view in Burp Suite.

### **Proxying HTTPS** <a href="#z7k9hignhwu3" id="z7k9hignhwu3"></a>

* When intercepting HTTP traffic, an issue may be encountered when navigating to sites with TLS enabled.
  * For example, when accessing a site like https://google.com/, an error will be received indicating that the PortSwigger Certificate Authority (CA) is not authorised to secure the connection.
* This happens because the browser does not trust the certificate presented by Burp Suite.
* To overcome this issue, manually add the PortSwigger CA certificate to the local browser's list of trusted certificate authorities:
  * **Download the CA Certificate**: With the Burp Proxy activated, navigate to http://burp/cert.
    * This will download a file called cacert.der.
    * Save this file locally.
  * **Access Firefox Certificate Settings**: Type about:preferences into the Firefox URL bar and press Enter.
    * This will go to the Firefox settings page.
    * Search the page for 'certificates' and click on the **View Certificates** button.
  * **Import the CA Certificate**: In the Certificate Manager window, click on the **Import** button.
    * Select the cacert.der file that you downloaded in the previous step.
  * **Set Trust for the CA Certificate**: In the subsequent window that appears, check the box that says 'Trust this CA to identify websites' and click OK.
* By completing these steps, the PortSwigger CA certificate has been added to the list of trusted certificate authorities.
* Now visits to any TLS-enabled site will not present the certificate error.
  * The browser now trusts the PortSwigger CA certificate and securely communicates with TLS-enabled websites through the Burp Suite Proxy.

### **Example Attack** <a href="#eph39wtifnhr" id="eph39wtifnhr"></a>

* A support form is found on a website with 'Contact email' and 'Type your query here' text fields.
* In a real-world web app pentest, this would be tested for a variety of things, one of which would be Cross-Site Scripting (or XSS).
  * XSS can be thought of as injecting a client-side script (usually in Javascript) into a webpage in such a way that it executes.
  * There are various kinds of XSS – the type used here is referred to as "Reflected" XSS, as it only affects the person making the web request.

#### **Walkthrough** <a href="#xf1rp95jxome" id="xf1rp95jxome"></a>

* Type \<script>alert("Succ3ssful XSS")\</script> into the 'Contact Email' field.
* There is a client-side filter in place which prevents adding any special characters that aren't allowed in email addresses.
* Client-side filters are absurdly easy to bypass.
* There are a variety of ways to disable the script or just prevent it from loading in the first place.
* Focus on bypassing the filter.
* Make sure that the Burp Proxy is active and that intercept is on.
* Enter some legitimate data into the support form.
  * For example: pentester@example.thm as an email address, and Test Attack as a query.
* Submit the form — the request will be intercepted by the proxy.
* With the request captured in the proxy, change the email field to be the very simple payload from above: \<script>alert("Succ3ssful XSS")\</script>.
* After pasting in the payload, select it, then URL encode it with the Ctrl + U shortcut to make it safe to send.
* Finally, press the 'Forward"' button to send the request.
* An alert box will be received from the site indicating a successful XSS attack.
