# Burp Suite: Extensions
## The Extensions Interface
* Provides an overview of the extensions loaded into the tool:
  * **Extensions List**: the top box displays a list of the extensions that are currently installed in Burp Suite for the current project.
      * Allows activation or deactivation of individual extensions.
  * **Managing Extensions**: on the left side of the Extensions interface, there are options to manage extensions:
      * **Add**: use this button to install new extensions from files on your disk.
          * These files can be custom-coded modules or modules obtained from external sources that are not available in the official BApp store.
      * **Remove**: allows selected extensions to be uninstalled from Burp Suite.
      * **Up/Down**: control the order in which installed extensions are listed.
          * The order determines the sequence in which extensions are invoked when processing traffic.
          * Extensions are applied in descending order, starting from the top of the list and moving down.
            * The order is essential, especially when dealing with extensions that modify requests, as some may conflict or interfere with others.
* **Details, Output, and Errors**: towards the bottom of the window, there are sections for the currently selected extension:
    * **Details**: provides information about the selected extension, such as its name, version, and description.
    * **Output**: displays any relevant output or results during extension execution.
    * **Errors**: if an extension encounters any errors during execution, they will be shown in this section.
        * This can be useful for debugging and troubleshooting extension issues.
* Extensions interface in Burp Suite allows users to manage and monitor the installed extensions, activate or deactivate them for specific projects, and view important details, output, and errors related to each extension.
* By using extensions, Burp Suite becomes a powerful and customizable platform for various security testing and web application assessment tasks.

## The BApp Store
* BApp Store (Burp App Store) allows us easy discovery and integration of official extensions seamlessly into the tool.
* Extensions can be written in various languages, with Java and Python being the most common choices.
* Java extensions integrate automatically with the Burp Suite framework, while Python extensions require the Jython interpreter.

### BApp Java Extenion Installation
* To get a feel for the BApp store and install a Java extension, install the Request Timer extension, written by Nick Taylor.
  * The Request Timer extension logs the time it takes for each request to receive a response.
  * This functionality is particularly useful for identifying and exploiting time-based vulnerabilities.
    * For instance, if a login form takes an extra second to process requests with valid usernames compared to invalid ones, the time differences can be userd to determine which usernames are valid.
* Follow these steps to install the Request Timer extension from the BApp store:
  1. Switch to the **BApp Store** sub-tab in Burp Suite.
  2. Use the search function to find **Request Timer**.
     * There should only be one result for this extension.
  3. Click on the returned extension to view more details.
  4. Click the **Install** button to install the Request Timer extension.
* A new tab appears in the main menu at the top of the Burp Suite interface after successfully installing the extension.
  * Different extensions may have varying behaviours.
  * Some may add new items to right-click context menus, while others create entirely new tabs in the main menu bar.
* Highly recommend switching to the new tab and exploring the extension to understand its functionalities better.
  * Request Timer can be valuable in various scenarios, especially when assessing web application security and identifying potential time-based vulnerabilities.

## Jython
* Jython Interpreter JAR file needs to be included in Python modules in Burp Suite.
  * Jython Interpreter JAR file is a Java implementation of Python.
* Enables running of Python-based extensions within Burp Suite.
* Follow these steps to integrate Jython into Burp Suite on the local machine:
  1. **Download Jython JAR** by visiting the [Jython website](https://www.jython.org/download) and download the standalone JAR archive.
  2. Look for the **Jython Standalone** option.
     * Save the JAR file to a location locally.
  3. **Configure Jython in Burp Suite** by switching to the **Extensions** module.
       * Then, go to the **Extensions settings** sub-tab.
  4. **Python Environment** scroll down to the 'Python environment' section.
  5. **Set Jython JAR Location** in the 'Location of Jython standalone JAR file' field, set the path to the downloaded Jython JAR file.
* Once these steps are complete3d, Jython will be integrated with Burp Suite, allowing use of Python modules in the tool.
* This integration significantly increases the number of available extensions and enhances capabilities in performing various security testing and web application assessment tasks.
* The process of adding Jython to Burp Suite is the same for all operating systems, as Java is a multi-platform technology.

## The Burp Suite API
* Access to a wide range of API endpoints in the Burp Suite Extensions module that allows creation and integration of custom modules.
* These APIs expose various functionalities, enabling extension of the capabilities of Burp Suite to suit specific needs.
* To view the available API endpoints, navigate to the **APIs** sub-tab within the Extensions module.
  * Each item listed in the left-hand panel represents a different API endpoint that can be accessed from within extensions.
* The Extensions APIs give developers significant power and flexibility when writing custom extensions.
  * Use these APIs to seamlessly interact with Burp Suite's existing functionality and tailor your extensions to perform specific tasks.
* Burp Suite supports multiple languages for writing extensions, such as:
  * Java (Natively): can directly use Java to write extensions for Burp Suite, taking advantage of the powerful APIs available.
  * Python (via Jython): can utilise Jython, which is a Java implementation of Python to create Burp Suite extensions.
  * Ruby (via JRuby): can leverage JRuby, a Java implementation of Ruby, to build Burp Suite extensions.
* Coding custom extensions for Burp Suite can be a complex task.
  * PortSwigger provides a comprehensive reference that is an excellent resource for developing Burp Suite extensions.
  * To learn more about Burp Suite extension development and to access the detailed reference, visit PortSwigger's [official documentation](https://portswigger.net/burp/extender/writing-your-first-burp-suite-extension).
    * This resource will provide the information and guidance needed to create powerful and customised extensions that enhance your experience with Burp Suite.
