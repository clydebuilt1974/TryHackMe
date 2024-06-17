# Walking an Application

## **Why Explore a Website?** <a href="#id-2ng3e0ojclbl" id="id-2ng3e0ojclbl"></a>

* Discover features that could potentially be vulnerable.
* Attempt to exploit them to assess whether or not they are.
* Vulnerable features are usually parts of the website that require some interactivity with the user.
* Finding interactive portions of the website can be as easy as spotting a login form to manually reviewing the website's JavaScript.
* An excellent place to start is with a browser exploring the website and noting down the individual pages/areas/features with a summary for each one.

## **What is Page Source?** <a href="#xlajy5y7ume4" id="xlajy5y7ume4"></a>

* Human readable code returned to the browser/client from the web server each time a request is made.
  * HTML (HyperText Markup Language).
  * CSS (Cascading Style Sheets).
  * JavaScript.
* Can help discover more information about a web application.

### **How to view the Page Source** <a href="#f1x974sbqttk" id="f1x974sbqttk"></a>

* Right-click on the page while viewing a website to display an option on the menu that says View Page Source.
* Most browsers support putting view-source: in front of the URL: view-source:https://www.google.com/

### **Common HTML Page Source Code** <a href="#s4dt1ycn5v1x" id="s4dt1ycn5v1x"></a>

#### **Comments**

* Code starting with `<!--` and ending with `->`.
* May ne messages left by the website developer usually to explain something in the code to other programmers or even notes/reminders for themselves.
* Comments do not get displayed on the actual webpage.

#### **Anchor Tags**

* Links to different pages in HTML are written in anchor tags.
* HTML elements that start with `<a`).
* The link that will be redirected to is stored in an `href` attribute.

#### **External Files**

* CSS, JavaScript and Images can be included using the HTML code.

#### **Frameworks**

* Many websites are not made from scratch and use a framework.
* These are a collection of pre-made code that easily allows a developer to include common features that a website would require, such as blogs, user management, form processing, and much more, saving the developers hours or days of development.
* Viewing the page source can often give clues into whether a framework is in use and, if so, which framework and even what version.
* Knowing the framework and version can be a powerful find as there may be public vulnerabilities in the framework, and the website might not be using the most up to date version.

## **Developer Tools** <a href="#s12ggd1iu8d" id="s12ggd1iu8d"></a>

* Tool kit included in modern browsers used to aid web developers in debugging web applications.
* A tester can leverage these tools to provide a much better understanding of the web application.

### **How to Open Developer Tools** <a href="#rcyi4k4shnzu" id="rcyi4k4shnzu"></a>

#### **Firefox**

Click on the Firefox Menu on the top right of the browser, then select Web Developer and then on the submenu select Web Developer Tools.

#### **Chrome**

Click on the Chrome Menu on the right hand side of the browser and then select More Tools and then Developer Tools.

#### **Safari**

First enable the develop menu. In Safari open preferences.  Then click on the advanced tab and then tick the checkbox at the bottom labelled Show Develop menu in menu bar.

#### **Edge**

Click on the Edge Menu on the right hand side of the browser and then select More Tools and then Developer Tools.

#### **Internet Explorer**

Click on the cog menu on the right hand side of the browser and then select F12 Developer Tools.

#### **Element Inspector Developer Tool** <a href="#lm5v4o9sp78y" id="lm5v4o9sp78y"></a>

* Page source does not always represent what's shown on a webpage.  CSS, JavaScript and user interaction can change the content and style of the page.
* Element inspector provides a live representation of what has been displayed in the browser window.
* Page elements can also be edited and interacted with, which is helpful for web developers to debug issues.

1. Click into the news section of the fake website.
2. An item has been blocked with a floating notice above the content stating only premium customers may view the article.  These floating boxes are often referred to as paywalls as they put up a metaphorical wall in front of the content until the user pays.
3. Right-click on the premium notice (paywall) to select the Inspect option from the menu to open the developer tools either on the bottom or right-hand side depending on your browser or preferences.
4. The elements/HTML that make up the website are now displayed.
5. Locate the DIV element with the class `premium-customer-blocker` and click on it.
6. All the CSS styles in the styles box are displayed that apply to this element.
7. The style of interest is the `display: block`.
8. Click on the word block to enter a new value.
9. Type `none` to make the box disappear and reveal the content underneath it.
10. If the element did not have a display field, clicking below the last style and adding in `display: none` would accomplish the same result.

#### **Debugger Developer Tool** <a href="#id-7crvjyrcm07x" id="id-7crvjyrcm07x"></a>

* Intended for debugging JavaScript.
* Excellent feature for web developers trying to work out why something might not be working.
* Gives penetration testers the option of digging deep into the JavaScript code.
* Debugger is called Sources in Google Chrome.

1. Click into the contact page on the fake website.
2. A rapid flash of red is seen on the screen each time the page is loaded.
3. The Debugger will be used to work out what this red flash is and if it contains anything interesting.  Debugging a red dot wouldn't be something that would be done in the real world as a penetration tester, but it does allow familiarisation with the Debugger.
4. In both browsers, on the left-hand side there is a list of all the resources the current webpage is using.
5. Click into the assets folder to display flash.min.js.
6. Clicking on the file displays the contents of the JavaScript file.
   * Many times when viewing javascript files everything is on one line because it has been minimised, which means all formatting (tabs, spacing and newlines) have been removed to make the file smaller.
   * flash.min.js is no exception to this, and it has also been obfusticated, which makes it purposely difficult to read, so it can't be copied as easily by other developers.
   * Some of the formatting can be returned by using the "Pretty Print" option, which looks like two braces { } to make it a little more readable.
   * Due to the obfustication, it's still difficult to comprehend what is going on with the flash.min.js file.
7. Scroll to the bottom of the file to see the `flash['remove']();` line.
8. This bit of JavaScript is what is removing the red popup from the page.

* Another feature of debugger is called breakpoints and can be utilised.
  * These are points in the code that can force the browser to stop processing the JavaScript and pause the current execution.

1. Click the line number that contains the `flash['remove']();` code and notice it turns blue.
2. This has inserted a breakpoint on the line.

#### **Network Developer Tool** <a href="#f7e8uh4m7mqm" id="f7e8uh4m7mqm"></a>

* Used to keep track of every external request a webpage makes.
* Click on the Network tab and refresh the page to see all the files the page is requesting.
* Press the trash can icon to delete the list if it gets a bit overpopulated.

1. With the network tab open, fill in the contact form of the fake IT Support website and press the Send Message button.
2. An event appears in the network tab.
3. This is the form being submitted in the background using a method called AJAX.  AJAX is a method for sending and receiving network data in a web application background without interfering by changing the current web page.
