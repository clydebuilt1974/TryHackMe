# Introduction to Cyber Security

### **What is Offensive Security?** <a href="#d2fr82hlpmo" id="d2fr82hlpmo"></a>

* Breaking into computer systems.
* Exploiting software bugs.
* Finding loopholes in applications to gain unauthorised access to them.
* Must behave like a hacker to beat a hacker.
  * Find vulnerabilities before a cybercriminal does.

### **Hack a test website with GoBuster** <a href="#id-8avn5z1incgg" id="id-8avn5z1incgg"></a>

* Brute-force a website using **GoBuster** to find hidden directories and pages.
  * GoBuster takes a wordlist of potential page or directory names.
    * Brute forces the website with the wordlist.
    * Displays status of 200 for all pages/directories found.

1. Open a Terminal.
2. Find hidden website pages.
   * Scan using gobuster -u http://fakebank.com -w wordlist.txt dir
     * \-u states website to scan.
     * \-w takes wordlist to iterate through to find hidden pages.
3. Exploit the website
   * Secret /bank-transfer page found by GoBuster.
     * Critical risk for the bank as this allows an attacker to steal money from any bank account.
   * An ethical hacker would (with permission) find vulnerabilities in the banking application and report them to the bank to fix before a hacker exploits them.

### **Careers in Cyber Security** <a href="#id-7cnym4u7kf8r" id="id-7cnym4u7kf8r"></a>

### **How to start learning?** <a href="#p4pqmbfz1u2p" id="p4pqmbfz1u2p"></a>

* Break it down, learn an area of cyber security of interest, and regularly practise using hands-on exercises.
* Build a habit of learning a little bit each day to acquire the knowledge to get a first job in the industry.

### **What careers are there?** <a href="#qkeifar4o524" id="qkeifar4o524"></a>

* **Penetration Tester** tests technology products to find exploitable security vulnerabilities.
* **Red Teamer** plays the role of an adversary, attacking an organisation and providing feedback from an enemy's perspective.
