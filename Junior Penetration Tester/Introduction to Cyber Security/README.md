# What is Offensive Security?
* Breaking into computer systems, exploiting software bugs, and finding loopholes in applications to gain unauthorised access to them.
* To beat a hacker, need to behave like a hacker; finding vulnerabilities and recommending patches before a cybercriminal does.
## Hack a fake bank website
* Brute-force the website using **GoBuster** to find hidden directories and pages. 
  * Tool takes a wordlist of potential page or directory names.
  * Brute forces the website with the wordlist.
  * Displays status of `200` for all pages/directories found.
1. Open a Terminal.
2. Find hidden website pages.
   * Scan the website `gobuster -u http://fakebank.com -w wordlist.txt dir`
     * `-u` states website to scan.
     * `-w` takes wordlist to iterate through to find hidden pages.
3. Hack the website
   * Secret `/bank-transfer` page found by GoBuster.
   * Critical risk for the bank as this allows an attacker to steal money from any bank account.
   * An ethical hacker would (with permission) find vulnerabilities in the banking application and report them to the bank to fix before a hacker exploits them.
# Careers in Cyber Security
## How to start learning?
* Break it down, learn an area of cyber security of interest, and regularly practise using hands-on exercises. 
* Build a habit of learning a little bit each day to acquire the knowledge to get a first job in the industry.
## What careers are there?
* **Penetration Tester** tests technology products to find exploitable security vulnerabilities.
* **Red Teamer** plays the role of an adversary, attacking an organisation and providing feedback from an enemy's perspective.
