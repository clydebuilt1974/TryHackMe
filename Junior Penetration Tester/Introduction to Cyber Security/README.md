# What is Offensive Security?
* Breaking into computer systems, exploiting software bugs, and finding loopholes in applications to gain unauthorised access to them.
** To beat a hacker, need to behave like a hacker; finding vulnerabilities and recommending patches before a cybercriminal does.
## Hack your first machine
* Brute-force a fake bank website using **GoBuster** to find hidden directories and pages. 
  * GoBuster takes a wordlist of potential page or directory names.
  * Brute forces the website with the wordlist.
  * Returns if a page exists.
### 1. Open a Terminal
### 2. Find hidden website pages
* Scan the website using GoBuster with a wordlist and display all pages that exist on the site: 

`gobuster -u http://fakebank.com -w wordlist.txt dir`

* -u states the website to scan
*  -w takes a wordlist to iterate through to find hidden pages.
* GoBuster advises the pages it found in the list of page/directory names indicated by Status: 200:
