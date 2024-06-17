# Introduction to Metasploit

### **Introduction** <a href="#ojgoc2bzaa6m" id="ojgoc2bzaa6m"></a>

* Metasploit is the most widely used exploitation framework.
* Set of tools that allow information gathering, scanning, exploitation, exploit development, post-exploitation, and more.
  * Also useful for vulnerability research and exploit development.
* Two main versions.
  * **Metasploit Pro**: commercial version that facilitates the automation and management of tasks.
    * This version has a graphical user interface (GUI).
  * **Metasploit Framework**: open-source version that works from the command line.
* Main components.
  * **msfconsole**: main command-line interface.
  * **Modules**: supporting modules such as exploits, scanners, payloads, etc.
  * **Tools**: stand-alone tools that will help vulnerability research, vulnerability assessment, or penetration testing.
    * msfvenom, pattern\_create and pattern\_offset.

### **Main Components** <a href="#oq8ea72zy8o" id="oq8ea72zy8o"></a>

* Metasploit console is main interface to interact with modules.
  * Launch it using the msfconsole command.
* Modules are components built to perform a specific task.
  * Exploiting a vulnerability, scanning a target, or performing a brute-force attack.
* **Exploit**: piece of code that uses a vulnerability present on the target system.
* **Vulnerability**: design, coding, or logic flaw affecting the target system.
  * Exploitation of a vulnerability can result in disclosing confidential information or allowing the attacker to execute code on the target system.
* **Payload**: an exploit will take advantage of a vulnerability.
  * Payloads are the code that will run on the target system to exploit a vulnerability.

#### **Auxiliary** <a href="#id-4zttwss8yamp" id="id-4zttwss8yamp"></a>

* Supporting modules.
  * Scanners, crawlers and fuzzers.

#### **Encoders** <a href="#z80f6hg6ksxj" id="z80f6hg6ksxj"></a>

* Allow encoding of the exploit and payload to try and bypass signature-based antivirus solutions.
  * Signature-based antivirus and security solutions have a database of known threats.
    * They detect threats by comparing suspicious files to this database and raise an alert if there is a match.
* Encoders can have a limited success rate as antivirus solutions can perform additional checks.

### Evasion <a href="#ab72w0fs9mh9" id="ab72w0fs9mh9"></a>

* Try direct attempts to evade antivirus software.

#### **NOPs** <a href="#cid2vs1lmcz7" id="cid2vs1lmcz7"></a>

* NOPs (No OPeration) do nothing.
* They are represented in the Intel x86 CPU family.
  * Represented with 0x90, following which the CPU will do nothing for one cycle.
* Often used as a buffer to achieve consistent payload sizes.

#### **Payloads** <a href="#fjatghkjv6jf" id="fjatghkjv6jf"></a>

* Code that will run on the target system.
  * Leverages a vulnerability on the target system.
  * Getting a shell, loading a malware or backdoor to the target system, running a command, or launching calc.exe as a proof of concept to add to the penetration test report.
* Running commands on the target system is already an important step.
* Having an interactive connection that allows commands to be typed that will be executed on the target system is better.
  * These are called 'shells'.
* Metasploit offers the ability to send different payloads that can open shells on the target system.
* Four different directories under payloads.
* **Adapters**: wrap single payloads to convert them into different formats.
  * Normal single payload can be wrapped inside a Powershell adapter, which will make a single powershell command that will execute the payload.
* **Singles**: self-contained payloads (add user, launch notepad.exe, etc.).
  * Do not need to download an additional component to run.
* **Stagers**: responsible for setting up a connection channel between Metasploit and the target system.
  * Useful when working with staged payloads.
  * 'Staged payloads' will first upload a stager on the target system then download the rest of the payload (stage).
  * This provides some advantages as the initial size of the payload will be relatively small compared to the full payload sent at once.
* **Stages**: downloaded by the stager.
  * This will allow larger sized payloads to be used.
* Metasploit has a subtle way to help identify single ('inline') payloads and staged payloads.
* Inline (or single) payload as indicated by the \_ between 'shell' and 'reverse'.

generic/shell\_reverse\_tcp

* Staged payload as indicated by the / between 'shell' and 'reverse'.

windows/x64/shell/reverse\_tcp

#### **Post** <a href="#sb89a8lw1mxz" id="sb89a8lw1mxz"></a>

* Useful on the final stage (post-exploitation) of the penetration testing process.

### **Msfconsole** <a href="#id-7c7eytefkd5r" id="id-7c7eytefkd5r"></a>

* Main interface to the Metasploit Framework.
* Launch it using the msfconsole command on any system the Metasploit Framework is installed on.
* Command line will change to msf6.
* Metasploit console (msfconsole) can be used like a regular command-line shell.
  * The first command is ls which lists the contents of the folder from which Metasploit was launched using the msfconsole command.
  * Followed by a ping sent to Google's DNS IP address (8.8.8.8).
    * Had to add the -c 1 option so only a single ping was sent as OS is Linux.
    * Ping process would otherwise continue until stopped using CTRL+C.

msf6 > ls

\[\*] exec: ls

burpsuite\_community\_linux\_v2021\_8\_1.sh Instructions Scripts

Desktop Pictures thinclient\_drives

Downloads Postman Tools

msf6 > ping -c 1 8.8.8.8

\[\*] exec: ping -c 1 8.8.8.8

PING 8.8.8.8 (8.8.8.8) 56(84) bytes of data.

64 bytes from 8.8.8.8: icmp\_seq=1 ttl=109 time=1.33 ms

\--- 8.8.8.8 ping statistics ---

1 packets transmitted, 1 received, 0% packet loss, time 0ms

rtt min/avg/max/mdev = 1.335/1.335/1.335/0.000 ms

msf6 >

* Msfconsole supports most Linux commands, including clear (to clear the terminal screen).
* Will not allow some features of a regular command line to be used (e.g. does not support output redirection).

msf6 > help > help.txt

\[-] No such command

msf6 >

* Help command can be used on its own or for a specific command.

msf6 > help set

Usage: set \[option] \[value]

* Set the given option to value.
* If value is omitted, print the current value.
* If both are omitted, print options that are currently set.
* If run from a module context, this will set the value in the module's datastore.
* Use -g to operate on the global datastore.
* If setting a PAYLOAD, this command can take an index from \`show payloads'.

msf6 >

* Use the history command to see commands typed earlier.

msf6 > history

1 use exploit/multi/http/nostromo\_code\_exec

2 set lhost 10.10.16.17

3 set rport 80

4 options

5 set rhosts 10.10.29.187

6 run

7 exit

8 exit -y

9 version

10 use exploit/multi/script/web\_delivery

* Important feature of msfconsole is the support of tab completion.
  * Start typing he and press the tab key and it auto-completes to help.
* Msfconsole is managed by context.
  * All parameter settings will be lost if the module is changed unless set as a global variable.
* Once you type the use exploit/windows/smb/ms17\_010\_eternalblue command, you will see the command line prompt change from msf6 to “msf6 exploit(windows/smb/ms17\_010\_eternalblue)”.

'EternalBlue' is an exploit allegedly developed by the U.S. National Security Agency (N.S.A.) for a vulnerability affecting the SMBv1 server on numerous Windows systems. The SMB (Server Message Block) is widely used in Windows networks for file sharing and even for sending files to printers. EternalBlue was leaked by the cybercriminal group "Shadow Brokers" in April 2017. In May 2017, this vulnerability was exploited worldwide in the WannaCry ransomware attack.

msf6 > use exploit/windows/smb/ms17\_010\_eternalblue

\[\*] No payload configured, defaulting to windows/x64/meterpreter/reverse\_tcp

msf6 exploit(windows/smb/ms17\_010\_eternalblue) >

* Module to be used can also be selected with the use command followed by the number at the beginning of the search result line.
* Can still run the commands previously mentioned while the prompt has changed.
  * Did not 'enter' a folder as would be typically expected in an OS command line.

msf6 exploit(windows/smb/ms17\_010\_eternalblue) > ls

\[\*] exec: ls

burpsuite\_community\_linux\_v2021\_8\_1.sh Instructions Scripts

Desktop Pictures thinclient\_drives

Downloads Postman Tools

msf6 exploit(windows/smb/ms17\_010\_eternalblue) >

* Prompt now advises that a context is set in which to work.
  * Verify this by typing the show options command.
  * This will print options related to the chosen exploit.
  * Can be used in any context followed by a module type (auxiliary, payload, exploit, etc.) to list available modules.
    * Will list all modules if used from the msfconsole prompt.
* Leave the context using the back command.

msf6 exploit(windows/smb/ms17\_010\_eternalblue) > back

msf6 >

* Further information on any module can be obtained by typing the info command.
* Can use info command followed by module’s path from the msfconsole prompt.
  * info exploit/windows/smb/ms17\_010\_eternalblue).
* Info is not a help menu but will display detailed information on the module such as its author, relevant sources, etc.

### **Search** <a href="#qkq75fjiazbv" id="qkq75fjiazbv"></a>

* One of the most useful commands in msfconsole.
* Searches the Metasploit Framework database for modules relevant to the given search parameter.
* Can conduct searches using CVE numbers, exploit names (eternalblue, heartbleed, etc.), or target system.
* Output of search command provides an overview of each returned module.
  * 'name' column gives more information than just the module name.
  * Type of module (auxiliary, exploit, etc.).
  * Category of the module (scanner, admin, windows, Unix, etc.).
* Use any module returned in a search result with the command use followed by the number at the beginning of the result line.
  * Use 0 instead of use auxiliary/admin/smb/ms17\_010\_command).
* 'rank' column is also contains essential information.
  * [Exploits are rated based on their reliability](https://github.com/rapid7/metasploit-framework/wiki/Exploit-Ranking).
* Can direct the search function using keywords such as type and platform.
  * Set type to auxiliary to only include auxiliary modules.
* Exploits take advantage of a vulnerability on the target system and may always show unexpected behaviour.
  * Low-ranking exploit may work perfectly and an excellent ranked exploit may crash the target system.

### **Working with modules** <a href="#id-26ur4yak38at" id="id-26ur4yak38at"></a>

* Need to set parameters once module context is set.
  * Always check the msfconsole prompt to ensure the right context is set.
* Good practice to use the show options command to list the required parameters.
* All parameters are set using the same command syntax set PARAMETER\_NAME VALUE.
* **Regular command prompt**: You can not use Metasploit commands here.
  * root@ip-10-10-XX-XX:\~#
* **msfconsole prompt**: msf6 (or msf5 depending on your installed version) is the msfconsole prompt.
  * No context is set here, so context-specific commands to set parameters and run modules can not be used here.
  * msf6 >
* **Context prompt**: Once you have decided to use a module and used the set command to chose it, the msfconsole will show the context.
  * Use context-specific commands (e.g. set RHOSTS 10.10.x.x) here.
  * msf6 exploit(windows/smb/ms17\_010\_eternalblue) >.
* **Meterpreter prompt**: Meterpreter is an important payload.
  * Meterpreter agent was loaded to the target system and connected back.
  * Can use Meterpreter specific commands here.
  * meterpreter >
* **Shell on the target system**: May have access to a command shell on the target system once the exploit is completed.
  * This is a regular command line and all commands typed here run on the target system.
  * C:\Windows\system32>
* Some required parameter values will be pre-populated.
  * Make sure you check if these should remain the same for the target.
    * Web exploit could have an RPORT (remote port: the port on the target system Metasploit will try to connect to and run the exploit) value preset to 80 but the target web application could be using port 8080.
* Can use the show options command to check a value was set correctly.
* **RHOSTS**: 'Remote host'.
  * IP address of the target system.
  * Single IP address or a network range can be set.
  * Supports the CIDR (Classless Inter-Domain Routing) notation (/24, /16, etc.) or a network range (10.10.10.x – 10.10.10.y).
  * Can also use a file where targets are listed using file:/path/of/the/target\_file.txt.
* **RPORT**: 'Remote port'.
  * Port on the target system the vulnerable application is running on.
* **PAYLOAD**: The payload to use with the exploit.
* **LHOST**: 'Localhost'.
  * The attacking machine IP address.
* **LPORT**: 'Local port'.
  * Port used for the reverse shell to connect back to.
  * This is a port on the attacking machine and can be set to any port not used by any other application.
* **SESSION**: Each connection established to the target system using Metasploit will have a session ID.
  * Use this with post-exploitation modules that will connect to the target system using an existing connection.
* Override any set parameter using the set command again with a different value.
* Clear any parameter value using the unset command or clear all set parameters using unset all.
* Use the setg command to set values that will be used for all modules.
  * Sets the value so it can be used by default across different modules.
  * Clear any value set using unsetg.

1. Use the ms17\_010\_eternalblue exploitable.
2. Set RHOSTS variable using the setg command instead of the set command.
3. Use the back command to leave the exploit context.
4. Use an auxiliary.
   * This module is a scanner to discover MS17-010 vulnerabilities.
5. show options command shows the RHOSTS parameter is already populated with the IP address of the target system.

### **Using modules** <a href="#n7y1v8gng8fb" id="n7y1v8gng8fb"></a>

* Launch the module using the exploit command.
  * Also supports the run command.
    * Alias created for the exploit command as the word exploit did not make sense when using modules that were not exploits (port scanners, vulnerability scanners, etc.).
* Can be used without any parameters or using the -z parameter.
  * exploit -z will run the exploit and background the session as soon as it opens.
  * This will return to the context prompt from which the exploit was run.
* Some modules support the check option.
  * Check if the target system is vulnerable without exploiting it.

### **Sessions** <a href="#wvc0vzwan7hh" id="wvc0vzwan7hh"></a>

* Session will be created once a vulnerability has been successfully exploited.
  * Communication channel established between the target system and Metasploit.
* Use the background command to background the session prompt and go back to the msfconsole prompt.
  * CTRL+Z can also be used to background sessions.

meterpreter > background

\[\*] Backgrounding session 2...

msf6 exploit(windows/smb/ms17\_010\_eternalblue) >

* Can be used from the msfconsole prompt or any context to see the existing sessions.
* Use sessions -i command followed by the desired session number to interact with any session.
