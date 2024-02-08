# Introduction
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
      * msfvenom, pattern_create and pattern_offset.

## Main Components
* Metasploit console is main interface to interact with modules.
  * Launch it using the `msfconsole` command.
* Modules are components built to perform a specific task.
  * Exploiting a vulnerability, scanning a target, or performing a brute-force attack.
* **Exploit**: piece of code that uses a vulnerability present on the target system.
* **Vulnerability**: design, coding, or logic flaw affecting the target system.
    * Exploitation of a vulnerability can result in disclosing confidential information or allowing the attacker to execute code on the target system.
* **Payload**: an exploit will take advantage of a vulnerability.
    * Payloads are the code that will run on the target system to exploit a vulnerabilitiy.

### Auxiliary
* Spporting modules.
  * Scanners, crawlers and fuzzers.
```
root@ip-10-10-135-188:/opt/metasploit-framework/embedded/framework/modules# tree -L 1 auxiliary/
auxiliary/
├── admin
├── analyze
├── bnat
├── client
├── cloud
├── crawler
├── docx
├── dos
├── example.py
├── example.rb
├── fileformat
├── fuzzers
├── gather
├── parser
├── pdf
├── scanner
├── server
├── sniffer
├── spoof
├── sqli
├── voip
└── vsploit

20 directories, 2 files
```   

### Encoders
* Allow encoding of the exploit and payload to try and bypass signature-based antivirus solutions.
  * Signature-based antivirus and security solutions have a database of known threats.
    * They detect threats by comparing suspicious files to this database and raise an alert if there is a match.
* Encoders can have a limited success rate as antivirus solutions can perform additional checks.
```
root@ip-10-10-135-188:/opt/metasploit-framework/embedded/framework/modules# tree -L 1 encoders/
encoders/
├── cmd
├── generic
├── mipsbe
├── mipsle
├── php
├── ppc
├── ruby
├── sparc
├── x64
└── x86

10 directories, 0 files  
```

# Evasion
* Try direct attempts to evade antivirus software.
```
root@ip-10-10-135-188:/opt/metasploit-framework/embedded/framework/modules# tree -L 2 evasion/
evasion/
└── windows
    ├── applocker_evasion_install_util.rb
    ├── applocker_evasion_msbuild.rb
    ├── applocker_evasion_presentationhost.rb
    ├── applocker_evasion_regasm_regsvcs.rb
    ├── applocker_evasion_workflow_compiler.rb
    ├── process_herpaderping.rb
    ├── syscall_inject.rb
    ├── windows_defender_exe.rb
    └── windows_defender_js_hta.rb

1 directory, 9 files
```

### Exploits
```
root@ip-10-10-135-188:/opt/metasploit-framework/embedded/framework/modules# tree -L 1 exploits/
exploits/
├── aix
├── android
├── apple_ios
├── bsd
├── bsdi
├── dialup
├── example_linux_priv_esc.rb
├── example.py
├── example.rb
├── example_webapp.rb
├── firefox
├── freebsd
├── hpux
├── irix
├── linux
├── mainframe
├── multi
├── netware
├── openbsd
├── osx
├── qnx
├── solaris
├── unix
└── windows

20 directories, 4 files
```
### NOPs
* NOPs (No OPeration) do nothing.
* They are represented in the Intel x86 CPU family.
  * Represented with 0x90, following which the CPU will do nothing for one cycle.
* Often used as a buffer to achieve consistent payload sizes.
```
root@ip-10-10-135-188:/opt/metasploit-framework/embedded/framework/modules# tree -L 1 nops/
nops/
├── aarch64
├── armle
├── cmd
├── mipsbe
├── php
├── ppc
├── sparc
├── tty
├── x64
└── x86

10 directories, 0 files 
```
### Payloads
* Code that will run on the target system.
  * Leverages a vulnerability on the target system.
  * Getting a shell, loading a malware or backdoor to the target system, running a command, or launching calc.exe as a proof of concept to add to the penetration test report.
* Running commands on the target system is already an important step.
* Having an interactive connection that allows commands to be typed that will be executed on the target system is better.
  * These are called 'shells'.
* Metasploit offers the ability to send different payloads that can open shells on the target system.
```
root@ip-10-10-135-188:/opt/metasploit-framework/embedded/framework/modules# tree -L 1 payloads/
payloads/
├── adapters
├── singles
├── stagers
└── stages

4 directories, 0 files   
```
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
* Inline (or single) payload as indicated by the `_` between 'shell' and 'reverse'.
```
generic/shell_reverse_tcp
```
* Staged payload as indicated by the `/` between 'shell' and 'reverse'.
```
windows/x64/shell/reverse_tcp
```

### Post
* Useful on the final stage (post-exploitation) of the penetration testing process.
```
root@ip-10-10-135-188:/opt/metasploit-framework/embedded/framework/modules# tree -L 1 post/
post/
├── aix
├── android
├── apple_ios
├── bsd
├── firefox
├── hardware
├── linux
├── multi
├── networking
├── osx
├── solaris
└── windows

12 directories, 0 files
```

## Msfconsole
* Main interface to the Metasploit Framework.
* Launch it using the `msfconsole` command on any system the Metasploit Framework is installed on.
* Command line will change to `msf6`.
* Metasploit console (msfconsole) can be used like a regular command-line shell.
  * The first command is `ls` which lists the contents of the folder from which Metasploit was launched using the msfconsole command.
  * Followed by a ping sent to Google's DNS IP address (8.8.8.8).
    * Had to add the `-c 1` option so only a single ping was sent as OS is Linux.
    * Ping process would otherwise continue until stopped using `CTRL+C`.
```
msf6 > ls
[*] exec: ls

burpsuite_community_linux_v2021_8_1.sh	Instructions  Scripts
Desktop		Pictures      thinclient_drives
Downloads		Postman       Tools
msf6 > ping -c 1 8.8.8.8
[*] exec: ping -c 1 8.8.8.8

PING 8.8.8.8 (8.8.8.8) 56(84) bytes of data.
64 bytes from 8.8.8.8: icmp_seq=1 ttl=109 time=1.33 ms

--- 8.8.8.8 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 1.335/1.335/1.335/0.000 ms
msf6 >
```
* Msfconsole supports most Linux commands, including clear (to clear the terminal screen).
* Will not allow some features of a regular command line to be used (e.g. does not support output redirection).
```
msf6 > help > help.txt
[-] No such command
msf6 >
```
* `Help` command can be used on its own or for a specific command.
```
msf6 > help set
Usage: set [option] [value]
```
* Set the given option to value.
* If value is omitted, print the current value.
* If both are omitted, print options that are currently set.
* If run from a module context, this will set the value in the module's datastore.
* Use -g to operate on the global datastore.
* If setting a PAYLOAD, this command can take an index from `show payloads'.
```
msf6 >
```
* Use the `history` command to see commands typed earlier.
```
msf6 > history
1  use exploit/multi/http/nostromo_code_exec
2  set lhost 10.10.16.17
3  set rport 80
4  options
5  set rhosts 10.10.29.187
6  run
7  exit
8  exit -y
9  version
10  use exploit/multi/script/web_delivery
```
* Important feature of msfconsole is the support of tab completion.
  * Start typing `he` and press the tab key and it auto-completes to `help`.
* Msfconsole is managed by context.
  * All parameter settings will be lost if the module is changed unless set as a global variable.

* Once you type the use exploit/windows/smb/ms17_010_eternalblue command, you will see the command line prompt change from msf6 to “msf6 exploit(windows/smb/ms17_010_eternalblue)”.
> 'EternalBlue' is an exploit allegedly developed by the U.S. National Security Agency (N.S.A.) for a vulnerability affecting the SMBv1 server on numerous Windows systems. The SMB (Server Message Block) is widely used in Windows networks for file sharing and even for sending files to printers. EternalBlue was leaked by the cybercriminal group "Shadow Brokers" in April 2017. In May 2017, this vulnerability was exploited worldwide in the WannaCry ransomware attack.
```
msf6 > use exploit/windows/smb/ms17_010_eternalblue 
[*] No payload configured, defaulting to windows/x64/meterpreter/reverse_tcp
msf6 exploit(windows/smb/ms17_010_eternalblue) >       
```
* Module to be used can also be selected with the `use` command followed by the number at the beginning of the search result line.
* Can still run the commands previously mentioned while the prompt has changed.
  * Did not 'enter' a folder as would be typically expected in an OS command line.
```
msf6 exploit(windows/smb/ms17_010_eternalblue) > ls
[*] exec: ls

burpsuite_community_linux_v2021_8_1.sh	Instructions  Scripts
Desktop	Pictures      thinclient_drives
Downloads	Postman       Tools
msf6 exploit(windows/smb/ms17_010_eternalblue) >
```
* Prompt now advises that a context is set in which to work.
  * Verify this by typing the `show options` command.
  * This will print options related to the chosen exploit.
  * Can be used in any context followed by a module type (auxiliary, payload, exploit, etc.) to list available modules. 
    * Will list all modules if used from the msfconsole prompt.
* Leave the context using the `back` command.
```
msf6 exploit(windows/smb/ms17_010_eternalblue) > back
msf6 > 
```
* Further information on any module can be obtained by typing the `info` command.
* Can use `info` command followed by module’s path from the msfconsole prompt.
  * `info exploit/windows/smb/ms17_010_eternalblue)`.
* `Info` is not a help menu but will display detailed information on the module such as its author, relevant sources, etc.

## Search
* One of the most useful commands in msfconsole is search.
* This command will search the Metasploit Framework database for modules relevant to the given search parameter.
* You can conduct searches using CVE numbers, exploit names (eternalblue, heartbleed, etc.), or target system.
* The output of the search command provides an overview of each returned module.
* You may notice the “name” column already gives more information than just the module name.
* You can see the type of module (auxiliary, exploit, etc.) and the category of the module (scanner, admin, windows, Unix, etc.).
* You can use any module returned in a search result with the command use followed by the number at the beginning of the result line. (e.g. use 0 instead of use auxiliary/admin/smb/ms17_010_command)
* Another essential piece of information returned is in the “rank” column.
* Exploits are rated based on their reliability. The table below provides their respective descriptions.
* Source: https://github.com/rapid7/metasploit-framework/wiki/Exploit-Ranking
* You can direct the search function using keywords such as type and platform.
* For example, if we wanted our search results to only include auxiliary modules, we could set the type to auxiliary.
* The screenshot below shows the output of the search type:auxiliary telnet command.
* Please remember that exploits take advantage of a vulnerability on the target system and may always show unexpected behaviour.
* A low-ranking exploit may work perfectly, and an excellent ranked exploit may not, or worse, crash the target system.

## Working with modules
* Any Metasploit version 5 or 6 will have menus and screens similar to those shown here so you can use the AttackBox or any operating system installed on your local computer.
Once you have entered the context of a module using the use command followed by the module name, you will need to set parameters. The most common parameters you will use are listed below. Remember, based on the module you use, additional or different parameters may need to be set. It is good practice to use the show options command to list the required parameters.
All parameters are set using the same command syntax:
set PARAMETER_NAME VALUE
Before we proceed, remember to always check the msfconsole prompt to ensure you are in the right context. When dealing with Metasploit, you may see five different prompts:
The regular command prompt: You can not use Metasploit commands here.
root@ip-10-10-XX-XX:~#
The msfconsole prompt: msf6 (or msf5 depending on your installed version) is the msfconsole prompt. As you can see, no context is set here, so context-specific commands to set parameters and run modules can not be used here.
msf6 >
A context prompt: Once you have decided to use a module and used the set command to chose it, the msfconsole will show the context. You can use context-specific commands (e.g. set RHOSTS 10.10.x.x) here.
msf6 exploit(windows/smb/ms17_010_eternalblue) >
The Meterpreter prompt: Meterpreter is an important payload we will see in detail later in this module. This means a Meterpreter agent was loaded to the target system and connected back to you. You can use Meterpreter specific commands here.
meterpreter >
A shell on the target system: Once the exploit is completed, you may have access to a command shell on the target system. This is a regular command line, and all commands typed here run on the target system.
C:\Windows\system32>

As mentioned earlier, the show options command will list all available parameters.

       
As you can see in the screenshot above, some of these parameters require a value for the exploit to work. Some required parameter values will be pre-populated, make sure you check if these should remain the same for your target. For example, a web exploit could have an RPORT (remote port: the port on the target system Metasploit will try to connect to and run the exploit) value preset to 80, but your target web application could be using port 8080.
In this example, we will set the RHOSTS parameter to the IP address of our target system using the set command.


Once you have set a parameter, you can use the show options command to check the value was set correctly.

Parameters you will often use are:

RHOSTS: “Remote host”, the IP address of the target system. A single IP address or a network range can be set. This will support the CIDR (Classless Inter-Domain Routing) notation (/24, /16, etc.) or a network range (10.10.10.x – 10.10.10.y). You can also use a file where targets are listed, one target per line using file:/path/of/the/target_file.txt, as you can see below.


RPORT: “Remote port”, the port on the target system the vulnerable application is running on.
PAYLOAD: The payload you will use with the exploit.
LHOST: “Localhost”, the attacking machine (your AttackBox or Kali Linux) IP address.
LPORT: “Local port”, the port you will use for the reverse shell to connect back to. This is a port on your attacking machine, and you can set it to any port not used by any other application.
SESSION: Each connection established to the target system using Metasploit will have a session ID. You will use this with post-exploitation modules that will connect to the target system using an existing connection.

You can override any set parameter using the set command again with a different value. You can also clear any parameter value using the unset command or clear all set parameters with the unset all command.


       
You can use the setg command to set values that will be used for all modules. The setg command is used like the set command. The difference is that if you use the set command to set a value using a module and you switch to another module, you will need to set the value again. The setg command allows you to set the value so it can be used by default across different modules. You can clear any value set with setg using unsetg.
The example below uses the following flow;
We use the ms17_010_eternalblue exploitable
We set the RHOSTS variable using the setg command instead of the set command
We use the back command to leave the exploit context
We use an auxiliary (this module is a scanner to discover MS17-010 vulnerabilities)
The show options command shows the RHOSTS parameter is already populated with the IP address of the target system.

       
The setg command sets a global value that will be used until you exit Metasploit or clear it using the unsetg command.

## Using modules
Once all module parameters are set, you can launch the module using the exploit command. Metasploit also supports the run command, which is an alias created for the exploit command as the word exploit did not make sense when using modules that were not exploits (port scanners, vulnerability scanners, etc.).

The exploit command can be used without any parameters or using the “-z” parameter.
The exploit -z command will run the exploit and background the session as soon as it opens.

       
This will return you the context prompt from which you have run the exploit.
Some modules support the check option. This will check if the target system is vulnerable without exploiting it.

## Sessions
Once a vulnerability has been successfully exploited, a session will be created. This is the communication channel established between the target system and Metasploit.
You can use the background command to background the session prompt and go back to the msfconsole prompt.
```
meterpreter > background
[*] Backgrounding session 2...
msf6 exploit(windows/smb/ms17_010_eternalblue) > 
```      
Alternatively, CTRL+Z can be used to background sessions.
The sessions command can be used from the msfconsole prompt or any context to see the existing sessions.
To interact with any session, you can use the sessions -i command followed by the desired session number.
