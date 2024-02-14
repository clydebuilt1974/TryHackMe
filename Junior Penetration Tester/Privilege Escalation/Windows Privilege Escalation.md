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
type %userprofile%
\AppData\Roaming\Microsoft\Windows\PowerShell\PSreadline\ConsoleHost_history.txt
```
* Retrieve history using PowerShell.
```
type $ENV:userprofile
\AppData\Roaming\Microsoft\Windows\PowerShell\PSreadline\ConsoleHost_history.txt
```
## Saved Windows Credentials
* Windows allows other credentials to be used.
* List saved credentials (cannot see passwords).
```
cmdkey /list
```
* Try any "interesting" credentials using `runas`.
```
runas /savecred /user:admin cmd.exe
```
## Internet Information Services (IIS) Configuration
* Default web server on Windows.
* Configuration stored in `web.config` file.
  * This may store database passwords or configured authentication mechanisms.
* Possible `web.config` locations.
  * C:\inetpub\wwwroot\web.config
  * C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config
* Find database connection string in the file.
```
type C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config | findstr connectionString
```
## Retrieve Credentials from Software: PuTTY
* PuTTY is SSH client commonly found on Windows systems.
* Users can store sessions where proxy configurations may include cleartext authentication credentials.
* Retrieve stored proxy credentials from the registry.
```
reg query HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\Sessions\ /f "Proxy" /s
```
* Any software that stores passwords (browsers, email clients, FTP clients, SSH clients VNC software) may have methods to recover passwords saved by the user.

# Other Quick Wins


# Abusing Service Misconfigurations


# Abusing Dangerous Privileges


# Abusing Vulnerable Software


# Tools of the Trade


# Conclusion
