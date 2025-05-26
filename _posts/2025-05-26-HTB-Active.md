---
title: Hack The Box - CTF Lab - Active - Easy
date: 2025-05-25 00:00:01 +0800
image: /images/thumbnails/Active.png
categories: [HTB Labs]
tags: [CPTS, Easy]
---
Active is an easy to medium difficulty machine, which features two very prevalent techniques to gain privileges within an Active Directory environment.

We of course start with a full nmap scan:
```
sudo nmap -sC -sV -p- 10.10.10.100

Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-05-26 16:18 EDT
Nmap scan report for 10.10.10.100
Host is up (0.028s latency).
Not shown: 65512 closed tcp ports (reset)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Microsoft DNS 6.1.7601 (1DB15D39) (Windows Server 2008 R2 SP1)
| dns-nsid: 
|_  bind.version: Microsoft DNS 6.1.7601 (1DB15D39)
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-05-26 20:19:18Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5722/tcp  open  msrpc         Microsoft Windows RPC
9389/tcp  open  mc-nmf        .NET Message Framing
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49152/tcp open  msrpc         Microsoft Windows RPC
49153/tcp open  msrpc         Microsoft Windows RPC
49154/tcp open  msrpc         Microsoft Windows RPC
49155/tcp open  msrpc         Microsoft Windows RPC
49157/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49158/tcp open  msrpc         Microsoft Windows RPC
49165/tcp open  msrpc         Microsoft Windows RPC
49166/tcp open  msrpc         Microsoft Windows RPC
49168/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows_server_2008:r2:sp1, cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   2:1:0: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2025-05-26T20:20:15
|_  start_date: 2025-05-26T19:55:29

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 114.87 seconds
```
From the nmap scan, we notice that the host is a Domain Controller since it is running LDAP. We also know the OS version is Windows Server 2008 and the domain is active.htb. 

Like we did in HTB-Forest, we can try using Impacket's GetNPUsers.py to see if there are any domain users who do not have Kerberos preauthentication enabled which would allow us to access their TGT/hashed password. 

```
GetNPUsers.py -dc-ip 10.10.10.100 -request 'active.htb/'

[-] Error in searchRequest -> operationsError: 000004DC: LdapErr: DSID-0C09075A, comment: In order to perform this operation a successful bind must be completed on the connection., data 0, v1db1
```
Unfortunately we see that the DC does not allow for anonymous binding.

Next, we try testing against the SMB service. 




