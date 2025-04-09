---
title: Hack The Box - CTF Lab - Forest
date: 2025-03-14 00:00:01 +0800
image: /images/HackTheBoxForest.jpg
categories: [HTB Labs]
tags: [CPTS]
---
This is the first HackTheBox CTF lab in the famous Ippsec's unofficial CPTS preparation playlist. I will attempt to blog all 20 boxes in the playlist; this is the first one of the 20 boxes. All boxes will be done in the classic Adventure Mode where no step-by-step questions/tips will be given so that we can simulate a black-box environment. Of course, if I get stuck for one or two hours and if neither my entire methodology nor ChatGPT, Grok3, ClaudeAI can solve the question I will give up and turn on the easier Guided Mode for tips. 

Upon connecting to the VPN on the HackTheBox platform, we are given an IP address of the target that is 10.10.10.161. 

I first pinged the target IP but got no response. It took me some time to figure out that HackTheBox's TCP OpenVPN was not working and had to switch to UDP OpenVPN. After that, an nmap scan went smoothly:
```
sudo nmap -sC -sV 10.10.10.161
[sudo] password for kchen: 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-04-08 21:50 EDT
Nmap scan report for 10.10.10.161
Host is up (0.028s latency).
Not shown: 960 closed tcp ports (reset), 29 filtered tcp ports (no-response)
PORT     STATE SERVICE      VERSION
53/tcp   open  domain       Simple DNS Plus
88/tcp   open  kerberos-sec Microsoft Windows Kerberos (server time: 2025-04-09 01:57:39Z)
135/tcp  open  msrpc        Microsoft Windows RPC
139/tcp  open  netbios-ssn  Microsoft Windows netbios-ssn
389/tcp  open  ldap         Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds Windows Server 2016 Standard 14393 microsoft-ds (workgroup: HTB)
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap         Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
Service Info: Host: FOREST; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: required
| smb-os-discovery: 
|   OS: Windows Server 2016 Standard 14393 (Windows Server 2016 Standard 6.3)
|   Computer name: FOREST
|   NetBIOS computer name: FOREST\x00
|   Domain name: htb.local
|   Forest name: htb.local
|   FQDN: FOREST.htb.local
|_  System time: 2025-04-08T18:57:46-07:00
| smb2-time: 
|   date: 2025-04-09T01:57:47
|_  start_date: 2025-04-08T17:08:25
|_clock-skew: mean: 2h26m49s, deviation: 4h02m31s, median: 6m47s
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required

```
