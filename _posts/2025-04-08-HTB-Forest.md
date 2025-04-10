---
title: Hack The Box - CTF Lab - Forest
date: 2025-04-08 00:00:01 +0800
image: /images/HackTheBoxForest.jpg
categories: [HTB Labs]
tags: [CPTS]
---
This is the first HackTheBox CTF lab in the famous Ippsec's unofficial CPTS preparation playlist. I will attempt to blog all 20 boxes in the playlist; this is the first of 20 boxes. 

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
I first tried seeing if I could access any websites with the ip on my browser on all of the HTTP ports but that did not give me anything. 

I then tried enumerating for possible subdomains:
```
ffuf -w SecLists/Discovery/DNS/namelist.txt:FUZZ -u http://10.10.10.161/ -H "Host:FUZZ.htb.local"
```
but got nothing.

I see that the SMB service is open on the domain controller. I try using smbclient to authenticate as a null user:
```
smbclient -N -L //10.10.10.161
Anonymous login successful

	Sharename       Type      Comment
	---------       ----      -------
SMB1 disabled -- no workgroup available
```
I get a successful anonymous login but no connection since SMB1 is disabled for security reasons. 

I try using crackmapexec to enumerate shares but I got a permission error. I did get the Windows Server version though:
```
crackmapexec smb 10.10.10.161 --shares -u '' -p ''
Windows Server 2016 Standard 14393 x64
Error enumerating shares: STATUS_ACCESS_DENIED
```

I try rpcclient:
```
rpcclient -U "" 10.10.10.161
Password for [WORKGROUP\]:
Cannot connect to server.  Error was NT_STATUS_LOGON_FAILURE
```

I try samrdump.py and get a list of accounts on the DC, as well as knowledge that it is using Microsoft Exchange. I save the output for future reference using the following command:
```
samrdump.py 10.10.10.161 > samrdump_output.txt
```
I try smbmap but it throws an error.

I try enum4linux, had to set it up in a virtual environment, and got a lot of potentially useful output:
```
|    Policies via RPC for 10.10.10.161    |
 =========================================
[*] Trying port 445/tcp
[+] Found policy:
Domain password information:
  Password history length: 24
  Minimum password length: 7
  Maximum password age: not set
  Password properties:
  - DOMAIN_PASSWORD_COMPLEX: false
  - DOMAIN_PASSWORD_NO_ANON_CHANGE: false
  - DOMAIN_PASSWORD_NO_CLEAR_CHANGE: false
  - DOMAIN_PASSWORD_LOCKOUT_ADMINS: false
  - DOMAIN_PASSWORD_PASSWORD_STORE_CLEARTEXT: false
  - DOMAIN_PASSWORD_REFUSE_PASSWORD_CHANGE: false
Domain lockout information:
  Lockout observation window: 30 minutes
  Lockout duration: 30 minutes
  Lockout threshold: None
Domain logoff information:
  Force logoff time: not set

|    Listener Scan on 10.10.10.161    |
 =====================================
[*] Checking LDAP
[+] LDAP is accessible on 389/tcp
[*] Checking LDAPS
[+] LDAPS is accessible on 636/tcp
[*] Checking SMB
[+] SMB is accessible on 445/tcp
[*] Checking SMB over NetBIOS
[+] SMB over NetBIOS is accessible on 139/tcp

[+] Domain: HTB
[+] Domain SID: S-1-5-21-3072663084-364016917-1341370565
[+] Membership: domain member

|    RPC Session Check on 10.10.10.161    |
 =========================================
[*] Check for null session
[+] Server allows session using username '', password ''
```
Since I see that the server allows session using username and password, I try to use smbclient again. I will try with the -smb2 tag as well as trying to enumerate the default $IPC share, which works:
```
smbclient -N -m SMB2 //10.10.10.161/IPC$
Anonymous login successful
Try "help" to get a list of possible commands.
smb>
```
The smb service does not allow us to use "ls" to list the directory unfortunately. I exit out of smbclient and try to connect with a null session using rpcclient -N instead since rpcclient would have more functionality, which works:
```
rpcclient -N -U "" 10.10.10.161
rpcclient $> 
```
but I don't get anything interesting either.

It is possible that SMB is a dead end. We will try exploiting LDAP instead since we see that LDAP is open from enum4linux:
```
[*] Checking LDAP
[+] LDAP is accessible on 389/tcp
[*] Checking LDAPS
[+] LDAPS is accessible on 636/tcp
```
We use this command:
```
ldapsearch -x -H ldap://10.10.10.161 -b "DC=htb,DC=local"
```
and we get a huge page of domain information, meaning that the domain controller is misconfigured to allow for LDAP binds. 
We can save this output to a text file and be able to pull all of the usernames from the LDAP service using ldapsearch:
```
ldapsearch -x -H ldap://10.10.10.161 -b "DC=htb,DC=local" '(objectClass=User)' sAMAccountName | grep sAMAccountName | awk '{print $2}'
```

 