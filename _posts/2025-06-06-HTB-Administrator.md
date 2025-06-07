---
title: Hack The Box - CTF Lab - Administrator - Medium
date: 2025-06-07 00:00:01 +0800
image: /images/thumbnails/Administrator.jpg
categories: [HTB Labs]
tags: [CPTS, Medium]
---
Administrator is a medium-difficulty Windows machine designed around a complete domain compromise scenario, where credentials for a low-privileged user are provided. To gain access to the michael account, ACLs (Access Control Lists) over privileged objects are enumerated, leading us to discover that the user olivia has GenericAll permissions over michael, allowing us to reset his password. With access as michael, it is revealed that he can force a password change on the user benjamin, whose password is reset. This grants access to FTP where a backup.psafe3 file is discovered, cracked, and reveals credentials for several users. These credentials are sprayed across the domain, revealing valid credentials for the user emily. Further enumeration shows that emily has GenericWrite permissions over the user ethan, allowing us to perform a targeted Kerberoasting attack. The recovered hash is cracked and reveals valid credentials for ethan, who is found to have DCSync rights ultimately allowing retrieval of the Administrator account hash and full domain compromise.

" As is common in real life Windows pentests, you will start the Administrator box with credentials for the following account: Username: Olivia Password: ichliebedich "

First we do a full nmap scan:
```
sudo nmap -sC -sV -p- 10.10.11.42

Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-06-06 19:54 EDT
Nmap scan report for 10.10.11.42
Host is up (0.031s latency).
Not shown: 65509 closed tcp ports (reset)
PORT      STATE SERVICE       VERSION
21/tcp    open  ftp           Microsoft ftpd
| ftp-syst: 
|_  SYST: Windows_NT
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-06-07 06:54:56Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: administrator.htb0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: administrator.htb0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
49671/tcp open  msrpc         Microsoft Windows RPC
57554/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
57559/tcp open  msrpc         Microsoft Windows RPC
57570/tcp open  msrpc         Microsoft Windows RPC
57581/tcp open  msrpc         Microsoft Windows RPC
57617/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2025-06-07T06:55:51
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
|_clock-skew: 6h59m59s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 99.39 seconds
```
We notice the presence of an ftp server on port 21. 

We try to connect to it with the provided user credentials:
```
ftp Olivia@10.10.11.42
Connected to 10.10.11.42.
220 Microsoft FTP Service
331 Password required
Password: 
530 User cannot log in, home directory inaccessible.
ftp: Login failed
ftp> 
```
but the user Olivia is either restricted or does not have an ftp directory.

From the credentials we were given (Olivia:ichliebedich), let's test if this is a local computer account or a domain user account by using ldapsearch:
```
ldapsearch -x -H ldap://10.10.11.42 -D "ADMINISTRATOR\Olivia" -w ichliebedich -b "DC=administrator,DC=htb0" -s sub "(objectClass=*)"
# extended LDIF
#
# LDAPv3
# base <DC=administrator,DC=htb0> with scope subtree
# filter: (objectClass=*)
# requesting: ALL
#

# search result
search: 2
result: 10 Referral
text: 0000202B: RefErr: DSID-0310084B, data 0, 1 access points
	ref 1: 'adminis
 trator.htb0'

ref: ldap://administrator.htb0/DC=administrator,DC=htb0

# numResponses: 1
```
and by using the NETBIOS format we see that there is an entry on the domain controller.

Now that we have confirmed these are domain user credentials, we can use bloodhound.py to ingest the LDAP data from the domain controller. Normally we would use Sharphound.exe, but that would require access to a Windows host which we don't have. Bloodhound.py only requires domain credentials:
```
pipx install bloodhound-ce

bloodhound-ce-python -u Olivia -p ichliebedich -d administrator.htb -c All -ns 10.10.11.42 -dc administrator.htb
INFO: BloodHound.py for BloodHound Community Edition
INFO: Found AD domain: administrator.htb
INFO: Getting TGT for user
WARNING: Failed to get Kerberos TGT. Falling back to NTLM authentication. Error: [Errno Connection error (administrator.htb:88)] [Errno -2] Name or service not known
INFO: Connecting to LDAP server: administrator.htb
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: administrator.htb
INFO: Found 11 users
INFO: Found 53 groups
INFO: Found 2 gpos
INFO: Found 1 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: dc.administrator.htb
INFO: Done in 00M 05S
```
Then we can use our bloodhound installation (installation guide at https://bloodhound.specterops.io/get-started/quickstart/community-edition-quickstart) and import all of these files generated by the bloodhound-ce-python collector.

After everything is imported, we can go ahead and find all the attributes of our user Olivia in Bloodhound.

In pathfinding, we see that Olivia has GenericAll permissions to a user called Michael:
![image tooltip](images\screenshots\Screenshot%202025-06-07%20135530.png)














