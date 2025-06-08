---
title: Hack The Box - CTF Lab - Delivery - Easy
date: 2025-06-09 00:00:01 +0800
image: /images/thumbnails/delivery.png
categories: [HTB Labs]
tags: [CPTS, Easy]
---
Delivery is an easy difficulty Linux machine that features the support ticketing system osTicket where it is possible by using a technique called TicketTrick, a non-authenticated user to be granted with access to a temporary company email. This "feature" permits the registration at MatterMost and the join of internal team channel. It is revealed through that channel that users have been using same password variant "PleaseSubscribe!" for internal access. In channel it is also disclosed the credentials for the mail user which can give the initial foothold to the system. While enumerating the file system we come across the mattermost configuration file which reveals MySQL database credentials. By having access to the database a password hash can be extracted from Users table and crack it using the "PleaseSubscribe!" pattern. After cracking the hash it is possible to login as user root.

First a full nmap scan:
```
sudo nmap -sC -sV -p- 10.10.10.222

Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-06-08 15:25 EDT
Nmap scan report for 10.10.10.222
Host is up (0.026s latency).
Not shown: 65532 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 9c:40:fa:85:9b:01:ac:ac:0e:bc:0c:19:51:8a:ee:27 (RSA)
|   256 5a:0c:c0:3b:9b:76:55:2e:6e:c4:f4:b9:5d:76:17:09 (ECDSA)
|_  256 b7:9d:f7:48:9d:a2:f2:76:30:fd:42:d3:35:3a:80:8c (ED25519)
80/tcp   open  http    nginx 1.14.2
|_http-title: Welcome
|_http-server-header: nginx/1.14.2
8065/tcp open  unknown
| fingerprint-strings: 
|   GenericLines, Help, RTSPRequest, SSLSessionReq, TerminalServerCookie: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest: 
|     HTTP/1.0 200 OK
|     Accept-Ranges: bytes
|     Cache-Control: no-cache, max-age=31556926, public
|     Content-Length: 3108
|     Content-Security-Policy: frame-ancestors 'self'; script-src 'self' cdn.rudderlabs.com
|     Content-Type: text/html; charset=utf-8
|     Last-Modified: Sun, 08 Jun 2025 19:11:21 GMT
|     X-Frame-Options: SAMEORIGIN
|     X-Request-Id: gqj4byf7ztbnur67ksakjubt6o
|     X-Version-Id: 5.30.0.5.30.1.57fb31b889bf81d99d8af8176d4bbaaa.false
|     Date: Sun, 08 Jun 2025 19:25:37 GMT
|     <!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1,user-scalable=0"><meta name="robots" content="noindex, nofollow"><meta name="referrer" content="no-referrer"><title>Mattermost</title><meta name="mobile-web-app-capable" content="yes"><meta name="application-name" content="Mattermost"><meta name="format-detection" content="telephone=no"><link re
|   HTTPOptions: 
|     HTTP/1.0 405 Method Not Allowed
|     Date: Sun, 08 Jun 2025 19:25:37 GMT
|_    Content-Length: 0
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
Since there is a port 80, we find a webpage at 10.10.10.222. We see on the webpage that there is a link to the domain name "helpdesk.delivery.htb," which gives us two domain names to add to our /etc/hosts file:
```
10.10.10.222 helpdesk.delivery.htb delivery.htb
```
