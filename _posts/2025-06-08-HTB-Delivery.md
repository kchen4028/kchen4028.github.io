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

