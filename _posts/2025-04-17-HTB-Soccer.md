---
title: Hack The Box - CTF Lab - Soccer - Easy
date: 2025-04-12 00:00:01 +0800
image: /images/Soccer.png
categories: [HTB Labs]
tags: [CPTS, Easy]
---
Soccer is an easy difficulty Linux machine that features a foothold based on default credentials, forfeiting access to a vulnerable version of the "Tiny File Manager", which in turn leads to a reverse shell on the target system ("CVE-2021-45010"). Enumerating the target reveals a subdomain which is vulnerable to a blind SQL injection through websockets. Leveraging the SQLi leads to dumped "SSH" credentials for the "player" user, who can run "dstat" using "doas"- an alternative to "sudo". By creating a custom "Python" plugin for "doas", a shell as "root" is then spawned through the "SUID" bit of the "doas" binary, leading to fully escalated privileges.


