# [06 - Shocker](https://app.hackthebox.com/machines/Shocker)

  * [description](#description)
  * [walkthrough](#walkthrough)
    * [recon](#recon)
  * [flag](#flag)
![Shocker.png](Shocker.png)

## description
> 10.10.10.56

## walkthrough

### recon

```
$ nmap -sV -sC -A -Pn -p- shocker.htb
Starting Nmap 7.80 ( https://nmap.org ) at 2022-07-23 14:54 MDT
Nmap scan report for shocker.htb (10.10.10.56)
Host is up (0.058s latency).
Not shown: 65533 closed ports
PORT     STATE SERVICE VERSION
80/tcp   open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
2222/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 c4:f8:ad:e8:f8:04:77:de:cf:15:0d:63:0a:18:7e:49 (RSA)
|   256 22:8f:b1:97:bf:0f:17:08:fc:7e:2c:8f:e9:77:3a:48 (ECDSA)
|_  256 e6:ac:27:a3:b5:a9:f1:12:3c:34:a5:5d:5b:eb:3d:e9 (ED25519)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### 80

returns
> Don't bug me!

with

![bug.jpg](bug.jpg)


gobuster dir with `common.txt` found nothing except index.html
gobuster vhosts with subdomain-5000 found a few `\d` subdomains, all 400 and the same length (422)

the name definitely leans towards `ShellShock`, but we still need something other than index.html, right?

`/cgi-bin` gives us a 403, while `/cgi-bin2` gives a 404, there is something there.. what are some defaults? `index.cgi` does not exist

`CGIs.txt has ~700 matches for that and we already ran it with no results

tried `/cgi-bin/` with `bugme`, `bug`, `bug-me` flavors of `.pl` and `.cgi`






## flag
```
user:
root:
```
