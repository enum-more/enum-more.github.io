---
title: "1337UP Live - Liikt#1337"
classes: wide
tag: 
  - "ctf"
header:
  teaser: /assets/images/ctf/ctf.png
ribbon: green
description: "A walkthrough on misc challenge from 1337UP Live 2022"
categories:
  - Blog
---

Here goes the challenge description

<center>
<img src="https://raw.githubusercontent.com/AidenPearce369/AidenPearce369.github.io/main/_posts/CTF/1337UP-Live-Pics/liikt-1.png" style="width:50%">
</center>

After downloading the zip file, extracting the contents using password

Doing ```strings``` on it,

```c
┌──(kali㉿aidenpearce369)-[~/IntigritiCTF/Liikt/Kali-Linux]
└─$ cat * 2>/dev/null | grep -a "1337UP{"
flag1:<-- START 1337UP{5530491e6c0b5159
liikt:x:1001:1001:,,,:/home/liikt:/bin/bash� 1337UP{5530��
flag1:<-- START 1337UP{5530491e6c0b5159
flag1:<-- START 1337UP{5530491e6c0b5159
flag1:<-- START 1337UP{5530491e6c0b5159
flag1:<-- START 1337UP{5530491e6c0b5159
```

Seems like we have found first part of the flag

It is a memory image & virtual hardisk of VMWare images

Importing it into VMWare and started booting it, we will face the login prompt with absolutely no idea of login credentials

The only way to bypass this is to use a small trick on ```GRUB``` to spawn ```root shell```

Changing ```ro ...``` in GRUB to ```rw init=/bin/bash``` and loading it will give us a root level shell, where we can use ```passwd``` command to change password for ```root``` user

For detailed [blog](https://www.layerstack.com/resources/tutorials/Resetting-root-password-for-Linux-Cloud-Servers-by-booting-into-Single-User-Mode)

After gaining shell, we can see a user named ```liikt```

```c
┌──(root💀kali)-[~]
└─# id
uid=0(root) gid=0(root) groups=0(root),4(adm),20(dialout),119(wireshark),142(kaboxer)
                                                                                                                                                                                                                                           
┌──(root💀kali)-[~]
└─# hostname
kali
                                                                                                                                                                                                                                           
┌──(root💀kali)-[~]
└─# ls /home 
kali  liikt
```

Lets find the string ```flag1:<-- START 1337UP{5530491e6c0b5159``` with filename, which we found earlier in memory 

```c
┌──(root💀kali)-[~]
└─# grep -H -r "1337UP{" /  2>/dev/null
/etc/passwd:flag1:<-- START 1337UP{5530491e6c0b5159
^C
                                                                                                                                                                                                                                           
┌──(root💀kali)-[~]
└─# tail /etc/passwd                                                                                                                                                                                                                 
saned:x:128:135::/var/lib/saned:/usr/sbin/nologin
inetsim:x:129:137::/var/lib/inetsim:/usr/sbin/nologin
lightdm:x:130:138:Light Display Manager:/var/lib/lightdm:/bin/false
colord:x:131:139:colord colour management daemon,,,:/var/lib/colord:/usr/sbin/nologin
geoclue:x:132:140::/var/lib/geoclue:/usr/sbin/nologin
king-phisher:x:133:141::/var/lib/king-phisher:/usr/sbin/nologin
kali:x:1000:1000:Kali,,,:/home/kali:/usr/bin/zsh
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
liikt:x:1001:1001:,,,:/home/liikt:/bin/bash
flag1:<-- START 1337UP{5530491e6c0b5159
```

Now we have to find the second part of the flag

After some enumeration

```c
┌──(root💀kali)-[~]
└─# cd /home/liikt/
                                                                                                                                                                                                                                           
┌──(root💀kali)-[/home/liikt]
└─# ls
Desktop  Documents  Downloads  Music  Pictures  Public  pwned.txt  Templates  Videos
                                                                                                                                                                                                                                           
┌──(root💀kali)-[/home/liikt]
└─# cat pwned.txt  
Here lies the list of systems with poor security and what I have on them (Just so I don't forget):

0.0.0.0 (backdoor with liikytongue)
8.8.8.8 (backdoor with liikt)
127.0.0.1 (backdoor with real_root)
blacknote.ctf.intigriti.io (backdoor with blackn0te)
yeeter.thisisnotrealsite.com (data dump)
footbook.thisisnotrealsite.com(data dump)
```

Seems like we have to find some creds for backdoor/ data dump

While enumerating I saw ```MySQL``` and ```Postgres``` installed in this machine

My thought is to give a try on those

After starting ```MySQL service```,

```c
┌──(root💀kali)-[/home/liikt]
└─# mysql -u root
ERROR 2002 (HY000): Can't connect to local MySQL server through socket '/run/mysqld/mysqld.sock' (2)
                                                                                                                                                                                                                                           
┌──(root💀kali)-[/home/liikt]
└─#  sudo service mysqld start                                                                                                                                                                                                  

                                                                                                                                                                                                                                           
┌──(root💀kali)-[/home/liikt]
└─# mysql -u root             
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MariaDB connection id is 30
Server version: 10.5.12-MariaDB-1 Debian 11

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MariaDB [(none)]> 
```

Lets enumerate it further,

```c
MariaDB [(none)]> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| mysql              |
| performance_schema |
| yeeter_dump        |
+--------------------+
4 rows in set (0.000 sec)

MariaDB [(none)]> use yeeter_dump;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
MariaDB [yeeter_dump]> show tables;
+-----------------------+
| Tables_in_yeeter_dump |
+-----------------------+
| creds                 |
+-----------------------+
1 row in set (0.000 sec)

MariaDB [yeeter_dump]> select * from creds;
+----------------------------------+---------------------------------+
| email                            | password                        |
+----------------------------------+---------------------------------+
| peter@email.com                  | Lowstreet4                      |
| amy@fake.com                     | Applest652                      |
| hannah@loser.net                 | Mountain21!#13$f                |
| michael54@lousymail.com          | Valley345$fs                    |
| sandy@spongebob.com              | Oceanblvd2                      |
| betty@meme.com                   | GreenGrass1                     |
| johnhammond@youtuber.com         | PlzSubscribe!#XD                |
| followmytwitter@BlacknoteSec.com | BlacknoteSec                    |
| liikt@hacker.com                 | best_h3ckerman!69-              |
| peter_parker@avengers.com        | Sp00derm4n                      |
| thor@asgard.com                  | StrongestAvenger1               |
| pink@draconian.com               | MainRoad989                     |
| viola@email.com                  | ViolaPlaysViolin00              |
| uanikolayf@gmailya.com           | qwertyuiop                      |
| willing@mail.com                 | SF4ss4fds56                     |
| sdfdslike@mail.com               | Password01                      |
| pinkdraconian@youtuber.com       | IntigritiRockz6969_             |
| perfect@blue.com                 | dizCTF2ez!                      |
| matt_e@dev.com                   | Pwn2Ez4m3                       |
| fumenoid@dev.com                 | I4mJust4N00b                    |
| congon4tor@dev.com               | webm3up!                        |
| lorem@ipsumdolor.sit             | amet!consectetur                |
| qwerty@qwerty.com                | asdfghjkl1234                   |
| thegamer@games.com               | wtfgames!$                      |
| justemail@random.com             | fhcnawisg456                    |
| whateberafsd@asdf.com            | bjhgawf243                      |
| igiveup@mails.com                | randomasd                       |
| afdasdf.mail.com                 | kjhgfwff123                     |
| hjsadf@asd.com                   | nbxvcsduycg                     |
| sinister_matrix@coolguy.com      | jbhaf#jyavnw54                  |
| pwnfunction@youtuber.com         | hackercamp.co                   |
| optional@ctf.com                 | I4amJust4Ch4d                   |
| badboy17@byteforce.com           | h4xl33terrrrrr45                |
| streaker_rules@byteforce.com     | cryptog0d6969                   |
| lucas@byteforce.com              | lukeflima69                     |
| szymex73@ctf.com                 | justanothern00b                 |
| calebjstewart@dev.com            | UsePwnCat                       |
| ashok_b_simping@mlp.com          | IAmAcl0wn69                     |
| d0minik@mlp.com                  | polarbears4recute137            |
| smellycharlie@oldman.com         | ageisjustanumber!#$             |
| liveoverflow@youtuber.com        | isthereanyoneelsebetter?!       |
| kevinmitnick@oldschool.com       | legend                          |
| ippsec@youtube.com               | whatsgoingonyoutubethisisippsec |
| sfsd@sgsg.com                    | asdfasdfkjhg2354                |
| jhgaf@nbasaf.com                 | hbadjegf546                     |
| bjhacwg@afsjhgkwsjf.com          | ajhfskgseuf                     |
| nbmygf@sajh.com                  | bvjhhgf                         |
| postmalone@music.com             | makingApostRequest              |
| lame@lame.com                    | sadfgsf                         |
| whateven@what.com                | wgfasgb                         |
+----------------------------------+---------------------------------+
50 rows in set (0.001 sec)

MariaDB [yeeter_dump]> 
```

Seems like login creds, but for why

From the hint of ```pwned.txt``` we can see theres a legit hostname ```blacknote.ctf.intigriti.io```

Because, the CTF was hosted on ```ctf.intigriti.io```, it was merely a subdomain

Scanning this hostname with ```nmap```,

```c
┌──(root💀kali)-[/home/liikt]
└─# nmap blacknote.ctf.intigriti.io -sC -A -sV
Starting Nmap 7.92 ( https://nmap.org ) at 2022-03-12 13:13 EST
Nmap scan report for blacknote.ctf.intigriti.io (34.76.107.214)
Host is up (0.035s latency).
rDNS record for 34.76.107.214: 214.107.76.34.bc.googleusercontent.com
Not shown: 999 filtered tcp ports (no-response)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 23:7b:2b:00:c4:18:cf:a4:2e:a5:1b:19:e5:97:71:c9 (RSA)
|   256 1c:f7:37:b1:75:95:7d:3f:88:eb:47:94:c4:35:cf:56 (ECDSA)
|_  256 6f:4e:1d:84:73:d7:42:4b:e1:04:54:04:56:ae:c8:9e (ED25519)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: WAP|general purpose
Running: Actiontec embedded, Linux 2.4.X|3.X, Microsoft Windows XP|7|2012
OS CPE: cpe:/h:actiontec:mi424wr-gen3i cpe:/o:linux:linux_kernel cpe:/o:linux:linux_kernel:2.4.37 cpe:/o:linux:linux_kernel:3.2 cpe:/o:microsoft:windows_xp::sp3 cpe:/o:microsoft:windows_7 cpe:/o:microsoft:windows_server_2012
OS details: Actiontec MI424WR-GEN3I WAP, DD-WRT v24-sp2 (Linux 2.4.37), Linux 3.2, Microsoft Windows XP SP3, Microsoft Windows XP SP3 or Windows 7 or Windows Server 2012
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 80/tcp)
HOP RTT     ADDRESS
1   0.14 ms 192.168.116.2
2   0.16 ms 214.107.76.34.bc.googleusercontent.com (34.76.107.214)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 131.02 seconds
```

Seems like ```SSH``` is open

And from ```pwned.txt``` the hint says, ```backdoor with blackn0te```

Lets assume the username is ```blackn0te```

And from the dumped creds, ```liikt@hacker.com:best_h3ckerman!69-``` matches the description

While connecting with ```ssh```, it prompts for ```id_rsa``` password,

```c
┌──(root💀kali)-[~/.ssh]
└─# ssh blackn0te@blacknote.ctf.intigriti.io
Enter passphrase for key '/root/.ssh/id_rsa': 
```

Lets use john to crack it,

```c
┌──(root💀kali)-[~/.ssh]
└─# ls
hash_ssh  id_rsa  id_rsa.pub  known_hosts  known_hosts.old  pass.txt
                                                                                                                                                                                                                                           
┌──(root💀kali)-[~/.ssh]
└─# /usr/share/john/ssh2john.py id_rsa > hash_ssh

──(root💀kali)-[~/.ssh]
└─# john hash_ssh --wordlist=pass.txt   
Using default input encoding: UTF-8
Loaded 1 password hash (SSH, SSH private key [RSA/DSA/EC/OPENSSH 32/32])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 2 for all loaded hashes
Cost 2 (iteration count) is 16 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
Warning: Only 1 candidate left, minimum 4 needed for performance.
best_h3ckerman!69- (id_rsa)     
1g 0:00:00:00 DONE (2022-03-12 13:40) 2.325g/s 2.325p/s 2.325c/s 2.325C/s best_h3ckerman!69-
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

It is confirmed that the password for ```id_rsa``` is ```best_h3ckerman!69-```

Lets use SSH to gain access

```c
┌──(root💀kali)-[~/.ssh]
└─# ssh blackn0te@blacknote.ctf.intigriti.io
Enter passphrase for key '/root/.ssh/id_rsa': 
Welcome to Ubuntu 20.04.4 LTS (GNU/Linux 5.4.144+ x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

This system has been minimized by removing packages and content that are
not required on a system that users do not log into.

To restore this content, you can run the 'unminimize' command.
Last login: Sat Mar 12 18:28:34 2022 from 10.10.0.16
$ id
uid=1000(blackn0te) gid=1000(blackn0te) groups=1000(blackn0te)
$ hostname
misc-liikt1337-db9d484b9-6b7bf
$ ls
flag2.txt  notes.txt  write_anything
$ cat flag2.txt
ff82f00c4e57d0bb} --> END
$ 
```

So the final flag is ```1337UP{5530491e6c0b5159ff82f00c4e57d0bb}```

