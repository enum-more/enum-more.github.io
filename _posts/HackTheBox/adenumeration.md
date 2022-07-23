---
title: "THM - Enumerating Active Directory"
classes: wide
header:
  teaser: /assets/images/htb/htb.png
ribbon: blue
description: "Writeup for THM - # Enumerating Active Directory"
categories:
  - THM
---

The given box ```Enumerating Active Directory``` is a AD machine 

- [TryHackMe- Enumerating Active Directory](#tryhackme---Enumerating-Active-Directory)
  - [Command Prompt](#command-prompt)
  - [Powershell with AD-RSAT](#powershell-with-ad-rsat)
  - [BloodHound](#bloodhound)

<center>
<img src = "https://github.com/enum-more/obsidian_vault/raw/main/thm/adenumeration/assets/attacking-ad.png" />
</center>

<center>
<img src = "https://github.com/enum-more/obsidian_vault/raw/main/thm/adenumeration/assets/network-diagram.png" />
</center>

<center>
<img src = "https://github.com/enum-more/obsidian_vault/raw/main/thm/adenumeration/assets/dns.png" />
</center>


```shell
root@rE3oN:~/enum-more/obsidian_vault/thm/adenumeration# sudo systemctl restart NetworkManager

root@rE3oN:~/enum-more/obsidian_vault/thm/adenumeration# nslookup thmdc.za.tryhackme.com
Server:         10.200.68.101
Address:        10.200.68.101#53

Name:   thmdc.za.tryhackme.com
Address: 10.200.68.101
```


<center>
<img src = "https://github.com/enum-more/obsidian_vault/raw/main/thm/adenumeration/assets/ad_creds.png" />
</center>


```shell
root@rE3oN:~/enum-more/obsidian_vault/thm/adenumeration# cat ad_credentials.txt
Username: tony.holland
Password: Mhvn2334
```

```cmd
Microsoft Windows [Version 10.0.17763.1098]
(c) 2018 Microsoft Corporation. All rights reserved.

za\tony.holland@THMJMP1 C:\Users\tony.holland>dir \\za.tryhackme.com\SYSVOL\
 Volume in drive \\za.tryhackme.com\SYSVOL is Windows
 Volume Serial Number is 1634-22A9

 Directory of \\za.tryhackme.com\SYSVOL

02/24/2022  10:57 PM    <DIR>          .
02/24/2022  10:57 PM    <DIR>          ..
02/24/2022  10:57 PM    <JUNCTION>     za.tryhackme.com [C:\Windows\SYSVOL\domain]
               0 File(s)              0 bytes
               3 Dir(s)  51,574,280,192 bytes free
```

```shell
root@rE3oN:~/enum-more/obsidian_vault/thm/adenumeration# xfreerdp /u:tony.holland /p:Mhvn2334 /v:thmjmp1.za.tryhackme.com /dynamic-resolution
[21:49:07:554] [4816:4817] [WARN][com.freerdp.crypto] - Certificate verification failure 'self-signed certificate (18)' at stack position 0
[21:49:07:554] [4816:4817] [WARN][com.freerdp.crypto] - CN = THMJMP1.za.tryhackme.com
Certificate details for thmjmp1.za.tryhackme.com:3389 (RDP-Server):
        Common Name: THMJMP1.za.tryhackme.com
        Subject:     CN = THMJMP1.za.tryhackme.com
        Issuer:      CN = THMJMP1.za.tryhackme.com
        Thumbprint:  67:fe:05:1b:5b:a3:59:2a:c1:f5:e4:db:fc:ca:a2:31:39:b0:35:0c:c8:29:f7:ce:5d:d4:f0:b9:fa:1b:14:df
The above X.509 certificate could not be verified, possibly because you do not have
the CA certificate in your certificate store, or the certificate has expired.
Please look at the OpenSSL documentation on how to add a private CA to the store.
Do you trust the above certificate? (Y/T/N) y
```

<center>
<img src = "https://github.com/enum-more/obsidian_vault/raw/main/thm/adenumeration/assets/domain&trust.png" />
</center>

<center>
<img src = "https://github.com/enum-more/obsidian_vault/raw/main/thm/adenumeration/assets/change_forest.png" />
</center>

<center>
<img src = "https://github.com/enum-more/obsidian_vault/raw/main/thm/adenumeration/assets/sites&service.png" />
</center>

<center>
<img src = "https://github.com/enum-more/obsidian_vault/raw/main/thm/adenumeration/assets/change_forest.png" />
</center>

<center>
<img src = "https://github.com/enum-more/obsidian_vault/raw/main/thm/adenumeration/assets/user&computer.png" />
</center>

<center>
<img src = "https://github.com/enum-more/obsidian_vault/raw/main/thm/adenumeration/assets/change_domain.png" />
</center>

<center>
<img src = "https://github.com/enum-more/obsidian_vault/raw/main/thm/adenumeration/assets/advanced_feature.png" />
</center>

<center>
<img src = "https://github.com/enum-more/obsidian_vault/raw/main/thm/adenumeration/assets/groups.png" />
</center>

<center>
<img src = "https://github.com/enum-more/obsidian_vault/raw/main/thm/adenumeration/assets/detailed_view.png" />
</center>

### Command Prompt

```powershell
PS C:\Users\tony.holland> net user /domain
The request will be processed at a domain controller for domain za.tryhackme.com.


User accounts for \\THMDC.za.tryhackme.com

-------------------------------------------------------------------------------
aaron.conway             aaron.hancock            aaron.harris
aaron.johnson            aaron.lewis              aaron.moore
aaron.patel              aaron.smith              abbie.joyce
abbie.robertson          abbie.taylor             abbie.walker
abdul.akhtar             abdul.bates              abdul.holt
abdul.jones              abdul.wall               abdul.west
abdul.wilson             abigail.cox              abigail.cox1
abigail.smith            abigail.ward             abigail.wheeler
adam.heath               adam.jones               adam.parker
adam.pugh                adam.reynolds            adam.woodward
Administrator            adrian.blake             adrian.chapman
adrian.foster            adrian.wilson            aimee.ball
aimee.dean               aimee.humphries          aimee.jones
aimee.potter             aimee.robinson           alan.brown
alan.jones               albert.elliott           albert.harrison
[..]

PS C:\Users\tony.holland> net user zoe.marshall /domain
The request will be processed at a domain controller for domain za.tryhackme.com.

User name                    zoe.marshall
Full Name                    Zoe Marshall
Comment
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            2/24/2022 11:06:06 PM
Password expires             Never
Password changeable          2/24/2022 11:06:06 PM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   Never

Logon hours allowed          All

Local Group Memberships
Global Group memberships     *Domain Users         *Internet Access
The command completed successfully.

PS C:\Users\tony.holland> net group /domain
The request will be processed at a domain controller for domain za.tryhackme.com.


Group Accounts for \\THMDC.za.tryhackme.com

-------------------------------------------------------------------------------
*Cloneable Domain Controllers
*DnsUpdateProxy
*Domain Admins
*Domain Computers
*Domain Controllers
*Domain Guests
*Domain Users
*Enterprise Admins
*Enterprise Key Admins
*Enterprise Read-only Domain Controllers
*Group Policy Creator Owners
*HR Share RW
*Internet Access
*Key Admins
*Protected Users
*Read-only Domain Controllers
*Schema Admins
*Server Admins
*Tier 0 Admins
*Tier 1 Admins
*Tier 2 Admins
The command completed successfully.

PS C:\Users\tony.holland> net group "Tier 1 Admins" /domain
The request will be processed at a domain controller for domain za.tryhackme.com.

Group name     Tier 1 Admins
Comment

Members

-------------------------------------------------------------------------------
t1_arthur.tyler          t1_gary.moss             t1_henry.miller
t1_jill.wallis           t1_joel.stephenson       t1_marian.yates
t1_rosie.bryant
The command completed successfully.

PS C:\Users\tony.holland> net accounts /domain
The request will be processed at a domain controller for domain za.tryhackme.com.

Force user logoff how long after time expires?:       Never
Minimum password age (days):                          0
Maximum password age (days):                          Unlimited
Minimum password length:                              0
Length of password history maintained:                None
Lockout threshold:                                    Never
Lockout duration (minutes):                           30
Lockout observation window (minutes):                 30
Computer role:                                        PRIMARY
The command completed successfully.

PS C:\Users\tony.holland> net user aaron.harris /domain
The request will be processed at a domain controller for domain za.tryhackme.com.

User name                    aaron.harris
Full Name                    Aaron Harris
Comment
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            2/24/2022 11:05:11 PM
Password expires             Never
Password changeable          2/24/2022 11:05:11 PM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   Never

Logon hours allowed          All

Local Group Memberships
Global Group memberships     *Domain Users         *Internet Access
The command completed successfully.

PS C:\Users\tony.holland> net user guest /domain
The request will be processed at a domain controller for domain za.tryhackme.com.

User name                    Guest
Full Name
Comment                      Built-in account for guest access to the computer/domain
User's comment
Country/region code          000 (System Default)
Account active               No
Account expires              Never

Password last set            7/20/2022 6:09:17 PM
Password expires             Never
Password changeable          7/20/2022 6:09:17 PM
Password required            No
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   Never

Logon hours allowed          All

Local Group Memberships      *Guests
Global Group memberships     *Domain Guests
The command completed successfully.
```

### Powershell with AD-RSAT

```powershell
PS C:\Users\tony.holland> Get-ADUser -Identity gordon.stevens -Server za.tryhackme.com -Properties *


AccountExpirationDate                :
accountExpires                       : 9223372036854775807
AccountLockoutTime                   :
AccountNotDelegated                  : False
AllowReversiblePasswordEncryption    : False
AuthenticationPolicy                 : {}
AuthenticationPolicySilo             : {}
BadLogonCount                        : 0
badPasswordTime                      : 0
badPwdCount                          : 0
CannotChangePassword                 : False
CanonicalName                        : za.tryhackme.com/People/Consulting/gordon.stevens
Certificates                         : {}
City                                 :
CN                                   : gordon.stevens
codePage                             : 0
Company                              :
CompoundIdentitySupported            : {}
Country                              :
countryCode                          : 0
Created                              : 2/24/2022 10:06:44 PM
createTimeStamp                      : 2/24/2022 10:06:44 PM
Deleted                              :
Department                           : Consulting
Description                          :
DisplayName                          : Gordon Stevens
DistinguishedName                    : CN=gordon.stevens,OU=Consulting,OU=People,DC=za,DC=tryhackme,DC=com
Division                             :
DoesNotRequirePreAuth                : False
dSCorePropagationData                : {1/1/1601 12:00:00 AM}
EmailAddress                         :
EmployeeID                           :
EmployeeNumber                       :
Enabled                              : True
Fax                                  :
GivenName                            : Gordon
HomeDirectory                        :
HomedirRequired                      : False
HomeDrive                            :
HomePage                             :
HomePhone                            :
Initials                             :
instanceType                         : 4
isDeleted                            :
KerberosEncryptionType               : {}
LastBadPasswordAttempt               :
LastKnownParent                      :
lastLogoff                           : 0
lastLogon                            : 132908987618422496
LastLogonDate                        : 4/29/2022 11:13:07 PM
lastLogonTimestamp                   : 132957439878817675
LockedOut                            : False
logonCount                           : 4
LogonWorkstations                    :
Manager                              :
MemberOf                             : {CN=Internet Access,OU=Groups,DC=za,DC=tryhackme,DC=com}
MNSLogonAccount                      : False
MobilePhone                          :
Modified                             : 4/29/2022 11:13:07 PM
modifyTimeStamp                      : 4/29/2022 11:13:07 PM
msDS-User-Account-Control-Computed   : 0
Name                                 : gordon.stevens
nTSecurityDescriptor                 : System.DirectoryServices.ActiveDirectorySecurity
ObjectCategory                       : CN=Person,CN=Schema,CN=Configuration,DC=za,DC=tryhackme,DC=com
ObjectClass                          : user
ObjectGUID                           : 48ddd5f1-37ae-4040-a281-47dd58313fcb
objectSid                            : S-1-5-21-3330634377-1326264276-632209373-3058
Office                               :
OfficePhone                          :
Organization                         :
OtherName                            :
PasswordExpired                      : False
PasswordLastSet                      : 2/24/2022 10:06:44 PM
PasswordNeverExpires                 : False
PasswordNotRequired                  : False
POBox                                :
PostalCode                           :
PrimaryGroup                         : CN=Domain Users,CN=Users,DC=za,DC=tryhackme,DC=com
primaryGroupID                       : 513
PrincipalsAllowedToDelegateToAccount : {}
ProfilePath                          :
ProtectedFromAccidentalDeletion      : False
pwdLastSet                           : 132902140043901058
SamAccountName                       : gordon.stevens
sAMAccountType                       : 805306368
ScriptPath                           :
sDRightsEffective                    : 0
ServicePrincipalNames                : {}
SID                                  : S-1-5-21-3330634377-1326264276-632209373-3058
SIDHistory                           : {}
SmartcardLogonRequired               : False
sn                                   : Stevens
State                                :
StreetAddress                        :
Surname                              : Stevens
Title                                : Mid-level
TrustedForDelegation                 : False
TrustedToAuthForDelegation           : False
UseDESKeyOnly                        : False
userAccountControl                   : 512
userCertificate                      : {}
UserPrincipalName                    :
uSNChanged                           : 103860
uSNCreated                           : 30825
whenChanged                          : 4/29/2022 11:13:07 PM
whenCreated                          : 2/24/2022 10:06:44 PM



PS C:\Users\tony.holland> Get-ADUser -Filter 'Name -like "*stevens"' -Server za.tryhackme.com | Format-Table Name,SamAccountName -A

Name             SamAccountName
----             --------------
chloe.stevens    chloe.stevens
samantha.stevens samantha.stevens
mohammed.stevens mohammed.stevens
jacob.stevens    jacob.stevens
timothy.stevens  timothy.stevens
trevor.stevens   trevor.stevens
owen.stevens     owen.stevens
jane.stevens     jane.stevens
janice.stevens   janice.stevens
gordon.stevens   gordon.stevens


PS C:\Users\tony.holland> Get-ADGroup -Identity Administrators -Server za.tryhackme.com


DistinguishedName : CN=Administrators,CN=Builtin,DC=za,DC=tryhackme,DC=com
GroupCategory     : Security
GroupScope        : DomainLocal
Name              : Administrators
ObjectClass       : group
ObjectGUID        : f4d1cbcd-4a6f-4531-8550-0394c3273c4f
SamAccountName    : Administrators
SID               : S-1-5-32-544



PS C:\Users\tony.holland> Get-ADGroupMember -Identity Administrators -Server za.tryhackme.com


distinguishedName : CN=Domain Admins,CN=Users,DC=za,DC=tryhackme,DC=com
name              : Domain Admins
objectClass       : group
objectGUID        : 8a6186e5-e20f-4f13-b1b0-067f3326f67c
SamAccountName    : Domain Admins
SID               : S-1-5-21-3330634377-1326264276-632209373-512

distinguishedName : CN=Enterprise Admins,CN=Users,DC=za,DC=tryhackme,DC=com
name              : Enterprise Admins
objectClass       : group
objectGUID        : 93846b04-25b9-4915-baca-e98cce4541c6
SamAccountName    : Enterprise Admins
SID               : S-1-5-21-3330634377-1326264276-632209373-519

distinguishedName : CN=vagrant,CN=Users,DC=za,DC=tryhackme,DC=com
name              : vagrant
objectClass       : user
objectGUID        : ed901eff-9ec0-4851-ba32-7a26a8f0858f
SamAccountName    : vagrant
SID               : S-1-5-21-3330634377-1326264276-632209373-1000

distinguishedName : CN=Administrator,CN=Users,DC=za,DC=tryhackme,DC=com
name              : Administrator
objectClass       : user
objectGUID        : b10fe384-bcce-450b-85c8-218e3c79b30f
SamAccountName    : Administrator
SID               : S-1-5-21-3330634377-1326264276-632209373-500



PS C:\Users\tony.holland>  $ChangeDate = New-Object DateTime(2022, 02, 28, 12, 00, 00)
PS C:\Users\tony.holland> Get-ADObject -Filter 'whenChanged -gt $ChangeDate' -includeDeletedObjects -Server za.tryhackme.com


Deleted           :
DistinguishedName : DC=za,DC=tryhackme,DC=com
Name              : za
ObjectClass       : domainDNS
ObjectGUID        : 518ee1e7-f427-4e91-a081-bb75e655ce7a

Deleted           :
DistinguishedName : CN=Administrator,CN=Users,DC=za,DC=tryhackme,DC=com
Name              : Administrator
ObjectClass       : user
ObjectGUID        : b10fe384-bcce-450b-85c8-218e3c79b30f

Deleted           :
DistinguishedName : CN=vagrant,CN=Users,DC=za,DC=tryhackme,DC=com
Name              : vagrant
ObjectClass       : user
ObjectGUID        : ed901eff-9ec0-4851-ba32-7a26a8f0858f

Deleted           :
DistinguishedName : CN=THMDC,OU=Domain Controllers,DC=za,DC=tryhackme,DC=com
Name              : THMDC
ObjectClass       : computer
ObjectGUID        : 910d503f-f1ba-428c-b5ea-14fc2b6972a0

Deleted           :
DistinguishedName : CN=Domain Admins,CN=Users,DC=za,DC=tryhackme,DC=com
Name              : Domain Admins
ObjectClass       : group
ObjectGUID        : 8a6186e5-e20f-4f13-b1b0-067f3326f67c

Deleted           :
DistinguishedName : CN=RID Manager$,CN=System,DC=za,DC=tryhackme,DC=com
Name              : RID Manager$
ObjectClass       : rIDManager
ObjectGUID        : 2fc1c4ed-1d56-491f-a293-26032ed3fe5c

Deleted           :
DistinguishedName : CN=kathryn.dickinson,OU=Engineering,OU=People,DC=za,DC=tryhackme,DC=com
Name              : kathryn.dickinson
ObjectClass       : user
ObjectGUID        : 8c70aaaa-751f-4741-afc0-c32de7ae1dba

Deleted           :
DistinguishedName : CN=arthur.campbell,OU=Engineering,OU=People,DC=za,DC=tryhackme,DC=com
Name              : arthur.campbell
ObjectClass       : user
ObjectGUID        : c77a6fc9-0f93-4432-a87e-59b74b995b46

Deleted           :
DistinguishedName : CN=georgina.edwards,OU=Sales,OU=People,DC=za,DC=tryhackme,DC=com
Name              : georgina.edwards
ObjectClass       : user
ObjectGUID        : 65c5a0d4-d9ee-4d86-8a40-c3e3d872f6a7


PS C:\Users\tony.holland> Get-ADObject -Filter 'badPwdCount -gt 0' -Server za.tryhackme.com

DistinguishedName                                                        Name              ObjectClass ObjectGUID
-----------------                                                        ----              ----------- ----------
CN=Administrator,CN=Users,DC=za,DC=tryhackme,DC=com                      Administrator     user        b10fe384-bcce-450b-85c8-218e3c79b30f
CN=maurice.palmer,OU=Consulting,OU=People,DC=za,DC=tryhackme,DC=com      maurice.palmer    user        152c3bd1-5490-4e02-9811-2edaf6d2973b
CN=henry.taylor,OU=IT,OU=People,DC=za,DC=tryhackme,DC=com                henry.taylor      user        154e4541-219e-4fa9-a5bf-ec5a367c5e21
CN=frank.fletcher,OU=IT,OU=People,DC=za,DC=tryhackme,DC=com              frank.fletcher    user        3dd92645-4b2d-4ba0-957c-9f6c20421d54
CN=henry.black,OU=Engineering,OU=People,DC=za,DC=tryhackme,DC=com        henry.black       user        379df099-f89b-47fa-886d-ae915e2f8d32
CN=mark.oconnor,OU=Engineering,OU=People,DC=za,DC=tryhackme,DC=com       mark.oconnor      user        e0bb6195-9f2e-4de1-83a5-0f9613a28e8f
CN=dawn.hughes,OU=Finance,OU=People,DC=za,DC=tryhackme,DC=com            dawn.hughes       user        fed968f3-3e5e-4d36-b66a-289ddb6e8db2
CN=joanne.davies,OU=Marketing,OU=People,DC=za,DC=tryhackme,DC=com        joanne.davies     user        81b8d2ab-d3e1-4316-8115-9d305a0824b8
CN=alan.jones,OU=Human Resources,OU=People,DC=za,DC=tryhackme,DC=com     alan.jones        user        88922cf5-828b-48f4-ab30-86d37381233c
CN=maria.sheppard,OU=Human Resources,OU=People,DC=za,DC=tryhackme,DC=com maria.sheppard    user        edeffae5-eb5c-4c4a-8ba1-64e750e84fbe
CN=sophie.blackburn,OU=Consulting,OU=People,DC=za,DC=tryhackme,DC=com    sophie.blackburn  user        e2854343-659c-4b90-94ac-111af7c60ce3
CN=dominic.elliott,OU=Finance,OU=People,DC=za,DC=tryhackme,DC=com        dominic.elliott   user        2a5eabcc-0bff-4341-a2ce-f14fc1621894
CN=louise.talbot,OU=Consulting,OU=People,DC=za,DC=tryhackme,DC=com       louise.talbot     user        b5fe09ec-935d-4158-8413-3b596da9e11c
CN=jennifer.wood,OU=Engineering,OU=People,DC=za,DC=tryhackme,DC=com      jennifer.wood     user        90d6e815-5260-4a26-b5c3-b3fb6a28f192
CN=frances.chapman,OU=Engineering,OU=People,DC=za,DC=tryhackme,DC=com    frances.chapman   user        26616091-bb69-4182-99e7-41d61e578034
CN=dawn.turner,OU=Finance,OU=People,DC=za,DC=tryhackme,DC=com            dawn.turner       user        178cb599-6a57-41cb-94b6-30415f04a008
CN=samantha.thompson,OU=Engineering,OU=People,DC=za,DC=tryhackme,DC=com  samantha.thompson user        f78decbb-6ec8-40bb-9190-af2193a23ee5
CN=anthony.reynolds,OU=Marketing,OU=People,DC=za,DC=tryhackme,DC=com     anthony.reynolds  user        ab44469f-8752-4bb7-bd36-10e6705028e4


PS C:\Users\tony.holland> Get-ADDomain -Server za.tryhackme.com


AllowedDNSSuffixes                 : {}
ChildDomains                       : {}
ComputersContainer                 : CN=Computers,DC=za,DC=tryhackme,DC=com
DeletedObjectsContainer            : CN=Deleted Objects,DC=za,DC=tryhackme,DC=com
DistinguishedName                  : DC=za,DC=tryhackme,DC=com
DNSRoot                            : za.tryhackme.com
DomainControllersContainer         : OU=Domain Controllers,DC=za,DC=tryhackme,DC=com
DomainMode                         : Windows2012R2Domain
DomainSID                          : S-1-5-21-3330634377-1326264276-632209373
ForeignSecurityPrincipalsContainer : CN=ForeignSecurityPrincipals,DC=za,DC=tryhackme,DC=com
Forest                             : za.tryhackme.com
InfrastructureMaster               : THMDC.za.tryhackme.com
LastLogonReplicationInterval       :
LinkedGroupPolicyObjects           : {CN={31B2F340-016D-11D2-945F-00C04FB984F9},CN=Policies,CN=System,DC=za,DC=tryhackme,DC=com}
LostAndFoundContainer              : CN=LostAndFound,DC=za,DC=tryhackme,DC=com
ManagedBy                          :
Name                               : za
NetBIOSName                        : ZA
ObjectClass                        : domainDNS
ObjectGUID                         : 518ee1e7-f427-4e91-a081-bb75e655ce7a
ParentDomain                       :
PDCEmulator                        : THMDC.za.tryhackme.com
PublicKeyRequiredPasswordRolling   :
QuotasContainer                    : CN=NTDS Quotas,DC=za,DC=tryhackme,DC=com
ReadOnlyReplicaDirectoryServers    : {}
ReplicaDirectoryServers            : {THMDC.za.tryhackme.com}
RIDMaster                          : THMDC.za.tryhackme.com
SubordinateReferences              : {DC=ForestDnsZones,DC=za,DC=tryhackme,DC=com, DC=DomainDnsZones,DC=za,DC=tryhackme,DC=com, CN=Configuration,DC=za,DC=tryhackme,DC=com}
SystemsContainer                   : CN=System,DC=za,DC=tryhackme,DC=com
UsersContainer                     : CN=Users,DC=za,DC=tryhackme,DC=com


PS C:\Users\tony.holland> Set-ADAccountPassword -Identity tony.holland -Server za.tryhackme.com -OldPassword (ConvertTo-SecureString -AsPlaintext "Mhvn2334" -force) -NewPassword (ConvertTo-SecureString -AsPlainText "ajith12345" -Force)
Set-ADAccountPassword : The password does not meet the length, complexity, or history requirement of the domain.
At line:1 char:1
+ Set-ADAccountPassword -Identity tony.holland -Server za.tryhackme.com ...
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : InvalidData: (tony.holland:ADAccount) [Set-ADAccountPassword], ADPasswordComplexityException
    + FullyQualifiedErrorId : ActiveDirectoryServer:1325,Microsoft.ActiveDirectory.Management.Commands.SetADAccountPassword

PS C:\Users\tony.holland> Get-ADUser -Identity beth.nolan -Server za.tryhackme.com -Properties *


AccountExpirationDate                :
accountExpires                       : 9223372036854775807
AccountLockoutTime                   :
AccountNotDelegated                  : False
AllowReversiblePasswordEncryption    : False
AuthenticationPolicy                 : {}
AuthenticationPolicySilo             : {}
BadLogonCount                        : 0
badPasswordTime                      : 0
badPwdCount                          : 0
CannotChangePassword                 : False
CanonicalName                        : za.tryhackme.com/People/Sales/beth.nolan
Certificates                         : {}
City                                 :
CN                                   : beth.nolan
codePage                             : 0
Company                              :
CompoundIdentitySupported            : {}
Country                              :
countryCode                          : 0
Created                              : 2/24/2022 10:06:25 PM
createTimeStamp                      : 2/24/2022 10:06:25 PM
Deleted                              :
Department                           : Sales
Description                          :
DisplayName                          : Beth Nolan
DistinguishedName                    : CN=beth.nolan,OU=Sales,OU=People,DC=za,DC=tryhackme,DC=com
Division                             :
DoesNotRequirePreAuth                : False
dSCorePropagationData                : {1/1/1601 12:00:00 AM}
EmailAddress                         :
EmployeeID                           :
EmployeeNumber                       :
Enabled                              : True
Fax                                  :
GivenName                            : Beth
HomeDirectory                        :
HomedirRequired                      : False
HomeDrive                            :
HomePage                             :
HomePhone                            :
Initials                             :
instanceType                         : 4
isDeleted                            :
KerberosEncryptionType               : {}
LastBadPasswordAttempt               :
LastKnownParent                      :
lastLogoff                           : 0
lastLogon                            : 0
LastLogonDate                        :
LockedOut                            : False
logonCount                           : 0
LogonWorkstations                    :
Manager                              :
MemberOf                             : {CN=Internet Access,OU=Groups,DC=za,DC=tryhackme,DC=com}
MNSLogonAccount                      : False
MobilePhone                          :
Modified                             : 2/24/2022 10:06:25 PM
modifyTimeStamp                      : 2/24/2022 10:06:25 PM
msDS-User-Account-Control-Computed   : 0
Name                                 : beth.nolan
nTSecurityDescriptor                 : System.DirectoryServices.ActiveDirectorySecurity
ObjectCategory                       : CN=Person,CN=Schema,CN=Configuration,DC=za,DC=tryhackme,DC=com
ObjectClass                          : user
ObjectGUID                           : c4ae7c4c-4f98-4366-b3a1-c57debe3256f
objectSid                            : S-1-5-21-3330634377-1326264276-632209373-2760
Office                               :
OfficePhone                          :
Organization                         :
OtherName                            :
PasswordExpired                      : False
PasswordLastSet                      : 2/24/2022 10:06:25 PM
PasswordNeverExpires                 : False
PasswordNotRequired                  : False
POBox                                :
PostalCode                           :
PrimaryGroup                         : CN=Domain Users,CN=Users,DC=za,DC=tryhackme,DC=com
primaryGroupID                       : 513
PrincipalsAllowedToDelegateToAccount : {}
ProfilePath                          :
ProtectedFromAccidentalDeletion      : False
pwdLastSet                           : 132902139856391082
SamAccountName                       : beth.nolan
sAMAccountType                       : 805306368
ScriptPath                           :
sDRightsEffective                    : 0
ServicePrincipalNames                : {}
SID                                  : S-1-5-21-3330634377-1326264276-632209373-2760
SIDHistory                           : {}
SmartcardLogonRequired               : False
sn                                   : Nolan
State                                :
StreetAddress                        :
Surname                              : Nolan
Title                                : Senior
TrustedForDelegation                 : False
TrustedToAuthForDelegation           : False
UseDESKeyOnly                        : False
userAccountControl                   : 512
userCertificate                      : {}
UserPrincipalName                    :
uSNChanged                           : 28070
uSNCreated                           : 28066
whenChanged                          : 2/24/2022 10:06:25 PM
whenCreated                          : 2/24/2022 10:06:25 PM



PS C:\Users\tony.holland> Get-ADUser -Identity annette.manning -Server za.tryhackme.com -Properties *


AccountExpirationDate                :
accountExpires                       : 9223372036854775807
AccountLockoutTime                   :
AccountNotDelegated                  : False
AllowReversiblePasswordEncryption    : False
AuthenticationPolicy                 : {}
AuthenticationPolicySilo             : {}
BadLogonCount                        : 0
badPasswordTime                      : 0
badPwdCount                          : 0
CannotChangePassword                 : False
CanonicalName                        : za.tryhackme.com/People/Marketing/annette.manning
Certificates                         : {}
City                                 :
CN                                   : annette.manning
codePage                             : 0
Company                              :
CompoundIdentitySupported            : {}
Country                              :
countryCode                          : 0
Created                              : 2/24/2022 10:04:50 PM
createTimeStamp                      : 2/24/2022 10:04:50 PM
Deleted                              :
Department                           : Marketing
Description                          :
DisplayName                          : Annette Manning
DistinguishedName                    : CN=annette.manning,OU=Marketing,OU=People,DC=za,DC=tryhackme,DC=com
Division                             :
DoesNotRequirePreAuth                : False
dSCorePropagationData                : {1/1/1601 12:00:00 AM}
EmailAddress                         :
EmployeeID                           :
EmployeeNumber                       :
Enabled                              : True
Fax                                  :
GivenName                            : Annette
HomeDirectory                        :
HomedirRequired                      : False
HomeDrive                            :
HomePage                             :
HomePhone                            :
Initials                             :
instanceType                         : 4
isDeleted                            :
KerberosEncryptionType               : {}
LastBadPasswordAttempt               :
LastKnownParent                      :
lastLogoff                           : 0
lastLogon                            : 0
LastLogonDate                        :
LockedOut                            : False
logonCount                           : 0
LogonWorkstations                    :
Manager                              :
MemberOf                             : {CN=Internet Access,OU=Groups,DC=za,DC=tryhackme,DC=com}
MNSLogonAccount                      : False
MobilePhone                          :
Modified                             : 2/24/2022 10:04:50 PM
modifyTimeStamp                      : 2/24/2022 10:04:50 PM
msDS-User-Account-Control-Computed   : 0
Name                                 : annette.manning
nTSecurityDescriptor                 : System.DirectoryServices.ActiveDirectorySecurity
ObjectCategory                       : CN=Person,CN=Schema,CN=Configuration,DC=za,DC=tryhackme,DC=com
ObjectClass                          : user
ObjectGUID                           : 57069bf6-db28-4988-ac9e-0254ca51bb2f
objectSid                            : S-1-5-21-3330634377-1326264276-632209373-1257
Office                               :
OfficePhone                          :
Organization                         :
OtherName                            :
PasswordExpired                      : False
PasswordLastSet                      : 2/24/2022 10:04:50 PM
PasswordNeverExpires                 : False
PasswordNotRequired                  : False
POBox                                :
PostalCode                           :
PrimaryGroup                         : CN=Domain Users,CN=Users,DC=za,DC=tryhackme,DC=com
primaryGroupID                       : 513
PrincipalsAllowedToDelegateToAccount : {}
ProfilePath                          :
ProtectedFromAccidentalDeletion      : False
pwdLastSet                           : 132902138902335915
SamAccountName                       : annette.manning
sAMAccountType                       : 805306368
ScriptPath                           :
sDRightsEffective                    : 0
ServicePrincipalNames                : {}
SID                                  : S-1-5-21-3330634377-1326264276-632209373-1257
SIDHistory                           : {}
SmartcardLogonRequired               : False
sn                                   : Manning
State                                :
StreetAddress                        :
Surname                              : Manning
Title                                : Associate
TrustedForDelegation                 : False
TrustedToAuthForDelegation           : False
UseDESKeyOnly                        : False
userAccountControl                   : 512
userCertificate                      : {}
UserPrincipalName                    :
uSNChanged                           : 14150
uSNCreated                           : 14146
whenChanged                          : 2/24/2022 10:04:50 PM
whenCreated                          : 2/24/2022 10:04:50 PM


PS C:\Users\tony.holland> Get-ADGroup -Identity "Tier 2 Admins" -Server za.tryhackme.com -Properties *


CanonicalName                   : za.tryhackme.com/Groups/Tier 2 Admins
CN                              : Tier 2 Admins
Created                         : 2/24/2022 10:04:41 PM
createTimeStamp                 : 2/24/2022 10:04:41 PM
Deleted                         :
Description                     :
DisplayName                     : Tier 2 Admins
DistinguishedName               : CN=Tier 2 Admins,OU=Groups,DC=za,DC=tryhackme,DC=com
dSCorePropagationData           : {1/1/1601 12:00:00 AM}
GroupCategory                   : Security
GroupScope                      : Global
groupType                       : -2147483646
HomePage                        :
instanceType                    : 4
isDeleted                       :
LastKnownParent                 :
ManagedBy                       :
member                          : {CN=t2_jeremy.leonard,OU=T2,OU=Admins,DC=za,DC=tryhackme,DC=com, CN=t2_marian.yates,OU=T2,OU=Admins,DC=za,DC=tryhackme,DC=com,
                                  CN=t2_tom.bray,OU=T2,OU=Admins,DC=za,DC=tryhackme,DC=com, CN=t2_zoe.watson,OU=T2,OU=Admins,DC=za,DC=tryhackme,DC=com...}
MemberOf                        : {}
Members                         : {CN=t2_jeremy.leonard,OU=T2,OU=Admins,DC=za,DC=tryhackme,DC=com, CN=t2_marian.yates,OU=T2,OU=Admins,DC=za,DC=tryhackme,DC=com,
                                  CN=t2_tom.bray,OU=T2,OU=Admins,DC=za,DC=tryhackme,DC=com, CN=t2_zoe.watson,OU=T2,OU=Admins,DC=za,DC=tryhackme,DC=com...}
Modified                        : 2/24/2022 10:06:21 PM
modifyTimeStamp                 : 2/24/2022 10:06:21 PM
Name                            : Tier 2 Admins
nTSecurityDescriptor            : System.DirectoryServices.ActiveDirectorySecurity
ObjectCategory                  : CN=Group,CN=Schema,CN=Configuration,DC=za,DC=tryhackme,DC=com
ObjectClass                     : group
ObjectGUID                      : 6edab731-c305-4959-bd34-4ca1eefe2b3f
objectSid                       : S-1-5-21-3330634377-1326264276-632209373-1104
ProtectedFromAccidentalDeletion : False
SamAccountName                  : Tier 2 Admins
sAMAccountType                  : 268435456
sDRightsEffective               : 0
SID                             : S-1-5-21-3330634377-1326264276-632209373-1104
SIDHistory                      : {}
uSNChanged                      : 27391
uSNCreated                      : 12781
whenChanged                     : 2/24/2022 10:06:21 PM
whenCreated                     : 2/24/2022 10:04:41 PM



PS C:\Users\tony.holland> Get-ADGroup -Identity "Enterprise Admins" -Server za.tryhackme.com -Properties *


adminCount                      : 1
CanonicalName                   : za.tryhackme.com/Users/Enterprise Admins
CN                              : Enterprise Admins
Created                         : 2/24/2022 9:58:38 PM
createTimeStamp                 : 2/24/2022 9:58:38 PM
Deleted                         :
Description                     : Designated administrators of the enterprise
DisplayName                     :
DistinguishedName               : CN=Enterprise Admins,CN=Users,DC=za,DC=tryhackme,DC=com
dSCorePropagationData           : {2/24/2022 10:13:48 PM, 2/24/2022 9:58:38 PM, 1/1/1601 12:04:16 AM}
GroupCategory                   : Security
GroupScope                      : Universal
groupType                       : -2147483640
HomePage                        :
instanceType                    : 4
isCriticalSystemObject          : True
isDeleted                       :
LastKnownParent                 :
ManagedBy                       :
member                          : {CN=Administrator,CN=Users,DC=za,DC=tryhackme,DC=com}
MemberOf                        : {CN=Denied RODC Password Replication Group,CN=Users,DC=za,DC=tryhackme,DC=com, CN=Administrators,CN=Builtin,DC=za,DC=tryhackme,DC=com}
Members                         : {CN=Administrator,CN=Users,DC=za,DC=tryhackme,DC=com}
Modified                        : 2/24/2022 10:13:48 PM
modifyTimeStamp                 : 2/24/2022 10:13:48 PM
Name                            : Enterprise Admins
nTSecurityDescriptor            : System.DirectoryServices.ActiveDirectorySecurity
ObjectCategory                  : CN=Group,CN=Schema,CN=Configuration,DC=za,DC=tryhackme,DC=com
ObjectClass                     : group
ObjectGUID                      : 93846b04-25b9-4915-baca-e98cce4541c6
objectSid                       : S-1-5-21-3330634377-1326264276-632209373-519
ProtectedFromAccidentalDeletion : False
SamAccountName                  : Enterprise Admins
sAMAccountType                  : 268435456
sDRightsEffective               : 0
SID                             : S-1-5-21-3330634377-1326264276-632209373-519
SIDHistory                      : {}
uSNChanged                      : 31668
uSNCreated                      : 12339
whenChanged                     : 2/24/2022 10:13:48 PM
whenCreated                     : 2/24/2022 9:58:38 PM
```

### BloodHound

<center>
<img src = "https://github.com/enum-more/obsidian_vault/raw/main/thm/adenumeration/assets/databaseinfo.png" />
</center>

<center>
<img src = "https://github.com/enum-more/obsidian_vault/raw/main/thm/adenumeration/assets/enum-computers.png" />
</center>

<center>
<img src = "https://github.com/enum-more/obsidian_vault/raw/main/thm/adenumeration/assets/nodeinfo.png" />
</center>

<center>
<img src = "https://github.com/enum-more/obsidian_vault/raw/main/thm/adenumeration/assets/analysis.png" />
</center>
