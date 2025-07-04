## Introduction

Active Directory plays a huge role in managing user identities and access across enterprise networks, making it a prime target for attackers looking to compromise a network.

This post dives into key indicators of compromise (IoCs) associated with common Active Directory attacks and popular offensive tools like Impacket and Netexec. Whether you're on the offensive or defensive side, this blog is designed to provide practical insight. Red teamers can use it to better understand how their attacks appear in logs, while defenders can apply these detections to improve detections.

This is part one of a multi-part detection engineering blog series that covers a range of common and advanced attacks targeting Active Directory environments.

> **Note:** Prior knowledge of these attacks is recommended to fully understand the detection logic presented.

---

## Table of Contents

- [Detecting Password Spraying](#detecting-password-spraying)
- [Detecting AS-REP Roasting](#detecting-as-rep-roasting)
- [Detecting Anomalous TGT Requests](#detecting-anomalous-tgt-requests)
- [Detecting Kerberoasting](#detecting-kerberoasting)
- [Detecting Kerberoasting Without Pre-Authentication](#detecting-kerberoasting-without-pre-authentication)
- [Detecting DCSync Attacks](#detecting-dcsync-attacks)
  - [Mimikatz](#detecting-dcsync-with-mimikatz)
  - [Netexec](#detecting-dcsync-with-netexec)
- [Detecting Pass-The-Hash](#detecting-pass-the-hash)

---

## Detecting Password Spraying
Unlike brute force attacks, password spraying involves trying a small number of commonly used passwords against multiple user accounts. We chose Kerbrute as the tool for this attack because it generates distinct event logs that we can use to detect the activity.

**Tool:** [Kerbrute](https://github.com/ropnop/kerbrute)

**Command:**
```bash
./kerbrute passwordspray usernames.txt "bP@ssw0rd" -d testlab.local --dc dc.testlab.local
```
When the spray is successful, two `Event ID 4768` logs are typically generated for each account. The first log will have a `Client Address` of `192.168.108.129`, and the second will show `::ffff:192.168.108.129`. This is expected behavior due to IPv4 and IPv6 representations.

What stands out is the `Ticket Options` value: both logs show `0x10`, which is highly suspicious. Normally, you’d expect values like `0x40810010` or `0x40810000`. This anomaly allows us to create a detection rule.

---

**Example Log 1 — Event ID 4768**

```
A Kerberos authentication ticket (TGT) was requested.

Account Information:
    Account Name:		bob
    Supplied Realm Name:	TESTLAB.LOCAL
    User ID:			TESTLAB\bob

Service Information:
    Service Name:		krbtgt
    Service ID:		TESTLAB\krbtgt

Network Information:
    Client Address:		192.168.108.129
    Client Port:		35136

Additional Information:
    Ticket Options:		0x10
    Result Code:		0x0
    Ticket Encryption Type:	0x12
    Pre-Authentication Type:	2
...
```

**Example Log 2 — Event ID 4768**

```
A Kerberos authentication ticket (TGT) was requested.

Account Information:
    Account Name:		bob
    Supplied Realm Name:	TESTLAB.LOCAL
    User ID:			TESTLAB\bob

Service Information:
    Service Name:		krbtgt
    Service ID:		TESTLAB\krbtgt

Network Information:
    Client Address:		::ffff:192.168.108.129
    Client Port:		49052

Additional Information:
    Ticket Options:		0x10
    Result Code:		0x0
    Ticket Encryption Type:	0x12
    Pre-Authentication Type:	2
...
```

---

### Detection Rule

- **Rule Name:** Kerbrute Password Spray
- **Query:**

```elasticsearch
winlog.event_data.TicketOptions: "0x10" AND winlog.event_id: "4768"
```

- **Description:** Flags Kerberos TGT requests with an abnormal `TicketOptions` value of `0x10`, which is commonly seen during password spraying with Kerbrute.
  
---

## Detecting AS-REP Roasting

AS-REP Roasting is a well-known technique that targets accounts not requiring Kerberos pre-authentication. With no need to supply credentials, an attacker can request an encrypted TGT and attempt to crack it offline

**Tool:** [Impacket - GetNPUsers](https://github.com/fortra/impacket)

**Command:**
```bash
impacket-GetNPUsers -no-pass -usersfile npusers.txt testlab.local/
```

When executed, the following characteristics are observed in the resulting Kerberos TGT request (`Event ID 4768`):

- `Ticket Encryption Type`: `0x17` (RC4), which is uncommon in modern environments.
- `Ticket Options`: `0x50800000`, not normally seen in legitimate requests.
- `Pre-Authentication Type`: `0`, indicating no pre-authentication was required.

---

**Example Log — Event ID 4768**

```
A Kerberos authentication ticket (TGT) was requested.

Account Information:
    Account Name:		alice
    Supplied Realm Name:	TESTLAB.LOCAL
    User ID:			    TESTLAB\alice

Service Information:
    Service Name:		krbtgt
    Service ID:		    TESTLAB\krbtgt

Network Information:
    Client Address:		::ffff:192.168.108.129
    Client Port:		    44884

Additional Information:
    Ticket Options:		    0x50800000
    Result Code:		    0x0
    Ticket Encryption Type:	0x17
    Pre-Authentication Type:	0
...
```
---

### Detection Rule

- **Rule Name:** AS-REP Roasting - GetNPUsers
- **Query:**
```elasticsearch
winlog.event_data.TicketOptions: "0x50800000" AND
winlog.event_data.TicketEncryptionType: "0x17" AND
winlog.event_data.PreAuthType: "0" AND
winlog.event_id: "4768"
```
---

## Detecting Anomalous TGT Requests

Attackers often use tools like Impacket's `getTGT` to request a Ticket Granting Ticket (TGT) that can later be used for Pass-The-Ticket (PTT) attacks. These requests generate anomalous Kerberos logs, making them useful for detection.

**Tool:** [Impacket - getTGT](https://github.com/fortra/impacket)

**Command:**
```bash
impacket-getTGT testlab.local/bob:'bP@ssw0rd'
```

When using `getTGT`, the TGT request produces an `Event ID 4768` log. While this looks like a normal TGT request, certain fields raise red flags:

- `Ticket Options`: `0x50800000` — unusual for standard TGT requests.
- `Ticket Encryption Type`: `0x12` — standard, but paired with the above option is suspicious.
- `Pre-Authentication Type`: `2` — indicates pre-auth was used, typical for interactive login but not enough to normalize the request.

---

**Example Log — Event ID 4768**

```
A Kerberos authentication ticket (TGT) was requested.

Account Information:
    Account Name:		    bob
    Supplied Realm Name:	TESTLAB.LOCAL
    User ID:			    TESTLAB\bob

Service Information:
    Service Name:		    krbtgt
    Service ID:		    TESTLAB\krbtgt

Network Information:
    Client Address:		    ::ffff:192.168.108.129
    Client Port:		    56732

Additional Information:
    Ticket Options:		    0x50800000
    Result Code:		    0x0
    Ticket Encryption Type:	0x12
    Pre-Authentication Type:	2
...
```

---

### Detection Rule

- **Rule Name:** Impacket TGT Request
- **Query:**
```elasticsearch
winlog.event_id: "4768" AND
winlog.event_data.TicketOptions: "0x50800000" AND
winlog.event_data.TicketEncryptionType: "0x12" AND
winlog.event_data.PreAuthType: "2"
```

- **Description:** This log is the result of Impacket requesting a TGT, most likely with impacket-GetTGT. This allows attackers to request TGTs likely to be used with Pass-The-Ticket (PTT) attacks.

---

## Detecting Kerberoasting

Kerberoasting is a technique where attackers request service tickets for service accounts, then attempt to crack them offline. We used Impacket's `GetUserSPNs` tool to simulate this attack and identify detectable indicators.

**Tool:** [Impacket - GetUserSPNs](https://github.com/fortra/impacket)

**Command:**
```bash
impacket-GetUserSPNs testlab.local/bob:'bP@ssw0rd' -request
```

This command causes two suspicious Kerberos logs to be generated:

- A `TGT` request (`Event ID 4768`) with `Ticket Options: 0x50800000` and `Encryption Type: 0x17`
- A `Service Ticket` request (`Event ID 4769`) with `Ticket Options: 0x40810010` and `Encryption Type: 0x17

The 4768 log is unique to `GetUserSPNs` and differs from what is seen with `getTGT`. The 4769 logalso appears when using `getST`.

---

**Example Log — Event ID 4768 (TGT Request)**

```
A Kerberos authentication ticket (TGT) was requested.

Account Information:
    Account Name:		    bob
    Supplied Realm Name:	TESTLAB.LOCAL
    User ID:			    TESTLAB\bob

Service Information:
    Service Name:		    krbtgt
    Service ID:		    TESTLAB\krbtgt

Network Information:
    Client Address:		    ::ffff:192.168.108.129
    Client Port:		    51172

Additional Information:
    Ticket Options:		    0x50800000
    Result Code:		    0x0
    Ticket Encryption Type:	0x17
    Pre-Authentication Type:	2
...
```

---

### Detection Rule 1 — TGT Request

- **Rule Name:** Kerberoasting with Impacket - TGT Request
- **Query:**
```elasticsearch
winlog.event_id: "4768" AND
winlog.event_data.TicketOptions: "0x50800000" AND
winlog.event_data.TicketEncryptionType: "0x17" AND
winlog.event_data.PreAuthType: "2"
```

- **Description:** Detects the Kerberoasting TGT request behavior from Impacket’s `GetUserSPNs -request`. This 4768 log is unique and does not match those generated by `getTGT`.

---

**Example Log — Event ID 4769 (ST Request)**

```
A Kerberos service ticket was requested.

Account Information:
    Account Name:		bob@TESTLAB.LOCAL
    Account Domain:		TESTLAB.LOCAL
    Logon GUID:		    {94545896-fc6e-e45f-9932-ce3d48fdfa23}

Service Information:
    Service Name:		bob
    Service ID:		    TESTLAB\bob

Network Information:
    Client Address:		::ffff:192.168.108.129
    Client Port:		51190

Additional Information:
    Ticket Options:		0x40810010
    Ticket Encryption Type:	0x17
    Failure Code:		0x0
    Transited Services:	-
...
```

---

### Detection Rule 2 — ST Request

- **Rule Name:** Kerberoasting with Impacket - ST Request
- **Query:**
```elasticsearch
winlog.event_id: "4769" AND
winlog.event_data.TicketOptions: "0x40810010" AND
winlog.event_data.TicketEncryptionType: "0x17"
```

- **Description:** Detects service ticket requests using RC4 encryption which is typically seen when using `GetUserSPNs` or `getST` to perform Kerberoasting.

---

## Detecting Kerberoasting Without Pre-Authentication

This is just like AS-REP roasting, except attackers are able to use the user that does not require pre-authentication to request service tickets to other SPNs by simply changing the target SPN from krbtgt to another SPN. This allows for kerberoasting without credentials. The resulting generated log looks like an AS-REP Roasting generated log except the “Service Name” will not be krbtgt.

**Tool:** [Impacket - GetUserSPNs (no-preauth)](https://github.com/fortra/impacket)

**Command:**
```bash
impacket-GetUserSPNs -no-preauth "alice" -usersfile usernames -dc-host 192.168.108.139 testlab.local/
```

The resulting log resembles AS-REP Roasting, but with one major difference: the **Service Name is _not_ `krbtgt`** — meaning the request was made for an SPN and not a TGT. This allowed us to craft a targeted detection.

---

**Example Log — Event ID 4768**

```
A Kerberos authentication ticket (TGT) was requested.

Account Information:
    Account Name:		    alice
    Supplied Realm Name:	    TESTLAB.LOCAL
    User ID:			    TESTLAB\alice

Service Information:
    Service Name:		    bob
    Service ID:		    TESTLAB\bob

Network Information:
    Client Address:		    ::ffff:192.168.108.129
    Client Port:		    47502

Additional Information:
    Ticket Options:		    0x50800000
    Result Code:		    0x0
    Ticket Encryption Type:	0x17
    Pre-Authentication Type:	0
...
```

---

### Detection Rule

- **Rule Name:** Kerberoasting Without Pre-Authentication
- **Query:**
```elasticsearch
winlog.event_id: "4768" AND
winlog.event_data.TicketOptions: "0x50800000" AND
winlog.event_data.PreAuthType: "0" AND
NOT service.name: "krbtgt"
```

- **Description:** Detects Kerberoasting performed against a user with pre-authentication disabled. The presence of a non-krbtgt SPN and PreAuthType `0` indicates this unusual ticket request without valid credentials.

---

## Detecting DCSync Attacks

DCSync is a powerful technique which is used to replicate a domain controllers behavior and extract credentials from Active Directory. Both [Mimikatz](https://github.com/gentilkiwi/mimikatz) and [Netexec](https://github.com/Pennyw0rth/NetExec) support this attack.

### Detecting Mimikatz's DCSync

**Tool:** [Mimikatz](https://github.com/gentilkiwi/mimikatz)

**Command:**

```bash
mimikatz.exe "lsadump::dcsync /user:krbtgt" exit
````

When Mimikatz is used to perform a DCSync, it generates **four** `4662` logs instead of the usual one that is associated with a typical sync between domain controllers. These logs differ in both the **Account Name** and the **GUIDs** used:

* **Normal behavior**: One `4662` log from each DC (Notice it’s only 1 log for each DC, and the account name is the domain controller machine account, and note the GUIDs in the properties field.)
- insert normal dcsync picture
  
* **Mimikatz DCSync**: Four `4662` logs from a **user account** with the action “An operation was performed on an object”.
- insert mimikatz dcsync picture

---

1. **Account Name**

  If we were a Domain Administrator user when we run a DCSync attack, we can see the **Account Name** would be anomalous   because it’s supposed to be a Domain Controller machine account performing a sync, not a user account.  
  Now you could elevate to SYSTEM as a domain controller and then run a DCSync attack which would make the account name look normal. So this is why we also flag the **GUIDs** as shown below.
- insert picture

2. **GUIDs**

  Next is flagging the **GUIDs**. As mentioned before, Mimikatz will generate 4 logs.  
  Logs 1 & 2 will look the same and have the same GUIDs. It will have a GUID of:
  `1131f6aa-9c07-11d1-f79f-00c04fc2dcd2` — _which is_ **DS-Replication-Get-Changes**
- insert pic
- insert pic

  Log 3 will look very different, however. It will not have a GUID beginning with `1131f6a` and instead will have `89e95b76-444d-4c62-991a-0facbeda640c` which is **DS-Replication-Get-Changes-In-Filtered-Set.**
- insert pic

  Log 4 will look very similar to Logs 1 & 2, but it will have a slightly different GUID. It will have a GUID of `1131f6ad-9c07-11d1-f79f-00c04fc2dcd2` which is **DS-Replication-Get-Changes-All**.
- insert pic


**Bonus Notes**

When performing a DCSync attack from outside of a domain controller, packets will be sent over the **DCERPC**, **EPM**, and **DRSUAPI** protocols.

![DCSync network traffic](/imgs/dcsync/dcsync-network-packets.png)

**However**, if you execute a DCSync attack while on a domain controller, it will perform everything locally with the domain controller and **no packets** with the protocols mentioned above will be sent.

### **Detecting Netexec’s DCSync**

There are 3 methods of performing a dcsync with netexec. 1. Using drsuapi to sync a single user, 2. ntdsutil.exe 3. vss.

1. **Drsuapi to sync a single user**
    
    The command to DCSync a single user with Netexec over the Drsuapu protocol is:
    
    `nxc smb 192.168.108.139 -u Administrator -d testlab.local -p 'P@ssw0rd' --ntds --user krbtgt`
    
    ![image.png](image%208.png)
    
    When using netexec to dump a specific user, it was generate 3 event id 4662 logs. The first 2 will have a normal GUID of `1131f6aa-9c07-11d1-f79f-00c04fc2dcd2`, which is *DS-Replication-Get-Changes*.
    
    ![image.png](image%209.png)
    
    ![image.png](image%2010.png)
    
    However the third generated log will have a GUID of `1131f6ad-9c07-11d1-f79f-00c04fc2dcd2` which is *DS-Replication-Get-Changes-All*.
    
    ![image.png](image%2011.png)
    
    Again we can look for non domain controller machine accounts too, just like the Mimikatz detection.
    
2. **ntdsutil.exe**
    
    Netexec can perform a DCSync by using the LOLBIN (living off the land binary) ntdsutil.exe. ntdsutil.exe is not a common utility run on the environment. It does not blend in with day to day activities.
    
    `nxc smb 192.168.1.100 -u UserName -p 'PASSWORDHERE' -M ntdsutil`
    
    ![image.png](image%2012.png)
    
    ![image.png](image%2013.png)
    
    This is the chain of events when running when running the -M ntdsutil command. To detect this we can look for process creation with event id 1 and the process.command_line as any of the below.
    
    ```c
    cmd.exe /Q /c powershell "ntdsutil.exe 'ac i ntds' 'ifm' 'create full C:\Windows\Temp\172963876' q q" 1> \Windows\Temp\QuGPmj 2>&1
    powershell "ntdsutil.exe 'ac i ntds' 'ifm' 'create full C:\Windows\Temp\172963876' q q"
    "C:\Windows\system32\ntdsutil.exe" "ac i ntds" ifm "create full C:\Windows\Temp\172963876" q q
    cmd.exe /Q /c rmdir /s /q C:\Windows\Temp\172963876 1> \Windows\Temp\vofITR 2>&1
    ```
    
    The first command executes the second which executes the third. The third created a directory called ‘172963876’ in C:\Windows\Temp and standard out was sent to a random file called vofITR with the following content below.
    
    ![image.png](image%2014.png)
    
    This file then gets deleted with the rmdir command, and another file gets created in its place. Additionally, the ‘172963876’ directory contains the ntds.dit and the SECURITY and SYSTEM registry keys. This entire directory will be deleted shortly after.
    
    ![image.png](image%2015.png)
    
    After the command is finished running, we will have the .tmp file and the new file with no extensions remaining. Both of these will have no contents in them.
    
    ![image.png](image%2016.png)
    
    Lastly, there will be lots of event id 4799 logs generated on the domain controller. (182 from my testing to be exact) with the process executable of either C:\Windows\System32\ntdsutil.exe or C:\Windows\System32\VSSVC.exe.
    
    ![image.png](image%2017.png)
    
    We can build another alert for this.
    
3. **Volume Shadow Copy Service (VSS)**
    
    Lastly Netexec has an option to dump ntds.dit with the volume shadow copy service (VSS) using the following command:
    
    `nxc smb 192.168.108.139 -u 'Administrator' -d testlab.local -p 'P@ssw0rd' --ntds vss`
    
    ![image.png](image%2018.png)
    
    Running this command will generate 2 logs. One event id `4904` and one `4905`. The process executable will be `C:\Windows\System32\VSSVC.exe`.
    
    ![image.png](image%2019.png)
    
    ![image.png](image%2020.png)
    
    Netexec will run this command on the box:
    
    ```c
    C:\Windows\system32\cmd.exe /Q /c echo C:\Windows\system32\cmd.exe /C vssadmin list shadows /for=C: ^> C:\Windows\Temp\__output > C:\Windows\TEMP\execute.bat & C:\Windows\system32\cmd.exe /Q /c C:\Windows\TEMP\execute.bat & del C:\Windows\TEMP\execute.bat
    ```
    
    Then it will also run this command to copy the the shadow copy to C:\Windows\Temp
    
    ```c
    C:\Windows\system32\cmd.exe  /C copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy23\Windows\NTDS\ntds.dit C:\Windows\Temp\yDBdCgmM.tmp 
    ```
    
    We can build a command line detection with the process command lines shown above and event code 1
    
    ![image.png](image%2021.png)
    

**Final DCSync detections:**

1. **Rule Name:** Single User DCSync - Mimikatz or Netexec
    
    **Detection Query:**
    
    ```elasticsearch
event.code:"4662" AND (NOT message:"*1131f6aa-9c07-11d1-f79f-00c04fc2dcd2*" OR user.name NOT LIKE "*$")
    ```
    
    **Rule Description:** This alert is the result of an event log id 4662 DCSync directory replication that doesn’t come from a machine account name, OR has a GUID in the properties not equal to `1131f6aa-9c07-11d1-f79f-00c04fc2dcd2`
    
2. **Rule Name:** Netexec Ntdsutil DCSync Module - Anomalous Event Logs
    
    **Detection Query:**
    
    `event.code:"4799" and (winlog.event_data.CallerProcessName:"C:\\Windows\\System32\\ntdsutil.exe" or winlog.event_data.CallerProcessName:"C:\\Windows\\System32\\VSSVC.exe")`
    
    **Rule Description:** This alert is the result of detected event logs that align with Netexec’s ntdsutil module to perform a DCSync attack by looking for event id 4799 with the process executable name of C:\Windows\System32\ntdsutil.exe or C:\Windows\System32\VSSVC.exe
    
3. **Rule Name:** Netexec Ntdsutil DCSync Module - Command Line Detection
    
    **Detection Query:**
    
    `event.code:"1" and ((message:"*cmd.exe /Q /c powershell \"ntdsutil.exe 'ac i ntds' 'ifm' 'create full C:\\Windows\\Temp\\*" and message:" q q\" 1> \\Windows\\Temp\\*" and message:"*2>&1*") or (message:"*powershell  \"ntdsutil.exe 'ac i ntds' 'ifm' 'create full C:\\Windows\\Temp\\*" and message:"*' q q\"*") or (message:"*\"C:\\Windows\\system32\\ntdsutil.exe\" \"ac i ntds\" ifm \"create full C:\\Windows\\Temp\\*" and message:"*\"q q") or (message:"*cmd.exe /Q /c rmdir /s /q C:\\Windows\\Temp\\*" and "*1> \\Windows\\Temp\\*" and "*2>&1*"))`
    
    **Rule Description:** This is another alert as a result of Netexec’s ntdsutil module to perform a DCSync attack by looking for process creation with event id 1 and the process.command_line as any of the below:
    
    ```c
    cmd.exe /Q /c powershell "ntdsutil.exe 'ac i ntds' 'ifm' 'create full C:\Windows\Temp\*' q q" 1> \Windows\Temp\* 2>&1
    powershell "ntdsutil.exe 'ac i ntds' 'ifm' 'create full C:\Windows\Temp\*' q q"
    "C:\Windows\system32\ntdsutil.exe" "ac i ntds" ifm "create full C:\Windows\Temp\*" q q
    cmd.exe /Q /c rmdir /s /q C:\Windows\Temp\* 1> \Windows\Temp\* 2>&1
    ```
    
4. **Rule Name:** Netexec Ntds VSS Option - Command Line Detection
    
    **Detection Query:**
    
    `event.code:"1" and (message:"*C:\\Windows\\system32\\cmd.exe /Q /c echo C:\\Windows\\system32\\cmd.exe /C vssadmin list shadows /for=C: ^> C:\\Windows\\Temp\\__output > C:\\Windows\\TEMP\\execute.bat & C:\\Windows\\system32\\cmd.exe /Q /c C:\\Windows\\TEMP\\execute.bat & del C:\\Windows\\TEMP\\execute.bat*" or message:"*C:\\Windows\\system32\\cmd.exe /Q /c C:\\Windows\\TEMP\\execute.bat*" or message:"*C:\\Windows\\system32\\cmd.exe /C vssadmin list shadows /for=C:*" or message:"*vssadmin  list shadows /for=C:*" or message:"*C:\\Windows\\system32\\vssvc.exe*" or (message:"*C:\\Windows\\system32\\cmd.exe /Q /c echo C:\\Windows\\system32\\cmd.exe /C copy \\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy23\\Windows\\NTDS\\ntds.dit C:\\Windows\\Temp\\*" and message:"*C:\\Windows\\Temp\\__output > C:\\Windows\\TEMP\\execute.bat & C:\\Windows\\system32\\cmd.exe /Q /c C:\\Windows\\TEMP\\execute.bat & del C:\\Windows\\TEMP\\execute.bat*") or message:"*C:\\Windows\\system32\\cmd.exe /Q /c C:\\Windows\\TEMP\\execute.bat*" or message:"*C:\\Windows\\system32\\cmd.exe /C copy \\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy23\\Windows\\NTDS\\ntds.dit C:\\Windows\\Temp\\*")`
    
    **Rule Description:** This alert is the result of Netexec’s VSS option to perform a DCSync attack by looking for process creation with event id 1 and the process.command_line as any of the below:
    
    ```c
    C:\Windows\system32\cmd.exe /Q /c echo C:\Windows\system32\cmd.exe /C vssadmin list shadows /for=C: ^> C:\Windows\Temp\__output > C:\Windows\TEMP\execute.bat & C:\Windows\system32\cmd.exe /Q /c C:\Windows\TEMP\execute.bat & del C:\Windows\TEMP\execute.bat
    C:\Windows\system32\cmd.exe  /C copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy23\Windows\NTDS\ntds.dit C:\Windows\Temp\*.tmp 
    ```
    
5. **Rule Name:** Netexec Ntds VSS Option - Event Log Detection
    
    **Detection Query:**
    
    `(event.code: 4904 OR event.code: 4905) AND process.executable: "C:\\Windows\\System32\\VSSVC.exe"`
    
    **Rule Description:** This is another alert as a result of Netexec’s VSS option to perform a DCSync attack by looking for generated event logs ID `4904` and `4905` with process executable name of `C:\Windows\System32\VSSVC.exe`

- Detects shadow copy creation via `VSSVC.exe`

---
