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




