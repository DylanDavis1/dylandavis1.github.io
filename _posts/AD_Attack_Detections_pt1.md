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

### 💡 Detection Rule

- **Rule Name:** Kerbrute Password Spray
- **Query:**

```elasticsearch
winlog.event_data.TicketOptions: "0x10" AND winlog.event_id: "4768"
```

- **Description:** Flags Kerberos TGT requests with an abnormal `TicketOptions` value of `0x10`, which is commonly seen during password spraying with Kerbrute.
```
