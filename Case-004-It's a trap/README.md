# Case 004 - It's a Trap! (Traffic Analysis Opportunity)

> **Platform:** Malware-Traffic-Analysis.net
>
> **Exercise Date:** 2025-06-13
>
> **Difficulty:** Intermediate
>
> **Category:** Incident Response / Malware Traffic Analysis / DFIR

---

# Objective

Investigate a packet capture (PCAP) and supporting forensic artifacts to identify the compromised Windows workstation, analyze the infection chain, and understand the post-exploitation network activity.

Unlike previous exercises, this case does not provide official answers and instead encourages analysts to reconstruct the incident using both network traffic and forensic evidence.

---

# Scenario

A Windows workstation on the internal network accessed a compromised website that delivered malicious JavaScript, which executed PowerShell to download a second-stage payload.

The objective of this investigation was to:

- Identify the compromised Windows workstation
- Identify the associated Windows user
- Reconstruct the infection chain
- Identify the malware delivery infrastructure
- Correlate browser cache artifacts with network traffic

---

# Environment

| Item | Value |
|------|-------|
| LAN Range | 10.6.13.0/24 |
| Domain | massfriction.com |
| Active Directory | MASSFRICTION |
| Domain Controller | WIN-DQL4WFWJXQ4 (10.6.13.3) |
| Gateway | 10.6.13.1 |

---

# Initial Investigation

Since no Indicators of Compromise (IOCs) were provided, the investigation began by reviewing network statistics.

Using:

```
Statistics
    └── Conversations
```

revealed an internal host generating unusual communication with several external domains.

Primary suspect:

```
10.6.13.133
```

---

# Investigation Process

## Step 1 - Identify Suspicious Infrastructure

Multiple suspicious domains were observed during the investigation:

```
dng-microsoftds.com
hillcoweb.com
www.truglomedspa.com
```

Initial review suggested these domains were involved in different stages of the infection.

---

## Step 2 - Analyze Browser Activity

TLS traffic was reviewed using the following filter:

```wireshark
ip.addr == 10.6.13.133 &&
tls.handshake.extensions_server_name contains "truglomedspa.com"
```

This confirmed that the workstation communicated with:

```
www.truglomedspa.com
```

---

## Step 3 - Correlate Browser Cache

Supporting forensic artifacts contained browser cache entries showing multiple resources downloaded from:

```
https://www.truglomedspa.com
```

Examples included:

- CSS files
- Cached website resources
- Web page artifacts

These cache entries confirmed that the user successfully browsed the website rather than merely attempting a connection.

---

## Step 4 - Analyze Malicious JavaScript

One recovered JavaScript file contained an embedded PowerShell downloader.

Important observations:

### Stage 1

```javascript
window.path='truglomedspa.com'
```

indicating the compromised website.

---

### Stage 2

The JavaScript constructed the following URL:

```
https://dng-microsoftds.com/Gsdg4976.txt
```

PowerShell then executed:

```powershell
DownloadString(...)
```

followed by:

```powershell
iex
```

indicating execution of a remotely hosted payload.

---

### Stage 3

Another variable referenced:

```
https://hillcoweb.com/stat.php
```

This appears to be related to post-exploitation communication or malware reporting.

---

## Step 5 - Identify the Victim

Windows authentication traffic identified the compromised workstation.

| Item | Value |
|------|-------|
| Victim IP | 10.6.13.133 |
| Hostname | DESKTOP-5AVE44C |
| MAC Address | 24:77:03:ac:97:df |
| User | Roman Gaines |

---

# Evidence Correlation

The victim was identified using multiple independent sources.

### Network Traffic

TLS traffic showed:

```
10.6.13.133
        ↓
www.truglomedspa.com
```

---

### Browser Cache

Recovered browser cache confirmed resources were downloaded from:

```
https://www.truglomedspa.com
```

---

### Windows Authentication

Kerberos traffic identified the workstation:

```
DESKTOP-5AVE44C
```

and the associated Windows user:

```
Roman Gaines
```

---

# Infection Chain

```
User Browses
        │
        ▼
www.truglomedspa.com
        │
        ▼
Malicious JavaScript
        │
        ▼
PowerShell
        │
        ▼
DownloadString()
        │
        ▼
https://dng-microsoftds.com/Gsdg4976.txt
        │
        ▼
Invoke-Expression (iex)
        │
        ▼
Post-Infection Communication
        │
        ▼
hillcoweb.com/stat.php
```

---

# Indicators of Compromise (IOCs)

## Victim

| Item | Value |
|------|-------|
| IP Address | 10.6.13.133 |
| MAC Address | 24:77:03:ac:97:df |
| Hostname | DESKTOP-5AVE44C |
| User | Roman Gaines |

---

## Malicious Infrastructure

| Type | Value |
|------|-------|
| Initial Website | www.truglomedspa.com |
| Stage 2 Payload | https://dng-microsoftds.com/Gsdg4976.txt |
| Possible C2 / Reporting | https://hillcoweb.com/stat.php |

---

# Detection Techniques Used

- Conversation Analysis
- TLS SNI Analysis
- Browser Cache Analysis
- JavaScript Analysis
- PowerShell Analysis
- Kerberos Investigation
- IOC Correlation
- Evidence Correlation

---

# Lessons Learned

This exercise emphasized reconstructing an incident using multiple evidence sources instead of relying on a single protocol.

Key takeaways:

- Start investigations by understanding overall communication patterns instead of immediately applying protocol-specific filters.
- Browser cache artifacts provide valuable confirmation that a user accessed and downloaded content from a website.
- TLS Server Name Indication (SNI) can reveal visited domains even when HTTP traffic is unavailable.
- Malicious JavaScript often exposes the complete execution chain, including PowerShell downloaders and second-stage payloads.
- Correlating network traffic with forensic artifacts significantly increases confidence in investigation findings.
- Multiple independent sources should always be used to validate conclusions during incident response.

---

# Skills Practiced

- Wireshark
- Malware Traffic Analysis
- Browser Forensics
- IOC Pivoting
- PowerShell Analysis
- JavaScript Analysis
- TLS Analysis
- Kerberos Analysis
- Incident Response
- Digital Forensics
- Evidence Correlation

---

# Evidence

Recommended screenshots:

- Statistics → Conversations
- TLS SNI showing truglomedspa.com
- Browser cache entries
- Malicious JavaScript
- PowerShell DownloadString()
- Kerberos showing DESKTOP-5AVE44C
- Final IOC summary

---

# Analyst Reflection

This was the first investigation that combined network traffic with forensic artifacts instead of relying solely on packet analysis.

Rather than answering predefined questions, the investigation focused on reconstructing the attack chain by correlating browser cache, TLS traffic, PowerShell execution, JavaScript, and Windows authentication artifacts. This approach closely resembles real-world SOC and DFIR investigations, where conclusions are built from multiple independent sources of evidence rather than a single indicator.