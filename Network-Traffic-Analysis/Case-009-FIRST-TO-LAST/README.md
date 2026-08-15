# 2026-08-09 - Traffic Analysis Exercise: FormBook / XLoader

## Overview

This investigation analyzes a packet capture (PCAP) from a Windows enterprise environment. The objective was to identify the infected host, determine the affected user, and investigate the malicious network activity associated with the provided SOC alerts.

The alerts identified **FormBook Command-and-Control (C2) check-in activity** beginning at approximately **02:13 UTC**.

During the investigation, the infected host was identified as `172.16.8.49`. DNS and HTTP traffic from this host was correlated with the external infrastructure identified in the alerts.

The exercise's analysis indicates that the malware is likely **XLoader**, a rebrand or successor to FormBook.

---

# Executive Summary

At approximately **02:13 UTC**, the Windows workstation `172.16.8.49` began generating network activity associated with FormBook/XLoader C2 communication.

The provided SOC alerts identified several external IP addresses as FormBook C2 infrastructure. During PCAP analysis, the victim was observed resolving `www.taibeinan.cc` through `bili003jiqun1.cdn.dun555.com` to `38.182.168.246`.

The IP address `38.182.168.246` directly matched one of the external IP addresses listed in the FormBook C2 alerts.

Additional suspicious HTTP activity was observed involving `www.grinswakebthu.info`, including repeated POST requests to `/irpw/` containing approximately 69 KB of form-encoded data.

The observed traffic is consistent with malware command-and-control communication and potential collection activity.

No malware executable or DLL was successfully extracted from the available PCAP.

---

# Victim Details

| Field | Value |
|--------|-------|
| Host Name | DESKTOP-5NLV63K |
| IP Address | 172.16.8.49 |
| MAC Address | 00:12:f0:28:d4:34 |
| Windows User | rvance |
| Full Name | Ryamond Vance |
| Domain | firsttolast.tech |

---

# Investigation Process

## 1. Victim Identification

The suspected infected workstation was identified by correlating the internal traffic with the FormBook C2 alerts.

The victim IP address was:

172.16.8.49

The MAC address was identified as:

00:12:f0:28:d4:34

Further analysis of Windows authentication and directory-related traffic revealed:

Host Name: DESKTOP-5NLV63K
Windows User: rvance
Full Name: Ryamond Vance

---

## 2. FormBook C2 Alert Correlation

The provided SOC alerts reported FormBook C2 check-ins to several external IP addresses beginning around 02:13 UTC.

Observed alert IP addresses included:

172.64.155.76
146.59.71.167
38.182.168.246
45.130.41.161
172.67.162.153
121.54.163.148

The PCAP investigation was then used to determine whether the suspected victim communicated with this infrastructure.
---

## 3. DNS Investigation

A DNS query from the suspected victim was identified for:

www.taibeinan.cc

The DNS response revealed the following resolution chain:

www.taibeinan.cc
        ↓
bili003jiqun1.cdn.dun555.com
        ↓
38.182.168.246

The final IP address:

38.182.168.246

matched one of the external IP addresses identified in the FormBook C2 alerts.

This provided a direct correlation between the PCAP traffic and the SOC alert.
---

## 4. Suspicious HTTP Traffic

Additional HTTP traffic from the victim was observed involving:

www.grinswakebthu.info

One of the significant requests was:

POST /irpw/ HTTP/1.1
Host: www.grinswakebthu.info
Origin: http://www.grinswakebthu.info
Content-Type: application/x-www-form-urlencoded
Content-Length: 69101

The POST body contained a large encoded-looking parameter.

The approximately 69 KB HTTP POST request was considered suspicious because it occurred during the same period as the confirmed FormBook/XLoader C2 activity.

Repeated irpw HTTP objects were also observed in Wireshark.
---

## 5. C2 Communication

The combination of the supplied alerts and PCAP evidence provides a strong C2 correlation.

The observed communication can be summarized as:

172.16.8.49
     |
     | DNS
     ↓
www.taibeinan.cc
     |
     ↓
bili003jiqun1.cdn.dun555.com
     |
     ↓
38.182.168.246
     |
     ↓
FormBook/XLoader C2

The external IP 38.182.168.246 was one of the IP addresses explicitly identified by the provided SOC alert.

---

## 6. HTTP Object Analysis

Wireshark's HTTP object export was examined for potentially malicious files.

Observed HTTP objects included:

connecttest.txt
irpw
lqjm
8nw8

The repeated irpw objects were associated with the suspicious HTTP POST traffic.

No obvious malware executable or DLL was identified from the HTTP objects examined.

---

## 7. SMB Object Analysis

SMB objects were also examined.

Observed files included:

gpt.ini
GptTmpl.inf
Registry.pol
Customer Contact List.xlsx
Quarterly Sales Report.xlsx

No obvious malware executable was identified from the SMB objects examined.

The traffic involving 172.16.8.53 was associated with a separate Windows host and normal Windows/domain-controller activity rather than the identified infected workstation.

Indicators of Compromise (IOCs)
Victim
Hostname: DESKTOP-5NLV63K
Windows User: rvance
Full Name: Ryamond Vance
IP Address: 172.16.8.49
MAC Address: 00:12:f0:28:d4:34
External C2 IP Addresses
172.64.155.76
146.59.71.167
38.182.168.246
45.130.41.161
172.67.162.153
121.54.163.148
Domains
www.taibeinan.cc
bili003jiqun1.cdn.dun555.com
www.grinswakebthu.info
HTTP Endpoint
POST /irpw/

Host:

www.grinswakebthu.info
Attack Timeline
~02:13 UTC
First FormBook C2 alert observed.
Victim workstation identified as 172.16.8.49.

↓

02:13–02:16 UTC
Multiple FormBook C2 check-in alerts generated.
External C2 infrastructure included 38.182.168.246.

↓

During investigation
DNS query for www.taibeinan.cc identified.
DNS resolution led to bili003jiqun1.cdn.dun555.com.
The domain resolved to 38.182.168.246.

↓

Following C2 activity
Suspicious HTTP communication to www.grinswakebthu.info observed.
Repeated POST requests to /irpw/ were identified.
Large approximately 69 KB form-encoded POST data was observed.

↓

Post-compromise activity
Continued HTTP communication with suspicious external infrastructure.
C2 activity was consistent with FormBook/XLoader behavior.

---

## MITRE ATT&CK Mapping

| Tactic              | Technique                                 | ID        | Evidence / Relevance                                                                      |
| ------------------- | ----------------------------------------- | --------- | ----------------------------------------------------------------------------------------- |
| Command and Control | Application Layer Protocol: Web Protocols | T1071.001 | HTTP-based C2 communication and FormBook/XLoader check-ins were observed.                 |
| Collection          | Browser Session Hijacking                 | T1185     | Relevant to documented XLoader/FormBook session and browser-data collection capabilities. |
| Collection          | Clipboard Data                            | T1115     | Relevant to documented XLoader/FormBook collection capabilities.                          |
| Credential Access   | Credentials from Web Browsers             | T1555.003 | Relevant to documented XLoader/FormBook browser credential collection capabilities.       |
| Discovery           | System Information Discovery              | T1082     | Relevant to documented malware system-information collection capabilities.                |
| Discovery           | System Owner/User Discovery               | T1033     | Relevant to the malware obtaining information about the logged-in user.                   |

---

## Malware Identification

The provided SOC alerts identified the activity as:

ET MALWARE FormBook CnC Checkin

Further analysis associated the activity with XLoader, which is described in the exercise analysis as a rebrand or successor to FormBook.

Therefore, the malware is documented as:

FormBook / XLoader

Malware File and SHA256

Wireshark HTTP and SMB objects were examined for malware binaries.

No obvious malware executable or DLL was successfully extracted from the available PCAP.

Therefore:

Malware File: Not recovered
SHA256: Not available

No external malware hash was included because no malware binary was extracted from this PCAP.
---

## Conclusion

The packet capture provides evidence that the Windows workstation DESKTOP-5NLV63K at 172.16.8.49 was infected with malware associated with FormBook/XLoader.

The strongest evidence was the correlation between the provided SOC alerts and the PCAP. The victim resolved www.taibeinan.cc through bili003jiqun1.cdn.dun555.com to 38.182.168.246, which directly matched one of the FormBook C2 IP addresses listed in the alerts.

Additional suspicious HTTP POST traffic to www.grinswakebthu.info/irpw/ was observed, including a large approximately 69 KB request.

No malware binary was successfully recovered from the PCAP, so no malware SHA256 hash was available.

Overall, the observed network traffic is consistent with an active FormBook/XLoader command-and-control infection.

---

## Skills Practiced

Wireshark packet analysis
SOC alert correlation
Victim identification
DNS analysis
HTTP analysis
Command-and-Control detection
Malware traffic analysis
HTTP object extraction
SMB object analysis
IOC extraction
Incident timeline construction
MITRE ATT&CK mapping
Incident reporting