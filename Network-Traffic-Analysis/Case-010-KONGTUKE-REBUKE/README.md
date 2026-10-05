# 2026-09-11 - Traffic Analysis Exercise: KONGTUKE REBUKE!

## Overview

This investigation analyzes a packet capture (PCAP) from a Windows enterprise environment. The objective was to identify the infected Windows client, determine the affected user, and investigate suspicious network activity associated with the identified workstation.

The exercise required identifying the following information:

- Infected Windows client IP address
- MAC address
- Hostname
- Windows user account
- Full name of the user

During the investigation, the infected host was identified as `10.9.11.135`.

Further analysis of the PCAP revealed suspicious DNS and HTTP activity involving multiple unusual external domains and repeated binary HTTP communications originating from the identified workstation.

---

## Executive Summary

The infected Windows workstation was identified as `10.9.11.135`.

Network traffic was analyzed using Wireshark to correlate the workstation's IP address with its MAC address, hostname, Windows user account, and full name.

The identified victim was:

| Field | Value |
|---|---|
| IP Address | `10.9.11.135` |
| MAC Address | `08:d4:0c:7a:29:1e` |
| Hostname | `DESKTOP-6T17ZFM` |
| Windows User | `gmcdowell` |
| Full Name | `Gabriel McDowell` |

Additional analysis identified suspicious DNS and HTTP traffic involving domains such as `know.mom-nower.com` and `second.bert-hits.com`.

Repeated HTTP GET and POST requests containing binary-looking data were observed between the infected workstation and external infrastructure.

The primary objective of this exercise was host and user identification. The additional traffic analysis was performed to understand the surrounding suspicious activity.

---

## Lab Environment

| Field | Value |
|---|---|
| Internal Network | `10.9.11.0/24` |
| Domain | `overhands.org` |
| AD Environment | `OVERHANDS` |
| Domain Controller IP | `10.9.11.2` |
| Domain Controller Hostname | `WIN-GTWXC9UYSE4` |
| Gateway | `10.9.11.1` |
| Broadcast | `10.9.11.255` |
| Tool | Wireshark |

---

## Victim Details

| Field | Value |
|---|---|
| Host Name | `DESKTOP-6T17ZFM` |
| IP Address | `10.9.11.135` |
| MAC Address | `08:d4:0c:7a:29:1e` |
| Windows User | `gmcdowell` |
| Full Name | `Gabriel McDowell` |
| Domain | `overhands.org` |

---

## Investigation Process

### 1. Victim Identification

The investigation began by examining traffic inside the `10.9.11.0/24` network.

The Domain Controller was identified as:

`10.9.11.2 - WIN-GTWXC9UYSE4`

Traffic involving internal hosts was then reviewed to identify the workstation associated with the suspicious activity.

The infected Windows client was identified as:

`10.9.11.135`

---

### 2. MAC Address Identification

After identifying the suspected workstation IP address, network traffic was reviewed to correlate the IP address with the workstation's MAC address.

The identified MAC address was:

`08:d4:0c:7a:29:1e`

This provided the hardware-level identity of the suspected endpoint.

---

### 3. Hostname Identification

Browser/NetBIOS-related traffic was examined to determine the Windows hostname associated with the identified IP address.

The following Wireshark display filter was useful:

`browser.response_computer_name`

The hostname was identified as:

`DESKTOP-6T17ZFM`

---

### 4. Windows User Identification

Kerberos authentication traffic was analyzed to identify the Windows account associated with the workstation.

The following Wireshark display filter was used:

`kerberos.cname_string == 1`

The Windows account was identified as:

`gmcdowell`

---

### 5. Full Name Identification

SAMR traffic was examined to retrieve additional Windows account information.

The following Wireshark field was used:

`samr.samr_UserInfo21.full_name`

The full name associated with the Windows account was:

`Gabriel McDowell`

---

## Suspicious Network Traffic

After identifying the infected workstation, traffic originating from `10.9.11.135` was examined further.

Several unusual domains were observed in DNS and HTTP traffic.

Examples included:

| Suspicious Domain |
|---|
| `know.mom-nower.com` |
| `second.bert-hits.com` |
| `gets.bert-hits.com` |
| `www.bert-hits.com` |
| `hyko.fif-lost.com` |
| `stream.fif-lost.com` |
| `now.comonto-rsr.com` |
| `start.comonto-rsr.com` |
| `firt.comonto-rsr.com` |

These domains were investigated as part of the network traffic analysis.

---

## DNS Investigation

DNS queries originating from the identified workstation were filtered using:

`ip.addr == 10.9.11.135 && dns && dns.flags.response == 0`

A notable DNS query was observed for:

`second.bert-hits.com`

The DNS response resolved the domain to:

`146.70.139.165`

The resulting communication was then investigated using:

`ip.addr == 10.9.11.135 && ip.addr == 146.70.139.165 && http`

---

## HTTP Investigation

HTTP traffic involving the identified workstation was examined using:

`ip.addr == 10.9.11.135 && http`

Repeated HTTP communication was observed between the workstation and suspicious external infrastructure.

One observed communication involved:

`10.9.11.135 → 146.70.139.165`

The requests included repeated POST activity with randomized-looking URIs and a long identifier:

`99099296646b5ffb8188092fb5030b7890c1de2d6a058cab178d4548c4dca1ab`

Some requests contained:

`Content-Type: application/octet-stream`

Binary-looking request bodies were observed.

A 75-byte POST request received:

`HTTP/1.1 406 Not Acceptable`

with:

`content-length: 0`

A larger approximately 26 KB POST request received:

`HTTP/1.1 400 Bad Request`

with:

`content-length: 0`

These transactions did not provide evidence of a successful payload download.

---

## HTTP Communication with know.mom-nower.com

Another significant domain observed during the investigation was:

`know.mom-nower.com`

The domain resolved to:

`86.106.87.134`

HTTP traffic involving the domain showed repeated GET and POST communication from the infected workstation.

One observed POST request contained:

`POST /3o/q8ays8j9z&4a0fd955c05d43841a9a8d921ceec63b0dc5b431a9fb54b33ad7848707bc16e9/6eqjs5617i HTTP/1.1`

`Host: know.mom-nower.com`

`Content-Type: application/octet-stream`

The request also contained session-related cookies and a binary request body.

The server returned:

`HTTP/1.1 200 OK`

with a binary-looking response body.

---

## Binary HTTP Response

Another HTTP GET request to `know.mom-nower.com` returned:

`HTTP/1.1 200 OK`

with:

`content-length: 187`

The response body began with:

`1f 8b 08`

The response therefore appeared to contain compressed/binary data.

The transaction was documented as suspicious binary HTTP communication. The exact contents and purpose of the response were not established during this investigation.

---

## Server Response Analysis

Traffic from:

`86.106.87.134`

to:

`10.9.11.135`

was also reviewed.

The server generated repeated responses including:

- `HTTP/1.1 204 No Content`
- `HTTP/1.1 200 OK`
- `HTTP/1.1 400 Bad Request`
- `HTTP/1.1 406 Not Acceptable`

The repeated communication pattern indicated automated HTTP communication between the workstation and the external server.

However, the exact malware functionality responsible for the traffic was not established from the available evidence.

---

## Key Wireshark Filters

### Domain Controller Identification

`browser.command == 0x0f`

### Hostname Identification

`browser.response_computer_name`

### Windows Account Identification

`kerberos.cname_string == 1`

### Full Name Identification

`samr.samr_UserInfo21.full_name`

### Investigate Victim

`ip.addr == 10.9.11.135`

### DNS Traffic

`ip.addr == 10.9.11.135 && dns`

### DNS Queries

`ip.addr == 10.9.11.135 && dns && dns.flags.response == 0`

### HTTP Traffic

`ip.addr == 10.9.11.135 && http`

### HTTP Requests

`ip.addr == 10.9.11.135 && http.request`

### HTTP POST Requests

`ip.addr == 10.9.11.135 && http.request.method == "POST"`

### Specific Suspicious Domain

`http.host == "know.mom-nower.com"`

### Specific External IP

`ip.addr == 10.9.11.135 && ip.addr == 146.70.139.165 && http`

---

## Indicators of Compromise (IOCs)

### Victim

| Type | Value |
|---|---|
| IP Address | `10.9.11.135` |
| MAC Address | `08:d4:0c:7a:29:1e` |
| Hostname | `DESKTOP-6T17ZFM` |
| Windows User | `gmcdowell` |
| Full Name | `Gabriel McDowell` |
| Domain | `overhands.org` |

### Suspicious Domains

| Domain |
|---|
| `know.mom-nower.com` |
| `second.bert-hits.com` |
| `gets.bert-hits.com` |
| `www.bert-hits.com` |
| `hyko.fif-lost.com` |
| `stream.fif-lost.com` |
| `now.comonto-rsr.com` |
| `start.comonto-rsr.com` |
| `firt.comonto-rsr.com` |

### Suspicious IP Addresses

| IP Address | Context |
|---|---|
| `146.70.139.165` | Resolved from `second.bert-hits.com` |
| `86.106.87.134` | Resolved from `know.mom-nower.com` |

### Observed HTTP Characteristics

| Indicator | Observation |
|---|---|
| Content Type | `application/octet-stream` |
| HTTP Methods | GET / POST |
| Response Codes | `200`, `204`, `400`, `406` |
| Binary Data | Observed in HTTP request/response bodies |

---

## Investigation Timeline

| Stage | Activity |
|---|---|
| Initial Analysis | Internal network `10.9.11.0/24` identified and Domain Controller located at `10.9.11.2`. |
| Victim Identification | Suspicious Windows client identified as `10.9.11.135`. |
| Host Correlation | MAC address identified as `08:d4:0c:7a:29:1e`. |
| Hostname Identification | Hostname identified as `DESKTOP-6T17ZFM`. |
| User Identification | Windows account identified as `gmcdowell`. |
| User Correlation | Full name identified as `Gabriel McDowell`. |
| DNS Analysis | Suspicious domains including `second.bert-hits.com` and `know.mom-nower.com` were observed. |
| DNS Resolution | `second.bert-hits.com` resolved to `146.70.139.165`. |
| HTTP Analysis | Repeated GET/POST traffic to suspicious external infrastructure was identified. |
| Binary Traffic | HTTP requests and responses containing binary-looking data were observed. |
| Final Assessment | The workstation was identified as the infected client and suspicious automated external communication was documented. |

---

## MITRE ATT&CK Mapping

| Tactic | Technique | ID | Evidence / Relevance |
|---|---|---|---|
| Command and Control | Application Layer Protocol: Web Protocols | T1071.001 | Repeated HTTP communication with suspicious external infrastructure was observed. |
| Discovery | System Owner/User Discovery | T1033 | Windows account information was identified during the investigation. |
| Discovery | System Information Discovery | T1082 | Hostname and system-related information were identified during the investigation. |

> These mappings describe techniques relevant to the observed traffic and investigation process. They do not independently prove that a specific malware family executed each technique.

---

## Malware Identification

The exercise primarily focused on identifying the infected Windows client and associated user information.

The observed traffic contained suspicious automated HTTP communication, binary request/response bodies, and multiple unusual external domains.

However, the available PCAP analysis did not provide enough evidence to confidently identify the exact malware family or determine the precise functionality of every observed HTTP transaction.

Therefore:

| Field | Result |
|---|---|
| Malware Family | Not conclusively identified |
| Malware Binary | Not recovered |
| SHA256 | Not available |

No external malware hash was included because no malware binary was extracted from the PCAP.

---

## Conclusion

The packet capture analysis successfully identified the infected Windows workstation and the associated user.

The identified endpoint was:

| Field | Finding |
|---|---|
| IP Address | `10.9.11.135` |
| MAC Address | `08:d4:0c:7a:29:1e` |
| Hostname | `DESKTOP-6T17ZFM` |
| Windows User | `gmcdowell` |
| Full Name | `Gabriel McDowell` |

Further investigation revealed suspicious DNS and HTTP activity involving multiple unusual domains, including:

- `know.mom-nower.com`
- `second.bert-hits.com`
- `gets.bert-hits.com`
- `www.bert-hits.com`
- `hyko.fif-lost.com`

The workstation communicated with external IP addresses including:

- `146.70.139.165`
- `86.106.87.134`

Repeated HTTP GET and POST requests containing binary-looking data were observed.

The exercise's primary objective was host and user identification. The additional network analysis helped establish the suspicious nature of the workstation's external communications, but the exact malware family and functionality were not conclusively established from the PCAP alone.

No malware executable was recovered, so no malware SHA256 hash was available.

---

## Skills Practiced

- PCAP Analysis
- Wireshark
- Network Traffic Analysis
- Victim Identification
- MAC Address Correlation
- Hostname Identification
- Windows User Identification
- Kerberos Analysis
- SAMR Analysis
- DNS Analysis
- HTTP Analysis
- Suspicious Domain Identification
- IOC Extraction
- C2 Traffic Investigation
- Binary HTTP Traffic Analysis
- SOC Investigation Methodology
- Evidence-Based Analysis
- Incident Documentation
- MITRE ATT&CK Mapping

---

## Reference

**Exercise:** KONGTUKE REBUKE!

**Source:** Malware-Traffic-Analysis.net

The exercise PCAP and additional materials were provided as part of the training exercise.
