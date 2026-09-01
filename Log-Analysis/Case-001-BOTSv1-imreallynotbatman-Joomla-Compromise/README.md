# Incident Investigation: Web Application Compromise of imreallynotbatman.com

**Dataset:** Splunk BOTSv1 (Boss of the SOC v1)
**Threat Actor:** Po1s0n1vy APT Group
**Tools Used:** Splunk (SPL), Suricata IDS logs, Splunk Stream (`stream:http`), Sysmon
**Analyst:** [Your Name]

## Summary

An external threat actor conducted reconnaissance, exploitation, and a successful compromise
against `imreallynotbatman.com`, a Joomla-based web application hosted at `192.168.250.70`.
The attacker gained administrative access, uploaded a web shell and a malicious executable via
a vulnerable Joomla component, executed the binary on the host, and defaced the website.

This report documents the investigation from initial detection through to confirmed impact,
using only evidence pulled directly from network and host logs — every claim below is backed
by a specific log entry, not assumption.

## Key Findings

| Finding | Value |
|---|---|
| Reconnaissance IP | `40.80.148.42` |
| Brute-force IP | `23.22.63.114` |
| Target host | `192.168.250.70` (`imreallynotbatman.com`) |
| CMS | Joomla |
| Scanning tool identified | Acunetix Web Vulnerability Scanner (Free Edition) v10.0 |
| First brute-force password attempted | `12345678` |
| Correct admin password (cracked) | `batman` |
| IP that reused the cracked credential to log in | `40.80.148.42` |
| Malicious files uploaded | `3791.exe`, `agent.php` |
| MD5 hash of `3791.exe` | `AAE3F5A29935E6ABCC2C2754D12A9AF0` |
| Vulnerable components exploited | `com_installer`, `com_extplorer` |
| Defacement file | `poisonivy-is-coming-for-you-batman.jpeg` |
| Defacement resource domain | `prankglassinebracket.jumpingcrab.com` |
| Defacement domain resolved IP | `23.22.63.114` |
| Attributed group | Po1s0n1vy |

## Investigation Timeline & Methodology

### 1. Identifying the Reconnaissance Actor

Suricata IDS alerts were reviewed to identify anomalous external traffic:

```spl
index=botsv1 sourcetype=suricata
| stats count by src_ip
| sort -count
```

Filtering to external (non-RFC1918) IPs and cross-referencing alert signatures confirmed
`40.80.148.42` as the source of a broad, automated vulnerability scan:

```spl
index=botsv1 sourcetype=suricata src_ip=40.80.148.42 event_type=alert
| stats count by alert.signature
| sort -count
```

The signature `ET SCAN Acunetix Version 6 (Free Edition) Scan Detected`, combined with the
`Acunetix-Product` HTTP header present in raw request headers, confirmed the tool in use.

### 2. Scoping the Target Application

```spl
index=botsv1 sourcetype=suricata dest_ip=192.168.250.70 event_type=alert
| stats count by http.hostname, http.url
```

URL patterns (`/joomla/index.php/component/search/...`, `/joomla/administrator/...`) confirmed
the target as a **Joomla CMS** installation.

### 3. Validating Exploitation Attempts (SQLi, XSS, Shellshock)

Rather than trusting IDS alert names at face value, each attack category was validated against
the actual server response:

- **SQL Injection (time-based blind):** Payloads used `SLEEP()`/`pg_sleep()` functions.
  Response times were measured directly from `stream:http` (`response_time` field, in
  microseconds) and found to be sub-millisecond — proving the injected delay never executed.
  Joomla's `com_search` component instead threw HTTP 500 errors, mangling the payload into an
  invalid view name.
- **Cross-Site Scripting:** Payloads (`<script>`, `onmouseover=`) were found reflected back in
  responses **still percent-encoded** (e.g. `%3Cscript%3E`), confirming the browser would never
  render them as executable HTML.
- **Shellshock (CVE-2014-6271):** All attempts against `/cgi-bin/*` paths returned HTTP 404.
  The target server (Microsoft IIS) has no CGI/Bash execution path, making this exploit
  structurally inapplicable regardless of patch status.

**Conclusion:** these three attack classes were attempted but did not succeed.

### 4. Identifying the Brute-Force Attack

A second external IP was found submitting rapid POST requests to the Joomla admin login:

```spl
index=botsv1 sourcetype=stream:http dest_ip=192.168.250.70 http_method=POST uri="*administrator*"
| table _time, form_data, http_user_agent, status
```

- Source: `23.22.63.114`
- User-Agent: `Python-urllib/2.7` (confirms scripted, non-browser automation)
- Technique: dictionary attack against `username=admin`, cycling common weak passwords
- First password attempted (chronologically earliest): `12345678`
- 412 total attempts recorded

The correct password was extracted by pulling every submitted `passwd` value out of `form_data`
and grouping by both password and source IP:

```spl
index=botsv1 sourcetype=stream:http dest_ip=192.168.250.70 http_method=POST uri=/joomla/administrator/index.php
| rex field=form_data "passwd=(?<password>\w+)"
| stats count by password, src_ip
| sort -count
```

This revealed the correct password, **`batman`**, appearing twice — once from `23.22.63.114`
(as just one guess among hundreds in the dictionary) and again from **`40.80.148.42`**, the same
IP previously identified as the Acunetix reconnaissance source. This is a significant finding:
the actor split roles across their infrastructure — `23.22.63.114` handled the automated
credential-cracking, while `40.80.148.42` reused the cracked credential to perform an
authenticated, manual login and carry out the actual exploitation that followed.

### 5. Confirming Successful Compromise

The initial hypothesis — that a distinct HTTP response would mark a successful login — did not
hold up under testing; Joomla's redirect behavior was not reliably distinguishable at the
network layer for this dataset. The actual proof of compromise was found further along the
attack chain: an **authenticated file upload**.

```spl
index=botsv1 sourcetype=stream:http dest_ip=192.168.250.70 http_method=POST "multipart/form-data" "*.exe"
| table _time, src_ip, uri, form_data
```

This uncovered a request to:
```
/joomla/administrator/index.php?option=com_extplorer&tmpl=component
```

Sent using a **valid, authenticated session cookie**, uploading two files simultaneously:
- `3791.exe` — a Windows PE executable (confirmed via `MZ`/`PE` binary headers in the raw
  request body)
- `agent.php` — a web shell

The server responded:
```json
{"action":"upload","message":"Upload successful!","error":"Upload successful!","success":true}
```

A separate, earlier request also showed a second vulnerable component exploited
(`com_installer`), used to deliver a heavily obfuscated PHP payload — the obfuscation
technique (splitting strings across dozens of variables, reconstructing function names like
`create_function` at runtime) was specifically designed to evade signature-based detection,
explaining why it did not trigger any Suricata alert.

### 6. Confirming Execution on the Host

Sysmon logs on the affected server (`we1149srv.waynecorpinc.local`) were queried directly for
the uploaded filename:

```spl
index=botsv1 "3791.exe" sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
```

Result: Sysmon **EventID 5 (Process Terminated)** for:
```
Image: C:\inetpub\wwwroot\joomla\3791.exe
```

This confirms the uploaded binary was not just written to disk — it executed on the host.
A further search against Sysmon process-creation events (EventCode=1) recovered the file hash:

```
MD5: AAE3F5A29935E6ABCC2C2754D12A9AF0
```

This hash can be used to pivot to threat intelligence sources (e.g. VirusTotal) to identify
the malware family and confirm known-malicious status.

## Attack Chain Summary

```
Reconnaissance (Acunetix scan, 40.80.148.42)
        │
        ├── SQLi / XSS / Shellshock attempts → FAILED (input sanitization / platform mismatch)
        │
        ▼
Brute-force admin login (23.22.63.114, dictionary attack, Python-urllib)
        │
        ▼
Authenticated session obtained
        │
        ▼
Exploitation of com_installer (obfuscated PHP payload) and com_extplorer (file upload)
        │
        ▼
Upload of 3791.exe + agent.php (webshell) → confirmed via server "success":true response
        │
        ▼
Execution of 3791.exe on host (confirmed via Sysmon EventID 5)
        │
        ▼
Website defacement (image pulled from prankglassinebracket.jumpingcrab.com)
```

## Lessons / Analyst Notes

- **IDS alerts confirm attempts, not success.** Every "Possible" or "Attempt" signature in
  this investigation required direct verification against server response content and timing
  before being treated as evidence of compromise.
- **Absence of an IDS alert does not mean absence of an attack.** The brute-force login and the
  `com_installer` web shell delivery generated no Suricata alerts at all — both were only found
  by directly inspecting HTTP transaction logs.
- **The real compromise vector differed from the most heavily-alerted one.** The largest volume
  of alerts came from the automated Acunetix scan, which ultimately failed. The actual breach
  came through a lower-noise, targeted exploitation of file-upload functionality.

## MITRE ATT&CK Mapping

| Stage | Tactic | Technique | Evidence |
|---|---|---|---|
| Reconnaissance | TA0043 | T1595.002 – Vulnerability Scanning | Acunetix traffic, Suricata alert |
| Initial Access (failed) | TA0001 | T1190 – Exploit Public-Facing Application | SQLi/XSS/Shellshock attempts |
| Credential Access | TA0006 | T1110.001 – Password Guessing | 412 brute-force POSTs, `23.22.63.114` |
| Initial Access (successful) | TA0001 | T1190 – Exploit Public-Facing Application | `com_installer` / `com_extplorer` exploitation |
| Execution | TA0002 | T1059 – Command and Scripting Interpreter | Obfuscated PHP payload execution |
| Persistence | TA0003 | T1505.003 – Server Software Component: Web Shell | `agent.php` upload |
| Defense Evasion | TA0005 | T1027 – Obfuscated Files or Information | String-splicing PHP obfuscation |
| Execution | TA0002 | Native binary execution | Sysmon EventID 5, `3791.exe` |
| Impact | TA0040 | T1491.002 – External Defacement | Defacement image from malicious external domain |

## Tools & Data Sources

- Splunk BOTSv1 dataset
- `suricata` (IDS alerts)
- `stream:http` (Splunk Stream HTTP transaction logs)
- `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`
