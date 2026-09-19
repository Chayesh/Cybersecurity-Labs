# Incident Response Report: RobbCo Corporate Espionage Investigation

**TryHackMe Room:** The Digital Trail (AI/ML-Assisted DFIR)
**Role:** Lead Forensic Investigator
**Client:** RobbCo (software/firmware/OS vendor)

---

## Executive Summary

RobbCo's SOC flagged an off-hours login and suspicious activity, prompting an emergency forensic investigation. Analysis confirmed a targeted spear-phishing attack against an engineering employee (j.morgan) led to credential compromise, lateral privilege escalation to the company founder's account (r.house), deployment of a disguised persistence mechanism, and ultimately exfiltration-ready theft of proprietary source code (RETROS BIOS firmware and the MF Boot Agent bootloader).

This investigation combined machine learning-assisted triage — using scikit-learn-based anomaly detection across authentication logs and the filesystem — with manual human validation, illustrating both the value and the limitations of AI in DFIR workflows.

---

## Attack Timeline

| Time | Event |
|---|---|
| Prior | Spear-phishing email sent to j.morgan from a spoofed external vendor address, posing as an overdue invoice |
| Prior | Malicious macro-laden `.ods` attachment opened, silently harvesting shell history, session data, and system usernames |
| Prior | Harvested data exfiltrated via HTTP POST to attacker infrastructure |
| 03:00:01 | Failed SSH login attempt as `admin` |
| 03:01:02 | Successful SSH login as `j.morgan` using compromised credentials |
| ~03:0X | First-stage dropper and reverse shell stub deployed under j.morgan's context |
| ~03:1X | Privilege escalation via abuse of legitimate `sudo` access — attacker planted their SSH key in r.house's `authorized_keys` |
| 03:15:00 | Successful public-key SSH login as `r.house` |
| Post-escalation | Second reverse shell deployed, disguised as a legitimate monitoring binary, backed by a fabricated log file to support the ruse |
| Final stage | Proprietary source code compressed, base64-encoded, and staged in shared memory (`/dev/shm`) for exfiltration |

---

## Initial Access: Phishing Analysis

The intrusion began with a spear-phishing email disguised as an urgent overdue invoice, referencing a fictitious joint energy project to add legitimacy and urgency — a classic social engineering pressure tactic. The attached spreadsheet contained an embedded macro that, once opened, silently executed a data-harvesting script and exfiltrated the results to attacker-controlled infrastructure.

**Key TTPs (MITRE ATT&CK):**
- **T1566.001** — Phishing: Spearphishing Attachment
- **T1204.002** — User Execution: Malicious File
- **T1005** — Data from Local System (harvested via macro)
- **T1041** — Exfiltration Over C2 Channel

---

## Privilege Escalation

Rather than exploiting a software vulnerability, the attacker abused *legitimate* administrative permissions already available to the compromised account, directly editing the founder's `authorized_keys` file to plant persistent SSH access. This is a notable finding: no exploit or CVE was required, only misuse of standing privileges.

**Key TTPs:**
- **T1098.004** — Account Manipulation: SSH Authorized Keys
- **T1078** — Valid Accounts

---

## Persistence and Defense Evasion

Post-escalation, the attacker deployed a second reverse shell disguised as a system monitoring utility, supported by a fabricated log file designed to make the binary appear legitimate to a casual review. This is a notable defense evasion technique — masquerading malicious tooling as expected infrastructure.

**Key TTPs:**
- **T1036.005** — Masquerading: Match Legitimate Name or Location
- **T1547** — Boot or Logon Autostart Execution / Persistence via disguised binary
- **T1070** — Indicator Removal (via fabricated telemetry)

---

## Exfiltration Staging

The attacker's ultimate objective was RobbCo's proprietary source code — its firmware and bootloader. The stolen material was compressed, encoded, and staged in `/dev/shm` (volatile shared memory), a stealthy location less likely to persist across reboots or draw attention during routine disk-based review.

**Key TTPs:**
- **T1560.001** — Archive Collected Data
- **T1027** — Obfuscated Files or Information (base64 encoding)
- **T1074.001** — Local Data Staging

---

## AI/ML in the Investigation: Lessons Learned

Two scikit-learn-based classifiers accelerated this investigation significantly:

1. A **log anomaly classifier** flagged the suspicious authentication events purely from behavioral/timing features, without prior knowledge of the attack.
2. A **file anomaly classifier** flagged suspicious artifacts across sensitive directories using features like entropy, path, and permissions.

Critically, the file classifier **also flagged RobbCo's legitimate proprietary source code as suspicious** — a false positive caused by high entropy in compiled/compressed-like source files. This reinforced a central principle of AI-assisted forensics: **ML models are a triage and prioritization aid, not a source of ground truth.** Every flagged artifact still required human analyst validation before being included in the final incident narrative.

---

## Conclusion

This incident demonstrates a full attack lifecycle — phishing, credential theft, lateral movement, privilege escalation via legitimate permission abuse, disguised persistence, and IP theft — successfully reconstructed through a hybrid workflow of ML-assisted anomaly detection and manual forensic validation. The case underscores that AI can dramatically reduce time-to-detection in DFIR, but human expertise remains essential to interpret, verify, and contextualize its output.
