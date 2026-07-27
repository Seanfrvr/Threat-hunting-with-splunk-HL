# 🛡️ Threat Hunting with Splunk (Home Lab)

SOC threat hunting and incident analysis across Windows/Linux authentication, PowerShell obfuscation, and network logs using the Splunk **BOTSv3 (Boss of the SOC v3)** dataset.

---

## 🚀 Lab Architecture & Environment

* **SIEM Platform:** Splunk Enterprise (`v10.4.1`)
* **Dataset:** Boss of the SOC v3 (`index=botsv3`)
* **Analysis Tools:** CyberChef, VirusTotal, Splunk Search Processing Language (SPL)
* **Framework Alignment:** MITRE ATT&CK Framework

---

## 🔍 Investigation Scenarios

| # | Scenario Title | Focus Area | Core Technologies | MITRE ATT&CK | Status |
| :-: | :--- | :--- | :--- | :--- | :-: |
| **01** | [Encoded PowerShell Execution Analysis](./scenarios/scenario-1-powershell.md) | Obfuscation & Malicious Download Cradles | Windows Event Logs, Base64, CyberChef | [T1059.001](https://attack.mitre.org/techniques/T1059/001/), [T1140](https://attack.mitre.org/techniques/T1140/) | `Completed` |
| **02** | [Linux SSH Brute Force Analysis](./scenarios/scenario-2-ssh-bruteforce.md) | Account Reconnaissance & Brute Force | `linux_secure`, SPL Regex (`rex`), SSH Logs | [T1110.001](https://attack.mitre.org/techniques/T1110/001/), [T1087](https://attack.mitre.org/techniques/T1087/) | `Completed` |

---

## 🛠️ Key Skills Demonstrated

* **SPL Query Construction:** Writing targeted Splunk queries using wildcards, boolean logic, and field extractions.
* **Payload Deobfuscation:** Decoding Base64 strings encoded in UTF-16LE via CyberChef to expose hidden command-line parameters.
* **IoC Extraction & Defanging:** Safely isolating and defanging network Indicators of Compromise (`hxxp[:]//...`) for incident reporting.
* **Detection & Remediation:** Translating attack signatures into actionable SOC defense recommendations (e.g., Script Block Logging, Constrained Language Mode).

---

## 📌 Repository Structure

```text
.
├── README.md                 # Project Overview & Scenario Navigation
├── images/                   # Screenshots & Forensic Artifacts
└── scenarios/                # Detailed Incident Investigation Reports
    └── scenario-1-powershell.md
