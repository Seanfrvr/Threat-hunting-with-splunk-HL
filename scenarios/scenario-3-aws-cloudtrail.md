# 🚨 Scenario 3: AWS CloudTrail Threat Hunt — S3 Asset Exposure & Identity Compromise

## 📌 Executive Summary
Threat hunting analysis in Splunk against the `BOTSv3` dataset identified unauthorized configuration changes to an AWS S3 bucket. Investigation of IAM user `bstoll` revealed automated reconnaissance across S3 and EC2 services, followed by a permissions change (`PutBucketAcl`) that exposed the `frothlywebcode` bucket. Forensic verification confirmed **zero data exfiltration** — no `GetObject` calls were logged against the bucket.

---

## 🎯 MITRE ATT&CK Mapping

* **Tactic:** Initial Access ([TA0001](https://attack.mitre.org/tactics/TA0001/)) ➔ **Technique:** Valid Accounts ([T1078](https://attack.mitre.org/techniques/T1078/))
* **Tactic:** Discovery ([TA0007](https://attack.mitre.org/tactics/TA0007/)) ➔ **Techniques:** Account Discovery ([T1087](https://attack.mitre.org/techniques/T1087/)), Permission Groups Discovery ([T1069](https://attack.mitre.org/techniques/T1069/)), Cloud Infrastructure Discovery ([T1580](https://attack.mitre.org/techniques/T1580/))
* **Tactic:** Collection ([TA0009](https://attack.mitre.org/tactics/TA0009/)) ➔ **Technique:** Data from Cloud Storage ([T1530](https://attack.mitre.org/techniques/T1530/)) — *attempted, not achieved*

---

## 🧾 Indicators of Compromise (IOCs)

| Indicator | Value |
| :--- | :--- |
| **Compromised Identity** | `bstoll` |
| **User ARN** | `arn:aws:iam::622676721278:user/bstoll` |
| **AWS Account ID** | `622676721278` |
| **Access Key ID** | `ASIAZB6TMXZ7FWTIS4NJ` |
| **Target S3 Bucket** | `frothlywebcode` |
| **Source IP (login/recon)** | `157.97.121.132` |
| **Source IP (S3 exposure)** | `107.77.212.175` |
| **Log Host** | `splunk.froth.ly` |
| **Impact** | Low Confidentiality Risk / High Integrity Risk |

---

## 🔍 Investigation Walkthrough

### Step 1: Incident Detection & Identification

Searching CloudTrail for bucket ACL/policy modifications surfaced two `PutBucketAcl` calls against `frothlywebcode`:

```spl
index=botsv3 sourcetype="aws:cloudtrail" (eventName=PutBucketAcl OR eventName=PutBucketPolicy)
| table _time, userIdentity.userName, eventName, requestParameters.bucketName, sourceIPAddress
```

**Results:** 2 events — both `PutBucketAcl` by `bstoll` from `107.77.212.175`, at `2018-08-20 15:01:46` and `15:57:54`.

![Figure 1.1: Detection of unauthorized PutBucketAcl event](../images/1_s3_acl_detection.png)
*Figure 1.1: Initial detection of unauthorized `PutBucketAcl` calls targeting bucket `frothlywebcode` by user `bstoll`.*

Expanding the raw event confirmed the identity context: ARN `arn:aws:iam::622676721278:user/bstoll`, access key `ASIAZB6TMXZ7FWTIS4NJ`, request ID `6A18BDBBC85C6E81`, principal ID `AIDAJUFKXZ4LV4EN4MGK`.

![Figure 1.2: Expanded CloudTrail JSON payload](../images/2_cloudtrail_json_payload.png)
*Figure 1.2: Expanded CloudTrail JSON payload detailing IAM user ARN, access key, and origin IP.*

### Step 2: Attacker Activity Breakdown

**2a. Chronological timeline.** Sorting all 615 events by `_time` pins down the actual sequence of the attack:

```spl
index=botsv3 sourcetype="aws:cloudtrail" (userIdentity.userName="bstoll" OR sourceIPAddress="107.77.212.175")
| stats count by _time, eventName, eventSource, userIdentity.userName, sourceIPAddress
| sort _time
```

| Time | Event | Source IP |
| :--- | :--- | :--- |
| 11:35:27 | `ConsoleLogin` | `157.97.121.132` |
| 11:35:53 | `GetAccountPasswordPolicy`, `GetAccountSummary`, `ListAccessKeys`, `ListAccountAliases` | `157.97.121.132` |
| 11:35:58 | `ListUsers` (x2) | `157.97.121.132` |
| 11:35:59 | `ListGroups` | `157.97.121.132` |
| 11:36:04 | `GetUser`, `ListAttachedUserPolicies` | `157.97.121.132` |

**Reading:** within 40 seconds of logging in, `bstoll` ran a scripted burst of IAM discovery commands — checking password policy, account limits, existing access keys, and other users/groups/policies. This is automated enumeration, not manual browsing.

![Figure 2.1: Chronological attacker timeline](../images/5_attacker_timeline.png)
*Figure 2.1: Chronological sequence showing `ConsoleLogin` from `157.97.121.132` immediately followed by automated IAM enumeration.*

**2b. Volume ranking.** Separately, ranking the same 615 events by total count (not time) shows where the bulk of the activity landed later in the session:

```spl
index=botsv3 sourcetype="aws:cloudtrail" (userIdentity.userName="bstoll" OR sourceIPAddress="107.77.212.175")
| stats count by eventName, eventSource
| sort - count
```

| Rank | Event Name | Source | Count |
| :--- | :--- | :--- | :---: |
| 1 | `GetBucketAcl` | s3.amazonaws.com | 55 |
| 1 | `GetBucketPolicy` | s3.amazonaws.com | 55 |
| 3 | `DescribeInstances` | ec2.amazonaws.com | 44 |
| 4 | `DescribeInstanceStatus` | ec2.amazonaws.com | 43 |
| 5 | `DescribeVolumeStatus` / `DescribeVolumes` | ec2.amazonaws.com | 41 |

**Reading:** most of the 615 total calls were spent auditing S3 bucket permissions and mapping EC2 infrastructure — some arriving in scripted bursts of 10-15 calls within the same second — rather than the one-off IAM discovery commands seen in the initial 40-second window above.

![Figure 2.2: Top API actions by count](../images/3_attacker_api_recon.png)
*Figure 2.2: Volume ranking of all 615 events, showing S3 permission auditing and EC2 infrastructure discovery as the dominant activity.*

### Step 3: Exfiltration Verification

To confirm whether any files were actually downloaded from the exposed bucket:

```spl
index=botsv3 frothlywebcode eventName=GetObject
```

**Result: 0 events — no results found.**

![Figure 3.1: Zero GetObject events](../images/4_exfiltration_verification.png)
*Figure 3.1: Exfiltration check returned 0 events, confirming no data was downloaded from `frothlywebcode`.*

*(Screenshots for this scenario: `1_s3_acl_detection.png`, `2_cloudtrail_json_payload.png`, `3_attacker_api_recon.png`, `4_exfiltration_verification.png`, `5_attacker_timeline.png`)*

---

## 🛡️ Response & Mitigation Recommendations

1. **Revoke Credentials:** Deactivate access key `ASIAZB6TMXZ7FWTIS4NJ` and terminate any active sessions for `bstoll`.
2. **Remediate S3 Permissions:** Revert the `frothlywebcode` ACL to private and enable **S3 Block Public Access** at the account level.
3. **Harden IAM:** Enforce MFA on all console logins and apply least-privilege policies to reduce the blast radius of a single compromised identity.
