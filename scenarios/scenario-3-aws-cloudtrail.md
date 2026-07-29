# 🚨 Scenario 3: AWS CloudTrail Threat Hunt — S3 Asset Exposure & Identity Compromise

## 📌 Executive Summary
Threat hunting analysis in Splunk against the `BOTSv3` dataset identified unauthorized configuration changes to an AWS S3 bucket. Investigation of IAM user `bstoll` revealed automated reconnaissance across S3 and EC2 services, followed by a permissions change (`PutBucketAcl`) that exposed the `frothlywebcode` bucket. Forensic verification confirmed **zero data exfiltration** — no `GetObject` calls were logged against the bucket.

---

## 🎯 MITRE ATT&CK Mapping

* **Tactic:** Discovery ([TA0007](https://attack.mitre.org/tactics/TA0007/)) ➔ **Technique:** Cloud Infrastructure Discovery ([T1580](https://attack.mitre.org/techniques/T1580/))
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
| **Source IP** | `107.77.212.175` |
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

Pivoting on `bstoll` and the source IP surfaced 615 total events. Ranking by volume (not chronology) shows what the actor spent the most time doing:

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

**Reading:** the actor spent the bulk of their 615 API calls auditing S3 bucket permissions and mapping EC2 infrastructure (instances, volumes, tags, security groups) — consistent with an attacker scoping out what they could access and expose next, rather than one-off actions like `ListUsers`.

![Figure 2.1: Top API actions by count](../images/3_attacker_api_recon.png)
*Figure 2.1: Breakdown of top API actions showing heavy S3 permission auditing and EC2 infrastructure reconnaissance.*

### Step 3: Exfiltration Verification

To confirm whether any files were actually downloaded from the exposed bucket:

```spl
index=botsv3 frothlywebcode eventName=GetObject
```

**Result: 0 events — no results found.**

![Figure 3.1: Zero GetObject events](../images/4_exfiltration_verification.png)
*Figure 3.1: Exfiltration check returned 0 events, confirming no data was downloaded from `frothlywebcode`.*

---

## 🛡️ Response & Mitigation Recommendations

1. **Revoke Credentials:** Deactivate access key `ASIAZB6TMXZ7FWTIS4NJ` and terminate any active sessions for `bstoll`.
2. **Remediate S3 Permissions:** Revert the `frothlywebcode` ACL to private and enable **S3 Block Public Access** at the account level.
3. **Harden IAM:** Enforce MFA on all console logins and apply least-privilege policies to reduce the blast radius of a single compromised identity.
