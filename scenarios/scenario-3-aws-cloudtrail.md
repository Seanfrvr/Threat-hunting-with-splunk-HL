Scenario 3: AWS CloudTrail Threat Hunt — S3 Asset Exposure & Identity Compromise
Executive Summary

During threat hunting analysis in Splunk using the BOTSv3 dataset, unauthorized configuration changes were detected on an AWS S3 bucket. Further investigation revealed a compromised IAM user account (bstoll) executing automated discovery scripts, modifying access keys for persistence, exposing bucket permissions via PutBucketAcl, and conducting EC2 infrastructure reconnaissance across two distinct source IP addresses. Forensic log analysis confirmed zero data exfiltration (0 GetObject calls logged).
Technical Details & Indicators of Compromise (IOCs)

    Compromised Account: bstoll

    Target AWS Account ID: 622676721278

    Target User ARN: arn:aws:iam::622676721278:user/bstoll

    Target S3 Bucket: frothlywebcode

    Attacker Source IPs:

        157.97.121.132 (Initial AWS Console Login & IAM Recon)

        107.77.212.175 (S3 Bucket ACL Modification & EC2 Recon)

    Impact Assessment: Low Confidentiality Risk / High Integrity Risk (Bucket exposed, but no files downloaded).

Investigation Walkthrough
Step 1: Incident Detection & Identification

Searching CloudTrail management events for bucket policy or ACL modifications revealed suspicious PutBucketAcl activity targeting the frothlywebcode bucket.
Splunk SPL

index=botsv3 sourcetype="aws:cloudtrail" (eventName=PutBucketAcl OR eventName=PutBucketPolicy)
| table _time, userIdentity.userName, eventName, requestParameters.bucketName, sourceIPAddress

Figure 1.1: Initial detection of unauthorized PutBucketAcl calls targeting bucket frothlywebcode by user bstoll.

Expanding the raw log context confirmed the target user ARN (arn:aws:iam::622676721278:user/bstoll), access key ID (ASIAZB6TMXZ7FWTIS4NJ), and origin IP (107.77.212.175).

Figure 1.2: Expanded CloudTrail JSON payload detailing IAM user ARN, session attributes, and origin IP.
Step 2: Attacker Scope & Chronological Timeline

Pivoting on identity bstoll and associated IPs revealed the full kill chain sequence:

    Initial Access (11:35:27): AWS Console login from 157.97.121.132.

    Persistence (11:36:12): Executed UpdateAccessKey to alter/create programmatic API access keys.

    IAM Recon (11:35 - 11:36): Enumerated users (ListUsers), policies (ListAttachedUserPolicies), and groups (ListGroups).

    S3 Exposure (15:01 - 15:57): Shifted to IP 107.77.212.175, listed buckets (ListBuckets), and altered ACL permissions (PutBucketAcl).

    EC2 Recon (16:06+): Expanded enumeration to virtual infrastructure (DescribeInstances, DescribeVolumes, DescribeSecurityGroups).

Splunk SPL

index=botsv3 sourcetype="aws:cloudtrail" (userIdentity.userName="bstoll" OR sourceIPAddress="107.77.212.175")
| stats count by eventName, eventSource
| sort - count

Figure 2.1: Breakdown of top API actions highlighting automated IAM, S3, and EC2 reconnaissance.
Step 3: Exfiltration Verification

To determine if sensitive files were downloaded following the ACL modification, S3 access events were queried for GetObject calls against frothlywebcode.
Splunk SPL

index=botsv3 frothlywebcode eventName=GetObject

Figure 3.1: Exfiltration investigation returned 0 events, confirming no data exfiltration occurred.
Remediation & Mitigation Recommendations

    Revoke Credentials: Immediately deactivate Access Key ASIAZB6TMXZ7FWTIS4NJ and terminate active console sessions for bstoll.

    Remediate S3 Permissions: Revert frothlywebcode bucket ACL to private and enable AWS S3 Block Public Access at the account level.

    Identity & Access Management: Enforce Multi-Factor Authentication (MFA) across all console logins and enforce strict Least Privilege policies on IAM users.
