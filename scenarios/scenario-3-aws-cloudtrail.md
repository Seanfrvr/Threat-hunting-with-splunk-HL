<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Scenario 3: AWS CloudTrail Threat Hunt</title>
</head>
<body>

    <h1>Scenario 3: AWS CloudTrail Threat Hunt — S3 Asset Exposure & Identity Compromise</h1>

    <h2>Executive Summary</h2>
    <p>
        During threat hunting analysis in Splunk using the <code>BOTSv3</code> dataset, unauthorized configuration changes were detected on an AWS S3 bucket. Further investigation revealed a compromised IAM user account (<code>bstoll</code>) executing automated discovery scripts, modifying access keys for persistence, exposing bucket permissions via <code>PutBucketAcl</code>, and conducting EC2 infrastructure reconnaissance across two distinct source IP addresses. Forensic log analysis confirmed <strong>zero data exfiltration</strong> (<code>0</code> <code>GetObject</code> calls logged).
    </p>

    <hr>

    <h2>Technical Details & Indicators of Compromise (IOCs)</h2>
    <ul>
        <li><strong>Compromised Account:</strong> <code>bstoll</code></li>
        <li><strong>Target AWS Account ID:</strong> <code>622676721278</code></li>
        <li><strong>Target User ARN:</strong> <code>arn:aws:iam::622676721278:user/bstoll</code></li>
        <li><strong>Target S3 Bucket:</strong> <code>frothlywebcode</code></li>
        <li><strong>Attacker Source IPs:</strong>
            <ul>
                <li><code>157.97.121.132</code> (Initial AWS Console Login & IAM Recon)</li>
                <li><code>107.77.212.175</code> (S3 Bucket ACL Modification & EC2 Recon)</li>
            </ul>
        </li>
        <li><strong>Impact Assessment:</strong> <strong>Low Confidentiality Risk / High Integrity Risk</strong> (Bucket exposed, but no files downloaded).</li>
    </ul>

    <hr>

    <h2>Investigation Walkthrough</h2>

    <h3>Step 1: Incident Detection & Identification</h3>
    <p>Searching CloudTrail management events for bucket policy or ACL modifications revealed suspicious <code>PutBucketAcl</code> activity targeting the <code>frothlywebcode</code> bucket.</p>

    <pre><code>index=botsv3 sourcetype="aws:cloudtrail" (eventName=PutBucketAcl OR eventName=PutBucketPolicy)
| table _time, userIdentity.userName, eventName, requestParameters.bucketName, sourceIPAddress</code></pre>

    <p>
        <img src="../images/1_s3_acl_detection.png" alt="Figure 1.1: Detection of unauthorized PutBucketAcl event"><br>
        <em>Figure 1.1: Initial detection of unauthorized <code>PutBucketAcl</code> calls targeting bucket <code>frothlywebcode</code> by user <code>bstoll</code>.</em>
    </p>

    <p>Expanding the raw log context confirmed the target user ARN (<code>arn:aws:iam::622676721278:user/bstoll</code>), access key ID (<code>ASIAZB6TMXZ7FWTIS4NJ</code>), and origin IP (<code>107.77.212.175</code>).</p>

    <p>
        <img src="../images/2_cloudtrail_json_payload.png" alt="Figure 1.2: Raw JSON context showing IAM details"><br>
        <em>Figure 1.2: Expanded CloudTrail JSON payload detailing IAM user ARN, session attributes, and origin IP.</em>
    </p>

    <hr>

    <h3>Step 2: Attacker Scope & Chronological Timeline</h3>
    <p>Pivoting on identity <code>bstoll</code> and associated IPs revealed the full kill chain sequence:</p>

    <ol>
        <li><strong>Initial Access (11:35:27):</strong> AWS Console login from <code>157.97.121.132</code>.</li>
        <li><strong>Persistence (11:36:12):</strong> Executed <code>UpdateAccessKey</code> to alter/create programmatic API access keys.</li>
        <li><strong>IAM Recon (11:35 - 11:36):</strong> Enumerated users (<code>ListUsers</code>), policies (<code>ListAttachedUserPolicies</code>), and groups (<code>ListGroups</code>).</li>
        <li><strong>S3 Exposure (15:01 - 15:57):</strong> Shifted to IP <code>107.77.212.175</code>, listed buckets (<code>ListBuckets</code>), and altered ACL permissions (<code>PutBucketAcl</code>).</li>
        <li><strong>EC2 Recon (16:06+):</strong> Expanded enumeration to virtual infrastructure (<code>DescribeInstances</code>, <code>DescribeVolumes</code>, <code>DescribeSecurityGroups</code>).</li>
    </ol>

    <pre><code>index=botsv3 sourcetype="aws:cloudtrail" (userIdentity.userName="bstoll" OR sourceIPAddress="107.77.212.175")
| stats count by eventName, eventSource
| sort - count</code></pre>

    <p>
        <img src="../images/3_attacker_api_recon.png" alt="Figure 2.1: Chronological attack timeline and high-volume API calls"><br>
        <em>Figure 2.1: Breakdown of top API actions highlighting automated IAM, S3, and EC2 reconnaissance.</em>
    </p>

    <hr>

    <h3>Step 3: Exfiltration Verification</h3>
    <p>To determine if sensitive files were downloaded following the ACL modification, S3 access events were queried for <code>GetObject</code> calls against <code>frothlywebcode</code>.</p>

    <pre><code>index=botsv3 frothlywebcode eventName=GetObject</code></pre>

    <p>
        <img src="../images/4_exfiltration_verification.png" alt="Figure 3.1: Zero events returned for GetObject exfiltration query"><br>
        <em>Figure 3.1: Exfiltration investigation returned 0 events, confirming no data exfiltration occurred.</em>
    </p>

    <hr>

    <h2>Remediation & Mitigation Recommendations</h2>
    <ol>
        <li><strong>Revoke Credentials:</strong> Immediately deactivate Access Key <code>ASIAZB6TMXZ7FWTIS4NJ</code> and terminate active console sessions for <code>bstoll</code>.</li>
        <li><strong>Remediate S3 Permissions:</strong> Revert <code>frothlywebcode</code> bucket ACL to private and enable AWS <strong>S3 Block Public Access</strong> at the account level.</li>
        <li><strong>Identity & Access Management:</strong> Enforce Multi-Factor Authentication (MFA) across all console logins and enforce strict Least Privilege policies on IAM users.</li>
    </ol>

</body>
</html>
