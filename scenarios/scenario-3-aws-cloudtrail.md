# Scenario 3: AWS CloudTrail Threat Hunt — S3 Asset Exposure & Identity Compromise

<h2>Executive Summary</h2>
<p>
  During threat hunting analysis in Splunk using the <code>BOTSv3</code> dataset, unauthorized configuration changes were detected on an AWS S3 bucket. Further investigation revealed a compromised IAM user account (<code>bstoll</code>) executing automated discovery scripts, modifying access keys for persistence, exposing bucket permissions via <code>PutBucketAcl</code>, and conducting EC2 infrastructure reconnaissance across two distinct source IP addresses. Forensic log analysis confirmed <b>zero data exfiltration</b> (<code>0</code> <code>GetObject</code> calls logged).
</p>

<hr>

<h2>Technical Details & Indicators of Compromise (IOCs)</h2>
<ul>
  <li><b>Compromised Account:</b> <code>bstoll</code></li>
  <li><b>Target AWS Account ID:</b> <code>622676721278</code></li>
  <li><b>Target User ARN:</b> <code>arn:aws:iam::622676721278:user/bstoll</code></li>
  <li><b>Target S3 Bucket:</b> <code>frothlywebcode</code></li>
  <li><b>Attacker Source IPs:</b>
    <ul>
      <li><code>157.97.121.132</code> (Initial AWS Console Login & IAM Recon)</li>
      <li><code>107.77.212.175</code> (S3 Bucket ACL Modification & EC2 Recon)</li>
    </ul>
  </li>
  <li><b>Impact Assessment:</b> <b>Low Confidentiality Risk / High Integrity Risk</b> (Bucket exposed, but no files downloaded).</li>
</ul>

<hr>

<h2>Investigation Walkthrough</h2>

<h3>Step 1: Incident Detection & Identification</h3>
<p>Searching CloudTrail management events for bucket policy or ACL modifications revealed suspicious <code>PutBucketAcl</code> activity targeting the <code>frothlywebcode</code> bucket.</p>

```spl
index=botsv3 sourcetype="aws:cloudtrail" (eventName=PutBucketAcl OR eventName=PutBucketPolicy)
| table _time, userIdentity.userName, eventName, requestParameters.bucketName, sourceIPAddress`

<hr>

<h3>Step 2: Attacker Scope & Chronological Timeline</h3>
<p>Pivoting on identity <code>bstoll</code> and associated IPs revealed the full kill chain sequence:</p>

<ol>
  <li><b>Initial Access (11:35:27):</b> AWS Console login from <code>157.97.121.132</code>.</li>
  <li><b>Persistence (11:36:12):</b> Executed <code>UpdateAccessKey</code> to alter/create programmatic API access keys.</li>
  <li><b>IAM Recon (11:35 - 11:36):</b> Enumerated users (<code>ListUsers</code>), policies (<code>ListAttachedUserPolicies</code>), and groups (<code>ListGroups</code>).</li>
  <li><b>S3 Exposure (15:01 - 15:57):</b> Shifted to IP <code>107.77.212.175</code>, listed buckets (<code>ListBuckets</code>), and altered ACL permissions (<code>PutBucketAcl</code>).</li>
  <li><b>EC2 Recon (16:06+):</b> Expanded enumeration to virtual infrastructure (<code>DescribeInstances</code>, <code>DescribeVolumes</code>, <code>DescribeSecurityGroups</code>).</li>
</ol>

```spl
index=botsv3 sourcetype="aws:cloudtrail" (userIdentity.userName="bstoll" OR sourceIPAddress="107.77.212.175")
| stats count by eventName, eventSource
| sort - count`````

<hr>

<h2>Remediation & Mitigation Recommendations</h2>
<ol>
  <li><b>Revoke Credentials:</b> Immediately deactivate Access Key <code>ASIAZB6TMXZ7FWTIS4NJ</code> and terminate active console sessions for <code>bstoll</code>.</li>
  <li><b>Remediate S3 Permissions:</b> Revert <code>frothlywebcode</code> bucket ACL to private and enable AWS <b>S3 Block Public Access</b> at the account level.</li>
  <li><b>Identity & Access Management:</b> Enforce Multi-Factor Authentication (MFA) across all console logins and enforce strict Least Privilege policies on IAM users.</li>
</ol>
