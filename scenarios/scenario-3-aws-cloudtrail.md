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
| table _time, userIdentity.userName, eventName, requestParameters.bucketName, sourceIPAddress
