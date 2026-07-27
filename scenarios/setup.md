<h1>⚙️ Lab Setup & Environment Deployment</h1>

<h2>📌 Overview</h2>
<p>This document details the deployment of the SOC threat hunting home lab environment. Splunk Enterprise was containerized using Docker to process and index the <strong>Boss of the SOC v3 (BOTSv3)</strong> dataset for incident analysis.</p>

<hr>

<h2>🐳 1. Docker Container Deployment</h2>
<p>Splunk Enterprise (v10.4.1) was deployed as a background daemon on a Linux host using Docker. Port 8000 was mapped to expose the Web UI.</p>

<pre><code>sudo systemctl enable --now docker
sudo docker run -d \
  --name splunk \
  -p 8000:8000 \
  -e "SPLUNK_START_ARGS=--accept-license" \
  -e "SPLUNK_PASSWORD=<YOUR_SECURE_PASSWORD>" \
  splunk/splunk:latest</code></pre>

<p><img src="./images/setup_docker_splunk.png" alt="Docker Splunk Setup"></p>
<p><em>Figure 1: Terminal output displaying Docker pulling and initializing the Splunk Enterprise container.</em></p>

<hr>

<h2>📊 2. Dataset Ingestion & Verification</h2>
<p>After installing the BOTSv3 app and dataset, an environment check was run in the Splunk search bar to verify that event logs across sourcetypes were properly indexed.</p>

<pre><code>index=botsv3 earliest=0
| stats count by sourcetype</code></pre>

<p><img src="./images/setup_ingestion.png" alt="Splunk Data Ingestion Verification"></p>
<p><em>Figure 2: Splunk search results confirming 1,944,092 indexed events across sourcetypes (AWS, Linux, Windows, Web logs).</em></p>
