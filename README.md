---

## Architecture Overview

![SOC Architecture](images/architecture.png)

This diagram shows the overall SOC automation architecture, including Wazuh, TheHive, Shuffle SOAR, threat intelligence enrichment, and alert notification flow.

---

## Wazuh Configuration & Detection

![Wazuh Configuration](images/conf.png)

Custom Wazuh configuration used to ingest Sysmon logs and detect credential-dumping activity.

---

## Mimikatz Detection

![Mimikatz Detection](images/mimi.png)

Wazuh detection of Mimikatz execution on the Windows endpoint using Sysmon telemetry and custom rules.

---

## Regex-Based Rule Matching

![Regex Rules](images/regex.png)

Regex patterns used to identify suspicious process behavior associated with credential dumping.

---

## Shuffle SOAR Automation

![Shuffle Workflow](images/shuffler.png)

Shuffle SOAR workflow used to enrich alerts, extract hashes, query VirusTotal, and automate incident response actions.

---

## TheHive Incident Creation

![TheHive Case](images/hive.png)

Automatically created incident case in TheHive based on enriched alerts from Shuffle.

---

## Email Alert Notification

![Email Alert](images/gmail.png)

Automated email notification sent to analysts when a high-severity alert and incident are generated.

---

## Wazuh Manager Infrastructure

![Wazuh Instance](images/wazuhins.png)

Cloud-hosted Wazuh Manager instance responsible for log ingestion, detection, and alert forwarding.

---

## Firewall Configuration

![UFW Rules](images/ufw.png)

UFW firewall rules securing the SOC infrastructure while allowing required services over port 443.

---

## Cloud Hosting Platform

![Vultr Hosting](images/vultr.png)

Vultr cloud infrastructure hosting the Wazuh Manager and TheHive services.

---
