---

## Project Overview

This project implements a cloud-based SOC architecture where Wazuh functions as the SIEM and endpoint monitoring platform, TheHive is used for incident and case management, and Shuffle provides automated SOAR workflows for alert enrichment and response.

![SOC Architecture](images/architecture.png)

---

## Infrastructure & Cloud Setup

Provisioned Ubuntu-based cloud instances on Vultr to host the Wazuh Manager and TheHive services. Configured firewall rules (UFW) to allow secure web access over port 443.

![Vultr Cloud Hosting](images/vultr.png)
Vultr cloud infrastructure hosting the Wazuh Manager and TheHive services.

![UFW Firewall Configuration](images/ufw.png)

---

## Configuration & Endpoint Monitoring

Installed the Wazuh agent on a Windows 10 endpoint and integrated Sysmon to collect detailed Windows process and security telemetry. Updated the agent’s `ossec.conf` configuration to ingest Sysmon event logs for enhanced detection capabilities.

![Wazuh Agent Configuration](images/conf.png)

![Wazuh Manager Instance](images/wazuhins.png)

---

## SOC Automation with Shuffle & VirusTotal

Developed an automated SOAR workflow in Shuffle that triggers on Wazuh alerts, extracts SHA256 file hashes using Regex, and enriches the alert by querying the VirusTotal API for threat intelligence and reputation data.

![Shuffle SOAR Workflow](images/shuffler.png)

![Regex-Based Hash Extraction](images/regex.png)

---

## Incident Response & Result

Simulated a credential-dumping attack by executing Mimikatz on the Windows endpoint. The activity was successfully detected by Wazuh, enriched via Shuffle automation, and escalated through both an automatically created incident ticket in TheHive and an email alert.

![Mimikatz Execution Detection](images/mimi.png)
Execution of Mimikatz on the monitored Windows endpoint to simulate malicious credential access.

![TheHive Incident Case](images/hive.png)
TheHive automatically receives the alert from Wazuh and generates an incident case for analyst investigation.

![Email Alert Notification](images/gmail.png)
Automated email notification generated via Shuffle SOAR upon detection of Mimikatz activity.



---
