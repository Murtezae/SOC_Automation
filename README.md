# 
Overview:

This project demonstrates an automated Security Operations Center (SOC) workflow using Wazuh for detection, TheHive for incident case management, 
and Shuffle for SOAR-based alert enrichment and response. A simulated credential-dumping attack using Mimikatz was detected, enriched with threat 
intelligence, and automatically escalated.


Architecture:

Wazuh – SIEM and endpoint monitoring
Sysmon – Enhanced Windows telemetry
TheHive – Incident and case management
Shuffle – SOAR automation and alert enrichment
VirusTotal – Threat intelligence enrichment
Email – Automated alert notification


Environment:

Cloud-hosted Ubuntu instances (Vultr) for Wazuh Manager and TheHive
Windows 10 endpoint with Wazuh Agent and Sysmon installed
Secure web access enabled via port 443



Detection & Automation Flow:

Sysmon captures process activity on the Windows endpoint
Wazuh ingests logs and detects Mimikatz execution
Alert is forwarded to Shuffle for automated enrichment
SHA256 hashes are extracted and checked against VirusTotal
Incident case is created in TheHive
Automated email notification is sent to analysts



Results:

Successful detection of Mimikatz credential-dumping activity
Automated alert enrichment and incident creation
End-to-end SOC workflow without manual intervention



Skills Demonstrated:

SIEM deployment and log analysis
Endpoint monitoring and detection engineering
SOAR automation and threat intelligence enrichment
Incident response and case management
