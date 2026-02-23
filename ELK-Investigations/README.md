# ELK Investigation Lab

## Overview
This lab documents hands-on investigation work using the Elastic Stack (ELK) as a SIEM platform.

## Objectives
- Analyze VPN logs
- Identify suspicious login patterns
- Perform log filtering and search queries
- Create dashboards and visualizations
- Detect potential malicious behavior

## Tools Used
- Elasticsearch
- Logstash
- Kibana
- TryHackMe ELK Lab Environment

## Investigation Summary

### Scenario
Investigated VPN logs to identify unusual login activity and possible brute-force behavior.

### Key Findings
- Identified high-volume login attempts from a single IP address
- Detected abnormal login times outside standard business hours
- Observed repeated failed login attempts followed by successful authentication

### Skills Practiced
- Log searching and filtering
- Query building
- Event correlation
- Dashboard creation
- Threat pattern recognition

---

More labs will be added as skills expand.

## Example Query Used

GET vpn-logs/_search
{
  "query": {
    "match": {
      "event.outcome": "failure"
    }
  }
}

### What This Does

- Filters VPN authentication logs for failed login attempts  
- Helps identify potential brute-force or credential stuffing activity  
- Supports early-stage incident detection and triage within a SOC environment  

### Analyst Action

If repeated failures are observed from a single IP:
- Correlate timestamps
- Check geo-location anomalies
- Escalate per incident response plan if threshold exceeded
