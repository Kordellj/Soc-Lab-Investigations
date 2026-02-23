# ELK Investigation: Suspicious VPN Activity

## Investigation Summary
Multiple failed VPN login attempts observed in ELK.

**Detection Goal:** Identify potential brute-force activity.  
**Data Source:** VPN authentication logs  
**MITRE Mapping:** T1110 – Brute Force  

---

## Scenario
Several failed authentication attempts were detected from a single external IP address outside of normal business hours.

---

## Detection Logic
Example Query Used:

GET vpn-logs/_search
{
  "query": {
    "match": {
      "event.outcome": "failure"
    }
  }
}



---

## Key Findings
- High volume of failed logins from one IP
- Activity outside business hours
- Pattern consistent with brute-force attempts

---

## Analyst Response
- Verified account status
- Checked geo-location of source IP
- Escalated per incident response plan
- Recommended temporary account lockout

---

## MITRE ATT&CK Mapping
- Technique: T1110 – Brute Force
- Tactic: Credential Access

---

## Skills Demonstrated
- Log filtering and analysis
- Pattern recognition
- Incident triage workflow
- MITRE ATT&CK mapping
