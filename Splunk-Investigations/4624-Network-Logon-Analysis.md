# Splunk Investigation – Event ID 4624 Network Logon Analysis

## Objective
Investigate successful logon activity (Event ID 4624) to identify suspicious authentication patterns.

---

## Step 1 – Identify Successful Logons

### Query Used:

index=main EventID=4624
| stats count by TargetUserName
| sort - count


### Findings:
- WORKSTATION5$ – 8 logons
- James – 3 logons

WORKSTATION5$ represents machine account authentication.
James is a standard user account.

---

## Step 2 – Analyze Logon Type

### Query Used:

index=main EventID=4624 TargetUserName=James
| stats count by LogonType


### Findings:
- Logon Type 3 – Network Logon (3 occurrences)

Logon Type 3 indicates network-based authentication (remote connection, SMB, etc.).

---

## Step 3 – Identify Source IP Address

### Query Used:

index=main EventID=4624 TargetUserName=James
| table _time LogonType WorkstationName IpAddress
| sort _time


### Findings:
- Source IP: 172.90.12.11
- Logon Type: 3 (Network)
- Multiple successful logons from same external IP

---

## Step 4 – Validate Activity Pattern

### Query Used:

index=main EventID=4624 IpAddress=172.90.12.11
| stats count by LogonType


### Findings:
- 11 total network logons (Type 3) from 172.90.12.11

---

## Investigation Summary

Multiple successful network logons (Event ID 4624, Logon Type 3) were observed from IP address:

**172.90.12.11**

The account "James" authenticated multiple times via network logon from the same IP.

No failed logons (Event ID 4625) were observed in this dataset.

---

## Security Assessment

Network logons from a single IP may indicate:
- Normal user remote access
- Lateral movement
- Credential reuse
- Automated authentication activity

Further investigation recommended:
- Check geolocation of IP
- Validate if IP is internal or external
- Correlate with Event ID 4672 (Special Privileges Assigned)
- Review additional authentication logs

---

## Skills Demonstrated

- Splunk SPL querying
- Windows Event Log analysis
- Logon Type interpretation
- IP correlation
- Threat hunting methodology
- SOC investigation documentation

---

Author: Kordell Jackson  
Tool: Splunk Enterprise  
Environment: TryHackMe AttackBox Lab
