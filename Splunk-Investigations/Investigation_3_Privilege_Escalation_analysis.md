# Investigation 3 – Privilege Escalation & Process Creation Analysis

## Objective
Investigate potential privilege escalation activity and suspicious process execution within Windows Security logs.

---

## Step 1 – Identify Logon Events

### SPL Query


index=windows EventID=4624
| stats count by TargetUserName


### Purpose (English Translation)
Search Windows logs for successful logon events and summarize how many times each user logged in.

### Findings
- 4 users observed
- James logged in successfully
- Logon Type 3 (Network Logon)

---

## Step 2 – Identify Special Privileges Assigned

### SPL Query


index=windows EventID=4672
| table _time SubjectUserName Privileges


### Purpose (English Translation)
Search for accounts that were assigned special privileges upon logon and display the time, username, and privileges granted.

### Findings
- User: James
- Special privileges assigned at logon
- Privilege field showed:
  - SeImpersonatePrivilege
  - Other elevated rights
- Group name field was blank
- Indicates elevated access session

---

## Step 3 – Investigate Process Creation After Privileged Logon

### SPL Query


index=windows EventID=4688
| stats count by SubjectUserName NewProcessName


### Purpose (English Translation)
Search for newly created processes and summarize which users executed them.

### Findings
- James executed processes after privileged logon
- Suspicious process behavior observed
- Potential administrative or remote execution activity

---

## Step 4 – Source IP Analysis

### SPL Query


index=windows EventID=4624
| stats count by TargetUserName IpAddress


### Purpose (English Translation)
Identify IP addresses associated with successful logons.

### Findings
- James used IP address: 172.90.12.11
- Appears to be a public IP
- Network logons occurred from external source
- No failed login attempts detected

---

## Analyst Conclusion

James successfully authenticated via network logon (Type 3), was assigned special privileges (EventID 4672), and created processes (EventID 4688).

The login originated from a public IP address (172.90.12.11), which raises concern.

Sequence of Events:
1. Successful network logon
2. Elevated privileges assigned
3. Process creation executed

This pattern may indicate:
- Privilege escalation
- Potential lateral movement
- Suspicious remote administrative activity

Further investigation recommended:
- Validate James' job role and access requirements
- Confirm IP legitimacy
- Review command-line execution details
- Check for lateral authentication attempts on other hosts

---

## Incident Response Framework Alignment

- Identification: Detected privileged logon activity
- Containment: Recommend session review and account monitoring
- Eradication: If malicious, revoke elevated privileges
- Recovery: Reset credentials and review access control
- Lessons Learned: Implement alerting for 4672 + 4688 correlation
