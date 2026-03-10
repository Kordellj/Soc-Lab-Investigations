# Lab 8 – Unauthorized Account Creation Investigation

## Objective

Detect unauthorized user account creation using Windows Event ID 4720.

Attackers frequently create new accounts to maintain persistence after gaining access to a system.

---

# Event Investigated

Event ID: 4720  
Description: A user account was created

---

# Splunk Query Used

```
index=main EventID=4720
| table _time SubjectUserName TargetUserName
```

---

# Investigation Results

| Time | User Creating Account | New Account |
|-----|-----|-----|
| 2022 | James | Alberto |

The logs show that the user **James created a new account named Alberto**.

---

# Security Analysis

This behavior is suspicious because attackers often create new user accounts after obtaining administrative privileges in order to maintain persistence within a compromised system.

Earlier investigation logs showed that **James executed administrative tools including PowerShell, WMIC, and NET commands**, suggesting that the account creation may be part of a larger attack chain.

---

# Attack Chain Observed

```
4624 → Successful Login
4672 → Privileged Login
4688 → Process Execution
4720 → New User Account Created
```

This sequence strongly suggests potential malicious activity.

---

# Recommended Incident Response Actions

If this activity were detected in a real environment:

1. Investigate the **James account**
2. Disable the **Alberto account**
3. Review authentication activity for both users
4. Check for additional persistence mechanisms
5. Determine whether lateral movement occurred

---

# Skills Demonstrated

• Windows Event Log Analysis  
• Splunk Query Investigation  
• Account Manipulation Detection  
• SOC Incident Analysis
