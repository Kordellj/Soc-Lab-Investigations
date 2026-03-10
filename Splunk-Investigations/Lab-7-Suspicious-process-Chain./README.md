# Lab 6 – Suspicious Process Chain Investigation (PowerShell → WMIC → NET)

## Objective

Investigate suspicious process creation events using Splunk to identify potential attacker activity leveraging built-in Windows administrative tools.

This investigation focuses on detecting **Living-Off-The-Land (LOLBins)** tools such as:

- PowerShell
- WMIC
- NET commands

These tools are commonly abused by attackers to perform lateral movement and account manipulation without dropping malware.

---

# Environment

Platform: TryHackMe SOC Investigation Lab  
SIEM: Splunk  
Log Source: Windows Security Event Logs  
Event ID Investigated: **4688 – Process Creation**

---

# Investigation Steps

## Step 1 – Identify Process Creation Events

First, process creation activity was reviewed to determine which programs were executed on the system.

Splunk Query:

```
index=main EventID=4688
| stats count by NewProcessName
| sort -count
```

### Result

Most frequently executed process:

```
C:\Windows\System32\svchost.exe
```

This is expected behavior because `svchost.exe` manages Windows services.

---

# Step 2 – Hunt for Suspicious Administrative Tools

Next, common attacker tools were searched for within process creation logs.

Splunk Query:

```
index=main EventID=4688
| search NewProcessName="*powershell*" OR NewProcessName="*cmd*" OR NewProcessName="*wmic*" OR NewProcessName="*net*"
| table _time SubjectUserName NewProcessName ParentProcessName
```

---

# Step 3 – Identify Suspicious Process Chain

The following suspicious processes were identified:

| Time | User | Process | Parent Process |
|-----|-----|-----|-----|
| 2022-05-11 | James | wmic.exe | powershell.exe |
| 2022-05-11 | WORKSTATION6$ | net.exe | wmiprvse.exe |
| 2022-05-11 | James | net1.exe | net.exe |

---

# Process Chain Analysis

The investigation revealed the following execution chain:

```
powershell.exe
      ↓
wmic.exe
      ↓
net.exe
      ↓
net1.exe
```

This behavior is suspicious because attackers frequently use PowerShell to launch administrative tools such as WMIC and NET commands.

These tools can be used for:

- Creating new user accounts
- Modifying group memberships
- Lateral movement
- Executing remote commands

---

# Security Analysis

The user **James** executed several administrative tools through PowerShell, indicating potential attacker activity.

The usage of:

- PowerShell
- WMIC
- NET commands

suggests the possibility of account manipulation or system enumeration.

These tools are considered **Living-Off-The-Land Binaries (LOLBins)** because attackers abuse legitimate system tools to avoid detection.

---

# Detection Strategy

SOC analysts can detect this activity by monitoring:

- Event ID **4688 (Process Creation)**
- Suspicious parent-child process relationships
- Administrative tool usage by non-administrative users

Example detection logic:

```
powershell.exe → wmic.exe → net.exe
```

---

# Incident Response Recommendation

If this activity were detected in a real environment, analysts should:

1. Investigate the **James** user account
2. Check for newly created user accounts
3. Review authentication logs for unusual activity
4. Determine if lateral movement occurred
5. Disable compromised accounts if necessary

---

# Key Takeaways

This investigation demonstrates how attackers abuse built-in Windows tools to execute commands and manipulate systems without deploying malware.

Monitoring process creation logs allows SOC analysts to detect suspicious activity and identify potential attacker behavior early.

---

# Skills Demonstrated

- Splunk Query Development
- Windows Event Log Analysis
- Process Chain Investigation
- Living-Off-The-Land Detection
- Soc Incident Analysis
