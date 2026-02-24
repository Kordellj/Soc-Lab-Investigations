# 4688 Process Creation Investigation (Splunk)

## 🎯 Objective
Investigate Windows Event ID 4688 (Process Creation) events to identify suspicious behavior.

---

## 🧪 Environment
- Platform: Splunk Enterprise
- Log Source: Windows Security Logs
- Index: main

---

## 🔎 Step 1 – Review All Process Creations

```spl
index=main EventID=4688
| stats count by NewProcessName
```

### Findings:
Reviewed all created processes to identify potentially suspicious binaries.

📸 Screenshot:
![Step 1](4688-Process-Creation-Investigation/screenshots/4688-overview.png)
---

## Step 2 – Investigate WMIC Execution

### SPL Query
```spl
index=main EventID=4688 NewProcessName="*wmic*"
| table _time ParentProcessName NewProcessName CommandLine SubjectUserName
| sort _time
```

### Findings
- **ParentProcessName:** `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
- **NewProcessName:** `C:\Windows\System32\wbem\WMIC.exe`
- **SubjectUserName:** `James`

### Analysis
WMIC was launched from PowerShell under the user **James**.

PowerShell spawning WMIC is noteworthy because:
- WMIC can be used for remote command execution
- It is commonly abused for lateral movement
- It allows system and user enumeration

In a real SOC investigation, this would warrant deeper review of:
- The full command line arguments
- Network connections during execution
- Related authentication events (4624 logons)

📸 Screenshot:
![Step 2](4688-Process-Creation-Investigation/screenshots/4688-wmic.png)

## 🔍 Step 3 – Investigate net.exe Usage

```spl
index=main EventID=4688 NewProcessName="*net.exe*"
| table _time ParentProcessName NewProcessName CommandLine SubjectUserName
| sort _time
```

### Findings:
- net.exe executed
- Reviewed command line activity
- net.exe can be used for user management and privilege modification

📸 Screenshot:
![Step 3](4688-Process-Creation-Investigation/screenshots/4688-net.png)

---

## 🧠 Analyst Assessment

Event ID 4688 logs were reviewed to identify suspicious process creation activity.

WMIC and net.exe were identified as potentially sensitive binaries due to their ability to:
- Perform remote execution
- Modify user accounts
- Conduct administrative actions

No clear malicious command-line activity was identified in this dataset. However, this lab demonstrates how attackers may leverage legitimate Windows utilities (Living Off the Land Binaries – LOLBins) for post-compromise activity.

---

## 🏁 Conclusion

This investigation demonstrates:
- Process creation analysis
- Parent-child process review
- Command-line inspection
- Suspicious binary identification
- Basic threat hunting workflow in Splunk
