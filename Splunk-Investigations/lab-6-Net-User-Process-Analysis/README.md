Splunk-Investigations/Lab-6-Net-User-Process-Analysis/README.md
📄 Lab 6 – Suspicious Process Creation (Net User via WMIC)
🧠 Objective

Investigate suspicious process creation activity involving account creation using native Windows tools.

This lab focuses on:

Event ID 4688 (Process Creation)

Identifying malicious use of net.exe

Parent-child process relationships

Correlating activity with elevated privileges (Event ID 4672)

🔍 Step 1 – Identify Process Creation Events

SPL Query:

index=main EventID=4688
| stats count by NewProcessName
📖 Translation in English:

Search Windows logs for all process creation events and summarize how many times each process was executed.

🔍 Step 2 – Hunt for Account Creation Commands

SPL Query:

index=main EventID=4688 NewProcessName="*net.exe*"
| table _time SubjectUserName NewProcessName ParentProcessName CommandLine
📖 Translation in English:

Search for instances where net.exe was executed, and display:

Time

User who executed it

Process name

Parent process

Full command line

🔎 Findings

User James executed net.exe

The command line revealed:

net user Alberto Password123 /add

Parent process involved: wmic.exe

Activity occurred after elevated privileges were assigned (Event ID 4672)

🚨 Why This Is Suspicious

net user /add creates a new local account.

WMIC can be used for remote execution.

Account creation combined with privilege escalation is a common persistence technique.

Activity occurred during network logon sessions (Logon Type 3).

The user was assigned special privileges (Event ID 4672).

This chain of events strongly suggests:

Unauthorized privilege escalation

Persistence attempt

Possible lateral movement setup

🔗 Correlated Events
Event ID	Meaning
4624	Successful Logon
4672	Special Privileges Assigned
4688	Process Creation
4720	User Account Created
🛡 Recommended Response

Disable the newly created account (Alberto)

Investigate user James

Review all activity from source IP address 172.90.12.11

Check for lateral movement indicators

Validate if the account creation was authorized

Initiate containment if malicious

🎯 SOC Analyst Takeaway

Successful logins alone are not enough to determine compromise.

What matters is:

What privileges were assigned

What processes were created

Whether new accounts were added

Whether administrative tools were abused

Attackers often:

Gain valid credentials

Escalate privileges

Create persistence via local accounts

Use native tools (Living off the Land)

This investigation demonstrates detection of suspicious account creation via process monitoring.
