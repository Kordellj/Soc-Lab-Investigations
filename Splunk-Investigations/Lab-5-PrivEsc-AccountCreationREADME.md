# Lab 5 — Privilege Escalation + Account Creation (Splunk Investigation)

## Goal
Investigate Windows security logs to identify suspicious activity involving:
- **4672** (Special privileges assigned to new logon)
- **4624** (Successful logon)
- **4688** (Process creation)

Focus: determine whether a user received elevated privileges and then used them to create a new local account.

---

## Environment
- Platform: TryHackMe (Splunk Search & Reporting)
- Data Source: Windows Security Event Logs
- Index Used: `main` (TryHackMe lab dataset)

---

## Key Findings (Summary)
- A real user account (**James**) appeared in multiple relevant events compared to system/service accounts (e.g., `SYSTEM`, accounts ending in `$`).
- Evidence suggests a chain:
  1) User logon activity (4624)
  2) Special privileges assigned at logon (4672)
  3) Process creation tied to account creation (4688), including commands consistent with creating a new user.

**Suspicious behavior:** elevated privileges + process execution that creates a new account.

---

## Investigation Steps + SPL (with English translation)

### 1) Identify who is receiving special privileges (Event ID 4672)
**SPL**
```spl
index=main EventID=4672
| stats count by SubjectUserName
| sort -count

English
Search Windows logs for all events where special privileges were assigned at logon, then summarize how many times each account received them.

What I looked for

Normal user names (not SYSTEM)

Non-machine accounts (machine accounts typically end with $)

2) Focus on the suspicious user (James) for privileged logons (4672)

SPL

index=main EventID=4672 SubjectUserName="James"
| table _time SubjectUserName TargetUserName PrivilegeList
| sort _time

English
Show the timestamp and privilege details for instances where James was assigned special privileges.

Note
In this dataset, the PrivilegeList field may not display as a clean column even though the raw event contains it. Reviewing the raw event shows privileges (example: impersonation-related privileges).

3) Confirm successful logons for the suspicious user (Event ID 4624)

SPL

index=main EventID=4624 TargetUserName="James"
| table _time TargetUserName IpAddress LogonType
| sort _time

English
Show when James successfully logged in, and from what IP address / logon type.

Why this matters
A 4624 alone isn’t always suspicious — but it becomes important when it’s followed by privileged logon + suspicious process execution.

4) Identify process creation activity tied to the suspicious user (Event ID 4688)

SPL

index=main EventID=4688 TargetUserName="James"
| table _time NewProcessName ParentProcessName CommandLine
| sort _time

English
Show what processes James created, what spawned them, and the command line used.

5) Confirm account creation behavior inside command line output (net.exe / net1.exe)

SPL

index=main EventID=4688
| search CommandLine="*net user*" OR CommandLine="*net1 user*"
| table _time TargetUserName NewProcessName CommandLine
| sort _time

English
Search for process creation events that include commands used to create users (common attacker technique).

Observed
Commands consistent with creating a new user account, such as:

net user /add ...

net1 user /add ...

Interpretation (Why this is suspicious)

4672 means a logon session received elevated privileges.

4688 shows what the user did after logging in.

In this case, elevated privileges + process creation + user creation commands strongly suggests malicious behavior or compromised credentials.

Recommended Next Checks (What I would do as a SOC Analyst)

Identify whether the created user was added to privileged groups (Administrators / Remote Desktop Users).

Check for additional persistence actions (scheduled tasks, services, registry run keys).

Check lateral movement signs (WMI, PSExec, remote service creation).

Validate whether the source IP is expected for the user and environment.
