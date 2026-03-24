# 🚨 Investigation of Suspicious External Authentication Traffic Using Splunk

## 📌 Scenario
A potential security concern was identified involving repeated authentication activity within a Windows environment. The goal of this investigation was to analyze authentication logs and determine whether the activity represented normal behavior or a possible security risk.

## 🎯 Objective
- Identify successful network logon activity  
- Detect unusual authentication behavior  
- Determine whether external IP addresses were interacting with internal systems  
- Analyze authentication methods used  

## 🛠️ Tools Used
- Splunk  
- Windows Event Logs  
- TryHackMe AttackBox  

---

## 🔍 Investigation

### Step 1: Identify Network Logon Activity

Query:
index=main EventID=4624 LogonType=3
| stats count by LogonType
| sort -count


Findings:  
I identified 20 successful network logon events. All events were Logon Type 3, which confirms that the activity involved network-based authentication rather than local logins.

---

### Step 2: Review Authentication Fields

Query:
index=main EventID=4624 LogonType=3
| table AccountName WorkstationName ProcessName AuthenticationPackageName IpAddress TargetUserName ComputerName


Findings:  
Some fields such as AccountName and WorkstationName were not populated, so I pivoted to the fields that contained useful data. The authentication type was consistently Kerberos, and I observed a repeated IP address (172.90.12.11) along with a repeated machine account (WORKSTATION5$).

![Field Review](screenshots/step1-field-review.png)

---

### Step 3: Identify Most Active IP Address

Query:
index=main EventID=4624 LogonType=3
| stats count by IpAddress
| sort -count


Findings:  
The IP address 172.90.12.11 generated 11 successful logon events, making it the most active source in the dataset. Other IP addresses were minimal or represented local/IPv6 traffic.

![Top IP](screenshots/step2-top-ip.png)

---

### Step 4: Investigate Suspicious IP Activity

Query:
index=main EventID=4624 IpAddress="172.90.12.11"
| table _time TargetUserName ComputerName AuthenticationPackageName


Findings:  
I observed repeated authentication attempts from 172.90.12.11 targeting the system WORKSTATION5$. There was also user activity involving “James.” All authentication events used Kerberos, which is typically associated with internal domain environments.

![IP Breakdown](screenshots/step3-ip-breakdown.png)

---

## 🌐 Network Analysis

Internal IP ranges include:
- 10.x.x.x  
- 192.168.x.x  
- 172.16–172.31.x.x  

The IP address **172.90.12.11** falls outside of these ranges, meaning it is a **public (external) IP address**.

---

## 🧠 Analysis Summary

This investigation identified repeated successful network logons (Event ID 4624, Logon Type 3) originating from the external IP address 172.90.12.11. This IP generated the highest volume of authentication activity and was associated with Kerberos authentication targeting internal systems such as WORKSTATION5$, along with user activity involving James.

Because Kerberos is typically used within internal domain environments, repeated authentication from an external IP may indicate unauthorized access, misconfigured network exposure, or abnormal authentication behavior.

---

## 🎯 Key Insight

This investigation demonstrates how authentication logs can reveal suspicious network behavior, especially when external sources interact with internal systems. Monitoring this type of activity is critical for both network engineers and security analysts.

---

## 🛡️ Recommendations

- Restrict external access to authentication services  
- Review firewall rules and exposure points  
- Monitor repeated authentication attempts from external IPs  
- Investigate the IP address 172.90.12.11  
- Enable alerting for abnormal Kerberos activity  

---

## 🧭 MITRE ATT&CK Mapping

- T1078 – Valid Accounts  
- T1021 – Remote Services  

---

## ✅ Conclusion

The investigation revealed repeated authentication activity from a public IP address interacting with internal systems using Kerberos. This behavior is not typical and should be investigated further, as it may indicate unauthorized access or network misconfiguration.

---

