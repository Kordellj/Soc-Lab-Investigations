# 🔍 Lab 11: Process Termination Analysis (Event ID 4689)

## 📌 Objective
The objective of this lab was to analyze process termination events (Event ID 4689) in Splunk to identify potentially suspicious activity, such as attackers terminating processes to evade detection.

---

## 🧪 Environment
- Tool: Splunk Enterprise 8.2.6  
- Data Source: Windows Event Logs  
- Index: main  

---

## 🔎 Investigation Steps

### 1. Identify Terminated Processes
index=main EventID=4689
| stats count by ProcessName, AccountName
| sort -count

### 2. Review Process Activity
index=main EventID=4689
| table _time, ProcessName, AccountName

---

## 📊 Findings

The following processes were observed:

- backgroundTaskHost.exe  
- conhost.exe  
- svchost.exe  
- gpupdate.exe  
- net.exe  
- net1.exe  
- raserver.exe  
- WMIC.exe  

---

## 🚨 Analysis

Most processes observed (e.g., svchost.exe, backgroundTaskHost.exe) are standard Windows processes and are commonly terminated during normal system operations.

However, several processes require further attention:

- **WMIC.exe**
  - Commonly used for system management and remote execution  
  - Frequently abused by attackers for lateral movement and reconnaissance  

- **net.exe / net1.exe**
  - Used for account and network management  
  - Often leveraged in post-exploitation activity  

No corresponding process creation events (Event ID 4688) were identified for WMIC, which may indicate limited logging visibility in the environment.

---

## 🧠 Conclusion

No definitive malicious activity was confirmed. However, the presence of administrative tools such as WMIC and net.exe suggests potential post-exploitation behavior.

Additionally, the inability to correlate process creation events highlights gaps in telemetry, which can limit full visibility during investigations.

---

## 💡 Key Takeaways

- Process termination logs can reveal attacker cleanup behavior  
- Administrative tools like WMIC and net.exe are high-value indicators  
- Limited logging visibility can impact investigation accuracy  
- Correlation between multiple event types is critical in SOC analysis  

---

## 🛠 Skills Demonstrated

- Log analysis using Splunk  
- Event correlation  
- Threat hunting with limited data  
- Identifying suspicious system behavior  

---

## 📷 Evidence

(Add your screenshots here in GitHub after uploading them)
