# Threat-Hunting-THE-AZUKI-BREACH-SAGA-Part-1

# Threat Hunt Capture the Flag — gab-intern-vm

**Author:** Monica Francis — First-time Capture the Flag threat hunt
**Timeframe Analyzed:** 2025-10-01 - 2025-10-15 UTC

## Quick Flags Reference

| Flag | Description | Evidence / Answer |
|------|-------------|-----------------|
| 1 | Initial Execution Detection | `` |
| 2 | Defense Disabling | `` |
| 3 | Quick Data Probe | `` |
| 4 | Host Context Recon | `` |
| 5 | Storage Surface Mapping | `` |
| 6 | Connectivity & Name Resolution Check | `` |
| 7 | Interactive Session Discovery | `` |
| 8 | Runtime Application Inventory | `` |
| 9 | Privilege Surface Check | `` |
| 10 | Proof-of-Access & Egress Validation | `` |
| 11 | Bundling / Staging Artifacts | `` |
| 12 | Outbound Transfer Attempt (Simulated) | `` |
| 13 | Scheduled Re-Execution Persistence | `` |
| 14 | Autorun Fallback Persistence | `` |
| 15 | Planted Narrative / Cover Artifact | `` |

---

## Scenario


---



**Most Suspicious Machine:** ``

**KQL Used to Identify Suspicious Machine:**
```kql

```


---

## Flags

<details>
<summary>Flag 1 —  INITIAL ACCESS - Remote Access Source</summary>

**Objective:**  Identify the source of unauthorized access via Remote Desktop Protocol.

**KQL Used:**
```kql
DeviceLogonEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where ActionType contains "LogonSuccess"
| project Timestamp, RemoteDeviceName, ActionType, LogonType, RemoteIP, RemotePort
```


**Answer / Evidence:** `88.97.178.12`


</details>

<details>
<summary>Flag 2 — INITIAL ACCESS - Compromised User Account</summary>

**Objective:** Determine which credentials were compromised to assess unauthorized access.

**KQL Used:**
```kql
DeviceLogonEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where ActionType contains "LogonSuccess"
|project Timestamp, RemoteDeviceName, ActionType, LogonType, AccountName, RemoteIP, RemotePort
//| where LogonType has_any ("Remote", "Access")
```


**Answer / Evidence:** `kenji.sato`


</details>

<details>
<summary>Flag 3 — DISCOVERY - Network Reconnaissance</summary>

**Objective:** Identify lateral movement opportunities through network enumeration.

**KQL Used:**
```kql
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where ProcessCommandLine has_any ("esxcli", "Arp", "ipconfig", "ifconfig", "nbtstat", "route")
| project Timestamp, ActionType, ProcessCommandLine

```

**Answer / Evidence:** `"ARP.EXE" -a`


</details>

<details>
<summary>Flag 4 — DEFENCE EVASION - Malware Staging Directory</summary>

**Objective:** Identify activity related to the creation of staging directories for malicious tools.

**KQL Used:**
```kql
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where ProcessCommandLine has_any ("mkdir", "New", "attrib")
| project Timestamp, ActionType, ProcessCommandLine

```

**Answer / Evidence:** `C:\ProgramData\WindowsCache`


</details>

<details>
<summary>Flag 5 — DEFENCE EVASION - File Extension Exclusions</summary>

**Objective:** Identify file extension exclusions added to Windows Defender during the attack.

**KQL Used:**
```kql
DeviceRegistryEvents
| where DeviceName == "azuki-sl"
| where RegistryKey contains "Exclusions\\Extensions"
| where ActionType == "RegistryValueSet"

```


**Answer / Evidence:** `3`


</details>

<details>
<summary>Flag 6 — DEFENCE EVASION - Temporary Folder Exclusion</summary>

**Objective:** Determine temporary folder paths excluded from Windows Defender scanning.

**KQL Used:**
```kql
DeviceRegistryEvents
| where DeviceName == "azuki-sl"
| where RegistryKey contains "Exclusions\\Paths"
//| where ActionType == "RegistryValueSet"

```


**Answer / Evidence:** `C:\Users\KENJI~1.SAT\AppData\Local\Temp`


</details>

<details>
<summary>Flag 7 — DEFENCE EVASION - Download Utility Abuse</summary>

**Objective:**  Identify legitimate tools used to download malware covertly.

**KQL Used:**
```kql
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where Timestamp > datetime(2025-11-19T18:49:47.9876797Z)
| where ProcessCommandLine has_any ("http://", "https://")
| where ProcessCommandLine has_any (".exe", ".dll", ".bat", ".ps1", ".zip", ".dat")
| project Timestamp, DeviceName, FileName, ProcessCommandLine
| order by Timestamp asc

```


**Answer / Evidence:** `Certutil.exe`



</details>

<details>
<summary>Flag 8 — PERSISTENCE - Scheduled Task Name</summary>

**Objective:** Identify the scheduled task created for persistence.

**KQL Used:**
```kql
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where Timestamp > datetime(2025-11-19T18:49:47.9876797Z)
| where FileName == "schtasks.exe"
| where ProcessCommandLine has_any ("create", "query")
| project Timestamp, ActionType, FileName, ProcessCommandLine
```

**Answer / Evidence:** `Windows Update Check`


</details>

<details>
<summary>Flag 9 —  PERSISTENCE - Scheduled Task Target</summary>

**Objective:** Determine the executable path configured in the scheduled task for persistence.

**KQL Used:**
```kql

```

**Answer / Evidence:** `C:\ProgramData\WindowsCache\svchost.exe`


</details>

<details>
<summary>Flag 10 — COMMAND & CONTROL - C2 Server Address</summary>

**Objective:** Identify the command and control server used by the attacker.

**KQL Used:**
```kql
DeviceNetworkEvents
| where DeviceName == "azuki-sl"
| where Timestamp >= datetime(2025-11-19T19:06:58.7993762Z)
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteIP, RemotePort
| order by Timestamp asc
```

**Answer / Evidence:** `78.141.196.6`


</details>

<details>
<summary>Flag 11 — COMMAND & CONTROL - C2 Communication Port</summary>

**Objective:** Identify the destination port used for command and control communications. 

**KQL Used:**
```kql
DeviceNetworkEvents
| where DeviceName == "azuki-sl"
| where Timestamp >= datetime(2025-11-19T19:06:58.7993762Z)
| where RemotePort == "443"
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteIP, RemotePort
| order by Timestamp asc

```

**Answer / Evidence:** `443`


</details>

<details>
<summary>Flag 12 — CREDENTIAL ACCESS - Credential Theft Tool</summary>

**Objective:** Identify the filename of the credential dumping tool used by the attacker.

**KQL Used:**
```kql
DeviceFileEvents
| where DeviceName == "azuki-sl"
| where Timestamp >= datetime(2025-11-19T19:06:58.7993762Z)
| where FileName matches regex @"^[a-zA-Z0-9]{1,4}\.exe$"
| project Timestamp, FileName, FolderPath, SHA256
| order by Timestamp asc
```


**Answer / Evidence:** `mm.exe`



</details>

<details>
<summary>Flag 13 — CREDENTIAL ACCESS - Memory Extraction Module</summary>

**Objective:**  Identify the module used to extract logon passwords from memory.

**KQL Used:**
```kql
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where FileName == "mm.exe"
| project Timestamp, FileName, ProcessCommandLine
| order by Timestamp asc
```

**Answer / Evidence:** `sekurlsa::logonpasswords`



</details>

<details>
<summary>Flag 14 — COLLECTION - Data Staging Archive</summary>

**Objective:**  Identify the compressed archive filename used for data exfiltration.

**KQL Used:**
```kql
DeviceFileEvents
| where DeviceName == "azuki-sl"
| where Timestamp > datetime(2025-11-19T19:06:58.7993762Z)
| where FileName has ".zip"
//| project Timestamp, FileName, ProcessCommandLine
| order by Timestamp asc
```

**Answer / Evidence:** `export-data.zip`



</details>

<details>
<summary>Flag 15 — EXFILTRATION - Exfiltration Channel</summary>

**Objective:**  Identify the cloud service used to exfiltrate stolen data.

**KQL Used:**
```kql
DeviceNetworkEvents
| where DeviceName == "azuki-sl"
| where RemotePort == 443
| where Timestamp > datetime(2025-11-19T19:06:58.7993762Z)
| project Timestamp, DeviceName, InitiatingProcessFileName, RemoteUrl, RemoteIP
| order by Timestamp asc

```


**Answer / Evidence:** `discord`



</details>

<details>
<summary>Flag 16 —  ANTI-FORENSICS - Log Tampering</summary>

**Objective:**

**KQL Used:**
```kql
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where ProcessCommandLine contains "wevtutil"
| project Timestamp, ProcessCommandLine
| order by Timestamp asc
```


**Answer / Evidence:** `Security`

**Analyst Note:** 

</details>

</details>

<details>
<summary>Flag 17 —  IMPACT - Persistence Account</summary>

**Objective:**

**KQL Used:**
```kql
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where ProcessCommandLine contains "/add"
| project Timestamp, ActionType, FileName, ProcessCommandLine, InitiatingProcessFileName
```


**Answer / Evidence:** `support`

**Analyst Note:** 

</details>

</details>

<details>
<summary>Flag 18 —  EXECUTION - Malicious Script</summary>

**Objective:**

**KQL Used:**
```kql
DeviceFileEvents
| where DeviceName == "azuki-sl"
| where Timestamp <= datetime(2025-11-19T18:49:47.9876797Z)
| where ActionType == "FileCreated"
| where FolderPath contains "temp"
| where InitiatingProcessCommandLine has_any ("Start", "Invoke")
| project Timestamp, ActionType, FileName, FolderPath, InitiatingProcessCommandLine
```


**Answer / Evidence:** `wupdate.ps1`

**Analyst Note:** 

</details>

</details>

<details>
<summary>Flag 19 —  LATERAL MOVEMENT - Secondary Target</summary>

**Objective:**

**KQL Used:**
```kql
DeviceNetworkEvents
| where DeviceName == "azuki-sl"
| where InitiatingProcessCommandLine has_any ("cmdkey", "mstsc")
| project Timestamp, ActionType, RemoteIP, InitiatingProcessCommandLine, InitiatingProcessParentFileName, InitiatingProcessRemoteSessionDeviceName
```


**Answer / Evidence:** `10.1.0.188`

**Analyst Note:** 

</details>

<details>
<summary>Flag 20 —   LATERAL MOVEMENT - Remote Access Tool</summary>

**Objective:**

**KQL Used:**
```kql
DeviceNetworkEvents
| where DeviceName == "azuki-sl"
| where InitiatingProcessCommandLine has_any ("cmdkey", "mstsc")
| project Timestamp, ActionType, RemoteIP, InitiatingProcessFileName, InitiatingProcessRemoteSessionDeviceName
| order by Timestamp asc
```


**Answer / Evidence:** `mstsc.exe`

**Analyst Note:** 

</details>

---

## Analyst Reasoning / Logical Flow

1. 
