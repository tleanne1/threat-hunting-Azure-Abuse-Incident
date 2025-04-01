![brute-force-attack](https://github.com/user-attachments/assets/e597fd2e-687a-46b4-bf4e-df957ff9287e)

## Threat Hunt Report: Azure Abuse Incident Involving Brute-Force Attacks

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)

## Summary
This report summarizes the results of a threat hunt investigation in response to a Microsoft Azure Safeguards Team abuse notice. Microsoft flagged IP address `20.81.228.191`, associated with Azure VM `sakel-lunix-2`, for brute-force traffic. The investigation confirms the abuse report, identifies the initial compromise point (Ground Zero), and outlines attacker activity, persistence, and lateral movement.

Although no successful login was directly tied to a remote IP, a root-level process (`dash`) was executed immediately after 101 failed login attempts from IP `37.32.15.8`. We assess with high confidence that this IP is the source of the compromise.

**Date:** March 2025
**Subscription ID:** `3c95e63a-895a-4386-991e-edbbf57de5c8`
**Impacted Resource:** `sakel-lunix-2` (Geo: East US 2)

---

## Timeline of Events

| Timestamp (UTC)            | Event Description                                                         |
|----------------------------|---------------------------------------------------------------------------|
| Feb 24, 2025 - 6:47 PM     | `dash` executed on `ff-vm-lx-224-base` (initial compromise)                   |
| Feb 24, 2025 - 6:47 PM     | Internal SSH connection from `ff-vm-lx-224-base` to `10.0.0.8`                |
| Mar 16, 2025 - 12:47 AM    | `sakel-lunix-2` executes `dash`; cron jobs initiate root access               |
| Mar 16, 2025 - 2:06 AM     | External root login on `sakel-lunix-2` from IP `14.45.226.52`                 |
| Mar 18, 2025 - 6:40 AM     | Microsoft abuse alert triggered for IP `20.81.228.191`                

---

## Validation of Abuse Claim

- Confirmed brute-force traffic from `sakel-lunix-2` to multiple external IPs on port 22.
- Activity aligned with timestamp and evidence in Microsoft's notice.

---

## Origin of Malicious Activity

**Ground Zero Identified:  `ff-vm-lx-224-base` (Azure Linux VM)**
On `sakel-lunix-2`, further activity was observed including `dash` execution, cron persistence, and SSH brute-force behavior that was ultimately flagged by Microsoft Azure Safeguards Team.

This investigation confirms `ff-vm-lx-224-base` as the earliest compromised host in the environment, acting as the attack origin from which lateral movement and outbound abuse campaigns were launched.

Just seconds before dash was executed on `ff-vm-lx-224-base`, it accepted an SSH connection from internal IP `10.0.0.8`, which was previously identified as an attacker pivot system.

This validates that:
- `ff-vm-lx-224-base` was compromised first
- The attacker pivoted internally to `10.0.0.8`
- From there, they reached `sakel-lunix-2` and other VMs

--- 

## Indicators of Compromise (IOCs)

**Files/Processes:**
- `/usr/bin/dash` (abused for in-memory execution)
- PowerShell processes with -ExecutionPolicy Bypass
- Scheduled task: AC Power Download
- Multiple sshd processes (on `ff-vm-lx-224-base`)

**IPs Contacted or Logged In to Compromised Hosts:**
- `168.63.129.16` (likely metadata)
- `31.128.3.244` - `31.128.3.247` (external SSH brute-force targets)
- `37.32.15.8`  (initial brute force attempts)
- `14.45.226.52` (external root login to sakel-lunix-2)
- `123.7.142.76` (root login to ff-vm-lx-224-base)

**Hash Values:**
- `dash` SHA1: `42e94914c7800c7063c51d7a17aec3a2069a3769`
- `grep` SHA1: `4364e3437c75199361968b77f556d29c097b93e5`

---

## Attacker Behavior & TTPs (MITRE ATT&CK)
- Initial Access: Exploit Public-Facing Application / Brute Force (T1190 / T1110)
- Execution: Command & Scripting Interpreter: Unix Shell / PowerShell (T1059.004/.001)
- Persistence: Scheduled Task/Job (T1053)
- Privilege Escalation: Abuse of `TrustedInstaller.exe` / Registry Modification (T1547.001)
- Defense Evasion: Disabling Security Tools / Registry Modification (T1562.001)
- Lateral Movement: Remote Services: SMB/NTLM Brute Force (T1021.002)
- Command and Control: SSH (T1021.004)

---

## Recommendations

**🔧 Immediate Remediation**
- Isolate affected VMs from the network
- Terminate all active sessions
- Reimage compromised systems
- Reset credentials (root, SYSTEM, reused accounts)
- Delete malicious scheduled task `AC Power Download`
- Block outbound SSH traffic
- Notify Microsoft of threat validation

**🛡️ Long-Term Hardening**
- Enforce MFA
- Enable Just-in-Time VM access
- Restrict SSH access via NSG or Bastion
- Enable Adaptive Application Controls
- Deploy centralized log retention
- Rotate and audit credentials
- Automate threat hunting playbooks

---

## Support Queries Executed

The following KQL queries were used throughout the investigation. Screenshots of results can be found in the appendix.

**🔹 Initial Investigation & Verification**

```kql
DeviceInfo
| where PublicIP == "20.81.228.191"
```
<img width="1438" alt="image1" src="https://github.com/user-attachments/assets/b2070083-2e97-4aee-a265-5a24fc0245a8" />
<br><br>

```kql
union *
| summarize count() by Type
```
<img width="705" alt="image2" src="https://github.com/user-attachments/assets/bd7d9ca2-3d77-47e4-9bd2-8172232584a7" />
<br><br>

```kql
DeviceProcessEvents
| summarize count()
```
<img width="602" alt="image3" src="https://github.com/user-attachments/assets/0959cbfd-96ac-4934-babe-3be1a5842759" />

---

**🔹 Failed and Successful Login Attempts**

```kql
DeviceLogonEvents
| where DeviceName == "sakel-lunix-2"
| where ActionType == "LogonFailed"
| summarize AttemptCount=count() by AccountName, RemoteIP, bin(Timestamp, 5m)
| order by AttemptCount desc
```
<img width="1131" alt="image4" src="https://github.com/user-attachments/assets/7ed739ba-7354-425e-b091-67bcc726bba2" />
<br><br>

```kql
DeviceLogonEvents
| where DeviceName == "sakel-lunix-2"
| where ActionType == "LogonSuccess"
| summarize AttemptCount=count() by AccountName, RemoteIP, bin(Timestamp, 5m)
| order by AttemptCount desc
```
<img width="970" alt="image5" src="https://github.com/user-attachments/assets/ccb4c002-eaca-435d-a01f-588350e283ac" />

---

**🔹 Initial Exploitation / 'dash' Execution**

```kql
DeviceProcessEvents
| where DeviceName == "sakel-lunix-2"
| where Timestamp > ago(30d)
| order by Timestamp asc
```
<img width="1443" alt="image8" src="https://github.com/user-attachments/assets/f2882094-7dc3-4463-aa7f-4e68b35dbaa3" />
<br><br>

```kql
DeviceProcessEvents
| where DeviceName == "sakel-lunix-2"
| where FileName == "dash"
| order by Timestamp asc
```
<img width="1434" alt="image9" src="https://github.com/user-attachments/assets/aeb2d66b-c6dc-4fd2-b0cb-2cbaa3116bb9" />

---

**🔹 Attack Behavior from Internal Hosts**

```kql
DeviceLogonEvents
| where DeviceName == "vm-final-lab-ha"
| where RemoteIP == "10.0.0.8"
| order by Timestamp asc
```
<img width="1415" alt="image10" src="https://github.com/user-attachments/assets/21f76b58-3dd5-4eb6-819c-60ff8c17d431" />
<br><br>

```kql
DeviceProcessEvents
| where DeviceName == "vm-final-lab-ha"
| where FileName == "powershell.exe"
| order by Timestamp asc
| project Timestamp, ProcessCommandLine, InitiatingProcessFileName
```
<img width="832" alt="image11" src="https://github.com/user-attachments/assets/5a6c4998-187e-4dd5-8666-d67f9c31f8c8" />
<br><br>

```kql
DeviceEvents
| where DeviceName == "vm-final-lab-ha"
| where ActionType contains "PowerShellCommand"
| order by Timestamp asc
```
<img width="971" alt="image12" src="https://github.com/user-attachments/assets/3c4742fc-8335-458e-956c-d9853ed093a5" />

---

**🔹 Persistence Mechanisms**

```kql
DeviceEvents
| where DeviceName == "vm-final-lab-ha"
| where ActionType contains "ScheduledTaskCreated" or ActionType contains "ScheduledTaskModified"
| order by Timestamp asc
```
<img width="1376" alt="image13" src="https://github.com/user-attachments/assets/4c134d03-6b66-489f-bcf1-bbfb0506fe7c" />
<br><br>

```kql
DeviceFileEvents
| where DeviceName == "vm-final-lab-ha"
| where ActionType == "FileCreated"
| where FolderPath contains "C:\\Windows\\Tasks" or FolderPath contains "C:\\Windows\\System32\\Tasks"
| order by Timestamp asc
```
<img width="1408" alt="image14" src="https://github.com/user-attachments/assets/4caf4cd6-b489-4584-a17e-ec063e223106" />
<br><br>

```kql
DeviceProcessEvents
| where DeviceName == "vm-final-lab-ha"
| where InitiatingProcessFileName == "taskhostw.exe" or InitiatingProcessFileName == "svchost.exe"
| where Timestamp > datetime(2025-03-15 8:43:00 PM)
| order by Timestamp asc
```
<img width="1360" alt="image15" src="https://github.com/user-attachments/assets/4ceaf41d-b79f-4770-a72b-59ea67049972" />

---

**🔹 Network Lateral Movement & Brute Force**

```kql
DeviceNetworkEvents
| where RemoteIP == "10.0.0.8"
| summarize ConnectionCount=count() by DeviceName, RemotePort
| order by ConnectionCount desc
```
<img width="627" alt="image16" src="https://github.com/user-attachments/assets/18219c05-8340-4fbf-8a72-9863a7a16e0a" />
<br><br>

```kql
DeviceNetworkEvents
| where RemoteIP == "10.0.0.8"
| order by Timestamp asc
| take 10
```
<img width="1353" alt="image17" src="https://github.com/user-attachments/assets/2e3c2952-b21f-402c-8cb9-e3a65f217870" />
<br><br>

---

🔹 Final Attribution – Confirm Ground Zero

```kql
DeviceProcessEvents
| where DeviceName == "sakel-lunix-2"
| order by Timestamp asc
| take 10
```
<img width="1365" alt="image18" src="https://github.com/user-attachments/assets/89669687-45a8-4541-b5a3-d2414dcfea02" />
<br><br>

```kql
DeviceNetworkEvents
| where DeviceName == "sakel-lunix-2"
| where RemoteIP !startswith "10."
| order by Timestamp asc
```
<img width="1236" alt="image19" src="https://github.com/user-attachments/assets/20e72e25-c2bc-4a33-a946-c664da5e816f" />
<br><br>

```kql
DeviceLogonEvents
| where DeviceName == "sakel-lunix-2"
| order by Timestamp asc
```
<img width="1298" alt="image20" src="https://github.com/user-attachments/assets/2df616dc-2288-4cbd-9295-7ba531442544" />

---

**🔹 Ground Zero Confirmation (ff-vm-lx-224-base)**

```kql
DeviceProcessEvents
| where DeviceName == "ff-vm-lx-224-base.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net"
| where InitiatingProcessAccountName == "root"
| where FileName in ("bash", "sh", "dash", "python", "wget", "curl")
| order by Timestamp asc
```
<img width="1368" alt="image21" src="https://github.com/user-attachments/assets/6ff0c718-20a4-46bd-bfb2-823d1010448c" />

<br><br>

```kql
DeviceNetworkEvents
| where DeviceName == "ff-vm-lx-224-base.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net"
| where RemoteIP startswith "10."  // look for internal connections
| where Timestamp between (datetime(2025-02-24 18:30:00) .. datetime(2025-03-16 00:00:00))
```
<img width="1358" alt="image22" src="https://github.com/user-attachments/assets/692d2cee-42c6-4c97-808d-8496f9b6ad40" />

---

## Final Notes
This incident demonstrates the importance of layered monitoring across cloud infrastructure and endpoint systems. Swift action and comprehensive hunting successfully identified the threat origin and progression.

- **Status:** Incident Confirmed & Scoped
- **Ground Zero:** `ff-vm-lx-224-base`
- **Scope:** Lateral movement confirmed to `10.0.0.8`, `sakel-lunux-2`, and `vm-final-lab-ha`

---

## Appendices: Detailed Host Findings

### Appendix A – Host: sakel-lunix-2
- **Summary:** Azure Linux VM used in brute-force traffic. Root shell executed via dash and persistent access maintained via cron.
- **Timeline:**
  - Mar 16, 2025 - 12:47:44 AM: `dash` executed
  - Mar 16, 2025 - 12:48:01 AM: Root cron job initiated
  - Mar 16, 2025 - 2:06 AM: Login from IP `14.45.226.52`
- **IOCs:** dash, IPs `37.32.15.8`, `14.45.226.52`

### Appendix B – Host: vm-final-lab-ha
- **Summary:** Windows VM accessed from `10.0.0.8`, PowerShell used, scheduled task created for persistence.
- **Timeline:**
  - Mar 15, 2025 - 7:35 PM: Lateral movement starts
  - Mar 15, 2025 - 7:36 PM: PowerShell script execution
  - Mar 15, 2025 - 8:43 PM: Scheduled task `AC Power Download` created
- **IOCs:** `schtasks.exe`, `powershell.exe`, pivot IP `10.0.0.8`
  
## Appendix C – Host: ff-vm-lx-224-base
- **Summary:** Earliest confirmed compromise. Accessed via IP `123.7.142.76`, executed dash as root. Pivoted internally to `10.0.0.8`.
- **Timeline:**
  - Feb 24, 2025 - 6:46 PM: SSH connection to `10.0.0.8`
  - Feb 24, 2025 - 6:47 PM: `dash` executed
- **IOCs:** `123.7.142.76`, `dash`, sshd
