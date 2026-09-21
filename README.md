# SOC Monitoring & Threat Detection Lab using Splunk & Microsoft Sentinel

## Overview

This project demonstrates the design and implementation of a Security Operations Center (SOC) home lab for security monitoring, threat detection, and incident investigation using Splunk Enterprise, Microsoft Sentinel, Sysmon, and Windows Event Logs.

The lab simulates real-world attack scenarios, including brute-force attacks, PowerShell abuse, and suspicious process execution. Security events are collected, analyzed, and investigated using SIEM technologies to develop practical SOC analyst skills.

---

## Objectives

* Build a SOC monitoring lab using industry-standard tools.
* Collect and analyze Windows Event Logs and Sysmon telemetry.
* Simulate common attack techniques in a controlled environment.
* Create detections using Splunk SPL and Microsoft Sentinel KQL.
* Investigate security alerts and identify Indicators of Compromise (IOCs).
* Apply MITRE ATT&CK techniques to security incidents.
* Develop incident investigation and response workflows.

---

## Lab Environment

### Operating Systems

* Kali Linux
* Windows 10

### Security Monitoring

* Splunk Enterprise
* Microsoft Sentinel
* Sysmon
* Windows Event Logs

### Attack Simulation Tools

* Hydra
* PowerShell
* Windows Command Line
* Kali Linux Security Tools

### Analysis Tools

* Splunk SPL
* Kusto Query Language (KQL)
* MITRE ATT&CK Framework

---

## Architecture

```text
Attacker Machine (Kali Linux)
             |
             v
Victim Machine (Windows 10 + Sysmon)
             |
             +-------------------+
             |                   |
             v                   v
      Splunk Enterprise    Microsoft Sentinel
             |                   |
             +---------+---------+
                       |
                       v
              Alert Investigation
                       |
                       v
                Incident Response
```

---

## Log Collection

### Windows Logs Collected

* Security Logs
* System Logs
* Application Logs
* PowerShell Logs

### Sysmon Logs Collected

* Process Creation
* Network Connections
* Image Loads
* File Creation Events
* Registry Modifications

### Data Sources

* Windows Event Viewer
* Sysmon
* Splunk Universal Forwarder
* Microsoft Sentinel Data Connectors

---

## Attack Simulations

### Scenario 1: Brute-Force Login Attack

#### Objective

Generate multiple failed authentication events.

#### Attack Tool

Hydra (Kali Linux)

#### Expected Events

* Event ID 4625 (Failed Logon)
* Multiple authentication failures

#### Detection Goal

Identify brute-force attempts through excessive failed logins.

---

### Scenario 2: PowerShell Abuse

#### Objective

Simulate suspicious PowerShell execution.

#### Commands Executed

```powershell
powershell.exe
whoami
ipconfig
net user
```

#### Expected Events

* Event ID 4104 (PowerShell Script Block Logging)
* Sysmon Event ID 1 (Process Creation)

#### Detection Goal

Identify suspicious PowerShell activity and command execution.

---

### Scenario 3: Suspicious Process Execution

#### Objective

Generate process creation telemetry.

#### Commands Executed

```cmd
cmd.exe
powershell.exe
```

#### Expected Events

* Sysmon Event ID 1
* Process Tree Relationships

#### Detection Goal

Identify suspicious parent-child process behavior.

---

## Splunk Detection Rules

### Brute-Force Detection

```spl
index=wineventlog EventCode=4625
| stats count by Account_Name Source_Network_Address
| where count > 10
```

### PowerShell Detection

```spl
index=sysmon Image="*powershell.exe*"
```

### Suspicious Process Creation

```spl
index=sysmon EventCode=1
| table _time Computer ParentImage Image User
```

---

## Microsoft Sentinel Detection Rules

### Failed Login Detection

```kql
SecurityEvent
| where EventID == 4625
| summarize FailedAttempts=count() by Account
| where FailedAttempts > 10
```

### PowerShell Activity Detection

```kql
SecurityEvent
| where EventID == 4104
```

### Process Monitoring

```kql
Event
| where EventID == 1
```

---

## Alert Investigation Workflow

### Step 1: Alert Review

Analyze:

* Alert Name
* Timestamp
* Source Host
* User Account
* Event ID
* Severity

### Step 2: Event Analysis

Review:

* Process Activity
* Authentication Logs
* PowerShell Commands
* Network Connections

### Step 3: IOC Identification

Extract:

* IP Addresses
* User Accounts
* Process Names
* Command Lines

### Step 4: Incident Classification

Map activity to MITRE ATT&CK techniques.

### Step 5: Incident Documentation

Document findings and recommendations.

---

## MITRE ATT&CK Mapping

| Technique ID | Technique                         |
| ------------ | --------------------------------- |
| T1110        | Brute Force                       |
| T1059.001    | PowerShell                        |
| T1059        | Command and Scripting Interpreter |
| T1082        | System Information Discovery      |
| T1078        | Valid Accounts                    |

---

## Sample Investigation

### Alert

Multiple Failed Login Attempts Detected

### Host

WIN10-LAB

### Event ID

4625

### Investigation Findings

* Repeated authentication failures detected.
* Multiple login attempts from the same source.
* Activity consistent with brute-force behavior.

### MITRE ATT&CK

T1110 – Brute Force

### Recommendation

* Investigate source system.
* Review account lockout policies.
* Monitor for successful authentication attempts.
* Escalate if suspicious activity continues.

---

## Skills Demonstrated

### SIEM Operations

* Splunk Enterprise
* Microsoft Sentinel
* SPL Query Development
* KQL Query Development

### Security Monitoring

* Alert Triage
* Event Correlation
* Log Analysis
* Threat Detection

### Incident Response

* Incident Investigation
* IOC Identification
* Root Cause Analysis
* Security Reporting

### Endpoint Monitoring

* Sysmon
* Windows Event Logs
* PowerShell Logging
* Process Analysis

---

## Future Enhancements

* Automated Alerting
* Threat Intelligence Integration
* SOAR Automation
* Custom Detection Rules
* Threat Hunting Dashboards
* Advanced Correlation Searches

---

## Project Repository Structure

```text
SOC-Monitoring-Threat-Detection-Lab/

├── README.md
├── Architecture
│   └── Architecture-Diagram.png
├── Splunk
│   ├── SPL-Queries.md
│   └── Detection-Rules.md
├── Sentinel
│   ├── KQL-Queries.md
│   └── Analytics-Rules.md
├── Screenshots
│   ├── Splunk-Dashboard
│   ├── Sentinel-Incidents
│   ├── Sysmon-Logs
│   └── Attack-Simulation
├── Incident-Reports
│   ├── BruteForce-Incident.pdf
│   └── PowerShell-Abuse-Incident.pdf
└── MITRE-Mapping
    └── ATTACK-Mapping.md
```

## Author

**Ajay Kumar Reddy Karasani**

SOC Analyst | Cybersecurity Graduate

**Technologies:** Splunk, Microsoft Sentinel, Sysmon, Windows Event Logs, Kali Linux, MITRE ATT&CK, Incident Response
