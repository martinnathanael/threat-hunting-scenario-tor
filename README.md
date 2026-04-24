# Official [Cyber Range](http://joshmadakor.tech/cyber-range) Project

<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/martinnathanael/threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched the DeviceFileEvents table for ANY file that had the string “tor” in it and discovered what looks like the user “labuser” downloaded a Tor executable, installed it, and browsed it, which then resulted in many Tor-related files being copied to the desktop and the creation of a file called “Tor-shopping-list.txt” on the desktop. The events began at: 2026-04-23T21:05:15.7622047Z.

**Query used to locate events:**

```kql
DeviceFileEvents
| where FileName contains "tor"
| where InitiatingProcessAccountName == "labuser"
| where DeviceName == "nkam-thunt-vm"
| where Timestamp >= datetime(2026-04-23T21:05:15.7622047Z)
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```
<img width="1105" height="384" alt="image" src="https://github.com/user-attachments/assets/26568c3b-cdc5-4d69-91b8-d51a487c5d5f" />


---

### 2. Searched the `DeviceProcessEvents` Table

Searched the DeviceProcessEvents table for ANY ProcessCommandLine that contained the string “tor-browser-windows-x86_64-portable-15.0.10.exe”. Based on the logs returned, at 5:09 PM, on a virtual machine named nkam-thunt-vm, a user called labuser reaches into their Downloads folder and launches a file—a portable Tor Browser installer—a privacy-focused tool designed to mask identity and route internet traffic through hidden relay networks.
In that moment, the system quietly records the event: a new process springs to life from
 C:\Users\labuser\Downloads\..., carrying a long digital fingerprint (its SHA256 hash), confirming exactly what was executed.


**Query used to locate event:**

```kql

DeviceProcessEvents
| where DeviceName == "nkam-thunt-vm"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-15.0.10.exe."
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```


---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched the DeviceProcessEvents table for any indications that the user “labuser” opened the Tor browser. Found evidence that they did, in fact, launch it at 2026-04-23T21:05:45.1246333Z.
There were several other instances of firefox.exe (Tor) as well as tor.exe spawned afterwards.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "nkam-thunt-vm"
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
| order by Timestamp desc
```
<img width="1346" height="356" alt="image" src="https://github.com/user-attachments/assets/a673ce9e-267d-4825-a58d-6551e49b6a2e" />


---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched the DeviceNetworkEvents table for any indication that the Tor browser was used to establish a connection using any of the known Tor ports. At 2026-04-23T21:10:16.8288529Z, just minutes after launching the Tor Browser, the same machine quietly reaches out into the internet.
Behind the scenes, a process called tor.exe—the engine of the Tor network—successfully connects to a remote server at 185.44.65.162 over port 9001, a channel commonly used by Tor relays to pass encrypted traffic between nodes.
That connection points to a strange-looking web address, nnntq4hpq6qc.com, blending into the kind of obscure infrastructure typical of the Tor network, where traffic is bounced through multiple relays to obscure its origin. There were a few other connections from the known Tor ports.

**Query used to locate events:**

```kql
DeviceNetworkEvents  
| where DeviceName == "threat-hunt-lab"  
| where InitiatingProcessAccountName != "system"  
| where InitiatingProcessFileName in ("tor.exe", "firefox.exe")  
| where RemotePort in ("9001", "9030", "9040", "9050", "9051", "9150", "80", "443")  
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath  
| order by Timestamp desc
```
<img width="1305" height="327" alt="image" src="https://github.com/user-attachments/assets/5d684e5b-6238-4f15-b303-b0b362500ca3" />


---

## Chronological Event Timeline 

Timeline of Events
1. Initial Download (Earliest Evidence)
2026-04-23 17:05:15
File tor-browser-windows-x86_64-portable-15.0.10.exe is deleted from:

 C:\Users\labuser\Downloads\


This strongly implies the file existed prior to this timestamp and was likely downloaded just before.
2026-04-23 17:05:36 – 17:05:44
Multiple Tor-related files begin appearing:
tor.exe
Torbutton.txt
Tor-Launcher.txt
Tor Browser.lnk
Indicates initial extraction/unpacking of the portable Tor Browser.

2. Installation / Execution of Installer
2026-04-23 17:05:16
Process created:

 tor-browser-windows-x86_64-portable-15.0.10.exe


Executed from:

 C:\Users\labuser\Downloads\


2026-04-23 17:09:25
Same installer executed again
Suggests:
Re-run of installer OR
Continued setup phase

3. Tor Browser Extraction & Setup
2026-04-23 17:06:01 – 17:06:07
Multiple process creations:
firefox.exe
tor.exe
Supporting files created:
storage.sqlite
storage-sync-v2.sqlite
Indicates:
Tor Browser fully extracted to the Desktop
Internal browser components are initializing

4. Tor Browser Launch (Primary Execution)
2026-04-23 17:09:43 – 17:09:50
High volume of process activity:
Multiple instances of firefox.exe
tor.exe launched with a configuration file
Example command:

 "tor.exe" -f C:\Users\labuser\Desktop\Tor Browser\...


2026-04-23 17:11:45
An additional firefox.exe process was spawned
Indicates active browsing session

5. Network Activity (Tor Usage Confirmed)
2026-04-23 17:10:16
First confirmed Tor network connection:
Process: tor.exe
Remote IP: 185.44.65.162
Port: 9001 (Tor relay port)
URL: nnntq4hpq6qc.com
2026-04-23 17:11:08 – 17:11:09
Multiple successful outbound connections:
Ports: 9001, 9150
Remote IPs:
157.90.183.103
51.15.40.38
54.37.255.75
Additional randomized Tor-like domains observed
Indicates:
Active Tor circuit establishment
Traffic routed through multiple relay nodes

6. Post-Usage File Activity (Artifacts Created)
2026-04-23 17:09:36
Creation of Tor-related files:
tor.txt
Torbutton.txt
Tor-Launcher.txt
2026-04-23 17:25:03
File created on Desktop:

 tor-shopping-list.txt


Shortcut also created:

 tor-shopping-list.lnk


Indicates:
User interaction with Tor session
Likely manual file creation during browsing session


---

## Summary

The user labuser on system nkam-thunt-vm intentionally downloaded and executed a portable Tor Browser package from their Downloads directory. The application was extracted to the Desktop and launched, spawning multiple firefox.exe and tor.exe processes consistent with Tor Browser operation.
Within minutes of execution, the system began establishing encrypted outbound connections over known Tor ports (9001, 9150) to multiple external relay nodes, confirming active use of the Tor network for anonymized browsing.
Following successful usage, the user created a file named tor-shopping-list.txt on the Desktop, indicating interactive activity during the Tor session.
There is no evidence of persistence mechanisms or lateral movement, but the behavior clearly demonstrates:
Intentional installation
Execution
Active anonymized network communication via Tor
This activity is consistent with user-driven Tor usage rather than automated or malicious deployment, though it may still violate organizational policy depending on restrictions around anonymization tools.

---

## Response Taken

TOR usage was confirmed on endpoint nkam-thunt-vm. The device was isolated, and the user's direct manager was notified.

---
