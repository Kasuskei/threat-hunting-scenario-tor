<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/joshmadakor0/threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages Leveraged
- Windows 11 Virtual Machines (Microsoft Azure)
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

Searched the DeviceFileEvents table for any file that had the string “tor” in it, and discovered what appeared to be the user “labuser” downloaded a tor installer, did something that resulted in many tor-related files being copied to the desktop and the creation of a file called “tor-shopping-list.txt” at 2025-11-23T06:39:11.7823414Z on the desktop. These events began at: 2025-11-23T06:21:08.2963061Z
Query used to locate event:
DeviceFileEvents
| where DeviceName == "isaac-mde-threa"
| where InitiatingProcessAccountName == "labuser"
| where FileName contains "tor"
| where Timestamp >= datetime(2025-11-23T06:21:08.2963061Z)
| order by Timestamp desc 
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName

---

### 2. Searched the `DeviceProcessEvents` Table

Searched the DeviceProcessEvents table for any ProcessCommandLine that contained the string “tor-browser-windows-x86_64-portable-15.0.2.exe”. Based on the logs returned, at 2025-11-23T06:28:26.1177063Z an employee on the “isaac-mde-threa” device ran the file tor-browser-windows-x86_64-portable-15.0.2.exe from their Downloads folder, using a command that triggered a silent installation. 
Query used to locate event:
DeviceProcessEvents
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-15.0.2.exe"
| where DeviceName == "isaac-mde-threa"
| project Timestamp, DeviceName, ActionType, FileName, ProcessCommandLine, FolderPath, SHA256, AccountName

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched the DeviceProcessEvents table for any indication that user “employee” actually opened the tor browser. There was evidence that they did open it at 2025-11-23T06:32:20.6987905Z. There were several other instances of firefox.exe (tor) as well as tor.exe spawned afterwards.
Query used to locate event:
DeviceProcessEvents
| where DeviceName == "isaac-mde-threa"
| where ProcessCommandLine has_any ("tor.exe","firefox.exe")
| project Timestamp, DeviceName, AccountName, ActionType, ProcessCommandLine, FolderPath, SHA256, FileName

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched the DeviceNetworkEvents table for any indication the tor browser was used to establish a connection using any of the known tor ports. At 2025-11-23T06:29:19.3668527Z, user “labuser” successfully established a connection to the remote IP address 217.255.34.123 on port 9001. The connection was initiated by the process tor.exe, located in the folder c:\users\labuser\desktop\tor browser\browser\torbrowser\tor\tor.exe. There were other connections made to sites over port 443.
Query used:
DeviceNetworkEvents
| where DeviceName == "isaac-mde-threa"
| where InitiatingProcessFileName in~ ("tor.exe", "firefox.exe")
| where RemotePort in (9001, 9030, 9040, 9050, 9051, 9150)
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFolderPath
| order by Timestamp desc

---

## Chronological Event Timeline 

Download & Installation
2025-11-23 06:21:08 – File tor-browser-windows-x86_64-portable-15.0.2.exe created in C:\Users\labuser\Downloads\.
2025-11-23 06:21:21 – Same installer file deleted from Downloads folder.
2025-11-23 06:21:22 – Process tor-browser-windows-x86_64-portable-15.0.2.exe executed from Downloads folder.
2025-11-23 06:28:26 – Silent installation triggered: "tor-browser-windows-x86_64-portable-15.0.2.exe /S".
Tor Browser Installation Artifacts
2025-11-23 06:21:50–06:21:52 – Multiple Tor-related license files (tor.txt, Torbutton.txt, Tor-Launcher.txt) and tor.exe created in C:\Users\labuser\Desktop\Tor Browser\Browser\TorBrowser\.
2025-11-23 06:22:03–06:22:09 – Shortcuts (Tor Browser.lnk) created on Desktop and Start Menu.
Tor Browser Execution
2025-11-23 06:29:04–06:32:34 – Multiple firefox.exe processes spawned from Tor Browser directory, including tab, GPU, utility, and content processes.
2025-11-23 06:29:16 – tor.exe process launched with configuration pointing to torrc and control ports (127.0.0.1:9151, 127.0.0.1:9150).
Network Connections
2025-11-23 06:29:19 – tor.exe connects to remote IP 217.255.34.123 on port 9001 (Tor relay).
2025-11-23 06:29:23–06:29:24 – tor.exe connects to 93.158.213.15 on port 443, with URL https://www.7eslllxcfrkgn.com.
2025-11-23 06:29:38 – firefox.exe communicates locally with 127.0.0.1:9150 (Tor SOCKS proxy).
2025-11-23 06:29:48–06:29:49 – tor.exe connects to 62.141.37.218 on port 443, with URL https://www.lzisk6ou.com.
User Activity Evidence
2025-11-23 06:39:11 – File tor-shopping-list.txt created on Desktop, alongside shortcut tor-shopping-list.lnk in Recent files, indicating a list or notes related to their tor browser activitie

---

## Summary

The user "employee" on the "threat-hunt-lab" device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named `tor-shopping-list.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

---

## Response Taken

TOR usage was confirmed on endpoint isaac-mde-threa by the user labuser. The device was isolated and the user's direct manager was notified.
