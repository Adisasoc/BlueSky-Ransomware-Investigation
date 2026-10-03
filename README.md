# BlueSky-Ransomware-Investigation
Investigation of a BlueSky ransomware attack using Wireshark, Windows Event Viewer, PowerShell and VirusTotal.

# BlueSky Ransomware Investigation

## Overview

In this investigation, I analysed a BlueSky ransomware attack using a PCAP file and Windows Event Logs provided by CyberDefenders.

I followed the attack from the initial network activity through the MSSQL compromise, PowerShell execution, privilege escalation, defense evasion, persistence, credential dumping, lateral movement and finally the ransomware deployment.

Throughout the investigation, I correlated network traffic with Windows events and PowerShell activity to understand how the attack progressed.

## Tools Used

- Wireshark
- Windows Event Viewer
- PowerShell
- VirusTotal

## Investigation
