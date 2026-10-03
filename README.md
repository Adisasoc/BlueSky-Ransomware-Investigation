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
### Q1 — Identifying the Source IP

> Knowing the source IP of the attack allows security teams to respond to potential threats quickly. Can you identify the source IP responsible for potential port scanning activity?

I started by opening the PCAP file in Wireshark and filtering for TCP SYN packets:

`tcp.flags.syn == 1 && tcp.flags.ack == 0`

The results showed `87.96.21.84` repeatedly sending SYN requests to `87.96.21.81` across multiple destination ports. This pattern identified `87.96.21.84` as the source of the port scanning activity.

![Wireshark showing repeated SYN requests from the source IP](screenshots/01-port-scan.png)

**Finding:** `87.96.21.84`

### Q2 — Identifying the Targeted Account

> During the investigation, it's essential to determine the account targeted by the attacker. Can you identify the targeted account username?

After identifying `87.96.21.84` as the source of the scanning activity, I moved to Windows Event Viewer to see if the same IP appeared in the host logs.

I searched for `87.96.21.84` and found an MSSQLSERVER Event ID `18456`. The event showed a failed SQL Server login from the same IP, with the username `sa` and the reason stating that the password did not match.

This connected the network activity I saw in Wireshark with the authentication activity on the SQL Server.

![Windows Event Viewer showing the failed MSSQL login](screenshots/02-mssql-failed-login.png)

**Finding:** `sa`
