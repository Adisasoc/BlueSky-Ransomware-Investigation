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
### Q3 — Confirming Successful Access

> We need to determine if the attacker succeeded in gaining access. Can you provide the correct password discovered by the attacker?

After seeing the failed login attempts against the `sa` account, I went back to the PCAP to check the SQL login traffic.

I filtered for TDS login packets using:

`tds.type == 0x10`

Looking at the TDS7 Login Packet showed the `sa` account authenticating to `87.96.21.81`, along with the password used for the login.

![TDS7 login packet showing the SQL credentials](screenshots/03-tds-login.png)

**Finding:** `cyb3rd3f3nd3r$`
### Q4 — Enabling Command Execution

> Attackers often change some settings to facilitate lateral movement within a network. What setting did the attacker enable to control the target host further and execute further commands?

After confirming the SQL access, I followed the same traffic using **Follow TCP Stream** to see what the attacker did after logging in.

In the stream, I found commands being used to enable `xp_cmdshell`. The SQL Server response confirmed the change:

`Configuration option 'xp_cmdshell' changed from 0 to 1`

With `xp_cmdshell` enabled, commands could be executed on the Windows host through SQL Server.

![TCP stream showing xp_cmdshell being enabled](screenshots/04-xp-cmdshell.png)

**Finding:** `xp_cmdshell`
### Q5 — Identifying the Process Used for C2 Injection

> Process injection is often used by attackers to escalate privileges within a system. What process did the attacker inject the C2 into to gain administrative privileges?

At this point, I moved back to the Windows Event Logs and searched through the PowerShell activity.

I found PowerShell Event ID `400`, where the event details showed `MSFConsole` as the host and `winlogon.exe` as the `HostApplication`.

This linked `winlogon.exe` to the attacker's C2 activity.

![PowerShell Event ID 400 showing winlogon.exe](screenshots/05-winlogon-injection.png)

**Finding:** `winlogon.exe`
