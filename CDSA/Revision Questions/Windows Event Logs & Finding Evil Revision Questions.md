# Windows Event Logs & Finding Evil Revision Questions

### 1. Windows Event Logs Overview

Explain the purpose of Windows Event Logs and describe why they are essential during security investigations.

### 2. Default Windows Event Logs

Describe the five default Windows Event Logs and explain the primary purpose of each.

### 3. Event Log Structure

List and explain the significance of the main components found within a Windows event log entry, including why fields such as Event ID and Keywords are useful during investigations.

### 4. Important Security Event IDs

Explain the security significance of the following Event IDs: 1102, 4624, 4625, 4672, 4698, and 7045.

### 5. System Event IDs

Describe the purpose of System Event IDs 1074, 6005, 6006, 6013, and 7040, and explain how they can assist an incident responder.

### 6. Sysmon

Explain what Sysmon is, its primary components, and why it provides greater visibility than standard Windows Security Logs.

### 7. Event Tracing for Windows (ETW)

Describe how Event Tracing for Windows (ETW) works, including the roles of controllers, providers, consumers, channels, and ETL files.

### 8. ETW Providers

Compare the four types of ETW providers (MOF, WPP, Manifest-based, and TraceLogging) and explain the purpose of restricted providers.

### 9. Get-WinEvent

Explain the purpose of the Get-WinEvent PowerShell cmdlet and describe the different ways it can retrieve event data.

### 10. Security Monitoring

Explain why understanding a network baseline is important when analysing Windows event logs and identifying indicators of compromise.

### 11. Investigating Recent System Events

Write a PowerShell command using Get-WinEvent to display the 50 most recent System log events, showing the TimeCreated, ID, ProviderName, LevelDisplayName, and Message fields.

### 12. Reviewing WinRM Activity

Write a PowerShell command to retrieve the 30 oldest events from the Microsoft-Windows-WinRM/Operational log and display the key event details.

### 13. Reading an EVTX File

Write a PowerShell command to read the first five events from an exported EVTX file and display the event details in a formatted table.

### 14. Filtering Sysmon Events

Write a Get-WinEvent command that filters the Microsoft-Windows-Sysmon/Operational log for Event IDs 1 and 3 between two specified dates using a FilterHashtable.

### 15. Investigating ETW

Provide the commands to:

1. Display all active ETW tracing sessions.
2. List all registered ETW providers.
3. Explain why using `findstr` can be useful when viewing the provider list.
