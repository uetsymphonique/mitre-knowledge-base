# DC0063 - Windows Registry Key Modification

## Description

Changes made to an existing registry key or its values. These modifications can include altering permissions, modifying stored data, or updating configuration settings.

*Data Collection Measures:*

- Windows Event Logs
    - Event ID 4657 - Registry Value Modified: Logs changes to registry values, including modifications to startup entries, security settings, or system configurations.
- Sysmon (System Monitor) for Windows
    - Sysmon Event ID 13 - Registry Value Set: Captures changes to specific registry values.
    - Sysmon Event ID 14 - Registry Key & Value Renamed: Logs renaming of registry keys, which may indicate evasion attempts.
- Endpoint Detection and Response (EDR) Solutions
    - Monitor registry modifications for suspicious behavior.

## Log Sources

| Log Source | Channel |
|------------|---------|
| `Windows Registry` | None |
| `WinEventLog:Security` | EventCode=4657 |
| `WinEventLog:Security` | EventCode=4663, 4670, 4656 |
| `WinEventLog:Sysmon` | StubPath value written under HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components |
| `m365:unified` | MacroSecuritySettingsChanged or SafeModeDisabled |
| `WinEventLog:Sysmon` | EventCode=13, 14 |
| `WinEventLog:Security` | modification to Winlogon registry keys such as Shell, Notify, or Userinit |
| `WinEventLog:Security` | Registry key modification HKLM\Software\Policies\Microsoft\Windows NT\DNSClient\EnableMulticast |
| `macos:unifiedlog` | g_CiOptions modification or SIP state change |
| `WinEventLog:Sysmon` | Autoruns reports DLLs in AppInit_DLLs key |
