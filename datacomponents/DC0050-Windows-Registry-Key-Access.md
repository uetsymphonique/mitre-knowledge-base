# DC0050 - Windows Registry Key Access

## Description

The action of opening a specific Windows Registry key, typically to read its associated value. This activity can be used for system configuration, application settings retrieval, and security policies.

## Log Sources

| Log Source | Channel |
|------------|---------|
| `WinEventLog:Security` | EventCode=4663, 4670, 4656 |
| `WinEventLog:Security` | EventCode=4657 |
| `EDR:hunting` | Behavioral rule for registry enumeration under credential-related paths |
| `Autoruns:RegistryScan` | Enumerate Winlogon subkeys for unknown or unsigned binaries |
