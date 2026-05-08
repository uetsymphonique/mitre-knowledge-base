# DC0102 - Network Share Access

## Description

Opening a network share, which makes the contents available to the requestor (ex: Windows EID 5140 or 5145)

## Log Sources

| Log Source | Channel |
|------------|---------|
| `Network Share` | None |
| `WinEventLog:Microsoft-Windows-SMBClient/Security` | EventCode=31001 |
| `WinEventLog:Security` | EventCode=5140 |
| `WinEventLog:Security` | EventCode=5145 |
| `WinEventLog:Microsoft-Windows-SMBServer` | Access to SYSVOL share from non-admin user or unusual endpoints |
| `NSM:Flow` | smb_files.log |
| `m365:unified` | FileUploaded, FileAccessed |
