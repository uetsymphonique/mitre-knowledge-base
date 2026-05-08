# DC0065 - Service Modification

## Description

Changes made to an existing service or daemon, such as modifying the service name, start type, execution parameters, or security configurations.

## Log Sources

| Log Source | Channel |
|------------|---------|
| `Service` | None |
| `WinEventLog:Microsoft-IIS-Configuration` | Module or ISAPI filter registration events |
| `WinEventLog:System` | EventCode=7040 |
