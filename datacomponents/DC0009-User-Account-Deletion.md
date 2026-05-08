# DC0009 - User Account Deletion

## Description

The removal of a user, service, or machine account from an operating system, cloud identity management system, or directory service.

## Log Sources

| Log Source | Channel |
|------------|---------|
| `WinEventLog:Security` | EventCode=4726, 4657 |
| `esxi:hostd` | method=RemoveUser or esxcli system account remove invocation |
| `m365:unified` | Remove-Mailbox, Set-Mailbox |
