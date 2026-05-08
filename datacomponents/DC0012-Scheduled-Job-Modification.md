# DC0012 - Scheduled Job Modification

## Description

Changes made to an existing scheduled job, including modifications to its execution parameters, command payload, or execution timing.

## Log Sources

| Log Source | Channel |
|------------|---------|
| `Scheduled Job` | None |
| `auditd:CONFIG_CHANGE` | /var/log/audit/audit.log |
| `m365:exchange` | Remove-InboxRule, Clear-Mailbox |
| `WinEventLog:Security` | EventCode=4702 |
