# DC0040 - File Deletion

## Description

Refers to events where files are removed from a system or storage device. These events can indicate legitimate housekeeping activities or malicious actions such as attackers attempting to cover their tracks. Monitoring file deletions helps organizations identify unauthorized or suspicious activities.

## Log Sources

| Log Source | Channel |
|------------|---------|
| `File` | None |
| `auditd:SYSCALL` | unlink/unlinkat on service binaries or data targets |
| `auditd:SYSCALL` | file deletion |
| `macos:osquery` | file_events |
| `esxi:shell` | shell history |
| `WinEventLog:Sysmon` | EventCode=23 |
| `auditd:SYSCALL` | PATH |
| `esxi:shell` | /var/log/shell.log |
| `esxi:hostd` | delete action |
| `auditd:SYSCALL` | unlink, unlinkat, openat, write |
| `macos:unifiedlog` | exec rm -rf\|dd if=/dev\|srm\|file unlink |
| `auditd:SYSCALL` | unlink, unlinkat, rmdir |
| `auditd:SYSCALL` | unlink, rename, open |
| `linux:Sysmon` | EventCode=23 |
| `fs:fsusage` | unlink, fs_delete |
| `docker:daemon` | container file operations |
| `esxi:hostd` | rm, clearlogs, logrotate |
| `esxi:hostd` | Datastore file operations |
| `macos:osquery` | CREATE, DELETE, WRITE: Stored data manipulation attempts by unauthorized processes |
| `auditd:SYSCALL` | unlink/unlinkat |
| `WinEventLog:Microsoft-Windows-Backup` | Windows Backup Catalog deletion or catalog corruption |
| `auditd:CONFIG_CHANGE` | /etc/fstab, /etc/systemd/* |
