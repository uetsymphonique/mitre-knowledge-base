# DC0033 - Process Termination

## Description

The exit or termination of a running process on a system. This can occur due to normal operations, user-initiated commands, or malicious actions such as process termination by malware to disable security controls.

## Log Sources

| Log Source | Channel |
|------------|---------|
| `Process` | None |
| `WinEventLog:Sysmon` | EventCode=5 |
| `linux:syslog` | Unexpected termination of daemons or critical services not aligned with admin change tickets |
| `macos:osquery` | process_termination: Unexpected termination of processes tied to vulnerable or high-value services |
| `esxi:hostd` | Log entries indicating VM powered off or forcibly terminated |
| `macos:unifiedlog` | Terminal process killed (killall Terminal) immediately after sudoers modification |
| `auditd:SYSCALL` | exit_group |
| `macos:unifiedlog` | process.*exit.*code |
| `linux:osquery` | unexpected termination of syslog or rsyslog processes |
| `auditd:SYSCALL` | Process segfault or abnormal termination after invoking vulnerable syscall sequence |
| `auditd:SYSCALL` | kill syscalls targeting logging/security processes |
| `macos:unifiedlog` | Termination of syspolicyd or XProtect processes |
| `docker:runtime` | Termination of monitoring sidecar or security container |
