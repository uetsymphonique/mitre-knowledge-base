# DC0035 - Process Access

## Description

Refers to an event where one process attempts to open another process, typically to inspect or manipulate its memory, access handles, or modify execution flow. Monitoring these access attempts can provide valuable insight into both benign and malicious behaviors, such as debugging, inter-process communication (IPC), or process injection.

*Data Collection Measures:*

- Endpoint Detection and Response (EDR) Tools:
    -  EDR solutions that provide telemetry on inter-process access and memory manipulation.
- Sysmon (Windows):
    - Event ID 10: Captures process access attempts, including:
        - Source process (initiator)
        - Target process (victim)
        - Access rights requested
        - Process ID correlation
- Windows Event Logs:
    - Event ID 4656 (Audit Handle to an Object): Logs access attempts to system objects.
    - Event ID 4690 (Attempted Process Modification): Can help identify unauthorized process changes.
- Linux/macOS Monitoring:
    - AuditD: Monitors process access through syscall tracing (e.g., `ptrace`, `open`, `read`, `write`).
    - eBPF/XDP: Used for low-level monitoring of kernel process access.
    - OSQuery: Query process access behavior via structured SQL-like logging.
- Procmon (Process Monitor) and Debugging Tools:
    - Windows Procmon: Captures real-time process interactions.
    - Linux strace / ptrace: Useful for tracking process behavior at the system call level.

## Log Sources

| Log Source | Channel |
|------------|---------|
| `WinEventLog:Sysmon` | EventCode=10 |
| `linux:osquery` | Process State |
| `auditd:SYSCALL` | ptrace attach |
| `macos:unifiedlog` | ptrace or task_for_pid |
| `macos:osquery` | process_open |
| `auditd:SYSCALL` | High frequency of accept(), read(), or SSL_read() syscalls tied to nginx/apache processes |
| `Apple TCC Logs` | Microphone Access Events |
| `auditd:SYSCALL` | ptrace |
| `linux:syslog` | syscalls (open, read, ioctl) on /dev/input or /proc/*/fd/* |
| `WinEventLog:Sysmon` | EventCode=25 |
| `macos:endpointsecurity` | ES_EVENT_TYPE_NOTIFY_OPEN |
| `macos:unifiedlog` | Unexpected NSXPCConnection calls by non-Apple-signed or abnormal binaries |
| `WinEventLog:Security` | EventCode=4663, 4670, 4656 |
| `macos:unifiedlog` | Unusual Mach port registration or access attempts between unrelated processes |
| `macos:unifiedlog` | subsystem=com.apple.security, library=libsystem_kernel.dylib |
| `auditd:SYSCALL` | ptrace syscall or access to /proc/*/mem |
| `macos:unifiedlog` | vm_read, task_for_pid, or file open to cookie databases |
| `linux:osquery` | process_events |
| `auditd:SYSCALL` | ACCESS |
| `auditd:SYSCALL` | execve, fork, mmap, ptrace |
| `auditd:SYSCALL` | ptrace or process_vm_readv |
| `macos:osquery` | unexpected memory inspection |
