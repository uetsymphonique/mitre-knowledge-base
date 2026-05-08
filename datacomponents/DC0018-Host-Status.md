# DC0018 - Host Status

## Description

Logging, messaging, and other artifacts that highlight the health and operational state of host-based security sensors, such as Endpoint Detection and Response (EDR) agents, antivirus software, logging services, and system monitoring tools. Monitoring sensor health is essential for detecting misconfigurations, sensor failures, tampering, or deliberate security control evasion by adversaries.

*Data Collection Measures:*

- Windows Event Logs:
    - Event ID 1074 (System Shutdown): Detects unexpected system reboots/shutdowns.
    - Event ID 6006 (Event Log Stopped): Logs when Windows event logging is stopped.
    - Event ID 16 (Sysmon): Detects configuration state changes that may indicate log tampering.
    - Event ID 12 (Windows Defender Status Change) – Detects changes in Windows Defender state.
- Linux/macOS Monitoring:
    - `/var/log/syslog`, `/var/log/auth.log`, `/var/log/kern.log`
    - Journald (journalctl) for kernel and system alerts.
- Endpoint Detection and Response (EDR) Tools:
    - Monitor agent health status, detect sensor tampering, and alert on missing telemetry.
- Mobile Threat Intelligence Logs:
    - Samsung Knox, SafetyNet, iOS Secure Enclave provide sensor health status for mobile endpoints.

## Log Sources

| Log Source | Channel |
|------------|---------|
| `Sensor Health` | None |
| `macos:osquery` | interface_details  |
| `Windows:perfmon` | Sustained CPU/memory exhaustion by service process (e.g., w3wp.exe) |
| `macos:unifiedlog` | Web service process (e.g., httpd) entering crash loop or consuming excessive CPU |
| `AWS:CloudWatch` | Sustained spike in CPU usage on EC2 instance with web service role |
| `WinEventLog:System` | System shutdowns due to bugcheck (Event ID 1001) or watchdog timer expirations |
| `linux:syslog` | Out of memory killer invoked or kernel panic entries |
| `macos:unifiedlog` | Spike in CPU or memory use from non-user-initiated processes |
| `AWS:CloudWatch` | StatusCheckFailed or StatusCheckFailed_System for burstable instances (t2/t3) |
| `kubernetes:events` | CrashLoopBackOff, OOMKilled, container restart count exceeds threshold |
| `WinEventLog:Sysmon` | EventCode=16 |
| `Windows:perfmon` | High sustained CPU usage by a single process |
| `linux:procfs` | Sustained high /proc/[pid]/stat usage |
| `AWS:CloudWatch` | Sustained EC2 CPU usage above normal baseline |
| `prometheus:metrics` | Container CPU/Memory usage exceeding threshold |
| `linux:syslog` | Service stop or disable messages for security tools not reflected in SIEM alerts |
| `macos:unifiedlog` | Termination or disabling of XProtect, Gatekeeper, or third-party AV daemons |
| `AWS:CloudWatch` | NetworkOut spike beyond baseline |
| `WinEventLog:Microsoft-Windows-TCPIP` | Connection queue overflow or failure to allocate TCP state object |
| `NSM:Flow` | TCP: possible SYN flood or backlog limit exceeded |
| `macos:unifiedlog` | network stack resource exhaustion, tcp_accept queue overflow, repeated resets |
| `WinEventLog:Security` | EventCode=1166, 7045 |
| `auditd:SYSCALL` | firmware_update, kexec_load |
| `journald:boot` | Secure Boot failure, firmware version change |
| `macos:unifiedlog` | EFI firmware integrity check failed |
| `macos:syslog` | Hardware UUID or device list drift |
| `Windows:perfmon` | Sudden spike in outbound throughput without corresponding inbound traffic |
| `sar:network` | Outbound network saturation with minimal process activity |
| `AWS:CloudWatch` | Sudden spike in network output without a corresponding inbound request ratio |
| `Windows:perfmon` | Sudden spikes in CPU/Memory usage linked to specific application processes |
| `AWS:CloudMetrics` | Autoscaling, memory/cpu alarms, or instance unhealthiness |
| `macos:unifiedlog` | System Integrity Protection (SIP) state reported as disabled |
| `AWS:CloudWatch` | Unusual CPU burst or metric anomalies |
| `WinEventLog:Security` | EventCode=1074 |
| `WinEventLog:Security` | EventCode=6006 |
| `linux:syslog` | system is powering down |
| `macos:unifiedlog` | System shutdown or reboot requested |
| `esxi:hostd` | Powering off or restarting host |
| `networkdevice:syslog` | System reboot scheduled or performed |
