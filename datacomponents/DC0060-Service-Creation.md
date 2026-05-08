# DC0060 - Service Creation

## Description

The registration of a new service or daemon on an operating system.

*Data Collection Measures:*

- Windows Event Logs
    - Event ID 4697 - Captures the creation of a new Windows service.
    - Event ID 7045 - Captures services installed by administrators or adversaries.
    - Event ID 7034 - Could indicate malicious service modification or exploitation.
- Sysmon Logs
    - Sysmon Event ID 1 - Process Creation (captures service executables).
    - Sysmon Event ID 4 - Service state changes (detects service installation).
    - Sysmon Event ID 13 - Registry modifications (captures service persistence changes).
- PowerShell Logging
    - Monitor `New-Service` and `Set-Service` PowerShell cmdlets in Event ID 4104 (Script Block Logging).
- Linux/macOS Collection Methods
    - AuditD & Syslog Daemon Logs (`/var/log/syslog`, `/var/log/messages`, `/var/log/daemon.log`)
    - AuditD Rules:
        - `auditctl -w /etc/systemd/system -p wa -k service_creation`
        - Detects changes to `systemd` service configurations.
- Systemd Journals (`journalctl -u <service_name>`)
    - Captures newly created systemd services.
- LaunchDaemons & LaunchAgents (macOS)
    - Monitor `/Library/LaunchDaemons/` and `/Library/LaunchAgents/` for new plist files.

## Log Sources

| Log Source | Channel |
|------------|---------|
| `Service` | None |
| `WinEventLog:System` | EventCode=7036 |
| `auditd:CONFIG_CHANGE` | creation or modification of systemd services |
| `macos:osquery` | Process Events and Launch Daemons |
| `WinEventLog:System` | EventCode=7045 |
| `linux:osquery` | newly registered unit file with ExecStart pointing to unknown binary |
| `macos:unifiedlog` | creation or loading of new launchd services |
| `WinEventLog:Security` | EventCode=4697 |
| `linux:syslog` | systemctl start/enable with uncommon binary paths |
| `WinEventLog:System` | EventCode=7031, 7034 |
| `macos:osquery` | launch_daemons |
| `macos:unifiedlog` | launchd loading new LaunchDaemon or changes to existing daemon configuration |
| `macos:osquery` | detection of new launch agents with suspicious paths or unsigned binaries |
| `kubernetes:audit` | create |
| `containerLogs:systemd_unit_files` | unit file referencing container binary with persistent flags |
