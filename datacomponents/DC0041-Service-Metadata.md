# DC0041 - Service Metadata

## Description

Contextual data about a service/daemon, which may include information such as name, service executable, start type, etc.

## Log Sources

| Log Source | Channel |
|------------|---------|
| `Service` | None |
| `WinEventLog:Sysmon` | EventCode=4 |
| `linux:syslog` | service stopped messages |
| `macos:unifiedlog` | launchctl disable or bootout calls |
| `esxi:hostd` | Stop VM or disable service events via vim-cmd |
| `linux:syslog` | auditd service stopped or disabled |
| `macos:osquery` | launchd |
| `linux:osquery` | scheduled/real-time |
| `macos:unifiedlog` | subsystem=com.apple.launchservices |
| `esxi:hostd` | registers services with legitimate-sounding names |
| `WinEventLog:System` | EventCode=7035 |
| `linux:syslog` | Service restart with modified executable path |
| `macos:unifiedlog` | Observed loading of new LaunchAgent or LaunchDaemon plist |
| `kubernetes:audit` | seccomp or AppArmor profile changes |
| `WinEventLog:System` | Service stopped or RecoveryDisabled set via REAgentC |
| `esxi:hostd` | Service events |
| `WinEventLog:WinRM` | EventCode=6 |
| `auditd:CONFIG_CHANGE` | delete: Modification of systemd unit files or config for security agents |
| `macos:unifiedlog` | Modification of system configuration profiles affecting security tools |
| `kubernetes:audit` | kubectl delete or patch of security pods/admission controllers |
| `networkdevice:config` | write: Startup configuration changes disabling security checks |
