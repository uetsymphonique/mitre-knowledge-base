# DC0034 - Process Metadata

## Description

Contextual data about a running process, which may include information such as environment variables, image name, user/owner, etc.

## Log Sources

| Log Source | Channel |
|------------|---------|
| `Process` | None |
| `macos:unifiedlog` | subsystem=com.apple.process |
| `WinEventLog:Microsoft-Windows-CodeIntegrity/Operational` | CodeIntegrity/WDAC events indicating unsigned/invalid DLL loads |
| `linux:syslog` | sudo or service accounts invoking loaders with suspicious env vars |
| `macos:osquery` | Process Context |
| `esxi:auth` | user session |
| `networkdevice:syslog` | Admin activity |
| `auditd:SYSCALL` | execve call for sudo where euid != uid |
| `macos:unifiedlog` | subsystem=com.apple.TCC |
| `macos:unifiedlog` | exec of binary with setuid/setgid and EUID != UID |
| `macos:unifiedlog` | process |
| `auditd:SYSCALL` | Use of fork/exec with DISPLAY unset or redirected |
| `EDR:Telemetry` | Process lineage and API usage enrichment (GetSystemTime, GetTimeZoneInformation, NtQuerySystemTime) |
| `esxi:hostd` | /var/log/hostd.log API calls reading/altering time/ntp settings |
| `auditd:SYSCALL` | execve, prctl, or ptrace activity affecting process memory or command-line arguments |
| `linux:osquery` | Cross-reference argv[0] with actual executable path and parent process metadata |
| `WinEventLog:AppLocker` | AppLocker audit/blocks showing developer utilities executing scripts/binaries outside policy |
| `EDR:hunting` | Correlation of signer info, parent-child lineage, rare invocation context (user host role), and API surfaces (CreateProcess*, LoadLibrary*) |
| `WinEventLog:Microsoft-Windows-Security-Mitigations/KernelMode` | ETW telemetry indicating ClickOnce deployment (dfsvc.exe) launching payloads |
| `etw:Microsoft-Windows-ClickOnce` | provider: Event Tracing for Windows (ETW) events associated with ClickOnce deployment (dfsvc.exe activity) |
| `WinEventLog:Microsoft-Windows-Windows Camera Frame Server/Operational` | Process session start/stop events for camera pipeline by unexpected executables |
| `linux:osquery` | select: path LIKE '/dev/video%' |
| `linux:osquery` | state=attached/debugged |
| `macos:unifiedlog` | Code Execution & Entitlement Access |
| `macos:unifiedlog` | Process opening SSH_AUTH_SOCK or /tmp/ssh-* socket not owned by same UID |
| `macos:unifiedlog` | code signature/memory protection |
| `auditd:SYSCALL` | execve with UID ≠ EUID |
| `auditd:SYSCALL` | execve with escalated privileges |
| `AWS:CloudTrail` | cross-account or unexpected assume role |
| `macos:unifiedlog` | log collect from launchd and process start |
| `containerd:events` | Docker or containerd image pulls and process executions |
| `linux:syslog` | Kernel or daemon warnings of downgraded TLS or cryptographic settings |
| `macos:unifiedlog` | Modifications or writes to EFI system partition for downgraded bootloaders |
| `macos:unifiedlog` | non-shell process tree accessing bash history |
| `linux:osquery` | process metadata mismatch between /proc and runtime attributes |
| `linux:osquery` | process environment variables containing LD_PRELOAD |
| `WinEventLog:PowerShell` | EventCode=400, 403 |
| `macos:osquery` | Process Execution + Hash |
| `etw:Microsoft-Windows-Kernel-Process` | process_start: EventHeader.ProcessId true parent vs reported PPID mismatch |
| `macos:endpointsecurity` | ES_EVENT_TYPE_NOTIFY_EXEC, ES_EVENT_TYPE_NOTIFY_MMAP |
| `WinEventLog:Microsoft-Windows-CodeIntegrity/Operational` | Unsigned/invalid signature modules or images loaded by msbuild.exe or its children |
| `WinEventLog:Microsoft-Windows-DeviceGuard/Operational` | WDAC policy audit/block affecting msbuild.exe spawned payloads |
| `WinEventLog:Microsoft-Windows-SmartAppControl/Operational` | Smart App Control decisions (audit/block) for msbuild.exe-launched executables |
| `WinEventLog:Microsoft-Windows-CodeIntegrity/Operational` | Unsigned or untrusted modules loaded during JamPlus.exe runtime |
