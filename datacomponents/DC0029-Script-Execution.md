# DC0029 - Script Execution

## Description

The execution of a text file that contains code via the interpreter.

## Log Sources

| Log Source | Channel |
|------------|---------|
| `Script` | None |
| `m365:office` | VBA auto_open, auto_close, or document_open events |
| `macos:unifiedlog` | log stream --predicate 'eventMessage contains "python"' |
| `linux:syslog` | /var/log/syslog |
| `WinEventLog:System` | EventCode=1502, 1503 |
| `macos:unifiedlog` | log stream --predicate 'eventMessage contains "wscript" OR "vbs"' |
| `macos:unifiedlog` | osascript or AppleScript invocation modifying UI |
| `networkdevice:runtime` | runtime |
| `macos:unifiedlog` | log |
| `esxi:vmkernel` | boot |
| `macos:unifiedlog` | AppleScript creating login item via 'System Events' dictionary |
| `WinEventLog:PowerShell` | EventCode=4103, 4104, 4105, 4106 |
| `WinEventLog:Application` | Stored procedure creation, modification, or xp_cmdshell invocation via SQL logs or SQL Server auditing |
| `ApplicationLogs:SQL` | Stored procedure creation or modification with shell invocation (e.g., system(), exec()) |
| `macos:unifiedlog` | subsystem=launchservices |
| `WinEventLog:PowerShell` | Set-ADUser or Set-ADAuthenticationPolicy with MFA attributes disabled |
| `EDR:scriptblock` | Process Tree + Script Block Logging |
| `linux:syslog` | boot logs |
| `m365:defender` | ScriptBlockLogging + AMSI |
| `macos:unifiedlog` | log stream with predicate 'eventMessage CONTAINS "osascript"' |
| `etw:Microsoft-Antimalware-Scan-Interface` | Amsi/Script content + API verdicts during in-memory staging |
| `esxi:shell` | None |
| `WinEventLog:System` | EventCode=4016, 5312 |
| `auditd:PROCTITLE` | scripting loop invoking sleep/ping |
| `WinEventLog:PowerShell` | Scripts with references to XML parsing, AES decryption, or gpprefdecrypt logic |
| `macos:syslog` | system.log, asl.log |
| `macos:osquery` | exec: Unexpected execution of osascript or AppleScript targeting sensitive apps |
| `macos:unifiedlog` | subsystem=com.apple.Security or com.apple.applescript |
| `azure:activity` | Microsoft.Compute/virtualMachines/runCommand/action: Abnormal initiation of Azure RunCommand jobs or PowerShell/Bash payloads |
| `EDR:AMSI` | Malicious inline C#/script blobs embedded in MSBuild projects if intercepted by AMSI-aware loaders (rare but possible via chained LOLBins) |
| `macos:unifiedlog` | osascript, AppleScript, or Python execution triggered immediately after HID connection |
| `m365:unified` | Scripted Activity |
