# DC0059 - File Metadata

## Description

contextual information about a file, including attributes such as the file's name, size, type, content (e.g., signatures, headers, media), user/owner, permissions, timestamps, and other related properties. File metadata provides insights into a file's characteristics and can be used to detect malicious activity, unauthorized modifications, or other anomalies. Examples: 

- File Ownership and Permissions: Checking the owner and permissions of a critical configuration file like /etc/passwd on Linux or C:\Windows\System32\config\SAM on Windows.
- Timestamps: Analyzing the creation, modification, and access timestamps of a file.
- File Content and Signatures: Extracting the headers of an executable file to verify its signature or detect packing/obfuscation.
- File Attributes: Analyzing attributes like hidden, system, or read-only flags in Windows.
- File Hashes: Generating MD5, SHA-1, or SHA-256 hashes of files to compare against threat intelligence feeds.
- File Location: Monitoring files located in unusual directories or paths, such as temporary or user folders.

## Log Sources

| Log Source | Channel |
|------------|---------|
| `File` | None |
| `linux:osquery` | event-based |
| `WinEventLog:Microsoft-Windows-CodeIntegrity/Operational` | Invalid/Unsigned image when developer tool launches newly installed binaries |
| `journald:package` | dpkg/apt or yum/dnf transaction logs (install/update of build tools) |
| `linux:osquery` | file_events, hash |
| `macos:unifiedlog` | softwareupdated/homebrew/install logs, pkginstalld events |
| `macos:unifiedlog` | AMFI or Gatekeeper signature/notarization failures for newly installed dev components |
| `auditd:SYSCALL` | Inotify watch creation or auditctl changes on /etc/cron* or /lib/systemd/system/ |
| `linux:syslog` | Discrepancies in _VBA_PROJECT p-code vs source code extracted with oletools/pcodedmp |
| `macos:unifiedlog` | Detection of altered _VBA_PROJECT or PerformanceCache streams |
| `EDR:file` | File Metadata Inspection (Low String Entropy, Missing PDB) |
| `linux:osquery` | hash, elf_info, file_metadata |
| `macos:osquery` | code_signing, file_metadata |
| `WinEventLog:Windows Defender` | Operational log |
| `macos:unifiedlog` | subsystem:syspolicyd |
| `macos:unifiedlog` | File metadata updated with UF_HIDDEN flag |
| `WinEventLog:Sysmon` | EventCode=15 |
| `auditd:PATH` | file path matches exclusion directories |
| `auditd:SYSCALL` | PATH |
| `auditd:PATH` | PATH |
| `macos:endpointsecurity` | es_event_file_rename_t or es_event_file_write_t |
| `linux:osquery` | file_events |
| `fs:fileevents` | /var/log/install.log |
| `auditd:SYSCALL` | file write after sleep delay |
| `esxi:vmkernel` | Upload of file to datastore |
| `ebpf:syscalls` | Unexpected container volume unmount + file deletion |
| `macos:osquery` | file_events |
| `EDR:file` | File Metadata Analysis (PE overlays, entropy) |
| `linux:osquery` | elf_info, hash, yara_matches |
| `macos:osquery` | mach_o_info, file_metadata |
| `macos:unifiedlog` | Code signature validation fails or is absent post-binary modification |
| `fs:filesystem` | Binary file hash changes outside of update/patch cycles |
| `linux:osquery` | Read headers and detect MIME type mismatch |
| `macos:unifiedlog` | Code signing verification failures or bypassed trust decisions |
| `NSM:Flow` | Observed File Transfers |
| `esxi:vmkernel` | Storage access and file ops |
| `macos:unifiedlog` | Creation of new LaunchAgent or LoginItem plist files in ~/Library/LaunchAgents/ |
| `auditd:CONFIG_CHANGE` | chmod or chown of hook files indicating privilege escalation or execution permission change |
| `macos:unifiedlog` | filesystem events |
| `macos:unifiedlog` | xattr -d com.apple.quarantine or similar attribute removal commands |
| `macos:unifiedlog` | Gatekeeper quarantine policy decision anomalies recorded in com.apple.LaunchServices.QuarantineEventsV2 |
| `linux:syslog` | application or system execution logs |
| `WinEventLog:Security` | EventCode=4663, 4670, 4656 |
| `auditd:SYSCALL` | syscall in (chmod, fchmod, fchmodat, chown, fchown, fchownat, setxattr, lsetxattr, fsetxattr) |
| `linux:syslog` | file permission modification events in kernel messages |
| `fs:fsevents` | file system events indicating permission or attribute changes |
| `OpenBSM:AuditTrail` | BSM audit events for file permission modifications |
| `esxi:hostd` | host daemon events related to file or VM permission changes |
| `esxi:vmkernel` | VMware kernel events for file system permission modifications |
| `WinEventLog:Microsoft-Windows-CodeIntegrity/Operational` | Unsigned or invalid image for newly installed/updated binaries |
| `journald:package` | dpkg/apt/yum/dnf transaction logs; vendor updaters in systemd journals |
| `macos:unifiedlog` | pkginstalld/softwareupdated/Homebrew install transactions |
| `macos:unifiedlog` | AMFI/Gatekeeper code signature or notarization failures |
| `EDR:detection` | App reputation telemetry |
| `gatekeeper/quarantine database` | LaunchServices quarantine |
| `linux:osquery` | file_events.path |
| `auditd:SYSCALL` | setuid or setgid bit changes |
| `linux:osquery` | Filesystem modifications to trusted paths |
| `fs:fsusage` | filesystem monitoring of exec/open |
| `auditd:SYSCALL` | syscall in (chmod, fchmod, fchmodat, chown, fchown, fchownat, lchown, setxattr, lsetxattr, fsetxattr, removexattr, lremovexattr, fremovexattr) |
| `auditd:PATH` | file path modifications on critical system directories (/etc, /usr/bin, /usr/sbin, /var, /opt) |
| `linux:syslog` | kernel messages related to file system permission changes and security violations |
| `OpenBSM:AuditTrail` | BSM audit events for file permission, ownership, and attribute modifications with user context |
| `macos:unifiedlog` | kernel extension and system extension logs related to file system security violations or SIP bypass attempts |
| `WinEventLog:Microsoft-Windows-CodeIntegrity/Operational` | Code integrity violations in boot-start drivers or firmware |
| `fwupd:logs` | Firmware updates applied or failed |
| `macos:endpointsecurity` | es_event_authentication |
| `esxi:vmkernel` | Datastore modification events |
| `linux:osquery` | Write or modify .desktop file in XDG autostart path |
| `macos:unifiedlog` | Unexpected application binary modifications or altered signing status |
| `auditd:SYSCALL` | setxattr or getxattr system call |
| `macos:unifiedlog` | extended attribute write or modification |
| `WinEventLog:Security` | EventCode=4663, 4656, 4658 |
| `auditd:SYSCALL` | chmod, chown, setxattr, or file writes to /etc/ssl/* or /usr/local/share/ca-certificates/* |
| `macos:unifiedlog` | New certificate trust settings added by unexpected process |
| `esxi:syslog` | Datastore file hidden or renamed unexpectedly |
| `WinEventLog:Windows Defender` | Operational |
| `macos:unifiedlog` | subsystem=com.apple.lsd |
| `saas:RepoEvents` | New file added or modified in PR targeting CI/CD or build config (e.g., `gitlab-ci.yml`, `build.gradle`, `pom.xml`, `.github/workflows/*.yml`) |
| `WinEventLog:Microsoft-Windows-CodeIntegrity/Operational` | CodeIntegrity reports 'Invalid image hash' or 'Unsigned image' for new/updated binaries |
| `WinEventLog:Microsoft-Windows-Windows Defender/Operational` | SmartScreen or ASR blocks on newly downloaded installer/updater |
| `WinEventLog:Setup` | MSI/Product install, repair or update events |
| `journald:package` | dpkg/apt install, remove, upgrade events |
| `journald:package` | yum/dnf install or update transactions |
| `linux:osquery` | hash, rpm_packages, deb_packages, file_events |
| `macos:unifiedlog` | installer or system_installd 'PackageKit: install succeeded/failed' with non-notarized or unknown signer |
| `macos:unifiedlog` | Gatekeeper/AMFI 'code signature invalid' / 'not notarized' messages |
| `networkdevice:syslog` | OS version query results inconsistent with expected or approved version list |
| `macos:unifiedlog` | File creation or modification with com.apple.ResourceFork extended attribute |
