# DC0039 - File Creation

## Description

A new file is created on a system or network storage. This action often signifies an operation such as saving a document, writing data, or deploying a file. Logging these events helps identify legitimate or potentially malicious file creation activities. Examples include logging file creation events (e.g., Sysmon Event ID 11 or Linux auditd logs).

## Log Sources

| Log Source | Channel |
|------------|---------|
| `File` | None |
| `WinEventLog:Sysmon` | EventCode=11 |
| `auditd:SYSCALL` | creat |
| `macos:unifiedlog` | file write |
| `macos:osquery` | CREATE/MODIFY: Modification of app.asar inside .app bundle |
| `auditd:FILE` | File creation with name starting with '.' |
| `macos:unifiedlog` | Creation or modification of browser extension .plist files |
| `auditd:SYSCALL` | open or creat syscalls targeting excluded paths |
| `macos:unifiedlog` | file creation in AV exclusion directories |
| `auditd:SYSCALL` | file creation/modification |
| `macos:unifiedlog` | file write/create |
| `esxi:vmkernel` | file write |
| `snmp:syslog` | firmware write/log event |
| `auditd:SYSCALL` | open,creat,rename: Writes in $HOME/Downloads, /tmp, ~/.cache with exe/script/archive/office extensions |
| `fs:fsevents` | Create in /Users/*/Downloads or /private/var/folders/* with quarantine attribute |
| `macos:unifiedlog` | file events |
| `esxi:vmkernel` | VMFS file creation |
| `auditd:SYSCALL` | write/open, FIM audit |
| `fs:fsusage` | open/write/exec calls |
| `macos:unifiedlog` | Creation of .plist under /Library/Managed Preferences/ |
| `fs:fileevents` | creat |
| `fs:fsusage` | disk activity on /Library/LaunchAgents or LaunchDaemons |
| `macos:osquery` | file_events |
| `auditd:SYSCALL` | open: Write to ~/.vscode-cli/code_tunnel.json |
| `macos:unifiedlog` | creation of ~/.vscode-cli/code_tunnel.json |
| `macos:unifiedlog` | create/modify dylib files in monitored directories |
| `auditd:SYSCALL` | write |
| `linux:Sysmon` | New files in /tmp, /var/tmp, $HOME/.cache, executed within TimeWindow after browser HTTP fetch |
| `macos:unifiedlog` | New files written to /var/folders, /tmp, ~/Library/Caches, or ~/Downloads by browser context or its children |
| `auditd:FILE` | create: New file created in system binaries or temp directories |
| `macos:unifiedlog` | File created in ~/Library/LaunchAgents or executable directories |
| `auditd:SYSCALL` | open, unlink, rename: File creation or deletion involving critical stored data |
| `macos:unifiedlog` | Process wrote large .mov/.mp4 in user temp/hidden dirs |
| `macos:unifiedlog` | logd:file write |
| `fs:fsusage` | File IO |
| `auditd:SYSCALL` | creat, open, write on /etc/systemd/system and /usr/lib/systemd/system |
| `macos:unifiedlog` | File creation |
| `macos:unifiedlog` | Attachment files written to ~/Downloads or temporary folders |
| `fs:fsusage` | file activity |
| `CloudTrail:PutObject` | PutObject |
| `auditd:PATH` | Creation of files with extensions .sql, .csv, .sqlite, especially in user directories |
| `macos:unifiedlog` | Writes of .sql/.csv/.xlsx files to user documents/downloads |
| `auditd:PATH` | New .py/.js/.sh files written to ~/.local/, ~/.cache/, or /tmp/ within 5 min of package install |
| `auditd:SYSCALL` | write, open, or rename to /etc/systemd/system/*.service |
| `auditd:FILE` | create: Creation of .zip, .gz, .bz2 files in /tmp, /var/tmp, or /home directories |
| `macos:unifiedlog` | Creation of .zip, .gz, .dmg archives in /Users, /tmp, or application directories |
| `fs:fsusage` | file open/write |
| `macos:endpointsecurity` | ES_EVENT_TYPE_NOTIFY_CREATE: path under /Users/*/(Downloads\|Desktop\|Library/*/Containers\|Library/Group Containers) AND extension in SuspiciousExtensions |
| `auditd:SYSCALL` | open/create/rename: name in (/home/*/Downloads/*\|/tmp/*\|/run/user/*\|/media/*) AND ext in SuspiciousExtensions |
| `auditd:FILE` | create: Creation of archive files in /tmp, /var/tmp, or user home directories |
| `macos:unifiedlog` | Creation of .zip, .dmg, .tar.gz files in /Users, /tmp, or application directories |
| `linux:osquery` | file_events |
| `macos:unifiedlog` | File Events |
| `auditd:SYSCALL` | File creations of *.qcow2, *.vdi, *.vmdk outside standard VM directories |
| `macos:unifiedlog` | Creation or modification of postinstall scripts within .pkg or .mpkg contents |
| `auditd:SYSCALL` | open: File creation under /tmp, /var/tmp, ~/.cache with executable bit or shell shebang |
| `macos:unifiedlog` | create: New files in /tmp or ~/Library/Application Support/* with executable or script extensions |
| `auditd:SYSCALL` | open, write, unlink |
| `WinEventLog:Sysmon` | File creation of suspicious scripts/binaries in temporary directories |
| `macos:unifiedlog` | File creation of unsigned binaries/scripts in user cache or download directories |
| `auditd:SYSCALL` | File creation events in /var/mail or /var/spool/mail exceeding baseline thresholds |
| `fs:fsusage` | create: Attachment file creation in ~/Library/Mail directories |
| `WinEventLog:Microsoft-Windows-Shell-Core` | New startup folder shortcut or binary placed in Startup directory |
| `auditd:SYSCALL` | write or create file after .bash_history access |
| `auditd:SYSCALL` | new file created in /var/www/html, /srv/http, or similar web root |
| `fs:launchdaemons` | file_create |
| `auditd:PATH` | mount target path within /proc/* |
| `macos:fsevents` | /Library/StartupItems/, ~/Library/LaunchAgents/ |
| `fs:fsusage` | write or chmod to ~/Library/LaunchAgents/*.plist |
| `auditd:PATH` | creation of .so files in non-standard directories (e.g., /tmp, /home/*) |
| `auditd:FILE` | create: Creation of files with anomalous headers and entropy levels in /tmp or user directories |
| `macos:unifiedlog` | Creation of files with anomalous headers and entropy values |
| `auditd:SYSCALL` | Access or modification to /lib/modules or creation of .ko files |
| `fs:fsevents` | Directory events (kFSEventStreamEventFlagItemCreated) |
| `gcp:workspaceaudit` | drive.activity logs |
| `fs:fileevents` | create/write/rename in user-writable paths |
| `auditd:PATH` | WRITE: Drop of binaries/scripts in ~/.local, /tmp, or /opt tool dirs |
| `macos:osquery` | CREATE/MODIFY: Creation of LaunchAgents/Daemons plists in user/system locations |
| `auditd:SYSCALL` | open,create |
| `auditd:FILE` | Creation of hidden files (.*) in sensitive directories (/etc, /var, /usr/bin) |
| `macos:unifiedlog` | Creation of LaunchAgents/LaunchDaemons in hidden or non-standard directories |
| `auditd:FILE` | create: Creation of files ending in .tar, .gz, .bz2, .zip in /tmp or /var/tmp |
| `macos:unifiedlog` | Creation of .zip or .dmg files in user-accessible or temporary directories |
| `fs:fsusage` | file write |
| `macos:endpointsecurity` | es_event_open |
| `macos:unifiedlog` | file create or modify in /etc/emond.d/rules or /private/var/db/emondClients |
| `auditd:SYSCALL` | open,creat,rename,write |
| `macos:unifiedlog` | Writes under ~/Library/Application Support/Code*/extensions or JetBrains plugins |
| `AWS:CloudTrail` | PutObject |
