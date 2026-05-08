# DC0055 - File Access

## Description

To events where a file is opened or accessed, making its contents available to the requester. This includes reading, executing, or interacting with files by authorized or unauthorized entities. Examples include logging file access events (e.g., Windows Event ID 4663), monitoring file reads, and detecting unusual file access patterns. Examples: 

- File Read Operations: A user opens a sensitive document (e.g., financial_report.xlsx) on a shared drive.
- File Execution: A script or executable file is accessed and executed (e.g., malware.exe is run from a temporary directory).
- Unauthorized File Access: An unauthorized user attempts to access a protected configuration file (e.g., `/etc/passwd` on Linux or `System32` files on Windows).
- File Access Patterns: Bulk access to multiple files in a short time (e.g., mass access to documents on a file server).
- File Access via Network: Files on a network share are accessed remotely (e.g., logs of SMB file access).

## Log Sources

| Log Source | Channel |
|------------|---------|
| `File` | None |
| `m365:unified` | FileAccessed, MailboxAccessed |
| `auditd:SYSCALL` | open, read, or stat of browser config files |
| `macos:unifiedlog` | Access to ~/Library/*/Safari or Chrome directories by non-browser processes |
| `WinEventLog:Security` | EventCode=4663, 4670, 4656 |
| `macos:unifiedlog` | file events |
| `gcp:audit` | Write operations to storage |
| `esxi:vmkernel` | VMFS access logs |
| `macos:endpointsecurity` | ES_EVENT_TYPE_NOTIFY_OPEN: Open of .dylib/.so in user-writable locations |
| `auditd:SYSCALL` | open: File access attempt on /tmp/krb5cc_* or /tmp/krb5.ccache |
| `macos:unifiedlog` | Kerberos framework calls to API:{uuid} cache outside normal process lineage |
| `auditd:SYSCALL` | openat |
| `auditd:FILE` | /home/*/.mozilla/firefox/*/logins.json OR /home/*/.config/google-chrome/*/Login Data |
| `macos:unifiedlog` | ~/Library/Application Support/Google/Chrome/*/Login Data OR ~/Library/Application Support/Firefox/*/logins.json |
| `auditd:SYSCALL` | open |
| `auditd:FILE` | /proc/*/mem read attempt |
| `auditd:PATH` | Read access to known backup software configuration files (e.g., /etc/rsnapshot.conf, /opt/veeam/config.ini) |
| `macos:unifiedlog` | Read access to Time Machine plist files or CCC configurations in ~/Library/Preferences/ |
| `auditd:SYSCALL` | open, read |
| `linux:syslog` | auth.log or custom tool logs |
| `fs:fsusage` | file |
| `linux:syslog` | /var/log/syslog |
| `macos:osquery` | file_events |
| `auditd:SYSCALL` | open, flock, fcntl, unlink |
| `fs:fsusage` | File Access Monitor |
| `macos:unifiedlog` | log stream - file subsystem |
| `auditd:SYSCALL` | read/open of sensitive files |
| `macos:unifiedlog` | file read of sensitive directories |
| `esxi:hostd` | datastore file access |
| `auditd:SYSCALL` | Unusual processes accessing or modifying cookie databases |
| `macos:unifiedlog` | Abnormal process access to Safari or Chrome cookie storage |
| `auditd:SYSCALL` | PATH records referencing /dev/video* |
| `macos:endpointsecurity` | open: Process opens AppleCamera/IOUSB device nodes or AVFoundation frameworks |
| `ebpf:syscalls` | container_file_activity |
| `fs:fsusage` | Disk Activity Tracing |
| `macos:keychain` | Access to Keychain DB or system.keychain |
| `auditd:SYSCALL` | open, read: /etc/ssl/, /etc/pki/, ~/.pki/nssdb/ |
| `macos:keychain` | ~/Library/Keychains, /Library/Keychains |
| `m365:unified` | Bulk downloads or API extractions from Microsoft-hosted data repositories (e.g., Dynamics 365) |
| `auditd:PATH` | open: Access to sensitive log files (/var/log/auth.log, /var/log/secure, /var/log/syslog) |
| `macos:unifiedlog` | open: Access to /var/log/system.log or related security event logs |
| `azure:activity` | CollectGuestLogs: Unexpected collection of guest logs by Azure VM Agent outside normal maintenance windows |
| `esxi:hostd` | read: Access to sensitive log files by non-admin users |
| `auditd:SYSCALL` | Processes reading credential or token cache files |
| `auditd:SYSCALL` | read/open of sensitive file directories |
| `esxi:hostd` | datastore/log file access |
| `fs:fsusage` | filesystem activity |
| `WinEventLog:Microsoft-Windows-Windows Defender/Operational` | Suspicious file execution on removable media path |
| `auditd:PATH` | PATH |
| `auditd:SYSCALL` | open/read of sensitive config or secret files |
| `macos:unifiedlog` | open/read of *.plist or .env files |
| `ebpf:syscalls` | open/read on secret mount paths |
| `CloudTrail:GetObject` | sensitive credential files in buckets or local image storage |
| `auditd:SYSCALL` | open/read of sensitive directories |
| `macos:unifiedlog` | read of user document directories |
| `esxi:syslog` | guest OS outbound transfer logs |
| `fs:fsusage` | Filesystem Call Monitoring |
| `esxi:hostd` | vSphere File API Access |
| `auditd:SYSCALL` | open/read: Access to /proc/self/status with focus on TracerPID field |
| `fs:fsusage` | read/write |
| `esxis:vmkernel` | Datastore Access |
| `auditd:SYSCALL` | open/read access to ~/.bash_history |
| `macos:endpointsecurity` | open or read syscall to ~/.bash_history |
| `macos:unifiedlog` | read access to ~/Library/Keychains/login.keychain-db |
| `auditd:SYSCALL` | open,read |
| `macos:unifiedlog` | filesystem and process events |
| `auditd:SYSCALL` | open/read system calls to ~/.bash_history or /etc/shadow |
| `macos:unifiedlog` | read access to ~/Library/Keychains or history files by terminal processes |
| `auditd:SYSCALL` | read of /run/secrets or docker volumes by non-entrypoint process |
| `macos:unifiedlog` | access to /Volumes/SharePoint or network mount |
| `auditd:SYSCALL` | Reads of ~/.bash_history, ~/.mozilla, or access to /dev/input |
| `macos:unifiedlog` | Access to ~/Library/Safari/Bookmarks.plist or recent files |
| `auditd:SYSCALL` | open/read |
| `macos:unifiedlog` | access to keychain database |
| `auditd:PATH` | file read |
| `linux:syslog` | kernel messages related to cryptographic operations, module loading, and filesystem access patterns |
| `fs:fsevents` | file system events indicating access to system configuration files and environmental information sources |
| `macos:endpointsecurity` | es_event_open, es_event_exec |
| `auditd:SYSCALL` | open: Access to named pipes or FIFO in /tmp or /dev/shm by unexpected processes |
| `auditd:SYSCALL` | open or read to browser cookie storage |
| `fs:fsusage` | file open for known browser cookie paths |
| `auditd:SYSCALL` | open, read, mount |
| `fs:fsusage` | file reads/writes from /Volumes/ |
| `macos:unifiedlog` | log stream - file provider subsystem |
| `auditd:SYSCALL` | file |
| `kubernetes:audit` | GET or LIST requests to /var/run/secrets/kubernetes.io/serviceaccount/ followed by access to the Kubernetes API server |
| `auditd:SYSCALL` | Access to /var/lib/sss/secrets/secrets.ldb or .secrets.mkey |
| `fs:quarantine` | /var/log/quarantine.log |
| `desktop:file_manager` | nautilus, dolphin, or gvfs logs |
| `linux:osquery` | /proc/*/maps access |
| `auditd:SYSCALL` | open/read of sensitive directories (/etc, /home/*) |
| `macos:unifiedlog` | read/write of user documents prior to upload |
| `esxi:hostd` | file copy or datastore upload via HTTPS |
| `macos:unifiedlog` | open/read access to private key files (id_rsa, *.pem, *.p12) |
| `linux:osquery` | None |
| `macos:osquery` | None |
| `fs:fileevents` | File system access events with kFSEventStreamEventFlagItemRemoved, kFSEventStreamEventFlagItemRenamed flags for environmental artifact collection (/System/Library, /usr/sbin, plist files) |
| `auditd:FS` | read: File access to /proc/modules or /sys/module/ |
| `macos:unifiedlog` | read: File access to /System/Library/Extensions/ or related kernel extension paths |
| `auditd:SYSCALL` | PATH |
| `auditd:SYSCALL` | open/read on ~/.local/share/keepassxc/* OR ~/.password-store/* |
| `macos:unifiedlog` | *.opvault OR *.ldb OR *.kdbx |
