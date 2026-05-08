# DC0061 - File Modification

## Description

Changes made to a file, including updates to its contents, metadata, access permissions, or attributes. These modifications may indicate legitimate activity (e.g., software updates) or unauthorized changes (e.g., tampering, ransomware, or adversarial modifications). Examples: 

- Content Modifications: Changes to the content of a configuration file, such as modifying `/etc/ssh/sshd_config` on Linux or `C:\Windows\System32\drivers\etc\hosts` on Windows.
- Permission Changes: Altering file permissions to allow broader access, such as changing a file from `644` to `777` on Linux or modifying NTFS permissions on Windows.
- Attribute Modifications: Changing a file's attributes to hidden, read-only, or system on Windows.
- Timestamp Manipulation: Adjusting a file's creation or modification timestamp using tools like `touch` in Linux or timestomping tools on Windows.
- Software or System File Changes: Modifying system files such as `boot.ini`, kernel modules, or application binaries.

## Log Sources

| Log Source | Channel |
|------------|---------|
| `File` | None |
| `auditd:SYSCALL` | open/write calls modifying ~/.bashrc, ~/.profile, or /etc/paths.d |
| `macos:unifiedlog` | File modification in /etc/paths.d or user shell rc files |
| `fs:fileevents` | /var/log/quarantine.log |
| `macos:unifiedlog` | Modification of ~/Library/LaunchAgents or /Library/LaunchDaemons plist |
| `auditd:SYSCALL` | open, write |
| `auditd:SYSCALL` | AUDIT_SYSCALL (open, write, rename, unlink) |
| `macos:endpointsecurity` | ES_EVENT_TYPE_NOTIFY_WRITE, targeting .zshrc, .zlogin, .zprofile |
| `fs:fileevents` | /var/log/install.log |
| `auditd:SYSCALL` | PATH |
| `macos:osquery` | file_events |
| `WinEventLog:Sysmon` | EventCode=2 |
| `auditd:SYSCALL` | execve call for modification of /etc/sudoers or writing to /var/db/sudo |
| `auditd:SYSCALL` | open, write: File modifications under /etc/ssl/certs, /usr/local/share/ca-certificates, or /etc/pki/ca-trust/source/anchors |
| `macos:osquery` | query: Enumeration of root certificates showing unexpected additions |
| `auditd:SYSCALL` | open, unlink, rename: Suspicious file access, deletion, or modification of sensitive paths |
| `macos:unifiedlog` | Anomalous plist modifications or sensitive file overwrites by non-standard processes |
| `auditd:FILE` | Modification or deletion of /etc/audit/audit.rules or /etc/audit/audit.conf |
| `auditd:SYSCALL` | open/write of .service unit files |
| `auditd:SYSCALL` | open/write/unlink |
| `macos:unifiedlog` | loginwindow or desktopservices modified settings or files |
| `ESXiLogs:messages` | changes to /etc/motd or /etc/vmware/welcome |
| `auditd:SYSCALL` | write, rename |
| `containerd:runtime` | file change monitoring within /etc/cron.*, /tmp, or mounted volumes |
| `esxi:cron` | manual edits to /etc/rc.local.d/local.sh or cron.d |
| `auditd:PATH` | /etc/passwd or /etc/group file write |
| `auditd:SYSCALL` | write |
| `macos:unifiedlog` | SecurityAgentPlugins modification |
| `macos:unifiedlog` | write: File modifications to *.plist within LaunchAgents, LaunchDaemons, Application Support, or Preferences directories |
| `linux:osquery` | file_events |
| `esxi:hostd` | boot |
| `networkdevice:syslog` | config |
| `macos:unifiedlog` | Modification of backgrounditems.btm or creation of LoginItems subdirectory in .app bundle |
| `fs:filesystem` | Modification or creation of files matching 'com.apple.loginwindow.*.plist' in ~/Library/Preferences/ByHost |
| `auditd:SYSCALL` | write \| PATH=/home/*/.ssh/authorized_keys |
| `macos:auth` | ~/.ssh/authorized_keys |
| `gcp:audit` | compute.instances.setMetadata |
| `azure:resource` | PATCH vm/authorized_keys |
| `esxi:shell` | file write or edit |
| `linux:syslog` | rename |
| `ebpf:syscalls` | file_write |
| `macos:unifiedlog` | Modification of plist with apple.awt.UIElement set to TRUE |
| `fs:fsusage` | unlink, write |
| `auditd:SYSCALL` | open, write: Write operations targeting /dev/sda, /dev/nvme0n1, or EFI partition mounts |
| `auditd:PATH` | write: Modification of /boot/grub/*, /boot/efi/EFI/*, or initramfs images |
| `networkdevice:config` | config-change: timezone or ntp server configuration change after a time query command |
| `macos:unifiedlog` | replace existing dylibs |
| `networkdevice:config` | Configuration changes to boot variables, startup image paths, or checksum verification failures |
| `firmware:update` | Unexpected or unscheduled firmware updates, image overwrites, or failed signature validation |
| `IntegrityCheck:ImageValidation` | Checksum or hash mismatch between running image and known-good vendor-provided image |
| `macos:osquery` | File modifications in ~/Library/Preferences/ |
| `auditd:SYSCALL` | open/write to /etc/pam.d/* |
| `macos:unifiedlog` | Modification of /Library/Security/SecurityAgentPlugins |
| `macos:unifiedlog` | Modifications to Mail.app plist files controlling message rules |
| `WinEventLog:Security` | EventCode=4663, 4670, 4656 |
| `auditd:SYSCALL` | write: Modification of structured stored data by suspicious processes |
| `linux:syslog` | Unexpected log entries or malformed SQL operations in databases |
| `macos:unifiedlog` | Unexpected creation or modification of stored data files in protected directories |
| `auditd:SYSCALL` | openat, write, rename, unlink |
| `macos:unifiedlog` | file encrypted\|new file with .encrypted extension\|disk write burst |
| `esxi:vmkernel` | rename .vmdk to .*.locked\|datastore write spike |
| `macos:unifiedlog` | Mach-O binary modified or LC_LOAD_DYLIB segment inserted |
| `auditd:SYSCALL` | open/write syscalls targeting /etc/ld.so.preload or binaries in /usr/bin |
| `macos:unifiedlog` | Modified application plist or binary replacement in /Applications |
| `esxi:shell` | admin command usage |
| `networkdevice:syslog` | startup-config |
| `macos:unifiedlog` | File creation or overwrite in common web-hosting folders |
| `esxi:vmkernel` | Unauthorized file modifications within datastore volumes via shell access or vCLI |
| `networkdevice:config` | Configuration changes referencing 'crypto', 'key length', 'cipher', or downgrade of encryption settings |
| `FirmwareLogs:Update` | Unexpected firmware or image updates modifying cryptographic modules |
| `fs:plist` | /var/root/Library/Preferences/com.apple.loginwindow.plist |
| `auditd:SYSCALL` | modification of existing .service file |
| `auditd:PATH` | write or create events on *.pth, sitecustomize.py, usercustomize.py in site-packages or dist-packages |
| `macos:unifiedlog` | write of plist files in /Library/LaunchAgents or /Library/LaunchDaemons |
| `WinEventLog:System` | Unexpected modification to lsass.exe or cryptdll.dll |
| `networkconfig` | unexpected OS image file upload or modification events |
| `network:runtime` | checksum or runtime memory verification failures |
| `macos:unifiedlog` | write |
| `auditd:SYSCALL` | open, write: Modification of /boot/grub/* or /boot/efi/* |
| `macos:unifiedlog` | Modification of /System/Library/CoreServices/boot.efi |
| `macos:unifiedlog` | Modification of LaunchAgents or LaunchDaemons plist files |
| `auditd:SYSCALL` | chmod |
| `auditd:SYSCALL` | rename,chmod |
| `fs:fsevents` | create/write/rename under user-writable paths |
| `macos:osquery` | Changes to LSFileQuarantineEnabled field in Info.plist |
| `fs:fsusage` | file access to /usr/lib/cron/tabs/ and cron output files |
| `esxi:hostd` | modification of crontab or local.sh entries |
| `networkdevice:config` | Configuration file modified or replaced on network device |
| `macos:unifiedlog` | Plist modifications containing virtualization run configurations |
| `fs:fsusage` | file access to /usr/lib/cron/at and job execution path |
| `macos:unifiedlog` | binary modified or replaced |
| `esxi:hostd` | binary or module replacement event |
| `networkdevice:config` | Configuration change events referencing encryption, TLS/SSL, or IPSec settings |
| `networkdevice:firmware` | Unexpected firmware update or image modification affecting crypto modules |
| `fs:fsevents` | file system events indicating permission, ownership, or extended attribute changes on critical paths. File system modification events with kFSEventStreamEventFlagItemChangeOwner, kFSEventStreamEventFlagItemXattrMod flags |
| `auditd:FILE` | Modification of Display Manager configuration files (/etc/gdm3/*, /etc/lightdm/*) |
| `macos:unifiedlog` | Modification of /Library/Preferences/com.apple.loginwindow plist |
| `auditd:SYSCALL` | Modification of user shell profile or trap registration via echo/redirection (e.g., echo "trap 'malicious_cmd' INT" >> ~/.bashrc) |
| `macos:unifiedlog` | File write or append to .zshrc, .bash_profile, .zprofile, etc. |
| `auditd:SYSCALL` | chmod, write, create, open |
| `fs:fsevents` | Extensions |
| `auditd:SYSCALL` | open, write: File writes to application binaries or libraries at runtime |
| `macos:osquery` | CALCULATE: Mismatch in file integrity of critical macOS applications |
| `auditd:SYSCALL` | file write operations in /Library/WebServer/Documents |
| `fs:launchdaemons` | file_modify |
| `auditd:PATH` | write: File modifications to /etc/systemd/sleep.conf or related power configuration files |
| `macos:unifiedlog` | write: File modification to com.apple.PowerManagement.plist or related system preference files |
| `fs:fsusage` | modification of existing LaunchAgents plist |
| `macos:unifiedlog` | create/modify dylib in monitored directories |
| `WinEventLog:CodeIntegrity` | EventCode=3033 |
| `auditd:SYSCALL` | write operation on /etc/passwd or /etc/shadow |
| `macos:unifiedlog` | modification to /var/db/dslocal/nodes/Default/users/ |
| `linux:osquery` | New or modified kernel object files (.ko) within /lib/modules directory |
| `macos:osquery` | Modifications to /var/db/SystemPolicyConfiguration/KextPolicy or kext_policy table |
| `networkdevice:audit` | SNMP configuration changes, such as enabling read/write access or modifying community strings |
| `macos:osquery` | write |
| `auditd:SYSCALL` | mount or losetup commands creating hidden or encrypted FS |
| `macos:unifiedlog` | Hidden volume attachment or modification events |
| `macos:unifiedlog` | Suspicious plist edits for volume mounting behavior |
| `networkdevice:config` | Configuration changes to startup image paths, boot loader parameters, or debug flags |
| `networkdevice:syslog` | Checksum/hash mismatch between device OS image and baseline known-good version |
| `macos:unifiedlog` | file writes |
| `m365:defender` | OfficeTelemetry or DLP |
| `fs:fsusage` | Filesystem Access Logging |
| `networkdevice:config` | Configuration changes referencing cryptographic hardware modules or disabling hardware acceleration |
| `FirmwareLogs:Update` | Unexpected firmware updates that alter encryption libraries or disable hardware crypto modules |
| `m365:office` | Anomalous editing of invoice or payment document templates |
| `fs:fsusage` | truncate, unlink, write |
| `macos:unifiedlog` | Modification or replacement of /Library/Application Support/com.apple.TCC/TCC.db or ~/Library/Application Support/com.apple.TCC/TCC.db |
| `linux:fim` | Changes to /etc/rc.local.d/local.sh or creation of unexpected startup files in persistent partitions (/etc/init.d, /store, /locker) |
| `macos:endpointsecurity` | write, rename |
| `auditd:SYSCALL` | open/write to /proc/*/mem or /proc/*/maps |
| `sysdig:file` | evt.type=write |
| `macos:unifiedlog` | rule definitions written to emond rule plists |
| `networkdevice:config` | Configuration changes referencing older image versions or unexpected boot parameters |
| `FileIntegrity:ImageValidation` | Hash/checksum mismatch against baseline vendor-provided OS image versions |
| `auditd:SYSCALL` | write or rename to /etc/systemd/system or /etc/init.d |
| `fs:fsusage` | file write to launchd plist paths |
| `auditd:SYSCALL` | modification of entrypoint scripts or init containers |
| `fs:plist_monitoring` | /Users/*/Library/Mail/V*/MailData/RulesActiveState.plist |
| `auditd:SYSCALL` | chmod/chown to /etc/passwd or /etc/shadow |
| `auditd:SYSCALL` | open/write syscalls targeting web directory files |
| `macos:unifiedlog` | Terminal/Editor processes modifying web folder |
| `esxi:vmkernel` | /var/log/vmkernel.log |
