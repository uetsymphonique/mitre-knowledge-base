# fs

51 unique events

| Log Source | Channel | Data Components |
|------------|---------|-----------------|
| `fs:fileevents` | /Library/LaunchDaemons/*.plist, ~/Library/LaunchAgents/*.plist | Scheduled Job Metadata |
| `fs:fileevents` | /var/log/install.log | File Metadata, File Modification |
| `fs:fileevents` | /var/log/quarantine.log | File Modification |
| `fs:fileevents` | File system access events with kFSEventStreamEventFlagItemRemoved, kFSEventStreamEventFlagItemRenamed flags for environmental artifact collection (/System/Library, /usr/sbin, plist files) | File Access |
| `fs:fileevents` | creat | File Creation |
| `fs:fileevents` | create/write/rename in user-writable paths | File Creation |
| `fs:filesystem` | Binary file hash changes outside of update/patch cycles | File Metadata |
| `fs:filesystem` | Modification or creation of files matching 'com.apple.loginwindow.*.plist' in ~/Library/Preferences/ByHost | File Modification |
| `fs:fsevents` | Create in /Users/*/Downloads or /private/var/folders/* with quarantine attribute | File Creation |
| `fs:fsevents` | Directory events (kFSEventStreamEventFlagItemCreated) | File Creation |
| `fs:fsevents` | Extensions | File Modification |
| `fs:fsevents` | create/write/rename under user-writable paths | File Modification |
| `fs:fsevents` | file system events indicating access to system configuration files and environmental information sources | File Access |
| `fs:fsevents` | file system events indicating permission or attribute changes | File Metadata |
| `fs:fsevents` | file system events indicating permission, ownership, or extended attribute changes on critical paths. File system modification events with kFSEventStreamEventFlagItemChangeOwner, kFSEventStreamEventFlagItemXattrMod flags | File Modification |
| `fs:fsusage` | Detached process execution with no associated parent | OS API Execution |
| `fs:fsusage` | Disk Activity Tracing | File Access |
| `fs:fsusage` | Execution of disguised binaries | Process Creation |
| `fs:fsusage` | File Access Monitor | File Access |
| `fs:fsusage` | File IO | File Creation |
| `fs:fsusage` | Filesystem Access Logging | File Modification |
| `fs:fsusage` | Filesystem Call Monitoring | File Access |
| `fs:fsusage` | access to BPF devices or interface IOCTLs | Command Execution |
| `fs:fsusage` | binary execution of security_authtrampoline | Process Creation |
| `fs:fsusage` | create: Attachment file creation in ~/Library/Mail directories | File Creation |
| `fs:fsusage` | disk activity on /Library/LaunchAgents or LaunchDaemons | File Creation |
| `fs:fsusage` | file | File Access |
| `fs:fsusage` | file access to /usr/lib/cron/at and job execution path | File Modification |
| `fs:fsusage` | file access to /usr/lib/cron/tabs/ and cron output files | File Modification |
| `fs:fsusage` | file activity | File Creation |
| `fs:fsusage` | file open for known browser cookie paths | File Access |
| `fs:fsusage` | file open/write | File Creation |
| `fs:fsusage` | file reads/writes from /Volumes/ | File Access |
| `fs:fsusage` | file system activity monitor | Command Execution |
| `fs:fsusage` | file write | File Creation |
| `fs:fsusage` | file write to launchd plist paths | File Modification |
| `fs:fsusage` | filesystem activity | File Access |
| `fs:fsusage` | filesystem monitoring of exec/open | File Metadata |
| `fs:fsusage` | modification of existing LaunchAgents plist | File Modification |
| `fs:fsusage` | open/read/mount operations | Drive Access |
| `fs:fsusage` | open/write/exec calls | File Creation |
| `fs:fsusage` | read/write | File Access |
| `fs:fsusage` | truncate, unlink, write | File Modification |
| `fs:fsusage` | unlink, fs_delete | File Deletion |
| `fs:fsusage` | unlink, write | File Modification |
| `fs:fsusage` | write or chmod to ~/Library/LaunchAgents/*.plist | File Creation |
| `fs:launchdaemons` | file_create | File Creation |
| `fs:launchdaemons` | file_modify | File Modification |
| `fs:plist` | /var/root/Library/Preferences/com.apple.loginwindow.plist | File Modification |
| `fs:plist_monitoring` | /Users/*/Library/Mail/V*/MailData/RulesActiveState.plist | File Modification |
| `fs:quarantine` | /var/log/quarantine.log | File Access |
