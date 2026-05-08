# macos

612 unique events

| Log Source | Channel | Data Components |
|------------|---------|-----------------|
| `macos:MDM` | profiles -P\|getaccountpolicies | User Account Metadata |
| `macos:auth` | ~/.ssh/authorized_keys | File Modification |
| `macos:cron` | cron/launchd | Scheduled Job Creation |
| `macos:endpointSecurity` | ES_EVENT_TYPE_NOTIFY_EXEC | Process Creation |
| `macos:endpointsecurity` | ES_EVENT_MMAP | Process Modification |
| `macos:endpointsecurity` | ES_EVENT_TYPE_NOTIFY_CONNECT | Network Connection Creation |
| `macos:endpointsecurity` | ES_EVENT_TYPE_NOTIFY_CREATE: path under /Users/*/(Downloads\|Desktop\|Library/*/Containers\|Library/Group Containers) AND extension in SuspiciousExtensions | File Creation |
| `macos:endpointsecurity` | ES_EVENT_TYPE_NOTIFY_EXEC | Process Creation |
| `macos:endpointsecurity` | ES_EVENT_TYPE_NOTIFY_EXEC with unusual parent-child process relationships from zsh | Process Creation |
| `macos:endpointsecurity` | ES_EVENT_TYPE_NOTIFY_EXEC, ES_EVENT_TYPE_NOTIFY_MMAP | Process Metadata |
| `macos:endpointsecurity` | ES_EVENT_TYPE_NOTIFY_EXEC: Process execution of "sharing -l", "smbutil view", "mount_smbfs" | Process Creation |
| `macos:endpointsecurity` | ES_EVENT_TYPE_NOTIFY_EXEC: arguments contain long, non-standard tokens / custom alphabets | Process Creation |
| `macos:endpointsecurity` | ES_EVENT_TYPE_NOTIFY_KEXTLOAD | Module Load |
| `macos:endpointsecurity` | ES_EVENT_TYPE_NOTIFY_MMAP | Process Modification |
| `macos:endpointsecurity` | ES_EVENT_TYPE_NOTIFY_OPEN | Process Access |
| `macos:endpointsecurity` | ES_EVENT_TYPE_NOTIFY_OPEN: Open of .dylib/.so in user-writable locations | File Access |
| `macos:endpointsecurity` | ES_EVENT_TYPE_NOTIFY_WRITE, targeting .zshrc, .zlogin, .zprofile | File Modification |
| `macos:endpointsecurity` | es_event_authentication | File Metadata |
| `macos:endpointsecurity` | es_event_exec | Process Creation |
| `macos:endpointsecurity` | es_event_file_rename_t or es_event_file_write_t | File Metadata |
| `macos:endpointsecurity` | es_event_open | File Creation |
| `macos:endpointsecurity` | es_event_open, es_event_exec | File Access |
| `macos:endpointsecurity` | exec | Process Creation |
| `macos:endpointsecurity` | exec events | Process Creation |
| `macos:endpointsecurity` | exec: Exec of ffmpeg, avfoundation-based binaries, or custom signed apps accessing camera | Process Creation |
| `macos:endpointsecurity` | exec: Process execution context for loaders calling dlopen/dlsym | Process Creation |
| `macos:endpointsecurity` | exec: arguments contain Base64-like strings | Process Creation |
| `macos:endpointsecurity` | exec: binary == "/usr/sbin/systemsetup" and args contains "-gettimezone" | Process Creation |
| `macos:endpointsecurity` | open or read syscall to ~/.bash_history | File Access |
| `macos:endpointsecurity` | open: Process opens AppleCamera/IOUSB device nodes or AVFoundation frameworks | File Access |
| `macos:endpointsecurity` | write, rename | File Modification |
| `macos:fsevents` | /Library/StartupItems/, ~/Library/LaunchAgents/ | File Creation |
| `macos:jamf` | RemoteCommandExecution | Application Log Content |
| `macos:keychain` | Access to Keychain DB or system.keychain | File Access |
| `macos:keychain` | ~/Library/Keychains, /Library/Keychains | File Access |
| `macos:launchd` | launchd.plist and logs | Scheduled Job Metadata |
| `macos:osquery` | CALCULATE: Integrity validation of transmitted data via hash checks | OS API Execution |
| `macos:osquery` | CALCULATE: Mismatch in file integrity of critical macOS applications | File Modification |
| `macos:osquery` | CONNECT: Long-lived connections from remote-control parents to external IPs/domains | Network Connection Creation |
| `macos:osquery` | CREATE, DELETE, WRITE: Stored data manipulation attempts by unauthorized processes | File Deletion |
| `macos:osquery` | CREATE/MODIFY: Creation of LaunchAgents/Daemons plists in user/system locations | File Creation |
| `macos:osquery` | CREATE/MODIFY: Modification of app.asar inside .app bundle | File Creation |
| `macos:osquery` | Changes to LSFileQuarantineEnabled field in Info.plist | File Modification |
| `macos:osquery` | Execution of flooding tools or compiled packet generators | Process Creation |
| `macos:osquery` | Execution of non-standard binaries accessing Kerberos APIs | Process Creation |
| `macos:osquery` | File modifications in ~/Library/Preferences/ | File Modification |
| `macos:osquery` | Interpreter exec with suspicious arguments as above | Command Execution |
| `macos:osquery` | Invocation of osascript or dylib injection | Process Creation |
| `macos:osquery` | Memory Mappings | Process Modification |
| `macos:osquery` | Modifications to /var/db/SystemPolicyConfiguration/KextPolicy or kext_policy table | File Modification |
| `macos:osquery` | New kext entries not signed by Apple or outside standard identifier prefix | Kernel Module Load |
| `macos:osquery` | None | File Access, Network Connection Creation |
| `macos:osquery` | Process Context | Process Metadata |
| `macos:osquery` | Process Events and Launch Daemons | Service Creation |
| `macos:osquery` | Process Execution + Hash | Process Metadata |
| `macos:osquery` | Processes executing kextload, spctl, or modifying kernel extension directories | Process Creation |
| `macos:osquery` | Rapid spawning of resource-heavy applications (e.g., Preview, Safari, Office) | Process Creation |
| `macos:osquery` | Unexpected changes in EFI or NVRAM variables controlling hardware boot state | Firmware Modification |
| `macos:osquery` | Unsigned or ad-hoc signed process executions in user contexts | Process Creation |
| `macos:osquery` | code_signing, file_metadata | File Metadata |
| `macos:osquery` | curl, python scripts, rsync with internal share URLs | Process Creation |
| `macos:osquery` | detection of new launch agents with suspicious paths or unsigned binaries | Service Creation |
| `macos:osquery` | exec | Process Creation |
| `macos:osquery` | exec: Unexpected execution of osascript or AppleScript targeting sensitive apps | Script Execution |
| `macos:osquery` | execution of trusted tools interacting with external endpoints | Network Connection Creation |
| `macos:osquery` | execve | Process Creation |
| `macos:osquery` | execve: Processes unexpectedly invoking Keychain or authentication APIs | Process Creation |
| `macos:osquery` | execve: Unsigned or unnotarized processes launched with high privileges | Process Creation |
| `macos:osquery` | execve: command LIKE '%systemsetup -gettimezone%' OR '%date%' | Process Creation |
| `macos:osquery` | file_events | File Access, File Creation, File Deletion, File Metadata, File Modification |
| `macos:osquery` | file_events - cron, launchd | Scheduled Job Creation |
| `macos:osquery` | interface_details | Host Status |
| `macos:osquery` | launch_daemons | Service Creation |
| `macos:osquery` | launchd | Service Metadata |
| `macos:osquery` | launchd + process_events | Command Execution |
| `macos:osquery` | launchd or network_events | Network Connection Creation |
| `macos:osquery` | launchd or process_events | Process Creation |
| `macos:osquery` | launchd, processes | Process Creation |
| `macos:osquery` | launchd_jobs | Scheduled Job Creation |
| `macos:osquery` | mach_o_info, file_metadata | File Metadata |
| `macos:osquery` | open, execve: Unexpected processes accessing or modifying critical files | OS API Execution |
| `macos:osquery` | parent_name in ('sshd','httpd','screensharingd') spawning shells or scripting runtimes. | Process Creation |
| `macos:osquery` | process event monitoring with focus on discovery utilities and cryptographic framework usage correlation | Process Creation |
| `macos:osquery` | process execution monitoring for permission modification utilities with command-line argument analysis | Process Creation |
| `macos:osquery` | process reading browser configuration paths | Process Creation |
| `macos:osquery` | process_events | Process Creation |
| `macos:osquery` | process_events + launchd | Network Connection Creation |
| `macos:osquery` | process_events OR launchd | Process Creation |
| `macos:osquery` | process_events table | Process Creation |
| `macos:osquery` | process_events where path like '%tcpdump%' | Process Creation |
| `macos:osquery` | process_events, socket_events | Network Connection Creation |
| `macos:osquery` | process_events/socket_events | Network Connection Creation |
| `macos:osquery` | process_open | Process Access |
| `macos:osquery` | process_termination: Unexpected termination of processes tied to vulnerable or high-value services | Process Termination |
| `macos:osquery` | processes | Process Creation |
| `macos:osquery` | query: Enumeration of root certificates showing unexpected additions | File Modification |
| `macos:osquery` | query: Historical list of associated SSIDs compared against baseline | Network Traffic Flow |
| `macos:osquery` | query: process_events, launchd, and tcc.db access | Process Creation |
| `macos:osquery` | select: path LIKE '%/Library/%/*.dylib' OR '/tmp/*.dylib' | Module Load |
| `macos:osquery` | socket_events | Network Traffic Flow |
| `macos:osquery` | unexpected memory inspection | Process Access |
| `macos:osquery` | usb_devices | Drive Access |
| `macos:osquery` | write | File Modification |
| `macos:syslog` | /var/log/system.log | Command Execution |
| `macos:syslog` | DYLD_INSERT_LIBRARIES anomalies | Module Load |
| `macos:syslog` | Hardware UUID or device list drift | Host Status |
| `macos:syslog` | system.log | Command Execution |
| `macos:syslog` | system.log, asl.log | Script Execution |
| `macos:unifiedlog` | *.opvault OR *.ldb OR *.kdbx | File Access |
| `macos:unifiedlog` | AMFI or Gatekeeper signature/notarization failures for newly installed dev components | File Metadata |
| `macos:unifiedlog` | AMFI/Gatekeeper code signature or notarization failures | File Metadata |
| `macos:unifiedlog` | ARP table updates inconsistent with expected gateway or DHCP lease assignments | Network Traffic Flow |
| `macos:unifiedlog` | Abnormal memory operations (XOR/bitwise loops) during archive generation | Process Modification |
| `macos:unifiedlog` | Abnormal process access to Safari or Chrome cookie storage | File Access |
| `macos:unifiedlog` | Abnormal terminations of com.apple.security.* or 3rd-party security daemons | Application Log Content |
| `macos:unifiedlog` | Access decisions to kTCCServiceCamera for unexpected binaries | OS API Execution |
| `macos:unifiedlog` | Access to Keychain items or browser credential stores | Logon Session Creation |
| `macos:unifiedlog` | Access to ~/Library/*/Safari or Chrome directories by non-browser processes | File Access |
| `macos:unifiedlog` | Access to ~/Library/Safari/Bookmarks.plist or recent files | File Access |
| `macos:unifiedlog` | Anomalous dyld dynamic library loads or RWX memory mappings in browser process | Process Modification |
| `macos:unifiedlog` | Anomalous keychain access attempts targeting payment credentials | Application Log Content |
| `macos:unifiedlog` | Anomalous plist modifications or sensitive file overwrites by non-standard processes | File Modification |
| `macos:unifiedlog` | App/web server logs ingested via unified logging or filebeat (nginx/apache/node). | Application Log Content |
| `macos:unifiedlog` | AppleScript creating login item via 'System Events' dictionary | Script Execution |
| `macos:unifiedlog` | Application errors or resource contention from excessive frontend or script invocation | Application Log Content |
| `macos:unifiedlog` | Association and authentication events including failures and new SSIDs | Network Connection Creation |
| `macos:unifiedlog` | Attachment files written to ~/Downloads or temporary folders | File Creation |
| `macos:unifiedlog` | Authentication inconsistencies where commands are executed without corresponding login events | Logon Session Creation |
| `macos:unifiedlog` | Browser processes launching unexpected interpreters (osascript, bash) | Process Creation |
| `macos:unifiedlog` | Calls to AuthorizationExecuteWithPrivileges() observed via Apple System Logger or security_auditing tools | OS API Execution |
| `macos:unifiedlog` | Child processes of Safari, Chrome, or Firefox executing scripting interpreters | Process Creation |
| `macos:unifiedlog` | Code Execution & Entitlement Access | Process Metadata |
| `macos:unifiedlog` | Code signature validation fails or is absent post-binary modification | File Metadata |
| `macos:unifiedlog` | Code signing verification failures or bypassed trust decisions | File Metadata |
| `macos:unifiedlog` | Command line containing `trap` or `echo 'trap` written to login shell files | Process Creation |
| `macos:unifiedlog` | Command line contains smbutil view //, mount_smbfs // | Command Execution |
| `macos:unifiedlog` | Command line invocation of pip3, brew install, npm install from interactive Terminal | Process Creation |
| `macos:unifiedlog` | Configuration profile modified or new profile installed | Application Log Content |
| `macos:unifiedlog` | Connections to suspicious domains with mismatched certificate or unusual patterns | Network Traffic Content |
| `macos:unifiedlog` | Crash log entries for a process receiving malformed input or known exploit patterns | Application Log Content |
| `macos:unifiedlog` | Creation of .plist under /Library/Managed Preferences/ | File Creation |
| `macos:unifiedlog` | Creation of .zip or .dmg files in user-accessible or temporary directories | File Creation |
| `macos:unifiedlog` | Creation of .zip, .dmg, .tar.gz files in /Users, /tmp, or application directories | File Creation |
| `macos:unifiedlog` | Creation of .zip, .gz, .dmg archives in /Users, /tmp, or application directories | File Creation |
| `macos:unifiedlog` | Creation of LaunchAgents/LaunchDaemons in hidden or non-standard directories | File Creation |
| `macos:unifiedlog` | Creation of files with anomalous headers and entropy values | File Creation |
| `macos:unifiedlog` | Creation of new LaunchAgent or LoginItem plist files in ~/Library/LaunchAgents/ | File Metadata |
| `macos:unifiedlog` | Creation of user account with UID <500 | User Account Metadata |
| `macos:unifiedlog` | Creation or modification of browser extension .plist files | File Creation |
| `macos:unifiedlog` | Creation or modification of postinstall scripts within .pkg or .mpkg contents | File Creation |
| `macos:unifiedlog` | DNS query with pseudo-random subdomain patterns | Network Traffic Content |
| `macos:unifiedlog` | DNS responses followed by connections to ports outside standard ranges | Network Traffic Content |
| `macos:unifiedlog` | DS daemon log entries | Command Execution |
| `macos:unifiedlog` | DYLD event subsystem | Module Load |
| `macos:unifiedlog` | Detection of altered _VBA_PROJECT or PerformanceCache streams | File Metadata |
| `macos:unifiedlog` | Device attached\|enumerated VID/PID | Application Log Content |
| `macos:unifiedlog` | Dylib loaded from abnormal location | Module Load |
| `macos:unifiedlog` | EFI firmware integrity check failed | Host Status |
| `macos:unifiedlog` | Electron app spawning unexpected child process | Process Creation |
| `macos:unifiedlog` | Encrypted connection with anomalous payload entropy | Network Traffic Content |
| `macos:unifiedlog` | Encrypted session initiation by unexpected binary | Network Traffic Content |
| `macos:unifiedlog` | Exec of tcpdump, rvictl, custom tools linked to libpcap.A.dylib; sysextd/systemextensionsctl events for NetworkExtension content filters. | Process Creation |
| `macos:unifiedlog` | Execution of 'profiles install -type=configuration' | Command Execution |
| `macos:unifiedlog` | Execution of /usr/bin/security add-trusted-cert or keychain modifications to System.keychain | Command Execution |
| `macos:unifiedlog` | Execution of /usr/libexec/security_authtrampoline or child processes originating from non-trusted binaries triggering credential prompts | Process Creation |
| `macos:unifiedlog` | Execution of /usr/sbin/installer spawning child process from within /private/tmp or package contents | Process Creation |
| `macos:unifiedlog` | Execution of Code.app, idea, JetBrainsToolbox, eclipse with install/extension flags | Process Creation |
| `macos:unifiedlog` | Execution of Java apps or other processes with hidden window attributes | Process Creation |
| `macos:unifiedlog` | Execution of Python, Swift, or other binaries invoking archiving libraries | Process Creation |
| `macos:unifiedlog` | Execution of Terminal, osascript, or other interpreters originating from Mail or Preview | Process Creation |
| `macos:unifiedlog` | Execution of binaries with TCC protected access under unexpected parent processes such as Finder.app, SystemUIServer, or nsurlsessiond | Process Creation |
| `macos:unifiedlog` | Execution of binaries with unsigned or anomalously signed certificates | Process Creation |
| `macos:unifiedlog` | Execution of binary listed in newly modified LaunchAgent plist | Process Creation |
| `macos:unifiedlog` | Execution of bless or nvram modifying boot parameters | Process Creation |
| `macos:unifiedlog` | Execution of chflags hidden or SetFile -a V | Command Execution |
| `macos:unifiedlog` | Execution of chflags hidden or setfile -a V | Command Execution |
| `macos:unifiedlog` | Execution of commands like `ls -l@`, `xattr -l`, or custom tools interacting with resource forks | Command Execution |
| `macos:unifiedlog` | Execution of diskutil or hdiutil attaching hidden partitions | Process Creation |
| `macos:unifiedlog` | Execution of dscl . create with IsHidden=1 | Command Execution |
| `macos:unifiedlog` | Execution of input detection APIs (e.g., CGEventSourceKeyState) | OS API Execution |
| `macos:unifiedlog` | Execution of launchctl unload, kill, or removal of security agent daemons | Process Creation |
| `macos:unifiedlog` | Execution of launchctl with setenv or bootout targeting TCC.db or AppleScript under Finder context | Command Execution |
| `macos:unifiedlog` | Execution of launchctl with suspicious arguments | Process Creation |
| `macos:unifiedlog` | Execution of log show, fs_usage, or cat targeting system.log | Command Execution |
| `macos:unifiedlog` | Execution of older or non-standard interpreters | Process Creation |
| `macos:unifiedlog` | Execution of osascript, bash, or Terminal initiated from Mail.app or Safari | Process Creation |
| `macos:unifiedlog` | Execution of ping, nping, or crafted network packets via bash or python to reflection services | Process Creation |
| `macos:unifiedlog` | Execution of process launched via loginwindow session restore | Process Creation |
| `macos:unifiedlog` | Execution of process with DYLD_INSERT_LIBRARIES set | Process Creation |
| `macos:unifiedlog` | Execution of processes linked to hijacked sessions (e.g., anomalous parent-child process lineage) | Process Creation |
| `macos:unifiedlog` | Execution of processes mimicking Apple Security & Privacy GUIs | Process Creation |
| `macos:unifiedlog` | Execution of scp, rsync, curl with remote destination | Process Creation |
| `macos:unifiedlog` | Execution of ssh or sftp without corresponding login event | Process Creation |
| `macos:unifiedlog` | Execution of system_profiler or osascript invoking enumeration | Process Creation |
| `macos:unifiedlog` | Execution of unexpected terminal or web scripts modifying /Library/WebServer/Documents | Process Creation |
| `macos:unifiedlog` | Execution of zip, ditto, hdiutil, or openssl by non-terminal parent processes | Process Creation |
| `macos:unifiedlog` | Execution of zip, ditto, hdiutil, or openssl by processes not normally associated with archiving | Process Creation |
| `macos:unifiedlog` | File Events | File Creation |
| `macos:unifiedlog` | File created in ~/Library/LaunchAgents or executable directories | File Creation |
| `macos:unifiedlog` | File creation | File Creation |
| `macos:unifiedlog` | File creation of unsigned binaries/scripts in user cache or download directories | File Creation |
| `macos:unifiedlog` | File creation or modification with com.apple.ResourceFork extended attribute | File Metadata |
| `macos:unifiedlog` | File creation or overwrite in common web-hosting folders | File Modification |
| `macos:unifiedlog` | File metadata updated with UF_HIDDEN flag | File Metadata |
| `macos:unifiedlog` | File modification in /etc/paths.d or user shell rc files | File Modification |
| `macos:unifiedlog` | File write or append to .zshrc, .bash_profile, .zprofile, etc. | File Modification |
| `macos:unifiedlog` | Firewall rule enable/disable or listen socket changes | Network Traffic Flow |
| `macos:unifiedlog` | Firewall/PF anchor load or rule change events. | Network Traffic Flow |
| `macos:unifiedlog` | Firmware update events or kernel extension (kext) loads not signed by Apple | Firmware Modification |
| `macos:unifiedlog` | First outbound connection from the same PID/user shortly after an inbound trigger. | Network Connection Creation |
| `macos:unifiedlog` | Gatekeeper quarantine policy decision anomalies recorded in com.apple.LaunchServices.QuarantineEventsV2 | File Metadata |
| `macos:unifiedlog` | Gatekeeper/AMFI 'code signature invalid' / 'not notarized' messages | File Metadata |
| `macos:unifiedlog` | Group membership change for admin or wheel | Logon Session Metadata |
| `macos:unifiedlog` | HTTP POST with encoded content in user-agent or cookie field | Network Traffic Content |
| `macos:unifiedlog` | HTTPS POST requests to pastebin.com or similar | Network Traffic Flow |
| `macos:unifiedlog` | HTTPS POST to known webhook URLs | Network Traffic Flow |
| `macos:unifiedlog` | Hardware enumeration events via IOKit or USBMuxd showing TinyPilot or unknown keyboard/mouse | Drive Creation |
| `macos:unifiedlog` | Hidden volume attachment or modification events | File Modification |
| `macos:unifiedlog` | High entropy domain queries with multiple NXDOMAINs | Network Traffic Flow |
| `macos:unifiedlog` | IOKit disk write calls targeting raw devices | Drive Modification |
| `macos:unifiedlog` | IOKit raw disk write activity targeting physical devices | Drive Modification |
| `macos:unifiedlog` | IOKit raw disk write to EFI/boot partition sectors | Drive Modification |
| `macos:unifiedlog` | Inbound connections to VNC/SSH ports | Network Connection Creation |
| `macos:unifiedlog` | Inbound email activity with suspicious domains or mismatched sender information | Application Log Content |
| `macos:unifiedlog` | Inbound messages with attachments from suspicious domains | Application Log Content |
| `macos:unifiedlog` | Invocation of SMLoginItemSetEnabled by non-system or recently installed application | OS API Execution |
| `macos:unifiedlog` | Kerberos framework calls to API:{uuid} cache outside normal process lineage | File Access |
| `macos:unifiedlog` | Keychain or user login post-access | Logon Session Creation |
| `macos:unifiedlog` | Loading of libz.dylib, libarchive.dylib by non-standard applications | Module Load |
| `macos:unifiedlog` | Login Window and Authd errors | User Account Authentication |
| `macos:unifiedlog` | Login failure / authorization denied | User Account Authentication |
| `macos:unifiedlog` | Login success without MFA step | User Account Authentication |
| `macos:unifiedlog` | LoginWindow context with associated PID linked to reopened plist paths | Logon Session Metadata |
| `macos:unifiedlog` | Logs from unifiedlogging that show browser crashes, plugin enumerations, extension installs or errors around the same time as suspicious network fetches | Application Log Content |
| `macos:unifiedlog` | Mach-O binary modified or LC_LOAD_DYLIB segment inserted | File Modification |
| `macos:unifiedlog` | Mail or AppleScript subsystem | Application Log Content |
| `macos:unifiedlog` | Mail.app executing with parameters updating rules state | Process Creation |
| `macos:unifiedlog` | Mail.app or third-party clients sending messages with mismatched From headers | Application Log Content |
| `macos:unifiedlog` | Modification of /Library/Preferences/com.apple.loginwindow plist | File Modification |
| `macos:unifiedlog` | Modification of /Library/Security/SecurityAgentPlugins | File Modification |
| `macos:unifiedlog` | Modification of /System/Library/CoreServices/boot.efi | File Modification |
| `macos:unifiedlog` | Modification of LaunchAgents or LaunchDaemons plist files | File Modification |
| `macos:unifiedlog` | Modification of backgrounditems.btm or creation of LoginItems subdirectory in .app bundle | File Modification |
| `macos:unifiedlog` | Modification of plist with apple.awt.UIElement set to TRUE | File Modification |
| `macos:unifiedlog` | Modification of system configuration profiles affecting security tools | Service Metadata |
| `macos:unifiedlog` | Modification of ~/Library/LaunchAgents or /Library/LaunchDaemons plist | File Modification |
| `macos:unifiedlog` | Modification or replacement of /Library/Application Support/com.apple.TCC/TCC.db or ~/Library/Application Support/com.apple.TCC/TCC.db | File Modification |
| `macos:unifiedlog` | Modifications or writes to EFI system partition for downgraded bootloaders | Process Metadata |
| `macos:unifiedlog` | Modifications to Mail.app plist files controlling message rules | File Modification |
| `macos:unifiedlog` | Modified application plist or binary replacement in /Applications | File Modification |
| `macos:unifiedlog` | New IOUSB keyboard/HID device enumerated with suspicious attributes | Drive Creation |
| `macos:unifiedlog` | New certificate trust settings added by unexpected process | File Metadata |
| `macos:unifiedlog` | New files written to /var/folders, /tmp, ~/Library/Caches, or ~/Downloads by browser context or its children | File Creation |
| `macos:unifiedlog` | New session initiated using cookies without normal MFA or password validation | Web Credential Usage |
| `macos:unifiedlog` | New/modified launchd plist (persistence/scheduling) within TimeWindow after time query | Scheduled Job Metadata |
| `macos:unifiedlog` | Non-standard processes invoking financial applications or payment APIs | Process Creation |
| `macos:unifiedlog` | None | Command Execution, Network Connection Creation, Network Traffic Content, OS API Execution, Process Creation |
| `macos:unifiedlog` | Observed loading of new LaunchAgent or LaunchDaemon plist | Service Metadata |
| `macos:unifiedlog` | Outbound Traffic | Network Connection Creation |
| `macos:unifiedlog` | Outbound UDP spikes to external reflector IPs | Network Traffic Flow |
| `macos:unifiedlog` | Outbound connections from IDE processes to marketplace/tunnel domains | Network Traffic Flow |
| `macos:unifiedlog` | Outgoing or incoming calls with non-standard caller IDs or unusual metadata | Application Log Content |
| `macos:unifiedlog` | Persistent outbound connections with consistent periodicity | Network Traffic Content |
| `macos:unifiedlog` | Persistent outbound traffic to mining domains | Network Traffic Content |
| `macos:unifiedlog` | Plist modifications containing virtualization run configurations | File Modification |
| `macos:unifiedlog` | Post-login execution of unrecognized child process from launchd or loginwindow | Process Creation |
| `macos:unifiedlog` | Preview.app, Safari.app, or Mail.app spawning new processes outside normal patterns | Process Creation |
| `macos:unifiedlog` | Process Execution | Process Creation |
| `macos:unifiedlog` | Process creation events where command line = pmset with arguments affecting sleep, hibernatemode, displaysleep | Process Creation |
| `macos:unifiedlog` | Process creation involving binaries interacting with resource fork data | Process Creation |
| `macos:unifiedlog` | Process creation with parent PID of 1 (launchd) | Process Creation |
| `macos:unifiedlog` | Process exec of remote-control apps or binaries with headless/connect flags | Process Creation |
| `macos:unifiedlog` | Process execution for VBoxHeadless, prl_vm_app, vmware-vmx | Process Creation |
| `macos:unifiedlog` | Process execution logs showing discovery commands like mdfind, system_profiler, or launchctl list | Process Creation |
| `macos:unifiedlog` | Process execution of Microsoft Word, Excel, PowerPoint with macro execution attempts | Process Creation |
| `macos:unifiedlog` | Process execution or directory service changes | User Account Modification |
| `macos:unifiedlog` | Process execution path inconsistent with baseline PATH directories | Process Creation |
| `macos:unifiedlog` | Process invoking SSL routines from Security framework | Process Creation |
| `macos:unifiedlog` | Process invoking SecKeyCreateRandomKey or asymmetric crypto APIs | Process Creation |
| `macos:unifiedlog` | Process launch | Process Creation |
| `macos:unifiedlog` | Process memory maps new dylib (dylib_load event) | Module Load |
| `macos:unifiedlog` | Process opening SSH_AUTH_SOCK or /tmp/ssh-* socket not owned by same UID | Process Metadata |
| `macos:unifiedlog` | Process start of Java or native DB client tools | Process Creation |
| `macos:unifiedlog` | Process using AES/RC4 routines unexpectedly | Process Creation |
| `macos:unifiedlog` | Process wrote large .mov/.mp4 in user temp/hidden dirs | File Creation |
| `macos:unifiedlog` | Rapid domain-to-IP resolution changes for same domain | Network Traffic Flow |
| `macos:unifiedlog` | Rapid incoming TLS handshakes or HTTP requests in quick succession | Network Traffic Content |
| `macos:unifiedlog` | Read access to Time Machine plist files or CCC configurations in ~/Library/Preferences/ | File Access |
| `macos:unifiedlog` | Received messages containing embedded links or attachments from non-enterprise services | Application Log Content |
| `macos:unifiedlog` | Received messages with embedded or shortened URLs | Application Log Content |
| `macos:unifiedlog` | Remote login (ssh) or screen sharing authentication attempts | Logon Session Metadata |
| `macos:unifiedlog` | Repeated process crashes logged by CrashReporter or system instability logs in com.apple.console | Application Log Content |
| `macos:unifiedlog` | Repetitive inbound email delivery activity logged within a short time window | Application Log Content |
| `macos:unifiedlog` | SPF fail OR DKIM fail OR DMARC fail OR mismatched header vs envelope domains | Application Log Content |
| `macos:unifiedlog` | Script interpreter invoked by nginx/apache worker process | Process Creation |
| `macos:unifiedlog` | Security framework operations including keychain access, cryptographic operations, and certificate validation | Command Execution |
| `macos:unifiedlog` | SecurityAgentPlugins modification | File Modification |
| `macos:unifiedlog` | Session reuse without new auth event | Logon Session Creation |
| `macos:unifiedlog` | Set or unset HIST* variables in shell environment | Command Execution |
| `macos:unifiedlog` | Spike in CPU or memory use from non-user-initiated processes | Host Status |
| `macos:unifiedlog` | Suspicious Swift/Objective-C or scripting processes writing archive-like outputs | Process Creation |
| `macos:unifiedlog` | Suspicious anomalies in transmitted data integrity during application network operations | Network Traffic Flow |
| `macos:unifiedlog` | Suspicious outbound HTTPS requests to domains flagged as newly registered or untrusted after spearphishing message interaction | Network Traffic Content |
| `macos:unifiedlog` | Suspicious outbound traffic from browser binary to non-standard domains | Network Traffic Flow |
| `macos:unifiedlog` | Suspicious plist edits for volume mounting behavior | File Modification |
| `macos:unifiedlog` | System Integrity Protection (SIP) state reported as disabled | Host Status |
| `macos:unifiedlog` | System process modifications altering DNS/proxy settings | Process Creation |
| `macos:unifiedlog` | System shutdown or reboot requested | Host Status |
| `macos:unifiedlog` | TLS connections with abnormal handshake sequence or self-signed cert | Network Traffic Content |
| `macos:unifiedlog` | Terminal process killed (killall Terminal) immediately after sudoers modification | Process Termination |
| `macos:unifiedlog` | Terminal/Editor processes modifying web folder | File Modification |
| `macos:unifiedlog` | Termination of syspolicyd or XProtect processes | Process Termination |
| `macos:unifiedlog` | Termination or disabling of XProtect, Gatekeeper, or third-party AV daemons | Host Status |
| `macos:unifiedlog` | Trust validation failures or bypass attempts during notarization and code signing checks | Process Creation |
| `macos:unifiedlog` | Unexpected NSXPCConnection calls by non-Apple-signed or abnormal binaries | Process Access |
| `macos:unifiedlog` | Unexpected application binary modifications or altered signing status | File Metadata |
| `macos:unifiedlog` | Unexpected applications generating outbound DNS queries | Process Creation |
| `macos:unifiedlog` | Unexpected apps generating frequent DNS queries | Process Creation |
| `macos:unifiedlog` | Unexpected apps performing repeated DNS lookups | Process Creation |
| `macos:unifiedlog` | Unexpected child process of Safari or Chrome | Process Creation |
| `macos:unifiedlog` | Unexpected creation or modification of stored data files in protected directories | File Modification |
| `macos:unifiedlog` | Unexpected processes making network calls based on DNS-derived ports | Process Creation |
| `macos:unifiedlog` | Unexpected processes registered with launchd | Process Creation |
| `macos:unifiedlog` | Unsigned binary execution following SIP change | Process Creation |
| `macos:unifiedlog` | Unusual Kerberos TGS-REQ without TGT or anomalous ticket lifetime | Logon Session Metadata |
| `macos:unifiedlog` | Unusual Mach port registration or access attempts between unrelated processes | Process Access |
| `macos:unifiedlog` | Unusual child process tree indicating attempted recovery after crash | Process Creation |
| `macos:unifiedlog` | User credential prompt events without associated trusted installer package | User Account Authentication |
| `macos:unifiedlog` | UserLoggedIn | Logon Session Creation |
| `macos:unifiedlog` | Volume Mount + File Read | Drive Creation |
| `macos:unifiedlog` | Volume Mount + Process Trace + File Read | Drive Creation |
| `macos:unifiedlog` | Web server process initiating outbound TCP connections not tied to normal server traffic | Network Traffic Content |
| `macos:unifiedlog` | Web service process (e.g., httpd) entering crash loop or consuming excessive CPU | Host Status |
| `macos:unifiedlog` | Web sessions initiated with newly forged tokens | Web Credential Usage |
| `macos:unifiedlog` | Writes of .sql/.csv/.xlsx files to user documents/downloads | File Creation |
| `macos:unifiedlog` | Writes under ~/Library/Application Support/Code*/extensions or JetBrains plugins | File Creation |
| `macos:unifiedlog` | XPC messages requesting privileged actions from untrusted or unsigned clients | Named Pipe Metadata |
| `macos:unifiedlog` | access or unlock attempt to keychain database | OS API Execution |
| `macos:unifiedlog` | access to /Volumes/SharePoint or network mount | File Access |
| `macos:unifiedlog` | access to keychain database | File Access |
| `macos:unifiedlog` | application logs referencing NSTimer, sleep, or launchd delays | OS API Execution |
| `macos:unifiedlog` | audio APIs | OS API Execution |
| `macos:unifiedlog` | auth | User Account Authentication |
| `macos:unifiedlog` | authd | User Account Authentication |
| `macos:unifiedlog` | authd generating multiple MFA token requests | Logon Session Metadata |
| `macos:unifiedlog` | authentication | Logon Session Creation |
| `macos:unifiedlog` | authentication plugin load or modification events | Logon Session Creation |
| `macos:unifiedlog` | authorization execute privilege requests | OS API Execution |
| `macos:unifiedlog` | background process persists beyond user logout | Process Creation |
| `macos:unifiedlog` | base64 -d or osascript invoked on staged file | Command Execution |
| `macos:unifiedlog` | base64 or curl processes chained within short execution window | Command Execution |
| `macos:unifiedlog` | binary modified or replaced | File Modification |
| `macos:unifiedlog` | boot failure events or SMC validation errors | Firmware Modification |
| `macos:unifiedlog` | chmod command with arguments including '+s', 'u+s', or numeric values 4000–6777 | Command Execution |
| `macos:unifiedlog` | code signature/memory protection | Process Metadata |
| `macos:unifiedlog` | com.apple.accountsd, com.apple.opendirectoryd | User Account Modification |
| `macos:unifiedlog` | com.apple.diskarbitration | Drive Creation |
| `macos:unifiedlog` | com.apple.firmwareupdater activity or update-firmware binary invoked | Process Creation |
| `macos:unifiedlog` | com.apple.mail.* exec.* | Process Creation |
| `macos:unifiedlog` | com.apple.network | Network Traffic Flow |
| `macos:unifiedlog` | com.apple.securityd, com.apple.tccd | OS API Execution |
| `macos:unifiedlog` | command execution triggered by emond (e.g., shell, curl, python) | Command Execution |
| `macos:unifiedlog` | command includes dscl . delete or sysadminctl --deleteUser | Command Execution |
| `macos:unifiedlog` | command line or log output shows non-standard encoding routines | Process Creation |
| `macos:unifiedlog` | connection attempts | Network Connection Creation |
| `macos:unifiedlog` | connection open | Network Connection Creation |
| `macos:unifiedlog` | create/modify dylib files in monitored directories | File Creation |
| `macos:unifiedlog` | create/modify dylib in monitored directories | File Modification |
| `macos:unifiedlog` | create: New files in /tmp or ~/Library/Application Support/* with executable or script extensions | File Creation |
| `macos:unifiedlog` | creation of ~/.vscode-cli/code_tunnel.json | File Creation |
| `macos:unifiedlog` | creation or loading of new launchd services | Service Creation |
| `macos:unifiedlog` | csrutil disable | Command Execution |
| `macos:unifiedlog` | curl\|osascript.*open location | Network Traffic Content |
| `macos:unifiedlog` | defaults read -g AppleLocale or systemsetup -gettimezone | Command Execution |
| `macos:unifiedlog` | defaults read -g AppleLocale, systemsetup -gettimezone | Command Execution |
| `macos:unifiedlog` | defaults write com.apple.system.logging or logd manipulation | Command Execution |
| `macos:unifiedlog` | delay/sleep library usage in user context | Module Load |
| `macos:unifiedlog` | diskutil eraseDisk / asr restore with destructive flags | Command Execution |
| `macos:unifiedlog` | diskutil eraseDisk/zeroDisk or asr restore with destructive flags | Command Execution |
| `macos:unifiedlog` | diskutil partitionDisk or eraseVolume with partition scheme modifications | Command Execution |
| `macos:unifiedlog` | dns-sd, mDNSResponder, socket activity | Network Traffic Content |
| `macos:unifiedlog` | dscl -create | Command Execution |
| `macos:unifiedlog` | dscl . -create | Command Execution |
| `macos:unifiedlog` | dsconfigad or dscl with create or append options for AD-bound users | Command Execution |
| `macos:unifiedlog` | dyld/unified log entries indicating image load from non-system paths | Module Load |
| `macos:unifiedlog` | dynamic loading of sleep-related functions or sandbox detection libraries | Module Load |
| `macos:unifiedlog` | encrypted outbound traffic carrying unexpected application data | Network Traffic Content |
| `macos:unifiedlog` | eventMessage = 'open', 'sendto', 'connect' | Network Traffic Content |
| `macos:unifiedlog` | eventMessage = 'promiscuous' | Network Traffic Content |
| `macos:unifiedlog` | eventMessage CONTAINS 'screensharingd' or 'AuthorizationRefCreate' | Logon Session Creation |
| `macos:unifiedlog` | exec /usr/bin/pwpolicy | Process Creation |
| `macos:unifiedlog` | exec events where web process starts a shell/tooling | Process Creation |
| `macos:unifiedlog` | exec logs | Process Creation |
| `macos:unifiedlog` | exec of binary with setuid/setgid and EUID != UID | Process Metadata |
| `macos:unifiedlog` | exec of osascript, bash, curl with suspicious parameters | Process Creation |
| `macos:unifiedlog` | exec or spawn calls to proxy tools or torrent clients | Process Creation |
| `macos:unifiedlog` | exec or spawn of 'system_profiler', 'ioreg', 'kextstat', 'sysctl', or calls to sysctl API | Process Creation |
| `macos:unifiedlog` | exec or sudo usage with NOPASSWD context or echo modifying sudoers | Command Execution |
| `macos:unifiedlog` | exec rm -rf\|dd if=/dev\|srm\|file unlink | File Deletion |
| `macos:unifiedlog` | exec srm\|exec openssl\|exec gpg | Process Creation |
| `macos:unifiedlog` | exec: Execution of /sbin/pfctl, /usr/libexec/ApplicationFirewall/socketfilterfw, ifconfig, tcpdump, npcap/libpcap consumers | Process Creation |
| `macos:unifiedlog` | exec: Execution of defaults, plutil, or common editors (vim/nano) targeting plist files | Process Creation |
| `macos:unifiedlog` | exec: Execution of kextstat, kextfind, or ioreg targeting driver information | Process Creation |
| `macos:unifiedlog` | exec: Execution of pfctl, socketfilterfw, launchctl start ssh/telnet, libpcap consumers. | Process Creation |
| `macos:unifiedlog` | exec: Invocation of /usr/bin/defaults write or /usr/bin/plutil modifying plist keys | Command Execution |
| `macos:unifiedlog` | exec: ParentImage in (Terminal, iTerm2) AND Image in (/bin/zsh,/bin/bash,/usr/bin/python*) AND CommandLine matches '(curl\|wget).*(\\|\|\\|\s*sh\|bash)\|base64 -D\|python -c' | Process Creation |
| `macos:unifiedlog` | execution of 'security', 'cat', or 'grep' commands accessing credential storage | Command Execution |
| `macos:unifiedlog` | execution of /sbin/emond with child processes launched | Process Creation |
| `macos:unifiedlog` | execution of Office binaries with network activity | Process Creation |
| `macos:unifiedlog` | execution of curl, git, or Office processes with network connections | Process Creation |
| `macos:unifiedlog` | execution of curl, osascript, or unexpected Office processes | Process Creation |
| `macos:unifiedlog` | execution of curl, rclone, or Office apps invoking network sessions | Process Creation |
| `macos:unifiedlog` | execution of launchctl load/unload/start commands | Command Execution |
| `macos:unifiedlog` | execution of memory inspection tools (lldb, gdb, osqueryi) | Process Creation |
| `macos:unifiedlog` | execution of modified binary without valid signature | Process Creation |
| `macos:unifiedlog` | execution of osascript, curl, or unexpected automation | Process Creation |
| `macos:unifiedlog` | execution of process with DYLD_INSERT_LIBRARIES set | Process Creation |
| `macos:unifiedlog` | execution of security or osascript | Process Creation |
| `macos:unifiedlog` | execution of security, sqlite3, or unauthorized binaries | Process Creation |
| `macos:unifiedlog` | execution of security-agent detection or enumeration commands | Command Execution |
| `macos:unifiedlog` | execution of system_profiler, ioreg, kextstat with argument patterns related to VM/sandbox checks | Process Creation |
| `macos:unifiedlog` | execve or dylib load from memory without backing file | Process Creation |
| `macos:unifiedlog` | execve: Helper tools invoked through XPC executing unexpected binaries | Process Creation |
| `macos:unifiedlog` | extended attribute write or modification | File Metadata |
| `macos:unifiedlog` | file create or modify in /etc/emond.d/rules or /private/var/db/emondClients | File Creation |
| `macos:unifiedlog` | file creation in AV exclusion directories | File Creation |
| `macos:unifiedlog` | file encrypted\|new file with .encrypted extension\|disk write burst | File Modification |
| `macos:unifiedlog` | file events | File Access, File Creation |
| `macos:unifiedlog` | file read of sensitive directories | File Access |
| `macos:unifiedlog` | file write | File Creation |
| `macos:unifiedlog` | file write/create | File Creation |
| `macos:unifiedlog` | file writes | File Modification |
| `macos:unifiedlog` | filesystem and process events | File Access |
| `macos:unifiedlog` | filesystem events | File Metadata |
| `macos:unifiedlog` | flock\|NSDistributedLock\|FileHandle.*lockForWriting | OS API Execution |
| `macos:unifiedlog` | forwarded encrypted traffic | Network Traffic Flow |
| `macos:unifiedlog` | g_CiOptions modification or SIP state change | Windows Registry Key Modification |
| `macos:unifiedlog` | grep/cat on files matching credential patterns | Command Execution |
| `macos:unifiedlog` | httpd spawning bash, zsh, python, or osascript | Process Creation |
| `macos:unifiedlog` | installer or system_installd 'PackageKit: install succeeded/failed' with non-notarized or unknown signer | File Metadata |
| `macos:unifiedlog` | kernel extension and system extension logs related to file system security violations or SIP bypass attempts | File Metadata |
| `macos:unifiedlog` | kextload execution from Terminal or suspicious paths | Command Execution |
| `macos:unifiedlog` | launch and dylib load | Module Load |
| `macos:unifiedlog` | launch of Terminal.app or shell with non-standard environment setup | Process Creation |
| `macos:unifiedlog` | launch of bash/zsh/python/osascript targeting key file locations | Process Creation |
| `macos:unifiedlog` | launch of remote desktop app or helper binary | Process Creation |
| `macos:unifiedlog` | launchctl activity and process creation | Process Creation |
| `macos:unifiedlog` | launchctl disable or bootout calls | Service Metadata |
| `macos:unifiedlog` | launchctl load or boot-time plist registration | Command Execution |
| `macos:unifiedlog` | launchctl load/unload or plist file modification | Command Execution |
| `macos:unifiedlog` | launchctl spawning new processes | Process Creation |
| `macos:unifiedlog` | launchctl unload, kill, or pkill commands affecting daemons or background services | Command Execution |
| `macos:unifiedlog` | launchd loading new LaunchDaemon or changes to existing daemon configuration | Service Creation |
| `macos:unifiedlog` | launchd or cron spawning mining binaries | Process Creation |
| `macos:unifiedlog` | launchd or osascript spawns process with delay command | Process Creation |
| `macos:unifiedlog` | launchd services binding to non-standard ports | Process Creation |
| `macos:unifiedlog` | launchd spawning processes tied to new or modified LaunchDaemon .plist entries | Process Creation |
| `macos:unifiedlog` | launchservices events for misleading extensions | Process Creation |
| `macos:unifiedlog` | launchservices or loginwindow events | Process Creation |
| `macos:unifiedlog` | loading of unexpected dylibs compared to historical baselines | Module Load |
| `macos:unifiedlog` | log | Script Execution |
| `macos:unifiedlog` | log collect --predicate | Process Creation |
| `macos:unifiedlog` | log collect from launchd and process start | Process Metadata |
| `macos:unifiedlog` | log messages related to disk enumeration context or Terminal session | Command Execution |
| `macos:unifiedlog` | log show --predicate 'eventMessage contains "Authentication"' | User Account Authentication |
| `macos:unifiedlog` | log show --predicate 'process == <utility>' | Command Execution |
| `macos:unifiedlog` | log stream | Command Execution |
| `macos:unifiedlog` | log stream 'eventMessage contains "dns_request"' | Network Traffic Flow |
| `macos:unifiedlog` | log stream 'eventMessage contains pubsub or broker' | Process Creation |
| `macos:unifiedlog` | log stream (subsystem: com.apple.system.networking) | Network Traffic Content |
| `macos:unifiedlog` | log stream - file provider subsystem | File Access |
| `macos:unifiedlog` | log stream - file subsystem | File Access |
| `macos:unifiedlog` | log stream - process subsystem | Process Creation |
| `macos:unifiedlog` | log stream --info --predicate 'eventMessage CONTAINS "exec"' | Process Creation |
| `macos:unifiedlog` | log stream --info --predicate 'subsystem == "com.apple.cfprefsd"' | Process Creation |
| `macos:unifiedlog` | log stream --predicate | Command Execution |
| `macos:unifiedlog` | log stream --predicate 'eventMessage contains "USBMSC"' | Drive Creation |
| `macos:unifiedlog` | log stream --predicate 'eventMessage contains "exec"' | Process Creation |
| `macos:unifiedlog` | log stream --predicate 'eventMessage contains "loginwindow" or "pfctl"' | Command Execution |
| `macos:unifiedlog` | log stream --predicate 'eventMessage contains "python"' | Script Execution |
| `macos:unifiedlog` | log stream --predicate 'eventMessage contains "wscript" OR "vbs"' | Script Execution |
| `macos:unifiedlog` | log stream --predicate 'processImagePath CONTAINS "curl" OR "osascript"' | Process Creation |
| `macos:unifiedlog` | log stream --predicate 'processImagePath contains "zip" OR "base64"' | Command Execution |
| `macos:unifiedlog` | log stream cleared or truncated | Application Log Content |
| `macos:unifiedlog` | log stream network activity | Network Connection Creation |
| `macos:unifiedlog` | log stream process subsystem | Process Creation |
| `macos:unifiedlog` | log stream with predicate 'eventMessage CONTAINS "osascript"' | Script Execution |
| `macos:unifiedlog` | logMessage contains pbpaste or osascript | Process Creation |
| `macos:unifiedlog` | logd:file write | File Creation |
| `macos:unifiedlog` | loginwindow or desktopservices modified settings or files | File Modification |
| `macos:unifiedlog` | loginwindow or sshd | Logon Session Metadata |
| `macos:unifiedlog` | loginwindow or sshd events with external IP | Logon Session Metadata |
| `macos:unifiedlog` | loginwindow or sshd successful login events | Logon Session Creation |
| `macos:unifiedlog` | loginwindow or tccd-related entries | Process Creation |
| `macos:unifiedlog` | loginwindow, sshd | Logon Session Metadata |
| `macos:unifiedlog` | memory mapping | Process Modification |
| `macos:unifiedlog` | modification to /var/db/dslocal/nodes/Default/users/ | File Modification |
| `macos:unifiedlog` | mounted\|appeared\|DA: disk* attached | Drive Creation |
| `macos:unifiedlog` | network | Network Connection Creation |
| `macos:unifiedlog` | network connection events | Network Connection Creation |
| `macos:unifiedlog` | network flow | Network Traffic Content |
| `macos:unifiedlog` | network sessions initiated by remote desktop apps | Network Connection Creation |
| `macos:unifiedlog` | network stack resource exhaustion, tcp_accept queue overflow, repeated resets | Host Status |
| `macos:unifiedlog` | network, socket, and http logs | Network Traffic Content |
| `macos:unifiedlog` | networkd or com.apple.network | Network Traffic Flow |
| `macos:unifiedlog` | networkd or socket | Network Connection Creation |
| `macos:unifiedlog` | new DHCP configuration with anomalous DNS or router values | Application Log Content |
| `macos:unifiedlog` | nohup, disown, or osascript execution patterns | Command Execution |
| `macos:unifiedlog` | non-shell process tree accessing bash history | Process Metadata |
| `macos:unifiedlog` | open URL\|clicked link\|LSQuarantineAttach | Network Traffic Content |
| `macos:unifiedlog` | open/read access to private key files (id_rsa, *.pem, *.p12) | File Access |
| `macos:unifiedlog` | open/read of *.plist or .env files | File Access |
| `macos:unifiedlog` | open: Access to /var/log/system.log or related security event logs | File Access |
| `macos:unifiedlog` | opendirectoryd crashes or abnormal authentication errors | Application Log Content |
| `macos:unifiedlog` | opened document\|clicked link\|EXC_BAD_ACCESS\|abort\|LSQuarantine | Application Log Content |
| `macos:unifiedlog` | osascript or AppleScript invocation modifying UI | Script Execution |
| `macos:unifiedlog` | osascript, AppleScript, or Python execution triggered immediately after HID connection | Script Execution |
| `macos:unifiedlog` | outbound HTTPS connections to cloud storage APIs | Network Traffic Content |
| `macos:unifiedlog` | outbound HTTPS connections to code repository APIs | Network Traffic Content |
| `macos:unifiedlog` | outbound TCP/UDP traffic over unexpected port | Network Traffic Flow |
| `macos:unifiedlog` | outbound TLS connections to cloud storage providers | Network Traffic Content |
| `macos:unifiedlog` | pfctl -d, socketfilterfw --setglobalstate off, or modifications to com.apple.alf | Command Execution |
| `macos:unifiedlog` | pkginstalld/softwareupdated/Homebrew install transactions | File Metadata |
| `macos:unifiedlog` | process | Process Creation, Process Metadata |
| `macos:unifiedlog` | process 'crashed'\|'EXC_BAD_ACCESS' for sshd, screensharingd, httpd; launchd restarts of these daemons. | Application Log Content |
| `macos:unifiedlog` | process + network activity | Network Traffic Content |
| `macos:unifiedlog` | process + network metrics correlation for bandwidth saturation | Network Traffic Content |
| `macos:unifiedlog` | process = 'ssh' OR eventMessage CONTAINS 'ssh' | Network Traffic Content |
| `macos:unifiedlog` | process = 'sshd' | Logon Session Metadata |
| `macos:unifiedlog` | process activity stream | Process Creation |
| `macos:unifiedlog` | process activity, exec events | Process Creation |
| `macos:unifiedlog` | process and file events via log stream | Process Creation |
| `macos:unifiedlog` | process and signing chain events | Process Creation |
| `macos:unifiedlog` | process calling security find-certificate, export, or import | Command Execution |
| `macos:unifiedlog` | process command line contains base64, -enc, openssl enc -base64 | Process Creation |
| `macos:unifiedlog` | process crash, abort, code signing violations | Application Log Content |
| `macos:unifiedlog` | process created with repeated ICMP or UDP flood behavior | Process Creation |
| `macos:unifiedlog` | process event | Process Creation |
| `macos:unifiedlog` | process events | Process Creation |
| `macos:unifiedlog` | process exec | Process Creation |
| `macos:unifiedlog` | process exec events of systemsetup, date, ioreg with command_line parameters indicating time discovery | Process Creation |
| `macos:unifiedlog` | process execution events for chmod, chown, chflags with parameter analysis and target path examination | Process Creation |
| `macos:unifiedlog` | process execution events for chmod, chown, chflags with unusual parameters or targets | Process Creation |
| `macos:unifiedlog` | process execution events for discovery utilities (system_profiler, sw_vers, dscl, networksetup) with command-line parameter analysis | Process Creation |
| `macos:unifiedlog` | process execution events for system discovery utilities (system_profiler, sysctl, networksetup, ioreg) with parameter analysis | Process Creation |
| `macos:unifiedlog` | process execution events with dylib load activity | Module Load |
| `macos:unifiedlog` | process execution of ssh with -L/-R forwarding flags | Process Creation |
| `macos:unifiedlog` | process launch | Process Creation |
| `macos:unifiedlog` | process launch of diskutil or system_profiler with SPStorageDataType | Process Creation |
| `macos:unifiedlog` | process logs | Process Creation |
| `macos:unifiedlog` | process writes or modifies files in excluded paths | Process Creation |
| `macos:unifiedlog` | process, library load, memory operations | Process Modification |
| `macos:unifiedlog` | process, network | Network Traffic Content |
| `macos:unifiedlog` | process, socket, and DNS logs | Process Creation |
| `macos:unifiedlog` | process.*exit.*code | Process Termination |
| `macos:unifiedlog` | process: at, job runner | Command Execution |
| `macos:unifiedlog` | process: code or jetbrains-gateway launching with --tunnel or --remote | Process Creation |
| `macos:unifiedlog` | process: crontab edits, launch of cron job | Scheduled Job Creation |
| `macos:unifiedlog` | process: exec | Process Creation |
| `macos:unifiedlog` | process: exec + filewrite: ~/.ssh/authorized_keys | Process Creation |
| `macos:unifiedlog` | process: spawn, exec | Process Creation |
| `macos:unifiedlog` | process::exec | Process Creation |
| `macos:unifiedlog` | process:exec | Process Creation |
| `macos:unifiedlog` | process:exec and kext load events | Process Creation |
| `macos:unifiedlog` | process:launch | Process Creation |
| `macos:unifiedlog` | process:spawn | Process Creation |
| `macos:unifiedlog` | process:spawn, process:exec | Command Execution |
| `macos:unifiedlog` | process_create: Process creation where parent is Safari/Google Chrome and child is script interpreter or signed-but-unusual helper binary | Process Creation |
| `macos:unifiedlog` | process_exec: image in {/bin/bash,/bin/zsh,/usr/bin/osascript,/usr/bin/python*,/usr/bin/curl,/usr/bin/ssh,/usr/bin/open} AND parent in {Preview, TextEdit, Microsoft Word, Microsoft Excel, AdobeReader, Archive Utility, Finder} | Process Creation |
| `macos:unifiedlog` | process_name IN ("VBoxManage", "prlctl") AND command CONTAINS ("list", "show") | Process Creation |
| `macos:unifiedlog` | profiles install -type=configuration | Command Execution |
| `macos:unifiedlog` | ptrace or task_for_pid | Process Access |
| `macos:unifiedlog` | ptrace: Processes invoking ptrace with PTRACE_TRACEME flag | OS API Execution |
| `macos:unifiedlog` | pwpolicy\|PasswordPolicy | Command Execution |
| `macos:unifiedlog` | quarantine or AV-related subsystem | Application Log Content |
| `macos:unifiedlog` | read access to ~/Library/Keychains or history files by terminal processes | File Access |
| `macos:unifiedlog` | read access to ~/Library/Keychains/login.keychain-db | File Access |
| `macos:unifiedlog` | read of user document directories | File Access |
| `macos:unifiedlog` | read/write of user documents prior to upload | File Access |
| `macos:unifiedlog` | read: File access to /System/Library/Extensions/ or related kernel extension paths | File Access |
| `macos:unifiedlog` | replace existing dylibs | File Modification |
| `macos:unifiedlog` | rule definitions written to emond rule plists | File Modification |
| `macos:unifiedlog` | security OR injection attempts into 1Password OR LastPass | Process Creation |
| `macos:unifiedlog` | shutdown -h now or reboot | Process Creation |
| `macos:unifiedlog` | softwareupdated/homebrew/install logs, pkginstalld events | File Metadata |
| `macos:unifiedlog` | spctl --master-disable, csrutil disable, or defaults write to disable Gatekeeper | Command Execution |
| `macos:unifiedlog` | subsystem: com.apple.WebKit or com.apple.WebKit.Networking | Network Traffic Content |
| `macos:unifiedlog` | subsystem: com.apple.network | Network Traffic Content |
| `macos:unifiedlog` | subsystem:com.apple.Terminal | Command Execution |
| `macos:unifiedlog` | subsystem:syspolicyd | File Metadata |
| `macos:unifiedlog` | subsystem=com.apple.Security or com.apple.applescript | Script Execution |
| `macos:unifiedlog` | subsystem=com.apple.TCC | Process Metadata |
| `macos:unifiedlog` | subsystem=com.apple.WebKit | Network Traffic Content |
| `macos:unifiedlog` | subsystem=com.apple.kextd | Module Load |
| `macos:unifiedlog` | subsystem=com.apple.launchservices | Service Metadata |
| `macos:unifiedlog` | subsystem=com.apple.lsd | File Metadata |
| `macos:unifiedlog` | subsystem=com.apple.process | Process Metadata |
| `macos:unifiedlog` | subsystem=com.apple.security, library=libsystem_kernel.dylib | Process Access |
| `macos:unifiedlog` | subsystem=launchservices | Script Execution |
| `macos:unifiedlog` | successful sudo or authentication for account not normally associated with admin actions | User Account Authentication |
| `macos:unifiedlog` | sudden burst in outgoing packets from same PID | Network Traffic Flow |
| `macos:unifiedlog` | suspicious dlopen/dlsym usage in non-development processes | Module Load |
| `macos:unifiedlog` | tcp/udp | Network Traffic Flow |
| `macos:unifiedlog` | vm_read, task_for_pid, or file open to cookie databases | Process Access |
| `macos:unifiedlog` | write | File Modification |
| `macos:unifiedlog` | write of plist files in /Library/LaunchAgents or /Library/LaunchDaemons | File Modification |
| `macos:unifiedlog` | write: File modification to com.apple.PowerManagement.plist or related system preference files | File Modification |
| `macos:unifiedlog` | write: File modifications to *.plist within LaunchAgents, LaunchDaemons, Application Support, or Preferences directories | File Modification |
| `macos:unifiedlog` | xattr -d com.apple.quarantine or similar attribute removal commands | File Metadata |
| `macos:unifiedlog` | xattr -d com.apple.quarantine or similar removal commands | Command Execution |
| `macos:unifiedlog` | xattr utility execution with -w or -p flags | Command Execution |
| `macos:unifiedlog` | ~/Library/Application Support/Google/Chrome/*/Login Data OR ~/Library/Application Support/Firefox/*/logins.json | File Access |
