# DC0032 - Process Creation

## Description

Refers to the event in which a new process (executable) is initialized by an operating system. This can involve parent-child process relationships, process arguments, and environmental variables. Monitoring process creation is crucial for detecting malicious behaviors, such as execution of unauthorized binaries, scripting abuse, or privilege escalation attempts..

## Log Sources

| Log Source | Channel |
|------------|---------|
| `Process` | None |
| `auditd:SYSCALL` | execve |
| `macos:unifiedlog` | log stream 'eventMessage contains pubsub or broker' |
| `WinEventLog:Sysmon` | EventCode=1 |
| `linux:osquery` | Execution of binary resolved from $PATH not located in /usr/bin or /bin |
| `macos:unifiedlog` | Process execution path inconsistent with baseline PATH directories |
| `macos:endpointsecurity` | ES_EVENT_TYPE_NOTIFY_EXEC |
| `WinEventLog:Security` | EventCode=4688 |
| `linux:osquery` | process_events |
| `macos:endpointsecurity` | exec |
| `macos:osquery` | processes |
| `macos:unifiedlog` | Execution of launchctl with suspicious arguments |
| `auditd:SYSCALL` | execve network tools |
| `macos:osquery` | process_events |
| `auditd:SYSCALL` | execve calls to soffice.bin with suspicious macro execution flags |
| `macos:unifiedlog` | Process execution of Microsoft Word, Excel, PowerPoint with macro execution attempts |
| `macos:osquery` | process reading browser configuration paths |
| `macos:unifiedlog` | exec logs |
| `auditd:EXECVE` | execve: Processes launched with LD_PRELOAD/LD_LIBRARY_PATH pointing to non-system dirs |
| `macos:endpointsecurity` | exec: Process execution context for loaders calling dlopen/dlsym |
| `auditd:EXECVE` | EXECVE |
| `auditd:EXECVE` | execution of unexpected binaries during user shell startup |
| `macos:unifiedlog` | launch of Terminal.app or shell with non-standard environment setup |
| `macos:endpointsecurity` | ES_EVENT_TYPE_NOTIFY_EXEC with unusual parent-child process relationships from zsh |
| `auditd:SYSCALL` | execve of systemctl or service stop |
| `auditd:SYSCALL` | execve of launchctl or pkill |
| `macos:unifiedlog` | process::exec |
| `auditd:SYSCALL` | execve: Execution of klist, kinit, or tools interacting with ccache outside normal user context |
| `macos:osquery` | Execution of non-standard binaries accessing Kerberos APIs |
| `auditd:SYSCALL` | execve: Electron-based binary spawning shell or script interpreter |
| `macos:unifiedlog` | Electron app spawning unexpected child process |
| `esxi:shell` | /root/.ash_history or /etc/init.d/* |
| `auditd:SYSCALL` | execve calls with high-frequency or known bandwidth-intensive tools |
| `macos:unifiedlog` | exec or spawn calls to proxy tools or torrent clients |
| `containers:osquery` | bandwidth-intensive command execution from within a container namespace |
| `macos:unifiedlog` | process launch |
| `macos:unifiedlog` | log stream --info --predicate 'subsystem == "com.apple.cfprefsd"' |
| `macos:unifiedlog` | execution of security, sqlite3, or unauthorized binaries |
| `macos:unifiedlog` | Unexpected applications generating outbound DNS queries |
| `linux:Sysmon` | EventCode=1 |
| `macos:osquery` | execve |
| `macos:unifiedlog` | Unexpected child process of Safari or Chrome |
| `auditd:SYSCALL` | execve or syscall invoking vm artifact check commands (e.g., dmidecode, lspci, dmesg) |
| `macos:unifiedlog` | execution of system_profiler, ioreg, kextstat with argument patterns related to VM/sandbox checks |
| `macos:unifiedlog` | process writes or modifies files in excluded paths |
| `macos:unifiedlog` | process |
| `macos:unifiedlog` | com.apple.mail.* exec.* |
| `macos:unifiedlog` | execution of memory inspection tools (lldb, gdb, osqueryi) |
| `esxi:vobd` | /var/log/vobd.log |
| `kubernetes:apiserver` | kubectl exec or kubelet API calls targeting running pods |
| `docker:audit` | Process execution events within container namespace context |
| `auditd:SYSCALL` | process persists beyond parent shell termination |
| `macos:unifiedlog` | background process persists beyond user logout |
| `auditd:SYSCALL` | execve: Execution of scripts or binaries sourced from mail directories (/var/mail, ~/Maildir) |
| `macos:unifiedlog` | Preview.app, Safari.app, or Mail.app spawning new processes outside normal patterns |
| `esxi:hostd` | process execution across cloud VM |
| `auditd:EXECVE` | systemctl spawning managed processes |
| `macos:unifiedlog` | None |
| `esxi:shell` | /var/log/shell.log |
| `macos:unifiedlog` | Execution of processes linked to hijacked sessions (e.g., anomalous parent-child process lineage) |
| `macos:unifiedlog` | exec events where web process starts a shell/tooling |
| `docker:events` | Docker/Kubernetes audit of exec/attach (kubectl exec) or unexpected child processes inside container |
| `macos:unifiedlog` | exec of osascript, bash, curl with suspicious parameters |
| `auditd:SYSCALL` | execve: Execution of container management CLIs (docker, crictl, kubectl) or interpreted shells (sh, bash, python) within container context |
| `macos:endpointsecurity` | es_event_exec |
| `auditd:SYSCALL` | execve: Execution of discovery commands targeting backup binaries, processes, or config paths |
| `macos:unifiedlog` | Process execution logs showing discovery commands like mdfind, system_profiler, or launchctl list |
| `macos:osquery` | process_events OR launchd |
| `auditd:EXECVE` | execve |
| `macos:osquery` | launchd or process_events |
| `macos:unifiedlog` | process and file events via log stream |
| `auditd:SYSCALL` | execve: Execution of scripts or binaries spawned from browser processes |
| `macos:unifiedlog` | Browser processes launching unexpected interpreters (osascript, bash) |
| `macos:unifiedlog` | exec: Execution of defaults, plutil, or common editors (vim/nano) targeting plist files |
| `auditd:SYSCALL` | EXECVE |
| `macos:unifiedlog` | process:exec |
| `auditd:SYSCALL` | execve: Execution of bash, python, or perl processes spawned by browser/email client |
| `macos:unifiedlog` | Execution of osascript, bash, or Terminal initiated from Mail.app or Safari |
| `auditd:SYSCALL` | execve of /bin/sh,/bin/bash,/usr/bin/curl,/usr/bin/python by service accounts (e.g., apache, mysql, nobody) immediately after inbound network activity. |
| `macos:osquery` | parent_name in ('sshd','httpd','screensharingd') spawning shells or scripting runtimes. |
| `macos:unifiedlog` | process activity stream |
| `auditd:SYSCALL` | SYSCALL record where exe contains passwd/userdel/chage and auid != root |
| `macos:unifiedlog` | Post-login execution of unrecognized child process from launchd or loginwindow |
| `auditd:SYSCALL` | execve of base64\|openssl\|xxd\|python\|perl with arguments matching Base64 flags |
| `macos:unifiedlog` | process command line contains base64, -enc, openssl enc -base64 |
| `macos:endpointsecurity` | exec: arguments contain Base64-like strings |
| `esxi:shell` | commands containing base64, openssl enc -base64, xxd -p |
| `macos:unifiedlog` | Execution of process launched via loginwindow session restore |
| `macos:unifiedlog` | process: exec + filewrite: ~/.ssh/authorized_keys |
| `containerd:runtime` | /var/log/containers/*.log |
| `macos:unifiedlog` | Execution of Java apps or other processes with hidden window attributes |
| `macos:unifiedlog` | Process Execution |
| `auditd:SYSCALL` | execve on code or jetbrains-gateway with remote flags |
| `macos:unifiedlog` | process: code or jetbrains-gateway launching with --tunnel or --remote |
| `macos:unifiedlog` | log stream --predicate 'processImagePath CONTAINS "curl" OR "osascript"' |
| `auditd:EXECVE` | Execution of dd, shred, wipe targeting block devices |
| `auditd:SYSCALL` | execve of sleep or ping command within script interpreted by bash/python |
| `auditd:SYSCALL` | execve or socket/connect system calls from processes using crypto libraries |
| `macos:unifiedlog` | Process using AES/RC4 routines unexpectedly |
| `linux:osquery` | execution of known firewall binaries |
| `auditd:SYSCALL` | type=EXECVE or SYSCALL for /bin/date, /usr/bin/timedatectl, /sbin/hwclock, /bin/cat /etc/timezone, /bin/cat /proc/uptime |
| `linux:osquery` | execve: command like 'date', 'timedatectl', 'hwclock', 'cat /etc/timezone' |
| `macos:unifiedlog` | process exec events of systemsetup, date, ioreg with command_line parameters indicating time discovery |
| `macos:endpointsecurity` | exec: binary == "/usr/sbin/systemsetup" and args contains "-gettimezone" |
| `macos:osquery` | execve: command LIKE '%systemsetup -gettimezone%' OR '%date%' |
| `macos:unifiedlog` | execution of osascript, curl, or unexpected automation |
| `macos:unifiedlog` | exec /usr/bin/pwpolicy |
| `auditd:SYSCALL` | socket(AF_PACKET\|AF_INET, SOCK_RAW, *), setsockopt(… SO_ATTACH_FILTER\|SO_ATTACH_BPF …), bpf(cmd=BPF_PROG_LOAD), open/openat path="/dev/bpf*" (BSD/macOS-like) or setcap cap_net_raw. |
| `linux:syslog` | KERN messages about eBPF program load/verify or LSM denials related to bpf. |
| `OpenBSM:AuditTrail` | open/openat of /dev/bpf*; ioctl BIOCSETF-like operations. |
| `macos:unifiedlog` | Exec of tcpdump, rvictl, custom tools linked to libpcap.A.dylib; sysextd/systemextensionsctl events for NetworkExtension content filters. |
| `auditd:EXECVE` | /usr/sbin/postfix, /usr/sbin/exim, /usr/sbin/sendmail |
| `auditd:SYSCALL` | execution of known flash tools (e.g., flashrom, fwupd) |
| `macos:unifiedlog` | com.apple.firmwareupdater activity or update-firmware binary invoked |
| `auditd:SYSCALL` | execve of system tools like dmidecode, lspci, lscpu, dmesg, systemd-detect-virt |
| `macos:unifiedlog` | exec or spawn of 'system_profiler', 'ioreg', 'kextstat', 'sysctl', or calls to sysctl API |
| `macos:endpointSecurity` | ES_EVENT_TYPE_NOTIFY_EXEC |
| `auditd:SYSCALL` | execve: Suspicious binaries or scripts interacting with authentication binaries (sshd, gdm, login) |
| `macos:osquery` | execve: Processes unexpectedly invoking Keychain or authentication APIs |
| `auditd:SYSCALL` | execve: execve calls where a browser/webview process is parent and child is interpreter (python, sh, ruby) or downloader (curl, wget) |
| `macos:unifiedlog` | process_create: Process creation where parent is Safari/Google Chrome and child is script interpreter or signed-but-unusual helper binary |
| `auditd:EXECVE` | None |
| `macos:unifiedlog` | process:launch |
| `auditd:EXECVE` | Shell commands invoked by SQL process such as postgres, mysqld, or mariadbd |
| `auditd:SYSCALL` | execve of smbclient, smbmap, rpcclient, nmblookup, crackmapexec smb |
| `macos:endpointsecurity` | ES_EVENT_TYPE_NOTIFY_EXEC: Process execution of "sharing -l", "smbutil view", "mount_smbfs" |
| `macos:unifiedlog` | Execution of scp, rsync, curl with remote destination |
| `macos:unifiedlog` | logMessage contains pbpaste or osascript |
| `auditd:SYSCALL` | execve call with argv matching known disk enumeration commands (lsblk, parted, fdisk) |
| `macos:unifiedlog` | process launch of diskutil or system_profiler with SPStorageDataType |
| `esxi:hostd` | execution of esxcli with args matching 'storage', 'filesystem', 'core device list' |
| `macos:unifiedlog` | Mail.app executing with parameters updating rules state |
| `esxi:shell` | /var/log/vmkernel.log, /var/log/vmkwarning.log |
| `macos:endpointsecurity` | exec: Exec of ffmpeg, avfoundation-based binaries, or custom signed apps accessing camera |
| `kubernetes:apiserver` | exec into pod followed by secret retrieval via API |
| `macos:unifiedlog` | process_name IN ("VBoxManage", "prlctl") AND command CONTAINS ("list", "show") |
| `macos:unifiedlog` | exec srm\|exec openssl\|exec gpg |
| `linux:osquery` | Process execution with LD_PRELOAD or modified library path |
| `macos:unifiedlog` | Execution of process with DYLD_INSERT_LIBRARIES set |
| `linux:Sysmon` | process creation events linked to container namespaces executing host-level binaries |
| `macos:unifiedlog` | process and signing chain events |
| `macos:unifiedlog` | launchservices events for misleading extensions |
| `fs:fsusage` | Execution of disguised binaries |
| `linux:osquery` | process listening or connecting on non-standard ports |
| `macos:unifiedlog` | launchd services binding to non-standard ports |
| `auditd:SYSCALL` | execve, connect |
| `esxi:cron` | process or cron activity |
| `macos:unifiedlog` | Execution of binaries with unsigned or anomalously signed certificates |
| `auditd:SYSCALL` | execve logging for /usr/bin/systemctl and systemd-run |
| `macos:osquery` | Invocation of osascript or dylib injection |
| `auditd:SYSCALL` | execve: Execution of files saved in mail or download directories |
| `macos:unifiedlog` | Execution of Terminal, osascript, or other interpreters originating from Mail or Preview |
| `macos:unifiedlog` | process events |
| `linux:syslog` | Unauthorized sudo or shell access, especially leading to file changes in /var/www or /srv/http |
| `macos:unifiedlog` | Execution of unexpected terminal or web scripts modifying /Library/WebServer/Documents |
| `auditd:SYSCALL` | execve: Execution of CLI tools like psql, mysql, mongo, sqlite3 |
| `macos:unifiedlog` | Process start of Java or native DB client tools |
| `macos:unifiedlog` | loginwindow or tccd-related entries |
| `macos:osquery` | query: process_events, launchd, and tcc.db access |
| `ebpf:syscalls` | process execution or network connect from just-created container PID namespace |
| `auditd:SYSCALL` | execve: Execution of pip, npm, gem, or similar package managers |
| `macos:unifiedlog` | Command line invocation of pip3, brew install, npm install from interactive Terminal |
| `auditd:SYSCALL` | fork/exec of service via PID 1 (systemd) |
| `auditd:EXECVE` | Execution of ssh/scp/sftp without corresponding authentication log |
| `macos:unifiedlog` | Execution of ssh or sftp without corresponding login event |
| `auditd:SYSCALL` | execve: execve where exe=/usr/bin/python3 or similar interpreter |
| `macos:unifiedlog` | launch of remote desktop app or helper binary |
| `macos:unifiedlog` | Unexpected processes making network calls based on DNS-derived ports |
| `macos:unifiedlog` | launchctl spawning new processes |
| `macos:unifiedlog` | launchctl activity and process creation |
| `containerd:events` | New container with suspicious image name or high resource usage |
| `macos:unifiedlog` | Execution of Python, Swift, or other binaries invoking archiving libraries |
| `linux:osquery` | Processes linked with libssl or crypto libraries making outbound connections |
| `macos:unifiedlog` | Process invoking SSL routines from Security framework |
| `auditd:SYSCALL` | Execution of binaries located in /etc/init.d/ or systemd service paths |
| `macos:unifiedlog` | Execution of binary listed in newly modified LaunchAgent plist |
| `macos:unifiedlog` | Execution of bless or nvram modifying boot parameters |
| `macos:unifiedlog` | Unexpected processes registered with launchd |
| `macos:unifiedlog` | Process launch |
| `macos:unifiedlog` | execution of curl, osascript, or unexpected Office processes |
| `macos:osquery` | exec |
| `macos:unifiedlog` | Trust validation failures or bypass attempts during notarization and code signing checks |
| `esxi:vmkernel` | spawned shell or execution environment activity |
| `macos:unifiedlog` | process_exec: image in {/bin/bash,/bin/zsh,/usr/bin/osascript,/usr/bin/python*,/usr/bin/curl,/usr/bin/ssh,/usr/bin/open} AND parent in {Preview, TextEdit, Microsoft Word, Microsoft Excel, AdobeReader, Archive Utility, Finder} |
| `auditd:SYSCALL` | execve: exe in {/bin/bash,/bin/sh,/usr/bin/python*,/usr/bin/perl,/usr/bin/php,/usr/bin/node,/usr/bin/curl,/usr/bin/wget,/usr/bin/xdg-open,/usr/bin/ssh,/usr/bin/rundll32 (wine)} AND ppid process is a document viewer/browser |
| `auditd:EXECVE` | Execution of dd/sgdisk with arguments writing to sector 0 or partition table |
| `macos:unifiedlog` | Execution of zip, ditto, hdiutil, or openssl by processes not normally associated with archiving |
| `macos:unifiedlog` | process execution events for chmod, chown, chflags with unusual parameters or targets |
| `m365:defender` | AdvancedHunting(DeviceEvents, ProcessCreate, ImageLoad, AMSI/ETW derived signals) |
| `macos:unifiedlog` | execve or dylib load from memory without backing file |
| `auditd:SYSCALL` | execve: Commands that alter firewall or start listeners: iptables\|nft\|ufw\|firewall-cmd\|pfctl\|systemctl start sshd/telnet/dropbear; raw-socket/libpcap tools (tcpdump, tshark, nmap --raw). |
| `macos:unifiedlog` | exec: Execution of pfctl, socketfilterfw, launchctl start ssh/telnet, libpcap consumers. |
| `esxi:shell` | Shell Execution |
| `macos:unifiedlog` | Unusual child process tree indicating attempted recovery after crash |
| `auditd:SYSCALL` | execve: Execution of binaries/scripts presenting false health messages for security daemons |
| `macos:unifiedlog` | Execution of processes mimicking Apple Security & Privacy GUIs |
| `auditd:SYSCALL` | execve, setifflags |
| `macos:osquery` | process_events where path like '%tcpdump%' |
| `auditd:EXECVE` | Execution of dd, shred, or wipe with arguments targeting block devices |
| `auditd:EXECVE` | systemctl stop auditd, kill -9 <pid>, or modifications to /etc/selinux/config |
| `macos:unifiedlog` | execution of curl, git, or Office processes with network connections |
| `macos:unifiedlog` | log stream - process subsystem |
| `auditd:SYSCALL` | execve calls for qemu-system*, kvm, or VBoxHeadless |
| `macos:unifiedlog` | Process execution for VBoxHeadless, prl_vm_app, vmware-vmx |
| `macos:unifiedlog` | process logs |
| `esxi:shell` | None |
| `auditd:SYSCALL` | execve of interpreters (python, perl), custom binaries, or shell utilities with long arguments containing non-standard tokens |
| `macos:endpointsecurity` | ES_EVENT_TYPE_NOTIFY_EXEC: arguments contain long, non-standard tokens / custom alphabets |
| `macos:unifiedlog` | command line or log output shows non-standard encoding routines |
| `esxi:shell` | commands containing long non-standard tokens or custom lookup tables |
| `macos:unifiedlog` | Execution of /usr/sbin/installer spawning child process from within /private/tmp or package contents |
| `auditd:SYSCALL` | Execution of dpkg or rpm followed by fork/execve from within postinst, prerm, etc. |
| `macos:unifiedlog` | execve: Helper tools invoked through XPC executing unexpected binaries |
| `macos:unifiedlog` | execution of modified binary without valid signature |
| `auditd:SYSCALL` | execve: exe in (/usr/bin/bash,/usr/bin/sh,/usr/bin/zsh,/usr/bin/python*) AND cmdline matches '(curl\|wget).*(\\|\|\\|\s*sh\|bash)\|base64\s*-d\|python\s*-c' |
| `macos:unifiedlog` | exec: ParentImage in (Terminal, iTerm2) AND Image in (/bin/zsh,/bin/bash,/usr/bin/python*) AND CommandLine matches '(curl\|wget).*(\\|\|\\|\s*sh\|bash)\|base64 -D\|python -c' |
| `macos:unifiedlog` | process created with repeated ICMP or UDP flood behavior |
| `fs:fsusage` | binary execution of security_authtrampoline |
| `macos:unifiedlog` | process: exec |
| `esxi:vmkernel` | Exec |
| `macos:unifiedlog` | Child processes of Safari, Chrome, or Firefox executing scripting interpreters |
| `macos:unifiedlog` | Execution of older or non-standard interpreters |
| `linux:osquery` | process execution events for permission modification utilities with command-line analysis |
| `macos:unifiedlog` | process execution events for chmod, chown, chflags with parameter analysis and target path examination |
| `macos:osquery` | process execution monitoring for permission modification utilities with command-line argument analysis |
| `auditd:SYSCALL` | Invocation of packet generation tools (e.g., hping3, nping) or fork bombs |
| `macos:osquery` | Execution of flooding tools or compiled packet generators |
| `esxi:hostd` | process |
| `auditd:SYSCALL` | execve for proxy tools |
| `macos:unifiedlog` | process, socket, and DNS logs |
| `macos:osquery` | process_events table |
| `macos:unifiedlog` | Command line containing `trap` or `echo 'trap` written to login shell files |
| `macos:unifiedlog` | log collect --predicate |
| `auditd:SYSCALL` | execve or nanosleep with no stdout/stderr I/O |
| `macos:unifiedlog` | launchd or osascript spawns process with delay command |
| `linux:syslog` | systemd-udevd spawning user-defined action from RUN+= |
| `ebpf:syscalls` | execve |
| `macos:unifiedlog` | process:spawn |
| `macos:unifiedlog` | log stream --predicate 'eventMessage contains "exec"' |
| `auditd:EXECVE` | cat\|less\|grep accessing .bash_history from a non-shell process |
| `auditd:EXECVE` | Process execution via .desktop Exec path from /etc/xdg/autostart or ~/.config/autostart |
| `auditd:SYSCALL` | Execution of dpkg, rpm, or other package manager with list flag |
| `macos:unifiedlog` | Execution of system_profiler or osascript invoking enumeration |
| `auditd:SYSCALL` | apache2 or nginx spawning sh, bash, or python interpreter |
| `macos:unifiedlog` | httpd spawning bash, zsh, python, or osascript |
| `macos:unifiedlog` | Execution of /usr/libexec/security_authtrampoline or child processes originating from non-trusted binaries triggering credential prompts |
| `macos:unifiedlog` | execution of security or osascript |
| `macos:unifiedlog` | launchd spawning processes tied to new or modified LaunchDaemon .plist entries |
| `macos:unifiedlog` | Execution of ping, nping, or crafted network packets via bash or python to reflection services |
| `auditd:SYSCALL` | execve: Execution of commands modifying iptables/nftables to block selective IPs |
| `macos:unifiedlog` | System process modifications altering DNS/proxy settings |
| `containerd:Events` | unusual process spawned from container image context |
| `macos:osquery` | curl, python scripts, rsync with internal share URLs |
| `macos:unifiedlog` | process: spawn, exec |
| `macos:osquery` | Rapid spawning of resource-heavy applications (e.g., Preview, Safari, Office) |
| `macos:unifiedlog` | Process creation events where command line = pmset with arguments affecting sleep, hibernatemode, displaysleep |
| `macos:unifiedlog` | Unexpected apps performing repeated DNS lookups |
| `macos:unifiedlog` | launchservices or loginwindow events |
| `auditd:SYSCALL` | execve with LD_PRELOAD or linker-related environment variables set |
| `macos:unifiedlog` | execution of process with DYLD_INSERT_LIBRARIES set |
| `macos:unifiedlog` | Suspicious Swift/Objective-C or scripting processes writing archive-like outputs |
| `auditd:SYSCALL` | execve of re-parented process |
| `linux:osquery` | Anomalous parent PID change |
| `macos:unifiedlog` | Process creation with parent PID of 1 (launchd) |
| `linux:osquery` | child process invoking dynamic linker post-ptrace |
| `macos:osquery` | Processes executing kextload, spctl, or modifying kernel extension directories |
| `macos:osquery` | Unsigned or ad-hoc signed process executions in user contexts |
| `macos:unifiedlog` | Execution of diskutil or hdiutil attaching hidden partitions |
| `macos:unifiedlog` | process execution events for discovery utilities (system_profiler, sw_vers, dscl, networksetup) with command-line parameter analysis |
| `macos:osquery` | process event monitoring with focus on discovery utilities and cryptographic framework usage correlation |
| `macos:unifiedlog` | Unexpected apps generating frequent DNS queries |
| `macos:unifiedlog` | process exec |
| `auditd:SYSCALL` | socket: Suspicious creation of AF_UNIX sockets outside expected daemons |
| `macos:unifiedlog` | Non-standard processes invoking financial applications or payment APIs |
| `auditd:SYSCALL` | execve: Agent/headless flags (listen/connect/reverse/tunnel) or remote-control binaries spawning shells |
| `auditd:SYSCALL` | systemctl enable/start: Creation/enablement of custom .service units in /etc/systemd/system |
| `macos:unifiedlog` | Process exec of remote-control apps or binaries with headless/connect flags |
| `auditd:SYSCALL` | execve: systemctl stop, service stop, or kill -9 on security daemons (e.g., falcon-sensor, auditd) |
| `macos:unifiedlog` | Execution of launchctl unload, kill, or removal of security agent daemons |
| `macos:unifiedlog` | process activity, exec events |
| `macos:unifiedlog` | log stream process subsystem |
| `macos:unifiedlog` | process:exec and kext load events |
| `macos:unifiedlog` | log stream --info --predicate 'eventMessage CONTAINS "exec"' |
| `WinEventLog:Microsoft-Windows-DotNETRuntime` | Unexpected AppDomain creation events or anomalous AppDomainManager assembly load behavior |
| `auditd:SYSCALL` | Execution of network stress tools or anomalies in socket/syscall behavior |
| `macos:unifiedlog` | Unsigned binary execution following SIP change |
| `auditd:SYSCALL` | execve: Commands altering firewall or enabling listeners (iptables, nft, ufw, firewall-cmd, systemctl start *ssh*/*telnet*, ip route add, tcpdump, tshark) |
| `macos:unifiedlog` | exec: Execution of /sbin/pfctl, /usr/libexec/ApplicationFirewall/socketfilterfw, ifconfig, tcpdump, npcap/libpcap consumers |
| `macos:unifiedlog` | Execution of zip, ditto, hdiutil, or openssl by non-terminal parent processes |
| `macos:unifiedlog` | Execution of binaries with TCC protected access under unexpected parent processes such as Finder.app, SystemUIServer, or nsurlsessiond |
| `WinEventLog:AppLocker` | EventCode=8003, 8004 |
| `auditd:SYSCALL` | execve, unlink |
| `macos:osquery` | launchd, processes |
| `linux:osquery` | socat, ssh, or nc processes opening unexpected ports |
| `macos:unifiedlog` | process execution of ssh with -L/-R forwarding flags |
| `macos:unifiedlog` | launchd or cron spawning mining binaries |
| `auditd:SYSCALL` | execve or socket/connect system calls for processes using RSA handshake |
| `macos:unifiedlog` | Process invoking SecKeyCreateRandomKey or asymmetric crypto APIs |
| `azure:vmguest` | Unexpected execution of cloud agent processes (e.g., WindowsAzureGuestAgent.exe, ssm-agent) followed by arbitrary script or binary execution |
| `macos:unifiedlog` | Script interpreter invoked by nginx/apache worker process |
| `macos:unifiedlog` | execution of Office binaries with network activity |
| `macos:unifiedlog` | launch of bash/zsh/python/osascript targeting key file locations |
| `macos:unifiedlog` | execution of /sbin/emond with child processes launched |
| `etw:Microsoft-Windows-Kernel-Process` | provider: ETW CreateProcess events linking msbuild.exe to suspicious children where standard logs are incomplete |
| `macos:unifiedlog` | shutdown -h now or reboot |
| `macos:unifiedlog` | Execution of Code.app, idea, JetBrainsToolbox, eclipse with install/extension flags |
| `macos:unifiedlog` | process execution events for system discovery utilities (system_profiler, sysctl, networksetup, ioreg) with parameter analysis |
| `OpenBSM:AuditTrail` | BSM audit events for process execution and system call monitoring during reconnaissance |
| `esxi:hostd` | host daemon events related to VM operations and configuration queries during reconnaissance |
| `esxi:vmkernel` | VMware kernel events for hardware and system configuration access during environmental validation |
| `linux:osquery` | processes modifying environment variables related to history logging |
| `auditd:SYSCALL` | execve: parent process is usb/hid device handler, child process bash/python invoked |
| `macos:unifiedlog` | execution of curl, rclone, or Office apps invoking network sessions |
| `macos:unifiedlog` | exec: Execution of kextstat, kextfind, or ioreg targeting driver information |
| `macos:endpointsecurity` | exec events |
| `macos:unifiedlog` | Process creation involving binaries interacting with resource fork data |
| `macos:unifiedlog` | process event |
| `auditd:SYSCALL` | execve: Execution of suspicious exploit binaries targeting security daemons |
| `macos:osquery` | execve: Unsigned or unnotarized processes launched with high privileges |
| `macos:unifiedlog` | security OR injection attempts into 1Password OR LastPass |
