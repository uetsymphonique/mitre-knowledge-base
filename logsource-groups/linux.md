# linux

150 unique events

| Log Source | Channel | Data Components |
|------------|---------|-----------------|
| `linux:Sysmon` | EventCode=1 | Process Creation |
| `linux:Sysmon` | EventCode=23 | File Deletion |
| `linux:Sysmon` | EventCode=3, 22 | Network Connection Creation |
| `linux:Sysmon` | EventCode=7 | Module Load |
| `linux:Sysmon` | New files in /tmp, /var/tmp, $HOME/.cache, executed within TimeWindow after browser HTTP fetch | File Creation |
| `linux:Sysmon` | process creation events linked to container namespaces executing host-level binaries | Process Creation |
| `linux:auth` | User login event followed by unexpected process tree | Logon Session Creation |
| `linux:auth` | sshd login | User Account Authentication |
| `linux:cli` | /home/*/.bash_history | Command Execution |
| `linux:cli` | Shell history logs | Command Execution |
| `linux:cli` | Terminal Command History | Command Execution |
| `linux:cli` | cleared or truncated .bash_history | Application Log Content |
| `linux:cli` | command logging | Command Execution |
| `linux:cron` | Scheduled execution of unknown or unusual script/binary | Scheduled Job Creation |
| `linux:cron` | cron activity | Scheduled Job Metadata |
| `linux:fim` | Changes to /etc/rc.local.d/local.sh or creation of unexpected startup files in persistent partitions (/etc/init.d, /store, /locker) | File Modification |
| `linux:osquery` | /proc/*/maps access | File Access |
| `linux:osquery` | Anomalous parent PID change | Process Creation |
| `linux:osquery` | Command-line includes base64 -d or openssl enc -d | Command Execution |
| `linux:osquery` | Cross-reference argv[0] with actual executable path and parent process metadata | Process Metadata |
| `linux:osquery` | Detection of bitwise operations or custom encryption functions in memory traces | Process Modification |
| `linux:osquery` | Dynamic Linking State | Module Load |
| `linux:osquery` | Execution of binary resolved from $PATH not located in /usr/bin or /bin | Process Creation |
| `linux:osquery` | Filesystem modifications to trusted paths | File Metadata |
| `linux:osquery` | Listing of /etc/passwd and /etc/shadow metadata | User Account Metadata |
| `linux:osquery` | New or modified kernel object files (.ko) within /lib/modules directory | File Modification |
| `linux:osquery` | None | File Access |
| `linux:osquery` | Process State | Process Access |
| `linux:osquery` | Process execution with LD_PRELOAD or modified library path | Process Creation |
| `linux:osquery` | Process linked with libcrypto.so making external connections | Module Load |
| `linux:osquery` | Processes linked with libssl or crypto libraries making outbound connections | Process Creation |
| `linux:osquery` | Processes linked with libssl/libcrypto performing network activity | Module Load |
| `linux:osquery` | Read headers and detect MIME type mismatch | File Metadata |
| `linux:osquery` | Write or modify .desktop file in XDG autostart path | File Metadata |
| `linux:osquery` | child process invoking dynamic linker post-ptrace | Process Creation |
| `linux:osquery` | crontab, systemd_timers | Scheduled Job Creation |
| `linux:osquery` | elf_info, hash, yara_matches | File Metadata |
| `linux:osquery` | event-based | File Metadata |
| `linux:osquery` | execution of known firewall binaries | Process Creation |
| `linux:osquery` | execve: command like 'date', 'timedatectl', 'hwclock', 'cat /etc/timezone' | Process Creation |
| `linux:osquery` | family=AF_PACKET or protocol raw; process name not in allowlist. | Network Connection Creation |
| `linux:osquery` | file_events | File Creation, File Metadata, File Modification, Scheduled Job Creation |
| `linux:osquery` | file_events, hash | File Metadata |
| `linux:osquery` | file_events.path | File Metadata |
| `linux:osquery` | hardware_events | Drive Access |
| `linux:osquery` | hash, elf_info, file_metadata | File Metadata |
| `linux:osquery` | hash, rpm_packages, deb_packages, file_events | File Metadata |
| `linux:osquery` | mount_events | Drive Creation |
| `linux:osquery` | newly registered unit file with ExecStart pointing to unknown binary | Service Creation |
| `linux:osquery` | process environment variables containing LD_PRELOAD | Process Metadata |
| `linux:osquery` | process execution events for permission modification utilities with command-line analysis | Process Creation |
| `linux:osquery` | process listening or connecting on non-standard ports | Process Creation |
| `linux:osquery` | process metadata mismatch between /proc and runtime attributes | Process Metadata |
| `linux:osquery` | process_events | Process Access, Process Creation |
| `linux:osquery` | process_events.command_line | Command Execution |
| `linux:osquery` | processes modifying environment variables related to history logging | Process Creation |
| `linux:osquery` | scheduled/real-time | Service Metadata |
| `linux:osquery` | select: Open files path LIKE '/tmp/%.so' OR '/dev/shm/%.so' | Module Load |
| `linux:osquery` | select: path LIKE '/dev/video%' | Process Metadata |
| `linux:osquery` | socat, ssh, or nc processes opening unexpected ports | Process Creation |
| `linux:osquery` | socket_events | Network Traffic Flow |
| `linux:osquery` | state=attached/debugged | Process Metadata |
| `linux:osquery` | unexpected termination of syslog or rsyslog processes | Process Termination |
| `linux:procfs` | /proc/[pid]/maps, /proc/[pid]/mem | Process Modification |
| `linux:procfs` | Sustained high /proc/[pid]/stat usage | Host Status |
| `linux:shell` | Manual invocation of software enumeration commands via interactive shell | Command Execution |
| `linux:syslog` | /var/log/syslog | File Access, Script Execution |
| `linux:syslog` | Accepted publickey/password for * from * port * ssh2 | Logon Session Creation |
| `linux:syslog` | Application or browser logs (webview errors, plugin enumerations) indicating suspicious script evaluation or plugin loads | Application Log Content |
| `linux:syslog` | Authentication attempts into finance-related servers from unusual IPs or times | Application Log Content |
| `linux:syslog` | Block device write errors or unusual bootloader activity | Drive Modification |
| `linux:syslog` | CLI access to 'show running-config', 'show password', or 'cat config.txt' | Command Execution |
| `linux:syslog` | DNS response IPs followed by connections to non-standard calculated ports | Network Traffic Content |
| `linux:syslog` | Device attach logs containing TinyPilot/PiKVM identifiers | Drive Creation |
| `linux:syslog` | Discrepancies in _VBA_PROJECT p-code vs source code extracted with oletools/pcodedmp | File Metadata |
| `linux:syslog` | Driver load events or firmware load failures for hardware devices | Driver Load |
| `linux:syslog` | Error/warning logs from services indicating load spike or worker exhaustion | Application Log Content |
| `linux:syslog` | Execution of modified binaries or abnormal library load sequences | OS API Execution |
| `linux:syslog` | Execution of non-standard script or binary by cron | Scheduled Job Creation |
| `linux:syslog` | Failed password for invalid user | User Account Authentication |
| `linux:syslog` | Inbound messages from webmail services containing attachments or URLs | Application Log Content |
| `linux:syslog` | Integrity mismatch warnings or malformed packets detected | Network Traffic Content |
| `linux:syslog` | KERN messages about eBPF program load/verify or LSM denials related to bpf. | Process Creation |
| `linux:syslog` | Kernel or daemon warnings of downgraded TLS or cryptographic settings | Process Metadata |
| `linux:syslog` | Module registration or stacktrace logs indicating segmentation faults or unknown module errors | Application Log Content |
| `linux:syslog` | Multiple IP addresses assigned to the same domain in rapid sequence | Network Traffic Flow |
| `linux:syslog` | Multiple NXDOMAIN responses and high entropy domains | Network Traffic Content |
| `linux:syslog` | New HID device enumeration with type 'keyboard' followed by immediate input injection | Drive Creation |
| `linux:syslog` | New Wi-Fi connection established or repeated association failures | Network Connection Creation |
| `linux:syslog` | Non-standard processes negotiating SSL/TLS key exchanges | Application Log Content |
| `linux:syslog` | None | Logon Session Creation, Logon Session Metadata, Network Connection Creation |
| `linux:syslog` | Out of memory killer invoked or kernel panic entries | Host Status |
| `linux:syslog` | Query to suspicious domain with high entropy or low reputation | Network Traffic Content |
| `linux:syslog` | Repetitive HTTP 408, 500, or 503 errors logged within short timeframe | Application Log Content |
| `linux:syslog` | SPF fail OR DKIM fail OR DMARC fail OR mismatched from_domain vs return_path_domain | Application Log Content |
| `linux:syslog` | SSH failed login | User Account Authentication |
| `linux:syslog` | Segfaults, kernel oops, or crashes in security software processes | Application Log Content |
| `linux:syslog` | Service restart with modified executable path | Service Metadata |
| `linux:syslog` | Service stop or disable messages for security tools not reflected in SIEM alerts | Host Status |
| `linux:syslog` | Sudo or root escalation followed by filesystem mount commands | Command Execution |
| `linux:syslog` | Suspicious script or command execution targeting browser folders | Command Execution |
| `linux:syslog` | System daemons initiating encrypted sessions with unexpected destinations | Application Log Content |
| `linux:syslog` | Unauthorized sudo or shell access, especially leading to file changes in /var/www or /srv/http | Process Creation |
| `linux:syslog` | Unexpected SQL or application log entries showing tampered or malformed data | Network Traffic Content |
| `linux:syslog` | Unexpected log entries or malformed SQL operations in databases | File Modification |
| `linux:syslog` | Unexpected termination of daemons or critical services not aligned with admin change tickets | Process Termination |
| `linux:syslog` | Unusual kinit or klist activity | Active Directory Credential Request |
| `linux:syslog` | Unusual outbound transfers from CLI tools like base64, gzip, or netcat | Command Execution |
| `linux:syslog` | application or system execution logs | File Metadata |
| `linux:syslog` | auditd service stopped or disabled | Service Metadata |
| `linux:syslog` | auth.log / secure.log | Logon Session Creation |
| `linux:syslog` | auth.log or custom tool logs | File Access |
| `linux:syslog` | authentication and authorization events during environmental validation phase | User Account Authentication |
| `linux:syslog` | authentication success after file access | Logon Session Creation |
| `linux:syslog` | boot logs | Script Execution |
| `linux:syslog` | browser/office crash, segfault, abnormal termination | Application Log Content |
| `linux:syslog` | cron activity | Command Execution |
| `linux:syslog` | curl\|wget\|python .*http | Network Traffic Content |
| `linux:syslog` | dmesg or syslog for module loads | Driver Load |
| `linux:syslog` | file permission modification events in kernel messages | File Metadata |
| `linux:syslog` | iptables or nftables rule changes | Firewall Rule Modification |
| `linux:syslog` | kernel messages related to cryptographic operations, module loading, and filesystem access patterns | File Access |
| `linux:syslog` | kernel messages related to file system permission changes and security violations | File Metadata |
| `linux:syslog` | kernel\|systemd messages indicating 'segmentation fault'\|'core dumped'\|'service terminated unexpectedly' for sshd, smbd, vsftpd, mysqld, httpd, etc. | Application Log Content |
| `linux:syslog` | kmod | Module Load |
| `linux:syslog` | milter configuration updated, transport rule initialized, unexpected script execution | Application Log Content |
| `linux:syslog` | mount/umount or file copy logs | Drive Access |
| `linux:syslog` | network | Network Connection Creation |
| `linux:syslog` | opened document\|clicked link\|segfault\|abnormal termination\|sandbox | Application Log Content |
| `linux:syslog` | postfix/smtpd | Network Connection Creation |
| `linux:syslog` | processes binding to non-standard ports or sshd configured on unexpected port | Application Log Content |
| `linux:syslog` | rename | File Modification |
| `linux:syslog` | service stopped messages | Service Metadata |
| `linux:syslog` | sshd logs | Command Execution |
| `linux:syslog` | sshd sessions with unusual port forwarding parameters | Application Log Content |
| `linux:syslog` | sshd: Accepted password/publickey | Logon Session Creation |
| `linux:syslog` | sshd[pid]: Failed password | User Account Authentication |
| `linux:syslog` | sssd / sudo logs | Logon Session Metadata |
| `linux:syslog` | sudo chage\|grep pam_pwquality\|cat /etc/login.defs | Command Execution |
| `linux:syslog` | sudo execution of ffmpeg/gst-launch/v4l2-ctl by non-standard user | Command Execution |
| `linux:syslog` | sudo or service accounts invoking loaders with suspicious env vars | Process Metadata |
| `linux:syslog` | sudo or su access prior to content change | User Account Modification |
| `linux:syslog` | sudo/date/timedatectl execution by non-standard users | User Account Authentication |
| `linux:syslog` | suspicious DHCP lease assignment with unexpected DNS or gateway | Application Log Content |
| `linux:syslog` | syscalls (open, read, ioctl) on /dev/input or /proc/*/fd/* | Process Access |
| `linux:syslog` | system daemons initiating TLS sessions outside expected services | Application Log Content |
| `linux:syslog` | system is powering down | Host Status |
| `linux:syslog` | systemctl start/enable with uncommon binary paths | Service Creation |
| `linux:syslog` | systemd-udevd spawning user-defined action from RUN+= | Process Creation |
| `linux:syslog` | usb * new\|thunderbolt\|pci .* added\|block.*: new .* device | Application Log Content |
