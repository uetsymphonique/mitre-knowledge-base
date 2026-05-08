# DC0064 - Command Execution

## Description

Command Execution involves monitoring and capturing the execution of textual commands (including shell commands, cmdlets, and scripts) within an operating system or application. These commands may include arguments or parameters and are typically executed through interpreters such as `cmd.exe`, `bash`, `zsh`, `PowerShell`, or programmatic execution. Examples: 

- Windows Command Prompt
    - dir – Lists directory contents.
    - net user – Queries or manipulates user accounts.
    - tasklist – Lists running processes.
- PowerShell
    - Get-Process – Retrieves processes running on a system.
    - Set-ExecutionPolicy – Changes PowerShell script execution policies.
    - Invoke-WebRequest – Downloads remote resources.
- Linux Shell
    - ls – Lists files in a directory.
    - cat /etc/passwd – Reads the user accounts file.
    - curl http://malicious-site.com – Retrieves content from a malicious URL.
- Container Environments
    - docker exec – Executes a command inside a running container.
    - kubectl exec – Runs commands in Kubernetes pods.
- macOS Terminal
    - open – Opens files or URLs.
    - dscl . -list /Users – Lists all users on the system.
    - osascript -e – Executes AppleScript commands.

## Log Sources

| Log Source | Channel |
|------------|---------|
| `Command` | None |
| `auditd:SYSCALL` | execution of realmd, samba-tool, or ldapmodify with user-related arguments |
| `macos:unifiedlog` | dsconfigad or dscl with create or append options for AD-bound users |
| `EDR:AMSI` | None |
| `linux:syslog` | cron activity |
| `WinEventLog:PowerShell` | Get-ADTrust\|GetAllTrustRelationships |
| `gcp:audit` | None |
| `auditd:SYSCALL` | Execution of script interpreters by systemd timer (ExecStart) |
| `AWS:CloudTrail` | InvokeFunction |
| `m365:unified` | Automated forwarding or file sync initiated by a logic app |
| `WinEventLog:PowerShell` | EventCode=4103, 4104, 4105, 4106 |
| `linux:syslog` | Suspicious script or command execution targeting browser folders |
| `esxi:shell` | snapshot create/copy, esxcli |
| `auditd:SYSCALL` | execve: Commands like systemctl stop <service>, service <service> stop, or kill -9 <pid> |
| `macos:unifiedlog` | launchctl unload, kill, or pkill commands affecting daemons or background services |
| `macos:unifiedlog` | execution of security-agent detection or enumeration commands |
| `macos:unifiedlog` | log stream --predicate |
| `WinEventLog:PowerShell` | Execution of Microsoft script to enumerate custom forms in Outlook mailbox |
| `m365:messagetrace` | Inbound email triggers execution of mailbox-stored custom form |
| `auditd:EXECVE` | Use of mv or cp to rename files with '.' prefix |
| `macos:unifiedlog` | Execution of chflags hidden or SetFile -a V |
| `esxi:shell` | interactive shell |
| `networkdevice:cli` | CLI command |
| `macos:unifiedlog` | log stream |
| `esxi:vmkernel` | /var/log/vmkernel.log |
| `auditd:SYSCALL` | execve calls to locale, timedatectl, or cat /etc/timezone |
| `macos:unifiedlog` | defaults read -g AppleLocale, systemsetup -gettimezone |
| `macos:unifiedlog` | profiles install -type=configuration |
| `auditd:SYSCALL` | sleep function usage or loops (nanosleep, usleep) in scripts |
| `m365:unified` | Search-Mailbox, Get-MessageTrace, eDiscovery requests |
| `EDR:cli` | Command Line Telemetry |
| `macos:unifiedlog` | log stream --predicate 'eventMessage contains "loginwindow" or "pfctl"' |
| `networkdevice:syslog` | Command Audit / Configuration Change |
| `WinEventLog:Microsoft-Office/OutlookAddinMonitor` | Outlook loading add-in via unexpected load path or non-default profile context |
| `macos:unifiedlog` | exec or sudo usage with NOPASSWD context or echo modifying sudoers |
| `WinEventLog:Security` | EventCode=4103, 4104, 4105, 4106 |
| `auditd:EXECVE` | execve: Execution of update-ca-certificates or trust anchor modification commands |
| `macos:unifiedlog` | Execution of /usr/bin/security add-trusted-cert or keychain modifications to System.keychain |
| `auditd:EXECVE` | gcore, gdb, strings, hexdump execution |
| `auditd:SYSCALL` | connect, execve, write |
| `esxi:hostd` | command execution |
| `auditd:EXECVE` | Execution of auditctl, systemctl stop auditd, or kill -9 auditd |
| `macos:syslog` | system.log |
| `esxi:hostd` | /var/log/hostd.log |
| `esxi:shell` | /var/log/shell.log |
| `docker:daemon` | docker exec or docker run with unexpected command/entrypoint |
| `auditd:SYSCALL` | execve call including 'nohup' or trailing '&' |
| `macos:unifiedlog` | nohup, disown, or osascript execution patterns |
| `WinEventLog:PowerShell` | CommandLine=copy-item or robocopy from UNC path |
| `esxi:shell` | invoked remote scripts (esxcli) |
| `auditd:EXECVE` | execution of systemctl with subcommands start, stop, enable, disable |
| `networkdevice:cli` | Policy Update |
| `auditd:SYSCALL` | None |
| `AWS:CloudTrail` | eventName: RunInstances, CreateUser, PutRolePolicy, InvokeCommand |
| `gcp:audit` | methodName: setIamPolicy, startInstance, createServiceAccount |
| `auditd:SYSCALL` | execve: Commands executed within an SSH session where no matching logon/authentication event exists |
| `esxi:hostd` | modification of config files or shell command execution |
| `kubernetes:audit` | Shell process (e.g., /bin/sh, /bin/bash) spawned in a container without an interactive session attached (i.e., automation anomaly) |
| `macos:unifiedlog` | Execution of 'profiles install -type=configuration' |
| `macos:unifiedlog` | subsystem:com.apple.Terminal |
| `networkdevice:syslog` | eventlog |
| `esxi:hostd` | shell access or job registration |
| `WinEventLog:PowerShell` | PowerShell launched from outlook.exe or triggered without user invocation |
| `m365:messagetrace` | Inbound email matches crafted rule trigger pattern tied to persistence logic |
| `linus:syslog` | None |
| `linux:syslog` | Unusual outbound transfers from CLI tools like base64, gzip, or netcat |
| `macos:unifiedlog` | base64 or curl processes chained within short execution window |
| `esxi:shell` | base64 or gzip use within shell session |
| `macos:unifiedlog` | exec: Invocation of /usr/bin/defaults write or /usr/bin/plutil modifying plist keys |
| `auditd:SYSCALL` | chmod, execve |
| `macos:unifiedlog` | chmod command with arguments including '+s', 'u+s', or numeric values 4000–6777 |
| `macos:unifiedlog` | command includes dscl . delete or sysadminctl --deleteUser |
| `fs:fsusage` | file system activity monitor |
| `networkdevice:cli` | ip ssh pubkey-chain |
| `esxi:shell` | scripts or binaries with misleading names |
| `auditd:EXECVE` | Execution of GUI-related binaries with suppressed window/display flags |
| `linuxsyslog` | nslcd or winbind logs |
| `macos:unifiedlog` | DS daemon log entries |
| `esxi:hostd` | logline inspection |
| `macos:unifiedlog` | diskutil eraseDisk / asr restore with destructive flags |
| `networkdevice:cli` | erase flash:, erase startup-config, format disk |
| `networkdevice:syslog` | command_exec |
| `auditd:SYSCALL` | execve: iptables, nft, firewall-cmd modifications |
| `macos:unifiedlog` | pfctl -d, socketfilterfw --setglobalstate off, or modifications to com.apple.alf |
| `esxi:hostd` | esxcli network firewall set commands |
| `docker:events` | container exec rm\|container stop --force |
| `esxi:hostd` | event stream |
| `networkdevice:cli` | CLI command logs |
| `esxi:shell` | /var/log/shell.log entries containing "esxcli system clock get" |
| `networkdevice:syslog` | command-exec: CLI commands containing "show clock", "show clock detail", "show timezone" executed by suspicious user/source |
| `networkdevice:cli` | cmd: cmd=show clock detail |
| `auditd:EXECVE` | curl -X POST, wget --post-data |
| `linux:syslog` | sudo chage\|grep pam_pwquality\|cat /etc/login.defs |
| `macos:unifiedlog` | pwpolicy\|PasswordPolicy |
| `networkdevice:syslog` | cmd='show aaa*' OR 'show running-config \| include password\|aaa' OR 'show aaa common-criteria policy all' |
| `networkdevice:syslog` | CLI command audit |
| `networkdevice:cli` | Execution of commands to load, copy, or replace system images (e.g., 'copy tftp flash', 'boot system') |
| `WinEventLog:PowerShell` | Execution of PowerShell script to enumerate or remove malicious Home Page folder config |
| `m365:messagetrace` | Inbound email triggering Outlook to auto-access folder tied to malicious Home Page |
| `macos:unifiedlog` | Command line contains smbutil view //, mount_smbfs // |
| `auditd:SYSCALL` | execve: Invocation of scp, rsync, curl, or sftp |
| `esxi:hostd` | scp/ssh used to move file across hosts |
| `auditd:EXECVE` | command line arguments containing lsblk, fdisk, parted |
| `macos:unifiedlog` | log messages related to disk enumeration context or Terminal session |
| `auditd:SYSCALL` | execve calls modifying local mail filter configuration files |
| `esxi:hostd` | None |
| `esxi:shell` | None |
| `networkdevice:cli` | None |
| `linux:syslog` | sudo execution of ffmpeg/gst-launch/v4l2-ctl by non-standard user |
| `docker:api` | docker logs access or container inspect commands from non-administrative users |
| `esxi:shell` | command IN ("esxcli vm process list", "vim-cmd vmsvc/getallvms") |
| `auditd:SYSCALL` | execve: process_name IN ("virsh", "VBoxManage", "qemu-img") AND command IN ("list", "info") |
| `esxi:shell` | openssl\|tar\|dd |
| `AWS:CloudTrail` | SSM RunCommand |
| `azure:activity` | Intune PowerShell Scripts |
| `m365:exchange` | Cmdlet: Get-GlobalAddressList, Get-Recipient |
| `networkdevice:cli` | Execution of commands like 'show running-config', 'copy running-config', or 'export config' |
| `esxi:syslog` | boot logs |
| `networkdevice:syslog` | system boot logs |
| `auditd:SYSCALL` | execve: service stop syslog, systemctl stop rsyslog, kill -9 syslog |
| `macos:unifiedlog` | defaults write com.apple.system.logging or logd manipulation |
| `esxi:hostd` | esxcli system syslog config set or reload |
| `auditd:SYSCALL` | execve: openssl pkcs12, certutil, keytool |
| `macos:unifiedlog` | process calling security find-certificate, export, or import |
| `networkdevice:cli` | Execution of CLI commands altering crypto parameters (e.g., 'crypto key generate rsa modulus 512') |
| `auditd:SYSCALL` | execve: Process in container namespace executes curl\|wget\|bash\|sh\|python\|nc with outbound args |
| `m365:exchange` | Get-RoleGroup, Get-DistributionGroup |
| `auditd:SYSCALL` | execution of systemctl or service with enable/start parameters |
| `auditd:SYSCALL` | execve: Execution of cat, less, grep, journalctl targeting log directories (/var/log/) |
| `macos:unifiedlog` | Execution of log show, fs_usage, or cat targeting system.log |
| `AWS:CloudTrail` | GetLogEvents: High frequency log exports from CloudWatch or equivalent services |
| `esxi:shell` | Execution of cat, tail, grep targeting /var/log/vmkernel.log or /var/log/hostd.log |
| `esxi:shell` | CLI usage logs |
| `macos:syslog` | /var/log/system.log |
| `macos:unifiedlog` | execution of launchctl load/unload/start commands |
| `WinEventLog:PowerShell` | Exchange Cmdlets |
| `auditd:SYSCALL` | execve: Execution of python, perl, or custom binaries invoking compression libraries |
| `auditd:SYSCALL` | execve, USER_CMD |
| `auditd:USER_CMD` | USER_CMD |
| `esxi:shell` | Command execution trace |
| `auditd:SYSCALL` | bash/zsh of base64, tar, gzip, or openssl immediately after file write |
| `linux:osquery` | Command-line includes base64 -d or openssl enc -d |
| `macos:unifiedlog` | base64 -d or osascript invoked on staged file |
| `auditd:EXECVE` | exec: Execution of dd, efibootmgr, or flashrom modifying firmware/boot partitions |
| `auditd:EXECVE` | curl -d, wget --post-data |
| `auditd:SYSCALL` | execve: Processes executing sendmail/postfix with forged headers |
| `macos:unifiedlog` | diskutil partitionDisk or eraseVolume with partition scheme modifications |
| `networkdevice:cli` | format flash:, format disk, reformat commands |
| `auditd:SYSCALL` | execve: Execution of tar, gzip, bzip2, xz, zip, or openssl with compression/encryption arguments |
| `auditd:PROCTITLE` | proctitle contains chmod, chown, setfacl, or attr commands with suspicious parameters |
| `esxi:shell` | shell command execution for chmod, chown, or file permission modification on VMFS or system files |
| `networkdevice:Firewall` | Audit trail or CLI/API access indicating commands like no access-list, delete rule-set, clear config |
| `auditd:EXECVE` | grep/cat/awk on files with password fields |
| `macos:unifiedlog` | grep/cat on files matching credential patterns |
| `kubernetes:audit` | process execution involving curl, grep, or awk on secrets |
| `AWS:CloudTrail` | command-line execution invoking credential enumeration |
| `auditd:SYSCALL` | promiscuous mode transitions (ioctl or ifconfig) |
| `fs:fsusage` | access to BPF devices or interface IOCTLs |
| `networkdevice:syslog` | exec command='monitor capture' |
| `WinEventLog:Microsoft-Office-Alerts` | Unexpected DLL or component loaded at Office startup |
| `m365:office` | Startup execution includes non-default component |
| `macos:unifiedlog` | diskutil eraseDisk/zeroDisk or asr restore with destructive flags |
| `networkdevice:cli` | erase flash:, erase nvram:, format disk |
| `macos:unifiedlog` | spctl --master-disable, csrutil disable, or defaults write to disable Gatekeeper |
| `esxi:shell` | esxcli system syslog config set --loghost='' or stopping hostd service |
| `networkdevice:syslog` | no logging buffered, no aaa new-model, disable firewall |
| `auditd:EXECVE` | git push, curl -X POST |
| `linux:cli` | command logging |
| `esxi:hostd` | command log |
| `networkdevice:cli` | command logs |
| `networkdevice:syslog` | interactive shell logging |
| `esxi:hostd` | Execution of '/bin/vmx' or modifications to '/etc/rc.local.d/local.sh' |
| `auditd:SYSCALL` | chattr, rm, shred, dd run on recovery directories or partitions |
| `networkdevice:syslog` | command sequence: erase → format → reload |
| `macos:unifiedlog` | process: at, job runner |
| `macos:osquery` | Interpreter exec with suspicious arguments as above |
| `auditd:SYSCALL` | execve: Execution of curl or wget writing files to /tmp/* followed by chmod or execution |
| `auditd:SYSCALL` | execve: Execution of downgraded interpreters such as python2 or forced fallback commands |
| `auditd:PROCTITLE` | proctitle contains chmod, chown, chgrp, setfacl, or attr with suspicious parameters (777, 755, +x, -R) |
| `auditd:EXECVE` | Execution of gsettings set org.gnome.login-screen disable-user-list true |
| `macos:unifiedlog` | Execution of dscl . create with IsHidden=1 |
| `linux:syslog` | sshd logs |
| `esxi:shell` | Shell Access/Command Execution |
| `networkdevice:syslog` | CLI Command Logging |
| `auditd:CONFIG_CHANGE` | udev rule reload or trigger command executed |
| `linux:cli` | Shell history logs |
| `macos:unifiedlog` | log stream --predicate 'processImagePath contains "zip" OR "base64"' |
| `networkdevice:cli` | command logging |
| `esxi:hostd` | Command Execution |
| `macos:osquery` | launchd + process_events |
| `esxi:vmkernel` | DCUI shell start, BusyBox activity |
| `esxi:hostd` | remote CLI + vim-cmd logging |
| `networkdevice:syslog` | CLI Command Audit |
| `m365:defender` | Activity Log: Command Invocation |
| `WinEventLog:PowerShell` | CmdletName: Get-Recipient, Get-User |
| `WinEventLog:PowerShell` | Execution of 'Get-WmiObject Win32_Product' or similar PowerShell cmdlets |
| `linux:shell` | Manual invocation of software enumeration commands via interactive shell |
| `auditd:SYSCALL` | Command line arguments including SPApplicationsDataType |
| `AWS:CloudTrail` | ssm:GetCommandInvocation |
| `esxi:shell` | esxcli software vib list |
| `auditd:EXECVE` | execution of setfattr or getfattr commands |
| `macos:unifiedlog` | xattr utility execution with -w or -p flags |
| `auditd:SYSCALL` | Execution of spoofing tools (e.g., hping3, nping, scapy) sending UDP packets to known amplifier ports |
| `auditd:SYSCALL` | execution of tools like cat, grep, or awk on credential files |
| `macos:unifiedlog` | execution of 'security', 'cat', or 'grep' commands accessing credential storage |
| `linux:syslog` | CLI access to 'show running-config', 'show password', or 'cat config.txt' |
| `auditd:SYSCALL` | execve of curl, rsync, wget with internal knowledge base or IPs |
| `esxi:shell` | /root/.ash_history |
| `auditd:SYSCALL` | execve: Execution of systemctl, loginctl, or systemd-inhibit commands related to sleep/hibernate |
| `auditd:SYSCALL` | Execution of xev, xdotool, or input activity emulators |
| `macos:unifiedlog` | launchctl load or boot-time plist registration |
| `auditd:SYSCALL` | execve: Execution of interpreters creating archive-like outputs without calling tar/gzip |
| `networkdevice:syslog` | command audit |
| `networkdevice:cli` | Interface commands |
| `macos:unifiedlog` | dscl -create |
| `esxi:vmkernel` | esxcli system account add |
| `ebpf:syscalls` | useradd or /etc/passwd modified inside container |
| `auditd:SYSCALL` | Execution of insmod, modprobe, or rmmod commands by non-standard users or outside expected timeframes |
| `macos:unifiedlog` | kextload execution from Terminal or suspicious paths |
| `WinEventLog:PowerShell` | Execution of PowerShell without -NoProfile flag |
| `auditd:EXECVE` | Process execution of update-ca-certificates or openssl with suspicious arguments |
| `macos:unifiedlog` | xattr -d com.apple.quarantine or similar removal commands |
| `azure:signinlogs` | OperationName=SetDomainAuthentication OR Update-MsolFederatedDomain |
| `linux:syslog` | Sudo or root escalation followed by filesystem mount commands |
| `WinEventLog:PowerShell` | EventCode=4101 |
| `networkdevice:cli` | Execution of privileged commands such as 'copy tftp flash', 'boot system', or 'debug memory' |
| `auditd:SYSCALL` | execve syscalls for discovery commands (uname, hostname, id, whoami, ps, netstat, mount) with command-line parameter analysis |
| `auditd:PROCTITLE` | process title records containing discovery command sequences and environmental assessment patterns |
| `macos:unifiedlog` | Security framework operations including keychain access, cryptographic operations, and certificate validation |
| `m365:unified` | Set-Mailbox, New-InboxRule |
| `macos:unifiedlog` | None |
| `networkdevice:cli` | Execution of commands disabling crypto hardware acceleration (e.g., 'no crypto engine enable') |
| `auditd:SYSCALL` | execve: Execution of curl, wget, or custom scripts accessing financial endpoints |
| `auditd:EXECVE` | Execution of chattr to set +i or +a attributes |
| `macos:unifiedlog` | Execution of chflags hidden or setfile -a V |
| `esxi:shell` | mv, rename, or chmod commands moving VM files into hidden directories |
| `esxi:hostd` | execution + payload hints |
| `linux:osquery` | process_events.command_line |
| `macos:unifiedlog` | process:spawn, process:exec |
| `esxi:vobd` | shell session start |
| `networkdevice:cli` | shell command |
| `WinEventLog:Microsoft-Office-Alerts` | Office application warning or alert on macro execution from template |
| `m365:unified` | Set-Mailbox, Set-MailboxPolicy, Set-TrustedLocation |
| `m365:office` | Execution of unsigned macro from template |
| `linux:cli` | Terminal Command History |
| `macos:unifiedlog` | csrutil disable |
| `macos:unifiedlog` | log show --predicate 'process == <utility>' |
| `networkdevice:syslog` | Privilege-level command execution |
| `auditd:SYSCALL` | execve: Execution of tar, gzip, bzip2, or openssl with output redirection |
| `saas:PRMetadata` | Commit message or branch name contains encoded strings or payload indicators |
| `macos:unifiedlog` | Execution of launchctl with setenv or bootout targeting TCC.db or AppleScript under Finder context |
| `esxi:shell` | `esxcli software vib install` with `--force` or `--no-sig-check` from shell history or `shell.log` |
| `AWS:CloudTrail` | SendCommand, StartSession, ExecuteCommand: Unexpected AWS Systems Manager command execution targeting EC2 instances |
| `esxi:vmkernel` | Unexpected restarts of management agents or shell access |
| `auditd:EXECVE` | curl or wget with POST/PUT options |
| `networkdevice:syslog` | Detected CLI command to export key material |
| `networkdevice:config` | PKI export or certificate manipulation commands |
| `macos:unifiedlog` | command execution triggered by emond (e.g., shell, curl, python) |
| `esxi:vmkernel` | esxcli, vim-cmd invocation |
| `esxi:shell` | CLI session activity |
| `auditd:SYSCALL` | execve=/sbin/shutdown or /sbin/reboot |
| `esxi:shell` | esxcli system shutdown or reboot invoked |
| `networkdevice:syslog` | reload command issued |
| `auditd:PROCTITLE` | command-line execution patterns for system discovery utilities (uname, hostname, ifconfig, netstat, lsof, ps, mount) |
| `esxi:shell` | shell command execution for system discovery (vim-cmd, esxcli, vmware-cmd) targeting VM inventory and host configuration |
| `vpxd.log` | VM inventory queries and configuration enumeration through vCenter API calls |
| `auditd:SYSCALL` | execve calls modifying HISTFILE or HISTCONTROL via unset/export |
| `macos:unifiedlog` | Set or unset HIST* variables in shell environment |
| `esxi:shell` | unset HISTFILE or HISTFILESIZE modifications |
| `networkdevice:cli` | Commands like 'no logging' or equivalents that disable session history |
| `auditd:SYSCALL` | execve calls to /usr/bin/locale or shell execution of $LANG |
| `macos:unifiedlog` | defaults read -g AppleLocale or systemsetup -gettimezone |
| `networkdevice:cli` | Execution of commands such as 'copy tftp flash', 'boot system <image>', 'reload' |
| `auditd:EXECVE` | curl -T, rclone copy |
| `auditd:SYSCALL` | execution of systemctl or service with enable/start/modify |
| `macos:unifiedlog` | launchctl load/unload or plist file modification |
| `networkdevice:syslog` | syslog facility LOCAL7 or trap messages |
| `linux:cli` | /home/*/.bash_history |
| `auditd:SYSCALL` | execve: Execution of lsmod, modinfo, or cat /proc/modules |
| `networkdevice:config` | Configuration changes referencing 'boot system tftp' or modification of startup-config pointing to external TFTP servers |
| `macos:unifiedlog` | dscl . -create |
| `macos:unifiedlog` | Execution of commands like `ls -l@`, `xattr -l`, or custom tools interacting with resource forks |
| `esxi:vpxd` | vCenter Management |
