# esxi

167 unique events

| Log Source | Channel | Data Components |
|------------|---------|-----------------|
| `esxi:auth` | /var/log/auth.log | User Account Authentication |
| `esxi:auth` | None | Logon Session Metadata |
| `esxi:auth` | SSH session/login | User Account Authentication |
| `esxi:auth` | Shell login or escalation | Logon Session Creation |
| `esxi:auth` | interactive shell or SSH access preceding storage enumeration | User Account Authentication |
| `esxi:auth` | user session | Process Metadata |
| `esxi:cron` | execution of scheduled job | Scheduled Job Creation |
| `esxi:cron` | manual edits to /etc/rc.local.d/local.sh or cron.d | File Modification |
| `esxi:cron` | process or cron activity | Process Creation |
| `esxi:esxupdate` | /var/log/esxupdate.log contains VIB installed with `--force` or `--no-sig-check` and non-standard acceptance levels | Application Log Content |
| `esxi:esxupdate` | /var/log/esxupdate.log or /var/log/vmksummary.log | Network Connection Creation |
| `esxi:hostd` | /var/log/hostd.log | Command Execution, Logon Session Metadata |
| `esxi:hostd` | /var/log/hostd.log API calls reading/altering time/ntp settings | Process Metadata |
| `esxi:hostd` | /var/log/hostd.log anomalies (faults, crashes, restarts) around inbound connections | Application Log Content |
| `esxi:hostd` | CLI network calls | Network Traffic Flow |
| `esxi:hostd` | Command Execution | Command Execution |
| `esxi:hostd` | Datastore file operations | File Deletion |
| `esxi:hostd` | Execution of '/bin/vmx' or modifications to '/etc/rc.local.d/local.sh' | Command Execution |
| `esxi:hostd` | Guest Operations API invocation: StartProgramInGuest, ListProcessesInGuest, ListFileInGuest, InitiateFileTransferFromGuest | Application Log Content |
| `esxi:hostd` | Host daemon command log entries related to vib enumeration | Application Log Content |
| `esxi:hostd` | Keywords: 'Backtrace','Signal 11','PANIC','hostd restarted','assert' or 'Service terminated unexpectedly' in /var/log/hostd.log, /var/log/vmkernel.log, /var/log/syslog.log. | Application Log Content |
| `esxi:hostd` | Log entries indicating VM powered off or forcibly terminated | Process Termination |
| `esxi:hostd` | New extension/module install with unknown vendor ID | Application Log Content |
| `esxi:hostd` | None | Command Execution |
| `esxi:hostd` | Powering off or restarting host | Host Status |
| `esxi:hostd` | Remote access API calls and file uploads | OS API Execution |
| `esxi:hostd` | Service events | Service Metadata |
| `esxi:hostd` | Service initiated connections | Network Connection Creation |
| `esxi:hostd` | Service-Based Network Connection | Network Connection Creation |
| `esxi:hostd` | Stop VM or disable service events via vim-cmd | Service Metadata |
| `esxi:hostd` | System service interactions | Network Connection Creation |
| `esxi:hostd` | binary or module replacement event | File Modification |
| `esxi:hostd` | boot | File Modification |
| `esxi:hostd` | command execution | Command Execution |
| `esxi:hostd` | command log | Command Execution |
| `esxi:hostd` | datastore file access | File Access |
| `esxi:hostd` | datastore/log file access | File Access |
| `esxi:hostd` | delete action | File Deletion |
| `esxi:hostd` | esxcli network firewall set commands | Command Execution |
| `esxi:hostd` | esxcli system syslog config set or reload | Command Execution |
| `esxi:hostd` | event stream | Command Execution |
| `esxi:hostd` | execution + payload hints | Command Execution |
| `esxi:hostd` | execution of esxcli with args matching 'storage', 'filesystem', 'core device list' | Process Creation |
| `esxi:hostd` | file copy or datastore upload via HTTPS | File Access |
| `esxi:hostd` | host daemon events related to VM operations and configuration queries during reconnaissance | Process Creation |
| `esxi:hostd` | host daemon events related to file or VM permission changes | File Metadata |
| `esxi:hostd` | logline inspection | Command Execution |
| `esxi:hostd` | method=RemoveUser or esxcli system account remove invocation | User Account Deletion |
| `esxi:hostd` | modification of config files or shell command execution | Command Execution |
| `esxi:hostd` | modification of crontab or local.sh entries | File Modification |
| `esxi:hostd` | process | Process Creation |
| `esxi:hostd` | process execution across cloud VM | Process Creation |
| `esxi:hostd` | read: Access to sensitive log files by non-admin users | File Access |
| `esxi:hostd` | registers services with legitimate-sounding names | Service Metadata |
| `esxi:hostd` | remote CLI + vim-cmd logging | Command Execution |
| `esxi:hostd` | rm, clearlogs, logrotate | File Deletion |
| `esxi:hostd` | scp/ssh used to move file across hosts | Command Execution |
| `esxi:hostd` | shell access or job registration | Command Execution |
| `esxi:hostd` | snapshot.removeall or snapshot file deletion | Snapshot Deletion |
| `esxi:hostd` | task creation events | Scheduled Job Creation |
| `esxi:hostd` | unexpected script invocations producing long encoded strings | Application Log Content |
| `esxi:hostd` | unexpected script/command invocations via hostd | Application Log Content |
| `esxi:hostd` | vSphere API calls modifying firewall settings | Firewall Rule Modification |
| `esxi:hostd` | vSphere File API Access | File Access |
| `esxi:shell` | /root/.ash_history | Command Execution |
| `esxi:shell` | /root/.ash_history or /etc/init.d/* | Process Creation |
| `esxi:shell` | /var/log/shell.log | Command Execution, File Deletion, Process Creation |
| `esxi:shell` | /var/log/shell.log entries containing "esxcli system clock get" | Command Execution |
| `esxi:shell` | /var/log/vmkernel.log, /var/log/vmkwarning.log | Process Creation |
| `esxi:shell` | CLI session activity | Command Execution |
| `esxi:shell` | CLI usage logs | Command Execution |
| `esxi:shell` | Command execution trace | Command Execution |
| `esxi:shell` | Execution of cat, tail, grep targeting /var/log/vmkernel.log or /var/log/hostd.log | Command Execution |
| `esxi:shell` | None | Command Execution, Process Creation, Script Execution |
| `esxi:shell` | Shell Access/Command Execution | Command Execution |
| `esxi:shell` | Shell Execution | Process Creation |
| `esxi:shell` | `esxcli software vib install` with `--force` or `--no-sig-check` from shell history or `shell.log` | Command Execution |
| `esxi:shell` | admin command usage | File Modification |
| `esxi:shell` | base64 or gzip use within shell session | Command Execution |
| `esxi:shell` | command IN ("esxcli vm process list", "vim-cmd vmsvc/getallvms") | Command Execution |
| `esxi:shell` | commands containing base64, openssl enc -base64, xxd -p | Process Creation |
| `esxi:shell` | commands containing long non-standard tokens or custom lookup tables | Process Creation |
| `esxi:shell` | esxcli software vib list | Command Execution |
| `esxi:shell` | esxcli system shutdown or reboot invoked | Command Execution |
| `esxi:shell` | esxcli system syslog config set --loghost='' or stopping hostd service | Command Execution |
| `esxi:shell` | file write or edit | File Modification |
| `esxi:shell` | interactive shell | Command Execution |
| `esxi:shell` | invoked remote scripts (esxcli) | Command Execution |
| `esxi:shell` | mv, rename, or chmod commands moving VM files into hidden directories | Command Execution |
| `esxi:shell` | openssl\|tar\|dd | Command Execution |
| `esxi:shell` | scripts or binaries with misleading names | Command Execution |
| `esxi:shell` | shell command execution for chmod, chown, or file permission modification on VMFS or system files | Command Execution |
| `esxi:shell` | shell command execution for system discovery (vim-cmd, esxcli, vmware-cmd) targeting VM inventory and host configuration | Command Execution |
| `esxi:shell` | shell history | File Deletion |
| `esxi:shell` | snapshot create/copy, esxcli | Command Execution |
| `esxi:shell` | unset HISTFILE or HISTFILESIZE modifications | Command Execution |
| `esxi:syslog` | /var/log/syslog.log | Network Traffic Flow |
| `esxi:syslog` | /var/log/vpxa.log task invocations tied to time configuration | Scheduled Job Metadata |
| `esxi:syslog` | DNS resolution events leading to outbound traffic on unexpected ports | Network Traffic Flow |
| `esxi:syslog` | Datastore file hidden or renamed unexpectedly | File Metadata |
| `esxi:syslog` | Frequent DNS queries with high entropy names or NXDOMAIN results | Network Traffic Flow |
| `esxi:syslog` | Frequent DNS resolution of same domain with rotating IPs | Network Traffic Flow |
| `esxi:syslog` | boot logs | Command Execution |
| `esxi:syslog` | esxcli network vswitch or DNS resolver configuration updates | Network Traffic Flow |
| `esxi:syslog` | guest OS outbound transfer logs | File Access |
| `esxi:vmkernel` | /var/log/vmkernel.log | Command Execution, File Modification, Network Traffic Flow |
| `esxi:vmkernel` | DCUI shell start, BusyBox activity | Command Execution |
| `esxi:vmkernel` | DNS lookups resolving to domains with rapid changes in registration metadata | Domain Registration |
| `esxi:vmkernel` | Datastore modification events | File Metadata |
| `esxi:vmkernel` | Disabling or modifying firewall rules | Firewall Disable |
| `esxi:vmkernel` | Exec | Process Creation |
| `esxi:vmkernel` | HTTPS POST connections to pastebin-like domains | Network Traffic Content |
| `esxi:vmkernel` | HTTPS POST connections to webhook endpoints | Network Traffic Content |
| `esxi:vmkernel` | HTTPS traffic to repository domains | Network Traffic Flow |
| `esxi:vmkernel` | Inspection of sockets showing encrypted sessions from non-baseline processes | Network Traffic Content |
| `esxi:vmkernel` | Network activity | Network Traffic Content |
| `esxi:vmkernel` | None | Network Connection Creation, Network Traffic Flow |
| `esxi:vmkernel` | Outbound traffic using encoded payloads post-login | Network Traffic Content |
| `esxi:vmkernel` | Startup script and task execution logs | Scheduled Job Creation |
| `esxi:vmkernel` | Storage access and file ops | File Metadata |
| `esxi:vmkernel` | Suspicious traffic filtered or redirected by VM networking stack | Network Traffic Content |
| `esxi:vmkernel` | Unauthorized file modifications within datastore volumes via shell access or vCLI | File Modification |
| `esxi:vmkernel` | Unexpected restarts of management agents or shell access | Command Execution |
| `esxi:vmkernel` | Upload of file to datastore | File Metadata |
| `esxi:vmkernel` | VM exit/entry anomalies, unexpected hypercalls, or kernel module loading | Kernel Module Load |
| `esxi:vmkernel` | VMCI syslog entries | Network Traffic Content |
| `esxi:vmkernel` | VMFS access logs | File Access |
| `esxi:vmkernel` | VMFS file creation | File Creation |
| `esxi:vmkernel` | VMX startup messages without associated vCenter inventory records | Image Metadata |
| `esxi:vmkernel` | VMware kernel events for file system permission modifications | File Metadata |
| `esxi:vmkernel` | VMware kernel events for hardware and system configuration access during environmental validation | Process Creation |
| `esxi:vmkernel` | boot | Script Execution |
| `esxi:vmkernel` | egress log analysis | Network Traffic Flow |
| `esxi:vmkernel` | egress logs | Network Traffic Flow |
| `esxi:vmkernel` | esxcli system account add | Command Execution |
| `esxi:vmkernel` | esxcli, vim-cmd invocation | Command Execution |
| `esxi:vmkernel` | file delete\|datastore purge | Volume Deletion |
| `esxi:vmkernel` | file write | File Creation |
| `esxi:vmkernel` | module load | Module Load |
| `esxi:vmkernel` | network activity | Network Connection Creation |
| `esxi:vmkernel` | network flows to external cloud services | Network Traffic Flow |
| `esxi:vmkernel` | network session initiation with external HTTPS services | Network Connection Creation |
| `esxi:vmkernel` | network stack module logs | Network Traffic Content |
| `esxi:vmkernel` | port 22 access | Network Traffic Flow |
| `esxi:vmkernel` | protocol egress | Network Connection Creation |
| `esxi:vmkernel` | rename .vmdk to .*.locked\|datastore write spike | File Modification |
| `esxi:vmkernel` | snapshot create/write events | Snapshot Creation |
| `esxi:vmkernel` | spawned shell or execution environment activity | Process Creation |
| `esxi:vmkernel` | unexpected module load | Module Load |
| `esxi:vmkernel` | vim.fault.*, DCUI login, SSH shell | Logon Session Creation |
| `esxi:vmkernel` | vmkernel / OpenSLP logs for malformed requests | Application Log Content |
| `esxi:vob` | NFS/remote access logs | Network Traffic Content |
| `esxi:vobd` | /var/log/vobd.log | Process Creation |
| `esxi:vobd` | Network Events | Network Traffic Flow |
| `esxi:vobd` | shell session start | Command Execution |
| `esxi:vpxa` | connection attempts and data transmission logs | Network Traffic Flow |
| `esxi:vpxa` | user login from unexpected IP or non-admin user role | User Account Authentication |
| `esxi:vpxa` | vim.SessionManager.login / vim.AccountManager.createUser | Active Directory Object Modification |
| `esxi:vpxd` | /var/log/vmware/vpxd.log | User Account Authentication |
| `esxi:vpxd` | ESXi process initiating asymmetric handshake with external host | Application Log Content |
| `esxi:vpxd` | ESXi processes relaying traffic via SSH or unexpected ports | Network Traffic Flow |
| `esxi:vpxd` | ESXi service connections on unexpected ports | Network Traffic Flow |
| `esxi:vpxd` | None | Network Traffic Flow |
| `esxi:vpxd` | Symmetric crypto routines triggered for external session | Application Log Content |
| `esxi:vpxd` | TLS session established by ESXi service to unapproved endpoint | Network Traffic Flow |
| `esxi:vpxd` | permission change operations on datastores or VMs | Active Directory Object Modification |
| `esxi:vpxd` | vCenter Management | Command Execution |
