# auditd

355 unique events

| Log Source | Channel | Data Components |
|------------|---------|-----------------|
| `auditd:AUTH` | pam_unix or pam_google_authenticator invoked repeatedly within short interval | User Account Authentication |
| `auditd:CONFIG_CHANGE` | /etc/fstab, /etc/systemd/* | File Deletion |
| `auditd:CONFIG_CHANGE` | /var/log/audit/audit.log | Scheduled Job Modification |
| `auditd:CONFIG_CHANGE` | chmod or chown of hook files indicating privilege escalation or execution permission change | File Metadata |
| `auditd:CONFIG_CHANGE` | creation or modification of systemd services | Service Creation |
| `auditd:CONFIG_CHANGE` | delete: Modification of systemd unit files or config for security agents | Service Metadata |
| `auditd:CONFIG_CHANGE` | udev rule reload or trigger command executed | Command Execution |
| `auditd:EXECVE` | /usr/sbin/postfix, /usr/sbin/exim, /usr/sbin/sendmail | Process Creation |
| `auditd:EXECVE` | EXECVE | Process Creation |
| `auditd:EXECVE` | Execution of GUI-related binaries with suppressed window/display flags | Command Execution |
| `auditd:EXECVE` | Execution of auditctl, systemctl stop auditd, or kill -9 auditd | Command Execution |
| `auditd:EXECVE` | Execution of chattr to set +i or +a attributes | Command Execution |
| `auditd:EXECVE` | Execution of dd, shred, or wipe with arguments targeting block devices | Process Creation |
| `auditd:EXECVE` | Execution of dd, shred, wipe targeting block devices | Process Creation |
| `auditd:EXECVE` | Execution of dd/sgdisk with arguments writing to sector 0 or partition table | Process Creation |
| `auditd:EXECVE` | Execution of gsettings set org.gnome.login-screen disable-user-list true | Command Execution |
| `auditd:EXECVE` | Execution of ssh/scp/sftp without corresponding authentication log | Process Creation |
| `auditd:EXECVE` | None | Process Creation |
| `auditd:EXECVE` | Process execution of update-ca-certificates or openssl with suspicious arguments | Command Execution |
| `auditd:EXECVE` | Process execution via .desktop Exec path from /etc/xdg/autostart or ~/.config/autostart | Process Creation |
| `auditd:EXECVE` | Shell commands invoked by SQL process such as postgres, mysqld, or mariadbd | Process Creation |
| `auditd:EXECVE` | Use of mv or cp to rename files with '.' prefix | Command Execution |
| `auditd:EXECVE` | cat\|less\|grep accessing .bash_history from a non-shell process | Process Creation |
| `auditd:EXECVE` | command line arguments containing lsblk, fdisk, parted | Command Execution |
| `auditd:EXECVE` | curl -T, rclone copy | Command Execution |
| `auditd:EXECVE` | curl -X POST, wget --post-data | Command Execution |
| `auditd:EXECVE` | curl -d, wget --post-data | Command Execution |
| `auditd:EXECVE` | curl or wget with POST/PUT options | Command Execution |
| `auditd:EXECVE` | exec: Execution of dd, efibootmgr, or flashrom modifying firmware/boot partitions | Command Execution |
| `auditd:EXECVE` | execution of setfattr or getfattr commands | Command Execution |
| `auditd:EXECVE` | execution of systemctl with subcommands start, stop, enable, disable | Command Execution |
| `auditd:EXECVE` | execution of unexpected binaries during user shell startup | Process Creation |
| `auditd:EXECVE` | execve | Process Creation |
| `auditd:EXECVE` | execve: Execution of update-ca-certificates or trust anchor modification commands | Command Execution |
| `auditd:EXECVE` | execve: Processes launched with LD_PRELOAD/LD_LIBRARY_PATH pointing to non-system dirs | Process Creation |
| `auditd:EXECVE` | gcore, gdb, strings, hexdump execution | Command Execution |
| `auditd:EXECVE` | git push, curl -X POST | Command Execution |
| `auditd:EXECVE` | grep/cat/awk on files with password fields | Command Execution |
| `auditd:EXECVE` | systemctl spawning managed processes | Process Creation |
| `auditd:EXECVE` | systemctl stop auditd, kill -9 <pid>, or modifications to /etc/selinux/config | Process Creation |
| `auditd:FILE` | /home/*/.mozilla/firefox/*/logins.json OR /home/*/.config/google-chrome/*/Login Data | File Access |
| `auditd:FILE` | /proc/*/mem read attempt | File Access |
| `auditd:FILE` | Creation of hidden files (.*) in sensitive directories (/etc, /var, /usr/bin) | File Creation |
| `auditd:FILE` | File creation with name starting with '.' | File Creation |
| `auditd:FILE` | Modification of Display Manager configuration files (/etc/gdm3/*, /etc/lightdm/*) | File Modification |
| `auditd:FILE` | Modification or deletion of /etc/audit/audit.rules or /etc/audit/audit.conf | File Modification |
| `auditd:FILE` | create: Creation of .zip, .gz, .bz2 files in /tmp, /var/tmp, or /home directories | File Creation |
| `auditd:FILE` | create: Creation of archive files in /tmp, /var/tmp, or user home directories | File Creation |
| `auditd:FILE` | create: Creation of files ending in .tar, .gz, .bz2, .zip in /tmp or /var/tmp | File Creation |
| `auditd:FILE` | create: Creation of files with anomalous headers and entropy levels in /tmp or user directories | File Creation |
| `auditd:FILE` | create: New file created in system binaries or temp directories | File Creation |
| `auditd:FS` | read: File access to /proc/modules or /sys/module/ | File Access |
| `auditd:MMAP` | load: Loading of libzip.so, libz.so, or libbz2.so by processes not normally associated with archiving | Module Load |
| `auditd:MMAP` | memory region with RWX permissions allocated | OS API Execution |
| `auditd:PATH` | /etc/passwd or /etc/group file write | File Modification |
| `auditd:PATH` | Creation of files with extensions .sql, .csv, .sqlite, especially in user directories | File Creation |
| `auditd:PATH` | New .py/.js/.sh files written to ~/.local/, ~/.cache/, or /tmp/ within 5 min of package install | File Creation |
| `auditd:PATH` | PATH | File Access, File Metadata |
| `auditd:PATH` | Read access to known backup software configuration files (e.g., /etc/rsnapshot.conf, /opt/veeam/config.ini) | File Access |
| `auditd:PATH` | WRITE: Drop of binaries/scripts in ~/.local, /tmp, or /opt tool dirs | File Creation |
| `auditd:PATH` | creation of .so files in non-standard directories (e.g., /tmp, /home/*) | File Creation |
| `auditd:PATH` | file path matches exclusion directories | File Metadata |
| `auditd:PATH` | file path modifications on critical system directories (/etc, /usr/bin, /usr/sbin, /var, /opt) | File Metadata |
| `auditd:PATH` | file read | File Access |
| `auditd:PATH` | mount target path within /proc/* | File Creation |
| `auditd:PATH` | open: Access to sensitive log files (/var/log/auth.log, /var/log/secure, /var/log/syslog) | File Access |
| `auditd:PATH` | write or create events on *.pth, sitecustomize.py, usercustomize.py in site-packages or dist-packages | File Modification |
| `auditd:PATH` | write: File modifications to /etc/systemd/sleep.conf or related power configuration files | File Modification |
| `auditd:PATH` | write: Modification of /boot/grub/*, /boot/efi/EFI/*, or initramfs images | File Modification |
| `auditd:PROCTITLE` | command-line execution patterns for system discovery utilities (uname, hostname, ifconfig, netstat, lsof, ps, mount) | Command Execution |
| `auditd:PROCTITLE` | process title records containing discovery command sequences and environmental assessment patterns | Command Execution |
| `auditd:PROCTITLE` | proctitle contains chmod, chown, chgrp, setfacl, or attr with suspicious parameters (777, 755, +x, -R) | Command Execution |
| `auditd:PROCTITLE` | proctitle contains chmod, chown, setfacl, or attr commands with suspicious parameters | Command Execution |
| `auditd:PROCTITLE` | scripting loop invoking sleep/ping | Script Execution |
| `auditd:SYSCALL` | ACCESS | Process Access |
| `auditd:SYSCALL` | AUDIT_SYSCALL (open, write, rename, unlink) | File Modification |
| `auditd:SYSCALL` | Access or modification to /lib/modules or creation of .ko files | File Creation |
| `auditd:SYSCALL` | Access to /var/lib/sss/secrets/secrets.ldb or .secrets.mkey | File Access |
| `auditd:SYSCALL` | Command line arguments including SPApplicationsDataType | Command Execution |
| `auditd:SYSCALL` | EXECVE | Process Creation |
| `auditd:SYSCALL` | Execution of binaries located in /etc/init.d/ or systemd service paths | Process Creation |
| `auditd:SYSCALL` | Execution of dpkg or rpm followed by fork/execve from within postinst, prerm, etc. | Process Creation |
| `auditd:SYSCALL` | Execution of dpkg, rpm, or other package manager with list flag | Process Creation |
| `auditd:SYSCALL` | Execution of insmod, modprobe, or rmmod commands by non-standard users or outside expected timeframes | Command Execution |
| `auditd:SYSCALL` | Execution of network stress tools or anomalies in socket/syscall behavior | Process Creation |
| `auditd:SYSCALL` | Execution of script interpreters by systemd timer (ExecStart) | Command Execution |
| `auditd:SYSCALL` | Execution of spoofing tools (e.g., hping3, nping, scapy) sending UDP packets to known amplifier ports | Command Execution |
| `auditd:SYSCALL` | Execution of xev, xdotool, or input activity emulators | Command Execution |
| `auditd:SYSCALL` | File creation events in /var/mail or /var/spool/mail exceeding baseline thresholds | File Creation |
| `auditd:SYSCALL` | File creations of *.qcow2, *.vdi, *.vmdk outside standard VM directories | File Creation |
| `auditd:SYSCALL` | High frequency of accept(), read(), or SSL_read() syscalls tied to nginx/apache processes | Process Access |
| `auditd:SYSCALL` | Inotify watch creation or auditctl changes on /etc/cron* or /lib/systemd/system/ | File Metadata |
| `auditd:SYSCALL` | Invocation of packet generation tools (e.g., hping3, nping) or fork bombs | Process Creation |
| `auditd:SYSCALL` | Kernel Device Events - USB Block Devices | Drive Creation |
| `auditd:SYSCALL` | LD_PRELOAD Logging | Module Load |
| `auditd:SYSCALL` | Modification of user shell profile or trap registration via echo/redirection (e.g., echo "trap 'malicious_cmd' INT" >> ~/.bashrc) | File Modification |
| `auditd:SYSCALL` | None | Command Execution |
| `auditd:SYSCALL` | PATH | File Access, File Deletion, File Metadata, File Modification |
| `auditd:SYSCALL` | PATH records referencing /dev/video* | File Access |
| `auditd:SYSCALL` | Process segfault or abnormal termination after invoking vulnerable syscall sequence | Process Termination |
| `auditd:SYSCALL` | Processes reading credential or token cache files | File Access |
| `auditd:SYSCALL` | Reads of ~/.bash_history, ~/.mozilla, or access to /dev/input | File Access |
| `auditd:SYSCALL` | Removable media mount notification | Drive Creation |
| `auditd:SYSCALL` | Rules capturing clock_gettime, time, gettimeofday syscalls when enabled | OS API Execution |
| `auditd:SYSCALL` | SYSCALL for usermod or /etc/group file modification | User Account Modification |
| `auditd:SYSCALL` | SYSCALL ptrace/mprotect | Process Modification |
| `auditd:SYSCALL` | SYSCALL record where exe contains passwd/userdel/chage and auid != root | Process Creation |
| `auditd:SYSCALL` | Unusual processes accessing or modifying cookie databases | File Access |
| `auditd:SYSCALL` | Use of fork/exec with DISPLAY unset or redirected | Process Metadata |
| `auditd:SYSCALL` | adduser | User Account Creation |
| `auditd:SYSCALL` | apache2 or nginx spawning sh, bash, or python interpreter | Process Creation |
| `auditd:SYSCALL` | bash/zsh of base64, tar, gzip, or openssl immediately after file write | Command Execution |
| `auditd:SYSCALL` | capset or setns | Logon Session Creation |
| `auditd:SYSCALL` | chattr, rm, shred, dd run on recovery directories or partitions | Command Execution |
| `auditd:SYSCALL` | chmod | File Modification |
| `auditd:SYSCALL` | chmod, chown, setxattr, or file writes to /etc/ssl/* or /usr/local/share/ca-certificates/* | File Metadata |
| `auditd:SYSCALL` | chmod, execve | Command Execution |
| `auditd:SYSCALL` | chmod, write, create, open | File Modification |
| `auditd:SYSCALL` | chmod/chown to /etc/passwd or /etc/shadow | File Modification |
| `auditd:SYSCALL` | connect | Network Connection Creation |
| `auditd:SYSCALL` | connect or sendto system call with burst pattern | Network Traffic Flow |
| `auditd:SYSCALL` | connect, execve, write | Command Execution |
| `auditd:SYSCALL` | connect/sendto | Network Connection Creation |
| `auditd:SYSCALL` | creat | File Creation |
| `auditd:SYSCALL` | creat, open, write on /etc/systemd/system and /usr/lib/systemd/system | File Creation |
| `auditd:SYSCALL` | device event logs | Drive Creation |
| `auditd:SYSCALL` | dmesg | Module Load |
| `auditd:SYSCALL` | execution of known flash tools (e.g., flashrom, fwupd) | Process Creation |
| `auditd:SYSCALL` | execution of realmd, samba-tool, or ldapmodify with user-related arguments | Command Execution |
| `auditd:SYSCALL` | execution of ssh, scp, or sftp using previously unseen credentials or keys | User Account Authentication |
| `auditd:SYSCALL` | execution of systemctl or service with enable/start parameters | Command Execution |
| `auditd:SYSCALL` | execution of systemctl or service with enable/start/modify | Command Execution |
| `auditd:SYSCALL` | execution of tools like cat, grep, or awk on credential files | Command Execution |
| `auditd:SYSCALL` | execve | Process Creation |
| `auditd:SYSCALL` | execve call for modification of /etc/sudoers or writing to /var/db/sudo | File Modification |
| `auditd:SYSCALL` | execve call for sudo where euid != uid | Process Metadata |
| `auditd:SYSCALL` | execve call including 'nohup' or trailing '&' | Command Execution |
| `auditd:SYSCALL` | execve call with argv matching known disk enumeration commands (lsblk, parted, fdisk) | Process Creation |
| `auditd:SYSCALL` | execve calls for qemu-system*, kvm, or VBoxHeadless | Process Creation |
| `auditd:SYSCALL` | execve calls modifying HISTFILE or HISTCONTROL via unset/export | Command Execution |
| `auditd:SYSCALL` | execve calls modifying local mail filter configuration files | Command Execution |
| `auditd:SYSCALL` | execve calls to /usr/bin/locale or shell execution of $LANG | Command Execution |
| `auditd:SYSCALL` | execve calls to locale, timedatectl, or cat /etc/timezone | Command Execution |
| `auditd:SYSCALL` | execve calls to soffice.bin with suspicious macro execution flags | Process Creation |
| `auditd:SYSCALL` | execve calls with high-frequency or known bandwidth-intensive tools | Process Creation |
| `auditd:SYSCALL` | execve for proxy tools | Process Creation |
| `auditd:SYSCALL` | execve logging for /usr/bin/systemctl and systemd-run | Process Creation |
| `auditd:SYSCALL` | execve network tools | Process Creation |
| `auditd:SYSCALL` | execve of /bin/sh,/bin/bash,/usr/bin/curl,/usr/bin/python by service accounts (e.g., apache, mysql, nobody) immediately after inbound network activity. | Process Creation |
| `auditd:SYSCALL` | execve of base64\|openssl\|xxd\|python\|perl with arguments matching Base64 flags | Process Creation |
| `auditd:SYSCALL` | execve of curl, rsync, wget with internal knowledge base or IPs | Command Execution |
| `auditd:SYSCALL` | execve of dd or sed targeting /proc/*/mem | OS API Execution |
| `auditd:SYSCALL` | execve of interpreters (python, perl), custom binaries, or shell utilities with long arguments containing non-standard tokens | Process Creation |
| `auditd:SYSCALL` | execve of launchctl or pkill | Process Creation |
| `auditd:SYSCALL` | execve of re-parented process | Process Creation |
| `auditd:SYSCALL` | execve of sleep or ping command within script interpreted by bash/python | Process Creation |
| `auditd:SYSCALL` | execve of smbclient, smbmap, rpcclient, nmblookup, crackmapexec smb | Process Creation |
| `auditd:SYSCALL` | execve of system tools like dmidecode, lspci, lscpu, dmesg, systemd-detect-virt | Process Creation |
| `auditd:SYSCALL` | execve of systemctl or service stop | Process Creation |
| `auditd:SYSCALL` | execve on code or jetbrains-gateway with remote flags | Process Creation |
| `auditd:SYSCALL` | execve or nanosleep with no stdout/stderr I/O | Process Creation |
| `auditd:SYSCALL` | execve or socket/connect system calls for processes using RSA handshake | Process Creation |
| `auditd:SYSCALL` | execve or socket/connect system calls from processes using crypto libraries | Process Creation |
| `auditd:SYSCALL` | execve or syscall invoking vm artifact check commands (e.g., dmidecode, lspci, dmesg) | Process Creation |
| `auditd:SYSCALL` | execve syscalls for discovery commands (uname, hostname, id, whoami, ps, netstat, mount) with command-line parameter analysis | Command Execution |
| `auditd:SYSCALL` | execve with LD_PRELOAD or linker-related environment variables set | Process Creation |
| `auditd:SYSCALL` | execve with UID ≠ EUID | Process Metadata |
| `auditd:SYSCALL` | execve with escalated privileges | Process Metadata |
| `auditd:SYSCALL` | execve, USER_CMD | Command Execution |
| `auditd:SYSCALL` | execve, connect | Process Creation |
| `auditd:SYSCALL` | execve, fork, mmap, ptrace | Process Access |
| `auditd:SYSCALL` | execve, prctl, or ptrace activity affecting process memory or command-line arguments | Process Metadata |
| `auditd:SYSCALL` | execve, setifflags | Process Creation |
| `auditd:SYSCALL` | execve, unlink | Process Creation |
| `auditd:SYSCALL` | execve,socket,connect,openat | Logon Session Metadata |
| `auditd:SYSCALL` | execve: Agent/headless flags (listen/connect/reverse/tunnel) or remote-control binaries spawning shells | Process Creation |
| `auditd:SYSCALL` | execve: Commands altering firewall or enabling listeners (iptables, nft, ufw, firewall-cmd, systemctl start *ssh*/*telnet*, ip route add, tcpdump, tshark) | Process Creation |
| `auditd:SYSCALL` | execve: Commands executed within an SSH session where no matching logon/authentication event exists | Command Execution |
| `auditd:SYSCALL` | execve: Commands like systemctl stop <service>, service <service> stop, or kill -9 <pid> | Command Execution |
| `auditd:SYSCALL` | execve: Commands that alter firewall or start listeners: iptables\|nft\|ufw\|firewall-cmd\|pfctl\|systemctl start sshd/telnet/dropbear; raw-socket/libpcap tools (tcpdump, tshark, nmap --raw). | Process Creation |
| `auditd:SYSCALL` | execve: Electron-based binary spawning shell or script interpreter | Process Creation |
| `auditd:SYSCALL` | execve: Execs of chromium, google-chrome, firefox, libreoffice with http(s) in cmdline | Network Connection Creation |
| `auditd:SYSCALL` | execve: Execution of CLI tools like psql, mysql, mongo, sqlite3 | Process Creation |
| `auditd:SYSCALL` | execve: Execution of bash, python, or perl processes spawned by browser/email client | Process Creation |
| `auditd:SYSCALL` | execve: Execution of binaries/scripts presenting false health messages for security daemons | Process Creation |
| `auditd:SYSCALL` | execve: Execution of cat, less, grep, journalctl targeting log directories (/var/log/) | Command Execution |
| `auditd:SYSCALL` | execve: Execution of commands modifying iptables/nftables to block selective IPs | Process Creation |
| `auditd:SYSCALL` | execve: Execution of container management CLIs (docker, crictl, kubectl) or interpreted shells (sh, bash, python) within container context | Process Creation |
| `auditd:SYSCALL` | execve: Execution of curl or wget writing files to /tmp/* followed by chmod or execution | Command Execution |
| `auditd:SYSCALL` | execve: Execution of curl, wget, or custom scripts accessing financial endpoints | Command Execution |
| `auditd:SYSCALL` | execve: Execution of discovery commands targeting backup binaries, processes, or config paths | Process Creation |
| `auditd:SYSCALL` | execve: Execution of downgraded interpreters such as python2 or forced fallback commands | Command Execution |
| `auditd:SYSCALL` | execve: Execution of files saved in mail or download directories | Process Creation |
| `auditd:SYSCALL` | execve: Execution of interpreters creating archive-like outputs without calling tar/gzip | Command Execution |
| `auditd:SYSCALL` | execve: Execution of klist, kinit, or tools interacting with ccache outside normal user context | Process Creation |
| `auditd:SYSCALL` | execve: Execution of lsmod, modinfo, or cat /proc/modules | Command Execution |
| `auditd:SYSCALL` | execve: Execution of pip, npm, gem, or similar package managers | Process Creation |
| `auditd:SYSCALL` | execve: Execution of python, perl, or custom binaries invoking compression libraries | Command Execution |
| `auditd:SYSCALL` | execve: Execution of scripts or binaries sourced from mail directories (/var/mail, ~/Maildir) | Process Creation |
| `auditd:SYSCALL` | execve: Execution of scripts or binaries spawned from browser processes | Process Creation |
| `auditd:SYSCALL` | execve: Execution of suspicious exploit binaries targeting security daemons | Process Creation |
| `auditd:SYSCALL` | execve: Execution of systemctl, loginctl, or systemd-inhibit commands related to sleep/hibernate | Command Execution |
| `auditd:SYSCALL` | execve: Execution of tar, gzip, bzip2, or openssl with output redirection | Command Execution |
| `auditd:SYSCALL` | execve: Execution of tar, gzip, bzip2, xz, zip, or openssl with compression/encryption arguments | Command Execution |
| `auditd:SYSCALL` | execve: Invocation of scp, rsync, curl, or sftp | Command Execution |
| `auditd:SYSCALL` | execve: Process in container namespace executes curl\|wget\|bash\|sh\|python\|nc with outbound args | Command Execution |
| `auditd:SYSCALL` | execve: Processes executing sendmail/postfix with forged headers | Command Execution |
| `auditd:SYSCALL` | execve: Suspicious binaries or scripts interacting with authentication binaries (sshd, gdm, login) | Process Creation |
| `auditd:SYSCALL` | execve: exe in (/usr/bin/bash,/usr/bin/sh,/usr/bin/zsh,/usr/bin/python*) AND cmdline matches '(curl\|wget).*(\\|\|\\|\s*sh\|bash)\|base64\s*-d\|python\s*-c' | Process Creation |
| `auditd:SYSCALL` | execve: exe in {/bin/bash,/bin/sh,/usr/bin/python*,/usr/bin/perl,/usr/bin/php,/usr/bin/node,/usr/bin/curl,/usr/bin/wget,/usr/bin/xdg-open,/usr/bin/ssh,/usr/bin/rundll32 (wine)} AND ppid process is a document viewer/browser | Process Creation |
| `auditd:SYSCALL` | execve: execve calls where a browser/webview process is parent and child is interpreter (python, sh, ruby) or downloader (curl, wget) | Process Creation |
| `auditd:SYSCALL` | execve: execve where exe=/usr/bin/python3 or similar interpreter | Process Creation |
| `auditd:SYSCALL` | execve: iptables, nft, firewall-cmd modifications | Command Execution |
| `auditd:SYSCALL` | execve: openssl pkcs12, certutil, keytool | Command Execution |
| `auditd:SYSCALL` | execve: parent process is usb/hid device handler, child process bash/python invoked | Process Creation |
| `auditd:SYSCALL` | execve: process_name IN ("virsh", "VBoxManage", "qemu-img") AND command IN ("list", "info") | Command Execution |
| `auditd:SYSCALL` | execve: service stop syslog, systemctl stop rsyslog, kill -9 syslog | Command Execution |
| `auditd:SYSCALL` | execve: systemctl stop, service stop, or kill -9 on security daemons (e.g., falcon-sensor, auditd) | Process Creation |
| `auditd:SYSCALL` | execve=/sbin/shutdown or /sbin/reboot | Command Execution |
| `auditd:SYSCALL` | exit_group | Process Termination |
| `auditd:SYSCALL` | file | File Access |
| `auditd:SYSCALL` | file creation/modification | File Creation |
| `auditd:SYSCALL` | file deletion | File Deletion |
| `auditd:SYSCALL` | file write after sleep delay | File Metadata |
| `auditd:SYSCALL` | file write operations in /Library/WebServer/Documents | File Modification |
| `auditd:SYSCALL` | firmware_update, kexec_load | Host Status |
| `auditd:SYSCALL` | fork/clone/daemon syscall tracing | OS API Execution |
| `auditd:SYSCALL` | fork/exec of service via PID 1 (systemd) | Process Creation |
| `auditd:SYSCALL` | ioctl/write: Direct firmware update or device memory manipulation syscalls | Firmware Modification |
| `auditd:SYSCALL` | ioctl: Changes to wireless network interfaces (up, down, reassociate) | Network Traffic Flow |
| `auditd:SYSCALL` | kill syscalls targeting auditd process | Process Modification |
| `auditd:SYSCALL` | kill syscalls targeting logging/security processes | Process Termination |
| `auditd:SYSCALL` | mknod,open,openat | Drive Creation |
| `auditd:SYSCALL` | mmap | Module Load |
| `auditd:SYSCALL` | mmap, ptrace, process_vm_writev or direct memory ops | OS API Execution |
| `auditd:SYSCALL` | modification of entrypoint scripts or init containers | File Modification |
| `auditd:SYSCALL` | modification of existing .service file | File Modification |
| `auditd:SYSCALL` | module load or memory map path | Module Load |
| `auditd:SYSCALL` | mount or losetup commands creating hidden or encrypted FS | File Modification |
| `auditd:SYSCALL` | mount system call with bind or remap flags | OS API Execution |
| `auditd:SYSCALL` | mprotect | Process Modification |
| `auditd:SYSCALL` | new file created in /var/www/html, /srv/http, or similar web root | File Creation |
| `auditd:SYSCALL` | open | File Access |
| `auditd:SYSCALL` | open or connect syscalls on /tmp/ssh-* or $SSH_AUTH_SOCK | Network Connection Creation |
| `auditd:SYSCALL` | open or creat syscalls targeting excluded paths | File Creation |
| `auditd:SYSCALL` | open or read to browser cookie storage | File Access |
| `auditd:SYSCALL` | open, flock, fcntl, unlink | File Access |
| `auditd:SYSCALL` | open, read | File Access |
| `auditd:SYSCALL` | open, read, mount | File Access |
| `auditd:SYSCALL` | open, read, or stat of browser config files | File Access |
| `auditd:SYSCALL` | open, read: /etc/ssl/, /etc/pki/, ~/.pki/nssdb/ | File Access |
| `auditd:SYSCALL` | open, rename | Process Modification |
| `auditd:SYSCALL` | open, unlink, rename: File creation or deletion involving critical stored data | File Creation |
| `auditd:SYSCALL` | open, unlink, rename: Suspicious file access, deletion, or modification of sensitive paths | File Modification |
| `auditd:SYSCALL` | open, write | File Modification |
| `auditd:SYSCALL` | open, write, unlink | File Creation |
| `auditd:SYSCALL` | open, write: File modifications under /etc/ssl/certs, /usr/local/share/ca-certificates, or /etc/pki/ca-trust/source/anchors | File Modification |
| `auditd:SYSCALL` | open, write: File writes to application binaries or libraries at runtime | File Modification |
| `auditd:SYSCALL` | open, write: Modification of /boot/grub/* or /boot/efi/* | File Modification |
| `auditd:SYSCALL` | open, write: Write operations targeting /dev/sda, /dev/nvme0n1, or EFI partition mounts | File Modification |
| `auditd:SYSCALL` | open,creat,rename,write | File Creation |
| `auditd:SYSCALL` | open,creat,rename: Writes in $HOME/Downloads, /tmp, ~/.cache with exe/script/archive/office extensions | File Creation |
| `auditd:SYSCALL` | open,create | File Creation |
| `auditd:SYSCALL` | open,openat,read | User Account Metadata |
| `auditd:SYSCALL` | open,read | File Access |
| `auditd:SYSCALL` | open/create/rename: name in (/home/*/Downloads/*\|/tmp/*\|/run/user/*\|/media/*) AND ext in SuspiciousExtensions | File Creation |
| `auditd:SYSCALL` | open/read | File Access |
| `auditd:SYSCALL` | open/read access to ~/.bash_history | File Access |
| `auditd:SYSCALL` | open/read of sensitive config or secret files | File Access |
| `auditd:SYSCALL` | open/read of sensitive directories | File Access |
| `auditd:SYSCALL` | open/read of sensitive directories (/etc, /home/*) | File Access |
| `auditd:SYSCALL` | open/read on ~/.local/share/keepassxc/* OR ~/.password-store/* | File Access |
| `auditd:SYSCALL` | open/read system calls to ~/.bash_history or /etc/shadow | File Access |
| `auditd:SYSCALL` | open/read: Access to /proc/self/status with focus on TracerPID field | File Access |
| `auditd:SYSCALL` | open/write calls modifying ~/.bashrc, ~/.profile, or /etc/paths.d | File Modification |
| `auditd:SYSCALL` | open/write of .service unit files | File Modification |
| `auditd:SYSCALL` | open/write syscalls on /dev/sd* or /dev/nvme* | Drive Access |
| `auditd:SYSCALL` | open/write syscalls targeting /etc/ld.so.preload or binaries in /usr/bin | File Modification |
| `auditd:SYSCALL` | open/write syscalls targeting web directory files | File Modification |
| `auditd:SYSCALL` | open/write syscalls to block devices (/dev/sd*, /dev/nvme*) | Drive Access |
| `auditd:SYSCALL` | open/write to /etc/pam.d/* | File Modification |
| `auditd:SYSCALL` | open/write to /proc/*/mem or /proc/*/maps | File Modification |
| `auditd:SYSCALL` | open/write/unlink | File Modification |
| `auditd:SYSCALL` | open: Access to named pipes or FIFO in /tmp or /dev/shm by unexpected processes | File Access |
| `auditd:SYSCALL` | open: File access attempt on /tmp/krb5cc_* or /tmp/krb5.ccache | File Access |
| `auditd:SYSCALL` | open: File creation under /tmp, /var/tmp, ~/.cache with executable bit or shell shebang | File Creation |
| `auditd:SYSCALL` | open: Write to ~/.vscode-cli/code_tunnel.json | File Creation |
| `auditd:SYSCALL` | openat | File Access |
| `auditd:SYSCALL` | openat, write, rename, unlink | File Modification |
| `auditd:SYSCALL` | openat,connect -k discovery | Network Connection Creation |
| `auditd:SYSCALL` | openat/read/ioctl: openat/read/ioctl on /dev/video* by uncommon user/process | OS API Execution |
| `auditd:SYSCALL` | openat/read/mmap: Open/mmap .so files from non-standard paths | Module Load |
| `auditd:SYSCALL` | outbound connections | Network Connection Creation |
| `auditd:SYSCALL` | pam_authenticate, sshd | User Account Authentication |
| `auditd:SYSCALL` | process persists beyond parent shell termination | Process Creation |
| `auditd:SYSCALL` | promiscuous mode transitions (ioctl or ifconfig) | Command Execution |
| `auditd:SYSCALL` | ptrace | Process Access |
| `auditd:SYSCALL` | ptrace attach | Process Access |
| `auditd:SYSCALL` | ptrace or process_vm_readv | Process Access |
| `auditd:SYSCALL` | ptrace syscall or access to /proc/*/mem | Process Access |
| `auditd:SYSCALL` | ptrace, ioctl | OS API Execution |
| `auditd:SYSCALL` | ptrace, mmap, mprotect, open, dlopen | OS API Execution |
| `auditd:SYSCALL` | ptrace, mmap, process_vm_writev | OS API Execution |
| `auditd:SYSCALL` | read of /run/secrets or docker volumes by non-entrypoint process | File Access |
| `auditd:SYSCALL` | read/open of sensitive file directories | File Access |
| `auditd:SYSCALL` | read/open of sensitive files | File Access |
| `auditd:SYSCALL` | rename | Process Modification |
| `auditd:SYSCALL` | rename, chmod | Process Modification |
| `auditd:SYSCALL` | rename,chmod | File Modification |
| `auditd:SYSCALL` | send, recv, write: Abnormal interception or alteration of transmitted data | OS API Execution |
| `auditd:SYSCALL` | sendto/connect | Network Connection Creation |
| `auditd:SYSCALL` | setsockopt, ioctl modifying ARP entries | Network Traffic Content |
| `auditd:SYSCALL` | setuid or setgid bit changes | File Metadata |
| `auditd:SYSCALL` | setxattr or getxattr system call | File Metadata |
| `auditd:SYSCALL` | sleep function usage or loops (nanosleep, usleep) in scripts | Command Execution |
| `auditd:SYSCALL` | socket(AF_PACKET\|AF_INET, SOCK_RAW, *), setsockopt(… SO_ATTACH_FILTER\|SO_ATTACH_BPF …), bpf(cmd=BPF_PROG_LOAD), open/openat path="/dev/bpf*" (BSD/macOS-like) or setcap cap_net_raw. | Process Creation |
| `auditd:SYSCALL` | socket/bind: New bind() to a previously closed port shortly after the sequence. | Network Connection Creation |
| `auditd:SYSCALL` | socket/bind: Process binds to a new local port shortly after knock | Network Connection Creation |
| `auditd:SYSCALL` | socket/connect | Network Traffic Flow |
| `auditd:SYSCALL` | socket/connect calls showing SSH processes forwarding arbitrary ports | Network Connection Creation |
| `auditd:SYSCALL` | socket/connect syscalls | Network Traffic Flow |
| `auditd:SYSCALL` | socket/connect with TLS context by unexpected process | Network Connection Creation |
| `auditd:SYSCALL` | socket: Suspicious creation of AF_UNIX sockets outside expected daemons | Process Creation |
| `auditd:SYSCALL` | ssh logins or execve of remote commands | Logon Session Metadata |
| `auditd:SYSCALL` | sudo or pkexec invocation | OS API Execution |
| `auditd:SYSCALL` | syscall in (chmod, fchmod, fchmodat, chown, fchown, fchownat, lchown, setxattr, lsetxattr, fsetxattr, removexattr, lremovexattr, fremovexattr) | File Metadata |
| `auditd:SYSCALL` | syscall in (chmod, fchmod, fchmodat, chown, fchown, fchownat, setxattr, lsetxattr, fsetxattr) | File Metadata |
| `auditd:SYSCALL` | systemctl enable/start: Creation/enablement of custom .service units in /etc/systemd/system | Process Creation |
| `auditd:SYSCALL` | type=EXECVE or SYSCALL for /bin/date, /usr/bin/timedatectl, /sbin/hwclock, /bin/cat /etc/timezone, /bin/cat /proc/uptime | Process Creation |
| `auditd:SYSCALL` | udev events or drive enumeration involving TinyPilot paths or device classes | Drive Creation |
| `auditd:SYSCALL` | unlink, rename, open | File Deletion |
| `auditd:SYSCALL` | unlink, unlinkat, openat, write | File Deletion |
| `auditd:SYSCALL` | unlink, unlinkat, rmdir | File Deletion |
| `auditd:SYSCALL` | unlink/unlinkat | File Deletion |
| `auditd:SYSCALL` | unlink/unlinkat on service binaries or data targets | File Deletion |
| `auditd:SYSCALL` | unshare, mount, keyctl, setns syscalls executed by containerized processes | OS API Execution |
| `auditd:SYSCALL` | useradd or adduser executed | User Account Creation |
| `auditd:SYSCALL` | usermod, groupmod, passwd | User Account Modification |
| `auditd:SYSCALL` | usermod, or account rename system calls | User Account Modification |
| `auditd:SYSCALL` | write | File Creation, File Modification |
| `auditd:SYSCALL` | write access to /dev/mem or /sys/firmware/efi/efivars | Firmware Modification |
| `auditd:SYSCALL` | write operation on /etc/passwd or /etc/shadow | File Modification |
| `auditd:SYSCALL` | write or create file after .bash_history access | File Creation |
| `auditd:SYSCALL` | write or rename to /etc/systemd/system or /etc/init.d | File Modification |
| `auditd:SYSCALL` | write syscalls to /dev/sd* targeting offset 0 | Drive Access |
| `auditd:SYSCALL` | write \| PATH=/home/*/.ssh/authorized_keys | File Modification |
| `auditd:SYSCALL` | write, open, or rename to /etc/systemd/system/*.service | File Creation |
| `auditd:SYSCALL` | write, rename | File Modification |
| `auditd:SYSCALL` | write/open, FIM audit | File Creation |
| `auditd:SYSCALL` | write: Modification of structured stored data by suspicious processes | File Modification |
| `auditd:USER_CMD` | USER_CMD | Command Execution |
| `auditd:USER_LOGIN` | USER_AUTH | User Account Authentication |
| `auditd:USER_LOGIN` | USER_LOGIN | Logon Session Metadata |
| `auditd:file-events` | open of suspicious .so from non-standard paths | Module Load |
| `auditd:memprotect` | change from PROT_READ\|PROT_WRITE to PROT_EXEC | Process Modification |
