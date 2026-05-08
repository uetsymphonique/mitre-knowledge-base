# networkdevice

102 unique events

| Log Source | Channel | Data Components |
|------------|---------|-----------------|
| `networkdevice:Firewall` | Audit trail or CLI/API access indicating commands like no access-list, delete rule-set, clear config | Command Execution |
| `networkdevice:Firewall` | Login from untrusted IP, or new admin account accessing firewall console/API | Logon Session Creation |
| `networkdevice:Firewall` | update_rule: Access control or NAT rule modified or disabled outside maintenance window | Firewall Rule Modification |
| `networkdevice:Flow` | Traffic from mirrored interface to mirror target IP | Network Connection Creation |
| `networkdevice:IDS` | content inspection / PCAP / HTTP body | Network Traffic Content |
| `networkdevice:audit` | SNMP configuration changes, such as enabling read/write access or modifying community strings | File Modification |
| `networkdevice:cli` | CLI command | Command Execution |
| `networkdevice:cli` | CLI command logs | Command Execution |
| `networkdevice:cli` | Commands like 'no logging' or equivalents that disable session history | Command Execution |
| `networkdevice:cli` | Execution of CLI commands altering crypto parameters (e.g., 'crypto key generate rsa modulus 512') | Command Execution |
| `networkdevice:cli` | Execution of commands disabling crypto hardware acceleration (e.g., 'no crypto engine enable') | Command Execution |
| `networkdevice:cli` | Execution of commands like 'show running-config', 'copy running-config', or 'export config' | Command Execution |
| `networkdevice:cli` | Execution of commands such as 'copy tftp flash', 'boot system <image>', 'reload' | Command Execution |
| `networkdevice:cli` | Execution of commands to load, copy, or replace system images (e.g., 'copy tftp flash', 'boot system') | Command Execution |
| `networkdevice:cli` | Execution of privileged commands such as 'copy tftp flash', 'boot system', or 'debug memory' | Command Execution |
| `networkdevice:cli` | Interface commands | Command Execution |
| `networkdevice:cli` | None | Command Execution |
| `networkdevice:cli` | Policy Update | Command Execution |
| `networkdevice:cli` | cmd: cmd=show clock detail | Command Execution |
| `networkdevice:cli` | command logging | Command Execution |
| `networkdevice:cli` | command logs | Command Execution |
| `networkdevice:cli` | erase flash:, erase nvram:, format disk | Command Execution |
| `networkdevice:cli` | erase flash:, erase startup-config, format disk | Command Execution |
| `networkdevice:cli` | firewall disable commands or suspicious ACL modifications | Firewall Rule Modification |
| `networkdevice:cli` | format flash:, format disk, reformat commands | Command Execution |
| `networkdevice:cli` | ip ssh pubkey-chain | Command Execution |
| `networkdevice:cli` | shell command | Command Execution |
| `networkdevice:config` | Boot image path or firmware configuration variable modified outside of maintenance windows | Firmware Modification |
| `networkdevice:config` | Boot variable modified to point to non-standard or unsigned image | Firmware Modification |
| `networkdevice:config` | Configuration change events referencing encryption, TLS/SSL, or IPSec settings | File Modification |
| `networkdevice:config` | Configuration changes referencing 'boot system tftp' or modification of startup-config pointing to external TFTP servers | Command Execution |
| `networkdevice:config` | Configuration changes referencing 'crypto', 'key length', 'cipher', or downgrade of encryption settings | File Modification |
| `networkdevice:config` | Configuration changes referencing cryptographic hardware modules or disabling hardware acceleration | File Modification |
| `networkdevice:config` | Configuration changes referencing older image versions or unexpected boot parameters | File Modification |
| `networkdevice:config` | Configuration changes to boot variables, startup image paths, or checksum verification failures | File Modification |
| `networkdevice:config` | Configuration changes to startup image paths, boot loader parameters, or debug flags | File Modification |
| `networkdevice:config` | Configuration file modified or replaced on network device | File Modification |
| `networkdevice:config` | Log entries indicating ROMMON image upgrade commands (boot system, upgrade rom-monitor) | Firmware Modification |
| `networkdevice:config` | NAT table modification (add/update/delete rule) | Network Traffic Content |
| `networkdevice:config` | PKI export or certificate manipulation commands | Command Execution |
| `networkdevice:config` | config-change: timezone or ntp server configuration change after a time query command | File Modification |
| `networkdevice:config` | write: Startup configuration changes disabling security checks | Service Metadata |
| `networkdevice:controlplane` | Syslog from edge devices with HTTP 500s on mgmt portal, SmartInstall events, unexpected CLI commands | Application Log Content |
| `networkdevice:firmware` | Firmware update initiated or bootloader tampering detected | Firmware Modification |
| `networkdevice:firmware` | Unexpected firmware image upload events via TFTP/FTP/SCP | Drive Modification |
| `networkdevice:firmware` | Unexpected firmware update or image modification affecting crypto modules | File Modification |
| `networkdevice:runtime` | Firmware image uploaded via TFTP/FTP/SCP | Drive Modification |
| `networkdevice:runtime` | runtime | Script Execution |
| `networkdevice:syslog` | AAA or TACACS authentication failures | User Account Authentication |
| `networkdevice:syslog` | AAA, RADIUS, or TACACS authentication | User Account Authentication |
| `networkdevice:syslog` | ACL/Firewall rule modification or new route injection | Network Traffic Content |
| `networkdevice:syslog` | Admin activity | Process Metadata |
| `networkdevice:syslog` | Authentication failures or unusual community string usage in SNMP queries | Network Traffic Content |
| `networkdevice:syslog` | Authentication failures, unexpected community string usage, or unauthorized SNMPv1/v2 requests | Network Traffic Content |
| `networkdevice:syslog` | Boot information log showing image loaded from TFTP server instead of local storage | Firmware Modification |
| `networkdevice:syslog` | CLI Command Audit | Command Execution |
| `networkdevice:syslog` | CLI Command Logging | Command Execution |
| `networkdevice:syslog` | CLI command audit | Command Execution |
| `networkdevice:syslog` | Checksum/hash mismatch between device OS image and baseline known-good version | File Modification |
| `networkdevice:syslog` | Command Audit / Configuration Change | Command Execution |
| `networkdevice:syslog` | Config change: CLI/NETCONF/SNMP – 'monitor session', 'mirror port' | Network Traffic Flow |
| `networkdevice:syslog` | Config/ACL changes, line vty transport input changes, telnet/ssh/http(s) enable, image/feature module changes. | Network Traffic Flow |
| `networkdevice:syslog` | Config/ACL/line vty changes, service enable (telnet/ssh/http(s)), module reloads | Network Traffic Flow |
| `networkdevice:syslog` | Custom firmware or routing changes | Firmware Modification |
| `networkdevice:syslog` | Detected CLI command to export key material | Command Execution |
| `networkdevice:syslog` | Dynamic route changes | Network Connection Creation |
| `networkdevice:syslog` | Failed and successful logins to network devices outside approved admin IP ranges | User Account Authentication |
| `networkdevice:syslog` | Failed authentication requests redirected to non-standard portals | Application Log Content |
| `networkdevice:syslog` | Image Upgrade / Configuration Change | Firmware Modification |
| `networkdevice:syslog` | OS version query results inconsistent with expected or approved version list | File Metadata |
| `networkdevice:syslog` | Privilege-level command execution | Command Execution |
| `networkdevice:syslog` | Privileged login followed by destructive command sequence | User Account Authentication |
| `networkdevice:syslog` | Privileged login followed by destructive format command | User Account Authentication |
| `networkdevice:syslog` | SIP REGISTER, INVITE, or unusual call destination metadata | Application Log Content |
| `networkdevice:syslog` | System reboot scheduled or performed | Host Status |
| `networkdevice:syslog` | Unexpected reload, crashinfo, or boot message not tied to scheduled maintenance | OS API Execution |
| `networkdevice:syslog` | User privilege escalation to level 15/root prior to destructive commands | User Account Authentication |
| `networkdevice:syslog` | aaa privilege_exec | OS API Execution |
| `networkdevice:syslog` | admin login events | User Account Authentication |
| `networkdevice:syslog` | authentication & authorization | User Account Authentication |
| `networkdevice:syslog` | authentication logs | User Account Authentication |
| `networkdevice:syslog` | authorization/accounting logs | User Account Authentication |
| `networkdevice:syslog` | cmd='show aaa*' OR 'show running-config \| include password\|aaa' OR 'show aaa common-criteria policy all' | Command Execution |
| `networkdevice:syslog` | command audit | Command Execution |
| `networkdevice:syslog` | command sequence: erase → format → reload | Command Execution |
| `networkdevice:syslog` | command-exec: CLI commands containing "show clock", "show clock detail", "show timezone" executed by suspicious user/source | Command Execution |
| `networkdevice:syslog` | command_exec | Command Execution |
| `networkdevice:syslog` | config | File Modification |
| `networkdevice:syslog` | config access, authentication logs | User Account Authentication |
| `networkdevice:syslog` | config change (e.g., logging buffered, pcap buffers) | Network Traffic Content |
| `networkdevice:syslog` | config push events | Application Log Content |
| `networkdevice:syslog` | eventlog | Command Execution |
| `networkdevice:syslog` | exec command='monitor capture' | Command Execution |
| `networkdevice:syslog` | flow records | Network Traffic Flow |
| `networkdevice:syslog` | interactive shell logging | Command Execution |
| `networkdevice:syslog` | login failed | User Account Authentication |
| `networkdevice:syslog` | no logging buffered, no aaa new-model, disable firewall | Command Execution |
| `networkdevice:syslog` | reload command issued | Command Execution |
| `networkdevice:syslog` | startup-config | File Modification |
| `networkdevice:syslog` | syslog facility LOCAL7 or trap messages | Command Execution |
| `networkdevice:syslog` | system boot logs | Command Execution |
| `networkdevice:syslog` | username <user> privilege <level> | User Account Creation |
