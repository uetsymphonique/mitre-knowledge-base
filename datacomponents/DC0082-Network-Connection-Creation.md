# DC0082 - Network Connection Creation

## Description

The initial establishment of a network session, where a system or process initiates a connection to a local or remote endpoint. This typically involves capturing socket information (source/destination IP, ports, protocol) and tracking session metadata. Monitoring these events helps detect lateral movement, exfiltration, and command-and-control (C2) activities.

*Data Collection Measures:*

- Windows:
    - Event ID 5156 – Filtering Platform Connection - Logs network connections permitted by Windows Filtering Platform (WFP).
    - Sysmon Event ID 3 – Network Connection Initiated - Captures process, source/destination IP, ports, and parent process.
- Linux/macOS:
    - Netfilter (iptables), nftables logs - Tracks incoming and outgoing network connections.
    - AuditD (`connect` syscall) - Logs TCP, UDP, and ICMP connections.
    - Zeek (`conn.log`) - Captures protocol, duration, and bytes transferred.
- Cloud & Network Infrastructure:
    - AWS VPC Flow Logs / Azure NSG Flow Logs - Logs IP traffic at the network level in cloud environments.
    - Zeek (conn.log) or Suricata (network events) - Captures packet metadata for detection and correlation.
- Endpoint Detection & Response (EDR):
    - Detect anomalous network activity such as new C2 connections or data exfiltration attempts.

## Log Sources

| Log Source | Channel |
|------------|---------|
| `Network Traffic` | None |
| `AWS:VPCFlowLogs` | Outbound connection to 169.254.169.254 from EC2 workload |
| `macos:unifiedlog` | connection attempts |
| `esxi:hostd` | System service interactions |
| `WinEventLog:Sysmon` | EventCode=3, 22 |
| `NSM:Connections` | web domain alerts |
| `auditd:SYSCALL` | connect |
| `macos:osquery` | process_events/socket_events |
| `NSM:Firewall` | Outbound Connections |
| `macos:unifiedlog` | connection open |
| `auditd:SYSCALL` | execve: Execs of chromium, google-chrome, firefox, libreoffice with http(s) in cmdline |
| `NSM:Flow` | New TCP/443 or TCP/80 to domain not previously seen for the user/host |
| `NSM:Connections` | New outbound connection from Safari/Chrome/Firefox/Word |
| `NSM:Flow` | conn.log |
| `macos:osquery` | execution of trusted tools interacting with external endpoints |
| `linux:Sysmon` | EventCode=3, 22 |
| `WinEventLog:Microsoft-Windows-Bits-Client/Operational` | BITS job lifecycle events such as job create/modify/transfer/complete and URL/remote name fields |
| `NSM:Firewall` | proxy or TLS inspection logs |
| `macos:unifiedlog` | network connection events |
| `esxi:vmkernel` | protocol egress |
| `NSM:Flow` | Outbound connection to *.tunnels.api.visualstudio.com or *.devtunnels.ms |
| `NSM:Flow` | Connections to *.devtunnels.ms or tunnels.api.visualstudio.com |
| `NSM:Flow` | HTTPs connection to tunnels.api.visualstudio.com |
| `WinEventLog:Security` | EventCode=5156, 5157 |
| `linux:osquery` | family=AF_PACKET or protocol raw; process name not in allowlist. |
| `macos:unifiedlog` | First outbound connection from the same PID/user shortly after an inbound trigger. |
| `NSM:Flow` | Outbound or inbound TFTP file transfers of ROMMON or firmware binaries |
| `NSM:Connections` | Outbound connections from newly spawned child processes or from the browser to uncommon endpoints or on anomalous ports |
| `NSM:Flow` | connection: TCP connections to ports 139/445 to multiple hosts |
| `NSM:Flow` | connection: SMB connections to multiple internal hosts |
| `auditd:SYSCALL` | connect/sendto |
| `macos:endpointsecurity` | ES_EVENT_TYPE_NOTIFY_CONNECT |
| `snmp:access` | GETBULK/GETNEXT requests for OIDs associated with configuration parameters |
| `esxi:hostd` | Service initiated connections |
| `AWS:VPCFlowLogs` | Large transfer volume (>20MB) from RDS IP range to external public IPs |
| `AWS:VPCFlowLogs` | High outbound traffic from new region resource |
| `NSM:Flow` | Outbound HTTP/S initiated by newly installed interpreter process |
| `auditd:SYSCALL` | open or connect syscalls on /tmp/ssh-* or $SSH_AUTH_SOCK |
| `NSM:Flow` | outbound connections to RMM services or to unusual destination ports |
| `macos:unifiedlog` | network sessions initiated by remote desktop apps |
| `AWS:VPCFlowLogs` | Outbound connections to port 22, 3389 |
| `auditd:SYSCALL` | socket/connect with TLS context by unexpected process |
| `NSM:Flow` | Multiple failed connections (conn_state=REJ/S0 or history has 'R') across distinct ports from the same src_ip followed by success to a specific port. |
| `auditd:SYSCALL` | socket/bind: New bind() to a previously closed port shortly after the sequence. |
| `NSM:Flow` | Sequence of REJ/S0 then SF success from same src_ip within TimeWindow. |
| `NSM:Flow` | Series of denied/closed flows to distinct ports then success to mgmt port from same src_ip within TimeWindow. |
| `NSM:Flow` | Outbound traffic spike through formerly blocked ports/subnets following config change |
| `cni:netflow` | outbound connection to internal or external APIs |
| `macos:osquery` | launchd or network_events |
| `networkdevice:syslog` | Dynamic route changes |
| `NSM:Flow` | New egress to Internet by the same UID/host shortly after terminal exec |
| `NSM:Flow` | connection: Inbound connections to SSH or VPN ports |
| `macos:unifiedlog` | Inbound connections to VNC/SSH ports |
| `NSM:Flow` | External access to container ports (2375, 6443) |
| `linux:syslog` | network |
| `macos:osquery` | process_events + launchd |
| `esxi:esxupdate` | /var/log/esxupdate.log or /var/log/vmksummary.log |
| `ebpf:syscalls` | socket connect |
| `NSM:Flow` | remote access |
| `NSM:Flow` | Outbound Connections |
| `macos:unifiedlog` | network |
| `AWS:VPCFlowLogs` | Traffic observed on mirror destination instance |
| `networkdevice:Flow` | Traffic from mirrored interface to mirror target IP |
| `macos:osquery` | process_events, socket_events |
| `esxi:vmkernel` | network activity |
| `NSM:Flow` | connection attempts |
| `NSM:Flow` | High-volume or repeated SNMP GETBULK/GETNEXT queries from untrusted or external IPs |
| `auditd:SYSCALL` | sendto/connect |
| `NSM:Flow` | outbound connections from host during or immediately after image build |
| `macos:unifiedlog` | Outbound Traffic |
| `esxi:hostd` | Service-Based Network Connection |
| `linux:syslog` | postfix/smtpd |
| `NSM:Flow` | new outbound connection from browser/office lineage |
| `NSM:Flow` | new outbound connection from exploited lineage |
| `macos:osquery` | CONNECT: Long-lived connections from remote-control parents to external IPs/domains |
| `auditd:SYSCALL` | outbound connections |
| `macos:unifiedlog` | None |
| `esxi:vmkernel` | None |
| `macos:unifiedlog` | networkd or socket |
| `macos:unifiedlog` | log stream network activity |
| `NSM:Flow` | Multiple failed connections to closed ports (history contains 'R' or conn_state in {REJ, S0}) followed by a successful handshake to a new port from same src within TimeWindowKnock |
| `auditd:SYSCALL` | socket/bind: Process binds to a new local port shortly after knock |
| `NSM:Flow` | Closed-port hits followed by success from same src_ip |
| `NSM:Flow` | Port-knock pattern from one src to device unicast,broadcast,network addresses on same port within TimeWindowKnock |
| `WinEventLog:Microsoft-Windows-WLAN-AutoConfig` | EventCode=8001, 8002, 8003 |
| `linux:syslog` | New Wi-Fi connection established or repeated association failures |
| `macos:unifiedlog` | Association and authentication events including failures and new SSIDs |
| `auditd:SYSCALL` | socket/connect calls showing SSH processes forwarding arbitrary ports |
| `esxi:vmkernel` | network session initiation with external HTTPS services |
| `WinEventLog:System` | EventCode=8001 |
| `linux:syslog` | None |
| `macos:osquery` | None |
| `auditd:SYSCALL` | openat,connect -k discovery |
| `NSM:Flow` | Unexpected inbound/outbound TFTP traffic for device image files |
| `NSM:Flow` | Unexpected or unauthorized inbound connections to SNMP, NETCONF, or RESTCONF services |
