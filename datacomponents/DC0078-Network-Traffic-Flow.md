# DC0078 - Network Traffic Flow

## Description

Summarized network packet data that captures session-level details such as source/destination IPs, ports, protocol types, timestamps, and data volume, without storing full packet payloads. This is commonly used for traffic analysis, anomaly detection, and network performance monitoring.

## Log Sources

| Log Source | Channel |
|------------|---------|
| `Network Traffic` | None |
| `macos:osquery` | socket_events |
| `NSM:Flow` | Unexpected flows between segmented networks or prohibited ports |
| `snmp:config` | Configuration change traps or policy enforcement failures |
| `NSM:Flow` | First-time outbound connections to package registries or unknown hosts immediately after restore/build |
| `NSM:Flow` | First-time egress to new registries/CDNs post-install/build |
| `NSM:Flow` | First-time egress to non-approved registries after dependency install |
| `NSM:Flow` | Outbound connections to TCP 139,445 and HTTP/HTTPS to WebDAV endpoints from workstation subnets |
| `NSM:Flow` | large outbound data flows or long-duration connections |
| `AWS:VPCFlowLogs` | egress > 90th percentile or frequent connection reuse |
| `NSM:Flow` | conn.log |
| `auditd:SYSCALL` | socket/connect |
| `esxi:syslog` | esxcli network vswitch or DNS resolver configuration updates |
| `esxi:vobd` | Network Events |
| `iptables:LOG` | TCP connections |
| `NSM:Flow` | connection metadata |
| `wineventlog:dhcp` | DHCP Lease Granted |
| `NSM:Flow` | LEASE_GRANTED |
| `NSM:Flow` | MAC not in allow-list acquiring IP (DHCP) |
| `Windows Firewall Log` | SMB over high port |
| `NSM:Connections` | Internal connection logging |
| `NSM:Flow` | pf firewall logs |
| `esxi:vmkernel` | /var/log/vmkernel.log |
| `NSM:Flow` | Inter-segment traffic |
| `NSM:Flow` | None |
| `NSM:Flow` | Long-lived or hijacked SSH sessions maintained with no active user activity |
| `AWS:VPCFlowLogs` | VPC/NSG flow logs for pod/instance egress to Internet or metadata |
| `macos:unifiedlog` | Suspicious outbound traffic from browser binary to non-standard domains |
| `NSM:Flow` | Abnormal browser traffic volume or destination |
| `NSM:Flow` | Outbound requests to domains not previously resolved or associated with phishing campaigns |
| `NSM:Flow` | Outbound traffic to domains/IPs not previously resolved, occurring shortly after attachment download or link click |
| `M365Defender:DeviceNetworkEvents` | NetworkConnection: bytes_sent >> bytes_received anomaly |
| `PF:Logs` | outbound flows with bytes_out >> bytes_in |
| `NSX:FlowLogs` | network_flow: bytes_out >> bytes_in to external |
| `NSM:Flow` | NetFlow/Zeek conn.log |
| `AWS:VPCFlowLogs` | Outbound data flows |
| `NSM:Flow` | Flow records with entropy signatures resembling symmetric encryption |
| `NSM:Flow` | flow records |
| `networkdevice:syslog` | flow records |
| `macos:unifiedlog` | HTTPS POST to known webhook URLs |
| `saas:api` | Webhook registrations or repeated POST activity |
| `NSM:Flow` | Source/destination IP translation inconsistent with intended policy |
| `SNMP:DeviceLogs` | Unexpected NAT translation statistics or rule insertion events |
| `NSM:Flow` | Sudden spike in incoming flows to web service ports from single/multiple IPs |
| `AWS:VPCFlowLogs` | Unusual volume of inbound packets from single source across short time interval |
| `NSM:Flow` | port 5900 inbound |
| `NSM:Flow` | TCP port 5900 open |
| `NSM:firewall` | inbound connection to port 5900 |
| `NSM:Firewall` | Outbound connections to 139/445 to multiple destinations |
| `VPCFlowLogs:All` | High volume internal traffic with low entropy indicating looped or malicious DoS script |
| `NSM:Flow` | NetFlow/sFlow/PCAP |
| `NSM:Flow` | Outbound Network Flow |
| `macos:unifiedlog` | com.apple.network |
| `NSM:Flow` | Device-to-Device Deployment Flows |
| `auditd:SYSCALL` | socket/connect syscalls |
| `macos:unifiedlog` | outbound TCP/UDP traffic over unexpected port |
| `esxi:vpxd` | ESXi service connections on unexpected ports |
| `iptables:LOG` | OUTBOUND |
| `macos:unifiedlog` | tcp/udp |
| `esxi:hostd` | CLI network calls |
| `NSM:Flow` | Outbound traffic from suspicious new processes post-attachment execution |
| `macos:unifiedlog` | Suspicious anomalies in transmitted data integrity during application network operations |
| `esxi:syslog` | DNS resolution events leading to outbound traffic on unexpected ports |
| `NSM:Flow` | Outbound traffic to mining pools or proxies |
| `AWS:VPCFlowLogs` | Outbound flow logs to known mining pools |
| `container:cni` | Outbound network traffic to mining proxies |
| `esxi:vpxd` | TLS session established by ESXi service to unapproved endpoint |
| `NSM:Flow` | Session records with TLS-like byte patterns |
| `macos:unifiedlog` | HTTPS POST requests to pastebin.com or similar |
| `NetFlow:Flow` | new outbound connections from exploited process tree |
| `NSM:Connections` | new connections from exploited lineage |
| `NSM:Flow` | Unexpected route changes or duplicate gateway advertisements |
| `WinEventLog:Microsoft-Windows-Windows Firewall With Advanced Security/Firewall` | EventCode=2004, 2005, 2006 |
| `NSM:Flow` | Knock pattern: repeated REJ/S0 across ≥MinSequenceLen ports from same src_ip then SF success. |
| `macos:unifiedlog` | Firewall/PF anchor load or rule change events. |
| `networkdevice:syslog` | Config/ACL changes, line vty transport input changes, telnet/ssh/http(s) enable, image/feature module changes. |
| `NSM:Flow` | First-time egress to non-approved update hosts right after install/update |
| `NSM:Flow` | New outbound flows to non-approved vendor hosts post install |
| `NSM:Flow` | New/rare egress to non-approved update hosts after install |
| `NSM:Flow` | large outbound HTTPS uploads to repo domains |
| `esxi:vmkernel` | HTTPS traffic to repository domains |
| `NSM:Flow` | alert log |
| `esxi:vmkernel` | None |
| `NSM:Flow` | Outbound flow records |
| `m365:defender` | NetworkConnection: high out:in ratio, periodic beacons, protocol mismatch |
| `PF:Logs` | high out:in ratio or fixed-size periodic flows |
| `NSM:Flow` | network_flow: bytes_out >> bytes_in, fixed packet sizes/intervals to non-approved CIDRs |
| `auditd:SYSCALL` | connect or sendto system call with burst pattern |
| `macos:unifiedlog` | sudden burst in outgoing packets from same PID |
| `AWS:VPCFlowLogs` | source instance sends large volume of traffic in short window |
| `NSM:Flow` | session stats with bytes_out > bytes_in |
| `NIDS:Flow` | session stats with bytes_out > bytes_in |
| `esxi:vpxa` | connection attempts and data transmission logs |
| `PF:Logs` | External traffic to remote access services |
| `NSM:Flow` | High volumes of SYN/ACK packets with unacknowledged TCP handshakes |
| `dns:query` | Outbound resolution to hidden service domains (e.g., `.onion`) |
| `NSM:Flow` | conn.log + ssl.log with Tor fingerprinting |
| `macos:unifiedlog` | forwarded encrypted traffic |
| `NSM:Flow` | Relayed session pathing (multi-hop) |
| `NSM:Flow` | Outbound TCP SYN or UDP to multiple ports/hosts |
| `containerd:runtime` | container-level outbound traffic events |
| `WLANLogs:Association` | Multiple APs advertising the same SSID but with different BSSID/MAC or encryption type |
| `linux:osquery` | socket_events |
| `WinEventLog:Security` | ARP cache modification attempts observed through event tracing or security baselines |
| `NSM:Flow` | Gratuitous ARP replies with mismatched IP-MAC binding |
| `macos:unifiedlog` | ARP table updates inconsistent with expected gateway or DHCP lease assignments |
| `macos:unifiedlog` | networkd or com.apple.network |
| `macos:unifiedlog` | log stream 'eventMessage contains "dns_request"' |
| `esxi:syslog` | /var/log/syslog.log |
| `AWS:CloudTrail` | CreateTrafficMirrorSession or ModifyTrafficMirrorTarget |
| `networkdevice:syslog` | Config change: CLI/NETCONF/SNMP – 'monitor session', 'mirror port' |
| `NSM:Flow` | Outbound UDP floods targeting common reflection services with spoofed IP headers |
| `macos:unifiedlog` | Outbound UDP spikes to external reflector IPs |
| `AWS:VPCFlowLogs` | Large outbound UDP traffic to multiple public reflector IPs |
| `macos:unifiedlog` | High entropy domain queries with multiple NXDOMAINs |
| `esxi:syslog` | Frequent DNS queries with high entropy names or NXDOMAIN results |
| `vpxd.log` | API communication |
| `NSM:Connections` | Outbound Connection |
| `NSM:Flow` | Connection Tracking |
| `NSM:Firewall` | pf firewall logs |
| `NSM:Flow` | Flow Creation (NetFlow/sFlow) |
| `NSM:Flow` | conn.log, icmp.log |
| `NSM:Flow` | Abnormal SMB authentication attempts correlated with poisoned LLMNR/NBT-NS sessions |
| `NSM:Flow` | Gratuitous or duplicate DHCP OFFER packets from non-legitimate servers |
| `NSM:Connections` | Inbound on ports 5985/5986 |
| `linux:syslog` | Multiple IP addresses assigned to the same domain in rapid sequence |
| `macos:unifiedlog` | Rapid domain-to-IP resolution changes for same domain |
| `esxi:syslog` | Frequent DNS resolution of same domain with rotating IPs |
| `NSM:Flow` | uncommon ports |
| `NSM:Flow` | alternate ports |
| `esxi:vpxd` | None |
| `NSM:Flow` | conn.log or flow data |
| `esxi:vmkernel` | egress log analysis |
| `esxi:vmkernel` | egress logs |
| `NSM:Flow` | High volume flows with incomplete TCP sessions or single-packet bursts |
| `NSM:Flow` | Knock pattern: multiple REJ/S0 to distinct closed ports then successful connection to service_port |
| `macos:unifiedlog` | Firewall rule enable/disable or listen socket changes |
| `networkdevice:syslog` | Config/ACL/line vty changes, service enable (telnet/ssh/http(s)), module reloads |
| `auditd:SYSCALL` | ioctl: Changes to wireless network interfaces (up, down, reassociate) |
| `macos:osquery` | query: Historical list of associated SSIDs compared against baseline |
| `NSM:Flow` | First-time egress from host after new install to unknown update endpoints |
| `NSM:Flow` | First-time egress to unknown registries/mirrors immediately after install |
| `NSM:Flow` | New egress from app just installed to unknown update endpoints |
| `esxi:vpxd` | ESXi processes relaying traffic via SSH or unexpected ports |
| `NSM:Flow` | Outbound connection to mining pool port (3333, 4444, 5555) |
| `NSM:Flow` | Outbound traffic to mining pool upon container launch |
| `NSM:Flow` | Flow records with RSA key exchange on unexpected port |
| `NSM:Flow` | Outbound connections from web server binaries (apache2, nginx, php-fpm) to unknown external IPs |
| `NSM:Flow` | sustained outbound HTTPS sessions with high data volume |
| `NSM:Flow` | Connections from IDE hosts to marketplace/tunnel domains |
| `macos:unifiedlog` | Outbound connections from IDE processes to marketplace/tunnel domains |
| `NSM:Flow` | large HTTPS outbound uploads |
| `esxi:vmkernel` | network flows to external cloud services |
| `NSM:Flow` | TCP port 22 traffic |
| `esxi:vmkernel` | port 22 access |
