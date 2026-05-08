# DC0085 - Network Traffic Content

## Description

The full packet capture (PCAP) or session data that logs both protocol headers and payload content. This allows analysts to inspect command and control (C2) traffic, exfiltration, and other suspicious activity within network communications. Unlike metadata-based logs, full content analysis enables deeper protocol inspection, payload decoding, and forensic investigations.

*Data Collection Measures:*

- Network Packet Capture (Full Content Logging)
    - Wireshark / tcpdump / tshark
        - Full packet captures (PCAP files) for manual analysis or IDS correlation. `tcpdump -i eth0 -w capture.pcap`
    - Zeek (formerly Bro)
        - Extracts protocol headers and payload details into structured logs. `echo "redef Log::default_store = Log::ASCII;" > local.zeek | zeek -Cr capture.pcap local.zeek`
    - Suricata / Snort (IDS/IPS with PCAP Logging)
        - Deep packet inspection (DPI) with signature-based and behavioral analysis. `suricata -c /etc/suricata/suricata.yaml -i eth0 -l /var/log/suricata`
- Host-Based Collection
    - Sysmon Event ID 22 – DNS Query Logging, Captures DNS requests made by processes, useful for detecting C2 domains.
    - Sysmon Event ID 3 – Network Connection Initiated, Logs process-to-network connection relationships.
    - AuditD (Linux) – syscall=connect, Monitors outbound network requests from processes. `auditctl -a always,exit -F arch=b64 -S connect -k network_activity`
- Cloud & SaaS Traffic Collection
    - AWS VPC Flow Logs / Azure NSG Flow Logs / Google VPC Flow Logs, Captures metadata about inbound/outbound network traffic.
    - Cloud IDS (AWS GuardDuty, Azure Sentinel, Google Chronicle), Detects malicious activity in cloud environments by analyzing network traffic patterns.

## Log Sources

| Log Source | Channel |
|------------|---------|
| `Network Traffic` | None |
| `ebpf:syscalls` | Process within container accesses link-local address 169.254.169.254 |
| `WebProxy:AccessLogs` | SSRF-like patterns accessing metadata endpoint through proxy (e.g., Host: 169.254.169.254) |
| `NSM:Flow` | mqtt.log / xmpp.log (custom log feeds) |
| `NSM:Flow` | mqtt.log or AMQP custom log |
| `NSM:Flow` | mqtt.log, xmpp.log, amqp.log |
| `networkdevice:syslog` | ACL/Firewall rule modification or new route injection |
| `m365:office` | External HTTP/DNS connection from Office binary shortly after macro trigger |
| `NSM:Flow` | TCP/UDP |
| `NSM:Flow` | TCP session tracking |
| `NSM:Flow` | Captured packet payloads |
| `NSM:Flow` | session behavior |
| `esxi:vmkernel` | Network activity |
| `NSM:Flow` | External C2 channel over TLS |
| `NSM:Flow` | http/file-xfer: Inbound/outbound transfer of ELF shared objects |
| `NSM:Flow` | http.log, files.log |
| `NSM:Flow` | unexpected network activity initiated shortly after shell session starts |
| `NSM:Flow` | HTTP/WebDAV requests that contain NTLMSSP or PROPFIND/MOVE/OPTIONS with Authorization: NTLM |
| `NSM:Flow` | http.log, ssl.log |
| `NSM:Flow` | http.log, conn.log |
| `NSM:Flow` | SPAN or port-mirrored HTTP/S |
| `NSM:Flow` | http.log, ssl.log, websocket.log |
| `macos:unifiedlog` | process + network metrics correlation for bandwidth saturation |
| `docker:stats` | unusual network TX/RX byte deltas |
| `etw:Microsoft-Windows-WinINet` | HTTPS Inspection |
| `NSM:Flow` | ssl.log |
| `linux:syslog` | Query to suspicious domain with high entropy or low reputation |
| `macos:unifiedlog` | DNS query with pseudo-random subdomain patterns |
| `azure:vpcflow` | HTTP requests to 169.254.169.254 or Azure Metadata endpoints |
| `NSM:Flow` | Browser connections to known C2 or dynamic DNS domains |
| `NSM:Flow` | Session History Reset |
| `NSM:Flow` | HTTP  |
| `macos:unifiedlog` | network flow |
| `linux:syslog` | curl\|wget\|python .*http |
| `macos:unifiedlog` | curl\|osascript.*open location |
| `NSM:Flow` | query: High-volume LDAP traffic with filters targeting groupPolicyContainer attributes |
| `etw:Microsoft-Windows-NDIS-PacketCapture` | TLS Handshake/Network Flow |
| `NSM:Flow` | HTTP/TLS Logs |
| `macos:unifiedlog` | subsystem: com.apple.network |
| `linux:syslog` | Unexpected SQL or application log entries showing tampered or malformed data |
| `EDR:hunting` | Advanced Hunting: DeviceProcessEvents + DeviceNetworkEvents |
| `NSM:Flow` | Suspicious URL patterns, uncommon TLDs, short-lived domains, URL shorteners; HTTP method GET/POST |
| `NSM:Flow` | Suspicious URL patterns, uncommon TLDs, URL shorteners |
| `macos:unifiedlog` | open URL\|clicked link\|LSQuarantineAttach |
| `NSM:Flow` | Suspicious GET/POST; downloader patterns |
| `NSM:Flow` | SSH logins or scp activity |
| `NSM:Flow` | remote login and transfer |
| `esxi:vob` | NFS/remote access logs |
| `AWS:VPCFlowLogs` | Traffic between instances |
| `NSM:Flow` | conn.log |
| `WinEventLog:System` | EventCode=5005 (WLAN), EventCode=302 (Bluetooth) |
| `macos:unifiedlog` | None |
| `NSM:Flow` | Suspicious long-lived or reattached remote desktop sessions from unexpected IPs |
| `NSM:Flow` | HTTP payloads with SQLi/LFI/JNDI/deserialization indicators |
| `NSM:Flow` | outbound egress from web host after suspicious request |
| `NSM:Flow` | Requests towards cloud metadata or command & control from pod IPs |
| `ALB:HTTPLogs` | AWS ALB/ELB/GCP/Azure Application Gateway HTTP logs with unusual methods, long URIs, serialized payloads, 4xx/5xx bursts |
| `NSM:Flow` | Connections to TCP 427 (SLP) or vCenter web services from untrusted sources |
| `NSM:Flow` | NetFlow/sFlow for odd egress to Internet from mgmt plane |
| `NSM:Flow` | packet capture or DPI logs |
| `NSM:Flow` | http.log |
| `NSM:Flow` | SMB2_LOGOFF/SMB_TREE_DISCONNECT |
| `macos:unifiedlog` | Connections to suspicious domains with mismatched certificate or unusual patterns |
| `NSM:Flow` | Unusual Base64-encoded content in URI, headers, or POST body |
| `NSM:Flow` | Base64 strings or gzip in URI, headers, or POST body |
| `macos:unifiedlog` | HTTP POST with encoded content in user-agent or cookie field |
| `esxi:vmkernel` | Outbound traffic using encoded payloads post-login |
| `macos:unifiedlog` | Suspicious outbound HTTPS requests to domains flagged as newly registered or untrusted after spearphishing message interaction |
| `NSM:Flow` | Inbound connections to 445, 3389, 5985-5986 with high error/connection-reset rate, followed by new outbound sessions from the same host to internal assets within short interval. |
| `NSM:Flow` | Inbound connections to monitored service ports from external or unusual internal sources; rapid follow-on lateral connections from the same host. |
| `NSM:Flow` | Inbound to tcp/427 (OpenSLP), tcp/443 (vSphere APIs), tcp/902, tcp/5989 followed by new unexpected outbound sessions from the ESXi/vCenter host. |
| `NSM:Flow` | Inbound to 22/5900/8080 and follow-on internal connections. |
| `NSM:Flow` | http: HTTP body or headers contain long Base64 sections; gzip/deflate + Base64 |
| `NSM:Flow` | http: HTTP body contains long Base64 sections |
| `NSM:Flow` | http: Base64/MIME looking payloads from ESXi host IP |
| `NSM:Flow` | LDAP Bind/Search |
| `NSM:Flow` | LDAP Query |
| `macos:unifiedlog` | log stream (subsystem: com.apple.system.networking) |
| `NSM:Flow` | smtp.log |
| `NSM:Flow` | smtp.log, conn.log |
| `NSM:Flow` | remote CLI session detection |
| `macos:unifiedlog` | Encrypted connection with anomalous payload entropy |
| `esxcli:network` | Socket sessions with randomized payloads inconsistent with TLS |
| `NSM:Connections` | Symmetric encryption detected without TLS handshake sequence |
| `NSM:Flow` | http.log, ftp.log |
| `NSM:Flow` | PCAP inspection |
| `NSM:Flow` | large HTTPS POST requests to webhook endpoints |
| `esxi:vmkernel` | HTTPS POST connections to webhook endpoints |
| `NSM:Flow` | Single, low-volume inbound packet (REJ/S0/OTH or uncommon dport/protocol) from src_ip followed by outbound SF connection to src_ip. |
| `NSM:Flow` | Rare inbound packet characteristics (ICMP/UDP/TCP to uncommon port) from src_ip followed ≤TimeWindow by outbound SF from same host to src_ip. |
| `NSM:Flow` | Inbound one-off packet to uncommon port → outbound SF to same src_ip within TimeWindow. |
| `networkdevice:config` | NAT table modification (add/update/delete rule) |
| `NSM:Flow` | large upload to firmware interface port or path |
| `macos:unifiedlog` | Rapid incoming TLS handshakes or HTTP requests in quick succession |
| `NSM:Flow` | http.request: HTTP requests and responses for specific script resources, unexpected content-types (application/octet-stream for script URLs), suspicious referrers, or obfuscated javascript resources |
| `NSM:Flow` | http::response: HTTP responses with suspicious content-type for scripts, long obfuscated javascript bodies, or redirects to exploit kit domains |
| `NSM:Flow` | HTTP/HTTPS requests for script resources flagged by content inspection (excessive obfuscation, eval usage, unusual redirects) |
| `NSM:Connections` | TLS handshake + HTTP headers |
| `NSM:Flow` | ssl.log + http.log |
| `macos:unifiedlog` | network, socket, and http logs |
| `NSM:Firewall` | TLS/HTTP inspection |
| `NSM:Flow` | http/file-xfer: Outbound transfer of large video-like MIME types soon after capture |
| `container:proxy` | outbound/inbound network activity from spawned pods |
| `esxcli:network` | listening sockets bound to non-standard ports |
| `NSM:Flow` | Outbound SCP, TFTP, or FTP sessions carrying configuration file content |
| `NSM:Flow` | Session Transfer Content |
| `NSM:Flow` | Captured File Content |
| `NSM:Flow` | C2 exfiltration |
| `NSM:Flow` | Transferred file observations |
| `apache:access_log` | Unusual HTTP POST or PUT requests to paths such as '/uploads/', '/admin/', or CMS plugin folders |
| `NSM:Flow` | http::post: Outbound HTTP POST from host shortly after DB export activity |
| `NSM:Flow` | HTTPS API requests to Dropbox, iCloud, Google Drive, OneDrive shortly after DB tool usage |
| `NSM:Flow` | Observed downgrade in negotiated cipher suites or TLS/SSH versions across sessions |
| `NSM:Flow` | New egress from container IP/namespace to Internet or non-approved CIDRs/ASNs |
| `NSM:Flow` | New VM egress to crypto-mining pools or non-approved Internet ranges within minutes of boot |
| `docker:events` | remote API calls to /containers/create or /containers/{id}/start |
| `NSM:Flow` | http::request: Network connection to package registry or C2 from interpreter shortly after install |
| `linux:syslog` | Integrity mismatch warnings or malformed packets detected |
| `NSM:Flow` | http::request: Outbound HTTP initiated by Python interpreter |
| `WinEventLog:Sysmon` | Outbound requests with forged tokens/cookies in headers |
| `linux:syslog` | DNS response IPs followed by connections to non-standard calculated ports |
| `macos:unifiedlog` | DNS responses followed by connections to ports outside standard ranges |
| `macos:unifiedlog` | Persistent outbound traffic to mining domains |
| `macos:unifiedlog` | Encrypted session initiation by unexpected binary |
| `esxi:vmkernel` | Inspection of sockets showing encrypted sessions from non-baseline processes |
| `NSM:Connections` | Abnormal certificate chains or non-standard ports carrying TLS |
| `NSM:Flow` | DrsAddEntry, DrsReplicaAdd, GetNCChanges calls between non-DC and DCs. |
| `NSM:Flow` | large HTTPS POST requests to text storage domains |
| `esxi:vmkernel` | HTTPS POST connections to pastebin-like domains |
| `NSM:Flow` | Unexpected ARP replies or DNS responses inconsistent with authoritative servers |
| `NSM:Flow` | TLS downgrade or inconsistent DNS answers |
| `NSM:Flow` | Unusual request pattern leading up to service crash (e.g., malformed or oversized payload) |
| `AWS:VPCFlowLogs` | Large volume of malformed or synthetic payloads to application endpoints prior to failure |
| `networkconfig ` | interface flag PROMISC, netstat \| ip link \| ethtool |
| `macos:unifiedlog` | eventMessage = 'promiscuous' |
| `networkdevice:syslog` | config change (e.g., logging buffered, pcap buffers) |
| `macos:unifiedlog` | outbound HTTPS connections to code repository APIs |
| `azure:activity` | networkInsightsLogs |
| `gcp:audit` | network.query* |
| `WinEventLog:Microsoft-Windows-Windows Defender/Operational` | Unusual external domain access |
| `NSM:Flow` | conn.log or http.log |
| `NSM:Flow` | http: HTTP bodies/headers contain long tokens with non-standard alphabets or constant-size periodic POSTs |
| `NSM:Flow` | dns: DNS labels with excessive length and restricted custom alphabets (e.g., base36 only) repeated frequently |
| `NSM:Flow` | http: suspicious long tokens with custom alphabets in body/headers |
| `NSM:Flow` | http: HTTP bodies from ESXi host IPs containing long, non-standard tokens |
| `NSM:Flow` | Traffic patterns showing downgrade from strong encryption (AES-256) to weaker or plaintext protocols |
| `NSM:Flow` | HTTP(S) requests with User-Agents typical of PowerShell or curl from desktop; or URIs matching paste-inspired payload hosts |
| `NSM:Flow` | Egress to non-approved networks from host after terminal exec |
| `NSM:Flow` | Flow/PCAP analysis for outbound payloads |
| `NSM:Flow` | conn.log + files.log + ssl.log |
| `macos:unifiedlog` | eventMessage = 'open', 'sendto', 'connect' |
| `NSM:Flow` | HTTPS or custom protocol traffic with large payloads |
| `esxi:vmkernel` | network stack module logs |
| `NSM:Flow` | Unexpected script or binary content returned in HTTP response body |
| `NSM:Flow` | Injected content responses with unexpected script/malware signatures |
| `NSM:Flow` | Content injection observed in HTTPS responses with mismatched certificates or altered payloads |
| `NSM:Firewall` | High rate of inbound TCP SYN or ACK packets with missing 3-way handshake completion |
| `NSM:Firewall` | Anomalous TCP SYN or ACK spikes from specific source or interface |
| `saas:confluence` | REST API access from non-browser agents |
| `Netfilter/iptables` | Forwarded packets log |
| `NSM:Flow` | Relay patterns across IP hops |
| `NSM:Firewall` | Outbound encrypted traffic |
| `NSM:Flow` | ldap.log |
| `macos:unifiedlog` | dns-sd, mDNSResponder, socket activity |
| `networkdevice:IDS` | content inspection / PCAP / HTTP body |
| `NSM:Flow` | Probe responses from unauthorized APs responding to client probe requests |
| `auditd:SYSCALL` | setsockopt, ioctl modifying ARP entries |
| `NSM:Flow` | Excessive gratuitous ARP replies on local subnet |
| `NSM:Flow` | Inbound HTTP POST with suspicious payload size or user-agent |
| `NSM:Flow` | POST requests to .php, .jsp, .aspx files with high entropy body |
| `NSM:Flow` | dns.log |
| `NSM:FLow` | dns.log |
| `NSM:Flow` | Encrypted tunnels or proxy traffic to non-standard destinations |
| `esxi:vmkernel` | Suspicious traffic filtered or redirected by VM networking stack |
| `NSM:Flow` | large transfer from management IPs to unauthorized host |
| `NSM:Flow` | Sustained abnormal inbound request rate targeting application ports (e.g., 80/443/25) |
| `NSM:Flow` | ftp.log, smb_files.log |
| `NSM:Flow` | ftp.log, conn.log |
| `NSM:Flow` | mirror/SPAN port |
| `NSM:Flow` | ftp.log, conn.log, smb_files.log |
| `linux:syslog` | Multiple NXDOMAIN responses and high entropy domains |
| `NSM:Flow` | SSL/TLS Inspection or PCAP |
| `NSM:Flow` | conn.log, ssl.log |
| `macos:unifiedlog` | process + network activity |
| `NSM:Flow` | http, dns, smb, ssl logs |
| `NSM:Flow` | dns, ssl, conn |
| `NSM:Flow` | conn.log, http.log, dns.log, ssl.log |
| `networkdevice:syslog` | Authentication failures, unexpected community string usage, or unauthorized SNMPv1/v2 requests |
| `NSM:Flow` | ICMP/UDP traffic (Wireshark, Suricata, Zeek) |
| `NSM:Flow` | icmp.log, weird.log |
| `NSM:Flow` | ICMP/UDP monitoring (tcpdump, Wireshark, Zeek) |
| `esxi:vmkernel` | VMCI syslog entries |
| `NSM:Firewall` | ICMP/UDP protocol anomaly |
| `NSM:Flow` | Unusual responses to LLMNR (UDP 5355) or NBT-NS (UDP 137) queries from unauthorized hosts |
| `NSM:Flow` | DHCP OFFER or ACK with unauthorized DNS/gateway parameters |
| `NSM:Flow` | Multiple DHCP OFFER responses for a single DISCOVER |
| `NSM:Flow` | SSL/TLS Handshake Analysis |
| `NSM:Flow` | HTTP Header Metadata |
| `NSM:Flow` | Network Capture TLS/HTTP |
| `NSM:Content` | SSL Certificate Metadata |
| `NSM:Content` | HTTP Header Metadata |
| `NSM:Content` | TLS Fingerprint and Certificate Analysis |
| `NSM:Flow` | container egress to unknown IPs/domains |
| `gcp:vpcflow` | first 5m egress to unknown ASNs |
| `NSM:Flow` | HTTP Request Logging |
| `WinEventLog:iis` | IIS Logs |
| `macos:unifiedlog` | subsystem=com.apple.WebKit |
| `AWS:VPCFlowLogs` | Unusual volume of data transferred from S3 storage endpoints to non-corporate IPs |
| `NSM:Flow` | ssh connections originating from third-party CIDRs |
| `NSM:Flow` | ssh/smb connections to internal resources from third-party devices |
| `NSM:Flow` | Degraded encryption throughput or switch to weaker cipher suites compared to historical baselines |
| `NSM:Flow` | ssl.log (for TLS handshake analysis), dns.log (tunneling indicators) |
| `NSM:Flow` | host switch egress data |
| `NSM:Flow` | Outbound HTTP/S |
| `macos:unifiedlog` | subsystem: com.apple.WebKit or com.apple.WebKit.Networking |
| `NSM:Flow` | ssl.log - Certificate Analysis |
| `NSM:Flow` | ssl.log, conn.log |
| `NSM:Flow` | ssl.log, x509.log |
| `NSM:Flow` | Packets with unusual flags or payloads outside established flows (e.g., WoL magic FF×6 + 16×MAC) |
| `WIDS:AssociationLogs` | Unauthorized AP or anomalous MAC address connection attempts |
| `macos:unifiedlog` | encrypted outbound traffic carrying unexpected application data |
| `esxcli:network` | listening sockets bound with non-standard encapsulated protocols |
| `macos:unifiedlog` | Persistent outbound connections with consistent periodicity |
| `macos:unifiedlog` | TLS connections with abnormal handshake sequence or self-signed cert |
| `esxcli:network` | Socket inspection showing RSA key exchange outside baseline endpoints |
| `IDS:TLSInspection` | Malformed certs, incomplete asymmetric handshakes, or invalid CAs |
| `macos:unifiedlog` | Web server process initiating outbound TCP connections not tied to normal server traffic |
| `macos:unifiedlog` | outbound TLS connections to cloud storage providers |
| `saas:box` | API calls exceeding baseline thresholds |
| `macos:unifiedlog` | outbound HTTPS connections to cloud storage APIs |
| `AWS:VPCFlowLogs` | High volume internal-to-internal IP transfer or cross-account cloud transfer |
| `etw:Microsoft-Windows-WinINet` | WinINet API telemetry |
| `macos:unifiedlog` | process, network |
| `NSM:Connections` | Unusual POST requests to admin or upload endpoints |
| `NSM:Flow` | Suspicious POSTs to upload endpoints |
| `networkdevice:syslog` | Authentication failures or unusual community string usage in SNMP queries |
| `API:ConfigRepoAudit` | Access to configuration repository endpoints, unusual enumeration requests or mass downloads |
| `NSM:Content` | Traffic on RPC DRSUAPI |
| `macos:unifiedlog` | process = 'ssh' OR eventMessage CONTAINS 'ssh' |
