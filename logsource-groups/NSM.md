# NSM

276 unique events

| Log Source | Channel | Data Components |
|------------|---------|-----------------|
| `NSM:Connections` | Abnormal certificate chains or non-standard ports carrying TLS | Network Traffic Content |
| `NSM:Connections` | Accepted password or publickey for user from remote IP | User Account Authentication |
| `NSM:Connections` | Accepted publickey for user from unusual IP or without tty | Logon Session Creation |
| `NSM:Connections` | Failed password or accepted password for SSH users | Application Log Content |
| `NSM:Connections` | Inbound on ports 5985/5986 | Network Traffic Flow |
| `NSM:Connections` | Internal connection logging | Network Traffic Flow |
| `NSM:Connections` | Mismatch between recorded user logon and active sessions (e.g., wtmp/utmp entries without corresponding authentication in auth.log) | Logon Session Creation |
| `NSM:Connections` | Missing new login event but session activity continues | Logon Session Creation |
| `NSM:Connections` | New outbound connection from Safari/Chrome/Firefox/Word | Network Connection Creation |
| `NSM:Connections` | Outbound Connection | Network Traffic Flow |
| `NSM:Connections` | Outbound connections from newly spawned child processes or from the browser to uncommon endpoints or on anomalous ports | Network Connection Creation |
| `NSM:Connections` | Pre-authentication keys generated or token signing anomalies | Web Credential Usage |
| `NSM:Connections` | PushNotificationSent | Application Log Content |
| `NSM:Connections` | Repeated failed authentication attempts or replay patterns | User Account Authentication |
| `NSM:Connections` | Successful login without expected MFA challenge | User Account Authentication |
| `NSM:Connections` | Successful sudo or ssh from unknown IPs | Logon Session Metadata |
| `NSM:Connections` | Symmetric encryption detected without TLS handshake sequence | Network Traffic Content |
| `NSM:Connections` | TLS handshake + HTTP headers | Network Traffic Content |
| `NSM:Connections` | Unusual POST requests to admin or upload endpoints | Network Traffic Content |
| `NSM:Connections` | new connections from exploited lineage | Network Traffic Flow |
| `NSM:Connections` | simultaneous or anomalous logon sessions across multiple systems | Logon Session Creation |
| `NSM:Connections` | sshd or PAM logins | User Account Authentication |
| `NSM:Connections` | web domain alerts | Network Connection Creation |
| `NSM:Content` | HTTP Header Metadata | Network Traffic Content |
| `NSM:Content` | SSL Certificate Metadata | Network Traffic Content |
| `NSM:Content` | TLS Fingerprint and Certificate Analysis | Network Traffic Content |
| `NSM:Content` | Traffic on RPC DRSUAPI | Network Traffic Content |
| `NSM:FLow` | dns.log | Network Traffic Content |
| `NSM:Firewall` | Anomalous TCP SYN or ACK spikes from specific source or interface | Network Traffic Content |
| `NSM:Firewall` | High rate of inbound TCP SYN or ACK packets with missing 3-way handshake completion | Network Traffic Content |
| `NSM:Firewall` | ICMP/UDP protocol anomaly | Network Traffic Content |
| `NSM:Firewall` | Outbound Connections | Network Connection Creation |
| `NSM:Firewall` | Outbound connections to 139/445 to multiple destinations | Network Traffic Flow |
| `NSM:Firewall` | Outbound encrypted traffic | Network Traffic Content |
| `NSM:Firewall` | Policy Change / Rule Update | Firewall Rule Modification |
| `NSM:Firewall` | TLS/HTTP inspection | Network Traffic Content |
| `NSM:Firewall` | pf firewall logs | Network Traffic Flow |
| `NSM:Firewall` | proxy or TLS inspection logs | Network Connection Creation |
| `NSM:Firewall` | rule_modification: New or modified firewall rules related to wireless interfaces | Firewall Rule Modification |
| `NSM:Flow` | Abnormal SMB authentication attempts correlated with poisoned LLMNR/NBT-NS sessions | Network Traffic Flow |
| `NSM:Flow` | Abnormal browser traffic volume or destination | Network Traffic Flow |
| `NSM:Flow` | Altered response metadata or blocked content based on user-agent or geolocation | Response Metadata |
| `NSM:Flow` | Base64 strings or gzip in URI, headers, or POST body | Network Traffic Content |
| `NSM:Flow` | Browser connections to known C2 or dynamic DNS domains | Network Traffic Content |
| `NSM:Flow` | C2 exfiltration | Network Traffic Content |
| `NSM:Flow` | Captured File Content | Network Traffic Content |
| `NSM:Flow` | Captured packet payloads | Network Traffic Content |
| `NSM:Flow` | Closed-port hits followed by success from same src_ip | Network Connection Creation |
| `NSM:Flow` | Connection Tracking | Network Traffic Flow |
| `NSM:Flow` | Connections from IDE hosts to marketplace/tunnel domains | Network Traffic Flow |
| `NSM:Flow` | Connections to *.devtunnels.ms or tunnels.api.visualstudio.com | Network Connection Creation |
| `NSM:Flow` | Connections to TCP 427 (SLP) or vCenter web services from untrusted sources | Network Traffic Content |
| `NSM:Flow` | Content injection observed in HTTPS responses with mismatched certificates or altered payloads | Network Traffic Content |
| `NSM:Flow` | DHCP OFFER or ACK with unauthorized DNS/gateway parameters | Network Traffic Content |
| `NSM:Flow` | Degraded encryption throughput or switch to weaker cipher suites compared to historical baselines | Network Traffic Content |
| `NSM:Flow` | Device-to-Device Deployment Flows | Network Traffic Flow |
| `NSM:Flow` | DrsAddEntry, DrsReplicaAdd, GetNCChanges calls between non-DC and DCs. | Network Traffic Content |
| `NSM:Flow` | Egress to non-approved networks from host after terminal exec | Network Traffic Content |
| `NSM:Flow` | Encrypted tunnels or proxy traffic to non-standard destinations | Network Traffic Content |
| `NSM:Flow` | Excessive gratuitous ARP replies on local subnet | Network Traffic Content |
| `NSM:Flow` | External C2 channel over TLS | Network Traffic Content |
| `NSM:Flow` | External access to container ports (2375, 6443) | Network Connection Creation |
| `NSM:Flow` | First-time egress from host after new install to unknown update endpoints | Network Traffic Flow |
| `NSM:Flow` | First-time egress to new registries/CDNs post-install/build | Network Traffic Flow |
| `NSM:Flow` | First-time egress to non-approved registries after dependency install | Network Traffic Flow |
| `NSM:Flow` | First-time egress to non-approved update hosts right after install/update | Network Traffic Flow |
| `NSM:Flow` | First-time egress to unknown registries/mirrors immediately after install | Network Traffic Flow |
| `NSM:Flow` | First-time outbound connections to package registries or unknown hosts immediately after restore/build | Network Traffic Flow |
| `NSM:Flow` | Flow Creation (NetFlow/sFlow) | Network Traffic Flow |
| `NSM:Flow` | Flow records with RSA key exchange on unexpected port | Network Traffic Flow |
| `NSM:Flow` | Flow records with entropy signatures resembling symmetric encryption | Network Traffic Flow |
| `NSM:Flow` | Flow/PCAP analysis for outbound payloads | Network Traffic Content |
| `NSM:Flow` | Gratuitous ARP replies with mismatched IP-MAC binding | Network Traffic Flow |
| `NSM:Flow` | Gratuitous or duplicate DHCP OFFER packets from non-legitimate servers | Network Traffic Flow |
| `NSM:Flow` | HTTP | Network Traffic Content |
| `NSM:Flow` | HTTP Header Metadata | Network Traffic Content |
| `NSM:Flow` | HTTP Request Logging | Network Traffic Content |
| `NSM:Flow` | HTTP payloads with SQLi/LFI/JNDI/deserialization indicators | Network Traffic Content |
| `NSM:Flow` | HTTP(S) requests with User-Agents typical of PowerShell or curl from desktop; or URIs matching paste-inspired payload hosts | Network Traffic Content |
| `NSM:Flow` | HTTP/HTTPS requests for script resources flagged by content inspection (excessive obfuscation, eval usage, unusual redirects) | Network Traffic Content |
| `NSM:Flow` | HTTP/TLS Logs | Network Traffic Content |
| `NSM:Flow` | HTTP/WebDAV requests that contain NTLMSSP or PROPFIND/MOVE/OPTIONS with Authorization: NTLM | Network Traffic Content |
| `NSM:Flow` | HTTPS API requests to Dropbox, iCloud, Google Drive, OneDrive shortly after DB tool usage | Network Traffic Content |
| `NSM:Flow` | HTTPS or custom protocol traffic with large payloads | Network Traffic Content |
| `NSM:Flow` | HTTPs connection to tunnels.api.visualstudio.com | Network Connection Creation |
| `NSM:Flow` | High volume flows with incomplete TCP sessions or single-packet bursts | Network Traffic Flow |
| `NSM:Flow` | High volumes of SYN/ACK packets with unacknowledged TCP handshakes | Network Traffic Flow |
| `NSM:Flow` | High-volume or repeated SNMP GETBULK/GETNEXT queries from untrusted or external IPs | Network Connection Creation |
| `NSM:Flow` | ICMP/UDP monitoring (tcpdump, Wireshark, Zeek) | Network Traffic Content |
| `NSM:Flow` | ICMP/UDP traffic (Wireshark, Suricata, Zeek) | Network Traffic Content |
| `NSM:Flow` | Inbound HTTP POST with suspicious payload size or user-agent | Network Traffic Content |
| `NSM:Flow` | Inbound connections to 445, 3389, 5985-5986 with high error/connection-reset rate, followed by new outbound sessions from the same host to internal assets within short interval. | Network Traffic Content |
| `NSM:Flow` | Inbound connections to monitored service ports from external or unusual internal sources; rapid follow-on lateral connections from the same host. | Network Traffic Content |
| `NSM:Flow` | Inbound one-off packet to uncommon port → outbound SF to same src_ip within TimeWindow. | Network Traffic Content |
| `NSM:Flow` | Inbound to 22/5900/8080 and follow-on internal connections. | Network Traffic Content |
| `NSM:Flow` | Inbound to tcp/427 (OpenSLP), tcp/443 (vSphere APIs), tcp/902, tcp/5989 followed by new unexpected outbound sessions from the ESXi/vCenter host. | Network Traffic Content |
| `NSM:Flow` | Injected content responses with unexpected script/malware signatures | Network Traffic Content |
| `NSM:Flow` | Inter-segment traffic | Network Traffic Flow |
| `NSM:Flow` | Knock pattern: multiple REJ/S0 to distinct closed ports then successful connection to service_port | Network Traffic Flow |
| `NSM:Flow` | Knock pattern: repeated REJ/S0 across ≥MinSequenceLen ports from same src_ip then SF success. | Network Traffic Flow |
| `NSM:Flow` | LDAP Bind/Search | Network Traffic Content |
| `NSM:Flow` | LDAP Query | Network Traffic Content |
| `NSM:Flow` | LEASE_GRANTED | Network Traffic Flow |
| `NSM:Flow` | Long-lived or hijacked SSH sessions maintained with no active user activity | Network Traffic Flow |
| `NSM:Flow` | MAC not in allow-list acquiring IP (DHCP) | Network Traffic Flow |
| `NSM:Flow` | Multiple DHCP OFFER responses for a single DISCOVER | Network Traffic Content |
| `NSM:Flow` | Multiple failed connections (conn_state=REJ/S0 or history has 'R') across distinct ports from the same src_ip followed by success to a specific port. | Network Connection Creation |
| `NSM:Flow` | Multiple failed connections to closed ports (history contains 'R' or conn_state in {REJ, S0}) followed by a successful handshake to a new port from same src within TimeWindowKnock | Network Connection Creation |
| `NSM:Flow` | NetFlow/Zeek conn.log | Network Traffic Flow |
| `NSM:Flow` | NetFlow/sFlow for odd egress to Internet from mgmt plane | Network Traffic Content |
| `NSM:Flow` | NetFlow/sFlow/PCAP | Network Traffic Flow |
| `NSM:Flow` | Network Capture TLS/HTTP | Network Traffic Content |
| `NSM:Flow` | New TCP/443 or TCP/80 to domain not previously seen for the user/host | Network Connection Creation |
| `NSM:Flow` | New VM egress to crypto-mining pools or non-approved Internet ranges within minutes of boot | Network Traffic Content |
| `NSM:Flow` | New egress from app just installed to unknown update endpoints | Network Traffic Flow |
| `NSM:Flow` | New egress from container IP/namespace to Internet or non-approved CIDRs/ASNs | Network Traffic Content |
| `NSM:Flow` | New egress to Internet by the same UID/host shortly after terminal exec | Network Connection Creation |
| `NSM:Flow` | New outbound flows to non-approved vendor hosts post install | Network Traffic Flow |
| `NSM:Flow` | New/rare egress to non-approved update hosts after install | Network Traffic Flow |
| `NSM:Flow` | None | Network Traffic Flow |
| `NSM:Flow` | Observed File Transfers | File Metadata |
| `NSM:Flow` | Observed downgrade in negotiated cipher suites or TLS/SSH versions across sessions | Network Traffic Content |
| `NSM:Flow` | Outbound Connections | Network Connection Creation |
| `NSM:Flow` | Outbound HTTP/S | Network Traffic Content |
| `NSM:Flow` | Outbound HTTP/S initiated by newly installed interpreter process | Network Connection Creation |
| `NSM:Flow` | Outbound Network Flow | Network Traffic Flow |
| `NSM:Flow` | Outbound SCP, TFTP, or FTP sessions carrying configuration file content | Network Traffic Content |
| `NSM:Flow` | Outbound TCP SYN or UDP to multiple ports/hosts | Network Traffic Flow |
| `NSM:Flow` | Outbound UDP floods targeting common reflection services with spoofed IP headers | Network Traffic Flow |
| `NSM:Flow` | Outbound connection to *.tunnels.api.visualstudio.com or *.devtunnels.ms | Network Connection Creation |
| `NSM:Flow` | Outbound connection to mining pool port (3333, 4444, 5555) | Network Traffic Flow |
| `NSM:Flow` | Outbound connections from web server binaries (apache2, nginx, php-fpm) to unknown external IPs | Network Traffic Flow |
| `NSM:Flow` | Outbound connections to TCP 139,445 and HTTP/HTTPS to WebDAV endpoints from workstation subnets | Network Traffic Flow |
| `NSM:Flow` | Outbound flow records | Network Traffic Flow |
| `NSM:Flow` | Outbound or inbound TFTP file transfers of ROMMON or firmware binaries | Network Connection Creation |
| `NSM:Flow` | Outbound requests to domains not previously resolved or associated with phishing campaigns | Network Traffic Flow |
| `NSM:Flow` | Outbound traffic from suspicious new processes post-attachment execution | Network Traffic Flow |
| `NSM:Flow` | Outbound traffic spike through formerly blocked ports/subnets following config change | Network Connection Creation |
| `NSM:Flow` | Outbound traffic to domains/IPs not previously resolved, occurring shortly after attachment download or link click | Network Traffic Flow |
| `NSM:Flow` | Outbound traffic to mining pool upon container launch | Network Traffic Flow |
| `NSM:Flow` | Outbound traffic to mining pools or proxies | Network Traffic Flow |
| `NSM:Flow` | PCAP inspection | Network Traffic Content |
| `NSM:Flow` | POST requests to .php, .jsp, .aspx files with high entropy body | Network Traffic Content |
| `NSM:Flow` | Packets with unusual flags or payloads outside established flows (e.g., WoL magic FF×6 + 16×MAC) | Network Traffic Content |
| `NSM:Flow` | Port-knock pattern from one src to device unicast,broadcast,network addresses on same port within TimeWindowKnock | Network Connection Creation |
| `NSM:Flow` | Probe responses from unauthorized APs responding to client probe requests | Network Traffic Content |
| `NSM:Flow` | Rare inbound packet characteristics (ICMP/UDP/TCP to uncommon port) from src_ip followed ≤TimeWindow by outbound SF from same host to src_ip. | Network Traffic Content |
| `NSM:Flow` | Relay patterns across IP hops | Network Traffic Content |
| `NSM:Flow` | Relayed session pathing (multi-hop) | Network Traffic Flow |
| `NSM:Flow` | Requests towards cloud metadata or command & control from pod IPs | Network Traffic Content |
| `NSM:Flow` | SMB2_LOGOFF/SMB_TREE_DISCONNECT | Network Traffic Content |
| `NSM:Flow` | SPAN or port-mirrored HTTP/S | Network Traffic Content |
| `NSM:Flow` | SSH logins or scp activity | Network Traffic Content |
| `NSM:Flow` | SSL/TLS Handshake Analysis | Network Traffic Content |
| `NSM:Flow` | SSL/TLS Inspection or PCAP | Network Traffic Content |
| `NSM:Flow` | Sequence of REJ/S0 then SF success from same src_ip within TimeWindow. | Network Connection Creation |
| `NSM:Flow` | Series of denied/closed flows to distinct ports then success to mgmt port from same src_ip within TimeWindow. | Network Connection Creation |
| `NSM:Flow` | Session History Reset | Network Traffic Content |
| `NSM:Flow` | Session Transfer Content | Network Traffic Content |
| `NSM:Flow` | Session records with TLS-like byte patterns | Network Traffic Flow |
| `NSM:Flow` | Single, low-volume inbound packet (REJ/S0/OTH or uncommon dport/protocol) from src_ip followed by outbound SF connection to src_ip. | Network Traffic Content |
| `NSM:Flow` | Source/destination IP translation inconsistent with intended policy | Network Traffic Flow |
| `NSM:Flow` | Sudden spike in incoming flows to web service ports from single/multiple IPs | Network Traffic Flow |
| `NSM:Flow` | Suspicious GET/POST; downloader patterns | Network Traffic Content |
| `NSM:Flow` | Suspicious POSTs to upload endpoints | Network Traffic Content |
| `NSM:Flow` | Suspicious URL patterns, uncommon TLDs, URL shorteners | Network Traffic Content |
| `NSM:Flow` | Suspicious URL patterns, uncommon TLDs, short-lived domains, URL shorteners; HTTP method GET/POST | Network Traffic Content |
| `NSM:Flow` | Suspicious changes in TLS certificate responses or redirected domains | Response Content |
| `NSM:Flow` | Suspicious long-lived or reattached remote desktop sessions from unexpected IPs | Network Traffic Content |
| `NSM:Flow` | Sustained abnormal inbound request rate targeting application ports (e.g., 80/443/25) | Network Traffic Content |
| `NSM:Flow` | TCP port 22 traffic | Network Traffic Flow |
| `NSM:Flow` | TCP port 5900 open | Network Traffic Flow |
| `NSM:Flow` | TCP session tracking | Network Traffic Content |
| `NSM:Flow` | TCP/UDP | Network Traffic Content |
| `NSM:Flow` | TCP: possible SYN flood or backlog limit exceeded | Host Status |
| `NSM:Flow` | TGS-REQ and AS-REQ seen for new user shortly after domain-modifying process | User Account Authentication |
| `NSM:Flow` | TLS downgrade or inconsistent DNS answers | Network Traffic Content |
| `NSM:Flow` | Traffic patterns showing downgrade from strong encryption (AES-256) to weaker or plaintext protocols | Network Traffic Content |
| `NSM:Flow` | Transferred file observations | Network Traffic Content |
| `NSM:Flow` | Unexpected ARP replies or DNS responses inconsistent with authoritative servers | Network Traffic Content |
| `NSM:Flow` | Unexpected flows between segmented networks or prohibited ports | Network Traffic Flow |
| `NSM:Flow` | Unexpected inbound/outbound TFTP traffic for device image files | Network Connection Creation |
| `NSM:Flow` | Unexpected or unauthorized inbound connections to SNMP, NETCONF, or RESTCONF services | Network Connection Creation |
| `NSM:Flow` | Unexpected route changes or duplicate gateway advertisements | Network Traffic Flow |
| `NSM:Flow` | Unexpected script or binary content returned in HTTP response body | Network Traffic Content |
| `NSM:Flow` | Unusual Base64-encoded content in URI, headers, or POST body | Network Traffic Content |
| `NSM:Flow` | Unusual request pattern leading up to service crash (e.g., malformed or oversized payload) | Network Traffic Content |
| `NSM:Flow` | Unusual responses to LLMNR (UDP 5355) or NBT-NS (UDP 137) queries from unauthorized hosts | Network Traffic Content |
| `NSM:Flow` | alert log | Network Traffic Flow |
| `NSM:Flow` | alternate ports | Network Traffic Flow |
| `NSM:Flow` | conn.log | Network Connection Creation, Network Traffic Content, Network Traffic Flow |
| `NSM:Flow` | conn.log + files.log + ssl.log | Network Traffic Content |
| `NSM:Flow` | conn.log + ssl.log with Tor fingerprinting | Network Traffic Flow |
| `NSM:Flow` | conn.log or flow data | Network Traffic Flow |
| `NSM:Flow` | conn.log or http.log | Network Traffic Content |
| `NSM:Flow` | conn.log, http.log, dns.log, ssl.log | Network Traffic Content |
| `NSM:Flow` | conn.log, icmp.log | Network Traffic Flow |
| `NSM:Flow` | conn.log, ssl.log | Network Traffic Content |
| `NSM:Flow` | connection attempts | Network Connection Creation |
| `NSM:Flow` | connection metadata | Network Traffic Flow |
| `NSM:Flow` | connection: Inbound connections to SSH or VPN ports | Network Connection Creation |
| `NSM:Flow` | connection: SMB connections to multiple internal hosts | Network Connection Creation |
| `NSM:Flow` | connection: TCP connections to ports 139/445 to multiple hosts | Network Connection Creation |
| `NSM:Flow` | container egress to unknown IPs/domains | Network Traffic Content |
| `NSM:Flow` | dns, ssl, conn | Network Traffic Content |
| `NSM:Flow` | dns.log | Network Traffic Content |
| `NSM:Flow` | dns: DNS labels with excessive length and restricted custom alphabets (e.g., base36 only) repeated frequently | Network Traffic Content |
| `NSM:Flow` | flow records | Network Traffic Flow |
| `NSM:Flow` | ftp.log, conn.log | Network Traffic Content |
| `NSM:Flow` | ftp.log, conn.log, smb_files.log | Network Traffic Content |
| `NSM:Flow` | ftp.log, smb_files.log | Network Traffic Content |
| `NSM:Flow` | host switch egress data | Network Traffic Content |
| `NSM:Flow` | http, dns, smb, ssl logs | Network Traffic Content |
| `NSM:Flow` | http.log | Network Traffic Content |
| `NSM:Flow` | http.log, conn.log | Network Traffic Content |
| `NSM:Flow` | http.log, files.log | Network Traffic Content |
| `NSM:Flow` | http.log, ftp.log | Network Traffic Content |
| `NSM:Flow` | http.log, ssl.log | Network Traffic Content |
| `NSM:Flow` | http.log, ssl.log, websocket.log | Network Traffic Content |
| `NSM:Flow` | http.request: HTTP requests and responses for specific script resources, unexpected content-types (application/octet-stream for script URLs), suspicious referrers, or obfuscated javascript resources | Network Traffic Content |
| `NSM:Flow` | http/file-xfer: Inbound/outbound transfer of ELF shared objects | Network Traffic Content |
| `NSM:Flow` | http/file-xfer: Outbound transfer of large video-like MIME types soon after capture | Network Traffic Content |
| `NSM:Flow` | http: Base64/MIME looking payloads from ESXi host IP | Network Traffic Content |
| `NSM:Flow` | http: HTTP bodies from ESXi host IPs containing long, non-standard tokens | Network Traffic Content |
| `NSM:Flow` | http: HTTP bodies/headers contain long tokens with non-standard alphabets or constant-size periodic POSTs | Network Traffic Content |
| `NSM:Flow` | http: HTTP body contains long Base64 sections | Network Traffic Content |
| `NSM:Flow` | http: HTTP body or headers contain long Base64 sections; gzip/deflate + Base64 | Network Traffic Content |
| `NSM:Flow` | http: suspicious long tokens with custom alphabets in body/headers | Network Traffic Content |
| `NSM:Flow` | http::post: Outbound HTTP POST from host shortly after DB export activity | Network Traffic Content |
| `NSM:Flow` | http::request: Network connection to package registry or C2 from interpreter shortly after install | Network Traffic Content |
| `NSM:Flow` | http::request: Outbound HTTP initiated by Python interpreter | Network Traffic Content |
| `NSM:Flow` | http::response: HTTP responses with suspicious content-type for scripts, long obfuscated javascript bodies, or redirects to exploit kit domains | Network Traffic Content |
| `NSM:Flow` | icmp.log, weird.log | Network Traffic Content |
| `NSM:Flow` | large HTTPS POST requests to text storage domains | Network Traffic Content |
| `NSM:Flow` | large HTTPS POST requests to webhook endpoints | Network Traffic Content |
| `NSM:Flow` | large HTTPS outbound uploads | Network Traffic Flow |
| `NSM:Flow` | large outbound HTTPS uploads to repo domains | Network Traffic Flow |
| `NSM:Flow` | large outbound data flows or long-duration connections | Network Traffic Flow |
| `NSM:Flow` | large transfer from management IPs to unauthorized host | Network Traffic Content |
| `NSM:Flow` | large upload to firmware interface port or path | Network Traffic Content |
| `NSM:Flow` | ldap.log | Network Traffic Content |
| `NSM:Flow` | mirror/SPAN port | Network Traffic Content |
| `NSM:Flow` | mqtt.log / xmpp.log (custom log feeds) | Network Traffic Content |
| `NSM:Flow` | mqtt.log or AMQP custom log | Network Traffic Content |
| `NSM:Flow` | mqtt.log, xmpp.log, amqp.log | Network Traffic Content |
| `NSM:Flow` | network_flow: bytes_out >> bytes_in, fixed packet sizes/intervals to non-approved CIDRs | Network Traffic Flow |
| `NSM:Flow` | new outbound connection from browser/office lineage | Network Connection Creation |
| `NSM:Flow` | new outbound connection from exploited lineage | Network Connection Creation |
| `NSM:Flow` | outbound connections from host during or immediately after image build | Network Connection Creation |
| `NSM:Flow` | outbound connections to RMM services or to unusual destination ports | Network Connection Creation |
| `NSM:Flow` | outbound egress from web host after suspicious request | Network Traffic Content |
| `NSM:Flow` | packet capture or DPI logs | Network Traffic Content |
| `NSM:Flow` | pf firewall logs | Network Traffic Flow |
| `NSM:Flow` | port 5900 inbound | Network Traffic Flow |
| `NSM:Flow` | query: High-volume LDAP traffic with filters targeting groupPolicyContainer attributes | Network Traffic Content |
| `NSM:Flow` | remote CLI session detection | Network Traffic Content |
| `NSM:Flow` | remote access | Network Connection Creation |
| `NSM:Flow` | remote login and transfer | Network Traffic Content |
| `NSM:Flow` | session behavior | Network Traffic Content |
| `NSM:Flow` | session stats with bytes_out > bytes_in | Network Traffic Flow |
| `NSM:Flow` | smb_command: TreeConnectAndX to \\*\IPC$ / srvsvc or Trans2/NT_CREATE for listing shares | OS API Execution |
| `NSM:Flow` | smb_files.log | Network Share Access |
| `NSM:Flow` | smtp.log | Network Traffic Content |
| `NSM:Flow` | smtp.log, conn.log | Network Traffic Content |
| `NSM:Flow` | ssh connections originating from third-party CIDRs | Network Traffic Content |
| `NSM:Flow` | ssh/smb connections to internal resources from third-party devices | Network Traffic Content |
| `NSM:Flow` | ssl.log | Network Traffic Content |
| `NSM:Flow` | ssl.log (for TLS handshake analysis), dns.log (tunneling indicators) | Network Traffic Content |
| `NSM:Flow` | ssl.log + http.log | Network Traffic Content |
| `NSM:Flow` | ssl.log - Certificate Analysis | Network Traffic Content |
| `NSM:Flow` | ssl.log, conn.log | Network Traffic Content |
| `NSM:Flow` | ssl.log, x509.log | Network Traffic Content |
| `NSM:Flow` | sustained outbound HTTPS sessions with high data volume | Network Traffic Flow |
| `NSM:Flow` | uncommon ports | Network Traffic Flow |
| `NSM:Flow` | unexpected network activity initiated shortly after shell session starts | Network Traffic Content |
| `NSM:firewall` | inbound connection to port 5900 | Network Traffic Flow |
