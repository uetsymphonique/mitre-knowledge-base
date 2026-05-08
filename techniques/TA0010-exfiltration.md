### T1011 - Exfiltration Over Other Network Medium
Adversaries may attempt to exfiltrate data over a different network medium than the command and control channel. If the command and control network is a wired Internet connection, the exfiltration may occur, for example, over a WiFi connection, modem, cellular data connection, Bluetooth, or another radio frequency (RF) channel. Adversaries may choose to do this if they have sufficient access or proximity, and the connection might not be secured or defended as well as the primary Internet-connected channel because it is not routed through the same enterprise network.
**Detection**
- [AN0214] **[macOS]** AppleScript or system calls to activate WiFi/Bluetooth interfaces (`networksetup`, `blueutil`), followed by exfiltration via AirDrop, cloud sync, or network socket.
  - **Log sources:** `macos:unifiedlog` (None) [Network Traffic Content], `macos:osquery` (process_events) [Process Creation], `macos:osquery` (interface_details ) [Host Status]
- [AN0213] **[Linux]** Use of `rfkill`, `nmcli`, or low-level tools (e.g., `iw`, `hcitool`, `pppd`) to enable alternate interfaces followed by data transfer via non-primary NICs.
  - **Log sources:** `auditd:SYSCALL` (None) [Command Execution], `NSM:Flow` (None) [Network Traffic Flow]
- [AN0212] **[Windows]** Execution of file transfer or network access activity through non-primary interfaces (e.g., WiFi, Bluetooth, cellular) by processes not typically associated with such behavior (e.g., rundll32, powershell, regsvr32).
  - **Log sources:** `WinEventLog:Sysmon` (EventCode=3, 22) [Network Connection Creation], `WinEventLog:System` (EventCode=5005 (WLAN), EventCode=302 (Bluetooth)) [Network Traffic Content], `WinEventLog:Sysmon` (EventCode=11) [File Creation]
Adversaries may attempt to exfiltrate data over a different network medium than the command and control channel. If the command and control network is a wired Internet connection, the exfiltration may occur, for example, over a WiFi connection, modem, cellular data connection, Bluetooth, or another radio frequency (RF) channel. Adversaries may choose to do this if they have sufficient access or proximity, and the connection might not be secured or defended as well as the primary Internet-connected channel because it is not routed through the same enterprise network.


### T1011.001 - Exfiltration Over Other Network Medium: Exfiltration Over Bluetooth
Adversaries may attempt to exfiltrate data over Bluetooth rather than the command and control channel. If the command and control network is a wired Internet connection, an adversary may opt to exfiltrate data using a Bluetooth communication channel. Adversaries may choose to do this if they have sufficient access and proximity. Bluetooth connections might not be secured or defended as well as the primary Internet-connected channel because it is not routed through the same enterprise network.
**Detection**
- [AN1532] **[Linux]** Use of hcitool, bluetoothctl, or rfcomm to initialize Bluetooth connection paired with recent file reads by the same user or session.
  - **Log sources:** `auditd:SYSCALL` (None) [Command Execution], `linux:syslog` (None) [Network Connection Creation], `linux:osquery` (None) [File Access]
- [AN1531] **[Windows]** Detection of non-interactive or suspicious processes accessing Bluetooth interfaces and transmitting outbound traffic following file access or staging activity.
  - **Log sources:** `WinEventLog:System` (EventCode=8001) [Network Connection Creation], `WinEventLog:Sysmon` (EventCode=11) [File Creation], `WinEventLog:Sysmon` (EventCode=1) [Process Creation]
- [AN1533] **[macOS]** Observation of `blueutil`/`networksetup` commands or low-level APIs toggling Bluetooth or initiating transfers, especially if paired with recent large file read activity by non-GUI processes.
  - **Log sources:** `macos:unifiedlog` (None) [Command Execution], `macos:osquery` (None) [Network Connection Creation], `macos:osquery` (None) [File Access]
**Procedure Examples**
- [S0143] Flame: Flame has a module named BeetleJuice that contains Bluetooth functionality that may be used in different ways, including transmitting encoded information from the infected system over the Bluetooth protocol, acting as a Bluetooth beacon, and identifying other Bluetooth devices in the vicinity.


### T1020 - Automated Exfiltration
Adversaries may exfiltrate data, such as sensitive documents, through the use of automated processing after being gathered during Collection. When automated exfiltration is used, other exfiltration techniques likely apply as well to transfer the information out of the network, such as Exfiltration Over C2 Channel and Exfiltration Over Alternative Protocol.
**Detection**
- [AN1115] **[macOS]** Observation of LaunchAgents or LaunchDaemons establishing periodic external connections indicative of automated data transfer.
  - **Log sources:** `macos:unifiedlog` (process: exec) [Process Creation], `macos:unifiedlog` (network) [Network Connection Creation], `macos:cron` (cron/launchd) [Scheduled Job Creation]
- [AN1114] **[Linux]** Background scripts (e.g., via cron) or daemons transmitting data repeatedly to remote IPs or URLs.
  - **Log sources:** `auditd:SYSCALL` (execve) [Process Creation], `NSM:Flow` (Outbound Connections) [Network Connection Creation]
- [AN1113] **[Windows]** Detection of automated tools or scripts periodically transmitting data to external destinations using scheduled tasks or background processes.
  - **Log sources:** `WinEventLog:Security` (EventCode=4688) [Process Creation], `WinEventLog:Sysmon` (EventCode=3, 22) [Network Connection Creation]
**Procedure Examples**
- [S0491] StrongPity: StrongPity can automatically exfiltrate collected documents to the C2 server.
- [S0395] LightNeuron: LightNeuron can be configured to automatically exfiltrate files under a specified directory.
- [C0001] Frankenstein: During Frankenstein, the threat actors collected information via Empire, which was automatically sent back to the adversary's C2.
- [G0121] Sidewinder: Sidewinder has configured tools to automatically send collected files to attacker controlled servers.
- [S0363] Empire: Empire has the ability to automatically send collected data back to the threat actors' C2.
- [S0600] Doki: Doki has used a script that gathers information from a hardcoded list of IP addresses and uploads to an Ngrok URL.
- [C0046] ArcaneDoor: ArcaneDoor included scripted exfiltration of collected data.
- [S0090] Rover: Rover automatically searches for files on local drives based on a predefined list of file extensions and sends them to the command and control server every 60 minutes. Rover also automatically sends keylogger files and screenshots to the C2 server on a regular timeframe.
- [S1017] OutSteel: OutSteel can automatically upload collected files to its C2 server.
- [S0643] Peppy: Peppy has the ability to automatically exfiltrate files and keylogs.


### T1020.001 - Automated Exfiltration: Traffic Duplication
Adversaries may leverage traffic mirroring in order to automate data exfiltration over compromised infrastructure. Traffic mirroring is a native feature for some devices, often used for network analysis. For example, devices may be configured to forward network traffic to one or more destinations for analysis by a network analyzer or other monitoring device. Adversaries may abuse traffic mirroring to mirror or redirect network traffic through other infrastructure they control. Malicious modifications to network devices to enable traffic redirection may be possible through ROMMONkit or Patch System Image. Many cloud-based environments also support traffic mirroring. For example, AWS Traffic Mirroring, GCP Packet Mirroring, and Azure vTap allow users to define specified instances to collect traffic from and specified targets to send collected traffic to. Adversaries may use traffic duplication in conjunction with Network Sniffing, Input Capture, or Adversary-in-the-Middle depending on the goals and objectives of the adversary.
**Detection**
- [AN1132] **[Network Devices]** Unauthorized mirroring sessions initiated on routers/switches (e.g., via `monitor session`, `mirror port`) coupled with outbound traffic from mirrored interface to unexpected destinations.
  - **Log sources:** `networkdevice:syslog` (Config change: CLI/NETCONF/SNMP – 'monitor session', 'mirror port') [Network Traffic Flow], `networkdevice:Flow` (Traffic from mirrored interface to mirror target IP) [Network Connection Creation]
- [AN1131] **[IaaS]** Configuration changes to virtual TAP/mirror policies that forward traffic to unapproved destinations. Detection correlates management plane API calls with mirrored traffic observation.
  - **Log sources:** `AWS:CloudTrail` (CreateTrafficMirrorSession or ModifyTrafficMirrorTarget) [Network Traffic Flow], `AWS:VPCFlowLogs` (Traffic observed on mirror destination instance) [Network Connection Creation]
Adversaries may leverage traffic mirroring in order to automate data exfiltration over compromised infrastructure. Traffic mirroring is a native feature for some devices, often used for network analysis. For example, devices may be configured to forward network traffic to one or more destinations for analysis by a network analyzer or other monitoring device. Adversaries may abuse traffic mirroring to mirror or redirect network traffic through other infrastructure they control. Malicious modifications to network devices to enable traffic redirection may be possible through ROMMONkit or Patch System Image. Many cloud-based environments also support traffic mirroring. For example, AWS Traffic Mirroring, GCP Packet Mirroring, and Azure vTap allow users to define specified instances to collect traffic from and specified targets to send collected traffic to. Adversaries may use traffic duplication in conjunction with Network Sniffing, Input Capture, or Adversary-in-the-Middle depending on the goals and objectives of the adversary.


### T1029 - Scheduled Transfer
Adversaries may schedule data exfiltration to be performed only at certain times of day or at certain intervals. This could be done to blend traffic patterns with normal activity or availability. When scheduled exfiltration is used, other exfiltration techniques likely apply as well to transfer the information out of the network, such as Exfiltration Over C2 Channel or Exfiltration Over Alternative Protocol.
**Detection**
- [AN1119] **[Linux]** Detection of cron-based or script-based recurring transfers where the same script, user, or destination reappears at predictable intervals.
  - **Log sources:** `auditd:SYSCALL` (execve) [Process Creation], `linux:cron` (cron activity) [Scheduled Job Metadata], `NSM:Flow` (Outbound Connections) [Network Connection Creation]
- [AN1118] **[Windows]** Recurring network exfiltration initiated by scheduled or script-based processes exhibiting time-based regularity and consistent external destinations.
  - **Log sources:** `WinEventLog:Sysmon` (EventCode=1) [Process Creation], `WinEventLog:Sysmon` (EventCode=3, 22) [Network Connection Creation], `WinEventLog:System` (EventCode=106, 200) [Scheduled Job Metadata]
- [AN1120] **[macOS]** LaunchAgent or launchd recurring jobs initiating data transfer to consistent external IPs or domains with repeat timing signatures.
  - **Log sources:** `macos:endpointsecurity` (ES_EVENT_TYPE_NOTIFY_EXEC) [Process Creation], `macos:launchd` (launchd.plist and logs) [Scheduled Job Metadata], `macos:unifiedlog` (networkd or com.apple.network) [Network Traffic Flow]
**Procedure Examples**
- [S0283] jRAT: jRAT can be configured to reconnect at certain intervals.
- [S0696] Flagpro: Flagpro has the ability to wait for a specified time interval between communicating with and executing commands from C2.
- [S1019] Shark: Shark can pause C2 communications for a specified time.
- [S0395] LightNeuron: LightNeuron can be configured to exfiltrate data during nighttime or working hours.
- [S0223] POWERSTATS: POWERSTATS can sleep for a given number of seconds.
- [S0200] Dipsind: Dipsind can be configured to only run during normal working hours, which would make its communications harder to distinguish from normal traffic.
- [S0126] ComRAT: ComRAT has been programmed to sleep outside local business hours (9 to 5, Monday to Friday).
- [S0045] ADVSTORESHELL: ADVSTORESHELL collects, compresses, encrypts, and exfiltrates data to the C2 server every 10 minutes.
- [S0211] Linfo: Linfo creates a backdoor through which remote attackers can change the frequency at which compromised hosts contact remote C2 infrastructure.
- [S1100] Ninja: Ninja can configure its agent to work only in specific time frames.


### T1030 - Data Transfer Size Limits
An adversary may exfiltrate data in fixed size chunks instead of whole files or limit packet sizes below certain thresholds. This approach may be used to avoid triggering network data transfer threshold alerts.
**Detection**
- [AN0596] **[Windows]** Adversary uses a process to establish outbound connections that transmit uniform packet sizes at a consistent interval, avoiding threshold-based network alerts.
  - **Log sources:** `WinEventLog:Sysmon` (EventCode=3, 22) [Network Connection Creation], `NSM:Flow` (NetFlow/sFlow/PCAP) [Network Traffic Flow]
- [AN0597] **[Linux]** Outbound connections from non-network-facing processes repeatedly send similarly sized payloads within uniform time intervals.
  - **Log sources:** `auditd:SYSCALL` (connect/sendto) [Network Connection Creation], `NSM:Flow` (Outbound Network Flow) [Network Traffic Flow]
- [AN0598] **[macOS]** Processes on macOS initiate external connections that consistently transmit data in fixed sizes using LaunchAgents or unexpected users.
  - **Log sources:** `macos:unifiedlog` (com.apple.network) [Network Traffic Flow], `macos:endpointsecurity` (ES_EVENT_TYPE_NOTIFY_CONNECT) [Network Connection Creation]
**Procedure Examples**
- [G1040] Play: Play has split victims' files into chunks for exfiltration.
- [G1014] LuminousMoth: LuminousMoth has split archived files into multiple parts to bypass a 5MB limit.
- [G0027] Threat Group-3390: Threat Group-3390 actors have split RAR files for exfiltration into parts.
- [S0264] OopsIE: OopsIE exfiltrates command output and collected files to its C2 server in 1500-byte blocks.
- [S0150] POSHSPY: POSHSPY uploads data in 2048-byte chunks.
- [C0026] C0026: During C0026, the threat actors split encrypted archives containing stolen files and information into 3MB parts prior to exfiltration.
- [S0487] Kessel: Kessel can split the data to be exilftrated into chunks that will fit in subdomains of DNS queries.
- [S1020] Kevin: Kevin can exfiltrate data to the C2 server in 27-character chunks.
- [S0644] ObliqueRAT: ObliqueRAT can break large files of interest into smaller chunks to prepare them for exfiltration.
- [S1200] StealBit: StealBit can be configured to exfiltrate files at a specified rate to evade network detection mechanisms.


### T1041 - Exfiltration Over C2 Channel
Adversaries may steal data by exfiltrating it over an existing command and control channel. Stolen data is encoded into the normal communications channel using the same protocol as command and control communications.
**Detection**
- [AN0988] **[Windows]** Identifies suspicious outbound traffic volume mismatches from processes that typically do not generate network activity, particularly over C2 protocols like HTTPS, DNS, or custom TCP/UDP ports, following file or data access.
  - **Log sources:** `WinEventLog:Sysmon` (EventCode=1) [Process Creation], `WinEventLog:Sysmon` (EventCode=3, 22) [Network Connection Creation], `NSM:Flow` (Flow/PCAP analysis for outbound payloads) [Network Traffic Content], `WinEventLog:Security` (EventCode=4663, 4670, 4656) [File Access]
- [AN0989] **[Linux]** Monitors for processes reading sensitive files then immediately initiating unusual outbound connections or bulk transfer sessions over persistent sockets, particularly with encrypted or binary payloads.
  - **Log sources:** `auditd:SYSCALL` (execve) [Process Creation], `auditd:SYSCALL` (connect) [Network Connection Creation], `NSM:Flow` (conn.log + files.log + ssl.log) [Network Traffic Content], `NSM:Flow` (session stats with bytes_out > bytes_in) [Network Traffic Flow]
- [AN0990] **[macOS]** Detects unauthorized applications or scripts accessing sensitive data followed by establishing encrypted outbound communication to rare external destinations or with abnormal byte ratios.
  - **Log sources:** `macos:unifiedlog` (eventMessage = 'open', 'sendto', 'connect') [Network Traffic Content], `macos:osquery` (socket_events) [Network Traffic Flow], `macos:osquery` (process_events) [Process Creation]
- [AN0991] **[ESXi]** Detects VMs sending outbound traffic through non-standard services or to unknown destinations. Exfiltration over reverse shells tunneled via VMkernel or custom payloads routed via hostd/vpxa.
  - **Log sources:** `esxi:vpxa` (connection attempts and data transmission logs) [Network Traffic Flow], `esxi:vmkernel` (network stack module logs) [Network Traffic Content], `esxi:syslog` (guest OS outbound transfer logs) [File Access]
**Procedure Examples**
- [S1172] OilBooster: OilBooster can use an actor-controlled OneDrive account for C2 communication and exfiltration.
- [S0459] MechaFlounder: MechaFlounder has the ability to send the compromised user's account name and hostname within a URL to C2.
- [S0428] PoetRAT: PoetRAT has exfiltrated data over the C2 channel.
- [S0445] ShimRatReporter: ShimRatReporter sent generated reports to the C2 via HTTP POST requests.
- [S1019] Shark: Shark has the ability to upload files from the compromised host over a DNS or HTTP C2 channel.
- [S1210] Sagerunex: Sagerunex encrypts collected system data then exfiltrates via existing command and control channels.
- [S0533] SLOTHFULMEDIA: SLOTHFULMEDIA has sent system information to a C2 server via HTTP and HTTPS POST requests.
- [S1183] StrelaStealer: StrelaStealer exfiltrates collected email credentials via HTTP POST to command and control servers.
- [S1017] OutSteel: OutSteel can upload files from a compromised host over its C2 channel.
- [S1246] BeaverTail: BeaverTail has exfiltrated data collected from victim devices to C2 servers.


### T1048 - Exfiltration Over Alternative Protocol
Adversaries may steal data by exfiltrating it over a different protocol than that of the existing command and control channel. The data may also be sent to an alternate network location from the main command and control server. Alternate protocols include FTP, SMTP, HTTP/S, DNS, SMB, or any other network protocol not being used as the main command and control channel. Adversaries may also opt to encrypt and/or obfuscate these alternate channels. Exfiltration Over Alternative Protocol can be done using various common operating system utilities such as Net/SMB or FTP. On macOS and Linux curl may be used to invoke protocols such as HTTP/S or FTP/S to exfiltrate data from a system. Many IaaS and SaaS platforms (such as Microsoft Exchange, Microsoft SharePoint, GitHub, and AWS S3) support the direct download of files, emails, source code, and other sensitive information via the web console or Cloud API.
**Detection**
- [AN0367] **[Windows]** Detects unusual outbound file transfer behavior using protocols like FTP, SMB, SMTP, or DNS, involving non-standard processes, off-hour activity, or uncommonly high volume.
  - **Log sources:** `WinEventLog:Sysmon` (EventCode=3, 22) [Network Connection Creation], `WinEventLog:Sysmon` (EventCode=11) [File Creation], `WinEventLog:Security` (EventCode=4688) [Process Creation]
- [AN0371] **[ESXi]** Detects outbound traffic from hostd/vpxa or guest VM interfaces using unauthorized protocols such as FTP, HTTP POST bursts, or long-lived DNS tunnels.
  - **Log sources:** `esxi:hostd` (logline inspection) [Command Execution], `esxi:vmkernel` (protocol egress) [Network Connection Creation]
- [AN0368] **[Linux]** Detects file exfiltration using tools like curl, scp, or custom binaries over protocols such as FTP, HTTP/S, or DNS tunneling, especially outside baseline user behavior.
  - **Log sources:** `auditd:SYSCALL` (execve) [Process Creation], `auditd:SYSCALL` (connect) [Network Connection Creation], `auditd:SYSCALL` (open) [File Access], `auditd:SYSCALL` (write) [File Modification], `NSM:Flow` (NetFlow/Zeek conn.log) [Network Traffic Flow]
- [AN0370] **[IaaS]** Detects access to cloud APIs or CLI tools to move or sync files from sensitive buckets to external endpoints using protocols like HTTPS or S3 APIs.
  - **Log sources:** `AWS:CloudTrail` (GetObject, CopyObject) [Cloud Storage Access], `AWS:VPCFlowLogs` (Outbound data flows) [Network Traffic Flow]
- [AN0369] **[macOS]** Detects non-native file transfer via curl, Python scripts, or AppleScript using uncommon protocols like FTP, SMTP, or DNS exfiltration through mDNSResponder abuse.
  - **Log sources:** `macos:unifiedlog` (log stream (subsystem: com.apple.system.networking)) [Network Traffic Content], `macos:osquery` (process_events) [Process Creation], `macos:osquery` (file_events) [File Creation]
**Procedure Examples**
- [S0482] Bundlore: Bundlore uses the curl -s -L -o command to exfiltrate archived data to a URL.
- [S0428] PoetRAT: PoetRAT has used a .NET tool named dog.exe to exiltrate information over an e-mail account.
- [G1040] Play: Play has used WinSCP to exfiltrate data to actor-controlled accounts.
- [G0139] TeamTNT: TeamTNT has sent locally staged files with collected credentials to C2 servers using cURL.
- [S0631] Chaes: Chaes has exfiltrated its collected data from the infected machine to the C2, sometimes using the MIME protocol.
- [S0503] FrameworkPOS: FrameworkPOS can use DNS tunneling for exfiltration of credit card data.
- [S0641] Kobalos: Kobalos can exfiltrate credentials over the network via UDP.
- [S0203] Hydraq: Hydraq connects to a predefined domain on port 443 to exfil gathered information.
- [S0677] AADInternals: AADInternals can directly download cloud user data such as OneDrive files.


### T1048.001 - Exfiltration Over Alternative Protocol: Exfiltration Over Symmetric Encrypted Non-C2 Protocol
Adversaries may steal data by exfiltrating it over a symmetrically encrypted network protocol other than that of the existing command and control channel. The data may also be sent to an alternate network location from the main command and control server. Symmetric encryption algorithms are those that use shared or the same keys/secrets on each end of the channel. This requires an exchange or pre-arranged agreement/possession of the value used to encrypt and decrypt data. Network protocols that use asymmetric encryption often utilize symmetric encryption once keys are exchanged, but adversaries may opt to manually share keys and implement symmetric cryptographic algorithms (ex: RC4, AES) vice using mechanisms that are baked into a protocol. This may result in multiple layers of encryption (in protocols that are natively encrypted such as HTTPS) or encryption in protocols that not typically encrypted (such as HTTP or FTP).
**Detection**
- [AN1389] **[Windows]** Detects the execution of non-browser processes establishing outbound encrypted network connections using uncommon symmetric encryption protocols (e.g., AES via PowerShell or custom scripts) to alternate external destinations.
  - **Log sources:** `WinEventLog:Sysmon` (EventCode=3, 22) [Network Connection Creation], `WinEventLog:Sysmon` (EventCode=1) [Process Creation]
- [AN1391] **[macOS]** Detects symmetric key-based encryption operations (e.g., AES via Python, AppleScript, or OpenSSL) followed by unusual outbound connections from non-browser applications or scripted tools.
  - **Log sources:** `macos:unifiedlog` (log stream process subsystem) [Process Creation], `macos:osquery` (socket_events) [Network Traffic Flow], `macos:unifiedlog` (log stream network activity) [Network Connection Creation]
- [AN1392] **[ESXi]** Detects unexpected encrypted egress traffic from management services (e.g., hostd) or guest VMs utilizing symmetric encryption without traditional protocols (e.g., FTP with embedded AES ciphertext).
  - **Log sources:** `esxi:vmkernel` (egress log analysis) [Network Traffic Flow], `esxi:hostd` (execution + payload hints) [Command Execution], `NSM:Flow` (host switch egress data) [Network Traffic Content]
- [AN1390] **[Linux]** Detects command-line utilities or scripts using encryption libraries or symmetric algorithms (e.g., OpenSSL AES, GPG, Python + PyCrypto) in conjunction with outbound file transfers or traffic to external destinations.
  - **Log sources:** `auditd:SYSCALL` (execve) [Process Creation], `auditd:SYSCALL` (connect) [Network Connection Creation], `NSM:Flow` (conn.log or flow data) [Network Traffic Flow], `NSM:Flow` (ssl.log (for TLS handshake analysis), dns.log (tunneling indicators)) [Network Traffic Content]
Adversaries may steal data by exfiltrating it over a symmetrically encrypted network protocol other than that of the existing command and control channel. The data may also be sent to an alternate network location from the main command and control server. Symmetric encryption algorithms are those that use shared or the same keys/secrets on each end of the channel. This requires an exchange or pre-arranged agreement/possession of the value used to encrypt and decrypt data. Network protocols that use asymmetric encryption often utilize symmetric encryption once keys are exchanged, but adversaries may opt to manually share keys and implement symmetric cryptographic algorithms (ex: RC4, AES) vice using mechanisms that are baked into a protocol. This may result in multiple layers of encryption (in protocols that are natively encrypted such as HTTPS) or encryption in protocols that not typically encrypted (such as HTTP or FTP).


### T1048.002 - Exfiltration Over Alternative Protocol: Exfiltration Over Asymmetric Encrypted Non-C2 Protocol
Adversaries may steal data by exfiltrating it over an asymmetrically encrypted network protocol other than that of the existing command and control channel. The data may also be sent to an alternate network location from the main command and control server. Asymmetric encryption algorithms are those that use different keys on each end of the channel. Also known as public-key cryptography, this requires pairs of cryptographic keys that can encrypt/decrypt data from the corresponding key. Each end of the communication channels requires a private key (only in the procession of that entity) and the public key of the other entity. The public keys of each entity are exchanged before encrypted communications begin. Network protocols that use asymmetric encryption (such as HTTPS/TLS/SSL) often utilize symmetric encryption once keys are exchanged. Adversaries may opt to use these encrypted mechanisms that are baked into a protocol.
**Detection**
- [AN1416] **[ESXi]** Detects unexpected encrypted outbound connections from management components or guest VMs using TLS, particularly after data volume spikes or script-based orchestration from within guest environments.
  - **Log sources:** `esxi:hostd` (event stream) [Command Execution], `esxi:vmkernel` (egress logs) [Network Traffic Flow]
- [AN1415] **[macOS]** Detects abnormal encrypted network connections (via TLS/HTTPS) initiated by non-browser binaries, particularly after sensitive file access or compression events.
  - **Log sources:** `macos:osquery` (socket_events) [Network Traffic Flow], `macos:osquery` (process_events) [Process Creation], `macos:unifiedlog` (log stream - file provider subsystem) [File Access], `NSM:Flow` (ssl.log, x509.log) [Network Traffic Content]
- [AN1413] **[Windows]** Detects non-browser processes that establish encrypted outbound connections (e.g., TLS/SSL) to unfamiliar or atypical destinations for the host/user, following a data staging or compression event.
  - **Log sources:** `WinEventLog:Sysmon` (EventCode=3, 22) [Network Connection Creation], `WinEventLog:Sysmon` (EventCode=1) [Process Creation], `WinEventLog:Security` (EventCode=4663, 4670, 4656) [File Access], `NSM:Flow` (ssl.log - Certificate Analysis) [Network Traffic Content]
- [AN1414] **[Linux]** Detects staged file access (e.g., archive or obfuscation), followed by an encrypted outbound connection (TLS/HTTPS) from unusual processes such as curl/wget, Python scripts, or custom binaries.
  - **Log sources:** `auditd:SYSCALL` (execve) [Process Creation], `auditd:SYSCALL` (connect) [Network Connection Creation], `NSM:Flow` (ssl.log, conn.log) [Network Traffic Content], `auditd:SYSCALL` (open, read) [File Access]
**Procedure Examples**
- [G0007] APT28: APT28 has exfiltrated archives of collected data previously staged on a target's OWA server via HTTPS.
- [S0483] IcedID: IcedID has exfiltrated collected data via HTTPS.
- [G1012] CURIUM: CURIUM has used SMTPS to exfiltrate collected data from victims.
- [S1040] Rclone: Rclone can exfiltrate data over SFTP or HTTPS via WebDAV.
- [G1046] Storm-1811: Storm-1811 has exfiltrated captured user credentials via Secure Copy Protocol (SCP).
- [C0024] SolarWinds Compromise: During the SolarWinds Compromise, APT29 exfiltrated collected data over a simple HTTPS request to a password-protected archive staged on a victim's OWA servers.


### T1048.003 - Exfiltration Over Alternative Protocol: Exfiltration Over Unencrypted Non-C2 Protocol
Adversaries may steal data by exfiltrating it over an un-encrypted network protocol other than that of the existing command and control channel. The data may also be sent to an alternate network location from the main command and control server. Adversaries may opt to obfuscate this data, without the use of encryption, within network protocols that are natively unencrypted (such as HTTP, FTP, or DNS). This may include custom or publicly available encoding/compression algorithms (such as base64) as well as embedding data within protocol headers and fields.
**Detection**
- [AN0427] **[Network Devices]** Detects use of unencrypted protocols (e.g., TFTP, FTP, HTTP) to transfer configuration files, routing tables, or logs to untrusted IP addresses, especially using administrative commands like `copy run ftp:`.
  - **Log sources:** `networkdevice:cli` (CLI command logs) [Command Execution], `networkdevice:syslog` (flow records) [Network Traffic Flow], `NSM:Flow` (PCAP inspection) [Network Traffic Content]
- [AN0426] **[ESXi]** Detects shell-based scripts accessing configuration files or snapshots and transmitting them over unencrypted protocols such as FTP or HTTP to non-management IPs.
  - **Log sources:** `esxi:hostd` (event stream) [Command Execution], `NSM:Flow` (flow records) [Network Traffic Flow], `NSM:Flow` (http.log) [Network Traffic Content]
- [AN0424] **[Linux]** Detects file access or compression utilities followed by outbound connections using curl, wget, ftp, or custom binaries communicating over unencrypted protocols.
  - **Log sources:** `auditd:SYSCALL` (execve) [Process Creation], `auditd:SYSCALL` (connect) [Network Connection Creation], `NSM:Flow` (http.log, ftp.log) [Network Traffic Content], `NSM:Flow` (flow records) [Network Traffic Flow]
- [AN0425] **[macOS]** Detects abnormal outbound HTTP/FTP connections by local scripts or binaries outside of standard browser activity, following access to local documents or user data.
  - **Log sources:** `macos:osquery` (socket_events) [Network Traffic Flow], `macos:osquery` (process_events) [Process Creation], `macos:unifiedlog` (log stream - file subsystem) [File Access], `NSM:Flow` (http.log, ftp.log) [Network Traffic Content]
- [AN0423] **[Windows]** Detects data access or staging events followed by outbound data flows using unencrypted protocols (e.g., FTP, HTTP) initiated by unexpected processes or to rare destinations.
  - **Log sources:** `WinEventLog:Sysmon` (EventCode=3, 22) [Network Connection Creation], `WinEventLog:Sysmon` (EventCode=1) [Process Creation], `WinEventLog:Security` (EventCode=4663, 4670, 4656) [File Access], `NSM:Flow` (http.log, ftp.log) [Network Traffic Content]
**Procedure Examples**
- [G0032] Lazarus Group: Lazarus Group malware SierraBravo-Two generates an email message via SMTP containing information about newly infected victims.
- [G0061] FIN8: FIN8 has used FTP to exfiltrate collected data.
- [S0125] Remsec: Remsec can exfiltrate data via a DNS tunnel or email, separately from its C2 channel.
- [S0492] CookieMiner: CookieMiner has used the curl --upload-file command to exfiltrate data over HTTP.
- [S1043] ccf32: ccf32 can upload collected data and files to an FTP server.
- [S1116] WARPWIRE: WARPWIRE can send captured credentials to C2 via HTTP `GET` or `POST` requests.
- [S0356] KONNI: KONNI has used FTP to exfiltrate reconnaissance data out.
- [S0252] Brave Prince: Some Brave Prince variants have used South Korea's Daum email service to exfiltrate information, and later variants have posted the data to a web server via an HTTP post command.
- [S0674] CharmPower: CharmPower can send victim data via FTP with credentials hardcoded in the script.
- [S0050] CosmicDuke: CosmicDuke exfiltrates collected files over FTP or WebDAV. Exfiltration servers can be separately configured from C2 servers.


### T1052 - Exfiltration Over Physical Medium
Adversaries may attempt to exfiltrate data via a physical medium, such as a removable drive. In certain circumstances, such as an air-gapped network compromise, exfiltration could occur via a physical medium or device introduced by a user. Such media could be an external hard drive, USB drive, cellular phone, MP3 player, or other removable storage and processing device. The physical medium or device could be used as the final exfiltration point or to hop between otherwise disconnected systems.
**Detection**
- [AN0342] **[Windows]** Detects removable drive insertion followed by unusual file access, compression, or staging activity by unauthorized users or unexpected processes.
  - **Log sources:** `WinEventLog:Sysmon` (EventCode=1) [Process Creation], `WinEventLog:Sysmon` (EventCode=11) [File Creation], `WinEventLog:Security` (EventCode=4663, 4670, 4656) [File Access], `WinEventLog:System` (EventCode=1006, 10001) [Drive Creation]
- [AN0343] **[Linux]** Detects mounted external devices (via /media or /mnt) followed by large file read or copy operations by shell scripts, unauthorized users, or staging tools (e.g., tar, rsync).
  - **Log sources:** `auditd:SYSCALL` (open) [File Access], `auditd:SYSCALL` (device event logs) [Drive Creation]
- [AN0344] **[macOS]** Detects mounting of external volumes followed by high-volume or sensitive file access via Finder, terminal, or third-party apps (e.g., rsync, zip).
  - **Log sources:** `macos:unifiedlog` (Volume Mount + File Read) [Drive Creation], `macos:osquery` (file_events) [File Access], `fs:fsusage` (file system activity monitor) [Command Execution]
Adversaries may attempt to exfiltrate data via a physical medium, such as a removable drive. In certain circumstances, such as an air-gapped network compromise, exfiltration could occur via a physical medium or device introduced by a user. Such media could be an external hard drive, USB drive, cellular phone, MP3 player, or other removable storage and processing device. The physical medium or device could be used as the final exfiltration point or to hop between otherwise disconnected systems.


### T1052.001 - Exfiltration Over Physical Medium: Exfiltration over USB
Adversaries may attempt to exfiltrate data over a USB connected physical device. In certain circumstances, such as an air-gapped network compromise, exfiltration could occur via a USB device introduced by a user. The USB device could be used as the final exfiltration point or to hop between otherwise disconnected systems.
**Detection**
- [AN0616] **[Windows]** Detects USB device insertion followed by high-volume or sensitive file access and staging activity by suspicious processes or accounts.
  - **Log sources:** `WinEventLog:Sysmon` (EventCode=1) [Process Creation], `WinEventLog:Sysmon` (EventCode=11) [File Creation], `WinEventLog:Security` (EventCode=4663, 4670, 4656) [File Access], `WinEventLog:System` (EventCode=2003) [Drive Creation]
- [AN0617] **[Linux]** Detects USB block device mount followed by file access in sensitive directories or high-volume copy operations by user-controlled processes.
  - **Log sources:** `auditd:SYSCALL` (open, read) [File Access], `auditd:SYSCALL` (Kernel Device Events - USB Block Devices) [Drive Creation]
- [AN0618] **[macOS]** Detects external volume mount with Finder, Terminal, or script-initiated file copy from user profiles, sensitive folders, or cloud storage sync directories to USB.
  - **Log sources:** `macos:unifiedlog` (Volume Mount + Process Trace + File Read) [Drive Creation], `fs:fsusage` (Disk Activity Tracing) [File Access], `macos:osquery` (process_events) [Process Creation]
**Procedure Examples**
- [S0035] SPACESHIP: SPACESHIP copies staged data to removable drives when they are inserted into the system.
- [S0125] Remsec: Remsec contains a module to move data from airgapped networks to Internet-connected systems by using a removable USB device.
- [S0136] USBStealer: USBStealer exfiltrates collected files via removable media from air-gapped victims.
- [G0081] Tropic Trooper: Tropic Trooper has exfiltrated data using USB storage devices.
- [G0129] Mustang Panda: Mustang Panda has used a customized PlugX variant which could exfiltrate documents from air-gapped networks.
- [S0092] Agent.btz: Agent.btz creates a file named thumb.dd on all USB flash drives connected to the victim. This file contains information about the infected system and activity logs.
- [S0409] Machete: Machete has a feature to copy files from every drive onto a removable drive in a hidden folder.


### T1537 - Transfer Data to Cloud Account
Adversaries may exfiltrate data by transferring the data, including through sharing/syncing and creating backups of cloud environments, to another cloud account they control on the same service. A defender who is monitoring for large transfers to outside the cloud environment through normal file transfers or over command and control channels may not be watching for data transfers to another account within the same cloud provider. Such transfers may utilize existing cloud provider APIs and the internal address space of the cloud provider to blend into normal traffic or avoid data transfers over external network interfaces. Adversaries may also use cloud-native mechanisms to share victim data with adversary-controlled cloud accounts, such as creating anonymous file sharing links or, in Azure, a shared access signature (SAS) URI. Incidents have been observed where adversaries have created backups of cloud instances and transferred them to separate accounts.
**Detection**
- [AN1580] **[IaaS]** Detects snapshot sharing, backup exports, or data object transfers from victim-owned cloud accounts to other cloud identities within the same provider (e.g., AWS, Azure) using snapshot sharing, S3 bucket policy updates, or SAS URI generation.
  - **Log sources:** `AWS:CloudTrail` (ModifySnapshotAttribute) [Snapshot Modification], `AWS:CloudTrail` (PutBucketPolicy) [Cloud Storage Modification], `AWS:CloudTrail` (CreateSnapshot) [Snapshot Creation], `AWS:CloudTrail` (CopySnapshot) [Snapshot Metadata], `AWS:VPCFlowLogs` (High volume internal-to-internal IP transfer or cross-account cloud transfer) [Network Traffic Content]
- [AN1581] **[Office Suite]** Detects user activity that shares or syncs files with external domains via link generation, OneDrive external sharing, or file transfer actions involving non-whitelisted partner tenants.
  - **Log sources:** `m365:unified` (SharingSet) [Cloud Storage Modification], `m365:unified` (AnonymousLinkCreated) [Cloud Storage Metadata], `m365:unified` (FileAccessed) [Application Log Content]
- [AN1582] **[SaaS]** Detects use of built-in SaaS sharing mechanisms to transfer ownership or share access of critical data to external tenants or untrusted users through API calls or link generation features.
  - **Log sources:** `saas:googledrive` (drive.permission.add) [Cloud Storage Modification], `saas:box` (collaboration.invite) [Cloud Storage Metadata]
**Procedure Examples**
- [G1053] Storm-0501: Storm-0501 has copied data from the victims environment to their own infrastructure leveraging AzCopy CLI.
- [G1032] INC Ransom: INC Ransom has used Megasync to exfiltrate data to the cloud.
- [G1039] RedCurl: RedCurl has used cloud storage to exfiltrate data, in particular the megatools utilities were used to exfiltrate data to Mega, a file storage service.


### T1567 - Exfiltration Over Web Service
Adversaries may use an existing, legitimate external Web service to exfiltrate data rather than their primary command and control channel. Popular Web services acting as an exfiltration mechanism may give a significant amount of cover due to the likelihood that hosts within a network are already communicating with them prior to compromise. Firewall rules may also already exist to permit traffic to these services. Web service providers also commonly use SSL/TLS encryption, giving adversaries an added level of protection.
**Detection**
- [AN1514] **[SaaS]** Abnormal API calls from user accounts invoking file upload endpoints outside normal baselines (M365, Google Drive, Box). Defender perspective: monitor unified audit logs for elevated frequency of Upload, Create, or Copy operations from compromised accounts.
  - **Log sources:** `m365:unified` (FileUploaded or FileCopied events) [Application Log Content], `saas:box` (API calls exceeding baseline thresholds) [Network Traffic Content]
- [AN1511] **[Windows]** Processes that normally do not initiate network communications suddenly making outbound HTTPS connections with high outbound-to-inbound data ratios. Defender view: correlation between process creation logs (e.g., Word, Excel, PowerShell) and subsequent anomalous network traffic volumes toward common web services (Dropbox, Google Drive, OneDrive).
  - **Log sources:** `WinEventLog:Security` (EventCode=4688) [Process Creation], `WinEventLog:Sysmon` (EventCode=3, 22) [Network Connection Creation], `WinEventLog:Sysmon` (EventCode=11) [File Creation]
- [AN1512] **[Linux]** Processes (tar, curl, python scripts) accessing large file sets and initiating outbound HTTPS POST requests with payload sizes inconsistent with baseline activity. Defender perspective: detect abnormal sequence of file archival followed by encrypted uploads to external web services.
  - **Log sources:** `auditd:EXECVE` (curl or wget with POST/PUT options) [Command Execution], `auditd:SYSCALL` (open/read of sensitive directories (/etc, /home/*)) [File Access], `NSM:Flow` (sustained outbound HTTPS sessions with high data volume) [Network Traffic Flow]
- [AN1513] **[macOS]** Office apps or scripts writing files followed by xattr manipulation (to evade quarantine) and subsequent HTTPS uploads. Defender perspective: anomalous file modification + outbound TLS traffic originating from non-networking apps (Word, Excel, Preview).
  - **Log sources:** `macos:unifiedlog` (execution of Office binaries with network activity) [Process Creation], `macos:unifiedlog` (read/write of user documents prior to upload) [File Access], `macos:unifiedlog` (outbound TLS connections to cloud storage providers) [Network Traffic Content]
- [AN1515] **[ESXi]** ESXi guest OS or management interface processes establishing unexpected external HTTPS connections. Defender perspective: monitor vmx or hostd processes making outbound web requests with significant data transfer.
  - **Log sources:** `esxi:vmkernel` (network session initiation with external HTTPS services) [Network Connection Creation], `esxi:hostd` (file copy or datastore upload via HTTPS) [File Access]
**Procedure Examples**
- [G0059] Magic Hound: Magic Hound has used the Telegram API `sendMessage` to relay data on compromised devices.
- [G1052] Contagious Interview: Contagious Interview has leveraged Telegram API to exfiltrate stolen data.
- [C0051] APT28 Nearest Neighbor Campaign: During APT28 Nearest Neighbor Campaign, APT28 exfiltrated data over public-facing webservers – such as Google Drive.
- [S1171] OilCheck: OilCheck can upload documents from compromised hosts to a shared Microsoft Office 365 Outlook email account for exfiltration.
- [G0007] APT28: APT28 can exfiltrate data over Google Drive.
- [C0059] Salesforce Data Exfiltration: During Salesforce Data Exfiltration, threat actors exfiltrated data via legitimate Salesforce API communication channels including the Salesforce Data Loader application.
- [S0547] DropBook: DropBook has used legitimate web services to exfiltrate data.
- [S0622] AppleSeed: AppleSeed has exfiltrated files using web services.
- [S0508] ngrok: ngrok has been used by threat actors to configure servers for data exfiltration.
- [C0017] C0017: During C0017, APT41 used Cloudflare services for data exfiltration.


### T1567.001 - Exfiltration Over Web Service: Exfiltration to Code Repository
Adversaries may exfiltrate data to a code repository rather than over their primary command and control channel. Code repositories are often accessible via an API (ex: Access to these APIs are often over HTTPS, which gives the adversary an additional level of protection. Exfiltration to a code repository can also provide a significant amount of cover to the adversary if it is a popular service already used by hosts within the network.
**Detection**
- [AN0897] **[macOS]** Office or scripting applications initiating unusual HTTPS traffic to code repository APIs with high outbound-to-inbound ratios. Defender perspective: monitor for sensitive file access in combination with network connections to github.com, gitlab.com, or bitbucket.org.
  - **Log sources:** `macos:unifiedlog` (execution of curl, git, or Office processes with network connections) [Process Creation], `macos:unifiedlog` (read of user document directories) [File Access], `macos:unifiedlog` (outbound HTTPS connections to code repository APIs) [Network Traffic Content]
- [AN0895] **[Windows]** Processes such as PowerShell, Git, or curl initiating outbound HTTPS POST requests to known code repository APIs (e.g., github.com, gitlab.com) immediately following large file reads. Defender view: correlation between file access of sensitive directories (e.g., Documents, Finance) and abnormal data uploads to repository domains.
  - **Log sources:** `WinEventLog:Security` (EventCode=4663, 4670, 4656) [File Access], `WinEventLog:Sysmon` (EventCode=3, 22) [Network Connection Creation], `WinEventLog:Sysmon` (EventCode=1) [Process Creation]
- [AN0896] **[Linux]** Processes like git, curl, or python scripts executing commands that package files (tar, gzip) followed by HTTPS uploads to code repository endpoints. Defender view: detect unusual git push activity or scripted HTTPS requests outside normal developer work hours.
  - **Log sources:** `auditd:EXECVE` (git push, curl -X POST) [Command Execution], `auditd:SYSCALL` (open/read of sensitive directories) [File Access], `NSM:Flow` (large outbound HTTPS uploads to repo domains) [Network Traffic Flow]
- [AN0898] **[ESXi]** ESXi host processes (vmx, hostd) initiating HTTPS sessions toward external code repositories. Defender perspective: detect datastore reads followed by outbound web traffic inconsistent with administrative baselines.
  - **Log sources:** `esxi:hostd` (datastore file access) [File Access], `esxi:vmkernel` (HTTPS traffic to repository domains) [Network Traffic Flow]
**Procedure Examples**
- [S0363] Empire: Empire can use GitHub for data exfiltration.


### T1567.002 - Exfiltration Over Web Service: Exfiltration to Cloud Storage
Adversaries may exfiltrate data to a cloud storage service rather than over their primary command and control channel. Cloud storage services allow for the storage, edit, and retrieval of data from a remote cloud storage server over the Internet. Examples of cloud storage services include Dropbox and Google Docs. Exfiltration to these cloud storage services can provide a significant amount of cover to the adversary if hosts within the network are already communicating with the service.
**Detection**
- [AN1572] **[Linux]** Processes such as curl, wget, rclone, or custom scripts executing uploads to cloud storage endpoints. Defender perspective: detect chained events where tar/gzip is executed to compress files followed by HTTPS PUT/POST requests to known storage services.
  - **Log sources:** `auditd:EXECVE` (curl -T, rclone copy) [Command Execution], `auditd:SYSCALL` (read/open of sensitive file directories) [File Access], `NSM:Flow` (large HTTPS outbound uploads) [Network Traffic Flow]
- [AN1573] **[macOS]** Applications or scripts invoking cloud storage APIs (Dropbox sync, iCloud, Google Drive client) in unexpected contexts. Defender perspective: detect sensitive file reads by non-standard applications followed by unusual encrypted uploads to external cloud storage domains.
  - **Log sources:** `macos:unifiedlog` (execution of curl, rclone, or Office apps invoking network sessions) [Process Creation], `macos:unifiedlog` (file read of sensitive directories) [File Access], `macos:unifiedlog` (outbound HTTPS connections to cloud storage APIs) [Network Traffic Content]
- [AN1574] **[ESXi]** Unusual ESXi processes (vmx, hostd) reading datastore files and generating outbound HTTPS traffic toward external cloud storage endpoints. Defender perspective: anomalous datastore activity followed by network transfers to Dropbox, AWS S3, or other storage services.
  - **Log sources:** `esxi:hostd` (datastore file access) [File Access], `esxi:vmkernel` (network flows to external cloud services) [Network Traffic Flow]
- [AN1571] **[Windows]** Unusual processes (e.g., powershell.exe, excel.exe) accessing large local files and subsequently initiating HTTPS POST requests to domains associated with cloud storage services (e.g., dropbox.com, drive.google.com, box.com). Defender perspective: correlation between file reads in sensitive directories and high outbound traffic volume to known storage APIs.
  - **Log sources:** `WinEventLog:Security` (EventCode=4663, 4670, 4656) [File Access], `WinEventLog:Sysmon` (EventCode=3, 22) [Network Connection Creation], `WinEventLog:Sysmon` (EventCode=1) [Process Creation]
**Procedure Examples**
- [G0065] Leviathan: Leviathan has used an uploader known as LUNCHMONEY that can exfiltrate files to Dropbox.
- [G1024] Akira: Akira will exfiltrate victim data using applications such as Rclone.
- [G1014] LuminousMoth: LuminousMoth has exfiltrated data to Google Drive.
- [S1040] Rclone: Rclone can exfiltrate data to cloud storage services such as Dropbox, Google Drive, Amazon S3, and MEGA.
- [S0629] RainyDay: RainyDay can use a file exfiltration tool to upload specific files to Dropbox.
- [S1023] CreepyDrive: CreepyDrive can use cloud services including OneDrive for data exfiltration.
- [S0037] HAMMERTOSS: HAMMERTOSS exfiltrates data by uploading it to accounts created by the actors on Web cloud storage providers for the adversaries to retrieve later.
- [G0094] Kimsuky: Kimsuky has exfiltrated stolen files and data to actor-controlled Blogspot accounts. Kimsuky has also leveraged Dropbox for uploading victim system information.
- [G0027] Threat Group-3390: Threat Group-3390 has exfiltrated stolen data to Dropbox.
- [S1170] ODAgent: ODAgent can use an attacker-controlled OneDrive account for exfiltration.


### T1567.003 - Exfiltration Over Web Service: Exfiltration to Text Storage Sites
Adversaries may exfiltrate data to text storage sites instead of their primary command and control channel. Text storage sites, such as pastebin[.]com, are commonly used by developers to share code and other information. Text storage sites are often used to host malicious code for C2 communication (e.g., Stage Capabilities), but adversaries may also use these sites to exfiltrate collected data. Furthermore, paid features and encryption options may allow adversaries to conceal and store data more securely. **Note:** This is distinct from Exfiltration to Code Repository, which highlight access to code repositories via APIs.
**Detection**
- [AN0787] **[Windows]** Unexpected processes (e.g., powershell.exe, wscript.exe, office apps) initiating HTTP POST/PUT requests to text storage domains like pastebin.com or hastebin.com, particularly when preceded by file access in sensitive directories. Defender perspective: correlation of process lineage, large clipboard/file read operations, and outbound uploads to text storage services.
  - **Log sources:** `WinEventLog:Security` (EventCode=4663, 4670, 4656) [File Access], `WinEventLog:Sysmon` (EventCode=3, 22) [Network Connection Creation], `WinEventLog:Sysmon` (EventCode=1) [Process Creation]
- [AN0790] **[ESXi]** ESXi services (vmx, hostd) generating outbound HTTPS POST requests to text storage sites. Defender perspective: anomalous datastore or log reads chained with traffic to pastebin-like destinations.
  - **Log sources:** `esxi:hostd` (datastore/log file access) [File Access], `esxi:vmkernel` (HTTPS POST connections to pastebin-like domains) [Network Traffic Content]
- [AN0789] **[macOS]** Processes such as osascript, curl, or office applications sending data to text storage APIs/domains. Defender perspective: anomalous clipboard or file reads by unexpected applications immediately followed by outbound HTTPS requests to pastebin-like services.
  - **Log sources:** `macos:unifiedlog` (execution of curl, osascript, or unexpected Office processes) [Process Creation], `macos:unifiedlog` (file read of sensitive directories) [File Access], `macos:unifiedlog` (HTTPS POST requests to pastebin.com or similar) [Network Traffic Flow]
- [AN0788] **[Linux]** Use of curl, wget, or custom scripts to POST data to pastebin-like services. Defender perspective: identify chained behavior where files are compressed/read followed by HTTPS POST requests to text-sharing endpoints.
  - **Log sources:** `auditd:EXECVE` (curl -d, wget --post-data) [Command Execution], `auditd:SYSCALL` (read/open of sensitive file directories) [File Access], `NSM:Flow` (large HTTPS POST requests to text storage domains) [Network Traffic Content]
Adversaries may exfiltrate data to text storage sites instead of their primary command and control channel. Text storage sites, such as pastebin[.]com, are commonly used by developers to share code and other information. Text storage sites are often used to host malicious code for C2 communication (e.g., Stage Capabilities), but adversaries may also use these sites to exfiltrate collected data. Furthermore, paid features and encryption options may allow adversaries to conceal and store data more securely. **Note:** This is distinct from Exfiltration to Code Repository, which highlight access to code repositories via APIs.


### T1567.004 - Exfiltration Over Web Service: Exfiltration Over Webhook
Adversaries may exfiltrate data to a webhook endpoint rather than over their primary command and control channel. Webhooks are simple mechanisms for allowing a server to push data over HTTP/S to a client without the need for the client to continuously poll the server. Many public and commercial services, such as Discord, Slack, and `webhook.site`, support the creation of webhook endpoints that can be used by other services, such as Github, Jira, or Trello. When changes happen in the linked services (such as pushing a repository update or modifying a ticket), these services will automatically post the data to the webhook endpoint for use by the consuming application. Adversaries may link an adversary-owned environment to a victim-owned SaaS service to achieve repeated Automated Exfiltration of emails, chat messages, and other data. Alternatively, instead of linking the webhook endpoint to a service, an adversary can manually post staged data directly to the URL in order to exfiltrate it. Access to webhook endpoints is often over HTTPS, which gives the adversary an additional level of protection. Exfiltration leveraging webhooks can also blend in with normal network traffic if the webhook endpoint points to a commonly used SaaS application or collaboration service.
**Detection**
- [AN0437] **[Linux]** Processes such as curl, wget, or custom scripts initiating POST requests to webhook endpoints with encoded or bulk data. Defender perspective: abnormal chaining of file compression or access followed by outbound data to webhook URLs.
  - **Log sources:** `auditd:EXECVE` (curl -X POST, wget --post-data) [Command Execution], `auditd:SYSCALL` (read/open of sensitive files) [File Access], `NSM:Flow` (large HTTPS POST requests to webhook endpoints) [Network Traffic Content]
- [AN0439] **[ESXi]** VMware services or management daemons generating HTTP POST requests to webhook endpoints, chained with unusual datastore or log access. Defender perspective: exfiltration from VM logs or disk images over webhook URLs.
  - **Log sources:** `esxi:hostd` (datastore file access) [File Access], `esxi:vmkernel` (HTTPS POST connections to webhook endpoints) [Network Traffic Content]
- [AN0440] **[SaaS]** Suspicious SaaS tenant activity involving webhook configurations pointing to external or untrusted domains. Defender perspective: repeated automated exports or suspicious webhook endpoint registrations.
  - **Log sources:** `m365:unified` (Set-Mailbox, Add-InboxRule, RegisterWebhook) [Application Log Content], `saas:api` (Webhook registrations or repeated POST activity) [Network Traffic Flow]
- [AN0436] **[Windows]** Unusual processes (e.g., powershell.exe, wscript.exe, mshta.exe) posting data to webhook endpoints (Discord, Slack, webhook.site) using HTTP POST/PUT requests. Defender perspective: suspicious process lineage followed by outbound HTTPS traffic to webhook domains.
  - **Log sources:** `WinEventLog:Sysmon` (EventCode=1) [Process Creation], `WinEventLog:Sysmon` (EventCode=3, 22) [Network Connection Creation], `WinEventLog:Security` (EventCode=4663, 4670, 4656) [File Access]
- [AN0438] **[macOS]** Unexpected apps or scripts (osascript, curl, Automator workflows) exfiltrating data via webhooks. Defender perspective: correlation of clipboard/file read operations followed by HTTPS POST traffic to webhook services.
  - **Log sources:** `macos:unifiedlog` (execution of osascript, curl, or unexpected automation) [Process Creation], `macos:unifiedlog` (file read of sensitive directories) [File Access], `macos:unifiedlog` (HTTPS POST to known webhook URLs) [Network Traffic Flow]
Adversaries may exfiltrate data to a webhook endpoint rather than over their primary command and control channel. Webhooks are simple mechanisms for allowing a server to push data over HTTP/S to a client without the need for the client to continuously poll the server. Many public and commercial services, such as Discord, Slack, and `webhook.site`, support the creation of webhook endpoints that can be used by other services, such as Github, Jira, or Trello. When changes happen in the linked services (such as pushing a repository update or modifying a ticket), these services will automatically post the data to the webhook endpoint for use by the consuming application. Adversaries may link an adversary-owned environment to a victim-owned SaaS service to achieve repeated Automated Exfiltration of emails, chat messages, and other data. Alternatively, instead of linking the webhook endpoint to a service, an adversary can manually post staged data directly to the URL in order to exfiltrate it. Access to webhook endpoints is often over HTTPS, which gives the adversary an additional level of protection. Exfiltration leveraging webhooks can also blend in with normal network traffic if the webhook endpoint points to a commonly used SaaS application or collaboration service.

