### T1001 - Data Obfuscation
Adversaries may obfuscate command and control traffic to make it more difficult to detect. Command and control (C2) communications are hidden (but not necessarily encrypted) in an attempt to make the content more difficult to discover or decipher and to make the communication less conspicuous and hide commands from being seen. This encompasses many methods, such as adding junk data to protocol traffic, using steganography, or impersonating legitimate protocols.
**Detection**
- [AN0145] **[Linux]** Identifies custom or previously unseen userland processes initiating high-volume HTTP connections with low response volume.
- [AN0144] **[Windows]** Detects excessive outbound traffic to remote host over HTTP(S) from uncommon or previously unseen processes.
- [AN0146] **[macOS]** Flags unexpected user applications initiating long-lived HTTP(S) sessions with irregular traffic patterns.
**Procedure Examples**
- [S1183] StrelaStealer: StrelaStealer encrypts the payload of HTTP POST communications using the same XOR key used for the malware's DLL payload.
- [G0047] Gamaredon Group: Gamaredon Group has used obfuscated VBScripts with randomly generated variable names and concatenated strings.
- [S0439] Okrum: Okrum leverages the HTTP protocol for C2 communication, while hiding the actual messages in the Cookie and Set-Cookie headers of the HTTP requests.
- [S0533] SLOTHFULMEDIA: SLOTHFULMEDIA has hashed a string containing system information prior to exfiltration via POST requests.
- [S1100] Ninja: Ninja has the ability to modify headers and URL paths to hide malicious traffic in HTTP requests.
- [S0682] TrailBlazer: TrailBlazer can masquerade its C2 traffic as legitimate Google Notifications HTTP requests.
- [C0014] Operation Wocao: During Operation Wocao, threat actors encrypted IP addresses used for "Agent" proxy hops with RC4.
- [S1044] FunnyDream: FunnyDream can send compressed and obfuscated packets to C2.
- [S1111] DarkGate: DarkGate will retrieved encrypted commands from its command and control server for follow-on actions such as cryptocurrency mining.
- [S1120] FRAMESTING: FRAMESTING can send and receive zlib compressed data within `POST` requests.


### T1001.001 - Data Obfuscation: Junk Data
Adversaries may add junk data to protocols used for command and control to make detection more difficult. By adding random or meaningless data to the protocols used for command and control, adversaries can prevent trivial methods for decoding, deciphering, or otherwise analyzing the traffic. Examples may include appending/prepending data with junk characters or writing junk characters between significant characters.
**Detection**
- [AN0032] **[macOS]** Previously unseen applications generating outbound connections with atypical data flow characteristics, such as excessive data with no return response.
- [AN0030] **[Windows]** Processes generating large outbound connections with disproportionate send/receive ratios, often to uncommon ports or hosts, potentially inserting meaningless data into protocol payloads.
- [AN0031] **[Linux]** Outbound traffic with anomalous payload sizes and patterns from non-networking processes, often observed via packet inspection or connection logs.
- [AN0033] **[ESXi]** Anomalous traffic from ESXi host management daemons (like hostd or vpxa) embedding non-standard payloads in management protocols (e.g., HTTPS) or beaconing behavior.
**Procedure Examples**
- [S0016] P2P ZeuS: P2P ZeuS added junk data to outgoing UDP packets to peer implants.
- [S0134] Downdelph: Downdelph inserts pseudo-random characters between each original character during encoding of C2 network requests, making it difficult to write signatures on them.
- [S1047] Mori: Mori has obfuscated the FML.dll with 200MB of junk data.
- [S0574] BendyBear: BendyBear has used byte randomization to obscure its behavior.
- [S0682] TrailBlazer: TrailBlazer has used random identifier strings to obscure its C2 operations and result codes.
- [S0022] Uroburos: Uroburos can add extra characters in encoded strings to help mimic DNS legitimate requests.
- [S0626] P8RAT: P8RAT can send randomly-generated data as part of its C2 communication.
- [S0435] PLEAD: PLEAD samples were found to be highly obfuscated with junk code.
- [S1164] UPSTYLE: UPSTYLE retrieves a non-existent webpage from the command and control server then parses commands from the resulting error logs to decode commands to the web shell.
- [S1020] Kevin: Kevin can generate a sequence of dummy HTTP C2 requests to obscure traffic.


### T1001.002 - Data Obfuscation: Steganography
Adversaries may use steganographic techniques to hide command and control traffic to make detection efforts more difficult. Steganographic techniques can be used to hide data in digital messages that are transferred between systems. This hidden information can be used for command and control of compromised systems. In some cases, the passing of files embedded using steganography, such as image or document files, can be used for command and control.
**Detection**
- [AN0652] **[Linux]** Unusual use of steganographic or media processing binaries (e.g., `steghide`, `ffmpeg`, `imagemagick`) followed by outbound communication to external IPs with high data output and media MIME types.
- [AN0654] **[ESXi]** Suspicious modification of file artifacts (e.g., logs, ISO templates) on ESXi datastores, followed by beaconing or POST operations to external IPs potentially hiding payloads in file-like traffic.
- [AN0651] **[Windows]** Detect the creation or modification of common media file formats (e.g., .jpg, .png, .wav) following suspicious process activity like compression or encryption, especially when paired with lateral movement or exfiltration behavior.
- [AN0653] **[macOS]** Abnormal usage of Preview, ImageMagick, or binary editors to alter images/documents, followed by exfiltration or outbound connections with mismatched file MIME types or payload structure.
**Procedure Examples**
- [S1141] LunarWeb: LunarWeb can receive C2 commands hidden in the structure of .jpg and .gif images.
- [G0001] Axiom: Axiom has used steganography to hide its C2 communications.
- [S0037] HAMMERTOSS: HAMMERTOSS is controlled via commands that are appended to image files.
- [S0633] Sliver: Sliver can encode binary data into a .PNG file for C2 communication.
- [C0023] Operation Ghost: During Operation Ghost, APT29 used steganography to hide the communications between the implants and their C&C servers.
- [S0672] Zox: Zox has used the .PNG file format for C2 communications.
- [S0395] LightNeuron: LightNeuron is controlled via commands that are embedded into PDFs and JPGs using steganographic methods.
- [S0230] ZeroT: ZeroT has retrieved stage 2 payloads as Bitmap images that use Least Significant Bit (LSB) steganography.
- [S0187] Daserf: Daserf can use steganography to hide malicious code downloaded to the victim.
- [S0495] RDAT: RDAT can process steganographic images attached to email messages to send and receive C2 commands. RDAT can also embed additional messages within BMP images to communicate with the RDAT operator.


### T1001.003 - Data Obfuscation: Protocol or Service Impersonation
Adversaries may impersonate legitimate protocols or web service traffic to disguise command and control activity and thwart analysis efforts. By impersonating legitimate protocols or web services, adversaries can make their command and control traffic blend in with legitimate network traffic. Adversaries may impersonate a fake SSL/TLS handshake to make it look like subsequent traffic is SSL/TLS encrypted, potentially interfering with some security tooling, or to make the traffic look like it is related with a trusted entity. Adversaries may also leverage legitimate protocols to impersonate expected web traffic or trusted services. For example, adversaries may manipulate HTTP headers, URI endpoints, SSL certificates, and transmitted data to disguise C2 communications or mimic legitimate services such as Gmail, Google Drive, and Yahoo Messenger.
**Detection**
- [AN1297] **[ESXi]** ESXi hosts initiating connections from non-standard daemons mimicking HTTP/HTTPS or SNMP traffic, but with irregular payload formats or expired/unsigned TLS certificates.
- [AN1296] **[macOS]** Unsigned or suspicious applications initiating network traffic claiming to be browser, mail, or cloud clients. Detects impersonation via TLS fingerprint and User-Agent string deviation.
- [AN1294] **[Windows]** Untrusted processes creating outbound TLS/HTTPS connections with malformed certificates or header fields, often mismatched with target service behavior. Detects protocol impersonation attempts via traffic metadata analysis and host process lineage.
- [AN1295] **[Linux]** Detection of binaries spawning encrypted sessions using OpenSSL or curl to external services with mismatched ports/protocols. Identifies behavior where internal services simulate trusted cloud service traffic patterns.
**Procedure Examples**
- [G0032] Lazarus Group: Lazarus Group malware also uses a unique form of communication encryption known as FakeTLS that mimics TLS but uses a different encryption method, potentially evading SSL traffic inspection/decryption.
- [S1120] FRAMESTING: FRAMESTING uses a cookie named `DSID` to mimic the name of a cookie used by Ivanti Connect Secure appliances for maintaining VPN sessions.
- [S1227] StarProxy: StarProxy has utilized TLS record headers in network packets to impersonate various versions of TLS protocols to blend in with legitimate network traffic. StarProxy used FakeTLS to communicate with its C2 server.
- [S1228] PUBLOAD: PUBLOAD has modified HTTP POST requests to resemble legitimate communications. PUBLOAD used FakeTLS headers in network packets to impersonate various versions of TLS protocols to blend in with legitimate network traffic. PUBLOAD has utilized FakeTLS headers with the bytes 17 03 03.
- [G0129] Mustang Panda: Mustang Panda has utilized TLS record headers in network packets to impersonate various versions of TLS protocols to blend in with legitimate network traffic. Mustang Panda has used FakeTLS to communicate with its C2 servers.
- [S0154] Cobalt Strike: Cobalt Strike can leverage the HTTP protocol for C2 communication, while hiding the actual data in either an HTTP header, URI parameter, the transaction body, or appending it to the URI.
- [S0245] BADCALL: BADCALL uses a FakeTLS method during C2.
- [S0387] KeyBoy: KeyBoy uses custom SSL libraries to impersonate SSL in C2 traffic.
- [G0126] Higaisa: Higaisa used a FakeTLS session for C2 communications.
- [S0586] TAINTEDSCRIBE: TAINTEDSCRIBE has used FakeTLS for session authentication.


### T1008 - Fallback Channels
Adversaries may use fallback or alternate communication channels if the primary channel is compromised or inaccessible in order to maintain reliable command and control and to avoid data transfer thresholds.
**Detection**
- [AN1378] **[macOS]** Outbound fallback traffic from low-profile or background launch agents using unusual protocols or destinations after primary channel inactivity.
- [AN1379] **[ESXi]** Outbound traffic from host management services or guest-to-host interactions over unusual interfaces (e.g., backdoor API endpoints or external VPN tunnels).
- [AN1377] **[Linux]** Creation of outbound connections on alternate ports or using covert transport (e.g., ICMP, DNS) from non-network-intensive processes, following known disruption or blocked traffic.
- [AN1376] **[Windows]** Establishing network connections on uncommon ports or protocols following C2 disruption or blocking. Often executed by processes that typically exhibit no network activity.
**Procedure Examples**
- [S0044] JHUHUGIT: JHUHUGIT tests if it can reach its C2 server by first attempting a direct connection, and if it fails, obtaining proxy settings and sending the connection through a proxy, and finally injecting code into a running browser if the proxy method fails.
- [S0211] Linfo: Linfo creates a backdoor through which remote attackers can change C2 servers.
- [S0023] CHOPSTICK: CHOPSTICK can switch to a new C2 channel if the current one is broken.
- [G0049] OilRig: OilRig malware ISMAgent falls back to its DNS tunneling mechanism if it is unable to reach the C2 server over HTTP.
- [S0376] HOPLIGHT: HOPLIGHT has multiple C2 channels in place in case one fails.
- [S0260] InvisiMole: InvisiMole has been configured with several servers available for alternate C2 communications.
- [S0058] SslMM: SslMM has a hard-coded primary and backup C2 string.
- [S0377] Ebury: Ebury has implemented a fallback mechanism to begin using a DGA when the attacker hasn't connected to the infected system for three days.
- [S0017] BISCUIT: BISCUIT malware contains a secondary fallback command and control server that is contacted after the primary command and control server.
- [S0266] TrickBot: TrickBot can use secondary C2 servers for communication after establishing connectivity and relaying victim information to primary C2 servers.


### T1071 - Application Layer Protocol
Adversaries may communicate using OSI application layer protocols to avoid detection/network filtering by blending in with existing traffic. Commands to the remote system, and often the results of those commands, will be embedded within the protocol traffic between the client and server. Adversaries may utilize many different protocols, including those used for web browsing, transferring files, electronic mail, DNS, or publishing/subscribing. For connections that occur internally within an enclave (such as those between a proxy or pivot node and other nodes), commonly used protocols are SMB, SSH, or RDP.
**Detection**
- [AN1225] **[Windows]** Detects suspicious usage of common application-layer protocols (e.g., HTTP, HTTPS, DNS, SMB) by abnormal processes, with high outbound byte counts or irregular ports, possibly indicating command and control or data exfiltration.
- [AN1226] **[Linux]** Detects suspicious curl, wget, or custom socket traffic that leverages DNS, HTTPS, or IRC-style protocols with unbalanced traffic or beacon-like intervals.
- [AN1227] **[macOS]** Detects applications using abnormal protocols or high volume traffic not previously associated with the process image, such as Automator or AppleScript invoking curl or python sockets.
- [AN1228] **[Network Devices]** Detects application-layer tunneling or unauthorized app protocols like DNS-over-HTTPS, embedded C2 in TLS/HTTP headers, or misused SMB traffic crossing VLANs.
**Procedure Examples**
- [S0601] Hildegard: Hildegard has used an IRC channel for C2 communications.
- [G0059] Magic Hound: Magic Hound malware has used IRC for C2.
- [S0034] NETEAGLE: Adversaries can also use NETEAGLE to establish an RDP connection with a controller over TCP/7519.
- [C0041] FrostyGoop Incident: During FrostyGoop Incident, the adversary initiated Layer Two Tunnelling Protocol (L2TP) connections to Moscow-based IP addresses.
- [G0106] Rocke: Rocke issued wget requests from infected systems to the C2.
- [G1032] INC Ransom: INC Ransom has used valid accounts over RDP to connect to targeted systems.
- [S0623] Siloscape: Siloscape connects to an IRC server for C2.
- [S1084] QUIETEXIT: QUIETEXIT can use an inverse negotiated SSH connection as part of its C2.
- [S0038] Duqu: Duqu uses a custom command and control protocol that communicates over commonly used ports, and is frequently encapsulated by application layer protocols.
- [S0660] Clambling: Clambling has the ability to use Telnet for communication.


### T1071.001 - Application Layer Protocol: Web Protocols
Adversaries may communicate using application layer protocols associated with web traffic to avoid detection/network filtering by blending in with existing traffic. Commands to the remote system, and often the results of those commands, will be embedded within the protocol traffic between the client and server. Protocols such as HTTP/S and WebSocket that carry web traffic may be very common in environments. HTTP/S packets have many fields and headers in which data can be concealed. An adversary may abuse these protocols to communicate with systems under their control within a victim network while also mimicking normal, expected traffic.
**Detection**
- [AN0075] **[Windows]** Detects unexpected or high-volume HTTP/S/WebSocket communication from suspicious processes (e.g., PowerShell, rundll32) using uncommon user agents or mimicking browser traffic to unusual domains or IPs.
- [AN0079] **[Network Devices]** Detects Web protocol misuse such as encoded HTTP headers, WebSocket upgrade requests with abnormal payloads, or TLS handshake anomalies suggesting embedded C2 channels.
- [AN0078] **[ESXi]** Detects HTTP or HTTPS communication initiated by shell-based scripts or management daemons, especially those reaching public IPs over ports 80/443 using embedded curl or wget.
- [AN0077] **[macOS]** Detects applications such as Automator, AppleScript, or LaunchDaemons invoking HTTP/S traffic to non-standard domains or using suspicious headers (e.g., Base64 in URIs or cookie fields).
- [AN0076] **[Linux]** Detects curl, wget, Python requests, or custom HTTP clients communicating over non-standard ports, with repetitive or beacon-like patterns or POST-heavy behavior to rare domains.
**Procedure Examples**
- [S1047] Mori: Mori can communicate using HTTP over IPv4 or IPv6 depending on a flag set.
- [S0275] UPPERCUT: UPPERCUT has used HTTP for C2, including sending error codes in Cookie headers.
- [S0495] RDAT: RDAT can use HTTP communications for C2, as well as using the WinHTTP library to make requests to the Exchange Web Services API.
- [S1108] PULSECHECK: PULSECHECK can check HTTP request headers for a specific backdoor key and if found will output the result of the command in the variable `HTTP_X_CMD.`
- [S0207] Vasport: Vasport creates a backdoor by making a connection using a HTTP POST.
- [S0502] Drovorub: Drovorub can use the WebSocket protocol and has initiated communication with C2 servers with an HTTP Upgrade request.
- [S0144] ChChes: ChChes communicates to its C2 server over HTTP and embeds data within the Cookie HTTP header.
- [S1246] BeaverTail: BeaverTail has used HTTP GET request to download malicious payloads to include InvisibleFerret and HTTP POST to exfiltrate data to C2 infrastructure.
- [S1023] CreepyDrive: CreepyDrive can use HTTPS for C2 using the Microsoft Graph API.
- [S0091] Epic: Epic uses HTTP and HTTPS for C2 communications.


### T1071.002 - Application Layer Protocol: File Transfer Protocols
Adversaries may communicate using application layer protocols associated with transferring files to avoid detection/network filtering by blending in with existing traffic. Commands to the remote system, and often the results of those commands, will be embedded within the protocol traffic between the client and server. Protocols such as SMB, FTP, FTPS, and TFTP that transfer files may be very common in environments. Packets produced from these protocols may have many fields and headers in which data can be concealed. Data could also be concealed within the transferred files. An adversary may abuse these protocols to communicate with systems under their control within a victim network while also mimicking normal, expected traffic.
**Detection**
- [AN1170] **[Linux]** Detects usage of FTP, SCP, or TFTP by non-interactive shells or automation scripts transferring large data volumes to untrusted IPs.
- [AN1172] **[ESXi]** Detects file movement or outbound TFTP/FTP transfers from ESXi host initiated via shell commands or injected scripts, particularly from scratch partitions or /tmp.
- [AN1173] **[Network Devices]** Detects internal hosts generating large outbound FTP/TFTP/SMB sessions to external IPs, or file transfers using non-standard ports and application mismatches (e.g., FTP over port 80).
- [AN1171] **[macOS]** Detects Automator, AppleScript, or Terminal executing curl, lftp, or TFTP for binary transfer to untrusted IPs or unusual ports.
- [AN1169] **[Windows]** Detects FTP, SMB, or TFTP traffic initiated by suspicious processes like PowerShell, cmd.exe, or rundll32.exe—especially with large outbound file transfers or unbalanced traffic volume.
**Procedure Examples**
- [S0428] PoetRAT: PoetRAT has used FTP for C2 communications.
- [G0096] APT41: APT41 used exploit payloads that initiate download via ftp.
- [S0699] Mythic: Mythic supports SMB-based peer-to-peer C2 profiles.
- [C0055] Quad7 Activity: Quad7 Activity has used a File Transfer Protocol (FTP) server to download malicious binaries.
- [S0465] CARROTBALL: CARROTBALL has the ability to use FTP in C2 communications.
- [S0019] Regin: The Regin malware platform supports many standard protocols, including SMB.
- [S1228] PUBLOAD: PUBLOAD has used `curl` for data exfiltration over FTP.
- [S0409] Machete: Machete uses FTP for Command & Control.
- [S0161] XAgentOSX: XAgentOSX contains the ftpUpload function to use the FTPManager:uploadFile method to upload files from the target system.
- [S0201] JPIN: JPIN can communicate over FTP.


### T1071.003 - Application Layer Protocol: Mail Protocols
Adversaries may communicate using application layer protocols associated with electronic mail delivery to avoid detection/network filtering by blending in with existing traffic. Commands to the remote system, and often the results of those commands, will be embedded within the protocol traffic between the client and server. Protocols such as SMTP/S, POP3/S, and IMAP that carry electronic mail may be very common in environments. Packets produced from these protocols may have many fields and headers in which data can be concealed. Data could also be concealed within the email messages themselves. An adversary may abuse these protocols to communicate with systems under their control within a victim network while also mimicking normal, expected traffic.
**Detection**
- [AN0381] **[macOS]** Detects email-sending behavior via Terminal, AppleScript, or Automator that interfaces with SMTP or IMAP, typically using curl or mail-related APIs in unsanctioned contexts.
- [AN0382] **[Network Devices]** Detects hosts transmitting large volumes of SMTP, IMAP, or POP3 traffic to external IPs or relays that aren't associated with the enterprise mail infrastructure.
- [AN0380] **[Linux]** Detects non-interactive or script-driven email transmission using tools like `sendmail`, `mailx`, or custom SMTP scripts by background processes, especially when sending attachments or large payloads.
- [AN0379] **[Windows]** Detects unauthorized use of SMTP/IMAP/POP3 by suspicious binaries (e.g., PowerShell, rundll32) to exfiltrate data or beacon via email, often bypassing proxy or content filters.
**Procedure Examples**
- [S0126] ComRAT: ComRAT can use email attachments for command and control.
- [S0395] LightNeuron: LightNeuron uses SMTP for C2.
- [S0137] CORESHELL: CORESHELL can communicate over SMTP and POP3 for C2.
- [S0337] BadPatch: BadPatch uses SMTP for C2.
- [S0023] CHOPSTICK: Various implementations of CHOPSTICK communicate with C2 over SMTP and POP3.
- [G0010] Turla: Turla has used multiple backdoors which communicate with a C2 server via email attachments.
- [S0022] Uroburos: Uroburos can use custom communications protocols that ride over SMTP.
- [S0201] JPIN: JPIN can send email over SMTP.
- [S0125] Remsec: Remsec is capable of using SMTP for C2.
- [S0247] NavRAT: NavRAT uses the email platform, Naver, for C2 communications, leveraging SMTP.


### T1071.004 - Application Layer Protocol: DNS
Adversaries may communicate using the Domain Name System (DNS) application layer protocol to avoid detection/network filtering by blending in with existing traffic. Commands to the remote system, and often the results of those commands, will be embedded within the protocol traffic between the client and server. The DNS protocol serves an administrative function in computer networking and thus may be very common in environments. DNS traffic may also be allowed even before network authentication is completed. DNS packets contain many fields and headers in which data can be concealed. Often known as DNS tunneling, adversaries may abuse DNS to communicate with systems under their control within a victim network while also mimicking normal, expected traffic. DNS beaconing may be used to send commands to remote systems via DNS queries. A DNS beacon is created by tunneling DNS traffic (i.e. Protocol Tunneling). The commands may be embedded into different DNS records, for example, TXT or A records. DNS beacons may be difficult to detect because the beacons infrequently communicate with infected devices. Infrequent communication conceals the malicious DNS traffic with normal DNS traffic.
**Detection**
- [AN1125] **[ESXi]** Detects unusual outbound DNS traffic from ESXi hosts, often from shell scripts, custom daemons, or malicious VIBs interacting with external DNS infrastructure outside the management plane.
- [AN1121] **[Windows]** Detects high-frequency or anomalous DNS queries initiated by non-browser, non-system processes (e.g., PowerShell, rundll32, python.exe) used to establish command and control via DNS tunneling.
- [AN1123] **[macOS]** Detects scripting environments (AppleScript, osascript, curl) or non-native tools performing DNS queries with encoded subdomains, often used for data exfiltration or beaconing.
- [AN1122] **[Linux]** Detects local daemons or scripts generating outbound DNS queries with long or frequent subdomains, indicative of DNS tunneling via tools like `iodine`, `dnscat2`, or `dig` from cronjobs or reverse shells.
- [AN1124] **[Network Devices]** Detects clients issuing DNS queries with high volume, long subdomain lengths, encoded payload patterns, or to known malicious infrastructure; indicative of DNS-based C2 channels.
**Procedure Examples**
- [S0477] Goopy: Goopy has the ability to communicate with its C2 over DNS.
- [S0269] QUADAGENT: QUADAGENT uses DNS for C2 communications.
- [S0354] Denis: Denis has used DNS tunneling for C2 communications.
- [S0663] SysUpdate: SysUpdate has used DNS TXT requests as for its C2 communication.
- [S1111] DarkGate: DarkGate can cloak command and control traffic in DNS records from legitimate services to avoid reputation-based detection techniques.
- [S0146] TEXTMATE: TEXTMATE uses DNS TXT records for C2.
- [S1020] Kevin: Variants of Kevin can communicate over DNS through queries to the server for constructed domain names with embedded information.
- [S1015] Milan: Milan has the ability to use DNS for C2 communications.
- [S0377] Ebury: Ebury has used DNS requests over UDP port 53 for C2.
- [S0170] Helminth: Helminth can use DNS for C2.


### T1071.005 - Application Layer Protocol: Publish/Subscribe Protocols
Adversaries may communicate using publish/subscribe (pub/sub) application layer protocols to avoid detection/network filtering by blending in with existing traffic. Commands to the remote system, and often the results of those commands, will be embedded within the protocol traffic between the client and server. Protocols such as MQTT, XMPP, AMQP, and STOMP use a publish/subscribe design, with message distribution managed by a centralized broker. Publishers categorize their messages by topics, while subscribers receive messages according to their subscribed topics. An adversary may abuse publish/subscribe protocols to communicate with systems under their control from behind a message broker while also mimicking normal, expected traffic.
**Detection**
- [AN0004] **[macOS]** Detects osascript, curl, or custom binaries interacting with XMPP/MQTT brokers in unapproved destinations with encrypted payloads or frequent POST-like requests to broker URIs.
- [AN0003] **[Linux]** Detects CLI tools (e.g., mosquitto_pub, nc, python scripts) interacting with pub/sub brokers using unusual topic names, high-frequency publication rates, or obfuscated payloads to non-standard hosts.
- [AN0005] **[Network Devices]** Detects pub/sub traffic over unusual ports, high-frequency topic publications, and connections to known-bad or dynamic broker endpoints outside allowlisted infrastructure.
- [AN0002] **[Windows]** Detects non-standard processes (e.g., PowerShell, python.exe, rundll32.exe) making outbound connections using publish/subscribe protocols (e.g., MQTT, AMQP) over non-browser, encrypted channels, often beaconing to message brokers.
**Procedure Examples**
- [S0026] GLOOXMAIL: GLOOXMAIL communicates to servers operated by Google using the Jabber/XMPP protocol for C2.


### T1090 - Proxy
Adversaries may use a connection proxy to direct network traffic between systems or act as an intermediary for network communications to a command and control server to avoid direct connections to their infrastructure. Many tools exist that enable traffic redirection through proxies or port redirection, including HTRAN, ZXProxy, and ZXPortMap. Adversaries use these types of proxies to manage command and control communications, reduce the number of simultaneous outbound network connections, provide resiliency in the face of connection loss, or to ride over existing trusted communications paths between victims to avoid suspicion. Adversaries may chain together multiple proxies to further disguise the source of malicious traffic. Adversaries can also take advantage of routing schemes in Content Delivery Networks (CDNs) to proxy command and control traffic.
**Detection**
- [AN1229] **[Windows]** Suspicious process spawning (e.g., `rundll32`, `svchost`, `powershell`, or `netsh`) followed by network connection creation to internal hosts or uncommon external endpoints on high or non-standard ports.
- [AN1233] **[Network Devices]** Dynamic or static port forwarding rules added to route traffic through an internal host, or configuration changes to proxy firewall rules not aligned with baselined policy.
- [AN1231] **[macOS]** AppleScript, LaunchAgents, or remote login services (`ssh`, `networksetup`) establishing proxy tunnels or dynamic port forwards to external IPs or alternate local hosts.
- [AN1230] **[Linux]** User-space tools (e.g., `socat`, `ncat`, `iptables`, `ssh`) used in non-standard ways to establish reverse shells, port-forwarding, or inter-host connections. Often chained with uncommon outbound destinations or SSH tunnels.
- [AN1232] **[ESXi]** Direct use of `nc`, `socat`, or reverse tunnel scripts initiated by abnormal user contexts or unauthorized VIBs initiating connections from hypervisor to external systems.
**Procedure Examples**
- [S1210] Sagerunex: Sagerunex uses several proxy configuration settings to ensure connectivity.
- [S0198] NETWIRE: NETWIRE can implement use of proxies to pivot traffic.
- [S1114] ZIPLINE: ZIPLINE can create a proxy server on compromised hosts.
- [S1212] RansomHub: RansomHub can use a proxy to connect to remote SFTP servers.
- [S0669] KOCTOPUS: KOCTOPUS has deployed a modified version of Invoke-Ngrok to expose open local ports to the Internet.
- [G1017] Volt Typhoon: Volt Typhoon has used compromised devices and customized versions of open source tools such as FRP (Fast Reverse Proxy), Earthworm, and Impacket to proxy network traffic.
- [S0461] SDBbot: SDBbot has the ability to use port forwarding to establish a proxy between a target host and C2.
- [S0615] SombRAT: SombRAT has the ability to use an embedded SOCKS proxy in C2 communications.
- [S0040] HTRAN: HTRAN can proxy TCP socket connections to obfuscate command and control infrastructure.
- [S1144] FRP: FRP can proxy communications through a server in public IP space to local servers located behind a NAT or firewall.


### T1090.001 - Proxy: Internal Proxy
Adversaries may use an internal proxy to direct command and control traffic between two or more systems in a compromised environment. Many tools exist that enable traffic redirection through proxies or port redirection, including HTRAN, ZXProxy, and ZXPortMap. Adversaries use internal proxies to manage command and control communications inside a compromised environment, to reduce the number of simultaneous outbound network connections, to provide resiliency in the face of connection loss, or to ride over existing trusted communications paths between infected systems to avoid suspicion. Internal proxy connections may use common peer-to-peer (p2p) networking protocols, such as SMB, to better blend in with the environment. By using a compromised internal system as a proxy, adversaries may conceal the true destination of C2 traffic while reducing the need for numerous connections to external systems.
**Detection**
- [AN0208] **[Network Devices]** Configuration of internal NAT or proxy rules that redirect traffic between client segments internally (e.g., site-to-site port forwarding). Often used to relay internal beaconing or move traffic laterally through trust zones.
- [AN0205] **[Linux]** `socat`, `ssh`, `iptables`, or `ncat` invoked from user space or cron jobs to create port forwarding, reverse shells, or inter-host tunnels between compromised Linux systems. Behavior is typically paired with socket activity and high entropy traffic.
- [AN0207] **[ESXi]** ESXi shell execution of tools/scripts (`nc`, `socat`, `perl`) relaying network traffic to other internal hosts, especially when initiated by unauthorized users or VMs.
- [AN0206] **[macOS]** Execution of AppleScript or Automator services launching `ssh -L`, `socat`, or `launchctl` items that dynamically reroute traffic from one Mac endpoint to another. LaunchAgents used to establish permanent internal tunnels.
- [AN0204] **[Windows]** Anomalous process (e.g., `rundll32`, `svchost`, `cmd`) initiates connections to internal peer hosts not seen in typical communication baselines, used to proxy or forward traffic internally, often using SMB, RPC, or high ports.
**Procedure Examples**
- [G1047] Velvet Ant: Velvet Ant has tunneled traffic from victims through an internal, compromised host to proxy communications to command and control nodes.
- [S0556] Pay2Key: Pay2Key has designated machines in the compromised network to serve as reverse proxy pivot points to channel communications with C2.
- [S0038] Duqu: Duqu can be configured to have commands relayed over a peer-to-peer network of infected hosts if some of the hosts do not have Internet access.
- [C0024] SolarWinds Compromise: During the SolarWinds Compromise, APT29 used SSH port forwarding capabilities on public-facing systems, and configured at least one instance of Cobalt Strike to use a network pipe over SMB.
- [S0023] CHOPSTICK: CHOPSTICK used a proxy server between victims and the C2 server.
- [G1016] FIN13: FIN13 has utilized a proxy tool to communicate between compromised assets.
- [S0502] Drovorub: Drovorub can use a port forwarding rule on its agent module to relay network traffic through the client module to a remote host on the same network.
- [S0154] Cobalt Strike: Cobalt Strike can be configured to have commands relayed over a peer-to-peer network of infected hosts. This can be used to limit the number of egress points, or provide access to a host without direct internet access.
- [G0126] Higaisa: Higaisa discovered system proxy settings and used them if available.
- [S1060] Mafalda: Mafalda can create a named pipe to listen for and send data to a named pipe-based C2 server.


### T1090.002 - Proxy: External Proxy
Adversaries may use an external proxy to act as an intermediary for network communications to a command and control server to avoid direct connections to their infrastructure. Many tools exist that enable traffic redirection through proxies or port redirection, including HTRAN, ZXProxy, and ZXPortMap. Adversaries use these types of proxies to manage command and control communications, to provide resiliency in the face of connection loss, or to ride over existing trusted communications paths to avoid suspicion. External connection proxies are used to mask the destination of C2 traffic and are typically implemented with port redirectors. Compromised systems outside of the victim environment may be used for these purposes, as well as purchased infrastructure such as cloud-based resources or virtual private servers. Proxies may be chosen based on the low likelihood that a connection to them from a compromised system would be investigated. Victim systems would communicate directly with the external proxy on the Internet and then the proxy would forward communications to the C2 server.
**Detection**
- [AN0925] **[ESXi]** ESXi shell or guest VM tools initiate external connections via scripted traffic forwarding to Internet-based proxies. Detected by firewall or shell audit logs showing outbound connection spikes from hypervisor or guest VM to remote proxy nodes.
- [AN0922] **[Windows]** Unusual process (e.g., `rundll32`, `mshta`, `wscript`, or custom payloads) initiates network connection to external IPs/domains that proxy C2 traffic, often over uncommon ports or high entropy HTTP/S connections.
- [AN0923] **[Linux]** `curl`, `wget`, `ncat`, `socat`, or custom binaries initiate outbound traffic to Internet-based proxies (e.g., via VPS or CDN). Behavior may include reverse shell constructs or persistent outbound beacons.
- [AN0926] **[Network Devices]** Changes to NAT/firewall policies enabling outbound port forwarding from internal IPs to Internet-based proxy endpoints. Log spikes in outbound flows to CDN, VPS, or anomalous ASNs with few return packets.
- [AN0924] **[macOS]** AppleScript or terminal sessions launch tools (`curl`, `nc`, `ssh`) to external IPs not commonly accessed. Outbound connections are made by LaunchAgents/LaunchDaemons, often masquerading as system services.
**Procedure Examples**
- [S1084] QUIETEXIT: QUIETEXIT can proxy traffic via SOCKS.
- [G0087] APT39: APT39 has used various tools to proxy C2 communications.
- [S0444] ShimRat: ShimRat can use pre-configured HTTP proxies.
- [S0650] QakBot: QakBot has a module that can proxy C2 communications.
- [G0007] APT28: APT28 used other victims as proxies to relay command traffic, for instance using a compromised Georgian military email server as a hop point to NATO victims. The group has also used a tool that acts as a proxy to allow C2 even if the victim is behind a router. APT28 has also used a machine to relay and obscure communications between CHOPSTICK and their server.
- [G0053] FIN5: FIN5 maintains access to victim environments by using FLIPSIDE to create a proxy for a backup RDP tunnel.
- [G0131] Tonto Team: Tonto Team has routed their traffic through an external server in order to obfuscate their location.
- [S0699] Mythic: Mythic can leverage a modified SOCKS5 proxy to tunnel egress C2 traffic.
- [S0141] Winnti for Windows: The Winnti for Windows HTTP/S C2 mode can make use of an external proxy.
- [G0032] Lazarus Group: Lazarus Group has used multiple proxies to obfuscate network traffic from victims.


### T1090.003 - Proxy: Multi-hop Proxy
Adversaries may chain together multiple proxies to disguise the source of malicious traffic. Typically, a defender will be able to identify the last proxy traffic traversed before it enters their network; the defender may or may not be able to identify any previous proxies before the last-hop proxy. This technique makes identifying the original source of the malicious traffic even more difficult by requiring the defender to trace malicious traffic through several proxies to identify its source. For example, adversaries may construct or use onion routing networks – such as the publicly available Tor network – to transport encrypted C2 traffic through a compromised population, allowing communication with any device within the network. Adversaries may also use operational relay box (ORB) networks composed of virtual private servers (VPS), Internet of Things (IoT) devices, smart devices, and end-of-life routers to obfuscate their operations. In the case of network infrastructure, it is possible for an adversary to leverage multiple compromised devices to create a multi-hop proxy chain (i.e., Network Devices). By leveraging Patch System Image on routers, adversaries can add custom code to the affected network devices that will implement onion routing between those nodes. This method is dependent upon the Network Boundary Bridging method allowing the adversaries to cross the protected network boundary of the Internet perimeter and into the organization’s Wide-Area Network (WAN). Protocols such as ICMP may be used as a transport. Similarly, adversaries may abuse peer-to-peer (P2P) and blockchain-oriented infrastructure to implement routing between a decentralized network of peers.
**Detection**
- [AN1023] **[ESXi]** Outbound encrypted traffic initiated from hypervisor shell or via VM backdoor mechanisms to relays in VPS infrastructure, especially if traversing multiple nodes before reaching Internet destination. Packet captures or firewall logs show non-VM communication paths.
- [AN1020] **[Windows]** Suspicious processes (e.g., Tor clients, relays, unknown binaries) launch with sustained encrypted outbound traffic to known anonymity infrastructure (e.g., Tor, I2P), and may relay to additional internal systems via reverse proxying, ICMP tunneling, or socket forwarding.
- [AN1021] **[Linux]** Tools such as `tor`, `nglite`, `proxychains`, `chisel`, or custom daemons repeatedly initiate outbound sessions to multiple nodes before final destination. This behavior is abnormal for Linux services outside of VPN, monitoring, or CDN relay contexts.
- [AN1024] **[Network Devices]** Encrypted traffic or ICMP tunneling from border routers to internal routers or unknown external IPs. Forwarded traffic shows consistent hop-to-hop relaying without matching configured VPN or expected network topology.
- [AN1022] **[macOS]** LaunchAgents or LaunchDaemons initiate persistent Tor or relay processes that make encrypted outbound connections. May be paired with sandbox bypasses or unsigned executables communicating over SOCKS proxies.
**Procedure Examples**
- [S0276] Keydnap: Keydnap uses a copy of tor2web proxy for HTTPS communications.
- [S0282] MacSpy: MacSpy uses Tor for command and control.
- [S0342] GreyEnergy: GreyEnergy has used Tor relays for Command and Control servers.
- [G1003] Ember Bear: Ember Bear has configured multi-hop proxies via ProxyChains within victim environments.
- [S0386] Ursnif: Ursnif has used Tor for C2.
- [S0438] Attor: Attor has used Tor for C2 communication.
- [G0007] APT28: APT28 has routed traffic over Tor and VPN servers to obfuscate their activities.
- [C0004] CostaRicto: During CostaRicto, the threat actors used a layer of proxies to manage C2 communications.
- [G0100] Inception: Inception used chains of compromised routers to proxy C2 communications between them and cloud service providers.
- [G0065] Leviathan: Leviathan has used multi-hop proxies to disguise the source of their malicious traffic.


### T1090.004 - Proxy: Domain Fronting
Adversaries may take advantage of routing schemes in Content Delivery Networks (CDNs) and other services which host multiple domains to obfuscate the intended destination of HTTPS traffic or traffic tunneled through HTTPS. Domain fronting involves using different domain names in the SNI field of the TLS header and the Host field of the HTTP header. If both domains are served from the same CDN, then the CDN may route to the address specified in the HTTP header after unwrapping the TLS header. A variation of the the technique, "domainless" fronting, utilizes a SNI field that is left blank; this may allow the fronting to work even when the CDN attempts to validate that the SNI and HTTP Host fields match (if the blank SNI fields are ignored). For example, if domain-x and domain-y are customers of the same CDN, it is possible to place domain-x in the TLS header and domain-y in the HTTP header. Traffic will appear to be going to domain-x, however the CDN may route it to domain-y.
**Detection**
- [AN0567] **[ESXi]** Traffic originating from ESXi hosts or management interfaces displays SNI-to-Host mismatch behavior, particularly anomalous given typical infrastructure communication patterns.
- [AN0566] **[macOS]** Unsigned or user-space apps initiate TLS connections with one hostname and HTTP headers requesting a different domain, commonly abused in CDN-resident domain fronting techniques.
- [AN0565] **[Linux]** Applications such as `curl`, `wget`, or custom binaries initiate HTTPS connections where the TLS SNI is mismatched or absent while HTTP Host targets CDN-available C2 endpoints.
- [AN0564] **[Windows]** Suspicious outbound HTTPS connections where the TLS Server Name Indication (SNI) does not match the HTTP Host header, indicating potential use of domain fronting to mask C2 traffic via CDNs.
**Procedure Examples**
- [S0154] Cobalt Strike: Cobalt Strike has the ability to accept a value for HTTP Host Header to enable domain fronting.
- [G0016] APT29: APT29 has used the meek domain fronting plugin for Tor to hide the destination of C2 traffic.
- [S0175] meek: meek uses Domain Fronting to disguise the destination of network traffic as another server that is hosted in the same Content Delivery Network (CDN) as the intended destination.
- [S0699] Mythic: Mythic supports domain fronting via custom request headers.
- [S0649] SMOKEDHAM: SMOKEDHAM has used a fronted domain to obfuscate its hard-coded C2 server domain.


### T1092 - Communication Through Removable Media
Adversaries can perform command and control between compromised hosts on potentially disconnected networks using removable media to transfer commands from system to system. Both systems would need to be compromised, with the likelihood that an Internet-connected system was compromised first and the second through lateral movement by Replication Through Removable Media. Commands and files would be relayed from the disconnected system to the Internet-connected system to which the adversary has direct access.
**Detection**
- [AN0248] **[Linux]** Detection of file write-access to USB-mount directories (e.g., /media/, /run/media/) followed by same-file access or execution on another host.
- [AN0247] **[Windows]** Behavioral sequence where removable media is mounted, files are written/updated, and subsequently read/executed on a separate host, suggesting removable-media relay communication.
- [AN0249] **[macOS]** Correlates removable volume mounts (disk arbitration) with file I/O events on that volume, followed by same file execution shortly after insert.
**Procedure Examples**
- [S0023] CHOPSTICK: Part of APT28's operation involved using CHOPSTICK modules to copy itself to air-gapped machines, using files written to USB sticks to transfer data and command traffic.
- [G0007] APT28: APT28 uses a tool that captures information from air-gapped computers via an infected USB and transfers it to network-connected computer when the USB is inserted.
- [S0136] USBStealer: USBStealer drops commands for a second victim onto a removable media drive inserted into the first victim, and commands are executed when the drive is inserted into the second victim.


### T1095 - Non-Application Layer Protocol
Adversaries may use an OSI non-application layer protocol for communication between host and C2 server or among infected hosts within a network. The list of possible protocols is extensive. Specific examples include use of network layer protocols, such as the Internet Control Message Protocol (ICMP), transport layer protocols, such as the User Datagram Protocol (UDP), session layer protocols, such as Socket Secure (SOCKS), as well as redirected/tunneled protocols, such as Serial over LAN (SOL). ICMP communication between hosts is one example. Because ICMP is part of the Internet Protocol Suite, it is required to be implemented by all IP-compatible hosts. However, it is not as commonly monitored as other Internet Protocols such as TCP or UDP and may be used by adversaries to hide communications. In ESXi environments, adversaries may leverage the Virtual Machine Communication Interface (VMCI) for communication between guest virtual machines and the ESXi host. This traffic is similar to client-server communications on traditional network sockets but is localized to the physical machine running the ESXi host, meaning it does not traverse external networks (routers, switches). This results in communications that are invisible to external monitoring and standard networking tools like tcpdump, netstat, nmap, and Wireshark. By adding a VMCI backdoor to a compromised ESXi host, adversaries may persistently regain access from any guest VM to the compromised ESXi host’s backdoor, regardless of network segmentation or firewall rules in place.
**Detection**
- [AN1254] **[Windows]** Anomalous use of ICMP or UDP by non-network service processes for data exfiltration or remote control, especially if traffic bypasses proxy infrastructure or shows unusual flow patterns.
- [AN1256] **[macOS]** Unsigned binaries or interpreted scripts initiating non-standard protocols (ICMP, UDP, SOCKS) outside of baseline network behavior.
- [AN1258] **[Network Devices]** Non-standard port/protocol pairings or low-entropy ICMP traffic resembling tunneling patterns (e.g., fixed-size pings with delays).
- [AN1255] **[Linux]** ICMP or raw socket traffic generated by user-mode processes like bash, Python, or nc, typically using `ping`, `hping3`, or crafted packets via libpcap or scapy.
- [AN1257] **[ESXi]** VMCI (Virtual Machine Communication Interface) traffic between guest and host, or between VMs, originating from non-management tools or unauthorized binaries.
**Procedure Examples**
- [S1144] FRP: FRP can communicate over TCP, TCP stream multiplexing, KERN Communications Protocol (KCP), QUIC, and UDP.
- [S0352] OSX_OCEANLOTUS.D: OSX_OCEANLOTUS.D has used a custom binary protocol over port 443 for C2 traffic.
- [S0504] Anchor: Anchor has used ICMP in C2 communications.
- [S0076] FakeM: Some variants of FakeM use SSL to communicate with C2 servers.
- [S0456] Aria-body: Aria-body has used TCP in C2 communications.
- [S0660] Clambling: Clambling has the ability to use TCP and UDP for communication.
- [G0047] Gamaredon Group: Gamaredon Group has used SOCKS5 over port 9050 for C2 communication.
- [S1016] MacMa: MacMa has used a custom JSON-based protocol for its C&C communications.
- [S0155] WINDSHIELD: WINDSHIELD C2 traffic can communicate via TCP raw sockets.
- [S0666] Gelsemium: Gelsemium has the ability to use TCP and UDP in C2 communications.


### T1102 - Web Service
Adversaries may use an existing, legitimate external Web service as a means for relaying data to/from a compromised system. Popular websites, cloud services, and social media acting as a mechanism for C2 may give a significant amount of cover due to the likelihood that hosts within a network are already communicating with them prior to a compromise. Using common services, such as those offered by Google, Microsoft, or Twitter, makes it easier for adversaries to hide in expected noise. Web service providers commonly use SSL/TLS encryption, giving adversaries an added level of protection. Use of Web services may also protect back-end C2 infrastructure from discovery through malware binary analysis while also enabling operational resiliency (since this infrastructure may be dynamically changed).
**Detection**
- [AN1189] **[Windows]** Detects unusual outbound connections to web services from uncommon processes using SSL/TLS, particularly those exhibiting high outbound data volume or persistence.
- [AN1190] **[Linux]** Detects command-line tools, agents, or scripts making outbound HTTPS connections to popular web services like Discord, Slack, Dropbox, or Graph API in an unusual context.
- [AN1192] **[ESXi]** Detects guest VMs or management agents issuing HTTP(S) traffic to external services without a valid patch management or backup justification.
- [AN1191] **[macOS]** Detects user agents or background services making unauthorized or unscheduled web API calls to cloud/web services over HTTPS.
**Procedure Examples**
- [C0040] APT41 DUST: APT41 DUST used compromised Google Workspace accounts for command and control.
- [S1147] Nightdoor: Nightdoor can utilize Microsoft OneDrive or Google Drive for command and control purposes.
- [S1160] Latrodectus: Latrodectus has used Google Firebase to download malicious installation scripts.
- [C0027] C0027: During C0027, Scattered Spider downloaded tools from sites including file.io, GitHub, and paste.ee.
- [G1039] RedCurl: RedCurl has used web services to download malicious files.
- [G0100] Inception: Inception has incorporated at least five different cloud service providers into their C2 infrastructure including CloudMe.
- [S1086] Snip3: Snip3 can download additional payloads from web services including Pastebin and top4top.
- [S1130] Raspberry Robin: Raspberry Robin second stage payloads can be hosted as RAR files, containing a malicious EXE and DLL, on Discord servers.
- [S0335] Carbon: Carbon can use Pastebin to receive C2 commands.
- [G0106] Rocke: Rocke has used Pastebin, Gitee, and GitLab for Command and Control.


### T1102.001 - Web Service: Dead Drop Resolver
Adversaries may use an existing, legitimate external Web service to host information that points to additional command and control (C2) infrastructure. Adversaries may post content, known as a dead drop resolver, on Web services with embedded (and often obfuscated/encoded) domains or IP addresses. Once infected, victims will reach out to and be redirected by these resolvers. Popular websites and social media acting as a mechanism for C2 may give a significant amount of cover due to the likelihood that hosts within a network are already communicating with them prior to a compromise. Using common services, such as those offered by Google or Twitter, makes it easier for adversaries to hide in expected noise. Web service providers commonly use SSL/TLS encryption, giving adversaries an added level of protection. Use of a dead drop resolver may also protect back-end C2 infrastructure from discovery through malware binary analysis while also enabling operational resiliency (since this infrastructure may be dynamically changed).
**Detection**
- [AN0158] **[Windows]** Detection of a process or script that accesses a common web service to retrieve content containing obfuscated indicators of a secondary C2 server (dead drop resolver behavior).
- [AN0160] **[macOS]** Detection of a process or script that accesses a common web service to retrieve content containing obfuscated indicators of a secondary C2 server (dead drop resolver behavior).
- [AN0161] **[ESXi]** Detection of a process or script that accesses a common web service to retrieve content containing obfuscated indicators of a secondary C2 server (dead drop resolver behavior).
- [AN0159] **[Linux]** Detection of a process or script that accesses a common web service to retrieve content containing obfuscated indicators of a secondary C2 server (dead drop resolver behavior).
**Procedure Examples**
- [S0373] Astaroth: Astaroth can store C2 information on cloud hosting services such as AWS and CloudFlare and websites like YouTube and Facebook.
- [S0128] BADNEWS: BADNEWS collects C2 information via a dead drop resolver.
- [S1051] KEYPLUG: The KEYPLUG Windows variant has retrieved C2 addresses from encoded data in posts on tech community forums.
- [S0051] MiniDuke: Some MiniDuke components use Twitter to initially obtain the address of a C2 server or as a backup if no hard-coded C2 server responds.
- [S0531] Grandoreiro: Grandoreiro can obtain C2 information from Google Docs.
- [S0455] Metamorfo: Metamorfo has used YouTube to store and hide C&C server domains.
- [S0013] PlugX: PlugX uses Pastebin to store C2 addresses.
- [S0674] CharmPower: CharmPower can retrieve C2 domain information from actor-controlled S3 buckets.
- [S1201] TRANSLATEXT: TRANSLATEXT has used a dead drop resolver to retrieve configurations and commands from a public blog site.
- [G0106] Rocke: Rocke has used Pastebin to check the version of beaconing malware and redirect to another Pastebin hosting updated malware.


### T1102.002 - Web Service: Bidirectional Communication
Adversaries may use an existing, legitimate external Web service as a means for sending commands to and receiving output from a compromised system over the Web service channel. Compromised systems may leverage popular websites and social media to host command and control (C2) instructions. Those infected systems can then send the output from those commands back over that Web service channel. The return traffic may occur in a variety of ways, depending on the Web service being utilized. For example, the return traffic may take the form of the compromised system posting a comment on a forum, issuing a pull request to development project, updating a document hosted on a Web service, or by sending a Tweet. Popular websites and social media acting as a mechanism for C2 may give a significant amount of cover due to the likelihood that hosts within a network are already communicating with them prior to a compromise. Using common services, such as those offered by Google or Twitter, makes it easier for adversaries to hide in expected noise. Web service providers commonly use SSL/TLS encryption, giving adversaries an added level of protection.
**Detection**
- [AN0101] **[Linux]** Non-interactive system processes making encrypted HTTPS connections to well-known web services followed by high outbound traffic volume or scripted upload patterns.
- [AN0100] **[Windows]** Suspicious processes initiating encrypted HTTPS connections to common web service domains, followed by abnormal data upload behavior or automated posting behavior indicative of C2 bidirectional traffic.
- [AN0102] **[macOS]** Scripting engines (e.g., osascript, Python) initiating HTTPS requests to social media or content-sharing platforms, paired with automated response handling indicative of two-way communication.
**Procedure Examples**
- [S0393] PowerStallion: PowerStallion uses Microsoft OneDrive as a C2 server via a network drive mapped with net use.
- [S0651] BoxCaon: BoxCaon has used DropBox for C2 communications.
- [C0023] Operation Ghost: For Operation Ghost, APT29 used social media platforms to hide communications to C2 servers.
- [S1222] RIFLESPINE: RIFLESPINE can retrieve C2 commands from an encrypted file on Google Drive then upload the results of command execution back to Google Drive.
- [S0538] Crutch: Crutch can use Dropbox to receive commands and upload stolen data.
- [S0660] Clambling: Clambling can use Dropbox to download malicious payloads, send commands, and receive information.
- [S0229] Orz: Orz has used Technet and Pastebin web pages for command and control.
- [S0025] CALENDAR: The CALENDAR malware communicates through the use of events in Google Calendar.
- [S0046] CozyCar: CozyCar uses Twitter as a backup C2 channel to Twitter accounts specified in its configuration file.
- [S0248] yty: yty communicates to the C2 server by retrieving a Google Doc.


### T1102.003 - Web Service: One-Way Communication
Adversaries may use an existing, legitimate external Web service as a means for sending commands to a compromised system without receiving return output over the Web service channel. Compromised systems may leverage popular websites and social media to host command and control (C2) instructions. Those infected systems may opt to send the output from those commands back over a different C2 channel, including to another distinct Web service. Alternatively, compromised systems may return no output at all in cases where adversaries want to send instructions to systems and do not want a response. Popular websites and social media acting as a mechanism for C2 may give a significant amount of cover due to the likelihood that hosts within a network are already communicating with them prior to a compromise. Using common services, such as those offered by Google or Twitter, makes it easier for adversaries to hide in expected noise. Web service providers commonly use SSL/TLS encryption, giving adversaries an added level of protection.
**Detection**
- [AN1602] **[ESXi]** ESXi shell or scheduled tasks initiating outbound HTTPS to known public services without inbound return or loggable response, used to fetch instructions.
- [AN1599] **[Windows]** Suspicious process initiating outbound connections to web services without corresponding response or return traffic, indicative of one-way command channels.
- [AN1601] **[macOS]** Process using URLSession or similar API to fetch from web services without any response handling, indicative of one-way C2 channels.
- [AN1600] **[Linux]** Curl, wget, or custom HTTP clients initiated by uncommon user accounts or cron jobs to popular web services, with no observed response parsing logic.
**Procedure Examples**
- [C0046] ArcaneDoor: ArcaneDoor utilized HTTP command and control traffic where commands are intercepted from HTTP traffic to the device, parsed for appropriate identifiers and commands, and then executed.
- [S0568] EVILNUM: EVILNUM has used a one-way communication method via GitLab and Digital Point to perform C2.
- [G0065] Leviathan: Leviathan has received C2 instructions from user profiles created on legitimate websites such as Github and TechNet.
- [G0047] Gamaredon Group: Gamaredon Group has used Telegram Messenger content to discover the IP address for C2 communications.
- [S1210] Sagerunex: Sagerunex has used web services such as Twitter for command and control purposes.
- [S0455] Metamorfo: Metamorfo has downloaded a zip file for execution on the system.
- [S0052] OnionDuke: OnionDuke uses Twitter as a backup C2.
- [S1164] UPSTYLE: UPSTYLE parses encoded commands from error logs after attempting to resolve a non-existing webpage from the command and control server.
- [S0037] HAMMERTOSS: The "tDiscoverer" variant of HAMMERTOSS establishes a C2 channel by downloading resources from Web services like Twitter and GitHub. HAMMERTOSS binaries contain an algorithm that generates a different Twitter handle for the malware to check for instructions every day.


### T1104 - Multi-Stage Channels
Adversaries may create multiple stages for command and control that are employed under different conditions or for certain functions. Use of multiple stages may obfuscate the command and control channel to make detection more difficult. Remote access tools will call back to the first-stage command and control server for instructions. The first stage may have automated capabilities to collect basic host information, update tools, and upload additional files. A second remote access tool (RAT) could be uploaded at that point to redirect the host to the second-stage command and control server. The second stage will likely be more fully featured and allow the adversary to interact with the system through a reverse shell and additional RAT features. The different stages will likely be hosted separately with no overlapping infrastructure. The loader may also have backup first-stage callbacks or Fallback Channels in case the original first-stage communication path is discovered and blocked.
**Detection**
- [AN0639] **[macOS]** Initial process using NSURLSession or similar APIs reaches out to known staging domains, followed by creation of a reverse shell or RAT connecting to a second unrelated server.
- [AN0638] **[Linux]** Shell script or binary initiates curl/wget request to staging domain, writes output to disk or memory, and shortly afterward launches another process that establishes new outbound connection to a different IP or hostname.
- [AN0640] **[ESXi]** CLI-based or API-based network call from the hypervisor to external staging host, shortly followed by a connection to a second external IP by a spawned process or scheduled task.
- [AN0637] **[Windows]** Initial process initiates outbound connection to first-stage C2, receives payloads or commands, then spawns or injects into a second process that establishes a new outbound connection to an unrelated destination (second-stage C2).
**Procedure Examples**
- [G0022] APT3: An APT3 downloader first establishes a SOCKS5 connection to 192.157.198[.]103 using TCP port 1913; once the server response is verified, it then requests a connection to 192.184.60[.]229 on TCP port 81.
- [S1141] LunarWeb: LunarWeb can use one C2 URL for first contact and to upload information about the host computer and two additional C2 URLs for getting commands.
- [S0069] BLACKCOFFEE: BLACKCOFFEE uses Microsoft’s TechNet Web portal to obtain an encoded tag containing the IP address of a command and control server and then communicates separately with that IP address for C2. If the C2 server is discovered or shut down, the threat actors can update the encoded IP address on TechNet to maintain control of the victims’ machines.
- [C0056] RedPenguin: During RedPenguin, UNC3886 used malware with separate channels to request and carry out tasks from C2.
- [G0032] Lazarus Group: Lazarus Group has used multi-stage malware components that inject later stages into separate processes.
- [S0476] Valak: Valak can download additional modules and malware capable of using separate C2 channels.
- [S1206] JumbledPath: JumbledPath can communicate over a unique series of connections to send and retrieve data from exploited devices.
- [S0534] Bazar: The Bazar loader is used to download and execute the Bazar backdoor.
- [S1086] Snip3: Snip3 can download and execute additional payloads and modules over separate communication channels.
- [S1160] Latrodectus: Latrodectus has used a two-tiered C2 configuration with tier one nodes connecting to the victim and tier two nodes connecting to backend infrastructure.


### T1105 - Ingress Tool Transfer
Adversaries may transfer tools or other files from an external system into a compromised environment. Tools or files may be copied from an external adversary-controlled system to the victim network through the command and control channel or through alternate protocols such as ftp. Once present, adversaries may also transfer/spread tools between victim devices within a compromised environment (i.e. Lateral Tool Transfer). On Windows, adversaries may use various utilities to download tools, such as `copy`, `finger`, certutil, and PowerShell commands such as IEX(New-Object Net.WebClient).downloadString() and Invoke-WebRequest. On Linux and macOS systems, a variety of utilities also exist, such as `curl`, `scp`, `sftp`, `tftp`, `rsync`, `finger`, and `wget`. A number of these tools, such as `wget`, `curl`, and `scp`, also exist on ESXi. After downloading a file, a threat actor may attempt to verify its integrity by checking its hash value (e.g., via `certutil -hashfile`). Adversaries may also abuse installers and package managers, such as `yum` or `winget`, to download tools to victim hosts. Adversaries have also abused file application features, such as the Windows `search-ms` protocol handler, to deliver malicious files to victims through remote file searches invoked by User Execution (typically after interacting with Phishing lures). Files can also be transferred using various Web Services as well as native or otherwise present tools on the victim system. In some cases, adversaries may be able to leverage services that sync between a web-based and an on-premises client, such as Dropbox or OneDrive, to transfer files onto victim systems. For example, by compromising a cloud account and logging into the service's web portal, an adversary may be able to trigger an automatic syncing process that transfers the file onto the victim's machine.
**Detection**
- [AN0167] **[macOS]** Process execution of curl or wget followed by a network connection and a file created in temporary or user-specific directories.
- [AN0166] **[Linux]** Shell-based tools (curl, wget, scp) initiate connections to external domains followed by creation of executable files on disk.
- [AN0169] **[Network Devices]** Network device logs show anomalous inbound file transfers or uncharacteristic flows with high payload volume to network devices with storage or automation hooks.
- [AN0165] **[Windows]** Unusual or uncommon processes initiate network connections to external destinations followed by file creation (tools downloaded).
- [AN0168] **[ESXi]** Command line interface or vCLI triggers remote transfer using wget or curl, writing files into datastore paths or local tmp directories.
**Procedure Examples**
- [G0117] Fox Kitten: Fox Kitten has downloaded additional tools including PsExec directly to endpoints.
- [S0396] EvilBunny: EvilBunny has downloaded additional Lua scripts from the C2.
- [S0664] Pandora: Pandora can load additional drivers and files onto a victim machine.
- [S0444] ShimRat: ShimRat can download additional files.
- [S1228] PUBLOAD: PUBLOAD has acted as a stager that can download the next-stage payload from its C2 server. PUBLOAD has also delivered FDMTP as a secondary control tool and PTSOCKET for exfiltration to some infected systems.
- [S1118] BUSHWALK: BUSHWALK can write malicious payloads sent through a web request’s command parameter.
- [S1066] DarkTortilla: DarkTortilla can download additional packages for keylogging, cryptocurrency mining, and other capabilities; it can also retrieve malicious payloads such as Agent Tesla, AsyncRat, NanoCore, RedLine, Cobalt Strike, and Metasploit.
- [S0627] SodaMaster: SodaMaster has the ability to download additional payloads from C2 to the targeted system.
- [G1002] BITTER: BITTER has downloaded additional malware and tools onto a compromised host.
- [S1019] Shark: Shark can download additional files from its C2 via HTTP or DNS.


### T1132 - Data Encoding
Adversaries may encode data to make the content of command and control traffic more difficult to detect. Command and control (C2) information can be encoded using a standard data encoding system. Use of data encoding may adhere to existing protocol specifications and includes use of ASCII, Unicode, Base64, MIME, or other binary-to-text and character encoding systems. Some data encoding systems may also result in data compression, such as gzip.
**Detection**
- [AN0304] **[macOS]** Processes use built-in encoding utilities (e.g., `base64`, `xxd`, or `plutil`) to encode file contents followed by HTTP/HTTPS transfer via curl or custom applications.
- [AN0305] **[ESXi]** ESXi daemons (e.g., hostd, vpxa) are wrapped or impersonated to send large outbound traffic using gzip/Base64 encoding over SSH or HTTP. These actions follow suspicious logins or shell access.
- [AN0303] **[Linux]** Custom scripts or processes encode outbound traffic using gzip, Base64, or hex prior to exfiltration via curl, wget, or custom sockets. Encoding typically occurs before or during outbound connections from non-network daemons.
- [AN0302] **[Windows]** Atypical processes (e.g., powershell.exe, regsvr32.exe) encode large outbound traffic using Base64 or other character encodings; this traffic is sent over uncommon ports or embedded in protocol fields (e.g., HTTP cookies or headers).
**Procedure Examples**
- [G1047] Velvet Ant: Velvet Ant sent commands to compromised F5 BIG-IP devices in an encoded format requiring a passkey before interpretation and execution.
- [S0128] BADNEWS: After encrypting C2 data, BADNEWS converts it into a hexadecimal representation and then encodes it into base64.
- [S0699] Mythic: Mythic provides various transform functions to encode and/or randomize C2 data.
- [S0386] Ursnif: Ursnif has used encoded data in HTTP URLs for C2.
- [S0362] Linux Rabbit: Linux Rabbit sends the payload from the C2 server as an encoded URL parameter.
- [S0132] H1N1: H1N1 obfuscates C2 traffic with an altered version of base64.


### T1132.001 - Data Encoding: Standard Encoding
Adversaries may encode data with a standard data encoding system to make the content of command and control traffic more difficult to detect. Command and control (C2) information can be encoded using a standard data encoding system that adheres to existing protocol specifications. Common data encoding schemes include ASCII, Unicode, hexadecimal, Base64, and MIME. Some data encoding systems may also result in data compression, such as gzip.
**Detection**
- [AN0348] **[ESXi]** ESXi shell (BusyBox) or VMware utilities (openssl, python if present) used to Base64/hex encode data from datastore or config files → followed by abnormal egress from the host (NSX/flow logs) with asymmetric bytes_out or HTTPS posts to non-management endpoints.
- [AN0347] **[macOS]** Processes use base64/xxd/openssl/python Objective‑C APIs to encode data (seen in EndpointSecurity exec events or Unified Logs) → quick outbound connections with large bytes_out or HTTP POSTs carrying Base64/MIME bodies.
- [AN0345] **[Windows]** Process invokes a standard encoder (e.g., PowerShell -enc, certutil -encode, base64 via .NET/Invoke-Expression) or emits long Base64/hex literals → shortly followed by outbound network egress with high bytes_out:bytes_in ratio or HTTP headers/payloads containing Base64/MIME blocks.
- [AN0346] **[Linux]** Shell/utility (base64, xxd -p, od, openssl enc -base64, python/perl base64 libraries) encodes data → subsequent outbound connections (curl/wget/bash TCP, socat, python requests) with high asymmetry or Base64/MIME blobs in HTTP/DNS payloads.
**Procedure Examples**
- [S0610] SideTwist: SideTwist has used Base64 for encoded C2 traffic.
- [S0410] Fysbis: Fysbis can use Base64 to encode its C2 traffic.
- [S1021] DnsSystem: DnsSystem can Base64 encode data sent to C2.
- [S0045] ADVSTORESHELL: C2 traffic from ADVSTORESHELL is encrypted, then encoded with Base64 encoding.
- [S0696] Flagpro: Flagpro has encoded bidirectional data communications between a target system and C2 server using Base64.
- [S0603] Stuxnet: Stuxnet transforms encrypted binary data into an ASCII string in order to use it as a URL parameter value.
- [S0053] SeaDuke: SeaDuke C2 traffic is base64-encoded.
- [S1160] Latrodectus: Latrodectus has Base64-encoded the message body of a HTTP request sent to C2.
- [S1196] Troll Stealer: Troll Stealer performs XOR encryption and Base64 encoding of data prior to sending to command and control infrastructure.
- [G0034] Sandworm Team: Sandworm Team's BCS-server tool uses base64 encoding and HTML tags for the communication traffic between the C2 server.


### T1132.002 - Data Encoding: Non-Standard Encoding
Adversaries may encode data with a non-standard data encoding system to make the content of command and control traffic more difficult to detect. Command and control (C2) information can be encoded using a non-standard data encoding system that diverges from existing protocol specifications. Non-standard data encoding schemes may be based on or related to standard data encoding schemes, such as a modified Base64 encoding for the message body of an HTTP request.
**Detection**
- [AN0928] **[Linux]** Shell scripts or binaries implement custom mapping tables (tr/sed/awk/golang/rust/python encode loops), or emit long high-entropy tokens that fail Base64/Hex validation → correlated with egress showing asymmetric flow, protocol-mismatch payloads, or DNS/HTTP bodies containing low-diversity-but-long custom alphabets.
- [AN0927] **[Windows]** A process/script constructs or references a custom/alphabet translation table (e.g., 64/85/32+ arbitrary chars, XOR/base-N loops) or emits long high-entropy strings that do NOT validate as standard Base64/Hex → shortly after, the same process (or its child) generates outbound traffic with asymmetric bytes_out:bytes_in, fixed-size beacons, or protocol/header mismatches (e.g., Content-Type says JSON but body fails JSON parse / contains non-standard alphabet).
- [AN0929] **[macOS]** EndpointSecurity/Unified Logs show processes generating custom alphabets or long high-entropy, non-standard tokens → network logs (PF/Zeek/EDR) show asymmetric beacons, protocol mismatches, or periodic fixed-size posts.
- [AN0930] **[ESXi]** ESXi shell or scripts produce long, high-entropy tokens (non-standard alphabets) in shell.log/hostd, followed by outbound flows (NSX/Zeek) with asymmetric ratios or protocol mismatches to non-management endpoints.
**Procedure Examples**
- [S0346] OceanSalt: OceanSalt can encode data with a NOT operation before sending the data to the control server.
- [S1035] Small Sieve: Small Sieve can use a custom hex byte swapping encoding scheme to obfuscate tasking traffic.
- [S1239] TONESHELL: TONESHELL has encoded a payload with a random 32-byte key using XOR. TONESHELL has also encoded payloads with a 256-byte key using XOR.
- [S1090] NightClub: NightClub has used a non-standard encoding in DNS tunneling removing any `=` from the result of base64 encoding, and replacing `/` characters with `-s` and `+` characters with `-p`.
- [S0495] RDAT: RDAT can communicate with the C2 via subdomains that utilize base64 with character substitutions.
- [S0260] InvisiMole: InvisiMole can use a modified base32 encoding to encode data within the subdomain of C2 requests.
- [S0022] Uroburos: Uroburos can use a custom base62 and a de-facto base32 encoding that uses digits 0-9 and lowercase letters a-z in C2 communications.
- [S1189] Neo-reGeorg: Neo-reGeorg can use modified Base64 encoding to obfuscate communications.
- [S0031] BACKSPACE: Newer variants of BACKSPACE will encode C2 communications with a custom system.
- [S1149] CHIMNEYSWEEP: CHIMNEYSWEEP can use a custom Base64 alphabet for encoding C2.


### T1205 - Traffic Signaling
Adversaries may use traffic signaling to hide open ports or other malicious functionality used for persistence or command and control. Traffic signaling involves the use of a magic value or sequence that must be sent to a system to trigger a special response, such as opening a closed port or executing a malicious task. This may take the form of sending a series of packets with certain characteristics before a port will be opened that the adversary can use for command and control. Usually this series of packets consists of attempted connections to a predefined sequence of closed ports (i.e. Port Knocking), but can involve unusual flags, specific strings, or other unique characteristics. After the sequence is completed, opening a port may be accomplished by the host-based firewall, but could also be implemented by custom software. Adversaries may also communicate with an already open port, but the service listening on that port will only respond to commands or trigger other malicious functionality if passed the appropriate magic value(s). The observation of the signal packets to trigger the communication can be conducted through different methods. One means, originally implemented by Cd00r , is to use the libpcap libraries to sniff for the packets in question. Another method leverages raw sockets, which enables the malware to use ports that are already open for use by other programs. On network devices, adversaries may use crafted packets to enable Network Device Authentication for standard services offered by the device such as telnet. Such signaling may also be used to open a closed service port such as telnet, or to trigger module modification of malware implants on the device, adding, removing, or changing malicious capabilities. Adversaries may use crafted packets to attempt to connect to one or more (open or closed) ports, but may also attempt to connect to a router interface, broadcast, and network address IP on the same port in order to achieve their goals and objectives. To enable this traffic signaling on embedded devices, adversaries must first achieve and leverage Patch System Image due to the monolithic nature of the architecture. Adversaries may also use the Wake-on-LAN feature to turn on powered off systems. Wake-on-LAN is a hardware feature that allows a powered down system to be powered on, or woken up, by sending a magic packet to it. Once the system is powered on, it may become a target for lateral movement.
**Detection**
- [AN1448] **[Windows]** A remote host sends a short sequence of failed connection attempts (RST/ICMP unreachable) to a set of closed ports. Within a brief window the endpoint (a) adds/enables a firewall rule or (b) a sniffer-backed process begins listening or opens a new socket, after which a successful connection occurs. Also detects Wake-on-LAN magic packets seen on local segment.
- [AN1449] **[Linux]** Closed-port knock sequence from a remote IP followed by on-host firewall change (iptables/nftables) or daemon starts listening (socket open) and a successful TCP/UDP connect. Optional detection of libpcap/raw-socket sniffers spawning to watch for secret values.
- [AN1450] **[macOS]** Remote knock sequence followed by PF/socketfilterfw rule update or a background process listening on a new port; then a successful TCP session. Also flags WoL magic packets on local segment.
- [AN1451] **[Network Devices]** Crafted ‘synful knock’ patterns toward routers/switches (same src hits interface/broadcast/network address on same port in short order) followed by ACL/telnet/SSH enablement or module change. Detect device image/ACL updates then a new mgmt session.
**Procedure Examples**
- [C0029] Cutting Edge: During Cutting Edge, threat actors sent a magic 48-byte sequence to enable the PITSOCK backdoor to communicate via the `/tmp/clientsDownload.sock` socket.
- [S1114] ZIPLINE: ZIPLINE can identify a specific string in intercepted network traffic, `SSH-2.0-OpenSSH_0.3xx.`, to trigger its command functionality.
- [S1118] BUSHWALK: BUSHWALK can modify the `DSUserAgentCap.pm` Perl module on Ivanti Connect Secure VPNs and either activate or deactivate depending on the value of the user agent in incoming HTTP requests.
- [S0587] Penquin: Penquin will connect to C2 only after sniffing a "magic packet" value in TCP or UDP packets matching specific conditions.
- [S0519] SYNful Knock: SYNful Knock can be sent instructions via special packets to change its functionality. Code for new functionality can be included in these messages.
- [S0430] Winnti for Linux: Winnti for Linux has used a passive listener, capable of identifying a specific magic value before executing tasking, as a secondary command and control (C2) mechanism.
- [S0220] Chaos: Chaos provides a reverse shell is triggered upon receipt of a packet with a special string, sent to any port.
- [S0221] Umbreon: Umbreon provides additional access using its backdoor Espeon, providing a reverse shell upon receipt of a special packet.
- [S0641] Kobalos: Kobalos is triggered by an incoming TCP connection to a legitimate service from a specific source port.
- [S0664] Pandora: Pandora can identify if incoming HTTP traffic contains a token and if so it will intercept the traffic and process the received command.


### T1205.001 - Traffic Signaling: Port Knocking
Adversaries may use port knocking to hide open ports used for persistence or command and control. To enable a port, an adversary sends a series of attempted connections to a predefined sequence of closed ports. After the sequence is completed, opening a port is often accomplished by the host based firewall, but could also be implemented by custom software. This technique has been observed both for the dynamic opening of a listening port as well as the initiating of a connection to a listening server on a different system. The observation of the signal packets to trigger the communication can be conducted through different methods. One means, originally implemented by Cd00r , is to use the libpcap libraries to sniff for the packets in question. Another method leverages raw sockets, which enables the malware to use ports that are already open for use by other programs.
**Detection**
- [AN0842] **[Windows]** A remote source rapidly touches a short sequence of closed ports (SYN→RST/S0) on a Windows host. Within a short window the host changes firewall state (WFP rule added/modified or service starts listening) and then the same source completes the first successful handshake to the newly opened port.
- [AN0844] **[macOS]** A source performs a closed-port sequence; the endpoint enables a PF/socketfilterfw rule or a background process binds a port; then a successful connection completes from the same source.
- [AN0843] **[Linux]** A source performs a short closed-port sequence; the host then modifies iptables/nftables/ufw rules or starts a daemon binding a new socket, followed by a successful connection from the same source.
- [AN0845] **[Network Devices]** Router/switch receives a knock pattern (same src touches device unicast, broadcast, and network-address on same or stepped ports) followed by ACL/line-vty/service enable and the first mgmt session success.
**Procedure Examples**
- [S1060] Mafalda: Mafalda can use port-knocking to authenticate itself to another implant called Cryshell to establish an indirect connection to the C2 server.
- [S1219] REPTILE: REPTILE has the ability to control compromised endpoints via port knocking.
- [G0056] PROMETHIUM: PROMETHIUM has used a script that configures the knockd service and firewall to only accept C2 connections from systems that use a specified sequence of knock ports.
- [G1048] UNC3886: UNC3886 maintained persistence on FortiGate Firewalls through ICMP port knocking.
- [S1204] cd00r: cd00r can monitor for a single TCP-SYN packet to be sent in series to a configurable set of ports (200, 80, 22, 53 and 3 in the original code) before opening a port for communication.
- [S1059] metaMain: metaMain has authenticated itself to a different implant, Cryshell, through a port knocking and handshake procedure.


### T1205.002 - Traffic Signaling: Socket Filters
Adversaries may attach filters to a network socket to monitor then activate backdoors used for persistence or command and control. With elevated permissions, adversaries can use features such as the `libpcap` library to open sockets and install filters to allow or disallow certain types of data to come through the socket. The filter may apply to all traffic passing through the specified network interface (or every interface if not specified). When the network interface receives a packet matching the filter criteria, additional actions can be triggered on the host, such as activation of a reverse shell. To establish a connection, an adversary sends a crafted packet to the targeted host that matches the installed filter criteria. Adversaries have used these socket filters to trigger the installation of implants, conduct ping backs, and to invoke command shells. Communication with these socket filters may also be used in conjunction with Protocol Tunneling. Filters can be installed on any Unix-like platform with `libpcap` installed or on Windows hosts using `Winpcap`. Adversaries may use either `libpcap` with `pcap_setfilter` or the standard library function `setsockopt` with `SO_ATTACH_FILTER` options. Since the socket connection is not active until the packet is received, this behavior may be difficult to detect due to the lack of activity on a host, low CPU overhead, and limited visibility into raw socket usage.
**Detection**
- [AN0462] **[Windows]** Adversary installs/uses packet-capture or raw-socket capability (WinPcap/Npcap, wpcap/packet DLLs or raw socket attach) and sets a filter. A crafted inbound packet is observed; within a short window the host process that loaded capture libraries initiates an outbound connection (e.g., reverse shell) to the packet origin.
- [AN0463] **[Linux]** Process creates a raw/packet socket and attaches a (e)BPF filter (setsockopt SO_ATTACH_FILTER/ATTACH_BPF or bpf(BPF_PROG_LOAD)). Immediately after a matching inbound packet, the same process binds/connects outward to a remote host (reverse shell or beacon).
- [AN0464] **[macOS]** Process opens /dev/bpf* (libpcap) or loads NetworkExtension filter, then after a crafted inbound packet the same process initiates an outbound connection to the trigger origin.
**Procedure Examples**
- [S1224] CASTLETAP: CASTLETAP can listen for a specialized ICMP packet for activation on compromised network devices.
- [S1161] BPFDoor: BPFDoor uses BPF bytecode to attach a filter to a network socket to view ICMP, UDP, or TCP packets coming through ports 22 (ssh), 80 (http), and 443 (https). When BPFDoor finds a packet containing its “magic” bytes, it parses out two fields and forks itself. The parent process continues to monitor filtered traffic while the child process executes the instructions from the parsed fields.
- [S1123] PITSTOP: PITSTOP can listen and evaluate incoming commands on the domain socket, created by PITHOOK malware, located at `/data/runtime/cockpit/wd.fd` for a predefined magic byte sequence. PITSTOP can then duplicate the socket for further communication over TLS.
- [S0587] Penquin: Penquin installs a `TCP` and `UDP` filter on the `eth0` interface.


### T1219 - Remote Access Tools
An adversary may use legitimate remote access tools to establish an interactive command and control channel within a network. Remote access tools create a session between two trusted hosts through a graphical interface, a command line interaction, a protocol tunnel via development or management software, or hardware-level access such as KVM (Keyboard, Video, Mouse) over IP solutions. Desktop support software (usually graphical interface) and remote management software (typically command line interface) allow a user to control a computer remotely as if they are a local user inheriting the user or software permissions. This software is commonly used for troubleshooting, software installation, and system management. Adversaries may similarly abuse response features included in EDR and other defensive tools that enable remote access. Remote access tools may be installed and used post-compromise as an alternate communications channel for redundant access or to establish an interactive remote desktop session with the target system. It may also be used as a malware component to establish a reverse connection or back-connect to a service or adversary-controlled system. Installation of many remote access tools may also include persistence (e.g., the software's installation routine creates a Windows Service). Remote access modules/features may also exist as part of otherwise existing software (e.g., Google Chrome’s Remote Desktop).
**Detection**
- [AN1368] **[macOS]** Electron/GUI or headless RAT execution followed by LaunchAgent/Daemon persistence and persistent external connections; interactive children (osascript/sh/curl) spawned by parent.
- [AN1366] **[Windows]** Chain of remote access tool behavior: (1) initial execution of remote-control/assist agent or GUI under user context; (2) persistence via service or autorun; (3) long-lived outbound connection/tunnel to external infrastructure; (4) interactive control signals such as shell or file-manager child processes spawned by the RAT parent.
- [AN1367] **[Linux]** Sequence of RAT agent execution, systemd persistence, and long-lived external egress; optional interactive shells spawned from the agent.
**Procedure Examples**
- [G0139] TeamTNT: TeamTNT has established tmate sessions for C2 communications.
- [S0384] Dridex: Dridex contains a module for VNC.
- [S0148] RTM: RTM has the capability to download a VNC module from command and control (C2).
- [G0049] OilRig: OilRig has incorporated remote monitoring and management (RMM) tools into their operations including ngrok.
- [G0046] FIN7: FIN7 has utilized the remote management tool Atera to download malware to a compromised system.
- [G0115] GOLD SOUTHFIELD: GOLD SOUTHFIELD has used the cloud-based remote management and monitoring tool "ConnectWise Control" to deploy REvil.
- [G1032] INC Ransom: INC Ransom has used AnyDesk and PuTTY on compromised systems.
- [S0030] Carbanak: Carbanak has a plugin for VNC and Ammyy Admin Tool.
- [G1051] Medusa Group: Medusa Group has leveraged Remote Access Software for lateral movement and data exfiltration. Medusa Group has also been known to utilize Remote Access Software such as AnyDesk, Atera, ConnectWise, eHorus, N-Able, PDQ Deploy, PDQ Inventory, SimpleHelp and Splashtop.
- [G0105] DarkVishnya: DarkVishnya used DameWare Mini Remote Control for lateral movement.


### T1219.001 - Remote Access Tools: IDE Tunneling
Adversaries may abuse Integrated Development Environment (IDE) software with remote development features to establish an interactive command and control channel on target systems within a network. IDE tunneling combines SSH, port forwarding, file sharing, and debugging into a single secure connection, letting developers work on remote systems as if they were local. Unlike SSH and port forwarding, IDE tunneling encapsulates an entire session and may use proprietary tunneling protocols alongside SSH, allowing adversaries to blend in with legitimate development workflows. Some IDEs, like Visual Studio Code, also provide CLI tools (e.g., `code tunnel`) that adversaries may use to programmatically establish tunnels and generate web-accessible URLs for remote access. These tunnels can be authenticated through accounts such as GitHub, enabling the adversary to control the compromised system via a legitimate developer portal. Additionally, adversaries may use IDE tunneling for persistence. Some IDEs, such as Visual Studio Code and JetBrains, support automatic reconnection. Adversaries may configure the IDE to auto-launch at startup, re-establishing the tunnel upon execution. Compromised developer machines may also be exploited as jump hosts to move further into the network. IDE tunneling tools may be built-in or installed as IDE Extensions.
**Detection**
- [AN0377] **[macOS]** Detection of JetBrains or VSCode tunnel profile creation followed by unusual persistent SSH or IDE-based tunnel communications to devtunnel APIs.
- [AN0376] **[Linux]** Creation of VSCode tunnel configuration file combined with interactive remote session via code CLI or ssh with JetBrains gateway.
- [AN0375] **[Windows]** Detection of the creation of VSCode or JetBrains CLI tunneling profiles followed by persistent remote access via IDE-integrated tunnels, potentially authenticated via GitHub or JetBrains accounts.
**Procedure Examples**
- [G0129] Mustang Panda: Mustang Panda has utilized an established Github account to create a tunnel within the victim environment using Visual Studio Code through the `code.exe tunnel` command.


### T1219.002 - Remote Access Tools: Remote Desktop Software
An adversary may use legitimate desktop support software to establish an interactive command and control channel to target systems within networks. Desktop support software provides a graphical interface for remotely controlling another computer, transmitting the display output, keyboard input, and mouse control between devices using various protocols. Desktop support software, such as `VNC`, `Team Viewer`, `AnyDesk`, `ScreenConnect`, `LogMein`, `AmmyyAdmin`, and other remote monitoring and management (RMM) tools, are commonly used as legitimate technical support software and may be allowed by application control within a target environment. Remote access modules/features may also exist as part of otherwise existing software such as Zoom or Google Chrome’s Remote Desktop.
**Detection**
- [AN0716] **[macOS]** Initiation of remote desktop sessions via AnyDesk, TeamViewer, or Chrome Remote Desktop accompanied by unexpected user logins or system modifications
- [AN0715] **[Linux]** Execution of known or custom VNC/remote desktop daemons or tunneling agents that initiate external communication after launch
- [AN0714] **[Windows]** Adversary installation or use of RMM software (e.g., TeamViewer, AnyDesk, ScreenConnect) followed by outbound beaconing or remote session establishment
**Procedure Examples**
- [G1053] Storm-0501: Storm-0501 has used legitimate remote monitoring and management (RMM) tools including AnyDesk, NinjaOne, and Level.io.
- [G1052] Contagious Interview: Contagious Interview has downloaded remote management and monitoring software such as “AnyDesk” for post compromise activities.
- [G0120] Evilnum: EVILNUM has used the malware variant, TerraTV, to run a legitimate TeamViewer application to connect to compromised machines.
- [G1046] Storm-1811: Storm-1811 has abused multiple types of legitimate remote access software and tools, such as ScreenConnect, NetSupport Manager, and AnyDesk.
- [G0129] Mustang Panda: Mustang Panda has installed TeamViewer on targeted systems.
- [C0018] C0018: During C0018, the threat actors used AnyDesk to transfer tools between systems.
- [G0094] Kimsuky: Kimsuky has used a modified TeamViewer client as a command and control channel.
- [G0076] Thrip: Thrip used a cloud-based remote access software called LogMeIn for their attacks.
- [G0048] RTM: RTM has used a modified version of TeamViewer and Remote Utilities for remote access.
- [G1015] Scattered Spider: In addition to directing victims to run remote software, Scattered Spider members themselves also deploy RMM software including TeamViewer, AnyDesk, LogMeIn, ngrok, and ConnectWise to establish persistence on the compromised network.


### T1219.003 - Remote Access Tools: Remote Access Hardware
An adversary may use legitimate remote access hardware to establish an interactive command and control channel to target systems within networks. These services, including IP-based keyboard, video, or mouse (KVM) devices such as TinyPilot and PiKVM, are commonly used as legitimate tools and may be allowed by peripheral device policies within a target environment. Remote access hardware may be physically installed and used post-compromise as an alternate communications channel for redundant access or as a way to establish an interactive remote session with the target system. Using hardware-based remote access tools may allow threat actors to bypass software security solutions and gain more control over the compromised device(s).
**Detection**
- [AN0447] **[Linux]** Insertion of USB-based hardware proxies (e.g., PiKVM) which register under predictable names (e.g., tinypilot) or mount under known paths (e.g., /opt/tinypilot-privileged).
- [AN0446] **[Windows]** Detection of USB-based remote access hardware (e.g., TinyPilot, PiKVM) attached to the host via drive or peripheral enumeration, triggering vendor identifiers or unusual EDID announcements.
- [AN0448] **[macOS]** Attachment of hardware-backed USB KVM devices (e.g., TinyPilot) that enumerate new HID or serial communication interfaces with identifiable metadata.
An adversary may use legitimate remote access hardware to establish an interactive command and control channel to target systems within networks. These services, including IP-based keyboard, video, or mouse (KVM) devices such as TinyPilot and PiKVM, are commonly used as legitimate tools and may be allowed by peripheral device policies within a target environment. Remote access hardware may be physically installed and used post-compromise as an alternate communications channel for redundant access or as a way to establish an interactive remote session with the target system. Using hardware-based remote access tools may allow threat actors to bypass software security solutions and gain more control over the compromised device(s).


### T1568 - Dynamic Resolution
Adversaries may dynamically establish connections to command and control infrastructure to evade common detections and remediations. This may be achieved by using malware that shares a common algorithm with the infrastructure the adversary uses to receive the malware's communications. These calculations can be used to dynamically adjust parameters such as the domain name, IP address, or port number the malware uses for command and control. Adversaries may use dynamic resolution for the purpose of Fallback Channels. When contact is lost with the primary command and control server malware may employ dynamic resolution as a means to reestablishing command and control.
**Detection**
- [AN0110] **[Linux]** Monitor /var/log/audit/audit.log and DNS resolver logs for repeated failed lookups or connections to high-entropy domain names. Correlate suspicious DNS queries with process lineage (e.g., Python, bash, or unusual system daemons).
- [AN0112] **[ESXi]** Monitor esxcli and syslog records for DNS resolver changes or repeated queries to unusual external domains by management agents. Detect unauthorized changes to VM or host network settings that redirect DNS lookups.
- [AN0111] **[macOS]** Inspect unified logs for anomalous DNS resolutions triggered by non-network applications. Flag repeated connections to newly registered or algorithmically generated domains. Correlate with endpoint process telemetry.
- [AN0109] **[Windows]** Correlate high-frequency or anomalous DNS query activity with processes that do not normally generate network requests (e.g., Office apps, system utilities). Detect pseudo-random or high-entropy domain lookups indicative of domain generation algorithms (DGAs).
**Procedure Examples**
- [S0671] Tomiris: Tomiris has connected to a signalization server that provides a URL and port, and then Tomiris sends a GET request to that URL to establish C2.
- [G1042] RedEcho: RedEcho used dynamic DNS domains associated with malicious infrastructure.
- [S0666] Gelsemium: Gelsemium can use dynamic DNS domain names in C2.
- [C0005] Operation Spalax: For Operation Spalax, the threat actors used dynamic DNS services, including Duck DNS and DNS Exit, as part of their C2 infrastructure.
- [G1018] TA2541: TA2541 has used dynamic DNS services for C2 infrastructure.
- [G0134] Transparent Tribe: Transparent Tribe has used dynamic DNS services to set up C2.
- [G1002] BITTER: BITTER has used DDNS for C2 communications.
- [S0148] RTM: RTM has resolved Pony C2 server IP addresses by either converting Bitcoin blockchain transaction data to specific octets, or accessing IP addresses directly within the Namecoin blockchain.
- [G0016] APT29: APT29 has used Dynamic DNS providers for their malware C2 infrastructure.
- [S0034] NETEAGLE: NETEAGLE can use HTTP to download resources that contain an IP address and port number pair to connect to for C2.


### T1568.001 - Dynamic Resolution: Fast Flux DNS
Adversaries may use Fast Flux DNS to hide a command and control channel behind an array of rapidly changing IP addresses linked to a single domain resolution. This technique uses a fully qualified domain name, with multiple IP addresses assigned to it which are swapped with high frequency, using a combination of round robin IP addressing and short Time-To-Live (TTL) for a DNS resource record. The simplest, "single-flux" method, involves registering and de-registering an addresses as part of the DNS A (address) record list for a single DNS name. These registrations have a five-minute average lifespan, resulting in a constant shuffle of IP address resolution. In contrast, the "double-flux" method registers and de-registers an address as part of the DNS Name Server record list for the DNS zone, providing additional resilience for the connection. With double-flux additional hosts can act as a proxy to the C2 host, further insulating the true source of the C2 channel.
**Detection**
- [AN1333] **[macOS]** Use unified logs to identify processes issuing repeated DNS queries where the resolved IP addresses change frequently within very short TTL values. Correlate with outbound network traffic to validate C2-like patterns.
- [AN1331] **[Windows]** Identify repeated DNS resolutions where the same domain name returns multiple IPs in short succession, combined with low TTL values and high query volume from unusual processes. Correlate with process lineage (e.g., Office apps spawning abnormal DNS lookups).
- [AN1332] **[Linux]** Monitor resolver logs and auditd events for domains resolving to a rotating set of IPs within very short TTL intervals. Correlate high query rates from non-browser applications (e.g., python, curl).
- [AN1334] **[ESXi]** Monitor ESXi syslog and esxcli outputs for abnormal DNS resolver behavior, such as frequent domain-to-IP changes or unauthorized modifications of DNS settings used by management agents. Correlate domain lookups with short TTL values.
**Procedure Examples**
- [S1025] Amadey: Amadey has used fast flux DNS for its C2.
- [G0045] menuPass: menuPass has used dynamic DNS service providers to host malicious domains.
- [G0092] TA505: TA505 has used fast flux to mask botnets by distributing payloads across multiple IPs.
- [S0032] gh0st RAT: gh0st RAT operators have used dynamic DNS to mask the true location of their C2 behind rapidly changing IP addresses.
- [G0047] Gamaredon Group: Gamaredon Group has used fast flux DNS to mask their command and control channel behind rotating IP addresses. Additionally, Gamaredon Group has used a low-frequency variant of the single-flux method.
- [S0385] njRAT: njRAT has used a fast flux DNS for C2 IP resolution.


### T1568.002 - Dynamic Resolution: Domain Generation Algorithms
Adversaries may make use of Domain Generation Algorithms (DGAs) to dynamically identify a destination domain for command and control traffic rather than relying on a list of static IP addresses or domains. This has the advantage of making it much harder for defenders to block, track, or take over the command and control channel, as there potentially could be thousands of domains that malware can check for instructions. DGAs can take the form of apparently random or “gibberish” strings (ex: istgmxdejdnxuyla.ru) when they construct domain names by generating each letter. Alternatively, some DGAs employ whole words as the unit by concatenating words together instead of letters (ex: cityjulydish.net). Many DGAs are time-based, generating a different domain for each time period (hourly, daily, monthly, etc). Others incorporate a seed value as well to make predicting future domains more difficult for defenders. Adversaries may use DGAs for the purpose of Fallback Channels. When contact is lost with the primary command and control server malware may employ a DGA as a means to reestablishing command and control.
**Detection**
- [AN1179] **[Linux]** Identify processes issuing repeated DNS queries to random-looking domains with abnormal entropy or word concatenations. Correlate resolver logs with high NXDOMAIN rates and auditd socket connections.
- [AN1181] **[ESXi]** Use ESXi syslogs to track abnormal DNS query patterns from management agents or VMs. Identify high-frequency, low-TTL, or unresolvable domains as suspicious. Correlate with unusual management plane process activity.
- [AN1180] **[macOS]** Monitor unified DNS logs for abnormal domain queries with low lexical similarity to known domains, repeated failed lookups, and random string structures. Cross-check with process logs to confirm unusual origins (non-browser apps).
- [AN1178] **[Windows]** Correlate DNS queries that generate domains with high entropy or gibberish patterns, combined with short-lived connections from unusual processes. Monitor Sysmon DNS events and Windows Security logs for abnormal query rates and failed lookups.
**Procedure Examples**
- [S0456] Aria-body: Aria-body has the ability to use a DGA for C2 communications.
- [S0650] QakBot: QakBot can use domain generation algorithms in C2 communication.
- [S0600] Doki: Doki has used the DynDNS service and a DGA based on the Dogecoin blockchain to generate C2 domains.
- [S0051] MiniDuke: MiniDuke can use DGA to generate new Twitter URLs for C2.
- [S0150] POSHSPY: POSHSPY uses a DGA to derive command and control URLs from a word list.
- [S0673] DarkWatchman: DarkWatchman has used a DGA to generate a domain name for C2.
- [S0360] BONDUPDATER: BONDUPDATER uses a DGA to communicate with command and control servers.
- [G0096] APT41: APT41 has used DGAs to change their C2 servers monthly.
- [G0127] TA551: TA551 has used a DGA to generate URLs from executed macros.
- [S0608] Conficker: Conficker has used a DGA that seeds with the current UTC victim system date to generate domains.


### T1568.003 - Dynamic Resolution: DNS Calculation
Adversaries may perform calculations on addresses returned in DNS results to determine which port and IP address to use for command and control, rather than relying on a predetermined port number or the actual returned IP address. A IP and/or port number calculation can be used to bypass egress filtering on a C2 channel. One implementation of DNS Calculation is to take the first three octets of an IP address in a DNS response and use those values to calculate the port for command and control traffic.
**Detection**
- [AN0731] **[ESXi]** Analyze ESXi syslogs for management agents or VMs making outbound connections to dynamically calculated ports derived from DNS responses. Cross-check with VM traffic baselines to identify anomalies.
- [AN0729] **[Linux]** Inspect resolver and audit logs for processes initiating outbound connections to ports calculated from DNS response IPs. Abnormal ephemeral port usage shortly after DNS queries can indicate DNS calculation behavior.
- [AN0730] **[macOS]** Use unified logs to detect unusual DNS responses correlated with subsequent connections to calculated or non-standard ports. Monitor non-browser apps making repeated outbound connections that deviate from expected patterns.
- [AN0728] **[Windows]** Monitor DNS query results where subsequent connections use derived or unusual port numbers not explicitly resolved, especially when tied to suspicious processes. Correlate Sysmon DNS logs (Event ID 22) with process creation and socket activity.
**Procedure Examples**
- [G0005] APT12: APT12 has used multiple variants of DNS Calculation including multiplying the first two octets of an IP address and adding the third octet to that value in order to get a resulting command and control port.


### T1571 - Non-Standard Port
Adversaries may communicate using a protocol and port pairing that are typically not associated. For example, HTTPS over port 8088 or port 587 as opposed to the traditional port 443. Adversaries may make changes to the standard port used by a protocol to bypass filtering or muddle analysis/parsing of network data. Adversaries may also make changes to victim systems to abuse non-standard ports. For example, Registry keys and other configuration settings can be used to modify protocol and port pairings.
**Detection**
- [AN0636] **[ESXi]** VM services or management daemons communicating on ports not defined by VMware defaults, such as vpxa or hostd processes initiating traffic over high-numbered or unexpected ports.
- [AN0635] **[macOS]** Applications making outbound connections on non-standard ports or launchd services bound to ports inconsistent with system baselines.
- [AN0633] **[Windows]** Processes initiating outbound connections on uncommon ports or using protocols inconsistent with the assigned port. Correlating process creation with subsequent network connections reveals anomalies such as svchost.exe or Office applications using high, atypical ports.
- [AN0634] **[Linux]** Unusual daemons or user processes binding/listening on ports outside of standard ranges, or initiating client connections using mismatched protocol/port pairings.
**Procedure Examples**
- [G0090] WIRTE: WIRTE has used HTTPS over ports 2083 and 2087 for C2.
- [S1211] Hannotog: Hannotog uses non-standard listening ports, such as UDP 5900, for command and control purposes.
- [G0091] Silence: Silence has used port 444 when sending data about the system from the client to the server.
- [S1031] PingPull: PingPull can use HTTPS over port 8080 for C2.
- [G1052] Contagious Interview: Contagious Interview has used TCP port 1224 for C2.
- [G1042] RedEcho: RedEcho has used non-standard ports such as TCP 8080 for HTTP communication.
- [S0367] Emotet: Emotet has used HTTP over ports such as 20, 22, 443, 7080, and 50000, in addition to using ports commonly associated with HTTP/S.
- [S0491] StrongPity: StrongPity has used HTTPS over port 1402 in C2 communication.
- [S0428] PoetRAT: PoetRAT used TLS to encrypt communications over port 143
- [S0493] GoldenSpy: GoldenSpy has used HTTP over ports 9005 and 9006 for network traffic, 9002 for C2 requests, 33666 as a WebSocket, and 8090 to download files.


### T1572 - Protocol Tunneling
Adversaries may tunnel network communications to and from a victim system within a separate protocol to avoid detection/network filtering and/or enable access to otherwise unreachable systems. Tunneling involves explicitly encapsulating a protocol within another. This behavior may conceal malicious traffic by blending in with existing traffic and/or provide an outer layer of encryption (similar to a VPN). Tunneling could also enable routing of network packets that would otherwise not reach their intended destination, such as SMB, RDP, or other traffic that would be filtered by network appliances or not routed over the Internet. There are various means to encapsulate a protocol within another protocol. For example, adversaries may perform SSH tunneling (also known as SSH port forwarding), which involves forwarding arbitrary data over an encrypted SSH tunnel. Protocol Tunneling may also be abused by adversaries during Dynamic Resolution. Known as DNS over HTTPS (DoH), queries to resolve C2 infrastructure may be encapsulated within encrypted HTTPS packets. Adversaries may also leverage Protocol Tunneling in conjunction with Proxy and/or Protocol or Service Impersonation to further conceal C2 communications and infrastructure.
**Detection**
- [AN1485] **[macOS]** launchd or user-invoked processes (ssh, socat) encapsulating traffic via SSH tunnels, VPN-style tooling, or DNS-over-HTTPS clients. Defender sees outbound TLS traffic with embedded DNS or RDP payloads.
- [AN1484] **[Linux]** sshd, socat, or custom binaries initiating port forwarding or encapsulating traffic (e.g., RDP, SMB) through SSH or HTTP. Defender sees abnormal connect/bind syscalls, encrypted traffic on ports typically used for non-encrypted services, and outlier traffic volume patterns.
- [AN1483] **[Windows]** Processes such as plink.exe, ssh.exe, or netsh.exe establishing outbound network connections where traffic patterns show encapsulated protocols (e.g., RDP over SSH). Defender observations include anomalous process-to-network relationships, large asymmetric data flows, and port usage mismatches.
- [AN1486] **[ESXi]** VMware daemons or user processes encapsulating traffic (e.g., guest VMs tunneling via hostd). Defender sees network services inside ESXi creating flows inconsistent with management plane traffic, such as SSH forwarding or DNS-over-HTTPS from management interfaces.
**Procedure Examples**
- [C0027] C0027: During C0027, Scattered Spider used SSH tunneling in targeted environments.
- [S1189] Neo-reGeorg: Neo-reGeorg can tunnel data in and out of targeted networks.
- [G1016] FIN13: FIN13 has utilized web shells and Java tools for tunneling capabilities to and from compromised assets.
- [C0032] C0032: During the C0032 campaign, TEMP.Veles used encrypted SSH-based PLINK tunnels to transfer tools and enable RDP connections throughout the environment.
- [S1027] Heyoka Backdoor: Heyoka Backdoor can use spoofed DNS requests to create a bidirectional tunnel between a compromised host and its C2 servers.
- [G0059] Magic Hound: Magic Hound has used Plink to tunnel RDP over SSH.
- [G0037] FIN6: FIN6 used the Plink command-line utility to create SSH tunnels to C2 servers.
- [G1045] Salt Typhoon: Salt Typhoon has modified device configurations to create and use Generic Routing Encapsulation (GRE) tunnels.
- [S1187] reGeorg: reGeorg can tunnel TCP sessions including RDP, SSH, and SMB through HTTP.
- [S1141] LunarWeb: LunarWeb can run a custom binary protocol under HTTPS for C2.


### T1573 - Encrypted Channel
Adversaries may employ an encryption algorithm to conceal command and control traffic rather than relying on any inherent protections provided by a communication protocol. Despite the use of a secure algorithm, these implementations may be vulnerable to reverse engineering if secret keys are encoded and/or generated within malware samples/configuration files.
**Detection**
- [AN0763] **[Network Devices]** Unusual TLS tunnels through ports not normally encrypted (e.g., TLS on port 8080, 53). Defender sees NetFlow/IPFIX or packet inspection indicating high-entropy traffic volumes and asymmetric client/server exchange ratios.
- [AN0761] **[macOS]** Applications or launchd jobs initiating encrypted TLS traffic to rare external hosts. Defender observes unified logs showing ssl/TLS API calls by processes not baseline-approved, and payload entropy suggesting encrypted C2 sessions.
- [AN0759] **[Windows]** Processes that normally do not initiate network connections establishing outbound encrypted TLS/SSL sessions, especially with asymmetric traffic volumes (client sending more than receiving) or non-standard certificate chains. Defender observations correlate process creation with unexpected network encryption libraries being loaded.
- [AN0762] **[ESXi]** VMware management daemons or guest processes initiating encrypted connections outside expected vCenter, update servers, or internal comms. Defender identifies hostd or vpxa initiating outbound TLS flows with uncommon destinations.
- [AN0760] **[Linux]** Processes like curl, wget, python, socat, or custom binaries initiating TLS/SSL sessions to non-standard destinations. Defender sees abnormal syscalls for connect(), loading of libssl libraries, and persistent outbound encrypted traffic from daemons not normally communicating externally.
**Procedure Examples**
- [S0662] RCSession: RCSession can use an encrypted beacon to check in with C2.
- [S0498] Cryptoistic: Cryptoistic can engage in encrypted communications with C2.
- [S1198] Gomir: Gomir uses a custom encryption algorithm for content sent to command and control infrastructure.
- [S0631] Chaes: Chaes has used encryption for its C2 channel.
- [G0081] Tropic Trooper: Tropic Trooper has encrypted traffic with the C2 to prevent network detection.
- [S1046] PowGoop: PowGoop can receive encrypted commands from C2.
- [G0059] Magic Hound: Magic Hound has used an encrypted http proxy in C2 communications.
- [S1012] PowerLess: PowerLess can use an encrypted channel for C2 communications.
- [G1002] BITTER: BITTER has encrypted their C2 communications.
- [C0035] KV Botnet Activity: KV Botnet Activity command and control activity includes transmission of an RSA public key in communication from the server, but this is followed by subsequent negotiation stages that represent a form of handshake similar to TLS negotiation.


### T1573.001 - Encrypted Channel: Symmetric Cryptography
Adversaries may employ a known symmetric encryption algorithm to conceal command and control traffic rather than relying on any inherent protections provided by a communication protocol. Symmetric encryption algorithms use the same key for plaintext encryption and ciphertext decryption. Common symmetric encryption algorithms include AES, DES, 3DES, Blowfish, and RC4.
**Detection**
- [AN0403] **[ESXi]** ESXi daemons (hostd, vpxa) unexpectedly using symmetric encryption routines for external connections. Defender identifies logs of service traffic with encrypted payloads inconsistent with VMware management baselines.
- [AN0402] **[macOS]** Launchd jobs or user processes invoking symmetric crypto APIs from the Security framework and generating outbound connections carrying randomized payloads inconsistent with normal TLS patterns.
- [AN0400] **[Windows]** Processes that typically do not perform cryptographic operations loading symmetric encryption libraries (e.g., bcryptprimitives.dll, aes.dll), then initiating outbound connections with high-entropy payloads. Defender correlates process creation, DLL load, and anomalous encrypted traffic patterns.
- [AN0401] **[Linux]** Unexpected processes (e.g., bash, python, custom binaries) dynamically loading libcrypto or performing AES/RC4 encryption operations, then initiating outbound sessions with abnormal byte entropy or asymmetric traffic patterns.
- [AN0404] **[Network Devices]** Flows showing encrypted payloads with high entropy not matching TLS handshake patterns, particularly when occurring on non-standard ports. Defender observes NetFlow/IPFIX byte distribution anomalies or IDS/IPS detecting symmetric encryption patterns without associated key exchange.
**Procedure Examples**
- [S0384] Dridex: Dridex has encrypted traffic with RC4.
- [S0649] SMOKEDHAM: SMOKEDHAM has encrypted its C2 traffic with RC4.
- [S0260] InvisiMole: InvisiMole uses variations of a simple XOR encryption routine for C&C communications.
- [S1227] StarProxy: StarProxy has leveraged two 256-byte XOR keys to encrypt and decrypt network packets using a custom algorithm.
- [S0663] SysUpdate: SysUpdate has used DES to encrypt all C2 communications.
- [S0367] Emotet: Emotet is known to use RSA keys for encrypting C2 traffic.
- [S0113] Prikormka: Prikormka encrypts some C2 traffic with the Blowfish cipher.
- [S0066] 3PARA RAT: 3PARA RAT command and control commands are encrypted within the HTTP C2 channel using the DES algorithm in CBC mode with a key derived from the MD5 hash of the string HYF54&%9&jkMCXuiS. 3PARA RAT will use an 8-byte XOR key derived from the string HYF54&%9&jkMCXuiS if the DES decoding fails
- [S1202] LockBit 3.0: LockBit 3.0 can encrypt C2 communications with AES.
- [S0034] NETEAGLE: NETEAGLE will decrypt resources it downloads with HTTP requests by using RC4 with the key "ScoutEagle."


### T1573.002 - Encrypted Channel: Asymmetric Cryptography
Adversaries may employ a known asymmetric encryption algorithm to conceal command and control traffic rather than relying on any inherent protections provided by a communication protocol. Asymmetric cryptography, also known as public key cryptography, uses a keypair per party: one public that can be freely distributed, and one private. Due to how the keys are generated, the sender encrypts data with the receiver’s public key and the receiver decrypts the data with their private key. This ensures that only the intended recipient can read the encrypted data. Common public key encryption algorithms include RSA and ElGamal. For efficiency, many protocols (including SSL/TLS) use symmetric cryptography once a connection is established, but use asymmetric cryptography to establish or transmit a key. As such, these protocols are classified as Asymmetric Cryptography.
**Detection**
- [AN1499] **[ESXi]** VMware services (hostd, vpxa) unexpectedly negotiating asymmetric crypto sessions to external endpoints outside vCenter or update servers. Defender sees encrypted handshakes in logs inconsistent with baseline ESXi communication patterns.
- [AN1497] **[Linux]** Processes (e.g., bash, python, custom binaries) dynamically linking libcrypto/libssl for RSA key exchange, then creating external connections with abnormal certificate validation or handshake anomalies. Defender observes syscall traces and outbound asymmetric key exchanges from non-SSL-native processes.
- [AN1500] **[Network Devices]** Encrypted sessions detected with asymmetric key exchange anomalies on non-standard ports or with invalid/malformed certs. Defender correlates NetFlow/IPFIX with IDS/IPS detecting RSA exchanges outside expected TLS flows.
- [AN1498] **[macOS]** Applications or launchd services invoking RSA or public-key routines from the Security framework, followed by outbound SSL/TLS sessions with unrecognized certs or anomalous handshakes. Defender observes unified logs of API calls and suspicious network entropy.
- [AN1496] **[Windows]** Processes not typically associated with encryption loading asymmetric crypto libraries (e.g., rsaenh.dll, crypt32.dll) and subsequently initiating outbound TLS/SSL connections with abnormal certificate chains or handshakes. Defender correlates process creation, module load, and unusual encrypted sessions.
**Procedure Examples**
- [S0615] SombRAT: SombRAT can SSL encrypt C2 traffic.
- [S0022] Uroburos: Uroburos has used a combination of a Diffie-Hellman key exchange mixed with a pre-shared key (PSK) to encrypt its top layer of C2 communications.
- [S0687] Cyclops Blink: Cyclops Blink can encrypt C2 messages with AES-256-CBC sent underneath TLS. OpenSSL library functions are also used to encrypt each message using a randomly generated key and IV, which are then encrypted using a hard-coded RSA public key.
- [S1219] REPTILE: REPTILE can use TLS over raw TCP for secure C2.
- [S1123] PITSTOP: PITSTOP has the ability to communicate over TLS.
- [G1018] TA2541: TA2541 has used TLS encrypted C2 communications including for campaigns using AsyncRAT.
- [C0014] Operation Wocao: During Operation Wocao, threat actors' proxy implementation "Agent" upgraded the socket in use to a TLS socket.
- [S0455] Metamorfo: Metamorfo's C2 communication has been encrypted using OpenSSL.
- [S0018] Sykipot: Sykipot uses SSL for encrypting C2 communications.
- [S0534] Bazar: Bazar can use TLS in C2 communications.


### T1659 - Content Injection
Adversaries may gain access and continuously communicate with victims by injecting malicious content into systems through online network traffic. Rather than luring victims to malicious payloads hosted on a compromised website (i.e., Drive-by Target followed by Drive-by Compromise), adversaries may initially access victims through compromised data-transfer channels where they can manipulate traffic and/or inject their own content. These compromised online network channels may also be used to deliver additional payloads (i.e., Ingress Tool Transfer) and other data to already compromised systems. Adversaries may inject content to victim systems in various ways, including: * From the middle, where the adversary is in-between legitimate online client-server communications (**Note:** this is similar but distinct from Adversary-in-the-Middle, which describes AiTM activity solely within an enterprise environment) * From the side, where malicious content is injected and races to the client as a fake response to requests of a legitimate online server Content injection is often the result of compromised upstream communication channels, for example at the level of an internet service provider (ISP) as is the case with "lawful interception."
**Detection**
- [AN0993] **[Linux]** Detect curl/wget commands saving executable/script payloads to /tmp or /var/tmp followed by execution. Monitor packet captures or IDS/IPS alerts for injected responses or mismatched content types.
- [AN0992] **[Windows]** Detect suspicious file creations and process executions triggered by browser activity (e.g., injected payloads written to %AppData% or Temp directories, then executed). Correlate network anomalies with subsequent local process creation or script execution.
- [AN0994] **[macOS]** Monitor unified logs for processes spawned from Safari or other browsers that immediately load scripts or executables. Detect file drops in ~/Library/Caches or ~/Downloads that execute shortly after being written.
**Procedure Examples**
- [S1088] Disco: Disco has achieved initial access and execution through content injection into DNS, HTTP, and SMB replies to targeted hosts that redirect them to download malicious files.
- [G1019] MoustachedBouncer: MoustachedBouncer has injected content into DNS, HTTP, and SMB replies to redirect specifically-targeted victims to a fake Windows Update page to download malware.


### T1665 - Hide Infrastructure
Adversaries may manipulate network traffic in order to hide and evade detection of their C2 infrastructure. This can be accomplished by identifying and filtering traffic from defensive tools, masking malicious domains to obfuscate the true destination from both automated scanning tools and security researchers, and otherwise hiding malicious artifacts to delay discovery and prolong the effectiveness of adversary infrastructure that could otherwise be identified, blocked, or taken down entirely. C2 networks may include the use of Proxy or VPNs to disguise IP addresses, which can allow adversaries to blend in with normal network traffic and bypass conditional access policies or anti-abuse protections. For example, an adversary may use a virtual private cloud to spoof their IP address to closer align with a victim's IP address ranges. This may also bypass security measures relying on geolocation of the source IP address. Adversaries may also attempt to filter network traffic in order to evade defensive tools in numerous ways, including blocking/redirecting common incident responder or security appliance user agents. Filtering traffic based on IP and geo-fencing may also avoid automated sandboxing or researcher activity (i.e., Virtualization/Sandbox Evasion). Hiding C2 infrastructure may also be supported by Resource Development activities such as Acquire Infrastructure and Compromise Infrastructure. For example, using widely trusted hosting services or domains such as prominent URL shortening providers or marketing services for C2 networks may enable adversaries to present benign content that later redirects victims to malicious web pages or infrastructure once specific conditions are met.
**Detection**
- [AN1151] **[Network Devices]** Inspect network telemetry for adversary attempts to blend malicious traffic with legitimate flows using VPNs, proxies, or geolocation spoofing. Defensive teams may observe anomalous tunnels, encrypted sessions to suspicious domains, or geo-mismatched IP activity.
- [AN1152] **[ESXi]** Monitor VM-level DNS and network traffic logs for adversary-controlled domains or selective response behavior (e.g., dropped requests from security scanners).
- [AN1148] **[Windows]** Monitor DNS queries, proxy logs, and user-agent strings for anomalous patterns associated with adversary attempts to hide infrastructure. Defenders may observe DNS resolutions to short-lived domains, abnormal WHOIS registration data, or filtering of known defensive/responder IP addresses.
- [AN1150] **[macOS]** Monitor unified logs for manipulation of proxy configurations, DNS resolution, or filtering rules. Adversaries may redirect responses or use trusted domains that later resolve to malicious C2 infrastructure.
- [AN1149] **[Linux]** Detect adversaries filtering traffic or modifying server responses to evade scanning. Monitor iptables, nftables, or proxy configurations that deny or redirect requests from known scanning agents or defensive tools.
**Procedure Examples**
- [C0055] Quad7 Activity: Quad7 Activity has rotated the compromised SOHO IPs used in password spraying activity to hamper detection and network blocking activities by defenders.
- [G0128] ZIRCONIUM: ZIRCONIUM has utilized an ORB (operational relay box) network – consisting compromised devices such as small office and home office (SOHO) routers, IoT devices, and leased virtual private servers (VPS) – to obfuscate the origin of C2 traffic.
- [C0024] SolarWinds Compromise: During the SolarWinds Compromise, APT29 set the hostnames of their C2 infrastructure to match legitimate hostnames in the victim environment. They also used IP addresses originating from the same country as the victim for their VPN infrastructure.
- [S1206] JumbledPath: JumbledPath can use a chain of jump hosts to communicate with compromised devices to obscure actor infrastructure.
- [S1111] DarkGate: DarkGate command and control includes hard-coded domains in the malware masquerading as legitimate services such as Akamai CDN or Amazon Web Services.
- [G0016] APT29: APT29 uses compromised residential endpoints, typically within the same ISP IP address range, as proxies to hide the true source of C2 traffic.
- [S1164] UPSTYLE: UPSTYLE attempts to retrieve a non-existent webpage from the command and control server resulting in hidden commands sent via resulting error messages.

