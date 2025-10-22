### T1011.001 - Exfiltration Over Other Network Medium: Exfiltration Over Bluetooth

Description:

Adversaries may attempt to exfiltrate data over Bluetooth rather than the command and control channel. If the command and control network is a wired Internet connection, an adversary may opt to exfiltrate data using a Bluetooth communication channel. Adversaries may choose to do this if they have sufficient access and proximity. Bluetooth connections might not be secured or defended as well as the primary Internet-connected channel because it is not routed through the same enterprise network.

Procedures:

- [S0143] Flame: Flame has a module named BeetleJuice that contains Bluetooth functionality that may be used in different ways, including transmitting encoded information from the infected system over the Bluetooth protocol, acting as a Bluetooth beacon, and identifying other Bluetooth devices in the vicinity.


### T1020.001 - Automated Exfiltration: Traffic Duplication

Description:

Adversaries may leverage traffic mirroring in order to automate data exfiltration over compromised infrastructure. Traffic mirroring is a native feature for some devices, often used for network analysis. For example, devices may be configured to forward network traffic to one or more destinations for analysis by a network analyzer or other monitoring device. Adversaries may abuse traffic mirroring to mirror or redirect network traffic through other infrastructure they control. Malicious modifications to network devices to enable traffic redirection may be possible through ROMMONkit or Patch System Image. Many cloud-based environments also support traffic mirroring. For example, AWS Traffic Mirroring, GCP Packet Mirroring, and Azure vTap allow users to define specified instances to collect traffic from and specified targets to send collected traffic to. Adversaries may use traffic duplication in conjunction with Network Sniffing, Input Capture, or Adversary-in-the-Middle depending on the goals and objectives of the adversary.


### T1029 - Scheduled Transfer

Description:

Adversaries may schedule data exfiltration to be performed only at certain times of day or at certain intervals. This could be done to blend traffic patterns with normal activity or availability. When scheduled exfiltration is used, other exfiltration techniques likely apply as well to transfer the information out of the network, such as Exfiltration Over C2 Channel or Exfiltration Over Alternative Protocol.

Procedures:

- [S0283] jRAT: jRAT can be configured to reconnect at certain intervals.
- [S0696] Flagpro: Flagpro has the ability to wait for a specified time interval between communicating with and executing commands from C2.
- [S1019] Shark: Shark can pause C2 communications for a specified time.


### T1030 - Data Transfer Size Limits

Description:

An adversary may exfiltrate data in fixed size chunks instead of whole files or limit packet sizes below certain thresholds. This approach may be used to avoid triggering network data transfer threshold alerts.

Procedures:

- [G1040] Play: Play has split victims' files into chunks for exfiltration.
- [G1014] LuminousMoth: LuminousMoth has split archived files into multiple parts to bypass a 5MB limit.
- [G0027] Threat Group-3390: Threat Group-3390 actors have split RAR files for exfiltration into parts.


### T1041 - Exfiltration Over C2 Channel

Description:

Adversaries may steal data by exfiltrating it over an existing command and control channel. Stolen data is encoded into the normal communications channel using the same protocol as command and control communications.

Procedures:

- [S1172] OilBooster: OilBooster can use an actor-controlled OneDrive account for C2 communication and exfiltration.
- [S0459] MechaFlounder: MechaFlounder has the ability to send the compromised user's account name and hostname within a URL to C2.
- [S0428] PoetRAT: PoetRAT has exfiltrated data over the C2 channel.


### T1048.001 - Exfiltration Over Alternative Protocol: Exfiltration Over Symmetric Encrypted Non-C2 Protocol

Description:

Adversaries may steal data by exfiltrating it over a symmetrically encrypted network protocol other than that of the existing command and control channel. The data may also be sent to an alternate network location from the main command and control server. Symmetric encryption algorithms are those that use shared or the same keys/secrets on each end of the channel. This requires an exchange or pre-arranged agreement/possession of the value used to encrypt and decrypt data. Network protocols that use asymmetric encryption often utilize symmetric encryption once keys are exchanged, but adversaries may opt to manually share keys and implement symmetric cryptographic algorithms (ex: RC4, AES) vice using mechanisms that are baked into a protocol. This may result in multiple layers of encryption (in protocols that are natively encrypted such as HTTPS) or encryption in protocols that not typically encrypted (such as HTTP or FTP).

### T1048.002 - Exfiltration Over Alternative Protocol: Exfiltration Over Asymmetric Encrypted Non-C2 Protocol

Description:

Adversaries may steal data by exfiltrating it over an asymmetrically encrypted network protocol other than that of the existing command and control channel. The data may also be sent to an alternate network location from the main command and control server. Asymmetric encryption algorithms are those that use different keys on each end of the channel. Also known as public-key cryptography, this requires pairs of cryptographic keys that can encrypt/decrypt data from the corresponding key. Each end of the communication channels requires a private key (only in the procession of that entity) and the public key of the other entity. The public keys of each entity are exchanged before encrypted communications begin. Network protocols that use asymmetric encryption (such as HTTPS/TLS/SSL) often utilize symmetric encryption once keys are exchanged. Adversaries may opt to use these encrypted mechanisms that are baked into a protocol.

Procedures:

- [G0007] APT28: APT28 has exfiltrated archives of collected data previously staged on a target's OWA server via HTTPS.
- [S0483] IcedID: IcedID has exfiltrated collected data via HTTPS.
- [G1012] CURIUM: CURIUM has used SMTPS to exfiltrate collected data from victims.

### T1048.003 - Exfiltration Over Alternative Protocol: Exfiltration Over Unencrypted Non-C2 Protocol

Description:

Adversaries may steal data by exfiltrating it over an un-encrypted network protocol other than that of the existing command and control channel. The data may also be sent to an alternate network location from the main command and control server. Adversaries may opt to obfuscate this data, without the use of encryption, within network protocols that are natively unencrypted (such as HTTP, FTP, or DNS). This may include custom or publicly available encoding/compression algorithms (such as base64) as well as embedding data within protocol headers and fields.

Procedures:

- [G0032] Lazarus Group: Lazarus Group malware SierraBravo-Two generates an email message via SMTP containing information about newly infected victims.
- [G0061] FIN8: FIN8 has used FTP to exfiltrate collected data.
- [S0125] Remsec: Remsec can exfiltrate data via a DNS tunnel or email, separately from its C2 channel.


### T1052.001 - Exfiltration Over Physical Medium: Exfiltration over USB

Description:

Adversaries may attempt to exfiltrate data over a USB connected physical device. In certain circumstances, such as an air-gapped network compromise, exfiltration could occur via a USB device introduced by a user. The USB device could be used as the final exfiltration point or to hop between otherwise disconnected systems.

Procedures:

- [S0035] SPACESHIP: SPACESHIP copies staged data to removable drives when they are inserted into the system.
- [S0125] Remsec: Remsec contains a module to move data from airgapped networks to Internet-connected systems by using a removable USB device.
- [S0136] USBStealer: USBStealer exfiltrates collected files via removable media from air-gapped victims.


### T1537 - Transfer Data to Cloud Account

Description:

Adversaries may exfiltrate data by transferring the data, including through sharing/syncing and creating backups of cloud environments, to another cloud account they control on the same service. A defender who is monitoring for large transfers to outside the cloud environment through normal file transfers or over command and control channels may not be watching for data transfers to another account within the same cloud provider. Such transfers may utilize existing cloud provider APIs and the internal address space of the cloud provider to blend into normal traffic or avoid data transfers over external network interfaces. Adversaries may also use cloud-native mechanisms to share victim data with adversary-controlled cloud accounts, such as creating anonymous file sharing links or, in Azure, a shared access signature (SAS) URI. Incidents have been observed where adversaries have created backups of cloud instances and transferred them to separate accounts.

Procedures:

- [G1032] INC Ransom: INC Ransom has used Megasync to exfiltrate data to the cloud.
- [G1039] RedCurl: RedCurl has used cloud storage to exfiltrate data, in particular the megatools utilities were used to exfiltrate data to Mega, a file storage service.


### T1567.001 - Exfiltration Over Web Service: Exfiltration to Code Repository

Description:

Adversaries may exfiltrate data to a code repository rather than over their primary command and control channel. Code repositories are often accessible via an API (ex: Access to these APIs are often over HTTPS, which gives the adversary an additional level of protection. Exfiltration to a code repository can also provide a significant amount of cover to the adversary if it is a popular service already used by hosts within the network.

Procedures:

- [S0363] Empire: Empire can use GitHub for data exfiltration.

### T1567.002 - Exfiltration Over Web Service: Exfiltration to Cloud Storage

Description:

Adversaries may exfiltrate data to a cloud storage service rather than over their primary command and control channel. Cloud storage services allow for the storage, edit, and retrieval of data from a remote cloud storage server over the Internet. Examples of cloud storage services include Dropbox and Google Docs. Exfiltration to these cloud storage services can provide a significant amount of cover to the adversary if hosts within the network are already communicating with the service.

Procedures:

- [G0065] Leviathan: Leviathan has used an uploader known as LUNCHMONEY that can exfiltrate files to Dropbox.
- [G1024] Akira: Akira will exfiltrate victim data using applications such as Rclone.
- [G1014] LuminousMoth: LuminousMoth has exfiltrated data to Google Drive.

### T1567.003 - Exfiltration Over Web Service: Exfiltration to Text Storage Sites

Description:

Adversaries may exfiltrate data to text storage sites instead of their primary command and control channel. Text storage sites, such as pastebin[.]com, are commonly used by developers to share code and other information. Text storage sites are often used to host malicious code for C2 communication (e.g., Stage Capabilities), but adversaries may also use these sites to exfiltrate collected data. Furthermore, paid features and encryption options may allow adversaries to conceal and store data more securely. **Note:** This is distinct from Exfiltration to Code Repository, which highlight access to code repositories via APIs.

### T1567.004 - Exfiltration Over Web Service: Exfiltration Over Webhook

Description:

Adversaries may exfiltrate data to a webhook endpoint rather than over their primary command and control channel. Webhooks are simple mechanisms for allowing a server to push data over HTTP/S to a client without the need for the client to continuously poll the server. Many public and commercial services, such as Discord, Slack, and `webhook.site`, support the creation of webhook endpoints that can be used by other services, such as Github, Jira, or Trello. When changes happen in the linked services (such as pushing a repository update or modifying a ticket), these services will automatically post the data to the webhook endpoint for use by the consuming application. Adversaries may link an adversary-owned environment to a victim-owned SaaS service to achieve repeated Automated Exfiltration of emails, chat messages, and other data. Alternatively, instead of linking the webhook endpoint to a service, an adversary can manually post staged data directly to the URL in order to exfiltrate it. Access to webhook endpoints is often over HTTPS, which gives the adversary an additional level of protection. Exfiltration leveraging webhooks can also blend in with normal network traffic if the webhook endpoint points to a commonly used SaaS application or collaboration service.

