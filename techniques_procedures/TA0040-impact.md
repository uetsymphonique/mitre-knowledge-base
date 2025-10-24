### T1485.001 - Data Destruction: Lifecycle-Triggered Deletion

Procedures:

- Adversaries may modify the lifecycle policies of a cloud storage bucket to destroy all objects stored within. Cloud storage buckets often allow users to set lifecycle policies to automate the migration, archival, or deletion of objects after a set period of time. If a threat actor has sufficient permissions to modify these policies, they may be able to delete all objects at once. For example, in AWS environments, an adversary with the `PutLifecycleConfiguration` permission may use the `PutBucketLifecycle` API call to apply a lifecycle policy to an S3 bucket that deletes all objects in the bucket after one day. In addition to destroying data for purposes of extortion and Financial Theft, adversaries may also perform this action on buckets storing cloud logs for Indicator Removal.


### T1486 - Data Encrypted for Impact

Procedures:

- [S0449] Maze: Maze has disrupted systems by encrypting files on targeted machines, claiming to decrypt files if a ransom payment is made. Maze has used the ChaCha algorithm, based on Salsa20, and an RSA algorithm to encrypt files.
- [S0606] Bad Rabbit: Bad Rabbit has encrypted files and disks using AES-128-CBC and RSA-2048.
- [S0595] ThiefQuest: ThiefQuest encrypts a set of file extensions on a host, deletes the original files, and provides a ransom note with no contact information.
- [G0082] APT38: APT38 has used Hermes ransomware to encrypt files with AES256.
- [S0481] Ragnar Locker: Ragnar Locker encrypts files on the local machine and mapped drives prior to displaying a note demanding a ransom.
- [G1032] INC Ransom: INC Ransom has used INC Ransomware to encrypt victim's data.
- [S1180] BlackByte Ransomware: BlackByte Ransomware is ransomware using a shared key across victims for encryption.
- [C0038] HomeLand Justice: During HomeLand Justice, threat actors used ROADSWEEP ransomware to encrypt files on targeted systems.
- [S1073] Royal: Royal uses a multi-threaded encryption process that can partially encrypt targeted files with the OpenSSL library and the AES256 algorithm.
- [S0389] JCry: JCry has encrypted files and demanded Bitcoin to decrypt those files.
- [S0638] Babuk: Babuk can use ChaCha8 and ECDH to encrypt data.
- [S1137] Moneybird: Moneybird targets a common set of file types such as documents, certificates, and database files for encryption while avoiding executable, dynamic linked libraries, and similar items.
- [S0496] REvil: REvil can encrypt files on victim systems and demands a ransom to decrypt the files.
- [S0659] Diavol: Diavol has encrypted files using an RSA key though the `CryptEncrypt` API and has appended filenames with ".lock64".
- [S0625] Cuba: Cuba has the ability to encrypt system data and add the ".cuba" extension to encrypted files.


### T1489 - Service Stop

Procedures:

- [S0611] Clop: Clop can kill several processes and services related to backups and security solutions.
- [S0582] LookBack: LookBack can kill processes and delete services.
- [S0688] Meteor: Meteor can disconnect all network adapters on a compromised host using `powershell -Command "Get-WmiObject -class Win32_NetworkAdapter | ForEach { If ($.NetEnabled) { $.Disable() } }" > NUL`.
- [S1211] Hannotog: Hannotog can stop Windows services.
- [S0366] WannaCry: WannaCry attempts to kill processes associated with Exchange, Microsoft SQL Server, and MySQL to make it possible to encrypt their data stores.
- [S1073] Royal: Royal can use `RmShutDown` to kill applications and services using the resources that are targeted for encryption.
- [S0659] Diavol: Diavol will terminate services using the Service Control Manager (SCM) API.
- [S0640] Avaddon: Avaddon looks for and attempts to stop database processes.
- [S0365] Olympic Destroyer: Olympic Destroyer uses the API call ChangeServiceConfigW to disable all services on the affected system.
- [S1096] Cheerscrypt: Cheerscrypt has the ability to terminate VM processes on compromised hosts through execution of `esxcli vm process kill`.
- [S1058] Prestige: Prestige has attempted to stop the MSSQL Windows service to ensure successful encryption using `C:\Windows\System32\net.exe stop MSSQLSERVER`.
- [S0556] Pay2Key: Pay2Key can stop the MS SQL service at the end of the encryption process to release files locked by the service.
- [S1068] BlackCat: BlackCat has the ability to stop VM services on compromised networks.
- [S0400] RobbinHood: RobbinHood stops 181 Windows services on the system before beginning the encryption process.
- [G0032] Lazarus Group: Lazarus Group has stopped the MSExchangeIS service to render Exchange contents inaccessible to users.


### T1490 - Inhibit System Recovery

Procedures:

- [S1070] Black Basta: Black Basta can delete shadow copies using vssadmin.exe.
- [S0481] Ragnar Locker: Ragnar Locker can delete volume shadow copies using vssadmin delete shadows /all /quiet.
- [S0260] InvisiMole: InvisiMole can can remove all system restore points.
- [S1162] Playcrypt: Playcrypt can use AlphaVSS to delete shadow copies.
- [S0612] WastedLocker: WastedLocker can delete shadow volumes.
- [S0132] H1N1: H1N1 disable recovery options and deletes shadow copies from the victim.
- [S0400] RobbinHood: RobbinHood deletes shadow copies to ensure that all the data cannot be restored easily.
- [S0446] Ryuk: Ryuk has used vssadmin Delete Shadows /all /quiet to to delete volume shadow copies and vssadmin resize shadowstorage to force deletion of shadow copies created by third-party applications.
- [S0673] DarkWatchman: DarkWatchman can delete shadow volumes using vssadmin.exe.
- [S0605] EKANS: EKANS removes backups of Volume Shadow Copies to disable any restoration capabilities.
- [S1139] INC Ransomware: INC Ransomware can delete volume shadow copy backups from victim machines.
- [S0576] MegaCortex: MegaCortex has deleted volume shadow copies using vssadmin.exe.
- [S0616] DEATHRANSOM: DEATHRANSOM can delete volume shadow copies on compromised hosts.
- [S1073] Royal: Royal can delete shadow copy backups with vssadmin.exe using the command `delete shadows /all /quiet`.
- [S1181] BlackByte 2.0 Ransomware: BlackByte 2.0 Ransomware modifies volume shadow copies during execution in a way that destroys them on the victim machine.


### T1491.001 - Defacement: Internal Defacement

Procedures:

- [G0047] Gamaredon Group: Gamaredon Group has left taunting images and messages on the victims' desktops as proof of system access.
- [S1178] ShrinkLocker: ShrinkLocker renames disk labels on victim hosts to the threat actor's email address to enable the victim to contact the threat actor for ransom negotiation.
- [S1070] Black Basta: Black Basta has set the desktop wallpaper on victims' machines to display a ransom note.
- [S0659] Diavol: After encryption, Diavol will capture the desktop background window, set the background color to black, and change the desktop wallpaper to a newly created bitmap image with the text “All your files are encrypted! For more information see “README-FOR-DECRYPT.txt".
- [G1043] BlackByte: BlackByte left ransom notes in all directories where encryption takes place.
- [S1150] ROADSWEEP: ROADSWEEP has dropped ransom notes in targeted folders prior to encrypting the files.
- [S0688] Meteor: Meteor can change both the desktop wallpaper and the lock screen image to a custom image.
- [G0032] Lazarus Group: Lazarus Group replaced the background wallpaper of systems with a threatening image after rendering the system unbootable with a Disk Structure Wipe.
- [S1212] RansomHub: RansomHub has placed a ransom note on comrpomised systems to warn victims and provide directions for how to retrieve data.
- [S1068] BlackCat: BlackCat can change the desktop wallpaper on compromised hosts.
- [S1139] INC Ransomware: INC Ransomware has the ability to change the background wallpaper image to display the ransom note.

### T1491.002 - Defacement: External Defacement

Procedures:

- [G1003] Ember Bear: Ember Bear is linked to the defacement of several Ukrainian organization websites.
- [G0034] Sandworm Team: Sandworm Team defaced approximately 15,000 websites belonging to Georgian government, non-government, and private sector organizations in 2019.


### T1495 - Firmware Corruption

Procedures:

- [S0606] Bad Rabbit: Bad Rabbit has used an executable that installs a modified bootloader to prevent normal boot-up.
- [S0266] TrickBot: TrickBot module "Trickboot" can write or erase the UEFI/BIOS firmware of a compromised device.


### T1496.001 - Resource Hijacking: Compute Hijacking

Procedures:

- [S0532] Lucifer: Lucifer can use system resources to mine cryptocurrency, dropping XMRig to mine Monero.
- [S0468] Skidmap: Skidmap is a kernel-mode rootkit used for cryptocurrency mining.
- [S0492] CookieMiner: CookieMiner has loaded coinmining software onto systems to mine for Koto cryptocurrency.
- [G0106] Rocke: Rocke has distributed cryptomining malware.
- [S0486] Bonadan: Bonadan can download an additional module which has a cryptocurrency mining extension.
- [S0451] LoudMiner: LoudMiner harvested system resources to mine cryptocurrency, using XMRig to mine Monero.
- [S1111] DarkGate: DarkGate can deploy follow-on cryptocurrency mining payloads.
- [G0108] Blue Mockingbird: Blue Mockingbird has used XMRIG to mine cryptocurrency on victim systems.
- [S0434] Imminent Monitor: Imminent Monitor has the capability to run a cryptocurrency miner on the victim machine.
- [G0139] TeamTNT: TeamTNT has deployed XMRig Docker images to mine cryptocurrency. TeamTNT has also infected Docker containers and Kubernetes clusters with XMRig, and used RainbowMiner and lolMiner for mining cryptocurrency.
- [G0096] APT41: APT41 deployed a Monero cryptocurrency mining tool in a victim’s environment.
- [S0601] Hildegard: Hildegard has used xmrig to mine cryptocurrency.
- [C0045] ShadowRay: During ShadowRay, threat actors leveraged graphics processing units (GPU) on compromised nodes for cryptocurrency mining.
- [S0599] Kinsing: Kinsing has created and run a Bitcoin cryptocurrency miner.

### T1496.002 - Resource Hijacking: Bandwidth Hijacking

Procedures:

- Adversaries may leverage the network bandwidth resources of co-opted systems to complete resource-intensive tasks, which may impact system and/or hosted service availability. Adversaries may also use malware that leverages a system's network bandwidth as part of a botnet in order to facilitate Network Denial of Service campaigns and/or to seed malicious torrents. Alternatively, they may engage in proxyjacking by selling use of the victims' network bandwidth and IP address to proxyware services. Finally, they may engage in internet-wide scanning in order to identify additional targets for compromise. In addition to incurring potential financial costs or availability disruptions, this technique may cause reputational damage if a victim’s bandwidth is used for illegal activities.

### T1496.003 - Resource Hijacking: SMS Pumping

Procedures:

- Adversaries may leverage messaging services for SMS pumping, which may impact system and/or hosted service availability. SMS pumping is a type of telecommunications fraud whereby a threat actor first obtains a set of phone numbers from a telecommunications provider, then leverages a victim’s messaging infrastructure to send large amounts of SMS messages to numbers in that set. By generating SMS traffic to their phone number set, a threat actor may earn payments from the telecommunications provider. Threat actors often use publicly available web forms, such as one-time password (OTP) or account verification fields, in order to generate SMS traffic. These fields may leverage services such as Twilio, AWS SNS, and Amazon Cognito in the background. In response to the large quantity of requests, SMS costs may increase and communication channels may become overwhelmed.

### T1496.004 - Resource Hijacking: Cloud Service Hijacking

Procedures:

- Adversaries may leverage compromised software-as-a-service (SaaS) applications to complete resource-intensive tasks, which may impact hosted service availability. For example, adversaries may leverage email and messaging services, such as AWS Simple Email Service (SES), AWS Simple Notification Service (SNS), SendGrid, and Twilio, in order to send large quantities of spam / Phishing emails and SMS messages. Alternatively, they may engage in LLMJacking by leveraging reverse proxies to hijack the power of cloud-hosted AI models. In some cases, adversaries may leverage services that the victim is already using. In others, particularly when the service is part of a larger cloud platform, they may first enable the service. Leveraging SaaS applications may cause the victim to incur significant financial costs, use up service quotas, and otherwise impact availability.


### T1498.001 - Network Denial of Service: Direct Network Flood

Procedures:

- Adversaries may attempt to cause a denial of service (DoS) by directly sending a high-volume of network traffic to a target. This DoS attack may also reduce the availability and functionality of the targeted system(s) and network. Direct Network Floods are when one or more systems are used to send a high-volume of network packets towards the targeted service's network. Almost any network protocol may be used for flooding. Stateless protocols such as UDP or ICMP are commonly used but stateful protocols such as TCP can be used as well. Botnets are commonly used to conduct network flooding attacks against networks and services. Large botnets can generate a significant amount of traffic from systems spread across the global Internet. Adversaries may have the resources to build out and control their own botnet infrastructure or may rent time on an existing botnet to conduct an attack. In some of the worst cases for distributed DoS (DDoS), so many systems are used to generate the flood that each one only needs to send out a small amount of traffic to produce enough volume to saturate the target network. In such circumstances, distinguishing DDoS traffic from legitimate clients becomes exceedingly difficult. Botnets have been used in some of the most high-profile DDoS flooding attacks, such as the 2012 series of incidents that targeted major US banks.

### T1498.002 - Network Denial of Service: Reflection Amplification

Procedures:

- Adversaries may attempt to cause a denial of service (DoS) by reflecting a high-volume of network traffic to a target. This type of Network DoS takes advantage of a third-party server intermediary that hosts and will respond to a given spoofed source IP address. This third-party server is commonly termed a reflector. An adversary accomplishes a reflection attack by sending packets to reflectors with the spoofed address of the victim. Similar to Direct Network Floods, more than one system may be used to conduct the attack, or a botnet may be used. Likewise, one or more reflectors may be used to focus traffic on the target. This Network DoS attack may also reduce the availability and functionality of the targeted system(s) and network. Reflection attacks often take advantage of protocols with larger responses than requests in order to amplify their traffic, commonly known as a Reflection Amplification attack. Adversaries may be able to generate an increase in volume of attack traffic that is several orders of magnitude greater than the requests sent to the amplifiers. The extent of this increase will depending upon many variables, such as the protocol in question, the technique used, and the amplifying servers that actually produce the amplification in attack volume. Two prominent protocols that have enabled Reflection Amplification Floods are DNS and NTP, though the use of several others in the wild have been documented. In particular, the memcache protocol showed itself to be a powerful protocol, with amplification sizes up to 51,200 times the requesting packet.


### T1499.001 - Endpoint Denial of Service: OS Exhaustion Flood

Procedures:

- Adversaries may launch a denial of service (DoS) attack targeting an endpoint's operating system (OS). A system's OS is responsible for managing the finite resources as well as preventing the entire system from being overwhelmed by excessive demands on its capacity. These attacks do not need to exhaust the actual resources on a system; the attacks may simply exhaust the limits and available resources that an OS self-imposes. Different ways to achieve this exist, including TCP state-exhaustion attacks such as SYN floods and ACK floods. With SYN floods, excessive amounts of SYN packets are sent, but the 3-way TCP handshake is never completed. Because each OS has a maximum number of concurrent TCP connections that it will allow, this can quickly exhaust the ability of the system to receive new requests for TCP connections, thus preventing access to any TCP service provided by the server. ACK floods leverage the stateful nature of the TCP protocol. A flood of ACK packets are sent to the target. This forces the OS to search its state table for a related TCP connection that has already been established. Because the ACK packets are for connections that do not exist, the OS will have to search the entire state table to confirm that no match exists. When it is necessary to do this for a large flood of packets, the computational requirements can cause the server to become sluggish and/or unresponsive, due to the work it must do to eliminate the rogue ACK packets. This greatly reduces the resources available for providing the targeted service.

### T1499.002 - Endpoint Denial of Service: Service Exhaustion Flood

Procedures:

- Adversaries may target the different network services provided by systems to conduct a denial of service (DoS). Adversaries often target the availability of DNS and web services, however others have been targeted as well. Web server software can be attacked through a variety of means, some of which apply generally while others are specific to the software being used to provide the service. One example of this type of attack is known as a simple HTTP flood, where an adversary sends a large number of HTTP requests to a web server to overwhelm it and/or an application that runs on top of it. This flood relies on raw volume to accomplish the objective, exhausting any of the various resources required by the victim software to provide the service. Another variation, known as a SSL renegotiation attack, takes advantage of a protocol feature in SSL/TLS. The SSL/TLS protocol suite includes mechanisms for the client and server to agree on an encryption algorithm to use for subsequent secure connections. If SSL renegotiation is enabled, a request can be made for renegotiation of the crypto algorithm. In a renegotiation attack, the adversary establishes a SSL/TLS connection and then proceeds to make a series of renegotiation requests. Because the cryptographic renegotiation has a meaningful cost in computation cycles, this can cause an impact to the availability of the service when done in volume.

### T1499.003 - Endpoint Denial of Service: Application Exhaustion Flood

Procedures:

- Adversaries may target resource intensive features of applications to cause a denial of service (DoS), denying availability to those applications. For example, specific features in web applications may be highly resource intensive. Repeated requests to those features may be able to exhaust system resources and deny access to the application or the server itself.

### T1499.004 - Endpoint Denial of Service: Application or System Exploitation

Procedures:

- [S0604] Industroyer: Industroyer uses a custom DoS tool that leverages CVE-2015-5374 and targets hardcoded IP addresses of Siemens SIPROTEC devices.


### T1529 - System Shutdown/Reboot

Procedures:

- [S1125] AcidRain: AcidRain reboots the target system once the various wiping processes are complete.
- [S1033] DCSrv: DCSrv has a function to sleep for two hours before rebooting the system.
- [S1136] BFG Agonizer: BFG Agonizer uses elevated privileges to call NtRaiseHardError to induce a "blue screen of death" on infected systems, causing a system crash. Once shut down, the system is no longer bootable.
- [S1135] MultiLayer Wiper: MultiLayer Wiper reboots the infected system following wiping and related tasks to prevent system recovery.
- [S1167] AcidPour: AcidPour includes functionality to reboot the victim system following wiping actions, similar to AcidRain.
- [S0372] LockerGoga: LockerGoga has been observed shutting down infected systems.
- [S0365] Olympic Destroyer: Olympic Destroyer will shut down the compromised system after it is done modifying system configuration settings.
- [G0082] APT38: APT38 has used a custom MBR wiper named BOOTWRECK, which will initiate a system reboot after wiping the victim's MBR.
- [S0449] Maze: Maze has issued a shutdown command on a victim machine that, upon reboot, will run the ransomware within a VM.
- [G0067] APT37: APT37 has used malware that will issue the command shutdown /r /t 1 to reboot a system after wiping its MBR.
- [S0582] LookBack: LookBack can shutdown and reboot the victim machine.
- [S1133] Apostle: Apostle reboots the victim machine following wiping and related activity.
- [S0689] WhisperGate: WhisperGate can shutdown a compromised host through execution of `ExitWindowsEx` with the `EXW_SHUTDOWN` flag.
- [S0607] KillDisk: KillDisk attempts to reboot the machine by terminating specific processes.
- [S1207] XLoader: XLoader can initiate a system reboot or shutdown.


### T1531 - Account Access Removal

Procedures:

- [G1024] Akira: Akira deletes administrator accounts in victim networks prior to encryption.
- [S0576] MegaCortex: MegaCortex has changed user account passwords and logged users off the system.
- [S0372] LockerGoga: LockerGoga has been observed changing account passwords and logging off current users.
- [S0688] Meteor: Meteor has the ability to change the password of local users on compromised hosts and can log off users.
- [G1004] LAPSUS$: LAPSUS$ has removed a targeted organization's global admin accounts to lock the organization out of all access.
- [S1134] DEADWOOD: DEADWOOD changes the password for local and domain users via net.exe to a random 32 character string to prevent these accounts from logging on. Additionally, DEADWOOD will terminate the winlogon.exe process to prevent attempts to log on to the infected system.


### T1561.001 - Disk Wipe: Disk Content Wipe

Procedures:

- [S1205] cipher.exe: cipher.exe can be used to overwrite deleted data in specified folders.
- [S1134] DEADWOOD: DEADWOOD deletes files following overwriting them with random data.
- [S1125] AcidRain: AcidRain iterates over device file identifiers on the target, opens the device file, and either overwrites the file or calls various IOCTLS commands to erase it.
- [S0689] WhisperGate: WhisperGate can overwrite sectors of a victim host's hard drive at periodic offsets.
- [G0032] Lazarus Group: Lazarus Group has used malware like WhiskeyAlfa to overwrite the first 64MB of every drive with a mix of static and random buffers. A similar process is then used to wipe content in logical drives and, finally, attempt to wipe every byte of every sector on every drive. WhiskeyBravo can be used to overwrite the first 4.9MB of physical drives. WhiskeyDelta can overwrite the first 132MB or 1.5MB of each drive with random data from heap memory.
- [S0364] RawDisk: RawDisk has been used to directly access the hard disk to help overwrite arbitrarily sized portions of disk content.
- [S0576] MegaCortex: MegaCortex can wipe deleted data from all drives using cipher.exe.
- [G0047] Gamaredon Group: Gamaredon Group has used tools to delete files and folders from victims' desktops and profiles.
- [C0051] APT28 Nearest Neighbor Campaign: During APT28 Nearest Neighbor Campaign, APT28 used the native Microsoft utility cipher.exe to securely wipe files and folders – overwriting the deleted data using cmd.exe /c cipher /W:C.
- [S1167] AcidPour: AcidPour includes functionality to overwrite victim devices with the content of a buffer to wipe disk content.
- [S1133] Apostle: Apostle searches for files on available drives based on a list of extensions hard-coded into the sample for follow-on wipe activity.
- [S1010] VPNFilter: VPNFilter has the capability to wipe a portion of an infected device's firmware.
- [S0380] StoneDrill: StoneDrill can wipe the accessible physical or logical drives of the infected machine.
- [S0697] HermeticWiper: HermeticWiper has the ability to corrupt disk partitions and obtain raw disk access to destroy data.
- [S1068] BlackCat: BlackCat has the ability to wipe VM snapshots on compromised networks.

### T1561.002 - Disk Wipe: Disk Structure Wipe

Procedures:

- [S0140] Shamoon: Shamoon has been seen overwriting features of disk structure such as the MBR.
- [C0038] HomeLand Justice: During HomeLand Justice, threat actors used a version of ZeroCleare to wipe disk drives on targeted hosts.
- [S0697] HermeticWiper: HermeticWiper has the ability to corrupt disk partitions, damage the Master Boot Record (MBR), and overwrite the Master File Table (MFT) of all available physical drives.
- [S0364] RawDisk: RawDisk was used in Shamoon to help overwrite components of disk structure like the MBR and disk partitions.
- [S1136] BFG Agonizer: BFG Agonizer retrieves a device handle to \\\\.\\PhysicalDrive0 to wipe the boot sector of a given disk.
- [S0689] WhisperGate: WhisperGate can overwrite the Master Book Record (MBR) on victim systems with a malicious 16-bit bootloader.
- [G0082] APT38: APT38 has used a custom MBR wiper named BOOTWRECK to render systems inoperable.
- [G0034] Sandworm Team: Sandworm Team has used the BlackEnergy KillDisk component to corrupt the infected system's master boot record.
- [G0032] Lazarus Group: Lazarus Group malware SHARPKNOT overwrites and deletes the Master Boot Record (MBR) on the victim's machine and has possessed MBR wiper malware since at least 2009.
- [S0607] KillDisk: KillDisk overwrites the first sector of the Master Boot Record with “0x00”.
- [S0380] StoneDrill: StoneDrill can wipe the master boot record of an infected computer.
- [G1003] Ember Bear: Ember Bear conducted destructive operations against victims, including disk structure wiping, via the WhisperGate malware in Ukraine.
- [S1135] MultiLayer Wiper: MultiLayer Wiper opens a handle to \\\\\\\\.\\\\PhysicalDrive0 and wipes the first 512 bytes of data from this location, removing the boot sector.
- [S1134] DEADWOOD: DEADWOOD opens and writes zeroes to the first 512 bytes of each drive, deleting the MBR. DEADWOOD then sends the control code IOCTL_DISK_DELETE_DRIVE_LAYOUT to ensure the MBR is removed from the drive.
- [S1151] ZeroCleare: ZeroCleare can corrupt the file system and wipe the system drive on targeted hosts.


### T1565.001 - Data Manipulation: Stored Data Manipulation

Procedures:

- [S0562] SUNSPOT: SUNSPOT created a copy of the SolarWinds Orion software source file with a .bk extension to backup the original content, wrote SUNBURST using the same filename but with a .tmp extension, and then moved SUNBURST using MoveFileEx to the original filename with a .cs extension so it could be compiled within Orion software.
- [S1135] MultiLayer Wiper: MultiLayer Wiper changes the original path information of deleted files to make recovery efforts more difficult.
- [G0082] APT38: APT38 has used DYEPACK to create, delete, and alter records in databases used for SWIFT transactions.

### T1565.002 - Data Manipulation: Transmitted Data Manipulation

Procedures:

- [S0530] Melcoz: Melcoz can monitor the clipboard for cryptocurrency addresses and change the intended address to one controlled by the adversary.
- [G0082] APT38: APT38 has used DYEPACK to manipulate SWIFT messages en route to a printer.
- [S0395] LightNeuron: LightNeuron is capable of modifying email content, headers, and attachments during transit.
- [S0455] Metamorfo: Metamorfo has a function that can watch the contents of the system clipboard for valid bitcoin addresses, which it then overwrites with the attacker's address.

### T1565.003 - Data Manipulation: Runtime Data Manipulation

Procedures:

- [G0082] APT38: APT38 has used DYEPACK.FOX to manipulate PDF data as it is accessed to remove traces of fraudulent SWIFT transactions from the data displayed to the end user.


### T1657 - Financial Theft

Procedures:

- [G1032] INC Ransom: INC Ransom has stolen and encrypted victim's data in order to extort payment for keeping it private or decrypting it.
- [G1021] Cinnamon Tempest: Cinnamon Tempest has maintained leak sites for exfiltrated data in attempt to extort victims into paying a ransom.
- [G1026] Malteiro: Malteiro targets organizations in a wide variety of sectors via the use of Mispadu banking trojan with the goal of financial theft.
- [G0094] Kimsuky: Kimsuky has stolen and laundered cryptocurrency to self-fund operations including the acquisition of infrastructure.
- [G1016] FIN13: FIN13 has observed the victim's software and infrastructure over several months to understand the technical process of legitimate financial transactions, prior to attempting to conduct fraudulent transactions.
- [G1024] Akira: Akira engages in double-extortion ransomware, exfiltrating files then encrypting them, in order to prompt victims to pay a ransom.
- [G1015] Scattered Spider: Scattered Spider has deployed ransomware on compromised hosts for financial gain.
- [S1111] DarkGate: DarkGate can deploy payloads capable of capturing credentials related to cryptocurrency wallets.
- [G0083] SilverTerrier: SilverTerrier targets organizations in high technology, higher education, and manufacturing for business email compromise (BEC) campaigns with the goal of financial theft.
- [G1040] Play: Play demands ransom payments from victims to unencrypt filesystems and to not publish sensitive data exfiltrated from victim networks.


### T1667 - Email Bombing

Procedures:

- [G1046] Storm-1811: Storm-1811 has deployed large volumes of non-malicious email spam to victims in order to prompt follow-on interactions with the threat actor posing as IT support or helpdesk to resolve the problem.

