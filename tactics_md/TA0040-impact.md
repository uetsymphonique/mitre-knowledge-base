### T1485 - Data Destruction

Description:

Adversaries may destroy data and files on specific systems or in large numbers on a network to interrupt availability to systems, services, and network resources. Data destruction is likely to render stored data irrecoverable by forensic techniques through overwriting files or data on local and remote drives.(Citation: Symantec Shamoon 2012)(Citation: FireEye Shamoon Nov 2016)(Citation: Palo Alto Shamoon Nov 2016)(Citation: Kaspersky StoneDrill 2017)(Citation: Unit 42 Shamoon3 2018)(Citation: Talos Olympic Destroyer 2018) Common operating system file deletion commands such as <code>del</code> and <code>rm</code> often only remove pointers to files without wiping the contents of the files themselves, making the files recoverable by proper forensic methodology. This behavior is distinct from [Disk Content Wipe](https://attack.mitre.org/techniques/T1561/001) and [Disk Structure Wipe](https://attack.mitre.org/techniques/T1561/002) because individual files are destroyed rather than sections of a storage disk or the disk's logical structure.

Adversaries may attempt to overwrite files and directories with randomly generated data to make it irrecoverable.(Citation: Kaspersky StoneDrill 2017)(Citation: Unit 42 Shamoon3 2018) In some cases politically oriented image files have been used to overwrite data.(Citation: FireEye Shamoon Nov 2016)(Citation: Palo Alto Shamoon Nov 2016)(Citation: Kaspersky StoneDrill 2017)

To maximize impact on the target organization in operations where network-wide availability interruption is the goal, malware designed for destroying data may have worm-like features to propagate across a network by leveraging additional techniques like [Valid Accounts](https://attack.mitre.org/techniques/T1078), [OS Credential Dumping](https://attack.mitre.org/techniques/T1003), and [SMB/Windows Admin Shares](https://attack.mitre.org/techniques/T1021/002).(Citation: Symantec Shamoon 2012)(Citation: FireEye Shamoon Nov 2016)(Citation: Palo Alto Shamoon Nov 2016)(Citation: Kaspersky StoneDrill 2017)(Citation: Talos Olympic Destroyer 2018).

In cloud environments, adversaries may leverage access to delete cloud storage objects, machine images, database instances, and other infrastructure crucial to operations to damage an organization or their customers.(Citation: Data Destruction - Threat Post)(Citation: DOJ  - Cisco Insider) Similarly, they may delete virtual machines from on-prem virtualized environments.

Procedures:

- [S0659] Diavol: [Diavol](https://attack.mitre.org/software/S0659) can delete specified files from a targeted system.(Citation: Fortinet Diavol July 2021)
- [S0689] WhisperGate: [WhisperGate](https://attack.mitre.org/software/S0689) can corrupt files by overwriting the first 1 MB with `0xcc` and appending random extensions.(Citation: Microsoft WhisperGate January 2022)(Citation: Crowdstrike WhisperGate January 2022)(Citation: Cybereason WhisperGate February 2022)(Citation: Unit 42 WhisperGate January 2022)(Citation: Cisco Ukraine Wipers January 2022)(Citation: Medium S2W WhisperGate January 2022)
- [S0604] Industroyer: [Industroyer](https://attack.mitre.org/software/S0604)’s data wiper module clears registry keys and overwrites both ICS configuration and Windows files.(Citation: Dragos Crashoverride 2017)
- [G1004] LAPSUS$: [LAPSUS$](https://attack.mitre.org/groups/G1004) has deleted the target's systems and resources both on-premises and in the cloud.(Citation: MSTIC DEV-0537 Mar 2022)(Citation: NCC Group LAPSUS Apr 2022)
- [S0341] Xbash: [Xbash](https://attack.mitre.org/software/S0341) has destroyed Linux-based databases as part of its ransomware capabilities.(Citation: Unit42 Xbash Sept 2018)
- [G0032] Lazarus Group: [Lazarus Group](https://attack.mitre.org/groups/G0032) has used a custom secure delete function to overwrite file contents with data from heap memory.(Citation: Novetta Blockbuster)
- [S1125] AcidRain: [AcidRain](https://attack.mitre.org/software/S1125) performs an in-depth wipe of the target filesystem and various attached storage devices through either a data overwrite or calling various IOCTLS to erase it.(Citation: AcidRain JAGS 2022)
- [S0496] REvil: [REvil](https://attack.mitre.org/software/S0496) has the capability to destroy files and folders.(Citation: Kaspersky Sodin July 2019)(Citation: Secureworks GandCrab and REvil September 2019)(Citation: McAfee Sodinokibi October 2019)(Citation: McAfee Sodinokibi October 2019)(Citation: Intel 471 REvil March 2020)(Citation: Picus Sodinokibi January 2020)(Citation: Secureworks REvil September 2019)
- [S0265] Kazuar: [Kazuar](https://attack.mitre.org/software/S0265) can overwrite files with random data before deleting them.(Citation: Unit 42 Kazuar May 2017)
- [S0697] HermeticWiper: [HermeticWiper](https://attack.mitre.org/software/S0697) can recursively wipe folders and files in `Windows`, `Program Files`, `Program Files(x86)`, `PerfLogs`, `Boot, System`, `Volume Information`, and `AppData` folders using `FSCTL_MOVE_FILE`. [HermeticWiper](https://attack.mitre.org/software/S0697) can also overwrite symbolic links and big files in `My Documents` and on the Desktop with random bytes.(Citation: ESET Hermetic Wizard March 2022)
- [S1134] DEADWOOD: [DEADWOOD](https://attack.mitre.org/software/S1134) overwrites files on victim systems with random data to effectively destroy them.(Citation: SentinelOne Agrius 2021)
- [S0140] Shamoon: [Shamoon](https://attack.mitre.org/software/S0140) attempts to overwrite operating system files and disk structures with image files.(Citation: Symantec Shamoon 2012)(Citation: FireEye Shamoon Nov 2016)(Citation: Palo Alto Shamoon Nov 2016) In a later variant, randomly generated data was used for data overwrites.(Citation: Unit 42 Shamoon3 2018)(Citation: McAfee Shamoon December 2018)
- [S0139] PowerDuke: [PowerDuke](https://attack.mitre.org/software/S0139) has a command to write random data across a file and delete it.(Citation: Volexity PowerDuke November 2016)
- [C0034] 2022 Ukraine Electric Power Attack: During the [2022 Ukraine Electric Power Attack](https://attack.mitre.org/campaigns/C0034), [Sandworm Team](https://attack.mitre.org/groups/G0034) deployed [CaddyWiper](https://attack.mitre.org/software/S0693) on the victim’s IT environment systems to wipe files related to the OT capabilities, along with mapped drives, and physical drive partitions.(Citation: Mandiant-Sandworm-Ukraine-2022)
- [S0365] Olympic Destroyer: [Olympic Destroyer](https://attack.mitre.org/software/S0365) overwrites files locally and on remote shares.(Citation: Talos Olympic Destroyer 2018)(Citation: US District Court Indictment GRU Unit 74455 October 2020)
- [G0082] APT38: [APT38](https://attack.mitre.org/groups/G0082) has used a custom secure delete function to make deleted files unrecoverable.(Citation: FireEye APT38 Oct 2018)
- [S1135] MultiLayer Wiper: [MultiLayer Wiper](https://attack.mitre.org/software/S1135) deletes files on network drives, but corrupts and overwrites with random data files stored locally.(Citation: Unit42 Agrius 2023)
- [S0693] CaddyWiper: [CaddyWiper](https://attack.mitre.org/software/S0693) can work alphabetically through drives on a compromised system to take ownership of and overwrite all files.(Citation: ESET CaddyWiper March 2022)(Citation: Cisco CaddyWiper March 2022)
- [S0195] SDelete: [SDelete](https://attack.mitre.org/software/S0195) deletes data in a way that makes it unrecoverable.(Citation: Microsoft SDelete July 2016)
- [S0089] BlackEnergy: [BlackEnergy](https://attack.mitre.org/software/S0089) 2 contains a "Destroy" plug-in that destroys data stored on victim hard drives by overwriting file contents.(Citation: Securelist BlackEnergy Feb 2015)(Citation: ESET BlackEnergy Jan 2016)
- [S0364] RawDisk: [RawDisk](https://attack.mitre.org/software/S0364) was used in [Shamoon](https://attack.mitre.org/software/S0140) to write to protected system locations such as the MBR and disk partitions in an effort to destroy data.(Citation: Palo Alto Shamoon Nov 2016)(Citation: Unit 42 Shamoon3 2018)
- [S0688] Meteor: [Meteor](https://attack.mitre.org/software/S0688) can fill a victim's files and directories with zero-bytes in replacement of real content before deleting them.(Citation: Check Point Meteor Aug 2021)
- [S0607] KillDisk: [KillDisk](https://attack.mitre.org/software/S0607) deletes system files to make the OS unbootable. [KillDisk](https://attack.mitre.org/software/S0607) also targets and deletes files with 35 different file extensions.(Citation: ESEST Black Energy Jan 2016)
- [S1178] ShrinkLocker: [ShrinkLocker](https://attack.mitre.org/software/S1178) can initiate a destructive payload depending on the operating system check through resizing and reformatting portions of the victim machine's disk, leading to system instability and potential data corruption.(Citation: Splunk ShrinkLocker 2024)
- [G0034] Sandworm Team: [Sandworm Team](https://attack.mitre.org/groups/G0034) has used [CaddyWiper](https://attack.mitre.org/software/S0693), [SDelete](https://attack.mitre.org/software/S0195), and the [BlackEnergy](https://attack.mitre.org/software/S0089) KillDisk component to overwrite files on victim systems. (Citation: US-CERT Ukraine Feb 2016)(Citation: ESET Telebots June 2017)(Citation: Mandiant-Sandworm-Ukraine-2022) Additionally, [Sandworm Team](https://attack.mitre.org/groups/G0034) has used the JUNKMAIL tool to overwrite files with null bytes.(Citation: mandiant_apt44_unearthing_sandworm)
- [S0238] Proxysvc: [Proxysvc](https://attack.mitre.org/software/S0238) can overwrite files indicated by the attacker before deleting them.(Citation: McAfee GhostSecret)
- [S1133] Apostle: [Apostle](https://attack.mitre.org/software/S1133) initially masqueraded as ransomware but actual functionality is a data destruction tool, supported by an internal name linked to an early version, <code>wiper-action</code>. [Apostle](https://attack.mitre.org/software/S1133) writes random data to original files after an encrypted copy is created, along with resizing the original file to zero and changing time property metadata before finally deleting the original file.(Citation: SentinelOne Agrius 2021)
- [S1167] AcidPour: [AcidPour](https://attack.mitre.org/software/S1167) can perform an in-depth wipe of victim filesystems and attached storage devices through either data overwrite or calling various IOCTLS to erase them, similar to [AcidRain](https://attack.mitre.org/software/S1125).(Citation: SentinelOne AcidPour 2024)
- [S0380] StoneDrill: [StoneDrill](https://attack.mitre.org/software/S0380) has a disk wiper module that targets files other than those in the Windows directory.(Citation: Kaspersky StoneDrill 2017)

#### T1485.001 - Lifecycle-Triggered Deletion

Description:

Adversaries may modify the lifecycle policies of a cloud storage bucket to destroy all objects stored within.  

Cloud storage buckets often allow users to set lifecycle policies to automate the migration, archival, or deletion of objects after a set period of time.(Citation: AWS Storage Lifecycles)(Citation: GCP Storage Lifecycles)(Citation: Azure Storage Lifecycles) If a threat actor has sufficient permissions to modify these policies, they may be able to delete all objects at once. 

For example, in AWS environments, an adversary with the `PutLifecycleConfiguration` permission may use the `PutBucketLifecycle` API call to apply a lifecycle policy to an S3 bucket that deletes all objects in the bucket after one day.(Citation: Palo Alto Cloud Ransomware)(Citation: Halcyon AWS Ransomware 2025) In addition to destroying data for purposes of extortion and [Financial Theft](https://attack.mitre.org/techniques/T1657), adversaries may also perform this action on buckets storing cloud logs for [Indicator Removal](https://attack.mitre.org/techniques/T1070).(Citation: Datadog S3 Lifecycle CloudTrail Logs)


### T1486 - Data Encrypted for Impact

Description:

Adversaries may encrypt data on target systems or on large numbers of systems in a network to interrupt availability to system and network resources. They can attempt to render stored data inaccessible by encrypting files or data on local and remote drives and withholding access to a decryption key. This may be done in order to extract monetary compensation from a victim in exchange for decryption or a decryption key (ransomware) or to render data permanently inaccessible in cases where the key is not saved or transmitted.(Citation: US-CERT Ransomware 2016)(Citation: FireEye WannaCry 2017)(Citation: US-CERT NotPetya 2017)(Citation: US-CERT SamSam 2018)

In the case of ransomware, it is typical that common user files like Office documents, PDFs, images, videos, audio, text, and source code files will be encrypted (and often renamed and/or tagged with specific file markers). Adversaries may need to first employ other behaviors, such as [File and Directory Permissions Modification](https://attack.mitre.org/techniques/T1222) or [System Shutdown/Reboot](https://attack.mitre.org/techniques/T1529), in order to unlock and/or gain access to manipulate these files.(Citation: CarbonBlack Conti July 2020) In some cases, adversaries may encrypt critical system files, disk partitions, and the MBR.(Citation: US-CERT NotPetya 2017) Adversaries may also encrypt virtual machines hosted on ESXi or other hypervisors.(Citation: Crowdstrike Hypervisor Jackpotting Pt 2 2021) 

To maximize impact on the target organization, malware designed for encrypting data may have worm-like features to propagate across a network by leveraging other attack techniques like [Valid Accounts](https://attack.mitre.org/techniques/T1078), [OS Credential Dumping](https://attack.mitre.org/techniques/T1003), and [SMB/Windows Admin Shares](https://attack.mitre.org/techniques/T1021/002).(Citation: FireEye WannaCry 2017)(Citation: US-CERT NotPetya 2017) Encryption malware may also leverage [Internal Defacement](https://attack.mitre.org/techniques/T1491/001), such as changing victim wallpapers or ESXi server login messages, or otherwise intimidate victims by sending ransom notes or other messages to connected printers (known as "print bombing").(Citation: NHS Digital Egregor Nov 2020)(Citation: Varonis)

In cloud environments, storage objects within compromised accounts may also be encrypted.(Citation: Rhino S3 Ransomware Part 1) For example, in AWS environments, adversaries may leverage services such as AWS’s Server-Side Encryption with Customer Provided Keys (SSE-C) to encrypt data.(Citation: Halcyon AWS Ransomware 2025)

Procedures:

- [S0449] Maze: [Maze](https://attack.mitre.org/software/S0449) has disrupted systems by encrypting files on targeted machines, claiming to decrypt files if a ransom payment is made. [Maze](https://attack.mitre.org/software/S0449) has used the ChaCha algorithm, based on Salsa20, and an RSA algorithm to encrypt files.(Citation: FireEye Maze May 2020)
- [S0606] Bad Rabbit: [Bad Rabbit](https://attack.mitre.org/software/S0606) has encrypted files and disks using AES-128-CBC and RSA-2048.(Citation: Secure List Bad Rabbit)
- [S0595] ThiefQuest: [ThiefQuest](https://attack.mitre.org/software/S0595) encrypts a set of file extensions on a host, deletes the original files, and provides a ransom note with no contact information.(Citation: wardle evilquest partii)
- [G0082] APT38: [APT38](https://attack.mitre.org/groups/G0082) has used Hermes ransomware to encrypt files with AES256.(Citation: FireEye APT38 Oct 2018)
- [S0481] Ragnar Locker: [Ragnar Locker](https://attack.mitre.org/software/S0481) encrypts files on the local machine and mapped drives prior to displaying a note demanding a ransom.(Citation: Sophos Ragnar May 2020)(Citation: Cynet Ragnar Apr 2020)
- [G1032] INC Ransom: [INC Ransom](https://attack.mitre.org/groups/G1032) has used [INC Ransomware](https://attack.mitre.org/software/S1139) to encrypt victim's data.(Citation: SentinelOne INC Ransomware)(Citation: Huntress INC Ransom Group August 2023)(Citation: Bleeping Computer INC Ransomware March 2024)(Citation: Secureworks GOLD IONIC April 2024)(Citation: Cybereason INC Ransomware November 2023)(Citation: SOCRadar INC Ransom January 2024)
- [S1180] BlackByte Ransomware: [BlackByte Ransomware](https://attack.mitre.org/software/S1180) is ransomware using a shared key across victims for encryption.(Citation: Trustwave BlackByte 2021)
- [C0038] HomeLand Justice: During [HomeLand Justice](https://attack.mitre.org/campaigns/C0038), threat actors used [ROADSWEEP](https://attack.mitre.org/software/S1150) ransomware to encrypt files on targeted systems.(Citation: Mandiant ROADSWEEP August 2022)(Citation: CISA Iran Albanian Attacks September 2022)(Citation: Microsoft Albanian Government Attacks September 2022)
- [S1073] Royal: [Royal](https://attack.mitre.org/software/S1073) uses a multi-threaded encryption process that can partially encrypt targeted files with the OpenSSL library and the AES256 algorithm.(Citation: Cybereason Royal December 2022)(Citation: Kroll Royal Deep Dive February 2023)(Citation: Trend Micro Royal Linux ESXi February 2023)
- [S0389] JCry: [JCry](https://attack.mitre.org/software/S0389) has encrypted files and demanded Bitcoin to decrypt those files. (Citation: Carbon Black JCry May 2019)
- [S0638] Babuk: [Babuk](https://attack.mitre.org/software/S0638) can use ChaCha8 and ECDH to encrypt data.(Citation: Sogeti CERT ESEC Babuk March 2021)(Citation: McAfee Babuk February 2021)(Citation: Medium Babuk February 2021)(Citation: Trend Micro Ransomware February 2021)
- [S1137] Moneybird: [Moneybird](https://attack.mitre.org/software/S1137) targets a common set of file types such as documents, certificates, and database files for encryption while avoiding executable, dynamic linked libraries, and similar items.(Citation: CheckPoint Agrius 2023)
- [S0496] REvil: [REvil](https://attack.mitre.org/software/S0496) can encrypt files on victim systems and demands a ransom to decrypt the files.(Citation: Kaspersky Sodin July 2019)(Citation: Cylance Sodinokibi July 2019)(Citation: Talos Sodinokibi April 2019)(Citation: McAfee REvil October 2019)(Citation: Intel 471 REvil March 2020)(Citation: Picus Sodinokibi January 2020)(Citation: Secureworks REvil September 2019)(Citation: Tetra Defense Sodinokibi March 2020)
- [S0659] Diavol: [Diavol](https://attack.mitre.org/software/S0659) has encrypted files using an RSA key though the `CryptEncrypt` API and has appended filenames with ".lock64". (Citation: Fortinet Diavol July 2021)
- [S0625] Cuba: [Cuba](https://attack.mitre.org/software/S0625) has the ability to encrypt system data and add the ".cuba" extension to encrypted files.(Citation: McAfee Cuba April 2021)
- [S1162] Playcrypt: [Playcrypt](https://attack.mitre.org/software/S1162) encrypts files on targeted hosts with an AES-RSA hybrid encryption, encrypting every other file portion of 0x100000 bytes.(Citation: CISA Play Ransomware Advisory December 2023)(Citation: Trend Micro Ransomware Spotlight Play July 2023)
- [S1111] DarkGate: [DarkGate](https://attack.mitre.org/software/S1111) can deploy follow-on ransomware payloads.(Citation: Ensilo Darkgate 2018)
- [S1068] BlackCat: [BlackCat](https://attack.mitre.org/software/S1068) has the ability to encrypt Windows devices, Linux devices, and VMWare instances.(Citation: Microsoft BlackCat Jun 2022)
- [S1058] Prestige: [Prestige](https://attack.mitre.org/software/S1058) has leveraged the CryptoPP C++ library to encrypt files on target systems using AES and appended filenames with `.enc`.(Citation: Microsoft Prestige ransomware October 2022)
- [G0059] Magic Hound: [Magic Hound](https://attack.mitre.org/groups/G0059) has used BitLocker and DiskCryptor to encrypt targeted workstations. (Citation: DFIR Phosphorus November 2021)(Citation: Microsoft Iranian Threat Actor Trends November 2021)
- [S0372] LockerGoga: [LockerGoga](https://attack.mitre.org/software/S0372) has encrypted files, including core Windows OS files, using RSA-OAEP MGF1 and then demanded Bitcoin be paid for the decryption key.(Citation: CarbonBlack LockerGoga 2019)(Citation: Unit42 LockerGoga 2019)(Citation: Wired Lockergoga 2019)
- [S0616] DEATHRANSOM: [DEATHRANSOM](https://attack.mitre.org/software/S0616) can use public and private key pair encryption to encrypt files for ransom payment.(Citation: FireEye FiveHands April 2021)
- [S0605] EKANS: [EKANS](https://attack.mitre.org/software/S0605) uses standard encryption library functions to encrypt files.(Citation: Dragos EKANS)(Citation: Palo Alto Unit 42 EKANS)
- [S0654] ProLock: [ProLock](https://attack.mitre.org/software/S0654) can encrypt files on a compromised host with RC6, and encrypts the key with RSA-1024.(Citation: Group IB Ransomware September 2020)
- [S1053] AvosLocker: [AvosLocker](https://attack.mitre.org/software/S1053) has encrypted files and network resources using AES-256 and added an `.avos`, `.avos2`, or `.AvosLinux` extension to filenames.(Citation: Malwarebytes AvosLocker Jul 2021)(Citation: Trend Micro AvosLocker Apr 2022)(Citation: Cisco Talos Avos Jun 2022)(Citation: Joint CSA AvosLocker Mar 2022)
- [S0617] HELLOKITTY: [HELLOKITTY](https://attack.mitre.org/software/S0617) can use an embedded RSA-2048 public key to encrypt victim data for ransom.(Citation: FireEye FiveHands April 2021)
- [G1015] Scattered Spider: [Scattered Spider](https://attack.mitre.org/groups/G1015) has used BlackCat ransomware to encrypt files on VMWare ESXi servers.(Citation: CISA Scattered Spider Advisory November 2023)(Citation: MSTIC Octo Tempest Operations October 2023)
- [S0570] BitPaymer: [BitPaymer](https://attack.mitre.org/software/S0570) can import a hard-coded RSA 1024-bit public key, generate a 128-bit RC4 key for each file, and encrypt the file in place, appending <code>.locked</code> to the filename.(Citation: Crowdstrike Indrik November 2018)
- [S1096] Cheerscrypt: [Cheerscrypt](https://attack.mitre.org/software/S1096) can encrypt data on victim machines using a Sosemanuk stream cipher with an Elliptic-curve Diffie–Hellman (ECDH) generated key.(Citation: Trend Micro Cheerscrypt May 2022)(Citation: Sygnia Emperor Dragonfly October 2022)
- [S1181] BlackByte 2.0 Ransomware: [BlackByte 2.0 Ransomware](https://attack.mitre.org/software/S1181) is a ransomware variant associated with [BlackByte](https://attack.mitre.org/groups/G1043) operations.(Citation: Microsoft BlackByte 2023)
- [S0366] WannaCry: [WannaCry](https://attack.mitre.org/software/S0366) encrypts user files and demands that a ransom be paid in Bitcoin to decrypt those files.(Citation: LogRhythm WannaCry)(Citation: FireEye WannaCry 2017)(Citation: SecureWorks WannaCry Analysis)
- [G0046] FIN7: [FIN7](https://attack.mitre.org/groups/G0046) has encrypted virtual disk volumes on ESXi servers using a version of Darkside ransomware.(Citation: CrowdStrike Carbon Spider August 2021)(Citation: Mandiant FIN7 Apr 2022)
- [S1150] ROADSWEEP: [ROADSWEEP](https://attack.mitre.org/software/S1150) can RC4 encrypt content in blocks on targeted systems.(Citation: Mandiant ROADSWEEP August 2022)(Citation: CISA Iran Albanian Attacks September 2022)(Citation: Microsoft Albanian Government Attacks September 2022)
- [S1033] DCSrv: [DCSrv](https://attack.mitre.org/software/S1033) has encrypted drives using the core encryption mechanism from DiskCryptor.(Citation: Checkpoint MosesStaff Nov 2021)
- [S1070] Black Basta: [Black Basta](https://attack.mitre.org/software/S1070) can encrypt files with the ChaCha20 cypher and using a multithreaded process to increase speed.(Citation: Minerva Labs Black Basta May 2022)(Citation: BlackBerry Black Basta May 2022)(Citation: Cyble Black Basta May 2022)(Citation: NCC Group Black Basta June 2022)(Citation: Uptycs Black Basta ESXi June 2022)(Citation: Deep Instinct Black Basta August 2022)(Citation: Palo Alto Networks Black Basta August 2022)(Citation: Trend Micro Black Basta Spotlight September 2022)(Citation: Check Point Black Basta October 2022) [Black Basta](https://attack.mitre.org/software/S1070) has also encrypted files while the victim system is in safe mode, appending `.basta` upon completion.(Citation: Trend Micro Black Basta May 2022)
- [S0612] WastedLocker: [WastedLocker](https://attack.mitre.org/software/S0612) can encrypt data and leave a ransom note.(Citation: Symantec WastedLocker June 2020)(Citation: NCC Group WastedLocker June 2020)(Citation: Sentinel Labs WastedLocker July 2020)
- [C0018] C0018: During [C0018](https://attack.mitre.org/campaigns/C0018), the threat actors used [AvosLocker](https://attack.mitre.org/software/S1053) ransomware to encrypt files on the compromised network.(Citation: Cisco Talos Avos Jun 2022)(Citation: Costa AvosLocker May 2022)
- [S0583] Pysa: [Pysa](https://attack.mitre.org/software/S0583) has used RSA and AES-CBC encryption algorithm to encrypt a list of targeted file extensions.(Citation: CERT-FR PYSA April 2020)
- [S1178] ShrinkLocker: [ShrinkLocker](https://attack.mitre.org/software/S1178) uses the legitimate BitLocker application to encrypt victim files for ransom.(Citation: Kaspersky ShrinkLocker 2024)(Citation: Splunk ShrinkLocker 2024)
- [S1139] INC Ransomware: [INC Ransomware](https://attack.mitre.org/software/S1139) can encrypt data on victim systems, including through the use of partial encryption and multi-threading to speed encryption.(Citation: SentinelOne INC Ransomware)(Citation: Huntress INC Ransom Group August 2023)(Citation: Cybereason INC Ransomware November 2023)(Citation: SOCRadar INC Ransom January 2024)(Citation: SentinelOne INC Ransomware)
- [C0015] C0015: During [C0015](https://attack.mitre.org/campaigns/C0015), the threat actors used [Conti](https://attack.mitre.org/software/S0575) ransomware to encrypt a compromised network.(Citation: DFIR Conti Bazar Nov 2021)
- [S0576] MegaCortex: [MegaCortex](https://attack.mitre.org/software/S0576) has used the open-source library, Mbed Crypto, and generated AES keys to carry out the file encryption process.(Citation: IBM MegaCortex)(Citation: mbed-crypto)
- [S0242] SynAck: [SynAck](https://attack.mitre.org/software/S0242) encrypts the victims machine followed by asking the victim to pay a ransom. (Citation: SecureList SynAck Doppelgänging May 2018)
- [S0618] FIVEHANDS: [FIVEHANDS](https://attack.mitre.org/software/S0618) can use an embedded NTRU public key to encrypt data for ransom.(Citation: FireEye FiveHands April 2021)(Citation: CISA AR21-126A FIVEHANDS May 2021)(Citation: NCC Group Fivehands June 2021)
- [S0575] Conti: [Conti](https://attack.mitre.org/software/S0575) can use <code>CreateIoCompletionPort()</code>, <code>PostQueuedCompletionStatus()</code>, and <code>GetQueuedCompletionPort()</code> to rapidly encrypt files, excluding those with the extensions of .exe, .dll, and .lnk. It has used a different AES-256 encryption key per file with a bundled RAS-4096 public encryption key that is unique for each victim. [Conti](https://attack.mitre.org/software/S0575) can use “Windows Restart Manager” to ensure files are unlocked and open for encryption.(Citation: Cybereason Conti Jan 2021)(Citation: CarbonBlack Conti July 2020)(Citation: Cybleinc Conti January 2020)(Citation: CrowdStrike Wizard Spider October 2020)(Citation: DFIR Conti Bazar Nov 2021)
- [S0341] Xbash: [Xbash](https://attack.mitre.org/software/S0341) has maliciously encrypted victim's database systems and demanded a cryptocurrency ransom be paid.(Citation: Unit42 Xbash Sept 2018)
- [S0556] Pay2Key: [Pay2Key](https://attack.mitre.org/software/S0556) can encrypt data on victim's machines using RSA and AES algorithms in order to extort a ransom payment for decryption.(Citation: ClearkSky Fox Kitten February 2020)(Citation: Check Point Pay2Key November 2020)
- [G0034] Sandworm Team: [Sandworm Team](https://attack.mitre.org/groups/G0034) has used [Prestige](https://attack.mitre.org/software/S1058) ransomware to encrypt data at targeted organizations in transportation and related logistics industries in Ukraine and Poland.(Citation: Microsoft Prestige ransomware October 2022)
- [G1024] Akira: [Akira](https://attack.mitre.org/groups/G1024) encrypts files in victim environments as part of ransomware operations.(Citation: BushidoToken Akira 2023)(Citation: CISA Akira Ransomware APR 2024)
- [G1046] Storm-1811: [Storm-1811](https://attack.mitre.org/groups/G1046) is a financially-motivated entity linked to the deployment of [Black Basta](https://attack.mitre.org/software/S1070) ransomware in victim environments.(Citation: Microsoft Storm-1811 2024)
- [S1212] RansomHub: [RansomHub](https://attack.mitre.org/software/S1212) can use Elliptic Curve Encryption to encrypt files on targeted systems.(Citation: CISA RansomHub AUG 2024) [RansomHub](https://attack.mitre.org/software/S1212) can also skip content at regular intervals (ex. encrypt 1 MB, skip 3 MB) to optomize performance and enable faster encryption for large files.(Citation: Group-IB RansomHub FEB 2025)
- [S0554] Egregor: [Egregor](https://attack.mitre.org/software/S0554) can encrypt all non-system files using a hybrid AES-RSA algorithm prior to displaying a ransom note.(Citation: NHS Digital Egregor Nov 2020)(Citation: Cybereason Egregor Nov 2020)
- [G0119] Indrik Spider: [Indrik Spider](https://attack.mitre.org/groups/G0119) has encrypted domain-controlled systems using [BitPaymer](https://attack.mitre.org/software/S0570).(Citation: Crowdstrike Indrik November 2018) Additionally, [Indrik Spider](https://attack.mitre.org/groups/G0119) used [PsExec](https://attack.mitre.org/software/S0029) to execute a ransomware script.(Citation: Mandiant_UNC2165)
- [S0368] NotPetya: [NotPetya](https://attack.mitre.org/software/S0368) encrypts user files and disk structures like the MBR with 2048-bit RSA.(Citation: Talos Nyetya June 2017)(Citation: US-CERT NotPetya 2017)(Citation: US District Court Indictment GRU Unit 74455 October 2020)
- [S0370] SamSam: [SamSam](https://attack.mitre.org/software/S0370) encrypts victim files using RSA-2048 encryption and demands a ransom be paid in Bitcoin to decrypt those files.(Citation: Sophos SamSam Apr 2018)
- [G0096] APT41: [APT41](https://attack.mitre.org/groups/G0096) used a ransomware called Encryptor RaaS to encrypt files on the targeted systems and provide a ransom note to the user.(Citation: FireEye APT41 Aug 2019) [APT41](https://attack.mitre.org/groups/G0096) also used Microsoft Bitlocker to encrypt workstations and Jetico’s BestCrypt to encrypt servers.(Citation: apt41_dcsocytec_dec2022)
- [S0446] Ryuk: [Ryuk](https://attack.mitre.org/software/S0446) has used a combination of symmetric (AES) and asymmetric (RSA) encryption to encrypt files. Files have been encrypted with their own AES key and given a file extension of .RYK. Encrypted directories have had a ransom note of RyukReadMe.txt written to the directory.(Citation: CrowdStrike Ryuk January 2019)(Citation: CrowdStrike Wizard Spider October 2020)
- [S1194] Akira _v2: The [Akira _v2](https://attack.mitre.org/software/S1194) encryptor targets the `/vmfs/volumes/` path by default and can use the rust-crypto 0.2.36 library crate for the encryption processes.(Citation: Cisco Akira Ransomware OCT 2024)(Citation: Palo Alto Howling Scorpius DEC 2024)
- [S0640] Avaddon: [Avaddon](https://attack.mitre.org/software/S0640) encrypts the victim system using a combination of AES256 and RSA encryption schemes.(Citation: Arxiv Avaddon Feb 2021)
- [S0457] Netwalker: [Netwalker](https://attack.mitre.org/software/S0457) can encrypt files on infected machines to extort victims.(Citation: TrendMicro Netwalker May 2020)
- [S0607] KillDisk: [KillDisk](https://attack.mitre.org/software/S0607) has a ransomware component that encrypts files with an AES key that is also RSA-1028 encrypted.(Citation: KillDisk Ransomware)
- [S0611] Clop: [Clop](https://attack.mitre.org/software/S0611) can encrypt files using AES, RSA, and RC4 and will add the ".clop" extension to encrypted files.(Citation: Mcafee Clop Aug 2019)(Citation: Unit42 Clop April 2021)(Citation: Cybereason Clop Dec 2020)
- [G0092] TA505: [TA505](https://attack.mitre.org/groups/G0092) has used a wide variety of ransomware, such as [Clop](https://attack.mitre.org/software/S0611), Locky, Jaff, Bart, Philadelphia, and GlobeImposter, to encrypt victim files and demand a ransom payment.(Citation: Proofpoint TA505 Sep 2017)
- [S0658] XCSSET: [XCSSET](https://attack.mitre.org/software/S0658) performs AES-CBC encryption on files under <code>~/Documents</code>, <code>~/Downloads</code>, and
<code>~/Desktop</code> with a fixed key and renames files to give them a <code>.enc</code> extension. Only files with sizes 
less than 500MB are encrypted.(Citation: trendmicro xcsset xcode project 2020)
- [S0639] Seth-Locker: [Seth-Locker](https://attack.mitre.org/software/S0639) can encrypt files on a targeted system, appending them with the suffix .seth.(Citation: Trend Micro Ransomware February 2021)
- [S0140] Shamoon: [Shamoon](https://attack.mitre.org/software/S0140) has an operational mode for encrypting data instead of overwriting it.(Citation: Palo Alto Shamoon Nov 2016)(Citation: Unit 42 Shamoon3 2018)
- [S1202] LockBit 3.0: [LockBit 3.0](https://attack.mitre.org/software/S1202) can encrypt targeted data using the AES-256, ChaCha20, or RSA-2048 algorithms.(Citation: Joint Cybersecurity Advisory LockBit JUN 2023)(Citation: Sentinel Labs LockBit 3.0 JUL 2022)(Citation: Joint Cybersecurity Advisory LockBit 3.0 MAR 2023)(Citation: INCIBE-CERT LockBit MAR 2024)
- [S1199] LockBit 2.0: [LockBit 2.0](https://attack.mitre.org/software/S1199) can use standard AES and elliptic-curve cryptography algorithms to encrypt victim data.(Citation: Palo Alto Lockbit 2.0 JUN 2022)(Citation: SentinelOne LockBit 2.0)
- [S1133] Apostle: [Apostle](https://attack.mitre.org/software/S1133) creates new, encrypted versions of files then deletes the originals, with the new filenames consisting of a random GUID and ".lock" for an extension.(Citation: SentinelOne Agrius 2021)
- [G1043] BlackByte: [BlackByte](https://attack.mitre.org/groups/G1043) has encrypted victim files for ransom. Early versions of BlackByte ransomware used a common key for encryption, but later versions use unique keys per victim.(Citation: FBI BlackByte 2022)(Citation: Picus BlackByte 2022)(Citation: Symantec BlackByte 2022)(Citation: Microsoft BlackByte 2023)(Citation: Cisco BlackByte 2024)
- [S0400] RobbinHood: [RobbinHood](https://attack.mitre.org/software/S0400) will search for an RSA encryption key and then perform its encryption process on the system files.(Citation: CarbonBlack RobbinHood May 2019)
- [S1191] Megazord: [Megazord](https://attack.mitre.org/software/S1191) can encrypt files on targeted Windows hosts leaving them with a  ".powerranges" file extension.(Citation: CISA Akira Ransomware APR 2024)(Citation: Cisco Akira Ransomware OCT 2024)(Citation: Palo Alto Howling Scorpius DEC 2024)
- [G0061] FIN8: [FIN8](https://attack.mitre.org/groups/G0061) has deployed ransomware such as [Ragnar Locker](https://attack.mitre.org/software/S0481), White Rabbit, and attempted to execute Noberus on compromised networks.(Citation: Symantec FIN8 Jul 2023)
- [G1036] Moonstone Sleet: [Moonstone Sleet](https://attack.mitre.org/groups/G1036) has deployed ransomware in victim environments.(Citation: Microsoft Moonstone Sleet 2024)
- [S1129] Akira: [Akira](https://attack.mitre.org/software/S1129) can encrypt victim filesystems for financial extortion purposes including through the use of the ChaCha20 and ChaCha8 stream ciphers.(Citation: Kersten Akira 2023)(Citation: CISA Akira Ransomware APR 2024)(Citation: Cisco Akira Ransomware OCT 2024)


### T1489 - Service Stop

Description:

Adversaries may stop or disable services on a system to render those services unavailable to legitimate users. Stopping critical services or processes can inhibit or stop response to an incident or aid in the adversary's overall objectives to cause damage to the environment.(Citation: Talos Olympic Destroyer 2018)(Citation: Novetta Blockbuster) 

Adversaries may accomplish this by disabling individual services of high importance to an organization, such as <code>MSExchangeIS</code>, which will make Exchange content inaccessible.(Citation: Novetta Blockbuster) In some cases, adversaries may stop or disable many or all services to render systems unusable.(Citation: Talos Olympic Destroyer 2018) Services or processes may not allow for modification of their data stores while running. Adversaries may stop services or processes in order to conduct [Data Destruction](https://attack.mitre.org/techniques/T1485) or [Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486) on the data stores of services like Exchange and SQL Server, or on virtual machines hosted on ESXi infrastructure.(Citation: SecureWorks WannaCry Analysis)(Citation: Crowdstrike Hypervisor Jackpotting Pt 2 2021)

Procedures:

- [S0611] Clop: [Clop](https://attack.mitre.org/software/S0611) can kill several processes and services related to backups and security solutions.(Citation: Unit42 Clop April 2021)(Citation: Mcafee Clop Aug 2019)
- [S0582] LookBack: [LookBack](https://attack.mitre.org/software/S0582) can kill processes and delete services.(Citation: Proofpoint LookBack Malware Aug 2019)
- [S0688] Meteor: [Meteor](https://attack.mitre.org/software/S0688) can disconnect all network adapters on a compromised host using `powershell -Command "Get-WmiObject -class Win32_NetworkAdapter | ForEach { If ($.NetEnabled) { $.Disable() } }" > NUL`.(Citation: Check Point Meteor Aug 2021)
- [S1211] Hannotog: [Hannotog](https://attack.mitre.org/software/S1211) can stop Windows services.(Citation: Symantec Bilbug 2022)
- [S0366] WannaCry: [WannaCry](https://attack.mitre.org/software/S0366) attempts to kill processes associated with Exchange, Microsoft SQL Server, and MySQL to make it possible to encrypt their data stores.(Citation: FireEye WannaCry 2017)(Citation: SecureWorks WannaCry Analysis)
- [S1073] Royal: [Royal](https://attack.mitre.org/software/S1073) can use `RmShutDown` to kill  applications and services using the resources that are targeted for encryption.(Citation: Cybereason Royal December 2022)
- [S0659] Diavol: [Diavol](https://attack.mitre.org/software/S0659) will terminate services using the Service Control Manager (SCM) API.(Citation: Fortinet Diavol July 2021)
- [S0640] Avaddon: [Avaddon](https://attack.mitre.org/software/S0640) looks for and attempts to stop database processes.(Citation: Arxiv Avaddon Feb 2021)
- [S0365] Olympic Destroyer: [Olympic Destroyer](https://attack.mitre.org/software/S0365) uses the API call <code>ChangeServiceConfigW</code> to disable all services on the affected system.(Citation: Talos Olympic Destroyer 2018)
- [S1096] Cheerscrypt: [Cheerscrypt](https://attack.mitre.org/software/S1096) has the ability to terminate VM processes on compromised hosts through execution of `esxcli vm process kill`.(Citation: Trend Micro Cheerscrypt May 2022)
- [S1058] Prestige: [Prestige](https://attack.mitre.org/software/S1058) has attempted to stop the MSSQL Windows service to ensure successful encryption using `C:\Windows\System32\net.exe stop MSSQLSERVER`.(Citation: Microsoft Prestige ransomware October 2022)
- [S0556] Pay2Key: [Pay2Key](https://attack.mitre.org/software/S0556) can stop the MS SQL service at the end of the encryption process to release files locked by the service.(Citation: Check Point Pay2Key November 2020)
- [S1068] BlackCat: [BlackCat](https://attack.mitre.org/software/S1068) has the ability to stop VM services on compromised networks.(Citation: Microsoft BlackCat Jun 2022)(Citation: Sophos BlackCat Jul 2022)
- [S0400] RobbinHood: [RobbinHood](https://attack.mitre.org/software/S0400) stops 181 Windows services on the system before beginning the encryption process.(Citation: CarbonBlack RobbinHood May 2019)
- [G0032] Lazarus Group: [Lazarus Group](https://attack.mitre.org/groups/G0032) has stopped the MSExchangeIS service to render Exchange contents inaccessible to users.(Citation: Novetta Blockbuster Destructive Malware)
- [S1199] LockBit 2.0: [LockBit 2.0](https://attack.mitre.org/software/S1199) can automatically terminate processes that may interfere with the encryption or file extraction processes.(Citation: SentinelOne LockBit 2.0)
- [S1191] Megazord: [Megazord](https://attack.mitre.org/software/S1191) has the ability to terminate a list of services and processes.(Citation: Palo Alto Howling Scorpius DEC 2024)
- [S0638] Babuk: [Babuk](https://attack.mitre.org/software/S0638) can stop specific services related to backups.(Citation: Sogeti CERT ESEC Babuk March 2021)(Citation: McAfee Babuk February 2021)(Citation: Trend Micro Ransomware February 2021)
- [S0496] REvil: [REvil](https://attack.mitre.org/software/S0496) has the capability to stop services and kill processes.(Citation: Intel 471 REvil March 2020)(Citation: Secureworks REvil September 2019)
- [S0575] Conti: [Conti](https://attack.mitre.org/software/S0575) can stop up to 146 Windows services related to security, backup, database, and email solutions through the use of <code>net stop</code>.(Citation: CarbonBlack Conti July 2020)
- [S0446] Ryuk: [Ryuk](https://attack.mitre.org/software/S0446) has called <code>kill.bat</code> for stopping services, disabling services and killing processes.(Citation: CrowdStrike Ryuk January 2019)
- [S0625] Cuba: [Cuba](https://attack.mitre.org/software/S0625) has a hardcoded list of services and processes to terminate.(Citation: McAfee Cuba April 2021)
- [G0034] Sandworm Team: [Sandworm Team](https://attack.mitre.org/groups/G0034) attempts to stop the MSSQL Windows service to ensure successful encryption of locked files.(Citation: Microsoft Prestige ransomware October 2022)
- [G1004] LAPSUS$: [LAPSUS$](https://attack.mitre.org/groups/G1004) has shut down virtual machines from within a victim's on-premise VMware ESXi infrastructure.(Citation: NCC Group LAPSUS Apr 2022)
- [S0576] MegaCortex: [MegaCortex](https://attack.mitre.org/software/S0576) can stop and disable services on the system.(Citation: IBM MegaCortex)
- [S0604] Industroyer: [Industroyer](https://attack.mitre.org/software/S0604)’s data wiper module writes zeros into the registry keys in <code>SYSTEM\CurrentControlSet\Services</code> to render a system inoperable.(Citation: Dragos Crashoverride 2017)
- [S0607] KillDisk: [KillDisk](https://attack.mitre.org/software/S0607) terminates various processes to get the user to reboot the victim machine.(Citation: Trend Micro KillDisk 2)
- [S0481] Ragnar Locker: [Ragnar Locker](https://attack.mitre.org/software/S0481) has attempted to stop services associated with business applications and databases to release the lock on files used by these applications so they may be encrypted.(Citation: Sophos Ragnar May 2020)
- [S0533] SLOTHFULMEDIA: [SLOTHFULMEDIA](https://attack.mitre.org/software/S0533) has the capability to stop processes and services.(Citation: CISA MAR SLOTHFULMEDIA October 2020)
- [S0431] HotCroissant: [HotCroissant](https://attack.mitre.org/software/S0431) has the ability to stop services on the infected host.(Citation: Carbon Black HotCroissant April 2020)
- [S1181] BlackByte 2.0 Ransomware: [BlackByte 2.0 Ransomware](https://attack.mitre.org/software/S1181) can terminate running services.(Citation: Microsoft BlackByte 2023)
- [S0605] EKANS: [EKANS](https://attack.mitre.org/software/S0605) stops database, data backup solution, antivirus, and ICS-related processes.(Citation: Dragos EKANS)(Citation: FireEye Ransomware Feb 2020)(Citation: Palo Alto Unit 42 EKANS)
- [S1053] AvosLocker: [AvosLocker](https://attack.mitre.org/software/S1053) has terminated specific processes before encryption.(Citation: Malwarebytes AvosLocker Jul 2021)
- [S1202] LockBit 3.0: [LockBit 3.0](https://attack.mitre.org/software/S1202) can terminate targeted processes and services related to security, backup, database management, and other applications that could stop or interfere with encryption.(Citation: Joint Cybersecurity Advisory LockBit JUN 2023)(Citation: Sentinel Labs LockBit 3.0 JUL 2022)(Citation: Joint Cybersecurity Advisory LockBit 3.0 MAR 2023)(Citation: INCIBE-CERT LockBit MAR 2024)
- [S1150] ROADSWEEP: [ROADSWEEP](https://attack.mitre.org/software/S1150) can disable critical services and processes.(Citation: Mandiant ROADSWEEP August 2022)
- [G0102] Wizard Spider: [Wizard Spider](https://attack.mitre.org/groups/G0102) has used taskkill.exe and net.exe to stop backup, catalog, cloud, and other services prior to network encryption.(Citation: DFIR Ryuk's Return October 2020)
- [S0583] Pysa: [Pysa](https://attack.mitre.org/software/S0583) can stop services and processes.(Citation: CERT-FR PYSA April 2020)
- [S0697] HermeticWiper: [HermeticWiper](https://attack.mitre.org/software/S0697) has the ability to stop the Volume Shadow Copy service.(Citation: Qualys Hermetic Wiper March 2022)
- [S0449] Maze: [Maze](https://attack.mitre.org/software/S0449) has stopped SQL services to ensure it can encrypt any database.(Citation: Sophos Maze VM September 2020)
- [G0119] Indrik Spider: [Indrik Spider](https://attack.mitre.org/groups/G0119) has used [PsExec](https://attack.mitre.org/software/S0029) to stop services prior to the execution of ransomware.(Citation: Symantec WastedLocker June 2020)
- [S0457] Netwalker: [Netwalker](https://attack.mitre.org/software/S0457) can terminate system processes and services, some of which relate to backup software.(Citation: TrendMicro Netwalker May 2020)
- [S1139] INC Ransomware: [INC Ransomware](https://attack.mitre.org/software/S1139) can issue a command to kill a process on compromised hosts.(Citation: Cybereason INC Ransomware November 2023)
- [S1212] RansomHub: [RansomHub](https://attack.mitre.org/software/S1212) has the ability to terminate specified services.(Citation: Group-IB RansomHub FEB 2025)
- [S1194] Akira _v2: [Akira _v2](https://attack.mitre.org/software/S1194) can stop running virtual machines.(Citation: CISA Akira Ransomware APR 2024)(Citation: Cisco Akira Ransomware OCT 2024)(Citation: Palo Alto Howling Scorpius DEC 2024)


### T1490 - Inhibit System Recovery

Description:

Adversaries may delete or remove built-in data and turn off services designed to aid in the recovery of a corrupted system to prevent recovery.(Citation: Talos Olympic Destroyer 2018)(Citation: FireEye WannaCry 2017) This may deny access to available backups and recovery options.

Operating systems may contain features that can help fix corrupted systems, such as a backup catalog, volume shadow copies, and automatic repair features. Adversaries may disable or delete system recovery features to augment the effects of [Data Destruction](https://attack.mitre.org/techniques/T1485) and [Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486).(Citation: Talos Olympic Destroyer 2018)(Citation: FireEye WannaCry 2017) Furthermore, adversaries may disable recovery notifications, then corrupt backups.(Citation: disable_notif_synology_ransom)

A number of native Windows utilities have been used by adversaries to disable or delete system recovery features:

* <code>vssadmin.exe</code> can be used to delete all volume shadow copies on a system - <code>vssadmin.exe delete shadows /all /quiet</code>
* [Windows Management Instrumentation](https://attack.mitre.org/techniques/T1047) can be used to delete volume shadow copies - <code>wmic shadowcopy delete</code>
* <code>wbadmin.exe</code> can be used to delete the Windows Backup Catalog - <code>wbadmin.exe delete catalog -quiet</code>
* <code>bcdedit.exe</code> can be used to disable automatic Windows recovery features by modifying boot configuration data - <code>bcdedit.exe /set {default} bootstatuspolicy ignoreallfailures & bcdedit /set {default} recoveryenabled no</code>
* <code>REAgentC.exe</code> can be used to disable Windows Recovery Environment (WinRE) repair/recovery options of an infected system
* <code>diskshadow.exe</code> can be used to delete all volume shadow copies on a system - <code>diskshadow delete shadows all</code> (Citation: Diskshadow) (Citation: Crytox Ransomware)

On network devices, adversaries may leverage [Disk Wipe](https://attack.mitre.org/techniques/T1561) to delete backup firmware images and reformat the file system, then [System Shutdown/Reboot](https://attack.mitre.org/techniques/T1529) to reload the device. Together this activity may leave network devices completely inoperable and inhibit recovery operations.

On ESXi servers, adversaries may delete or encrypt snapshots of virtual machines to support [Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486), preventing them from being leveraged as backups (e.g., via ` vim-cmd vmsvc/snapshot.removeall`).(Citation: Cybereason)

Adversaries may also delete “online” backups that are connected to their network – whether via network storage media or through folders that sync to cloud services.(Citation: ZDNet Ransomware Backups 2020) In cloud environments, adversaries may disable versioning and backup policies and delete snapshots, database backups, machine images, and prior versions of objects designed to be used in disaster recovery scenarios.(Citation: Dark Reading Code Spaces Cyber Attack)(Citation: Rhino Security Labs AWS S3 Ransomware)

Procedures:

- [S1070] Black Basta: [Black Basta](https://attack.mitre.org/software/S1070) can delete shadow copies using vssadmin.exe.(Citation: Minerva Labs Black Basta May 2022)(Citation: Cyble Black Basta May 2022)(Citation: Trend Micro Black Basta May 2022)(Citation: Avertium Black Basta June 2022)(Citation: NCC Group Black Basta June 2022)(Citation: Deep Instinct Black Basta August 2022)(Citation: Palo Alto Networks Black Basta August 2022)(Citation: Trend Micro Black Basta Spotlight September 2022)(Citation: Trend Micro Black Basta Spotlight September 2022)(Citation: Check Point Black Basta October 2022)
- [S0481] Ragnar Locker: [Ragnar Locker](https://attack.mitre.org/software/S0481) can delete volume shadow copies using <code>vssadmin delete shadows /all /quiet</code>.(Citation: Sophos Ragnar May 2020)
- [S0260] InvisiMole: [InvisiMole](https://attack.mitre.org/software/S0260) can can remove all system restore points.(Citation: ESET InvisiMole June 2018)
- [S1162] Playcrypt: [Playcrypt](https://attack.mitre.org/software/S1162) can use AlphaVSS to delete shadow copies.(Citation: Trend Micro Ransomware Spotlight Play July 2023)
- [S0612] WastedLocker: [WastedLocker](https://attack.mitre.org/software/S0612) can delete shadow volumes.(Citation: Symantec WastedLocker June 2020)(Citation: NCC Group WastedLocker June 2020)(Citation: Sentinel Labs WastedLocker July 2020)
- [S0132] H1N1: [H1N1](https://attack.mitre.org/software/S0132) disable recovery options and deletes shadow copies from the victim.(Citation: Cisco H1N1 Part 2)
- [S0400] RobbinHood: [RobbinHood](https://attack.mitre.org/software/S0400) deletes shadow copies to ensure that all the data cannot be restored easily.(Citation: CarbonBlack RobbinHood May 2019)
- [S0446] Ryuk: [Ryuk](https://attack.mitre.org/software/S0446) has used <code>vssadmin Delete Shadows /all /quiet</code> to to delete volume shadow copies and <code>vssadmin resize shadowstorage</code> to force deletion of shadow copies created by third-party applications.(Citation: CrowdStrike Ryuk January 2019)
- [S0673] DarkWatchman: [DarkWatchman](https://attack.mitre.org/software/S0673) can delete shadow volumes using <code>vssadmin.exe</code>.(Citation: Prevailion DarkWatchman 2021)
- [S0605] EKANS: [EKANS](https://attack.mitre.org/software/S0605) removes backups of Volume Shadow Copies to disable any restoration capabilities.(Citation: Dragos EKANS)(Citation: Palo Alto Unit 42 EKANS)
- [S1139] INC Ransomware: [INC Ransomware](https://attack.mitre.org/software/S1139) can delete volume shadow copy backups from victim machines.(Citation: Cybereason INC Ransomware November 2023)
- [S0576] MegaCortex: [MegaCortex](https://attack.mitre.org/software/S0576) has deleted volume shadow copies using <code>vssadmin.exe</code>.(Citation: IBM MegaCortex)
- [S0616] DEATHRANSOM: [DEATHRANSOM](https://attack.mitre.org/software/S0616) can delete volume shadow copies on compromised hosts.(Citation: FireEye FiveHands April 2021)
- [S1073] Royal: [Royal](https://attack.mitre.org/software/S1073) can delete shadow copy backups with vssadmin.exe using the command `delete shadows /all /quiet`.(Citation: Cybereason Royal December 2022)(Citation: Kroll Royal Deep Dive February 2023)(Citation: CISA Royal AA23-061A March 2023)
- [S1181] BlackByte 2.0 Ransomware: [BlackByte 2.0 Ransomware](https://attack.mitre.org/software/S1181) modifies volume shadow copies during execution in a way that destroys them on the victim machine.(Citation: Microsoft BlackByte 2023)
- [S0640] Avaddon: [Avaddon](https://attack.mitre.org/software/S0640) deletes backups and shadow copies using native system tools.(Citation: Hornet Security Avaddon June 2020)(Citation: Arxiv Avaddon Feb 2021)
- [S1058] Prestige: [Prestige](https://attack.mitre.org/software/S1058) can delete the backup catalog from the target system using: `c:\Windows\System32\wbadmin.exe delete catalog -quiet` and can also delete volume shadow copies using: `\Windows\System32\vssadmin.exe delete shadows /all /quiet`.(Citation: Microsoft Prestige ransomware October 2022)
- [S1111] DarkGate: [DarkGate](https://attack.mitre.org/software/S1111) can delete system restore points through the command <code>cmd.exe /c vssadmin delete shadows /for=c: /all /quiet”</code>.(Citation: Ensilo Darkgate 2018)
- [S0697] HermeticWiper: [HermeticWiper](https://attack.mitre.org/software/S0697) can disable the VSS service on a compromised host using the service control manager.(Citation: Crowdstrike DriveSlayer February 2022)(Citation: ESET Hermetic Wizard March 2022)(Citation: Qualys Hermetic Wiper March 2022)
- [S0366] WannaCry: [WannaCry](https://attack.mitre.org/software/S0366) uses <code>vssadmin</code>, <code>wbadmin</code>, <code>bcdedit</code>, and <code>wmic</code> to delete and disable operating system recovery features.(Citation: LogRhythm WannaCry)(Citation: FireEye WannaCry 2017)(Citation: SecureWorks WannaCry Analysis)
- [G0102] Wizard Spider: [Wizard Spider](https://attack.mitre.org/groups/G0102) has used WMIC and vssadmin to manually delete volume shadow copies. [Wizard Spider](https://attack.mitre.org/groups/G0102) has also used [Conti](https://attack.mitre.org/software/S0575) ransomware to delete volume shadow copies automatically with the use of vssadmin.(Citation: Mandiant FIN12 Oct 2021)
- [S0638] Babuk: [Babuk](https://attack.mitre.org/software/S0638) has the ability to delete shadow volumes using <code>vssadmin.exe delete shadows /all /quiet</code>.(Citation: Sogeti CERT ESEC Babuk March 2021)(Citation: McAfee Babuk February 2021)
- [S0570] BitPaymer: [BitPaymer](https://attack.mitre.org/software/S0570) attempts to remove the backup shadow files from the host using <code>vssadmin.exe Delete Shadows /All /Quiet</code>.(Citation: Crowdstrike Indrik November 2018)
- [S1180] BlackByte Ransomware: [BlackByte Ransomware](https://attack.mitre.org/software/S1180) deletes all volume shadow copies and restore points among other actions to inhibit system recovery following ransomware deployment.(Citation: Trustwave BlackByte 2021)
- [S0617] HELLOKITTY: [HELLOKITTY](https://attack.mitre.org/software/S0617) can delete volume shadow copies on compromised hosts.(Citation: FireEye FiveHands April 2021)
- [S0457] Netwalker: [Netwalker](https://attack.mitre.org/software/S0457) can delete the infected system's Shadow Volumes to prevent recovery.(Citation: TrendMicro Netwalker May 2020)(Citation: Sophos Netwalker May 2020)
- [G1043] BlackByte: [BlackByte](https://attack.mitre.org/groups/G1043) resized and deleted volume shadow copy files to prevent system recovery after encryption.(Citation: Picus BlackByte 2022)(Citation: Symantec BlackByte 2022)
- [S1212] RansomHub: [RansomHub](https://attack.mitre.org/software/S1212) has used `vssadmin.exe` to delete volume shadow copies.(Citation: CISA RansomHub AUG 2024)(Citation: Group-IB RansomHub FEB 2025)
- [S0618] FIVEHANDS: [FIVEHANDS](https://attack.mitre.org/software/S0618) has the ability to delete volume shadow copies on compromised hosts.(Citation: FireEye FiveHands April 2021)(Citation: CISA AR21-126A FIVEHANDS May 2021)
- [S0575] Conti: [Conti](https://attack.mitre.org/software/S0575) can delete Windows Volume Shadow Copies using <code>vssadmin</code>.(Citation: CarbonBlack Conti July 2020)
- [S1129] Akira: [Akira](https://attack.mitre.org/software/S1129) will delete system volume shadow copies via PowerShell commands.(Citation: Kersten Akira 2023)(Citation: CISA Akira Ransomware APR 2024)
- [S0611] Clop: [Clop](https://attack.mitre.org/software/S0611) can delete the shadow volumes with <code>vssadmin Delete Shadows /all /quiet</code> and can use bcdedit to disable recovery options.(Citation: Mcafee Clop Aug 2019)
- [S1135] MultiLayer Wiper: [MultiLayer Wiper](https://attack.mitre.org/software/S1135) wipes the boot sector of infected systems to inhibit system recovery.(Citation: Unit42 Agrius 2023)
- [S0688] Meteor: [Meteor](https://attack.mitre.org/software/S0688) can use `bcdedit` to delete different boot identifiers on a compromised host; it can also use `vssadmin.exe delete shadows /all /quiet` and `C:\\Windows\\system32\\wbem\\wmic.exe shadowcopy delete`.(Citation: Check Point Meteor Aug 2021)
- [S0583] Pysa: [Pysa](https://attack.mitre.org/software/S0583) has the functionality to delete shadow copies.(Citation: CERT-FR PYSA April 2020)
- [G0034] Sandworm Team: [Sandworm Team](https://attack.mitre.org/groups/G0034) uses [Prestige](https://attack.mitre.org/software/S1058) to delete the backup catalog from the target system using: `C:\Windows\System32\wbadmin.exe delete catalog -quiet` and to delete volume shadow copies using: `C:\Windows\System32\vssadmin.exe delete shadows /all /quiet`. (Citation: Microsoft Prestige ransomware October 2022)
- [S0608] Conficker: [Conficker](https://attack.mitre.org/software/S0608) resets system restore points and deletes backup files.(Citation: SANS Conficker)
- [S0365] Olympic Destroyer: [Olympic Destroyer](https://attack.mitre.org/software/S0365) uses the native Windows utilities <code>vssadmin</code>, <code>wbadmin</code>, and <code>bcdedit</code> to delete and disable operating system recovery features such as the Windows backup catalog and Windows Automatic Repair.(Citation: Talos Olympic Destroyer 2018)
- [S0496] REvil: [REvil](https://attack.mitre.org/software/S0496) can use vssadmin to delete volume shadow copies and bcdedit to disable recovery features.(Citation: Kaspersky Sodin July 2019)(Citation: Cylance Sodinokibi July 2019)(Citation: Secureworks GandCrab and REvil September 2019)(Citation: Talos Sodinokibi April 2019)(Citation: McAfee Sodinokibi October 2019)(Citation: Intel 471 REvil March 2020)(Citation: Picus Sodinokibi January 2020)(Citation: Secureworks REvil September 2019)(Citation: Tetra Defense Sodinokibi March 2020)
- [S0449] Maze: [Maze](https://attack.mitre.org/software/S0449) has attempted to delete the shadow volumes of infected machines, once before and once after the encryption process.(Citation: McAfee Maze March 2020)(Citation: Sophos Maze VM September 2020)
- [S0659] Diavol: [Diavol](https://attack.mitre.org/software/S0659) can delete shadow copies using the `IVssBackupComponents` COM object to call the `DeleteSnapshots` method.(Citation: Fortinet Diavol July 2021)
- [S1202] LockBit 3.0: [LockBit 3.0](https://attack.mitre.org/software/S1202) can delete volume shadow copies.(Citation: Joint Cybersecurity Advisory LockBit JUN 2023)(Citation: Joint Cybersecurity Advisory LockBit 3.0 MAR 2023)(Citation: INCIBE-CERT LockBit MAR 2024)
- [S0389] JCry: [JCry](https://attack.mitre.org/software/S0389) has been observed deleting shadow copies to ensure that data cannot be restored easily.(Citation: Carbon Black JCry May 2019)
- [S1136] BFG Agonizer: [BFG Agonizer](https://attack.mitre.org/software/S1136) wipes the boot sector of infected machines to inhibit system recovery.(Citation: Unit42 Agrius 2023)
- [S1150] ROADSWEEP: [ROADSWEEP](https://attack.mitre.org/software/S1150) has the ability to disable `SystemRestore` and Volume Shadow Copies.(Citation: Mandiant ROADSWEEP August 2022)(Citation: CISA Iran Albanian Attacks September 2022)
- [S0654] ProLock: [ProLock](https://attack.mitre.org/software/S0654) can use vssadmin.exe to remove volume shadow copies.(Citation: Group IB Ransomware September 2020)
- [S1068] BlackCat: [BlackCat](https://attack.mitre.org/software/S1068) can delete shadow copies using `vssadmin.exe delete shadows /all /quiet` and `wmic.exe Shadowcopy Delete`; it can also modify the boot loader using `bcdedit /set {default} recoveryenabled No`.(Citation: Microsoft BlackCat Jun 2022)
- [S1199] LockBit 2.0: [LockBit 2.0](https://attack.mitre.org/software/S1199) has the ability to delete volume shadow copies on targeted hosts.(Citation: FBI Lockbit 2.0 FEB 2022)(Citation: Cybereason Lockbit 2.0)


### T1491 - Defacement

Description:

Adversaries may modify visual content available internally or externally to an enterprise network, thus affecting the integrity of the original content. Reasons for [Defacement](https://attack.mitre.org/techniques/T1491) include delivering messaging, intimidation, or claiming (possibly false) credit for an intrusion. Disturbing or offensive images may be used as a part of [Defacement](https://attack.mitre.org/techniques/T1491) in order to cause user discomfort, or to pressure compliance with accompanying messages.

#### T1491.001 - Internal Defacement

Description:

An adversary may deface systems internal to an organization in an attempt to intimidate or mislead users, thus discrediting the integrity of the systems. This may take the form of modifications to internal websites or server login messages, or directly to user systems with the replacement of the desktop wallpaper.(Citation: Novetta Blockbuster)(Citation: Varonis) Disturbing or offensive images may be used as a part of [Internal Defacement](https://attack.mitre.org/techniques/T1491/001) in order to cause user discomfort, or to pressure compliance with accompanying messages. Since internally defacing systems exposes an adversary's presence, it often takes place after other intrusion goals have been accomplished.(Citation: Novetta Blockbuster Destructive Malware)

Procedures:

- [G0047] Gamaredon Group: [Gamaredon Group](https://attack.mitre.org/groups/G0047) has left taunting images and messages on the victims' desktops as proof of system access.(Citation: CERT-EE Gamaredon January 2021)
- [S1178] ShrinkLocker: [ShrinkLocker](https://attack.mitre.org/software/S1178) renames disk labels on victim hosts to the threat actor's email address to enable the victim to contact the threat actor for ransom negotiation.(Citation: Kaspersky ShrinkLocker 2024)(Citation: Splunk ShrinkLocker 2024)
- [S1070] Black Basta: [Black Basta](https://attack.mitre.org/software/S1070) has set the desktop wallpaper on victims' machines to display a ransom note.(Citation: Minerva Labs Black Basta May 2022)(Citation: BlackBerry Black Basta May 2022)(Citation: Cyble Black Basta May 2022)(Citation: Trend Micro Black Basta May 2022)(Citation: Avertium Black Basta June 2022)(Citation: NCC Group Black Basta June 2022)(Citation: Deep Instinct Black Basta August 2022)(Citation: Palo Alto Networks Black Basta August 2022)(Citation: Check Point Black Basta October 2022)
- [S0659] Diavol: After encryption, [Diavol](https://attack.mitre.org/software/S0659) will capture the desktop background window, set the background color to black, and change the desktop wallpaper to a newly created bitmap image with the text “All your files are encrypted! For more information see “README-FOR-DECRYPT.txt".(Citation: Fortinet Diavol July 2021)
- [G1043] BlackByte: [BlackByte](https://attack.mitre.org/groups/G1043) left ransom notes in all directories where encryption takes place.(Citation: FBI BlackByte 2022)
- [S1150] ROADSWEEP: [ROADSWEEP](https://attack.mitre.org/software/S1150) has dropped ransom notes in targeted folders prior to encrypting the files.(Citation: Microsoft Albanian Government Attacks September 2022)
- [S0688] Meteor: [Meteor](https://attack.mitre.org/software/S0688) can change both the desktop wallpaper and the lock screen image to a custom image.(Citation: Check Point Meteor Aug 2021)
- [G0032] Lazarus Group: [Lazarus Group](https://attack.mitre.org/groups/G0032) replaced the background wallpaper of systems with a threatening image after rendering the system unbootable with a [Disk Structure Wipe](https://attack.mitre.org/techniques/T1561/002).(Citation: Novetta Blockbuster Destructive Malware)
- [S1212] RansomHub: [RansomHub](https://attack.mitre.org/software/S1212) has placed a ransom note on comrpomised systems to warn victims and provide directions for how to retrieve data.(Citation: CISA RansomHub AUG 2024)
- [S1068] BlackCat: [BlackCat](https://attack.mitre.org/software/S1068) can change the desktop wallpaper on compromised hosts.(Citation: Microsoft BlackCat Jun 2022)(Citation: Sophos BlackCat Jul 2022)
- [S1139] INC Ransomware: [INC Ransomware](https://attack.mitre.org/software/S1139) has the ability to change the background wallpaper image to display the ransom note.(Citation: Cybereason INC Ransomware November 2023)(Citation: Secureworks GOLD IONIC April 2024)

#### T1491.002 - External Defacement

Description:

An adversary may deface systems external to an organization in an attempt to deliver messaging, intimidate, or otherwise mislead an organization or users. [External Defacement](https://attack.mitre.org/techniques/T1491/002) may ultimately cause users to distrust the systems and to question/discredit the system’s integrity. Externally-facing websites are a common victim of defacement; often targeted by adversary and hacktivist groups in order to push a political message or spread propaganda.(Citation: FireEye Cyber Threats to Media Industries)(Citation: Kevin Mandia Statement to US Senate Committee on Intelligence)(Citation: Anonymous Hackers Deface Russian Govt Site) [External Defacement](https://attack.mitre.org/techniques/T1491/002) may be used as a catalyst to trigger events, or as a response to actions taken by an organization or government. Similarly, website defacement may also be used as setup, or a precursor, for future attacks such as [Drive-by Compromise](https://attack.mitre.org/techniques/T1189).(Citation: Trend Micro Deep Dive Into Defacement)

Procedures:

- [G1003] Ember Bear: [Ember Bear](https://attack.mitre.org/groups/G1003) is linked to the defacement of several Ukrainian organization websites.(Citation: Cadet Blizzard emerges as novel threat actor)
- [G0034] Sandworm Team: [Sandworm Team](https://attack.mitre.org/groups/G0034) defaced approximately 15,000 websites belonging to Georgian government, non-government, and private sector organizations in 2019.(Citation: US District Court Indictment GRU Unit 74455 October 2020)(Citation: UK NCSC Olympic Attacks October 2020)


### T1495 - Firmware Corruption

Description:

Adversaries may overwrite or corrupt the flash memory contents of system BIOS or other firmware in devices attached to a system in order to render them inoperable or unable to boot, thus denying the availability to use the devices and/or the system.(Citation: Symantec Chernobyl W95.CIH) Firmware is software that is loaded and executed from non-volatile memory on hardware devices in order to initialize and manage device functionality. These devices may include the motherboard, hard drive, or video cards.

In general, adversaries may manipulate, overwrite, or corrupt firmware in order to deny the use of the system or devices. For example, corruption of firmware responsible for loading the operating system for network devices may render the network devices inoperable.(Citation: dhs_threat_to_net_devices)(Citation: cisa_malware_orgs_ukraine) Depending on the device, this attack may also result in [Data Destruction](https://attack.mitre.org/techniques/T1485).

Procedures:

- [S0606] Bad Rabbit: [Bad Rabbit](https://attack.mitre.org/software/S0606) has used an executable that installs a modified bootloader to prevent normal boot-up.(Citation: Secure List Bad Rabbit)
- [S0266] TrickBot: [TrickBot](https://attack.mitre.org/software/S0266) module "Trickboot" can write or erase the UEFI/BIOS firmware of a compromised device.(Citation: Eclypsium Trickboot December 2020)


### T1496 - Resource Hijacking

Description:

Adversaries may leverage the resources of co-opted systems to complete resource-intensive tasks, which may impact system and/or hosted service availability. 

Resource hijacking may take a number of different forms. For example, adversaries may:

* Leverage compute resources in order to mine cryptocurrency
* Sell network bandwidth to proxy networks
* Generate SMS traffic for profit
* Abuse cloud-based messaging services to send large quantities of spam messages

In some cases, adversaries may leverage multiple types of Resource Hijacking at once.(Citation: Sysdig Cryptojacking Proxyjacking 2023)

#### T1496.001 - Compute Hijacking

Description:

Adversaries may leverage the compute resources of co-opted systems to complete resource-intensive tasks, which may impact system and/or hosted service availability. 

One common purpose for [Compute Hijacking](https://attack.mitre.org/techniques/T1496/001) is to validate transactions of cryptocurrency networks and earn virtual currency. Adversaries may consume enough system resources to negatively impact and/or cause affected machines to become unresponsive.(Citation: Kaspersky Lazarus Under The Hood Blog 2017) Servers and cloud-based systems are common targets because of the high potential for available resources, but user endpoint systems may also be compromised and used for [Compute Hijacking](https://attack.mitre.org/techniques/T1496/001) and cryptocurrency mining.(Citation: CloudSploit - Unused AWS Regions) Containerized environments may also be targeted due to the ease of deployment via exposed APIs and the potential for scaling mining activities by deploying or compromising multiple containers within an environment or cluster.(Citation: Unit 42 Hildegard Malware)(Citation: Trend Micro Exposed Docker APIs)

Additionally, some cryptocurrency mining malware identify then kill off processes for competing malware to ensure it’s not competing for resources.(Citation: Trend Micro War of Crypto Miners)

Procedures:

- [S0532] Lucifer: [Lucifer](https://attack.mitre.org/software/S0532) can use system resources to mine cryptocurrency, dropping XMRig to mine Monero.(Citation: Unit 42 Lucifer June 2020)
- [S0468] Skidmap: [Skidmap](https://attack.mitre.org/software/S0468) is a kernel-mode rootkit used for cryptocurrency mining.(Citation: Trend Micro Skidmap)
- [S0492] CookieMiner: [CookieMiner](https://attack.mitre.org/software/S0492) has loaded coinmining software onto systems to mine for Koto cryptocurrency. (Citation: Unit42 CookieMiner Jan 2019)
- [G0106] Rocke: [Rocke](https://attack.mitre.org/groups/G0106) has distributed cryptomining malware.(Citation: Talos Rocke August 2018)(Citation: Unit 42 Rocke January 2019)
- [S0486] Bonadan: [Bonadan](https://attack.mitre.org/software/S0486) can download an additional module which has a cryptocurrency mining extension.(Citation: ESET ForSSHe December 2018)
- [S0451] LoudMiner: [LoudMiner](https://attack.mitre.org/software/S0451) harvested system resources to mine cryptocurrency, using XMRig to mine Monero.(Citation: ESET LoudMiner June 2019)
- [S1111] DarkGate: [DarkGate](https://attack.mitre.org/software/S1111) can deploy follow-on cryptocurrency mining payloads.(Citation: Ensilo Darkgate 2018)
- [G0108] Blue Mockingbird: [Blue Mockingbird](https://attack.mitre.org/groups/G0108) has used XMRIG to mine cryptocurrency on victim systems.(Citation: RedCanary Mockingbird May 2020)
- [S0434] Imminent Monitor: [Imminent Monitor](https://attack.mitre.org/software/S0434) has the capability to run a cryptocurrency miner on the victim machine.(Citation: Imminent Unit42 Dec2019)
- [G0139] TeamTNT: [TeamTNT](https://attack.mitre.org/groups/G0139) has deployed XMRig Docker images to mine cryptocurrency.(Citation: Lacework TeamTNT May 2021)(Citation: Cado Security TeamTNT Worm August 2020) [TeamTNT](https://attack.mitre.org/groups/G0139) has also infected Docker containers and Kubernetes clusters with XMRig, and used RainbowMiner and lolMiner for mining cryptocurrency.(Citation: Cisco Talos Intelligence Group)
- [G0096] APT41: [APT41](https://attack.mitre.org/groups/G0096) deployed a Monero cryptocurrency mining tool in a victim’s environment.(Citation: FireEye APT41 Aug 2019)(Citation: apt41_mandiant)
- [S0601] Hildegard: [Hildegard](https://attack.mitre.org/software/S0601) has used xmrig to mine cryptocurrency.(Citation: Unit 42 Hildegard Malware)
- [C0045] ShadowRay: During [ShadowRay](https://attack.mitre.org/campaigns/C0045), threat actors leveraged graphics processing units (GPU) on compromised nodes for cryptocurrency mining.(Citation: Oligo ShadowRay Campaign MAR 2024)
- [S0599] Kinsing: [Kinsing](https://attack.mitre.org/software/S0599) has created and run a Bitcoin cryptocurrency miner.(Citation: Aqua Kinsing April 2020)(Citation: Sysdig Kinsing November 2020)

#### T1496.002 - Bandwidth Hijacking

Description:

Adversaries may leverage the network bandwidth resources of co-opted systems to complete resource-intensive tasks, which may impact system and/or hosted service availability. 

Adversaries may also use malware that leverages a system's network bandwidth as part of a botnet in order to facilitate [Network Denial of Service](https://attack.mitre.org/techniques/T1498) campaigns and/or to seed malicious torrents.(Citation: GoBotKR) Alternatively, they may engage in proxyjacking by selling use of the victims' network bandwidth and IP address to proxyware services.(Citation: Sysdig Proxyjacking) Finally, they may engage in internet-wide scanning in order to identify additional targets for compromise.(Citation: Unit 42 Leaked Environment Variables 2024)

In addition to incurring potential financial costs or availability disruptions, this technique may cause reputational damage if a victim’s bandwidth is used for illegal activities.(Citation: Sysdig Proxyjacking)

#### T1496.003 - SMS Pumping

Description:

Adversaries may leverage messaging services for SMS pumping, which may impact system and/or hosted service availability.(Citation: Twilio SMS Pumping) SMS pumping is a type of telecommunications fraud whereby a threat actor first obtains a set of phone numbers from a telecommunications provider, then leverages a victim’s messaging infrastructure to send large amounts of SMS messages to numbers in that set. By generating SMS traffic to their phone number set, a threat actor may earn payments from the telecommunications provider.(Citation: Twilio SMS Pumping Fraud)

Threat actors often use publicly available web forms, such as one-time password (OTP) or account verification fields, in order to generate SMS traffic. These fields may leverage services such as Twilio, AWS SNS, and Amazon Cognito in the background.(Citation: Twilio SMS Pumping)(Citation: AWS RE:Inforce Threat Detection 2024) In response to the large quantity of requests, SMS costs may increase and communication channels may become overwhelmed.(Citation: Twilio SMS Pumping)

#### T1496.004 - Cloud Service Hijacking

Description:

Adversaries may leverage compromised software-as-a-service (SaaS) applications to complete resource-intensive tasks, which may impact hosted service availability. 

For example, adversaries may leverage email and messaging services, such as AWS Simple Email Service (SES), AWS Simple Notification Service (SNS), SendGrid, and Twilio, in order to send large quantities of spam / [Phishing](https://attack.mitre.org/techniques/T1566) emails and SMS messages.(Citation: Invictus IR DangerDev 2024)(Citation: Permiso SES Abuse 2023)(Citation: SentinelLabs SNS Sender 2024) Alternatively, they may engage in LLMJacking by leveraging reverse proxies to hijack the power of cloud-hosted AI models.(Citation: Sysdig LLMJacking 2024)(Citation: Lacework LLMJacking 2024)

In some cases, adversaries may leverage services that the victim is already using. In others, particularly when the service is part of a larger cloud platform, they may first enable the service.(Citation: Sysdig LLMJacking 2024) Leveraging SaaS applications may cause the victim to incur significant financial costs, use up service quotas, and otherwise impact availability.


### T1498 - Network Denial of Service

Description:

Adversaries may perform Network Denial of Service (DoS) attacks to degrade or block the availability of targeted resources to users. Network DoS can be performed by exhausting the network bandwidth services rely on. Example resources include specific websites, email services, DNS, and web-based applications. Adversaries have been observed conducting network DoS attacks for political purposes(Citation: FireEye OpPoisonedHandover February 2016) and to support other malicious activities, including distraction(Citation: FSISAC FraudNetDoS September 2012), hacktivism, and extortion.(Citation: Symantec DDoS October 2014)

A Network DoS will occur when the bandwidth capacity of the network connection to a system is exhausted due to the volume of malicious traffic directed at the resource or the network connections and network devices the resource relies on. For example, an adversary may send 10Gbps of traffic to a server that is hosted by a network with a 1Gbps connection to the internet. This traffic can be generated by a single system or multiple systems spread across the internet, which is commonly referred to as a distributed DoS (DDoS).

To perform Network DoS attacks several aspects apply to multiple methods, including IP address spoofing, and botnets.

Adversaries may use the original IP address of an attacking system, or spoof the source IP address to make the attack traffic more difficult to trace back to the attacking system or to enable reflection. This can increase the difficulty defenders have in defending against the attack by reducing or eliminating the effectiveness of filtering by the source address on network defense devices.

For DoS attacks targeting the hosting system directly, see [Endpoint Denial of Service](https://attack.mitre.org/techniques/T1499).

Procedures:

- [G0007] APT28: In 2016, [APT28](https://attack.mitre.org/groups/G0007) conducted a distributed denial of service (DDoS) attack against the World Anti-Doping Agency.(Citation: US District Court Indictment GRU Oct 2018)
- [S1107] NKAbuse: [NKAbuse](https://attack.mitre.org/software/S1107) enables multiple types of network denial of service capabilities across several protocols post-installation.(Citation: NKAbuse SL)
- [S0532] Lucifer: [Lucifer](https://attack.mitre.org/software/S0532) can execute TCP, UDP,  and HTTP denial of service (DoS) attacks.(Citation: Unit 42 Lucifer June 2020)

#### T1498.001 - Direct Network Flood

Description:

Adversaries may attempt to cause a denial of service (DoS) by directly sending a high-volume of network traffic to a target. This DoS attack may also reduce the availability and functionality of the targeted system(s) and network. [Direct Network Flood](https://attack.mitre.org/techniques/T1498/001)s are when one or more systems are used to send a high-volume of network packets towards the targeted service's network. Almost any network protocol may be used for flooding. Stateless protocols such as UDP or ICMP are commonly used but stateful protocols such as TCP can be used as well.

Botnets are commonly used to conduct network flooding attacks against networks and services. Large botnets can generate a significant amount of traffic from systems spread across the global Internet. Adversaries may have the resources to build out and control their own botnet infrastructure or may rent time on an existing botnet to conduct an attack. In some of the worst cases for distributed DoS (DDoS), so many systems are used to generate the flood that each one only needs to send out a small amount of traffic to produce enough volume to saturate the target network. In such circumstances, distinguishing DDoS traffic from legitimate clients becomes exceedingly difficult. Botnets have been used in some of the most high-profile DDoS flooding attacks, such as the 2012 series of incidents that targeted major US banks.(Citation: USNYAG IranianBotnet March 2016)

#### T1498.002 - Reflection Amplification

Description:

Adversaries may attempt to cause a denial of service (DoS) by reflecting a high-volume of network traffic to a target. This type of Network DoS takes advantage of a third-party server intermediary that hosts and will respond to a given spoofed source IP address. This third-party server is commonly termed a reflector. An adversary accomplishes a reflection attack by sending packets to reflectors with the spoofed address of the victim. Similar to Direct Network Floods, more than one system may be used to conduct the attack, or a botnet may be used. Likewise, one or more reflectors may be used to focus traffic on the target.(Citation: Cloudflare ReflectionDoS May 2017) This Network DoS attack may also reduce the availability and functionality of the targeted system(s) and network.

Reflection attacks often take advantage of protocols with larger responses than requests in order to amplify their traffic, commonly known as a Reflection Amplification attack. Adversaries may be able to generate an increase in volume of attack traffic that is several orders of magnitude greater than the requests sent to the amplifiers. The extent of this increase will depending upon many variables, such as the protocol in question, the technique used, and the amplifying servers that actually produce the amplification in attack volume. Two prominent protocols that have enabled Reflection Amplification Floods are DNS(Citation: Cloudflare DNSamplficationDoS) and NTP(Citation: Cloudflare NTPamplifciationDoS), though the use of several others in the wild have been documented.(Citation: Arbor AnnualDoSreport Jan 2018)  In particular, the memcache protocol showed itself to be a powerful protocol, with amplification sizes up to 51,200 times the requesting packet.(Citation: Cloudflare Memcrashed Feb 2018)


### T1499 - Endpoint Denial of Service

Description:

Adversaries may perform Endpoint Denial of Service (DoS) attacks to degrade or block the availability of services to users. Endpoint DoS can be performed by exhausting the system resources those services are hosted on or exploiting the system to cause a persistent crash condition. Example services include websites, email services, DNS, and web-based applications. Adversaries have been observed conducting DoS attacks for political purposes(Citation: FireEye OpPoisonedHandover February 2016) and to support other malicious activities, including distraction(Citation: FSISAC FraudNetDoS September 2012), hacktivism, and extortion.(Citation: Symantec DDoS October 2014)

An Endpoint DoS denies the availability of a service without saturating the network used to provide access to the service. Adversaries can target various layers of the application stack that is hosted on the system used to provide the service. These layers include the Operating Systems (OS), server applications such as web servers, DNS servers, databases, and the (typically web-based) applications that sit on top of them. Attacking each layer requires different techniques that take advantage of bottlenecks that are unique to the respective components. A DoS attack may be generated by a single system or multiple systems spread across the internet, which is commonly referred to as a distributed DoS (DDoS).

To perform DoS attacks against endpoint resources, several aspects apply to multiple methods, including IP address spoofing and botnets.

Adversaries may use the original IP address of an attacking system, or spoof the source IP address to make the attack traffic more difficult to trace back to the attacking system or to enable reflection. This can increase the difficulty defenders have in defending against the attack by reducing or eliminating the effectiveness of filtering by the source address on network defense devices.

Botnets are commonly used to conduct DDoS attacks against networks and services. Large botnets can generate a significant amount of traffic from systems spread across the global internet. Adversaries may have the resources to build out and control their own botnet infrastructure or may rent time on an existing botnet to conduct an attack. In some of the worst cases for DDoS, so many systems are used to generate requests that each one only needs to send out a small amount of traffic to produce enough volume to exhaust the target's resources. In such circumstances, distinguishing DDoS traffic from legitimate clients becomes exceedingly difficult. Botnets have been used in some of the most high-profile DDoS attacks, such as the 2012 series of incidents that targeted major US banks.(Citation: USNYAG IranianBotnet March 2016)

In cases where traffic manipulation is used, there may be points in the global network (such as high traffic gateway routers) where packets can be altered and cause legitimate clients to execute code that directs network packets toward a target in high volume. This type of capability was previously used for the purposes of web censorship where client HTTP traffic was modified to include a reference to JavaScript that generated the DDoS code to overwhelm target web servers.(Citation: ArsTechnica Great Firewall of China)

For attacks attempting to saturate the providing network, see [Network Denial of Service](https://attack.mitre.org/techniques/T1498).

Procedures:

- [S0052] OnionDuke: [OnionDuke](https://attack.mitre.org/software/S0052) has the capability to use a Denial of Service module.(Citation: ESET Dukes October 2019)
- [G0034] Sandworm Team: [Sandworm Team](https://attack.mitre.org/groups/G0034) temporarily disrupted service to Georgian government, non-government, and private sector websites after compromising a Georgian web hosting provider in 2019.(Citation: US District Court Indictment GRU Unit 74455 October 2020)
- [S0412] ZxShell: [ZxShell](https://attack.mitre.org/software/S0412) has a feature to perform SYN flood attack on a host.(Citation: FireEye APT41 Aug 2019)(Citation: Talos ZxShell Oct 2014)

#### T1499.001 - OS Exhaustion Flood

Description:

Adversaries may launch a denial of service (DoS) attack targeting an endpoint's operating system (OS). A system's OS is responsible for managing the finite resources as well as preventing the entire system from being overwhelmed by excessive demands on its capacity. These attacks do not need to exhaust the actual resources on a system; the attacks may simply exhaust the limits and available resources that an OS self-imposes.

Different ways to achieve this exist, including TCP state-exhaustion attacks such as SYN floods and ACK floods.(Citation: Arbor AnnualDoSreport Jan 2018) With SYN floods, excessive amounts of SYN packets are sent, but the 3-way TCP handshake is never completed. Because each OS has a maximum number of concurrent TCP connections that it will allow, this can quickly exhaust the ability of the system to receive new requests for TCP connections, thus preventing access to any TCP service provided by the server.(Citation: Cloudflare SynFlood)

ACK floods leverage the stateful nature of the TCP protocol. A flood of ACK packets are sent to the target. This forces the OS to search its state table for a related TCP connection that has already been established. Because the ACK packets are for connections that do not exist, the OS will have to search the entire state table to confirm that no match exists. When it is necessary to do this for a large flood of packets, the computational requirements can cause the server to become sluggish and/or unresponsive, due to the work it must do to eliminate the rogue ACK packets. This greatly reduces the resources available for providing the targeted service.(Citation: Corero SYN-ACKflood)

#### T1499.002 - Service Exhaustion Flood

Description:

Adversaries may target the different network services provided by systems to conduct a denial of service (DoS). Adversaries often target the availability of DNS and web services, however others have been targeted as well.(Citation: Arbor AnnualDoSreport Jan 2018) Web server software can be attacked through a variety of means, some of which apply generally while others are specific to the software being used to provide the service.

One example of this type of attack is known as a simple HTTP flood, where an adversary sends a large number of HTTP requests to a web server to overwhelm it and/or an application that runs on top of it. This flood relies on raw volume to accomplish the objective, exhausting any of the various resources required by the victim software to provide the service.(Citation: Cloudflare HTTPflood)

Another variation, known as a SSL renegotiation attack, takes advantage of a protocol feature in SSL/TLS. The SSL/TLS protocol suite includes mechanisms for the client and server to agree on an encryption algorithm to use for subsequent secure connections. If SSL renegotiation is enabled, a request can be made for renegotiation of the crypto algorithm. In a renegotiation attack, the adversary establishes a SSL/TLS connection and then proceeds to make a series of renegotiation requests. Because the cryptographic renegotiation has a meaningful cost in computation cycles, this can cause an impact to the availability of the service when done in volume.(Citation: Arbor SSLDoS April 2012)

#### T1499.003 - Application Exhaustion Flood

Description:

Adversaries may target resource intensive features of applications to cause a denial of service (DoS), denying availability to those applications. For example, specific features in web applications may be highly resource intensive. Repeated requests to those features may be able to exhaust system resources and deny access to the application or the server itself.(Citation: Arbor AnnualDoSreport Jan 2018)

#### T1499.004 - Application or System Exploitation

Description:

Adversaries may exploit software vulnerabilities that can cause an application or system to crash and deny availability to users. (Citation: Sucuri BIND9 August 2015) Some systems may automatically restart critical applications and services when crashes occur, but they can likely be re-exploited to cause a persistent denial of service (DoS) condition.

Adversaries may exploit known or zero-day vulnerabilities to crash applications and/or systems, which may also lead to dependent applications and/or systems to be in a DoS condition. Crashed or restarted applications or systems may also have other effects such as [Data Destruction](https://attack.mitre.org/techniques/T1485), [Firmware Corruption](https://attack.mitre.org/techniques/T1495), [Service Stop](https://attack.mitre.org/techniques/T1489) etc. which may further cause a DoS condition and deny availability to critical information, applications and/or systems.

Procedures:

- [S0604] Industroyer: [Industroyer](https://attack.mitre.org/software/S0604) uses a custom DoS tool that leverages CVE-2015-5374 and targets hardcoded IP addresses of Siemens SIPROTEC devices.(Citation: ESET Industroyer)


### T1529 - System Shutdown/Reboot

Description:

Adversaries may shutdown/reboot systems to interrupt access to, or aid in the destruction of, those systems. Operating systems may contain commands to initiate a shutdown/reboot of a machine or network device. In some cases, these commands may also be used to initiate a shutdown/reboot of a remote computer or network device via [Network Device CLI](https://attack.mitre.org/techniques/T1059/008) (e.g. <code>reload</code>).(Citation: Microsoft Shutdown Oct 2017)(Citation: alert_TA18_106A) They may also include shutdown/reboot of a virtual machine via hypervisor / cloud consoles or command line tools.

Shutting down or rebooting systems may disrupt access to computer resources for legitimate users while also impeding incident response/recovery.

Adversaries may attempt to shutdown/reboot a system after impacting it in other ways, such as [Disk Structure Wipe](https://attack.mitre.org/techniques/T1561/002) or [Inhibit System Recovery](https://attack.mitre.org/techniques/T1490), to hasten the intended effects on system availability.(Citation: Talos Nyetya June 2017)(Citation: Talos Olympic Destroyer 2018)

Procedures:

- [S1125] AcidRain: [AcidRain](https://attack.mitre.org/software/S1125) reboots the target system once the various wiping processes are complete.(Citation: AcidRain JAGS 2022)
- [S1033] DCSrv: [DCSrv](https://attack.mitre.org/software/S1033) has a function to sleep for two hours before rebooting the system.(Citation: Checkpoint MosesStaff Nov 2021)
- [S1136] BFG Agonizer: [BFG Agonizer](https://attack.mitre.org/software/S1136) uses elevated privileges to call <code>NtRaiseHardError</code> to induce a "blue screen of death" on infected systems, causing a system crash. Once shut down, the system is no longer bootable.(Citation: Unit42 Agrius 2023)
- [S1135] MultiLayer Wiper: [MultiLayer Wiper](https://attack.mitre.org/software/S1135) reboots the infected system following wiping and related tasks to prevent system recovery.(Citation: Unit42 Agrius 2023)
- [S1167] AcidPour: [AcidPour](https://attack.mitre.org/software/S1167) includes functionality to reboot the victim system following wiping actions, similar to [AcidRain](https://attack.mitre.org/software/S1125).(Citation: SentinelOne AcidPour 2024)
- [S0372] LockerGoga: [LockerGoga](https://attack.mitre.org/software/S0372) has been observed shutting down infected systems.(Citation: Wired Lockergoga 2019)
- [S0365] Olympic Destroyer: [Olympic Destroyer](https://attack.mitre.org/software/S0365) will shut down the compromised system after it is done modifying system configuration settings.(Citation: Talos Olympic Destroyer 2018)(Citation: US District Court Indictment GRU Unit 74455 October 2020)
- [G0082] APT38: [APT38](https://attack.mitre.org/groups/G0082) has used a custom MBR wiper named BOOTWRECK, which will initiate a system reboot after wiping the victim's MBR.(Citation: FireEye APT38 Oct 2018)
- [S0449] Maze: [Maze](https://attack.mitre.org/software/S0449) has issued a shutdown command on a victim machine that, upon reboot, will run the ransomware within a VM.(Citation: Sophos Maze VM September 2020)
- [G0067] APT37: [APT37](https://attack.mitre.org/groups/G0067) has used malware that will issue the command <code>shutdown /r /t 1</code> to reboot a system after wiping its MBR.(Citation: Talos Group123)
- [S0582] LookBack: [LookBack](https://attack.mitre.org/software/S0582) can shutdown and reboot the victim machine.(Citation: Proofpoint LookBack Malware Aug 2019)
- [S1133] Apostle: [Apostle](https://attack.mitre.org/software/S1133) reboots the victim machine following wiping and related activity.(Citation: SentinelOne Agrius 2021)
- [S0689] WhisperGate: [WhisperGate](https://attack.mitre.org/software/S0689) can shutdown a compromised host through execution of `ExitWindowsEx` with the `EXW_SHUTDOWN` flag.(Citation: Cisco Ukraine Wipers January 2022)
- [S0607] KillDisk: [KillDisk](https://attack.mitre.org/software/S0607) attempts to reboot the machine by terminating specific processes.(Citation: Trend Micro KillDisk 2)
- [S1207] XLoader: [XLoader](https://attack.mitre.org/software/S1207) can initiate a system reboot or shutdown.(Citation: Google XLoader 2017)
- [S1178] ShrinkLocker: [ShrinkLocker](https://attack.mitre.org/software/S1178) can restart the victim system if it encounters an error during execution, and will forcibly shutdown the system following encryption to lock out victim users.(Citation: Kaspersky ShrinkLocker 2024)
- [S0368] NotPetya: [NotPetya](https://attack.mitre.org/software/S0368) will reboot the system one hour after infection.(Citation: Talos Nyetya June 2017)(Citation: US District Court Indictment GRU Unit 74455 October 2020)
- [S1160] Latrodectus: [Latrodectus](https://attack.mitre.org/software/S1160) has the ability to restart compromised hosts.(Citation: Elastic Latrodectus May 2024)
- [S1149] CHIMNEYSWEEP: [CHIMNEYSWEEP](https://attack.mitre.org/software/S1149) can reboot or shutdown the targeted system or logoff the current user.(Citation: Mandiant ROADSWEEP August 2022)
- [G0032] Lazarus Group: [Lazarus Group](https://attack.mitre.org/groups/G0032) has rebooted systems after destroying files and wiping the MBR on infected systems.(Citation: US-CERT SHARPKNOT June 2018)
- [S0140] Shamoon: [Shamoon](https://attack.mitre.org/software/S0140) will reboot the infected system once the wiping functionality has been completed.(Citation: Unit 42 Shamoon3 2018)(Citation: McAfee Shamoon December 2018)
- [S1111] DarkGate: [DarkGate](https://attack.mitre.org/software/S1111) has used the `shutdown`command to shut down and/or restart the victim system.(Citation: Rapid7 BlackBasta 2024)
- [S1070] Black Basta: [Black Basta](https://attack.mitre.org/software/S1070) has used `ShellExecuteA` to shut down and restart the victim system.(Citation: Trend Micro Black Basta May 2022)
- [S0697] HermeticWiper: [HermeticWiper](https://attack.mitre.org/software/S0697) can initiate a system shutdown.(Citation: SentinelOne Hermetic Wiper February 2022)(Citation: Qualys Hermetic Wiper March 2022)
- [S1053] AvosLocker: [AvosLocker](https://attack.mitre.org/software/S1053)’s Linux variant has terminated ESXi virtual machines.(Citation: Trend Micro AvosLocker Apr 2022)


### T1531 - Account Access Removal

Description:

Adversaries may interrupt availability of system and network resources by inhibiting access to accounts utilized by legitimate users. Accounts may be deleted, locked, or manipulated (ex: changed credentials) to remove access to accounts. Adversaries may also subsequently log off and/or perform a [System Shutdown/Reboot](https://attack.mitre.org/techniques/T1529) to set malicious changes into place.(Citation: CarbonBlack LockerGoga 2019)(Citation: Unit42 LockerGoga 2019)

In Windows, [Net](https://attack.mitre.org/software/S0039) utility, <code>Set-LocalUser</code> and <code>Set-ADAccountPassword</code> [PowerShell](https://attack.mitre.org/techniques/T1059/001) cmdlets may be used by adversaries to modify user accounts. Accounts could also be disabled by Group Policy. In Linux, the <code>passwd</code> utility may be used to change passwords. On ESXi servers, accounts can be removed or modified via esxcli (`system account set`, `system account remove`).

Adversaries who use ransomware or similar attacks may first perform this and other Impact behaviors, such as [Data Destruction](https://attack.mitre.org/techniques/T1485) and [Defacement](https://attack.mitre.org/techniques/T1491), in order to impede incident response/recovery before completing the [Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486) objective.

Procedures:

- [G1024] Akira: [Akira](https://attack.mitre.org/groups/G1024) deletes administrator accounts in victim networks prior to encryption.(Citation: Secureworks GOLD SAHARA)
- [S0576] MegaCortex: [MegaCortex](https://attack.mitre.org/software/S0576) has changed user account passwords and logged users off the system.(Citation: IBM MegaCortex)
- [S0372] LockerGoga: [LockerGoga](https://attack.mitre.org/software/S0372) has been observed changing account passwords and logging off current users.(Citation: CarbonBlack LockerGoga 2019)(Citation: Unit42 LockerGoga 2019)
- [S0688] Meteor: [Meteor](https://attack.mitre.org/software/S0688) has the ability to change the password of local users on compromised hosts and can log off users.(Citation: Check Point Meteor Aug 2021)
- [G1004] LAPSUS$: [LAPSUS$](https://attack.mitre.org/groups/G1004) has removed a targeted organization's global admin accounts to lock the organization out of all access.(Citation: MSTIC DEV-0537 Mar 2022)
- [S1134] DEADWOOD: [DEADWOOD](https://attack.mitre.org/software/S1134) changes the password for local and domain users via <code>net.exe</code> to a random 32 character string to prevent these accounts from logging on. Additionally, [DEADWOOD](https://attack.mitre.org/software/S1134) will terminate the <code>winlogon.exe</code> process to prevent attempts to log on to the infected system.(Citation: SentinelOne Agrius 2021)


### T1561 - Disk Wipe

Description:

Adversaries may wipe or corrupt raw disk data on specific systems or in large numbers in a network to interrupt availability to system and network resources. With direct write access to a disk, adversaries may attempt to overwrite portions of disk data. Adversaries may opt to wipe arbitrary portions of disk data and/or wipe disk structures like the master boot record (MBR). A complete wipe of all disk sectors may be attempted.

To maximize impact on the target organization in operations where network-wide availability interruption is the goal, malware used for wiping disks may have worm-like features to propagate across a network by leveraging additional techniques like [Valid Accounts](https://attack.mitre.org/techniques/T1078), [OS Credential Dumping](https://attack.mitre.org/techniques/T1003), and [SMB/Windows Admin Shares](https://attack.mitre.org/techniques/T1021/002).(Citation: Novetta Blockbuster Destructive Malware)

On network devices, adversaries may wipe configuration files and other data from the device using [Network Device CLI](https://attack.mitre.org/techniques/T1059/008) commands such as `erase`.(Citation: erase_cmd_cisco)

#### T1561.001 - Disk Content Wipe

Description:

Adversaries may erase the contents of storage devices on specific systems or in large numbers in a network to interrupt availability to system and network resources.

Adversaries may partially or completely overwrite the contents of a storage device rendering the data irrecoverable through the storage interface.(Citation: Novetta Blockbuster)(Citation: Novetta Blockbuster Destructive Malware)(Citation: DOJ Lazarus Sony 2018) Instead of wiping specific disk structures or files, adversaries with destructive intent may wipe arbitrary portions of disk content. To wipe disk content, adversaries may acquire direct access to the hard drive in order to overwrite arbitrarily sized portions of disk with random data.(Citation: Novetta Blockbuster Destructive Malware) Adversaries have also been observed leveraging third-party drivers like [RawDisk](https://attack.mitre.org/software/S0364) to directly access disk content.(Citation: Novetta Blockbuster)(Citation: Novetta Blockbuster Destructive Malware) This behavior is distinct from [Data Destruction](https://attack.mitre.org/techniques/T1485) because sections of the disk are erased instead of individual files.

To maximize impact on the target organization in operations where network-wide availability interruption is the goal, malware used for wiping disk content may have worm-like features to propagate across a network by leveraging additional techniques like [Valid Accounts](https://attack.mitre.org/techniques/T1078), [OS Credential Dumping](https://attack.mitre.org/techniques/T1003), and [SMB/Windows Admin Shares](https://attack.mitre.org/techniques/T1021/002).(Citation: Novetta Blockbuster Destructive Malware)

Procedures:

- [S1205] cipher.exe: [cipher.exe](https://attack.mitre.org/software/S1205) can be used to overwrite deleted data in specified folders.(Citation: Nearest Neighbor Volexity)
- [S1134] DEADWOOD: [DEADWOOD](https://attack.mitre.org/software/S1134) deletes files following overwriting them with random data.(Citation: SentinelOne Agrius 2021)
- [S1125] AcidRain: [AcidRain](https://attack.mitre.org/software/S1125) iterates over device file identifiers on the target, opens the device file, and either overwrites the file or calls various IOCTLS commands to erase it.(Citation: AcidRain JAGS 2022)
- [S0689] WhisperGate: [WhisperGate](https://attack.mitre.org/software/S0689) can overwrite sectors of a victim host's hard drive at periodic offsets.(Citation: Crowdstrike WhisperGate January 2022)(Citation: Cisco Ukraine Wipers January 2022)(Citation: Medium S2W WhisperGate January 2022)
- [G0032] Lazarus Group: [Lazarus Group](https://attack.mitre.org/groups/G0032) has used malware like WhiskeyAlfa to overwrite the first 64MB of every drive with a mix of static and random buffers. A similar process is then used to wipe content in logical drives and, finally, attempt to wipe every byte of every sector on every drive. WhiskeyBravo can be used to overwrite the first 4.9MB of physical drives. WhiskeyDelta can overwrite the first 132MB or 1.5MB of each drive with random data from heap memory.(Citation: Novetta Blockbuster Destructive Malware)
- [S0364] RawDisk: [RawDisk](https://attack.mitre.org/software/S0364) has been used to directly access the hard disk to help overwrite arbitrarily sized portions of disk content.(Citation: Novetta Blockbuster Destructive Malware)
- [S0576] MegaCortex: [MegaCortex](https://attack.mitre.org/software/S0576) can wipe deleted data from all drives using <code>[cipher.exe](https://attack.mitre.org/software/S1205)</code>.(Citation: IBM MegaCortex)
- [G0047] Gamaredon Group: [Gamaredon Group](https://attack.mitre.org/groups/G0047) has used tools to delete files and folders from victims' desktops and profiles.(Citation: CERT-EE Gamaredon January 2021)
- [C0051] APT28 Nearest Neighbor Campaign: During [APT28 Nearest Neighbor Campaign](https://attack.mitre.org/campaigns/C0051), [APT28](https://attack.mitre.org/groups/G0007) used the native Microsoft utility [cipher.exe](https://attack.mitre.org/software/S1205) to securely wipe files and folders – overwriting the deleted data using <code>cmd.exe /c cipher /W:C</code>.(Citation: Nearest Neighbor Volexity)
- [S1167] AcidPour: [AcidPour](https://attack.mitre.org/software/S1167) includes functionality to overwrite victim devices with the content of a buffer to wipe disk content.(Citation: SentinelOne AcidPour 2024)
- [S1133] Apostle: [Apostle](https://attack.mitre.org/software/S1133) searches for files on available drives based on a list of extensions hard-coded into the sample for follow-on wipe activity.(Citation: SentinelOne Agrius 2021)
- [S1010] VPNFilter: [VPNFilter](https://attack.mitre.org/software/S1010) has the capability to wipe a portion of an infected device's firmware.(Citation: VPNFilter Router)
- [S0380] StoneDrill: [StoneDrill](https://attack.mitre.org/software/S0380) can wipe the accessible physical or logical drives of the infected machine.(Citation: Symantec Elfin Mar 2019)
- [S0697] HermeticWiper: [HermeticWiper](https://attack.mitre.org/software/S0697) has the ability to corrupt disk partitions and obtain raw disk access to destroy data.(Citation: Crowdstrike DriveSlayer February 2022)(Citation: SentinelOne Hermetic Wiper February 2022)
- [S1068] BlackCat: [BlackCat](https://attack.mitre.org/software/S1068) has the ability to wipe VM snapshots on compromised networks.(Citation: Microsoft BlackCat Jun 2022)(Citation: Sophos BlackCat Jul 2022)
- [S1111] DarkGate: [DarkGate](https://attack.mitre.org/software/S1111) has deleted all files in the Mozilla directory using the following command: `/c del /q /f /s C:\Users\User\AppData\Roaming\Mozilla\firefox*`.(Citation: Rapid7 BlackBasta 2024)

#### T1561.002 - Disk Structure Wipe

Description:

Adversaries may corrupt or wipe the disk data structures on a hard drive necessary to boot a system; targeting specific critical systems or in large numbers in a network to interrupt availability to system and network resources. 

Adversaries may attempt to render the system unable to boot by overwriting critical data located in structures such as the master boot record (MBR) or partition table.(Citation: Symantec Shamoon 2012)(Citation: FireEye Shamoon Nov 2016)(Citation: Palo Alto Shamoon Nov 2016)(Citation: Kaspersky StoneDrill 2017)(Citation: Unit 42 Shamoon3 2018) The data contained in disk structures may include the initial executable code for loading an operating system or the location of the file system partitions on disk. If this information is not present, the computer will not be able to load an operating system during the boot process, leaving the computer unavailable. [Disk Structure Wipe](https://attack.mitre.org/techniques/T1561/002) may be performed in isolation, or along with [Disk Content Wipe](https://attack.mitre.org/techniques/T1561/001) if all sectors of a disk are wiped.

On a network devices, adversaries may reformat the file system using [Network Device CLI](https://attack.mitre.org/techniques/T1059/008) commands such as `format`.(Citation: format_cmd_cisco)

To maximize impact on the target organization, malware designed for destroying disk structures may have worm-like features to propagate across a network by leveraging other techniques like [Valid Accounts](https://attack.mitre.org/techniques/T1078), [OS Credential Dumping](https://attack.mitre.org/techniques/T1003), and [SMB/Windows Admin Shares](https://attack.mitre.org/techniques/T1021/002).(Citation: Symantec Shamoon 2012)(Citation: FireEye Shamoon Nov 2016)(Citation: Palo Alto Shamoon Nov 2016)(Citation: Kaspersky StoneDrill 2017)

Procedures:

- [S0140] Shamoon: [Shamoon](https://attack.mitre.org/software/S0140) has been seen overwriting features of disk structure such as the MBR.(Citation: Symantec Shamoon 2012)(Citation: FireEye Shamoon Nov 2016)(Citation: Palo Alto Shamoon Nov 2016)(Citation: Unit 42 Shamoon3 2018)
- [C0038] HomeLand Justice: During [HomeLand Justice](https://attack.mitre.org/campaigns/C0038), threat actors used a version of [ZeroCleare](https://attack.mitre.org/software/S1151) to wipe disk drives on targeted hosts.(Citation: CISA Iran Albanian Attacks September 2022)(Citation: Microsoft Albanian Government Attacks September 2022)
- [S0697] HermeticWiper: [HermeticWiper](https://attack.mitre.org/software/S0697) has the ability to corrupt disk partitions, damage the Master Boot Record (MBR), and overwrite the Master File Table (MFT) of all available physical drives.(Citation: SentinelOne Hermetic Wiper February 2022)(Citation: Symantec Ukraine Wipers February 2022)(Citation: Crowdstrike DriveSlayer February 2022)(Citation: Qualys Hermetic Wiper March 2022)
- [S0364] RawDisk: [RawDisk](https://attack.mitre.org/software/S0364) was used in [Shamoon](https://attack.mitre.org/software/S0140) to help overwrite components of disk structure like the MBR and disk partitions.(Citation: Palo Alto Shamoon Nov 2016)(Citation: Unit 42 Shamoon3 2018)
- [S1136] BFG Agonizer: [BFG Agonizer](https://attack.mitre.org/software/S1136) retrieves a device handle to <code>\\\\.\\PhysicalDrive0</code> to wipe the boot sector of a given disk.(Citation: Unit42 Agrius 2023)
- [S0689] WhisperGate: [WhisperGate](https://attack.mitre.org/software/S0689) can overwrite the Master Book Record (MBR) on victim systems with a malicious 16-bit bootloader.(Citation: Microsoft WhisperGate January 2022)(Citation: Crowdstrike WhisperGate January 2022)(Citation: Cybereason WhisperGate February 2022)(Citation: Unit 42 WhisperGate January 2022)(Citation: Cisco Ukraine Wipers January 2022)(Citation: Medium S2W WhisperGate January 2022)
- [G0082] APT38: [APT38](https://attack.mitre.org/groups/G0082) has used a custom MBR wiper named BOOTWRECK to render systems inoperable.(Citation: FireEye APT38 Oct 2018)
- [G0034] Sandworm Team: [Sandworm Team](https://attack.mitre.org/groups/G0034) has used the [BlackEnergy](https://attack.mitre.org/software/S0089) KillDisk component to corrupt the infected system's master boot record.(Citation: US-CERT Ukraine Feb 2016)(Citation: ESET Telebots June 2017)
- [G0032] Lazarus Group: [Lazarus Group](https://attack.mitre.org/groups/G0032) malware SHARPKNOT overwrites and deletes the Master Boot Record (MBR) on the victim's machine and has possessed MBR wiper malware since at least 2009.(Citation: US-CERT SHARPKNOT June 2018)(Citation: Novetta Blockbuster)
- [S0607] KillDisk: [KillDisk](https://attack.mitre.org/software/S0607) overwrites the first sector of the Master Boot Record with “0x00”.(Citation: Trend Micro KillDisk 1)
- [S0380] StoneDrill: [StoneDrill](https://attack.mitre.org/software/S0380) can wipe the master boot record of an infected computer.(Citation: Symantec Elfin Mar 2019)
- [G1003] Ember Bear: [Ember Bear](https://attack.mitre.org/groups/G1003) conducted destructive operations against victims, including disk structure wiping, via the [WhisperGate](https://attack.mitre.org/software/S0689) malware in Ukraine.(Citation: Cadet Blizzard emerges as novel threat actor)
- [S1135] MultiLayer Wiper: [MultiLayer Wiper](https://attack.mitre.org/software/S1135) opens a handle to <code>\\\\\\\\.\\\\PhysicalDrive0</code> and wipes the first 512 bytes of data from this location, removing the boot sector.(Citation: Unit42 Agrius 2023)
- [S1134] DEADWOOD: [DEADWOOD](https://attack.mitre.org/software/S1134) opens and writes zeroes to the first 512 bytes of each drive, deleting the MBR. [DEADWOOD](https://attack.mitre.org/software/S1134) then sends the control code <code>IOCTL_DISK_DELETE_DRIVE_LAYOUT</code> to ensure the MBR is removed from the drive.(Citation: SentinelOne Agrius 2021)
- [S1151] ZeroCleare: [ZeroCleare](https://attack.mitre.org/software/S1151) can corrupt the file system and wipe the system drive on targeted hosts.(Citation: Mandiant ROADSWEEP August 2022)(Citation: CISA Iran Albanian Attacks September 2022)(Citation: IBM ZeroCleare Wiper December 2019)
- [S0693] CaddyWiper: [CaddyWiper](https://attack.mitre.org/software/S0693) has the ability to destroy information about a physical drive's partitions including the MBR, GPT, and partition entries.(Citation: ESET CaddyWiper March 2022)(Citation: Cisco CaddyWiper March 2022)
- [G0067] APT37: [APT37](https://attack.mitre.org/groups/G0067) has access to destructive malware that is capable of overwriting a machine's Master Boot Record (MBR).(Citation: FireEye APT37 Feb 2018)(Citation: Talos Group123)


### T1565 - Data Manipulation

Description:

Adversaries may insert, delete, or manipulate data in order to influence external outcomes or hide activity, thus threatening the integrity of the data.(Citation: Sygnia Elephant Beetle Jan 2022) By manipulating data, adversaries may attempt to affect a business process, organizational understanding, or decision making.

The type of modification and the impact it will have depends on the target application and process as well as the goals and objectives of the adversary. For complex systems, an adversary would likely need special expertise and possibly access to specialized software related to the system that would typically be gained through a prolonged information gathering campaign in order to have the desired impact.

Procedures:

- [G1016] FIN13: [FIN13](https://attack.mitre.org/groups/G1016) has injected fraudulent transactions into compromised networks that mimic legitimate behavior to siphon off incremental amounts of money.(Citation: Sygnia Elephant Beetle Jan 2022)

#### T1565.001 - Stored Data Manipulation

Description:

Adversaries may insert, delete, or manipulate data at rest in order to influence external outcomes or hide activity, thus threatening the integrity of the data.(Citation: FireEye APT38 Oct 2018)(Citation: DOJ Lazarus Sony 2018) By manipulating stored data, adversaries may attempt to affect a business process, organizational understanding, and decision making.

Stored data could include a variety of file formats, such as Office files, databases, stored emails, and custom file formats. The type of modification and the impact it will have depends on the type of data as well as the goals and objectives of the adversary. For complex systems, an adversary would likely need special expertise and possibly access to specialized software related to the system that would typically be gained through a prolonged information gathering campaign in order to have the desired impact.

Procedures:

- [S0562] SUNSPOT: [SUNSPOT](https://attack.mitre.org/software/S0562) created a copy of the SolarWinds Orion software source file with a <code>.bk</code> extension to backup the original content, wrote [SUNBURST](https://attack.mitre.org/software/S0559) using the same filename but with a <code>.tmp</code> extension, and then moved [SUNBURST](https://attack.mitre.org/software/S0559) using <code>MoveFileEx</code> to the original filename with a <code>.cs</code> extension so it could be compiled within Orion software.(Citation: CrowdStrike SUNSPOT Implant January 2021)
- [S1135] MultiLayer Wiper: [MultiLayer Wiper](https://attack.mitre.org/software/S1135) changes the original path information of deleted files to make recovery efforts more difficult.(Citation: Unit42 Agrius 2023)
- [G0082] APT38: [APT38](https://attack.mitre.org/groups/G0082) has used DYEPACK to create, delete, and alter records in databases used for SWIFT transactions.(Citation: FireEye APT38 Oct 2018)

#### T1565.002 - Transmitted Data Manipulation

Description:

Adversaries may alter data en route to storage or other systems in order to manipulate external outcomes or hide activity, thus threatening the integrity of the data.(Citation: FireEye APT38 Oct 2018)(Citation: DOJ Lazarus Sony 2018) By manipulating transmitted data, adversaries may attempt to affect a business process, organizational understanding, and decision making.

Manipulation may be possible over a network connection or between system processes where there is an opportunity deploy a tool that will intercept and change information. The type of modification and the impact it will have depends on the target transmission mechanism as well as the goals and objectives of the adversary. For complex systems, an adversary would likely need special expertise and possibly access to specialized software related to the system that would typically be gained through a prolonged information gathering campaign in order to have the desired impact.

Procedures:

- [S0530] Melcoz: [Melcoz](https://attack.mitre.org/software/S0530) can monitor the clipboard for cryptocurrency addresses and change the intended address to one controlled by the adversary.(Citation: Securelist Brazilian Banking Malware July 2020)
- [G0082] APT38: [APT38](https://attack.mitre.org/groups/G0082) has used DYEPACK to manipulate SWIFT messages en route to a printer.(Citation: FireEye APT38 Oct 2018)
- [S0395] LightNeuron: [LightNeuron](https://attack.mitre.org/software/S0395) is capable of modifying email content, headers, and attachments during transit.(Citation: ESET LightNeuron May 2019)
- [S0455] Metamorfo: [Metamorfo](https://attack.mitre.org/software/S0455) has a function that can watch the contents of the system clipboard for valid bitcoin addresses, which it then overwrites with the attacker's address.(Citation: Fortinet Metamorfo Feb 2020)(Citation: ESET Casbaneiro Oct 2019)

#### T1565.003 - Runtime Data Manipulation

Description:

Adversaries may modify systems in order to manipulate the data as it is accessed and displayed to an end user, thus threatening the integrity of the data.(Citation: FireEye APT38 Oct 2018)(Citation: DOJ Lazarus Sony 2018) By manipulating runtime data, adversaries may attempt to affect a business process, organizational understanding, and decision making.

Adversaries may alter application binaries used to display data in order to cause runtime manipulations. Adversaries may also conduct [Change Default File Association](https://attack.mitre.org/techniques/T1546/001) and [Masquerading](https://attack.mitre.org/techniques/T1036) to cause a similar effect. The type of modification and the impact it will have depends on the target application and process as well as the goals and objectives of the adversary. For complex systems, an adversary would likely need special expertise and possibly access to specialized software related to the system that would typically be gained through a prolonged information gathering campaign in order to have the desired impact.

Procedures:

- [G0082] APT38: [APT38](https://attack.mitre.org/groups/G0082) has used DYEPACK.FOX to manipulate PDF data as it is accessed to remove traces of fraudulent SWIFT transactions from the data displayed to the end user.(Citation: FireEye APT38 Oct 2018)


### T1657 - Financial Theft

Description:

Adversaries may steal monetary resources from targets through extortion, social engineering, technical theft, or other methods aimed at their own financial gain at the expense of the availability of these resources for victims. Financial theft is the ultimate objective of several popular campaign types including extortion by ransomware,(Citation: FBI-ransomware) business email compromise (BEC) and fraud,(Citation: FBI-BEC) "pig butchering,"(Citation: wired-pig butchering) bank hacking,(Citation: DOJ-DPRK Heist) and exploiting cryptocurrency networks.(Citation: BBC-Ronin) 

Adversaries may [Compromise Accounts](https://attack.mitre.org/techniques/T1586) to conduct unauthorized transfers of funds.(Citation: Internet crime report 2022) In the case of business email compromise or email fraud, an adversary may utilize [Impersonation](https://attack.mitre.org/techniques/T1656) of a trusted entity. Once the social engineering is successful, victims can be deceived into sending money to financial accounts controlled by an adversary.(Citation: FBI-BEC) This creates the potential for multiple victims (i.e., compromised accounts as well as the ultimate monetary loss) in incidents involving financial theft.(Citation: VEC)

Extortion by ransomware may occur, for example, when an adversary demands payment from a victim after [Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486) (Citation: NYT-Colonial) and [Exfiltration](https://attack.mitre.org/tactics/TA0010) of data, followed by threatening to leak sensitive data to the public unless payment is made to the adversary.(Citation: Mandiant-leaks) Adversaries may use dedicated leak sites to distribute victim data.(Citation: Crowdstrike-leaks)

Due to the potentially immense business impact of financial theft, an adversary may abuse the possibility of financial theft and seeking monetary gain to divert attention from their true goals such as [Data Destruction](https://attack.mitre.org/techniques/T1485) and business disruption.(Citation: AP-NotPetya)

Procedures:

- [G1032] INC Ransom: [INC Ransom](https://attack.mitre.org/groups/G1032) has stolen and encrypted victim's data in order to extort payment for keeping it private or decrypting it.(Citation: Cybereason INC Ransomware November 2023)(Citation: Bleeping Computer INC Ransomware March 2024)(Citation: Secureworks GOLD IONIC April 2024)(Citation: SOCRadar INC Ransom January 2024)(Citation: SentinelOne INC Ransomware)
- [G1021] Cinnamon Tempest: [Cinnamon Tempest](https://attack.mitre.org/groups/G1021) has maintained leak sites for exfiltrated data in attempt to extort victims into paying a ransom.(Citation: Microsoft Ransomware as a Service)
- [G1026] Malteiro: [Malteiro](https://attack.mitre.org/groups/G1026) targets organizations in a wide variety of sectors via the use of [Mispadu](https://attack.mitre.org/software/S1122) banking trojan with the goal of financial theft.(Citation: SCILabs Malteiro 2021)
- [G0094] Kimsuky: [Kimsuky](https://attack.mitre.org/groups/G0094) has stolen and laundered cryptocurrency to self-fund operations including the acquisition of infrastructure.(Citation: Mandiant APT43 March 2024)(Citation: Mandiant APT43 Full PDF Report)
- [G1016] FIN13: [FIN13](https://attack.mitre.org/groups/G1016) has observed the victim's software and infrastructure over several months to understand the technical process of legitimate financial transactions, prior to attempting to conduct fraudulent transactions.(Citation: Sygnia Elephant Beetle Jan 2022)
- [G1024] Akira: [Akira](https://attack.mitre.org/groups/G1024) engages in double-extortion ransomware, exfiltrating files then encrypting them, in order to prompt victims to pay a ransom.(Citation: BushidoToken Akira 2023)(Citation: CISA Akira Ransomware APR 2024)
- [G1015] Scattered Spider: [Scattered Spider](https://attack.mitre.org/groups/G1015) has deployed ransomware on compromised hosts for financial gain.(Citation: CISA Scattered Spider Advisory November 2023)(Citation: Trellix Scattered Spider MO August 2023)
- [S1111] DarkGate: [DarkGate](https://attack.mitre.org/software/S1111) can deploy payloads capable of capturing credentials related to cryptocurrency wallets.(Citation: Ensilo Darkgate 2018)
- [G0083] SilverTerrier: [SilverTerrier](https://attack.mitre.org/groups/G0083) targets organizations in high technology, higher education, and manufacturing for business email compromise (BEC) campaigns with the goal of financial theft.(Citation: Unit42 SilverTerrier 2018)(Citation: Unit42 SilverTerrier 2016)
- [G1040] Play: [Play](https://attack.mitre.org/groups/G1040) demands ransom payments from victims to unencrypt filesystems and to not publish sensitive data exfiltrated from victim networks.(Citation: CISA Play Ransomware Advisory December 2023)


### T1667 - Email Bombing

Description:

Adversaries may flood targeted email addresses with an overwhelming volume of messages. This may bury legitimate emails in a flood of spam and disrupt business operations.(Citation: sophos-bombing)(Citation: krebs-email-bombing)

An adversary may accomplish email bombing by leveraging an automated bot to register a targeted address for e-mail lists that do not validate new signups, such as online newsletters. The result can be a wave of thousands of e-mails that effectively overloads the victim’s inbox.(Citation: krebs-email-bombing)(Citation: hhs-email-bombing)

By sending hundreds or thousands of e-mails in quick succession, adversaries may successfully divert attention away from and bury legitimate messages including security alerts, daily business processes like help desk tickets and client correspondence, or ongoing scams.(Citation: hhs-email-bombing) This behavior can also be used as a tool of harassment.(Citation: krebs-email-bombing)

This behavior may be a precursor for [Spearphishing Voice](https://attack.mitre.org/techniques/T1566/004). For example, an adversary may email bomb a target and then follow up with a phone call to fraudulently offer assistance. This social engineering may lead to the use of [Remote Access Software](https://attack.mitre.org/techniques/T1663) to steal credentials, deploy ransomware, conduct [Financial Theft](https://attack.mitre.org/techniques/T1657)(Citation: sophos-bombing), or engage in other malicious activity.(Citation: rapid7-email-bombing)

Procedures:

- [G1046] Storm-1811: [Storm-1811](https://attack.mitre.org/groups/G1046) has deployed large volumes of non-malicious email spam to victims in order to prompt follow-on interactions with the threat actor posing as IT support or helpdesk to resolve the problem.(Citation: rapid7-email-bombing)(Citation: RedCanary Storm-1811 2024)

