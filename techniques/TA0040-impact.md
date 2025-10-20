### T1485.001 - Data Destruction: Lifecycle-Triggered Deletion

Description:

Adversaries may modify the lifecycle policies of a cloud storage bucket to destroy all objects stored within. Cloud storage buckets often allow users to set lifecycle policies to automate the migration, archival, or deletion of objects after a set period of time. If a threat actor has sufficient permissions to modify these policies, they may be able to delete all objects at once. For example, in AWS environments, an adversary with the `PutLifecycleConfiguration` permission may use the `PutBucketLifecycle` API call to apply a lifecycle policy to an S3 bucket that deletes all objects in the bucket after one day. In addition to destroying data for purposes of extortion and Financial Theft, adversaries may also perform this action on buckets storing cloud logs for Indicator Removal.


### T1486 - Data Encrypted for Impact

Description:

Adversaries may encrypt data on target systems or on large numbers of systems in a network to interrupt availability to system and network resources. They can attempt to render stored data inaccessible by encrypting files or data on local and remote drives and withholding access to a decryption key. This may be done in order to extract monetary compensation from a victim in exchange for decryption or a decryption key (ransomware) or to render data permanently inaccessible in cases where the key is not saved or transmitted. In the case of ransomware, it is typical that common user files like Office documents, PDFs, images, videos, audio, text, and source code files will be encrypted (and often renamed and/or tagged with specific file markers). Adversaries may need to first employ other behaviors, such as File and Directory Permissions Modification or System Shutdown/Reboot, in order to unlock and/or gain access to manipulate these files. In some cases, adversaries may encrypt critical system files, disk partitions, and the MBR. Adversaries may also encrypt virtual machines hosted on ESXi or other hypervisors. To maximize impact on the target organization, malware designed for encrypting data may have worm-like features to propagate across a network by leveraging other attack techniques like Valid Accounts, OS Credential Dumping, and SMB/Windows Admin Shares. Encryption malware may also leverage Internal Defacement, such as changing victim wallpapers or ESXi server login messages, or otherwise intimidate victims by sending ransom notes or other messages to connected printers (known as "print bombing"). In cloud environments, storage objects within compromised accounts may also be encrypted. For example, in AWS environments, adversaries may leverage services such as AWS’s Server-Side Encryption with Customer Provided Keys (SSE-C) to encrypt data.

Detection:

Use process monitoring to monitor the execution and command line parameters of binaries involved in data destruction activity, such as vssadmin, wbadmin, and bcdedit. Monitor for the creation of suspicious files as well as unusual file modification activity. In particular, look for large quantities of file modifications in user directories. In some cases, monitoring for unusual kernel driver installation activity can aid in detection. In cloud environments, monitor for events that indicate storage objects have been anomalously replaced by copies.

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
- [S1162] Playcrypt: Playcrypt encrypts files on targeted hosts with an AES-RSA hybrid encryption, encrypting every other file portion of 0x100000 bytes.
- [S1111] DarkGate: DarkGate can deploy follow-on ransomware payloads.
- [S1068] BlackCat: BlackCat has the ability to encrypt Windows devices, Linux devices, and VMWare instances.
- [S1058] Prestige: Prestige has leveraged the CryptoPP C++ library to encrypt files on target systems using AES and appended filenames with `.enc`.
- [G0059] Magic Hound: Magic Hound has used BitLocker and DiskCryptor to encrypt targeted workstations.
- [S0372] LockerGoga: LockerGoga has encrypted files, including core Windows OS files, using RSA-OAEP MGF1 and then demanded Bitcoin be paid for the decryption key.
- [S0616] DEATHRANSOM: DEATHRANSOM can use public and private key pair encryption to encrypt files for ransom payment.
- [S0605] EKANS: EKANS uses standard encryption library functions to encrypt files.
- [S0654] ProLock: ProLock can encrypt files on a compromised host with RC6, and encrypts the key with RSA-1024.
- [S1053] AvosLocker: AvosLocker has encrypted files and network resources using AES-256 and added an `.avos`, `.avos2`, or `.AvosLinux` extension to filenames.
- [S0617] HELLOKITTY: HELLOKITTY can use an embedded RSA-2048 public key to encrypt victim data for ransom.
- [G1015] Scattered Spider: Scattered Spider has used BlackCat ransomware to encrypt files on VMWare ESXi servers.
- [S0570] BitPaymer: BitPaymer can import a hard-coded RSA 1024-bit public key, generate a 128-bit RC4 key for each file, and encrypt the file in place, appending .locked to the filename.
- [S1096] Cheerscrypt: Cheerscrypt can encrypt data on victim machines using a Sosemanuk stream cipher with an Elliptic-curve Diffie–Hellman (ECDH) generated key.
- [S1181] BlackByte 2.0 Ransomware: BlackByte 2.0 Ransomware is a ransomware variant associated with BlackByte operations.
- [S0366] WannaCry: WannaCry encrypts user files and demands that a ransom be paid in Bitcoin to decrypt those files.
- [G0046] FIN7: FIN7 has encrypted virtual disk volumes on ESXi servers using a version of Darkside ransomware.
- [S1150] ROADSWEEP: ROADSWEEP can RC4 encrypt content in blocks on targeted systems.
- [S1033] DCSrv: DCSrv has encrypted drives using the core encryption mechanism from DiskCryptor.
- [S1070] Black Basta: Black Basta can encrypt files with the ChaCha20 cypher and using a multithreaded process to increase speed. Black Basta has also encrypted files while the victim system is in safe mode, appending `.basta` upon completion.
- [S0612] WastedLocker: WastedLocker can encrypt data and leave a ransom note.
- [C0018] C0018: During C0018, the threat actors used AvosLocker ransomware to encrypt files on the compromised network.
- [S0583] Pysa: Pysa has used RSA and AES-CBC encryption algorithm to encrypt a list of targeted file extensions.
- [S1178] ShrinkLocker: ShrinkLocker uses the legitimate BitLocker application to encrypt victim files for ransom.
- [S1139] INC Ransomware: INC Ransomware can encrypt data on victim systems, including through the use of partial encryption and multi-threading to speed encryption.
- [C0015] C0015: During C0015, the threat actors used Conti ransomware to encrypt a compromised network.
- [S0576] MegaCortex: MegaCortex has used the open-source library, Mbed Crypto, and generated AES keys to carry out the file encryption process.
- [S0242] SynAck: SynAck encrypts the victims machine followed by asking the victim to pay a ransom.
- [S0618] FIVEHANDS: FIVEHANDS can use an embedded NTRU public key to encrypt data for ransom.
- [S0575] Conti: Conti can use CreateIoCompletionPort(), PostQueuedCompletionStatus(), and GetQueuedCompletionPort() to rapidly encrypt files, excluding those with the extensions of .exe, .dll, and .lnk. It has used a different AES-256 encryption key per file with a bundled RAS-4096 public encryption key that is unique for each victim. Conti can use “Windows Restart Manager” to ensure files are unlocked and open for encryption.
- [S0341] Xbash: Xbash has maliciously encrypted victim's database systems and demanded a cryptocurrency ransom be paid.
- [S0556] Pay2Key: Pay2Key can encrypt data on victim's machines using RSA and AES algorithms in order to extort a ransom payment for decryption.
- [G0034] Sandworm Team: Sandworm Team has used Prestige ransomware to encrypt data at targeted organizations in transportation and related logistics industries in Ukraine and Poland.
- [G1024] Akira: Akira encrypts files in victim environments as part of ransomware operations.
- [G1046] Storm-1811: Storm-1811 is a financially-motivated entity linked to the deployment of Black Basta ransomware in victim environments.
- [S1212] RansomHub: RansomHub can use Elliptic Curve Encryption to encrypt files on targeted systems. RansomHub can also skip content at regular intervals (ex. encrypt 1 MB, skip 3 MB) to optomize performance and enable faster encryption for large files.
- [S0554] Egregor: Egregor can encrypt all non-system files using a hybrid AES-RSA algorithm prior to displaying a ransom note.
- [G0119] Indrik Spider: Indrik Spider has encrypted domain-controlled systems using BitPaymer. Additionally, Indrik Spider used PsExec to execute a ransomware script.
- [S0368] NotPetya: NotPetya encrypts user files and disk structures like the MBR with 2048-bit RSA.
- [S0370] SamSam: SamSam encrypts victim files using RSA-2048 encryption and demands a ransom be paid in Bitcoin to decrypt those files.
- [G0096] APT41: APT41 used a ransomware called Encryptor RaaS to encrypt files on the targeted systems and provide a ransom note to the user. APT41 also used Microsoft Bitlocker to encrypt workstations and Jetico’s BestCrypt to encrypt servers.
- [S0446] Ryuk: Ryuk has used a combination of symmetric (AES) and asymmetric (RSA) encryption to encrypt files. Files have been encrypted with their own AES key and given a file extension of .RYK. Encrypted directories have had a ransom note of RyukReadMe.txt written to the directory.
- [S1194] Akira _v2: The Akira _v2 encryptor targets the `/vmfs/volumes/` path by default and can use the rust-crypto 0.2.36 library crate for the encryption processes.
- [S0640] Avaddon: Avaddon encrypts the victim system using a combination of AES256 and RSA encryption schemes.
- [S0457] Netwalker: Netwalker can encrypt files on infected machines to extort victims.
- [S0607] KillDisk: KillDisk has a ransomware component that encrypts files with an AES key that is also RSA-1028 encrypted.
- [S0611] Clop: Clop can encrypt files using AES, RSA, and RC4 and will add the ".clop" extension to encrypted files.
- [G0092] TA505: TA505 has used a wide variety of ransomware, such as Clop, Locky, Jaff, Bart, Philadelphia, and GlobeImposter, to encrypt victim files and demand a ransom payment.
- [S0658] XCSSET: XCSSET performs AES-CBC encryption on files under ~/Documents, ~/Downloads, and ~/Desktop with a fixed key and renames files to give them a .enc extension. Only files with sizes less than 500MB are encrypted.
- [S0639] Seth-Locker: Seth-Locker can encrypt files on a targeted system, appending them with the suffix .seth.
- [S0140] Shamoon: Shamoon has an operational mode for encrypting data instead of overwriting it.
- [S1202] LockBit 3.0: LockBit 3.0 can encrypt targeted data using the AES-256, ChaCha20, or RSA-2048 algorithms.
- [S1199] LockBit 2.0: LockBit 2.0 can use standard AES and elliptic-curve cryptography algorithms to encrypt victim data.
- [S1133] Apostle: Apostle creates new, encrypted versions of files then deletes the originals, with the new filenames consisting of a random GUID and ".lock" for an extension.
- [G1043] BlackByte: BlackByte has encrypted victim files for ransom. Early versions of BlackByte ransomware used a common key for encryption, but later versions use unique keys per victim.
- [S0400] RobbinHood: RobbinHood will search for an RSA encryption key and then perform its encryption process on the system files.
- [S1191] Megazord: Megazord can encrypt files on targeted Windows hosts leaving them with a ".powerranges" file extension.
- [G0061] FIN8: FIN8 has deployed ransomware such as Ragnar Locker, White Rabbit, and attempted to execute Noberus on compromised networks.
- [G1036] Moonstone Sleet: Moonstone Sleet has deployed ransomware in victim environments.
- [S1129] Akira: Akira can encrypt victim filesystems for financial extortion purposes including through the use of the ChaCha20 and ChaCha8 stream ciphers.


### T1489 - Service Stop

Description:

Adversaries may stop or disable services on a system to render those services unavailable to legitimate users. Stopping critical services or processes can inhibit or stop response to an incident or aid in the adversary's overall objectives to cause damage to the environment. Adversaries may accomplish this by disabling individual services of high importance to an organization, such as MSExchangeIS, which will make Exchange content inaccessible. In some cases, adversaries may stop or disable many or all services to render systems unusable. Services or processes may not allow for modification of their data stores while running. Adversaries may stop services or processes in order to conduct Data Destruction or Data Encrypted for Impact on the data stores of services like Exchange and SQL Server, or on virtual machines hosted on ESXi infrastructure.

Detection:

Monitor processes and command-line arguments to see if critical processes are terminated or stop running. Monitor for edits for modifications to services and startup programs that correspond to services of high importance. Look for changes to services that do not correlate with known software, patch cycles, etc. Windows service information is stored in the Registry at HKLM\SYSTEM\CurrentControlSet\Services. Systemd service unit files are stored within the /etc/systemd/system, /usr/lib/systemd/system/, and /home/.config/systemd/user/ directories, as well as associated symbolic links. Alterations to the service binary path or the service startup type changed to disabled may be suspicious. Remote access tools with built-in features may interact directly with the Windows API to perform these functions outside of typical system utilities. For example, ChangeServiceConfigW may be used by an adversary to prevent services from starting.

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
- [S1199] LockBit 2.0: LockBit 2.0 can automatically terminate processes that may interfere with the encryption or file extraction processes.
- [S1191] Megazord: Megazord has the ability to terminate a list of services and processes.
- [S0638] Babuk: Babuk can stop specific services related to backups.
- [S0496] REvil: REvil has the capability to stop services and kill processes.
- [S0575] Conti: Conti can stop up to 146 Windows services related to security, backup, database, and email solutions through the use of net stop.
- [S0446] Ryuk: Ryuk has called kill.bat for stopping services, disabling services and killing processes.
- [S0625] Cuba: Cuba has a hardcoded list of services and processes to terminate.
- [G0034] Sandworm Team: Sandworm Team attempts to stop the MSSQL Windows service to ensure successful encryption of locked files.
- [G1004] LAPSUS$: LAPSUS$ has shut down virtual machines from within a victim's on-premise VMware ESXi infrastructure.
- [S0576] MegaCortex: MegaCortex can stop and disable services on the system.
- [S0604] Industroyer: Industroyer’s data wiper module writes zeros into the registry keys in SYSTEM\CurrentControlSet\Services to render a system inoperable.
- [S0607] KillDisk: KillDisk terminates various processes to get the user to reboot the victim machine.
- [S0481] Ragnar Locker: Ragnar Locker has attempted to stop services associated with business applications and databases to release the lock on files used by these applications so they may be encrypted.
- [S0533] SLOTHFULMEDIA: SLOTHFULMEDIA has the capability to stop processes and services.
- [S0431] HotCroissant: HotCroissant has the ability to stop services on the infected host.
- [S1181] BlackByte 2.0 Ransomware: BlackByte 2.0 Ransomware can terminate running services.
- [S0605] EKANS: EKANS stops database, data backup solution, antivirus, and ICS-related processes.
- [S1053] AvosLocker: AvosLocker has terminated specific processes before encryption.
- [S1202] LockBit 3.0: LockBit 3.0 can terminate targeted processes and services related to security, backup, database management, and other applications that could stop or interfere with encryption.
- [S1150] ROADSWEEP: ROADSWEEP can disable critical services and processes.
- [G0102] Wizard Spider: Wizard Spider has used taskkill.exe and net.exe to stop backup, catalog, cloud, and other services prior to network encryption.
- [S0583] Pysa: Pysa can stop services and processes.
- [S0697] HermeticWiper: HermeticWiper has the ability to stop the Volume Shadow Copy service.
- [S0449] Maze: Maze has stopped SQL services to ensure it can encrypt any database.
- [G0119] Indrik Spider: Indrik Spider has used PsExec to stop services prior to the execution of ransomware.
- [S0457] Netwalker: Netwalker can terminate system processes and services, some of which relate to backup software.
- [S1139] INC Ransomware: INC Ransomware can issue a command to kill a process on compromised hosts.
- [S1212] RansomHub: RansomHub has the ability to terminate specified services.
- [S1194] Akira _v2: Akira _v2 can stop running virtual machines.


### T1490 - Inhibit System Recovery

Description:

Adversaries may delete or remove built-in data and turn off services designed to aid in the recovery of a corrupted system to prevent recovery. This may deny access to available backups and recovery options. Operating systems may contain features that can help fix corrupted systems, such as a backup catalog, volume shadow copies, and automatic repair features. Adversaries may disable or delete system recovery features to augment the effects of Data Destruction and Data Encrypted for Impact. Furthermore, adversaries may disable recovery notifications, then corrupt backups. A number of native Windows utilities have been used by adversaries to disable or delete system recovery features: * vssadmin.exe can be used to delete all volume shadow copies on a system - vssadmin.exe delete shadows /all /quiet * Windows Management Instrumentation can be used to delete volume shadow copies - wmic shadowcopy delete * wbadmin.exe can be used to delete the Windows Backup Catalog - wbadmin.exe delete catalog -quiet * bcdedit.exe can be used to disable automatic Windows recovery features by modifying boot configuration data - bcdedit.exe /set {default} bootstatuspolicy ignoreallfailures & bcdedit /set {default} recoveryenabled no * REAgentC.exe can be used to disable Windows Recovery Environment (WinRE) repair/recovery options of an infected system * diskshadow.exe can be used to delete all volume shadow copies on a system - diskshadow delete shadows all On network devices, adversaries may leverage Disk Wipe to delete backup firmware images and reformat the file system, then System Shutdown/Reboot to reload the device. Together this activity may leave network devices completely inoperable and inhibit recovery operations. On ESXi servers, adversaries may delete or encrypt snapshots of virtual machines to support Data Encrypted for Impact, preventing them from being leveraged as backups (e.g., via ` vim-cmd vmsvc/snapshot.removeall`). Adversaries may also delete “online” backups that are connected to their network – whether via network storage media or through folders that sync to cloud services. In cloud environments, adversaries may disable versioning and backup policies and delete snapshots, database backups, machine images, and prior versions of objects designed to be used in disaster recovery scenarios.

Detection:

Use process monitoring to monitor the execution and command line parameters of binaries involved in inhibiting system recovery, such as vssadmin, wbadmin, bcdedit, REAgentC, and diskshadow. The Windows event logs, ex. Event ID 524 indicating a system catalog was deleted, may contain entries associated with suspicious activity. Monitor the status of services involved in system recovery. Monitor the registry for changes associated with system recovery features (ex: the creation of HKEY_CURRENT_USER\Software\Policies\Microsoft\PreviousVersions\DisableLocalPage). For network infrastructure devices, collect AAA logging to monitor for `erase`, `format`, and `reload` commands being run in succession.

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
- [S0640] Avaddon: Avaddon deletes backups and shadow copies using native system tools.
- [S1058] Prestige: Prestige can delete the backup catalog from the target system using: `c:\Windows\System32\wbadmin.exe delete catalog -quiet` and can also delete volume shadow copies using: `\Windows\System32\vssadmin.exe delete shadows /all /quiet`.
- [S1111] DarkGate: DarkGate can delete system restore points through the command cmd.exe /c vssadmin delete shadows /for=c: /all /quiet”.
- [S0697] HermeticWiper: HermeticWiper can disable the VSS service on a compromised host using the service control manager.
- [S0366] WannaCry: WannaCry uses vssadmin, wbadmin, bcdedit, and wmic to delete and disable operating system recovery features.
- [G0102] Wizard Spider: Wizard Spider has used WMIC and vssadmin to manually delete volume shadow copies. Wizard Spider has also used Conti ransomware to delete volume shadow copies automatically with the use of vssadmin.
- [S0638] Babuk: Babuk has the ability to delete shadow volumes using vssadmin.exe delete shadows /all /quiet.
- [S0570] BitPaymer: BitPaymer attempts to remove the backup shadow files from the host using vssadmin.exe Delete Shadows /All /Quiet.
- [S1180] BlackByte Ransomware: BlackByte Ransomware deletes all volume shadow copies and restore points among other actions to inhibit system recovery following ransomware deployment.
- [S0617] HELLOKITTY: HELLOKITTY can delete volume shadow copies on compromised hosts.
- [S0457] Netwalker: Netwalker can delete the infected system's Shadow Volumes to prevent recovery.
- [G1043] BlackByte: BlackByte resized and deleted volume shadow copy files to prevent system recovery after encryption.
- [S1212] RansomHub: RansomHub has used `vssadmin.exe` to delete volume shadow copies.
- [S0618] FIVEHANDS: FIVEHANDS has the ability to delete volume shadow copies on compromised hosts.
- [S0575] Conti: Conti can delete Windows Volume Shadow Copies using vssadmin.
- [S1129] Akira: Akira will delete system volume shadow copies via PowerShell commands.
- [S0611] Clop: Clop can delete the shadow volumes with vssadmin Delete Shadows /all /quiet and can use bcdedit to disable recovery options.
- [S1135] MultiLayer Wiper: MultiLayer Wiper wipes the boot sector of infected systems to inhibit system recovery.
- [S0688] Meteor: Meteor can use `bcdedit` to delete different boot identifiers on a compromised host; it can also use `vssadmin.exe delete shadows /all /quiet` and `C:\\Windows\\system32\\wbem\\wmic.exe shadowcopy delete`.
- [S0583] Pysa: Pysa has the functionality to delete shadow copies.
- [G0034] Sandworm Team: Sandworm Team uses Prestige to delete the backup catalog from the target system using: `C:\Windows\System32\wbadmin.exe delete catalog -quiet` and to delete volume shadow copies using: `C:\Windows\System32\vssadmin.exe delete shadows /all /quiet`.
- [S0608] Conficker: Conficker resets system restore points and deletes backup files.
- [S0365] Olympic Destroyer: Olympic Destroyer uses the native Windows utilities vssadmin, wbadmin, and bcdedit to delete and disable operating system recovery features such as the Windows backup catalog and Windows Automatic Repair.
- [S0496] REvil: REvil can use vssadmin to delete volume shadow copies and bcdedit to disable recovery features.
- [S0449] Maze: Maze has attempted to delete the shadow volumes of infected machines, once before and once after the encryption process.
- [S0659] Diavol: Diavol can delete shadow copies using the `IVssBackupComponents` COM object to call the `DeleteSnapshots` method.
- [S1202] LockBit 3.0: LockBit 3.0 can delete volume shadow copies.
- [S0389] JCry: JCry has been observed deleting shadow copies to ensure that data cannot be restored easily.
- [S1136] BFG Agonizer: BFG Agonizer wipes the boot sector of infected machines to inhibit system recovery.
- [S1150] ROADSWEEP: ROADSWEEP has the ability to disable `SystemRestore` and Volume Shadow Copies.
- [S0654] ProLock: ProLock can use vssadmin.exe to remove volume shadow copies.
- [S1068] BlackCat: BlackCat can delete shadow copies using `vssadmin.exe delete shadows /all /quiet` and `wmic.exe Shadowcopy Delete`; it can also modify the boot loader using `bcdedit /set {default} recoveryenabled No`.
- [S1199] LockBit 2.0: LockBit 2.0 has the ability to delete volume shadow copies on targeted hosts.


### T1491.001 - Defacement: Internal Defacement

Description:

An adversary may deface systems internal to an organization in an attempt to intimidate or mislead users, thus discrediting the integrity of the systems. This may take the form of modifications to internal websites or server login messages, or directly to user systems with the replacement of the desktop wallpaper. Disturbing or offensive images may be used as a part of Internal Defacement in order to cause user discomfort, or to pressure compliance with accompanying messages. Since internally defacing systems exposes an adversary's presence, it often takes place after other intrusion goals have been accomplished.

Detection:

Monitor internal and websites for unplanned content changes. Monitor application logs for abnormal behavior that may indicate attempted or successful exploitation. Use deep packet inspection to look for artifacts of common exploit traffic, such as SQL injection. Web Application Firewalls may detect improper inputs attempting exploitation.

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

Description:

An adversary may deface systems external to an organization in an attempt to deliver messaging, intimidate, or otherwise mislead an organization or users. External Defacement may ultimately cause users to distrust the systems and to question/discredit the system’s integrity. Externally-facing websites are a common victim of defacement; often targeted by adversary and hacktivist groups in order to push a political message or spread propaganda. External Defacement may be used as a catalyst to trigger events, or as a response to actions taken by an organization or government. Similarly, website defacement may also be used as setup, or a precursor, for future attacks such as Drive-by Compromise.

Detection:

Monitor external websites for unplanned content changes. Monitor application logs for abnormal behavior that may indicate attempted or successful exploitation. Use deep packet inspection to look for artifacts of common exploit traffic, such as SQL injection. Web Application Firewalls may detect improper inputs attempting exploitation.

Procedures:

- [G1003] Ember Bear: Ember Bear is linked to the defacement of several Ukrainian organization websites.
- [G0034] Sandworm Team: Sandworm Team defaced approximately 15,000 websites belonging to Georgian government, non-government, and private sector organizations in 2019.


### T1495 - Firmware Corruption

Description:

Adversaries may overwrite or corrupt the flash memory contents of system BIOS or other firmware in devices attached to a system in order to render them inoperable or unable to boot, thus denying the availability to use the devices and/or the system. Firmware is software that is loaded and executed from non-volatile memory on hardware devices in order to initialize and manage device functionality. These devices may include the motherboard, hard drive, or video cards. In general, adversaries may manipulate, overwrite, or corrupt firmware in order to deny the use of the system or devices. For example, corruption of firmware responsible for loading the operating system for network devices may render the network devices inoperable. Depending on the device, this attack may also result in Data Destruction.

Detection:

System firmware manipulation may be detected. Log attempts to read/write to BIOS and compare against known patching behavior.

Procedures:

- [S0606] Bad Rabbit: Bad Rabbit has used an executable that installs a modified bootloader to prevent normal boot-up.
- [S0266] TrickBot: TrickBot module "Trickboot" can write or erase the UEFI/BIOS firmware of a compromised device.


### T1496.001 - Resource Hijacking: Compute Hijacking

Description:

Adversaries may leverage the compute resources of co-opted systems to complete resource-intensive tasks, which may impact system and/or hosted service availability. One common purpose for Compute Hijacking is to validate transactions of cryptocurrency networks and earn virtual currency. Adversaries may consume enough system resources to negatively impact and/or cause affected machines to become unresponsive. Servers and cloud-based systems are common targets because of the high potential for available resources, but user endpoint systems may also be compromised and used for Compute Hijacking and cryptocurrency mining. Containerized environments may also be targeted due to the ease of deployment via exposed APIs and the potential for scaling mining activities by deploying or compromising multiple containers within an environment or cluster. Additionally, some cryptocurrency mining malware identify then kill off processes for competing malware to ensure it’s not competing for resources.

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

Description:

Adversaries may leverage the network bandwidth resources of co-opted systems to complete resource-intensive tasks, which may impact system and/or hosted service availability. Adversaries may also use malware that leverages a system's network bandwidth as part of a botnet in order to facilitate Network Denial of Service campaigns and/or to seed malicious torrents. Alternatively, they may engage in proxyjacking by selling use of the victims' network bandwidth and IP address to proxyware services. Finally, they may engage in internet-wide scanning in order to identify additional targets for compromise. In addition to incurring potential financial costs or availability disruptions, this technique may cause reputational damage if a victim’s bandwidth is used for illegal activities.

### T1496.003 - Resource Hijacking: SMS Pumping

Description:

Adversaries may leverage messaging services for SMS pumping, which may impact system and/or hosted service availability. SMS pumping is a type of telecommunications fraud whereby a threat actor first obtains a set of phone numbers from a telecommunications provider, then leverages a victim’s messaging infrastructure to send large amounts of SMS messages to numbers in that set. By generating SMS traffic to their phone number set, a threat actor may earn payments from the telecommunications provider. Threat actors often use publicly available web forms, such as one-time password (OTP) or account verification fields, in order to generate SMS traffic. These fields may leverage services such as Twilio, AWS SNS, and Amazon Cognito in the background. In response to the large quantity of requests, SMS costs may increase and communication channels may become overwhelmed.

### T1496.004 - Resource Hijacking: Cloud Service Hijacking

Description:

Adversaries may leverage compromised software-as-a-service (SaaS) applications to complete resource-intensive tasks, which may impact hosted service availability. For example, adversaries may leverage email and messaging services, such as AWS Simple Email Service (SES), AWS Simple Notification Service (SNS), SendGrid, and Twilio, in order to send large quantities of spam / Phishing emails and SMS messages. Alternatively, they may engage in LLMJacking by leveraging reverse proxies to hijack the power of cloud-hosted AI models. In some cases, adversaries may leverage services that the victim is already using. In others, particularly when the service is part of a larger cloud platform, they may first enable the service. Leveraging SaaS applications may cause the victim to incur significant financial costs, use up service quotas, and otherwise impact availability.


### T1498.001 - Network Denial of Service: Direct Network Flood

Description:

Adversaries may attempt to cause a denial of service (DoS) by directly sending a high-volume of network traffic to a target. This DoS attack may also reduce the availability and functionality of the targeted system(s) and network. Direct Network Floods are when one or more systems are used to send a high-volume of network packets towards the targeted service's network. Almost any network protocol may be used for flooding. Stateless protocols such as UDP or ICMP are commonly used but stateful protocols such as TCP can be used as well. Botnets are commonly used to conduct network flooding attacks against networks and services. Large botnets can generate a significant amount of traffic from systems spread across the global Internet. Adversaries may have the resources to build out and control their own botnet infrastructure or may rent time on an existing botnet to conduct an attack. In some of the worst cases for distributed DoS (DDoS), so many systems are used to generate the flood that each one only needs to send out a small amount of traffic to produce enough volume to saturate the target network. In such circumstances, distinguishing DDoS traffic from legitimate clients becomes exceedingly difficult. Botnets have been used in some of the most high-profile DDoS flooding attacks, such as the 2012 series of incidents that targeted major US banks.

Detection:

Detection of a network flood can sometimes be achieved before the traffic volume is sufficient to cause impact to the availability of the service, but such response time typically requires very aggressive monitoring and responsiveness or services provided by an upstream network service provider. Typical network throughput monitoring tools such as netflow, SNMP, and custom scripts can be used to detect sudden increases in network or service utilization. Real-time, automated, and qualitative study of the network traffic can identify a sudden surge in one type of protocol can be used to detect a network flood event as it starts. Often, the lead time may be small and the indicator of an event availability of the network or service drops. The analysis tools mentioned can then be used to determine the type of DoS causing the outage and help with remediation.

### T1498.002 - Network Denial of Service: Reflection Amplification

Description:

Adversaries may attempt to cause a denial of service (DoS) by reflecting a high-volume of network traffic to a target. This type of Network DoS takes advantage of a third-party server intermediary that hosts and will respond to a given spoofed source IP address. This third-party server is commonly termed a reflector. An adversary accomplishes a reflection attack by sending packets to reflectors with the spoofed address of the victim. Similar to Direct Network Floods, more than one system may be used to conduct the attack, or a botnet may be used. Likewise, one or more reflectors may be used to focus traffic on the target. This Network DoS attack may also reduce the availability and functionality of the targeted system(s) and network. Reflection attacks often take advantage of protocols with larger responses than requests in order to amplify their traffic, commonly known as a Reflection Amplification attack. Adversaries may be able to generate an increase in volume of attack traffic that is several orders of magnitude greater than the requests sent to the amplifiers. The extent of this increase will depending upon many variables, such as the protocol in question, the technique used, and the amplifying servers that actually produce the amplification in attack volume. Two prominent protocols that have enabled Reflection Amplification Floods are DNS and NTP, though the use of several others in the wild have been documented. In particular, the memcache protocol showed itself to be a powerful protocol, with amplification sizes up to 51,200 times the requesting packet.

Detection:

Detection of reflection amplification can sometimes be achieved before the traffic volume is sufficient to cause impact to the availability of the service, but such response time typically requires very aggressive monitoring and responsiveness or services provided by an upstream network service provider. Typical network throughput monitoring tools such as netflow, SNMP, and custom scripts can be used to detect sudden increases in network or service utilization. Real-time, automated, and qualitative study of the network traffic can identify a sudden surge in one type of protocol can be used to detect a reflection amplification DoS event as it starts. Often, the lead time may be small and the indicator of an event availability of the network or service drops. The analysis tools mentioned can then be used to determine the type of DoS causing the outage and help with remediation.


### T1499.001 - Endpoint Denial of Service: OS Exhaustion Flood

Description:

Adversaries may launch a denial of service (DoS) attack targeting an endpoint's operating system (OS). A system's OS is responsible for managing the finite resources as well as preventing the entire system from being overwhelmed by excessive demands on its capacity. These attacks do not need to exhaust the actual resources on a system; the attacks may simply exhaust the limits and available resources that an OS self-imposes. Different ways to achieve this exist, including TCP state-exhaustion attacks such as SYN floods and ACK floods. With SYN floods, excessive amounts of SYN packets are sent, but the 3-way TCP handshake is never completed. Because each OS has a maximum number of concurrent TCP connections that it will allow, this can quickly exhaust the ability of the system to receive new requests for TCP connections, thus preventing access to any TCP service provided by the server. ACK floods leverage the stateful nature of the TCP protocol. A flood of ACK packets are sent to the target. This forces the OS to search its state table for a related TCP connection that has already been established. Because the ACK packets are for connections that do not exist, the OS will have to search the entire state table to confirm that no match exists. When it is necessary to do this for a large flood of packets, the computational requirements can cause the server to become sluggish and/or unresponsive, due to the work it must do to eliminate the rogue ACK packets. This greatly reduces the resources available for providing the targeted service.

Detection:

Detection of Endpoint DoS can sometimes be achieved before the effect is sufficient to cause significant impact to the availability of the service, but such response time typically requires very aggressive monitoring and responsiveness. Typical network throughput monitoring tools such as netflow, SNMP, and custom scripts can be used to detect sudden increases in circuit utilization. Real-time, automated, and qualitative study of the network traffic can identify a sudden surge in one type of protocol can be used to detect an attack as it starts.

### T1499.002 - Endpoint Denial of Service: Service Exhaustion Flood

Description:

Adversaries may target the different network services provided by systems to conduct a denial of service (DoS). Adversaries often target the availability of DNS and web services, however others have been targeted as well. Web server software can be attacked through a variety of means, some of which apply generally while others are specific to the software being used to provide the service. One example of this type of attack is known as a simple HTTP flood, where an adversary sends a large number of HTTP requests to a web server to overwhelm it and/or an application that runs on top of it. This flood relies on raw volume to accomplish the objective, exhausting any of the various resources required by the victim software to provide the service. Another variation, known as a SSL renegotiation attack, takes advantage of a protocol feature in SSL/TLS. The SSL/TLS protocol suite includes mechanisms for the client and server to agree on an encryption algorithm to use for subsequent secure connections. If SSL renegotiation is enabled, a request can be made for renegotiation of the crypto algorithm. In a renegotiation attack, the adversary establishes a SSL/TLS connection and then proceeds to make a series of renegotiation requests. Because the cryptographic renegotiation has a meaningful cost in computation cycles, this can cause an impact to the availability of the service when done in volume.

Detection:

Detection of Endpoint DoS can sometimes be achieved before the effect is sufficient to cause significant impact to the availability of the service, but such response time typically requires very aggressive monitoring and responsiveness. Typical network throughput monitoring tools such as netflow, SNMP, and custom scripts can be used to detect sudden increases in circuit utilization. Real-time, automated, and qualitative study of the network traffic can identify a sudden surge in one type of protocol can be used to detect an attack as it starts. In addition to network level detections, endpoint logging and instrumentation can be useful for detection. Attacks targeting web applications may generate logs in the web server, application server, and/or database server that can be used to identify the type of attack, possibly before the impact is felt. Externally monitor the availability of services that may be targeted by an Endpoint DoS.

### T1499.003 - Endpoint Denial of Service: Application Exhaustion Flood

Description:

Adversaries may target resource intensive features of applications to cause a denial of service (DoS), denying availability to those applications. For example, specific features in web applications may be highly resource intensive. Repeated requests to those features may be able to exhaust system resources and deny access to the application or the server itself.

Detection:

Detection of Endpoint DoS can sometimes be achieved before the effect is sufficient to cause significant impact to the availability of the service, but such response time typically requires very aggressive monitoring and responsiveness. Typical network throughput monitoring tools such as netflow, SNMP, and custom scripts can be used to detect sudden increases in circuit utilization. Real-time, automated, and qualitative study of the network traffic can identify a sudden surge in one type of protocol can be used to detect an attack as it starts. In addition to network level detections, endpoint logging and instrumentation can be useful for detection. Attacks targeting web applications may generate logs in the web server, application server, and/or database server that can be used to identify the type of attack, possibly before the impact is felt.

### T1499.004 - Endpoint Denial of Service: Application or System Exploitation

Description:

Adversaries may exploit software vulnerabilities that can cause an application or system to crash and deny availability to users. Some systems may automatically restart critical applications and services when crashes occur, but they can likely be re-exploited to cause a persistent denial of service (DoS) condition. Adversaries may exploit known or zero-day vulnerabilities to crash applications and/or systems, which may also lead to dependent applications and/or systems to be in a DoS condition. Crashed or restarted applications or systems may also have other effects such as Data Destruction, Firmware Corruption, Service Stop etc. which may further cause a DoS condition and deny availability to critical information, applications and/or systems.

Detection:

Attacks targeting web applications may generate logs in the web server, application server, and/or database server that can be used to identify the type of attack. Externally monitor the availability of services that may be targeted by an Endpoint DoS.

Procedures:

- [S0604] Industroyer: Industroyer uses a custom DoS tool that leverages CVE-2015-5374 and targets hardcoded IP addresses of Siemens SIPROTEC devices.


### T1529 - System Shutdown/Reboot

Description:

Adversaries may shutdown/reboot systems to interrupt access to, or aid in the destruction of, those systems. Operating systems may contain commands to initiate a shutdown/reboot of a machine or network device. In some cases, these commands may also be used to initiate a shutdown/reboot of a remote computer or network device via Network Device CLI (e.g. reload). They may also include shutdown/reboot of a virtual machine via hypervisor / cloud consoles or command line tools. Shutting down or rebooting systems may disrupt access to computer resources for legitimate users while also impeding incident response/recovery. Adversaries may attempt to shutdown/reboot a system after impacting it in other ways, such as Disk Structure Wipe or Inhibit System Recovery, to hasten the intended effects on system availability.

Detection:

Use process monitoring to monitor the execution and command line parameters of binaries involved in shutting down or rebooting systems. Windows event logs may also designate activity associated with a shutdown/reboot, ex. Event ID 1074 and 6006. Unexpected or unauthorized commands from network cli on network devices may also be associated with shutdown/reboot, e.g. the reload command.

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
- [S1178] ShrinkLocker: ShrinkLocker can restart the victim system if it encounters an error during execution, and will forcibly shutdown the system following encryption to lock out victim users.
- [S0368] NotPetya: NotPetya will reboot the system one hour after infection.
- [S1160] Latrodectus: Latrodectus has the ability to restart compromised hosts.
- [S1149] CHIMNEYSWEEP: CHIMNEYSWEEP can reboot or shutdown the targeted system or logoff the current user.
- [G0032] Lazarus Group: Lazarus Group has rebooted systems after destroying files and wiping the MBR on infected systems.
- [S0140] Shamoon: Shamoon will reboot the infected system once the wiping functionality has been completed.
- [S1111] DarkGate: DarkGate has used the `shutdown`command to shut down and/or restart the victim system.
- [S1070] Black Basta: Black Basta has used `ShellExecuteA` to shut down and restart the victim system.
- [S0697] HermeticWiper: HermeticWiper can initiate a system shutdown.
- [S1053] AvosLocker: AvosLocker’s Linux variant has terminated ESXi virtual machines.


### T1531 - Account Access Removal

Description:

Adversaries may interrupt availability of system and network resources by inhibiting access to accounts utilized by legitimate users. Accounts may be deleted, locked, or manipulated (ex: changed credentials) to remove access to accounts. Adversaries may also subsequently log off and/or perform a System Shutdown/Reboot to set malicious changes into place. In Windows, Net utility, Set-LocalUser and Set-ADAccountPassword PowerShell cmdlets may be used by adversaries to modify user accounts. Accounts could also be disabled by Group Policy. In Linux, the passwd utility may be used to change passwords. On ESXi servers, accounts can be removed or modified via esxcli (`system account set`, `system account remove`). Adversaries who use ransomware or similar attacks may first perform this and other Impact behaviors, such as Data Destruction and Defacement, in order to impede incident response/recovery before completing the Data Encrypted for Impact objective.

Detection:

Use process monitoring to monitor the execution and command line parameters of binaries involved in deleting accounts or changing passwords, such as use of Net. Windows event logs may also designate activity associated with an adversary's attempt to remove access to an account: * Event ID 4723 - An attempt was made to change an account's password * Event ID 4724 - An attempt was made to reset an account's password * Event ID 4726 - A user account was deleted * Event ID 4740 - A user account was locked out Alerting on Net and these Event IDs may generate a high degree of false positives, so compare against baseline knowledge for how systems are typically used and correlate modification events with other indications of malicious activity where possible.

Procedures:

- [G1024] Akira: Akira deletes administrator accounts in victim networks prior to encryption.
- [S0576] MegaCortex: MegaCortex has changed user account passwords and logged users off the system.
- [S0372] LockerGoga: LockerGoga has been observed changing account passwords and logging off current users.
- [S0688] Meteor: Meteor has the ability to change the password of local users on compromised hosts and can log off users.
- [G1004] LAPSUS$: LAPSUS$ has removed a targeted organization's global admin accounts to lock the organization out of all access.
- [S1134] DEADWOOD: DEADWOOD changes the password for local and domain users via net.exe to a random 32 character string to prevent these accounts from logging on. Additionally, DEADWOOD will terminate the winlogon.exe process to prevent attempts to log on to the infected system.


### T1561.001 - Disk Wipe: Disk Content Wipe

Description:

Adversaries may erase the contents of storage devices on specific systems or in large numbers in a network to interrupt availability to system and network resources. Adversaries may partially or completely overwrite the contents of a storage device rendering the data irrecoverable through the storage interface. Instead of wiping specific disk structures or files, adversaries with destructive intent may wipe arbitrary portions of disk content. To wipe disk content, adversaries may acquire direct access to the hard drive in order to overwrite arbitrarily sized portions of disk with random data. Adversaries have also been observed leveraging third-party drivers like RawDisk to directly access disk content. This behavior is distinct from Data Destruction because sections of the disk are erased instead of individual files. To maximize impact on the target organization in operations where network-wide availability interruption is the goal, malware used for wiping disk content may have worm-like features to propagate across a network by leveraging additional techniques like Valid Accounts, OS Credential Dumping, and SMB/Windows Admin Shares.

Detection:

Look for attempts to read/write to sensitive locations like the partition boot sector or BIOS parameter block/superblock. Monitor for direct access read/write attempts using the \\\\.\\ notation. Monitor for unusual kernel driver installation activity. For network infrastructure devices, collect AAA logging to monitor for `erase` commands that delete critical configuration files.

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
- [S1111] DarkGate: DarkGate has deleted all files in the Mozilla directory using the following command: `/c del /q /f /s C:\Users\User\AppData\Roaming\Mozilla\firefox*`.

### T1561.002 - Disk Wipe: Disk Structure Wipe

Description:

Adversaries may corrupt or wipe the disk data structures on a hard drive necessary to boot a system; targeting specific critical systems or in large numbers in a network to interrupt availability to system and network resources. Adversaries may attempt to render the system unable to boot by overwriting critical data located in structures such as the master boot record (MBR) or partition table. The data contained in disk structures may include the initial executable code for loading an operating system or the location of the file system partitions on disk. If this information is not present, the computer will not be able to load an operating system during the boot process, leaving the computer unavailable. Disk Structure Wipe may be performed in isolation, or along with Disk Content Wipe if all sectors of a disk are wiped. On a network devices, adversaries may reformat the file system using Network Device CLI commands such as `format`. To maximize impact on the target organization, malware designed for destroying disk structures may have worm-like features to propagate across a network by leveraging other techniques like Valid Accounts, OS Credential Dumping, and SMB/Windows Admin Shares.

Detection:

Look for attempts to read/write to sensitive locations like the master boot record and the disk partition table. Monitor for direct access read/write attempts using the \\\\.\\ notation. Monitor for unusual kernel driver installation activity. For network infrastructure devices, collect AAA logging to monitor for `format` commands being run to erase the file structure and prevent recovery of the device.

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
- [S0693] CaddyWiper: CaddyWiper has the ability to destroy information about a physical drive's partitions including the MBR, GPT, and partition entries.
- [G0067] APT37: APT37 has access to destructive malware that is capable of overwriting a machine's Master Boot Record (MBR).


### T1565.001 - Data Manipulation: Stored Data Manipulation

Description:

Adversaries may insert, delete, or manipulate data at rest in order to influence external outcomes or hide activity, thus threatening the integrity of the data. By manipulating stored data, adversaries may attempt to affect a business process, organizational understanding, and decision making. Stored data could include a variety of file formats, such as Office files, databases, stored emails, and custom file formats. The type of modification and the impact it will have depends on the type of data as well as the goals and objectives of the adversary. For complex systems, an adversary would likely need special expertise and possibly access to specialized software related to the system that would typically be gained through a prolonged information gathering campaign in order to have the desired impact.

Detection:

Where applicable, inspect important file hashes, locations, and modifications for suspicious/unexpected values.

Procedures:

- [S0562] SUNSPOT: SUNSPOT created a copy of the SolarWinds Orion software source file with a .bk extension to backup the original content, wrote SUNBURST using the same filename but with a .tmp extension, and then moved SUNBURST using MoveFileEx to the original filename with a .cs extension so it could be compiled within Orion software.
- [S1135] MultiLayer Wiper: MultiLayer Wiper changes the original path information of deleted files to make recovery efforts more difficult.
- [G0082] APT38: APT38 has used DYEPACK to create, delete, and alter records in databases used for SWIFT transactions.

### T1565.002 - Data Manipulation: Transmitted Data Manipulation

Description:

Adversaries may alter data en route to storage or other systems in order to manipulate external outcomes or hide activity, thus threatening the integrity of the data. By manipulating transmitted data, adversaries may attempt to affect a business process, organizational understanding, and decision making. Manipulation may be possible over a network connection or between system processes where there is an opportunity deploy a tool that will intercept and change information. The type of modification and the impact it will have depends on the target transmission mechanism as well as the goals and objectives of the adversary. For complex systems, an adversary would likely need special expertise and possibly access to specialized software related to the system that would typically be gained through a prolonged information gathering campaign in order to have the desired impact.

Detection:

Detecting the manipulation of data as at passes over a network can be difficult without the appropriate tools. In some cases integrity verification checks, such as file hashing, may be used on critical files as they transit a network. With some critical processes involving transmission of data, manual or out-of-band integrity checking may be useful for identifying manipulated data.

Procedures:

- [S0530] Melcoz: Melcoz can monitor the clipboard for cryptocurrency addresses and change the intended address to one controlled by the adversary.
- [G0082] APT38: APT38 has used DYEPACK to manipulate SWIFT messages en route to a printer.
- [S0395] LightNeuron: LightNeuron is capable of modifying email content, headers, and attachments during transit.
- [S0455] Metamorfo: Metamorfo has a function that can watch the contents of the system clipboard for valid bitcoin addresses, which it then overwrites with the attacker's address.

### T1565.003 - Data Manipulation: Runtime Data Manipulation

Description:

Adversaries may modify systems in order to manipulate the data as it is accessed and displayed to an end user, thus threatening the integrity of the data. By manipulating runtime data, adversaries may attempt to affect a business process, organizational understanding, and decision making. Adversaries may alter application binaries used to display data in order to cause runtime manipulations. Adversaries may also conduct Change Default File Association and Masquerading to cause a similar effect. The type of modification and the impact it will have depends on the target application and process as well as the goals and objectives of the adversary. For complex systems, an adversary would likely need special expertise and possibly access to specialized software related to the system that would typically be gained through a prolonged information gathering campaign in order to have the desired impact.

Detection:

Inspect important application binary file hashes, locations, and modifications for suspicious/unexpected values.

Procedures:

- [G0082] APT38: APT38 has used DYEPACK.FOX to manipulate PDF data as it is accessed to remove traces of fraudulent SWIFT transactions from the data displayed to the end user.


### T1657 - Financial Theft

Description:

Adversaries may steal monetary resources from targets through extortion, social engineering, technical theft, or other methods aimed at their own financial gain at the expense of the availability of these resources for victims. Financial theft is the ultimate objective of several popular campaign types including extortion by ransomware, business email compromise (BEC) and fraud, "pig butchering," bank hacking, and exploiting cryptocurrency networks. Adversaries may Compromise Accounts to conduct unauthorized transfers of funds. In the case of business email compromise or email fraud, an adversary may utilize Impersonation of a trusted entity. Once the social engineering is successful, victims can be deceived into sending money to financial accounts controlled by an adversary. This creates the potential for multiple victims (i.e., compromised accounts as well as the ultimate monetary loss) in incidents involving financial theft. Extortion by ransomware may occur, for example, when an adversary demands payment from a victim after Data Encrypted for Impact and Exfiltration of data, followed by threatening to leak sensitive data to the public unless payment is made to the adversary. Adversaries may use dedicated leak sites to distribute victim data. Due to the potentially immense business impact of financial theft, an adversary may abuse the possibility of financial theft and seeking monetary gain to divert attention from their true goals such as Data Destruction and business disruption.

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

Description:

Adversaries may flood targeted email addresses with an overwhelming volume of messages. This may bury legitimate emails in a flood of spam and disrupt business operations. An adversary may accomplish email bombing by leveraging an automated bot to register a targeted address for e-mail lists that do not validate new signups, such as online newsletters. The result can be a wave of thousands of e-mails that effectively overloads the victim’s inbox. By sending hundreds or thousands of e-mails in quick succession, adversaries may successfully divert attention away from and bury legitimate messages including security alerts, daily business processes like help desk tickets and client correspondence, or ongoing scams. This behavior can also be used as a tool of harassment. This behavior may be a precursor for Spearphishing Voice. For example, an adversary may email bomb a target and then follow up with a phone call to fraudulently offer assistance. This social engineering may lead to the use of Remote Access Software to steal credentials, deploy ransomware, conduct Financial Theft, or engage in other malicious activity.

Procedures:

- [G1046] Storm-1811: Storm-1811 has deployed large volumes of non-malicious email spam to victims in order to prompt follow-on interactions with the threat actor posing as IT support or helpdesk to resolve the problem.

