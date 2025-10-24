### T1021.001 - Remote Services: Remote Desktop Protocol

Procedures:

- [G0094] Kimsuky: Kimsuky has used RDP for direct remote point-and-click access.
- [G1032] INC Ransom: INC Ransom has used RDP to move laterally.
- [S0154] Cobalt Strike: Cobalt Strike can start a VNC-based remote desktop server and tunnel the connection through the already established C2 channel.
- [S0262] QuasarRAT: QuasarRAT has a module for performing remote desktop access.
- [G1017] Volt Typhoon: Volt Typhoon has moved laterally to the Domain Controller via RDP using a compromised account with domain administrator privileges.
- [G1023] APT5: APT5 has moved laterally throughout victim environments using RDP.
- [S0350] zwShell: zwShell has used RDP for lateral movement.
- [G0049] OilRig: OilRig has used Remote Desktop Protocol for lateral movement. The group has also used tunneling tools to tunnel RDP into the environment.
- [G0040] Patchwork: Patchwork attempted to use RDP to move laterally.
- [G0061] FIN8: FIN8 has used RDP for lateral movement.
- [G1043] BlackByte: BlackByte has used RDP to access other hosts within victim networks.
- [S0434] Imminent Monitor: Imminent Monitor has a module for performing remote desktop access.
- [S0670] WarzoneRAT: WarzoneRAT has the ability to control an infected PC using RDP.
- [G0087] APT39: APT39 has been seen using RDP for lateral movement and persistence, in some cases employing the rdpwinst tool for mangement of multiple sessions.
- [G0059] Magic Hound: Magic Hound has used Remote Desktop Services to copy tools on targeted systems.

### T1021.002 - Remote Services: SMB/Windows Admin Shares

Procedures:

- [S0575] Conti: Conti can spread via SMB and encrypts files on different hosts, potentially compromising an entire network.
- [G1009] Moses Staff: Moses Staff has used batch scripts that can enable SMB on a compromised host.
- [G0028] Threat Group-1314: Threat Group-1314 actors mapped network drives using net use.
- [C0049] Leviathan Australian Intrusions: Leviathan used remote shares to move laterally through victim networks during Leviathan Australian Intrusions.
- [S0698] HermeticWizard: HermeticWizard can use a list of hardcoded credentials to to authenticate via NTLMSSP to the SMB shares on remote systems.
- [G0143] Aquatic Panda: Aquatic Panda used remote shares to enable lateral movement in victim environments.
- [S0367] Emotet: Emotet has leveraged the Admin$, C$, and IPC$ shares for lateral movement.
- [S0350] zwShell: zwShell has been copied over network shares to move laterally.
- [S0446] Ryuk: Ryuk has used the C$ network share for lateral movement.
- [S0029] PsExec: PsExec, a tool that has been used by adversaries, writes programs to the ADMIN$ network share to execute commands on remote systems.
- [G0102] Wizard Spider: Wizard Spider has used SMB to drop Cobalt Strike Beacon on a domain controller for lateral movement.
- [S0140] Shamoon: Shamoon accesses network share(s), enables share access to the target device, copies an executable payload to the target system, and uses a Scheduled Task/Job to execute the malware.
- [G0096] APT41: APT41 has transferred implant files using Windows Admin Shares and the Server Message Block (SMB) protocol, then executes files through Windows Management Instrumentation (WMI).
- [S1073] Royal: Royal can use SMB to connect to move laterally.
- [G0004] Ke3chang: Ke3chang actors have been known to copy files to the network shares of other computers to move laterally.

### T1021.003 - Remote Services: Distributed Component Object Model

Procedures:

- [S0363] Empire: Empire can utilize Invoke-DCOM to leverage remote COM execution for lateral movement.
- [S0692] SILENTTRINITY: SILENTTRINITY can use `System` namespace methods to execute lateral movement using DCOM.
- [S0154] Cobalt Strike: Cobalt Strike can deliver Beacon payloads for lateral movement by leveraging remote COM execution.

### T1021.004 - Remote Services: SSH

Procedures:

- [G0046] FIN7: FIN7 has used SSH to move laterally through victim environments.
- [G0032] Lazarus Group: Lazarus Group used SSH and the PuTTy PSCP utility to gain access to a restricted segment of a compromised network.
- [G0065] Leviathan: Leviathan used ssh for internal reconnaissance.
- [C0029] Cutting Edge: During Cutting Edge, threat actors used SSH for lateral movement.
- [C0032] C0032: During the C0032 campaign, TEMP.Veles relied on encrypted SSH-based tunnels to transfer tools and for remote command/program execution.
- [G0098] BlackTech: BlackTech has used Putty for remote access.
- [S0363] Empire: Empire contains modules for executing commands over SSH as well as in-memory VNC agent injection.
- [G0143] Aquatic Panda: Aquatic Panda used SSH with captured user credentials to move laterally in victim environments.
- [S0154] Cobalt Strike: Cobalt Strike can SSH to a remote service.
- [S1187] reGeorg: reGeorg can communicate using SSH through an HTTP tunnel.
- [G0036] GCMAN: GCMAN uses Putty for lateral movement.
- [S0599] Kinsing: Kinsing has used SSH for lateral movement.
- [G0117] Fox Kitten: Fox Kitten has used the PuTTY and Plink tools for lateral movement.
- [G0139] TeamTNT: TeamTNT has used SSH to connect back to victim machines. TeamTNT has also used SSH to transfer tools and payloads onto victim hosts and execute them.
- [G1046] Storm-1811: Storm-1811 has used OpenSSH to establish an SSH tunnel to victims for persistent access.

### T1021.005 - Remote Services: VNC

Procedures:

- [S0412] ZxShell: ZxShell supports functionality for VNC sessions.
- [G0047] Gamaredon Group: Gamaredon Group has used VNC tools, including UltraVNC, to remotely interact with compromised hosts.
- [G0046] FIN7: FIN7 has used TightVNC to control compromised hosts.
- [S1014] DanBot: DanBot can use VNC for remote access to targeted systems.
- [S0484] Carberp: Carberp can start a remote VNC session by downloading a new plugin.
- [G0036] GCMAN: GCMAN uses VNC for lateral movement.
- [G0117] Fox Kitten: Fox Kitten has installed TightVNC server and client on compromised servers and endpoints for lateral movement.
- [S0266] TrickBot: TrickBot has used a VNC module to monitor the victim and collect information to pivot to valuable systems on the network
- [S0279] Proton: Proton uses VNC to connect into systems.
- [S0670] WarzoneRAT: WarzoneRAT has the ability of performing remote desktop access via a VNC console.
- [S1160] Latrodectus: Latrodectus has routed C2 traffic using Keyhole VNC.

### T1021.006 - Remote Services: Windows Remote Management

Procedures:

- [G1016] FIN13: FIN13 has leveraged `WMI` to move laterally within a compromised network via application servers and SQL servers.
- [S1063] Brute Ratel C4: Brute Ratel C4 can use WinRM for pivoting.
- [G0114] Chimera: Chimera has used WinRM for lateral movement.
- [C0024] SolarWinds Compromise: During the SolarWinds Compromise, APT29 used WinRM via PowerShell to execute commands and payloads on remote hosts.
- [S0154] Cobalt Strike: Cobalt Strike can use WinRM to execute a payload on a remote host.
- [C0048] Operation MidnightEclipse: During Operation MidnightEclipse, threat actors used WinRM to move laterally in targeted networks.
- [S0692] SILENTTRINITY: SILENTTRINITY tracks `TrustedHosts` and can move laterally to these targets via WinRM.
- [G0027] Threat Group-3390: Threat Group-3390 has used WinRM to enable remote execution.
- [G0102] Wizard Spider: Wizard Spider has used Window Remote Management to move laterally through a victim network.

### T1021.007 - Remote Services: Cloud Services

Procedures:

- [C0027] C0027: During C0027, Scattered Spider used compromised Azure credentials for credential theft activity and lateral movement to on-premises systems.
- [G0016] APT29: APT29 has leveraged compromised high-privileged on-premises accounts synced to Office 365 to move laterally into a cloud environment, including through the use of Azure AD PowerShell.
- [G1015] Scattered Spider: During C0027, Scattered Spider used compromised Azure credentials for credential theft activity and lateral movement to on-premises systems. Scattered Spider has also leveraged pre-existing AWS EC2 instances for lateral movement and data collection purposes.

### T1021.008 - Remote Services: Direct Cloud VM Connections

Procedures:

- Adversaries may leverage Valid Accounts to log directly into accessible cloud hosted compute infrastructure through cloud native methods. Many cloud providers offer interactive connections to virtual infrastructure that can be accessed through the Cloud API, such as Azure Serial Console, AWS EC2 Instance Connect, and AWS System Manager.. Methods of authentication for these connections can include passwords, application access tokens, or SSH keys. These cloud native methods may, by default, allow for privileged access on the host with SYSTEM or root level access. Adversaries may utilize these cloud native methods to directly access virtual infrastructure and pivot through an environment. These connections typically provide direct console access to the VM rather than the execution of scripts (i.e., Cloud Administration Command).


### T1072 - Software Deployment Tools

Procedures:

- [G0050] APT32: APT32 compromised McAfee ePO to move laterally by distributing malware as a software deployment task.
- [G0034] Sandworm Team: Sandworm Team has used the commercially available tool RemoteExec for agentless remote code execution.
- [G0091] Silence: Silence has used RAdmin, a remote software tool used to remotely control workstations and ATMs.
- [S0041] Wiper: It is believed that a patch management system for an anti-virus product commonly installed among targeted companies was used to distribute the Wiper malware.
- [G0028] Threat Group-1314: Threat Group-1314 actors used a victim's endpoint management platform, Altiris, for lateral movement.
- [C0018] C0018: During C0018, the threat actors used PDQ Deploy to move AvosLocker and tools across the network.


### T1080 - Taint Shared Content

Procedures:

- [S0132] H1N1: H1N1 has functionality to copy itself to network shares.
- [G0012] Darkhotel: Darkhotel used a virus that propagates by infecting executables stored on shared drives.
- [G1039] RedCurl: RedCurl has placed modified LNK files on network drives for lateral movement.
- [S0458] Ramsay: Ramsay can spread itself by infecting other portable executable files on networks shared drives.
- [G0047] Gamaredon Group: Gamaredon Group has injected malicious macros into all Word and Excel documents on mapped network drives.
- [G0060] BRONZE BUTLER: BRONZE BUTLER has placed malware on file shares and given it the same name as legitimate documents on the share.
- [S0260] InvisiMole: InvisiMole can replace legitimate software or documents in the compromised network with their trojanized versions, in an attempt to propagate itself within the network.
- [G1021] Cinnamon Tempest: Cinnamon Tempest has deployed ransomware from a batch file in a network share.
- [S0575] Conti: Conti can spread itself by infecting other remote machines via network shared drives.
- [S0133] Miner-C: Miner-C copies itself into the public folder of Network Attached Storage (NAS) devices and infects new victims who open the file.
- [S0603] Stuxnet: Stuxnet infects remote servers via network shares and by infecting WinCC database views with malicious code.
- [S0386] Ursnif: Ursnif has copied itself to and infected files in network drives for propagation.


### T1091 - Replication Through Removable Media

Procedures:

- [S0143] Flame: Flame contains modules to infect USB sticks and spread laterally to other Windows systems the stick is plugged into using Autorun functionality.
- [S0028] SHIPSHAPE: APT30 may have used the SHIPSHAPE malware to move onto air-gapped networks. SHIPSHAPE targets removable drives to spread to other systems by modifying the drive to use Autorun to execute or by hiding legitimate document files and copying an executable to the folder with the same name as the legitimate document.
- [G1014] LuminousMoth: LuminousMoth has used malicious DLLs to spread malware to connected removable USB drives on infected machines.
- [S0130] Unknown Logger: Unknown Logger is capable of spreading to USB devices.
- [G1007] Aoqin Dragon: Aoqin Dragon has used a dropper that employs a worm infection strategy using a removable device to breach a secure network environment.
- [S0062] DustySky: DustySky searches for removable media and duplicates itself onto it.
- [S0132] H1N1: H1N1 has functionality to copy itself to removable media.
- [G0012] Darkhotel: Darkhotel's selective infector modifies executables stored on removable media as a method of spreading across computers.
- [S0603] Stuxnet: Stuxnet can propagate via removable media using an autorun.inf file or the CVE-2010-2568 LNK vulnerability.
- [G0129] Mustang Panda: Mustang Panda has used a customized PlugX variant which could spread through USB connections.
- [S1130] Raspberry Robin: Raspberry Robin has historically used infected USB media to spread to new victims.
- [S0092] Agent.btz: Agent.btz drops itself onto removable media devices and creates an autorun.inf file with an instruction to run that file. When the device is inserted into another system, it opens autorun.inf and loads the malware.
- [S0385] njRAT: njRAT can be configured to spread via removable drives.
- [S0452] USBferry: USBferry can copy its installer to attached USB storage devices.
- [S0023] CHOPSTICK: Part of APT28's operation involved using CHOPSTICK modules to copy itself to air-gapped machines and using files written to USB sticks to transfer data and command traffic.


### T1210 - Exploitation of Remote Services

Procedures:

- [S0143] Flame: Flame can use MS10-061 to exploit a print spooler vulnerability in a remote system with a shared printer in order to move laterally.
- [S0366] WannaCry: WannaCry uses an exploit in SMBv1 to spread itself to other remote systems on a network.
- [G0102] Wizard Spider: Wizard Spider has exploited or attempted to exploit Zerologon (CVE-2020-1472) and EternalBlue (MS17-010) vulnerabilities.
- [G0117] Fox Kitten: Fox Kitten has exploited known vulnerabilities in remote services including RDP.
- [G1006] Earth Lusca: Earth Lusca has used Mimikatz to exploit a domain controller via the ZeroLogon exploit (CVE-2020-1472).
- [S0603] Stuxnet: Stuxnet propagates using the MS10-061 Print Spooler and MS08-067 Windows Server Service vulnerabilities.
- [S0650] QakBot: QakBot can move laterally using worm-like functionality through exploitation of SMB.
- [S0367] Emotet: Emotet has been seen exploiting SMB via a vulnerability exploit like EternalBlue (MS17-010) to achieve lateral movement and propagation.
- [S0363] Empire: Empire has a limited number of built-in modules for exploiting remote SMB, JBoss, and Jenkins servers.
- [S0606] Bad Rabbit: Bad Rabbit used the EternalRomance SMB exploit to spread through victim networks.
- [S0368] NotPetya: NotPetya can use two exploits in SMBv1, EternalBlue and EternalRomance, to spread itself to other remote systems on the network.
- [G1003] Ember Bear: Ember Bear has used exploits for vulnerabilities such as MS17-010, also known as `Eternal Blue`, during operations.
- [S0260] InvisiMole: InvisiMole can spread within a network via the BlueKeep (CVE-2019-0708) and EternalBlue (CVE-2017-0144) vulnerabilities in RDP and SMB respectively.
- [G0007] APT28: APT28 exploited a Windows SMB Remote Code Execution Vulnerability to conduct lateral movement.
- [S0608] Conficker: Conficker exploited the MS08-067 Windows vulnerability for remote code execution through a crafted RPC request.


### T1534 - Internal Spearphishing

Procedures:

- [G0047] Gamaredon Group: Gamaredon Group has used an Outlook VBA module on infected systems to send phishing emails with malicious attachments to other employees within the organization.
- [G0094] Kimsuky: Kimsuky has sent internal spearphishing emails for lateral movement after stealing victim information.
- [C0022] Operation Dream Job: During Operation Dream Job, Lazarus Group conducted internal spearphishing from within a compromised organization.
- [G0065] Leviathan: Leviathan has conducted internal spearphishing within the victim's environment for lateral movement.
- [G1001] HEXANE: HEXANE has conducted internal spearphishing attacks against executives, HR, and IT personnel to gain information and access.


### T1550.001 - Use Alternate Authentication Material: Application Access Token

Procedures:

- [S0683] Peirates: Peirates can use stolen service account tokens to perform its operations. It also enables adversaries to switch between valid service accounts.
- [S1023] CreepyDrive: CreepyDrive can use legitimate OAuth refresh tokens to authenticate with OneDrive.
- [C0024] SolarWinds Compromise: During the SolarWinds Compromise, APT29 used compromised service principals to make changes to the Office 365 environment.
- [G0007] APT28: APT28 has used several malicious applications that abused OAuth access tokens to gain access to target email accounts, including Gmail and Yahoo Mail.
- [G0125] HAFNIUM: HAFNIUM has abused service principals with administrative permissions for data exfiltration.

### T1550.002 - Use Alternate Authentication Material: Pass the Hash

Procedures:

- [G0050] APT32: APT32 has used pass the hash for lateral movement.
- [S0154] Cobalt Strike: Cobalt Strike can perform pass the hash.
- [S0122] Pass-The-Hash Toolkit: Pass-The-Hash Toolkit can perform pass the hash.
- [G0007] APT28: APT28 has used pass the hash for lateral movement.
- [G0143] Aquatic Panda: Aquatic Panda used a registry edit to enable a Windows feature called RestrictedAdmin in victim environments. This change allowed Aquatic Panda to leverage "pass the hash" mechanisms as the alteration allows for RDP connections with a valid account name and hash only, without possessing a cleartext password value.
- [G0114] Chimera: Chimera has dumped password hashes for use in pass the hash authentication attacks.
- [G0006] APT1: The APT1 group is known to have used pass the hash.
- [G0102] Wizard Spider: Wizard Spider has used the `Invoke-SMBExec` PowerShell cmdlet to execute the pass-the-hash technique and utilized stolen password hashes to move laterally.
- [S0376] HOPLIGHT: HOPLIGHT has been observed loading several APIs associated with Pass the Hash.
- [S0378] PoshC2: PoshC2 has a number of modules that leverage pass the hash for lateral movement.
- [S0002] Mimikatz: Mimikatz's SEKURLSA::Pth module can impersonate a user, with only a password hash, to execute arbitrary commands.
- [G0096] APT41: APT41 uses tools such as Mimikatz to enable lateral movement via captured password hashes.
- [G0094] Kimsuky: Kimsuky has used pass the hash for authentication to remote access software used in C2.
- [S0363] Empire: Empire can perform pass the hash attacks.
- [G1016] FIN13: FIN13 has used the PowerShell utility `Invoke-SMBExec` to execute the pass the hash method for lateral movement within an compromised environment.

### T1550.003 - Use Alternate Authentication Material: Pass the Ticket

Procedures:

- [S0053] SeaDuke: Some SeaDuke samples have a module to use pass the ticket with Kerberos for authentication.
- [G0016] APT29: APT29 used Kerberos ticket attacks for lateral movement.
- [S0002] Mimikatz: Mimikatz’s LSADUMP::DCSync and KERBEROS::PTT modules implement the three steps required to extract the krbtgt account hash and create/use Kerberos tickets.
- [S0192] Pupy: Pupy can also perform pass-the-ticket.
- [G0050] APT32: APT32 successfully gained remote access by using pass the ticket.
- [G0060] BRONZE BUTLER: BRONZE BUTLER has created forged Kerberos Ticket Granting Ticket (TGT) and Ticket Granting Service (TGS) tickets to maintain administrative access.

### T1550.004 - Use Alternate Authentication Material: Web Session Cookie

Procedures:

- [G1033] Star Blizzard: Star Blizzard has bypassed multi-factor authentication on victim email accounts by using session cookies stolen using EvilGinx.
- [C0024] SolarWinds Compromise: During the SolarWinds Compromise, APT29 used stolen cookies to access cloud resources and a forged `duo-sid` cookie to bypass MFA set on an email account.


### T1563.001 - Remote Service Session Hijacking: SSH Hijacking

Procedures:

- Adversaries may hijack a legitimate user's SSH session to move laterally within an environment. Secure Shell (SSH) is a standard means of remote access on Linux and macOS systems. It allows a user to connect to another system via an encrypted tunnel, commonly authenticating through a password, certificate or the use of an asymmetric encryption key pair. In order to move laterally from a compromised host, adversaries may take advantage of trust relationships established with other systems via public key authentication in active SSH sessions by hijacking an existing connection to another system. This may occur through compromising the SSH agent itself or by having access to the agent's socket. If an adversary is able to obtain root access, then hijacking SSH sessions is likely trivial. SSH Hijacking differs from use of SSH because it hijacks an existing SSH session rather than creating a new session using Valid Accounts.

### T1563.002 - Remote Service Session Hijacking: RDP Hijacking

Procedures:

- [S0366] WannaCry: WannaCry enumerates current remote desktop sessions and tries to execute the malware on each session.
- [G0001] Axiom: Axiom has targeted victims with remote administration tools including RDP.


### T1570 - Lateral Tool Transfer

Procedures:

- [S0367] Emotet: Emotet has copied itself to remote systems using the `service.exe` filename.
- [S1139] INC Ransomware: INC Ransomware can push its encryption executable to multiple endpoints within compromised infrastructure.
- [S1068] BlackCat: BlackCat can replicate itself across connected servers via `psexec`.
- [S1132] IPsec Helper: IPsec Helper can download additional payloads from command and control nodes and execute them.
- [G0050] APT32: APT32 has deployed tools after moving laterally using administrative accounts.
- [G1007] Aoqin Dragon: Aoqin Dragon has spread malware in target networks by copying modules to folders masquerading as removable devices.
- [S0457] Netwalker: Operators deploying Netwalker have used psexec to copy the Netwalker payload across accessible systems.
- [S0190] BITSAdmin: BITSAdmin can be used to create BITS Jobs to upload and/or download files from SMB file servers.
- [G0051] FIN10: FIN10 has deployed Meterpreter stagers and SplinterRAT instances in the victim network after moving laterally.
- [S0095] ftp: ftp may be abused by adversaries to transfer tools or files between systems within a compromised environment.
- [S0404] esentutl: esentutl can be used to copy files to/from a remote share.
- [G1003] Ember Bear: Ember Bear retrieves follow-on payloads direct from adversary-owned infrastructure for deployment on compromised hosts.
- [S0532] Lucifer: Lucifer can use certutil for propagation on Windows hosts within intranets.
- [G1017] Volt Typhoon: Volt Typhoon has copied web shells between servers in targeted environments.
- [G1047] Velvet Ant: Velvet Ant transferred files laterally within victim networks through the Impacket toolkit.

