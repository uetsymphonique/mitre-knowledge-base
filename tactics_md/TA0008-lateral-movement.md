### T1021 - Remote Services

Description:

Adversaries may use [Valid Accounts](https://attack.mitre.org/techniques/T1078) to log into a service that accepts remote connections, such as telnet, SSH, and VNC. The adversary may then perform actions as the logged-on user.

In an enterprise environment, servers and workstations can be organized into domains. Domains provide centralized identity management, allowing users to login using one set of credentials across the entire network. If an adversary is able to obtain a set of valid domain credentials, they could login to many different machines using remote access protocols such as secure shell (SSH) or remote desktop protocol (RDP).(Citation: SSH Secure Shell)(Citation: TechNet Remote Desktop Services) They could also login to accessible SaaS or IaaS services, such as those that federate their identities to the domain, or management platforms for internal virtualization environments such as VMware vCenter. 

Legitimate applications (such as [Software Deployment Tools](https://attack.mitre.org/techniques/T1072) and other administrative programs) may utilize [Remote Services](https://attack.mitre.org/techniques/T1021) to access remote hosts. For example, Apple Remote Desktop (ARD) on macOS is native software used for remote management. ARD leverages a blend of protocols, including [VNC](https://attack.mitre.org/techniques/T1021/005) to send the screen and control buffers and [SSH](https://attack.mitre.org/techniques/T1021/004) for secure file transfer.(Citation: Remote Management MDM macOS)(Citation: Kickstart Apple Remote Desktop commands)(Citation: Apple Remote Desktop Admin Guide 3.3) Adversaries can abuse applications such as ARD to gain remote code execution and perform lateral movement. In versions of macOS prior to 10.14, an adversary can escalate an SSH session to an ARD session which enables an adversary to accept TCC (Transparency, Consent, and Control) prompts without user interaction and gain access to data.(Citation: FireEye 2019 Apple Remote Desktop)(Citation: Lockboxx ARD 2019)(Citation: Kickstart Apple Remote Desktop commands)

Procedures:

- [G0102] Wizard Spider: [Wizard Spider](https://attack.mitre.org/groups/G0102) has used the WebDAV protocol to execute [Ryuk](https://attack.mitre.org/software/S0446) payloads hosted on network file shares.(Citation: Mandiant FIN12 Oct 2021)
- [S1016] MacMa: [MacMa](https://attack.mitre.org/software/S1016) can manage remote screen sessions.(Citation: ESET DazzleSpy Jan 2022)
- [S1063] Brute Ratel C4: [Brute Ratel C4](https://attack.mitre.org/software/S1063) has the ability to use RPC for lateral movement.(Citation: Palo Alto Brute Ratel July 2022)
- [S0437] Kivars: [Kivars](https://attack.mitre.org/software/S0437) has the ability to remotely trigger keyboard input and mouse clicks. (Citation: TrendMicro BlackTech June 2017)
- [G0143] Aquatic Panda: [Aquatic Panda](https://attack.mitre.org/groups/G0143) used remote scheduled tasks to install malicious software on victim systems during lateral movement actions.(Citation: Crowdstrike HuntReport 2022)
- [S0603] Stuxnet: [Stuxnet](https://attack.mitre.org/software/S0603) can propagate via peer-to-peer communication and updates using RPC.(Citation: Nicolas Falliere, Liam O Murchu, Eric Chien February 2011)
- [G1003] Ember Bear: [Ember Bear](https://attack.mitre.org/groups/G1003) uses valid network credentials gathered through credential harvesting to move laterally within victim networks, often employing the [Impacket](https://attack.mitre.org/software/S0357) framework to do so.(Citation: Cadet Blizzard emerges as novel threat actor)

#### T1021.001 - Remote Desktop Protocol

Description:

Adversaries may use [Valid Accounts](https://attack.mitre.org/techniques/T1078) to log into a computer using the Remote Desktop Protocol (RDP). The adversary may then perform actions as the logged-on user.

Remote desktop is a common feature in operating systems. It allows a user to log into an interactive session with a system desktop graphical user interface on a remote system. Microsoft refers to its implementation of the Remote Desktop Protocol (RDP) as Remote Desktop Services (RDS).(Citation: TechNet Remote Desktop Services) 

Adversaries may connect to a remote system over RDP/RDS to expand access if the service is enabled and allows access to accounts with known credentials. Adversaries will likely use Credential Access techniques to acquire credentials to use with RDP. Adversaries may also use RDP in conjunction with the [Accessibility Features](https://attack.mitre.org/techniques/T1546/008) or [Terminal Services DLL](https://attack.mitre.org/techniques/T1505/005) for Persistence.(Citation: Alperovitch Malware)

Procedures:

- [G0094] Kimsuky: [Kimsuky](https://attack.mitre.org/groups/G0094) has used RDP for direct remote point-and-click access.(Citation: Netscout Stolen Pencil Dec 2018)
- [G1032] INC Ransom: [INC Ransom](https://attack.mitre.org/groups/G1032) has used RDP to move laterally.(Citation: Cybereason INC Ransomware November 2023)(Citation: Huntress INC Ransom Group August 2023)(Citation: SOCRadar INC Ransom January 2024)(Citation: Huntress INC Ransomware May 2024)
- [S0154] Cobalt Strike: [Cobalt Strike](https://attack.mitre.org/software/S0154) can start a VNC-based remote desktop server and tunnel the connection through the already established C2 channel.(Citation: cobaltstrike manual)(Citation: Cybereason Bumblebee August 2022)
- [S0262] QuasarRAT: [QuasarRAT](https://attack.mitre.org/software/S0262) has a module for performing remote desktop access.(Citation: GitHub QuasarRAT)(Citation: Volexity Patchwork June 2018)
- [G1017] Volt Typhoon: [Volt Typhoon](https://attack.mitre.org/groups/G1017) has moved laterally to the Domain Controller via RDP using a compromised account with domain administrator privileges.(Citation: CISA AA24-038A PRC Critical Infrastructure February 2024)
- [G1023] APT5: [APT5](https://attack.mitre.org/groups/G1023) has moved laterally throughout victim environments using RDP.(Citation: Mandiant Pulse Secure Update May 2021)
- [S0350] zwShell: [zwShell](https://attack.mitre.org/software/S0350) has used RDP for lateral movement.(Citation: McAfee Night Dragon)
- [G0049] OilRig: [OilRig](https://attack.mitre.org/groups/G0049) has used Remote Desktop Protocol for lateral movement. The group has also used tunneling tools to tunnel RDP into the environment.(Citation: Unit42 OilRig Playbook 2023)(Citation: FireEye APT34 Webinar Dec 2017)(Citation: Crowdstrike GTR2020 Mar 2020)(Citation: Symantec Crambus OCT 2023)(Citation: Symantec Crambus OCT 2023)
- [G0040] Patchwork: [Patchwork](https://attack.mitre.org/groups/G0040) attempted to use RDP to move laterally.(Citation: Cymmetria Patchwork)
- [G0061] FIN8: [FIN8](https://attack.mitre.org/groups/G0061) has used RDP for lateral movement.(Citation: FireEye Know Your Enemy FIN8 Aug 2016)
- [G1043] BlackByte: [BlackByte](https://attack.mitre.org/groups/G1043) has used RDP to access other hosts within victim networks.(Citation: Microsoft BlackByte 2023)(Citation: Cisco BlackByte 2024)
- [S0434] Imminent Monitor: [Imminent Monitor](https://attack.mitre.org/software/S0434) has a module for performing remote desktop access.(Citation: QiAnXin APT-C-36 Feb2019)
- [S0670] WarzoneRAT: [WarzoneRAT](https://attack.mitre.org/software/S0670) has the ability to control an infected PC using RDP.(Citation: Check Point Warzone Feb 2020)
- [G0087] APT39: [APT39](https://attack.mitre.org/groups/G0087) has been seen using RDP for lateral movement and persistence, in some cases employing the rdpwinst tool for mangement of multiple sessions.(Citation: FireEye APT39 Jan 2019)(Citation: BitDefender Chafer May 2020)
- [G0059] Magic Hound: [Magic Hound](https://attack.mitre.org/groups/G0059) has used Remote Desktop Services to copy tools on targeted systems.(Citation: DFIR Report APT35 ProxyShell March 2022)(Citation: DFIR Phosphorus November 2021)
- [G0102] Wizard Spider: [Wizard Spider](https://attack.mitre.org/groups/G0102) has used RDP for lateral movement and to deploy ransomware interactively.(Citation: CrowdStrike Grim Spider May 2019)(Citation: DHS/CISA Ransomware Targeting Healthcare October 2020)(Citation: DFIR Ryuk 2 Hour Speed Run November 2020)(Citation: Mandiant FIN12 Oct 2021)
- [G0143] Aquatic Panda: [Aquatic Panda](https://attack.mitre.org/groups/G0143) leveraged stolen credentials to move laterally via RDP in victim environments.(Citation: Crowdstrike HuntReport 2022)
- [S0030] Carbanak: [Carbanak](https://attack.mitre.org/software/S0030) enables concurrent Remote Desktop Protocol (RDP) sessions.(Citation: FireEye CARBANAK June 2017)
- [C0024] SolarWinds Compromise: During the [SolarWinds Compromise](https://attack.mitre.org/campaigns/C0024), [APT29](https://attack.mitre.org/groups/G0016) used RDP sessions from public-facing systems to internal servers.(Citation: CrowdStrike StellarParticle January 2022)
- [C0018] C0018: During [C0018](https://attack.mitre.org/campaigns/C0018), the threat actors opened a variety of ports to establish RDP connections, including ports 28035, 32467, 41578, and 46892.(Citation: Costa AvosLocker May 2022)
- [C0029] Cutting Edge: During [Cutting Edge](https://attack.mitre.org/campaigns/C0029), threat actors used RDP with compromised credentials for lateral movement.(Citation: Volexity Ivanti Zero-Day Exploitation January 2024)
- [G0046] FIN7: [FIN7](https://attack.mitre.org/groups/G0046) has used RDP to move laterally in victim environments.(Citation: CrowdStrike Carbon Spider August 2021)
- [G0119] Indrik Spider: [Indrik Spider](https://attack.mitre.org/groups/G0119) has used RDP for lateral movement.(Citation: Mandiant_UNC2165)
- [C0032] C0032: During the [C0032](https://attack.mitre.org/campaigns/C0032) campaign, [TEMP.Veles](https://attack.mitre.org/groups/G0088) utilized RDP throughout an operation.(Citation: FireEye TRITON 2019)
- [C0038] HomeLand Justice: During [HomeLand Justice](https://attack.mitre.org/campaigns/C0038), threat actors primarily used RDP for lateral movement in the victim environment.(Citation: CISA Iran Albanian Attacks September 2022)(Citation: Microsoft Albanian Government Attacks September 2022)
- [G0091] Silence: [Silence](https://attack.mitre.org/groups/G0091) has used RDP for lateral movement.(Citation: Group IB Silence Sept 2018)
- [S1187] reGeorg: [reGeorg](https://attack.mitre.org/software/S1187) can be used to tunnel RDP connections.(Citation: Fortinet reGeorg MAR 2019)
- [S0379] Revenge RAT: [Revenge RAT](https://attack.mitre.org/software/S0379) has a plugin to perform RDP access.(Citation: Cylance Shaheen Nov 2018)
- [S0382] ServHelper: [ServHelper](https://attack.mitre.org/software/S0382) has commands for adding a remote desktop user and sending RDP traffic to the attacker through a reverse SSH tunnel.(Citation: Proofpoint TA505 Jan 2019)
- [G1001] HEXANE: [HEXANE](https://attack.mitre.org/groups/G1001) has used remote desktop sessions for lateral movement.(Citation: SecureWorks August 2019)
- [G0001] Axiom: [Axiom](https://attack.mitre.org/groups/G0001) has used RDP during operations.(Citation: Novetta-Axiom)
- [G0080] Cobalt Group: [Cobalt Group](https://attack.mitre.org/groups/G0080) has used Remote Desktop Protocol to conduct lateral movement.(Citation: Group IB Cobalt Aug 2017)
- [G1024] Akira: [Akira](https://attack.mitre.org/groups/G1024) has used RDP for lateral movement.(Citation: Cisco Akira Ransomware OCT 2024)
- [S0461] SDBbot: [SDBbot](https://attack.mitre.org/software/S0461) has the ability to use RDP to connect to victim's machines.(Citation: Proofpoint TA505 October 2019)
- [S0250] Koadic: [Koadic](https://attack.mitre.org/software/S0250) can enable remote desktop on the victim's machine.(Citation: Github Koadic)
- [S0283] jRAT: [jRAT](https://attack.mitre.org/software/S0283) can support RDP control.(Citation: Kaspersky Adwind Feb 2016)
- [G1030] Agrius: [Agrius](https://attack.mitre.org/groups/G1030) tunnels RDP traffic through deployed web shells to access victim environments via compromised accounts.(Citation: SentinelOne Agrius 2021) [Agrius](https://attack.mitre.org/groups/G1030) used the Plink tool to tunnel RDP connections for remote access and lateral movement in victim environments.(Citation: Unit42 Agrius 2023)
- [S0385] njRAT: [njRAT](https://attack.mitre.org/software/S0385) has a module for performing remote desktop access.(Citation: Fidelis njRAT June 2013)
- [S0583] Pysa: [Pysa](https://attack.mitre.org/software/S0583) has laterally moved using RDP connections.(Citation: CERT-FR PYSA April 2020)
- [C0051] APT28 Nearest Neighbor Campaign: During [APT28 Nearest Neighbor Campaign](https://attack.mitre.org/campaigns/C0051), [APT28](https://attack.mitre.org/groups/G0007) used RDP for lateral movement.(Citation: Nearest Neighbor Volexity)
- [S0192] Pupy: [Pupy](https://attack.mitre.org/software/S0192) can enable/disable RDP connection and can start a remote desktop session using a browser web socket client.(Citation: GitHub Pupy)
- [S0334] DarkComet: [DarkComet](https://attack.mitre.org/software/S0334) can open an active screen of the victim’s machine and take control of the mouse and keyboard.(Citation: Malwarebytes DarkComet March 2018)
- [G0037] FIN6: [FIN6](https://attack.mitre.org/groups/G0037) used RDP to move laterally in victim networks.(Citation: FireEye FIN6 April 2016)(Citation: FireEye FIN6 Apr 2019)
- [G0051] FIN10: [FIN10](https://attack.mitre.org/groups/G0051) has used RDP to move laterally to systems in the victim environment.(Citation: FireEye FIN10 June 2017)
- [S0412] ZxShell: [ZxShell](https://attack.mitre.org/software/S0412) has remote desktop functionality.(Citation: Talos ZxShell Oct 2014)
- [G1016] FIN13: [FIN13](https://attack.mitre.org/groups/G1016) has remotely accessed compromised environments via Remote Desktop Services (RDS) for lateral movement.(Citation: Mandiant FIN13 Aug 2022)
- [G0108] Blue Mockingbird: [Blue Mockingbird](https://attack.mitre.org/groups/G0108) has used Remote Desktop to log on to servers interactively and manually copy files to remote hosts.(Citation: RedCanary Mockingbird May 2020)
- [G0045] menuPass: [menuPass](https://attack.mitre.org/groups/G0045) has used RDP connections to move across the victim network.(Citation: PWC Cloud Hopper April 2017)(Citation: District Court of NY APT10 Indictment December 2018)
- [C0015] C0015: During [C0015](https://attack.mitre.org/campaigns/C0015), the threat actors used RDP to access specific network hosts of interest.(Citation: DFIR Conti Bazar Nov 2021)
- [G0032] Lazarus Group: [Lazarus Group](https://attack.mitre.org/groups/G0032) malware SierraCharlie uses RDP for propagation.(Citation: Novetta Blockbuster)(Citation: Novetta Blockbuster RATs)
- [G0022] APT3: [APT3](https://attack.mitre.org/groups/G0022) enables the Remote Desktop Protocol for persistence.(Citation: aptsim) [APT3](https://attack.mitre.org/groups/G0022) has also interacted with compromised systems to browse and copy files through RDP sessions.(Citation: Twitter Cglyer Status Update APT3 eml)
- [G0117] Fox Kitten: [Fox Kitten](https://attack.mitre.org/groups/G0117) has used RDP to log in and move laterally in the target environment.(Citation: CISA AA20-259A Iran-Based Actor September 2020)(Citation: ClearSky Pay2Kitten December 2020)
- [G0065] Leviathan: [Leviathan](https://attack.mitre.org/groups/G0065) has targeted RDP credentials and used it to move through the victim environment.(Citation: FireEye APT40 March 2019)
- [G0035] Dragonfly: [Dragonfly](https://attack.mitre.org/groups/G0035) has moved laterally via RDP.(Citation: US-CERT TA18-074A)
- [G0096] APT41: [APT41](https://attack.mitre.org/groups/G0096) used RDP for lateral movement.(Citation: FireEye APT41 Aug 2019)(Citation: Crowdstrike GTR2020 Mar 2020) [APT41](https://attack.mitre.org/groups/G0096) used NATBypass to expose local RDP ports on compromised systems to the Internet.(Citation: apt41_dcsocytec_dec2022)
- [G0114] Chimera: [Chimera](https://attack.mitre.org/groups/G0114) has used RDP to access targeted systems.(Citation: Cycraft Chimera April 2020)
- [G0006] APT1: The [APT1](https://attack.mitre.org/groups/G0006) group is known to have used RDP during operations.(Citation: FireEye PLA)

#### T1021.002 - SMB/Windows Admin Shares

Description:

Adversaries may use [Valid Accounts](https://attack.mitre.org/techniques/T1078) to interact with a remote network share using Server Message Block (SMB). The adversary may then perform actions as the logged-on user.

SMB is a file, printer, and serial port sharing protocol for Windows machines on the same network or domain. Adversaries may use SMB to interact with file shares, allowing them to move laterally throughout a network. Linux and macOS implementations of SMB typically use Samba.

Windows systems have hidden network shares that are accessible only to administrators and provide the ability for remote file copy and other administrative functions. Example network shares include `C$`, `ADMIN$`, and `IPC$`. Adversaries may use this technique in conjunction with administrator-level [Valid Accounts](https://attack.mitre.org/techniques/T1078) to remotely access a networked system over SMB,(Citation: Wikipedia Server Message Block) to interact with systems using remote procedure calls (RPCs),(Citation: TechNet RPC) transfer files, and run transferred binaries through remote Execution. Example execution techniques that rely on authenticated sessions over SMB/RPC are [Scheduled Task/Job](https://attack.mitre.org/techniques/T1053), [Service Execution](https://attack.mitre.org/techniques/T1569/002), and [Windows Management Instrumentation](https://attack.mitre.org/techniques/T1047). Adversaries can also use NTLM hashes to access administrator shares on systems with [Pass the Hash](https://attack.mitre.org/techniques/T1550/002) and certain configuration and patch levels.(Citation: Microsoft Admin Shares)

Procedures:

- [S0575] Conti: [Conti](https://attack.mitre.org/software/S0575) can spread via SMB and encrypts files on different hosts, potentially compromising an entire network.(Citation: Cybereason Conti Jan 2021)(Citation: CarbonBlack Conti July 2020)
- [G1009] Moses Staff: [Moses Staff](https://attack.mitre.org/groups/G1009) has used batch scripts that can enable SMB on a compromised host.(Citation: Checkpoint MosesStaff Nov 2021)
- [G0028] Threat Group-1314: [Threat Group-1314](https://attack.mitre.org/groups/G0028) actors mapped network drives using <code>net use</code>.(Citation: Dell TG-1314)
- [C0049] Leviathan Australian Intrusions: [Leviathan](https://attack.mitre.org/groups/G0065) used remote shares to move laterally through victim networks during [Leviathan Australian Intrusions](https://attack.mitre.org/campaigns/C0049).(Citation: CISA Leviathan 2024)
- [S0698] HermeticWizard: [HermeticWizard](https://attack.mitre.org/software/S0698) can use a list of hardcoded credentials to to authenticate via NTLMSSP to the SMB shares on remote systems.(Citation: ESET Hermetic Wizard March 2022)
- [G0143] Aquatic Panda: [Aquatic Panda](https://attack.mitre.org/groups/G0143) used remote shares to enable lateral movement in victim environments.(Citation: Crowdstrike HuntReport 2022)
- [S0367] Emotet: [Emotet](https://attack.mitre.org/software/S0367) has leveraged the Admin$, C$, and IPC$ shares for lateral movement. (Citation: Malwarebytes Emotet Dec 2017)(Citation: Binary Defense Emotes Wi-Fi Spreader)
- [S0350] zwShell: [zwShell](https://attack.mitre.org/software/S0350) has been copied over network shares to move laterally.(Citation: McAfee Night Dragon)
- [S0446] Ryuk: [Ryuk](https://attack.mitre.org/software/S0446) has used the C$ network share for lateral movement.(Citation: Bleeping Computer - Ryuk WoL)
- [S0029] PsExec: [PsExec](https://attack.mitre.org/software/S0029), a tool that has been used by adversaries, writes programs to the <code>ADMIN$</code> network share to execute commands on remote systems.(Citation: PsExec Russinovich)
- [G0102] Wizard Spider: [Wizard Spider](https://attack.mitre.org/groups/G0102) has used SMB to drop Cobalt Strike Beacon on a domain controller for lateral movement.(Citation: DFIR Ryuk 2 Hour Speed Run November 2020)(Citation: DFIR Ryuk's Return October 2020)
- [S0140] Shamoon: [Shamoon](https://attack.mitre.org/software/S0140) accesses network share(s), enables share access to the target device, copies an executable payload to the target system, and uses a [Scheduled Task/Job](https://attack.mitre.org/techniques/T1053) to execute the malware.(Citation: FireEye Shamoon Nov 2016)
- [G0096] APT41: [APT41](https://attack.mitre.org/groups/G0096) has transferred implant files using Windows Admin Shares and the Server Message Block (SMB) protocol, then executes files through Windows Management Instrumentation (WMI).(Citation: Crowdstrike GTR2020 Mar 2020)(Citation: apt41_dcsocytec_dec2022)
- [S1073] Royal: [Royal](https://attack.mitre.org/software/S1073) can use SMB to connect to move laterally.(Citation: Cybereason Royal December 2022)
- [G0004] Ke3chang: [Ke3chang](https://attack.mitre.org/groups/G0004) actors have been known to copy files to the network shares of other computers to move laterally.(Citation: Mandiant Operation Ke3chang November 2014)(Citation: NCC Group APT15 Alive and Strong)
- [S0368] NotPetya: [NotPetya](https://attack.mitre.org/software/S0368) can use [PsExec](https://attack.mitre.org/software/S0029), which interacts with the <code>ADMIN$</code> network share to execute commands on remote systems.(Citation: Talos Nyetya June 2017)(Citation: US-CERT NotPetya 2017)(Citation: PsExec Russinovich)
- [G0010] Turla: [Turla](https://attack.mitre.org/groups/G0010) used <code>net use</code> commands to connect to lateral systems within a network.(Citation: Kaspersky Turla)
- [S0659] Diavol: [Diavol](https://attack.mitre.org/software/S0659) can spread throughout a network via SMB prior to encryption.(Citation: Fortinet Diavol July 2021)
- [S0089] BlackEnergy: [BlackEnergy](https://attack.mitre.org/software/S0089) has run a plug-in on a victim to spread through the local network by using [PsExec](https://attack.mitre.org/software/S0029) and accessing admin shares.(Citation: Securelist BlackEnergy Nov 2014)
- [C0024] SolarWinds Compromise: During the [SolarWinds Compromise](https://attack.mitre.org/campaigns/C0024), [APT29](https://attack.mitre.org/groups/G0016) used administrative accounts to connect over SMB to targeted users.(Citation: CrowdStrike StellarParticle January 2022)
- [G1016] FIN13: [FIN13](https://attack.mitre.org/groups/G1016) has leveraged SMB to move laterally within a compromised network via application servers and SQL servers.(Citation: Sygnia Elephant Beetle Jan 2022)
- [G0114] Chimera: [Chimera](https://attack.mitre.org/groups/G0114) has used Windows admin shares to move laterally.(Citation: Cycraft Chimera April 2020)(Citation: NCC Group Chimera January 2021)
- [G0117] Fox Kitten: [Fox Kitten](https://attack.mitre.org/groups/G0117) has used valid accounts to access SMB shares.(Citation: CISA AA20-259A Iran-Based Actor September 2020)
- [G1040] Play: [Play](https://attack.mitre.org/groups/G1040) has used [Cobalt Strike](https://attack.mitre.org/software/S0154) to move laterally via SMB.(Citation: Trend Micro Ransomware Spotlight Play July 2023)
- [S1063] Brute Ratel C4: [Brute Ratel C4](https://attack.mitre.org/software/S1063) has the ability to use SMB to pivot in compromised networks.(Citation: Palo Alto Brute Ratel July 2022)(Citation: MDSec Brute Ratel August 2022)(Citation: Dark Vortex Brute Ratel C4)
- [S0672] Zox: [Zox](https://attack.mitre.org/software/S0672) has the ability to use SMB for communication.(Citation: Novetta-Axiom)
- [S1212] RansomHub: [RansomHub](https://attack.mitre.org/software/S1212) can use credentials provided in its configuration to move laterally from the infected machine over SMBv2.(Citation: Group-IB RansomHub FEB 2025)
- [S0608] Conficker: [Conficker](https://attack.mitre.org/software/S0608) variants spread through NetBIOS share propagation.(Citation: SANS Conficker)
- [G0034] Sandworm Team: [Sandworm Team](https://attack.mitre.org/groups/G0034) has copied payloads to the `ADMIN$` share of remote systems and run <code>net use</code> to connect to network shares.(Citation: Dragos Crashoverride 2018)(Citation: Microsoft Prestige ransomware October 2022)
- [C0014] Operation Wocao: During [Operation Wocao](https://attack.mitre.org/campaigns/C0014), threat actors used [Impacket](https://attack.mitre.org/software/S0357)'s smbexec.py as well as accessing the C$ and IPC$ shares to move laterally.(Citation: FoxIT Wocao December 2019)
- [S0038] Duqu: Adversaries can instruct [Duqu](https://attack.mitre.org/software/S0038) to spread laterally by copying itself to shares it has enumerated and for which it has obtained legitimate credentials (via keylogging or other means). The remote host is then infected by using the compromised credentials to schedule a task on remote machines that executes the malware.(Citation: Symantec W32.Duqu)
- [S0236] Kwampirs: [Kwampirs](https://attack.mitre.org/software/S0236) copies itself over network shares to move laterally on a victim network.(Citation: Symantec Orangeworm April 2018)
- [G1022] ToddyCat: [ToddyCat](https://attack.mitre.org/groups/G1022) has used locally mounted network shares for lateral movement through targated environments.(Citation: Kaspersky ToddyCat Check Logs October 2023)
- [G0022] APT3: [APT3](https://attack.mitre.org/groups/G0022) will copy files over to Windows Admin Shares (like ADMIN$) as part of lateral movement.(Citation: Symantec Buckeye)
- [C0048] Operation MidnightEclipse: During [Operation MidnightEclipse](https://attack.mitre.org/campaigns/C0048), threat actors used SMB to pivot internally in victim networks.(Citation: Volexity UPSTYLE 2024)
- [S0039] Net: Lateral movement can be done with [Net](https://attack.mitre.org/software/S0039) through <code>net use</code> commands to connect to the on remote systems.(Citation: Savill 1999)
- [G0061] FIN8: [FIN8](https://attack.mitre.org/groups/G0061) has attempted to map to C$ on enumerated hosts to test the scope of their current credentials/context. [FIN8](https://attack.mitre.org/groups/G0061) has also used smbexec from the [Impacket](https://attack.mitre.org/software/S0357) suite for lateral movement.(Citation: FireEye Know Your Enemy FIN8 Aug 2016)(Citation: Bitdefender Sardonic Aug 2021)
- [C0038] HomeLand Justice: During [HomeLand Justice](https://attack.mitre.org/campaigns/C0038), threat actors used SMB for lateral movement.(Citation: CISA Iran Albanian Attacks September 2022)(Citation: Microsoft Albanian Government Attacks September 2022)
- [C0029] Cutting Edge: During [Cutting Edge](https://attack.mitre.org/campaigns/C0029), threat actors moved laterally using compromised credentials to connect to internal Windows systems with SMB.(Citation: Volexity Ivanti Zero-Day Exploitation January 2024)
- [S0019] Regin: The [Regin](https://attack.mitre.org/software/S0019) malware platform can use Windows admin shares to move laterally.(Citation: Kaspersky Regin)
- [G0108] Blue Mockingbird: [Blue Mockingbird](https://attack.mitre.org/groups/G0108) has used Windows Explorer to manually copy malicious files to remote hosts over SMB.(Citation: RedCanary Mockingbird May 2020)
- [G0050] APT32: [APT32](https://attack.mitre.org/groups/G0050) used [Net](https://attack.mitre.org/software/S0039) to use Windows' hidden network shares to copy their tools to remote machines for execution.(Citation: Cybereason Cobalt Kitty 2017)
- [S0603] Stuxnet: [Stuxnet](https://attack.mitre.org/software/S0603) propagates to available network shares.(Citation: Nicolas Falliere, Liam O Murchu, Eric Chien February 2011)
- [G1021] Cinnamon Tempest: [Cinnamon Tempest](https://attack.mitre.org/groups/G1021) has used SMBexec for lateral movement.(Citation: Sygnia Emperor Dragonfly October 2022)
- [S1199] LockBit 2.0: [LockBit 2.0](https://attack.mitre.org/software/S1199) has the ability to move laterally via SMB.(Citation: Palo Alto Lockbit 2.0 JUN 2022)(Citation: SentinelOne LockBit 2.0)
- [S0154] Cobalt Strike: [Cobalt Strike](https://attack.mitre.org/software/S0154) can use Window admin shares (C$ and ADMIN$) for lateral movement.(Citation: Cobalt Strike TTPs Dec 2017)(Citation: Trend Micro Black Basta October 2022)
- [G1043] BlackByte: [BlackByte](https://attack.mitre.org/groups/G1043) used SMB file shares to distribute payloads throughout victim networks, including BlackByte ransomware variants during wormable operations.(Citation: Picus BlackByte 2022)(Citation: Microsoft BlackByte 2023)(Citation: Cisco BlackByte 2024)
- [G1047] Velvet Ant: [Velvet Ant](https://attack.mitre.org/groups/G1047) has transferred tools within victim environments using SMB.(Citation: Sygnia VelvetAnt 2024A)
- [S1180] BlackByte Ransomware: [BlackByte Ransomware](https://attack.mitre.org/software/S1180) uses mapped shared folders to transfer ransomware payloads via SMB.(Citation: Trustwave BlackByte 2021)
- [S1187] reGeorg: [reGeorg](https://attack.mitre.org/software/S1187) has the ability to tunnel SMB sessions.(Citation: Fortinet reGeorg MAR 2019)
- [S0365] Olympic Destroyer: [Olympic Destroyer](https://attack.mitre.org/software/S0365) uses [PsExec](https://attack.mitre.org/software/S0029) to interact with the <code>ADMIN$</code> network share to execute commands on remote systems.(Citation: Talos Olympic Destroyer 2018)(Citation: PsExec Russinovich)
- [C0051] APT28 Nearest Neighbor Campaign: During [APT28 Nearest Neighbor Campaign](https://attack.mitre.org/campaigns/C0051), [APT28](https://attack.mitre.org/groups/G0007) leveraged SMB to transfer files and move laterally.(Citation: Nearest Neighbor Volexity)
- [G0071] Orangeworm: [Orangeworm](https://attack.mitre.org/groups/G0071) has copied its backdoor across open network shares, including ADMIN$, C$WINDOWS, D$WINDOWS, and E$WINDOWS.(Citation: Symantec Orangeworm April 2018)
- [S1202] LockBit 3.0: [LockBit 3.0](https://attack.mitre.org/software/S1202) can use SMB for lateral movement.(Citation: Joint Cybersecurity Advisory LockBit 3.0 MAR 2023)
- [G0032] Lazarus Group: [Lazarus Group](https://attack.mitre.org/groups/G0032) malware SierraAlfa accesses the <code>ADMIN$</code> share via SMB to conduct lateral movement.(Citation: Novetta Blockbuster)(Citation: Novetta Blockbuster RATs)
- [S0056] Net Crawler: [Net Crawler](https://attack.mitre.org/software/S0056) uses Windows admin shares to establish authenticated sessions to remote systems over SMB as part of lateral movement.(Citation: Cylance Cleaver)
- [S0532] Lucifer: [Lucifer](https://attack.mitre.org/software/S0532) can infect victims by brute forcing SMB.(Citation: Unit 42 Lucifer June 2020)
- [C0025] 2016 Ukraine Electric Power Attack: During the [2016 Ukraine Electric Power Attack](https://attack.mitre.org/campaigns/C0025), [Sandworm Team](https://attack.mitre.org/groups/G0034) utilized `net use` to connect to network shares.(Citation: Dragos Crashoverride 2018)
- [G0009] Deep Panda: [Deep Panda](https://attack.mitre.org/groups/G0009) uses net.exe to connect to network shares using <code>net use</code> commands with compromised credentials.(Citation: Alperovitch 2014)
- [S0504] Anchor: [Anchor](https://attack.mitre.org/software/S0504) can support windows execution via SMB shares.(Citation: Medium Anchor DNS July 2020)
- [G0087] APT39: [APT39](https://attack.mitre.org/groups/G0087) has used SMB for lateral movement.(Citation: Symantec Chafer February 2018)
- [G0007] APT28: [APT28](https://attack.mitre.org/groups/G0007) has mapped network drives using [Net](https://attack.mitre.org/software/S0039) and administrator credentials.(Citation: Cybersecurity Advisory GRU Brute Force Campaign July 2021)
- [G1046] Storm-1811: [Storm-1811](https://attack.mitre.org/groups/G1046) has attempted to move laterally in victim environments via SMB using [Impacket](https://attack.mitre.org/software/S0357).(Citation: rapid7-email-bombing)

#### T1021.003 - Distributed Component Object Model

Description:

Adversaries may use [Valid Accounts](https://attack.mitre.org/techniques/T1078) to interact with remote machines by taking advantage of Distributed Component Object Model (DCOM). The adversary may then perform actions as the logged-on user.

The Windows Component Object Model (COM) is a component of the native Windows application programming interface (API) that enables interaction between software objects, or executable code that implements one or more interfaces. Through COM, a client object can call methods of server objects, which are typically Dynamic Link Libraries (DLL) or executables (EXE). Distributed COM (DCOM) is transparent middleware that extends the functionality of COM beyond a local computer using remote procedure call (RPC) technology.(Citation: Fireeye Hunting COM June 2019)(Citation: Microsoft COM)

Permissions to interact with local and remote server COM objects are specified by access control lists (ACL) in the Registry.(Citation: Microsoft Process Wide Com Keys) By default, only Administrators may remotely activate and launch COM objects through DCOM.(Citation: Microsoft COM ACL)

Through DCOM, adversaries operating in the context of an appropriately privileged user can remotely obtain arbitrary and even direct shellcode execution through Office applications(Citation: Enigma Outlook DCOM Lateral Movement Nov 2017) as well as other Windows objects that contain insecure methods.(Citation: Enigma MMC20 COM Jan 2017)(Citation: Enigma DCOM Lateral Movement Jan 2017) DCOM can also execute macros in existing documents(Citation: Enigma Excel DCOM Sept 2017) and may also invoke [Dynamic Data Exchange](https://attack.mitre.org/techniques/T1559/002) (DDE) execution directly through a COM created instance of a Microsoft Office application(Citation: Cyberreason DCOM DDE Lateral Movement Nov 2017), bypassing the need for a malicious document. DCOM can be used as a method of remotely interacting with [Windows Management Instrumentation](https://attack.mitre.org/techniques/T1047). (Citation: MSDN WMI)

Procedures:

- [S0363] Empire: [Empire](https://attack.mitre.org/software/S0363) can utilize <code>Invoke-DCOM</code> to leverage remote COM execution for lateral movement.(Citation: Github PowerShell Empire)
- [S0692] SILENTTRINITY: [SILENTTRINITY](https://attack.mitre.org/software/S0692) can use `System` namespace methods to execute lateral movement using DCOM.(Citation: GitHub SILENTTRINITY Modules July 2019)
- [S0154] Cobalt Strike: [Cobalt Strike](https://attack.mitre.org/software/S0154) can deliver Beacon payloads for lateral movement by leveraging remote COM execution.(Citation: Cobalt Strike DCOM Jan 2017)

#### T1021.004 - SSH

Description:

Adversaries may use [Valid Accounts](https://attack.mitre.org/techniques/T1078) to log into remote machines using Secure Shell (SSH). The adversary may then perform actions as the logged-on user.

SSH is a protocol that allows authorized users to open remote shells on other computers. Many Linux and macOS versions come with SSH installed by default, although typically disabled until the user enables it. On ESXi, SSH can be enabled either directly on the host (e.g., via `vim-cmd hostsvc/enable_ssh`) or via vCenter.(Citation: Sygnia ESXi Ransomware 2025)(Citation: TrendMicro ESXI Ransomware)(Citation: Sygnia Abyss Locker 2025) The SSH server can be configured to use standard password authentication or public-private keypairs in lieu of or in addition to a password. In this authentication scenario, the user’s public key must be in a special file on the computer running the server that lists which keypairs are allowed to login as that user (i.e., [SSH Authorized Keys](https://attack.mitre.org/techniques/T1098/004)).

Procedures:

- [G0046] FIN7: [FIN7](https://attack.mitre.org/groups/G0046) has used SSH to move laterally through victim environments.(Citation: CrowdStrike Carbon Spider August 2021)
- [G0032] Lazarus Group: [Lazarus Group](https://attack.mitre.org/groups/G0032) used SSH and the PuTTy PSCP utility to gain access to a restricted segment of a compromised network.(Citation: Kaspersky ThreatNeedle Feb 2021)
- [G0065] Leviathan: [Leviathan](https://attack.mitre.org/groups/G0065) used ssh for internal reconnaissance.(Citation: FireEye APT40 March 2019)
- [C0029] Cutting Edge: During [Cutting Edge](https://attack.mitre.org/campaigns/C0029), threat actors used SSH for lateral movement.(Citation: Volexity Ivanti Zero-Day Exploitation January 2024)
- [C0032] C0032: During the [C0032](https://attack.mitre.org/campaigns/C0032) campaign, [TEMP.Veles](https://attack.mitre.org/groups/G0088) relied on encrypted SSH-based tunnels to transfer tools and for remote command/program execution.(Citation: FireEye TRITON 2019)
- [G0098] BlackTech: [BlackTech](https://attack.mitre.org/groups/G0098) has used Putty for remote access.(Citation: Symantec Palmerworm Sep 2020)
- [S0363] Empire: [Empire](https://attack.mitre.org/software/S0363) contains modules for executing commands over SSH as well as in-memory VNC agent injection.(Citation: Github PowerShell Empire)
- [G0143] Aquatic Panda: [Aquatic Panda](https://attack.mitre.org/groups/G0143) used SSH with captured user credentials to move laterally in victim environments.(Citation: Crowdstrike HuntReport 2022)
- [S0154] Cobalt Strike: [Cobalt Strike](https://attack.mitre.org/software/S0154) can SSH to a remote service.(Citation: Cobalt Strike TTPs Dec 2017)(Citation: Cobalt Strike Manual 4.3 November 2020)
- [S1187] reGeorg: [reGeorg](https://attack.mitre.org/software/S1187) can communicate using SSH through an HTTP tunnel.(Citation: Fortinet reGeorg MAR 2019)
- [G0036] GCMAN: [GCMAN](https://attack.mitre.org/groups/G0036) uses Putty for lateral movement.(Citation: Securelist GCMAN)
- [S0599] Kinsing: [Kinsing](https://attack.mitre.org/software/S0599) has used SSH for lateral movement.(Citation: Aqua Kinsing April 2020)
- [G0117] Fox Kitten: [Fox Kitten](https://attack.mitre.org/groups/G0117) has used the PuTTY and Plink tools for lateral movement.(Citation: CISA AA20-259A Iran-Based Actor September 2020)
- [G0139] TeamTNT: [TeamTNT](https://attack.mitre.org/groups/G0139) has used SSH to connect back to victim machines.(Citation: Intezer TeamTNT September 2020) [TeamTNT](https://attack.mitre.org/groups/G0139) has also used SSH to transfer tools and payloads onto victim hosts and execute them.(Citation: Cisco Talos Intelligence Group)
- [G1046] Storm-1811: [Storm-1811](https://attack.mitre.org/groups/G1046) has used OpenSSH to establish an SSH tunnel to victims for persistent access.(Citation: Microsoft Storm-1811 2024)
- [G1045] Salt Typhoon: [Salt Typhoon](https://attack.mitre.org/groups/G1045) has modified the loopback address on compromised switches and used them as the source of SSH connections to additional devices within the target environment, allowing them to bypass access control lists (ACLs).(Citation: Cisco Salt Typhoon FEB 2025)
- [G0049] OilRig: [OilRig](https://attack.mitre.org/groups/G0049) has used Putty to access compromised systems.(Citation: Unit42 OilRig Playbook 2023)
- [G1023] APT5: [APT5](https://attack.mitre.org/groups/G1023) has used SSH for lateral movement in compromised environments including for enabling access to ESXi host servers.(Citation: Mandiant Pulse Secure Update May 2021)
- [C0049] Leviathan Australian Intrusions: [Leviathan](https://attack.mitre.org/groups/G0065) used SSH brute force techniques to move laterally within victim environments during [Leviathan Australian Intrusions](https://attack.mitre.org/campaigns/C0049).(Citation: CISA Leviathan 2024)
- [G1016] FIN13: [FIN13](https://attack.mitre.org/groups/G1016) has remotely accessed compromised environments via secure shell (SSH) for lateral movement.(Citation: Mandiant FIN13 Aug 2022)
- [G0045] menuPass: [menuPass](https://attack.mitre.org/groups/G0045) has used Putty Secure Copy Client (PSCP) to transfer data.(Citation: PWC Cloud Hopper April 2017)
- [G0119] Indrik Spider: [Indrik Spider](https://attack.mitre.org/groups/G0119) has used SSH for lateral movement.(Citation: Mandiant_UNC2165)
- [G0106] Rocke: [Rocke](https://attack.mitre.org/groups/G0106) has spread its coinminer via SSH.(Citation: Anomali Rocke March 2019)
- [G0087] APT39: [APT39](https://attack.mitre.org/groups/G0087) used secure shell (SSH) to move laterally among their targets.(Citation: FireEye APT39 Jan 2019)

#### T1021.005 - VNC

Description:

Adversaries may use [Valid Accounts](https://attack.mitre.org/techniques/T1078) to remotely control machines using Virtual Network Computing (VNC).  VNC is a platform-independent desktop sharing system that uses the RFB (“remote framebuffer”) protocol to enable users to remotely control another computer’s display by relaying the screen, mouse, and keyboard inputs over the network.(Citation: The Remote Framebuffer Protocol)

VNC differs from [Remote Desktop Protocol](https://attack.mitre.org/techniques/T1021/001) as VNC is screen-sharing software rather than resource-sharing software. By default, VNC uses the system's authentication, but it can be configured to use credentials specific to VNC.(Citation: MacOS VNC software for Remote Desktop)(Citation: VNC Authentication)

Adversaries may abuse VNC to perform malicious actions as the logged-on user such as opening documents, downloading files, and running arbitrary commands. An adversary could use VNC to remotely control and monitor a system to collect data and information to pivot to other systems within the network. Specific VNC libraries/implementations have also been susceptible to brute force attacks and memory usage exploitation.(Citation: Hijacking VNC)(Citation: macOS root VNC login without authentication)(Citation: VNC Vulnerabilities)(Citation: Offensive Security VNC Authentication Check)(Citation: Attacking VNC Servers PentestLab)(Citation: Havana authentication bug)

Procedures:

- [S0412] ZxShell: [ZxShell](https://attack.mitre.org/software/S0412) supports functionality for VNC sessions.(Citation: Talos ZxShell Oct 2014)
- [G0047] Gamaredon Group: [Gamaredon Group](https://attack.mitre.org/groups/G0047) has used VNC tools, including UltraVNC, to remotely interact with compromised hosts.(Citation: Symantec Shuckworm January 2022)(Citation: Microsoft Actinium February 2022)(Citation: Unit 42 Gamaredon February 2022)
- [G0046] FIN7: [FIN7](https://attack.mitre.org/groups/G0046) has used TightVNC to control compromised hosts.(Citation: CrowdStrike Carbon Spider August 2021)
- [S1014] DanBot: [DanBot](https://attack.mitre.org/software/S1014) can use VNC for remote access to targeted systems.(Citation: ClearSky Siamesekitten August 2021)
- [S0484] Carberp: [Carberp](https://attack.mitre.org/software/S0484) can start a remote VNC session by downloading a new plugin.(Citation: Prevx Carberp March 2011)
- [G0036] GCMAN: [GCMAN](https://attack.mitre.org/groups/G0036) uses VNC for lateral movement.(Citation: Securelist GCMAN)
- [G0117] Fox Kitten: [Fox Kitten](https://attack.mitre.org/groups/G0117) has installed TightVNC server and client on compromised servers and endpoints for lateral movement.(Citation: CISA AA20-259A Iran-Based Actor September 2020)
- [S0266] TrickBot: [TrickBot](https://attack.mitre.org/software/S0266) has used a VNC module to monitor the victim and collect information to pivot to valuable systems on the network (Citation: Trickbot VNC module July 2021)(Citation: Bitdefender Trickbot VNC module Whitepaper 2021)
- [S0279] Proton: [Proton](https://attack.mitre.org/software/S0279) uses VNC to connect into systems.(Citation: objsee mac malware 2017)
- [S0670] WarzoneRAT: [WarzoneRAT](https://attack.mitre.org/software/S0670) has the ability of performing remote desktop access via a VNC console.(Citation: Check Point Warzone Feb 2020)
- [S1160] Latrodectus: [Latrodectus](https://attack.mitre.org/software/S1160) has routed C2 traffic using Keyhole VNC.(Citation: Palo Alto Latrodectus Activity June 2024)

#### T1021.006 - Windows Remote Management

Description:

Adversaries may use [Valid Accounts](https://attack.mitre.org/techniques/T1078) to interact with remote systems using Windows Remote Management (WinRM). The adversary may then perform actions as the logged-on user.

WinRM is the name of both a Windows service and a protocol that allows a user to interact with a remote system (e.g., run an executable, modify the Registry, modify services).(Citation: Microsoft WinRM) It may be called with the `winrm` command or by any number of programs such as PowerShell.(Citation: Jacobsen 2014) WinRM  can be used as a method of remotely interacting with [Windows Management Instrumentation](https://attack.mitre.org/techniques/T1047).(Citation: MSDN WMI)

Procedures:

- [G1016] FIN13: [FIN13](https://attack.mitre.org/groups/G1016) has leveraged `WMI` to move laterally within a compromised network via application servers and SQL servers.(Citation: Sygnia Elephant Beetle Jan 2022)
- [S1063] Brute Ratel C4: [Brute Ratel C4](https://attack.mitre.org/software/S1063) can use WinRM for pivoting.(Citation: Palo Alto Brute Ratel July 2022)
- [G0114] Chimera: [Chimera](https://attack.mitre.org/groups/G0114) has used WinRM for lateral movement.(Citation: NCC Group Chimera January 2021)
- [C0024] SolarWinds Compromise: During the [SolarWinds Compromise](https://attack.mitre.org/campaigns/C0024), [APT29](https://attack.mitre.org/groups/G0016) used WinRM via PowerShell to execute commands and payloads on remote hosts.(Citation: Symantec RAINDROP January 2021)
- [S0154] Cobalt Strike: [Cobalt Strike](https://attack.mitre.org/software/S0154) can use <code>WinRM</code> to execute a payload on a remote host.(Citation: cobaltstrike manual)(Citation: Cobalt Strike Manual 4.3 November 2020)
- [C0048] Operation MidnightEclipse: During [Operation MidnightEclipse](https://attack.mitre.org/campaigns/C0048), threat actors used WinRM to move laterally in targeted networks.(Citation: Volexity UPSTYLE 2024)
- [S0692] SILENTTRINITY: [SILENTTRINITY](https://attack.mitre.org/software/S0692) tracks `TrustedHosts` and can move laterally to these targets via WinRM.(Citation: GitHub SILENTTRINITY Modules July 2019)
- [G0027] Threat Group-3390: [Threat Group-3390](https://attack.mitre.org/groups/G0027) has used WinRM to enable remote execution.(Citation: SecureWorks BRONZE UNION June 2017)
- [G0102] Wizard Spider: [Wizard Spider](https://attack.mitre.org/groups/G0102) has used Window Remote Management to move laterally through a victim network.(Citation: DHS/CISA Ransomware Targeting Healthcare October 2020)

#### T1021.007 - Cloud Services

Description:

Adversaries may log into accessible cloud services within a compromised environment using [Valid Accounts](https://attack.mitre.org/techniques/T1078) that are synchronized with or federated to on-premises user identities. The adversary may then perform management actions or access cloud-hosted resources as the logged-on user. 

Many enterprises federate centrally managed user identities to cloud services, allowing users to login with their domain credentials in order to access the cloud control plane. Similarly, adversaries may connect to available cloud services through the web console or through the cloud command line interface (CLI) (e.g., [Cloud API](https://attack.mitre.org/techniques/T1059/009)), using commands such as <code>Connect-AZAccount</code> for Azure PowerShell, <code>Connect-MgGraph</code> for Microsoft Graph PowerShell, and <code>gcloud auth login</code> for the Google Cloud CLI.

In some cases, adversaries may be able to authenticate to these services via [Application Access Token](https://attack.mitre.org/techniques/T1550/001) instead of a username and password.

Procedures:

- [C0027] C0027: During [C0027](https://attack.mitre.org/campaigns/C0027), [Scattered Spider](https://attack.mitre.org/groups/G1015) used compromised Azure credentials for credential theft activity and lateral movement to on-premises systems.(Citation: Crowdstrike TELCO BPO Campaign December 2022)
- [G0016] APT29: [APT29](https://attack.mitre.org/groups/G0016) has leveraged compromised high-privileged on-premises accounts synced to Office 365 to move laterally into a cloud environment, including through the use of Azure AD PowerShell.(Citation: Mandiant Remediation and Hardening Strategies for Microsoft 365)
- [G1015] Scattered Spider: During [C0027](https://attack.mitre.org/campaigns/C0027), [Scattered Spider](https://attack.mitre.org/groups/G1015) used compromised Azure credentials for credential theft activity and lateral movement to on-premises systems.(Citation: Crowdstrike TELCO BPO Campaign December 2022)

Scattered Spider has also leveraged pre-existing AWS EC2 instances for lateral movement and data collection purposes.(Citation: CISA Scattered Spider Advisory November 2023)

#### T1021.008 - Direct Cloud VM Connections

Description:

Adversaries may leverage [Valid Accounts](https://attack.mitre.org/techniques/T1078) to log directly into accessible cloud hosted compute infrastructure through cloud native methods. Many cloud providers offer interactive connections to virtual infrastructure that can be accessed through the [Cloud API](https://attack.mitre.org/techniques/T1059/009), such as Azure Serial Console(Citation: Azure Serial Console), AWS EC2 Instance Connect(Citation: EC2 Instance Connect)(Citation: lucr-3: Getting SaaS-y in the cloud), and AWS System Manager.(Citation: AWS System Manager).

Methods of authentication for these connections can include passwords, application access tokens, or SSH keys. These cloud native methods may, by default, allow for privileged access on the host with SYSTEM or root level access. 

Adversaries may utilize these cloud native methods to directly access virtual infrastructure and pivot through an environment.(Citation: SIM Swapping and Abuse of the Microsoft Azure Serial Console) These connections typically provide direct console access to the VM rather than the execution of scripts (i.e., [Cloud Administration Command](https://attack.mitre.org/techniques/T1651)).


### T1072 - Software Deployment Tools

Description:

Adversaries may gain access to and use centralized software suites installed within an enterprise to execute commands and move laterally through the network. Configuration management and software deployment applications may be used in an enterprise network or cloud environment for routine administration purposes. These systems may also be integrated into CI/CD pipelines. Examples of such solutions include: SCCM, HBSS, Altiris, AWS Systems Manager, Microsoft Intune, Azure Arc, and GCP Deployment Manager.  

Access to network-wide or enterprise-wide endpoint management software may enable an adversary to achieve remote code execution on all connected systems. The access may be used to laterally move to other systems, gather information, or cause a specific effect, such as wiping the hard drives on all endpoints.

SaaS-based configuration management services may allow for broad [Cloud Administration Command](https://attack.mitre.org/techniques/T1651) on cloud-hosted instances, as well as the execution of arbitrary commands on on-premises endpoints. For example, Microsoft Configuration Manager allows Global or Intune Administrators to run scripts as SYSTEM on on-premises devices joined to Entra ID.(Citation: SpecterOps Lateral Movement from Azure to On-Prem AD 2020) Such services may also utilize [Web Protocols](https://attack.mitre.org/techniques/T1071/001) to communicate back to adversary owned infrastructure.(Citation: Mitiga Security Advisory: SSM Agent as Remote Access Trojan)

Network infrastructure devices may also have configuration management tools that can be similarly abused by adversaries.(Citation: Fortinet Zero-Day and Custom Malware Used by Suspected Chinese Actor in Espionage Operation)

The permissions required for this action vary by system configuration; local credentials may be sufficient with direct access to the third-party system, or specific domain credentials may be required. However, the system may require an administrative account to log in or to access specific functionality.

Procedures:

- [G0050] APT32: [APT32](https://attack.mitre.org/groups/G0050) compromised McAfee ePO to move laterally by distributing malware as a software deployment task.(Citation: FireEye APT32 May 2017)
- [G0034] Sandworm Team: [Sandworm Team](https://attack.mitre.org/groups/G0034) has used the commercially available tool RemoteExec for agentless remote code execution.(Citation: Microsoft Prestige ransomware October 2022)
- [G0091] Silence: [Silence](https://attack.mitre.org/groups/G0091) has used RAdmin, a remote software tool used to remotely control workstations and ATMs.(Citation: Group IB Silence Sept 2018)
- [S0041] Wiper: It is believed that a patch management system for an anti-virus product commonly installed among targeted companies was used to distribute the [Wiper](https://attack.mitre.org/software/S0041) malware.(Citation: Dell Wiper)
- [G0028] Threat Group-1314: [Threat Group-1314](https://attack.mitre.org/groups/G0028) actors used a victim's endpoint management platform, Altiris, for lateral movement.(Citation: Dell TG-1314)
- [C0018] C0018: During [C0018](https://attack.mitre.org/campaigns/C0018), the threat actors used PDQ Deploy to move [AvosLocker](https://attack.mitre.org/software/S1053) and tools across the network.(Citation: Cisco Talos Avos Jun 2022)


### T1080 - Taint Shared Content

Description:

Adversaries may deliver payloads to remote systems by adding content to shared storage locations, such as network drives or internal code repositories. Content stored on network drives or in other shared locations may be tainted by adding malicious programs, scripts, or exploit code to otherwise valid files. Once a user opens the shared tainted content, the malicious portion can be executed to run the adversary's code on a remote system. Adversaries may use tainted shared content to move laterally.

A directory share pivot is a variation on this technique that uses several other techniques to propagate malware when users access a shared network directory. It uses [Shortcut Modification](https://attack.mitre.org/techniques/T1547/009) of directory .LNK files that use [Masquerading](https://attack.mitre.org/techniques/T1036) to look like the real directories, which are hidden through [Hidden Files and Directories](https://attack.mitre.org/techniques/T1564/001). The malicious .LNK-based directories have an embedded command that executes the hidden malware file in the directory and then opens the real intended directory so that the user's expected action still occurs. When used with frequently used network directories, the technique may result in frequent reinfections and broad access to systems and potentially to new and higher privileged accounts. (Citation: Retwin Directory Share Pivot)

Adversaries may also compromise shared network directories through binary infections by appending or prepending its code to the healthy binary on the shared network directory. The malware may modify the original entry point (OEP) of the healthy binary to ensure that it is executed before the legitimate code. The infection could continue to spread via the newly infected file when it is executed by a remote system. These infections may target both binary and non-binary formats that end with extensions including, but not limited to, .EXE, .DLL, .SCR, .BAT, and/or .VBS.

Procedures:

- [S0132] H1N1: [H1N1](https://attack.mitre.org/software/S0132) has functionality to copy itself to network shares.(Citation: Cisco H1N1 Part 2)
- [G0012] Darkhotel: [Darkhotel](https://attack.mitre.org/groups/G0012) used a virus that propagates by infecting executables stored on shared drives.(Citation: Kaspersky Darkhotel)
- [G1039] RedCurl: [RedCurl](https://attack.mitre.org/groups/G1039) has placed modified LNK files on network drives for lateral movement.(Citation: group-ib_redcurl1)(Citation: group-ib_redcurl2)
- [S0458] Ramsay: [Ramsay](https://attack.mitre.org/software/S0458) can spread itself by infecting other portable executable files on networks shared drives.(Citation: Eset Ramsay May 2020)
- [G0047] Gamaredon Group: [Gamaredon Group](https://attack.mitre.org/groups/G0047) has injected malicious macros into all Word and Excel documents on mapped network drives.(Citation: ESET Gamaredon June 2020)
- [G0060] BRONZE BUTLER: [BRONZE BUTLER](https://attack.mitre.org/groups/G0060) has placed malware on file shares and given it the same name as legitimate documents on the share.(Citation: Secureworks BRONZE BUTLER Oct 2017)
- [S0260] InvisiMole: [InvisiMole](https://attack.mitre.org/software/S0260) can replace legitimate software or documents in the compromised network with their trojanized versions, in an attempt to propagate itself within the network.(Citation: ESET InvisiMole June 2020)
- [G1021] Cinnamon Tempest: [Cinnamon Tempest](https://attack.mitre.org/groups/G1021) has deployed ransomware from a batch file in a network share.(Citation: Microsoft Ransomware as a Service)
- [S0575] Conti: [Conti](https://attack.mitre.org/software/S0575) can spread itself by infecting other remote machines via network shared drives.(Citation: Cybereason Conti Jan 2021)(Citation: CarbonBlack Conti July 2020)
- [S0133] Miner-C: [Miner-C](https://attack.mitre.org/software/S0133) copies itself into the public folder of Network Attached Storage (NAS) devices and infects new victims who open the file.(Citation: Softpedia MinerC)
- [S0603] Stuxnet: [Stuxnet](https://attack.mitre.org/software/S0603) infects remote servers via network shares and by infecting WinCC database views with malicious code.(Citation: Nicolas Falliere, Liam O Murchu, Eric Chien February 2011)
- [S0386] Ursnif: [Ursnif](https://attack.mitre.org/software/S0386) has copied itself to and infected files in network drives for propagation.(Citation: TrendMicro Ursnif Mar 2015)(Citation: TrendMicro Ursnif File Dec 2014)


### T1091 - Replication Through Removable Media

Description:

Adversaries may move onto systems, possibly those on disconnected or air-gapped networks, by copying malware to removable media and taking advantage of Autorun features when the media is inserted into a system and executes. In the case of Lateral Movement, this may occur through modification of executable files stored on removable media or by copying malware and renaming it to look like a legitimate file to trick users into executing it on a separate system. In the case of Initial Access, this may occur through manual manipulation of the media, modification of systems used to initially format the media, or modification to the media's firmware itself.

Mobile devices may also be used to infect PCs with malware if connected via USB.(Citation: Exploiting Smartphone USB ) This infection may be achieved using devices (Android, iOS, etc.) and, in some instances, USB charging cables.(Citation: Windows Malware Infecting Android)(Citation: iPhone Charging Cable Hack) For example, when a smartphone is connected to a system, it may appear to be mounted similar to a USB-connected disk drive. If malware that is compatible with the connected system is on the mobile device, the malware could infect the machine (especially if Autorun features are enabled).

Procedures:

- [S0143] Flame: [Flame](https://attack.mitre.org/software/S0143) contains modules to infect USB sticks and spread laterally to other Windows systems the stick is plugged into using Autorun functionality.(Citation: Kaspersky Flame)
- [S0028] SHIPSHAPE: [APT30](https://attack.mitre.org/groups/G0013) may have used the [SHIPSHAPE](https://attack.mitre.org/software/S0028) malware to move onto air-gapped networks. [SHIPSHAPE](https://attack.mitre.org/software/S0028) targets removable drives to spread to other systems by modifying the drive to use Autorun to execute or by hiding legitimate document files and copying an executable to the folder with the same name as the legitimate document.(Citation: FireEye APT30)
- [G1014] LuminousMoth: [LuminousMoth](https://attack.mitre.org/groups/G1014) has used malicious DLLs to spread malware to connected removable USB drives on infected machines.(Citation: Kaspersky LuminousMoth July 2021)(Citation: Bitdefender LuminousMoth July 2021)
- [S0130] Unknown Logger: [Unknown Logger](https://attack.mitre.org/software/S0130) is capable of spreading to USB devices.(Citation: Forcepoint Monsoon)
- [G1007] Aoqin Dragon: [Aoqin Dragon](https://attack.mitre.org/groups/G1007) has used a dropper that employs a worm infection strategy using a removable device to breach a secure network environment.(Citation: SentinelOne Aoqin Dragon June 2022)
- [S0062] DustySky: [DustySky](https://attack.mitre.org/software/S0062) searches for removable media and duplicates itself onto it.(Citation: DustySky)
- [S0132] H1N1: [H1N1](https://attack.mitre.org/software/S0132) has functionality to copy itself to removable media.(Citation: Cisco H1N1 Part 2)
- [G0012] Darkhotel: [Darkhotel](https://attack.mitre.org/groups/G0012)'s selective infector modifies executables stored on removable media as a method of spreading across computers.(Citation: Kaspersky Darkhotel)
- [S0603] Stuxnet: [Stuxnet](https://attack.mitre.org/software/S0603) can propagate via removable media using an autorun.inf file or the CVE-2010-2568 LNK vulnerability.(Citation: Nicolas Falliere, Liam O Murchu, Eric Chien February 2011)
- [G0129] Mustang Panda: [Mustang Panda](https://attack.mitre.org/groups/G0129) has used a customized [PlugX](https://attack.mitre.org/software/S0013) variant which could spread through USB connections.(Citation: Avira Mustang Panda January 2020)
- [S1130] Raspberry Robin: [Raspberry Robin](https://attack.mitre.org/software/S1130) has historically used infected USB media to spread to new victims.(Citation: TrendMicro RaspberryRobin 2022)(Citation: RedCanary RaspberryRobin 2022)
- [S0092] Agent.btz: [Agent.btz](https://attack.mitre.org/software/S0092) drops itself onto removable media devices and creates an autorun.inf file with an instruction to run that file. When the device is inserted into another system, it opens autorun.inf and loads the malware.(Citation: ThreatExpert Agent.btz)
- [S0385] njRAT: [njRAT](https://attack.mitre.org/software/S0385) can be configured to spread via removable drives.(Citation: Fidelis njRAT June 2013)(Citation: Trend Micro njRAT 2018)
- [S0452] USBferry: [USBferry](https://attack.mitre.org/software/S0452) can copy its installer to attached USB storage devices.(Citation: TrendMicro Tropic Trooper May 2020)
- [S0023] CHOPSTICK: Part of [APT28](https://attack.mitre.org/groups/G0007)'s operation involved using [CHOPSTICK](https://attack.mitre.org/software/S0023) modules to copy itself to air-gapped machines and using files written to USB sticks to transfer data and command traffic.(Citation: FireEye APT28)(Citation: Microsoft SIR Vol 19)(Citation: Secureworks IRON TWILIGHT Active Measures March 2017)
- [S0115] Crimson: [Crimson](https://attack.mitre.org/software/S0115) can spread across systems by infecting removable media.(Citation: Kaspersky Transparent Tribe August 2020)
- [G0046] FIN7: [FIN7](https://attack.mitre.org/groups/G0046) actors have mailed USB drives to potential victims containing malware that downloads and installs various backdoors, including in some cases for ransomware operations.(Citation: FBI Flash FIN7 USB)
- [S0458] Ramsay: [Ramsay](https://attack.mitre.org/software/S0458) can spread itself by infecting other portable executable files on removable drives.(Citation: Eset Ramsay May 2020)
- [S0650] QakBot: [QakBot](https://attack.mitre.org/software/S0650) has the ability to use removable drives to spread through compromised networks.(Citation: Trend Micro Qakbot May 2020)
- [S1074] ANDROMEDA: [ANDROMEDA](https://attack.mitre.org/software/S1074) has been spread via infected USB keys.(Citation: Mandiant Suspected Turla Campaign February 2023)
- [S0136] USBStealer: [USBStealer](https://attack.mitre.org/software/S0136) drops itself onto removable media and relies on Autorun to execute the malicious file when a user opens the removable media on another system.(Citation: ESET Sednit USBStealer 2014)
- [G0007] APT28: [APT28](https://attack.mitre.org/groups/G0007) uses a tool to infect connected USB devices and transmit itself to air-gapped computers when the infected USB device is inserted.(Citation: Microsoft SIR Vol 19)
- [S0608] Conficker: [Conficker](https://attack.mitre.org/software/S0608) variants used the Windows AUTORUN feature to spread through USB propagation.(Citation: SANS Conficker)(Citation: Trend Micro Conficker)
- [S0386] Ursnif: [Ursnif](https://attack.mitre.org/software/S0386) has copied itself to and infected removable drives for propagation.(Citation: TrendMicro Ursnif Mar 2015)(Citation: TrendMicro Ursnif File Dec 2014)
- [G0081] Tropic Trooper: [Tropic Trooper](https://attack.mitre.org/groups/G0081) has attempted to transfer [USBferry](https://attack.mitre.org/software/S0452) from an infected USB device by copying an Autorun function to the target machine.(Citation: TrendMicro Tropic Trooper May 2020)


### T1210 - Exploitation of Remote Services

Description:

Adversaries may exploit remote services to gain unauthorized access to internal systems once inside of a network. Exploitation of a software vulnerability occurs when an adversary takes advantage of a programming error in a program, service, or within the operating system software or kernel itself to execute adversary-controlled code. A common goal for post-compromise exploitation of remote services is for lateral movement to enable access to a remote system.

An adversary may need to determine if the remote system is in a vulnerable state, which may be done through [Network Service Discovery](https://attack.mitre.org/techniques/T1046) or other Discovery methods looking for common, vulnerable software that may be deployed in the network, the lack of certain patches that may indicate vulnerabilities,  or security software that may be used to detect or contain remote exploitation. Servers are likely a high value target for lateral movement exploitation, but endpoint systems may also be at risk if they provide an advantage or access to additional resources.

There are several well-known vulnerabilities that exist in common services such as SMB(Citation: CIS Multiple SMB Vulnerabilities) and RDP(Citation: NVD CVE-2017-0176) as well as applications that may be used within internal networks such as MySQL(Citation: NVD CVE-2016-6662) and web server services.(Citation: NVD CVE-2014-7169)(Citation: Ars Technica VMWare Code Execution Vulnerability 2021) Additionally, there have been a number of vulnerabilities in VMware vCenter installations, which may enable threat actors to move laterally from the compromised vCenter server to virtual machines or even to ESXi hypervisors.(Citation: Broadcom VMSA-2024-0019)

Depending on the permissions level of the vulnerable remote service an adversary may achieve [Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1068) as a result of lateral movement exploitation as well.

Procedures:

- [S0143] Flame: [Flame](https://attack.mitre.org/software/S0143) can use MS10-061 to exploit a print spooler vulnerability in a remote system with a shared printer in order to move laterally.(Citation: Kaspersky Flame)(Citation: Kaspersky Flame Functionality)
- [S0366] WannaCry: [WannaCry](https://attack.mitre.org/software/S0366) uses an exploit in SMBv1 to spread itself to other remote systems on a network.(Citation: LogRhythm WannaCry)(Citation: FireEye WannaCry 2017)(Citation: US-CERT WannaCry 2017)
- [G0102] Wizard Spider: [Wizard Spider](https://attack.mitre.org/groups/G0102) has exploited or attempted to exploit Zerologon (CVE-2020-1472) and EternalBlue (MS17-010) vulnerabilities.(Citation: FireEye KEGTAP SINGLEMALT October 2020)(Citation: DFIR Ryuk's Return October 2020)(Citation: DFIR Ryuk in 5 Hours October 2020)
- [G0117] Fox Kitten: [Fox Kitten](https://attack.mitre.org/groups/G0117) has exploited known vulnerabilities in remote services including RDP.(Citation: ClearkSky Fox Kitten February 2020)(Citation: CrowdStrike PIONEER KITTEN August 2020)(Citation: ClearSky Pay2Kitten December 2020)
- [G1006] Earth Lusca: [Earth Lusca](https://attack.mitre.org/groups/G1006) has used [Mimikatz](https://attack.mitre.org/software/S0002) to exploit a domain controller via the ZeroLogon exploit (CVE-2020-1472).(Citation: TrendMicro EarthLusca 2022)
- [S0603] Stuxnet: [Stuxnet](https://attack.mitre.org/software/S0603) propagates using the MS10-061 Print Spooler and MS08-067 Windows Server Service vulnerabilities.(Citation: Nicolas Falliere, Liam O Murchu, Eric Chien February 2011)
- [S0650] QakBot: [QakBot](https://attack.mitre.org/software/S0650) can move laterally using worm-like functionality through exploitation of SMB.(Citation: Crowdstrike Qakbot October 2020)
- [S0367] Emotet: [Emotet](https://attack.mitre.org/software/S0367) has been seen exploiting SMB via a vulnerability exploit like EternalBlue (MS17-010) to achieve lateral movement and propagation.(Citation: Symantec Emotet Jul 2018)(Citation: US-CERT Emotet Jul 2018)(Citation: Secureworks Emotet Nov 2018)(Citation: Red Canary Emotet Feb 2019)
- [S0363] Empire: [Empire](https://attack.mitre.org/software/S0363) has a limited number of built-in modules for exploiting remote SMB, JBoss, and Jenkins servers.(Citation: Github PowerShell Empire)
- [S0606] Bad Rabbit: [Bad Rabbit](https://attack.mitre.org/software/S0606) used the EternalRomance SMB exploit to spread through victim networks.(Citation: Secure List Bad Rabbit)
- [S0368] NotPetya: [NotPetya](https://attack.mitre.org/software/S0368) can use two exploits in SMBv1, EternalBlue and EternalRomance, to spread itself to other remote systems on the network.(Citation: Talos Nyetya June 2017)(Citation: US-CERT NotPetya 2017)(Citation: US District Court Indictment GRU Unit 74455 October 2020)
- [G1003] Ember Bear: [Ember Bear](https://attack.mitre.org/groups/G1003) has used exploits for vulnerabilities such as MS17-010, also known as `Eternal Blue`, during operations.(Citation: CISA GRU29155 2024)
- [S0260] InvisiMole: [InvisiMole](https://attack.mitre.org/software/S0260) can spread within a network via the BlueKeep (CVE-2019-0708) and EternalBlue (CVE-2017-0144) vulnerabilities in RDP and SMB respectively.(Citation: ESET InvisiMole June 2020)
- [G0007] APT28: [APT28](https://attack.mitre.org/groups/G0007) exploited a Windows SMB Remote Code Execution Vulnerability to conduct lateral movement.(Citation: FireEye APT28)(Citation: FireEye APT28 Hospitality Aug 2017)(Citation: MS17-010 March 2017)
- [S0608] Conficker: [Conficker](https://attack.mitre.org/software/S0608) exploited the MS08-067 Windows vulnerability for remote code execution through a crafted RPC request.(Citation: SANS Conficker)
- [S0378] PoshC2: [PoshC2](https://attack.mitre.org/software/S0378) contains a module for exploiting SMB via EternalBlue.(Citation: GitHub PoshC2)
- [S0532] Lucifer: [Lucifer](https://attack.mitre.org/software/S0532) can exploit multiple vulnerabilities including EternalBlue (CVE-2017-0144) and EternalRomance (CVE-2017-0144).(Citation: Unit 42 Lucifer June 2020)
- [G0131] Tonto Team: [Tonto Team](https://attack.mitre.org/groups/G0131) has used EternalBlue exploits for lateral movement.(Citation: TrendMicro Tonto Team October 2020)
- [G0045] menuPass: [menuPass](https://attack.mitre.org/groups/G0045) has used tools to exploit the ZeroLogon vulnerability (CVE-2020-1472).(Citation: Symantec Cicada November 2020)
- [S0266] TrickBot: [TrickBot](https://attack.mitre.org/software/S0266) utilizes EternalBlue and EternalRomance exploits for lateral movement in the modules wormwinDll, wormDll, mwormDll, nwormDll, tabDll.(Citation: ESET Trickbot Oct 2020)
- [G0035] Dragonfly: [Dragonfly](https://attack.mitre.org/groups/G0035) has exploited a Windows Netlogon vulnerability (CVE-2020-1472) to obtain access to Windows Active Directory servers.(Citation: CISA AA20-296A Berserk Bear December 2020)
- [G0069] MuddyWater: [MuddyWater](https://attack.mitre.org/groups/G0069) has exploited the Microsoft Netlogon vulnerability (CVE-2020-1472).(Citation: DHS CISA AA22-055A MuddyWater February 2022)
- [G0027] Threat Group-3390: [Threat Group-3390](https://attack.mitre.org/groups/G0027) has exploited MS17-010 to move laterally to other systems on the network.(Citation: Unit42 Emissary Panda May 2019)
- [G0046] FIN7: [FIN7](https://attack.mitre.org/groups/G0046) has exploited ZeroLogon (CVE-2020-1472) against vulnerable domain controllers.(Citation: CrowdStrike Carbon Spider August 2021)


### T1534 - Internal Spearphishing

Description:

After they already have access to accounts or systems within the environment, adversaries may use internal spearphishing to gain access to additional information or compromise other users within the same organization. Internal spearphishing is multi-staged campaign where a legitimate account is initially compromised either by controlling the user's device or by compromising the account credentials of the user. Adversaries may then attempt to take advantage of the trusted internal account to increase the likelihood of tricking more victims into falling for phish attempts, often incorporating [Impersonation](https://attack.mitre.org/techniques/T1656).(Citation: Trend Micro - Int SP)

For example, adversaries may leverage [Spearphishing Attachment](https://attack.mitre.org/techniques/T1566/001) or [Spearphishing Link](https://attack.mitre.org/techniques/T1566/002) as part of internal spearphishing to deliver a payload or redirect to an external site to capture credentials through [Input Capture](https://attack.mitre.org/techniques/T1056) on sites that mimic login interfaces.

Adversaries may also leverage internal chat apps, such as Microsoft Teams, to spread malicious content or engage users in attempts to capture sensitive information and/or credentials.(Citation: Int SP - chat apps)

Procedures:

- [G0047] Gamaredon Group: [Gamaredon Group](https://attack.mitre.org/groups/G0047) has used an Outlook VBA module on infected systems to send phishing emails with malicious attachments to other employees within the organization.(Citation: ESET Gamaredon June 2020)
- [G0094] Kimsuky: [Kimsuky](https://attack.mitre.org/groups/G0094) has sent internal spearphishing emails for lateral movement after stealing victim information.(Citation: KISA Operation Muzabi)
- [C0022] Operation Dream Job: During [Operation Dream Job](https://attack.mitre.org/campaigns/C0022), [Lazarus Group](https://attack.mitre.org/groups/G0032) conducted internal spearphishing from within a compromised organization.(Citation: ClearSky Lazarus Aug 2020)
- [G0065] Leviathan: [Leviathan](https://attack.mitre.org/groups/G0065) has conducted internal spearphishing within the victim's environment for lateral movement.(Citation: CISA AA21-200A APT40 July 2021)
- [G1001] HEXANE: [HEXANE](https://attack.mitre.org/groups/G1001) has conducted internal spearphishing attacks against executives, HR, and IT personnel to gain information and access.(Citation: SecureWorks August 2019)


### T1550 - Use Alternate Authentication Material

Description:

Adversaries may use alternate authentication material, such as password hashes, Kerberos tickets, and application access tokens, in order to move laterally within an environment and bypass normal system access controls. 

Authentication processes generally require a valid identity (e.g., username) along with one or more authentication factors (e.g., password, pin, physical smart card, token generator, etc.). Alternate authentication material is legitimately generated by systems after a user or application successfully authenticates by providing a valid identity and the required authentication factor(s). Alternate authentication material may also be generated during the identity creation process.(Citation: NIST Authentication)(Citation: NIST MFA)

Caching alternate authentication material allows the system to verify an identity has successfully authenticated without asking the user to reenter authentication factor(s). Because the alternate authentication must be maintained by the system—either in memory or on disk—it may be at risk of being stolen through [Credential Access](https://attack.mitre.org/tactics/TA0006) techniques. By stealing alternate authentication material, adversaries are able to bypass system access controls and authenticate to systems without knowing the plaintext password or any additional authentication factors.

Procedures:

- [C0024] SolarWinds Compromise: During the [SolarWinds Compromise](https://attack.mitre.org/campaigns/C0024), [APT29](https://attack.mitre.org/groups/G0016) used forged SAML tokens that allowed the actors to impersonate users and bypass MFA, enabling [APT29](https://attack.mitre.org/groups/G0016) to access enterprise cloud applications and services.(Citation: Microsoft 365 Defender Solorigate)(Citation: Secureworks IRON RITUAL Profile)
- [S0661] FoggyWeb: [FoggyWeb](https://attack.mitre.org/software/S0661) can allow abuse of a compromised AD FS server's SAML token.(Citation: MSTIC FoggyWeb September 2021)

#### T1550.001 - Application Access Token

Description:

Adversaries may use stolen application access tokens to bypass the typical authentication process and access restricted accounts, information, or services on remote systems. These tokens are typically stolen from users or services and used in lieu of login credentials.

Application access tokens are used to make authorized API requests on behalf of a user or service and are commonly used to access resources in cloud, container-based applications, and software-as-a-service (SaaS).(Citation: Auth0 - Why You Should Always Use Access Tokens to Secure APIs Sept 2019) 

OAuth is one commonly implemented framework that issues tokens to users for access to systems. These frameworks are used collaboratively to verify the user and determine what actions the user is allowed to perform. Once identity is established, the token allows actions to be authorized, without passing the actual credentials of the user. Therefore, compromise of the token can grant the adversary access to resources of other sites through a malicious application.(Citation: okta)

For example, with a cloud-based email service, once an OAuth access token is granted to a malicious application, it can potentially gain long-term access to features of the user account if a "refresh" token enabling background access is awarded.(Citation: Microsoft Identity Platform Access 2019) With an OAuth access token an adversary can use the user-granted REST API to perform functions such as email searching and contact enumeration.(Citation: Staaldraad Phishing with OAuth 2017)

Compromised access tokens may be used as an initial step in compromising other services. For example, if a token grants access to a victim’s primary email, the adversary may be able to extend access to all other services which the target subscribes by triggering forgotten password routines. In AWS and GCP environments, adversaries can trigger a request for a short-lived access token with the privileges of another user account.(Citation: Google Cloud Service Account Credentials)(Citation: AWS Temporary Security Credentials) The adversary can then use this token to request data or perform actions the original account could not. If permissions for this feature are misconfigured – for example, by allowing all users to request a token for a particular account - an adversary may be able to gain initial access to a Cloud Account or escalate their privileges.(Citation: Rhino Security Labs Enumerating AWS Roles)

Direct API access through a token negates the effectiveness of a second authentication factor and may be immune to intuitive countermeasures like changing passwords.  For example, in AWS environments, an adversary who compromises a user’s AWS API credentials may be able to use the `sts:GetFederationToken` API call to create a federated user session, which will have the same permissions as the original user but may persist even if the original user credentials are deactivated.(Citation: Crowdstrike AWS User Federation Persistence) Additionally, access abuse over an API channel can be difficult to detect even from the service provider end, as the access can still align well with a legitimate workflow.

Procedures:

- [S0683] Peirates: [Peirates](https://attack.mitre.org/software/S0683) can use stolen service account tokens to perform its operations. It also enables adversaries to switch between valid service accounts.(Citation: Peirates GitHub)
- [S1023] CreepyDrive: [CreepyDrive](https://attack.mitre.org/software/S1023) can use legitimate OAuth refresh tokens to authenticate with OneDrive.(Citation: Microsoft POLONIUM June 2022)
- [C0024] SolarWinds Compromise: During the [SolarWinds Compromise](https://attack.mitre.org/campaigns/C0024), [APT29](https://attack.mitre.org/groups/G0016) used compromised service principals to make changes to the Office 365 environment.(Citation: CrowdStrike StellarParticle January 2022)
- [G0007] APT28: [APT28](https://attack.mitre.org/groups/G0007) has used several malicious applications that abused OAuth access tokens to gain access to target email accounts, including Gmail and Yahoo Mail.(Citation: Trend Micro Pawn Storm OAuth 2017)
- [G0125] HAFNIUM: [HAFNIUM](https://attack.mitre.org/groups/G0125) has abused service principals with administrative permissions for data exfiltration.(Citation: Microsoft Silk Typhoon MAR 2025)

#### T1550.002 - Pass the Hash

Description:

Adversaries may “pass the hash” using stolen password hashes to move laterally within an environment, bypassing normal system access controls. Pass the hash (PtH) is a method of authenticating as a user without having access to the user's cleartext password. This method bypasses standard authentication steps that require a cleartext password, moving directly into the portion of the authentication that uses the password hash.

When performing PtH, valid password hashes for the account being used are captured using a [Credential Access](https://attack.mitre.org/tactics/TA0006) technique. Captured hashes are used with PtH to authenticate as that user. Once authenticated, PtH may be used to perform actions on local or remote systems.

Adversaries may also use stolen password hashes to "overpass the hash." Similar to PtH, this involves using a password hash to authenticate as a user but also uses the password hash to create a valid Kerberos ticket. This ticket can then be used to perform [Pass the Ticket](https://attack.mitre.org/techniques/T1550/003) attacks.(Citation: Stealthbits Overpass-the-Hash)

Procedures:

- [G0050] APT32: [APT32](https://attack.mitre.org/groups/G0050) has used pass the hash for lateral movement.(Citation: Cybereason Cobalt Kitty 2017)
- [S0154] Cobalt Strike: [Cobalt Strike](https://attack.mitre.org/software/S0154) can perform pass the hash.(Citation: Cobalt Strike TTPs Dec 2017)
- [S0122] Pass-The-Hash Toolkit: [Pass-The-Hash Toolkit](https://attack.mitre.org/software/S0122) can perform pass the hash.(Citation: Mandiant APT1)
- [G0007] APT28: [APT28](https://attack.mitre.org/groups/G0007) has used pass the hash for lateral movement.(Citation: Microsoft SIR Vol 19)
- [G0143] Aquatic Panda: [Aquatic Panda](https://attack.mitre.org/groups/G0143) used a registry edit to enable a Windows feature called <code>RestrictedAdmin</code> in victim environments. This change allowed [Aquatic Panda](https://attack.mitre.org/groups/G0143) to leverage "pass the hash" mechanisms as the alteration allows for RDP connections with a valid account name and hash only, without possessing a cleartext password value.(Citation: Crowdstrike HuntReport 2022)
- [G0114] Chimera: [Chimera](https://attack.mitre.org/groups/G0114) has dumped password hashes for use in pass the hash authentication attacks.(Citation: NCC Group Chimera January 2021)
- [G0006] APT1: The [APT1](https://attack.mitre.org/groups/G0006) group is known to have used pass the hash.(Citation: Mandiant APT1)
- [G0102] Wizard Spider: [Wizard Spider](https://attack.mitre.org/groups/G0102) has used the `Invoke-SMBExec` PowerShell cmdlet to execute the pass-the-hash technique and utilized stolen password hashes to move laterally.(Citation: Mandiant FIN12 Oct 2021)
- [S0376] HOPLIGHT: [HOPLIGHT](https://attack.mitre.org/software/S0376) has been observed loading several APIs associated with Pass the Hash.(Citation: US-CERT HOPLIGHT Apr 2019)
- [S0378] PoshC2: [PoshC2](https://attack.mitre.org/software/S0378) has a number of modules that leverage pass the hash for lateral movement.(Citation: GitHub PoshC2)
- [S0002] Mimikatz: [Mimikatz](https://attack.mitre.org/software/S0002)'s <code>SEKURLSA::Pth</code> module can impersonate a user, with only a password hash, to execute arbitrary commands.(Citation: Adsecurity Mimikatz Guide)(Citation: NCSC Joint Report Public Tools)(Citation: Cobalt Strike Manual 4.3 November 2020)
- [G0096] APT41: [APT41](https://attack.mitre.org/groups/G0096) uses tools such as [Mimikatz](https://attack.mitre.org/software/S0002) to enable lateral movement via captured password hashes.(Citation: Rostovcev APT41 2021)
- [G0094] Kimsuky: [Kimsuky](https://attack.mitre.org/groups/G0094) has used pass the hash for authentication to remote access software used in C2.(Citation: CISA AA20-301A Kimsuky)
- [S0363] Empire: [Empire](https://attack.mitre.org/software/S0363) can perform pass the hash attacks.(Citation: Github PowerShell Empire)
- [G1016] FIN13: [FIN13](https://attack.mitre.org/groups/G1016) has used the PowerShell utility `Invoke-SMBExec` to execute the pass the hash method for lateral movement within an compromised environment.(Citation: Mandiant FIN13 Aug 2022)
- [G1003] Ember Bear: [Ember Bear](https://attack.mitre.org/groups/G1003) has used pass-the-hash techniques for lateral movement in victim environments.(Citation: CISA GRU29155 2024)
- [S1081] BADHATCH: [BADHATCH](https://attack.mitre.org/software/S1081) can perform pass the hash on compromised machines with x64 versions.(Citation: BitDefender BADHATCH Mar 2021)
- [S0488] CrackMapExec: [CrackMapExec](https://attack.mitre.org/software/S0488) can pass the hash to authenticate via SMB.(Citation: CME Github September 2018)
- [C0002] Night Dragon: During [Night Dragon](https://attack.mitre.org/campaigns/C0002), threat actors used pass-the-hash tools to obtain authenticated access to sensitive internal desktops and servers.(Citation: McAfee Night Dragon)
- [G0093] GALLIUM: [GALLIUM](https://attack.mitre.org/groups/G0093) used dumped hashes to authenticate to other machines via pass the hash.(Citation: Cybereason Soft Cell June 2019)

#### T1550.003 - Pass the Ticket

Description:

Adversaries may “pass the ticket” using stolen Kerberos tickets to move laterally within an environment, bypassing normal system access controls. Pass the ticket (PtT) is a method of authenticating to a system using Kerberos tickets without having access to an account's password. Kerberos authentication can be used as the first step to lateral movement to a remote system.

When preforming PtT, valid Kerberos tickets for [Valid Accounts](https://attack.mitre.org/techniques/T1078) are captured by [OS Credential Dumping](https://attack.mitre.org/techniques/T1003). A user's service tickets or ticket granting ticket (TGT) may be obtained, depending on the level of access. A service ticket allows for access to a particular resource, whereas a TGT can be used to request service tickets from the Ticket Granting Service (TGS) to access any resource the user has privileges to access.(Citation: ADSecurity AD Kerberos Attacks)(Citation: GentilKiwi Pass the Ticket)

A [Silver Ticket](https://attack.mitre.org/techniques/T1558/002) can be obtained for services that use Kerberos as an authentication mechanism and are used to generate tickets to access that particular resource and the system that hosts the resource (e.g., SharePoint).(Citation: ADSecurity AD Kerberos Attacks)

A [Golden Ticket](https://attack.mitre.org/techniques/T1558/001) can be obtained for the domain using the Key Distribution Service account KRBTGT account NTLM hash, which enables generation of TGTs for any account in Active Directory.(Citation: Campbell 2014)

Adversaries may also create a valid Kerberos ticket using other user information, such as stolen password hashes or AES keys. For example, "overpassing the hash" involves using a NTLM password hash to authenticate as a user (i.e. [Pass the Hash](https://attack.mitre.org/techniques/T1550/002)) while also using the password hash to create a valid Kerberos ticket.(Citation: Stealthbits Overpass-the-Hash)

Procedures:

- [S0053] SeaDuke: Some [SeaDuke](https://attack.mitre.org/software/S0053) samples have a module to use pass the ticket with Kerberos for authentication.(Citation: Symantec Seaduke 2015)
- [G0016] APT29: [APT29](https://attack.mitre.org/groups/G0016) used Kerberos ticket attacks for lateral movement.(Citation: Mandiant No Easy Breach)
- [S0002] Mimikatz: [Mimikatz](https://attack.mitre.org/software/S0002)’s <code>LSADUMP::DCSync</code> and <code>KERBEROS::PTT</code> modules implement the three steps required to extract the krbtgt account hash and create/use Kerberos tickets.(Citation: Adsecurity Mimikatz Guide)(Citation: AdSecurity Kerberos GT Aug 2015)(Citation: Harmj0y DCSync Sept 2015)(Citation: NCSC Joint Report Public Tools)
- [S0192] Pupy: [Pupy](https://attack.mitre.org/software/S0192) can also perform pass-the-ticket.(Citation: GitHub Pupy)
- [G0050] APT32: [APT32](https://attack.mitre.org/groups/G0050) successfully gained remote access by using pass the ticket.(Citation: Cybereason Cobalt Kitty 2017)
- [G0060] BRONZE BUTLER: [BRONZE BUTLER](https://attack.mitre.org/groups/G0060) has created forged Kerberos Ticket Granting Ticket (TGT) and Ticket Granting Service (TGS) tickets to maintain administrative access.(Citation: Secureworks BRONZE BUTLER Oct 2017)

#### T1550.004 - Web Session Cookie

Description:

Adversaries can use stolen session cookies to authenticate to web applications and services. This technique bypasses some multi-factor authentication protocols since the session is already authenticated.(Citation: Pass The Cookie)

Authentication cookies are commonly used in web applications, including cloud-based services, after a user has authenticated to the service so credentials are not passed and re-authentication does not need to occur as frequently. Cookies are often valid for an extended period of time, even if the web application is not actively used. After the cookie is obtained through [Steal Web Session Cookie](https://attack.mitre.org/techniques/T1539) or [Web Cookies](https://attack.mitre.org/techniques/T1606/001), the adversary may then import the cookie into a browser they control and is then able to use the site or application as the user for as long as the session cookie is active. Once logged into the site, an adversary can access sensitive information, read email, or perform actions that the victim account has permissions to perform.

There have been examples of malware targeting session cookies to bypass multi-factor authentication systems.(Citation: Unit 42 Mac Crypto Cookies January 2019)

Procedures:

- [G1033] Star Blizzard: [Star Blizzard](https://attack.mitre.org/groups/G1033) has bypassed multi-factor authentication on victim email accounts by using session cookies stolen using EvilGinx.(Citation: CISA Star Blizzard Advisory December 2023)
- [C0024] SolarWinds Compromise: During the [SolarWinds Compromise](https://attack.mitre.org/campaigns/C0024), [APT29](https://attack.mitre.org/groups/G0016) used stolen cookies to access cloud resources and a forged `duo-sid` cookie to bypass MFA set on an email account.(Citation: Volexity SolarWinds)(Citation: CrowdStrike StellarParticle January 2022)


### T1563 - Remote Service Session Hijacking

Description:

Adversaries may take control of preexisting sessions with remote services to move laterally in an environment. Users may use valid credentials to log into a service specifically designed to accept remote connections, such as telnet, SSH, and RDP. When a user logs into a service, a session will be established that will allow them to maintain a continuous interaction with that service.

Adversaries may commandeer these sessions to carry out actions on remote systems. [Remote Service Session Hijacking](https://attack.mitre.org/techniques/T1563) differs from use of [Remote Services](https://attack.mitre.org/techniques/T1021) because it hijacks an existing session rather than creating a new session using [Valid Accounts](https://attack.mitre.org/techniques/T1078).(Citation: RDP Hijacking Medium)(Citation: Breach Post-mortem SSH Hijack)

#### T1563.001 - SSH Hijacking

Description:

Adversaries may hijack a legitimate user's SSH session to move laterally within an environment. Secure Shell (SSH) is a standard means of remote access on Linux and macOS systems. It allows a user to connect to another system via an encrypted tunnel, commonly authenticating through a password, certificate or the use of an asymmetric encryption key pair.

In order to move laterally from a compromised host, adversaries may take advantage of trust relationships established with other systems via public key authentication in active SSH sessions by hijacking an existing connection to another system. This may occur through compromising the SSH agent itself or by having access to the agent's socket. If an adversary is able to obtain root access, then hijacking SSH sessions is likely trivial.(Citation: Slideshare Abusing SSH)(Citation: SSHjack Blackhat)(Citation: Clockwork SSH Agent Hijacking)(Citation: Breach Post-mortem SSH Hijack)

[SSH Hijacking](https://attack.mitre.org/techniques/T1563/001) differs from use of [SSH](https://attack.mitre.org/techniques/T1021/004) because it hijacks an existing SSH session rather than creating a new session using [Valid Accounts](https://attack.mitre.org/techniques/T1078).

#### T1563.002 - RDP Hijacking

Description:

Adversaries may hijack a legitimate user’s remote desktop session to move laterally within an environment. Remote desktop is a common feature in operating systems. It allows a user to log into an interactive session with a system desktop graphical user interface on a remote system. Microsoft refers to its implementation of the Remote Desktop Protocol (RDP) as Remote Desktop Services (RDS).(Citation: TechNet Remote Desktop Services)

Adversaries may perform RDP session hijacking which involves stealing a legitimate user's remote session. Typically, a user is notified when someone else is trying to steal their session. With System permissions and using Terminal Services Console, `c:\windows\system32\tscon.exe [session number to be stolen]`, an adversary can hijack a session without the need for credentials or prompts to the user.(Citation: RDP Hijacking Korznikov) This can be done remotely or locally and with active or disconnected sessions.(Citation: RDP Hijacking Medium) It can also lead to [Remote System Discovery](https://attack.mitre.org/techniques/T1018) and Privilege Escalation by stealing a Domain Admin or higher privileged account session. All of this can be done by using native Windows commands, but it has also been added as a feature in red teaming tools.(Citation: Kali Redsnarf)

Procedures:

- [S0366] WannaCry: [WannaCry](https://attack.mitre.org/software/S0366) enumerates current remote desktop sessions and tries to execute the malware on each session.(Citation: LogRhythm WannaCry)
- [G0001] Axiom: [Axiom](https://attack.mitre.org/groups/G0001) has targeted victims with remote administration tools including RDP.(Citation: Novetta-Axiom)


### T1570 - Lateral Tool Transfer

Description:

Adversaries may transfer tools or other files between systems in a compromised environment. Once brought into the victim environment (i.e., [Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105)) files may then be copied from one system to another to stage adversary tools or other files over the course of an operation.

Adversaries may copy files between internal victim systems to support lateral movement using inherent file sharing protocols such as file sharing over [SMB/Windows Admin Shares](https://attack.mitre.org/techniques/T1021/002) to connected network shares or with authenticated connections via [Remote Desktop Protocol](https://attack.mitre.org/techniques/T1021/001).(Citation: Unit42 LockerGoga 2019)

Files can also be transferred using native or otherwise present tools on the victim system, such as scp, rsync, curl, sftp, and [ftp](https://attack.mitre.org/software/S0095). In some cases, adversaries may be able to leverage [Web Service](https://attack.mitre.org/techniques/T1102)s such as Dropbox or OneDrive to copy files from one machine to another via shared, automatically synced folders.(Citation: Dropbox Malware Sync)

Procedures:

- [S0367] Emotet: [Emotet](https://attack.mitre.org/software/S0367) has copied itself to remote systems using the `service.exe` filename.(Citation: Binary Defense Emotes Wi-Fi Spreader)
- [S1139] INC Ransomware: [INC Ransomware](https://attack.mitre.org/software/S1139) can push its encryption executable to multiple endpoints within compromised infrastructure.(Citation: Huntress INC Ransom Group August 2023)
- [S1068] BlackCat: [BlackCat](https://attack.mitre.org/software/S1068) can replicate itself across connected servers via `psexec`.(Citation: Microsoft BlackCat Jun 2022)
- [S1132] IPsec Helper: [IPsec Helper](https://attack.mitre.org/software/S1132) can download additional payloads from command and control nodes and execute them.(Citation: SentinelOne Agrius 2021)
- [G0050] APT32: [APT32](https://attack.mitre.org/groups/G0050) has deployed tools after moving laterally using administrative accounts.(Citation: Cybereason Cobalt Kitty 2017)
- [G1007] Aoqin Dragon: [Aoqin Dragon](https://attack.mitre.org/groups/G1007) has spread malware in target networks by copying modules to folders masquerading as removable devices.(Citation: SentinelOne Aoqin Dragon June 2022)
- [S0457] Netwalker: Operators deploying [Netwalker](https://attack.mitre.org/software/S0457) have used psexec to copy the [Netwalker](https://attack.mitre.org/software/S0457) payload across accessible systems.(Citation: Sophos Netwalker May 2020)
- [S0190] BITSAdmin: [BITSAdmin](https://attack.mitre.org/software/S0190) can be used to create [BITS Jobs](https://attack.mitre.org/techniques/T1197) to upload and/or download files from SMB file servers.(Citation: Microsoft About BITS)
- [G0051] FIN10: [FIN10](https://attack.mitre.org/groups/G0051) has deployed Meterpreter stagers and SplinterRAT instances in the victim network after moving laterally.(Citation: FireEye FIN10 June 2017)
- [S0095] ftp: [ftp](https://attack.mitre.org/software/S0095) may be abused by adversaries to transfer tools or files between systems within a compromised environment.(Citation: Microsoft FTP)(Citation: Linux FTP)
- [S0404] esentutl: [esentutl](https://attack.mitre.org/software/S0404) can be used to copy files to/from a remote share.(Citation: LOLBAS Esentutl)
- [G1003] Ember Bear: [Ember Bear](https://attack.mitre.org/groups/G1003) retrieves follow-on payloads direct from adversary-owned infrastructure for deployment on compromised hosts.(Citation: Cadet Blizzard emerges as novel threat actor)
- [S0532] Lucifer: [Lucifer](https://attack.mitre.org/software/S0532) can use [certutil](https://attack.mitre.org/software/S0160) for propagation on Windows hosts within intranets.(Citation: Unit 42 Lucifer June 2020)
- [G1017] Volt Typhoon: [Volt Typhoon](https://attack.mitre.org/groups/G1017) has copied web shells between servers in targeted environments.(Citation: Secureworks BRONZE SILHOUETTE May 2023)
- [G1047] Velvet Ant: [Velvet Ant](https://attack.mitre.org/groups/G1047) transferred files laterally within victim networks through the [Impacket](https://attack.mitre.org/software/S0357) toolkit.(Citation: Sygnia VelvetAnt 2024A)
- [G0102] Wizard Spider: [Wizard Spider](https://attack.mitre.org/groups/G0102) has used stolen credentials to copy tools into the <code>%TEMP%</code> directory of domain controllers.(Citation: CrowdStrike Grim Spider May 2019)
- [G0010] Turla: [Turla](https://attack.mitre.org/groups/G0010) RPC backdoors can be used to transfer files to/from victim machines on the local network.(Citation: ESET Turla PowerShell May 2019)(Citation: Symantec Waterbug Jun 2019)
- [C0018] C0018: During [C0018](https://attack.mitre.org/campaigns/C0018), the threat actors transferred the SoftPerfect Network Scanner and other tools to machines in the network using AnyDesk and PDQ Deploy.(Citation: Cisco Talos Avos Jun 2022)(Citation: Costa AvosLocker May 2022)
- [S1180] BlackByte Ransomware: [BlackByte Ransomware](https://attack.mitre.org/software/S1180) spreads itself laterally by writing the JavaScript launcher file to mapped shared folders.(Citation: Trustwave BlackByte 2021)
- [C0025] 2016 Ukraine Electric Power Attack: During the [2016 Ukraine Electric Power Attack](https://attack.mitre.org/campaigns/C0025), [Sandworm Team](https://attack.mitre.org/groups/G0034) used `move` to transfer files to a network share.(Citation: Dragos Crashoverride 2018)
- [S0361] Expand: [Expand](https://attack.mitre.org/software/S0361) can be used to download or upload a file over a network share.(Citation: LOLBAS Expand)
- [G1043] BlackByte: [BlackByte](https://attack.mitre.org/groups/G1043) transfered tools such as [Cobalt Strike](https://attack.mitre.org/software/S0154) and the AnyDesk remote access tool during operations using SMB shares.(Citation: Picus BlackByte 2022)
- [G0114] Chimera: [Chimera](https://attack.mitre.org/groups/G0114) has copied tools between compromised hosts using SMB.(Citation: NCC Group Chimera January 2021)
- [S0365] Olympic Destroyer: [Olympic Destroyer](https://attack.mitre.org/software/S0365) attempts to copy itself to remote machines on the network.(Citation: Talos Olympic Destroyer 2018)
- [C0014] Operation Wocao: During [Operation Wocao](https://attack.mitre.org/campaigns/C0014), threat actors used SMB to copy files to and from target systems.(Citation: FoxIT Wocao December 2019)
- [C0034] 2022 Ukraine Electric Power Attack: During the [2022 Ukraine Electric Power Attack](https://attack.mitre.org/campaigns/C0034), [Sandworm Team](https://attack.mitre.org/groups/G0034) used a Group Policy Object (GPO) to copy [CaddyWiper](https://attack.mitre.org/software/S0693)'s executable `msserver.exe` from a staging server to a local hard drive before deployment.(Citation: Mandiant-Sandworm-Ukraine-2022)
- [G0093] GALLIUM: [GALLIUM](https://attack.mitre.org/groups/G0093) has used [PsExec](https://attack.mitre.org/software/S0029) to move laterally between hosts in the target network.(Citation: Microsoft GALLIUM December 2019)
- [S0140] Shamoon: [Shamoon](https://attack.mitre.org/software/S0140) attempts to copy itself to remote machines on the network.(Citation: Palo Alto Shamoon Nov 2016)
- [G1046] Storm-1811: [Storm-1811](https://attack.mitre.org/groups/G1046) has used the [Impacket](https://attack.mitre.org/software/S0357) toolset to move and remotely execute payloads to other hosts in victim networks.(Citation: rapid7-email-bombing)
- [G0059] Magic Hound: [Magic Hound](https://attack.mitre.org/groups/G0059) has copied tools within a compromised network using RDP.(Citation: DFIR Phosphorus November 2021)
- [G1032] INC Ransom: [INC Ransom](https://attack.mitre.org/groups/G1032) has used a rapid succession of copy commands to install a file encryption executable across multiple endpoints within compromised infrastructure.(Citation: Huntress INC Ransom Group August 2023)(Citation: Secureworks GOLD IONIC April 2024)
- [S0029] PsExec: [PsExec](https://attack.mitre.org/software/S0029) can be used to download or upload a file over a network share.(Citation: PsExec Russinovich)
- [S0698] HermeticWizard: [HermeticWizard](https://attack.mitre.org/software/S0698) can copy files to other machines on a compromised network.(Citation: ESET Hermetic Wizard March 2022)
- [S0062] DustySky: [DustySky](https://attack.mitre.org/software/S0062) searches for network drives and removable media and duplicates itself onto them.(Citation: DustySky)
- [C0038] HomeLand Justice: During [HomeLand Justice](https://attack.mitre.org/campaigns/C0038), threat actors initiated a process named Mellona.exe to spread the [ROADSWEEP](https://attack.mitre.org/software/S1150) file encryptor and a persistence script to a list of internal machines.(Citation: CISA Iran Albanian Attacks September 2022)
- [S0357] Impacket: [Impacket](https://attack.mitre.org/software/S0357) has used its `wmiexec` command, leveraging Windows Management Instrumentation, to remotely stage and execute payloads in victim networks.(Citation: Sygnia VelvetAnt 2024A)
- [G0034] Sandworm Team: [Sandworm Team](https://attack.mitre.org/groups/G0034) has used `move` to transfer files to a network share and has copied payloads--such as [Prestige](https://attack.mitre.org/software/S1058) ransomware--to an Active Directory Domain Controller and distributed via the Default Domain Group Policy Object.(Citation: Dragos Crashoverride 2018)(Citation: Microsoft Prestige ransomware October 2022) Additionally, [Sandworm Team](https://attack.mitre.org/groups/G0034) has transferred an ISO file into the OT network to gain initial access.(Citation: Mandiant-Sandworm-Ukraine-2022)
- [C0028] 2015 Ukraine Electric Power Attack: During the [2015 Ukraine Electric Power Attack](https://attack.mitre.org/campaigns/C0028), [Sandworm Team](https://attack.mitre.org/groups/G0034) moved their tools laterally within the corporate network and between the ICS and corporate network. (Citation: Booz Allen Hamilton)
- [S1017] OutSteel: [OutSteel](https://attack.mitre.org/software/S1017) can download the [Saint Bot](https://attack.mitre.org/software/S1018) malware for follow-on execution.(Citation: Palo Alto Unit 42 OutSteel SaintBot February 2022 )
- [G1030] Agrius: [Agrius](https://attack.mitre.org/groups/G1030) downloaded some payloads for follow-on execution from legitimate filesharing services such as <code>ufile.io</code> and <code>easyupload.io</code>.(Citation: CheckPoint Agrius 2023)
- [S0372] LockerGoga: [LockerGoga](https://attack.mitre.org/software/S0372) has been observed moving around the victim network via SMB, indicating the actors behind this ransomware are manually copying files form computer to computer instead of self-propagating.(Citation: Unit42 LockerGoga 2019)
- [S0603] Stuxnet: [Stuxnet](https://attack.mitre.org/software/S0603) uses an RPC server that contains a file dropping routine and support for payload version updates for P2P communications within a victim network.(Citation: Nicolas Falliere, Liam O Murchu, Eric Chien February 2011)
- [C0015] C0015: During [C0015](https://attack.mitre.org/campaigns/C0015), the threat actors used WMI to load [Cobalt Strike](https://attack.mitre.org/software/S0154) onto additional hosts within a compromised network.(Citation: DFIR Conti Bazar Nov 2021)
- [G0096] APT41: [APT41](https://attack.mitre.org/groups/G0096) uses remote shares to move and remotely execute payloads during lateral movemement.(Citation: Rostovcev APT41 2021)
- [S0106] cmd: [cmd](https://attack.mitre.org/software/S0106) can be used to copy files to/from a remotely connected internal system.(Citation: TechNet Copy)
- [S0366] WannaCry: [WannaCry](https://attack.mitre.org/software/S0366) attempts to copy itself to remote computers after gaining access via an SMB exploit.(Citation: LogRhythm WannaCry)

