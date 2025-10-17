### T1005 - Data from Local System

Description:

Adversaries may search local system sources, such as file systems, configuration files, local databases, or virtual machine files, to find files of interest and sensitive data prior to Exfiltration.

Adversaries may do this using a [Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059), such as [cmd](https://attack.mitre.org/software/S0106) as well as a [Network Device CLI](https://attack.mitre.org/techniques/T1059/008), which have functionality to interact with the file system to gather information.(Citation: show_run_config_cmd_cisco) Adversaries may also use [Automated Collection](https://attack.mitre.org/techniques/T1119) on the local system.

Procedures:

- [S1196] Troll Stealer: [Troll Stealer](https://attack.mitre.org/software/S1196) gathers information from infected systems such as SSH information from the victim's `.ssh` directory.(Citation: Symantec Troll Stealer 2024) [Troll Stealer](https://attack.mitre.org/software/S1196) collects information from local FileZilla installations and Microsoft Sticky Note.(Citation: S2W Troll Stealer 2024)
- [G0094] Kimsuky: [Kimsuky](https://attack.mitre.org/groups/G0094) has collected Office, PDF, and HWP documents from its victims.(Citation: Securelist Kimsuky Sept 2013)(Citation: Talos Kimsuky Nov 2021)
- [G0060] BRONZE BUTLER: [BRONZE BUTLER](https://attack.mitre.org/groups/G0060) has exfiltrated files stolen from local systems.(Citation: Secureworks BRONZE BUTLER Oct 2017)
- [S0238] Proxysvc: [Proxysvc](https://attack.mitre.org/software/S0238) searches the local system and gathers data.(Citation: McAfee GhostSecret)
- [S0502] Drovorub: [Drovorub](https://attack.mitre.org/software/S0502) can transfer files from the victim machine.(Citation: NSA/FBI Drovorub August 2020)
- [S0498] Cryptoistic: [Cryptoistic](https://attack.mitre.org/software/S0498) can retrieve files from the local file system.(Citation: SentinelOne Lazarus macOS July 2020)
- [S0653] xCaon: [xCaon](https://attack.mitre.org/software/S0653) has uploaded files from victims' machines.(Citation: Checkpoint IndigoZebra July 2021)
- [G1004] LAPSUS$: [LAPSUS$](https://attack.mitre.org/groups/G1004) uploaded sensitive files, information, and credentials from a targeted organization for extortion or public release.(Citation: MSTIC DEV-0537 Mar 2022)
- [C0048] Operation MidnightEclipse: During [Operation MidnightEclipse](https://attack.mitre.org/campaigns/C0048), threat actors stole saved cookies and login data from targeted systems.(Citation: Volexity UPSTYLE 2024)
- [G0087] APT39: [APT39](https://attack.mitre.org/groups/G0087) has used various tools to steal files from the compromised host.(Citation: Symantec Chafer February 2018)(Citation: FBI FLASH APT39 September 2020)
- [S0650] QakBot: [QakBot](https://attack.mitre.org/software/S0650) can use a variety of commands, including esentutl.exe to steal sensitive data from Internet Explorer and Microsoft Edge, to acquire information that is subsequently exfiltrated.(Citation: Red Canary Qbot)(Citation: Kaspersky QakBot September 2021)
- [S1043] ccf32: [ccf32](https://attack.mitre.org/software/S1043) can collect files from a compromised host.(Citation: Bitdefender FunnyDream Campaign November 2020)
- [S0567] Dtrack: [Dtrack](https://attack.mitre.org/software/S0567) can collect a variety of information from victim machines.(Citation: CyberBit Dtrack)
- [S0239] Bankshot: [Bankshot](https://attack.mitre.org/software/S0239) collects files from the local system.(Citation: McAfee Bankshot)
- [S0128] BADNEWS: When it first starts, [BADNEWS](https://attack.mitre.org/software/S0128) crawls the victim's local drives and collects documents with the following extensions: .doc, .docx, .pdf, .ppt, .pptx, and .txt.(Citation: Forcepoint Monsoon)(Citation: PaloAlto Patchwork Mar 2018)
- [G0125] HAFNIUM: [HAFNIUM](https://attack.mitre.org/groups/G0125) has collected data and files from a compromised machine.(Citation: Rapid7 HAFNIUM Mar 2021)(Citation: Microsoft Silk Typhoon MAR 2025)
- [S1064] SVCReady: [SVCReady](https://attack.mitre.org/software/S1064) can collect data from an infected host.(Citation: HP SVCReady Jun 2022)
- [S0448] Rising Sun: [Rising Sun](https://attack.mitre.org/software/S0448) has collected data and files from a compromised host.(Citation: McAfee Sharpshooter December 2018)
- [S0197] PUNCHTRACK: [PUNCHTRACK](https://attack.mitre.org/software/S0197) scrapes memory for properly formatted payment card data.(Citation: FireEye Fin8 May 2016)(Citation: FireEye Know Your Enemy FIN8 Aug 2016)
- [S0020] China Chopper: [China Chopper](https://attack.mitre.org/software/S0020)'s server component can upload local files.(Citation: FireEye Periscope March 2018)(Citation: Lee 2013)(Citation: NCSC Joint Report Public Tools)(Citation: Rapid7 HAFNIUM Mar 2021)
- [G0001] Axiom: [Axiom](https://attack.mitre.org/groups/G0001) has collected data from a compromised network.(Citation: Novetta-Axiom)
- [G0049] OilRig: [OilRig](https://attack.mitre.org/groups/G0049) has used PowerShell to upload files from compromised systems.(Citation: Trend Micro Earth Simnavaz October 2024)
- [S0022] Uroburos: [Uroburos](https://attack.mitre.org/software/S0022) can use its `Get` command to exfiltrate specified files from the compromised system.(Citation: Joint Cybersecurity Advisory AA23-129A Snake Malware May 2023)
- [S0340] Octopus: [Octopus](https://attack.mitre.org/software/S0340) can exfiltrate files from the system using a documents collector tool.(Citation: ESET Nomadic Octopus 2018)
- [S0036] FLASHFLOOD: [FLASHFLOOD](https://attack.mitre.org/software/S0036) searches for interesting files (either a default or customized set of file extensions) on the local system. [FLASHFLOOD](https://attack.mitre.org/software/S0036) will scan the My Recent Documents, Desktop, Temporary Internet Files, and TEMP directories. [FLASHFLOOD](https://attack.mitre.org/software/S0036) also collects information stored in the Windows Address Book.(Citation: FireEye APT30)
- [S0598] P.A.S. Webshell: [P.A.S. Webshell](https://attack.mitre.org/software/S0598) has the ability to copy files on a compromised host.(Citation: ANSSI Sandworm January 2021)
- [G1022] ToddyCat: [ToddyCat](https://attack.mitre.org/groups/G1022) has run scripts to collect documents from targeted hosts.(Citation: Kaspersky ToddyCat Check Logs October 2023)
- [S0154] Cobalt Strike: [Cobalt Strike](https://attack.mitre.org/software/S0154) can collect data from a local system.(Citation: Cobalt Strike TTPs Dec 2017)(Citation: Cobalt Strike Manual 4.3 November 2020)
- [G0124] Windigo: [Windigo](https://attack.mitre.org/groups/G0124) has used a script to gather credentials in files left on disk by OpenSSH backdoors.(Citation: ESET ForSSHe December 2018)
- [S0632] GrimAgent: [GrimAgent](https://attack.mitre.org/software/S0632) can collect data and files from a compromised host.(Citation: Group IB GrimAgent July 2021)
- [S1090] NightClub: [NightClub](https://attack.mitre.org/software/S1090) can use a file monitor to steal specific files from targeted systems.(Citation: MoustachedBouncer ESET August 2023)
- [S0630] Nebulae: [Nebulae](https://attack.mitre.org/software/S0630) has the capability to upload collected files to C2.(Citation: Bitdefender Naikon April 2021)
- [S0356] KONNI: [KONNI](https://attack.mitre.org/software/S0356) has stored collected information and discovered processes in a tmp file.(Citation: Malwarebytes Konni Aug 2021)
- [S0670] WarzoneRAT: [WarzoneRAT](https://attack.mitre.org/software/S0670) can collect data from a compromised host.(Citation: Check Point Warzone Feb 2020)
- [S1031] PingPull: [PingPull](https://attack.mitre.org/software/S1031) can collect data from a compromised host.(Citation: Unit 42 PingPull Jun 2022)
- [S0194] PowerSploit: [PowerSploit](https://attack.mitre.org/software/S0194) contains a collection of Exfiltration modules that can access data from local files, volumes, and processes.(Citation: GitHub PowerSploit May 2012)(Citation: PowerSploit Documentation)
- [C0002] Night Dragon: During [Night Dragon](https://attack.mitre.org/campaigns/C0002), the threat actors collected files and other data from compromised systems.(Citation: McAfee Night Dragon)
- [S1113] RAPIDPULSE: [RAPIDPULSE](https://attack.mitre.org/software/S1113) retrieves files from the victim system via encrypted commands sent to the web shell.(Citation: Mandiant Pulse Secure Update May 2021)
- [G0117] Fox Kitten: [Fox Kitten](https://attack.mitre.org/groups/G0117) has searched local system resources to access sensitive documents.(Citation: CISA AA20-259A Iran-Based Actor September 2020)
- [S0572] Caterpillar WebShell: [Caterpillar WebShell](https://attack.mitre.org/software/S0572) has a module to collect information from the local database.(Citation: ClearSky Lebanese Cedar Jan 2021)
- [G0138] Andariel: [Andariel](https://attack.mitre.org/groups/G0138) has collected large numbers of files from compromised network systems for later extraction.(Citation: FSI Andariel Campaign Rifle July 2017)
- [G1039] RedCurl: [RedCurl](https://attack.mitre.org/groups/G1039) has collected data from the local disk of compromised hosts.(Citation: group-ib_redcurl1)(Citation: group-ib_redcurl2)
- [S1025] Amadey: [Amadey](https://attack.mitre.org/software/S1025) can collect information from a compromised host.(Citation: BlackBerry Amadey 2020)
- [S0520] BLINDINGCAN: [BLINDINGCAN](https://attack.mitre.org/software/S0520) has uploaded files from victim machines.(Citation: US-CERT BLINDINGCAN Aug 2020)
- [G0006] APT1: [APT1](https://attack.mitre.org/groups/G0006) has collected files from a local victim.(Citation: Mandiant APT1)
- [G0093] GALLIUM: [GALLIUM](https://attack.mitre.org/groups/G0093) collected data from the victim's local system, including password hashes from the SAM hive in the Registry.(Citation: Cybereason Soft Cell June 2019)
- [S0615] SombRAT: [SombRAT](https://attack.mitre.org/software/S0615) has collected data and files from a compromised host.(Citation: BlackBerry CostaRicto November 2020)(Citation: CISA AR21-126A FIVEHANDS May 2021)
- [G0016] APT29: [APT29](https://attack.mitre.org/groups/G0016) has stolen data from compromised hosts.(Citation: Mandiant APT29 Eye Spy Email Nov 22)
- [G0032] Lazarus Group: [Lazarus Group](https://attack.mitre.org/groups/G0032) has collected data and files from compromised networks.(Citation: Novetta Blockbuster)(Citation: Novetta Blockbuster Loaders)(Citation: Novetta Blockbuster RATs)(Citation: Kaspersky ThreatNeedle Feb 2021)
- [S0458] Ramsay: [Ramsay](https://attack.mitre.org/software/S0458) can collect Microsoft Word documents from the target's file system, as well as <code>.txt</code>, <code>.doc</code>, and <code>.xls</code> files from the Internet Explorer cache.(Citation: Eset Ramsay May 2020)(Citation: Antiy CERT Ramsay April 2020)
- [S1148] Raccoon Stealer: [Raccoon Stealer](https://attack.mitre.org/software/S1148) collects data from victim machines based on configuration information received from command and control nodes.(Citation: S2W Racoon 2022)(Citation: Sekoia Raccoon2 2022)
- [S0652] MarkiRAT: [MarkiRAT](https://attack.mitre.org/software/S0652) can upload data from the victim's machine to the C2 server.(Citation: Kaspersky Ferocious Kitten Jun 2021)
- [G0047] Gamaredon Group: [Gamaredon Group](https://attack.mitre.org/groups/G0047) has collected files from infected systems and uploaded them to a C2 server.(Citation: ESET Gamaredon June 2020)
- [G1030] Agrius: [Agrius](https://attack.mitre.org/groups/G1030) gathered data from database and other critical servers in victim environments, then used wiping mechanisms as an anti-analysis and anti-forensics mechanism.(Citation: Unit42 Agrius 2023)
- [S1017] OutSteel: [OutSteel](https://attack.mitre.org/software/S1017) can collect information from a compromised host.(Citation: Palo Alto Unit 42 OutSteel SaintBot February 2022 )
- [S0514] WellMess: [WellMess](https://attack.mitre.org/software/S0514) can send files from the victim machine to C2.(Citation: PWC WellMess July 2020)(Citation: CISA WellMess July 2020)
- [G0037] FIN6: [FIN6](https://attack.mitre.org/groups/G0037) has collected and exfiltrated payment card data from compromised systems.(Citation: Trend Micro FIN6 October 2019)(Citation: RiskIQ British Airways September 2018)(Citation: RiskIQ Newegg September 2018)
- [S1160] Latrodectus: [Latrodectus](https://attack.mitre.org/software/S1160) can collect data from a compromised host using a stealer module.(Citation: Bitsight Latrodectus June 2024)
- [G0143] Aquatic Panda: [Aquatic Panda](https://attack.mitre.org/groups/G0143) captured local Windows security event log data from victim machines using the <code>wevtutil</code> utility to extract contents to an <code>evtx</code> output file.(Citation: Crowdstrike HuntReport 2022)
- [S1060] Mafalda: [Mafalda](https://attack.mitre.org/software/S1060) can collect files and information from a compromised host.(Citation: SentinelLabs Metador Sept 2022)
- [S0663] SysUpdate: [SysUpdate](https://attack.mitre.org/software/S0663) can collect information and files from a compromised host.(Citation: Lunghi Iron Tiger Linux)
- [S0248] yty: [yty](https://attack.mitre.org/software/S0248) collects files with the following extensions: .ppt, .pptx, .pdf, .doc, .docx, .xls, .xlsx, .docm, .rtf, .inp, .xlsm, .csv, .odt, .pps, .vcf and sends them back to the C2 server.(Citation: ASERT Donot March 2018)
- [S1039] Bumblebee: [Bumblebee](https://attack.mitre.org/software/S1039) can capture and compress stolen credentials from the Registry and volume shadow copies.(Citation: Cybereason Bumblebee August 2022)
- [S0634] EnvyScout: [EnvyScout](https://attack.mitre.org/software/S0634) can collect sensitive NTLM material from a compromised host.(Citation: MSTIC Nobelium Toolset May 2021)
- [C0014] Operation Wocao: During [Operation Wocao](https://attack.mitre.org/campaigns/C0014), threat actors exfiltrated files and directories of interest from the targeted system.(Citation: FoxIT Wocao December 2019)
- [G0010] Turla: [Turla](https://attack.mitre.org/groups/G0010) RPC backdoors can upload files from victim machines.(Citation: ESET Turla PowerShell May 2019)
- [S0203] Hydraq: [Hydraq](https://attack.mitre.org/software/S0203) creates a backdoor through which remote attackers can read data from files.(Citation: Symantec Trojan.Hydraq Jan 2010)(Citation: Symantec Hydraq Jan 2010)
- [S0559] SUNBURST: [SUNBURST](https://attack.mitre.org/software/S0559) collected information from a compromised host.(Citation: Microsoft Analyzing Solorigate Dec 2020)(Citation: FireEye SUNBURST Backdoor December 2020)
- [S0661] FoggyWeb: [FoggyWeb](https://attack.mitre.org/software/S0661) can retrieve configuration data from a compromised AD FS server.(Citation: MSTIC FoggyWeb September 2021)
- [S0687] Cyclops Blink: [Cyclops Blink](https://attack.mitre.org/software/S0687) can upload files from a compromised host.(Citation: NCSC Cyclops Blink February 2022)
- [S1012] PowerLess: [PowerLess](https://attack.mitre.org/software/S1012) has the ability to exfiltrate data, including Chrome and Edge browser database files, from compromised machines.(Citation: Cybereason PowerLess February 2022)
- [G0096] APT41: [APT41](https://attack.mitre.org/groups/G0096) has uploaded files and data from a compromised host.(Citation: Group IB APT 41 June 2021)
- [S1149] CHIMNEYSWEEP: [CHIMNEYSWEEP](https://attack.mitre.org/software/S1149) can collect files from compromised hosts.(Citation: Mandiant ROADSWEEP August 2022)
- [S0694] DRATzarus: [DRATzarus](https://attack.mitre.org/software/S0694) can collect information from a compromised host.(Citation: ClearSky Lazarus Aug 2020)
- [C0015] C0015: During [C0015](https://attack.mitre.org/campaigns/C0015), the threat actors obtained files and data from the compromised network.(Citation: DFIR Conti Bazar Nov 2021)
- [S1085] Sardonic: [Sardonic](https://attack.mitre.org/software/S1085) has the ability to collect data from a compromised machine to deliver to the attacker.(Citation: Symantec FIN8 Jul 2023)
- [S1111] DarkGate: [DarkGate](https://attack.mitre.org/software/S1111) has stolen `sitemanager.xml` and `recentservers.xml` from `%APPDATA%\FileZilla\` if present.(Citation: Rapid7 BlackBasta 2024)
- [S1146] MgBot: [MgBot](https://attack.mitre.org/software/S1146) includes modules for collecting files from local systems based on a given set of properties and filenames.(Citation: ESET EvasivePanda 2023)
- [S0564] BlackMould: [BlackMould](https://attack.mitre.org/software/S0564) can copy files on a compromised host.(Citation: Microsoft GALLIUM December 2019)
- [S0079] MobileOrder: [MobileOrder](https://attack.mitre.org/software/S0079) exfiltrates data collected from the victim mobile device.(Citation: Scarlet Mimic Jan 2016)
- [S0412] ZxShell: [ZxShell](https://attack.mitre.org/software/S0412) can transfer files from a compromised host.(Citation: Talos ZxShell Oct 2014)
- [S0534] Bazar: [Bazar](https://attack.mitre.org/software/S0534) can retrieve information from the infected machine.(Citation: Cybereason Bazar July 2020)
- [S0646] SpicyOmelette: [SpicyOmelette](https://attack.mitre.org/software/S0646) has collected data and other information from a compromised host.(Citation: Secureworks GOLD KINGSWOOD September 2018)
- [S1089] SharpDisco: [SharpDisco](https://attack.mitre.org/software/S1089) has dropped a recent-files stealer plugin to `C:\Users\Public\WinSrcNT\It11.exe`.(Citation: MoustachedBouncer ESET August 2023)
- [C0022] Operation Dream Job: During [Operation Dream Job](https://attack.mitre.org/campaigns/C0022), [Lazarus Group](https://attack.mitre.org/groups/G0032) used malicious Trojans and DLL files to exfiltrate data from an infected host.(Citation: ClearSky Lazarus Aug 2020)(Citation: McAfee Lazarus Jul 2020)
- [S1014] DanBot: [DanBot](https://attack.mitre.org/software/S1014) can upload files from compromised hosts.(Citation: SecureWorks August 2019)
- [S0260] InvisiMole: [InvisiMole](https://attack.mitre.org/software/S0260) can collect data from the system, and can monitor changes in specified directories.(Citation: ESET InvisiMole June 2018)
- [S0115] Crimson: [Crimson](https://attack.mitre.org/software/S0115) can collect information from a compromised host.(Citation: Cisco Talos Transparent Tribe Education Campaign July 2022)
- [S0533] SLOTHFULMEDIA: [SLOTHFULMEDIA](https://attack.mitre.org/software/S0533) has uploaded files and information from victim machines.(Citation: CISA MAR SLOTHFULMEDIA October 2020)
- [S0622] AppleSeed: [AppleSeed](https://attack.mitre.org/software/S0622) can collect data on a compromised host.(Citation: Malwarebytes Kimsuky June 2021)(Citation: KISA Operation Muzabi)
- [S1016] MacMa: [MacMa](https://attack.mitre.org/software/S1016) can collect then exfiltrate files from the compromised system.(Citation: ESET DazzleSpy Jan 2022)
- [S1110] SLIGHTPULSE: [SLIGHTPULSE](https://attack.mitre.org/software/S1110) can read files specified on the local system.(Citation: Mandiant Pulse Secure Zero-Day April 2021)
- [G1014] LuminousMoth: [LuminousMoth](https://attack.mitre.org/groups/G1014) has collected files and data from compromised machines.(Citation: Kaspersky LuminousMoth July 2021)(Citation: Bitdefender LuminousMoth July 2021)
- [G0067] APT37: [APT37](https://attack.mitre.org/groups/G0067) has collected data from victims' local systems.(Citation: FireEye APT37 Feb 2018)
- [S1131] NPPSPY: [NPPSPY](https://attack.mitre.org/software/S1131) records data entered from the local system logon at Winlogon to capture credentials in cleartext.(Citation: Huntress NPPSPY 2022)
- [S0696] Flagpro: [Flagpro](https://attack.mitre.org/software/S0696) can collect data from a compromised host, including Windows authentication information.(Citation: NTT Security Flagpro new December 2021)
- [S0011] Taidoor: [Taidoor](https://attack.mitre.org/software/S0011) can upload data and files from a victim's machine.(Citation: TrendMicro Taidoor)
- [S1022] IceApple: [IceApple](https://attack.mitre.org/software/S1022) can collect files, passwords, and other data from a compromised host.(Citation: CrowdStrike IceApple May 2022)
- [S0083] Misdat: [Misdat](https://attack.mitre.org/software/S0083) has collected files and data from a compromised host.(Citation: Cylance Dust Storm)
- [S0671] Tomiris: [Tomiris](https://attack.mitre.org/software/S0671) has the ability to collect recent files matching a hardcoded list of extensions prior to exfiltration.(Citation: Kaspersky Tomiris Sep 2021)
- [G0035] Dragonfly: [Dragonfly](https://attack.mitre.org/groups/G0035) has collected data from local victim systems.(Citation: US-CERT TA18-074A)
- [G1012] CURIUM: [CURIUM](https://attack.mitre.org/groups/G1012) has exfiltrated data from a compromised machine.(Citation: Microsoft Iranian Threat Actor Trends November 2021)
- [S1019] Shark: [Shark](https://attack.mitre.org/software/S1019) can upload files to its C2.(Citation: ClearSky Siamesekitten August 2021)(Citation: Accenture Lyceum Targets November 2021)
- [S1065] Woody RAT: [Woody RAT](https://attack.mitre.org/software/S1065) can collect information from a compromised host.(Citation: MalwareBytes WoodyRAT Aug 2022)
- [S0658] XCSSET: [XCSSET](https://attack.mitre.org/software/S0658) collects contacts and application data from files in Desktop, Documents, Downloads, Dropbox, and WeChat folders.(Citation: trendmicro xcsset xcode project 2020)
- [C0024] SolarWinds Compromise: During the [SolarWinds Compromise](https://attack.mitre.org/campaigns/C0024), [APT29](https://attack.mitre.org/groups/G0016) extracted files from compromised networks.(Citation: Volexity SolarWinds)
- [G0007] APT28: [APT28](https://attack.mitre.org/groups/G0007) has retrieved internal documents from machines inside victim environments, including by using [Forfiles](https://attack.mitre.org/software/S0193) to stage documents before exfiltration.(Citation: Überwachung APT28 Forfiles June 2015)(Citation: DOJ GRU Indictment Jul 2018)(Citation: TrendMicro Pawn Storm 2019)(Citation: Cybersecurity Advisory GRU Brute Force Campaign July 2021)
- [S0651] BoxCaon: [BoxCaon](https://attack.mitre.org/software/S0651) can upload files from a compromised host.(Citation: Checkpoint IndigoZebra July 2021)
- [S1063] Brute Ratel C4: [Brute Ratel C4](https://attack.mitre.org/software/S1063) has the ability to upload files from a compromised system.(Citation: Palo Alto Brute Ratel July 2022)
- [S1029] AuTo Stealer: [AuTo Stealer](https://attack.mitre.org/software/S1029) can collect data such as PowerPoint files, Word documents, Excel files, PDF files, text files, database files, and image files from an infected machine.(Citation: MalwareBytes SideCopy Dec 2021)
- [S0461] SDBbot: [SDBbot](https://attack.mitre.org/software/S0461) has the ability to access the file system on a compromised host.(Citation: Proofpoint TA505 October 2019)
- [S0262] QuasarRAT: [QuasarRAT](https://attack.mitre.org/software/S0262) can retrieve files from compromised client machines.(Citation: CISA AR18-352A Quasar RAT December 2018)
- [S0386] Ursnif: [Ursnif](https://attack.mitre.org/software/S0386) has collected files from victim machines, including certificates and cookies.(Citation: TrendMicro BKDR_URSNIF.SM)
- [S0090] Rover: [Rover](https://attack.mitre.org/software/S0090) searches for files on local drives based on a predefined list of file extensions.(Citation: Palo Alto Rover)
- [S0503] FrameworkPOS: [FrameworkPOS](https://attack.mitre.org/software/S0503) can collect elements related to credit card data from process memory.(Citation: SentinelOne FrameworkPOS September 2019)
- [C0017] C0017: During [C0017](https://attack.mitre.org/campaigns/C0017), [APT41](https://attack.mitre.org/groups/G0096) collected information related to compromised machines as well as Personal Identifiable Information (PII) from victim networks.(Citation: Mandiant APT41)
- [S0274] Calisto: [Calisto](https://attack.mitre.org/software/S0274) can collect data from user directories.(Citation: Securelist Calisto July 2018)
- [S0266] TrickBot: [TrickBot](https://attack.mitre.org/software/S0266) collects local files and information from the victim’s local machine.(Citation: S2 Grupo TrickBot June 2017)
- [S0268] Bisonal: [Bisonal](https://attack.mitre.org/software/S0268) has collected information from a compromised host.(Citation: Talos Bisonal Mar 2020)
- [G0100] Inception: [Inception](https://attack.mitre.org/groups/G0100) used a file hunting plugin to collect .txt, .pdf, .xls or .doc files from the infected host.(Citation: Kaspersky Cloud Atlas August 2019)
- [S1050] PcShare: [PcShare](https://attack.mitre.org/software/S1050) can collect files and information from a compromised host.(Citation: Bitdefender FunnyDream Campaign November 2020)
- [S1026] Mongall: [Mongall](https://attack.mitre.org/software/S1026) has the ability to upload files from victim's machines.(Citation: SentinelOne Aoqin Dragon June 2022)
- [S1132] IPsec Helper: [IPsec Helper](https://attack.mitre.org/software/S1132) can identify specific files and folders for follow-on exfiltration.(Citation: SentinelOne Agrius 2021)
- [G0004] Ke3chang: [Ke3chang](https://attack.mitre.org/groups/G0004) gathered information and files from local directories for exfiltration.(Citation: Mandiant Operation Ke3chang November 2014)(Citation: Microsoft NICKEL December 2021)
- [G0040] Patchwork: [Patchwork](https://attack.mitre.org/groups/G0040) collected and exfiltrated files from the infected system.(Citation: Cymmetria Patchwork)
- [S0665] ThreatNeedle: [ThreatNeedle](https://attack.mitre.org/software/S0665) can collect data and files from a compromised host.(Citation: Kaspersky ThreatNeedle Feb 2021)
- [S1159] DUSTTRAP: [DUSTTRAP](https://attack.mitre.org/software/S1159) can gather data from infected systems.(Citation: Google Cloud APT41 2024)
- [G0022] APT3: [APT3](https://attack.mitre.org/groups/G0022) will identify Microsoft Office documents on the victim's computer.(Citation: aptsim)
- [S0395] LightNeuron: [LightNeuron](https://attack.mitre.org/software/S0395) can collect files from a local system.(Citation: ESET LightNeuron May 2019)
- [S0169] RawPOS: [RawPOS](https://attack.mitre.org/software/S0169) dumps memory from specific processes on a victim system, parses the dumped files, and scrapes them for credit card data.(Citation: Kroll RawPOS Jan 2017)(Citation: TrendMicro RawPOS April 2015)(Citation: Mandiant FIN5 GrrCON Oct 2016)
- [S1021] DnsSystem: [DnsSystem](https://attack.mitre.org/software/S1021) can upload files from infected machines after receiving a command with `uploaddd` in the string.(Citation: Zscaler Lyceum DnsSystem June 2022)
- [S0193] Forfiles: [Forfiles](https://attack.mitre.org/software/S0193) can be used to act on (ex: copy, move, etc.) files/directories in a system during (ex: copy files into a staging area before).(Citation: Überwachung APT28 Forfiles June 2015)
- [S0512] FatDuke: [FatDuke](https://attack.mitre.org/software/S0512) can copy files and directories from a compromised host.(Citation: ESET Dukes October 2019)
- [S1020] Kevin: [Kevin](https://attack.mitre.org/software/S1020) can upload logs and other data from a compromised host.(Citation: Kaspersky Lyceum October 2021)
- [S0645] Wevtutil: [Wevtutil](https://attack.mitre.org/software/S0645) can be used to export events from a specific log.(Citation: Wevtutil Microsoft Documentation)(Citation: F-Secure Lazarus Cryptocurrency Aug 2020)
- [S0223] POWERSTATS: [POWERSTATS](https://attack.mitre.org/software/S0223) can upload files from compromised hosts.(Citation: FireEye MuddyWater Mar 2018)
- [S0610] SideTwist: [SideTwist](https://attack.mitre.org/software/S0610) has the ability to upload files from a compromised host.(Citation: Check Point APT34 April 2021)
- [S0690] Green Lambert: [Green Lambert](https://attack.mitre.org/software/S0690) can collect data from a compromised host.(Citation: Objective See Green Lambert for OSX Oct 2021)
- [S1059] metaMain: [metaMain](https://attack.mitre.org/software/S1059) can collect files and system information from a compromised host.(Citation: SentinelLabs Metador Sept 2022)(Citation: SentinelLabs Metador Technical Appendix Sept 2022)
- [S0691] Neoichor: [Neoichor](https://attack.mitre.org/software/S0691) can upload files from a victim's machine.(Citation: Microsoft NICKEL December 2021)
- [S0672] Zox: [Zox](https://attack.mitre.org/software/S0672) has the ability to upload files from a targeted system.(Citation: Novetta-Axiom)
- [S0673] DarkWatchman: [DarkWatchman](https://attack.mitre.org/software/S0673) can collect files from a compromised host.(Citation: Prevailion DarkWatchman 2021)
- [S0666] Gelsemium: [Gelsemium](https://attack.mitre.org/software/S0666) can collect data from a compromised host.(Citation: ESET Gelsemium June 2021)
- [S1015] Milan: [Milan](https://attack.mitre.org/software/S1015) can upload files from a compromised host.(Citation: ClearSky Siamesekitten August 2021)
- [C0006] Operation Honeybee: During [Operation Honeybee](https://attack.mitre.org/campaigns/C0006), the threat actors collected data from compromised hosts.(Citation: McAfee Honeybee)
- [S1101] LoFiSe: [LoFiSe](https://attack.mitre.org/software/S1101) can collect files of interest from targeted systems.(Citation: Kaspersky ToddyCat Check Logs October 2023)
- [S0642] BADFLICK: [BADFLICK](https://attack.mitre.org/software/S0642) has uploaded files from victims' machines.(Citation: Accenture MUDCARP March 2019)
- [S0674] CharmPower: [CharmPower](https://attack.mitre.org/software/S0674) can collect data and files from a compromised host.(Citation: Check Point APT35 CharmPower January 2022)
- [S0084] Mis-Type: [Mis-Type](https://attack.mitre.org/software/S0084) has collected files and data from a compromised host.(Citation: Cylance Dust Storm)
- [S0594] Out1: [Out1](https://attack.mitre.org/software/S0594) can copy files and Registry data from compromised hosts.(Citation: Trend Micro Muddy Water March 2021)
- [G0027] Threat Group-3390: [Threat Group-3390](https://attack.mitre.org/groups/G0027) ran a command to compile an archive of file types of interest from the victim user's directories.(Citation: SecureWorks BRONZE UNION June 2017)
- [S1023] CreepyDrive: [CreepyDrive](https://attack.mitre.org/software/S1023) can upload files to C2 from victim machines.(Citation: Microsoft POLONIUM June 2022)
- [S0237] GravityRAT: [GravityRAT](https://attack.mitre.org/software/S0237) steals files with the following extensions: .docx, .doc, .pptx, .ppt, .xlsx, .xls, .rtf, and .pdf.(Citation: Talos GravityRAT)
- [S0492] CookieMiner: [CookieMiner](https://attack.mitre.org/software/S0492) has retrieved iPhone text messages from iTunes phone backup files.(Citation: Unit42 CookieMiner Jan 2019)
- [S0686] QuietSieve: [QuietSieve](https://attack.mitre.org/software/S0686) can collect files from a compromised host.(Citation: Microsoft Actinium February 2022)
- [S0452] USBferry: [USBferry](https://attack.mitre.org/software/S0452) can collect information from an air-gapped host machine.(Citation: TrendMicro Tropic Trooper May 2020)
- [C0029] Cutting Edge: During [Cutting Edge](https://attack.mitre.org/campaigns/C0029), threat actors stole the running configuration and cache data from targeted Ivanti Connect Secure VPNs.(Citation: Volexity Ivanti Zero-Day Exploitation January 2024)(Citation: Mandiant Cutting Edge Part 2 January 2024)
- [S0668] TinyTurla: [TinyTurla](https://attack.mitre.org/software/S0668) can upload files from a compromised host.(Citation: Talos TinyTurla September 2021)
- [S0409] Machete: [Machete](https://attack.mitre.org/software/S0409) searches the File system for files of interest.(Citation: ESET Machete July 2019)
- [C0001] Frankenstein: During [Frankenstein](https://attack.mitre.org/campaigns/C0001), the threat actors used [Empire](https://attack.mitre.org/software/S0363) to gather various local system information.(Citation: Talos Frankenstein June 2019)
- [G0046] FIN7: [FIN7](https://attack.mitre.org/groups/G0046) has collected files and other sensitive information from a compromised network.(Citation: CrowdStrike Carbon Spider August 2021)
- [S1200] StealBit: [StealBit](https://attack.mitre.org/software/S1200) can upload data and files to the LockBit victim-shaming site.(Citation: FBI Lockbit 2.0 FEB 2022)(Citation: Cybereason StealBit Exfiltration Tool)
- [S0517] Pillowmint: [Pillowmint](https://attack.mitre.org/software/S0517) has collected credit card data using native API functions.(Citation: Trustwave Pillowmint June 2020)
- [S0477] Goopy: [Goopy](https://attack.mitre.org/software/S0477) has the ability to exfiltrate documents from infected systems.(Citation: Cybereason Cobalt Kitty 2017)
- [S0012] PoisonIvy: [PoisonIvy](https://attack.mitre.org/software/S0012) creates a backdoor through which remote attackers can steal system information.(Citation: Symantec Darkmoon Aug 2005)
- [S0500] MCMD: [MCMD](https://attack.mitre.org/software/S0500) has the ability to upload files from an infected device.(Citation: Secureworks MCMD July 2019)
- [G1003] Ember Bear: [Ember Bear](https://attack.mitre.org/groups/G1003) gathers victim system information such as enumerating the volume of a given device or extracting system and security event logs for analysis.(Citation: Cadet Blizzard emerges as novel threat actor)(Citation: CISA GRU29155 2024)
- [C0004] CostaRicto: During [CostaRicto](https://attack.mitre.org/campaigns/C0004), the threat actors collected data and files from compromised networks.(Citation: BlackBerry CostaRicto November 2020)
- [S0662] RCSession: [RCSession](https://attack.mitre.org/software/S0662) can collect data from a compromised host.(Citation: Profero APT27 December 2020)(Citation: Trend Micro DRBControl February 2020)
- [S1044] FunnyDream: [FunnyDream](https://attack.mitre.org/software/S1044) can upload files from victims' machines.(Citation: Bitdefender FunnyDream Campaign November 2020)(Citation: Kaspersky APT Trends Q1 2020)
- [S0015] Ixeshe: [Ixeshe](https://attack.mitre.org/software/S0015) can collect data from a local system.(Citation: Trend Micro IXESHE 2012)
- [S0352] OSX_OCEANLOTUS.D: [OSX_OCEANLOTUS.D](https://attack.mitre.org/software/S0352) has the ability to upload files from a compromised host.(Citation: Trend Micro MacOS Backdoor November 2020)
- [S0538] Crutch: [Crutch](https://attack.mitre.org/software/S0538) can exfiltrate files from compromised systems.(Citation: ESET Crutch December 2020)
- [S0250] Koadic: [Koadic](https://attack.mitre.org/software/S0250) can download files off the target system to send back to the server.(Citation: Github Koadic)(Citation: MalwareBytes LazyScripter Feb 2021)
- [G0038] Stealth Falcon: [Stealth Falcon](https://attack.mitre.org/groups/G0038) malware gathers data from the local victim system.(Citation: Citizen Lab Stealth Falcon May 2016)
- [S0240] ROKRAT: [ROKRAT](https://attack.mitre.org/software/S0240) can collect host data and specific file types.(Citation: NCCGroup RokRat Nov 2018)(Citation: Volexity InkySquid RokRAT August 2021)(Citation: Malwarebytes RokRAT VBA January 2021)
- [G0082] APT38: [APT38](https://attack.mitre.org/groups/G0082) has collected data from a compromised host.(Citation: CISA AA20-239A BeagleBoyz August 2020)
- [S0381] FlawedAmmyy: [FlawedAmmyy](https://attack.mitre.org/software/S0381) has collected information and files from a compromised machine.(Citation: Korean FSI TA505 2020)
- [G1017] Volt Typhoon: [Volt Typhoon](https://attack.mitre.org/groups/G1017) has stolen files from a sensitive file server and the Active Directory database from targeted environments, and used [Wevtutil](https://attack.mitre.org/software/S0645) to extract event log information.(Citation: Joint Cybersecurity Advisory Volt Typhoon June 2023)(Citation: Secureworks BRONZE SILHOUETTE May 2023)(Citation: CISA AA24-038A PRC Critical Infrastructure February 2024)
- [S0211] Linfo: [Linfo](https://attack.mitre.org/software/S0211) creates a backdoor through which remote attackers can obtain data from local systems.(Citation: Symantec Linfo May 2012)
- [S0444] ShimRat: [ShimRat](https://attack.mitre.org/software/S0444) has the capability to upload collected files to a C2.(Citation: FOX-IT May 2016 Mofang)
- [S0048] PinchDuke: [PinchDuke](https://attack.mitre.org/software/S0048) collects user files from the compromised host based on predefined file extensions.(Citation: F-Secure The Dukes)
- [S0667] Chrommme: [Chrommme](https://attack.mitre.org/software/S0667) can collect data from a local system.(Citation: ESET Gelsemium June 2021)
- [S0050] CosmicDuke: [CosmicDuke](https://attack.mitre.org/software/S0050) steals user files from local hard drives with file extensions that match a predefined list.(Citation: F-Secure Cosmicduke)
- [S0337] BadPatch: [BadPatch](https://attack.mitre.org/software/S0337) collects files from the local system that have the following extensions, then prepares them for exfiltration: .xls, .xlsx, .pdf, .mdb, .rar, .zip, .doc, .docx.(Citation: Unit 42 BadPatch Oct 2017)
- [S0404] esentutl: [esentutl](https://attack.mitre.org/software/S0404) can be used to collect data from local file systems.(Citation: Red Canary 2021 Threat Detection Report March 2021)
- [S0009] Hikit: [Hikit](https://attack.mitre.org/software/S0009) can upload files from compromised machines.(Citation: Novetta-Axiom)
- [S1013] ZxxZ: [ZxxZ](https://attack.mitre.org/software/S1013) can collect data from a compromised host.(Citation: Cisco Talos Bitter Bangladesh May 2022)
- [G0045] menuPass: [menuPass](https://attack.mitre.org/groups/G0045) has collected various files from the compromised computers.(Citation: DOJ APT10 Dec 2018)(Citation: Symantec Cicada November 2020)
- [G0102] Wizard Spider: [Wizard Spider](https://attack.mitre.org/groups/G0102) has collected data from a compromised host prior to exfiltration.(Citation: Mandiant FIN12 Oct 2021)
- [S0265] Kazuar: [Kazuar](https://attack.mitre.org/software/S0265) uploads files from a specified directory to the C2 server.(Citation: Unit 42 Kazuar May 2017)
- [S0208] Pasam: [Pasam](https://attack.mitre.org/software/S0208) creates a backdoor through which remote attackers can retrieve files.(Citation: Symantec Pasam May 2012)
- [S0526] KGH_SPY: [KGH_SPY](https://attack.mitre.org/software/S0526) can send a file containing victim system information to C2.(Citation: Cybereason Kimsuky November 2020)
- [G0059] Magic Hound: [Magic Hound](https://attack.mitre.org/groups/G0059) has used a web shell to exfiltrate a ZIP file containing a dump of LSASS memory on a compromised machine.(Citation: DFIR Report APT35 ProxyShell March 2022)(Citation: DFIR Phosphorus November 2021)
- [S0467] TajMahal: [TajMahal](https://attack.mitre.org/software/S0467) has the ability to steal documents from the local system including the print spooler queue.(Citation: Kaspersky TajMahal April 2019)
- [C0012] Operation CuckooBees: During [Operation CuckooBees](https://attack.mitre.org/campaigns/C0012), the threat actors collected data, files, and other information from compromised networks.(Citation: Cybereason OperationCuckooBees May 2022)
- [G0070] Dark Caracal: [Dark Caracal](https://attack.mitre.org/groups/G0070) collected complete contents of the 'Pictures' folder from compromised Windows systems.(Citation: Lookout Dark Caracal Jan 2018)
- [S1037] STARWHALE: [STARWHALE](https://attack.mitre.org/software/S1037) can collect data from an infected local host.(Citation: DHS CISA AA22-055A MuddyWater February 2022)
- [S1075] KOPILUWAK: [KOPILUWAK](https://attack.mitre.org/software/S1075) can gather information from compromised hosts.(Citation: Mandiant Suspected Turla Campaign February 2023)
- [S0660] Clambling: [Clambling](https://attack.mitre.org/software/S0660) can collect information from a compromised host.(Citation: Trend Micro DRBControl February 2020)
- [S0515] WellMail: [WellMail](https://attack.mitre.org/software/S0515) can exfiltrate files from the victim machine.(Citation: CISA WellMail July 2020)
- [S0629] RainyDay: [RainyDay](https://attack.mitre.org/software/S0629) can use a file exfiltration tool to collect recently changed files on a compromised host.(Citation: Bitdefender Naikon April 2021)
- [S1034] StrifeWater: [StrifeWater](https://attack.mitre.org/software/S1034) can collect data from a compromised host.(Citation: Cybereason StrifeWater Feb 2022)
- [S0234] Bandook: [Bandook](https://attack.mitre.org/software/S0234) can collect local files from the system .(Citation: CheckPoint Bandook Nov 2020)
- [G0034] Sandworm Team: [Sandworm Team](https://attack.mitre.org/groups/G0034) has exfiltrated internal documents, files, and other data from compromised hosts.(Citation: US District Court Indictment GRU Unit 74455 October 2020)
- [S1028] Action RAT: [Action RAT](https://attack.mitre.org/software/S1028) can collect local data from an infected machine.(Citation: MalwareBytes SideCopy Dec 2021)
- [S1102] Pcexter: [Pcexter](https://attack.mitre.org/software/S1102) can upload files from targeted systems.(Citation: Kaspersky ToddyCat Check Logs October 2023)
- [G1016] FIN13: [FIN13](https://attack.mitre.org/groups/G1016) has gathered stolen credentials, sensitive data such as point-of-sale (POS), and ATM data from a compromised network before exfiltration.(Citation: Mandiant FIN13 Aug 2022)(Citation: Sygnia Elephant Beetle Jan 2022)
- [S0385] njRAT: [njRAT](https://attack.mitre.org/software/S0385) can collect data from a local system.(Citation: Fidelis njRAT June 2013)
- [S1099] Samurai: [Samurai](https://attack.mitre.org/software/S1099) can leverage an exfiltration module to download arbitrary files from compromised machines.(Citation: Kaspersky ToddyCat June 2022)
- [S1018] Saint Bot: [Saint Bot](https://attack.mitre.org/software/S1018) can collect files and information from a compromised host.(Citation: Malwarebytes Saint Bot April 2021)
- [C0026] C0026: During [C0026](https://attack.mitre.org/campaigns/C0026), the threat actors collected documents from compromised hosts.(Citation: Mandiant Suspected Turla Campaign February 2023)


### T1025 - Data from Removable Media

Description:

Adversaries may search connected removable media on computers they have compromised to find files of interest. Sensitive data can be collected from any removable media (optical disk drive, USB memory, etc.) connected to the compromised system prior to Exfiltration. Interactive command shells may be in use, and common functionality within [cmd](https://attack.mitre.org/software/S0106) may be used to gather information. 

Some adversaries may also use [Automated Collection](https://attack.mitre.org/techniques/T1119) on removable media.

Procedures:

- [S0136] USBStealer: Once a removable media device is inserted back into the first victim, [USBStealer](https://attack.mitre.org/software/S0136) collects data from it that was exfiltrated from a second victim.(Citation: ESET Sednit USBStealer 2014)(Citation: Kaspersky Sofacy)
- [S0260] InvisiMole: [InvisiMole](https://attack.mitre.org/software/S0260) can collect jpeg files from connected MTP devices.(Citation: ESET InvisiMole June 2020)
- [S0456] Aria-body: [Aria-body](https://attack.mitre.org/software/S0456) has the ability to collect data from USB devices.(Citation: CheckPoint Naikon May 2020)
- [G0049] OilRig: [OilRig](https://attack.mitre.org/groups/G0049) has used Wireshark’s usbcapcmd utility to capture USB traffic.(Citation: Symantec Crambus OCT 2023)
- [S0569] Explosive: [Explosive](https://attack.mitre.org/software/S0569) can scan all .exe files located in the USB drive.(Citation: CheckPoint Volatile Cedar March 2015)
- [S0237] GravityRAT: [GravityRAT](https://attack.mitre.org/software/S0237) steals files based on an extension list if a USB drive is connected to the system.(Citation: Talos GravityRAT)
- [S0090] Rover: [Rover](https://attack.mitre.org/software/S0090) searches for files on attached removable drives based on a predefined list of file extensions every five seconds.(Citation: Palo Alto Rover)
- [S1146] MgBot: [MgBot](https://attack.mitre.org/software/S1146) includes modules capable of gathering information from USB thumb drives and CD-ROMs on the victim machine given a list of provided criteria.(Citation: ESET EvasivePanda 2023)
- [G0047] Gamaredon Group: A [Gamaredon Group](https://attack.mitre.org/groups/G0047) file stealer has the capability to steal data from newly connected logical volumes on a system, including USB drives.(Citation: Palo Alto Gamaredon Feb 2017)(Citation: ESET Gamaredon June 2020)
- [G0007] APT28: An [APT28](https://attack.mitre.org/groups/G0007) backdoor may collect the entire contents of an inserted USB device.(Citation: Microsoft SIR Vol 19)
- [S0125] Remsec: [Remsec](https://attack.mitre.org/software/S0125) has a package that collects documents from any inserted USB sticks.(Citation: Kaspersky ProjectSauron Technical Analysis)
- [S0128] BADNEWS: [BADNEWS](https://attack.mitre.org/software/S0128) copies files with certain extensions from USB devices to
a predefined directory.(Citation: TrendMicro Patchwork Dec 2017)
- [S0113] Prikormka: [Prikormka](https://attack.mitre.org/software/S0113) contains a module that collects documents with certain extensions from removable media or fixed drives connected via USB.(Citation: ESET Operation Groundbait)
- [S0538] Crutch: [Crutch](https://attack.mitre.org/software/S0538) can monitor removable drives and exfiltrate files matching a given extension list.(Citation: ESET Crutch December 2020)
- [S0115] Crimson: [Crimson](https://attack.mitre.org/software/S0115) contains a module to collect data from removable drives.(Citation: Proofpoint Operation Transparent Tribe March 2016)(Citation: Kaspersky Transparent Tribe August 2020)
- [S0409] Machete: [Machete](https://attack.mitre.org/software/S0409) can find, encrypt, and upload files from fixed and removable drives.(Citation: Cylance Machete Mar 2017)(Citation: ESET Machete July 2019)
- [S0644] ObliqueRAT: [ObliqueRAT](https://attack.mitre.org/software/S0644) has the ability to extract data from removable devices connected to the endpoint.(Citation: Talos Oblique RAT March 2021)
- [G0010] Turla: [Turla](https://attack.mitre.org/groups/G0010) RPC backdoors can collect files from USB thumb drives.(Citation: ESET Turla PowerShell May 2019)(Citation: Symantec Waterbug Jun 2019)
- [S0467] TajMahal: [TajMahal](https://attack.mitre.org/software/S0467) has the ability to steal written CD images and files of interest from previously connected removable drives when they become available again.(Citation: Kaspersky TajMahal April 2019)
- [S0036] FLASHFLOOD: [FLASHFLOOD](https://attack.mitre.org/software/S0036) searches for interesting files (either a default or customized set of file extensions) on removable media and copies them to a staging area. The default file types copied would include data copied to the drive by [SPACESHIP](https://attack.mitre.org/software/S0035).(Citation: FireEye APT30)
- [S0622] AppleSeed: [AppleSeed](https://attack.mitre.org/software/S0622) can find and collect data from removable media devices.(Citation: Malwarebytes Kimsuky June 2021)(Citation: KISA Operation Muzabi)
- [S1044] FunnyDream: The [FunnyDream](https://attack.mitre.org/software/S1044) FilePakMonitor component has the ability to collect files from removable devices.(Citation: Bitdefender FunnyDream Campaign November 2020)
- [S0458] Ramsay: [Ramsay](https://attack.mitre.org/software/S0458) can collect data from removable media and stage it for exfiltration.(Citation: Eset Ramsay May 2020)
- [S0050] CosmicDuke: [CosmicDuke](https://attack.mitre.org/software/S0050) steals user files from removable media with file extensions and keywords that match a predefined list.(Citation: F-Secure Cosmicduke)


### T1039 - Data from Network Shared Drive

Description:

Adversaries may search network shares on computers they have compromised to find files of interest. Sensitive data can be collected from remote systems via shared network drives (host shared directory, network file server, etc.) that are accessible from the current system prior to Exfiltration. Interactive command shells may be in use, and common functionality within [cmd](https://attack.mitre.org/software/S0106) may be used to gather information.

Procedures:

- [G1039] RedCurl: [RedCurl](https://attack.mitre.org/groups/G1039) has collected data about network drives.(Citation: group-ib_redcurl1)(Citation: group-ib_redcurl2)
- [S0050] CosmicDuke: [CosmicDuke](https://attack.mitre.org/software/S0050) steals user files from network shared drives with file extensions and keywords that match a predefined list.(Citation: F-Secure Cosmicduke)
- [G0007] APT28: [APT28](https://attack.mitre.org/groups/G0007) has collected files from network shared drives.(Citation: Cybersecurity Advisory GRU Brute Force Campaign July 2021)
- [G0047] Gamaredon Group: [Gamaredon Group](https://attack.mitre.org/groups/G0047) malware has collected Microsoft Office documents from mapped network drives.(Citation: ESET Gamaredon June 2020)
- [G0060] BRONZE BUTLER: [BRONZE BUTLER](https://attack.mitre.org/groups/G0060) has exfiltrated files stolen from file shares.(Citation: Secureworks BRONZE BUTLER Oct 2017)
- [S0554] Egregor: [Egregor](https://attack.mitre.org/software/S0554) can collect any files found in the enumerated drivers before sending it to its C2 channel.(Citation: NHS Digital Egregor Nov 2020)
- [G0054] Sowbug: [Sowbug](https://attack.mitre.org/groups/G0054) extracted Word documents from a file server on a victim network.(Citation: Symantec Sowbug Nov 2017)
- [S0458] Ramsay: [Ramsay](https://attack.mitre.org/software/S0458) can collect data from network drives and stage it for exfiltration.(Citation: Eset Ramsay May 2020)
- [S0128] BADNEWS: When it first starts, [BADNEWS](https://attack.mitre.org/software/S0128) crawls the victim's mapped drives and collects documents with the following extensions: .doc, .docx, .pdf, .ppt, .pptx, and .txt.(Citation: Forcepoint Monsoon)
- [G0114] Chimera: [Chimera](https://attack.mitre.org/groups/G0114) has collected data of interest from network shares.(Citation: NCC Group Chimera January 2021)
- [G0045] menuPass: [menuPass](https://attack.mitre.org/groups/G0045) has collected data from remote systems by mounting network shares with <code>net use</code> and using Robocopy to transfer data.(Citation: PWC Cloud Hopper April 2017)
- [C0015] C0015: During [C0015](https://attack.mitre.org/campaigns/C0015), the threat actors collected files from network shared drives prior to network encryption.(Citation: DFIR Conti Bazar Nov 2021)
- [G0117] Fox Kitten: [Fox Kitten](https://attack.mitre.org/groups/G0117) has searched network shares to access sensitive documents.(Citation: CISA AA20-259A Iran-Based Actor September 2020)


### T1056 - Input Capture

Description:

Adversaries may use methods of capturing user input to obtain credentials or collect information. During normal system usage, users often provide credentials to various different locations, such as login pages/portals or system dialog boxes. Input capture mechanisms may be transparent to the user (e.g. [Credential API Hooking](https://attack.mitre.org/techniques/T1056/004)) or rely on deceiving the user into providing input into what they believe to be a genuine service (e.g. [Web Portal Capture](https://attack.mitre.org/techniques/T1056/003)).

Procedures:

- [G1044] APT42: [APT42](https://attack.mitre.org/groups/G1044) has used credential harvesting websites.(Citation: Mandiant APT42-untangling)
- [G1046] Storm-1811: [Storm-1811](https://attack.mitre.org/groups/G1046) has used a PowerShell script to capture user credentials after prompting a user to authenticate to run a malicious script masquerading as a legitimate update item.(Citation: rapid7-email-bombing)
- [S1059] metaMain: [metaMain](https://attack.mitre.org/software/S1059) can log mouse events.(Citation: SentinelLabs Metador Technical Appendix Sept 2022)
- [S1060] Mafalda: [Mafalda](https://attack.mitre.org/software/S1060) can conduct mouse event logging.(Citation: SentinelLabs Metador Technical Appendix Sept 2022)
- [C0039] Versa Director Zero Day Exploitation: [Versa Director Zero Day Exploitation](https://attack.mitre.org/campaigns/C0039) intercepted and harvested credentials from user logins to compromised devices.(Citation: Lumen Versa 2024)
- [S0631] Chaes: [Chaes](https://attack.mitre.org/software/S0631) has a module to perform any API hooking it desires.(Citation: Cybereason Chaes Nov 2020)
- [C0049] Leviathan Australian Intrusions: [Leviathan](https://attack.mitre.org/groups/G0065) captured submitted multfactor authentication codes and other technical artifacts related to remote access sessions during [Leviathan Australian Intrusions](https://attack.mitre.org/campaigns/C0049).(Citation: CISA Leviathan 2024)
- [S0381] FlawedAmmyy: [FlawedAmmyy](https://attack.mitre.org/software/S0381) can collect mouse events.(Citation: Korean FSI TA505 2020)
- [S0641] Kobalos: [Kobalos](https://attack.mitre.org/software/S0641) has used a compromised SSH client to capture the hostname, port, username and password used to establish an SSH connection from the compromised host.(Citation: ESET Kobalos Feb 2021)(Citation: ESET Kobalos Jan 2021)
- [S1131] NPPSPY: [NPPSPY](https://attack.mitre.org/software/S1131) captures user input into the Winlogon process by redirecting RPC traffic from legitimate listening DLLs within the operating system to a newly registered malicious item that allows for recording logon information in cleartext.(Citation: Huntress NPPSPY 2022)
- [G0087] APT39: [APT39](https://attack.mitre.org/groups/G0087) has utilized tools to capture mouse movements.(Citation: FBI FLASH APT39 September 2020)

#### T1056.001 - Keylogging

Description:

Adversaries may log user keystrokes to intercept credentials as the user types them. Keylogging is likely to be used to acquire credentials for new access opportunities when [OS Credential Dumping](https://attack.mitre.org/techniques/T1003) efforts are not effective, and may require an adversary to intercept keystrokes on a system for a substantial period of time before credentials can be successfully captured. In order to increase the likelihood of capturing credentials quickly, an adversary may also perform actions such as clearing browser cookies to force users to reauthenticate to systems.(Citation: Talos Kimsuky Nov 2021)

Keylogging is the most prevalent type of input capture, with many different ways of intercepting keystrokes.(Citation: Adventures of a Keystroke) Some methods include:

* Hooking API callbacks used for processing keystrokes. Unlike [Credential API Hooking](https://attack.mitre.org/techniques/T1056/004), this focuses solely on API functions intended for processing keystroke data.
* Reading raw keystroke data from the hardware buffer.
* Windows Registry modifications.
* Custom drivers.
* [Modify System Image](https://attack.mitre.org/techniques/T1601) may provide adversaries with hooks into the operating system of network devices to read raw keystrokes for login sessions.(Citation: Cisco Blog Legacy Device Attacks)

Procedures:

- [G0059] Magic Hound: [Magic Hound](https://attack.mitre.org/groups/G0059) malware is capable of keylogging.(Citation: Unit 42 Magic Hound Feb 2017)
- [C0014] Operation Wocao: During [Operation Wocao](https://attack.mitre.org/campaigns/C0014), threat actors obtained the password for the victim's password manager via a custom keylogger.(Citation: FoxIT Wocao December 2019)
- [S0021] Derusbi: [Derusbi](https://attack.mitre.org/software/S0021) is capable of logging keystrokes.(Citation: FireEye Periscope March 2018)
- [S1012] PowerLess: [PowerLess](https://attack.mitre.org/software/S1012) can use a module to log keystrokes.(Citation: Cybereason PowerLess February 2022)
- [S0643] Peppy: [Peppy](https://attack.mitre.org/software/S0643) can log keystrokes on compromised hosts.(Citation: Proofpoint Operation Transparent Tribe March 2016)
- [S0670] WarzoneRAT: [WarzoneRAT](https://attack.mitre.org/software/S0670) has the capability to install a live and offline keylogger, including through the use of the `GetAsyncKeyState` Windows API.(Citation: Check Point Warzone Feb 2020)(Citation: Uptycs Warzone UAC Bypass November 2020)
- [S0038] Duqu: [Duqu](https://attack.mitre.org/software/S0038) can track key presses with a keylogger module.(Citation: Symantec W32.Duqu)
- [S0283] jRAT: [jRAT](https://attack.mitre.org/software/S0283) has the capability to log keystrokes from the victim’s machine, both offline and online.(Citation: jRAT Symantec Aug 2018)(Citation: Kaspersky Adwind Feb 2016)
- [S0455] Metamorfo: [Metamorfo](https://attack.mitre.org/software/S0455) has a command to launch a keylogger and capture keystrokes on the victim’s machine.(Citation: Fortinet Metamorfo Feb 2020)(Citation: ESET Casbaneiro Oct 2019)
- [S0045] ADVSTORESHELL: [ADVSTORESHELL](https://attack.mitre.org/software/S0045) can perform keylogging.(Citation: ESET Sednit Part 2)(Citation: Bitdefender APT28 Dec 2015)
- [S1146] MgBot: [MgBot](https://attack.mitre.org/software/S1146) includes keylogger payloads focused on the QQ chat application.(Citation: ESET EvasivePanda 2023)(Citation: Symantec Daggerfly 2023)
- [G0087] APT39: [APT39](https://attack.mitre.org/groups/G0087) has used tools for capturing keystrokes.(Citation: Symantec Chafer February 2018)(Citation: FBI FLASH APT39 September 2020)
- [S0149] MoonWind: [MoonWind](https://attack.mitre.org/software/S0149) has a keylogger.(Citation: Palo Alto MoonWind March 2017)
- [S0152] EvilGrab: [EvilGrab](https://attack.mitre.org/software/S0152) has the capability to capture keystrokes.(Citation: PWC Cloud Hopper Technical Annex April 2017)
- [S0161] XAgentOSX: [XAgentOSX](https://attack.mitre.org/software/S0161) contains keylogging functionality that will monitor for active application windows and write them to the log, it can handle special characters, and it will buffer by default 50 characters before sending them out over the C2 infrastructure.(Citation: XAgentOSX 2017)
- [S0363] Empire: [Empire](https://attack.mitre.org/software/S0363) includes keylogging capabilities for Windows, Linux, and macOS systems.(Citation: Github PowerShell Empire)
- [S0339] Micropsia: [Micropsia](https://attack.mitre.org/software/S0339) has keylogging capabilities.(Citation: Radware Micropsia July 2018)
- [S0113] Prikormka: [Prikormka](https://attack.mitre.org/software/S0113) contains a keylogger module that collects keystrokes and the titles of foreground windows.(Citation: ESET Operation Groundbait)
- [G0082] APT38: [APT38](https://attack.mitre.org/groups/G0082) used a Trojan called KEYLIME to capture keystrokes from the victim’s machine.(Citation: FireEye APT38 Oct 2018)
- [S0410] Fysbis: [Fysbis](https://attack.mitre.org/software/S0410) can perform keylogging.(Citation: Fysbis Palo Alto Analysis)
- [S0194] PowerSploit: [PowerSploit](https://attack.mitre.org/software/S0194)'s <code>Get-Keystrokes</code> Exfiltration module can log keystrokes.(Citation: GitHub PowerSploit May 2012)(Citation: PowerSploit Documentation)
- [S0379] Revenge RAT: [Revenge RAT](https://attack.mitre.org/software/S0379) has a plugin for keylogging.(Citation: Cylance Shaheen Nov 2018)(Citation: Cofense RevengeRAT Feb 2019)
- [G1017] Volt Typhoon: [Volt Typhoon](https://attack.mitre.org/groups/G1017) has created and accessed a file named rult3uil.log on compromised domain controllers to capture keypresses and command execution.(Citation: CISA AA24-038A PRC Critical Infrastructure February 2024)
- [S0167] Matryoshka: [Matryoshka](https://attack.mitre.org/software/S0167) is capable of keylogging.(Citation: ClearSky Wilted Tulip July 2017)(Citation: CopyKittens Nov 2015)
- [G0130] Ajax Security Team: [Ajax Security Team](https://attack.mitre.org/groups/G0130) has used CWoolger and MPK, custom-developed malware, which recorded all keystrokes on an infected system.(Citation: Check Point Rocket Kitten)
- [S0381] FlawedAmmyy: [FlawedAmmyy](https://attack.mitre.org/software/S0381) can collect keyboard events.(Citation: Korean FSI TA505 2020)
- [S0148] RTM: [RTM](https://attack.mitre.org/software/S0148) can record keystrokes from both the keyboard and virtual keyboard.(Citation: ESET RTM Feb 2017)(Citation: Unit42 Redaman January 2019)
- [S0454] Cadelspy: [Cadelspy](https://attack.mitre.org/software/S0454) has the ability to log keystrokes on the compromised host.(Citation: Symantec Chafer Dec 2015)
- [S0567] Dtrack: [Dtrack](https://attack.mitre.org/software/S0567)’s dropper contains a keylogging executable.(Citation: Securelist Dtrack)
- [S0434] Imminent Monitor: [Imminent Monitor](https://attack.mitre.org/software/S0434) has a keylogging module.(Citation: Imminent Unit42 Dec2019)
- [S0261] Catchamas: [Catchamas](https://attack.mitre.org/software/S0261) collects keystrokes from the victim’s machine.(Citation: Symantec Catchamas April 2018)
- [S0154] Cobalt Strike: [Cobalt Strike](https://attack.mitre.org/software/S0154) can track key presses with a keylogger module.(Citation: cobaltstrike manual)(Citation: Amnesty Intl. Ocean Lotus February 2021)(Citation: Cobalt Strike Manual 4.3 November 2020)
- [S0033] NetTraveler: [NetTraveler](https://attack.mitre.org/software/S0033) contains a keylogger.(Citation: Kaspersky NetTraveler)
- [G0007] APT28: [APT28](https://attack.mitre.org/groups/G0007) has used tools to perform keylogging.(Citation: Microsoft SIR Vol 19)(Citation: DOJ GRU Indictment Jul 2018)(Citation: TrendMicro Pawn Storm Dec 2020)
- [S0262] QuasarRAT: [QuasarRAT](https://attack.mitre.org/software/S0262) has a built-in keylogger.(Citation: GitHub QuasarRAT)(Citation: Volexity Patchwork June 2018)
- [S0125] Remsec: [Remsec](https://attack.mitre.org/software/S0125) contains a keylogger component.(Citation: Symantec Remsec IOCs)(Citation: Kaspersky ProjectSauron Technical Analysis)
- [S1159] DUSTTRAP: [DUSTTRAP](https://attack.mitre.org/software/S1159) can perform keylogging operations.(Citation: Google Cloud APT41 2024)
- [S0072] OwaAuth: [OwaAuth](https://attack.mitre.org/software/S0072) captures and DES-encrypts credentials before writing the username and password to a log file, <code>C:\log.txt</code>.(Citation: Dell TG-3390)
- [S0234] Bandook: [Bandook](https://attack.mitre.org/software/S0234) contains keylogging capabilities.(Citation: BH Manul Aug 2016)
- [S0240] ROKRAT: [ROKRAT](https://attack.mitre.org/software/S0240) can use  `SetWindowsHookEx` and `GetKeyNameText` to capture keystrokes.(Citation: Talos ROKRAT)(Citation: Volexity InkySquid RokRAT August 2021)
- [G0012] Darkhotel: [Darkhotel](https://attack.mitre.org/groups/G0012) has used a keylogger.(Citation: Kaspersky Darkhotel)
- [S0019] Regin: [Regin](https://attack.mitre.org/software/S0019) contains a keylogger.(Citation: Kaspersky Regin)
- [S0013] PlugX: [PlugX](https://attack.mitre.org/software/S0013) has a module for capturing keystrokes per process including window titles.(Citation: CIRCL PlugX March 2013)
- [S0533] SLOTHFULMEDIA: [SLOTHFULMEDIA](https://attack.mitre.org/software/S0533) has a keylogging capability.(Citation: CISA MAR SLOTHFULMEDIA October 2020)
- [S0414] BabyShark: [BabyShark](https://attack.mitre.org/software/S0414) has a [PowerShell](https://attack.mitre.org/techniques/T1059/001)-based remote administration ability that can implement a PowerShell or C# based keylogger.(Citation: Unit42 BabyShark Apr 2019)
- [S0257] VERMIN: [VERMIN](https://attack.mitre.org/software/S0257) collects keystrokes from the victim machine.(Citation: Unit 42 VERMIN Jan 2018)
- [S0128] BADNEWS: When it first starts, [BADNEWS](https://attack.mitre.org/software/S0128) spawns a new thread to log keystrokes.(Citation: Forcepoint Monsoon)(Citation: PaloAlto Patchwork Mar 2018)(Citation: TrendMicro Patchwork Dec 2017)
- [S0012] PoisonIvy: [PoisonIvy](https://attack.mitre.org/software/S0012) contains a keylogger.(Citation: FireEye Poison Ivy)(Citation: Symantec Darkmoon Aug 2005)
- [S0652] MarkiRAT: [MarkiRAT](https://attack.mitre.org/software/S0652) can capture all keystrokes on a compromised host.(Citation: Kaspersky Ferocious Kitten Jun 2021)
- [S0595] ThiefQuest: [ThiefQuest](https://attack.mitre.org/software/S0595) uses the <code>CGEventTap</code> functions to perform keylogging.(Citation: Trendmicro Evolving ThiefQuest 2020)
- [S0348] Cardinal RAT: [Cardinal RAT](https://attack.mitre.org/software/S0348) can log keystrokes.(Citation: PaloAlto CardinalRat Apr 2017)
- [S0375] Remexi: [Remexi](https://attack.mitre.org/software/S0375) gathers and exfiltrates keystrokes from the machine.(Citation: Securelist Remexi Jan 2019)
- [S0260] InvisiMole: [InvisiMole](https://attack.mitre.org/software/S0260) can capture keystrokes on a compromised host.(Citation: ESET InvisiMole June 2020)
- [S0213] DOGCALL: [DOGCALL](https://attack.mitre.org/software/S0213) is capable of logging keystrokes.(Citation: FireEye APT37 Feb 2018)(Citation: Unit 42 Nokki Oct 2018)
- [S0253] RunningRAT: [RunningRAT](https://attack.mitre.org/software/S0253) captures keystrokes and sends them back to the C2 server.(Citation: McAfee Gold Dragon)
- [S0569] Explosive: [Explosive](https://attack.mitre.org/software/S0569) has leveraged its keylogging capabilities to gain access to administrator accounts on target servers.(Citation: CheckPoint Volatile Cedar March 2015)(Citation: ClearSky Lebanese Cedar Jan 2021)
- [G0045] menuPass: [menuPass](https://attack.mitre.org/groups/G0045) has used key loggers to steal usernames and passwords.(Citation: District Court of NY APT10 Indictment December 2018)
- [S0622] AppleSeed: [AppleSeed](https://attack.mitre.org/software/S0622) can use <code>GetKeyState</code> and <code>GetKeyboardState</code> to capture keystrokes on the victim’s machine.(Citation: Malwarebytes Kimsuky June 2021)(Citation: KISA Operation Muzabi)
- [S1207] XLoader: [XLoader](https://attack.mitre.org/software/S1207) can capture keystrokes from the victim machine.(Citation: Google XLoader 2017)
- [S0115] Crimson: [Crimson](https://attack.mitre.org/software/S0115) can use a module to perform keylogging on compromised hosts.(Citation: Proofpoint Operation Transparent Tribe March 2016)(Citation: Kaspersky Transparent Tribe August 2020)(Citation: Cisco Talos Transparent Tribe Education Campaign July 2022)
- [S0062] DustySky: [DustySky](https://attack.mitre.org/software/S0062) contains a keylogger.(Citation: DustySky)
- [S0378] PoshC2: [PoshC2](https://attack.mitre.org/software/S0378) has modules for keystroke logging and capturing credentials from spoofed Outlook authentication messages.(Citation: GitHub PoshC2)
- [S1050] PcShare: [PcShare](https://attack.mitre.org/software/S1050) has the ability to capture keystrokes.(Citation: Bitdefender FunnyDream Campaign November 2020)
- [G1023] APT5: [APT5](https://attack.mitre.org/groups/G1023) has used malware with keylogging capabilities to monitor the communications of targeted entities.(Citation: FireEye Southeast Asia Threat Landscape March 2015)(Citation: Mandiant Advanced Persistent Threats)
- [G0131] Tonto Team: [Tonto Team](https://attack.mitre.org/groups/G0131) has used keylogging tools in their operations.(Citation: TrendMicro Tonto Team October 2020)
- [S0337] BadPatch: [BadPatch](https://attack.mitre.org/software/S0337) has a keylogging capability.(Citation: Unit 42 BadPatch Oct 2017)
- [S0447] Lokibot: [Lokibot](https://attack.mitre.org/software/S0447) has the ability to capture input on the compromised host via keylogging.(Citation: FSecure Lokibot November 2019)
- [S0625] Cuba: [Cuba](https://attack.mitre.org/software/S0625) logs keystrokes via polling by using <code>GetKeyState</code> and <code>VkKeyScan</code> functions.(Citation: McAfee Cuba April 2021)
- [S0662] RCSession: [RCSession](https://attack.mitre.org/software/S0662) has the ability to capture keystrokes on a compromised host.(Citation: Trend Micro DRBControl February 2020)(Citation: Profero APT27 December 2020)
- [S0387] KeyBoy: [KeyBoy](https://attack.mitre.org/software/S0387) installs a keylogger for intercepting credentials and keystrokes.(Citation: Rapid7 KeyBoy Jun 2013)
- [S1122] Mispadu: [Mispadu](https://attack.mitre.org/software/S1122) can log keystrokes on the victim's machine.(Citation: ESET Security Mispadu Facebook Ads 2019)(Citation: Metabase Q Mispadu Trojan 2023)(Citation: SCILabs URSA/Mispadu Evolution 2023)
- [S0170] Helminth: The executable version of [Helminth](https://attack.mitre.org/software/S0170) has a module to log keystrokes.(Citation: Palo Alto OilRig May 2016)
- [G0027] Threat Group-3390: [Threat Group-3390](https://attack.mitre.org/groups/G0027) actors installed a credential logger on Microsoft Exchange servers. [Threat Group-3390](https://attack.mitre.org/groups/G0027) also leveraged the reconnaissance framework, ScanBox, to capture keystrokes.(Citation: Dell TG-3390)(Citation: Hacker News LuckyMouse June 2018)(Citation: Securelist LuckyMouse June 2018)
- [S0050] CosmicDuke: [CosmicDuke](https://attack.mitre.org/software/S0050) uses a keylogger.(Citation: F-Secure The Dukes)
- [S0373] Astaroth: [Astaroth](https://attack.mitre.org/software/S0373) logs keystrokes from the victim's machine. (Citation: Cofense Astaroth Sept 2018)
- [S0649] SMOKEDHAM: [SMOKEDHAM](https://attack.mitre.org/software/S0649) can continuously capture keystrokes.(Citation: FireEye Shining A Light on DARKSIDE May 2021)(Citation: FireEye SMOKEDHAM June 2021)
- [S0094] Trojan.Karagany: [Trojan.Karagany](https://attack.mitre.org/software/S0094) can capture keystrokes on a compromised host.(Citation: Secureworks Karagany July 2019)
- [S0201] JPIN: [JPIN](https://attack.mitre.org/software/S0201) contains a custom keylogger.(Citation: Microsoft PLATINUM April 2016)
- [S0018] Sykipot: [Sykipot](https://attack.mitre.org/software/S0018) contains keylogging functionality to steal passwords.(Citation: Alienvault Sykipot DOD Smart Cards)
- [S1111] DarkGate: [DarkGate](https://attack.mitre.org/software/S1111) will spawn a thread on execution to capture all keyboard events and write them to a predefined log file.(Citation: Ensilo Darkgate 2018)(Citation: Rapid7 BlackBasta 2024)
- [S1044] FunnyDream: The [FunnyDream](https://attack.mitre.org/software/S1044) Keyrecord component can capture keystrokes.(Citation: Bitdefender FunnyDream Campaign November 2020)
- [S1066] DarkTortilla: [DarkTortilla](https://attack.mitre.org/software/S1066) can download a keylogging module.(Citation: Secureworks DarkTortilla Aug 2022)
- [S0437] Kivars: [Kivars](https://attack.mitre.org/software/S0437) has the ability to initiate keylogging on the infected host.(Citation: TrendMicro BlackTech June 2017)
- [G0032] Lazarus Group: [Lazarus Group](https://attack.mitre.org/groups/G0032) malware KiloAlfa contains keylogging functionality.(Citation: Novetta Blockbuster)(Citation: Novetta Blockbuster Tools)
- [S0531] Grandoreiro: [Grandoreiro](https://attack.mitre.org/software/S0531) can log keystrokes on the victim's machine.(Citation: ESET Grandoreiro April 2020)
- [S0192] Pupy: [Pupy](https://attack.mitre.org/software/S0192) uses a keylogger to capture keystrokes it then sends back to the server after it is stopped.(Citation: GitHub Pupy)
- [S0030] Carbanak: [Carbanak](https://attack.mitre.org/software/S0030) logs key strokes for configured processes and sends them back to the C2 server.(Citation: Kaspersky Carbanak)(Citation: FireEye CARBANAK June 2017)
- [G0043] Group5: Malware used by [Group5](https://attack.mitre.org/groups/G0043) is capable of capturing keystrokes.(Citation: Citizen Lab Group5)
- [S0338] Cobian RAT: [Cobian RAT](https://attack.mitre.org/software/S0338) has a feature to perform keylogging on the victim’s machine.(Citation: Zscaler Cobian Aug 2017)
- [S0331] Agent Tesla: [Agent Tesla](https://attack.mitre.org/software/S0331) can log keystrokes on the victim’s machine.(Citation: Talos Agent Tesla Oct 2018)(Citation: DigiTrust Agent Tesla Jan 2017)(Citation: Fortinet Agent Tesla June 2017)(Citation: Bitdefender Agent Tesla April 2020)(Citation: SentinelLabs Agent Tesla Aug 2020)
- [G0068] PLATINUM: [PLATINUM](https://attack.mitre.org/groups/G0068) has used several different keyloggers.(Citation: Microsoft PLATINUM April 2016)
- [G0085] FIN4: [FIN4](https://attack.mitre.org/groups/G0085) has captured credentials via fake Outlook Web App (OWA) login pages and has also used a .NET based keylogger.(Citation: FireEye Hacking FIN4 Dec 2014)(Citation: FireEye Hacking FIN4 Video Dec 2014)
- [S0058] SslMM: [SslMM](https://attack.mitre.org/software/S0058) creates a new thread implementing a keylogging facility using Windows Keyboard Accelerators.(Citation: Baumgartner Naikon 2015)
- [S0023] CHOPSTICK: [CHOPSTICK](https://attack.mitre.org/software/S0023) is capable of performing keylogging.(Citation: Crowdstrike DNC June 2016)(Citation: ESET Sednit Part 2)(Citation: DOJ GRU Indictment Jul 2018)
- [S1090] NightClub: [NightClub](https://attack.mitre.org/software/S1090) can use a plugin for keylogging.(Citation: MoustachedBouncer ESET August 2023)
- [G0034] Sandworm Team: [Sandworm Team](https://attack.mitre.org/groups/G0034) has used a keylogger to capture keystrokes by using the SetWindowsHookEx function.(Citation: ESET Telebots Dec 2016)
- [S0660] Clambling: [Clambling](https://attack.mitre.org/software/S0660) can capture keystrokes on a compromised host.(Citation: Trend Micro DRBControl February 2020)(Citation: Talent-Jump Clambling February 2020)
- [S1149] CHIMNEYSWEEP: [CHIMNEYSWEEP](https://attack.mitre.org/software/S1149) has the ability to support keylogging.(Citation: Mandiant ROADSWEEP August 2022)
- [S0247] NavRAT: [NavRAT](https://attack.mitre.org/software/S0247) logs the keystrokes on the targeted system.(Citation: Talos NavRAT May 2018)
- [S0385] njRAT: [njRAT](https://attack.mitre.org/software/S0385) is capable of logging keystrokes.(Citation: Fidelis njRAT June 2013)(Citation: Trend Micro njRAT 2018)(Citation: Citizen Lab Group5)
- [S0336] NanoCore: [NanoCore](https://attack.mitre.org/software/S0336) can perform keylogging on the victim’s machine.(Citation: PaloAlto NanoCore Feb 2016)
- [S0279] Proton: [Proton](https://attack.mitre.org/software/S0279) uses a keylogger to capture keystrokes.(Citation: objsee mac malware 2017)
- [S0409] Machete: [Machete](https://attack.mitre.org/software/S0409) logs keystrokes from the victim’s machine.(Citation: ESET Machete July 2019)(Citation: Securelist Machete Aug 2014)(Citation: Cylance Machete Mar 2017)(Citation: 360 Machete Sep 2020)
- [G0094] Kimsuky: [Kimsuky](https://attack.mitre.org/groups/G0094) has used a PowerShell-based keylogger as well as a tool called MECHANICAL to log keystrokes.(Citation: EST Kimsuky April 2019)(Citation: Securelist Kimsuky Sept 2013)(Citation: CISA AA20-301A Kimsuky)(Citation: Netscout Stolen Pencil Dec 2018)(Citation: Talos Kimsuky Nov 2021)(Citation: KISA Operation Muzabi)
- [G0049] OilRig: [OilRig](https://attack.mitre.org/groups/G0049) has employed keyloggers including KEYPUNCH and LONGWATCH.(Citation: FireEye APT34 Webinar Dec 2017)(Citation: FireEye APT34 July 2019)(Citation: Symantec Crambus OCT 2023)
- [S0438] Attor: One of [Attor](https://attack.mitre.org/software/S0438)'s plugins can collect user credentials via capturing keystrokes and can capture keystrokes pressed within the window of the injected process.(Citation: ESET Attor Oct 2019)
- [G1044] APT42: [APT42](https://attack.mitre.org/groups/G1044) has used custom malware to log keystrokes.(Citation: Mandiant APT42-charms)
- [S0070] HTTPBrowser: [HTTPBrowser](https://attack.mitre.org/software/S0070) is capable of capturing keystrokes on victims.(Citation: Dell TG-3390)
- [G0054] Sowbug: [Sowbug](https://attack.mitre.org/groups/G0054) has used keylogging tools.(Citation: Symantec Sowbug Nov 2017)
- [S0248] yty: [yty](https://attack.mitre.org/software/S0248) uses a keylogger plugin to gather keystrokes.(Citation: ASERT Donot March 2018)
- [S1016] MacMa: [MacMa](https://attack.mitre.org/software/S1016) can use Core Graphics Event Taps to intercept user keystrokes from any text input field and saves them to text files. Text input fields include Spotlight, Finder, Safari, Mail, Messages, and other apps that have text fields for passwords.(Citation: Objective-See MacMa Nov 2021)(Citation: SentinelOne MacMa Nov 2021)
- [S0089] BlackEnergy: [BlackEnergy](https://attack.mitre.org/software/S0089) has run a keylogger plug-in on a victim.(Citation: Securelist BlackEnergy Nov 2014)
- [S0593] ECCENTRICBANDWAGON: [ECCENTRICBANDWAGON](https://attack.mitre.org/software/S0593) can capture and store keystrokes.(Citation: CISA EB Aug 2020)
- [S0032] gh0st RAT: [gh0st RAT](https://attack.mitre.org/software/S0032) has a keylogger.(Citation: Alintanahin 2014)(Citation: Gh0stRAT ATT March 2019)
- [S0076] FakeM: [FakeM](https://attack.mitre.org/software/S0076) contains a keylogger module.(Citation: Scarlet Mimic Jan 2016)
- [S0198] NETWIRE: [NETWIRE](https://attack.mitre.org/software/S0198) can perform keylogging.(Citation: McAfee Netwire Mar 2015)(Citation: FireEye APT33 Webinar Sept 2017)(Citation: FireEye NETWIRE March 2019)(Citation: Red Canary NETWIRE January 2020)(Citation: Proofpoint NETWIRE December 2020)
- [S0332] Remcos: [Remcos](https://attack.mitre.org/software/S0332) has a command for keylogging.(Citation: Fortinet Remcos Feb 2017)(Citation: Talos Remcos Aug 2018)
- [S0650] QakBot: [QakBot](https://attack.mitre.org/software/S0650) can capture keystrokes on a compromised host.(Citation: Kroll Qakbot June 2020)(Citation: Trend Micro Qakbot December 2020)(Citation: Kaspersky QakBot September 2021)
- [S0342] GreyEnergy: [GreyEnergy](https://attack.mitre.org/software/S0342) has a module to harvest pressed keystrokes.(Citation: ESET GreyEnergy Oct 2018)
- [G1001] HEXANE: [HEXANE](https://attack.mitre.org/groups/G1001) has used a PowerShell-based keylogger named `kl.ps1`.(Citation: SecureWorks August 2019)(Citation: Kaspersky Lyceum October 2021)
- [C0028] 2015 Ukraine Electric Power Attack: During the [2015 Ukraine Electric Power Attack](https://attack.mitre.org/campaigns/C0028), [Sandworm Team](https://attack.mitre.org/groups/G0034) gathered account credentials via a [BlackEnergy](https://attack.mitre.org/software/S0089) keylogger plugin. (Citation: Booz Allen Hamilton)(Citation: Ukraine15 - EISAC - 201603)
- [S0187] Daserf: [Daserf](https://attack.mitre.org/software/S0187) can log keystrokes.(Citation: Trend Micro Daserf Nov 2017)(Citation: Secureworks BRONZE BUTLER Oct 2017)
- [S0004] TinyZBot: [TinyZBot](https://attack.mitre.org/software/S0004) contains keylogger functionality.(Citation: Cylance Cleaver)
- [S0439] Okrum: [Okrum](https://attack.mitre.org/software/S0439) was seen using a keylogger tool to capture keystrokes. (Citation: ESET Okrum July 2019)
- [S0334] DarkComet: [DarkComet](https://attack.mitre.org/software/S0334) has a keylogging capability.(Citation: TrendMicro DarkComet Sept 2014)
- [G0050] APT32: [APT32](https://attack.mitre.org/groups/G0050) has abused the PasswordChangeNotify to monitor for and capture account password changes.(Citation: Cybereason Cobalt Kitty 2017)
- [C0029] Cutting Edge: During [Cutting Edge](https://attack.mitre.org/campaigns/C0029), threat actors modified a JavaScript file on the Web SSL VPN component of Ivanti Connect Secure devices to keylog credentials.(Citation: Volexity Ivanti Zero-Day Exploitation January 2024)
- [S0673] DarkWatchman: [DarkWatchman](https://attack.mitre.org/software/S0673) can track key presses with a keylogger module.(Citation: Prevailion DarkWatchman 2021)
- [S0330] Zeus Panda: [Zeus Panda](https://attack.mitre.org/software/S0330) can perform keylogging on the victim’s machine by hooking the functions TranslateMessage and WM_KEYDOWN.(Citation: GDATA Zeus Panda June 2017)
- [S0017] BISCUIT: [BISCUIT](https://attack.mitre.org/software/S0017) can capture keystrokes.(Citation: Mandiant APT1 Appendix)
- [S1059] metaMain: [metaMain](https://attack.mitre.org/software/S1059) has the ability to log keyboard events.(Citation: SentinelLabs Metador Sept 2022)(Citation: SentinelLabs Metador Technical Appendix Sept 2022)
- [S0088] Kasidet: [Kasidet](https://attack.mitre.org/software/S0088) has the ability to initiate keylogging.(Citation: Zscaler Kasidet)
- [S0282] MacSpy: [MacSpy](https://attack.mitre.org/software/S0282) captures keystrokes.(Citation: objsee mac malware 2017)
- [S0692] SILENTTRINITY: [SILENTTRINITY](https://attack.mitre.org/software/S0692) has a keylogging capability.(Citation: GitHub SILENTTRINITY Modules July 2019)
- [S0356] KONNI: [KONNI](https://attack.mitre.org/software/S0356) has the capability to perform keylogging.(Citation: Talos Konni May 2017)
- [S0526] KGH_SPY: [KGH_SPY](https://attack.mitre.org/software/S0526) can perform keylogging by polling the <code>GetAsyncKeyState()</code> function.(Citation: Cybereason Kimsuky November 2020)
- [S0130] Unknown Logger: [Unknown Logger](https://attack.mitre.org/software/S0130) is capable of recording keystrokes.(Citation: Forcepoint Monsoon)
- [G0022] APT3: [APT3](https://attack.mitre.org/groups/G0022) has used a keylogging tool that records keystrokes in encrypted files.(Citation: Symantec Buckeye)
- [S0467] TajMahal: [TajMahal](https://attack.mitre.org/software/S0467) has the ability to capture keystrokes on an infected host.(Citation: Kaspersky TajMahal April 2019)
- [G1016] FIN13: [FIN13](https://attack.mitre.org/groups/G1016) has logged the keystrokes of victims to escalate privileges.(Citation: Mandiant FIN13 Aug 2022)
- [S0412] ZxShell: [ZxShell](https://attack.mitre.org/software/S0412) has a feature to capture a remote computer's keystrokes using a keylogger.(Citation: FireEye APT41 Aug 2019)(Citation: Talos ZxShell Oct 2014)
- [G0004] Ke3chang: [Ke3chang](https://attack.mitre.org/groups/G0004) has used keyloggers.(Citation: NCC Group APT15 Alive and Strong)(Citation: Microsoft NICKEL December 2021)
- [S0090] Rover: [Rover](https://attack.mitre.org/software/S0090) has keylogging functionality.(Citation: Palo Alto Rover)
- [G0096] APT41: [APT41](https://attack.mitre.org/groups/G0096) used a keylogger called GEARSHIFT on a target system.(Citation: FireEye APT41 Aug 2019)
- [S1087] AsyncRAT: [AsyncRAT](https://attack.mitre.org/software/S1087) can capture keystrokes on the victim’s machine.(Citation: AsyncRAT GitHub)
- [S0428] PoetRAT: [PoetRAT](https://attack.mitre.org/software/S0428) has used a Python tool named klog.exe for keylogging.(Citation: Talos PoetRAT April 2020)

#### T1056.002 - GUI Input Capture

Description:

Adversaries may mimic common operating system GUI components to prompt users for credentials with a seemingly legitimate prompt. When programs are executed that need additional privileges than are present in the current user context, it is common for the operating system to prompt the user for proper credentials to authorize the elevated privileges for the task (ex: [Bypass User Account Control](https://attack.mitre.org/techniques/T1548/002)).

Adversaries may mimic this functionality to prompt users for credentials with a seemingly legitimate prompt for a number of reasons that mimic normal usage, such as a fake installer requiring additional access or a fake malware removal suite.(Citation: OSX Malware Exploits MacKeeper) This type of prompt can be used to collect credentials via various languages such as [AppleScript](https://attack.mitre.org/techniques/T1059/002)(Citation: LogRhythm Do You Trust Oct 2014)(Citation: OSX Keydnap malware)(Citation: Spoofing credential dialogs) and [PowerShell](https://attack.mitre.org/techniques/T1059/001).(Citation: LogRhythm Do You Trust Oct 2014)(Citation: Enigma Phishing for Credentials Jan 2015)(Citation: Spoofing credential dialogs) On Linux systems adversaries may launch dialog boxes prompting users for credentials from malicious shell scripts or the command line (i.e. [Unix Shell](https://attack.mitre.org/techniques/T1059/004)).(Citation: Spoofing credential dialogs)

Adversaries may also mimic common software authentication requests, such as those from browsers or email clients. This may also be paired with user activity monitoring (i.e., [Browser Information Discovery](https://attack.mitre.org/techniques/T1217) and/or [Application Window Discovery](https://attack.mitre.org/techniques/T1010)) to spoof prompts when users are naturally accessing sensitive sites/data.

Procedures:

- [S0279] Proton: [Proton](https://attack.mitre.org/software/S0279) prompts users for their credentials.(Citation: objsee mac malware 2017)
- [S0278] iKitten: [iKitten](https://attack.mitre.org/software/S0278) prompts the user for their credentials.(Citation: objsee mac malware 2017)
- [S0455] Metamorfo: [Metamorfo](https://attack.mitre.org/software/S0455) has displayed fake forms on top of banking sites to intercept credentials from victims.(Citation: FireEye Metamorfo Apr 2018)
- [S0274] Calisto: [Calisto](https://attack.mitre.org/software/S0274) presents an input prompt asking for the user's login and password.(Citation: Symantec Calisto July 2018)
- [S0276] Keydnap: [Keydnap](https://attack.mitre.org/software/S0276) prompts the users for credentials.(Citation: synack 2016 review)
- [G1039] RedCurl: [RedCurl](https://attack.mitre.org/groups/G1039) prompts the user for credentials through a Microsoft Outlook pop-up.(Citation: group-ib_redcurl1)(Citation: group-ib_redcurl2)
- [S0482] Bundlore: [Bundlore](https://attack.mitre.org/software/S0482) prompts the user for their credentials.(Citation: MacKeeper Bundlore Apr 2019)
- [G0085] FIN4: [FIN4](https://attack.mitre.org/groups/G0085) has presented victims with spoofed Windows Authentication prompts to collect their credentials.(Citation: FireEye Hacking FIN4 Dec 2014)(Citation: FireEye Hacking FIN4 Video Dec 2014)
- [S0281] Dok: [Dok](https://attack.mitre.org/software/S0281) prompts the user for credentials.(Citation: objsee mac malware 2017)
- [S1122] Mispadu: [Mispadu](https://attack.mitre.org/software/S1122) can monitor browser activity for online banking actions and display full-screen overlay images to block user access to the intended site or present additional data fields.(Citation: Segurança Informática URSA Sophisticated Loader 2020)(Citation: SCILabs Malteiro 2021)
- [S0658] XCSSET: [XCSSET](https://attack.mitre.org/software/S0658) prompts the user to input credentials using a native macOS dialog box leveraging the system process <code>/Applications/Safari.app/Contents/MacOS/SafariForWebKitDevelopment</code>.(Citation: trendmicro xcsset xcode project 2020)
- [S0692] SILENTTRINITY: [SILENTTRINITY](https://attack.mitre.org/software/S0692)'s `credphisher.py` module can prompt a current user for their credentials.(Citation: GitHub SILENTTRINITY Modules July 2019)
- [S1153] Cuckoo Stealer: [Cuckoo Stealer](https://attack.mitre.org/software/S1153) has captured passwords by prompting victims with a “macOS needs to access System Settings” GUI window.(Citation: Kandji Cuckoo April 2024)

#### T1056.003 - Web Portal Capture

Description:

Adversaries may install code on externally facing portals, such as a VPN login page, to capture and transmit credentials of users who attempt to log into the service. For example, a compromised login page may log provided user credentials before logging the user in to the service.

This variation on input capture may be conducted post-compromise using legitimate administrative access as a backup measure to maintain network access through [External Remote Services](https://attack.mitre.org/techniques/T1133) and [Valid Accounts](https://attack.mitre.org/techniques/T1078) or as part of the initial compromise by exploitation of the externally facing web service.(Citation: Volexity Virtual Private Keylogging)

Procedures:

- [G1035] Winter Vivern: [Winter Vivern](https://attack.mitre.org/groups/G1035) registered and hosted domains to allow for creation of web pages mimicking legitimate government email logon sites to collect logon information.(Citation: SentinelOne WinterVivern 2023)
- [C0030] Triton Safety Instrumented System Attack: In the [Triton Safety Instrumented System Attack](https://attack.mitre.org/campaigns/C0030), [TEMP.Veles](https://attack.mitre.org/groups/G0088) captured credentials as they were being changed by redirecting text-based login codes to websites they controlled.(Citation: Triton-EENews-2017)
- [S1116] WARPWIRE: [WARPWIRE](https://attack.mitre.org/software/S1116) can capture credentials submitted during the web logon process in order to access layer seven applications such as RDP.(Citation: Mandiant Cutting Edge January 2024)
- [S1022] IceApple: The [IceApple](https://attack.mitre.org/software/S1022) OWA credential logger can monitor for OWA authentication requests and log the credentials.(Citation: CrowdStrike IceApple May 2022)
- [C0029] Cutting Edge: During [Cutting Edge](https://attack.mitre.org/campaigns/C0029), threat actors modified the JavaScript loaded by the Ivanti Connect Secure login page to capture credentials entered.(Citation: Volexity Ivanti Zero-Day Exploitation January 2024)

#### T1056.004 - Credential API Hooking

Description:

Adversaries may hook into Windows application programming interface (API) functions and Linux system functions to collect user credentials. Malicious hooking mechanisms may capture API or function calls that include parameters that reveal user authentication credentials.(Citation: Microsoft TrojanSpy:Win32/Ursnif.gen!I Sept 2017) Unlike [Keylogging](https://attack.mitre.org/techniques/T1056/001), this technique focuses specifically on API functions that include parameters that reveal user credentials. 

In Windows, hooking involves redirecting calls to these functions and can be implemented via:

* **Hooks procedures**, which intercept and execute designated code in response to events such as messages, keystrokes, and mouse inputs.(Citation: Microsoft Hook Overview)(Citation: Elastic Process Injection July 2017)
* **Import address table (IAT) hooking**, which use modifications to a process’s IAT, where pointers to imported API functions are stored.(Citation: Elastic Process Injection July 2017)(Citation: Adlice Software IAT Hooks Oct 2014)(Citation: MWRInfoSecurity Dynamic Hooking 2015)
* **Inline hooking**, which overwrites the first bytes in an API function to redirect code flow.(Citation: Elastic Process Injection July 2017)(Citation: HighTech Bridge Inline Hooking Sept 2011)(Citation: MWRInfoSecurity Dynamic Hooking 2015)

In Linux and macOS, adversaries may hook into system functions via the `LD_PRELOAD` (Linux) or `DYLD_INSERT_LIBRARIES` (macOS) environment variables, which enables loading shared libraries into a program’s address space. For example, an adversary may capture credentials by hooking into the `libc read` function leveraged by SSH or SCP.(Citation: Intezer Symbiote 2022)

Procedures:

- [S0330] Zeus Panda: [Zeus Panda](https://attack.mitre.org/software/S0330) hooks processes by leveraging its own IAT hooked functions.(Citation: GDATA Zeus Panda June 2017)
- [S1154] VersaMem: [VersaMem](https://attack.mitre.org/software/S1154) hooked and overrided Versa's built-in authentication method, `setUserPassword`, to intercept plaintext credentials when submitted to the server.(Citation: Lumen Versa 2024)
- [S0484] Carberp: [Carberp](https://attack.mitre.org/software/S0484) has hooked several Windows API functions to steal credentials.(Citation: Prevx Carberp March 2011)
- [S0182] FinFisher: [FinFisher](https://attack.mitre.org/software/S0182) hooks processes by modifying IAT pointers to CreateWindowEx.(Citation: FinFisher Citation)(Citation: Elastic Process Injection July 2017)
- [S0386] Ursnif: [Ursnif](https://attack.mitre.org/software/S0386) has hooked APIs to perform a wide variety of information theft, such as monitoring traffic from browsers.(Citation: TrendMicro Ursnif Mar 2015)
- [S0412] ZxShell: [ZxShell](https://attack.mitre.org/software/S0412) hooks several API functions to spawn system threads.(Citation: Talos ZxShell Oct 2014)
- [G0068] PLATINUM: [PLATINUM](https://attack.mitre.org/groups/G0068) is capable of using Windows hook interfaces for information gathering such as credential access.(Citation: Microsoft PLATINUM April 2016)
- [S0251] Zebrocy: [Zebrocy](https://attack.mitre.org/software/S0251) installs an application-defined Windows hook to get notified when a network drive has been attached, so it can then use the hook to call its RecordToFile file stealing method.(Citation: Securelist Sofacy Feb 2018)
- [S0416] RDFSNIFFER: [RDFSNIFFER](https://attack.mitre.org/software/S0416) hooks several Win32 API functions to hijack elements of the remote system management user-interface.(Citation: FireEye FIN7 Oct 2019)
- [S0363] Empire: [Empire](https://attack.mitre.org/software/S0363) contains some modules that leverage API hooking to carry out tasks, such as netripper.(Citation: Github PowerShell Empire)
- [S0266] TrickBot: [TrickBot](https://attack.mitre.org/software/S0266) has the ability to capture RDP credentials by capturing the <code>CredEnumerateA</code> API(Citation: TrendMicro Trickbot Feb 2019)
- [S0353] NOKKI: [NOKKI](https://attack.mitre.org/software/S0353) uses the Windows call SetWindowsHookEx and begins injecting it into every GUI process running on the victim's machine.(Citation: Unit 42 NOKKI Sept 2018)


### T1074 - Data Staged

Description:

Adversaries may stage collected data in a central location or directory prior to Exfiltration. Data may be kept in separate files or combined into one file through techniques such as [Archive Collected Data](https://attack.mitre.org/techniques/T1560). Interactive command shells may be used, and common functionality within [cmd](https://attack.mitre.org/software/S0106) and bash may be used to copy data into a staging location.(Citation: PWC Cloud Hopper April 2017)

In cloud environments, adversaries may stage data within a particular instance or virtual machine before exfiltration. An adversary may [Create Cloud Instance](https://attack.mitre.org/techniques/T1578/002) and stage data in that instance.(Citation: Mandiant M-Trends 2020)

Adversaries may choose to stage data from a victim network in a centralized location prior to Exfiltration to minimize the number of connections made to their C2 server and better evade detection.

Procedures:

- [G0102] Wizard Spider: [Wizard Spider](https://attack.mitre.org/groups/G0102) has collected and staged credentials and network enumeration information, using  the networkdll and psfin [TrickBot](https://attack.mitre.org/software/S0266) modules.(Citation: CrowdStrike Grim Spider May 2019)
- [G1017] Volt Typhoon: [Volt Typhoon](https://attack.mitre.org/groups/G1017) has staged collected data in password-protected archives.(Citation: Microsoft Volt Typhoon May 2023)
- [G1032] INC Ransom: [INC Ransom](https://attack.mitre.org/groups/G1032) has staged data on compromised hosts prior to exfiltration.(Citation: Huntress INC Ransom Group August 2023)(Citation: SOCRadar INC Ransom January 2024)
- [S0641] Kobalos: [Kobalos](https://attack.mitre.org/software/S0641) can write captured SSH connection credentials to a file under the <code>/var/run</code> directory with a <code>.pid</code> extension for exfiltration.(Citation: ESET Kobalos Jan 2021)
- [S1020] Kevin: [Kevin](https://attack.mitre.org/software/S1020) can create directories to store logs and other collected data.(Citation: Kaspersky Lyceum October 2021)
- [S1076] QUIETCANARY: [QUIETCANARY](https://attack.mitre.org/software/S1076) has the ability to stage data prior to exfiltration.(Citation: Mandiant Suspected Turla Campaign February 2023)
- [G1015] Scattered Spider: [Scattered Spider](https://attack.mitre.org/groups/G1015) stages data in a centralized database prior to exfiltration.(Citation: CISA Scattered Spider Advisory November 2023)
- [S1019] Shark: [Shark](https://attack.mitre.org/software/S1019) has stored information in folders named `U1` and `U2` prior to exfiltration.(Citation: ClearSky Siamesekitten August 2021)

#### T1074.001 - Local Data Staging

Description:

Adversaries may stage collected data in a central location or directory on the local system prior to Exfiltration. Data may be kept in separate files or combined into one file through techniques such as [Archive Collected Data](https://attack.mitre.org/techniques/T1560). Interactive command shells may be used, and common functionality within [cmd](https://attack.mitre.org/software/S0106) and bash may be used to copy data into a staging location.

Adversaries may also stage collected data in various available formats/locations of a system, including local storage databases/repositories or the Windows Registry.(Citation: Prevailion DarkWatchman 2021)

Procedures:

- [G1046] Storm-1811: [Storm-1811](https://attack.mitre.org/groups/G1046) has locally staged captured credentials for subsequent manual exfiltration.(Citation: rapid7-email-bombing)
- [S0264] OopsIE: [OopsIE](https://attack.mitre.org/software/S0264) stages the output from command execution and collected files in specific folders before exfiltration.(Citation: Unit 42 OopsIE! Feb 2018)
- [S1029] AuTo Stealer: [AuTo Stealer](https://attack.mitre.org/software/S1029) can store collected data from an infected host to a file named `Hostname_UserName.txt` prior to exfiltration.(Citation: MalwareBytes SideCopy Dec 2021)
- [S1149] CHIMNEYSWEEP: [CHIMNEYSWEEP](https://attack.mitre.org/software/S1149) can store captured screenshots to disk including to a covert store named `APPX.%x%x%x%x%x.tmp` where `%x` is a random value.(Citation: Mandiant ROADSWEEP August 2022)
- [C0049] Leviathan Australian Intrusions: [Leviathan](https://attack.mitre.org/groups/G0065) stored captured credential material on local log files on victim systems during [Leviathan Australian Intrusions](https://attack.mitre.org/campaigns/C0049).(Citation: CISA Leviathan 2024)
- [S1110] SLIGHTPULSE: [SLIGHTPULSE](https://attack.mitre.org/software/S1110) has piped the output from executed commands to `/tmp/1`.(Citation: Mandiant Pulse Secure Zero-Day April 2021)
- [S0567] Dtrack: [Dtrack](https://attack.mitre.org/software/S0567) can save collected data to disk, different file formats, and network shares.(Citation: Securelist Dtrack)(Citation: CyberBit Dtrack)
- [S1196] Troll Stealer: [Troll Stealer](https://attack.mitre.org/software/S1196) encrypts gathered information on victim devices prior to exfiltrating it through command and control infrastructure.(Citation: S2W Troll Stealer 2024)
- [S1015] Milan: [Milan](https://attack.mitre.org/software/S1015) has saved files prior to upload from a compromised host to folders beginning with the characters `a9850d2f`.(Citation: ClearSky Siamesekitten August 2021)
- [S0247] NavRAT: [NavRAT](https://attack.mitre.org/software/S0247) writes multiple outputs to a TMP file using the >> method.(Citation: Talos NavRAT May 2018)
- [G0027] Threat Group-3390: [Threat Group-3390](https://attack.mitre.org/groups/G0027) has locally staged encrypted archives for later exfiltration efforts.(Citation: SecureWorks BRONZE UNION June 2017)
- [G0121] Sidewinder: [Sidewinder](https://attack.mitre.org/groups/G0121) has collected stolen files in a temporary folder in preparation for exfiltration.(Citation: ATT Sidewinder January 2021)
- [S0386] Ursnif: [Ursnif](https://attack.mitre.org/software/S0386) has used tmp files to stage gathered information.(Citation: TrendMicro Ursnif Mar 2015)
- [S1044] FunnyDream: [FunnyDream](https://attack.mitre.org/software/S1044) can stage collected information including screen captures and logged keystrokes locally.(Citation: Bitdefender FunnyDream Campaign November 2020)
- [C0032] C0032: During the [C0032](https://attack.mitre.org/campaigns/C0032) campaign, [TEMP.Veles](https://attack.mitre.org/groups/G0088) used staging folders that are infrequently used by legitimate users or processes to store data for exfiltration and tool deployment.(Citation: FireEye TRITON 2019)
- [G0053] FIN5: [FIN5](https://attack.mitre.org/groups/G0053) scripts save memory dump data into a specific directory on hosts in the victim environment.(Citation: Mandiant FIN5 GrrCON Oct 2016)
- [S0024] Dyre: [Dyre](https://attack.mitre.org/software/S0024) has the ability to create files in a TEMP folder to act as a database to store information.(Citation: Malwarebytes Dyreza November 2015)
- [S0337] BadPatch: [BadPatch](https://attack.mitre.org/software/S0337) stores collected data in log files before exfiltration.(Citation: Unit 42 BadPatch Oct 2017)
- [S0673] DarkWatchman: [DarkWatchman](https://attack.mitre.org/software/S0673) can stage local data in the Windows Registry.(Citation: Prevailion DarkWatchman 2021)
- [C0006] Operation Honeybee: During [Operation Honeybee](https://attack.mitre.org/campaigns/C0006), stolen data was copied into a text file using the format `From <COMPUTER-NAME> (<Month>-<Day> <Hour>-<Minute>-<Second>).txt` prior to compression, encoding, and exfiltration.(Citation: McAfee Honeybee)
- [C0014] Operation Wocao: During [Operation Wocao](https://attack.mitre.org/campaigns/C0014), threat actors staged archived files in a temporary directory prior to exfiltration.(Citation: FoxIT Wocao December 2019)
- [G0040] Patchwork: [Patchwork](https://attack.mitre.org/groups/G0040) copied all targeted files to a directory called index that was eventually uploaded to the C&C server.(Citation: TrendMicro Patchwork Dec 2017)
- [S1059] metaMain: [metaMain](https://attack.mitre.org/software/S1059) has stored the collected system files in a working directory.(Citation: SentinelLabs Metador Sept 2022)(Citation: SentinelLabs Metador Technical Appendix Sept 2022)
- [S1060] Mafalda: [Mafalda](https://attack.mitre.org/software/S1060) can place retrieved files into a destination directory.(Citation: SentinelLabs Metador Sept 2022)
- [S1016] MacMa: [MacMa](https://attack.mitre.org/software/S1016) has stored collected files locally before exfiltration.(Citation: Objective-See MacMa Nov 2021)
- [S0335] Carbon: [Carbon](https://attack.mitre.org/software/S0335) creates a base directory that contains the files and folders that are collected.(Citation: ESET Carbon Mar 2017)
- [S0458] Ramsay: [Ramsay](https://attack.mitre.org/software/S0458) can stage data prior to exfiltration in <code>%APPDATA%\Microsoft\UserSetting</code> and <code>%APPDATA%\Microsoft\UserSetting\MediaCache</code>.(Citation: Eset Ramsay May 2020)(Citation: Antiy CERT Ramsay April 2020)
- [C0015] C0015: During [C0015](https://attack.mitre.org/campaigns/C0015), PowerView's file share enumeration results were stored in the file `c:\ProgramData\found_shares.txt`.(Citation: DFIR Conti Bazar Nov 2021)
- [G1023] APT5: [APT5](https://attack.mitre.org/groups/G1023) has staged data on compromised systems prior to exfiltration often in `C:\Users\Public`.(Citation: Mandiant Pulse Secure Update May 2021)
- [G0030] Lotus Blossom: [Lotus Blossom](https://attack.mitre.org/groups/G0030) has locally staged compressed and archived data for follow-on exfiltration.(Citation: Cisco LotusBlossom 2025)
- [G0139] TeamTNT: [TeamTNT](https://attack.mitre.org/groups/G0139) has aggregated collected credentials in text files before exfiltrating.(Citation: Cisco Talos Intelligence Group)
- [S1153] Cuckoo Stealer: [Cuckoo Stealer](https://attack.mitre.org/software/S1153) has staged collected application data from Safari, Notes, and Keychain to `/var/folder`.(Citation: Kandji Cuckoo April 2024)
- [S0260] InvisiMole: [InvisiMole](https://attack.mitre.org/software/S0260) determines a working directory where it stores all the gathered data about the compromised machine.(Citation: ESET InvisiMole June 2018)(Citation: ESET InvisiMole June 2020)
- [G0119] Indrik Spider: [Indrik Spider](https://attack.mitre.org/groups/G0119) has stored collected data in a .tmp file.(Citation: Symantec WastedLocker June 2020)
- [G1030] Agrius: [Agrius](https://attack.mitre.org/groups/G1030) has used the folder, <code>C:\\windows\\temp\\s\\</code>, to stage data for exfiltration.(Citation: Unit42 Agrius 2023)
- [S1042] SUGARDUMP: [SUGARDUMP](https://attack.mitre.org/software/S1042) has stored collected data under `%<malware_execution_folder>%\\CrashLog.txt`.(Citation: Mandiant UNC3890 Aug 2022)
- [S0045] ADVSTORESHELL: [ADVSTORESHELL](https://attack.mitre.org/software/S0045) stores output from command execution in a .dat file in the %TEMP% directory.(Citation: ESET Sednit Part 2)
- [G0032] Lazarus Group: [Lazarus Group](https://attack.mitre.org/groups/G0032) malware IndiaIndia saves information gathered about the victim to a file that is saved in the %TEMP% directory, then compressed, encrypted, and uploaded to a C2 server.(Citation: Novetta Blockbuster)(Citation: Novetta Blockbuster Loaders)
- [S0667] Chrommme: [Chrommme](https://attack.mitre.org/software/S0667) can store captured system information locally prior to exfiltration.(Citation: ESET Gelsemium June 2021)
- [S0038] Duqu: Modules can be pushed to and executed by [Duqu](https://attack.mitre.org/software/S0038) that copy data to a staging area, compress it, and XOR encrypt it.(Citation: Symantec W32.Duqu)
- [S0438] Attor: [Attor](https://attack.mitre.org/software/S0438) has staged collected data in a central upload directory prior to exfiltration.(Citation: ESET Attor Oct 2019)
- [G0114] Chimera: [Chimera](https://attack.mitre.org/groups/G0114) has staged stolen data locally on compromised hosts.(Citation: NCC Group Chimera January 2021)
- [S0629] RainyDay: [RainyDay](https://attack.mitre.org/software/S0629) can use a file exfiltration tool to copy files to <code>C:\ProgramData\Adobe\temp</code> prior to exfiltration.(Citation: Bitdefender Naikon April 2021)
- [G0069] MuddyWater: [MuddyWater](https://attack.mitre.org/groups/G0069) has stored a decoy PDF file within a victim's `%temp%` folder.(Citation: Talos MuddyWater Jan 2022)
- [C0017] C0017: During [C0017](https://attack.mitre.org/campaigns/C0017), [APT41](https://attack.mitre.org/groups/G0096) copied the local `SAM` and `SYSTEM` Registry hives to a staging directory.(Citation: Mandiant APT41)
- [S0249] Gold Dragon: [Gold Dragon](https://attack.mitre.org/software/S0249) stores information gathered from the endpoint in a file named 1.hwp.(Citation: McAfee Gold Dragon)
- [C0051] APT28 Nearest Neighbor Campaign: During [APT28 Nearest Neighbor Campaign](https://attack.mitre.org/campaigns/C0051), [APT28](https://attack.mitre.org/groups/G0007) staged captured credential information in the <code>C:\ProgramData</code> directory.(Citation: Nearest Neighbor Volexity)
- [S0409] Machete: [Machete](https://attack.mitre.org/software/S0409) stores files and logs in a folder on the local drive.(Citation: ESET Machete July 2019)(Citation: Cylance Machete Mar 2017)
- [S0094] Trojan.Karagany: [Trojan.Karagany](https://attack.mitre.org/software/S0094) can create directories to store plugin output and stage data for exfiltration.(Citation: Symantec Dragonfly)(Citation: Secureworks Karagany July 2019)
- [S0012] PoisonIvy: [PoisonIvy](https://attack.mitre.org/software/S0012) stages collected data in a text file.(Citation: Symantec Darkmoon Aug 2005)
- [S0062] DustySky: [DustySky](https://attack.mitre.org/software/S0062) created folders in temp directories to host collected files before exfiltration.(Citation: Kaspersky MoleRATs April 2019)
- [S1104] SLOWPULSE: [SLOWPULSE](https://attack.mitre.org/software/S1104) can write logged ACE credentials to `/home/perl/PAUS.pm` in append mode, using the format string `%s:%s\n`.(Citation: Mandiant Pulse Secure Zero-Day April 2021)
- [S0395] LightNeuron: [LightNeuron](https://attack.mitre.org/software/S0395) can store email data in files and directories specified in its configuration, such as <code>C:\Windows\ServiceProfiles\NetworkService\appdata\Local\Temp\</code>.(Citation: ESET LightNeuron May 2019)
- [S1012] PowerLess: [PowerLess](https://attack.mitre.org/software/S1012) can stage stolen browser data in `C:\\Windows\\Temp\\cup.tmp` and keylogger data in `C:\\Windows\\Temp\\Report.06E17A5A-7325-4325-8E5D-E172EBA7FC5BK`.(Citation: Cybereason PowerLess February 2022)
- [G0022] APT3: [APT3](https://attack.mitre.org/groups/G0022) has been known to stage files for exfiltration in a single location.(Citation: aptsim)
- [S1213] Lumma Stealer: [Lumma Stealer](https://attack.mitre.org/software/S1213) has configured a custom user data directory such as a folder within `%USERPROFILE%\AppData\Roaming` for staging data.(Citation: TrendMicro LummaStealer 2025)
- [S0650] QakBot: [QakBot](https://attack.mitre.org/software/S0650) has stored stolen emails and other data into new folders prior to exfiltration.(Citation: Kroll Qakbot June 2020)
- [S0503] FrameworkPOS: [FrameworkPOS](https://attack.mitre.org/software/S0503) can identifiy payment card track data on the victim and copy it to a local file in a subdirectory of C:\Windows\.(Citation: FireEye FIN6 April 2016)
- [S1101] LoFiSe: [LoFiSe](https://attack.mitre.org/software/S1101) can save files to be evaluated for further exfiltration in the `C:\Programdata\Microsoft\` and 	`C:\windows\temp\` folders.
 (Citation: Kaspersky ToddyCat Check Logs October 2023)
- [S1043] ccf32: [ccf32](https://attack.mitre.org/software/S1043) can temporarily store files in a hidden directory on the local host.(Citation: Bitdefender FunnyDream Campaign November 2020)
- [G0102] Wizard Spider: [Wizard Spider](https://attack.mitre.org/groups/G0102) has staged ZIP files in local directories such as, `C:\PerfLogs\1\` and `C:\User\1\` prior to exfiltration.(Citation: Mandiant FIN12 Oct 2021)
- [S0340] Octopus: [Octopus](https://attack.mitre.org/software/S0340) has stored collected information in the Application Data directory on a compromised host.(Citation: Securelist Octopus Oct 2018)(Citation: ESET Nomadic Octopus 2018)
- [S0196] PUNCHBUGGY: [PUNCHBUGGY](https://attack.mitre.org/software/S0196) has saved information to a random temp file before exfil.(Citation: Morphisec ShellTea June 2019)
- [C0040] APT41 DUST: [APT41 DUST](https://attack.mitre.org/campaigns/C0040) involved exporting data from Oracle databases to local CSV files prior to exfiltration.(Citation: Google Cloud APT41 2024)
- [C0044] Juicy Mix: During [Juicy Mix](https://attack.mitre.org/campaigns/C0044), [OilRig](https://attack.mitre.org/groups/G0049) used browser data and credential stealer tools to stage stolen files named Cupdate, Eupdate, and IUpdate in the %TEMP% directory.(Citation: ESET OilRig Campaigns Sep 2023)
- [S0149] MoonWind: [MoonWind](https://attack.mitre.org/software/S0149) saves information from its keylogging routine as a .zip file in the present working directory.(Citation: Palo Alto MoonWind March 2017)
- [S0170] Helminth: [Helminth](https://attack.mitre.org/software/S0170) creates folders to store output from batch scripts prior to sending the information to its C2 server.(Citation: Palo Alto OilRig May 2016)
- [S0090] Rover: [Rover](https://attack.mitre.org/software/S0090) copies files from removable drives to <code>C:\system</code>.(Citation: Palo Alto Rover)
- [S0035] SPACESHIP: [SPACESHIP](https://attack.mitre.org/software/S0035) identifies files with certain extensions and copies them to a directory in the user's profile.(Citation: FireEye APT30)
- [S0081] Elise: [Elise](https://attack.mitre.org/software/S0081) creates a file in <code>AppData\Local\Microsoft\Windows\Explorer</code> and stores all harvested data in that file.(Citation: Accenture Dragonfish Jan 2018)
- [S0615] SombRAT: [SombRAT](https://attack.mitre.org/software/S0615) can store harvested data in a custom database under the %TEMP% directory.(Citation: BlackBerry CostaRicto November 2020)
- [G0094] Kimsuky: [Kimsuky](https://attack.mitre.org/groups/G0094) has staged collected data files under <code>C:\Program Files\Common Files\System\Ole DB\</code>.(Citation: CISA AA20-301A Kimsuky)(Citation: Talos Kimsuky Nov 2021)
- [G0087] APT39: [APT39](https://attack.mitre.org/groups/G0087) has utilized tools to aggregate data prior to exfiltration.(Citation: FBI FLASH APT39 September 2020)
- [G0093] GALLIUM: [GALLIUM](https://attack.mitre.org/groups/G0093) compressed and staged files in multi-part archives in the Recycle Bin prior to exfiltration.(Citation: Cybereason Soft Cell June 2019)
- [S0443] MESSAGETAP: [MESSAGETAP](https://attack.mitre.org/software/S0443) stored targeted SMS messages that matched its target list in CSV files on the compromised system.(Citation: FireEye MESSAGETAP October 2019)
- [S0261] Catchamas: [Catchamas](https://attack.mitre.org/software/S0261) stores the gathered data from the machine in .db files and .bmp files under four separate locations.(Citation: Symantec Catchamas April 2018)
- [S0169] RawPOS: Data captured by [RawPOS](https://attack.mitre.org/software/S0169) is placed in a temporary file under a directory named "memdump".(Citation: Kroll RawPOS Jan 2017)
- [S0647] Turian: [Turian](https://attack.mitre.org/software/S0647) can store copied files in a specific directory prior to exfiltration.(Citation: ESET BackdoorDiplomacy Jun 2021)
- [S1168] SampleCheck5000: [SampleCheck5000](https://attack.mitre.org/software/S1168) can log the output from C2 commands in an encrypted and compressed format on disk prior to exfiltration.(Citation: ESET OilRig Downloaders DEC 2023)
- [G0065] Leviathan: [Leviathan](https://attack.mitre.org/groups/G0065) has used C:\Windows\Debug and C:\Perflogs as staging directories.(Citation: FireEye Periscope March 2018)(Citation: CISA AA21-200A APT40 July 2021)
- [S0644] ObliqueRAT: [ObliqueRAT](https://attack.mitre.org/software/S0644) can copy specific files, webcam captures, and screenshots to local directories.(Citation: Talos Oblique RAT March 2021)
- [G0045] menuPass: [menuPass](https://attack.mitre.org/groups/G0045) stages data prior to exfiltration in multi-part archives, often saved in the Recycle Bin.(Citation: PWC Cloud Hopper April 2017)
- [C0048] Operation MidnightEclipse: During [Operation MidnightEclipse](https://attack.mitre.org/campaigns/C0048), threat actors copied files to the web application folder on compromised devices for exfiltration.(Citation: Palo Alto MidnightEclipse APR 2024)
- [G0135] BackdoorDiplomacy: [BackdoorDiplomacy](https://attack.mitre.org/groups/G0135) has copied files of interest to the main drive's recycle bin.(Citation: ESET BackdoorDiplomacy Jun 2021)
- [S0251] Zebrocy: [Zebrocy](https://attack.mitre.org/software/S0251) stores all collected information in a single file before exfiltration.(Citation: ESET Zebrocy Nov 2018)
- [S1210] Sagerunex: [Sagerunex](https://attack.mitre.org/software/S1210) gathers host information and stages it locally as a RAR file prior to exfiltration.(Citation: Cisco LotusBlossom 2025) [Sagerunex](https://attack.mitre.org/software/S1210) stores logged data in an encrypted file located at `%TEMP%/TS_FB56.tmp` during execution.(Citation: Symantec Bilbug 2022)
- [S0353] NOKKI: [NOKKI](https://attack.mitre.org/software/S0353) can collect data from the victim and stage it in <code>LOCALAPPDATA%\MicroSoft Updatea\uplog.tmp</code>.(Citation: Unit 42 NOKKI Sept 2018)
- [S0652] MarkiRAT: [MarkiRAT](https://attack.mitre.org/software/S0652) can store collected data locally in a created .nfo file.(Citation: Kaspersky Ferocious Kitten Jun 2021)
- [G0129] Mustang Panda: [Mustang Panda](https://attack.mitre.org/groups/G0129) has stored collected credential files in <code>c:\windows\temp</code> prior to exfiltration. [Mustang Panda](https://attack.mitre.org/groups/G0129) has also stored documents for exfiltration in a hidden folder on USB drives.(Citation: Secureworks BRONZE PRESIDENT December 2019)(Citation: Avira Mustang Panda January 2020)
- [S0147] Pteranodon: [Pteranodon](https://attack.mitre.org/software/S0147) creates various subdirectories under <code>%Temp%\reports\%</code> and copies files to those subdirectories. It also creates a folder at <code>C:\Users\<Username>\AppData\Roaming\Microsoft\store</code> to store screenshot JPEG files.(Citation: Palo Alto Gamaredon Feb 2017)
- [S0343] Exaramel for Windows: [Exaramel for Windows](https://attack.mitre.org/software/S0343) specifies a path to store files scheduled for exfiltration.(Citation: ESET TeleBots Oct 2018)
- [S0622] AppleSeed: [AppleSeed](https://attack.mitre.org/software/S0622) can stage files in a central location prior to exfiltration.(Citation: Malwarebytes Kimsuky June 2021)
- [S1090] NightClub: [NightClub](https://attack.mitre.org/software/S1090) has copied captured files and keystrokes to the `%TEMP%` directory of compromised hosts.(Citation: MoustachedBouncer ESET August 2023)
- [S1172] OilBooster: [OilBooster](https://attack.mitre.org/software/S1172) can stage files in the `tempFiles` directory for exfiltration.(Citation: ESET OilRig Downloaders DEC 2023)
- [S0128] BADNEWS: [BADNEWS](https://attack.mitre.org/software/S0128) copies documents under 15MB found on the victim system to is the user's <code>%temp%\SMB\</code> folder. It also copies files from USB devices to a predefined directory.(Citation: Forcepoint Monsoon)(Citation: TrendMicro Patchwork Dec 2017)
- [S0274] Calisto: [Calisto](https://attack.mitre.org/software/S0274) uses a hidden directory named .calisto to store data from the victim’s machine before exfiltration.(Citation: Securelist Calisto July 2018)(Citation: Symantec Calisto July 2018)
- [S0526] KGH_SPY: [KGH_SPY](https://attack.mitre.org/software/S0526) can save collected system information to a file named "info" before exfiltration.(Citation: Cybereason Kimsuky November 2020)
- [S0538] Crutch: [Crutch](https://attack.mitre.org/software/S0538) has staged stolen files in the <code>C:\AMD\Temp</code> directory.(Citation: ESET Crutch December 2020)
- [S0113] Prikormka: [Prikormka](https://attack.mitre.org/software/S0113) creates a directory, <code>%USERPROFILE%\AppData\Local\SKC\</code>, which is used to store collected log files.(Citation: ESET Operation Groundbait)
- [S0265] Kazuar: [Kazuar](https://attack.mitre.org/software/S0265) stages command output and collected data in files before exfiltration.(Citation: Unit 42 Kazuar May 2017)
- [S0084] Mis-Type: [Mis-Type](https://attack.mitre.org/software/S0084) has temporarily stored collected information to the files `“%AppData%\{Unique Identifier}\HOSTRURKLSR”` and `“%AppData%\{Unique Identifier}\NEWERSSEMP”`.(Citation: Cylance Dust Storm)
- [S1124] SocGholish: [SocGholish](https://attack.mitre.org/software/S1124) can send output from `whoami` to a local temp file using the naming convention `rad<5-hex-chars>.tmp`.(Citation: Red Canary SocGholish March 2024)
- [G0035] Dragonfly: [Dragonfly](https://attack.mitre.org/groups/G0035) has created a directory named "out" in the user's %AppData% folder and copied files to it.(Citation: US-CERT TA18-074A)
- [S0651] BoxCaon: [BoxCaon](https://attack.mitre.org/software/S0651) has created a working folder for collected files that it sends to the C2 server.(Citation: Checkpoint IndigoZebra July 2021)
- [S0198] NETWIRE: [NETWIRE](https://attack.mitre.org/software/S0198) has the ability to write collected data to a file created in the <code>./LOGS</code> directory.(Citation: FireEye NETWIRE March 2019)
- [S0036] FLASHFLOOD: [FLASHFLOOD](https://attack.mitre.org/software/S0036) stages data it copies from the local system or removable drives in the "%WINDIR%\$NtUninstallKB885884$\" directory.(Citation: FireEye APT30)
- [S1154] VersaMem: [VersaMem](https://attack.mitre.org/software/S1154) staged captured credentials locally at `/tmp/.temp.data`.(Citation: Lumen Versa 2024)
- [G1016] FIN13: [FIN13](https://attack.mitre.org/groups/G1016) has utilized the following temporary folders on compromised Windows and Linux systems for their operations prior to exfiltration: `C:\Windows\Temp` and `/tmp`.(Citation: Mandiant FIN13 Aug 2022)(Citation: Sygnia Elephant Beetle Jan 2022)
- [G0007] APT28: [APT28](https://attack.mitre.org/groups/G0007) has stored captured credential information in a file named pi.log.(Citation: Microsoft SIR Vol 19)
- [S1075] KOPILUWAK: [KOPILUWAK](https://attack.mitre.org/software/S1075) has piped the results from executed C2 commands to `%TEMP%\result2.dat` on the local machine.(Citation: Mandiant Suspected Turla Campaign February 2023)
- [S0373] Astaroth: [Astaroth](https://attack.mitre.org/software/S0373) collects data in a plaintext file named r1.log before exfiltration. (Citation: Cofense Astaroth Sept 2018)
- [S1037] STARWHALE: [STARWHALE](https://attack.mitre.org/software/S1037) has stored collected data in a file called `stari.txt`.(Citation: Mandiant UNC3313 Feb 2022)
- [S0197] PUNCHTRACK: [PUNCHTRACK](https://attack.mitre.org/software/S0197) aggregates collected data in a tmp file.(Citation: FireEye Know Your Enemy FIN8 Aug 2016)
- [S0593] ECCENTRICBANDWAGON: [ECCENTRICBANDWAGON](https://attack.mitre.org/software/S0593) has stored keystrokes and screenshots within the <code>%temp%\GoogleChrome</code>, <code>%temp%\Downloads</code>, and <code>%temp%\TrendMicroUpdate</code> directories.(Citation: CISA EB Aug 2020)
- [G1017] Volt Typhoon: [Volt Typhoon](https://attack.mitre.org/groups/G1017) has saved stolen files including the `ntds.dit` database and the `SYSTEM` and `SECURITY` Registry hives locally to the `C:\Windows\Temp\` directory.(Citation: Joint Cybersecurity Advisory Volt Typhoon June 2023)(Citation: Secureworks BRONZE SILHOUETTE May 2023)
- [S1109] PACEMAKER: [PACEMAKER](https://attack.mitre.org/software/S1109) has written extracted data to `tmp/dsserver-check.statementcounters`.(Citation: Mandiant Pulse Secure Zero-Day April 2021)
- [S1142] LunarMail: [LunarMail](https://attack.mitre.org/software/S1142) can create a directory in `%TEMP%\` to stage data prior to exfilration.(Citation: ESET Turla Lunar toolset May 2024)
- [S0136] USBStealer: [USBStealer](https://attack.mitre.org/software/S0136) collects files matching certain criteria from the victim and stores them in a local directory for later exfiltration.(Citation: ESET Sednit USBStealer 2014)(Citation: Kaspersky Sofacy)

#### T1074.002 - Remote Data Staging

Description:

Adversaries may stage data collected from multiple systems in a central location or directory on one system prior to Exfiltration. Data may be kept in separate files or combined into one file through techniques such as [Archive Collected Data](https://attack.mitre.org/techniques/T1560). Interactive command shells may be used, and common functionality within [cmd](https://attack.mitre.org/software/S0106) and bash may be used to copy data into a staging location.

In cloud environments, adversaries may stage data within a particular instance or virtual machine before exfiltration. An adversary may [Create Cloud Instance](https://attack.mitre.org/techniques/T1578/002) and stage data in that instance.(Citation: Mandiant M-Trends 2020)

By staging data on one system prior to Exfiltration, adversaries can minimize the number of connections made to their C2 server and better evade detection.

Procedures:

- [G0114] Chimera: [Chimera](https://attack.mitre.org/groups/G0114) has staged stolen data on designated servers in the target environment.(Citation: NCC Group Chimera January 2021)
- [G1041] Sea Turtle: [Sea Turtle](https://attack.mitre.org/groups/G1041) staged collected email archives in the public web directory of a website that was accessible from the internet.(Citation: Hunt Sea Turtle 2024)
- [S1043] ccf32: [ccf32](https://attack.mitre.org/software/S1043) has copied files to a remote machine infected with [Chinoxy](https://attack.mitre.org/software/S1041) or another backdoor.(Citation: Bitdefender FunnyDream Campaign November 2020)
- [C0024] SolarWinds Compromise: During the [SolarWinds Compromise](https://attack.mitre.org/campaigns/C0024), [APT29](https://attack.mitre.org/groups/G0016) staged data and files in password-protected archives on a victim's OWA server.(Citation: Volexity SolarWinds)
- [G0045] menuPass: [menuPass](https://attack.mitre.org/groups/G0045) has staged data on remote MSP systems or other victim networks prior to exfiltration.(Citation: PWC Cloud Hopper April 2017)(Citation: Symantec Cicada November 2020)
- [G0061] FIN8: [FIN8](https://attack.mitre.org/groups/G0061) aggregates staged data from a network into a single location.(Citation: FireEye Know Your Enemy FIN8 Aug 2016)
- [G0065] Leviathan: [Leviathan](https://attack.mitre.org/groups/G0065) has staged data remotely prior to exfiltration.(Citation: CISA AA21-200A APT40 July 2021)
- [G0007] APT28: [APT28](https://attack.mitre.org/groups/G0007) has staged archives of collected data on a target's Outlook Web Access (OWA) server.(Citation: Cybersecurity Advisory GRU Brute Force Campaign July 2021)
- [G1019] MoustachedBouncer: [MoustachedBouncer](https://attack.mitre.org/groups/G1019) has used plugins to save captured screenshots to `.\AActdata\` on an SMB share.(Citation: MoustachedBouncer ESET August 2023)
- [G1022] ToddyCat: [ToddyCat](https://attack.mitre.org/groups/G1022) manually transferred collected files to an exfiltration host using xcopy.(Citation: Kaspersky ToddyCat Check Logs October 2023)
- [G0037] FIN6: [FIN6](https://attack.mitre.org/groups/G0037) actors have compressed data from remote systems and moved it to another staging system before exfiltration.(Citation: FireEye FIN6 April 2016)
- [C0002] Night Dragon: During [Night Dragon](https://attack.mitre.org/campaigns/C0002), threat actors copied files to company web servers and subsequently downloaded them.(Citation: McAfee Night Dragon)
- [G0027] Threat Group-3390: [Threat Group-3390](https://attack.mitre.org/groups/G0027) has moved staged encrypted archives to Internet-facing servers that had previously been compromised with [China Chopper](https://attack.mitre.org/software/S0020) prior to exfiltration.(Citation: SecureWorks BRONZE UNION June 2017)


### T1113 - Screen Capture

Description:

Adversaries may attempt to take screen captures of the desktop to gather information over the course of an operation. Screen capturing functionality may be included as a feature of a remote access tool used in post-compromise operations. Taking a screenshot is also typically possible through native utilities or API calls, such as <code>CopyFromScreen</code>, <code>xwd</code>, or <code>screencapture</code>.(Citation: CopyFromScreen .NET)(Citation: Antiquated Mac Malware)

Procedures:

- [S0147] Pteranodon: [Pteranodon](https://attack.mitre.org/software/S0147) can capture screenshots at a configurable interval.(Citation: Palo Alto Gamaredon Feb 2017)(Citation: Unit 42 Gamaredon February 2022)
- [S0417] GRIFFON: [GRIFFON](https://attack.mitre.org/software/S0417) has used a screenshot module that can be used to take a screenshot of the remote system.(Citation: SecureList Griffon May 2019)
- [S0044] JHUHUGIT: A [JHUHUGIT](https://attack.mitre.org/software/S0044) variant takes screenshots by simulating the user pressing the "Take Screenshot" key (VK_SCREENSHOT), accessing the screenshot saved in the clipboard, and converting it to a JPG image.(Citation: Unit 42 Playbook Dec 2017)(Citation: Talos Seduploader Oct 2017)
- [S0331] Agent Tesla: [Agent Tesla](https://attack.mitre.org/software/S0331) can capture screenshots of the victim’s desktop.(Citation: Talos Agent Tesla Oct 2018)(Citation: DigiTrust Agent Tesla Jan 2017)(Citation: Fortinet Agent Tesla April 2018)(Citation: Fortinet Agent Tesla June 2017)(Citation: Bitdefender Agent Tesla April 2020)
- [G0035] Dragonfly: [Dragonfly](https://attack.mitre.org/groups/G0035) has performed screen captures of victims, including by using a tool, scr.exe (which matched the hash of ScreenUtil).(Citation: US-CERT TA18-074A)(Citation: Symantec Dragonfly Sept 2017)(Citation: Gigamon Berserk Bear October 2021)
- [S0192] Pupy: [Pupy](https://attack.mitre.org/software/S0192) can drop a mouse-logger that will take small screenshots around at each click and then send back to the server.(Citation: GitHub Pupy)
- [S0199] TURNEDUP: [TURNEDUP](https://attack.mitre.org/software/S0199) is capable of taking screenshots.(Citation: FireEye APT33 Sept 2017)
- [S0094] Trojan.Karagany: [Trojan.Karagany](https://attack.mitre.org/software/S0094) can take a desktop screenshot and save the file into <code>\ProgramData\Mail\MailAg\shot.png</code>.(Citation: Symantec Dragonfly)(Citation: Secureworks Karagany July 2019)
- [S0182] FinFisher: [FinFisher](https://attack.mitre.org/software/S0182) takes a screenshot of the screen and displays it on top of all other windows for few seconds in an apparent attempt to hide some messages showed by the system during the setup process.(Citation: FinFisher Citation)(Citation: Microsoft FinFisher March 2018)
- [S1207] XLoader: [XLoader](https://attack.mitre.org/software/S1207) can capture screenshots on compromised hosts.(Citation: Google XLoader 2017)(Citation: Netskope XLoader 2022)
- [S0338] Cobian RAT: [Cobian RAT](https://attack.mitre.org/software/S0338) has a feature to perform screen capture.(Citation: Zscaler Cobian Aug 2017)
- [S0128] BADNEWS: [BADNEWS](https://attack.mitre.org/software/S0128) has a command to take a screenshot and send it to the C2 server.(Citation: Forcepoint Monsoon)(Citation: PaloAlto Patchwork Mar 2018)
- [S0458] Ramsay: [Ramsay](https://attack.mitre.org/software/S0458) can take screenshots every 30 seconds as well as when an external removable storage device is connected.(Citation: Antiy CERT Ramsay April 2020)
- [S0089] BlackEnergy: [BlackEnergy](https://attack.mitre.org/software/S0089) is capable of taking screenshots.(Citation: Securelist BlackEnergy Nov 2014)
- [S1196] Troll Stealer: [Troll Stealer](https://attack.mitre.org/software/S1196) can capture screenshots from victim machines.(Citation: S2W Troll Stealer 2024)(Citation: Symantec Troll Stealer 2024)
- [S0030] Carbanak: [Carbanak](https://attack.mitre.org/software/S0030) performs desktop video recording and captures screenshots of the desktop and sends it to the C2 server.(Citation: FireEye CARBANAK June 2017)
- [S0644] ObliqueRAT: [ObliqueRAT](https://attack.mitre.org/software/S0644) can capture a screenshot of the current screen.(Citation: Talos Oblique RAT March 2021)
- [S0660] Clambling: [Clambling](https://attack.mitre.org/software/S0660) has the ability to capture screenshots.(Citation: Trend Micro DRBControl February 2020)
- [S1213] Lumma Stealer: [Lumma Stealer](https://attack.mitre.org/software/S1213) has taken screenshots of victim machines.(Citation: Cybereason LumaStealer Undated)
- [S1050] PcShare: [PcShare](https://attack.mitre.org/software/S1050) can take screen shots of a compromised machine.(Citation: Bitdefender FunnyDream Campaign November 2020)
- [S0363] Empire: [Empire](https://attack.mitre.org/software/S0363) is capable of capturing screenshots on Windows and macOS systems.(Citation: Github PowerShell Empire)
- [S1122] Mispadu: [Mispadu](https://attack.mitre.org/software/S1122) has the ability to capture screenshots on compromised hosts.(Citation: SCILabs Malteiro 2021)(Citation: SCILabs URSA/Mispadu Evolution 2023)(Citation: ESET Security Mispadu Facebook Ads 2019)(Citation: Metabase Q Mispadu Trojan 2023)
- [S0235] CrossRAT: [CrossRAT](https://attack.mitre.org/software/S0235) is capable of taking screen captures.(Citation: Lookout Dark Caracal Jan 2018)
- [S0113] Prikormka: [Prikormka](https://attack.mitre.org/software/S0113) contains a module that captures screenshots of the victim's desktop.(Citation: ESET Operation Groundbait)
- [G0060] BRONZE BUTLER: [BRONZE BUTLER](https://attack.mitre.org/groups/G0060) has used a tool to capture screenshots.(Citation: Secureworks BRONZE BUTLER Oct 2017)(Citation: Trend Micro Tick November 2019)
- [S0017] BISCUIT: [BISCUIT](https://attack.mitre.org/software/S0017) has a command to periodically take screenshots of the system.(Citation: Mandiant APT1 Appendix)
- [S1016] MacMa: [MacMa](https://attack.mitre.org/software/S1016) has used Apple’s Core Graphic APIs, such as `CGWindowListCreateImageFromArray`, to capture the user's screen and open windows.(Citation: ESET DazzleSpy Jan 2022)(Citation: Objective-See MacMa Nov 2021)
- [S1081] BADHATCH: [BADHATCH](https://attack.mitre.org/software/S1081) can take screenshots and send them to an actor-controlled C2 server.(Citation: BitDefender BADHATCH Mar 2021)
- [S1185] LightSpy: [LightSpy](https://attack.mitre.org/software/S1185) uses Apple's built-in AVFoundation Framework library to access the user's camera and screen. It uses the `AVCaptureStillImage` to take a picture using the user's camera and the `AVCaptureScreen` to take a screenshot or record the user's screen for a specified period of time.(Citation: Huntress LightSpy macOS 2024)
- [S0385] njRAT: [njRAT](https://attack.mitre.org/software/S0385) can capture screenshots of the victim’s machines.(Citation: Trend Micro njRAT 2018)
- [S0647] Turian: [Turian](https://attack.mitre.org/software/S0647) has the ability to take screenshots.(Citation: ESET BackdoorDiplomacy Jun 2021)
- [G0047] Gamaredon Group: [Gamaredon Group](https://attack.mitre.org/groups/G0047)'s malware can take screenshots of the compromised computer every minute.(Citation: ESET Gamaredon June 2020)
- [S0351] Cannon: [Cannon](https://attack.mitre.org/software/S0351) can take a screenshot of the desktop.(Citation: Unit42 Cannon Nov 2018)
- [S0251] Zebrocy: A variant of [Zebrocy](https://attack.mitre.org/software/S0251) captures screenshots of the victim’s machine in JPEG and BMP format.(Citation: Unit42 Cannon Nov 2018)(Citation: ESET Zebrocy Nov 2018)(Citation: Unit42 Sofacy Dec 2018)(Citation: ESET Zebrocy May 2019)(Citation: Accenture SNAKEMACKEREL Nov 2018)(Citation: CISA Zebrocy Oct 2020)
- [S0467] TajMahal: [TajMahal](https://attack.mitre.org/software/S0467) has the ability to take screenshots on an infected host including capturing content from windows of instant messaging applications.(Citation: Kaspersky TajMahal April 2019)
- [S0154] Cobalt Strike: [Cobalt Strike](https://attack.mitre.org/software/S0154)'s Beacon payload is capable of capturing screenshots.(Citation: cobaltstrike manual)(Citation: Amnesty Intl. Ocean Lotus February 2021)(Citation: Cobalt Strike Manual 4.3 November 2020)
- [S0546] SharpStage: [SharpStage](https://attack.mitre.org/software/S0546) has the ability to capture the victim's screen.(Citation: Cybereason Molerats Dec 2020)(Citation: BleepingComputer Molerats Dec 2020)
- [S0260] InvisiMole: [InvisiMole](https://attack.mitre.org/software/S0260) can capture screenshots of not only the entire screen, but of each separate window open, in case they are overlapping.(Citation: ESET InvisiMole June 2018)(Citation: ESET InvisiMole June 2020)
- [G0049] OilRig: [OilRig](https://attack.mitre.org/groups/G0049) has a tool called CANDYKING to capture a screenshot of user's desktop.(Citation: FireEye APT34 Webinar Dec 2017)
- [G0007] APT28: [APT28](https://attack.mitre.org/groups/G0007) has used tools to take screenshots from victims.(Citation: ESET Sednit Part 2)(Citation: XAgentOSX 2017)(Citation: DOJ GRU Indictment Jul 2018)(Citation: Secureworks IRON TWILIGHT Active Measures March 2017)
- [S0153] RedLeaves: [RedLeaves](https://attack.mitre.org/software/S0153) can capture screenshots.(Citation: FireEye APT10 April 2017)(Citation: Accenture Hogfish April 2018)
- [S0692] SILENTTRINITY: [SILENTTRINITY](https://attack.mitre.org/software/S0692) can take a screenshot of the current desktop.(Citation: GitHub SILENTTRINITY Modules July 2019)
- [S0495] RDAT: [RDAT](https://attack.mitre.org/software/S0495) can take a screenshot on the infected system.(Citation: Unit42 RDAT July 2020)
- [S0330] Zeus Panda: [Zeus Panda](https://attack.mitre.org/software/S0330) can take screenshots of the victim’s machine.(Citation: GDATA Zeus Panda June 2017)
- [S0412] ZxShell: [ZxShell](https://attack.mitre.org/software/S0412) can capture screenshots.(Citation: FireEye APT41 Aug 2019)
- [G1019] MoustachedBouncer: [MoustachedBouncer](https://attack.mitre.org/groups/G1019) has used plugins to take screenshots on targeted systems.(Citation: MoustachedBouncer ESET August 2023)
- [S0216] POORAIM: [POORAIM](https://attack.mitre.org/software/S0216) can perform screen capturing.(Citation: FireEye APT37 Feb 2018)
- [S0662] RCSession: [RCSession](https://attack.mitre.org/software/S0662) can capture screenshots from a compromised host.(Citation: Profero APT27 December 2020)
- [S0275] UPPERCUT: [UPPERCUT](https://attack.mitre.org/software/S0275) can capture desktop screenshots in the PNG format and send them to the C2 server.(Citation: FireEye APT10 Sept 2018)
- [S1063] Brute Ratel C4: [Brute Ratel C4](https://attack.mitre.org/software/S1063) can take screenshots on compromised hosts.(Citation: Palo Alto Brute Ratel July 2022)
- [G0115] GOLD SOUTHFIELD: [GOLD SOUTHFIELD](https://attack.mitre.org/groups/G0115) has used the remote monitoring and management tool ConnectWise to obtain screen captures from victim's machines.(Citation: Tetra Defense Sodinokibi March 2020)
- [S0680] LitePower: [LitePower](https://attack.mitre.org/software/S0680) can take system screenshots and save them to `%AppData%`.(Citation: Kaspersky WIRTE November 2021)
- [S0337] BadPatch: [BadPatch](https://attack.mitre.org/software/S0337) captures screenshots in .jpg format and then exfiltrates them.(Citation: Unit 42 BadPatch Oct 2017)
- [S0456] Aria-body: [Aria-body](https://attack.mitre.org/software/S0456) has the ability to capture screenshots on compromised hosts.(Citation: CheckPoint Naikon May 2020)
- [S1153] Cuckoo Stealer: [Cuckoo Stealer](https://attack.mitre.org/software/S1153) can run `screencapture` to collect screenshots from compromised hosts. (Citation: Kandji Cuckoo April 2024)
- [S0476] Valak: [Valak](https://attack.mitre.org/software/S0476) has the ability to take screenshots on a compromised host.(Citation: Cybereason Valak May 2020)
- [G1044] APT42: [APT42](https://attack.mitre.org/groups/G1044) has used malware, such as GHAMBAR and POWERPOST, to take screenshots.(Citation: Mandiant APT42-charms)
- [S1159] DUSTTRAP: [DUSTTRAP](https://attack.mitre.org/software/S1159) can capture screenshots.(Citation: Google Cloud APT41 2024)
- [S0090] Rover: [Rover](https://attack.mitre.org/software/S0090) takes screenshots of the compromised system's desktop and saves them to <code>C:\system\screenshot.bmp</code> for exfiltration every 60 minutes.(Citation: Palo Alto Rover)
- [S0681] Lizar: [Lizar](https://attack.mitre.org/software/S0681) can take JPEG screenshots of an infected system.(Citation: Threatpost Lizar May 2021)(Citation: BiZone Lizar May 2021)
- [G0059] Magic Hound: [Magic Hound](https://attack.mitre.org/groups/G0059) malware can take a screenshot and upload the file to its C2 server.(Citation: Unit 42 Magic Hound Feb 2017)
- [S1209] Quick Assist: [Quick Assist](https://attack.mitre.org/software/S1209) allows for the remote administrator to take screenshots of the running system.(Citation: Microsoft Quick Assist 2024)
- [S0643] Peppy: [Peppy](https://attack.mitre.org/software/S0643) can take screenshots on targeted systems.(Citation: Proofpoint Operation Transparent Tribe March 2016)
- [S0187] Daserf: [Daserf](https://attack.mitre.org/software/S0187) can take screenshots.(Citation: Trend Micro Daserf Nov 2017)(Citation: Secureworks BRONZE BUTLER Oct 2017)
- [S0004] TinyZBot: [TinyZBot](https://attack.mitre.org/software/S0004) contains screen capture functionality.(Citation: Cylance Cleaver)
- [G0069] MuddyWater: [MuddyWater](https://attack.mitre.org/groups/G0069) has used malware that can capture screenshots of the victim’s machine.(Citation: Securelist MuddyWater Oct 2018)
- [S0115] Crimson: [Crimson](https://attack.mitre.org/software/S0115) contains a command to perform screen captures.(Citation: Proofpoint Operation Transparent Tribe March 2016)(Citation: Kaspersky Transparent Tribe August 2020)(Citation: Cisco Talos Transparent Tribe Education Campaign July 2022)
- [G1035] Winter Vivern: [Winter Vivern](https://attack.mitre.org/groups/G1035) delivered PowerShell scripts capable of taking screenshots of victim machines.(Citation: CERT-UA WinterVivern 2023)
- [S0023] CHOPSTICK: [CHOPSTICK](https://attack.mitre.org/software/S0023) has the capability to capture screenshots.(Citation: DOJ GRU Indictment Jul 2018)
- [S0086] ZLib: [ZLib](https://attack.mitre.org/software/S0086) has the ability to obtain screenshots of the compromised system.(Citation: Cylance Dust Storm)
- [S0050] CosmicDuke: [CosmicDuke](https://attack.mitre.org/software/S0050) takes periodic screenshots and exfiltrates them.(Citation: F-Secure Cosmicduke)
- [S0438] Attor: [Attor](https://attack.mitre.org/software/S0438)'s has a plugin that captures screenshots of the target applications.(Citation: ESET Attor Oct 2019)
- [G0091] Silence: [Silence](https://attack.mitre.org/groups/G0091) can capture victim screen activity.(Citation: SecureList Silence Nov 2017)(Citation: Group IB Silence Sept 2018)
- [S1059] metaMain: [metaMain](https://attack.mitre.org/software/S1059) can take and save screenshots.(Citation: SentinelLabs Metador Sept 2022)(Citation: SentinelLabs Metador Technical Appendix Sept 2022)
- [G1017] Volt Typhoon: [Volt Typhoon](https://attack.mitre.org/groups/G1017) has obtained a screenshot of the victim's system using the gdi32.dll and gdiplus.dll libraries.(Citation: CISA AA24-038A PRC Critical Infrastructure February 2024)
- [S1064] SVCReady: [SVCReady](https://attack.mitre.org/software/S1064) can take a screenshot from an infected host.(Citation: HP SVCReady Jun 2022)
- [S0194] PowerSploit: [PowerSploit](https://attack.mitre.org/software/S0194)'s <code>Get-TimedScreenshot</code> Exfiltration module can take screenshots at regular intervals.(Citation: GitHub PowerSploit May 2012)(Citation: PowerSploit Documentation)
- [S0143] Flame: [Flame](https://attack.mitre.org/software/S0143) can take regular screenshots when certain applications are open that are sent to the command and control server.(Citation: Kaspersky Flame)
- [S1034] StrifeWater: [StrifeWater](https://attack.mitre.org/software/S1034) has the ability to take screen captures.(Citation: Cybereason StrifeWater Feb 2022)
- [S0257] VERMIN: [VERMIN](https://attack.mitre.org/software/S0257) can perform screen captures of the victim’s machine.(Citation: Unit 42 VERMIN Jan 2018)
- [S1156] Manjusaka: [Manjusaka](https://attack.mitre.org/software/S1156) can take screenshots of the victim desktop.(Citation: Talos Manjusaka 2022)
- [S0386] Ursnif: [Ursnif](https://attack.mitre.org/software/S0386) has used hooked APIs to take screenshots.(Citation: TrendMicro Ursnif Mar 2015)(Citation: TrendMicro BKDR_URSNIF.SM)
- [S1065] Woody RAT: [Woody RAT](https://attack.mitre.org/software/S1065) has the ability to take a screenshot of the infected host desktop using Windows GDI+.(Citation: MalwareBytes WoodyRAT Aug 2022)
- [S0582] LookBack: [LookBack](https://attack.mitre.org/software/S0582) can take desktop screenshots.(Citation: Proofpoint LookBack Malware Aug 2019)
- [S0593] ECCENTRICBANDWAGON: [ECCENTRICBANDWAGON](https://attack.mitre.org/software/S0593) can capture screenshots and store them locally.(Citation: CISA EB Aug 2020)
- [S1060] Mafalda: [Mafalda](https://attack.mitre.org/software/S1060) can take a screenshot of the target machine and save it to a file.(Citation: SentinelLabs Metador Sept 2022)
- [S0437] Kivars: [Kivars](https://attack.mitre.org/software/S0437) has the ability to capture screenshots on the infected host.(Citation: TrendMicro BlackTech June 2017)
- [S0633] Sliver: [Sliver](https://attack.mitre.org/software/S0633) can take screenshots of the victim’s active display.(Citation: GitHub Sliver Screen)
- [S0213] DOGCALL: [DOGCALL](https://attack.mitre.org/software/S0213) is capable of capturing screenshots of the victim's machine.(Citation: FireEye APT37 Feb 2018)(Citation: Unit 42 Nokki Oct 2018)
- [G0043] Group5: Malware used by [Group5](https://attack.mitre.org/groups/G0043) is capable of watching the victim's screen.(Citation: Citizen Lab Group5)
- [S0663] SysUpdate: [SysUpdate](https://attack.mitre.org/software/S0663) has the ability to capture screenshots.(Citation: Trend Micro Iron Tiger April 2021)
- [S0398] HyperBro: [HyperBro](https://attack.mitre.org/software/S0398) has the ability to take screenshots.(Citation: Unit42 Emissary Panda May 2019)
- [S1044] FunnyDream: The [FunnyDream](https://attack.mitre.org/software/S1044) ScreenCap component can take screenshots on a compromised host.(Citation: Bitdefender FunnyDream Campaign November 2020)
- [S1201] TRANSLATEXT: [TRANSLATEXT](https://attack.mitre.org/software/S1201) has the ability to capture screenshots of new browser tabs, based on the presence of the `Capture` flag.(Citation: Zscaler Kimsuky TRANSLATEXT)
- [G0087] APT39: [APT39](https://attack.mitre.org/groups/G0087) has used a screen capture utility to take screenshots on a compromised host.(Citation: Symantec Chafer February 2018)(Citation: FBI FLASH APT39 September 2020)
- [S0667] Chrommme: [Chrommme](https://attack.mitre.org/software/S0667) has the ability to capture screenshots.(Citation: ESET Gelsemium June 2021)
- [S0277] FruitFly: [FruitFly](https://attack.mitre.org/software/S0277) takes screenshots of the user's desktop.(Citation: objsee mac malware 2017)
- [S0332] Remcos: [Remcos](https://attack.mitre.org/software/S0332) takes automated screenshots of the infected machine.(Citation: Riskiq Remcos Jan 2018)
- [S1090] NightClub: [NightClub](https://attack.mitre.org/software/S1090) can load a module to call `CreateCompatibleDC` and `GdipSaveImageToStream` for screen capture.(Citation: MoustachedBouncer ESET August 2023)
- [S0381] FlawedAmmyy: [FlawedAmmyy](https://attack.mitre.org/software/S0381) can capture screenshots.(Citation: Korean FSI TA505 2020)
- [S0167] Matryoshka: [Matryoshka](https://attack.mitre.org/software/S0167) is capable of performing screen captures.(Citation: ClearSky Wilted Tulip July 2017)(Citation: CopyKittens Nov 2015)
- [S1148] Raccoon Stealer: [Raccoon Stealer](https://attack.mitre.org/software/S1148) can capture screenshots from victim systems.(Citation: S2W Racoon 2022)(Citation: Sekoia Raccoon2 2022)
- [S0062] DustySky: [DustySky](https://attack.mitre.org/software/S0062) captures PNG screenshots of the main screen.(Citation: Kaspersky MoleRATs April 2019)
- [S0234] Bandook: [Bandook](https://attack.mitre.org/software/S0234) is capable of taking an image of and uploading the current desktop.(Citation: Lookout Dark Caracal Jan 2018)(Citation: CheckPoint Bandook Nov 2020)
- [S0203] Hydraq: [Hydraq](https://attack.mitre.org/software/S0203) includes a component based on the code of VNC that can stream a live feed of the desktop of an infected host.(Citation: Symantec Hydraq Jan 2010)
- [S0629] RainyDay: [RainyDay](https://attack.mitre.org/software/S0629) has the ability to capture screenshots.(Citation: Bitdefender Naikon April 2021)
- [S0088] Kasidet: [Kasidet](https://attack.mitre.org/software/S0088) has the ability to initiate keylogging and screen captures.(Citation: Zscaler Kasidet)
- [S0356] KONNI: [KONNI](https://attack.mitre.org/software/S0356) can take screenshots of the victim’s machine.(Citation: Talos Konni May 2017)
- [S0032] gh0st RAT: [gh0st RAT](https://attack.mitre.org/software/S0032) can capture the victim’s screen remotely.(Citation: Nccgroup Gh0st April 2018)
- [S0265] Kazuar: [Kazuar](https://attack.mitre.org/software/S0265) captures screenshots of the victim’s screen.(Citation: Unit 42 Kazuar May 2017)
- [S0152] EvilGrab: [EvilGrab](https://attack.mitre.org/software/S0152) has the capability to capture screenshots.(Citation: PWC Cloud Hopper Technical Annex April 2017)
- [S0151] HALFBAKED: [HALFBAKED](https://attack.mitre.org/software/S0151) can obtain screenshots from the victim.(Citation: FireEye FIN7 April 2017)
- [S0455] Metamorfo: [Metamorfo](https://attack.mitre.org/software/S0455) can collect screenshots of the victim’s machine.(Citation: FireEye Metamorfo Apr 2018)(Citation: ESET Casbaneiro Oct 2019)
- [S0248] yty: [yty](https://attack.mitre.org/software/S0248) collects screenshots of the victim machine.(Citation: ASERT Donot March 2018)
- [S0339] Micropsia: [Micropsia](https://attack.mitre.org/software/S0339) takes screenshots every 90 seconds by calling the Gdi32.BitBlt API.(Citation: Radware Micropsia July 2018)
- [S0649] SMOKEDHAM: [SMOKEDHAM](https://attack.mitre.org/software/S0649) can capture screenshots of the victim’s desktop.(Citation: FireEye Shining A Light on DARKSIDE May 2021)(Citation: FireEye SMOKEDHAM June 2021)
- [S0013] PlugX: [PlugX](https://attack.mitre.org/software/S0013) allows the operator to capture screenshots.(Citation: CIRCL PlugX March 2013)
- [S0387] KeyBoy: [KeyBoy](https://attack.mitre.org/software/S0387) has a command to perform screen grabbing.(Citation: PWC KeyBoys Feb 2017)
- [S0273] Socksbot: [Socksbot](https://attack.mitre.org/software/S0273) can take screenshots.(Citation: TrendMicro Patchwork Dec 2017)
- [G0094] Kimsuky: [Kimsuky](https://attack.mitre.org/groups/G0094) has captured browser screenshots using [TRANSLATEXT](https://attack.mitre.org/software/S1201).(Citation: Zscaler Kimsuky TRANSLATEXT)
- [S0161] XAgentOSX: [XAgentOSX](https://attack.mitre.org/software/S0161) contains the takeScreenShot (along with startTakeScreenShot and stopTakeScreenShot) functions to take screenshots using the CGGetActiveDisplayList, CGDisplayCreateImage, and NSImage:initWithCGImage methods.(Citation: XAgentOSX 2017)
- [S0271] KEYMARBLE: [KEYMARBLE](https://attack.mitre.org/software/S0271) can capture screenshots of the victim’s machine.(Citation: US-CERT KEYMARBLE Aug 2018)
- [S0591] ConnectWise: [ConnectWise](https://attack.mitre.org/software/S0591) can take screenshots on remote hosts.(Citation: Anomali Static Kitten February 2021)
- [S1142] LunarMail: [LunarMail](https://attack.mitre.org/software/S1142) can capture screenshots from compromised hosts.(Citation: ESET Turla Lunar toolset May 2024)
- [S0240] ROKRAT: [ROKRAT](https://attack.mitre.org/software/S0240) can capture screenshots of the infected system using the `gdi32` library.(Citation: Talos ROKRAT)(Citation: Talos ROKRAT 2)(Citation: Securelist ScarCruft May 2019)(Citation: NCCGroup RokRat Nov 2018)(Citation: Malwarebytes RokRAT VBA January 2021)
- [S0379] Revenge RAT: [Revenge RAT](https://attack.mitre.org/software/S0379) has a plugin for screen capture.(Citation: Cylance Shaheen Nov 2018)
- [S0021] Derusbi: [Derusbi](https://attack.mitre.org/software/S0021) is capable of performing screen captures.(Citation: FireEye Periscope March 2018)
- [S0198] NETWIRE: [NETWIRE](https://attack.mitre.org/software/S0198) can capture the victim's screen.(Citation: McAfee Netwire Mar 2015)(Citation: FireEye NETWIRE March 2019)(Citation: Red Canary NETWIRE January 2020)(Citation: Proofpoint NETWIRE December 2020)
- [S0279] Proton: [Proton](https://attack.mitre.org/software/S0279) captures the content of the desktop with the screencapture binary.(Citation: objsee mac malware 2017)
- [S1149] CHIMNEYSWEEP: [CHIMNEYSWEEP](https://attack.mitre.org/software/S1149) can capture screenshots on targeted systems using a timer and either upload them or store them to disk.(Citation: Mandiant ROADSWEEP August 2022)
- [S0622] AppleSeed: [AppleSeed](https://attack.mitre.org/software/S0622) can take screenshots on a compromised host by calling a series of APIs.(Citation: Malwarebytes Kimsuky June 2021)(Citation: KISA Operation Muzabi)
- [S0375] Remexi: [Remexi](https://attack.mitre.org/software/S0375) takes screenshots of windows of interest.(Citation: Securelist Remexi Jan 2019)
- [S0217] SHUTTERSPEED: [SHUTTERSPEED](https://attack.mitre.org/software/S0217) can capture screenshots.(Citation: FireEye APT37 Feb 2018)
- [S0428] PoetRAT: [PoetRAT](https://attack.mitre.org/software/S0428) has the ability to take screen captures.(Citation: Talos PoetRAT April 2020)(Citation: Dragos Threat Report 2020)
- [S0454] Cadelspy: [Cadelspy](https://attack.mitre.org/software/S0454) has the ability to capture screenshots and webcam photos.(Citation: Symantec Chafer Dec 2015)
- [S0098] T9000: [T9000](https://attack.mitre.org/software/S0098) can take screenshots of the desktop and target application windows, saving them to user directories as one byte XOR encrypted .dat files.(Citation: Palo Alto T9000 Feb 2016)
- [S0674] CharmPower: [CharmPower](https://attack.mitre.org/software/S0674) has the ability to capture screenshots.(Citation: Check Point APT35 CharmPower January 2022)
- [S0484] Carberp: [Carberp](https://attack.mitre.org/software/S0484) can capture display screenshots with the screens_dll.dll plugin.(Citation: Prevx Carberp March 2011)
- [S0657] BLUELIGHT: [BLUELIGHT](https://attack.mitre.org/software/S0657) has captured a screenshot of the display every 30 seconds for the first 5 minutes after initiating a C2 loop, and then once every five minutes thereafter.(Citation: Volexity InkySquid BLUELIGHT August 2021)
- [S0282] MacSpy: [MacSpy](https://attack.mitre.org/software/S0282) can capture screenshots of the desktop over multiple monitors.(Citation: objsee mac malware 2017)
- [S0533] SLOTHFULMEDIA: [SLOTHFULMEDIA](https://attack.mitre.org/software/S0533) has taken a screenshot of a victim's desktop, named it "Filter3.jpg", and stored it in the local directory.(Citation: CISA MAR SLOTHFULMEDIA October 2020)
- [S0270] RogueRobin: [RogueRobin](https://attack.mitre.org/software/S0270) has a command named <code>$screenshot</code> that may be responsible for taking screenshots of the victim machine.(Citation: Unit 42 DarkHydrus July 2018)
- [S0631] Chaes: [Chaes](https://attack.mitre.org/software/S0631) can capture screenshots of the infected machine.(Citation: Cybereason Chaes Nov 2020)
- [S0223] POWERSTATS: [POWERSTATS](https://attack.mitre.org/software/S0223) can retrieve screenshots from compromised hosts.(Citation: FireEye MuddyWater Mar 2018)(Citation: TrendMicro POWERSTATS V3 June 2019)
- [S0283] jRAT: [jRAT](https://attack.mitre.org/software/S0283) has the capability to take screenshots of the victim’s machine.(Citation: jRAT Symantec Aug 2018)(Citation: Kaspersky Adwind Feb 2016)
- [S0592] RemoteUtilities: [RemoteUtilities](https://attack.mitre.org/software/S0592) can take screenshots on a compromised host.(Citation: Trend Micro Muddy Water March 2021)
- [G0070] Dark Caracal: [Dark Caracal](https://attack.mitre.org/groups/G0070) took screenshots using their Windows malware.(Citation: Lookout Dark Caracal Jan 2018)
- [S0184] POWRUNER: [POWRUNER](https://attack.mitre.org/software/S0184) can capture a screenshot from a victim.(Citation: FireEye APT34 Dec 2017)
- [S1087] AsyncRAT: [AsyncRAT](https://attack.mitre.org/software/S1087) has the ability to view the screen on compromised hosts.(Citation: AsyncRAT GitHub)
- [S0344] Azorult: [Azorult](https://attack.mitre.org/software/S0344) can capture screenshots of the victim’s machines.(Citation: Unit42 Azorult Nov 2018)
- [S0431] HotCroissant: [HotCroissant](https://attack.mitre.org/software/S0431) has the ability to do real time screen viewing on an infected host.(Citation: Carbon Black HotCroissant April 2020)
- [S0380] StoneDrill: [StoneDrill](https://attack.mitre.org/software/S0380) can take screenshots.(Citation: Kaspersky StoneDrill 2017)
- [S0261] Catchamas: [Catchamas](https://attack.mitre.org/software/S0261) captures screenshots based on specific keywords in the window’s title.(Citation: Symantec Catchamas April 2018)
- [S1107] NKAbuse: [NKAbuse](https://attack.mitre.org/software/S1107) can take screenshots of the victim machine.(Citation: NKAbuse SL)
- [G0046] FIN7: [FIN7](https://attack.mitre.org/groups/G0046) captured screenshots and desktop video recordings.(Citation: DOJ FIN7 Aug 2018)
- [S0348] Cardinal RAT: [Cardinal RAT](https://attack.mitre.org/software/S0348) can capture screenshots.(Citation: PaloAlto CardinalRat Apr 2017)
- [S0658] XCSSET: [XCSSET](https://attack.mitre.org/software/S0658) saves a screen capture of the victim's system with a numbered filename and <code>.jpg</code> extension. Screen captures are taken at specified intervals based on the system. (Citation: trendmicro xcsset xcode project 2020)
- [S0340] Octopus: [Octopus](https://attack.mitre.org/software/S0340) can capture screenshots of the victims’ machine.(Citation: Securelist Octopus Oct 2018)(Citation: Security Affairs DustSquad Oct 2018)(Citation: ESET Nomadic Octopus 2018)
- [S0148] RTM: [RTM](https://attack.mitre.org/software/S0148) can capture screenshots.(Citation: ESET RTM Feb 2017)(Citation: Unit42 Redaman January 2019)
- [S0686] QuietSieve: [QuietSieve](https://attack.mitre.org/software/S0686) has taken screenshots every five minutes and saved them to the user's local Application Data folder under `Temp\SymbolSourceSymbols\icons` or `Temp\ModeAuto\icons`.(Citation: Microsoft Actinium February 2022)
- [S0409] Machete: [Machete](https://attack.mitre.org/software/S0409) captures screenshots.(Citation: ESET Machete July 2019)(Citation: Securelist Machete Aug 2014)(Citation: Cylance Machete Mar 2017)(Citation: 360 Machete Sep 2020)
- [S0163] Janicab: [Janicab](https://attack.mitre.org/software/S0163) captured screenshots and sent them out to a C2 server.(Citation: f-secure janicab)(Citation: Janicab)
- [S0652] MarkiRAT: [MarkiRAT](https://attack.mitre.org/software/S0652) can capture screenshots that are initially saved as ‘scr.jpg’.(Citation: Kaspersky Ferocious Kitten Jun 2021)


### T1114 - Email Collection

Description:

Adversaries may target user email to collect sensitive information. Emails may contain sensitive data, including trade secrets or personal information, that can prove valuable to adversaries. Emails may also contain details of ongoing incident response operations, which may allow adversaries to adjust their techniques in order to maintain persistence or evade defenses.(Citation: TrustedSec OOB Communications)(Citation: CISA AA20-352A 2021) Adversaries can collect or forward email from mail servers or clients.

Procedures:

- [G1003] Ember Bear: [Ember Bear](https://attack.mitre.org/groups/G1003) attempts to collect mail from accessed systems and servers.(Citation: Cadet Blizzard emerges as novel threat actor)(Citation: CISA GRU29155 2024)
- [G0122] Silent Librarian: [Silent Librarian](https://attack.mitre.org/groups/G0122) has exfiltrated entire mailboxes from compromised accounts.(Citation: DOJ Iran Indictments March 2018)
- [S0367] Emotet: [Emotet](https://attack.mitre.org/software/S0367) has been observed leveraging a module that can scrape email addresses from Outlook.(Citation: CIS Emotet Dec 2018)(Citation: IBM IcedID November 2017)(Citation: Binary Defense Emotes Wi-Fi Spreader)
- [G0059] Magic Hound: [Magic Hound](https://attack.mitre.org/groups/G0059) has compromised email credentials in order to steal sensitive data.(Citation: Certfa Charming Kitten January 2021)
- [S1201] TRANSLATEXT: [TRANSLATEXT](https://attack.mitre.org/software/S1201) has exfiltrated collected email addresses to the C2 server.(Citation: Zscaler Kimsuky TRANSLATEXT)
- [G1015] Scattered Spider: [Scattered Spider](https://attack.mitre.org/groups/G1015) searched the victim’s Microsoft Exchange for emails about the intrusion and incident response.(Citation: CISA Scattered Spider Advisory November 2023)

#### T1114.001 - Local Email Collection

Description:

Adversaries may target user email on local systems to collect sensitive information. Files containing email data can be acquired from a user’s local system, such as Outlook storage or cache files.

Outlook stores data locally in offline data files with an extension of .ost. Outlook 2010 and later supports .ost file sizes up to 50GB, while earlier versions of Outlook support up to 20GB.(Citation: Outlook File Sizes) IMAP accounts in Outlook 2013 (and earlier) and POP accounts use Outlook Data Files (.pst) as opposed to .ost, whereas IMAP accounts in Outlook 2016 (and later) use .ost files. Both types of Outlook data files are typically stored in `C:\Users\<username>\Documents\Outlook Files` or `C:\Users\<username>\AppData\Local\Microsoft\Outlook`.(Citation: Microsoft Outlook Files)

Procedures:

- [S1142] LunarMail: [LunarMail](https://attack.mitre.org/software/S1142) can capture the recipients of sent email messages from compromised accounts.(Citation: ESET Turla Lunar toolset May 2024)
- [G1039] RedCurl: [RedCurl](https://attack.mitre.org/groups/G1039) has collected emails to use in future phishing campaigns.(Citation: group-ib_redcurl1)
- [S0226] Smoke Loader: [Smoke Loader](https://attack.mitre.org/software/S0226) searches through Outlook files and directories (e.g., inbox, sent, templates, drafts, archives, etc.).(Citation: Talos Smoke Loader July 2018)
- [S0650] QakBot: [QakBot](https://attack.mitre.org/software/S0650) can target and steal locally stored emails to support thread hijacking phishing campaigns.(Citation: Kroll Qakbot June 2020)(Citation: Trend Micro Qakbot December 2020)(Citation: Kaspersky QakBot September 2021)
- [G1041] Sea Turtle: [Sea Turtle](https://attack.mitre.org/groups/G1041) collected email archives from victim environments.(Citation: Hunt Sea Turtle 2024)
- [S0192] Pupy: [Pupy](https://attack.mitre.org/software/S0192) can interact with a victim’s Outlook session and look through folders and emails.(Citation: GitHub Pupy)
- [S0030] Carbanak: [Carbanak](https://attack.mitre.org/software/S0030) searches recursively for Outlook personal storage tables (PST) files within user directories and sends them back to the C2 server.(Citation: FireEye CARBANAK June 2017)
- [G0006] APT1: [APT1](https://attack.mitre.org/groups/G0006) uses two utilities, GETMAIL and MAPIGET, to steal email. GETMAIL extracts emails from archived Outlook .pst files.(Citation: Mandiant APT1)
- [S0115] Crimson: [Crimson](https://attack.mitre.org/software/S0115) contains a command to collect and exfiltrate emails from Outlook.(Citation: Proofpoint Operation Transparent Tribe March 2016)
- [C0002] Night Dragon: During [Night Dragon](https://attack.mitre.org/campaigns/C0002), threat actors used RAT malware to exfiltrate email archives.(Citation: McAfee Night Dragon)
- [S0363] Empire: [Empire](https://attack.mitre.org/software/S0363) has the ability to collect emails on a target system.(Citation: Github PowerShell Empire)
- [G0114] Chimera: [Chimera](https://attack.mitre.org/groups/G0114) has harvested data from victim's e-mail including through execution of <code>wmic /node:<ip> process call create "cmd /c copy c:\Users\<username>\<path>\backup.pst c:\windows\temp\backup.pst" copy "i:\<path>\<username>\My Documents\<filename>.pst"
copy</code>.(Citation: NCC Group Chimera January 2021)
- [S0526] KGH_SPY: [KGH_SPY](https://attack.mitre.org/software/S0526) can harvest data from mail clients.(Citation: Cybereason Kimsuky November 2020)
- [G0059] Magic Hound: [Magic Hound](https://attack.mitre.org/groups/G0059) has collected .PST archives.(Citation: FireEye APT35 2018)
- [S0050] CosmicDuke: [CosmicDuke](https://attack.mitre.org/software/S0050) searches for Microsoft Outlook data files with extensions .pst and .ost for collection and exfiltration.(Citation: F-Secure Cosmicduke)
- [S0594] Out1: [Out1](https://attack.mitre.org/software/S0594) can parse e-mails on a target machine.(Citation: Trend Micro Muddy Water March 2021)
- [G1035] Winter Vivern: [Winter Vivern](https://attack.mitre.org/groups/G1035) delivered malicious JavaScript payloads capable of exfiltrating email messages from exploited email servers.(Citation: ESET WinterVivern 2023)
- [S0367] Emotet: [Emotet](https://attack.mitre.org/software/S0367) has been observed leveraging a module that scrapes email data from Outlook.(Citation: CIS Emotet Dec 2018)

#### T1114.002 - Remote Email Collection

Description:

Adversaries may target an Exchange server, Office 365, or Google Workspace to collect sensitive information. Adversaries may leverage a user's credentials and interact directly with the Exchange server to acquire information from within a network. Adversaries may also access externally facing Exchange services, Office 365, or Google Workspace to access email using credentials or access tokens. Tools such as [MailSniper](https://attack.mitre.org/software/S0413) can be used to automate searches for specific keywords.

Procedures:

- [G0004] Ke3chang: [Ke3chang](https://attack.mitre.org/groups/G0004) has used compromised credentials and a .NET tool to dump data from Microsoft Exchange mailboxes.(Citation: NCC Group APT15 Alive and Strong)(Citation: Microsoft NICKEL December 2021)
- [S0413] MailSniper: [MailSniper](https://attack.mitre.org/software/S0413) can be used for searching through email in Exchange and Office 365 environments.(Citation: GitHub MailSniper)
- [C0024] SolarWinds Compromise: During the [SolarWinds Compromise](https://attack.mitre.org/campaigns/C0024), [APT29](https://attack.mitre.org/groups/G0016) collected emails from specific individuals, such as executives and IT staff, using `New-MailboxExportRequest` followed by `Get-MailboxExportRequest`.(Citation: Volexity SolarWinds)(Citation: Cybersecurity Advisory SVR TTP May 2021)
- [G0007] APT28: [APT28](https://attack.mitre.org/groups/G0007) has collected emails from victim Microsoft Exchange servers.(Citation: DOJ GRU Indictment Jul 2018)(Citation: Cybersecurity Advisory GRU Brute Force Campaign July 2021)
- [G1033] Star Blizzard: [Star Blizzard](https://attack.mitre.org/groups/G1033) has remotely accessed victims' email accounts to steal messages and attachments.(Citation: CISA Star Blizzard Advisory December 2023)
- [G0006] APT1: [APT1](https://attack.mitre.org/groups/G0006) uses two utilities, GETMAIL and MAPIGET, to steal email. MAPIGET steals email still on Exchange servers that has not yet been archived.(Citation: Mandiant APT1)
- [C0038] HomeLand Justice: During [HomeLand Justice](https://attack.mitre.org/campaigns/C0038), threat actors made multiple HTTP POST requests to the Exchange servers of the victim organization to transfer data.(Citation: CISA Iran Albanian Attacks September 2022)
- [S0395] LightNeuron: [LightNeuron](https://attack.mitre.org/software/S0395) collects Exchange emails matching rules specified in its configuration.(Citation: ESET LightNeuron May 2019)
- [G0016] APT29: [APT29](https://attack.mitre.org/groups/G0016) has collected emails from targeted mailboxes within a compromised Azure AD tenant and compromised Exchange servers, including via Exchange Web Services (EWS) API requests.(Citation: Mandiant APT29 Microsoft 365 2022)(Citation: Mandiant APT29 Eye Spy Email Nov 22)
- [S0053] SeaDuke: Some [SeaDuke](https://attack.mitre.org/software/S0053) samples have a module to extract email from Microsoft Exchange servers using compromised credentials.(Citation: Symantec Seaduke 2015)
- [G0125] HAFNIUM: [HAFNIUM](https://attack.mitre.org/groups/G0125) has used web shells and MSGraph to export mailbox data.(Citation: Microsoft HAFNIUM March 2020)(Citation: Volexity Exchange Marauder March 2021)(Citation: Microsoft Silk Typhoon MAR 2025)
- [S0476] Valak: [Valak](https://attack.mitre.org/software/S0476) can collect sensitive mailing information from Exchange servers, including credentials and the domain certificate of an enterprise.(Citation: Cybereason Valak May 2020)
- [G0059] Magic Hound: [Magic Hound](https://attack.mitre.org/groups/G0059) has exported emails from compromised Exchange servers including through use of the cmdlet `New-MailboxExportRequest.`(Citation: DFIR Report APT35 ProxyShell March 2022)(Citation: DFIR Phosphorus November 2021)
- [G0114] Chimera: [Chimera](https://attack.mitre.org/groups/G0114) has harvested data from remote mailboxes including through execution of <code>\\<hostname>\c$\Users\<username>\AppData\Local\Microsoft\Outlook*.ost</code>.(Citation: NCC Group Chimera January 2021)
- [G0035] Dragonfly: [Dragonfly](https://attack.mitre.org/groups/G0035) has accessed email accounts using Outlook Web Access.(Citation: US-CERT TA18-074A)
- [G0085] FIN4: [FIN4](https://attack.mitre.org/groups/G0085) has accessed and hijacked online email communications using stolen credentials.(Citation: FireEye Hacking FIN4 Dec 2014)(Citation: FireEye Hacking FIN4 Video Dec 2014)
- [G0077] Leafminer: [Leafminer](https://attack.mitre.org/groups/G0077) used a tool called MailSniper to search through the Exchange server mailboxes for keywords.(Citation: Symantec Leafminer July 2018)
- [G0094] Kimsuky: [Kimsuky](https://attack.mitre.org/groups/G0094) has used tools such as the MailFetch mail crawler to collect victim emails (excluding spam) from online services via IMAP.(Citation: KISA Operation Muzabi)

#### T1114.003 - Email Forwarding Rule

Description:

Adversaries may setup email forwarding rules to collect sensitive information. Adversaries may abuse email forwarding rules to monitor the activities of a victim, steal information, and further gain intelligence on the victim or the victim’s organization to use as part of further exploits or operations.(Citation: US-CERT TA18-068A 2018) Furthermore, email forwarding rules can allow adversaries to maintain persistent access to victim's emails even after compromised credentials are reset by administrators.(Citation: Pfammatter - Hidden Inbox Rules) Most email clients allow users to create inbox rules for various email functions, including forwarding to a different recipient. These rules may be created through a local email application, a web interface, or by command-line interface. Messages can be forwarded to internal or external recipients, and there are no restrictions limiting the extent of this rule. Administrators may also create forwarding rules for user accounts with the same considerations and outcomes.(Citation: Microsoft Tim McMichael Exchange Mail Forwarding 2)(Citation: Mac Forwarding Rules)

Any user or administrator within the organization (or adversary with valid credentials) can create rules to automatically forward all received messages to another recipient, forward emails to different locations based on the sender, and more. Adversaries may also hide the rule by making use of the Microsoft Messaging API (MAPI) to modify the rule properties, making it hidden and not visible from Outlook, OWA or most Exchange Administration tools.(Citation: Pfammatter - Hidden Inbox Rules)

In some environments, administrators may be able to enable email forwarding rules that operate organization-wide rather than on individual inboxes. For example, Microsoft Exchange supports transport rules that evaluate all mail an organization receives against user-specified conditions, then performs a user-specified action on mail that adheres to those conditions.(Citation: Microsoft Mail Flow Rules 2023) Adversaries that abuse such features may be able to enable forwarding on all or specific mail an organization receives.

Procedures:

- [G0122] Silent Librarian: [Silent Librarian](https://attack.mitre.org/groups/G0122) has set up auto forwarding rules on compromised e-mail accounts.(Citation: DOJ Iran Indictments March 2018)
- [G1004] LAPSUS$: [LAPSUS$](https://attack.mitre.org/groups/G1004) has set an Office 365 tenant level mail transport rule to send all mail in and out of the targeted organization to the newly created account.(Citation: MSTIC DEV-0537 Mar 2022)
- [G1033] Star Blizzard: [Star Blizzard](https://attack.mitre.org/groups/G1033) has abused email forwarding rules to monitor the activities of a victim, steal information, and maintain persistent access after compromised credentials are reset.(Citation: Microsoft Star Blizzard August 2022)(Citation: CISA Star Blizzard Advisory December 2023)
- [G0094] Kimsuky: [Kimsuky](https://attack.mitre.org/groups/G0094) has set auto-forward rules on victim's e-mail accounts.(Citation: CISA AA20-301A Kimsuky)


### T1115 - Clipboard Data

Description:

Adversaries may collect data stored in the clipboard from users copying information within or between applications. 

For example, on Windows adversaries can access clipboard data by using <code>clip.exe</code> or <code>Get-Clipboard</code>.(Citation: MSDN Clipboard)(Citation: clip_win_server)(Citation: CISA_AA21_200B) Additionally, adversaries may monitor then replace users’ clipboard with their data (e.g., [Transmitted Data Manipulation](https://attack.mitre.org/techniques/T1565/002)).(Citation: mining_ruby_reversinglabs)

macOS and Linux also have commands, such as <code>pbpaste</code>, to grab clipboard contents.(Citation: Operating with EmPyre)

Procedures:

- [S0331] Agent Tesla: [Agent Tesla](https://attack.mitre.org/software/S0331) can steal data from the victim’s clipboard.(Citation: Talos Agent Tesla Oct 2018)(Citation: Fortinet Agent Tesla April 2018)(Citation: Fortinet Agent Tesla June 2017)(Citation: Bitdefender Agent Tesla April 2020)
- [G0087] APT39: [APT39](https://attack.mitre.org/groups/G0087) has used tools capable of stealing contents of the clipboard.(Citation: Symantec Chafer February 2018)
- [S0148] RTM: [RTM](https://attack.mitre.org/software/S0148) collects data from the clipboard.(Citation: ESET RTM Feb 2017)(Citation: Unit42 Redaman January 2019)
- [S0692] SILENTTRINITY: [SILENTTRINITY](https://attack.mitre.org/software/S0692) can monitor Clipboard text and can use `System.Windows.Forms.Clipboard.GetText()` to collect data from the clipboard.(Citation: Github_SILENTTRINITY)
- [S0334] DarkComet: [DarkComet](https://attack.mitre.org/software/S0334) can steal data from the clipboard.(Citation: Malwarebytes DarkComet March 2018)
- [S0373] Astaroth: [Astaroth](https://attack.mitre.org/software/S0373) collects information from the clipboard by using the OpenClipboard() and GetClipboardData() libraries. (Citation: Cybereason Astaroth Feb 2019)
- [S0004] TinyZBot: [TinyZBot](https://attack.mitre.org/software/S0004) contains functionality to collect information from the clipboard.(Citation: Cylance Cleaver)
- [S0363] Empire: [Empire](https://attack.mitre.org/software/S0363) can harvest clipboard data on both Windows and macOS systems.(Citation: Github PowerShell Empire)
- [S0438] Attor: [Attor](https://attack.mitre.org/software/S0438) has a plugin that collects data stored in the Windows clipboard by using the OpenClipboard and GetClipboardData APIs.(Citation: ESET Attor Oct 2019)
- [S0332] Remcos: [Remcos](https://attack.mitre.org/software/S0332) steals and modifies data from the clipboard.(Citation: Riskiq Remcos Jan 2018)
- [S0257] VERMIN: [VERMIN](https://attack.mitre.org/software/S0257) collects data stored in the clipboard.(Citation: Unit 42 VERMIN Jan 2018)
- [C0014] Operation Wocao: During [Operation Wocao](https://attack.mitre.org/campaigns/C0014), threat actors collected clipboard data in plaintext.(Citation: FoxIT Wocao December 2019)
- [S1149] CHIMNEYSWEEP: [CHIMNEYSWEEP](https://attack.mitre.org/software/S1149) can capture content from the clipboard.(Citation: Mandiant ROADSWEEP August 2022)
- [S0356] KONNI: [KONNI](https://attack.mitre.org/software/S0356) had a feature to steal data from the clipboard.(Citation: Talos Konni May 2017)
- [S0375] Remexi: [Remexi](https://attack.mitre.org/software/S0375) collects text from the clipboard.(Citation: Securelist Remexi Jan 2019)
- [S0282] MacSpy: [MacSpy](https://attack.mitre.org/software/S0282) can steal clipboard contents.(Citation: objsee mac malware 2017)
- [S0454] Cadelspy: [Cadelspy](https://attack.mitre.org/software/S0454) has the ability to steal data from the clipboard.(Citation: Symantec Chafer Dec 2015)
- [S0250] Koadic: [Koadic](https://attack.mitre.org/software/S0250) can retrieve the current content of the user clipboard.(Citation: Github Koadic)
- [S0050] CosmicDuke: [CosmicDuke](https://attack.mitre.org/software/S0050) copies and exfiltrates the clipboard contents every 30 seconds.(Citation: F-Secure Cosmicduke)
- [S1207] XLoader: [XLoader](https://attack.mitre.org/software/S1207) can collect data stored in the victim's clipboard.(Citation: Google XLoader 2017)(Citation: Netskope XLoader 2022)
- [S0660] Clambling: [Clambling](https://attack.mitre.org/software/S0660) has the ability to capture and store clipboard data.(Citation: Trend Micro DRBControl February 2020)(Citation: Talent-Jump Clambling February 2020)
- [S1066] DarkTortilla: [DarkTortilla](https://attack.mitre.org/software/S1066) can download a clipboard information stealer module.(Citation: Secureworks DarkTortilla Aug 2022)
- [S0455] Metamorfo: [Metamorfo](https://attack.mitre.org/software/S0455) has a function to hijack data from the clipboard by monitoring the contents of the clipboard and replacing the cryptocurrency wallet with the attacker's.(Citation: Fortinet Metamorfo Feb 2020)(Citation: ESET Casbaneiro Oct 2019)
- [S0409] Machete: [Machete](https://attack.mitre.org/software/S0409) hijacks the clipboard data by creating an overlapped window that listens to keyboard events.(Citation: ESET Machete July 2019)(Citation: Securelist Machete Aug 2014)
- [S0044] JHUHUGIT: A [JHUHUGIT](https://attack.mitre.org/software/S0044) variant accesses a screenshot saved in the clipboard and converts it to a JPG image.(Citation: Unit 42 Playbook Dec 2017)
- [S0240] ROKRAT: [ROKRAT](https://attack.mitre.org/software/S0240) can extract clipboard data from a compromised host.(Citation: Volexity InkySquid RokRAT August 2021)
- [S1146] MgBot: [MgBot](https://attack.mitre.org/software/S1146) can capture clipboard data.(Citation: ESET EvasivePanda 2023)(Citation: Symantec Daggerfly 2023)
- [S0531] Grandoreiro: [Grandoreiro](https://attack.mitre.org/software/S0531) can capture clipboard data from a compromised host.(Citation: IBM Grandoreiro April 2020)
- [S0170] Helminth: The executable version of [Helminth](https://attack.mitre.org/software/S0170) has a module to log clipboard contents.(Citation: Palo Alto OilRig May 2016)
- [S0261] Catchamas: [Catchamas](https://attack.mitre.org/software/S0261) steals data stored in the clipboard.(Citation: Symantec Catchamas April 2018)
- [S0283] jRAT: [jRAT](https://attack.mitre.org/software/S0283) can capture clipboard data.(Citation: Kaspersky Adwind Feb 2016)
- [S0569] Explosive: [Explosive](https://attack.mitre.org/software/S0569) has a function to use the OpenClipboard wrapper.(Citation: CheckPoint Volatile Cedar March 2015)
- [G0082] APT38: [APT38](https://attack.mitre.org/groups/G0082) used a Trojan called KEYLIME to collect data from the clipboard.(Citation: FireEye APT38 Oct 2018)
- [S1111] DarkGate: [DarkGate](https://attack.mitre.org/software/S1111) starts a thread on execution that captures clipboard data and logs it to a predefined log file.(Citation: Ensilo Darkgate 2018)(Citation: Rapid7 BlackBasta 2024)
- [G0049] OilRig: [OilRig](https://attack.mitre.org/groups/G0049) has used infostealer tools to copy clipboard data.(Citation: Symantec Crambus OCT 2023)
- [S0330] Zeus Panda: [Zeus Panda](https://attack.mitre.org/software/S0330) can hook GetClipboardData function to watch for clipboard pastes to collect.(Citation: GDATA Zeus Panda June 2017)
- [S0530] Melcoz: [Melcoz](https://attack.mitre.org/software/S0530) can monitor content saved to the clipboard.(Citation: Securelist Brazilian Banking Malware July 2020)
- [S0253] RunningRAT: [RunningRAT](https://attack.mitre.org/software/S0253) contains code to open and copy data from the clipboard.(Citation: McAfee Gold Dragon)
- [S1122] Mispadu: [Mispadu](https://attack.mitre.org/software/S1122) has the ability to capture and replace Bitcoin wallet data in the clipboard on a compromised host.(Citation: ESET Security Mispadu Facebook Ads 2019)
- [S0381] FlawedAmmyy: [FlawedAmmyy](https://attack.mitre.org/software/S0381) can collect clipboard data.(Citation: Korean FSI TA505 2020)
- [S0652] MarkiRAT: [MarkiRAT](https://attack.mitre.org/software/S0652) can capture clipboard content.(Citation: Kaspersky Ferocious Kitten Jun 2021)
- [S0467] TajMahal: [TajMahal](https://attack.mitre.org/software/S0467) has the ability to steal data from the clipboard of an infected host.(Citation: Kaspersky TajMahal April 2019)


### T1119 - Automated Collection

Description:

Once established within a system or network, an adversary may use automated techniques for collecting internal data. Methods for performing this technique could include use of a [Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059) to search for and copy information fitting set criteria such as file type, location, or name at specific time intervals. 

In cloud-based environments, adversaries may also use cloud APIs, data pipelines, command line interfaces, or extract, transform, and load (ETL) services to automatically collect data.(Citation: Mandiant UNC3944 SMS Phishing 2023) 

This functionality could also be built into remote access tools. 

This technique may incorporate use of other techniques such as [File and Directory Discovery](https://attack.mitre.org/techniques/T1083) and [Lateral Tool Transfer](https://attack.mitre.org/techniques/T1570) to identify and move files, as well as [Cloud Service Dashboard](https://attack.mitre.org/techniques/T1538) and [Cloud Storage Object Discovery](https://attack.mitre.org/techniques/T1619) to identify resources in cloud environments.

Procedures:

- [S0098] T9000: [T9000](https://attack.mitre.org/software/S0098) searches removable storage devices for files with a pre-defined list of file extensions (e.g. * .doc, *.ppt, *.xls, *.docx, *.pptx, *.xlsx). Any matching files are encrypted and written to a local user directory.(Citation: Palo Alto T9000 Feb 2016)
- [S0090] Rover: [Rover](https://attack.mitre.org/software/S0090) automatically collects files from the local system and removable drives based on a predefined list of file extensions on a regular timeframe.(Citation: Palo Alto Rover)
- [S0339] Micropsia: [Micropsia](https://attack.mitre.org/software/S0339) executes an RAR tool to recursively archive files based on a predefined list of file extensions (*.xls, *.xlsx, *.csv, *.odt, *.doc, *.docx, *.ppt, *.pptx, *.pdf, *.mdb, *.accdb, *.accde, *.txt).(Citation: Radware Micropsia July 2018)
- [S1043] ccf32: [ccf32](https://attack.mitre.org/software/S1043) can be used to automatically collect files from a compromised host.(Citation: Bitdefender FunnyDream Campaign November 2020)
- [S1111] DarkGate: [DarkGate](https://attack.mitre.org/software/S1111) searches for stored credentials associated with cryptocurrency wallets and notifies the command and control server when identified.(Citation: Ensilo Darkgate 2018)
- [G0047] Gamaredon Group: [Gamaredon Group](https://attack.mitre.org/groups/G0047) has deployed scripts on compromised systems that automatically scan for interesting documents.(Citation: ESET Gamaredon June 2020)
- [S0244] Comnie: [Comnie](https://attack.mitre.org/software/S0244) executes a batch script to store discovery information in %TEMP%\info.dat and then uploads the temporarily file to the remote C2 server.(Citation: Palo Alto Comnie)
- [C0014] Operation Wocao: During [Operation Wocao](https://attack.mitre.org/campaigns/C0014), threat actors used a script to collect information about the infected system.(Citation: FoxIT Wocao December 2019)
- [S0684] ROADTools: [ROADTools](https://attack.mitre.org/software/S0684) automatically gathers data from Azure AD environments using the Azure Graph API.(Citation: Roadtools)
- [S0198] NETWIRE: [NETWIRE](https://attack.mitre.org/software/S0198) can automatically archive collected data.(Citation: Red Canary NETWIRE January 2020)
- [G1003] Ember Bear: [Ember Bear](https://attack.mitre.org/groups/G1003) engages in mass collection from compromised systems during intrusions.(Citation: Cadet Blizzard emerges as novel threat actor)
- [G1039] RedCurl: [RedCurl](https://attack.mitre.org/groups/G1039) has used batch scripts to collect data.(Citation: group-ib_redcurl1)(Citation: group-ib_redcurl2)
- [S0378] PoshC2: [PoshC2](https://attack.mitre.org/software/S0378) contains a module for recursively parsing through files and directories to gather valid credit card numbers.(Citation: GitHub PoshC2)
- [S0428] PoetRAT: [PoetRAT](https://attack.mitre.org/software/S0428) used file system monitoring to track modification and enable automatic exfiltration.(Citation: Talos PoetRAT April 2020)
- [S0363] Empire: [Empire](https://attack.mitre.org/software/S0363) can automatically gather the username, domain name, machine name, and other information from a compromised system.(Citation: Talos Frankenstein June 2019)
- [G0006] APT1: [APT1](https://attack.mitre.org/groups/G0006) used a batch script to perform a series of discovery techniques and saves it to a text file.(Citation: Mandiant APT1)
- [S0238] Proxysvc: [Proxysvc](https://attack.mitre.org/software/S0238) automatically collects data about the victim and sends it to the control server.(Citation: McAfee GhostSecret)
- [S0128] BADNEWS: [BADNEWS](https://attack.mitre.org/software/S0128) monitors USB devices and copies files with certain extensions to a predefined directory.(Citation: TrendMicro Patchwork Dec 2017)
- [S0467] TajMahal: [TajMahal](https://attack.mitre.org/software/S0467) has the ability to index and compress files into a send queue for exfiltration.(Citation: Kaspersky TajMahal April 2019)
- [G0004] Ke3chang: [Ke3chang](https://attack.mitre.org/groups/G0004) has performed frequent and scheduled data collection from victim networks.(Citation: Microsoft NICKEL December 2021)
- [G0053] FIN5: [FIN5](https://attack.mitre.org/groups/G0053) scans processes on all victim systems in the environment and uses automated scripts to pull back the results.(Citation: Mandiant FIN5 GrrCON Oct 2016)
- [S0257] VERMIN: [VERMIN](https://attack.mitre.org/software/S0257) saves each collected file with the automatically generated format {0:dd-MM-yyyy}.txt .(Citation: Unit 42 VERMIN Jan 2018)
- [G0125] HAFNIUM: [HAFNIUM](https://attack.mitre.org/groups/G0125) has used MSGraph to exfiltrate data from email, OneDrive, and SharePoint.(Citation: Microsoft Silk Typhoon MAR 2025)
- [G1030] Agrius: [Agrius](https://attack.mitre.org/groups/G1030) used a custom tool, <code>sql.net4.exe</code>, to query SQL databases and then identify and extract personally identifiable information.(Citation: Unit42 Agrius 2023)
- [S0455] Metamorfo: [Metamorfo](https://attack.mitre.org/software/S0455) has automatically collected mouse clicks, continuous screenshots on the machine, and set timers to collect the contents of the clipboard and website browsing.(Citation: FireEye Metamorfo Apr 2018)
- [G0007] APT28: [APT28](https://attack.mitre.org/groups/G0007) used a publicly available tool to gather and compress multiple documents on the DCCC and DNC networks.(Citation: DOJ GRU Indictment Jul 2018)
- [S0466] WindTail: [WindTail](https://attack.mitre.org/software/S0466) can identify and add files that possess specific file extensions to an array for archiving.(Citation: objective-see windtail2 jan 2019)
- [S0136] USBStealer: For all non-removable drives on a victim, [USBStealer](https://attack.mitre.org/software/S0136) executes automated collection of certain files for later exfiltration.(Citation: ESET Sednit USBStealer 2014)
- [S0622] AppleSeed: [AppleSeed](https://attack.mitre.org/software/S0622) has automatically collected data from USB drives, keystrokes, and screen images before exfiltration.(Citation: KISA Operation Muzabi)
- [S0476] Valak: [Valak](https://attack.mitre.org/software/S0476) can download a module to search for and build a report of harvested credential data.(Citation: SentinelOne Valak June 2020)
- [S1017] OutSteel: [OutSteel](https://attack.mitre.org/software/S1017) can automatically scan for and collect files with specific extensions.(Citation: Palo Alto Unit 42 OutSteel SaintBot February 2022 )
- [S0395] LightNeuron: [LightNeuron](https://attack.mitre.org/software/S0395) can be configured to automatically collect files under a specified directory.(Citation: ESET LightNeuron May 2019)
- [S0239] Bankshot: [Bankshot](https://attack.mitre.org/software/S0239) recursively generates a list of files within a directory and sends them back to the control server.(Citation: McAfee Bankshot)
- [S1109] PACEMAKER: [PACEMAKER](https://attack.mitre.org/software/S1109) can enter a loop to read `/proc/` entries every 2 seconds in order to read a target application's memory.(Citation: Mandiant Pulse Secure Zero-Day April 2021)
- [S0491] StrongPity: [StrongPity](https://attack.mitre.org/software/S0491) has a file searcher component that can automatically collect and archive files based on a predefined list of file extensions.(Citation: Bitdefender StrongPity June 2020)
- [S1044] FunnyDream: [FunnyDream](https://attack.mitre.org/software/S1044) can monitor files for changes and automatically collect them.(Citation: Bitdefender FunnyDream Campaign November 2020)
- [C0040] APT41 DUST: [APT41 DUST](https://attack.mitre.org/campaigns/C0040) used tools such as SQLULDR2 and PINEGROVE to gather local system and database information.(Citation: Google Cloud APT41 2024)
- [G1035] Winter Vivern: [Winter Vivern](https://attack.mitre.org/groups/G1035) delivered a PowerShell script capable of recursively scanning victim machines looking for various file types before exfiltrating identified files via HTTP.(Citation: CERT-UA WinterVivern 2023)
- [S0438] Attor: [Attor](https://attack.mitre.org/software/S0438) has automatically collected data about the compromised system.(Citation: ESET Attor Oct 2019)
- [G0142] Confucius: [Confucius](https://attack.mitre.org/groups/G0142) has used a file stealer to steal documents and images with the following extensions: txt, pdf, png, jpg, doc, xls, xlm, odp, ods, odt, rtf, ppt, xlsx, xlsm, docx, pptx, and jpeg.(Citation: TrendMicro Confucius APT Aug 2021)
- [C0046] ArcaneDoor: [ArcaneDoor](https://attack.mitre.org/campaigns/C0046) included collection of packet capture and system configuration information.(Citation: CCCS ArcaneDoor 2024)
- [G0049] OilRig: [OilRig](https://attack.mitre.org/groups/G0049) has used automated collection.(Citation: Unit42 OilRig Playbook 2023)
- [S0458] Ramsay: [Ramsay](https://attack.mitre.org/software/S0458) can conduct an initial scan for Microsoft Word documents on the local system, removable media, and connected network drives, before tagging and collecting them. It can continue tagging documents to collect with follow up scans.(Citation: Eset Ramsay May 2020)
- [S1148] Raccoon Stealer: [Raccoon Stealer](https://attack.mitre.org/software/S1148) collects files and directories from victim systems based on configuration data downloaded from command and control servers.(Citation: S2W Racoon 2022)(Citation: Sekoia Raccoon1 2022)(Citation: Sekoia Raccoon2 2022)
- [S0148] RTM: [RTM](https://attack.mitre.org/software/S0148) monitors browsing activity and automatically captures screenshots if a victim browses to a URL matching one of a list of strings.(Citation: ESET RTM Feb 2017)(Citation: Unit42 Redaman January 2019)
- [C0001] Frankenstein: During [Frankenstein](https://attack.mitre.org/campaigns/C0001), the threat actors used [Empire](https://attack.mitre.org/software/S0363) to automatically gather the username, domain name, machine name, and other system information.(Citation: Talos Frankenstein June 2019)
- [G0037] FIN6: [FIN6](https://attack.mitre.org/groups/G0037) has used a script to iterate through a list of compromised PoS systems, copy and remove data to a log file, and to bind to events from the submit payment button.(Citation: FireEye FIN6 April 2016)(Citation: Trend Micro FIN6 October 2019)
- [G0040] Patchwork: [Patchwork](https://attack.mitre.org/groups/G0040) developed a file stealer to search C:\ and collect files with certain extensions. [Patchwork](https://attack.mitre.org/groups/G0040) also executed a script to enumerate all drives, store them as a list, and upload generated files to the C2 server.(Citation: TrendMicro Patchwork Dec 2017)
- [G0081] Tropic Trooper: [Tropic Trooper](https://attack.mitre.org/groups/G0081) has collected information automatically using the adversary's [USBferry](https://attack.mitre.org/software/S0452) attack.(Citation: TrendMicro Tropic Trooper May 2020)
- [G0121] Sidewinder: [Sidewinder](https://attack.mitre.org/groups/G0121) has used tools to automatically collect system and network configuration information.(Citation: ATT Sidewinder January 2021)
- [G0114] Chimera: [Chimera](https://attack.mitre.org/groups/G0114) has used custom DLLs for continuous retrieval of data from memory.(Citation: NCC Group Chimera January 2021)
- [S0597] GoldFinder: [GoldFinder](https://attack.mitre.org/software/S0597) logged and stored information related to the route or hops a packet took from a compromised machine to a hardcoded C2 server, including the target C2 URL, HTTP response/status code, HTTP response headers and values, and data received from the C2 node.(Citation: MSTIC NOBELIUM Mar 2021)
- [G0027] Threat Group-3390: [Threat Group-3390](https://attack.mitre.org/groups/G0027) ran a command to compile an archive of file types of interest from the victim user's directories.(Citation: SecureWorks BRONZE UNION June 2017)
- [S0699] Mythic: [Mythic](https://attack.mitre.org/software/S0699) supports scripting of file downloads from agents.(Citation: Mythc Documentation)
- [S1213] Lumma Stealer: [Lumma Stealer](https://attack.mitre.org/software/S1213) has automated collection of various information including cryptocurrency wallet details.(Citation: Cybereason LumaStealer Undated)
- [G0129] Mustang Panda: [Mustang Panda](https://attack.mitre.org/groups/G0129) used custom batch scripts to collect files automatically from a targeted system.(Citation: Secureworks BRONZE PRESIDENT December 2019)
- [S0260] InvisiMole: [InvisiMole](https://attack.mitre.org/software/S0260) can sort and collect specific documents as well as generate a list of all files on a newly inserted drive and store them in an encrypted file.(Citation: ESET InvisiMole June 2018)(Citation: ESET InvisiMole June 2020)
- [S0538] Crutch: [Crutch](https://attack.mitre.org/software/S0538) can automatically monitor removable drives in a loop and copy interesting files.(Citation: ESET Crutch December 2020)
- [S0170] Helminth: A [Helminth](https://attack.mitre.org/software/S0170) VBScript receives a batch script to execute a set of commands in a command prompt.(Citation: Palo Alto OilRig May 2016)
- [S1078] RotaJakiro: Depending on the Linux distribution, [RotaJakiro](https://attack.mitre.org/software/S1078) executes a set of commands to collect device information and sends the collected information to the C2 server.(Citation: RotaJakiro 2021 netlab360 analysis)
- [S1131] NPPSPY: [NPPSPY](https://attack.mitre.org/software/S1131) collection is automatically recorded to a specified file on the victim machine.(Citation: Huntress NPPSPY 2022)
- [S1091] Pacu: [Pacu](https://attack.mitre.org/software/S1091) can automatically collect data, such as CloudFormation templates, EC2 user data, AWS Inspector reports, and IAM credential reports.(Citation: GitHub Pacu)
- [S0251] Zebrocy: [Zebrocy](https://attack.mitre.org/software/S0251) scans the system and automatically collects files with the following extensions: .doc, .docx, ,.xls, .xlsx, .pdf, .pptx, .rar, .zip, .jpg, .jpeg, .bmp, .tiff, .kum, .tlg, .sbx, .cr, .hse, .hsf, and .lhz.(Citation: ESET Zebrocy Nov 2018)(Citation: ESET Zebrocy May 2019)
- [S1183] StrelaStealer: [StrelaStealer](https://attack.mitre.org/software/S1183) attempts to identify and collect mail login data from Thunderbird and Outlook following execution.(Citation: DCSO StrelaStealer 2022)(Citation: PaloAlto StrelaStealer 2024)(Citation: Fortgale StrelaStealer 2023)(Citation: IBM StrelaStealer 2024)
- [G0045] menuPass: [menuPass](https://attack.mitre.org/groups/G0045) has used the Csvde tool to collect Active Directory files and data.(Citation: Symantec Cicada November 2020)
- [S1101] LoFiSe: [LoFiSe](https://attack.mitre.org/software/S1101) can collect all the files from the working directory every three hours and place them into a password-protected archive for further exfiltration.(Citation: Kaspersky ToddyCat Check Logs October 2023)
- [S0445] ShimRatReporter: [ShimRatReporter](https://attack.mitre.org/software/S0445) gathered information automatically, without instruction from a C2, related to the user and host machine that is compiled into a report and sent to the operators.(Citation: FOX-IT May 2016 Mofang)
- [S0443] MESSAGETAP: [MESSAGETAP](https://attack.mitre.org/software/S0443) checks two files, keyword_parm.txt and parm.txt, for instructions on how to target and save data parsed and extracted from SMS message data from the network traffic. If an SMS message contained either a phone number, IMSI number, or keyword that matched the predefined list, it is saved to a CSV file for later theft by the threat actor.(Citation: FireEye MESSAGETAP October 2019)


### T1123 - Audio Capture

Description:

An adversary can leverage a computer's peripheral devices (e.g., microphones and webcams) or applications (e.g., voice and video call services) to capture audio recordings for the purpose of listening into sensitive conversations to gather information.(Citation: ESET Attor Oct 2019)

Malware or scripts may be used to interact with the devices through an available API provided by the operating system or an application to capture audio. Audio files may be written to disk and exfiltrated later.

Procedures:

- [S0143] Flame: [Flame](https://attack.mitre.org/software/S0143) can record audio using any existing hardware recording devices.(Citation: Kaspersky Flame)(Citation: Kaspersky Flame Functionality)
- [S0240] ROKRAT: [ROKRAT](https://attack.mitre.org/software/S0240) has an audio capture and eavesdropping module.(Citation: Securelist ScarCruft May 2019)
- [S0234] Bandook: [Bandook](https://attack.mitre.org/software/S0234) has modules that are capable of capturing audio.(Citation: EFF Manul Aug 2016)
- [S0194] PowerSploit: [PowerSploit](https://attack.mitre.org/software/S0194)'s <code>Get-MicrophoneAudio</code> Exfiltration module can record system microphone audio.(Citation: GitHub PowerSploit May 2012)(Citation: PowerSploit Documentation)
- [S0257] VERMIN: [VERMIN](https://attack.mitre.org/software/S0257) can perform audio capture.(Citation: Unit 42 VERMIN Jan 2018)
- [S0467] TajMahal: [TajMahal](https://attack.mitre.org/software/S0467) has the ability to capture VoiceIP application audio on an infected host.(Citation: Kaspersky TajMahal April 2019)
- [S0192] Pupy: [Pupy](https://attack.mitre.org/software/S0192) can record sound with the microphone.(Citation: GitHub Pupy)
- [S0152] EvilGrab: [EvilGrab](https://attack.mitre.org/software/S0152) has the capability to capture audio from a victim machine.(Citation: PWC Cloud Hopper Technical Annex April 2017)
- [S1185] LightSpy: [LightSpy](https://attack.mitre.org/software/S1185) uses Apple's built-in AVFoundation Framework library to capture and manage audio recordings then transform them to JSON blobs for exfiltration.(Citation: Huntress LightSpy macOS 2024)
- [S0454] Cadelspy: [Cadelspy](https://attack.mitre.org/software/S0454) has the ability to record audio from the compromised host.(Citation: Symantec Chafer Dec 2015)
- [S0336] NanoCore: [NanoCore](https://attack.mitre.org/software/S0336) can capture audio feeds from the system.(Citation: DigiTrust NanoCore Jan 2017)(Citation: PaloAlto NanoCore Feb 2016)
- [S0115] Crimson: [Crimson](https://attack.mitre.org/software/S0115) can perform audio surveillance using microphones.(Citation: Kaspersky Transparent Tribe August 2020)
- [S1016] MacMa: [MacMa](https://attack.mitre.org/software/S1016) has the ability to record audio.(Citation: Objective-See MacMa Nov 2021)
- [S0098] T9000: [T9000](https://attack.mitre.org/software/S0098) uses the Skype API to record audio and video calls. It writes encrypted data to <code>%APPDATA%\Intel\Skype</code>.(Citation: Palo Alto T9000 Feb 2016)
- [S0409] Machete: [Machete](https://attack.mitre.org/software/S0409) captures audio from the computer’s microphone.(Citation: Securelist Machete Aug 2014)(Citation: Cylance Machete Mar 2017)(Citation: 360 Machete Sep 2020)
- [S0163] Janicab: [Janicab](https://attack.mitre.org/software/S0163) captured audio and sent it out to a C2 server.(Citation: f-secure janicab)(Citation: Janicab)
- [S0338] Cobian RAT: [Cobian RAT](https://attack.mitre.org/software/S0338) has a feature to perform voice recording on the victim’s machine.(Citation: Zscaler Cobian Aug 2017)
- [S0260] InvisiMole: [InvisiMole](https://attack.mitre.org/software/S0260) can record sound using input audio devices.(Citation: ESET InvisiMole June 2018)(Citation: ESET InvisiMole June 2020)
- [S0379] Revenge RAT: [Revenge RAT](https://attack.mitre.org/software/S0379) has a plugin for microphone interception.(Citation: Cylance Shaheen Nov 2018)(Citation: Cofense RevengeRAT Feb 2019)
- [S0021] Derusbi: [Derusbi](https://attack.mitre.org/software/S0021) is capable of performing audio captures.(Citation: FireEye Periscope March 2018)
- [S0334] DarkComet: [DarkComet](https://attack.mitre.org/software/S0334) can listen in to victims' conversations through the system’s microphone.(Citation: TrendMicro DarkComet Sept 2014)(Citation: Malwarebytes DarkComet March 2018)
- [S0282] MacSpy: [MacSpy](https://attack.mitre.org/software/S0282) can record the sounds from microphones on a computer.(Citation: objsee mac malware 2017)
- [S0434] Imminent Monitor: [Imminent Monitor](https://attack.mitre.org/software/S0434) has a remote microphone monitoring capability.(Citation: Imminent Unit42 Dec2019)(Citation: QiAnXin APT-C-36 Feb2019)
- [S0213] DOGCALL: [DOGCALL](https://attack.mitre.org/software/S0213) can capture microphone data from the victim's machine.(Citation: Unit 42 Nokki Oct 2018)
- [S0283] jRAT: [jRAT](https://attack.mitre.org/software/S0283) can capture microphone recordings.(Citation: Kaspersky Adwind Feb 2016)
- [S0332] Remcos: [Remcos](https://attack.mitre.org/software/S0332) can capture data from the system’s microphone.(Citation: Fortinet Remcos Feb 2017)
- [S0339] Micropsia: [Micropsia](https://attack.mitre.org/software/S0339) can perform microphone recording.(Citation: Radware Micropsia July 2018)
- [S1090] NightClub: [NightClub](https://attack.mitre.org/software/S1090) can load a module to leverage the LAME encoder and `mciSendStringW` to control and capture audio.(Citation: MoustachedBouncer ESET August 2023)
- [G0067] APT37: [APT37](https://attack.mitre.org/groups/G0067) has used an audio capturing utility known as SOUNDWAVE that captures microphone input.(Citation: FireEye APT37 Feb 2018)
- [S0438] Attor: [Attor](https://attack.mitre.org/software/S0438)'s has a plugin that is capable of recording audio using available input sound devices.(Citation: ESET Attor Oct 2019)
- [S1146] MgBot: [MgBot](https://attack.mitre.org/software/S1146) can capture input and output audio streams from infected devices.(Citation: ESET EvasivePanda 2023)(Citation: Symantec Daggerfly 2023)


### T1125 - Video Capture

Description:

An adversary can leverage a computer's peripheral devices (e.g., integrated cameras or webcams) or applications (e.g., video call services) to capture video recordings for the purpose of gathering information. Images may also be captured from devices or applications, potentially in specified intervals, in lieu of video files.

Malware or scripts may be used to interact with the devices through an available API provided by the operating system or an application to capture video or images. Video or image files may be written to disk and exfiltrated later. This technique differs from [Screen Capture](https://attack.mitre.org/techniques/T1113) due to use of specific devices or applications for video recording rather than capturing the victim's screen.

In macOS, there are a few different malware samples that record the user's webcam such as FruitFly and Proton. (Citation: objective-see 2017 review)

Procedures:

- [S0363] Empire: [Empire](https://attack.mitre.org/software/S0363) can capture webcam data on Windows and macOS systems.(Citation: Github PowerShell Empire)
- [S0660] Clambling: [Clambling](https://attack.mitre.org/software/S0660) can record screen content in AVI format.(Citation: Trend Micro DRBControl February 2020)(Citation: Talent-Jump Clambling February 2020)
- [S0115] Crimson: [Crimson](https://attack.mitre.org/software/S0115) can capture webcam video on targeted systems.(Citation: Proofpoint Operation Transparent Tribe March 2016)(Citation: Kaspersky Transparent Tribe August 2020)
- [S0467] TajMahal: [TajMahal](https://attack.mitre.org/software/S0467) has the ability to capture webcam video.(Citation: Kaspersky TajMahal April 2019)
- [S0338] Cobian RAT: [Cobian RAT](https://attack.mitre.org/software/S0338) has a feature to access the webcam on the victim’s machine.(Citation: Zscaler Cobian Aug 2017)
- [S0336] NanoCore: [NanoCore](https://attack.mitre.org/software/S0336) can access the victim's webcam and capture data.(Citation: DigiTrust NanoCore Jan 2017)(Citation: PaloAlto NanoCore Feb 2016)
- [S0283] jRAT: [jRAT](https://attack.mitre.org/software/S0283) has the capability to capture video from a webcam.(Citation: jRAT Symantec Aug 2018)(Citation: Kaspersky Adwind Feb 2016)
- [S0409] Machete: [Machete](https://attack.mitre.org/software/S0409) takes photos from the computer’s web camera.(Citation: Securelist Machete Aug 2014)(Citation: Cylance Machete Mar 2017)(Citation: 360 Machete Sep 2020)
- [S0379] Revenge RAT: [Revenge RAT](https://attack.mitre.org/software/S0379) has the ability to access the webcam.(Citation: Cylance Shaheen Nov 2018)(Citation: Cofense RevengeRAT Feb 2019)
- [S0334] DarkComet: [DarkComet](https://attack.mitre.org/software/S0334) can access the victim’s webcam to take pictures.(Citation: TrendMicro DarkComet Sept 2014)(Citation: Malwarebytes DarkComet March 2018)
- [S0385] njRAT: [njRAT](https://attack.mitre.org/software/S0385) can access the victim's webcam.(Citation: Fidelis njRAT June 2013)(Citation: Citizen Lab Group5)
- [S0331] Agent Tesla: [Agent Tesla](https://attack.mitre.org/software/S0331) can access the victim’s webcam and record video.(Citation: DigiTrust Agent Tesla Jan 2017)(Citation: Talos Agent Tesla Oct 2018)
- [G1003] Ember Bear: [Ember Bear](https://attack.mitre.org/groups/G1003) has exfiltrated images from compromised IP cameras.(Citation: CISA GRU29155 2024)
- [S0428] PoetRAT: [PoetRAT](https://attack.mitre.org/software/S0428) has used a Python tool named Bewmac to record the webcam on compromised hosts.(Citation: Talos PoetRAT April 2020)
- [G0091] Silence: [Silence](https://attack.mitre.org/groups/G0091) has been observed making videos of victims to observe bank employees day to day activities.(Citation: SecureList Silence Nov 2017)(Citation: Group IB Silence Sept 2018)
- [S0434] Imminent Monitor: [Imminent Monitor](https://attack.mitre.org/software/S0434) has a remote webcam monitoring capability.(Citation: Imminent Unit42 Dec2019)(Citation: QiAnXin APT-C-36 Feb2019)
- [S0591] ConnectWise: [ConnectWise](https://attack.mitre.org/software/S0591) can record video on remote hosts.(Citation: Anomali Static Kitten February 2021)
- [S0152] EvilGrab: [EvilGrab](https://attack.mitre.org/software/S0152) has the capability to capture video from a victim machine.(Citation: PWC Cloud Hopper Technical Annex April 2017)
- [S0265] Kazuar: [Kazuar](https://attack.mitre.org/software/S0265) captures images from the webcam.(Citation: Unit 42 Kazuar May 2017)
- [S1087] AsyncRAT: [AsyncRAT](https://attack.mitre.org/software/S1087) can record screen content on targeted systems.(Citation: AsyncRAT GitHub)
- [S0461] SDBbot: [SDBbot](https://attack.mitre.org/software/S0461) has the ability to record video on a compromised host.(Citation: Proofpoint TA505 October 2019)(Citation: IBM TA505 April 2020)
- [G0046] FIN7: [FIN7](https://attack.mitre.org/groups/G0046) created a custom video recording capability that could be used to monitor operations in the victim's environment.(Citation: FireEye FIN7 Aug 2018)(Citation: DOJ FIN7 Aug 2018)
- [S1209] Quick Assist: [Quick Assist](https://attack.mitre.org/software/S1209) allows for the remote administrator to view the interactive session of the running machine, including full screen activity.(Citation: Microsoft Quick Assist 2024)(Citation: Microsoft Storm-1811 2024)
- [S0412] ZxShell: [ZxShell](https://attack.mitre.org/software/S0412) has a command to perform video device spying.(Citation: Talos ZxShell Oct 2014)
- [S0670] WarzoneRAT: [WarzoneRAT](https://attack.mitre.org/software/S0670) can access the webcam on a victim's machine.(Citation: Check Point Warzone Feb 2020)(Citation: Uptycs Warzone UAC Bypass November 2020)
- [S0192] Pupy: [Pupy](https://attack.mitre.org/software/S0192) can access a connected webcam and capture pictures.(Citation: GitHub Pupy)
- [S0234] Bandook: [Bandook](https://attack.mitre.org/software/S0234) has modules that are capable of capturing video from a victim's webcam.(Citation: EFF Manul Aug 2016)
- [S0332] Remcos: [Remcos](https://attack.mitre.org/software/S0332) can access a system’s webcam and take pictures.(Citation: Fortinet Remcos Feb 2017)
- [S0260] InvisiMole: [InvisiMole](https://attack.mitre.org/software/S0260) can remotely activate the victim’s webcam to capture content.(Citation: ESET InvisiMole June 2018)(Citation: ESET InvisiMole June 2020)
- [S0021] Derusbi: [Derusbi](https://attack.mitre.org/software/S0021) is capable of capturing video.(Citation: FireEye Periscope March 2018)
- [S0644] ObliqueRAT: [ObliqueRAT](https://attack.mitre.org/software/S0644) can capture images from webcams on compromised hosts.(Citation: Talos Oblique RAT March 2021)
- [S0098] T9000: [T9000](https://attack.mitre.org/software/S0098) uses the Skype API to record audio and video calls. It writes encrypted data to <code>%APPDATA%\Intel\Skype</code>.(Citation: Palo Alto T9000 Feb 2016)
- [S0262] QuasarRAT: [QuasarRAT](https://attack.mitre.org/software/S0262) can perform webcam viewing.(Citation: GitHub QuasarRAT)(Citation: Volexity Patchwork June 2018)
- [S1050] PcShare: [PcShare](https://attack.mitre.org/software/S1050) can capture camera video as part of its collection process.(Citation: Bitdefender FunnyDream Campaign November 2020)


### T1185 - Browser Session Hijacking

Description:

Adversaries may take advantage of security vulnerabilities and inherent functionality in browser software to change content, modify user-behaviors, and intercept information as part of various browser session hijacking techniques.(Citation: Wikipedia Man in the Browser)

A specific example is when an adversary injects software into a browser that allows them to inherit cookies, HTTP sessions, and SSL client certificates of a user then use the browser as a way to pivot into an authenticated intranet.(Citation: Cobalt Strike Browser Pivot)(Citation: ICEBRG Chrome Extensions) Executing browser-based behaviors such as pivoting may require specific process permissions, such as <code>SeDebugPrivilege</code> and/or high-integrity/administrator rights.

Another example involves pivoting browser traffic from the adversary's browser through the user's browser by setting up a proxy which will redirect web traffic. This does not alter the user's traffic in any way, and the proxy connection can be severed as soon as the browser is closed. The adversary assumes the security context of whichever browser process the proxy is injected into. Browsers typically create a new process for each tab that is opened and permissions and certificates are separated accordingly. With these permissions, an adversary could potentially browse to any resource on an intranet, such as [Sharepoint](https://attack.mitre.org/techniques/T1213/002) or webmail, that is accessible through the browser and which the browser has sufficient permissions. Browser pivoting may also bypass security provided by 2-factor authentication.(Citation: cobaltstrike manual)

Procedures:

- [S0266] TrickBot: [TrickBot](https://attack.mitre.org/software/S0266) uses web injects and browser redirection to trick the user into providing their login credentials on a fake or modified web page.(Citation: Fidelis TrickBot Oct 2016)(Citation: IBM TrickBot Nov 2016)(Citation: Microsoft Totbrick Oct 2017)(Citation: Trend Micro Trickbot Nov 2018)
- [S0384] Dridex: [Dridex](https://attack.mitre.org/software/S0384) can perform browser attacks via web injects to steal information such as credentials, certificates, and cookies.(Citation: Dell Dridex Oct 2015)
- [S0484] Carberp: [Carberp](https://attack.mitre.org/software/S0484) has captured credentials when a user performs login through a SSL session.(Citation: Prevx Carberp March 2011)(Citation: Trusteer Carberp October 2010)
- [S1201] TRANSLATEXT: [TRANSLATEXT](https://attack.mitre.org/software/S1201) has the ability to use form-grabbing and event-listening to extract data from web data forms.(Citation: Zscaler Kimsuky TRANSLATEXT)
- [S0530] Melcoz: [Melcoz](https://attack.mitre.org/software/S0530) can monitor the victim's browser for online banking sessions and display an overlay window to manipulate the session in the background.(Citation: Securelist Brazilian Banking Malware July 2020)
- [S0331] Agent Tesla: [Agent Tesla](https://attack.mitre.org/software/S0331) has the ability to use form-grabbing to extract data from web data forms.(Citation: Bitdefender Agent Tesla April 2020)
- [S0531] Grandoreiro: [Grandoreiro](https://attack.mitre.org/software/S0531) can monitor browser activity for online banking actions and display full-screen overlay images to block user access to the intended site or present additional data fields.(Citation: Securelist Brazilian Banking Malware July 2020)(Citation: IBM Grandoreiro April 2020)(Citation: ESET Grandoreiro April 2020)
- [G0094] Kimsuky: [Kimsuky](https://attack.mitre.org/groups/G0094) has the ability to use form-grabbing to extract emails and passwords from web data forms.(Citation: Zscaler Kimsuky TRANSLATEXT)
- [S1207] XLoader: [XLoader](https://attack.mitre.org/software/S1207) can conduct form grabbing, steal cookies, and extract data from HTTP sessions.(Citation: Google XLoader 2017)
- [S0650] QakBot: [QakBot](https://attack.mitre.org/software/S0650) can use advanced web injects to steal web banking credentials.(Citation: Cyberint Qakbot May 2021)(Citation: Kaspersky QakBot September 2021)
- [S0154] Cobalt Strike: [Cobalt Strike](https://attack.mitre.org/software/S0154) can perform browser pivoting and inject into a user's browser to inherit cookies, authenticated HTTP sessions, and client SSL certificates.(Citation: cobaltstrike manual)(Citation: Cobalt Strike Manual 4.3 November 2020)
- [S0483] IcedID: [IcedID](https://attack.mitre.org/software/S0483) has used web injection attacks to redirect victims to spoofed sites designed to harvest banking and other credentials.  [IcedID](https://attack.mitre.org/software/S0483) can use a self signed TLS certificate in connection with the spoofed site and simultaneously maintains a live connection with the legitimate site to display the correct URL and certificates in the browser.(Citation: IBM IcedID November 2017)(Citation: Juniper IcedID June 2020)
- [S0631] Chaes: [Chaes](https://attack.mitre.org/software/S0631) has used the Puppeteer module to hook and monitor the Chrome web browser to collect user information from infected hosts.(Citation: Cybereason Chaes Nov 2020)
- [S0386] Ursnif: [Ursnif](https://attack.mitre.org/software/S0386) has injected HTML codes into banking sites to steal sensitive online banking information (ex: usernames and passwords).(Citation: TrendMicro BKDR_URSNIF.SM)


### T1213 - Data from Information Repositories

Description:

Adversaries may leverage information repositories to mine valuable information. Information repositories are tools that allow for storage of information, typically to facilitate collaboration or information sharing between users, and can store a wide variety of data that may aid adversaries in further objectives, such as Credential Access, Lateral Movement, or Defense Evasion, or direct access to the target information. Adversaries may also abuse external sharing features to share sensitive documents with recipients outside of the organization (i.e., [Transfer Data to Cloud Account](https://attack.mitre.org/techniques/T1537)). 

The following is a brief list of example information that may hold potential value to an adversary and may also be found on an information repository:

* Policies, procedures, and standards
* Physical / logical network diagrams
* System architecture diagrams
* Technical system documentation
* Testing / development credentials (i.e., [Unsecured Credentials](https://attack.mitre.org/techniques/T1552)) 
* Work / project schedules
* Source code snippets
* Links to network shares and other internal resources
* Contact or other sensitive information about business partners and customers, including personally identifiable information (PII) 

Information stored in a repository may vary based on the specific instance or environment. Specific common information repositories include the following:

* Storage services such as IaaS databases, enterprise databases, and more specialized platforms such as customer relationship management (CRM) databases 
* Collaboration platforms such as SharePoint, Confluence, and code repositories
* Messaging platforms such as Slack and Microsoft Teams 

In some cases, information repositories have been improperly secured, typically by unintentionally allowing for overly-broad access by all users or even public access to unauthenticated users. This is particularly common with cloud-native or cloud-hosted services, such as AWS Relational Database Service (RDS), Redis, or ElasticSearch.(Citation: Mitiga)(Citation: TrendMicro Exposed Redis 2020)(Citation: Cybernews Reuters Leak 2022)

Procedures:

- [C0049] Leviathan Australian Intrusions: [Leviathan](https://attack.mitre.org/groups/G0065) gathered information from SQL servers and Building Management System (BMS) servers during [Leviathan Australian Intrusions](https://attack.mitre.org/campaigns/C0049).(Citation: CISA Leviathan 2024)
- [G0034] Sandworm Team: [Sandworm Team](https://attack.mitre.org/groups/G0034) exfiltrates data of interest from enterprise databases using Adminer.(Citation: Leonard TAG 2023)
- [C0040] APT41 DUST: [APT41 DUST](https://attack.mitre.org/campaigns/C0040) collected data from victim Oracle databases using SQLULDR2.(Citation: Google Cloud APT41 2024)
- [G0037] FIN6: [FIN6](https://attack.mitre.org/groups/G0037) has collected schemas and user accounts from systems running SQL Server.(Citation: Visa FIN6 Feb 2019)
- [S1146] MgBot: [MgBot](https://attack.mitre.org/software/S1146) includes a module capable of stealing content from the Tencent QQ database storing user QQ message history on infected devices.(Citation: ESET EvasivePanda 2023)
- [C0024] SolarWinds Compromise: During the [SolarWinds Compromise](https://attack.mitre.org/campaigns/C0024), [APT29](https://attack.mitre.org/groups/G0016) accessed victims' internal knowledge repositories (wikis) to view sensitive corporate information on products, services, and internal business operations.(Citation: CrowdStrike StellarParticle January 2022)
- [S1148] Raccoon Stealer: [Raccoon Stealer](https://attack.mitre.org/software/S1148) gathers information from repositories associated with cryptocurrency wallets and the Telegram messaging service.(Citation: Sekoia Raccoon2 2022)
- [S1196] Troll Stealer: [Troll Stealer](https://attack.mitre.org/software/S1196) gathers information from the Government Public Key Infrastructure (GPKI) folder, associated with South Korean government public key infrastructure, on infected systems.(Citation: S2W Troll Stealer 2024)(Citation: Symantec Troll Stealer 2024)
- [G0007] APT28: [APT28](https://attack.mitre.org/groups/G0007) has collected files from various information repositories.(Citation: Cybersecurity Advisory GRU Brute Force Campaign July 2021)
- [G1041] Sea Turtle: [Sea Turtle](https://attack.mitre.org/groups/G1041) used the tool Adminer to remotely logon to the MySQL service of victim machines.(Citation: Hunt Sea Turtle 2024)
- [G0010] Turla: [Turla](https://attack.mitre.org/groups/G0010) has used a custom .NET tool to collect documents from an organization's internal central database.(Citation: ESET ComRAT May 2020)
- [S0598] P.A.S. Webshell: [P.A.S. Webshell](https://attack.mitre.org/software/S0598) has the ability to list and extract data from SQL databases.(Citation: ANSSI Sandworm January 2021)

#### T1213.001 - Confluence

Description:

Adversaries may leverage Confluence repositories to mine valuable information. Often found in development environments alongside Atlassian JIRA, Confluence is generally used to store development-related documentation, however, in general may contain more diverse categories of useful information, such as:

* Policies, procedures, and standards
* Physical / logical network diagrams
* System architecture diagrams
* Technical system documentation
* Testing / development credentials (i.e., [Unsecured Credentials](https://attack.mitre.org/techniques/T1552))
* Work / project schedules
* Source code snippets
* Links to network shares and other internal resources

Procedures:

- [G1004] LAPSUS$: [LAPSUS$](https://attack.mitre.org/groups/G1004) has searched a victim's network for collaboration platforms like Confluence and JIRA to discover further high-privilege account credentials.(Citation: MSTIC DEV-0537 Mar 2022)

#### T1213.002 - Sharepoint

Description:

Adversaries may leverage the SharePoint repository as a source to mine valuable information. SharePoint will often contain useful information for an adversary to learn about the structure and functionality of the internal network and systems. For example, the following is a list of example information that may hold potential value to an adversary and may also be found on SharePoint:

* Policies, procedures, and standards
* Physical / logical network diagrams
* System architecture diagrams
* Technical system documentation
* Testing / development credentials (i.e., [Unsecured Credentials](https://attack.mitre.org/techniques/T1552))
* Work / project schedules
* Source code snippets
* Links to network shares and other internal resources

Procedures:

- [G1024] Akira: [Akira](https://attack.mitre.org/groups/G1024) has accessed and downloaded information stored in SharePoint instances as part of data gathering and exfiltration activity.(Citation: Secureworks GOLD SAHARA)
- [G0125] HAFNIUM: [HAFNIUM](https://attack.mitre.org/groups/G0125) has abused compromised credentials to exfiltrate data from SharePoint.(Citation: Microsoft Silk Typhoon MAR 2025)
- [G1004] LAPSUS$: [LAPSUS$](https://attack.mitre.org/groups/G1004) has searched a victim's network for collaboration platforms like SharePoint to discover further high-privilege account credentials.(Citation: MSTIC DEV-0537 Mar 2022)(Citation: NCC Group LAPSUS Apr 2022)
- [S0227] spwebmember: [spwebmember](https://attack.mitre.org/software/S0227) is used to enumerate and dump information from Microsoft SharePoint.(Citation: NCC Group APT15 Alive and Strong)
- [G0114] Chimera: [Chimera](https://attack.mitre.org/groups/G0114) has collected documents from the victim's SharePoint.(Citation: NCC Group Chimera January 2021)
- [G0007] APT28: [APT28](https://attack.mitre.org/groups/G0007) has collected information from Microsoft SharePoint services within target networks.(Citation: RSAC 2015 Abu Dhabi Stefano Maccaglia)
- [C0027] C0027: During [C0027](https://attack.mitre.org/campaigns/C0027), [Scattered Spider](https://attack.mitre.org/groups/G1015) accessed victim SharePoint environments to search for VPN and MFA enrollment information, help desk instructions, and new hire guides.(Citation: Crowdstrike TELCO BPO Campaign December 2022)
- [G0004] Ke3chang: [Ke3chang](https://attack.mitre.org/groups/G0004) used a SharePoint enumeration and data dumping tool known as spwebmember.(Citation: NCC Group APT15 Alive and Strong)

#### T1213.003 - Code Repositories

Description:

Adversaries may leverage code repositories to collect valuable information. Code repositories are tools/services that store source code and automate software builds. They may be hosted internally or privately on third party sites such as Github, GitLab, SourceForge, and BitBucket. Users typically interact with code repositories through a web application or command-line utilities such as git.

Once adversaries gain access to a victim network or a private code repository, they may collect sensitive information such as proprietary source code or [Unsecured Credentials](https://attack.mitre.org/techniques/T1552) contained within software's source code.  Having access to software's source code may allow adversaries to develop [Exploits](https://attack.mitre.org/techniques/T1587/004), while credentials may provide access to additional resources using [Valid Accounts](https://attack.mitre.org/techniques/T1078).(Citation: Wired Uber Breach)(Citation: Krebs Adobe)

**Note:** This is distinct from [Code Repositories](https://attack.mitre.org/techniques/T1593/003), which focuses on conducting [Reconnaissance](https://attack.mitre.org/tactics/TA0043) via public code repositories.

Procedures:

- [G1004] LAPSUS$: [LAPSUS$](https://attack.mitre.org/groups/G1004) has searched a victim's network for code repositories like GitLab and GitHub to discover further high-privilege account credentials.(Citation: MSTIC DEV-0537 Mar 2022)(Citation: NCC Group LAPSUS Apr 2022)
- [G1015] Scattered Spider: [Scattered Spider](https://attack.mitre.org/groups/G1015) enumerates data stored within victim code repositories, such as internal GitHub repositories.(Citation: CISA Scattered Spider Advisory November 2023)(Citation: MSTIC Octo Tempest Operations October 2023)
- [C0024] SolarWinds Compromise: During the [SolarWinds Compromise](https://attack.mitre.org/campaigns/C0024), [APT29](https://attack.mitre.org/groups/G0016) downloaded source code from code repositories.(Citation: Microsoft Internal Solorigate Investigation Blog)
- [G0096] APT41: [APT41](https://attack.mitre.org/groups/G0096) cloned victim user Git repositories during intrusions.(Citation: Rostovcev APT41 2021)

#### T1213.004 - Customer Relationship Management Software

Description:

Adversaries may leverage Customer Relationship Management (CRM) software to mine valuable information. CRM software is used to assist organizations in tracking and managing customer interactions, as well as storing customer data.

Once adversaries gain access to a victim organization, they may mine CRM software for customer data. This may include personally identifiable information (PII) such as full names, emails, phone numbers, and addresses, as well as additional details such as purchase histories and IT support interactions. By collecting this data, an adversary may be able to send personalized [Phishing](https://attack.mitre.org/techniques/T1566) emails, engage in SIM swapping, or otherwise target the organization’s customers in ways that enable financial gain or the compromise of additional organizations.(Citation: Bleeping Computer US Cellular Hack 2022)(Citation: Bleeping Computer Mint Mobile Hack 2021)(Citation: Bleeping Computer Bank Hack 2020)

CRM software may be hosted on-premises or in the cloud. Information stored in these solutions may vary based on the specific instance or environment. Examples of CRM software include Microsoft Dynamics 365, Salesforce, Zoho, Zendesk, and HubSpot.

#### T1213.005 - Messaging Applications

Description:

Adversaries may leverage chat and messaging applications, such as Microsoft Teams, Google Chat, and Slack, to mine valuable information.  

The following is a brief list of example information that may hold potential value to an adversary and may also be found on messaging applications: 

* Testing / development credentials (i.e., [Chat Messages](https://attack.mitre.org/techniques/T1552/008)) 
* Source code snippets 
* Links to network shares and other internal resources 
* Proprietary data(Citation: Guardian Grand Theft Auto Leak 2022)
* Discussions about ongoing incident response efforts(Citation: SC Magazine Ragnar Locker 2021)(Citation: Microsoft DEV-0537)

In addition to exfiltrating data from messaging applications, adversaries may leverage data from chat messages in order to improve their targeting - for example, by learning more about an environment or evading ongoing incident response efforts.(Citation: Sentinel Labs NullBulge 2024)(Citation: Permiso Scattered Spider 2023)

Procedures:

- [G0117] Fox Kitten: [Fox Kitten](https://attack.mitre.org/groups/G0117) has accessed victim security and IT environments and Microsoft Teams to mine valuable information.(Citation: CISA AA20-259A Iran-Based Actor September 2020)
- [G1015] Scattered Spider: [Scattered Spider](https://attack.mitre.org/groups/G1015) threat actors search the victim’s Slack and Microsoft Teams for conversations about the intrusion and incident response.(Citation: CISA Scattered Spider Advisory November 2023)
- [G1004] LAPSUS$: [LAPSUS$](https://attack.mitre.org/groups/G1004) has searched a victim's network for organization collaboration channels like MS Teams or Slack to discover further high-privilege account credentials.(Citation: MSTIC DEV-0537 Mar 2022)


### T1530 - Data from Cloud Storage

Description:

Adversaries may access data from cloud storage.

Many IaaS providers offer solutions for online data object storage such as Amazon S3, Azure Storage, and Google Cloud Storage. Similarly, SaaS enterprise platforms such as Office 365 and Google Workspace provide cloud-based document storage to users through services such as OneDrive and Google Drive, while SaaS application providers such as Slack, Confluence, Salesforce, and Dropbox may provide cloud storage solutions as a peripheral or primary use case of their platform. 

In some cases, as with IaaS-based cloud storage, there exists no overarching application (such as SQL or Elasticsearch) with which to interact with the stored objects: instead, data from these solutions is retrieved directly though the [Cloud API](https://attack.mitre.org/techniques/T1059/009). In SaaS applications, adversaries may be able to collect this data directly from APIs or backend cloud storage objects, rather than through their front-end application or interface (i.e., [Data from Information Repositories](https://attack.mitre.org/techniques/T1213)). 

Adversaries may collect sensitive data from these cloud storage solutions. Providers typically offer security guides to help end users configure systems, though misconfigurations are a common problem.(Citation: Amazon S3 Security, 2019)(Citation: Microsoft Azure Storage Security, 2019)(Citation: Google Cloud Storage Best Practices, 2019) There have been numerous incidents where cloud storage has been improperly secured, typically by unintentionally allowing public access to unauthenticated users, overly-broad access by all users, or even access for any anonymous person outside the control of the Identity Access Management system without even needing basic user permissions.

This open access may expose various types of sensitive data, such as credit cards, personally identifiable information, or medical records.(Citation: Trend Micro S3 Exposed PII, 2017)(Citation: Wired Magecart S3 Buckets, 2019)(Citation: HIPAA Journal S3 Breach, 2017)(Citation: Rclone-mega-extortion_05_2021)

Adversaries may also obtain then abuse leaked credentials from source repositories, logs, or other means as a way to gain access to cloud storage objects.

Procedures:

- [G0117] Fox Kitten: [Fox Kitten](https://attack.mitre.org/groups/G0117) has obtained files from the victim's cloud storage instances.(Citation: CISA AA20-259A Iran-Based Actor September 2020)
- [S0683] Peirates: [Peirates](https://attack.mitre.org/software/S0683) can dump the contents of AWS S3 buckets. It can also retrieve service account tokens from kOps buckets in Google Cloud Storage or S3.(Citation: Peirates GitHub)
- [G1044] APT42: [APT42](https://attack.mitre.org/groups/G1044) has collected data from Microsoft 365 environments.(Citation: Mandiant APT42-untangling)(Citation: Mandiant APT42-charms)
- [G0125] HAFNIUM: [HAFNIUM](https://attack.mitre.org/groups/G0125) has exfitrated data from OneDrive.(Citation: Microsoft Silk Typhoon MAR 2025)
- [G1015] Scattered Spider: [Scattered Spider](https://attack.mitre.org/groups/G1015) enumerates data stored in cloud resources for collection and exfiltration purposes.(Citation: CISA Scattered Spider Advisory November 2023)
- [S1091] Pacu: [Pacu](https://attack.mitre.org/software/S1091) can enumerate and download files stored in AWS storage services, such as S3 buckets.(Citation: GitHub Pacu)
- [C0027] C0027: During [C0027](https://attack.mitre.org/campaigns/C0027), [Scattered Spider](https://attack.mitre.org/groups/G1015) accessed victim OneDrive environments to search for VPN and MFA enrollment information, help desk instructions, and new hire guides.(Citation: Crowdstrike TELCO BPO Campaign December 2022)
- [S0677] AADInternals: AADInternals can collect files from a user’s OneDrive.(Citation: AADInternals)


### T1557 - Adversary-in-the-Middle

Description:

Adversaries may attempt to position themselves between two or more networked devices using an adversary-in-the-middle (AiTM) technique to support follow-on behaviors such as [Network Sniffing](https://attack.mitre.org/techniques/T1040), [Transmitted Data Manipulation](https://attack.mitre.org/techniques/T1565/002), or replay attacks ([Exploitation for Credential Access](https://attack.mitre.org/techniques/T1212)). By abusing features of common networking protocols that can determine the flow of network traffic (e.g. ARP, DNS, LLMNR, etc.), adversaries may force a device to communicate through an adversary controlled system so they can collect information or perform additional actions.(Citation: Rapid7 MiTM Basics)

For example, adversaries may manipulate victim DNS settings to enable other malicious activities such as preventing/redirecting users from accessing legitimate sites and/or pushing additional malware.(Citation: ttint_rat)(Citation: dns_changer_trojans)(Citation: ad_blocker_with_miner) Adversaries may also manipulate DNS and leverage their position in order to intercept user credentials, including access tokens ([Steal Application Access Token](https://attack.mitre.org/techniques/T1528)) and session cookies ([Steal Web Session Cookie](https://attack.mitre.org/techniques/T1539)).(Citation: volexity_0day_sophos_FW)(Citation: Token tactics) [Downgrade Attack](https://attack.mitre.org/techniques/T1562/010)s can also be used to establish an AiTM position, such as by negotiating a less secure, deprecated, or weaker version of communication protocol (SSL/TLS) or encryption algorithm.(Citation: mitm_tls_downgrade_att)(Citation: taxonomy_downgrade_att_tls)(Citation: tlseminar_downgrade_att)

Adversaries may also leverage the AiTM position to attempt to monitor and/or modify traffic, such as in [Transmitted Data Manipulation](https://attack.mitre.org/techniques/T1565/002). Adversaries can setup a position similar to AiTM to prevent traffic from flowing to the appropriate destination, potentially to [Impair Defenses](https://attack.mitre.org/techniques/T1562) and/or in support of a [Network Denial of Service](https://attack.mitre.org/techniques/T1498).

Procedures:

- [S0281] Dok: [Dok](https://attack.mitre.org/software/S0281) proxies web traffic to potentially monitor and alter victim HTTP(S) traffic.(Citation: objsee mac malware 2017)(Citation: CheckPoint Dok)
- [G0094] Kimsuky: [Kimsuky](https://attack.mitre.org/groups/G0094) has used modified versions of PHProxy to examine web traffic between the victim and the accessed website.(Citation: CISA AA20-301A Kimsuky)
- [C0046] ArcaneDoor: [ArcaneDoor](https://attack.mitre.org/campaigns/C0046) included interception of HTTP traffic to victim devices to identify and parse command and control information sent to the device.(Citation: Cisco ArcaneDoor 2024)
- [S1131] NPPSPY: [NPPSPY](https://attack.mitre.org/software/S1131) opens a new network listener for the <code>mpnotify.exe</code> process that is typically contacted by the Winlogon process in Windows. A new, alternative RPC channel is set up with a malicious DLL recording plaintext credentials entered into Winlogon, effectively intercepting and redirecting the logon information.(Citation: Huntress NPPSPY 2022)
- [S1188] Line Runner: [Line Runner](https://attack.mitre.org/software/S1188) intercepts HTTP requests to the victim Cisco ASA, looking for a request with a 32-character, victim dependent parameter. If that parameter matches a value in the malware, a contained payload is then written to a Lua script and executed.(Citation: Cisco ArcaneDoor 2024)
- [G1041] Sea Turtle: [Sea Turtle](https://attack.mitre.org/groups/G1041) modified DNS records at service providers to redirect traffic from legitimate resources to [Sea Turtle](https://attack.mitre.org/groups/G1041)-controlled servers to enable adversary-in-the-middle attacks for credential capture.(Citation: Talos Sea Turtle 2019)(Citation: Talos Sea Turtle 2019_2)

#### T1557.001 - LLMNR/NBT-NS Poisoning and SMB Relay

Description:

By responding to LLMNR/NBT-NS network traffic, adversaries may spoof an authoritative source for name resolution to force communication with an adversary controlled system. This activity may be used to collect or relay authentication materials. 

Link-Local Multicast Name Resolution (LLMNR) and NetBIOS Name Service (NBT-NS) are Microsoft Windows components that serve as alternate methods of host identification. LLMNR is based upon the Domain Name System (DNS) format and allows hosts on the same local link to perform name resolution for other hosts. NBT-NS identifies systems on a local network by their NetBIOS name. (Citation: Wikipedia LLMNR)(Citation: TechNet NetBIOS)

Adversaries can spoof an authoritative source for name resolution on a victim network by responding to LLMNR (UDP 5355)/NBT-NS (UDP 137) traffic as if they know the identity of the requested host, effectively poisoning the service so that the victims will communicate with the adversary controlled system. If the requested host belongs to a resource that requires identification/authentication, the username and NTLMv2 hash will then be sent to the adversary controlled system. The adversary can then collect the hash information sent over the wire through tools that monitor the ports for traffic or through [Network Sniffing](https://attack.mitre.org/techniques/T1040) and crack the hashes offline through [Brute Force](https://attack.mitre.org/techniques/T1110) to obtain the plaintext passwords.

In some cases where an adversary has access to a system that is in the authentication path between systems or when automated scans that use credentials attempt to authenticate to an adversary controlled system, the NTLMv1/v2 hashes can be intercepted and relayed to access and execute code against a target system. The relay step can happen in conjunction with poisoning but may also be independent of it.(Citation: byt3bl33d3r NTLM Relaying)(Citation: Secure Ideas SMB Relay) Additionally, adversaries may encapsulate the NTLMv1/v2 hashes into various protocols, such as LDAP, SMB, MSSQL and HTTP, to expand and use multiple services with the valid NTLM response. 

Several tools may be used to poison name services within local networks such as NBNSpoof, Metasploit, and [Responder](https://attack.mitre.org/software/S0174).(Citation: GitHub NBNSpoof)(Citation: Rapid7 LLMNR Spoofer)(Citation: GitHub Responder)

Procedures:

- [S0357] Impacket: [Impacket](https://attack.mitre.org/software/S0357) modules like ntlmrelayx and smbrelayx can be used in conjunction with [Network Sniffing](https://attack.mitre.org/techniques/T1040) and [LLMNR/NBT-NS Poisoning and SMB Relay](https://attack.mitre.org/techniques/T1557/001) to gather NetNTLM credentials for [Brute Force](https://attack.mitre.org/techniques/T1110) or relay attacks that can gain code execution.(Citation: Impacket Tools)
- [S0363] Empire: [Empire](https://attack.mitre.org/software/S0363) can use Inveigh to conduct name service poisoning for credential theft and associated relay attacks.(Citation: Github PowerShell Empire)(Citation: GitHub Inveigh)
- [S0378] PoshC2: [PoshC2](https://attack.mitre.org/software/S0378) can use Inveigh to conduct name service poisoning for credential theft and associated relay attacks.(Citation: GitHub PoshC2)
- [G0032] Lazarus Group: [Lazarus Group](https://attack.mitre.org/groups/G0032) executed [Responder](https://attack.mitre.org/software/S0174) using the command <code>[Responder file path] -i [IP address] -rPv</code> on a compromised host to harvest credentials and move laterally.(Citation: Kaspersky ThreatNeedle Feb 2021)
- [G0102] Wizard Spider: [Wizard Spider](https://attack.mitre.org/groups/G0102) has used the Invoke-Inveigh PowerShell cmdlets, likely for name service poisoning.(Citation: FireEye KEGTAP SINGLEMALT October 2020)
- [S0192] Pupy: [Pupy](https://attack.mitre.org/software/S0192) can sniff plaintext network credentials and use NBNS Spoofing to poison name services.(Citation: GitHub Pupy)
- [S0174] Responder: [Responder](https://attack.mitre.org/software/S0174) is used to poison name services to gather hashes and credentials from systems within a local network.(Citation: GitHub Responder)

#### T1557.002 - ARP Cache Poisoning

Description:

Adversaries may poison Address Resolution Protocol (ARP) caches to position themselves between the communication of two or more networked devices. This activity may be used to enable follow-on behaviors such as [Network Sniffing](https://attack.mitre.org/techniques/T1040) or [Transmitted Data Manipulation](https://attack.mitre.org/techniques/T1565/002).

The ARP protocol is used to resolve IPv4 addresses to link layer addresses, such as a media access control (MAC) address.(Citation: RFC826 ARP) Devices in a local network segment communicate with each other by using link layer addresses. If a networked device does not have the link layer address of a particular networked device, it may send out a broadcast ARP request to the local network to translate the IP address to a MAC address. The device with the associated IP address directly replies with its MAC address. The networked device that made the ARP request will then use as well as store that information in its ARP cache.

An adversary may passively wait for an ARP request to poison the ARP cache of the requesting device. The adversary may reply with their MAC address, thus deceiving the victim by making them believe that they are communicating with the intended networked device. For the adversary to poison the ARP cache, their reply must be faster than the one made by the legitimate IP address owner. Adversaries may also send a gratuitous ARP reply that maliciously announces the ownership of a particular IP address to all the devices in the local network segment.

The ARP protocol is stateless and does not require authentication. Therefore, devices may wrongly add or update the MAC address of the IP address in their ARP cache.(Citation: Sans ARP Spoofing Aug 2003)(Citation: Cylance Cleaver)

Adversaries may use ARP cache poisoning as a means to intercept network traffic. This activity may be used to collect and/or relay data such as credentials, especially those sent over an insecure, unencrypted protocol.(Citation: Sans ARP Spoofing Aug 2003)

Procedures:

- [G0003] Cleaver: [Cleaver](https://attack.mitre.org/groups/G0003) has used custom tools to facilitate ARP cache poisoning.(Citation: Cylance Cleaver)
- [G1014] LuminousMoth: [LuminousMoth](https://attack.mitre.org/groups/G1014) has used ARP spoofing to redirect a compromised machine to an actor-controlled website.(Citation: Bitdefender LuminousMoth July 2021)

#### T1557.003 - DHCP Spoofing

Description:

Adversaries may redirect network traffic to adversary-owned systems by spoofing Dynamic Host Configuration Protocol (DHCP) traffic and acting as a malicious DHCP server on the victim network. By achieving the adversary-in-the-middle (AiTM) position, adversaries may collect network communications, including passed credentials, especially those sent over insecure, unencrypted protocols. This may also enable follow-on behaviors such as [Network Sniffing](https://attack.mitre.org/techniques/T1040) or [Transmitted Data Manipulation](https://attack.mitre.org/techniques/T1565/002).

DHCP is based on a client-server model and has two functionalities: a protocol for providing network configuration settings from a DHCP server to a client and a mechanism for allocating network addresses to clients.(Citation: rfc2131) The typical server-client interaction is as follows: 

1. The client broadcasts a `DISCOVER` message.

2. The server responds with an `OFFER` message, which includes an available network address. 

3. The client broadcasts a `REQUEST` message, which includes the network address offered. 

4. The server acknowledges with an `ACK` message and the client receives the network configuration parameters.

Adversaries may spoof as a rogue DHCP server on the victim network, from which legitimate hosts may receive malicious network configurations. For example, malware can act as a DHCP server and provide adversary-owned DNS servers to the victimized computers.(Citation: new_rogue_DHCP_serv_malware)(Citation: w32.tidserv.g) Through the malicious network configurations, an adversary may achieve the AiTM position, route client traffic through adversary-controlled systems, and collect information from the client network.

DHCPv6 clients can receive network configuration information without being assigned an IP address by sending a <code>INFORMATION-REQUEST (code 11)</code> message to the <code>All_DHCP_Relay_Agents_and_Servers</code> multicast address.(Citation: rfc3315) Adversaries may use their rogue DHCP server to respond to this request message with malicious network configurations.

Rather than establishing an AiTM position, adversaries may also abuse DHCP spoofing to perform a DHCP exhaustion attack (i.e, [Service Exhaustion Flood](https://attack.mitre.org/techniques/T1499/002)) by generating many broadcast DISCOVER messages to exhaust a network’s DHCP allocation pool.

#### T1557.004 - Evil Twin

Description:

Adversaries may host seemingly genuine Wi-Fi access points to deceive users into connecting to malicious networks as a way of supporting follow-on behaviors such as [Network Sniffing](https://attack.mitre.org/techniques/T1040), [Transmitted Data Manipulation](https://attack.mitre.org/techniques/T1565/002), or [Input Capture](https://attack.mitre.org/techniques/T1056).(Citation: Australia ‘Evil Twin’)

By using a Service Set Identifier (SSID) of a legitimate Wi-Fi network, fraudulent Wi-Fi access points may trick devices or users into connecting to malicious Wi-Fi networks.(Citation: Kaspersky evil twin)(Citation: medium evil twin)  Adversaries may provide a stronger signal strength or block access to Wi-Fi access points to coerce or entice victim devices into connecting to malicious networks.(Citation: specter ops evil twin)  A Wi-Fi Pineapple – a network security auditing and penetration testing tool – may be deployed in Evil Twin attacks for ease of use and broader range. Custom certificates may be used in an attempt to intercept HTTPS traffic. 

Similarly, adversaries may also listen for client devices sending probe requests for known or previously connected networks (Preferred Network Lists or PNLs). When a malicious access point receives a probe request, adversaries can respond with the same SSID to imitate the trusted, known network.(Citation: specter ops evil twin)  Victim devices are led to believe the responding access point is from their PNL and initiate a connection to the fraudulent network.

Upon logging into the malicious Wi-Fi access point, a user may be directed to a fake login page or captive portal webpage to capture the victim’s credentials. Once a user is logged into the fraudulent Wi-Fi network, the adversary may able to monitor network activity, manipulate data, or steal additional credentials. Locations with high concentrations of public Wi-Fi access, such as airports, coffee shops, or libraries, may be targets for adversaries to set up illegitimate Wi-Fi access points.

Procedures:

- [G0007] APT28: [APT28](https://attack.mitre.org/groups/G0007) has used a Wi-Fi Pineapple to set up Evil Twin Wi-Fi Poisoning for the purposes of capturing victim credentials or planting espionage-oriented malware.(Citation: US District Court Indictment GRU Oct 2018)


### T1560 - Archive Collected Data

Description:

An adversary may compress and/or encrypt data that is collected prior to exfiltration. Compressing the data can help to obfuscate the collected data and minimize the amount of data sent over the network.(Citation: DOJ GRU Indictment Jul 2018) Encryption can be used to hide information that is being exfiltrated from detection or make exfiltration less conspicuous upon inspection by a defender.

Both compression and encryption are done prior to exfiltration, and can be performed using a utility, 3rd party library, or custom method.

Procedures:

- [G0035] Dragonfly: [Dragonfly](https://attack.mitre.org/groups/G0035) has compressed data into .zip files prior to exfiltration.(Citation: US-CERT TA18-074A)
- [S0667] Chrommme: [Chrommme](https://attack.mitre.org/software/S0667) can encrypt and store on disk collected data before exfiltration.(Citation: ESET Gelsemium June 2021)
- [G0040] Patchwork: [Patchwork](https://attack.mitre.org/groups/G0040) encrypted the collected files' path with AES and then encoded them with base64.(Citation: TrendMicro Patchwork Dec 2017)
- [S0343] Exaramel for Windows: [Exaramel for Windows](https://attack.mitre.org/software/S0343) automatically encrypts files before sending them to the C2 server.(Citation: ESET TeleBots Oct 2018)
- [S0586] TAINTEDSCRIBE: [TAINTEDSCRIBE](https://attack.mitre.org/software/S0586) has used <code>FileReadZipSend</code> to compress a file and send to C2.(Citation: CISA MAR-10288834-2.v1  TAINTEDSCRIBE MAY 2020)
- [G0001] Axiom: [Axiom](https://attack.mitre.org/groups/G0001) has compressed and encrypted data prior to exfiltration.(Citation: Novetta-Axiom)
- [S1101] LoFiSe: [LoFiSe](https://attack.mitre.org/software/S1101) can collect files into password-protected ZIP-archives for exfiltration.(Citation: Kaspersky ToddyCat Check Logs October 2023)
- [S0521] BloodHound: [BloodHound](https://attack.mitre.org/software/S0521) can compress data collected by its SharpHound ingestor into a ZIP file to be written to disk.(Citation: GitHub Bloodhound)(Citation: Trend Micro Black Basta October 2022)
- [S0045] ADVSTORESHELL: [ADVSTORESHELL](https://attack.mitre.org/software/S0045) encrypts with the 3DES algorithm and a hardcoded key prior to exfiltration.(Citation: ESET Sednit Part 2)
- [G1003] Ember Bear: [Ember Bear](https://attack.mitre.org/groups/G1003) has compressed collected data prior to exfiltration.(Citation: CISA GRU29155 2024)
- [S0363] Empire: [Empire](https://attack.mitre.org/software/S0363) can ZIP directories on the target system.(Citation: Github PowerShell Empire)
- [S1039] Bumblebee: [Bumblebee](https://attack.mitre.org/software/S1039) can compress data stolen from the Registry and volume shadow copies prior to exfiltration.(Citation: Cybereason Bumblebee August 2022)
- [S0515] WellMail: [WellMail](https://attack.mitre.org/software/S0515) can archive files on the compromised host.(Citation: CISA WellMail July 2020)
- [G1043] BlackByte: [BlackByte](https://attack.mitre.org/groups/G1043) compressed data collected from victim environments prior to exfiltration.(Citation: Picus BlackByte 2022)
- [G0032] Lazarus Group: [Lazarus Group](https://attack.mitre.org/groups/G0032) has compressed exfiltrated data with RAR and used RomeoDelta malware to archive specified directories in .zip format, encrypt the .zip file, and upload it to C2. (Citation: Novetta Blockbuster Loaders)(Citation: Novetta Blockbuster RATs)(Citation: McAfee Lazarus Resurfaces Feb 2018)
- [S0454] Cadelspy: [Cadelspy](https://attack.mitre.org/software/S0454) has the ability to compress stolen data into a .cab file.(Citation: Symantec Chafer Dec 2015)
- [S1140] Spica: [Spica](https://attack.mitre.org/software/S1140) can archive collected documents for exfiltration.(Citation: Google TAG COLDRIVER January 2024)
- [S0395] LightNeuron: [LightNeuron](https://attack.mitre.org/software/S0395) contains a function to encrypt and store emails that it collects.(Citation: ESET LightNeuron May 2019)
- [S1196] Troll Stealer: [Troll Stealer](https://attack.mitre.org/software/S1196) compresses stolen data prior to exfiltration.(Citation: S2W Troll Stealer 2024)
- [G0007] APT28: [APT28](https://attack.mitre.org/groups/G0007) used a publicly available tool to gather and compress multiple documents on the DCCC and DNC networks.(Citation: DOJ GRU Indictment Jul 2018)
- [S0257] VERMIN: [VERMIN](https://attack.mitre.org/software/S0257) encrypts the collected files using 3-DES.(Citation: Unit 42 VERMIN Jan 2018)
- [S0445] ShimRatReporter: [ShimRatReporter](https://attack.mitre.org/software/S0445) used LZ compression to compress initial reconnaissance reports before sending to the C2.(Citation: FOX-IT May 2016 Mofang)
- [G0050] APT32: [APT32](https://attack.mitre.org/groups/G0050)'s backdoor has used LZMA compression and RC4 encryption before exfiltration.(Citation: ESET OceanLotus Mar 2019)
- [S0658] XCSSET: [XCSSET](https://attack.mitre.org/software/S0658) will compress entire <code>~/Desktop</code> folders excluding all <code>.git</code> folders, but only if the total data size is under 200MB.(Citation: trendmicro xcsset xcode project 2020)
- [S0249] Gold Dragon: [Gold Dragon](https://attack.mitre.org/software/S0249) encrypts data using Base64 before being sent to the command and control server.(Citation: McAfee Gold Dragon)
- [S0356] KONNI: [KONNI](https://attack.mitre.org/software/S0356) has encrypted data and files prior to exfiltration.(Citation: Malwarebytes Konni Aug 2021)
- [S1148] Raccoon Stealer: [Raccoon Stealer](https://attack.mitre.org/software/S1148) archives collected system information in a text f ile, `System info.txt`, prior to exfiltration.(Citation: Sekoia Raccoon2 2022)
- [S0198] NETWIRE: [NETWIRE](https://attack.mitre.org/software/S0198) has the ability to compress archived screenshots.(Citation: Red Canary NETWIRE January 2020)
- [S1012] PowerLess: [PowerLess](https://attack.mitre.org/software/S1012) can encrypt browser database files prior to exfiltration.(Citation: Cybereason PowerLess February 2022)
- [S0091] Epic: [Epic](https://attack.mitre.org/software/S0091) encrypts collected data using a public key framework before sending it over the C2 channel.(Citation: Kaspersky Turla) Some variants encrypt the collected data with AES and encode it with base64 before transmitting it to the C2 server.(Citation: Kaspersky Turla Aug 2014)
- [S0487] Kessel: [Kessel](https://attack.mitre.org/software/S0487) can RC4-encrypt credentials before sending to the C2.(Citation: ESET ForSSHe December 2018)
- [S0251] Zebrocy: [Zebrocy](https://attack.mitre.org/software/S0251)  has used a method similar to RC4 as well as AES for encryption and hexadecimal for encoding data before exfiltration. (Citation: Securelist Sofacy Feb 2018)(Citation: ESET Zebrocy Nov 2018)(Citation: CISA Zebrocy Oct 2020)
- [G0037] FIN6: Following data collection, [FIN6](https://attack.mitre.org/groups/G0037) has compressed log files into a ZIP archive prior to staging and exfiltration.(Citation: FireEye FIN6 April 2016)
- [S0010] Lurid: [Lurid](https://attack.mitre.org/software/S0010) can compress data before sending it.(Citation: Villeneuve 2011)
- [S0622] AppleSeed: [AppleSeed](https://attack.mitre.org/software/S0622) has compressed collected data before exfiltration.(Citation: KISA Operation Muzabi)
- [S1206] JumbledPath: [JumbledPath](https://attack.mitre.org/software/S1206) can compress and encrypt exfiltrated packet captures from targeted devices.(Citation: Cisco Salt Typhoon FEB 2025)
- [G1014] LuminousMoth: [LuminousMoth](https://attack.mitre.org/groups/G1014) has manually archived stolen files from victim machines before exfiltration.(Citation: Bitdefender LuminousMoth July 2021)
- [S0093] Backdoor.Oldrea: [Backdoor.Oldrea](https://attack.mitre.org/software/S0093) writes collected data to a temporary file in an encrypted form before exfiltration to a C2 server.(Citation: Symantec Dragonfly)
- [S0657] BLUELIGHT: [BLUELIGHT](https://attack.mitre.org/software/S0657) can zip files before exfiltration.(Citation: Volexity InkySquid BLUELIGHT August 2021)
- [S0267] FELIXROOT: [FELIXROOT](https://attack.mitre.org/software/S0267) encrypts collected data with AES and Base64 and then sends it to the C2 server.(Citation: FireEye FELIXROOT July 2018)
- [G0004] Ke3chang: The [Ke3chang](https://attack.mitre.org/groups/G0004) group has been known to compress data before exfiltration.(Citation: Mandiant Operation Ke3chang November 2014)
- [S0375] Remexi: [Remexi](https://attack.mitre.org/software/S0375) encrypts and adds all gathered browser data into files for upload to C2.(Citation: Securelist Remexi Jan 2019)
- [S0253] RunningRAT: [RunningRAT](https://attack.mitre.org/software/S0253) contains code to compress files.(Citation: McAfee Gold Dragon)
- [S0409] Machete: [Machete](https://attack.mitre.org/software/S0409) stores zipped files with profile data from installed web browsers.(Citation: ESET Machete July 2019)
- [S0331] Agent Tesla: [Agent Tesla](https://attack.mitre.org/software/S0331) can encrypt data with 3DES before sending it over to a C2 server.(Citation: Talos Agent Tesla Oct 2018)
- [S0567] Dtrack: [Dtrack](https://attack.mitre.org/software/S0567) packs collected data into a password protected archive.(Citation: Securelist Dtrack)
- [G0045] menuPass: [menuPass](https://attack.mitre.org/groups/G0045) has encrypted files and information before exfiltration.(Citation: DOJ APT10 Dec 2018)(Citation: District Court of NY APT10 Indictment December 2018)
- [S0187] Daserf: [Daserf](https://attack.mitre.org/software/S0187) hides collected data in password-protected .rar archives.(Citation: Symantec Tick Apr 2016)
- [G0065] Leviathan: [Leviathan](https://attack.mitre.org/groups/G0065) has archived victim's data prior to exfiltration.(Citation: CISA AA21-200A APT40 July 2021)
- [S0279] Proton: [Proton](https://attack.mitre.org/software/S0279) zips up files before exfiltrating them.(Citation: objsee mac malware 2017)
- [S0517] Pillowmint: [Pillowmint](https://attack.mitre.org/software/S0517) has encrypted stolen credit card information with AES and further encoded it with Base64.(Citation: Trustwave Pillowmint June 2020)
- [S0456] Aria-body: [Aria-body](https://attack.mitre.org/software/S0456) has used ZIP to compress data gathered on a compromised host.(Citation: CheckPoint Naikon May 2020)
- [S0113] Prikormka: After collecting documents from removable media, [Prikormka](https://attack.mitre.org/software/S0113) compresses the collected files, and encrypts it with Blowfish.(Citation: ESET Operation Groundbait)
- [S0681] Lizar: [Lizar](https://attack.mitre.org/software/S0681) has encrypted data before sending it to the server.(Citation: BiZone Lizar May 2021)

#### T1560.001 - Archive via Utility

Description:

Adversaries may use utilities to compress and/or encrypt collected data prior to exfiltration. Many utilities include functionalities to compress, encrypt, or otherwise package data into a format that is easier/more secure to transport.

Adversaries may abuse various utilities to compress or encrypt data before exfiltration. Some third party utilities may be preinstalled, such as <code>tar</code> on Linux and macOS or <code>zip</code> on Windows systems. 

On Windows, <code>diantz</code> or <code> makecab</code> may be used to package collected files into a cabinet (.cab) file. <code>diantz</code> may also be used to download and compress files from remote locations (i.e. [Remote Data Staging](https://attack.mitre.org/techniques/T1074/002)).(Citation: diantz.exe_lolbas) <code>xcopy</code> on Windows can copy files and directories with a variety of options. Additionally, adversaries may use [certutil](https://attack.mitre.org/software/S0160) to Base64 encode collected data before exfiltration. 

Adversaries may use also third party utilities, such as 7-Zip, WinRAR, and WinZip, to perform similar activities.(Citation: 7zip Homepage)(Citation: WinRAR Homepage)(Citation: WinZip Homepage)

Procedures:

- [S0538] Crutch: [Crutch](https://attack.mitre.org/software/S0538) has used the WinRAR utility to compress and encrypt stolen files.(Citation: ESET Crutch December 2020)
- [S0439] Okrum: [Okrum](https://attack.mitre.org/software/S0439) was seen using a RAR archiver tool to compress/decompress data.(Citation: ESET Okrum July 2019)
- [G0125] HAFNIUM: [HAFNIUM](https://attack.mitre.org/groups/G0125) has used 7-Zip and WinRAR to compress stolen files for exfiltration.(Citation: Microsoft HAFNIUM March 2020)(Citation: Volexity Exchange Marauder March 2021)
- [S0160] certutil: [certutil](https://attack.mitre.org/software/S0160) may be used to Base64 encode collected data.(Citation: TechNet Certutil)(Citation: LOLBAS Certutil)
- [C0012] Operation CuckooBees: During [Operation CuckooBees](https://attack.mitre.org/campaigns/C0012), the threat actors used the Makecab utility to compress and a version of WinRAR to create password-protected archives of stolen data prior to exfiltration.(Citation: Cybereason OperationCuckooBees May 2022)
- [G0045] menuPass: [menuPass](https://attack.mitre.org/groups/G0045) has compressed files before exfiltration using TAR and RAR.(Citation: PWC Cloud Hopper April 2017)(Citation: PWC Cloud Hopper Technical Annex April 2017)(Citation: Symantec Cicada November 2020)
- [G0102] Wizard Spider: [Wizard Spider](https://attack.mitre.org/groups/G0102) has archived data into ZIP files on compromised machines.(Citation: Mandiant FIN12 Oct 2021)
- [G0064] APT33: [APT33](https://attack.mitre.org/groups/G0064) has used WinRAR to compress data prior to exfil.(Citation: Symantec Elfin Mar 2019)
- [C0051] APT28 Nearest Neighbor Campaign: During [APT28 Nearest Neighbor Campaign](https://attack.mitre.org/campaigns/C0051), [APT28](https://attack.mitre.org/groups/G0007) used built-in PowerShell capabilities (<code>Compress-Archive</code> cmdlet) to compress collected data.(Citation: Nearest Neighbor Volexity)
- [S1043] ccf32: [ccf32](https://attack.mitre.org/software/S1043) has used `xcopy \\<target_host>\c$\users\public\path.7z c:\users\public\bin\<target_host>.7z /H /Y` to archive collected files.(Citation: Bitdefender FunnyDream Campaign November 2020)
- [G0117] Fox Kitten: [Fox Kitten](https://attack.mitre.org/groups/G0117) has used 7-Zip to archive data.(Citation: CISA AA20-259A Iran-Based Actor September 2020)
- [G0052] CopyKittens: [CopyKittens](https://attack.mitre.org/groups/G0052) uses ZPP, a .NET console program, to compress files with ZIP.(Citation: ClearSky Wilted Tulip July 2017)
- [G1017] Volt Typhoon: [Volt Typhoon](https://attack.mitre.org/groups/G1017) has archived the ntds.dit database as a multi-volume password-protected archive with 7-Zip.(Citation: Secureworks BRONZE SILHOUETTE May 2023)(Citation: CISA AA24-038A PRC Critical Infrastructure February 2024)
- [S0260] InvisiMole: [InvisiMole](https://attack.mitre.org/software/S0260) uses WinRAR to compress data that is intended to be exfiltrated.(Citation: ESET InvisiMole June 2018)
- [G0006] APT1: [APT1](https://attack.mitre.org/groups/G0006) has used RAR to compress files before moving them outside of the victim network.(Citation: Mandiant APT1)
- [G0129] Mustang Panda: [Mustang Panda](https://attack.mitre.org/groups/G0129) has used RAR to create password-protected archives of collected documents prior to exfiltration.(Citation: Secureworks BRONZE PRESIDENT December 2019)(Citation: Avira Mustang Panda January 2020)
- [G1040] Play: [Play](https://attack.mitre.org/groups/G1040) has used WinRAR to compress files prior to exfiltration.(Citation: CISA Play Ransomware Advisory December 2023)(Citation: Trend Micro Ransomware Spotlight Play July 2023)
- [G0114] Chimera: [Chimera](https://attack.mitre.org/groups/G0114) has used gzip for Linux OS and a modified RAR software to archive data on Windows hosts.(Citation: Cycraft Chimera April 2020)(Citation: NCC Group Chimera January 2021)
- [S0062] DustySky: [DustySky](https://attack.mitre.org/software/S0062) can compress files via RAR while staging data to be exfiltrated.(Citation: Kaspersky MoleRATs April 2019)
- [G0084] Gallmaker: [Gallmaker](https://attack.mitre.org/groups/G0084) has used WinZip, likely to archive data prior to exfiltration.(Citation: Symantec Gallmaker Oct 2018)
- [S0187] Daserf: [Daserf](https://attack.mitre.org/software/S0187) hides collected data in password-protected .rar archives.(Citation: Symantec Tick Apr 2016)
- [S1141] LunarWeb: [LunarWeb](https://attack.mitre.org/software/S1141) can create a ZIP archive with specified files and directories.(Citation: ESET Turla Lunar toolset May 2024)
- [G1041] Sea Turtle: [Sea Turtle](https://attack.mitre.org/groups/G1041) used the tar utility to create a local archive of email data on a victim system.(Citation: Hunt Sea Turtle 2024)
- [G0087] APT39: [APT39](https://attack.mitre.org/groups/G0087) has used WinRAR and 7-Zip to compress an archive stolen data.(Citation: FireEye APT39 Jan 2019)
- [S0378] PoshC2: [PoshC2](https://attack.mitre.org/software/S0378) contains a module for compressing data using ZIP.(Citation: GitHub PoshC2)
- [C0014] Operation Wocao: During [Operation Wocao](https://attack.mitre.org/campaigns/C0014), threat actors archived collected files with WinRAR, prior to exfiltration.(Citation: FoxIT Wocao December 2019)
- [S1168] SampleCheck5000: [SampleCheck5000](https://attack.mitre.org/software/S1168) can gzip compress files uploaded to a shared mailbox used for C2 and exfiltration.(Citation: ESET OilRig Downloaders DEC 2023)
- [G1039] RedCurl: [RedCurl](https://attack.mitre.org/groups/G1039) has downloaded 7-Zip to decompress password protected archives.(Citation: trendmicro_redcurl)
- [G1023] APT5: [APT5](https://attack.mitre.org/groups/G1023) has used the JAR/ZIP file format for exfiltrated files.(Citation: Mandiant Pulse Secure Update May 2021)
- [G1030] Agrius: [Agrius](https://attack.mitre.org/groups/G1030) used 7zip to archive extracted data in preparation for exfiltration.(Citation: Unit42 Agrius 2023)
- [S0196] PUNCHBUGGY: [PUNCHBUGGY](https://attack.mitre.org/software/S0196) has Gzipped information and saved it to a random temp file before exfil.(Citation: Morphisec ShellTea June 2019)
- [S0458] Ramsay: [Ramsay](https://attack.mitre.org/software/S0458) can compress and archive collected files using WinRAR.(Citation: Eset Ramsay May 2020)(Citation: Antiy CERT Ramsay April 2020)
- [C0007] FunnyDream: During [FunnyDream](https://attack.mitre.org/campaigns/C0007), the threat actors used 7zr.exe to add collected files to an archive.(Citation: Bitdefender FunnyDream Campaign November 2020)
- [S0647] Turian: [Turian](https://attack.mitre.org/software/S0647) can use WinRAR to create a password-protected archive for files of interest.(Citation: ESET BackdoorDiplomacy Jun 2021)
- [G0093] GALLIUM: [GALLIUM](https://attack.mitre.org/groups/G0093) used WinRAR to compress and encrypt stolen data prior to exfiltration.(Citation: Cybereason Soft Cell June 2019)(Citation: Microsoft GALLIUM December 2019)
- [G0096] APT41: [APT41](https://attack.mitre.org/groups/G0096) created a RAR archive of targeted files for exfiltration.(Citation: FireEye APT41 Aug 2019) Additionally, [APT41](https://attack.mitre.org/groups/G0096) used the makecab.exe utility to both download tools, such as NATBypass, to the victim network and to archive a file for exfiltration.(Citation: apt41_dcsocytec_dec2022)
- [S1022] IceApple: [IceApple](https://attack.mitre.org/software/S1022) can encrypt and compress files using Gzip prior to exfiltration.(Citation: CrowdStrike IceApple May 2022)
- [G0069] MuddyWater: [MuddyWater](https://attack.mitre.org/groups/G0069) has used the native Windows cabinet creation tool, makecab.exe, likely to compress stolen data to be uploaded.(Citation: Symantec MuddyWater Dec 2018)
- [G0007] APT28: [APT28](https://attack.mitre.org/groups/G0007) has used a variety of utilities, including WinRAR, to archive collected data with password protection.(Citation: Cybersecurity Advisory GRU Brute Force Campaign July 2021)
- [S0278] iKitten: [iKitten](https://attack.mitre.org/software/S0278) will zip up the /Library/Keychains directory before exfiltrating it.(Citation: objsee mac malware 2017)
- [S0466] WindTail: [WindTail](https://attack.mitre.org/software/S0466) has the ability to use the macOS built-in zip utility to archive files.(Citation: objective-see windtail2 jan 2019)
- [C0026] C0026: During [C0026](https://attack.mitre.org/campaigns/C0026), the threat actors used WinRAR to collect documents on targeted systems. The threat actors appeared to only exfiltrate files created after January 1, 2021.(Citation: Mandiant Suspected Turla Campaign February 2023)
- [G0010] Turla: [Turla](https://attack.mitre.org/groups/G0010) has encrypted files stolen from connected USB drives into a RAR file before exfiltration.(Citation: Symantec Waterbug Jun 2019)
- [S0212] CORALDECK: [CORALDECK](https://attack.mitre.org/software/S0212) has created password-protected RAR, WinImage, and zip archives to be exfiltrated.(Citation: FireEye APT37 Feb 2018)
- [G0054] Sowbug: [Sowbug](https://attack.mitre.org/groups/G0054) extracted documents and bundled them into a RAR archive.(Citation: Symantec Sowbug Nov 2017)
- [S0339] Micropsia: [Micropsia](https://attack.mitre.org/software/S0339) creates a RAR archive based on collected files on the victim's machine.(Citation: Radware Micropsia July 2018)
- [C0006] Operation Honeybee: During [Operation Honeybee](https://attack.mitre.org/campaigns/C0006), the threat actors uses zip to pack collected files before exfiltration.(Citation: McAfee Honeybee)
- [G0060] BRONZE BUTLER: [BRONZE BUTLER](https://attack.mitre.org/groups/G0060) has compressed data into password-protected RAR archives prior to exfiltration.(Citation: Secureworks BRONZE BUTLER Oct 2017)(Citation: Trend Micro Tick November 2019)
- [C0029] Cutting Edge: During [Cutting Edge](https://attack.mitre.org/campaigns/C0029), threat actors saved collected data to a tar archive.(Citation: Mandiant Cutting Edge Part 2 January 2024)
- [S0340] Octopus: [Octopus](https://attack.mitre.org/software/S0340) has compressed data before exfiltrating it using a tool called Abbrevia.(Citation: ESET Nomadic Octopus 2018)
- [G0094] Kimsuky: [Kimsuky](https://attack.mitre.org/groups/G0094) has used QuickZip to archive stolen files before exfiltration.(Citation: Talos Kimsuky Nov 2021)
- [G0022] APT3: [APT3](https://attack.mitre.org/groups/G0022) has used tools to compress data before exfilling it.(Citation: aptsim)
- [S0264] OopsIE: [OopsIE](https://attack.mitre.org/software/S0264) compresses collected files with GZipStream before sending them to its C2 server.(Citation: Unit 42 OopsIE! Feb 2018)
- [G0061] FIN8: [FIN8](https://attack.mitre.org/groups/G0061) has used RAR to compress collected data before exfiltration.(Citation: FireEye Know Your Enemy FIN8 Aug 2016)
- [G0004] Ke3chang: [Ke3chang](https://attack.mitre.org/groups/G0004) is known to use 7Zip and RAR with passwords to encrypt data prior to exfiltration.(Citation: Mandiant Operation Ke3chang November 2014)(Citation: Microsoft NICKEL December 2021)
- [C0040] APT41 DUST: [APT41 DUST](https://attack.mitre.org/campaigns/C0040) used `rar` to compress data downloaded from internal Oracle databases prior to exfiltration.(Citation: Google Cloud APT41 2024)
- [G0030] Lotus Blossom: [Lotus Blossom](https://attack.mitre.org/groups/G0030) has used WinRAR for compressing data in RAR format.(Citation: Cisco LotusBlossom 2025)(Citation: Symantec Bilbug 2022)
- [S0274] Calisto: [Calisto](https://attack.mitre.org/software/S0274) uses the <code>zip -r</code> command to compress the data collected on the local system.(Citation: Securelist Calisto July 2018)(Citation: Symantec Calisto July 2018)
- [G1016] FIN13: [FIN13](https://attack.mitre.org/groups/G1016) has compressed the dump output of compromised credentials with a 7zip binary.(Citation: Sygnia Elephant Beetle Jan 2022)
- [G1006] Earth Lusca: [Earth Lusca](https://attack.mitre.org/groups/G1006) has used WinRAR to compress stolen files into an archive prior to exfiltration.(Citation: TrendMicro EarthLusca 2022)
- [S0192] Pupy: [Pupy](https://attack.mitre.org/software/S0192) can compress data with Zip before sending it over C2.(Citation: GitHub Pupy)
- [S1040] Rclone: [Rclone](https://attack.mitre.org/software/S1040) can compress files using `gzip` prior to exfiltration.(Citation: Rclone)
- [G0059] Magic Hound: [Magic Hound](https://attack.mitre.org/groups/G0059) has used gzip to archive dumped LSASS process memory and RAR to stage and compress local folders.(Citation: FireEye APT35 2018)(Citation: DFIR Report APT35 ProxyShell March 2022)(Citation: DFIR Phosphorus November 2021)
- [S0441] PowerShower: [PowerShower](https://attack.mitre.org/software/S0441) has used 7Zip to compress .txt, .pdf, .xls or .doc files prior to exfiltration.(Citation: Kaspersky Cloud Atlas August 2019)
- [S0622] AppleSeed: [AppleSeed](https://attack.mitre.org/software/S0622) can zip and encrypt data collected on a target system.(Citation: Malwarebytes Kimsuky June 2021)
- [G0143] Aquatic Panda: [Aquatic Panda](https://attack.mitre.org/groups/G0143) has used several publicly available tools, including WinRAR and 7zip, to compress collected files and memory dumps prior to exfiltration.(Citation: CrowdStrike AQUATIC PANDA December 2021)(Citation: Crowdstrike HuntReport 2022)
- [S1210] Sagerunex: [Sagerunex](https://attack.mitre.org/software/S1210) has archived collected materials in RAR format.(Citation: Cisco LotusBlossom 2025)
- [G1032] INC Ransom: [INC Ransom](https://attack.mitre.org/groups/G1032) has used 7-Zip and WinRAR to archive collected data prior to exfiltration.(Citation: Huntress INC Ransom Group August 2023)(Citation: Secureworks GOLD IONIC April 2024)(Citation: SOCRadar INC Ransom January 2024)(Citation: Huntress INC Ransomware May 2024)
- [C0024] SolarWinds Compromise: During the [SolarWinds Compromise](https://attack.mitre.org/campaigns/C0024), [APT29](https://attack.mitre.org/groups/G0016) used 7-Zip to compress stolen emails into password-protected archives prior to exfltration; [APT29](https://attack.mitre.org/groups/G0016) also compressed text files into zipped archives.(Citation: Volexity SolarWinds)(Citation: Microsoft Deep Dive Solorigate January 2021)(Citation: CrowdStrike StellarParticle January 2022)
- [S0428] PoetRAT: [PoetRAT](https://attack.mitre.org/software/S0428) has the ability to compress files with zip.(Citation: Talos PoetRAT April 2020)
- [G1024] Akira: [Akira](https://attack.mitre.org/groups/G1024) uses utilities such as WinRAR to archive data prior to exfiltration.(Citation: Secureworks GOLD SAHARA)
- [C0022] Operation Dream Job: During [Operation Dream Job](https://attack.mitre.org/campaigns/C0022), [Lazarus Group](https://attack.mitre.org/groups/G0032) archived victim's data into a RAR file.(Citation: ESET Lazarus Jun 2020)
- [G1022] ToddyCat: [ToddyCat](https://attack.mitre.org/groups/G1022) has leveraged  xcopy, 7zip, and RAR to stage and compress collected documents prior to exfiltration.(Citation: Kaspersky ToddyCat Check Logs October 2023)

#### T1560.002 - Archive via Library

Description:

An adversary may compress or encrypt data that is collected prior to exfiltration using 3rd party libraries. Many libraries exist that can archive data, including [Python](https://attack.mitre.org/techniques/T1059/006) rarfile (Citation: PyPI RAR), libzip (Citation: libzip), and zlib (Citation: Zlib Github). Most libraries include functionality to encrypt and/or compress data.

Some archival libraries are preinstalled on systems, such as bzip2 on macOS and Linux, and zip on Windows. Note that the libraries are different from the utilities. The libraries can be linked against when compiling, while the utilities require spawning a subshell, or a similar execution mechanism.

Procedures:

- [S0467] TajMahal: [TajMahal](https://attack.mitre.org/software/S0467) has the ability to use the open source libraries XZip/Xunzip and zlib to compress files.(Citation: Kaspersky TajMahal April 2019)
- [S1141] LunarWeb: [LunarWeb](https://attack.mitre.org/software/S1141) can zlib-compress data prior to exfiltration.(Citation: ESET Turla Lunar toolset May 2024)
- [S0086] ZLib: The [ZLib](https://attack.mitre.org/software/S0086) backdoor compresses communications using the standard Zlib compression library.(Citation: Cylance Dust Storm)
- [S0127] BBSRAT: [BBSRAT](https://attack.mitre.org/software/S0127) can compress data with ZLIB prior to sending it back to the C2 server.(Citation: Palo Alto Networks BBSRAT)
- [S0260] InvisiMole: [InvisiMole](https://attack.mitre.org/software/S0260) can use zlib to compress and decompress data.(Citation: ESET InvisiMole June 2018)(Citation: ESET InvisiMole June 2020)
- [S0053] SeaDuke: [SeaDuke](https://attack.mitre.org/software/S0053) compressed data with zlib prior to sending it over C2.(Citation: Mandiant No Easy Breach)
- [S0354] Denis: [Denis](https://attack.mitre.org/software/S0354) compressed collected data using zlib.(Citation: Securelist Denis April 2017)
- [S0091] Epic: [Epic](https://attack.mitre.org/software/S0091) compresses the collected data with bzip2 before sending it to the C2 server.(Citation: Kaspersky Turla Aug 2014)
- [S0642] BADFLICK: [BADFLICK](https://attack.mitre.org/software/S0642) has compressed data using the aPLib compression library.(Citation: Accenture MUDCARP March 2019)
- [S0348] Cardinal RAT: [Cardinal RAT](https://attack.mitre.org/software/S0348) applies compression to C2 traffic using the ZLIB library.(Citation: PaloAlto CardinalRat Apr 2017)
- [S0352] OSX_OCEANLOTUS.D: [OSX_OCEANLOTUS.D](https://attack.mitre.org/software/S0352) scrambles and encrypts data using AES256 before sending it to the C2 server.(Citation: TrendMicro MacOS April 2018)(Citation: Trend Micro MacOS Backdoor November 2020)
- [G0032] Lazarus Group: [Lazarus Group](https://attack.mitre.org/groups/G0032) malware IndiaIndia saves information gathered about the victim to a file that is compressed with Zlib, encrypted, and uploaded to a C2 server.(Citation: Novetta Blockbuster RATs)(Citation: McAfee Lazarus Resurfaces Feb 2018)
- [S0661] FoggyWeb: [FoggyWeb](https://attack.mitre.org/software/S0661) can invoke the `Common.Compress` method to compress data with the C# GZipStream compression class.(Citation: MSTIC FoggyWeb September 2021)
- [S1044] FunnyDream: [FunnyDream](https://attack.mitre.org/software/S1044) has compressed collected files with zLib.(Citation: Bitdefender FunnyDream Campaign November 2020)
- [G0027] Threat Group-3390: [Threat Group-3390](https://attack.mitre.org/groups/G0027) has used RAR to compress, encrypt, and password-protect files prior to exfiltration.(Citation: SecureWorks BRONZE UNION June 2017)

#### T1560.003 - Archive via Custom Method

Description:

An adversary may compress or encrypt data that is collected prior to exfiltration using a custom method. Adversaries may choose to use custom archival methods, such as encryption with XOR or stream ciphers implemented with no external library or utility references. Custom implementations of well-known compression algorithms have also been used.(Citation: ESET Sednit Part 2)

Procedures:

- [S0438] Attor: [Attor](https://attack.mitre.org/software/S0438) encrypts collected data with a custom implementation of Blowfish and RSA ciphers.(Citation: ESET Attor Oct 2019)
- [S0657] BLUELIGHT: [BLUELIGHT](https://attack.mitre.org/software/S0657) has encoded data into a binary blob using XOR.(Citation: Volexity InkySquid BLUELIGHT August 2021)
- [G0037] FIN6: [FIN6](https://attack.mitre.org/groups/G0037) has encoded data gathered from the victim with a simple substitution cipher and single-byte XOR using the 0xAA key, and Base64 with character permutation.(Citation: FireEye FIN6 April 2016)(Citation: Trend Micro FIN6 October 2019)
- [S0038] Duqu: Modules can be pushed to and executed by [Duqu](https://attack.mitre.org/software/S0038) that copy data to a staging area, compress it, and XOR encrypt it.(Citation: Symantec W32.Duqu)
- [S0603] Stuxnet: [Stuxnet](https://attack.mitre.org/software/S0603) encrypts exfiltrated data via C2 with static 31-byte long XOR keys.(Citation: Nicolas Falliere, Liam O Murchu, Eric Chien February 2011)
- [S0035] SPACESHIP: Data [SPACESHIP](https://attack.mitre.org/software/S0035) copies to the staging area is compressed with zlib. Bytes are rotated by four positions and XOR'ed with 0x23.(Citation: FireEye APT30)
- [G0052] CopyKittens: [CopyKittens](https://attack.mitre.org/groups/G0052) encrypts data with a substitute cipher prior to exfiltration.(Citation: CopyKittens Nov 2015)
- [S0661] FoggyWeb: [FoggyWeb](https://attack.mitre.org/software/S0661) can use a dynamic XOR key and a custom XOR methodology to encode data before exfiltration. Also, [FoggyWeb](https://attack.mitre.org/software/S0661) can encode C2 command output within a legitimate WebP file.(Citation: MSTIC FoggyWeb September 2021)
- [S0198] NETWIRE: [NETWIRE](https://attack.mitre.org/software/S0198) has used a custom encryption algorithm to encrypt collected data.(Citation: FireEye NETWIRE March 2019)
- [S0448] Rising Sun: [Rising Sun](https://attack.mitre.org/software/S0448) can archive data using RC4 encryption and Base64 encoding prior to exfiltration.(Citation: McAfee Sharpshooter December 2018)
- [S0491] StrongPity: [StrongPity](https://attack.mitre.org/software/S0491) can compress and encrypt archived files into multiple .sft files with a repeated xor encryption scheme.(Citation: Talos Promethium June 2020)(Citation: Bitdefender StrongPity June 2020)
- [S0258] RGDoor: [RGDoor](https://attack.mitre.org/software/S0258) encrypts files with XOR before sending them back to the C2 server.(Citation: Unit 42 RGDoor Jan 2018)
- [S0169] RawPOS: [RawPOS](https://attack.mitre.org/software/S0169) encodes credit card data it collected from the victim with XOR.(Citation: TrendMicro RawPOS April 2015)(Citation: Mandiant FIN5 GrrCON Oct 2016)(Citation: Visa RawPOS March 2015)
- [S1059] metaMain: [metaMain](https://attack.mitre.org/software/S1059) has used XOR-based encryption for collected files before exfiltration.(Citation: SentinelLabs Metador Sept 2022)
- [S0458] Ramsay: [Ramsay](https://attack.mitre.org/software/S0458) can store collected documents in a custom container after encrypting and compressing them using RC4 and WinRAR.(Citation: Eset Ramsay May 2020)
- [G0129] Mustang Panda: [Mustang Panda](https://attack.mitre.org/groups/G0129) has encrypted documents with RC4 prior to exfiltration.(Citation: Avira Mustang Panda January 2020)
- [G0094] Kimsuky: [Kimsuky](https://attack.mitre.org/groups/G0094) has used RC4 encryption before exfil.(Citation: Securelist Kimsuky Sept 2013)
- [S0264] OopsIE: [OopsIE](https://attack.mitre.org/software/S0264) compresses collected files with a simple character replacement scheme before sending them to its C2 server.(Citation: Unit 42 OopsIE! Feb 2018)
- [S0615] SombRAT: [SombRAT](https://attack.mitre.org/software/S0615) has encrypted collected data with AES-256 using a hardcoded key.(Citation: BlackBerry CostaRicto November 2020)
- [S0409] Machete: [Machete](https://attack.mitre.org/software/S0409)'s collected data is encrypted with AES before exfiltration.(Citation: ESET Machete July 2019)
- [S0172] Reaver: [Reaver](https://attack.mitre.org/software/S0172) encrypts collected data with an incremental XOR key prior to exfiltration.(Citation: Palo Alto Reaver Nov 2017)
- [S0391] HAWKBALL: [HAWKBALL](https://attack.mitre.org/software/S0391) has encrypted data with XOR before sending it over the C2 channel.(Citation: FireEye HAWKBALL Jun 2019)
- [S0072] OwaAuth: [OwaAuth](https://attack.mitre.org/software/S0072) DES-encrypts captured credentials using the key 12345678 before writing the credentials to a log file.(Citation: Dell TG-3390)
- [S0260] InvisiMole: [InvisiMole](https://attack.mitre.org/software/S0260) uses a variation of the XOR cipher to encrypt files before exfiltration.(Citation: ESET InvisiMole June 2018)
- [S0098] T9000: [T9000](https://attack.mitre.org/software/S0098) encrypts collected data using a single byte XOR key.(Citation: Palo Alto T9000 Feb 2016)
- [S0045] ADVSTORESHELL: [ADVSTORESHELL](https://attack.mitre.org/software/S0045) compresses output data generated by command execution with a custom implementation of the Lempel–Ziv–Welch (LZW) algorithm.(Citation: ESET Sednit Part 2)
- [G0030] Lotus Blossom: [Lotus Blossom](https://attack.mitre.org/groups/G0030) has used custom tools to compress and archive data on victim systems.(Citation: Cisco LotusBlossom 2025)
- [S1030] Squirrelwaffle: [Squirrelwaffle](https://attack.mitre.org/software/S1030) has encrypted collected data using a XOR-based algorithm.(Citation: ZScaler Squirrelwaffle Sep 2021)
- [S0439] Okrum: [Okrum](https://attack.mitre.org/software/S0439) has used a custom implementation of AES encryption to encrypt collected data.(Citation: ESET Okrum July 2019)
- [S0352] OSX_OCEANLOTUS.D: [OSX_OCEANLOTUS.D](https://attack.mitre.org/software/S0352) has used AES in CBC mode to encrypt collected data when saving that data to disk.(Citation: Unit42 OceanLotus 2017)
- [S1044] FunnyDream: [FunnyDream](https://attack.mitre.org/software/S1044) has compressed collected files with zLib and encrypted them using an XOR operation with the string key from the command line or `qwerasdf` if the command line argument doesn’t contain the key. File names are obfuscated using XOR with the same key as the compressed file content.(Citation: Bitdefender FunnyDream Campaign November 2020)
- [S0443] MESSAGETAP: [MESSAGETAP](https://attack.mitre.org/software/S0443) has XOR-encrypted and stored contents of SMS messages that matched its target list. (Citation: FireEye MESSAGETAP October 2019)
- [S1042] SUGARDUMP: [SUGARDUMP](https://attack.mitre.org/software/S1042) has encrypted collected data using AES CBC mode and encoded it using Base64.(Citation: Mandiant UNC3890 Aug 2022)
- [C0017] C0017: During [C0017](https://attack.mitre.org/campaigns/C0017), [APT41](https://attack.mitre.org/groups/G0096) hex-encoded PII data prior to exfiltration.(Citation: Mandiant APT41)
- [S0503] FrameworkPOS: [FrameworkPOS](https://attack.mitre.org/software/S0503) can XOR credit card information before exfiltration.(Citation: SentinelOne FrameworkPOS September 2019)
- [S0092] Agent.btz: [Agent.btz](https://attack.mitre.org/software/S0092) saves system information into an XML file that is then XOR-encoded.(Citation: ThreatExpert Agent.btz)
- [G0032] Lazarus Group: A [Lazarus Group](https://attack.mitre.org/groups/G0032) malware sample encrypts data using a simple byte based XOR operation prior to exfiltration.(Citation: Novetta Blockbuster)(Citation: Novetta Blockbuster Loaders)(Citation: Novetta Blockbuster RATs)(Citation: McAfee Lazarus Resurfaces Feb 2018)
- [S0036] FLASHFLOOD: [FLASHFLOOD](https://attack.mitre.org/software/S0036) employs the same encoding scheme as [SPACESHIP](https://attack.mitre.org/software/S0035) for data it stages. Data is compressed with zlib, and bytes are rotated four times before being XOR'ed with 0x23.(Citation: FireEye APT30)


### T1602 - Data from Configuration Repository

Description:

Adversaries may collect data related to managed devices from configuration repositories. Configuration repositories are used by management systems in order to configure, manage, and control data on remote systems. Configuration repositories may also facilitate remote access and administration of devices.

Adversaries may target these repositories in order to collect large quantities of sensitive system administration data. Data from configuration repositories may be exposed by various protocols and software and can store a wide variety of data, much of which may align with adversary Discovery objectives.(Citation: US-CERT-TA18-106A)(Citation: US-CERT TA17-156A SNMP Abuse 2017)

#### T1602.001 - SNMP (MIB Dump)

Description:

Adversaries may target the Management Information Base (MIB) to collect and/or mine valuable information in a network managed using Simple Network Management Protocol (SNMP).

The MIB is a configuration repository that stores variable information accessible via SNMP in the form of object identifiers (OID). Each OID identifies a variable that can be read or set and permits active management tasks, such as configuration changes, through remote modification of these variables. SNMP can give administrators great insight in their systems, such as, system information, description of hardware, physical location, and software packages(Citation: SANS Information Security Reading Room Securing SNMP Securing SNMP). The MIB may also contain device operational information, including running configuration, routing table, and interface details.

Adversaries may use SNMP queries to collect MIB content directly from SNMP-managed devices in order to collect network information that allows the adversary to build network maps and facilitate future targeted exploitation.(Citation: US-CERT-TA18-106A)(Citation: Cisco Blog Legacy Device Attacks)

#### T1602.002 - Network Device Configuration Dump

Description:

Adversaries may access network configuration files to collect sensitive data about the device and the network. The network configuration is a file containing parameters that determine the operation of the device. The device typically stores an in-memory copy of the configuration while operating, and a separate configuration on non-volatile storage to load after device reset. Adversaries can inspect the configuration files to reveal information about the target network and its layout, the network device and its software, or identifying legitimate accounts and credentials for later use.

Adversaries can use common management tools and protocols, such as Simple Network Management Protocol (SNMP) and Smart Install (SMI), to access network configuration files.(Citation: US-CERT TA18-106A Network Infrastructure Devices 2018)(Citation: Cisco Blog Legacy Device Attacks) These tools may be used to query specific data from a configuration repository or configure the device to export the configuration for later analysis.

Procedures:

- [G1045] Salt Typhoon: [Salt Typhoon](https://attack.mitre.org/groups/G1045) has attempted to acquire credentials by dumping network device configurations.(Citation: Cisco Salt Typhoon FEB 2025)

