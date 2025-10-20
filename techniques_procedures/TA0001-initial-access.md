### T1078 - Valid Accounts

Description:

Adversaries may obtain and abuse credentials of existing accounts as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion. Compromised credentials may be used to bypass access controls placed on various resources on systems within the network and may even be used for persistent access to remote systems and externally available services, such as VPNs, Outlook Web Access, network devices, and remote desktop.(Citation: volexity_0day_sophos_FW) Compromised credentials may also grant an adversary increased privilege to specific systems or access to restricted areas of the network. Adversaries may choose not to use malware or tools in conjunction with the legitimate access those credentials provide to make it harder to detect their presence.

In some cases, adversaries may abuse inactive accounts: for example, those belonging to individuals who are no longer part of an organization. Using these accounts may allow the adversary to evade detection, as the original account user will not be present to identify any anomalous activity taking place on their account.(Citation: CISA MFA PrintNightmare)

The overlap of permissions for local, domain, and cloud accounts across a network of systems is of concern because the adversary may be able to pivot across accounts and systems to reach a high level of access (i.e., domain or enterprise administrator) to bypass access controls set within the enterprise.(Citation: TechNet Credential Theft)

Procedures:

- [G0096] APT41: [APT41](https://attack.mitre.org/groups/G0096) used compromised credentials to log on to other systems.(Citation: FireEye APT41 Aug 2019)(Citation: Crowdstrike GTR2020 Mar 2020)
- [G0061] FIN8: [FIN8](https://attack.mitre.org/groups/G0061) has used valid accounts for persistence and lateral movement.(Citation: FireEye Know Your Enemy FIN8 Aug 2016)
- [G0085] FIN4: [FIN4](https://attack.mitre.org/groups/G0085) has used legitimate credentials to hijack email communications.(Citation: FireEye Hacking FIN4 Dec 2014)(Citation: FireEye Hacking FIN4 Video Dec 2014)
- [G0046] FIN7: [FIN7](https://attack.mitre.org/groups/G0046) has harvested valid administrative credentials for lateral movement.(Citation: CrowdStrike Carbon Spider August 2021)
- [S0599] Kinsing: [Kinsing](https://attack.mitre.org/software/S0599) has used valid SSH credentials to access remote hosts.(Citation: Aqua Kinsing April 2020)
- [G0035] Dragonfly: [Dragonfly](https://attack.mitre.org/groups/G0035) has compromised user credentials and used valid accounts for operations.(Citation: US-CERT TA18-074A)(Citation: Gigamon Berserk Bear October 2021)(Citation: CISA AA20-296A Berserk Bear December 2020)
- [G0093] GALLIUM: [GALLIUM](https://attack.mitre.org/groups/G0093) leveraged valid accounts to maintain access to a victim network.(Citation: Cybereason Soft Cell June 2019)
- [G0026] APT18: [APT18](https://attack.mitre.org/groups/G0026) actors leverage legitimate credentials to log into external remote services.(Citation: RSA2017 Detect and Respond Adair)
- [G1017] Volt Typhoon: [Volt Typhoon](https://attack.mitre.org/groups/G1017) relies primarily on valid credentials for persistence.(Citation: CISA AA24-038A PRC Critical Infrastructure February 2024)
- [C0032] C0032: During the [C0032](https://attack.mitre.org/campaigns/C0032) campaign, [TEMP.Veles](https://attack.mitre.org/groups/G0088) used compromised VPN accounts.(Citation: FireEye TRITON 2019)
- [G0032] Lazarus Group: [Lazarus Group](https://attack.mitre.org/groups/G0032) has used administrator credentials to gain access to restricted network segments.(Citation: Kaspersky ThreatNeedle Feb 2021)
- [G0114] Chimera: [Chimera](https://attack.mitre.org/groups/G0114) has used a valid account to maintain persistence via scheduled task.(Citation: Cycraft Chimera April 2020)
- [S0053] SeaDuke: Some [SeaDuke](https://attack.mitre.org/software/S0053) samples have a module to extract email from Microsoft Exchange servers using compromised credentials.(Citation: Symantec Seaduke 2015)
- [S0567] Dtrack: [Dtrack](https://attack.mitre.org/software/S0567) used hard-coded credentials to gain access to a network share.(Citation: CyberBit Dtrack)
- [S0604] Industroyer: [Industroyer](https://attack.mitre.org/software/S0604) can use supplied user credentials to execute processes and stop services.(Citation: ESET Industroyer)
- [C0002] Night Dragon: During [Night Dragon](https://attack.mitre.org/campaigns/C0002), threat actors used compromised VPN accounts to gain access to victim systems.(Citation: McAfee Night Dragon)
- [G0045] menuPass: [menuPass](https://attack.mitre.org/groups/G0045) has used valid accounts including shared between Managed Service Providers and clients to move between the two environments.(Citation: PWC Cloud Hopper April 2017)(Citation: Symantec Cicada November 2020)(Citation: District Court of NY APT10 Indictment December 2018)(Citation: Securelist APT10 March 2021)
- [S0038] Duqu: Adversaries can instruct [Duqu](https://attack.mitre.org/software/S0038) to spread laterally by copying itself to shares it has enumerated and for which it has obtained legitimate credentials (via keylogging or other means). The remote host is then infected by using the compromised credentials to schedule a task on remote machines that executes the malware.(Citation: Symantec W32.Duqu)
- [G0034] Sandworm Team: [Sandworm Team](https://attack.mitre.org/groups/G0034) have used previously acquired legitimate credentials prior to attacks.(Citation: US-CERT Ukraine Feb 2016)
- [G1021] Cinnamon Tempest: [Cinnamon Tempest](https://attack.mitre.org/groups/G1021) has used compromised user accounts to deploy payloads and create system services.(Citation: Sygnia Emperor Dragonfly October 2022)
- [G1024] Akira: [Akira](https://attack.mitre.org/groups/G1024) uses valid account information to remotely access victim networks, such as VPN credentials.(Citation: Secureworks GOLD SAHARA)(Citation: Arctic Wolf Akira 2023)(Citation: Cisco Akira Ransomware OCT 2024)
- [C0048] Operation MidnightEclipse: During [Operation MidnightEclipse](https://attack.mitre.org/campaigns/C0048), threat actors extracted sensitive credentials while moving laterally through compromised networks.(Citation: Volexity UPSTYLE 2024)
- [G1004] LAPSUS$: [LAPSUS$](https://attack.mitre.org/groups/G1004) has used compromised credentials and/or session tokens to gain access into a victim's VPN, VDI, RDP, and IAMs.(Citation: MSTIC DEV-0537 Mar 2022)(Citation: NCC Group LAPSUS Apr 2022)
- [G0008] Carbanak: [Carbanak](https://attack.mitre.org/groups/G0008) actors used legitimate credentials of banking employees to perform operations that sent them millions of dollars.(Citation: Kaspersky Carbanak)
- [C0014] Operation Wocao: During [Operation Wocao](https://attack.mitre.org/campaigns/C0014), threat actors used valid VPN credentials to gain initial access.(Citation: FoxIT Wocao December 2019)
- [G0007] APT28: [APT28](https://attack.mitre.org/groups/G0007) has used legitimate credentials to gain initial access, maintain access, and exfiltrate data from a victim network. The group has specifically used credentials stolen through a spearphishing email to login to the DCCC network. The group has also leveraged default manufacturer's passwords to gain initial access to corporate networks via IoT devices such as a VOIP phone, printer, and video decoder.(Citation: Trend Micro Pawn Storm April 2017)(Citation: DOJ GRU Indictment Jul 2018)(Citation: Microsoft STRONTIUM Aug 2019)(Citation: Cybersecurity Advisory GRU Brute Force Campaign July 2021)
- [G0027] Threat Group-3390: [Threat Group-3390](https://attack.mitre.org/groups/G0027) actors obtain legitimate credentials using a variety of methods and use them to further lateral movement on victim networks.(Citation: Dell TG-3390)
- [G0039] Suckfly: [Suckfly](https://attack.mitre.org/groups/G0039) used legitimate account credentials that they dumped to navigate the internal victim network as though they were the legitimate account owner.(Citation: Symantec Suckfly May 2016)
- [G1040] Play: [Play](https://attack.mitre.org/groups/G1040) has used valid VPN accounts to achieve initial access.(Citation: CISA Play Ransomware Advisory December 2023)
- [C0028] 2015 Ukraine Electric Power Attack: During the [2015 Ukraine Electric Power Attack](https://attack.mitre.org/campaigns/C0028), [Sandworm Team](https://attack.mitre.org/groups/G0034) used valid accounts on the corporate network to escalate privileges, move laterally, and establish persistence within the corporate network. (Citation: Ukraine15 - EISAC - 201603)
- [G0001] Axiom: [Axiom](https://attack.mitre.org/groups/G0001) has used previously compromised administrative accounts to escalate privileges.(Citation: Novetta-Axiom)
- [G0119] Indrik Spider: [Indrik Spider](https://attack.mitre.org/groups/G0119) has used valid accounts for initial access and lateral movement.(Citation: Mandiant_UNC2165) [Indrik Spider](https://attack.mitre.org/groups/G0119) has also maintained access to the victim environment through the VPN infrastructure.(Citation: Mandiant_UNC2165)
- [G0065] Leviathan: [Leviathan](https://attack.mitre.org/groups/G0065) has obtained valid accounts to gain initial access.(Citation: CISA AA21-200A APT40 July 2021)(Citation: Accenture MUDCARP March 2019)(Citation: CISA Leviathan 2024)
- [G0011] PittyTiger: [PittyTiger](https://attack.mitre.org/groups/G0011) attempts to obtain legitimate credentials during operations.(Citation: Bizeul 2014)
- [G0091] Silence: [Silence](https://attack.mitre.org/groups/G0091) has used compromised credentials to log on to other systems and escalate privileges.(Citation: Group IB Silence Sept 2018)
- [G0049] OilRig: [OilRig](https://attack.mitre.org/groups/G0049) has used compromised credentials to access other systems on a victim network.(Citation: Unit42 OilRig Playbook 2023)(Citation: FireEye APT34 Webinar Dec 2017)(Citation: Crowdstrike GTR2020 Mar 2020)(Citation: IBM ZeroCleare Wiper December 2019)
- [C0049] Leviathan Australian Intrusions: [Leviathan](https://attack.mitre.org/groups/G0065) used captured, valid account information to log into victim web applications and appliances during [Leviathan Australian Intrusions](https://attack.mitre.org/campaigns/C0049).(Citation: CISA Leviathan 2024)
- [G0102] Wizard Spider: [Wizard Spider](https://attack.mitre.org/groups/G0102) has used valid credentials for privileged accounts with the goal of accessing domain controllers.(Citation: CrowdStrike Grim Spider May 2019)(Citation: Mandiant FIN12 Oct 2021)
- [G0016] APT29: [APT29](https://attack.mitre.org/groups/G0016) has used a compromised account to access an organization's VPN infrastructure.(Citation: Mandiant APT29 Microsoft 365 2022)
- [G1043] BlackByte: [BlackByte](https://attack.mitre.org/groups/G1043) has gained access to victim environments through legitimate VPN credentials.(Citation: Cisco BlackByte 2024)
- [G0004] Ke3chang: [Ke3chang](https://attack.mitre.org/groups/G0004) has used credential dumpers or stealers to obtain legitimate credentials, which they used to gain access to victim accounts.(Citation: Microsoft NICKEL December 2021)
- [G0051] FIN10: [FIN10](https://attack.mitre.org/groups/G0051) has used stolen credentials to connect remotely to victim networks using VPNs protected with only a single factor.(Citation: FireEye FIN10 June 2017)
- [G0064] APT33: [APT33](https://attack.mitre.org/groups/G0064) has used valid accounts for initial access and privilege escalation.(Citation: FireEye APT33 Webinar Sept 2017)(Citation: FireEye APT33 Guardrail)
- [G1032] INC Ransom: [INC Ransom](https://attack.mitre.org/groups/G1032) has used compromised valid accounts for access to victim environments.(Citation: Cybereason INC Ransomware November 2023)(Citation: Huntress INC Ransom Group August 2023)(Citation: SOCRadar INC Ransom January 2024)(Citation: Huntress INC Ransomware May 2024)
- [G0037] FIN6: To move laterally on a victim network, [FIN6](https://attack.mitre.org/groups/G0037) has used credentials stolen from various systems on which it gathered usernames and password hashes.(Citation: FireEye FIN6 April 2016)(Citation: FireEye FIN6 Apr 2019)(Citation: Visa FIN6 Feb 2019)
- [G0117] Fox Kitten: [Fox Kitten](https://attack.mitre.org/groups/G0117) has used valid credentials with various services during lateral movement.(Citation: CISA AA20-259A Iran-Based Actor September 2020)
- [G1005] POLONIUM: [POLONIUM](https://attack.mitre.org/groups/G1005) has used valid compromised credentials to gain access to victim environments.(Citation: Microsoft POLONIUM June 2022)
- [G0053] FIN5: [FIN5](https://attack.mitre.org/groups/G0053) has used legitimate VPN, RDP, Citrix, or VNC credentials to maintain access to a victim environment.(Citation: FireEye Respond Webinar July 2017)(Citation: DarkReading FireEye FIN5 Oct 2015)(Citation: Mandiant FIN5 GrrCON Oct 2016)
- [S0362] Linux Rabbit: [Linux Rabbit](https://attack.mitre.org/software/S0362) acquires valid SSH accounts through brute force. (Citation: Anomali Linux Rabbit 2018)
- [G0122] Silent Librarian: [Silent Librarian](https://attack.mitre.org/groups/G0122) has used compromised credentials to obtain unauthorized access to online accounts.(Citation: DOJ Iran Indictments March 2018)
- [G1041] Sea Turtle: [Sea Turtle](https://attack.mitre.org/groups/G1041) used compromised credentials to maintain long-term access to victim environments.(Citation: Talos Sea Turtle 2019)
- [G1033] Star Blizzard: [Star Blizzard](https://attack.mitre.org/groups/G1033) has used stolen credentials to sign into victim email accounts.(Citation: Microsoft Star Blizzard August 2022)(Citation: CISA Star Blizzard Advisory December 2023)
- [G0087] APT39: [APT39](https://attack.mitre.org/groups/G0087) has used stolen credentials to compromise Outlook Web Access (OWA).(Citation: FireEye APT39 Jan 2019)
- [C0024] SolarWinds Compromise: During the [SolarWinds Compromise](https://attack.mitre.org/campaigns/C0024), [APT29](https://attack.mitre.org/groups/G0016) used different compromised credentials for remote access and to move laterally.(Citation: FireEye SUNBURST Backdoor December 2020)(Citation: MSTIC NOBELIUM Mar 2021)(Citation: Cybersecurity Advisory SVR TTP May 2021)
- [C0038] HomeLand Justice: During [HomeLand Justice](https://attack.mitre.org/campaigns/C0038), threat actors used a compromised Exchange account to search mailboxes and create new Exchange accounts.(Citation: CISA Iran Albanian Attacks September 2022)

#### T1078.001 - Valid Accounts: Default Accounts

Description:

Adversaries may obtain and abuse credentials of a default account as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion. Default accounts are those that are built-into an OS, such as the Guest or Administrator accounts on Windows systems. Default accounts also include default factory/provider set accounts on other types of systems, software, or devices, including the root user account in AWS, the root user account in ESXi, and the default service account in Kubernetes.(Citation: Microsoft Local Accounts Feb 2019)(Citation: AWS Root User)(Citation: Threat Matrix for Kubernetes)

Default accounts are not limited to client machines; rather, they also include accounts that are preset for equipment such as network devices and computer applications, whether they are internal, open source, or commercial. Appliances that come preset with a username and password combination pose a serious threat to organizations that do not change it post installation, as they are easy targets for an adversary. Similarly, adversaries may also utilize publicly disclosed or stolen [Private Keys](https://attack.mitre.org/techniques/T1552/004) or credential materials to legitimately connect to remote environments via [Remote Services](https://attack.mitre.org/techniques/T1021).(Citation: Metasploit SSH Module)

Default accounts may be created on a system after initial setup by connecting or integrating it with another application. For example, when an ESXi server is connected to a vCenter server, a default privileged account called `vpxuser` is created on the ESXi server. If a threat actor is able to compromise this account’s credentials (for example, via [Exploitation for Credential Access](https://attack.mitre.org/techniques/T1212) on the vCenter host), they will then have access to the ESXi server.(Citation: Google Cloud Threat Intelligence VMWare ESXi Zero-Day 2023)(Citation: Pentera vCenter Information Disclosure)

Procedures:

- [G1016] FIN13: [FIN13](https://attack.mitre.org/groups/G1016) has leveraged default credentials for authenticating myWebMethods (WMS) and QLogic web management interface to gain initial access.(Citation: Sygnia Elephant Beetle Jan 2022)
- [S0537] HyperStack: [HyperStack](https://attack.mitre.org/software/S0537) can use default credentials to connect to IPC$ shares on remote machines.(Citation: Accenture HyperStack October 2020)
- [C0038] HomeLand Justice: During [HomeLand Justice](https://attack.mitre.org/campaigns/C0038), threat actors used the built-in administrator account to move laterally using RDP and [Impacket](https://attack.mitre.org/software/S0357).(Citation: Microsoft Albanian Government Attacks September 2022)
- [G0059] Magic Hound: [Magic Hound](https://attack.mitre.org/groups/G0059) enabled and used the default system managed account, DefaultAccount, via `"powershell.exe" /c net user DefaultAccount /active:yes` to connect to a targeted Exchange server over RDP.(Citation: DFIR Phosphorus November 2021)
- [S0603] Stuxnet: [Stuxnet](https://attack.mitre.org/software/S0603) infected WinCC machines via a hardcoded database server password.(Citation: Nicolas Falliere, Liam O Murchu, Eric Chien February 2011)
- [G1003] Ember Bear: [Ember Bear](https://attack.mitre.org/groups/G1003) has abused default user names and passwords in externally-accessible IP cameras for initial access.(Citation: CISA GRU29155 2024)

#### T1078.002 - Valid Accounts: Domain Accounts

Description:

Adversaries may obtain and abuse credentials of a domain account as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion.(Citation: TechNet Credential Theft) Domain accounts are those managed by Active Directory Domain Services where access and permissions are configured across systems and services that are part of that domain. Domain accounts can cover users, administrators, and services.(Citation: Microsoft AD Accounts)

Adversaries may compromise domain accounts, some with a high level of privileges, through various means such as [OS Credential Dumping](https://attack.mitre.org/techniques/T1003) or password reuse, allowing access to privileged resources of the domain.

Procedures:

- [S1024] CreepySnail: [CreepySnail](https://attack.mitre.org/software/S1024) can use stolen credentials to authenticate on target networks.(Citation: Microsoft POLONIUM June 2022)
- [C0002] Night Dragon: During [Night Dragon](https://attack.mitre.org/campaigns/C0002), threat actors used domain accounts to gain further access to victim systems.(Citation: McAfee Night Dragon)
- [C0023] Operation Ghost: For [Operation Ghost](https://attack.mitre.org/campaigns/C0023), [APT29](https://attack.mitre.org/groups/G0016) used stolen administrator credentials for lateral movement on compromised networks.(Citation: ESET Dukes October 2019)
- [C0048] Operation MidnightEclipse: During [Operation MidnightEclipse](https://attack.mitre.org/campaigns/C0048), threat actors used a compromised domain admin account to move laterally.(Citation: Volexity UPSTYLE 2024)
- [S0154] Cobalt Strike: [Cobalt Strike](https://attack.mitre.org/software/S0154) can use known credentials to run commands and spawn processes as a domain user account.(Citation: cobaltstrike manual)(Citation: CobaltStrike Daddy May 2017)(Citation: Cobalt Strike Manual 4.3 November 2020)
- [G0019] Naikon: [Naikon](https://attack.mitre.org/groups/G0019) has used administrator credentials for lateral movement in compromised networks.(Citation: Bitdefender Naikon April 2021)
- [C0049] Leviathan Australian Intrusions: [Leviathan](https://attack.mitre.org/groups/G0065) compromised domain credentials during [Leviathan Australian Intrusions](https://attack.mitre.org/campaigns/C0049).(Citation: CISA Leviathan 2024)
- [C0012] Operation CuckooBees: During [Operation CuckooBees](https://attack.mitre.org/campaigns/C0012), the threat actors used compromised domain administrator credentials as part of their lateral movement.(Citation: Cybereason OperationCuckooBees May 2022)
- [G1030] Agrius: [Agrius](https://attack.mitre.org/groups/G1030) attempted to acquire valid credentials for victim environments through various means to enable follow-on lateral movement.(Citation: Unit42 Agrius 2023)
- [G0102] Wizard Spider: [Wizard Spider](https://attack.mitre.org/groups/G0102) has used administrative accounts, including Domain Admin, to move laterally within a victim network.(Citation: FireEye KEGTAP SINGLEMALT October 2020)
- [G0034] Sandworm Team: [Sandworm Team](https://attack.mitre.org/groups/G0034) has used stolen credentials to access administrative accounts within the domain.(Citation: US District Court Indictment GRU Unit 74455 October 2020)(Citation: Microsoft Prestige ransomware October 2022)
- [C0024] SolarWinds Compromise: During the [SolarWinds Compromise](https://attack.mitre.org/campaigns/C0024), [APT29](https://attack.mitre.org/groups/G0016) used domain administrators' accounts to help facilitate lateral movement on compromised networks.(Citation: CrowdStrike StellarParticle January 2022)
- [S0446] Ryuk: [Ryuk](https://attack.mitre.org/software/S0446) can use stolen domain admin accounts to move laterally within a victim domain.(Citation: ANSSI RYUK RANSOMWARE)
- [G0049] OilRig: [OilRig](https://attack.mitre.org/groups/G0049) has used an exfiltration tool named STEALHOOK to retreive valid domain credentials.(Citation: Trend Micro Earth Simnavaz October 2024)
- [S0140] Shamoon: If [Shamoon](https://attack.mitre.org/software/S0140) cannot access shares using current privileges, it attempts access using hard coded, domain-specific credentials gathered earlier in the intrusion.(Citation: FireEye Shamoon Nov 2016)(Citation: Unit 42 Shamoon3 2018)
- [G1021] Cinnamon Tempest: [Cinnamon Tempest](https://attack.mitre.org/groups/G1021) has obtained highly privileged credentials such as domain administrator in order to deploy malware.(Citation: Microsoft Ransomware as a Service)
- [G1022] ToddyCat: [ToddyCat](https://attack.mitre.org/groups/G1022) has used compromised domain admin credentials to mount local network shares.(Citation: Kaspersky ToddyCat Check Logs October 2023)
- [G0119] Indrik Spider: [Indrik Spider](https://attack.mitre.org/groups/G0119) has collected credentials from infected systems, including domain accounts.(Citation: Crowdstrike Indrik November 2018)
- [G0022] APT3: [APT3](https://attack.mitre.org/groups/G0022) leverages valid accounts after gaining credentials for use within the victim domain.(Citation: Symantec Buckeye)
- [G0114] Chimera: [Chimera](https://attack.mitre.org/groups/G0114) has used compromised domain accounts to gain access to the target environment.(Citation: NCC Group Chimera January 2021)
- [C0014] Operation Wocao: During [Operation Wocao](https://attack.mitre.org/campaigns/C0014), threat actors used domain credentials, including domain admin, for lateral movement and privilege escalation.(Citation: FoxIT Wocao December 2019)
- [G1040] Play: [Play](https://attack.mitre.org/groups/G1040) has used valid domain accounts for access.(Citation: Trend Micro Ransomware Spotlight Play July 2023)
- [G0092] TA505: [TA505](https://attack.mitre.org/groups/G0092) has used stolen domain admin accounts to compromise additional hosts.(Citation: IBM TA505 April 2020)
- [G0028] Threat Group-1314: [Threat Group-1314](https://attack.mitre.org/groups/G0028) actors used compromised domain credentials for the victim's endpoint management platform, Altiris, to move laterally.(Citation: Dell TG-1314)
- [G1023] APT5: [APT5](https://attack.mitre.org/groups/G1023) has used legitimate account credentials to move laterally through compromised environments.(Citation: Mandiant Pulse Secure Zero-Day April 2021)
- [G0059] Magic Hound: [Magic Hound](https://attack.mitre.org/groups/G0059) has used domain administrator accounts after dumping LSASS process memory.(Citation: DFIR Phosphorus November 2021)
- [C0029] Cutting Edge: During [Cutting Edge](https://attack.mitre.org/campaigns/C0029), threat actors used compromised VPN accounts for lateral movement on targeted networks.(Citation: Volexity Ivanti Zero-Day Exploitation January 2024)
- [S0603] Stuxnet: [Stuxnet](https://attack.mitre.org/software/S0603) attempts to access network resources with a domain account’s credentials.(Citation: Nicolas Falliere, Liam O Murchu, Eric Chien February 2011)
- [G1017] Volt Typhoon: [Volt Typhoon](https://attack.mitre.org/groups/G1017) has used compromised domain accounts to authenticate to devices on compromised networks.(Citation: Microsoft Volt Typhoon May 2023)(Citation: Secureworks BRONZE SILHOUETTE May 2023)(Citation: CISA AA24-038A PRC Critical Infrastructure February 2024)
- [G1043] BlackByte: [BlackByte](https://attack.mitre.org/groups/G1043) captured credentials for or impersonated domain administration users.(Citation: Microsoft BlackByte 2023)(Citation: Cisco BlackByte 2024)
- [G0143] Aquatic Panda: [Aquatic Panda](https://attack.mitre.org/groups/G0143) used multiple mechanisms to capture valid user accounts for victim domains to enable lateral movement and access to additional hosts in victim environments.(Citation: Crowdstrike HuntReport 2022)

#### T1078.003 - Valid Accounts: Local Accounts

Description:

Adversaries may obtain and abuse credentials of a local account as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion. Local accounts are those configured by an organization for use by users, remote support, services, or for administration on a single system or service.

Local Accounts may also be abused to elevate privileges and harvest credentials through [OS Credential Dumping](https://attack.mitre.org/techniques/T1003). Password reuse may allow the abuse of local accounts across a set of machines on a network for the purposes of Privilege Escalation and Lateral Movement.

Procedures:

- [G0094] Kimsuky: [Kimsuky](https://attack.mitre.org/groups/G0094) has used a tool called GREASE to add a Windows admin account in order to allow them continued access via RDP.(Citation: Netscout Stolen Pencil Dec 2018)
- [S0367] Emotet: [Emotet](https://attack.mitre.org/software/S0367) can brute force a local admin password, then use it to facilitate lateral movement.(Citation: Malwarebytes Emotet Dec 2017)
- [S0154] Cobalt Strike: [Cobalt Strike](https://attack.mitre.org/software/S0154) can use known credentials to run commands and spawn processes as a local user account.(Citation: cobaltstrike manual)(Citation: CobaltStrike Daddy May 2017)
- [G0056] PROMETHIUM: [PROMETHIUM](https://attack.mitre.org/groups/G0056) has created admin accounts on a compromised host.(Citation: Bitdefender StrongPity June 2020)
- [G0051] FIN10: [FIN10](https://attack.mitre.org/groups/G0051) has moved laterally using the Local Administrator account.(Citation: FireEye FIN10 June 2017)
- [G1040] Play: [Play](https://attack.mitre.org/groups/G1040) has used valid  local accounts to gain initial access.(Citation: Trend Micro Ransomware Spotlight Play July 2023)
- [G0050] APT32: [APT32](https://attack.mitre.org/groups/G0050) has used legitimate local admin account credentials.(Citation: FireEye APT32 May 2017)
- [G1041] Sea Turtle: [Sea Turtle](https://attack.mitre.org/groups/G1041) compromised cPanel accounts in victim environments.(Citation: Hunt Sea Turtle 2024)
- [G0081] Tropic Trooper: [Tropic Trooper](https://attack.mitre.org/groups/G0081) has used known administrator account credentials to execute the backdoor directly.(Citation: TrendMicro Tropic Trooper May 2020)
- [G0125] HAFNIUM: [HAFNIUM](https://attack.mitre.org/groups/G0125) has used the NT AUTHORITY\SYSTEM account to create files on Exchange servers.(Citation: FireEye Exchange Zero Days March 2021)
- [G0046] FIN7: [FIN7](https://attack.mitre.org/groups/G0046) has used compromised credentials for access as SYSTEM on Exchange servers.(Citation: Microsoft Ransomware as a Service)
- [C0024] SolarWinds Compromise: During the [SolarWinds Compromise](https://attack.mitre.org/campaigns/C0024), [APT29](https://attack.mitre.org/groups/G0016) used compromised local accounts to access victims' networks.(Citation: CrowdStrike StellarParticle January 2022)
- [C0049] Leviathan Australian Intrusions: [Leviathan](https://attack.mitre.org/groups/G0065) used captured local account information, such as service accounts, for actions during [Leviathan Australian Intrusions](https://attack.mitre.org/campaigns/C0049).(Citation: CISA Leviathan 2024)
- [G1047] Velvet Ant: [Velvet Ant](https://attack.mitre.org/groups/G1047) accessed vulnerable Cisco switch devices using accounts with administrator privileges.(Citation: Sygnia VelvetAnt 2024B)
- [G0016] APT29: [APT29](https://attack.mitre.org/groups/G0016) targets dormant or inactive user accounts, accounts belonging to individuals no longer at the organization but whose accounts remain on the system, for access and persistence.(Citation: NCSC et al APT29 2024)
- [S0368] NotPetya: [NotPetya](https://attack.mitre.org/software/S0368) can use valid credentials with [PsExec](https://attack.mitre.org/software/S0029) or <code>wmic</code> to spread itself to remote systems.(Citation: Talos Nyetya June 2017)(Citation: US-CERT NotPetya 2017)
- [S1202] LockBit 3.0: [LockBit 3.0](https://attack.mitre.org/software/S1202) can use a compromised local account for lateral movement.(Citation: Joint Cybersecurity Advisory LockBit 3.0 MAR 2023)
- [S0221] Umbreon: [Umbreon](https://attack.mitre.org/software/S0221) creates valid local users to provide access to the system.(Citation: Umbreon Trend Micro)
- [C0014] Operation Wocao: During [Operation Wocao](https://attack.mitre.org/campaigns/C0014), threat actors used local account credentials found during the intrusion for lateral movement and privilege escalation.(Citation: FoxIT Wocao December 2019)
- [G0010] Turla: [Turla](https://attack.mitre.org/groups/G0010) has abused local accounts that have the same password across the victim’s network.(Citation: ESET Crutch December 2020)

#### T1078.004 - Valid Accounts: Cloud Accounts

Description:

Valid accounts in cloud environments may allow adversaries to perform actions to achieve Initial Access, Persistence, Privilege Escalation, or Defense Evasion. Cloud accounts are those created and configured by an organization for use by users, remote support, services, or for administration of resources within a cloud service provider or SaaS application. Cloud Accounts can exist solely in the cloud; alternatively, they may be hybrid-joined between on-premises systems and the cloud through syncing or federation with other identity sources such as Windows Active Directory.(Citation: AWS Identity Federation)(Citation: Google Federating GC)(Citation: Microsoft Deploying AD Federation)

Service or user accounts may be targeted by adversaries through [Brute Force](https://attack.mitre.org/techniques/T1110), [Phishing](https://attack.mitre.org/techniques/T1566), or various other means to gain access to the environment. Federated or synced accounts may be a pathway for the adversary to affect both on-premises systems and cloud environments - for example, by leveraging shared credentials to log onto [Remote Services](https://attack.mitre.org/techniques/T1021). High privileged cloud accounts, whether federated, synced, or cloud-only, may also allow pivoting to on-premises environments by leveraging SaaS-based [Software Deployment Tools](https://attack.mitre.org/techniques/T1072) to run commands on hybrid-joined devices.

An adversary may create long lasting [Additional Cloud Credentials](https://attack.mitre.org/techniques/T1098/001) on a compromised cloud account to maintain persistence in the environment. Such credentials may also be used to bypass security controls such as multi-factor authentication. 

Cloud accounts may also be able to assume [Temporary Elevated Cloud Access](https://attack.mitre.org/techniques/T1548/005) or other privileges through various means within the environment. Misconfigurations in role assignments or role assumption policies may allow an adversary to use these mechanisms to leverage permissions outside the intended scope of the account. Such over privileged accounts may be used to harvest sensitive data from online storage accounts and databases through [Cloud API](https://attack.mitre.org/techniques/T1059/009) or other methods. For example, in Azure environments, adversaries may target Azure Managed Identities, which allow associated Azure resources to request access tokens. By compromising a resource with an attached Managed Identity, such as an Azure VM, adversaries may be able to [Steal Application Access Token](https://attack.mitre.org/techniques/T1528)s to move laterally across the cloud environment.(Citation: SpecterOps Managed Identity 2022)

Procedures:

- [C0024] SolarWinds Compromise: During the [SolarWinds Compromise](https://attack.mitre.org/campaigns/C0024), [APT29](https://attack.mitre.org/groups/G0016) used a compromised O365 administrator account to create a new Service Principal.(Citation: CrowdStrike StellarParticle January 2022)
- [G0016] APT29: [APT29](https://attack.mitre.org/groups/G0016) has gained access to a global administrator account in Azure AD and has used `Service Principal` credentials in Exchange.(Citation: Mandiant APT29 Microsoft 365 2022)(Citation: Mandiant APT29 Eye Spy Email Nov 22)
- [G1023] APT5: [APT5](https://attack.mitre.org/groups/G1023) has accessed Microsoft M365 cloud environments using stolen credentials. (Citation: Mandiant Pulse Secure Update May 2021)
- [S0684] ROADTools: [ROADTools](https://attack.mitre.org/software/S0684) leverages valid cloud credentials to perform enumeration operations using the internal Azure AD Graph API.(Citation: Roadtools)
- [G0007] APT28: [APT28](https://attack.mitre.org/groups/G0007) has used compromised Office 365 service accounts with Global Administrator privileges to collect email from user inboxes.(Citation: Cybersecurity Advisory GRU Brute Force Campaign July 2021)
- [C0027] C0027: During [C0027](https://attack.mitre.org/campaigns/C0027), [Scattered Spider](https://attack.mitre.org/groups/G1015) leveraged compromised credentials from victim users  to authenticate to Azure tenants.(Citation: Crowdstrike TELCO BPO Campaign December 2022)
- [S0683] Peirates: [Peirates](https://attack.mitre.org/software/S0683) can use stolen service account tokens to perform its operations.(Citation: Peirates GitHub)
- [G0125] HAFNIUM: [HAFNIUM](https://attack.mitre.org/groups/G0125) has abused service principals in compromised environments to enable data exfiltration.(Citation: Microsoft Silk Typhoon MAR 2025)
- [S1091] Pacu: [Pacu](https://attack.mitre.org/software/S1091) leverages valid cloud accounts to perform most of its operations.(Citation: GitHub Pacu)
- [G0064] APT33: [APT33](https://attack.mitre.org/groups/G0064) has used compromised Office 365 accounts in tandem with [Ruler](https://attack.mitre.org/software/S0358) in an attempt to gain control of endpoints.(Citation: Microsoft Holmium June 2020)
- [G1004] LAPSUS$: [LAPSUS$](https://attack.mitre.org/groups/G1004) has used compromised credentials to access cloud assets within a target organization.(Citation: MSTIC DEV-0537 Mar 2022)
- [G0004] Ke3chang: [Ke3chang](https://attack.mitre.org/groups/G0004) has used compromised credentials to sign into victims’ Microsoft 365 accounts.(Citation: Microsoft NICKEL December 2021)


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


### T1133 - External Remote Services

Description:

Adversaries may leverage external-facing remote services to initially access and/or persist within a network. Remote services such as VPNs, Citrix, and other access mechanisms allow users to connect to internal enterprise network resources from external locations. There are often remote service gateways that manage connections and credential authentication for these services. Services such as [Windows Remote Management](https://attack.mitre.org/techniques/T1021/006) and [VNC](https://attack.mitre.org/techniques/T1021/005) can also be used externally.(Citation: MacOS VNC software for Remote Desktop)

Access to [Valid Accounts](https://attack.mitre.org/techniques/T1078) to use the service is often a requirement, which could be obtained through credential pharming or by obtaining the credentials from users after compromising the enterprise network.(Citation: Volexity Virtual Private Keylogging) Access to remote services may be used as a redundant or persistent access mechanism during an operation.

Access may also be gained through an exposed service that doesn’t require authentication. In containerized environments, this may include an exposed Docker API, Kubernetes API server, kubelet, or web application such as the Kubernetes dashboard.(Citation: Trend Micro Exposed Docker Server)(Citation: Unit 42 Hildegard Malware)

Procedures:

- [G0139] TeamTNT: [TeamTNT](https://attack.mitre.org/groups/G0139) has used open-source tools such as Weave Scope to target exposed Docker API ports and gain initial access to victim environments.(Citation: Intezer TeamTNT September 2020)(Citation: Cisco Talos Intelligence Group) [TeamTNT](https://attack.mitre.org/groups/G0139) has also targeted exposed kubelets for Kubernetes environments.(Citation: Unit 42 Hildegard Malware)
- [G1016] FIN13: [FIN13](https://attack.mitre.org/groups/G1016) has gained access to compromised environments via remote access services such as the corporate virtual private network (VPN).(Citation: Mandiant FIN13 Aug 2022)
- [C0012] Operation CuckooBees: During [Operation CuckooBees](https://attack.mitre.org/campaigns/C0012), the threat actors enabled WinRM over HTTP/HTTPS as a backup persistence mechanism using the following command: `cscript //nologo "C:\Windows\System32\winrm.vbs" set winrm/config/service@{EnableCompatibilityHttpsListener="true"}`.(Citation: Cybereason OperationCuckooBees May 2022)
- [S0362] Linux Rabbit: [Linux Rabbit](https://attack.mitre.org/software/S0362) attempts to gain access to the server via SSH.(Citation: Anomali Linux Rabbit 2018)
- [C0002] Night Dragon: During [Night Dragon](https://attack.mitre.org/campaigns/C0002), threat actors used compromised VPN accounts to gain access to victim systems.(Citation: McAfee Night Dragon)
- [S1060] Mafalda: [Mafalda](https://attack.mitre.org/software/S1060) can establish an SSH connection from a compromised host to a server.(Citation: SentinelLabs Metador Technical Appendix Sept 2022)
- [G1003] Ember Bear: [Ember Bear](https://attack.mitre.org/groups/G1003) have used VPNs both for initial access to victim environments and for persistence within them following compromise.(Citation: CISA GRU29155 2024)
- [G0026] APT18: [APT18](https://attack.mitre.org/groups/G0026) actors leverage legitimate credentials to log into external remote services.(Citation: RSA2017 Detect and Respond Adair)
- [G0034] Sandworm Team: [Sandworm Team](https://attack.mitre.org/groups/G0034) has used Dropbear SSH with a hardcoded backdoor password to maintain persistence within the target network. [Sandworm Team](https://attack.mitre.org/groups/G0034) has also used VPN tunnels established in legitimate software company infrastructure to gain access to internal networks of that software company's users.(Citation: ESET BlackEnergy Jan 2016)(Citation: ESET Telebots June 2017)(Citation: ANSSI Sandworm January 2021)(Citation: mandiant_apt44_unearthing_sandworm)
- [G1017] Volt Typhoon: [Volt Typhoon](https://attack.mitre.org/groups/G1017) has used VPNs to connect to victim environments and enable post-exploitation actions.(Citation: CISA AA24-038A PRC Critical Infrastructure February 2024)
- [G1047] Velvet Ant: [Velvet Ant](https://attack.mitre.org/groups/G1047) has leveraged access to internet-facing remote services to compromise and retain access to victim environments.(Citation: Sygnia VelvetAnt 2024A)
- [S0601] Hildegard: [Hildegard](https://attack.mitre.org/software/S0601) was executed through an unsecure kubelet that allowed anonymous access to the victim environment.(Citation: Unit 42 Hildegard Malware)
- [G1015] Scattered Spider: [Scattered Spider](https://attack.mitre.org/groups/G1015) has leveraged legitimate remote management tools to maintain persistent access.(Citation: CrowdStrike Scattered Spider BYOVD January 2023)
- [G0096] APT41: [APT41](https://attack.mitre.org/groups/G0096) compromised an online billing/payment service using VPN access between a third-party service provider and the targeted payment service.(Citation: FireEye APT41 Aug 2019)
- [G1004] LAPSUS$: [LAPSUS$](https://attack.mitre.org/groups/G1004) has gained access to internet-facing systems and applications, including virtual private network (VPN), remote desktop protocol (RDP), and virtual desktop infrastructure (VDI) including Citrix. (Citation: MSTIC DEV-0537 Mar 2022)(Citation: NCC Group LAPSUS Apr 2022)
- [G0049] OilRig: [OilRig](https://attack.mitre.org/groups/G0049) uses remote services such as VPN, Citrix, or OWA to persist in an environment.(Citation: FireEye APT34 Webinar Dec 2017)
- [G0093] GALLIUM: [GALLIUM](https://attack.mitre.org/groups/G0093) has used VPN services, including SoftEther VPN, to access and maintain persistence in victim environments.(Citation: Cybereason Soft Cell June 2019)(Citation: Microsoft GALLIUM December 2019)
- [G0004] Ke3chang: [Ke3chang](https://attack.mitre.org/groups/G0004) has gained access through VPNs including with compromised accounts and stolen VPN certificates.(Citation: NCC Group APT15 Alive and Strong)(Citation: Microsoft NICKEL December 2021)
- [C0028] 2015 Ukraine Electric Power Attack: During the [2015 Ukraine Electric Power Attack](https://attack.mitre.org/campaigns/C0028), [Sandworm Team](https://attack.mitre.org/groups/G0034) installed a modified Dropbear SSH client as the backdoor to target systems. (Citation: Booz Allen Hamilton)
- [G0102] Wizard Spider: [Wizard Spider](https://attack.mitre.org/groups/G0102) has accessed victim networks by using stolen credentials to access the corporate VPN infrastructure.(Citation: FireEye KEGTAP SINGLEMALT October 2020)
- [G0016] APT29: [APT29](https://attack.mitre.org/groups/G0016) has used compromised identities to access networks via VPNs and Citrix.(Citation: NCSC APT29 July 2020)(Citation: Mandiant APT29 Microsoft 365 2022)
- [C0004] CostaRicto: During [CostaRicto](https://attack.mitre.org/campaigns/C0004), the threat actors set up remote tunneling using an SSH tool to maintain access to a compromised environment.(Citation: BlackBerry CostaRicto November 2020)
- [G0094] Kimsuky: [Kimsuky](https://attack.mitre.org/groups/G0094) has used RDP to establish persistence.(Citation: CISA AA20-301A Kimsuky)
- [G0053] FIN5: [FIN5](https://attack.mitre.org/groups/G0053) has used legitimate VPN, Citrix, or VNC credentials to maintain access to a victim environment.(Citation: FireEye Respond Webinar July 2017)(Citation: DarkReading FireEye FIN5 Oct 2015)(Citation: Mandiant FIN5 GrrCON Oct 2016)
- [C0024] SolarWinds Compromise: For the [SolarWinds Compromise](https://attack.mitre.org/campaigns/C0024), [APT29](https://attack.mitre.org/groups/G0016) used compromised identities to access networks via SSH, VPNs, and other remote access tools.(Citation: MSTIC NOBELIUM Mar 2021)(Citation: CrowdStrike StellarParticle January 2022)
- [G0027] Threat Group-3390: [Threat Group-3390](https://attack.mitre.org/groups/G0027) actors look for and use VPN profiles during an operation to access the network using external VPN services.(Citation: Dell TG-3390) [Threat Group-3390](https://attack.mitre.org/groups/G0027) has also obtained OWA account credentials during intrusions that it subsequently used to attempt to regain access when evicted from a victim network.(Citation: SecureWorks BRONZE UNION June 2017)
- [G1041] Sea Turtle: [Sea Turtle](https://attack.mitre.org/groups/G1041) has used external-facing SSH to achieve initial access to the IT environments of victim organizations.(Citation: Hunt Sea Turtle 2024)
- [S0599] Kinsing: [Kinsing](https://attack.mitre.org/software/S0599) was executed in an Ubuntu container deployed via an open Docker daemon API.(Citation: Aqua Kinsing April 2020)
- [C0027] C0027: During [C0027](https://attack.mitre.org/campaigns/C0027), [Scattered Spider](https://attack.mitre.org/groups/G1015) used Citrix and VPNs to persist in compromised environments.(Citation: Crowdstrike TELCO BPO Campaign December 2022)
- [G0115] GOLD SOUTHFIELD: [GOLD SOUTHFIELD](https://attack.mitre.org/groups/G0115) has used publicly-accessible RDP and remote management and monitoring (RMM) servers to gain access to victim machines.(Citation: Secureworks REvil September 2019)
- [G0114] Chimera: [Chimera](https://attack.mitre.org/groups/G0114) has used legitimate credentials to login to an external VPN, Citrix, SSH, and other remote services.(Citation: Cycraft Chimera April 2020)(Citation: NCC Group Chimera January 2021)
- [C0032] C0032: During the [C0032](https://attack.mitre.org/campaigns/C0032) campaign, [TEMP.Veles](https://attack.mitre.org/groups/G0088) used VPN access to persist in the victim environment.(Citation: FireEye TRITON 2019)
- [G0035] Dragonfly: [Dragonfly](https://attack.mitre.org/groups/G0035) has used VPNs and Outlook Web Access (OWA) to maintain access to victim networks.(Citation: US-CERT TA18-074A)(Citation: CISA AA20-296A Berserk Bear December 2020)
- [G1024] Akira: [Akira](https://attack.mitre.org/groups/G1024) uses compromised VPN accounts for initial access to victim networks.(Citation: Secureworks GOLD SAHARA)
- [G0007] APT28: [APT28](https://attack.mitre.org/groups/G0007) has used [Tor](https://attack.mitre.org/software/S0183) and a variety of commercial VPN services to route brute force authentication attempts.(Citation: Cybersecurity Advisory GRU Brute Force Campaign July 2021)
- [G1040] Play: [Play](https://attack.mitre.org/groups/G1040) has used Remote Desktop Protocol (RDP) and Virtual Private Networks (VPN) for initial access.(Citation: CISA Play Ransomware Advisory December 2023)(Citation: Trend Micro Ransomware Spotlight Play July 2023)
- [C0014] Operation Wocao: During [Operation Wocao](https://attack.mitre.org/campaigns/C0014), threat actors used stolen credentials to connect to the victim's network via VPN.(Citation: FoxIT Wocao December 2019)
- [C0046] ArcaneDoor: [ArcaneDoor](https://attack.mitre.org/campaigns/C0046) used WebVPN sessions commonly associated with Clientless SSLVPN services to communicate to compromised devices.(Citation: CCCS ArcaneDoor 2024)
- [S0600] Doki: [Doki](https://attack.mitre.org/software/S0600) was executed through an open Docker daemon API port.(Citation: Intezer Doki July 20)
- [G0065] Leviathan: [Leviathan](https://attack.mitre.org/groups/G0065) has used external remote services such as virtual private networks (VPN) to gain initial access.(Citation: CISA AA21-200A APT40 July 2021)


### T1189 - Drive-by Compromise

Description:

Adversaries may gain access to a system through a user visiting a website over the normal course of browsing. Multiple ways of delivering exploit code to a browser exist (i.e., [Drive-by Target](https://attack.mitre.org/techniques/T1608/004)), including:

* A legitimate website is compromised, allowing adversaries to inject malicious code
* Script files served to a legitimate website from a publicly writeable cloud storage bucket are modified by an adversary
* Malicious ads are paid for and served through legitimate ad providers (i.e., [Malvertising](https://attack.mitre.org/techniques/T1583/008))
* Built-in web application interfaces that allow user-controllable content are leveraged for the insertion of malicious scripts or iFrames (e.g., cross-site scripting)

Browser push notifications may also be abused by adversaries and leveraged for malicious code injection via [User Execution](https://attack.mitre.org/techniques/T1204). By clicking "allow" on browser push notifications, users may be granting a website permission to run JavaScript code on their browser.(Citation: Push notifications - viruspositive)(Citation: push notification -mcafee)(Citation: push notifications - malwarebytes)

Often the website used by an adversary is one visited by a specific community, such as government, a particular industry, or a particular region, where the goal is to compromise a specific user or set of users based on a shared interest. This kind of targeted campaign is often referred to a strategic web compromise or watering hole attack. There are several known examples of this occurring.(Citation: Shadowserver Strategic Web Compromise)

Typical drive-by compromise process:

1. A user visits a website that is used to host the adversary controlled content.
2. Scripts automatically execute, typically searching versions of the browser and plugins for a potentially vulnerable version. The user may be required to assist in this process by enabling scripting, notifications, or active website components and ignoring warning dialog boxes.
3. Upon finding a vulnerable version, exploit code is delivered to the browser.
4. If exploitation is successful, the adversary will gain code execution on the user's system unless other protections are in place. In some cases, a second visit to the website after the initial scan is required before exploit code is delivered.

Unlike [Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190), the focus of this technique is to exploit software on a client endpoint upon visiting a website. This will commonly give an adversary access to systems on the internal network instead of external systems that may be in a DMZ.

Procedures:

- [G0134] Transparent Tribe: [Transparent Tribe](https://attack.mitre.org/groups/G0134) has used websites with malicious hyperlinks and iframes to infect targeted victims with [Crimson](https://attack.mitre.org/software/S0115), [njRAT](https://attack.mitre.org/software/S0385), and other malicious tools.(Citation: Proofpoint Operation Transparent Tribe March 2016)(Citation: Unit 42 ProjectM March 2016)(Citation: Talos Transparent Tribe May 2021)
- [G0048] RTM: [RTM](https://attack.mitre.org/groups/G0048) has distributed its malware via the RIG and SUNDOWN exploit kits, as well as online advertising network <code>Yandex.Direct</code>.(Citation: ESET RTM Feb 2017)(Citation: ESET Buhtrap and Buran April 2019)
- [G0068] PLATINUM: [PLATINUM](https://attack.mitre.org/groups/G0068) has sometimes used drive-by attacks against vulnerable browser plugins.(Citation: Microsoft PLATINUM April 2016)
- [G0112] Windshift: [Windshift](https://attack.mitre.org/groups/G0112) has used compromised websites to register custom URL schemes on a remote system.(Citation: objective-see windtail1 dec 2018)
- [S0215] KARAE: [KARAE](https://attack.mitre.org/software/S0215) was distributed through torrent file-sharing websites to South Korean victims, using a YouTube video downloader application as a lure.(Citation: FireEye APT37 Feb 2018)
- [S0483] IcedID: [IcedID](https://attack.mitre.org/software/S0483) has cloned legitimate websites/applications to distribute the malware.(Citation: Trendmicro_IcedID)
- [G1006] Earth Lusca: [Earth Lusca](https://attack.mitre.org/groups/G1006) has performed watering hole attacks.(Citation: TrendMicro EarthLusca 2022)
- [G0082] APT38: [APT38](https://attack.mitre.org/groups/G0082) has conducted watering holes schemes to gain initial access to victims.(Citation: FireEye APT38 Oct 2018)(Citation: CISA AA20-239A BeagleBoyz August 2020)
- [S0482] Bundlore: [Bundlore](https://attack.mitre.org/software/S0482) has been spread through malicious advertisements on websites.(Citation: MacKeeper Bundlore Apr 2019)
- [G0001] Axiom: [Axiom](https://attack.mitre.org/groups/G0001) has used watering hole attacks to gain access.(Citation: Cisco Group 72)
- [G0073] APT19: [APT19](https://attack.mitre.org/groups/G0073) performed a watering hole attack on forbes.com in 2014 to compromise targets.(Citation: Unit 42 C0d0so0 Jan 2016)
- [G0012] Darkhotel: [Darkhotel](https://attack.mitre.org/groups/G0012) used embedded iframes on hotel login portals to redirect selected victims to download malware.(Citation: Kaspersky Darkhotel)
- [G0138] Andariel: [Andariel](https://attack.mitre.org/groups/G0138) has used watering hole attacks, often with zero-day exploits, to gain initial access to victims within a specific IP range.(Citation: AhnLab Andariel Subgroup of Lazarus June 2018)(Citation: TrendMicro New Andariel Tactics July 2018)
- [G0007] APT28: [APT28](https://attack.mitre.org/groups/G0007) has compromised targets via strategic web compromise utilizing custom exploit kits.(Citation: Secureworks IRON TWILIGHT Active Measures March 2017) [APT28](https://attack.mitre.org/groups/G0007) used reflected cross-site scripting (XSS) against government websites to redirect users to phishing webpages.(Citation: Leonard TAG 2023)
- [G0035] Dragonfly: [Dragonfly](https://attack.mitre.org/groups/G0035) has compromised targets via strategic web compromise (SWC) utilizing a custom exploit kit.(Citation: Secureworks IRON LIBERTY July 2019)(Citation: US-CERT TA18-074A)(Citation: Gigamon Berserk Bear October 2021)
- [S0606] Bad Rabbit: [Bad Rabbit](https://attack.mitre.org/software/S0606) spread through watering holes on popular sites by injecting JavaScript into the HTML body or a <code>.js</code> file.(Citation: ESET Bad Rabbit)(Citation: Secure List Bad Rabbit)
- [G0070] Dark Caracal: [Dark Caracal](https://attack.mitre.org/groups/G0070) leveraged a watering hole to serve up malicious code.(Citation: Lookout Dark Caracal Jan 2018)
- [G0010] Turla: [Turla](https://attack.mitre.org/groups/G0010) has infected victims using watering holes.(Citation: ESET ComRAT May 2020)(Citation: Secureworks IRON HUNTER Profile)
- [G0040] Patchwork: [Patchwork](https://attack.mitre.org/groups/G0040) has used watering holes to deliver files with exploits to initial victims.(Citation: Symantec Patchwork)(Citation: Volexity Patchwork June 2018)
- [G0065] Leviathan: [Leviathan](https://attack.mitre.org/groups/G0065) has infected victims using watering holes.(Citation: CISA AA21-200A APT40 July 2021)
- [G0050] APT32: [APT32](https://attack.mitre.org/groups/G0050) has infected victims by tricking them into visiting compromised watering hole websites.(Citation: ESET OceanLotus)(Citation: Volexity Ocean Lotus November 2020)
- [G0060] BRONZE BUTLER: [BRONZE BUTLER](https://attack.mitre.org/groups/G0060) compromised three Japanese websites using a Flash exploit to perform watering hole attacks.(Citation: Symantec Tick Apr 2016)
- [C0016] Operation Dust Storm: During [Operation Dust Storm](https://attack.mitre.org/campaigns/C0016), the threat actors used a watering hole attack on a popular software reseller to exploit the then-zero-day Internet Explorer vulnerability CVE-2014-0322.(Citation: Cylance Dust Storm)
- [G0032] Lazarus Group: [Lazarus Group](https://attack.mitre.org/groups/G0032) delivered [RATANKBA](https://attack.mitre.org/software/S0241) and other malicious code to victims via a compromised legitimate website.(Citation: RATANKBA)(Citation: Google TAG Lazarus Jan 2021)
- [G0027] Threat Group-3390: [Threat Group-3390](https://attack.mitre.org/groups/G0027) has extensively used strategic web compromises to target victims.(Citation: Dell TG-3390)(Citation: Securelist LuckyMouse June 2018)
- [C0010] C0010: During [C0010](https://attack.mitre.org/campaigns/C0010), UNC3890 actors likely established a watering hole that was hosted on a login page of a legitimate Israeli shipping company that was active until at least November 2021.(Citation: Mandiant UNC3890 Aug 2022)
- [S0451] LoudMiner: [LoudMiner](https://attack.mitre.org/software/S0451) is typically bundled with pirated copies of Virtual Studio Technology (VST) for Windows and macOS.(Citation: ESET LoudMiner June 2019)
- [G1035] Winter Vivern: [Winter Vivern](https://attack.mitre.org/groups/G1035) created dedicated web pages mimicking legitimate government websites to deliver malicious fake anti-virus software.(Citation: CERT-UA WinterVivern 2023)
- [S1124] SocGholish: [SocGholish](https://attack.mitre.org/software/S1124) has been distributed through compromised websites with malicious content often masquerading as browser updates.(Citation: SocGholish-update)
- [G0066] Elderwood: [Elderwood](https://attack.mitre.org/groups/G0066) has delivered zero-day exploits and malware to victims by injecting malicious code into specific public Web pages visited by targets within a particular sector.(Citation: Symantec Elderwood Sept 2012)(Citation: CSM Elderwood Sept 2012)(Citation: Security Affairs Elderwood Sept 2012)
- [S0496] REvil: [REvil](https://attack.mitre.org/software/S0496) has infected victim machines through compromised websites and exploit kits.(Citation: Secureworks REvil September 2019)(Citation: McAfee Sodinokibi October 2019)(Citation: Picus Sodinokibi January 2020)(Citation: Secureworks GandCrab and REvil September 2019)
- [G1020] Mustard Tempest: [Mustard Tempest](https://attack.mitre.org/groups/G1020) has used drive-by downloads for initial infection, often using fake browser updates as a lure.(Citation: SocGholish-update)(Citation: SentinelOne SocGholish Infrastructure November 2022)(Citation: Red Canary SocGholish March 2024)(Citation: Secureworks Gold Prelude Profile)
- [G0067] APT37: [APT37](https://attack.mitre.org/groups/G0067) has used strategic web compromises, particularly of South Korean websites, to distribute malware. The group has also used torrent file-sharing sites to more indiscriminately disseminate malware to victims. As part of their compromises, the group has used a Javascript based profiler called RICECURRY to profile a victim's web browser and deliver malicious code accordingly.(Citation: Securelist ScarCruft Jun 2016)(Citation: FireEye APT37 Feb 2018)(Citation: Volexity InkySquid BLUELIGHT August 2021)
- [G0077] Leafminer: [Leafminer](https://attack.mitre.org/groups/G0077) has infected victims using watering holes.(Citation: Symantec Leafminer July 2018)
- [S0531] Grandoreiro: [Grandoreiro](https://attack.mitre.org/software/S0531) has used compromised websites and Google Ads to bait victims into downloading its installer.(Citation: Securelist Brazilian Banking Malware July 2020)(Citation: IBM Grandoreiro April 2020)
- [G0095] Machete: [Machete](https://attack.mitre.org/groups/G0095) has distributed [Machete](https://attack.mitre.org/software/S0409) through a fake blog website.(Citation: Securelist Machete Aug 2014)
- [G1012] CURIUM: [CURIUM](https://attack.mitre.org/groups/G1012) has used strategic website compromise to infect victims with malware such as [IMAPLoader](https://attack.mitre.org/software/S1152).(Citation: PWC Yellow Liderc 2023)
- [S1086] Snip3: [Snip3](https://attack.mitre.org/software/S1086) has been delivered to targets via downloads from malicious domains.(Citation: Telefonica Snip3 December 2021)
- [G1034] Daggerfly: [Daggerfly](https://attack.mitre.org/groups/G1034) has used strategic website compromise for initial access against victims.(Citation: ESET EvasivePanda 2024)
- [G0056] PROMETHIUM: [PROMETHIUM](https://attack.mitre.org/groups/G0056) has used watering hole attacks to deliver malicious versions of legitimate installers.(Citation: Bitdefender StrongPity June 2020)
- [S0216] POORAIM: [POORAIM](https://attack.mitre.org/software/S0216) has been delivered through compromised sites acting as watering holes.(Citation: FireEye APT37 Feb 2018)
- [G0124] Windigo: [Windigo](https://attack.mitre.org/groups/G0124) has distributed Windows malware via drive-by downloads.(Citation: ESET Windigo Mar 2014)
- [G0059] Magic Hound: [Magic Hound](https://attack.mitre.org/groups/G0059) has conducted watering-hole attacks through media and magazine websites.(Citation: ClearSky Kittens Back 3 August 2020)


### T1190 - Exploit Public-Facing Application

Description:

Adversaries may attempt to exploit a weakness in an Internet-facing host or system to initially access a network. The weakness in the system can be a software bug, a temporary glitch, or a misconfiguration.

Exploited applications are often websites/web servers, but can also include databases (like SQL), standard services (like SMB or SSH), network device administration and management protocols (like SNMP and Smart Install), and any other system with Internet-accessible open sockets.(Citation: NVD CVE-2016-6662)(Citation: CIS Multiple SMB Vulnerabilities)(Citation: US-CERT TA18-106A Network Infrastructure Devices 2018)(Citation: Cisco Blog Legacy Device Attacks)(Citation: NVD CVE-2014-7169) On ESXi infrastructure, adversaries may exploit exposed OpenSLP services; they may alternatively exploit exposed VMware vCenter servers.(Citation: Recorded Future ESXiArgs Ransomware 2023)(Citation: Ars Technica VMWare Code Execution Vulnerability 2021) Depending on the flaw being exploited, this may also involve [Exploitation for Defense Evasion](https://attack.mitre.org/techniques/T1211) or [Exploitation for Client Execution](https://attack.mitre.org/techniques/T1203).

If an application is hosted on cloud-based infrastructure and/or is containerized, then exploiting it may lead to compromise of the underlying instance or container. This can allow an adversary a path to access the cloud or container APIs (e.g., via the [Cloud Instance Metadata API](https://attack.mitre.org/techniques/T1552/005)), exploit container host access via [Escape to Host](https://attack.mitre.org/techniques/T1611), or take advantage of weak identity and access management policies.

Adversaries may also exploit edge network infrastructure and related appliances, specifically targeting devices that do not support robust host-based defenses.(Citation: Mandiant Fortinet Zero Day)(Citation: Wired Russia Cyberwar)

For websites and databases, the OWASP top 10 and CWE top 25 highlight the most common web-based vulnerabilities.(Citation: OWASP Top 10)(Citation: CWE top 25)

Procedures:

- [C0027] C0027: During [C0027](https://attack.mitre.org/campaigns/C0027), [Scattered Spider](https://attack.mitre.org/groups/G1015) exploited CVE-2021-35464 in the ForgeRock Open Access Management (OpenAM) application server to gain initial access.(Citation: Crowdstrike TELCO BPO Campaign December 2022)
- [G0106] Rocke: [Rocke](https://attack.mitre.org/groups/G0106) exploited Apache Struts, Oracle WebLogic (CVE-2017-10271), and Adobe ColdFusion (CVE-2017-3066) vulnerabilities to deliver malware.(Citation: Talos Rocke August 2018)(Citation: Unit 42 Rocke January 2019)
- [C0039] Versa Director Zero Day Exploitation: [Versa Director Zero Day Exploitation](https://attack.mitre.org/campaigns/C0039) involved exploitation of a vulnerability in Versa Director servers, since identified as CVE-2024-39717, for initial access and code execution.(Citation: Lumen Versa 2024)
- [C0045] ShadowRay: During [ShadowRay](https://attack.mitre.org/campaigns/C0045), threat actors exploited CVE-2023-48022 on publicly exposed Ray servers to steal computing power and to expose sensitive data.(Citation: Oligo ShadowRay Campaign MAR 2024)
- [G0027] Threat Group-3390: [Threat Group-3390](https://attack.mitre.org/groups/G0027) has exploited the Microsoft SharePoint vulnerability CVE-2019-0604 and CVE-2021-26855, CVE-2021-26857, CVE-2021-26858, and CVE-2021-27065 in Exchange Server.(Citation: Trend Micro Iron Tiger April 2021)
- [G0046] FIN7: [FIN7](https://attack.mitre.org/groups/G0046) has compromised targeted organizations through exploitation of CVE-2021-31207 in Exchange.(Citation: Microsoft Ransomware as a Service)
- [C0018] C0018: During [C0018](https://attack.mitre.org/campaigns/C0018), the threat actors exploited VMWare Horizon Unified Access Gateways that were vulnerable to several Log4Shell vulnerabilities, including CVE-2021-44228, CVE-2021-45046, CVE-2021-45105, and CVE-2021-44832.(Citation: Cisco Talos Avos Jun 2022)
- [S0623] Siloscape: [Siloscape](https://attack.mitre.org/software/S0623) is executed after the attacker gains initial access to a Windows container using a known vulnerability.(Citation: Unit 42 Siloscape Jun 2021)
- [G1017] Volt Typhoon: [Volt Typhoon](https://attack.mitre.org/groups/G1017) has gained initial access through exploitation of multiple vulnerabilities in internet-facing software and appliances such as Fortinet, Ivanti (formerly Pulse Secure), NETGEAR, Citrix, and Cisco.(Citation: Secureworks BRONZE SILHOUETTE May 2023)(Citation: CISA AA24-038A PRC Critical Infrastructure February 2024)
- [G0034] Sandworm Team: [Sandworm Team](https://attack.mitre.org/groups/G0034) exploits public-facing applications for initial access and to acquire infrastructure, such as exploitation of the EXIM mail transfer agent in Linux systems.(Citation: NSA Sandworm 2020)(Citation: Leonard TAG 2023)
- [G0007] APT28: [APT28](https://attack.mitre.org/groups/G0007) has used a variety of public exploits, including CVE 2020-0688 and CVE 2020-17144, to gain execution on vulnerable Microsoft Exchange; they have also conducted SQL injection attacks against external websites.(Citation: US District Court Indictment GRU Oct 2018)(Citation: Cybersecurity Advisory GRU Brute Force Campaign July 2021)
- [G0094] Kimsuky: [Kimsuky](https://attack.mitre.org/groups/G0094) has exploited various vulnerabilities for initial access, including Microsoft Exchange vulnerability CVE-2020-0688.(Citation: KISA Operation Muzabi)
- [G1003] Ember Bear: [Ember Bear](https://attack.mitre.org/groups/G1003) gains initial access to victim environments by exploiting external-facing services. Examples include exploitation of CVE-2021-26084 in Confluence servers; CVE-2022-41040, ProxyShell, and other vulnerabilities in Microsoft Exchange; and multiple vulnerabilities in open-source platforms such as content management systems.(Citation: Cadet Blizzard emerges as novel threat actor)(Citation: CISA GRU29155 2024)
- [C0014] Operation Wocao: During [Operation Wocao](https://attack.mitre.org/campaigns/C0014), threat actors gained initial access by exploiting vulnerabilities in JBoss webservers.(Citation: FoxIT Wocao December 2019)
- [C0002] Night Dragon: During [Night Dragon](https://attack.mitre.org/campaigns/C0002), threat actors used SQL injection exploits against extranet web servers to gain access.(Citation: McAfee Night Dragon)
- [C0017] C0017: During [C0017](https://attack.mitre.org/campaigns/C0017), [APT41](https://attack.mitre.org/groups/G0096) exploited CVE-2021-44207 in the USAHerds application and CVE-2021-44228 in Log4j, as well as other .NET deserialization, SQL injection, and directory traversal vulnerabilities to gain initial access.(Citation: Mandiant APT41)
- [G0135] BackdoorDiplomacy: [BackdoorDiplomacy](https://attack.mitre.org/groups/G0135) has exploited CVE-2020-5902, an F5 BIP-IP vulnerability, to drop a Linux backdoor. [BackdoorDiplomacy](https://attack.mitre.org/groups/G0135) has also exploited mis-configured Plesk servers.(Citation: ESET BackdoorDiplomacy Jun 2021)
- [G0115] GOLD SOUTHFIELD: [GOLD SOUTHFIELD](https://attack.mitre.org/groups/G0115) has exploited Oracle WebLogic vulnerabilities for initial compromise.(Citation: Secureworks REvil September 2019)
- [G1016] FIN13: [FIN13](https://attack.mitre.org/groups/G1016) has exploited known vulnerabilities such as CVE-2017-1000486 (Primefaces Application Expression Language Injection), CVE-2015-7450 (WebSphere Application Server SOAP Deserialization Exploit), CVE-2010-5326 (SAP NewWeaver Invoker Servlet Exploit), and EDB-ID-24963 (SAP NetWeaver ConfigServlet Remote Code Execution) to gain initial access.(Citation: Mandiant FIN13 Aug 2022)(Citation: Sygnia Elephant Beetle Jan 2022)
- [G0098] BlackTech: [BlackTech](https://attack.mitre.org/groups/G0098) has exploited a buffer overflow vulnerability in Microsoft Internet Information Services (IIS) 6.0, CVE-2017-7269, in order to establish a new HTTP or command and control (C2) server.(Citation: TrendMicro BlackTech June 2017)
- [S0225] sqlmap: [sqlmap](https://attack.mitre.org/software/S0225) can be used to automate exploitation of SQL injection vulnerabilities.(Citation: sqlmap Introduction)
- [G0059] Magic Hound: [Magic Hound](https://attack.mitre.org/groups/G0059) has exploited the Log4j utility (CVE-2021-44228), on-premises MS Exchange servers via "ProxyShell" (CVE-2021-34473, CVE-2021-34523, CVE-2021-31207), and Fortios SSL VPNs (CVE-2018-13379).(Citation: Check Point APT35 CharmPower January 2022)(Citation: DFIR Report APT35 ProxyShell March 2022)(Citation: Cybereason PowerLess February 2022)(Citation: DFIR Phosphorus November 2021)(Citation: Microsoft Iranian Threat Actor Trends November 2021)(Citation: Microsoft Log4j Vulnerability Exploitation December 2021)
- [C0049] Leviathan Australian Intrusions: [Leviathan](https://attack.mitre.org/groups/G0065) exploited public-facing web applications and appliances for initial access during [Leviathan Australian Intrusions](https://attack.mitre.org/campaigns/C0049).(Citation: CISA Leviathan 2024)
- [C0038] HomeLand Justice: For [HomeLand Justice](https://attack.mitre.org/campaigns/C0038), threat actors exploited CVE-2019-0604 in Microsoft SharePoint for initial access.(Citation: CISA Iran Albanian Attacks September 2022)
- [C0048] Operation MidnightEclipse: During [Operation MidnightEclipse](https://attack.mitre.org/campaigns/C0048), threat actors exploited CVE-2024-3400 in Palo Alto Networks GlobalProtect.(Citation: Volexity UPSTYLE 2024)(Citation: Palo Alto MidnightEclipse APR 2024)
- [S0516] SoreFang: [SoreFang](https://attack.mitre.org/software/S0516) can gain access by exploiting a Sangfor SSL VPN vulnerability that allows for the placement and delivery of malicious update binaries.(Citation: CISA SoreFang July 2016)
- [G1041] Sea Turtle: [Sea Turtle](https://attack.mitre.org/groups/G1041) gained access to victim environments by exploiting multiple known vulnerabilities over several campaigns.(Citation: Talos Sea Turtle 2019)(Citation: PWC Sea Turtle 2023)
- [S0412] ZxShell: [ZxShell](https://attack.mitre.org/software/S0412) has been dropped through exploitation of CVE-2011-2462, CVE-2013-3163, and CVE-2014-0322.(Citation: Talos ZxShell Oct 2014)
- [S1105] COATHANGER: [COATHANGER](https://attack.mitre.org/software/S1105) is installed following exploitation of a vulnerable FortiGate device. (Citation: NCSC-NL COATHANGER Feb 2024)
- [G0117] Fox Kitten: [Fox Kitten](https://attack.mitre.org/groups/G0117) has exploited known vulnerabilities in Fortinet, PulseSecure, and Palo Alto VPN appliances.(Citation: ClearkSky Fox Kitten February 2020)(Citation: Dragos PARISITE )(Citation: CrowdStrike PIONEER KITTEN August 2020)(Citation: CISA AA20-259A Iran-Based Actor September 2020)(Citation: ClearSky Pay2Kitten December 2020)
- [G1021] Cinnamon Tempest: [Cinnamon Tempest](https://attack.mitre.org/groups/G1021) has exploited multiple unpatched vulnerabilities for initial access including vulnerabilities in Microsoft Exchange, Manage Engine AdSelfService Plus, Confluence, and Log4j.(Citation: Microsoft Ransomware as a Service)(Citation: Microsoft Log4j Vulnerability Exploitation December 2021)(Citation: Sygnia Emperor Dragonfly October 2022)(Citation: SecureWorks BRONZE STARLIGHT Ransomware Operations June 2022)
- [G1043] BlackByte: [BlackByte](https://attack.mitre.org/groups/G1043) exploited vulnerabilities such as ProxyLogon and ProxyShell for initial access to victim environments.(Citation: FBI BlackByte 2022)(Citation: Picus BlackByte 2022)(Citation: Symantec BlackByte 2022)(Citation: Microsoft BlackByte 2023)
- [G0004] Ke3chang: [Ke3chang](https://attack.mitre.org/groups/G0004) has compromised networks by exploiting Internet-facing applications, including vulnerable Microsoft Exchange and SharePoint servers.(Citation: Microsoft NICKEL December 2021)
- [C0052] SPACEHOP Activity: [SPACEHOP Activity](https://attack.mitre.org/campaigns/C0052) has enabled the exploitation of CVE-2022-27518 and CVE-2022-27518 for illegitimate access.(Citation: NSA APT5 Citrix Threat Hunting December 2022)(Citation: ORB Mandiant)
- [C0012] Operation CuckooBees: During [Operation CuckooBees](https://attack.mitre.org/campaigns/C0012), the threat actors exploited multiple vulnerabilities in externally facing servers.(Citation: Cybereason OperationCuckooBees May 2022)
- [G1030] Agrius: [Agrius](https://attack.mitre.org/groups/G1030) exploits public-facing applications for initial access to victim environments. Examples include widespread attempts to exploit CVE-2018-13379 in FortiOS devices and SQL injection activity.(Citation: SentinelOne Agrius 2021)
- [C0024] SolarWinds Compromise: During the [SolarWinds Compromise](https://attack.mitre.org/campaigns/C0024), [APT29](https://attack.mitre.org/groups/G0016) exploited CVE-2020-0688 against the Microsoft Exchange Control Panel to regain access to a network.(Citation: Volexity SolarWinds)(Citation: Cybersecurity Advisory SVR TTP May 2021)
- [C0029] Cutting Edge: During [Cutting Edge](https://attack.mitre.org/campaigns/C0029), threat actors exploited CVE-2023-46805 and CVE-2024-21887 in Ivanti Connect Secure VPN appliances to enable authentication bypass and command injection. A server-side request forgery (SSRF) vulnerability, CVE-2024-21893, was identified later and used to bypass mitigations for the initial two vulnerabilities by chaining with CVE-2024-21887.(Citation: Mandiant Cutting Edge January 2024)(Citation: Volexity Ivanti Zero-Day Exploitation January 2024)(Citation: Volexity Ivanti Global Exploitation January 2024)(Citation: Mandiant Cutting Edge Part 2 January 2024)(Citation: Mandiant Cutting Edge Part 3 February 2024)
- [G0045] menuPass: [menuPass](https://attack.mitre.org/groups/G0045) has leveraged vulnerabilities in Pulse Secure VPNs to hijack sessions.(Citation: Securelist APT10 March 2021)
- [G1022] ToddyCat: [ToddyCat](https://attack.mitre.org/groups/G1022) has exploited the ProxyLogon vulnerability (CVE-2021-26855) to compromise Exchange Servers at multiple organizations.(Citation: Kaspersky ToddyCat June 2022)
- [G0108] Blue Mockingbird: [Blue Mockingbird](https://attack.mitre.org/groups/G0108) has gained initial access by exploiting CVE-2019-18935, a vulnerability within Telerik UI for ASP.NET AJAX.(Citation: RedCanary Mockingbird May 2020)
- [S1184] BOLDMOVE: [BOLDMOVE](https://attack.mitre.org/software/S1184) is associated with exploitation of CVE-2022-49475 in FortiOS.(Citation: Google Cloud BOLDMOVE 2023)
- [G0093] GALLIUM: [GALLIUM](https://attack.mitre.org/groups/G0093) exploited a publicly-facing servers including Wildfly/JBoss servers to gain access to the network.(Citation: Cybereason Soft Cell June 2019)(Citation: Microsoft GALLIUM December 2019)
- [C0053] FLORAHOX Activity: [FLORAHOX Activity](https://attack.mitre.org/campaigns/C0053) has exploited and infected vulnerable routers to recruit additional network devices into the ORB.(Citation: ORB Mandiant)
- [G1035] Winter Vivern: [Winter Vivern](https://attack.mitre.org/groups/G1035) has exploited known and zero-day vulnerabilities in software usch as Roundcube Webmail servers and the "Follina" vulnerability.(Citation: ESET WinterVivern 2023)(Citation: Proofpoint WinterVivern 2023)
- [G1006] Earth Lusca: [Earth Lusca](https://attack.mitre.org/groups/G1006) has compromised victims by directly exploiting vulnerabilities of public-facing servers, including those associated with Microsoft Exchange and Oracle GlassFish.(Citation: TrendMicro EarthLusca 2022)
- [C0046] ArcaneDoor: [ArcaneDoor](https://attack.mitre.org/campaigns/C0046) abused WebVPN traffic to targeted devices to achieve unauthorized remote code execution.(Citation: CCCS ArcaneDoor 2024)
- [G0016] APT29: [APT29](https://attack.mitre.org/groups/G0016) has exploited CVE-2019-19781 for Citrix, CVE-2019-11510 for Pulse Secure VPNs, CVE-2018-13379 for FortiGate VPNs, and CVE-2019-9670 in Zimbra software to gain access.(Citation: Cybersecurity Advisory SVR TTP May 2021)(Citation: NCSC APT29 July 2020)
- [G0065] Leviathan: [Leviathan](https://attack.mitre.org/groups/G0065) has used exploits against publicly-disclosed vulnerabilities for initial access into victim networks.(Citation: CISA Leviathan 2024)
- [G0123] Volatile Cedar: [Volatile Cedar](https://attack.mitre.org/groups/G0123) has targeted publicly facing web servers, with both automatic and manual vulnerability discovery.(Citation: CheckPoint Volatile Cedar March 2015) (Citation: ClearSky Lebanese Cedar Jan 2021)
- [G1032] INC Ransom: [INC Ransom](https://attack.mitre.org/groups/G1032) has exploited known vulnerabilities including CVE-2023-3519 in Citrix NetScaler for initial access.(Citation: SOCRadar INC Ransom January 2024)(Citation: SentinelOne INC Ransomware)
- [S0224] Havij: [Havij](https://attack.mitre.org/software/S0224) is used to automate SQL injection.(Citation: Check Point Havij Analysis)
- [G1009] Moses Staff: [Moses Staff](https://attack.mitre.org/groups/G1009) has exploited known vulnerabilities in public-facing infrastructure such as Microsoft Exchange Servers.(Citation: Checkpoint MosesStaff Nov 2021)
- [G0035] Dragonfly: [Dragonfly](https://attack.mitre.org/groups/G0035) has conducted SQL injection attacks, exploited vulnerabilities CVE-2019-19781 and CVE-2020-0688 for Citrix and MS Exchange, and CVE-2018-13379 for Fortinet VPNs.(Citation: CISA AA20-296A Berserk Bear December 2020)
- [G0001] Axiom: [Axiom](https://attack.mitre.org/groups/G0001) has been observed using SQL injection to gain access to systems.(Citation: Novetta-Axiom)(Citation: Cisco Group 72)
- [G0096] APT41: [APT41](https://attack.mitre.org/groups/G0096) exploited CVE-2020-10189 against Zoho ManageEngine Desktop Central through unsafe deserialization, and CVE-2019-19781 to compromise Citrix Application Delivery Controllers (ADC) and gateway devices.(Citation: FireEye APT41 March 2020) [APT41](https://attack.mitre.org/groups/G0096) leveraged vulnerabilities such as ProxyLogon exploitation or SQL injection for initial access.(Citation: Rostovcev APT41 2021) [APT41](https://attack.mitre.org/groups/G0096) exploited CVE-2021-26855 against a vulnerable Microsoft Exchange Server to gain initial access to the victim network.(Citation: apt41_dcsocytec_dec2022)
- [G1040] Play: [Play](https://attack.mitre.org/groups/G1040) has exploited known vulnerabilities for initial access including CVE-2018-13379 and CVE-2020-12812 in FortiOS and CVE-2022-41082 and CVE-2022-41040 ("ProxyNotShell") in Microsoft Exchange.(Citation: CISA Play Ransomware Advisory December 2023)(Citation: Trend Micro Ransomware Spotlight Play July 2023)
- [C0041] FrostyGoop Incident: [FrostyGoop Incident](https://attack.mitre.org/campaigns/C0041) was likely enabled by the adversary exploiting an unknown vulnerability in an external-facing router.(Citation: Dragos FROSTYGOOP 2024)
- [G0125] HAFNIUM: [HAFNIUM](https://attack.mitre.org/groups/G0125) has exploited multiple vulnerabilities to compromise edge devices and on-premises versions of Microsoft Exchange Server.(Citation: Microsoft HAFNIUM March 2020)(Citation: Volexity Exchange Marauder March 2021)(Citation: FireEye Exchange Zero Days March 2021)(Citation: Tarrask scheduled task)(Citation: Microsoft Log4j Vulnerability Exploitation December 2021)(Citation: Microsoft Silk Typhoon MAR 2025)
- [G1023] APT5: [APT5](https://attack.mitre.org/groups/G1023) has exploited vulnerabilities in externally facing software and devices including Pulse Secure VPNs and Citrix Application Delivery Controllers.(Citation: Mandiant Pulse Secure Zero-Day April 2021)(Citation: Mandiant Pulse Secure Update May 2021)(Citation: NSA APT5 Citrix Threat Hunting December 2022) (Citation: Microsoft East Asia Threats September 2023)
- [G0069] MuddyWater: [MuddyWater](https://attack.mitre.org/groups/G0069) has exploited the Microsoft Exchange memory corruption vulnerability (CVE-2020-0688).(Citation: DHS CISA AA22-055A MuddyWater February 2022)
- [G1045] Salt Typhoon: [Salt Typhoon](https://attack.mitre.org/groups/G1045) has exploited CVE-2018-0171 in the Smart Install feature of Cisco IOS and Cisco IOS XE software for initial access.(Citation: Cisco Salt Typhoon FEB 2025)
- [G0087] APT39: [APT39](https://attack.mitre.org/groups/G0087) has used SQL injection for initial compromise.(Citation: Symantec Chafer February 2018)


### T1195 - Supply Chain Compromise

Description:

Adversaries may manipulate products or product delivery mechanisms prior to receipt by a final consumer for the purpose of data or system compromise.

Supply chain compromise can take place at any stage of the supply chain including:

* Manipulation of development tools
* Manipulation of a development environment
* Manipulation of source code repositories (public or private)
* Manipulation of source code in open-source dependencies
* Manipulation of software update/distribution mechanisms
* Compromised/infected system images (multiple cases of removable media infected at the factory)(Citation: IBM Storwize)(Citation: Schneider Electric USB Malware) 
* Replacement of legitimate software with modified versions
* Sales of modified/counterfeit products to legitimate distributors
* Shipment interdiction

While supply chain compromise can impact any component of hardware or software, adversaries looking to gain execution have often focused on malicious additions to legitimate software in software distribution or update channels.(Citation: Avast CCleaner3 2018)(Citation: Microsoft Dofoil 2018)(Citation: Command Five SK 2011) Targeting may be specific to a desired victim set or malicious software may be distributed to a broad set of consumers but only move on to additional tactics on specific victims.(Citation: Symantec Elderwood Sept 2012)(Citation: Avast CCleaner3 2018)(Citation: Command Five SK 2011) Popular open source projects that are used as dependencies in many applications may also be targeted as a means to add malicious code to users of the dependency.(Citation: Trendmicro NPM Compromise)

Procedures:

- [S1213] Lumma Stealer: [Lumma Stealer](https://attack.mitre.org/software/S1213) has been delivered through cracked software downloads.(Citation: Cybereason LumaStealer Undated)(Citation: Fortinet LummaStealer 2024)(Citation: TrendMicro LummaStealer 2025)
- [G0049] OilRig: [OilRig](https://attack.mitre.org/groups/G0049) has leveraged compromised organizations to conduct supply chain attacks on government entities.(Citation: Trend Micro Earth Simnavaz October 2024)
- [S1148] Raccoon Stealer: [Raccoon Stealer](https://attack.mitre.org/software/S1148) has been distributed through cracked software downloads.(Citation: S2W Racoon 2022)
- [G1003] Ember Bear: [Ember Bear](https://attack.mitre.org/groups/G1003) has compromised information technology providers and software developers providing services to targets of interest, building initial access to ultimate victims at least in part through compromise of service providers that work with the victim organizations.(Citation: Cadet Blizzard emerges as novel threat actor)
- [G0034] Sandworm Team: [Sandworm Team](https://attack.mitre.org/groups/G0034) staged compromised versions of legitimate software installers on forums to achieve initial, untargetetd access in victim environments.(Citation: mandiant_apt44_unearthing_sandworm)

#### T1195.001 - Supply Chain Compromise: Compromise Software Dependencies and Development Tools

Description:

Adversaries may manipulate software dependencies and development tools prior to receipt by a final consumer for the purpose of data or system compromise. Applications often depend on external software to function properly. Popular open source projects that are used as dependencies in many applications may be targeted as a means to add malicious code to users of the dependency.(Citation: Trendmicro NPM Compromise)  

Targeting may be specific to a desired victim set or may be distributed to a broad set of consumers but only move on to additional tactics on specific victims.

Procedures:

- [S0658] XCSSET: [XCSSET](https://attack.mitre.org/software/S0658) adds malicious code to a host's Xcode projects by enumerating CocoaPods <code>target_integrator.rb</code> files under the <code>/Library/Ruby/Gems</code> folder or enumerates all <code>.xcodeproj</code> folders under a given directory. [XCSSET](https://attack.mitre.org/software/S0658) then downloads a script and Mach-O file into the Xcode project folder.(Citation: trendmicro xcsset xcode project 2020)

#### T1195.002 - Supply Chain Compromise: Compromise Software Supply Chain

Description:

Adversaries may manipulate application software prior to receipt by a final consumer for the purpose of data or system compromise. Supply chain compromise of software can take place in a number of ways, including manipulation of the application source code, manipulation of the update/distribution mechanism for that software, or replacing compiled releases with a modified version.

Targeting may be specific to a desired victim set or may be distributed to a broad set of consumers but only move on to additional tactics on specific victims.(Citation: Avast CCleaner3 2018)(Citation: Command Five SK 2011)

Procedures:

- [G0096] APT41: [APT41](https://attack.mitre.org/groups/G0096) gained access to production environments where they could inject malicious code into legitimate, signed files and widely distribute them to end users.(Citation: FireEye APT41 Aug 2019)
- [G0080] Cobalt Group: [Cobalt Group](https://attack.mitre.org/groups/G0080) has compromised legitimate web browser updates to deliver a backdoor. (Citation: Crowdstrike GTR2020 Mar 2020)
- [G0115] GOLD SOUTHFIELD: [GOLD SOUTHFIELD](https://attack.mitre.org/groups/G0115) has distributed ransomware by backdooring software installers via a strategic web compromise of the site hosting Italian WinRAR.(Citation: Secureworks REvil September 2019)(Citation: Secureworks GandCrab and REvil September 2019)(Citation: Secureworks GOLD SOUTHFIELD)
- [S0493] GoldenSpy: [GoldenSpy](https://attack.mitre.org/software/S0493) has been packaged with a legitimate tax preparation software.(Citation: Trustwave GoldenSpy June 2020)
- [S0562] SUNSPOT: [SUNSPOT](https://attack.mitre.org/software/S0562) malware was designed and used to insert [SUNBURST](https://attack.mitre.org/software/S0559) into software builds of the SolarWinds Orion IT management product.(Citation: CrowdStrike SUNSPOT Implant January 2021)
- [G0034] Sandworm Team: [Sandworm Team](https://attack.mitre.org/groups/G0034) has distributed [NotPetya](https://attack.mitre.org/software/S0368) by compromising the legitimate Ukrainian accounting software M.E.Doc and replacing a legitimate software update with a malicious one.(Citation: Secureworks NotPetya June 2017)(Citation: ESET Telebots June 2017)(Citation: US District Court Indictment GRU Unit 74455 October 2020)
- [S0222] CCBkdr: [CCBkdr](https://attack.mitre.org/software/S0222) was added to a legitimate, signed version 5.33 of the CCleaner software and distributed on CCleaner's distribution site.(Citation: Talos CCleanup 2017)(Citation: Intezer Aurora Sept 2017)(Citation: Avast CCleaner3 2018)
- [G0035] Dragonfly: [Dragonfly](https://attack.mitre.org/groups/G0035) has placed trojanized installers for control system software on legitimate vendor app stores.(Citation: Secureworks IRON LIBERTY July 2019)(Citation: Gigamon Berserk Bear October 2021)
- [G0027] Threat Group-3390: [Threat Group-3390](https://attack.mitre.org/groups/G0027) has compromised the Able Desktop installer to gain access to victim's environments.(Citation: Trend Micro Iron Tiger April 2021)
- [G1034] Daggerfly: [Daggerfly](https://attack.mitre.org/groups/G1034) is associated with several supply chain compromises using malicious updates to compromise victims.(Citation: ESET EvasivePanda 2023)(Citation: ESET EvasivePanda 2024)
- [G1036] Moonstone Sleet: [Moonstone Sleet](https://attack.mitre.org/groups/G1036) has distributed a trojanized version of PuTTY software for initial access to victims.(Citation: Microsoft Moonstone Sleet 2024)
- [C0024] SolarWinds Compromise: During the [SolarWinds Compromise](https://attack.mitre.org/campaigns/C0024), [APT29](https://attack.mitre.org/groups/G0016) gained initial network access to some victims via a trojanized update of SolarWinds Orion software.(Citation: SolarWinds Sunburst Sunspot Update January 2021)(Citation: FireEye SUNBURST Backdoor December 2020)(Citation: Cybersecurity Advisory SVR TTP May 2021)(Citation: Microsoft Deep Dive Solorigate January 2021)
- [G0046] FIN7: [FIN7](https://attack.mitre.org/groups/G0046) has gained initial access by compromising a victim's software supply chain.(Citation: Mandiant FIN7 Apr 2022)

#### T1195.003 - Supply Chain Compromise: Compromise Hardware Supply Chain

Description:

Adversaries may manipulate hardware components in products prior to receipt by a final consumer for the purpose of data or system compromise. By modifying hardware or firmware in the supply chain, adversaries can insert a backdoor into consumer networks that may be difficult to detect and give the adversary a high degree of control over the system. Hardware backdoors may be inserted into various devices, such as servers, workstations, network infrastructure, or peripherals.


### T1199 - Trusted Relationship

Description:

Adversaries may breach or otherwise leverage organizations who have access to intended victims. Access through trusted third party relationship abuses an existing connection that may not be protected or receives less scrutiny than standard mechanisms of gaining access to a network.

Organizations often grant elevated access to second or third-party external providers in order to allow them to manage internal systems as well as cloud-based environments. Some examples of these relationships include IT services contractors, managed security providers, infrastructure contractors (e.g. HVAC, elevators, physical security). The third-party provider's access may be intended to be limited to the infrastructure being maintained, but may exist on the same network as the rest of the enterprise. As such, [Valid Accounts](https://attack.mitre.org/techniques/T1078) used by the other party for access to internal network systems may be compromised and used.(Citation: CISA IT Service Providers)

In Office 365 environments, organizations may grant Microsoft partners or resellers delegated administrator permissions. By compromising a partner or reseller account, an adversary may be able to leverage existing delegated administrator relationships or send new delegated administrator offers to clients in order to gain administrative control over the victim tenant.(Citation: Office 365 Delegated Administration)

Procedures:

- [G0115] GOLD SOUTHFIELD: [GOLD SOUTHFIELD](https://attack.mitre.org/groups/G0115) has breached Managed Service Providers (MSP's) to deliver malware to MSP customers.(Citation: Secureworks REvil September 2019)
- [G0007] APT28: Once [APT28](https://attack.mitre.org/groups/G0007) gained access to the DCCC network, the group then proceeded to use that access to compromise the DNC network.(Citation: DOJ GRU Indictment Jul 2018)
- [G0027] Threat Group-3390: [Threat Group-3390](https://attack.mitre.org/groups/G0027) has compromised third party service providers to gain access to victim's environments.(Citation: Profero APT27 December 2020)
- [G0034] Sandworm Team: [Sandworm Team](https://attack.mitre.org/groups/G0034) has used dedicated network connections from one victim organization to gain unauthorized access to a separate organization.(Citation: US District Court Indictment GRU Unit 74455 October 2020) Additionally, [Sandworm Team](https://attack.mitre.org/groups/G0034) has accessed Internet service providers and telecommunication entities that provide mobile connectivity.(Citation: mandiant_apt44_unearthing_sandworm)
- [G0045] menuPass: [menuPass](https://attack.mitre.org/groups/G0045) has used legitimate access granted to Managed Service Providers in order to access victims of interest.(Citation: PWC Cloud Hopper Technical Annex April 2017)(Citation: FireEye APT10 April 2017)(Citation: Symantec Cicada November 2020)(Citation: DOJ APT10 Dec 2018)(Citation: District Court of NY APT10 Indictment December 2018)
- [C0024] SolarWinds Compromise: During the [SolarWinds Compromise](https://attack.mitre.org/campaigns/C0024), [APT29](https://attack.mitre.org/groups/G0016) gained access through compromised accounts at cloud solution partners, and used compromised certificates issued by Mimecast to authenticate to Mimecast customer systems.(Citation: Cybersecurity Advisory SVR TTP May 2021)(Citation: CrowdStrike StellarParticle January 2022)
- [G1039] RedCurl: [RedCurl](https://attack.mitre.org/groups/G1039) has gained access to a contractor to pivot to the victim’s infrastructure.(Citation: therecord_redcurl)
- [G0016] APT29: [APT29](https://attack.mitre.org/groups/G0016) has compromised IT, cloud services, and managed services providers to gain broad access to multiple customers for subsequent operations.(Citation: MSTIC Nobelium Oct 2021)
- [G1005] POLONIUM: [POLONIUM](https://attack.mitre.org/groups/G1005) has used compromised credentials from an IT company to target downstream customers including a law firm and aviation company.(Citation: Microsoft POLONIUM June 2022)
- [G0125] HAFNIUM: [HAFNIUM](https://attack.mitre.org/groups/G0125) has used stolen API keys and credentials associatd with privilege access management (PAM), cloud app providers, and cloud data management companies to access downstream customer environments.(Citation: Microsoft Silk Typhoon MAR 2025)
- [G1004] LAPSUS$: [LAPSUS$](https://attack.mitre.org/groups/G1004) has accessed internet-facing identity providers such as Azure Active Directory and Okta to target specific organizations.(Citation: MSTIC DEV-0537 Mar 2022)
- [G1041] Sea Turtle: [Sea Turtle](https://attack.mitre.org/groups/G1041) targeted third-party entities in trusted relationships with primary targets to ultimately achieve access at primary targets. Entities targeted included DNS registrars, telecommunication companies, and internet service providers.(Citation: Talos Sea Turtle 2019)


### T1200 - Hardware Additions

Description:

Adversaries may physically introduce computer accessories, networking hardware, or other computing devices into a system or network that can be used as a vector to gain access. Rather than just connecting and distributing payloads via removable storage (i.e. [Replication Through Removable Media](https://attack.mitre.org/techniques/T1091)), more robust hardware additions can be used to introduce new functionalities and/or features into a system that can then be abused.

While public references of usage by threat actors are scarce, many red teams/penetration testers leverage hardware additions for initial access. Commercial and open source products can be leveraged with capabilities such as passive network tapping, network traffic modification (i.e. [Adversary-in-the-Middle](https://attack.mitre.org/techniques/T1557)), keystroke injection, kernel memory reading via DMA, addition of new wireless access points to an existing network, and others.(Citation: Ossmann Star Feb 2011)(Citation: Aleks Weapons Nov 2015)(Citation: Frisk DMA August 2016)(Citation: McMillan Pwn March 2012)

Procedures:

- [G0105] DarkVishnya: [DarkVishnya](https://attack.mitre.org/groups/G0105) physically connected Bash Bunny, Raspberry Pi, netbooks, and inexpensive laptops to the target organization's environment to access the company’s local network.(Citation: Securelist DarkVishnya Dec 2018)


### T1566 - Phishing

Description:

Adversaries may send phishing messages to gain access to victim systems. All forms of phishing are electronically delivered social engineering. Phishing can be targeted, known as spearphishing. In spearphishing, a specific individual, company, or industry will be targeted by the adversary. More generally, adversaries can conduct non-targeted phishing, such as in mass malware spam campaigns.

Adversaries may send victims emails containing malicious attachments or links, typically to execute malicious code on victim systems. Phishing may also be conducted via third-party services, like social media platforms. Phishing may also involve social engineering techniques, such as posing as a trusted source, as well as evasive techniques such as removing or manipulating emails or metadata/headers from compromised accounts being abused to send messages (e.g., [Email Hiding Rules](https://attack.mitre.org/techniques/T1564/008)).(Citation: Microsoft OAuth Spam 2022)(Citation: Palo Alto Unit 42 VBA Infostealer 2014) Another way to accomplish this is by [Email Spoofing](https://attack.mitre.org/techniques/T1672)(Citation: Proofpoint-spoof) the identity of the sender, which can be used to fool both the human recipient as well as automated security tools,(Citation: cyberproof-double-bounce) or by including the intended target as a party to an existing email thread that includes malicious files or links (i.e., "thread hijacking").(Citation: phishing-krebs)

Victims may also receive phishing messages that instruct them to call a phone number where they are directed to visit a malicious URL, download malware,(Citation: sygnia Luna Month)(Citation: CISA Remote Monitoring and Management Software) or install adversary-accessible remote management tools onto their computer (i.e., [User Execution](https://attack.mitre.org/techniques/T1204)).(Citation: Unit42 Luna Moth)

Procedures:

- [S0009] Hikit: [Hikit](https://attack.mitre.org/software/S0009) has been spread through spear phishing.(Citation: Novetta-Axiom)
- [G0094] Kimsuky: [Kimsuky](https://attack.mitre.org/groups/G0094) has used spearphishing to gain initial access and intelligence.(Citation: MSFT-AI)(Citation: Mandiant APT43 Full PDF Report)
- [S1139] INC Ransomware: [INC Ransomware](https://attack.mitre.org/software/S1139) campaigns have used spearphishing emails for initial access.(Citation: SentinelOne INC Ransomware)
- [G1032] INC Ransom: [INC Ransom](https://attack.mitre.org/groups/G1032) has used phishing to gain initial access.(Citation: SOCRadar INC Ransom January 2024)(Citation: SentinelOne INC Ransomware)
- [G1041] Sea Turtle: [Sea Turtle](https://attack.mitre.org/groups/G1041) used spear phishing to gain initial access to victims.(Citation: Talos Sea Turtle 2019)
- [G0001] Axiom: [Axiom](https://attack.mitre.org/groups/G0001) has used spear phishing to initially compromise victims.(Citation: Cisco Group 72)(Citation: Novetta-Axiom)
- [S1073] Royal: [Royal](https://attack.mitre.org/software/S1073) has been spread through the use of phishing campaigns including "call back phishing" where victims are lured into calling a number provided through email.(Citation: Cybereason Royal December 2022)(Citation: Kroll Royal Deep Dive February 2023)(Citation: CISA Royal AA23-061A March 2023)
- [G0115] GOLD SOUTHFIELD: [GOLD SOUTHFIELD](https://attack.mitre.org/groups/G0115) has conducted malicious spam (malspam) campaigns to gain access to victim's machines.(Citation: Secureworks REvil September 2019)

#### T1566.001 - Phishing: Spearphishing Attachment

Description:

Adversaries may send spearphishing emails with a malicious attachment in an attempt to gain access to victim systems. Spearphishing attachment is a specific variant of spearphishing. Spearphishing attachment is different from other forms of spearphishing in that it employs the use of malware attached to an email. All forms of spearphishing are electronically delivered social engineering targeted at a specific individual, company, or industry. In this scenario, adversaries attach a file to the spearphishing email and usually rely upon [User Execution](https://attack.mitre.org/techniques/T1204) to gain execution.(Citation: Unit 42 DarkHydrus July 2018) Spearphishing may also involve social engineering techniques, such as posing as a trusted source.

There are many options for the attachment such as Microsoft Office documents, executables, PDFs, or archived files. Upon opening the attachment (and potentially clicking past protections), the adversary's payload exploits a vulnerability or directly executes on the user's system. The text of the spearphishing email usually tries to give a plausible reason why the file should be opened, and may explain how to bypass system protections in order to do so. The email may also contain instructions on how to decrypt an attachment, such as a zip file password, in order to evade email boundary defenses. Adversaries frequently manipulate file extensions and icons in order to make attached executables appear to be document files, or files exploiting one application appear to be a file for a different one.

Procedures:

- [G0080] Cobalt Group: [Cobalt Group](https://attack.mitre.org/groups/G0080) has sent spearphishing emails with various attachment types to corporate and personal email accounts of victim organizations. Attachment types have included .rtf, .doc, .xls, archives containing LNK files, and password protected archives containing .exe and .scr executables.(Citation: Talos Cobalt Group July 2018)(Citation: PTSecurity Cobalt Group Aug 2017)(Citation: PTSecurity Cobalt Dec 2016)(Citation: Group IB Cobalt Aug 2017)(Citation: Proofpoint Cobalt June 2017)(Citation: RiskIQ Cobalt Nov 2017)(Citation: Unit 42 Cobalt Gang Oct 2018)(Citation: TrendMicro Cobalt Group Nov 2017)
- [S0669] KOCTOPUS: [KOCTOPUS](https://attack.mitre.org/software/S0669) has been distributed via spearphishing emails with malicious attachments.(Citation: MalwareBytes LazyScripter Feb 2021)
- [C0028] 2015 Ukraine Electric Power Attack: During the [2015 Ukraine Electric Power Attack](https://attack.mitre.org/campaigns/C0028), [Sandworm Team](https://attack.mitre.org/groups/G0034) obtained their initial foothold into many IT systems using Microsoft Office attachments delivered through phishing emails. (Citation: Ukraine15 - EISAC - 201603)
- [S0447] Lokibot: [Lokibot](https://attack.mitre.org/software/S0447) is delivered via a malicious XLS attachment contained within a spearhpishing email.(Citation: Talos Lokibot Jan 2021)
- [G0032] Lazarus Group: [Lazarus Group](https://attack.mitre.org/groups/G0032) has targeted victims with spearphishing emails containing malicious Microsoft Word documents.(Citation: McAfee Bankshot)(Citation: Kaspersky ThreatNeedle Feb 2021)(Citation: Lazarus APT January 2022)(Citation: Qualys LolZarus)
- [G1031] Saint Bear: [Saint Bear](https://attack.mitre.org/groups/G1031) uses a variety of file formats, such as Microsoft Office documents, ZIP archives, PDF documents, and other items as phishing attachments for initial access.(Citation: Palo Alto Unit 42 OutSteel SaintBot February 2022 )
- [S0331] Agent Tesla: The primary delivered mechanism for [Agent Tesla](https://attack.mitre.org/software/S0331) is through email phishing messages.(Citation: Bitdefender Agent Tesla April 2020)
- [G0081] Tropic Trooper: [Tropic Trooper](https://attack.mitre.org/groups/G0081) sent spearphishing emails that contained malicious Microsoft Office and fake installer file attachments.(Citation: Unit 42 Tropic Trooper Nov 2016)(Citation: TrendMicro TropicTrooper 2015)(Citation: CitizenLab Tropic Trooper Aug 2018)(Citation: Anomali Pirate Panda April 2020)(Citation: TrendMicro Tropic Trooper May 2020)
- [G0037] FIN6: [FIN6](https://attack.mitre.org/groups/G0037) has targeted victims with e-mails containing malicious attachments.(Citation: Visa FIN6 Feb 2019)
- [S1064] SVCReady: [SVCReady](https://attack.mitre.org/software/S1064) has been distributed via spearphishing campaigns containing malicious Mircrosoft Word documents.(Citation: HP SVCReady Jun 2022)
- [G0007] APT28: [APT28](https://attack.mitre.org/groups/G0007) sent spearphishing emails containing malicious Microsoft Office and RAR attachments.(Citation: Unit 42 Sofacy Feb 2018)(Citation: Sofacy DealersChoice)(Citation: Palo Alto Sofacy 06-2018)(Citation: DOJ GRU Indictment Jul 2018)(Citation: Securelist Sofacy Feb 2018)(Citation: Accenture SNAKEMACKEREL Nov 2018)(Citation: TrendMicro Pawn Storm Dec 2020)(Citation: Secureworks IRON TWILIGHT Active Measures March 2017)
- [S1066] DarkTortilla: [DarkTortilla](https://attack.mitre.org/software/S1066) has been distributed via spearphishing emails containing archive attachments, with file types such as .iso, .zip, .img, .dmg, and .tar, as well as through malicious documents.(Citation: Secureworks DarkTortilla Aug 2022)
- [G0018] admin@338: [admin@338](https://attack.mitre.org/groups/G0018) has sent emails with malicious Microsoft Office documents attached.(Citation: FireEye admin@338)
- [G0112] Windshift: [Windshift](https://attack.mitre.org/groups/G0112) has sent spearphishing emails with attachment to harvest credentials and deliver malware.(Citation: SANS Windshift August 2018)
- [G0060] BRONZE BUTLER: [BRONZE BUTLER](https://attack.mitre.org/groups/G0060) used spearphishing emails with malicious Microsoft Word attachments to infect victims.(Citation: Symantec Tick Apr 2016)(Citation: Trend Micro Tick November 2019)
- [G0090] WIRTE: [WIRTE](https://attack.mitre.org/groups/G0090) has sent emails to intended victims with malicious MS Word and Excel attachments.(Citation: Kaspersky WIRTE November 2021)
- [G0069] MuddyWater: [MuddyWater](https://attack.mitre.org/groups/G0069) has compromised third parties and used compromised accounts to send spearphishing emails with targeted attachments to recipients.(Citation: Unit 42 MuddyWater Nov 2017)(Citation: FireEye MuddyWater Mar 2018)(Citation: Securelist MuddyWater Oct 2018)(Citation: ClearSky MuddyWater June 2019)(Citation: Anomali Static Kitten February 2021)(Citation: Trend Micro Muddy Water March 2021)	(Citation: DHS CISA AA22-055A MuddyWater February 2022)(Citation: Proofpoint TA450 Phishing March 2024)
- [G0045] menuPass: [menuPass](https://attack.mitre.org/groups/G0045) has sent malicious Office documents via email as part of spearphishing campaigns as well as executables disguised as documents.(Citation: PWC Cloud Hopper Technical Annex April 2017)(Citation: FireEye APT10 April 2017)(Citation: FireEye APT10 Sept 2018)(Citation: District Court of NY APT10 Indictment December 2018)
- [S0428] PoetRAT: [PoetRAT](https://attack.mitre.org/software/S0428) was distributed via malicious Word documents.(Citation: Talos PoetRAT April 2020)
- [S0148] RTM: [RTM](https://attack.mitre.org/software/S0148) has been delivered via spearphishing attachments disguised as PDF documents.(Citation: Unit42 Redaman January 2019)
- [G0027] Threat Group-3390: [Threat Group-3390](https://attack.mitre.org/groups/G0027) has used e-mail to deliver malicious attachments to victims.(Citation: Trend Micro DRBControl February 2020)
- [G0047] Gamaredon Group: [Gamaredon Group](https://attack.mitre.org/groups/G0047) has delivered spearphishing emails with malicious attachments to targets.(Citation: TrendMicro Gamaredon April 2020)(Citation: ESET Gamaredon June 2020)(Citation: CERT-EE Gamaredon January 2021)(Citation: Microsoft Actinium February 2022)(Citation: Unit 42 Gamaredon February 2022)(Citation: Secureworks IRON TILDEN Profile)(Citation: unit42_gamaredon_dec2022)
- [S0622] AppleSeed: [AppleSeed](https://attack.mitre.org/software/S0622) has been distributed to victims through malicious e-mail attachments.(Citation: Malwarebytes Kimsuky June 2021)
- [S0458] Ramsay: [Ramsay](https://attack.mitre.org/software/S0458) has been distributed through spearphishing emails with malicious attachments.(Citation: Antiy CERT Ramsay April 2020)
- [G0050] APT32: [APT32](https://attack.mitre.org/groups/G0050) has sent spearphishing emails with a malicious executable disguised as a document or spreadsheet.(Citation: ESET OceanLotus)(Citation: Cybereason Oceanlotus May 2017)(Citation: Cybereason Cobalt Kitty 2017)(Citation: ESET OceanLotus Mar 2019)(Citation: FireEye APT32 April 2020)(Citation: Amnesty Intl. Ocean Lotus February 2021)
- [G0012] Darkhotel: [Darkhotel](https://attack.mitre.org/groups/G0012) has sent spearphishing emails with malicious RAR and .LNK attachments.(Citation: Securelist Darkhotel Aug 2015)(Citation: Microsoft DUBNIUM July 2016)
- [G1002] BITTER: [BITTER](https://attack.mitre.org/groups/G1002) has sent spearphishing emails with a malicious RTF document or Excel spreadsheet.(Citation: Cisco Talos Bitter Bangladesh May 2022)(Citation: Forcepoint BITTER Pakistan Oct 2016)
- [G0016] APT29: [APT29](https://attack.mitre.org/groups/G0016) has used spearphishing emails with an attachment to deliver files with exploits to initial victims.(Citation: F-Secure The Dukes)(Citation: MSTIC NOBELIUM May 2021)(Citation: ESET T3 Threat Report 2021)(Citation: Secureworks IRON HEMLOCK Profile)
- [S0011] Taidoor: [Taidoor](https://attack.mitre.org/software/S0011) has been delivered through spearphishing emails.(Citation: TrendMicro Taidoor)
- [S0585] Kerrdown: [Kerrdown](https://attack.mitre.org/software/S0585) has been distributed through malicious e-mail attachments.(Citation: Amnesty Intl. Ocean Lotus February 2021)
- [G0100] Inception: [Inception](https://attack.mitre.org/groups/G0100) has used weaponized documents attached to spearphishing emails for reconnaissance and initial compromise.(Citation: Kaspersky Cloud Atlas December 2014)(Citation: Symantec Inception Framework March 2018)(Citation: Unit 42 Inception November 2018)(Citation: Kaspersky Cloud Atlas August 2019)
- [C0001] Frankenstein: During [Frankenstein](https://attack.mitre.org/campaigns/C0001), the threat actors likely used spearphishing emails to send malicious Microsoft Word documents.(Citation: Talos Frankenstein June 2019)
- [S0455] Metamorfo: [Metamorfo](https://attack.mitre.org/software/S0455) has been delivered to victims via emails with malicious HTML attachments.(Citation: FireEye Metamorfo Apr 2018)(Citation: ESET Casbaneiro Oct 2019)
- [G1011] EXOTIC LILY: [EXOTIC LILY](https://attack.mitre.org/groups/G1011) conducted an e-mail thread-hijacking campaign with malicious ISO attachments.(Citation: Google EXOTIC LILY March 2022)(Citation: Proofpoint Bumblebee April 2022)
- [G0130] Ajax Security Team: [Ajax Security Team](https://attack.mitre.org/groups/G0130) has used personalized spearphishing attachments.(Citation: Check Point Rocket Kitten)
- [S0631] Chaes: [Chaes](https://attack.mitre.org/software/S0631) has been delivered by sending victims a phishing email containing a malicious .docx file.(Citation: Cybereason Chaes Nov 2020)
- [G0035] Dragonfly: [Dragonfly](https://attack.mitre.org/groups/G0035) has sent emails with malicious attachments to gain initial access.(Citation: Gigamon Berserk Bear October 2021)
- [G0034] Sandworm Team: [Sandworm Team](https://attack.mitre.org/groups/G0034) has delivered malicious Microsoft Office and ZIP file attachments via spearphishing emails.(Citation: iSight Sandworm Oct 2014)(Citation: US-CERT Ukraine Feb 2016)(Citation: ESET Telebots Dec 2016)(Citation: US District Court Indictment GRU Unit 74455 October 2020)(Citation: Google_WinRAR_vuln_2023)(Citation: mandiant_apt44_unearthing_sandworm)
- [G0066] Elderwood: [Elderwood](https://attack.mitre.org/groups/G0066) has delivered zero-day exploits and malware to victims via targeted emails containing malicious attachments.(Citation: Symantec Elderwood Sept 2012)(Citation: CSM Elderwood Sept 2012)
- [C0015] C0015: For [C0015](https://attack.mitre.org/campaigns/C0015), security researchers assessed the threat actors likely used a phishing campaign to distribute a weaponized attachment to victims.(Citation: DFIR Conti Bazar Nov 2021)
- [G0064] APT33: [APT33](https://attack.mitre.org/groups/G0064) has sent spearphishing e-mails with archive attachments.(Citation: Microsoft Holmium June 2020)
- [S1160] Latrodectus: [Latrodectus](https://attack.mitre.org/software/S1160) has been distributed through reply-chain phishing emails with malicious attachments.(Citation: Bleeping Computer Latrodectus April 2024)
- [S0499] Hancitor: [Hancitor](https://attack.mitre.org/software/S0499) has been delivered via phishing emails with malicious attachments.(Citation: FireEye Hancitor)
- [G0021] Molerats: [Molerats](https://attack.mitre.org/groups/G0021) has sent phishing emails with malicious Microsoft Word and PDF attachments.(Citation: Kaspersky MoleRATs April 2019)(Citation: Unit42 Molerat Mar 2020)(Citation: Cybereason Molerats Dec 2020)
- [G0040] Patchwork: [Patchwork](https://attack.mitre.org/groups/G0040) has used spearphishing with an attachment to deliver files with exploits to initial victims.(Citation: Cymmetria Patchwork)(Citation: Securelist Dropping Elephant)(Citation: TrendMicro Patchwork Dec 2017)(Citation: Volexity Patchwork June 2018)
- [G0127] TA551: [TA551](https://attack.mitre.org/groups/G0127) has sent spearphishing attachments with password protected ZIP files.(Citation: Unit 42 Valak July 2020)(Citation: Unit 42 TA551 Jan 2021)(Citation: Secureworks GOLD CABIN)
- [G0048] RTM: [RTM](https://attack.mitre.org/groups/G0048) has used spearphishing attachments to distribute its malware.(Citation: Group IB RTM August 2019)
- [G1039] RedCurl: [RedCurl](https://attack.mitre.org/groups/G1039) has used phishing emails with malicious files to gain initial access.(Citation: group-ib_redcurl1)(Citation: trendmicro_redcurl)
- [G0096] APT41: [APT41](https://attack.mitre.org/groups/G0096) sent spearphishing emails with attachments such as compiled HTML (.chm) files to initially compromise their victims.(Citation: FireEye APT41 Aug 2019)
- [G1035] Winter Vivern: [Winter Vivern](https://attack.mitre.org/groups/G1035) leverages malicious attachments delivered via email for initial access activity.(Citation: DomainTools WinterVivern 2021)(Citation: SentinelOne WinterVivern 2023)(Citation: CERT-UA WinterVivern 2023)
- [G0126] Higaisa: [Higaisa](https://attack.mitre.org/groups/G0126) has sent spearphishing emails containing malicious attachments.(Citation: Malwarebytes Higaisa 2020)(Citation: Zscaler Higaisa 2020)
- [S0660] Clambling: [Clambling](https://attack.mitre.org/software/S0660) has been delivered to victim's machines through malicious e-mail attachments.(Citation: Trend Micro DRBControl February 2020)
- [S0634] EnvyScout: [EnvyScout](https://attack.mitre.org/software/S0634) has been distributed via spearphishing as an email attachment.(Citation: MSTIC Nobelium Toolset May 2021)
- [S1030] Squirrelwaffle: [Squirrelwaffle](https://attack.mitre.org/software/S1030) has been distributed via malicious Microsoft Office documents within spam emails.(Citation: Netskope Squirrelwaffle Oct 2021)
- [G0142] Confucius: [Confucius](https://attack.mitre.org/groups/G0142) has crafted and sent victims malicious attachments to gain initial access.(Citation: Uptycs Confucius APT Jan 2021)
- [S0373] Astaroth: [Astaroth](https://attack.mitre.org/software/S0373) has been delivered via malicious e-mail attachments.(Citation: Securelist Brazilian Banking Malware July 2020)
- [C0016] Operation Dust Storm: During [Operation Dust Storm](https://attack.mitre.org/campaigns/C0016), the threat actors sent spearphishing emails that contained a malicious Microsoft Word document.(Citation: Cylance Dust Storm)
- [S1014] DanBot: [DanBot](https://attack.mitre.org/software/S1014) has been distributed within a malicious Excel attachment via spearphishing emails.(Citation: SecureWorks August 2019)
- [C0037] Water Curupira Pikabot Distribution: [Water Curupira Pikabot Distribution](https://attack.mitre.org/campaigns/C0037) attached password-protected ZIP archives to deliver [Pikabot](https://attack.mitre.org/software/S1145) installers.(Citation: TrendMicro Pikabot 2024)
- [S1183] StrelaStealer: [StrelaStealer](https://attack.mitre.org/software/S1183) has been distributed as a spearphishing attachment.(Citation: DCSO StrelaStealer 2022)
- [S0670] WarzoneRAT: [WarzoneRAT](https://attack.mitre.org/software/S0670) has been distributed as a malicious attachment within an email.(Citation: Check Point Warzone Feb 2020)(Citation: Uptycs Confucius APT Jan 2021)
- [G0062] TA459: [TA459](https://attack.mitre.org/groups/G0062) has targeted victims using spearphishing emails with malicious Microsoft Word attachments.(Citation: Proofpoint TA459 April 2017)
- [G0098] BlackTech: [BlackTech](https://attack.mitre.org/groups/G0098) has used spearphishing e-mails with malicious password-protected archived files (ZIP or RAR) to deliver malware.(Citation: TrendMicro BlackTech June 2017)(Citation: NTT Security Flagpro new December 2021)
- [G0078] Gorgon Group: [Gorgon Group](https://attack.mitre.org/groups/G0078) sent emails to victims with malicious Microsoft Office documents attached.(Citation: Unit 42 Gorgon Group Aug 2018)
- [G0065] Leviathan: [Leviathan](https://attack.mitre.org/groups/G0065) has sent spearphishing emails with malicious attachments, including .rtf, .doc, and .xls files.(Citation: Proofpoint Leviathan Oct 2017)(Citation: CISA AA21-200A APT40 July 2021)
- [G0103] Mofang: [Mofang](https://attack.mitre.org/groups/G0103) delivered spearphishing emails with malicious documents, PDFs, or Excel files attached.(Citation: FOX-IT May 2016 Mofang)
- [S1086] Snip3: [Snip3](https://attack.mitre.org/software/S1086) has been delivered to victims through malicious e-mail attachments.(Citation: Telefonica Snip3 December 2021)
- [S0433] Rifdoor: [Rifdoor](https://attack.mitre.org/software/S0433) has been distributed in e-mails with malicious Excel or Word documents.(Citation: Carbon Black HotCroissant April 2020)
- [S0476] Valak: [Valak](https://attack.mitre.org/software/S0476) has been delivered via spearphishing e-mails with password protected ZIP files.(Citation: Unit 42 Valak July 2020)
- [G0019] Naikon: [Naikon](https://attack.mitre.org/groups/G0019) has used malicious e-mail attachments to deliver malware.(Citation: CheckPoint Naikon May 2020)
- [G0005] APT12: [APT12](https://attack.mitre.org/groups/G0005) has sent emails with malicious Microsoft Office documents and PDFs attached.(Citation: Moran 2014)(Citation: Trend Micro IXESHE 2012)
- [S0234] Bandook: [Bandook](https://attack.mitre.org/software/S0234) is delivered via a malicious Word document inside a zip file.(Citation: CheckPoint Bandook Nov 2020)
- [G0073] APT19: [APT19](https://attack.mitre.org/groups/G0073) sent spearphishing emails with malicious attachments in RTF and XLSM formats to deliver initial exploits.(Citation: FireEye APT19)
- [S0240] ROKRAT: [ROKRAT](https://attack.mitre.org/software/S0240) has been delivered via spearphishing emails that contain a malicious Hangul Office or Microsoft Word document.(Citation: Malwarebytes RokRAT VBA January 2021)
- [C0011] C0011: During [C0011](https://attack.mitre.org/campaigns/C0011), [Transparent Tribe](https://attack.mitre.org/groups/G0134) sent malicious attachments via email to student targets in India.(Citation: Cisco Talos Transparent Tribe Education Campaign July 2022)
- [G1033] Star Blizzard: [Star Blizzard](https://attack.mitre.org/groups/G1033) has sent emails with malicious .pdf files to spread malware.(Citation: Google TAG COLDRIVER January 2024)
- [C0005] Operation Spalax: During [Operation Spalax](https://attack.mitre.org/campaigns/C0005), the threat actors sent phishing emails that included a PDF document that in some cases led to the download and execution of malware.(Citation: ESET Operation Spalax Jan 2021)
- [G0013] APT30: [APT30](https://attack.mitre.org/groups/G0013) has used spearphishing emails with malicious DOC attachments.(Citation: FireEye APT30)
- [G0137] Ferocious Kitten: [Ferocious Kitten](https://attack.mitre.org/groups/G0137) has conducted spearphishing campaigns containing malicious documents to lure victims to open the attachments.(Citation: Kaspersky Ferocious Kitten Jun 2021)
- [G1026] Malteiro: [Malteiro](https://attack.mitre.org/groups/G1026) has sent spearphishing emails containing malicious .zip files.(Citation: SCILabs Malteiro 2021)
- [G1008] SideCopy: [SideCopy](https://attack.mitre.org/groups/G1008) has sent spearphishing emails with malicious hta file attachments.(Citation: MalwareBytes SideCopy Dec 2021)
- [S1207] XLoader: [XLoader](https://attack.mitre.org/software/S1207) has been delivered as a phishing attachment, including PDFs with embedded links, Word and Excel files, and various archive files (ZIP, RAR, ACE, and ISOs) containing EXE payloads.(Citation: Google XLoader 2017)(Citation: Acronis XLoader 2021)
- [C0022] Operation Dream Job: During [Operation Dream Job](https://attack.mitre.org/campaigns/C0022), [Lazarus Group](https://attack.mitre.org/groups/G0032) sent emails with malicious attachments to gain unauthorized access to targets' computers.(Citation: ClearSky Lazarus Aug 2020)(Citation: McAfee Lazarus Jul 2020)
- [S0268] Bisonal: [Bisonal](https://attack.mitre.org/software/S0268) has been delivered as malicious email attachments.(Citation: Talos Bisonal Mar 2020)
- [G0061] FIN8: [FIN8](https://attack.mitre.org/groups/G0061) has distributed targeted emails containing Word documents with embedded malicious macros.(Citation: FireEye Obfuscation June 2017)(Citation: FireEye Fin8 May 2016)(Citation: FireEye Know Your Enemy FIN8 Aug 2016)
- [G0133] Nomadic Octopus: [Nomadic Octopus](https://attack.mitre.org/groups/G0133) has targeted victims with spearphishing emails containing malicious attachments.(Citation: Security Affairs DustSquad Oct 2018)(Citation: ESET Nomadic Octopus 2018)
- [G0140] LazyScripter: [LazyScripter](https://attack.mitre.org/groups/G0140) has used spam emails weaponized with archive or document files as its initial infection vector.(Citation: MalwareBytes LazyScripter Feb 2021)
- [G0129] Mustang Panda: [Mustang Panda](https://attack.mitre.org/groups/G0129) has used spearphishing attachments to deliver initial access payloads.(Citation: Recorded Future REDDELTA July 2020)(Citation: Proofpoint TA416 November 2020)(Citation: Google TAG Ukraine Threat Landscape March 2022)
- [S1065] Woody RAT: [Woody RAT](https://attack.mitre.org/software/S1065) has been delivered via malicious Word documents and archive files.(Citation: MalwareBytes WoodyRAT Aug 2022)
- [G0049] OilRig: [OilRig](https://attack.mitre.org/groups/G0049) has sent spearphising emails with malicious attachments to potential victims using compromised and/or spoofed email accounts.(Citation: Unit 42 OopsIE! Feb 2018)(Citation: Unit 42 QUADAGENT July 2018)(Citation: Crowdstrike Helix Kitten Nov 2018)(Citation: ClearSky OilRig Jan 2017)
- [C0047] RedDelta Modified PlugX Infection Chain Operations: [Mustang Panda](https://attack.mitre.org/groups/G0129) leveraged malicious attachments in spearphishing emails for initial access to victim environments in [RedDelta Modified PlugX Infection Chain Operations](https://attack.mitre.org/campaigns/C0047).(Citation: Recorded Future RedDelta 2025)
- [G1036] Moonstone Sleet: [Moonstone Sleet](https://attack.mitre.org/groups/G1036) delivered various payloads to victims as spearphishing attachments.(Citation: Microsoft Moonstone Sleet 2024)
- [S0496] REvil: [REvil](https://attack.mitre.org/software/S0496) has been distributed via malicious e-mail attachments including MS Word Documents.(Citation: G Data Sodinokibi June 2019)(Citation: Cylance Sodinokibi July 2019)(Citation: Secureworks REvil September 2019)(Citation: McAfee Sodinokibi October 2019)(Citation: Picus Sodinokibi January 2020)
- [S0648] JSS Loader: [JSS Loader](https://attack.mitre.org/software/S0648) has been delivered by phishing emails containing malicious Microsoft Excel attachments.(Citation: eSentire FIN7 July 2021)
- [S0642] BADFLICK: [BADFLICK](https://attack.mitre.org/software/S0642) has been distributed via spearphishing campaigns containing malicious Microsoft Word documents.(Citation: Accenture MUDCARP March 2019)
- [S0356] KONNI: [KONNI](https://attack.mitre.org/software/S0356) has been delivered via spearphishing campaigns through a malicious Word document.(Citation: Malwarebytes Konni Aug 2021)
- [G0134] Transparent Tribe: [Transparent Tribe](https://attack.mitre.org/groups/G0134) has sent spearphishing e-mails with attachments to deliver malicious payloads.(Citation: Proofpoint Operation Transparent Tribe March 2016)(Citation: Kaspersky Transparent Tribe August 2020)(Citation: Talos Oblique RAT March 2021)(Citation: Talos Transparent Tribe May 2021)(Citation: Unit 42 ProjectM March 2016)
- [S1111] DarkGate: [DarkGate](https://attack.mitre.org/software/S1111) can be distributed through emails with malicious attachments from a spoofed email address.(Citation: Ensilo Darkgate 2018)
- [S0483] IcedID: [IcedID](https://attack.mitre.org/software/S0483) has been delivered via phishing e-mails with malicious attachments.(Citation: Juniper IcedID June 2020)(Citation: DFIR_Sodinokibi_Ransomware)
- [S0673] DarkWatchman: [DarkWatchman](https://attack.mitre.org/software/S0673) has been delivered via spearphishing emails that contain a malicious zip file.(Citation: Prevailion DarkWatchman 2021)
- [G0094] Kimsuky: [Kimsuky](https://attack.mitre.org/groups/G0094) has used emails containing Word, Excel and/or HWP (Hangul Word Processor) documents in their spearphishing campaigns.(Citation: Zdnet Kimsuky Dec 2018)(Citation: Securelist Kimsuky Sept 2013)(Citation: ThreatConnect Kimsuky September 2020)(Citation: VirusBulletin Kimsuky October 2019)(Citation: Cybereason Kimsuky November 2020)(Citation: Malwarebytes Kimsuky June 2021)(Citation: Talos Kimsuky Nov 2021)(Citation: KISA Operation Muzabi)
- [G0095] Machete: [Machete](https://attack.mitre.org/groups/G0095) has delivered spearphishing emails that contain a zipped file with malicious contents.(Citation: Securelist Machete Aug 2014)(Citation: ESET Machete July 2019)(Citation: 360 Machete Sep 2020)
- [S0650] QakBot: [QakBot](https://attack.mitre.org/software/S0650) has spread through emails with malicious attachments.(Citation: Trend Micro Qakbot May 2020)(Citation: Kroll Qakbot June 2020)(Citation: Trend Micro Qakbot December 2020)(Citation: Cyberint Qakbot May 2021)(Citation: ATT QakBot April 2021)(Citation: Kaspersky QakBot September 2021)(Citation: Group IB Ransomware September 2020)(Citation: Deep Instinct Black Basta August 2022)(Citation: Microsoft Ransomware as a Service)
- [G0085] FIN4: [FIN4](https://attack.mitre.org/groups/G0085) has used spearphishing emails containing attachments (which are often stolen, legitimate documents sent from compromised accounts) with embedded malicious macros.(Citation: FireEye Hacking FIN4 Dec 2014)(Citation: FireEye Hacking FIN4 Video Dec 2014)
- [S0340] Octopus: [Octopus](https://attack.mitre.org/software/S0340) has been delivered via spearsphishing emails.(Citation: ESET Nomadic Octopus 2018)
- [G0102] Wizard Spider: [Wizard Spider](https://attack.mitre.org/groups/G0102) has used spearphishing attachments to deliver Microsoft documents containing macros or PDFs containing malicious links to download either [Emotet](https://attack.mitre.org/software/S0367), Bokbot, [TrickBot](https://attack.mitre.org/software/S0266), or [Bazar](https://attack.mitre.org/software/S0534).(Citation: CrowdStrike Grim Spider May 2019)(Citation: Red Canary Hospital Thwarted Ryuk October 2020)(Citation: Mandiant FIN12 Oct 2021)
- [S1017] OutSteel: [OutSteel](https://attack.mitre.org/software/S1017) has been distributed as a malicious attachment within a spearphishing email.(Citation: Palo Alto Unit 42 OutSteel SaintBot February 2022 )
- [S1039] Bumblebee: [Bumblebee](https://attack.mitre.org/software/S1039) has gained execution through luring users into opening malicious attachments.(Citation: Proofpoint Bumblebee April 2022)(Citation: Symantec Bumblebee June 2022)(Citation: Cybereason Bumblebee August 2022)(Citation: Medium Ali Salem Bumblebee April 2022)
- [S1018] Saint Bot: [Saint Bot](https://attack.mitre.org/software/S1018) has been distributed as malicious attachments within spearphishing emails.(Citation: Malwarebytes Saint Bot April 2021)(Citation: Palo Alto Unit 42 OutSteel SaintBot February 2022 )
- [G0138] Andariel: [Andariel](https://attack.mitre.org/groups/G0138) has conducted spearphishing campaigns that included malicious Word or Excel attachments.(Citation: AhnLab Andariel Subgroup of Lazarus June 2018)(Citation: MalwareBytes Lazarus-Andariel Conceals Code April 2021)
- [G1018] TA2541: [TA2541](https://attack.mitre.org/groups/G1018) has sent phishing emails with malicious attachments for initial access including MS Word documents.(Citation: Proofpoint TA2541 February 2022)(Citation: Cisco Operation Layover September 2021)
- [S0665] ThreatNeedle: [ThreatNeedle](https://attack.mitre.org/software/S0665) has been distributed via a malicious Word document within a spearphishing email.(Citation: Kaspersky ThreatNeedle Feb 2021)
- [G0131] Tonto Team: [Tonto Team](https://attack.mitre.org/groups/G0131) has delivered payloads via spearphishing attachments.(Citation: TrendMicro Tonto Team October 2020)
- [S0453] Pony: [Pony](https://attack.mitre.org/software/S0453) has been delivered via spearphishing attachments.(Citation: Malwarebytes Pony April 2016)
- [G0121] Sidewinder: [Sidewinder](https://attack.mitre.org/groups/G0121) has sent e-mails with malicious attachments often crafted for specific targets.(Citation: ATT Sidewinder January 2021)
- [S0367] Emotet: [Emotet](https://attack.mitre.org/software/S0367) has been delivered by phishing emails containing attachments. (Citation: CIS Emotet Apr 2017)(Citation: Malwarebytes Emotet Dec 2017)(Citation: Symantec Emotet Jul 2018)(Citation: US-CERT Emotet Jul 2018)(Citation: Talos Emotet Jan 2019)(Citation: Trend Micro Emotet Jan 2019)(Citation: Picus Emotet Dec 2018)(Citation: Carbon Black Emotet Apr 2019)(Citation: IBM IcedID November 2017)
- [G0092] TA505: [TA505](https://attack.mitre.org/groups/G0092) has used spearphishing emails with malicious attachments to initially compromise victims.(Citation: Proofpoint TA505 Sep 2017)(Citation: Proofpoint TA505 June 2018)(Citation: Proofpoint TA505 Jan 2019)(Citation: Cybereason TA505 April 2019)(Citation: ProofPoint SettingContent-ms July 2018)(Citation: Proofpoint TA505 Mar 2018)(Citation: Trend Micro TA505 June 2019)(Citation: Proofpoint TA505 October 2019)(Citation: IBM TA505 April 2020)
- [G0046] FIN7: [FIN7](https://attack.mitre.org/groups/G0046) sent spearphishing emails with either malicious Microsoft Documents or RTF files attached.(Citation: FireEye FIN7 April 2017)(Citation: DOJ FIN7 Aug 2018)(Citation: Flashpoint FIN 7 March 2019)(Citation: eSentire FIN7 July 2021)(Citation: CrowdStrike Carbon Spider August 2021)
- [G0067] APT37: [APT37](https://attack.mitre.org/groups/G0067) delivers malware using spearphishing emails with malicious HWP attachments.(Citation: FireEye APT37 Feb 2018)(Citation: Talos Group123)(Citation: Securelist ScarCruft May 2019)
- [S1013] ZxxZ: [ZxxZ](https://attack.mitre.org/software/S1013) has been distributed via spearphishing emails, usually containing a malicious RTF or Excel attachment.(Citation: Cisco Talos Bitter Bangladesh May 2022)
- [S0528] Javali: [Javali](https://attack.mitre.org/software/S0528) has been delivered as malicious e-mail attachments.(Citation: Securelist Brazilian Banking Malware July 2020)
- [G1012] CURIUM: [CURIUM](https://attack.mitre.org/groups/G1012) has used phishing with malicious attachments for initial access to victim environments.(Citation: PWC Yellow Liderc 2023)
- [S1075] KOPILUWAK: [KOPILUWAK](https://attack.mitre.org/software/S1075) has been delivered to victims as a malicious email attachment.(Citation: Mandiant Suspected Turla Campaign February 2023)
- [G0091] Silence: [Silence](https://attack.mitre.org/groups/G0091) has sent emails with malicious DOCX, CHM, LNK and ZIP attachments. (Citation: Cyber Forensicator Silence Jan 2019)(Citation: SecureList Silence Nov 2017)(Citation: Group IB Silence Sept 2018)
- [S0696] Flagpro: [Flagpro](https://attack.mitre.org/software/S0696) has been distributed via spearphishing as an email attachment.(Citation: NTT Security Flagpro new December 2021)
- [S0520] BLINDINGCAN: [BLINDINGCAN](https://attack.mitre.org/software/S0520) has been delivered by phishing emails containing malicious Microsoft Office documents.(Citation: US-CERT BLINDINGCAN Aug 2020)
- [G0136] IndigoZebra: [IndigoZebra](https://attack.mitre.org/groups/G0136) sent spearphishing emails containing malicious password-protected RAR attachments.(Citation: HackerNews IndigoZebra July 2021)(Citation: Checkpoint IndigoZebra July 2021)
- [G0006] APT1: [APT1](https://attack.mitre.org/groups/G0006) has sent spearphishing emails containing malicious attachments.(Citation: Mandiant APT1)
- [G0082] APT38: [APT38](https://attack.mitre.org/groups/G0082) has conducted spearphishing campaigns using malicious email attachments.(Citation: CISA AA20-239A BeagleBoyz August 2020)
- [G0079] DarkHydrus: [DarkHydrus](https://attack.mitre.org/groups/G0079) has sent spearphishing emails with password-protected RAR archives containing malicious Excel Web Query files (.iqy). The group has also sent spearphishing emails that contained malicious Microsoft Office documents that use the “attachedTemplate” technique to load a template from a remote server.(Citation: Unit 42 DarkHydrus July 2018)(Citation: Unit 42 Phishery Aug 2018)(Citation: Unit 42 Playbook Dec 2017)
- [G0089] The White Company: [The White Company](https://attack.mitre.org/groups/G0089) has sent phishing emails with malicious Microsoft Word attachments to victims.(Citation: Cylance Shaheen Nov 2018)
- [S0198] NETWIRE: [NETWIRE](https://attack.mitre.org/software/S0198) has been spread via e-mail campaigns utilizing malicious attachments.(Citation: Unit 42 NETWIRE April 2020)(Citation: Proofpoint NETWIRE December 2020)
- [G0068] PLATINUM: [PLATINUM](https://attack.mitre.org/groups/G0068) has sent spearphishing emails with attachments to victims as its primary initial access vector.(Citation: Microsoft PLATINUM April 2016)
- [S1213] Lumma Stealer: [Lumma Stealer](https://attack.mitre.org/software/S1213)  has been delivered through phishing emails with malicious attachments.(Citation: Cybereason LumaStealer Undated)
- [G0075] Rancor: [Rancor](https://attack.mitre.org/groups/G0075) has attached a malicious document to an email to gain initial access.(Citation: Rancor Unit42 June 2018)
- [G0099] APT-C-36: [APT-C-36](https://attack.mitre.org/groups/G0099) has used spearphishing emails with password protected RAR attachment to avoid being detected by the email gateway.(Citation: QiAnXin APT-C-36 Feb2019)
- [G0087] APT39: [APT39](https://attack.mitre.org/groups/G0087) leveraged spearphishing emails with malicious attachments to initially compromise victims.(Citation: FireEye APT39 Jan 2019)(Citation: Symantec Chafer February 2018)(Citation: FBI FLASH APT39 September 2020)
- [S0346] OceanSalt: [OceanSalt](https://attack.mitre.org/software/S0346) has been delivered via spearphishing emails with Microsoft Office attachments.(Citation: McAfee Oceansalt Oct 2018)
- [G0084] Gallmaker: [Gallmaker](https://attack.mitre.org/groups/G0084) sent emails with malicious Microsoft Office documents attached.(Citation: Symantec Gallmaker Oct 2018)
- [S0266] TrickBot: [TrickBot](https://attack.mitre.org/software/S0266) has used an email with an Excel sheet containing a malicious macro to deploy the malware(Citation: TrendMicro Trickbot Feb 2019)

#### T1566.002 - Phishing: Spearphishing Link

Description:

Adversaries may send spearphishing emails with a malicious link in an attempt to gain access to victim systems. Spearphishing with a link is a specific variant of spearphishing. It is different from other forms of spearphishing in that it employs the use of links to download malware contained in email, instead of attaching malicious files to the email itself, to avoid defenses that may inspect email attachments. Spearphishing may also involve social engineering techniques, such as posing as a trusted source.

All forms of spearphishing are electronically delivered social engineering targeted at a specific individual, company, or industry. In this case, the malicious emails contain links. Generally, the links will be accompanied by social engineering text and require the user to actively click or copy and paste a URL into a browser, leveraging [User Execution](https://attack.mitre.org/techniques/T1204). The visited website may compromise the web browser using an exploit, or the user will be prompted to download applications, documents, zip files, or even executables depending on the pretext for the email in the first place.

Adversaries may also include links that are intended to interact directly with an email reader, including embedded images intended to exploit the end system directly. Additionally, adversaries may use seemingly benign links that abuse special characters to mimic legitimate websites (known as an "IDN homograph attack").(Citation: CISA IDN ST05-016) URLs may also be obfuscated by taking advantage of quirks in the URL schema, such as the acceptance of integer- or hexadecimal-based hostname formats and the automatic discarding of text before an “@” symbol: for example, `hxxp://google.com@1157586937`.(Citation: Mandiant URL Obfuscation 2023)

Adversaries may also utilize links to perform consent phishing, typically with OAuth 2.0 request URLs that when accepted by the user provide permissions/access for malicious applications, allowing adversaries to  [Steal Application Access Token](https://attack.mitre.org/techniques/T1528)s.(Citation: Trend Micro Pawn Storm OAuth 2017) These stolen access tokens allow the adversary to perform various actions on behalf of the user via API calls. (Citation: Microsoft OAuth 2.0 Consent Phishing 2021)

Adversaries may also utilize spearphishing links to [Steal Application Access Token](https://attack.mitre.org/techniques/T1528)s that grant immediate access to the victim environment. For example, a user may be lured through “consent phishing” into granting adversaries permissions/access via a malicious OAuth 2.0 request URL .(Citation: Trend Micro Pawn Storm OAuth 2017)(Citation: Microsoft OAuth 2.0 Consent Phishing 2021)

Similarly, malicious links may also target device-based authorization, such as OAuth 2.0 device authorization grant flow which is typically used to authenticate devices without UIs/browsers. Known as “device code phishing,” an adversary may send a link that directs the victim to a malicious authorization page where the user is tricked into entering a code/credentials that produces a device token.(Citation: SecureWorks Device Code Phishing 2021)(Citation: Netskope Device Code Phishing 2021)(Citation: Optiv Device Code Phishing 2021)

Procedures:

- [G0098] BlackTech: [BlackTech](https://attack.mitre.org/groups/G0098) has used spearphishing e-mails with links to cloud services to deliver malware.(Citation: TrendMicro BlackTech June 2017)
- [S0585] Kerrdown: [Kerrdown](https://attack.mitre.org/software/S0585) has been distributed via e-mails containing a malicious link.(Citation: Amnesty Intl. Ocean Lotus February 2021)
- [G0069] MuddyWater: [MuddyWater](https://attack.mitre.org/groups/G0069) has sent targeted spearphishing e-mails with malicious links.(Citation: Anomali Static Kitten February 2021)(Citation: Trend Micro Muddy Water March 2021)(Citation: Proofpoint TA450 Phishing March 2024)
- [G1014] LuminousMoth: [LuminousMoth](https://attack.mitre.org/groups/G1014) has sent spearphishing emails containing a malicious Dropbox download link.(Citation: Kaspersky LuminousMoth July 2021)
- [G0142] Confucius: [Confucius](https://attack.mitre.org/groups/G0142) has sent malicious links to victims through email campaigns.(Citation: TrendMicro Confucius APT Aug 2021)
- [G0103] Mofang: [Mofang](https://attack.mitre.org/groups/G0103) delivered spearphishing emails with malicious links included.(Citation: FOX-IT May 2016 Mofang)
- [G0094] Kimsuky: [Kimsuky](https://attack.mitre.org/groups/G0094) has sent spearphishing emails containing a link to a document that contained malicious macros or took the victim to an actor-controlled domain.(Citation: EST Kimsuky April 2019)(Citation: Netscout Stolen Pencil Dec 2018)(Citation: KISA Operation Muzabi)
- [G0121] Sidewinder: [Sidewinder](https://attack.mitre.org/groups/G0121) has sent e-mails with malicious links often crafted for specific targets.(Citation: ATT Sidewinder January 2021)(Citation: Cyble Sidewinder September 2020)
- [S0561] GuLoader: [GuLoader](https://attack.mitre.org/software/S0561) has been spread in phishing campaigns using malicious web links.(Citation: Unit 42 NETWIRE April 2020)
- [S1017] OutSteel: [OutSteel](https://attack.mitre.org/software/S1017) has been distributed through malicious links contained within spearphishing emails.(Citation: Palo Alto Unit 42 OutSteel SaintBot February 2022 )
- [C0002] Night Dragon: During [Night Dragon](https://attack.mitre.org/campaigns/C0002), threat actors sent spearphishing emails containing links to compromised websites where malware was downloaded.(Citation: McAfee Night Dragon)
- [S0669] KOCTOPUS: [KOCTOPUS](https://attack.mitre.org/software/S0669) has been distributed as a malicious link within an email.(Citation: MalwareBytes LazyScripter Feb 2021)
- [G0066] Elderwood: [Elderwood](https://attack.mitre.org/groups/G0066) has delivered zero-day exploits and malware to victims via targeted emails containing a link to malicious content hosted on an uncommon Web server.(Citation: Symantec Elderwood Sept 2012)(Citation: CSM Elderwood Sept 2012)
- [S0528] Javali: [Javali](https://attack.mitre.org/software/S0528) has been delivered via malicious links embedded in e-mails.(Citation: Securelist Brazilian Banking Malware July 2020)
- [S1111] DarkGate: [DarkGate](https://attack.mitre.org/software/S1111) is distributed in phishing emails containing links to distribute malicious VBS or MSI files.(Citation: Trellix Darkgate 2023) [DarkGate](https://attack.mitre.org/software/S1111) uses applications such as Microsoft Teams for distributing links to payloads.(Citation: Trellix Darkgate 2023)
- [S1030] Squirrelwaffle: [Squirrelwaffle](https://attack.mitre.org/software/S1030) has been distributed through phishing emails containing a malicious URL.(Citation: ZScaler Squirrelwaffle Sep 2021)
- [G0095] Machete: [Machete](https://attack.mitre.org/groups/G0095) has sent phishing emails that contain a link to an external server with ZIP and RAR archives.(Citation: Cylance Machete Mar 2017)(Citation: ESET Machete July 2019)
- [S0584] AppleJeus: [AppleJeus](https://attack.mitre.org/software/S0584) has been distributed via spearphishing link.(Citation: CISA AppleJeus Feb 2021)
- [G0046] FIN7: [FIN7](https://attack.mitre.org/groups/G0046) has conducted broad phishing campaigns using malicious links.(Citation: CrowdStrike Carbon Spider August 2021)
- [S0367] Emotet: [Emotet](https://attack.mitre.org/software/S0367) has been delivered by phishing emails containing links. (Citation: Trend Micro Banking Malware Jan 2019)(Citation: Kaspersky Emotet Jan 2019)(Citation: CIS Emotet Apr 2017)(Citation: Malwarebytes Emotet Dec 2017)(Citation: Symantec Emotet Jul 2018)(Citation: US-CERT Emotet Jul 2018)(Citation: Talos Emotet Jan 2019)(Citation: Talos Emotet Jan 2019)(Citation: Picus Emotet Dec 2018)
- [C0005] Operation Spalax: During [Operation Spalax](https://attack.mitre.org/campaigns/C0005), the threat actors sent phishing emails to victims that contained a malicious link.(Citation: ESET Operation Spalax Jan 2021)
- [G1020] Mustard Tempest: [Mustard Tempest](https://attack.mitre.org/groups/G1020) has sent victims emails containing links to compromised websites.(Citation: SocGholish-update)
- [G0034] Sandworm Team: [Sandworm Team](https://attack.mitre.org/groups/G0034) has crafted phishing emails containing malicious hyperlinks.(Citation: US District Court Indictment GRU Unit 74455 October 2020)
- [G0134] Transparent Tribe: [Transparent Tribe](https://attack.mitre.org/groups/G0134) has embedded links to malicious downloads in e-mails.(Citation: Talos Oblique RAT March 2021)(Citation: Talos Transparent Tribe May 2021)
- [G0120] Evilnum: [Evilnum](https://attack.mitre.org/groups/G0120) has sent spearphishing emails containing a link to a zip file hosted on Google Drive.(Citation: ESET EvilNum July 2020)
- [S1122] Mispadu: [Mispadu](https://attack.mitre.org/software/S1122) has been spread via malicious links embedded in emails.(Citation: SCILabs Malteiro 2021)
- [S0646] SpicyOmelette: [SpicyOmelette](https://attack.mitre.org/software/S0646) has been distributed via emails containing a malicious link that appears to be a PDF document.(Citation: Secureworks GOLD KINGSWOOD September 2018)
- [G0129] Mustang Panda: [Mustang Panda](https://attack.mitre.org/groups/G0129) has delivered malicious links to their intended targets.(Citation: McAfee Dianxun March 2021)
- [G0061] FIN8: [FIN8](https://attack.mitre.org/groups/G0061) has distributed targeted emails containing links to malicious documents with embedded macros.(Citation: FireEye Know Your Enemy FIN8 Aug 2016)
- [G0050] APT32: [APT32](https://attack.mitre.org/groups/G0050) has sent spearphishing emails containing malicious links.(Citation: ESET OceanLotus)(Citation: Cybereason Oceanlotus May 2017)(Citation: FireEye APT32 April 2020)(Citation: Volexity Ocean Lotus November 2020)(Citation: Amnesty Intl. Ocean Lotus February 2021)
- [S0453] Pony: [Pony](https://attack.mitre.org/software/S0453) has been delivered via spearphishing emails which contained malicious links.(Citation: Malwarebytes Pony April 2016)
- [G0022] APT3: [APT3](https://attack.mitre.org/groups/G0022) has sent spearphishing emails containing malicious links.(Citation: FireEye Clandestine Wolf)
- [G0006] APT1: [APT1](https://attack.mitre.org/groups/G0006) has sent spearphishing emails containing hyperlinks to malicious files.(Citation: Mandiant APT1)
- [G0032] Lazarus Group: [Lazarus Group](https://attack.mitre.org/groups/G0032) has sent malicious links to victims via email.(Citation: Kaspersky ThreatNeedle Feb 2021)
- [G0065] Leviathan: [Leviathan](https://attack.mitre.org/groups/G0065) has sent spearphishing emails with links, often using a fraudulent lookalike domain and stolen branding.(Citation: Proofpoint Leviathan Oct 2017)(Citation: CISA AA21-200A APT40 July 2021)
- [S1018] Saint Bot: [Saint Bot](https://attack.mitre.org/software/S1018) has been distributed through malicious links contained within spearphishing emails.(Citation: Palo Alto Unit 42 OutSteel SaintBot February 2022 )
- [G0064] APT33: [APT33](https://attack.mitre.org/groups/G0064) has sent spearphishing emails containing links to .hta files.(Citation: FireEye APT33 Sept 2017)(Citation: Symantec Elfin Mar 2019)
- [G0128] ZIRCONIUM: [ZIRCONIUM](https://attack.mitre.org/groups/G0128) has used malicious links in e-mails to deliver malware.(Citation: Microsoft Targeting Elections September 2020)(Citation: Google Election Threats October 2020)(Citation: Zscaler APT31 Covid-19 October 2020)
- [G1011] EXOTIC LILY: [EXOTIC LILY](https://attack.mitre.org/groups/G1011) has relied on victims to open malicious links in e-mails for execution.(Citation: Google EXOTIC LILY March 2022)
- [S0677] AADInternals: [AADInternals](https://attack.mitre.org/software/S0677) can send "consent phishing" emails containing malicious links designed to steal users’ access tokens.(Citation: AADInternals Documentation)
- [S1039] Bumblebee: [Bumblebee](https://attack.mitre.org/software/S1039) has been spread through e-mail campaigns with malicious links.(Citation: Proofpoint Bumblebee April 2022)(Citation: Cybereason Bumblebee August 2022)
- [C0011] C0011: During [C0011](https://attack.mitre.org/campaigns/C0011), [Transparent Tribe](https://attack.mitre.org/groups/G0134) sent emails containing a malicious link to student targets in India.(Citation: Cisco Talos Transparent Tribe Education Campaign July 2022)
- [S0266] TrickBot: [TrickBot](https://attack.mitre.org/software/S0266) has been delivered via malicious links in phishing e-mails.(Citation: Cyberreason Anchor December 2019)
- [G0021] Molerats: [Molerats](https://attack.mitre.org/groups/G0021) has sent phishing emails with malicious links included.(Citation: Kaspersky MoleRATs April 2019)
- [G0059] Magic Hound: [Magic Hound](https://attack.mitre.org/groups/G0059) has sent malicious URL links through email to victims. In some cases the URLs were shortened or linked to Word documents with malicious macros that executed PowerShells scripts to download [Pupy](https://attack.mitre.org/software/S0192).(Citation: Secureworks Cobalt Gypsy Feb 2017)(Citation: ClearSky Kittens Back 3 August 2020)(Citation: Certfa Charming Kitten January 2021)(Citation: Microsoft Iranian Threat Actor Trends November 2021)
- [S1124] SocGholish: [SocGholish](https://attack.mitre.org/software/S1124) has been spread via emails containing malicious links.(Citation: SocGholish-update)
- [G0049] OilRig: [OilRig](https://attack.mitre.org/groups/G0049) has sent spearphising emails with malicious links to potential victims.(Citation: Unit 42 OopsIE! Feb 2018)(Citation: ClearSky OilRig Jan 2017)
- [G0112] Windshift: [Windshift](https://attack.mitre.org/groups/G0112) has sent spearphishing emails with links to harvest credentials and deliver malware.(Citation: SANS Windshift August 2018)
- [C0047] RedDelta Modified PlugX Infection Chain Operations: [Mustang Panda](https://attack.mitre.org/groups/G0129) distributed malicious links in phishing emails leading to HTML files that would direct the victim to malicious MSC files if running Windows based on User Agent fingerprinting during [RedDelta Modified PlugX Infection Chain Operations](https://attack.mitre.org/campaigns/C0047).(Citation: Recorded Future RedDelta 2025)
- [G0080] Cobalt Group: [Cobalt Group](https://attack.mitre.org/groups/G0080) has sent emails with URLs pointing to malicious documents.(Citation: Talos Cobalt Group July 2018)(Citation: Secureworks GOLD KINGSWOOD September 2018)
- [S0198] NETWIRE: [NETWIRE](https://attack.mitre.org/software/S0198) has been spread via e-mail campaigns utilizing malicious links.(Citation: Unit 42 NETWIRE April 2020)
- [G0016] APT29: [APT29](https://attack.mitre.org/groups/G0016) has used spearphishing with a link to trick victims into clicking on a link to a zip file containing malicious files.(Citation: Mandiant No Easy Breach)(Citation: MSTIC NOBELIUM May 2021)(Citation: Secureworks IRON RITUAL USAID Phish May 2021)
- [G0085] FIN4: [FIN4](https://attack.mitre.org/groups/G0085) has used spearphishing emails (often sent from compromised accounts) containing malicious links.(Citation: FireEye Hacking FIN4 Dec 2014)(Citation: FireEye Hacking FIN4 Video Dec 2014)
- [C0021] C0021: During [C0021](https://attack.mitre.org/campaigns/C0021), the threat actors sent phishing emails with unique malicious links, likely for tracking victim clicks.(Citation: FireEye APT29 Nov 2018)(Citation: Microsoft Unidentified Dec 2018)
- [S1086] Snip3: [Snip3](https://attack.mitre.org/software/S1086) has been delivered to victims through e-mail links to malicious files.(Citation: Telefonica Snip3 December 2021)
- [S0650] QakBot: [QakBot](https://attack.mitre.org/software/S0650) has spread through emails with malicious links.(Citation: Trend Micro Qakbot May 2020)(Citation: Kroll Qakbot June 2020)(Citation: Trend Micro Qakbot December 2020)(Citation: ATT QakBot April 2021)(Citation: Kaspersky QakBot September 2021)(Citation: Group IB Ransomware September 2020)(Citation: Trend Micro Black Basta October 2022)
- [G1018] TA2541: [TA2541](https://attack.mitre.org/groups/G1018) has used spearphishing e-mails with malicious links to deliver malware.  (Citation: Proofpoint TA2541 February 2022)(Citation: Telefonica Snip3 December 2021)
- [S0499] Hancitor: [Hancitor](https://attack.mitre.org/software/S0499) has been delivered via phishing emails which contained malicious links.(Citation: Threatpost Hancitor)
- [S0534] Bazar: [Bazar](https://attack.mitre.org/software/S0534) has been spread via emails with embedded malicious links.(Citation: Cybereason Bazar July 2020)(Citation: Zscaler Bazar September 2020)(Citation: CrowdStrike Wizard Spider October 2020)
- [G1006] Earth Lusca: [Earth Lusca](https://attack.mitre.org/groups/G1006) has sent spearphishing emails to potential targets that contained a malicious link.(Citation: TrendMicro EarthLusca 2022)
- [G1039] RedCurl: [RedCurl](https://attack.mitre.org/groups/G1039) has used phishing emails with malicious links to gain initial access.(Citation: group-ib_redcurl1)(Citation: group-ib_redcurl2)
- [G1046] Storm-1811: [Storm-1811](https://attack.mitre.org/groups/G1046) has distributed malicious links to victims that redirect to EvilProxy-based phishing sites to harvest credentials.(Citation: Microsoft Storm-1811 2024)
- [G0010] Turla: [Turla](https://attack.mitre.org/groups/G0010) attempted to trick targets into clicking on a link featuring a seemingly legitimate domain from Adobe.com to download their malware and gain initial access.(Citation: ESET Turla Mosquito Jan 2018)
- [G0102] Wizard Spider: [Wizard Spider](https://attack.mitre.org/groups/G0102) has sent phishing emails containing a link to an actor-controlled Google Drive document or other free online file hosting services.(Citation: DHS/CISA Ransomware Targeting Healthcare October 2020)(Citation: DFIR Ryuk 2 Hour Speed Run November 2020)
- [S1160] Latrodectus: [Latrodectus](https://attack.mitre.org/software/S1160) has been distributed to victims through emails containing malicious links.(Citation: Latrodectus APR 2024)(Citation: Bleeping Computer Latrodectus April 2024)
- [G1037] TA577: [TA577](https://attack.mitre.org/groups/G1037) has sent emails containing links to malicious JavaScript files.(Citation: Latrodectus APR 2024)
- [G0040] Patchwork: [Patchwork](https://attack.mitre.org/groups/G0040) has used spearphishing with links to deliver files with exploits to initial victims.(Citation: Symantec Patchwork)(Citation: TrendMicro Patchwork Dec 2017)(Citation: Unit 42 BackConfig May 2020)
- [G0092] TA505: [TA505](https://attack.mitre.org/groups/G0092) has sent spearphishing emails containing malicious links.(Citation: Proofpoint TA505 Sep 2017)(Citation: Proofpoint TA505 Jan 2019)(Citation: Trend Micro TA505 June 2019)(Citation: Proofpoint TA505 October 2019)
- [G0140] LazyScripter: [LazyScripter](https://attack.mitre.org/groups/G0140) has used spam emails that contain a link that redirects the victim to download a malicious document.(Citation: MalwareBytes LazyScripter Feb 2021)
- [S0530] Melcoz: [Melcoz](https://attack.mitre.org/software/S0530) has been spread through malicious links embedded in e-mails.(Citation: Securelist Brazilian Banking Malware July 2020)
- [C0016] Operation Dust Storm: During [Operation Dust Storm](https://attack.mitre.org/campaigns/C0016), the threat actors sent spearphishing emails containing a malicious link.(Citation: Cylance Dust Storm)
- [S0531] Grandoreiro: [Grandoreiro](https://attack.mitre.org/software/S0531) has been spread via malicious links embedded in e-mails.(Citation: IBM Grandoreiro April 2020)(Citation: ESET Grandoreiro April 2020)
- [S0476] Valak: [Valak](https://attack.mitre.org/software/S0476) has been delivered via malicious links in e-mail.(Citation: SentinelOne Valak June 2020)
- [G1044] APT42: [APT42](https://attack.mitre.org/groups/G1044) has sent spearphishing emails containing malicious links.(Citation: Mandiant APT42-charms)(Citation: Mandiant APT42-untangling)(Citation: TAG APT42)
- [G0087] APT39: [APT39](https://attack.mitre.org/groups/G0087) leveraged spearphishing emails with malicious links to initially compromise victims.(Citation: FireEye APT39 Jan 2019)(Citation: FBI FLASH APT39 September 2020)
- [S1213] Lumma Stealer: [Lumma Stealer](https://attack.mitre.org/software/S1213) has been delivered through phishing emails containing malicious links.(Citation: Cybereason LumaStealer Undated)
- [C0022] Operation Dream Job: During [Operation Dream Job](https://attack.mitre.org/campaigns/C0022), [Lazarus Group](https://attack.mitre.org/groups/G0032) sent malicious OneDrive links with fictitious job offer advertisements via email.(Citation: ClearSky Lazarus Aug 2020)(Citation: ESET Lazarus Jun 2020)
- [C0036] Pikabot Distribution February 2024: [Pikabot Distribution February 2024](https://attack.mitre.org/campaigns/C0036) utilized emails with hyperlinks leading to malicious ZIP archive files containing scripts to download and install [Pikabot](https://attack.mitre.org/software/S1145).(Citation: Elastic Pikabot 2024)

#### T1566.003 - Phishing: Spearphishing via Service

Description:

Adversaries may send spearphishing messages via third-party services in an attempt to gain access to victim systems. Spearphishing via service is a specific variant of spearphishing. It is different from other forms of spearphishing in that it employs the use of third party services rather than directly via enterprise email channels. 

All forms of spearphishing are electronically delivered social engineering targeted at a specific individual, company, or industry. In this scenario, adversaries send messages through various social media services, personal webmail, and other non-enterprise controlled services.(Citation: Lookout Dark Caracal Jan 2018) These services are more likely to have a less-strict security policy than an enterprise. As with most kinds of spearphishing, the goal is to generate rapport with the target or get the target's interest in some way. Adversaries will create fake social media accounts and message employees for potential job opportunities. Doing so allows a plausible reason for asking about services, policies, and software that's running in an environment. The adversary can then send malicious links or attachments through these services.

A common example is to build rapport with a target via social media, then send content to a personal webmail service that the target uses on their work computer. This allows an adversary to bypass some email restrictions on the work account, and the target is more likely to open the file since it's something they were expecting. If the payload doesn't work as expected, the adversary can continue normal communications and troubleshoot with the target on how to get it working.

Procedures:

- [G1012] CURIUM: [CURIUM](https://attack.mitre.org/groups/G1012) has used social media to deliver malicious files to victims.(Citation: Microsoft Iranian Threat Actor Trends November 2021)
- [G0112] Windshift: [Windshift](https://attack.mitre.org/groups/G0112) has used fake personas on social media to engage and target victims.(Citation: SANS Windshift August 2018)
- [G0130] Ajax Security Team: [Ajax Security Team](https://attack.mitre.org/groups/G0130) has used various social media channels to spearphish victims.(Citation: FireEye Operation Saffron Rose 2013)
- [G1011] EXOTIC LILY: [EXOTIC LILY](https://attack.mitre.org/groups/G1011) has used the e-mail notification features of legitimate file sharing services for spearphishing.(Citation: Google EXOTIC LILY March 2022)
- [S1100] Ninja: [Ninja](https://attack.mitre.org/software/S1100) has been distributed to victims via the messaging app Telegram.(Citation: Kaspersky ToddyCat June 2022)
- [G1022] ToddyCat: [ToddyCat](https://attack.mitre.org/groups/G1022) has sent loaders configured to run [Ninja](https://attack.mitre.org/software/S1100) as zip archives via Telegram.(Citation: Kaspersky ToddyCat June 2022)
- [C0022] Operation Dream Job: During [Operation Dream Job](https://attack.mitre.org/campaigns/C0022), [Lazarus Group](https://attack.mitre.org/groups/G0032) sent victims spearphishing messages via LinkedIn concerning fictitious jobs.(Citation: ClearSky Lazarus Aug 2020)(Citation: ESET Lazarus Jun 2020)
- [G0037] FIN6: [FIN6](https://attack.mitre.org/groups/G0037) has used fake job advertisements sent via LinkedIn to spearphish targets.(Citation: Security Intelligence More Eggs Aug 2019)
- [G0016] APT29: [APT29](https://attack.mitre.org/groups/G0016) has used the legitimate mailing service Constant Contact to send phishing e-mails.(Citation: MSTIC NOBELIUM May 2021)
- [G0049] OilRig: [OilRig](https://attack.mitre.org/groups/G0049) has used LinkedIn to send spearphishing links.(Citation: FireEye APT34 July 2019)
- [G0070] Dark Caracal: [Dark Caracal](https://attack.mitre.org/groups/G0070) spearphished victims via Facebook and Whatsapp.(Citation: Lookout Dark Caracal Jan 2018)
- [G0032] Lazarus Group: [Lazarus Group](https://attack.mitre.org/groups/G0032) has used social media platforms, including LinkedIn and Twitter, to send spearphishing messages.(Citation: Google TAG Lazarus Jan 2021)
- [G1046] Storm-1811: [Storm-1811](https://attack.mitre.org/groups/G1046) has used Microsoft Teams to send messages and initiate voice calls to victims posing as IT support personnel.(Citation: Microsoft Storm-1811 2024)
- [G0059] Magic Hound: [Magic Hound](https://attack.mitre.org/groups/G0059) used various social media channels (such as LinkedIn) as well as messaging services (such as WhatsApp) to spearphish victims.(Citation: SecureWorks Mia Ash July 2017)(Citation: Microsoft Phosphorus Mar 2019)(Citation: ClearSky Kittens Back 3 August 2020)
- [G1036] Moonstone Sleet: [Moonstone Sleet](https://attack.mitre.org/groups/G1036) has used social media services to spear phish victims to deliver trojainized software.(Citation: Microsoft Moonstone Sleet 2024)

#### T1566.004 - Phishing: Spearphishing Voice

Description:

Adversaries may use voice communications to ultimately gain access to victim systems. Spearphishing voice is a specific variant of spearphishing. It is different from other forms of spearphishing in that is employs the use of manipulating a user into providing access to systems through a phone call or other forms of voice communications. Spearphishing frequently involves social engineering techniques, such as posing as a trusted source (ex: [Impersonation](https://attack.mitre.org/techniques/T1656)) and/or creating a sense of urgency or alarm for the recipient.

All forms of phishing are electronically delivered social engineering. In this scenario, adversaries are not directly sending malware to a victim vice relying on [User Execution](https://attack.mitre.org/techniques/T1204) for delivery and execution. For example, victims may receive phishing messages that instruct them to call a phone number where they are directed to visit a malicious URL, download malware,(Citation: sygnia Luna Month)(Citation: CISA Remote Monitoring and Management Software) or install adversary-accessible remote management tools ([Remote Access Tools](https://attack.mitre.org/techniques/T1219)) onto their computer.(Citation: Unit42 Luna Moth)

Adversaries may also combine voice phishing with [Multi-Factor Authentication Request Generation](https://attack.mitre.org/techniques/T1621) in order to trick users into divulging MFA credentials or accepting authentication prompts.(Citation: Proofpoint Vishing)

Procedures:

- [G1046] Storm-1811: [Storm-1811](https://attack.mitre.org/groups/G1046) has initiated voice calls with victims posing as IT support to prompt users to download and execute scripts and other tools for initial access.(Citation: Microsoft Storm-1811 2024)(Citation: rapid7-email-bombing)(Citation: RedCanary Storm-1811 2024)
- [C0027] C0027: During [C0027](https://attack.mitre.org/campaigns/C0027), [Scattered Spider](https://attack.mitre.org/groups/G1015) impersonated legitimate IT personnel in phone calls to direct victims to download a remote monitoring and management (RMM) tool that would allow the adversary to remotely control their system.(Citation: Crowdstrike TELCO BPO Campaign December 2022)


### T1659 - Content Injection

Description:

Adversaries may gain access and continuously communicate with victims by injecting malicious content into systems through online network traffic. Rather than luring victims to malicious payloads hosted on a compromised website (i.e., [Drive-by Target](https://attack.mitre.org/techniques/T1608/004) followed by [Drive-by Compromise](https://attack.mitre.org/techniques/T1189)), adversaries may initially access victims through compromised data-transfer channels where they can manipulate traffic and/or inject their own content. These compromised online network channels may also be used to deliver additional payloads (i.e., [Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105)) and other data to already compromised systems.(Citation: ESET MoustachedBouncer)

Adversaries may inject content to victim systems in various ways, including:

* From the middle, where the adversary is in-between legitimate online client-server communications (**Note:** this is similar but distinct from [Adversary-in-the-Middle](https://attack.mitre.org/techniques/T1557), which describes AiTM activity solely within an enterprise environment) (Citation: Kaspersky Encyclopedia MiTM)
* From the side, where malicious content is injected and races to the client as a fake response to requests of a legitimate online server (Citation: Kaspersky ManOnTheSide)

Content injection is often the result of compromised upstream communication channels, for example at the level of an internet service provider (ISP) as is the case with "lawful interception."(Citation: Kaspersky ManOnTheSide)(Citation: ESET MoustachedBouncer)(Citation: EFF China GitHub Attack)

Procedures:

- [S1088] Disco: [Disco](https://attack.mitre.org/software/S1088) has achieved initial access and execution through content injection into DNS,  HTTP, and SMB replies to targeted hosts that redirect them to download malicious files.(Citation: MoustachedBouncer ESET August 2023)
- [G1019] MoustachedBouncer: [MoustachedBouncer](https://attack.mitre.org/groups/G1019) has injected content into DNS, HTTP, and SMB replies to redirect specifically-targeted victims to a fake Windows Update page to download malware.(Citation: MoustachedBouncer ESET August 2023)


### T1669 - Wi-Fi Networks

Description:

Adversaries may gain initial access to target systems by connecting to wireless networks. They may accomplish this by exploiting open Wi-Fi networks used by target devices or by accessing secured Wi-Fi networks — requiring [Valid Accounts](https://attack.mitre.org/techniques/T1078) — belonging to a target organization.(Citation: DOJ GRU Charges 2018)(Citation: Nearest Neighbor Volexity) Establishing a connection to a Wi-Fi access point requires a certain level of proximity to both discover and maintain a stable network connection. 

Adversaries may establish a wireless connection through various methods, such as by physically positioning themselves near a Wi-Fi network to conduct close access operations. To bypass the need for physical proximity, adversaries may attempt to remotely compromise nearby third-party systems that have both wired and wireless network connections available (i.e., dual-homed systems). These third-party compromised devices can then serve as a bridge to connect to a target’s Wi-Fi network.(Citation: Nearest Neighbor Volexity)

Once an initial wireless connection is achieved, adversaries may leverage this access for follow-on activities in the victim network or further targeting of specific devices on the network. Adversaries may perform [Network Sniffing](https://attack.mitre.org/techniques/T1040) or [Adversary-in-the-Middle](https://attack.mitre.org/techniques/T1557) activities for [Credential Access](https://attack.mitre.org/tactics/TA0006) or [Discovery](https://attack.mitre.org/tactics/TA0007).

Procedures:

- [G0007] APT28: [APT28](https://attack.mitre.org/groups/G0007) has exploited open Wi-Fi access points for initial access to target devices using the network.(Citation: Nearest Neighbor Volexity)(Citation: DOJ GRU Charges 2018)
- [C0051] APT28 Nearest Neighbor Campaign: During [APT28 Nearest Neighbor Campaign](https://attack.mitre.org/campaigns/C0051), [APT28](https://attack.mitre.org/groups/G0007) established wireless connections to secure, enterprise Wi-Fi networks belonging to a target organization for initial access into the environment.(Citation: Nearest Neighbor Volexity)

