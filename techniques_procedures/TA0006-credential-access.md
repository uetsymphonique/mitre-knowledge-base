### T1003 - OS Credential Dumping

Description:

Adversaries may attempt to dump credentials to obtain account login and credential material, normally in the form of a hash or a clear text password. Credentials can be obtained from OS caches, memory, or structures.(Citation: Brining MimiKatz to Unix) Credentials can then be used to perform [Lateral Movement](https://attack.mitre.org/tactics/TA0008) and access restricted information.

Several of the tools mentioned in associated sub-techniques may be used by both adversaries and professional security testers. Additional custom tools likely exist as well.

Procedures:

- [G1003] Ember Bear: [Ember Bear](https://attack.mitre.org/groups/G1003) gathers credential material from target systems, such as SSH keys, to facilitate access to victim environments.(Citation: Cadet Blizzard emerges as novel threat actor)
- [G0087] APT39: [APT39](https://attack.mitre.org/groups/G0087) has used different versions of Mimikatz to obtain credentials.(Citation: BitDefender Chafer May 2020)
- [S0030] Carbanak: [Carbanak](https://attack.mitre.org/software/S0030) obtains Windows logon password details.(Citation: FireEye CARBANAK June 2017)
- [S1146] MgBot: [MgBot](https://attack.mitre.org/software/S1146) includes modules for dumping and capturing credentials from process memory.(Citation: Symantec Daggerfly 2023)
- [S0379] Revenge RAT: [Revenge RAT](https://attack.mitre.org/software/S0379) has a plugin for credential harvesting.(Citation: Cylance Shaheen Nov 2018)
- [S0048] PinchDuke: [PinchDuke](https://attack.mitre.org/software/S0048) steals credentials from compromised hosts. [PinchDuke](https://attack.mitre.org/software/S0048)'s credential stealing functionality is believed to be based on the source code of the Pinch credential stealing malware (also known as LdPinch). Credentials targeted by [PinchDuke](https://attack.mitre.org/software/S0048) include ones associated many sources such as WinInet Credential Cache, and Lightweight Directory Access Protocol (LDAP).(Citation: F-Secure The Dukes)
- [G0033] Poseidon Group: [Poseidon Group](https://attack.mitre.org/groups/G0033) conducts credential dumping on victims, with a focus on obtaining credentials belonging to domain and database servers.(Citation: Kaspersky Poseidon Group)
- [S0052] OnionDuke: [OnionDuke](https://attack.mitre.org/software/S0052) steals credentials from its victims.(Citation: F-Secure The Dukes)
- [G0131] Tonto Team: [Tonto Team](https://attack.mitre.org/groups/G0131) has used a variety of credential dumping tools.(Citation: TrendMicro Tonto Team October 2020)
- [G0050] APT32: [APT32](https://attack.mitre.org/groups/G0050) used GetPassword_x64 to harvest credentials.(Citation: Cybereason Oceanlotus May 2017)(Citation: Cybereason Cobalt Kitty 2017)
- [S0232] HOMEFRY: [HOMEFRY](https://attack.mitre.org/software/S0232) can perform credential dumping.(Citation: FireEye Periscope March 2018)
- [G0039] Suckfly: [Suckfly](https://attack.mitre.org/groups/G0039) used a signed credential-dumping tool to obtain victim account credentials.(Citation: Symantec Suckfly May 2016)
- [G1043] BlackByte: [BlackByte](https://attack.mitre.org/groups/G1043) used tools such as [Cobalt Strike](https://attack.mitre.org/software/S0154) and [Mimikatz](https://attack.mitre.org/software/S0002) to dump credentials from victim systems.(Citation: Picus BlackByte 2022)(Citation: Microsoft BlackByte 2023)
- [S0094] Trojan.Karagany: [Trojan.Karagany](https://attack.mitre.org/software/S0094) can dump passwords and save them into <code>\ProgramData\Mail\MailAg\pwds.txt</code>.(Citation: Symantec Dragonfly)
- [G0007] APT28: [APT28](https://attack.mitre.org/groups/G0007) regularly deploys both publicly available (ex: [Mimikatz](https://attack.mitre.org/software/S0002)) and custom password retrieval tools on victims.(Citation: ESET Sednit Part 2)(Citation: DOJ GRU Indictment Jul 2018)(Citation: US District Court Indictment GRU Oct 2018)
- [G0054] Sowbug: [Sowbug](https://attack.mitre.org/groups/G0054) has used credential dumping tools.(Citation: Symantec Sowbug Nov 2017)
- [G0001] Axiom: [Axiom](https://attack.mitre.org/groups/G0001) has been known to dump credentials.(Citation: Novetta-Axiom)
- [G0065] Leviathan: [Leviathan](https://attack.mitre.org/groups/G0065) has used publicly available tools to dump password hashes, including [HOMEFRY](https://attack.mitre.org/software/S0232).(Citation: FireEye APT40 March 2019)

#### T1003.001 - OS Credential Dumping: LSASS Memory

Description:

Adversaries may attempt to access credential material stored in the process memory of the Local Security Authority Subsystem Service (LSASS). After a user logs on, the system generates and stores a variety of credential materials in LSASS process memory. These credential materials can be harvested by an administrative user or SYSTEM and used to conduct [Lateral Movement](https://attack.mitre.org/tactics/TA0008) using [Use Alternate Authentication Material](https://attack.mitre.org/techniques/T1550).

As well as in-memory techniques, the LSASS process memory can be dumped from the target host and analyzed on a local system.

For example, on the target host use procdump:

* <code>procdump -ma lsass.exe lsass_dump</code>

Locally, mimikatz can be run using:

* <code>sekurlsa::Minidump lsassdump.dmp</code>
* <code>sekurlsa::logonPasswords</code>

Built-in Windows tools such as `comsvcs.dll` can also be used:

* <code>rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump PID  lsass.dmp full</code>(Citation: Volexity Exchange Marauder March 2021)(Citation: Symantec Attacks Against Government Sector)

Similar to [Image File Execution Options Injection](https://attack.mitre.org/techniques/T1546/012), the silent process exit mechanism can be abused to create a memory dump of `lsass.exe` through Windows Error Reporting (`WerFault.exe`).(Citation: Deep Instinct LSASS)

Windows Security Support Provider (SSP) DLLs are loaded into LSASS process at system start. Once loaded into the LSA, SSP DLLs have access to encrypted and plaintext passwords that are stored in Windows, such as any logged-on user's Domain password or smart card PINs. The SSP configuration is stored in two Registry keys: <code>HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages</code> and <code>HKLM\SYSTEM\CurrentControlSet\Control\Lsa\OSConfig\Security Packages</code>. An adversary may modify these Registry keys to add new SSPs, which will be loaded the next time the system boots, or when the AddSecurityPackage Windows API function is called.(Citation: Graeber 2014)

The following SSPs can be used to access credentials:

* Msv: Interactive logons, batch logons, and service logons are done through the MSV authentication package.
* Wdigest: The Digest Authentication protocol is designed for use with Hypertext Transfer Protocol (HTTP) and Simple Authentication Security Layer (SASL) exchanges.(Citation: TechNet Blogs Credential Protection)
* Kerberos: Preferred for mutual client-server domain authentication in Windows 2000 and later.
* CredSSP:  Provides SSO and Network Level Authentication for Remote Desktop Services.(Citation: TechNet Blogs Credential Protection)

Procedures:

- [G0119] Indrik Spider: [Indrik Spider](https://attack.mitre.org/groups/G0119) used [Cobalt Strike](https://attack.mitre.org/software/S0154) to carry out credential dumping using ProcDump.(Citation: Symantec WastedLocker June 2020)
- [C0014] Operation Wocao: During [Operation Wocao](https://attack.mitre.org/campaigns/C0014), threat actors used ProcDump to dump credentials from memory.(Citation: FoxIT Wocao December 2019)
- [G0049] OilRig: [OilRig](https://attack.mitre.org/groups/G0049) has used credential dumping tools such as [Mimikatz](https://attack.mitre.org/software/S0002) to steal credentials to accounts logged into the compromised system and to Outlook Web Access.(Citation: Unit42 OilRig Playbook 2023)(Citation: FireEye APT34 Webinar Dec 2017)(Citation: FireEye APT35 2018)(Citation: FireEye APT34 July 2019)
- [G0003] Cleaver: [Cleaver](https://attack.mitre.org/groups/G0003) has been known to dump credentials using Mimikatz and Windows Credential Editor.(Citation: Cylance Cleaver)
- [G0077] Leafminer: [Leafminer](https://attack.mitre.org/groups/G0077) used several tools for retrieving login and password information, including LaZagne and Mimikatz.(Citation: Symantec Leafminer July 2018)
- [G0027] Threat Group-3390: [Threat Group-3390](https://attack.mitre.org/groups/G0027) actors have used a modified version of [Mimikatz](https://attack.mitre.org/software/S0002) called Wrapikatz to dump credentials. They have also dumped credentials from domain controllers.(Citation: Dell TG-3390)(Citation: SecureWorks BRONZE UNION June 2017)
- [S0692] SILENTTRINITY: [SILENTTRINITY](https://attack.mitre.org/software/S0692) can create a memory dump of LSASS via the `MiniDumpWriteDump Win32` API call.(Citation: GitHub SILENTTRINITY Modules July 2019)
- [G0006] APT1: [APT1](https://attack.mitre.org/groups/G0006) has been known to use credential dumping using [Mimikatz](https://attack.mitre.org/software/S0002).(Citation: Mandiant APT1)
- [C0029] Cutting Edge: During [Cutting Edge](https://attack.mitre.org/campaigns/C0029), threat actors used Task Manager to dump LSASS memory from Windows devices to disk.(Citation: Volexity Ivanti Zero-Day Exploitation January 2024)
- [G0065] Leviathan: [Leviathan](https://attack.mitre.org/groups/G0065) has used publicly available tools to dump password hashes, including ProcDump and WCE.(Citation: FireEye APT40 March 2019)
- [G0061] FIN8: [FIN8](https://attack.mitre.org/groups/G0061) harvests credentials using Invoke-Mimikatz or Windows Credentials Editor (WCE).(Citation: FireEye Know Your Enemy FIN8 Aug 2016)
- [S0349] LaZagne: [LaZagne](https://attack.mitre.org/software/S0349) can perform credential dumping from memory to obtain account and password information.(Citation: GitHub LaZagne Dec 2018)
- [G0125] HAFNIUM: [HAFNIUM](https://attack.mitre.org/groups/G0125) has used <code>procdump</code> to dump the LSASS process memory.(Citation: Microsoft HAFNIUM March 2020)(Citation: Volexity Exchange Marauder March 2021)(Citation: Rapid7 HAFNIUM Mar 2021)
- [G0108] Blue Mockingbird: [Blue Mockingbird](https://attack.mitre.org/groups/G0108) has used Mimikatz to retrieve credentials from LSASS memory.(Citation: RedCanary Mockingbird May 2020)
- [S0121] Lslsass: [Lslsass](https://attack.mitre.org/software/S0121) can dump active logon session password hashes from the lsass process.(Citation: Mandiant APT1)
- [S0681] Lizar: [Lizar](https://attack.mitre.org/software/S0681) can run [Mimikatz](https://attack.mitre.org/software/S0002) to harvest credentials.(Citation: Threatpost Lizar May 2021)(Citation: BiZone Lizar May 2021)
- [G1017] Volt Typhoon: [Volt Typhoon](https://attack.mitre.org/groups/G1017) has attempted to access hashed credentials from the LSASS process memory space.(Citation: Microsoft Volt Typhoon May 2023)(Citation: CISA AA24-038A PRC Critical Infrastructure February 2024)
- [G0107] Whitefly: [Whitefly](https://attack.mitre.org/groups/G0107) has used [Mimikatz](https://attack.mitre.org/software/S0002) to obtain credentials.(Citation: Symantec Whitefly March 2019)
- [G0064] APT33: [APT33](https://attack.mitre.org/groups/G0064) has used a variety of publicly available tools like [LaZagne](https://attack.mitre.org/software/S0349), [Mimikatz](https://attack.mitre.org/software/S0002), and ProcDump to dump credentials.(Citation: Symantec Elfin Mar 2019)(Citation: FireEye APT33 Guardrail)
- [G1016] FIN13: [FIN13](https://attack.mitre.org/groups/G1016) has obtained memory dumps with ProcDump to parse and extract credentials from a victim's LSASS process memory with [Mimikatz](https://attack.mitre.org/software/S0002).(Citation: Mandiant FIN13 Aug 2022)(Citation: Sygnia Elephant Beetle Jan 2022)
- [S0606] Bad Rabbit: [Bad Rabbit](https://attack.mitre.org/software/S0606) has used [Mimikatz](https://attack.mitre.org/software/S0002) to harvest credentials from the victim's machine.(Citation: ESET Bad Rabbit)
- [G0050] APT32: [APT32](https://attack.mitre.org/groups/G0050) used Mimikatz and customized versions of Windows Credential Dumper to harvest credentials.(Citation: Cybereason Oceanlotus May 2017)(Citation: Cybereason Cobalt Kitty 2017)
- [G1030] Agrius: [Agrius](https://attack.mitre.org/groups/G1030) used tools such as [Mimikatz](https://attack.mitre.org/software/S0002) to dump LSASS memory to capture credentials in victim environments.(Citation: Unit42 Agrius 2023)
- [S0046] CozyCar: [CozyCar](https://attack.mitre.org/software/S0046) has executed [Mimikatz](https://attack.mitre.org/software/S0002) to harvest stored credentials from the victim and further victim penetration.(Citation: F-Secure CozyDuke)
- [S0357] Impacket: SecretsDump and [Mimikatz](https://attack.mitre.org/software/S0002) modules within [Impacket](https://attack.mitre.org/software/S0357) can perform credential dumping to obtain account and password information.(Citation: Impacket Tools)
- [G0093] GALLIUM: [GALLIUM](https://attack.mitre.org/groups/G0093) used a modified version of [Mimikatz](https://attack.mitre.org/software/S0002) along with a PowerShell-based [Mimikatz](https://attack.mitre.org/software/S0002) to dump credentials on the victim machines.(Citation: Cybereason Soft Cell June 2019)(Citation: Microsoft GALLIUM December 2019)
- [S0368] NotPetya: [NotPetya](https://attack.mitre.org/software/S0368) contains a modified version of [Mimikatz](https://attack.mitre.org/software/S0002) to help gather credentials that are later used for lateral movement.(Citation: Talos Nyetya June 2017)(Citation: US-CERT NotPetya 2017)(Citation: NCSC Joint Report Public Tools)
- [S0192] Pupy: [Pupy](https://attack.mitre.org/software/S0192) can execute Lazagne as well as [Mimikatz](https://attack.mitre.org/software/S0002) using PowerShell.(Citation: GitHub Pupy)
- [G1023] APT5: [APT5](https://attack.mitre.org/groups/G1023) has used the Task Manager process to target LSASS process memory in order to obtain NTLM password hashes. [APT5](https://attack.mitre.org/groups/G1023) has also dumped clear text passwords and hashes from memory using [Mimikatz](https://attack.mitre.org/software/S0002) hosted through an RDP mapped drive.(Citation: Mandiant Pulse Secure Update May 2021)
- [S0154] Cobalt Strike: [Cobalt Strike](https://attack.mitre.org/software/S0154) can spawn a job to inject into LSASS memory and dump password hashes.(Citation: Cobalt Strike Manual 4.3 November 2020)
- [S0378] PoshC2: [PoshC2](https://attack.mitre.org/software/S0378) contains an implementation of [Mimikatz](https://attack.mitre.org/software/S0002) to gather credentials from memory.(Citation: GitHub PoshC2)
- [G0060] BRONZE BUTLER: [BRONZE BUTLER](https://attack.mitre.org/groups/G0060) has used various tools (such as Mimikatz and WCE) to perform credential dumping.(Citation: Secureworks BRONZE BUTLER Oct 2017)
- [S0005] Windows Credential Editor: [Windows Credential Editor](https://attack.mitre.org/software/S0005) can dump credentials.(Citation: Amplia WCE)
- [G0087] APT39: [APT39](https://attack.mitre.org/groups/G0087) has used Mimikatz, Windows Credential Editor and ProcDump to dump credentials.(Citation: FireEye APT39 Jan 2019)
- [C0030] Triton Safety Instrumented System Attack: In the [Triton Safety Instrumented System Attack](https://attack.mitre.org/campaigns/C0030), [TEMP.Veles](https://attack.mitre.org/groups/G0088) used Mimikatz.(Citation: FireEye TRITON 2018)
- [G0059] Magic Hound: [Magic Hound](https://attack.mitre.org/groups/G0059) has stolen domain credentials by dumping LSASS process memory using Task Manager, comsvcs.dll, and from a Microsoft Active Directory Domain Controller using [Mimikatz](https://attack.mitre.org/software/S0002).(Citation: FireEye APT35 2018)(Citation: DFIR Report APT35 ProxyShell March 2022)(Citation: DFIR Phosphorus November 2021)(Citation: Microsoft Iranian Threat Actor Trends November 2021)
- [G1006] Earth Lusca: [Earth Lusca](https://attack.mitre.org/groups/G1006) has used ProcDump to obtain the hashes of credentials by dumping the memory of the LSASS process.(Citation: TrendMicro EarthLusca 2022)
- [S0428] PoetRAT: [PoetRAT](https://attack.mitre.org/software/S0428) used voStro.exe, a compiled pypykatz (Python version of [Mimikatz](https://attack.mitre.org/software/S0002)), to steal credentials.(Citation: Talos PoetRAT April 2020)
- [C0038] HomeLand Justice: During [HomeLand Justice](https://attack.mitre.org/campaigns/C0038), threat actors dumped LSASS memory on compromised hosts.(Citation: CISA Iran Albanian Attacks September 2022)
- [S0367] Emotet: [Emotet](https://attack.mitre.org/software/S0367) has been observed dropping and executing password grabber modules including [Mimikatz](https://attack.mitre.org/software/S0002).(Citation: Trend Micro Emotet Jan 2019)(Citation: emotet_hc3_nov2023)
- [G0068] PLATINUM: [PLATINUM](https://attack.mitre.org/groups/G0068) has used keyloggers that are also capable of dumping credentials.(Citation: Microsoft PLATINUM April 2016)
- [G0117] Fox Kitten: [Fox Kitten](https://attack.mitre.org/groups/G0117) has used prodump to dump credentials from LSASS.(Citation: CISA AA20-259A Iran-Based Actor September 2020)
- [S0056] Net Crawler: [Net Crawler](https://attack.mitre.org/software/S0056) uses credential dumpers such as [Mimikatz](https://attack.mitre.org/software/S0002) and [Windows Credential Editor](https://attack.mitre.org/software/S0005) to extract cached credentials from Windows systems.(Citation: Cylance Cleaver)
- [G0091] Silence: [Silence](https://attack.mitre.org/groups/G0091) has used the Farse6.1 utility (based on [Mimikatz](https://attack.mitre.org/software/S0002)) to extract credentials from lsass.exe.(Citation: Group IB Silence Sept 2018)
- [C0025] 2016 Ukraine Electric Power Attack: During the [2016 Ukraine Electric Power Attack](https://attack.mitre.org/campaigns/C0025), [Sandworm Team](https://attack.mitre.org/groups/G0034) used [Mimikatz](https://attack.mitre.org/software/S0002) to capture and use legitimate credentials.(Citation: Dragos Crashoverride 2018)
- [S0583] Pysa: [Pysa](https://attack.mitre.org/software/S0583) can perform OS credential dumping using [Mimikatz](https://attack.mitre.org/software/S0002).(Citation: CERT-FR PYSA April 2020)
- [S0002] Mimikatz: [Mimikatz](https://attack.mitre.org/software/S0002) performs credential dumping to obtain account and password information useful in gaining access to additional systems and enterprise network resources. It contains functionality to acquire information about credentials in many ways, including from the LSASS Memory.(Citation: Deply Mimikatz)(Citation: GitHub Mimikatz lsadump Module)(Citation: Directory Services Internals DPAPI Backup Keys Oct 2015)(Citation: NCSC Joint Report Public Tools)
- [G0034] Sandworm Team: [Sandworm Team](https://attack.mitre.org/groups/G0034) has used its plainpwd tool, a modified version of [Mimikatz](https://attack.mitre.org/software/S0002), and comsvcs.dll to dump Windows credentials from system memory.(Citation: ESET Telebots Dec 2016)(Citation: ESET Telebots June 2017)(Citation: Microsoft Prestige ransomware October 2022)
- [G1036] Moonstone Sleet: [Moonstone Sleet](https://attack.mitre.org/groups/G1036) retrieved credentials from LSASS memory.(Citation: Microsoft Moonstone Sleet 2024)
- [G0069] MuddyWater: [MuddyWater](https://attack.mitre.org/groups/G0069) has performed credential dumping with [Mimikatz](https://attack.mitre.org/software/S0002) and procdump64.exe.(Citation: Unit 42 MuddyWater Nov 2017)(Citation: Symantec MuddyWater Dec 2018)(Citation: Trend Micro Muddy Water March 2021)
- [G0102] Wizard Spider: [Wizard Spider](https://attack.mitre.org/groups/G0102) has dumped the lsass.exe memory to harvest credentials with the use of open-source tool [LaZagne](https://attack.mitre.org/software/S0349).(Citation: Mandiant FIN12 Oct 2021)
- [G0143] Aquatic Panda: [Aquatic Panda](https://attack.mitre.org/groups/G0143) has attempted to harvest credentials through LSASS memory dumping.(Citation: CrowdStrike AQUATIC PANDA December 2021)
- [G0004] Ke3chang: [Ke3chang](https://attack.mitre.org/groups/G0004) has dumped credentials, including by using [Mimikatz](https://attack.mitre.org/software/S0002).(Citation: Mandiant Operation Ke3chang November 2014)(Citation: NCC Group APT15 Alive and Strong)(Citation: Microsoft NICKEL December 2021)
- [G0022] APT3: [APT3](https://attack.mitre.org/groups/G0022) has used a tool to dump credentials by injecting itself into lsass.exe and triggering with the argument "dig."(Citation: Symantec Buckeye)
- [G0096] APT41: [APT41](https://attack.mitre.org/groups/G0096) has used hashdump, [Mimikatz](https://attack.mitre.org/software/S0002), Procdump, and the Windows Credential Editor to dump password hashes from memory and authenticate to other user accounts.(Citation: FireEye APT41 Aug 2019)(Citation: Group IB APT 41 June 2021)(Citation: apt41_dcsocytec_dec2022)
- [S0363] Empire: [Empire](https://attack.mitre.org/software/S0363) contains an implementation of [Mimikatz](https://attack.mitre.org/software/S0002) to gather credentials from memory.(Citation: Github PowerShell Empire)
- [S0187] Daserf: [Daserf](https://attack.mitre.org/software/S0187) leverages [Mimikatz](https://attack.mitre.org/software/S0002) and [Windows Credential Editor](https://attack.mitre.org/software/S0005) to steal credentials.(Citation: Symantec Tick Apr 2016)
- [G0037] FIN6: [FIN6](https://attack.mitre.org/groups/G0037) has used [Windows Credential Editor](https://attack.mitre.org/software/S0005) for credential dumping.(Citation: FireEye FIN6 April 2016)(Citation: FireEye FIN6 Apr 2019)
- [G1003] Ember Bear: [Ember Bear](https://attack.mitre.org/groups/G1003) uses legitimate Sysinternals tools such as procdump to dump LSASS memory.(Citation: Cadet Blizzard emerges as novel threat actor)(Citation: CISA GRU29155 2024)
- [S1060] Mafalda: [Mafalda](https://attack.mitre.org/software/S1060) can dump password hashes from `LSASS.exe`.(Citation: SentinelLabs Metador Technical Appendix Sept 2022)
- [G0007] APT28: [APT28](https://attack.mitre.org/groups/G0007) regularly deploys both publicly available (ex: [Mimikatz](https://attack.mitre.org/software/S0002)) and custom password retrieval tools on victims.(Citation: ESET Sednit Part 2)(Citation: DOJ GRU Indictment Jul 2018) They have also dumped the LSASS process memory using the MiniDump function.(Citation: Cybersecurity Advisory GRU Brute Force Campaign July 2021)
- [S0633] Sliver: [Sliver](https://attack.mitre.org/software/S0633) has a built-in `procdump` command allowing for retrieval of memory from processes such as `lsass.exe` for credential harvesting.(Citation: Cybereason Sliver Undated)
- [S0365] Olympic Destroyer: [Olympic Destroyer](https://attack.mitre.org/software/S0365) contains a module that tries to obtain credentials from LSASS, similar to [Mimikatz](https://attack.mitre.org/software/S0002). These credentials are used with [PsExec](https://attack.mitre.org/software/S0029) and [Windows Management Instrumentation](https://attack.mitre.org/techniques/T1047) to help the malware propagate itself across a network.(Citation: Talos Olympic Destroyer 2018)
- [G0094] Kimsuky: [Kimsuky](https://attack.mitre.org/groups/G0094) has gathered credentials using [Mimikatz](https://attack.mitre.org/software/S0002) and ProcDump.(Citation: CISA AA20-301A Kimsuky)(Citation: Netscout Stolen Pencil Dec 2018)(Citation: KISA Operation Muzabi)
- [G1040] Play: [Play](https://attack.mitre.org/groups/G1040) has used [Mimikatz](https://attack.mitre.org/software/S0002) and the Windows Task Manager to dump LSASS process memory.(Citation: Trend Micro Ransomware Spotlight Play July 2023)
- [G1039] RedCurl: [RedCurl](https://attack.mitre.org/groups/G1039) used [LaZagne](https://attack.mitre.org/software/S0349) to obtain passwords from memory.(Citation: group-ib_redcurl1)(Citation: group-ib_redcurl2)
- [S0439] Okrum: [Okrum](https://attack.mitre.org/software/S0439) was seen using MimikatzLite to perform credential dumping.(Citation: ESET Okrum July 2019)
- [S0194] PowerSploit: [PowerSploit](https://attack.mitre.org/software/S0194) contains a collection of Exfiltration modules that can harvest credentials using [Mimikatz](https://attack.mitre.org/software/S0002).(Citation: GitHub PowerSploit May 2012)(Citation: PowerSploit Documentation)
- [C0032] C0032: During the [C0032](https://attack.mitre.org/campaigns/C0032) campaign, [TEMP.Veles](https://attack.mitre.org/groups/G0088) used Mimikatz and a custom tool, SecHack, to harvest credentials.(Citation: FireEye TRITON 2019)
- [S0342] GreyEnergy: [GreyEnergy](https://attack.mitre.org/software/S0342) has a module for [Mimikatz](https://attack.mitre.org/software/S0002) to collect Windows credentials from the victim’s machine.(Citation: ESET GreyEnergy Oct 2018)

#### T1003.002 - OS Credential Dumping: Security Account Manager

Description:

Adversaries may attempt to extract credential material from the Security Account Manager (SAM) database either through in-memory techniques or through the Windows Registry where the SAM database is stored. The SAM is a database file that contains local accounts for the host, typically those found with the <code>net user</code> command. Enumerating the SAM database requires SYSTEM level access.

A number of tools can be used to retrieve the SAM file through in-memory techniques:

* pwdumpx.exe
* [gsecdump](https://attack.mitre.org/software/S0008)
* [Mimikatz](https://attack.mitre.org/software/S0002)
* secretsdump.py

Alternatively, the SAM can be extracted from the Registry with Reg:

* <code>reg save HKLM\sam sam</code>
* <code>reg save HKLM\system system</code>

Creddump7 can then be used to process the SAM database locally to retrieve hashes.(Citation: GitHub Creddump7)

Notes: 

* RID 500 account is the local, built-in administrator.
* RID 501 is the guest account.
* User accounts start with a RID of 1,000+.

Procedures:

- [G1034] Daggerfly: [Daggerfly](https://attack.mitre.org/groups/G1034) used [Reg](https://attack.mitre.org/software/S0075) to dump the Security Account Manager (SAM) hive from victim machines for follow-on credential extraction.(Citation: Symantec Daggerfly 2023)
- [S0488] CrackMapExec: [CrackMapExec](https://attack.mitre.org/software/S0488) can dump usernames and hashed passwords from the SAM.(Citation: CME Github September 2018)
- [S0008] gsecdump: [gsecdump](https://attack.mitre.org/software/S0008) can dump Windows password hashes from the SAM.(Citation: Microsoft Gsecdump)
- [G0093] GALLIUM: [GALLIUM](https://attack.mitre.org/groups/G0093) used <code>reg</code> commands to dump specific hives from the Windows Registry, such as the SAM hive, and obtain password hashes.(Citation: Cybereason Soft Cell June 2019)
- [C0041] FrostyGoop Incident: During [FrostyGoop Incident](https://attack.mitre.org/campaigns/C0041), the adversary retrieved the contents of the Security Account Manager (SAM) hive in the victim environment for credential capture.(Citation: Dragos FROSTYGOOP 2024)
- [G0016] APT29: [APT29](https://attack.mitre.org/groups/G0016) has used the `reg save` command to save registry hives.(Citation: Mandiant APT29 Eye Spy Email Nov 22)
- [S0250] Koadic: [Koadic](https://attack.mitre.org/software/S0250) can gather hashed passwords by dumping SAM/SECURITY hive.(Citation: Github Koadic)
- [G1016] FIN13: [FIN13](https://attack.mitre.org/groups/G1016) has extracted the SAM and SYSTEM registry hives using the `reg.exe` binary for obtaining password hashes from a compromised machine.(Citation: Sygnia Elephant Beetle Jan 2022)
- [C0017] C0017: During [C0017](https://attack.mitre.org/campaigns/C0017), [APT41](https://attack.mitre.org/groups/G0096) copied the `SAM` and `SYSTEM` Registry hives for credential harvesting.(Citation: Mandiant APT41)
- [S0006] pwdump: [pwdump](https://attack.mitre.org/software/S0006) can be used to dump credentials from the SAM.(Citation: Wikipedia pwdump)
- [G0035] Dragonfly: [Dragonfly](https://attack.mitre.org/groups/G0035) has dropped and executed SecretsDump to dump password hashes.(Citation: US-CERT TA18-074A)
- [G0004] Ke3chang: [Ke3chang](https://attack.mitre.org/groups/G0004) has dumped credentials, including by using gsecdump.(Citation: Mandiant Operation Ke3chang November 2014)(Citation: NCC Group APT15 Alive and Strong)
- [S0376] HOPLIGHT: [HOPLIGHT](https://attack.mitre.org/software/S0376) has the capability to harvest credentials and passwords from the SAM database.(Citation: US-CERT HOPLIGHT Apr 2019)
- [G1030] Agrius: [Agrius](https://attack.mitre.org/groups/G1030) dumped the SAM file on victim machines to capture credentials.(Citation: Unit42 Agrius 2023)
- [C0002] Night Dragon: During [Night Dragon](https://attack.mitre.org/campaigns/C0002), threat actors dumped account hashes using [gsecdump](https://attack.mitre.org/software/S0008).(Citation: McAfee Night Dragon)
- [S0002] Mimikatz: [Mimikatz](https://attack.mitre.org/software/S0002) performs credential dumping to obtain account and password information useful in gaining access to additional systems and enterprise network resources. It contains functionality to acquire information about credentials in many ways, including from the SAM table.(Citation: Deply Mimikatz)(Citation: GitHub Mimikatz lsadump Module)(Citation: Directory Services Internals DPAPI Backup Keys Oct 2015)(Citation: NCSC Joint Report Public Tools)
- [G0096] APT41: [APT41](https://attack.mitre.org/groups/G0096) extracted user account data from the Security Account Managerr (SAM), making a copy of this database from the registry using the <code>reg save</code> command or by exploiting volume shadow copies.(Citation: Rostovcev APT41 2021)
- [S0125] Remsec: [Remsec](https://attack.mitre.org/software/S0125) can dump the SAM database.(Citation: Kaspersky ProjectSauron Technical Analysis)
- [G1023] APT5: [APT5](https://attack.mitre.org/groups/G1023) has copied and exfiltrated the SAM Registry hive from targeted systems.(Citation: Mandiant Pulse Secure Update May 2021)
- [G0045] menuPass: [menuPass](https://attack.mitre.org/groups/G0045) has used a modified version of pentesting tools wmiexec.vbs and secretsdump.py to dump credentials.(Citation: PWC Cloud Hopper Technical Annex April 2017)(Citation: Github AD-Pentest-Script)
- [S0046] CozyCar: Password stealer and NTLM stealer modules in [CozyCar](https://attack.mitre.org/software/S0046) harvest stored credentials from the victim, including credentials used as part of Windows NTLM user authentication.(Citation: F-Secure CozyDuke)
- [G0027] Threat Group-3390: [Threat Group-3390](https://attack.mitre.org/groups/G0027) actors have used [gsecdump](https://attack.mitre.org/software/S0008) to dump credentials. They have also dumped credentials from domain controllers.(Citation: Dell TG-3390)(Citation: SecureWorks BRONZE UNION June 2017)
- [C0051] APT28 Nearest Neighbor Campaign: During [APT28 Nearest Neighbor Campaign](https://attack.mitre.org/campaigns/C0051), [APT28](https://attack.mitre.org/groups/G0007) used the following commands to dump SAM, SYSTEM, and SECURITY hives: <code>reg save hklm\sam, reg save hklm\system,</code> and <code>reg save hklm\security</code>.(Citation: Nearest Neighbor Volexity)
- [S0080] Mivast: [Mivast](https://attack.mitre.org/software/S0080) has the capability to gather NTLM password information.(Citation: Symantec Backdoor.Mivast)
- [S0357] Impacket: SecretsDump and [Mimikatz](https://attack.mitre.org/software/S0002) modules within [Impacket](https://attack.mitre.org/software/S0357) can perform credential dumping to obtain account and password information.(Citation: Impacket Tools)
- [C0012] Operation CuckooBees: During [Operation CuckooBees](https://attack.mitre.org/campaigns/C0012), the threat actors leveraged a custom tool to dump OS credentials and used following commands: `reg save HKLM\\SYSTEM system.hiv`, `reg save HKLM\\SAM sam.hiv`, and `reg save HKLM\\SECURITY security.hiv`, to dump SAM, SYSTEM and SECURITY hives.(Citation: Cybereason OperationCuckooBees May 2022)
- [S0371] POWERTON: [POWERTON](https://attack.mitre.org/software/S0371) has the ability to dump password hashes.(Citation: FireEye APT33 Guardrail)
- [G0102] Wizard Spider: [Wizard Spider](https://attack.mitre.org/groups/G0102) has acquired credentials from the SAM/SECURITY registry hives.(Citation: FireEye KEGTAP SINGLEMALT October 2020)
- [S0050] CosmicDuke: [CosmicDuke](https://attack.mitre.org/software/S0050) collects Windows account hashes.(Citation: F-Secure The Dukes)
- [S0154] Cobalt Strike: [Cobalt Strike](https://attack.mitre.org/software/S0154) can recover hashed passwords.(Citation: cobaltstrike manual)
- [S1022] IceApple: [IceApple](https://attack.mitre.org/software/S1022)'s Credential Dumper module can dump encrypted password hashes from SAM registry keys, including `HKLM\SAM\SAM\Domains\Account\F` and `HKLM\SAM\SAM\Domains\Account\Users\*\V`.(Citation: CrowdStrike IceApple May 2022)
- [G1003] Ember Bear: [Ember Bear](https://attack.mitre.org/groups/G1003) acquires victim credentials by extracting registry hives such as the Security Account Manager through commands such as <code>reg save</code>.(Citation: Cadet Blizzard emerges as novel threat actor)(Citation: CISA GRU29155 2024)
- [S0120] Fgdump: [Fgdump](https://attack.mitre.org/software/S0120) can dump Windows password hashes.(Citation: Mandiant APT1)

#### T1003.003 - OS Credential Dumping: NTDS

Description:

Adversaries may attempt to access or create a copy of the Active Directory domain database in order to steal credential information, as well as obtain other information about domain members such as devices, users, and access rights. By default, the NTDS file (NTDS.dit) is located in <code>%SystemRoot%\NTDS\Ntds.dit</code> of a domain controller.(Citation: Wikipedia Active Directory)

In addition to looking for NTDS files on active Domain Controllers, adversaries may search for backups that contain the same or similar information.(Citation: Metcalf 2015)

The following tools and techniques can be used to enumerate the NTDS file and the contents of the entire Active Directory hashes.

* Volume Shadow Copy
* secretsdump.py
* Using the in-built Windows tool, ntdsutil.exe
* Invoke-NinjaCopy

Procedures:

- [G0007] APT28: [APT28](https://attack.mitre.org/groups/G0007) has used the ntdsutil.exe utility to export the Active Directory database for credential access.(Citation: Cybersecurity Advisory GRU Brute Force Campaign July 2021)
- [C0051] APT28 Nearest Neighbor Campaign: During [APT28 Nearest Neighbor Campaign](https://attack.mitre.org/campaigns/C0051), [APT28](https://attack.mitre.org/groups/G0007) dumped NTDS.dit through creating volume shadow copies via <code>vssadmin</code>.(Citation: Nearest Neighbor Volexity)
- [C0048] Operation MidnightEclipse: During [Operation MidnightEclipse](https://attack.mitre.org/campaigns/C0048), threat actors obtained active directory credentials via the NTDS.DIT file.(Citation: Volexity UPSTYLE 2024)
- [S0488] CrackMapExec: [CrackMapExec](https://attack.mitre.org/software/S0488) can dump hashed passwords associated with Active Directory using Windows' Directory Replication Services API (DRSUAPI), or Volume Shadow Copy.(Citation: CME Github September 2018)
- [G1015] Scattered Spider: [Scattered Spider](https://attack.mitre.org/groups/G1015) has extracted the `NTDS.dit` file by creating volume shadow copies of virtual domain controller disks.(Citation: MSTIC Octo Tempest Operations October 2023)
- [G0034] Sandworm Team: [Sandworm Team](https://attack.mitre.org/groups/G0034) has used `ntdsutil.exe` to back up the Active Directory database, likely for credential access.(Citation: Microsoft Prestige ransomware October 2022)
- [G1016] FIN13: [FIN13](https://attack.mitre.org/groups/G1016) has harvested the NTDS.DIT file and leveraged the [Impacket](https://attack.mitre.org/software/S0357) tool on the compromised domain controller to locally decrypt it.(Citation: Sygnia Elephant Beetle Jan 2022)
- [S0404] esentutl: [esentutl](https://attack.mitre.org/software/S0404) can copy `ntds.dit` using the Volume Shadow Copy service.(Citation: LOLBAS Esentutl)(Citation: Cary Esentutl)
- [G0037] FIN6: [FIN6](https://attack.mitre.org/groups/G0037) has used Metasploit’s [PsExec](https://attack.mitre.org/software/S0029) NTDSGRAB module to obtain a copy of the victim's Active Directory database.(Citation: FireEye FIN6 April 2016)(Citation: FireEye FIN6 Apr 2019)
- [G1017] Volt Typhoon: [Volt Typhoon](https://attack.mitre.org/groups/G1017) has used ntds.util to create domain controller installation media containing usernames and password hashes.(Citation: Microsoft Volt Typhoon May 2023)(Citation: Joint Cybersecurity Advisory Volt Typhoon June 2023)(Citation: Secureworks BRONZE SILHOUETTE May 2023)(Citation: CISA AA24-038A PRC Critical Infrastructure February 2024)
- [G0045] menuPass: [menuPass](https://attack.mitre.org/groups/G0045) has used Ntdsutil to dump credentials.(Citation: Symantec Cicada November 2020)
- [G0114] Chimera: [Chimera](https://attack.mitre.org/groups/G0114) has gathered the SYSTEM registry and ntds.dit files from target systems.(Citation: Cycraft Chimera April 2020) [Chimera](https://attack.mitre.org/groups/G0114) specifically has used the NtdsAudit tool to dump the password hashes of domain users via <code>msadcs.exe "NTDS.dit" -s "SYSTEM" -p RecordedTV_pdmp.txt --users-csv RecordedTV_users.csv</code> and used ntdsutil to copy the Active Directory database.(Citation: NCC Group Chimera January 2021)
- [S0357] Impacket: SecretsDump and [Mimikatz](https://attack.mitre.org/software/S0002) modules within [Impacket](https://attack.mitre.org/software/S0357) can perform credential dumping to obtain account and password information from NTDS.dit.(Citation: Impacket Tools)
- [G0117] Fox Kitten: [Fox Kitten](https://attack.mitre.org/groups/G0117) has used Volume Shadow Copy to access credential information from NTDS.(Citation: CISA AA20-259A Iran-Based Actor September 2020)
- [C0029] Cutting Edge: During [Cutting Edge](https://attack.mitre.org/campaigns/C0029), threat actors accessed and mounted virtual hard disk backups to extract 
ntds.dit.(Citation: Volexity Ivanti Zero-Day Exploitation January 2024)
- [G0102] Wizard Spider: [Wizard Spider](https://attack.mitre.org/groups/G0102) has gained access to credentials via exported copies of the ntds.dit Active Directory database. [Wizard Spider](https://attack.mitre.org/groups/G0102) has also created a volume shadow copy and used a batch script file to collect NTDS.dit with the use of the Windows utility, ntdsutil.(Citation: FireEye KEGTAP SINGLEMALT October 2020)(Citation: Mandiant FIN12 Oct 2021)
- [G0035] Dragonfly: [Dragonfly](https://attack.mitre.org/groups/G0035) has dropped and executed SecretsDump to dump password hashes. They also obtained ntds.dit from domain controllers.(Citation: US-CERT TA18-074A)(Citation: Core Security Impacket)
- [S0250] Koadic: [Koadic](https://attack.mitre.org/software/S0250) can gather hashed passwords by gathering domain controller hashes from NTDS.(Citation: Github Koadic)
- [G0096] APT41: [APT41](https://attack.mitre.org/groups/G0096) used ntdsutil to obtain a copy of the victim environment <code>ntds.dit</code> file.(Citation: Rostovcev APT41 2021)
- [G0129] Mustang Panda: [Mustang Panda](https://attack.mitre.org/groups/G0129) has used vssadmin to create a volume shadow copy and retrieve the NTDS.dit file. [Mustang Panda](https://attack.mitre.org/groups/G0129) has also used <code>reg save</code> on the SYSTEM file Registry location to help extract the NTDS.dit file.(Citation: Secureworks BRONZE PRESIDENT December 2019)
- [G0004] Ke3chang: [Ke3chang](https://attack.mitre.org/groups/G0004) has used NTDSDump and other password dumping tools to gather credentials.(Citation: Microsoft NICKEL December 2021)
- [G0125] HAFNIUM: [HAFNIUM](https://attack.mitre.org/groups/G0125) has stolen copies of the Active Directory database (NTDS.DIT).(Citation: Volexity Exchange Marauder March 2021)(Citation: Microsoft Silk Typhoon MAR 2025)
- [G1004] LAPSUS$: [LAPSUS$](https://attack.mitre.org/groups/G1004) has used Windows built-in tool `ntdsutil` to extract the Active Directory (AD) database.(Citation: MSTIC DEV-0537 Mar 2022)

#### T1003.004 - OS Credential Dumping: LSA Secrets

Description:

Adversaries with SYSTEM access to a host may attempt to access Local Security Authority (LSA) secrets, which can contain a variety of different credential materials, such as credentials for service accounts.(Citation: Passcape LSA Secrets)(Citation: Microsoft AD Admin Tier Model)(Citation: Tilbury Windows Credentials) LSA secrets are stored in the registry at <code>HKEY_LOCAL_MACHINE\SECURITY\Policy\Secrets</code>. LSA secrets can also be dumped from memory.(Citation: ired Dumping LSA Secrets)

[Reg](https://attack.mitre.org/software/S0075) can be used to extract from the Registry. [Mimikatz](https://attack.mitre.org/software/S0002) can be used to extract secrets from memory.(Citation: ired Dumping LSA Secrets)

Procedures:

- [G0069] MuddyWater: [MuddyWater](https://attack.mitre.org/groups/G0069) has performed credential dumping with [LaZagne](https://attack.mitre.org/software/S0349).(Citation: Unit 42 MuddyWater Nov 2017)(Citation: Symantec MuddyWater Dec 2018)
- [S1022] IceApple: [IceApple](https://attack.mitre.org/software/S1022)'s Credential Dumper module can dump LSA secrets from registry keys, including: `HKLM\SECURITY\Policy\PolEKList\default`, `HKLM\SECURITY\Policy\Secrets\*\CurrVal`, and `HKLM\SECURITY\Policy\Secrets\*\OldVal`.(Citation: CrowdStrike IceApple May 2022)
- [S0050] CosmicDuke: [CosmicDuke](https://attack.mitre.org/software/S0050) collects LSA secrets.(Citation: F-Secure The Dukes)
- [S0008] gsecdump: [gsecdump](https://attack.mitre.org/software/S0008) can dump LSA secrets.(Citation: TrueSec Gsecdump)
- [S0349] LaZagne: [LaZagne](https://attack.mitre.org/software/S0349) can perform credential dumping from LSA secrets to obtain account and password information.(Citation: GitHub LaZagne Dec 2018)
- [G0027] Threat Group-3390: [Threat Group-3390](https://attack.mitre.org/groups/G0027) actors have used [gsecdump](https://attack.mitre.org/software/S0008) to dump credentials. They have also dumped credentials from domain controllers.(Citation: Dell TG-3390)(Citation: SecureWorks BRONZE UNION June 2017)
- [G0049] OilRig: [OilRig](https://attack.mitre.org/groups/G0049) has used credential dumping tools such as [LaZagne](https://attack.mitre.org/software/S0349) to steal credentials to accounts logged into the compromised system and to Outlook Web Access.(Citation: Unit42 OilRig Playbook 2023)(Citation: FireEye APT34 Webinar Dec 2017)(Citation: FireEye APT35 2018)(Citation: FireEye APT34 July 2019)
- [S0488] CrackMapExec: [CrackMapExec](https://attack.mitre.org/software/S0488) can dump hashed passwords from LSA secrets for the targeted system.(Citation: CME Github September 2018)
- [G0077] Leafminer: [Leafminer](https://attack.mitre.org/groups/G0077) used several tools for retrieving login and password information, including LaZagne.(Citation: Symantec Leafminer July 2018)
- [G0064] APT33: [APT33](https://attack.mitre.org/groups/G0064) has used a variety of publicly available tools like [LaZagne](https://attack.mitre.org/software/S0349) to gather credentials.(Citation: Symantec Elfin Mar 2019)(Citation: FireEye APT33 Guardrail)
- [G0016] APT29: [APT29](https://attack.mitre.org/groups/G0016) has used the `reg save` command to extract LSA secrets offline.(Citation: Mandiant APT29 Eye Spy Email Nov 22)
- [G0045] menuPass: [menuPass](https://attack.mitre.org/groups/G0045) has used a modified version of pentesting tools wmiexec.vbs and secretsdump.py to dump credentials.(Citation: PWC Cloud Hopper Technical Annex April 2017)(Citation: Github AD-Pentest-Script)
- [G0035] Dragonfly: [Dragonfly](https://attack.mitre.org/groups/G0035) has dropped and executed SecretsDump to dump password hashes.(Citation: US-CERT TA18-074A)(Citation: Core Security Impacket)
- [S0677] AADInternals: [AADInternals](https://attack.mitre.org/software/S0677) can dump secrets from the Local Security Authority.(Citation: AADInternals Documentation)
- [S0357] Impacket: SecretsDump and [Mimikatz](https://attack.mitre.org/software/S0002) modules within [Impacket](https://attack.mitre.org/software/S0357) can perform credential dumping to obtain account and password information.(Citation: Impacket Tools)
- [S0192] Pupy: [Pupy](https://attack.mitre.org/software/S0192) can use Lazagne for harvesting credentials.(Citation: GitHub Pupy)
- [G1003] Ember Bear: [Ember Bear](https://attack.mitre.org/groups/G1003) has used frameworks such as [Impacket](https://attack.mitre.org/software/S0357) to dump LSA secrets for credential capture.(Citation: CISA GRU29155 2024)
- [G0004] Ke3chang: [Ke3chang](https://attack.mitre.org/groups/G0004) has dumped credentials, including by using gsecdump.(Citation: Mandiant Operation Ke3chang November 2014)(Citation: NCC Group APT15 Alive and Strong)
- [S0002] Mimikatz: [Mimikatz](https://attack.mitre.org/software/S0002) performs credential dumping to obtain account and password information useful in gaining access to additional systems and enterprise network resources. It contains functionality to acquire information about credentials in many ways, including from the LSA.(Citation: Deply Mimikatz)(Citation: GitHub Mimikatz lsadump Module)(Citation: Directory Services Internals DPAPI Backup Keys Oct 2015)(Citation: NCSC Joint Report Public Tools)

#### T1003.005 - OS Credential Dumping: Cached Domain Credentials

Description:

Adversaries may attempt to access cached domain credentials used to allow authentication to occur in the event a domain controller is unavailable.(Citation: Microsoft - Cached Creds)

On Windows Vista and newer, the hash format is DCC2 (Domain Cached Credentials version 2) hash, also known as MS-Cache v2 hash.(Citation: PassLib mscache) The number of default cached credentials varies and can be altered per system. This hash does not allow pass-the-hash style attacks, and instead requires [Password Cracking](https://attack.mitre.org/techniques/T1110/002) to recover the plaintext password.(Citation: ired mscache)

On Linux systems, Active Directory credentials can be accessed through caches maintained by software like System Security Services Daemon (SSSD) or Quest Authentication Services (formerly VAS). Cached credential hashes are typically located at `/var/lib/sss/db/cache.[domain].ldb` for SSSD or `/var/opt/quest/vas/authcache/vas_auth.vdb` for Quest. Adversaries can use utilities, such as `tdbdump`, on these database files to dump the cached hashes and use [Password Cracking](https://attack.mitre.org/techniques/T1110/002) to obtain the plaintext password.(Citation: Brining MimiKatz to Unix) 

With SYSTEM or sudo access, the tools/utilities such as [Mimikatz](https://attack.mitre.org/software/S0002), [Reg](https://attack.mitre.org/software/S0075), and secretsdump.py for Windows or Linikatz for Linux can be used to extract the cached credentials.(Citation: Brining MimiKatz to Unix)

Note: Cached credentials for Windows Vista are derived using PBKDF2.(Citation: PassLib mscache)

Procedures:

- [S0439] Okrum: [Okrum](https://attack.mitre.org/software/S0439) was seen using modified Quarks PwDump to perform credential dumping.(Citation: ESET Okrum July 2019)
- [G0064] APT33: [APT33](https://attack.mitre.org/groups/G0064) has used a variety of publicly available tools like [LaZagne](https://attack.mitre.org/software/S0349) to gather credentials.(Citation: Symantec Elfin Mar 2019)(Citation: FireEye APT33 Guardrail)
- [G0077] Leafminer: [Leafminer](https://attack.mitre.org/groups/G0077) used several tools for retrieving login and password information, including LaZagne.(Citation: Symantec Leafminer July 2018)
- [S0119] Cachedump: [Cachedump](https://attack.mitre.org/software/S0119) can extract cached password hashes from cache entry information.(Citation: Mandiant APT1)
- [S0349] LaZagne: [LaZagne](https://attack.mitre.org/software/S0349) can perform credential dumping from MSCache to obtain account and password information.(Citation: GitHub LaZagne Dec 2018)
- [G0049] OilRig: [OilRig](https://attack.mitre.org/groups/G0049) has used credential dumping tools such as [LaZagne](https://attack.mitre.org/software/S0349) to steal credentials to accounts logged into the compromised system and to Outlook Web Access.(Citation: Unit42 OilRig Playbook 2023)(Citation: FireEye APT34 Webinar Dec 2017)(Citation: FireEye APT35 2018)(Citation: FireEye APT34 July 2019)
- [S0192] Pupy: [Pupy](https://attack.mitre.org/software/S0192) can use Lazagne for harvesting credentials.(Citation: GitHub Pupy)
- [G0069] MuddyWater: [MuddyWater](https://attack.mitre.org/groups/G0069) has performed credential dumping with [LaZagne](https://attack.mitre.org/software/S0349).(Citation: Unit 42 MuddyWater Nov 2017)(Citation: Symantec MuddyWater Dec 2018)

#### T1003.006 - OS Credential Dumping: DCSync

Description:

Adversaries may attempt to access credentials and other sensitive information by abusing a Windows Domain Controller's application programming interface (API)(Citation: Microsoft DRSR Dec 2017) (Citation: Microsoft GetNCCChanges) (Citation: Samba DRSUAPI) (Citation: Wine API samlib.dll) to simulate the replication process from a remote domain controller using a technique called DCSync.

Members of the Administrators, Domain Admins, and Enterprise Admin groups or computer accounts on the domain controller are able to run DCSync to pull password data(Citation: ADSecurity Mimikatz DCSync) from Active Directory, which may include current and historical hashes of potentially useful accounts such as KRBTGT and Administrators. The hashes can then in turn be used to create a [Golden Ticket](https://attack.mitre.org/techniques/T1558/001) for use in [Pass the Ticket](https://attack.mitre.org/techniques/T1550/003)(Citation: Harmj0y Mimikatz and DCSync) or change an account's password as noted in [Account Manipulation](https://attack.mitre.org/techniques/T1098).(Citation: InsiderThreat ChangeNTLM July 2017)

DCSync functionality has been included in the "lsadump" module in [Mimikatz](https://attack.mitre.org/software/S0002).(Citation: GitHub Mimikatz lsadump Module) Lsadump also includes NetSync, which performs DCSync over a legacy replication protocol.(Citation: Microsoft NRPC Dec 2017)

Procedures:

- [S0002] Mimikatz: [Mimikatz](https://attack.mitre.org/software/S0002) performs credential dumping to obtain account and password information useful in gaining access to additional systems and enterprise network resources. It contains functionality to acquire information about credentials in many ways, including from DCSync/NetSync.(Citation: Deply Mimikatz)(Citation: GitHub Mimikatz lsadump Module)(Citation: Directory Services Internals DPAPI Backup Keys Oct 2015)(Citation: NCSC Joint Report Public Tools)(Citation: Cobalt Strike Manual 4.3 November 2020)
- [G1006] Earth Lusca: [Earth Lusca](https://attack.mitre.org/groups/G1006) has used a <code>DCSync</code> command with [Mimikatz](https://attack.mitre.org/software/S0002) to retrieve credentials from an exploited controller.(Citation: TrendMicro EarthLusca 2022)
- [C0027] C0027: During [C0027](https://attack.mitre.org/campaigns/C0027), [Scattered Spider](https://attack.mitre.org/groups/G1015) performed domain replication.(Citation: Crowdstrike TELCO BPO Campaign December 2022)
- [C0014] Operation Wocao: During [Operation Wocao](https://attack.mitre.org/campaigns/C0014), threat actors used [Mimikatz](https://attack.mitre.org/software/S0002)'s DCSync to dump credentials from the memory of the targeted system.(Citation: FoxIT Wocao December 2019)
- [G1004] LAPSUS$: [LAPSUS$](https://attack.mitre.org/groups/G1004) has used DCSync attacks to gather credentials for privilege escalation routines.(Citation: MSTIC DEV-0537 Mar 2022)
- [C0024] SolarWinds Compromise: During the [SolarWinds Compromise](https://attack.mitre.org/campaigns/C0024), [APT29](https://attack.mitre.org/groups/G0016) used privileged accounts to replicate directory service data with domain controllers.(Citation: Microsoft 365 Defender Solorigate)(Citation: Microsoft Deep Dive Solorigate January 2021)(Citation: CrowdStrike StellarParticle January 2022)

#### T1003.007 - OS Credential Dumping: Proc Filesystem

Description:

Adversaries may gather credentials from the proc filesystem or `/proc`. The proc filesystem is a pseudo-filesystem used as an interface to kernel data structures for Linux based systems managing virtual memory. For each process, the `/proc/<PID>/maps` file shows how memory is mapped within the process’s virtual address space. And `/proc/<PID>/mem`, exposed for debugging purposes, provides access to the process’s virtual address space.(Citation: Picus Labs Proc cump 2022)(Citation: baeldung Linux proc map 2022)

When executing with root privileges, adversaries can search these memory locations for all processes on a system that contain patterns indicative of credentials. Adversaries may use regex patterns, such as <code>grep -E "^[0-9a-f-]* r" /proc/"$pid"/maps | cut -d' ' -f 1</code>, to look for fixed strings in memory structures or cached hashes.(Citation: atomic-red proc file system) When running without privileged access, processes can still view their own virtual memory locations. Some services or programs may save credentials in clear text inside the process’s memory.(Citation: MimiPenguin GitHub May 2017)(Citation: Polop Linux PrivEsc Gitbook)

If running as or with the permissions of a web browser, a process can search the `/maps` & `/mem` locations for common website credential patterns (that can also be used to find adjacent memory within the same structure) in which hashes or cleartext credentials may be located.

Procedures:

- [S1109] PACEMAKER: [PACEMAKER](https://attack.mitre.org/software/S1109) has the ability to extract credentials from OS memory.(Citation: Mandiant Pulse Secure Zero-Day April 2021)
- [S0349] LaZagne: [LaZagne](https://attack.mitre.org/software/S0349) can use the `<PID>/maps` and `<PID>/mem` files to identify regex patterns to dump cleartext passwords from the browser's process memory.(Citation: GitHub LaZagne Dec 2018)(Citation: Picus Labs Proc cump 2022)
- [S0179] MimiPenguin: [MimiPenguin](https://attack.mitre.org/software/S0179) can use the `<PID>/maps` and `<PID>/mem` file to search for regex patterns and dump the process memory.(Citation: MimiPenguin GitHub May 2017)(Citation: Picus Labs Proc cump 2022)

#### T1003.008 - OS Credential Dumping: /etc/passwd and /etc/shadow

Description:

Adversaries may attempt to dump the contents of <code>/etc/passwd</code> and <code>/etc/shadow</code> to enable offline password cracking. Most modern Linux operating systems use a combination of <code>/etc/passwd</code> and <code>/etc/shadow</code> to store user account information, including password hashes in <code>/etc/shadow</code>. By default, <code>/etc/shadow</code> is only readable by the root user.(Citation: Linux Password and Shadow File Formats)

Linux stores user information such as user ID, group ID, home directory path, and login shell in <code>/etc/passwd</code>. A "user" on the system may belong to a person or a service. All password hashes are stored in <code>/etc/shadow</code> - including entries for users with no passwords and users with locked or disabled accounts.(Citation: Linux Password and Shadow File Formats)

Adversaries may attempt to read or dump the <code>/etc/passwd</code> and <code>/etc/shadow</code> files on Linux systems via command line utilities such as the <code>cat</code> command.(Citation: Arctic Wolf) Additionally, the Linux utility <code>unshadow</code> can be used to combine the two files in a format suited for password cracking utilities such as John the Ripper - for example, via the command <code>/usr/bin/unshadow /etc/passwd /etc/shadow > /tmp/crack.password.db</code>(Citation: nixCraft - John the Ripper). Since the user information stored in <code>/etc/passwd</code> are linked to the password hashes in <code>/etc/shadow</code>, an adversary would need to have access to both.

Procedures:

- [S0349] LaZagne: [LaZagne](https://attack.mitre.org/software/S0349) can obtain credential information from /etc/shadow using the shadow.py module.(Citation: GitHub LaZagne Dec 2018)
- [C0045] ShadowRay: During [ShadowRay](https://attack.mitre.org/campaigns/C0045), threat actors used `cat /etc/shadow` to steal password hashes.(Citation: Oligo ShadowRay Campaign MAR 2024)


### T1040 - Network Sniffing

Description:

Adversaries may passively sniff network traffic to capture information about an environment, including authentication material passed over the network. Network sniffing refers to using the network interface on a system to monitor or capture information sent over a wired or wireless connection. An adversary may place a network interface into promiscuous mode to passively access data in transit over the network, or use span ports to capture a larger amount of data.

Data captured via this technique may include user credentials, especially those sent over an insecure, unencrypted protocol. Techniques for name service resolution poisoning, such as [LLMNR/NBT-NS Poisoning and SMB Relay](https://attack.mitre.org/techniques/T1557/001), can also be used to capture credentials to websites, proxies, and internal systems by redirecting traffic to an adversary.

Network sniffing may reveal configuration details, such as running services, version numbers, and other network characteristics (e.g. IP addresses, hostnames, VLAN IDs) necessary for subsequent [Lateral Movement](https://attack.mitre.org/tactics/TA0008) and/or [Defense Evasion](https://attack.mitre.org/tactics/TA0005) activities. Adversaries may likely also utilize network sniffing during [Adversary-in-the-Middle](https://attack.mitre.org/techniques/T1557) (AiTM) to passively gain additional knowledge about the environment.

In cloud-based environments, adversaries may still be able to use traffic mirroring services to sniff network traffic from virtual machines. For example, AWS Traffic Mirroring, GCP Packet Mirroring, and Azure vTap allow users to define specified instances to collect traffic from and specified targets to send collected traffic to.(Citation: AWS Traffic Mirroring)(Citation: GCP Packet Mirroring)(Citation: Azure Virtual Network TAP) Often, much of this traffic will be in cleartext due to the use of TLS termination at the load balancer level to reduce the strain of encrypting and decrypting traffic.(Citation: Rhino Security Labs AWS VPC Traffic Mirroring)(Citation: SpecterOps AWS Traffic Mirroring) The adversary can then use exfiltration techniques such as Transfer Data to Cloud Account in order to access the sniffed traffic.(Citation: Rhino Security Labs AWS VPC Traffic Mirroring)

On network devices, adversaries may perform network captures using [Network Device CLI](https://attack.mitre.org/techniques/T1059/008) commands such as `monitor capture`.(Citation: US-CERT-TA18-106A)(Citation: capture_embedded_packet_on_software)

Procedures:

- [G0034] Sandworm Team: [Sandworm Team](https://attack.mitre.org/groups/G0034) has used intercepter-NG to sniff passwords in network traffic.(Citation: ESET Telebots Dec 2016)
- [G0094] Kimsuky: [Kimsuky](https://attack.mitre.org/groups/G0094) has used the Nirsoft SniffPass network sniffer to obtain passwords sent over non-secure protocols.(Citation: CISA AA20-301A Kimsuky)(Citation: Netscout Stolen Pencil Dec 2018)
- [S0357] Impacket: [Impacket](https://attack.mitre.org/software/S0357) can be used to sniff network traffic via an interface or raw socket.(Citation: Impacket Tools)
- [S0590] NBTscan: [NBTscan](https://attack.mitre.org/software/S0590) can dump and print whole packet content.(Citation: Debian nbtscan Nov 2019)(Citation: SecTools nbtscan June 2003)
- [S0443] MESSAGETAP: [MESSAGETAP](https://attack.mitre.org/software/S0443) uses the libpcap library to listen to all traffic and parses network protocols starting with Ethernet and IP layers. It continues parsing protocol layers including SCTP, SCCP, and TCAP and finally extracts SMS message data and routing metadata.  (Citation: FireEye MESSAGETAP October 2019)
- [S1206] JumbledPath: [JumbledPath](https://attack.mitre.org/software/S1206) has the ability to perform packet capture on remote devices via actor-defined jump-hosts.(Citation: Cisco Salt Typhoon FEB 2025)
- [G1047] Velvet Ant: [Velvet Ant](https://attack.mitre.org/groups/G1047) has used a custom tool, "VELVETTAP", to perform packet capture from compromised F5 BIG-IP devices.(Citation: Sygnia VelvetAnt 2024A)
- [G1045] Salt Typhoon: [Salt Typhoon](https://attack.mitre.org/groups/G1045) has used a variety of tools and techniques to capture packet data between network interfaces.(Citation: Cisco Salt Typhoon FEB 2025)
- [C0028] 2015 Ukraine Electric Power Attack: During the [2015 Ukraine Electric Power Attack](https://attack.mitre.org/campaigns/C0028), [Sandworm Team](https://attack.mitre.org/groups/G0034) used [BlackEnergy](https://attack.mitre.org/software/S0089)’s network sniffer module to discover user credentials being sent over the network between the local LAN and the power grid’s industrial control systems. (Citation: Charles McLellan March 2016)
- [S0587] Penquin: [Penquin](https://attack.mitre.org/software/S0587) can sniff network traffic to look for packets matching specific conditions.(Citation: Leonardo Turla Penquin May 2020)(Citation: Kaspersky Turla Penquin December 2014)
- [S0661] FoggyWeb: [FoggyWeb](https://attack.mitre.org/software/S0661) can configure custom listeners to passively monitor all incoming HTTP GET and POST requests sent to the AD FS server from the intranet/internet and intercept HTTP requests that match the custom URI patterns defined by the actor.(Citation: MSTIC FoggyWeb September 2021)
- [S0363] Empire: [Empire](https://attack.mitre.org/software/S0363) can be used to conduct packet captures on target hosts.(Citation: Github PowerShell Empire)
- [S0174] Responder: [Responder](https://attack.mitre.org/software/S0174) captures hashes and credentials that are sent to the system after the name services have been poisoned.(Citation: GitHub Responder)
- [S0367] Emotet: [Emotet](https://attack.mitre.org/software/S0367) has been observed to hook network APIs to monitor network traffic. (Citation: Trend Micro Banking Malware Jan 2019)
- [C0046] ArcaneDoor: [ArcaneDoor](https://attack.mitre.org/campaigns/C0046) included network packet capture and sniffing for data collection in victim environments.(Citation: Cisco ArcaneDoor 2024)(Citation: CCCS ArcaneDoor 2024)
- [G0064] APT33: [APT33](https://attack.mitre.org/groups/G0064) has used SniffPass to collect credentials by sniffing network traffic.(Citation: Symantec Elfin Mar 2019)
- [S1204] cd00r: [cd00r](https://attack.mitre.org/software/S1204) can use the libpcap library to monitor captured packets for specifc sequences.(Citation: Hartrell cd00r 2002)
- [S1186] Line Dancer: [Line Dancer](https://attack.mitre.org/software/S1186) can create and exfiltrate packet captures from compromised environments.(Citation: Cisco ArcaneDoor 2024)
- [G0105] DarkVishnya: [DarkVishnya](https://attack.mitre.org/groups/G0105) used network sniffing to obtain login data. (Citation: Securelist DarkVishnya Dec 2018)
- [G0007] APT28: [APT28](https://attack.mitre.org/groups/G0007) deployed the open source tool Responder to conduct NetBIOS Name Service poisoning, which captured usernames and hashed passwords that allowed access to legitimate credentials.(Citation: FireEye APT28)(Citation: FireEye APT28 Hospitality Aug 2017) [APT28](https://attack.mitre.org/groups/G0007) close-access teams have used Wi-Fi pineapples to intercept Wi-Fi signals and user credentials.(Citation: US District Court Indictment GRU Oct 2018)
- [S1203] J-magic: [J-magic](https://attack.mitre.org/software/S1203) has a pcap listener function that can create an Extended Berkley Packet Filter (eBPF) on designated interfaces and ports.(Citation: Lumen J-Magic JAN 2025)
- [S0378] PoshC2: [PoshC2](https://attack.mitre.org/software/S0378) contains a module for taking packet captures on compromised hosts.(Citation: GitHub PoshC2)
- [S1154] VersaMem: [VersaMem](https://attack.mitre.org/software/S1154) hooked the Catalina application filter chain `doFilter` on compromised systems to monitor all inbound requests to the local Tomcat web server, inspecting them for parameters like passwords and follow-on Java modules.(Citation: Lumen Versa 2024)
- [S0019] Regin: [Regin](https://attack.mitre.org/software/S0019) appears to have functionality to sniff for credentials passed over HTTP, SMTP, and SMB.(Citation: Kaspersky Regin)


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

#### T1056.001 - Input Capture: Keylogging

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

#### T1056.002 - Input Capture: GUI Input Capture

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

#### T1056.003 - Input Capture: Web Portal Capture

Description:

Adversaries may install code on externally facing portals, such as a VPN login page, to capture and transmit credentials of users who attempt to log into the service. For example, a compromised login page may log provided user credentials before logging the user in to the service.

This variation on input capture may be conducted post-compromise using legitimate administrative access as a backup measure to maintain network access through [External Remote Services](https://attack.mitre.org/techniques/T1133) and [Valid Accounts](https://attack.mitre.org/techniques/T1078) or as part of the initial compromise by exploitation of the externally facing web service.(Citation: Volexity Virtual Private Keylogging)

Procedures:

- [G1035] Winter Vivern: [Winter Vivern](https://attack.mitre.org/groups/G1035) registered and hosted domains to allow for creation of web pages mimicking legitimate government email logon sites to collect logon information.(Citation: SentinelOne WinterVivern 2023)
- [C0030] Triton Safety Instrumented System Attack: In the [Triton Safety Instrumented System Attack](https://attack.mitre.org/campaigns/C0030), [TEMP.Veles](https://attack.mitre.org/groups/G0088) captured credentials as they were being changed by redirecting text-based login codes to websites they controlled.(Citation: Triton-EENews-2017)
- [S1116] WARPWIRE: [WARPWIRE](https://attack.mitre.org/software/S1116) can capture credentials submitted during the web logon process in order to access layer seven applications such as RDP.(Citation: Mandiant Cutting Edge January 2024)
- [S1022] IceApple: The [IceApple](https://attack.mitre.org/software/S1022) OWA credential logger can monitor for OWA authentication requests and log the credentials.(Citation: CrowdStrike IceApple May 2022)
- [C0029] Cutting Edge: During [Cutting Edge](https://attack.mitre.org/campaigns/C0029), threat actors modified the JavaScript loaded by the Ivanti Connect Secure login page to capture credentials entered.(Citation: Volexity Ivanti Zero-Day Exploitation January 2024)

#### T1056.004 - Input Capture: Credential API Hooking

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


### T1110 - Brute Force

Description:

Adversaries may use brute force techniques to gain access to accounts when passwords are unknown or when password hashes are obtained.(Citation: TrendMicro Pawn Storm Dec 2020) Without knowledge of the password for an account or set of accounts, an adversary may systematically guess the password using a repetitive or iterative mechanism.(Citation: Dragos Crashoverride 2018) Brute forcing passwords can take place via interaction with a service that will check the validity of those credentials or offline against previously acquired credential data, such as password hashes.

Brute forcing credentials may take place at various points during a breach. For example, adversaries may attempt to brute force access to [Valid Accounts](https://attack.mitre.org/techniques/T1078) within a victim environment leveraging knowledge gathered from other post-compromise behaviors such as [OS Credential Dumping](https://attack.mitre.org/techniques/T1003), [Account Discovery](https://attack.mitre.org/techniques/T1087), or [Password Policy Discovery](https://attack.mitre.org/techniques/T1201). Adversaries may also combine brute forcing activity with behaviors such as [External Remote Services](https://attack.mitre.org/techniques/T1133) as part of Initial Access.

Procedures:

- [G0117] Fox Kitten: [Fox Kitten](https://attack.mitre.org/groups/G0117) has brute forced RDP credentials.(Citation: ClearSky Pay2Kitten December 2020)
- [G1001] HEXANE: [HEXANE](https://attack.mitre.org/groups/G1001) has used brute force attacks to compromise valid credentials.(Citation: SecureWorks August 2019)
- [S0220] Chaos: [Chaos](https://attack.mitre.org/software/S0220) conducts brute force attacks against SSH services to gain initial access.(Citation: Chaos Stolen Backdoor)
- [S0572] Caterpillar WebShell: [Caterpillar WebShell](https://attack.mitre.org/software/S0572) has a module to perform brute force attacks on a system.(Citation: ClearSky Lebanese Cedar Jan 2021)
- [G1003] Ember Bear: [Ember Bear](https://attack.mitre.org/groups/G1003) used the `su-bruteforce` tool to brute force specific users using the `su` command.(Citation: CISA GRU29155 2024)
- [G0010] Turla: [Turla](https://attack.mitre.org/groups/G0010) may attempt to connect to systems within a victim's network using <code>net use</code> commands and a predefined list or collection of passwords.(Citation: Kaspersky Turla)
- [G0105] DarkVishnya: [DarkVishnya](https://attack.mitre.org/groups/G0105) used brute-force attack to obtain login data.(Citation: Securelist DarkVishnya Dec 2018)
- [C0022] Operation Dream Job: During [Operation Dream Job](https://attack.mitre.org/campaigns/C0022), [Lazarus Group](https://attack.mitre.org/groups/G0032) performed brute force attacks against administrator accounts.(Citation: ESET Lazarus Jun 2020)
- [G0053] FIN5: [FIN5](https://attack.mitre.org/groups/G0053) has has used the tool GET2 Penetrator to look for remote login and hard-coded credentials.(Citation: DarkReading FireEye FIN5 Oct 2015)(Citation: Mandiant FIN5 GrrCON Oct 2016)
- [S0599] Kinsing: [Kinsing](https://attack.mitre.org/software/S0599) has attempted to brute force hosts over SSH.(Citation: Aqua Kinsing April 2020)
- [G0096] APT41: [APT41](https://attack.mitre.org/groups/G0096) performed password brute-force attacks on the local admin account.(Citation: FireEye APT41 Aug 2019)
- [G0082] APT38: [APT38](https://attack.mitre.org/groups/G0082) has used brute force techniques to attempt account access when passwords are unknown or when password hashes are unavailable.(Citation: CISA AA20-239A BeagleBoyz August 2020)
- [G0049] OilRig: [OilRig](https://attack.mitre.org/groups/G0049) has used brute force techniques to obtain credentials.(Citation: FireEye APT34 Webinar Dec 2017)(Citation: IBM ZeroCleare Wiper December 2019)
- [S0378] PoshC2: [PoshC2](https://attack.mitre.org/software/S0378) has modules for brute forcing local administrator and AD user accounts.(Citation: GitHub PoshC2)
- [S0650] QakBot: [QakBot](https://attack.mitre.org/software/S0650) can conduct brute force attacks to capture credentials.(Citation: Kroll Qakbot June 2020)(Citation: Crowdstrike Qakbot October 2020)(Citation: Kaspersky QakBot September 2021)
- [G1030] Agrius: [Agrius](https://attack.mitre.org/groups/G1030) engaged in various brute forcing activities via SMB in victim environments.(Citation: Unit42 Agrius 2023)
- [G0087] APT39: [APT39](https://attack.mitre.org/groups/G0087) has used Ncrack to reveal credentials.(Citation: FireEye APT39 Jan 2019)
- [C0025] 2016 Ukraine Electric Power Attack: During the [2016 Ukraine Electric Power Attack](https://attack.mitre.org/campaigns/C0025), [Sandworm Team](https://attack.mitre.org/groups/G0034) used a script to attempt RPC authentication against a number of hosts.(Citation: Dragos Crashoverride 2018)
- [G0035] Dragonfly: [Dragonfly](https://attack.mitre.org/groups/G0035) has attempted to brute force credentials to gain access.(Citation: CISA AA20-296A Berserk Bear December 2020)
- [S0583] Pysa: [Pysa](https://attack.mitre.org/software/S0583) has used brute force attempts against a central management console, as well as some Active Directory accounts.(Citation: CERT-FR PYSA April 2020)
- [S0488] CrackMapExec: [CrackMapExec](https://attack.mitre.org/software/S0488) can brute force supplied user credentials across a network range.(Citation: CME Github September 2018)
- [G0007] APT28: [APT28](https://attack.mitre.org/groups/G0007) can perform brute force attacks to obtain credentials.(Citation: TrendMicro Pawn Storm 2019)(Citation: TrendMicro Pawn Storm Dec 2020)(Citation: Microsoft Targeting Elections September 2020)

#### T1110.001 - Brute Force: Password Guessing

Description:

Adversaries with no prior knowledge of legitimate credentials within the system or environment may guess passwords to attempt access to accounts. Without knowledge of the password for an account, an adversary may opt to systematically guess the password using a repetitive or iterative mechanism. An adversary may guess login credentials without prior knowledge of system or environment passwords during an operation by using a list of common passwords. Password guessing may or may not take into account the target's policies on password complexity or use policies that may lock accounts out after a number of failed attempts.

Guessing passwords can be a risky option because it could cause numerous authentication failures and account lockouts, depending on the organization's login failure policies. (Citation: Cylance Cleaver)

Typically, management services over commonly used ports are used when guessing passwords. Commonly targeted services include the following:

* SSH (22/TCP)
* Telnet (23/TCP)
* FTP (21/TCP)
* NetBIOS / SMB / Samba (139/TCP & 445/TCP)
* LDAP (389/TCP)
* Kerberos (88/TCP)
* RDP / Terminal Services (3389/TCP)
* HTTP/HTTP Management Services (80/TCP & 443/TCP)
* MSSQL (1433/TCP)
* Oracle (1521/TCP)
* MySQL (3306/TCP)
* VNC (5900/TCP)
* SNMP (161/UDP and 162/TCP/UDP)

In addition to management services, adversaries may "target single sign-on (SSO) and cloud-based applications utilizing federated authentication protocols," as well as externally facing email applications, such as Office 365.(Citation: US-CERT TA18-068A 2018). Further, adversaries may abuse network device interfaces (such as `wlanAPI`) to brute force accessible wifi-router(s) via wireless authentication protocols.(Citation: Trend Micro Emotet 2020)

In default environments, LDAP and Kerberos connection attempts are less likely to trigger events over SMB, which creates Windows "logon failure" event ID 4625.

Procedures:

- [S0020] China Chopper: [China Chopper](https://attack.mitre.org/software/S0020)'s server component can perform brute force password guessing against authentication portals.(Citation: FireEye Periscope March 2018)
- [S0367] Emotet: [Emotet](https://attack.mitre.org/software/S0367) has been observed using a hard coded list of passwords to brute force user accounts. (Citation: Malwarebytes Emotet Dec 2017)(Citation: Symantec Emotet Jul 2018)(Citation: US-CERT Emotet Jul 2018)(Citation: Secureworks Emotet Nov 2018)(Citation: CIS Emotet Dec 2018)(Citation: Binary Defense Emotes Wi-Fi Spreader)
- [S0374] SpeakUp: [SpeakUp](https://attack.mitre.org/software/S0374) can perform brute forcing using a pre-defined list of usernames and passwords in an attempt to log in to administrative panels. (Citation: CheckPoint SpeakUp Feb 2019)
- [G0007] APT28: [APT28](https://attack.mitre.org/groups/G0007) has used a brute-force/password-spray tooling that operated in two modes: in brute-force mode it typically sent over 300 authentication attempts per hour per targeted account over the course of several hours or days.(Citation: Microsoft STRONTIUM New Patterns Cred Harvesting Sept 2020) [APT28](https://attack.mitre.org/groups/G0007) has also used a Kubernetes cluster to conduct distributed, large-scale password guessing attacks.(Citation: Cybersecurity Advisory GRU Brute Force Campaign July 2021)
- [S0488] CrackMapExec: [CrackMapExec](https://attack.mitre.org/software/S0488) can brute force passwords for a specified user on a single target system or across an entire network.(Citation: CME Github September 2018)
- [S0698] HermeticWizard: [HermeticWizard](https://attack.mitre.org/software/S0698) can use a list of hardcoded credentials in attempt to authenticate to SMB shares.(Citation: ESET Hermetic Wizard March 2022)
- [G0016] APT29: [APT29](https://attack.mitre.org/groups/G0016) has successfully conducted password guessing attacks against a list of mailboxes.(Citation: Mandiant APT29 Microsoft 365 2022)
- [S0532] Lucifer: [Lucifer](https://attack.mitre.org/software/S0532) has attempted to brute force TCP ports 135 (RPC) and 1433 (MSSQL) with the default username or list of usernames and    passwords.(Citation: Unit 42 Lucifer June 2020)
- [S0453] Pony: [Pony](https://attack.mitre.org/software/S0453) has used a small dictionary of common passwords against a collected list of local accounts.(Citation: Malwarebytes Pony April 2016)
- [S0341] Xbash: [Xbash](https://attack.mitre.org/software/S0341) can obtain a list of weak passwords from the C2 server to use for brute forcing as well as attempt to brute force services with open ports.(Citation: Unit42 Xbash Sept 2018)(Citation: Trend Micro Xbash Sept 2018)
- [S0598] P.A.S. Webshell: [P.A.S. Webshell](https://attack.mitre.org/software/S0598) can use predefined users and passwords to execute brute force attacks against SSH, FTP, POP3, MySQL, MSSQL, and PostgreSQL services.(Citation: ANSSI Sandworm January 2021)

#### T1110.002 - Brute Force: Password Cracking

Description:

Adversaries may use password cracking to attempt to recover usable credentials, such as plaintext passwords, when credential material such as password hashes are obtained. [OS Credential Dumping](https://attack.mitre.org/techniques/T1003) can be used to obtain password hashes, this may only get an adversary so far when [Pass the Hash](https://attack.mitre.org/techniques/T1550/002) is not an option. Further,  adversaries may leverage [Data from Configuration Repository](https://attack.mitre.org/techniques/T1602) in order to obtain hashed credentials for network devices.(Citation: US-CERT-TA18-106A) 

Techniques to systematically guess the passwords used to compute hashes are available, or the adversary may use a pre-computed rainbow table to crack hashes. Cracking hashes is usually done on adversary-controlled systems outside of the target network.(Citation: Wikipedia Password cracking) The resulting plaintext password resulting from a successfully cracked hash may be used to log into systems, resources, and services in which the account has access.

Procedures:

- [G0022] APT3: [APT3](https://attack.mitre.org/groups/G0022) has been known to brute force password hashes to be able to leverage plain text credentials.(Citation: APT3 Adversary Emulation Plan)
- [S0056] Net Crawler: [Net Crawler](https://attack.mitre.org/software/S0056) uses a list of known credentials gathered through credential dumping to guess passwords to accounts as it spreads throughout a network.(Citation: Cylance Cleaver)
- [G0035] Dragonfly: [Dragonfly](https://attack.mitre.org/groups/G0035) has dropped and executed tools used for password cracking, including Hydra and [CrackMapExec](https://attack.mitre.org/software/S0488).(Citation: US-CERT TA18-074A)(Citation: Kali Hydra)
- [G1045] Salt Typhoon: [Salt Typhoon](https://attack.mitre.org/groups/G1045) has cracked passwords for accounts with weak encryption obtained from the configuration files of compromised network devices.(Citation: Cisco Salt Typhoon FEB 2025)
- [G0037] FIN6: [FIN6](https://attack.mitre.org/groups/G0037) has extracted password hashes from ntds.dit to crack offline.(Citation: FireEye FIN6 April 2016)
- [C0002] Night Dragon: During [Night Dragon](https://attack.mitre.org/campaigns/C0002), threat actors used Cain & Abel to crack password hashes.(Citation: McAfee Night Dragon)

#### T1110.003 - Brute Force: Password Spraying

Description:

Adversaries may use a single or small list of commonly used passwords against many different accounts to attempt to acquire valid account credentials. Password spraying uses one password (e.g. 'Password01'), or a small list of commonly used passwords, that may match the complexity policy of the domain. Logins are attempted with that password against many different accounts on a network to avoid account lockouts that would normally occur when brute forcing a single account with many passwords. (Citation: BlackHillsInfosec Password Spraying)

Typically, management services over commonly used ports are used when password spraying. Commonly targeted services include the following:

* SSH (22/TCP)
* Telnet (23/TCP)
* FTP (21/TCP)
* NetBIOS / SMB / Samba (139/TCP & 445/TCP)
* LDAP (389/TCP)
* Kerberos (88/TCP)
* RDP / Terminal Services (3389/TCP)
* HTTP/HTTP Management Services (80/TCP & 443/TCP)
* MSSQL (1433/TCP)
* Oracle (1521/TCP)
* MySQL (3306/TCP)
* VNC (5900/TCP)

In addition to management services, adversaries may "target single sign-on (SSO) and cloud-based applications utilizing federated authentication protocols," as well as externally facing email applications, such as Office 365.(Citation: US-CERT TA18-068A 2018)

In default environments, LDAP and Kerberos connection attempts are less likely to trigger events over SMB, which creates Windows "logon failure" event ID 4625.

Procedures:

- [G0125] HAFNIUM: [HAFNIUM](https://attack.mitre.org/groups/G0125) has gained initial access through password spray attacks.(Citation: Microsoft Silk Typhoon MAR 2025)
- [S0606] Bad Rabbit: [Bad Rabbit](https://attack.mitre.org/software/S0606)’s <code>infpub.dat</code> file uses NTLM login credentials to brute force Windows machines.(Citation: Secure List Bad Rabbit)
- [S0488] CrackMapExec: [CrackMapExec](https://attack.mitre.org/software/S0488) can brute force credential authentication by using a supplied list of usernames and a single password.(Citation: CME Github September 2018)
- [S0362] Linux Rabbit: [Linux Rabbit](https://attack.mitre.org/software/S0362) brute forces SSH passwords in order to attempt to gain access and install its malware onto the server. (Citation: Anomali Linux Rabbit 2018)
- [C0051] APT28 Nearest Neighbor Campaign: During [APT28 Nearest Neighbor Campaign](https://attack.mitre.org/campaigns/C0051), [APT28](https://attack.mitre.org/groups/G0007) performed password-spray attacks against public facing services to validate credentials.(Citation: Nearest Neighbor Volexity)
- [G1030] Agrius: [Agrius](https://attack.mitre.org/groups/G1030) engaged in password spraying via SMB in victim environments.(Citation: Unit42 Agrius 2023)
- [G1003] Ember Bear: [Ember Bear](https://attack.mitre.org/groups/G1003) has conducted password spraying against Outlook Web Access (OWA) infrastructure to identify valid user names and passwords.(Citation: CISA GRU29155 2024)
- [G0016] APT29: [APT29](https://attack.mitre.org/groups/G0016) has conducted brute force password spray attacks.(Citation: MSRC Nobelium June 2021)(Citation: MSTIC Nobelium Oct 2021)(Citation: NCSC et al APT29 2024)
- [G1001] HEXANE: [HEXANE](https://attack.mitre.org/groups/G1001) has used password spraying attacks to obtain valid credentials.(Citation: SecureWorks August 2019)
- [G0032] Lazarus Group: [Lazarus Group](https://attack.mitre.org/groups/G0032) malware attempts to connect to Windows shares for lateral movement by using a generated list of usernames, which center around permutations of the username Administrator, and weak passwords.(Citation: Novetta Blockbuster)(Citation: Novetta Blockbuster RATs)
- [G0064] APT33: [APT33](https://attack.mitre.org/groups/G0064) has used password spraying to gain access to target systems.(Citation: FireEye APT33 Guardrail)(Citation: Microsoft Holmium June 2020)
- [G0122] Silent Librarian: [Silent Librarian](https://attack.mitre.org/groups/G0122) has used collected lists of names and e-mail accounts to use in password spraying attacks against private sector targets.(Citation: DOJ Iran Indictments March 2018)
- [G0114] Chimera: [Chimera](https://attack.mitre.org/groups/G0114) has used multiple password spraying attacks against victim's remote services to obtain valid user and administrator accounts.(Citation: NCC Group Chimera January 2021)
- [S0413] MailSniper: [MailSniper](https://attack.mitre.org/software/S0413) can be used for password spraying against Exchange and Office 365.(Citation: GitHub MailSniper)
- [G0077] Leafminer: [Leafminer](https://attack.mitre.org/groups/G0077) used a tool called Total SMB BruteForcer to perform internal password spraying.(Citation: Symantec Leafminer July 2018)
- [G0007] APT28: [APT28](https://attack.mitre.org/groups/G0007) has used a brute-force/password-spray tooling that operated in two modes: in password-spraying mode it conducted approximately four authentication attempts per hour per targeted account over the course of several days or weeks.(Citation: Microsoft STRONTIUM New Patterns Cred Harvesting Sept 2020)(Citation: Microsoft Targeting Elections September 2020) [APT28](https://attack.mitre.org/groups/G0007) has also used a Kubernetes cluster to conduct distributed, large-scale password spray attacks.(Citation: Cybersecurity Advisory GRU Brute Force Campaign July 2021)

#### T1110.004 - Brute Force: Credential Stuffing

Description:

Adversaries may use credentials obtained from breach dumps of unrelated accounts to gain access to target accounts through credential overlap. Occasionally, large numbers of username and password pairs are dumped online when a website or service is compromised and the user account credentials accessed. The information may be useful to an adversary attempting to compromise accounts by taking advantage of the tendency for users to use the same passwords across personal and business accounts.

Credential stuffing is a risky option because it could cause numerous authentication failures and account lockouts, depending on the organization's login failure policies.

Typically, management services over commonly used ports are used when stuffing credentials. Commonly targeted services include the following:

* SSH (22/TCP)
* Telnet (23/TCP)
* FTP (21/TCP)
* NetBIOS / SMB / Samba (139/TCP & 445/TCP)
* LDAP (389/TCP)
* Kerberos (88/TCP)
* RDP / Terminal Services (3389/TCP)
* HTTP/HTTP Management Services (80/TCP & 443/TCP)
* MSSQL (1433/TCP)
* Oracle (1521/TCP)
* MySQL (3306/TCP)
* VNC (5900/TCP)

In addition to management services, adversaries may "target single sign-on (SSO) and cloud-based applications utilizing federated authentication protocols," as well as externally facing email applications, such as Office 365.(Citation: US-CERT TA18-068A 2018)

Procedures:

- [G0114] Chimera: [Chimera](https://attack.mitre.org/groups/G0114) has used credential stuffing against victim's remote services to obtain valid accounts.(Citation: NCC Group Chimera January 2021)
- [S0266] TrickBot: [TrickBot](https://attack.mitre.org/software/S0266) uses brute-force attack against RDP with rdpscanDll module.(Citation: ESET Trickbot Oct 2020)(Citation: Bitdefender Trickbot March 2020)


### T1111 - Multi-Factor Authentication Interception

Description:

Adversaries may target multi-factor authentication (MFA) mechanisms, (i.e., smart cards, token generators, etc.) to gain access to credentials that can be used to access systems, services, and network resources. Use of MFA is recommended and provides a higher level of security than usernames and passwords alone, but organizations should be aware of techniques that could be used to intercept and bypass these security mechanisms. 

If a smart card is used for multi-factor authentication, then a keylogger will need to be used to obtain the password associated with a smart card during normal use. With both an inserted card and access to the smart card password, an adversary can connect to a network resource using the infected system to proxy the authentication with the inserted hardware token. (Citation: Mandiant M Trends 2011)

Adversaries may also employ a keylogger to similarly target other hardware tokens, such as RSA SecurID. Capturing token input (including a user's personal identification code) may provide temporary access (i.e. replay the one-time passcode until the next value rollover) as well as possibly enabling adversaries to reliably predict future authentication values (given access to both the algorithm and any seed values used to generate appended temporary codes). (Citation: GCN RSA June 2011)

Other methods of MFA may be intercepted and used by an adversary to authenticate. It is common for one-time codes to be sent via out-of-band communications (email, SMS). If the device and/or service is not secured, then it may be vulnerable to interception. Service providers can also be targeted: for example, an adversary may compromise an SMS messaging service in order to steal MFA codes sent to users’ phones.(Citation: Okta Scatter Swine 2022)

Procedures:

- [S1104] SLOWPULSE: [SLOWPULSE](https://attack.mitre.org/software/S1104) can log credentials on compromised Pulse Secure VPNs during the `DSAuth::AceAuthServer::checkUsernamePassword`ACE-2FA authentication procedure.(Citation: Mandiant Pulse Secure Zero-Day April 2021)
- [S0018] Sykipot: [Sykipot](https://attack.mitre.org/software/S0018) is known to contain functionality that enables targeting of smart card technologies to proxy authentication for connections to restricted network resources using detected hardware tokens.(Citation: Alienvault Sykipot DOD Smart Cards)
- [C0014] Operation Wocao: During [Operation Wocao](https://attack.mitre.org/campaigns/C0014), threat actors used a custom collection method to intercept two-factor authentication soft tokens.(Citation: FoxIT Wocao December 2019)
- [G0094] Kimsuky: [Kimsuky](https://attack.mitre.org/groups/G0094) has used a proprietary tool to intercept one time passwords required for two-factor authentication.(Citation: KISA Operation Muzabi)
- [C0049] Leviathan Australian Intrusions: [Leviathan](https://attack.mitre.org/groups/G0065) abused compromised appliance access to collect multifactor authentication token values during [Leviathan Australian Intrusions](https://attack.mitre.org/campaigns/C0049).(Citation: CISA Leviathan 2024)
- [G0114] Chimera: [Chimera](https://attack.mitre.org/groups/G0114) has registered alternate phone numbers for compromised users to intercept 2FA codes sent via SMS.(Citation: NCC Group Chimera January 2021)
- [G1044] APT42: [APT42](https://attack.mitre.org/groups/G1044) has intercepted SMS-based one-time passwords and has set up two-factor authentication.(Citation: Mandiant APT42-charms) Additionally, [APT42](https://attack.mitre.org/groups/G1044) has used cloned or fake websites to capture MFA tokens.(Citation: Mandiant APT42-untangling)
- [G1004] LAPSUS$: [LAPSUS$](https://attack.mitre.org/groups/G1004) has replayed stolen session token and passwords to trigger simple-approval MFA prompts in hope of the legitimate user will grant necessary approval.(Citation: MSTIC DEV-0537 Mar 2022)


### T1187 - Forced Authentication

Description:

Adversaries may gather credential material by invoking or forcing a user to automatically provide authentication information through a mechanism in which they can intercept.

The Server Message Block (SMB) protocol is commonly used in Windows networks for authentication and communication between systems for access to resources and file sharing. When a Windows system attempts to connect to an SMB resource it will automatically attempt to authenticate and send credential information for the current user to the remote system. (Citation: Wikipedia Server Message Block) This behavior is typical in enterprise environments so that users do not need to enter credentials to access network resources.

Web Distributed Authoring and Versioning (WebDAV) is also typically used by Windows systems as a backup protocol when SMB is blocked or fails. WebDAV is an extension of HTTP and will typically operate over TCP ports 80 and 443. (Citation: Didier Stevens WebDAV Traffic) (Citation: Microsoft Managing WebDAV Security)

Adversaries may take advantage of this behavior to gain access to user account hashes through forced SMB/WebDAV authentication. An adversary can send an attachment to a user through spearphishing that contains a resource link to an external server controlled by the adversary (i.e. [Template Injection](https://attack.mitre.org/techniques/T1221)), or place a specially crafted file on navigation path for privileged accounts (e.g. .SCF file placed on desktop) or on a publicly accessible share to be accessed by victim(s). When the user's system accesses the untrusted resource it will attempt authentication and send information, including the user's hashed credentials, over SMB to the adversary controlled server. (Citation: GitHub Hashjacking) With access to the credential hash, an adversary can perform off-line [Brute Force](https://attack.mitre.org/techniques/T1110) cracking to gain access to plaintext credentials. (Citation: Cylance Redirect to SMB)

There are several different ways this can occur. (Citation: Osanda Stealing NetNTLM Hashes) Some specifics from in-the-wild use include:

* A spearphishing attachment containing a document with a resource that is automatically loaded when the document is opened (i.e. [Template Injection](https://attack.mitre.org/techniques/T1221)). The document can include, for example, a request similar to <code>file[:]//[remote address]/Normal.dotm</code> to trigger the SMB request. (Citation: US-CERT APT Energy Oct 2017)
* A modified .LNK or .SCF file with the icon filename pointing to an external reference such as <code>\\[remote address]\pic.png</code> that will force the system to load the resource when the icon is rendered to repeatedly gather credentials. (Citation: US-CERT APT Energy Oct 2017)

Procedures:

- [G0079] DarkHydrus: [DarkHydrus](https://attack.mitre.org/groups/G0079) used [Template Injection](https://attack.mitre.org/techniques/T1221) to launch an authentication window for users to enter their credentials.(Citation: Unit 42 Phishery Aug 2018)
- [G0035] Dragonfly: [Dragonfly](https://attack.mitre.org/groups/G0035) has gathered hashed user credentials over SMB using spearphishing attachments with external resource links and by modifying .LNK file icon resources to collect credentials from virtualized systems.(Citation: US-CERT TA18-074A)(Citation: Gigamon Berserk Bear October 2021)
- [S0634] EnvyScout: [EnvyScout](https://attack.mitre.org/software/S0634) can use protocol handlers to coax the operating system to send NTLMv2 authentication responses to attacker-controlled infrastructure.(Citation: MSTIC Nobelium Toolset May 2021)


### T1212 - Exploitation for Credential Access

Description:

Adversaries may exploit software vulnerabilities in an attempt to collect credentials. Exploitation of a software vulnerability occurs when an adversary takes advantage of a programming error in a program, service, or within the operating system software or kernel itself to execute adversary-controlled code. 

Credentialing and authentication mechanisms may be targeted for exploitation by adversaries as a means to gain access to useful credentials or circumvent the process to gain authenticated access to systems. One example of this is `MS14-068`, which targets Kerberos and can be used to forge Kerberos tickets using domain user permissions.(Citation: Technet MS14-068)(Citation: ADSecurity Detecting Forged Tickets) Another example of this is replay attacks, in which the adversary intercepts data packets sent between parties and then later replays these packets. If services don't properly validate authentication requests, these replayed packets may allow an adversary to impersonate one of the parties and gain unauthorized access or privileges.(Citation: Bugcrowd Replay Attack)(Citation: Comparitech Replay Attack)(Citation: Microsoft Midnight Blizzard Replay Attack)

Such exploitation has been demonstrated in cloud environments as well. For example, adversaries have exploited vulnerabilities in public cloud infrastructure that allowed for unintended authentication token creation and renewal.(Citation: Storm-0558 techniques for unauthorized email access)

Exploitation for credential access may also result in Privilege Escalation depending on the process targeted or credentials obtained.

Procedures:

- [C0049] Leviathan Australian Intrusions: [Leviathan](https://attack.mitre.org/groups/G0065) exploited vulnerable network appliances during [Leviathan Australian Intrusions](https://attack.mitre.org/campaigns/C0049), leading to the collection and exfiltration of valid credentials.(Citation: CISA Leviathan 2024)


### T1528 - Steal Application Access Token

Description:

Adversaries can steal application access tokens as a means of acquiring credentials to access remote systems and resources.

Application access tokens are used to make authorized API requests on behalf of a user or service and are commonly used as a way to access resources in cloud and container-based applications and software-as-a-service (SaaS).(Citation: Auth0 - Why You Should Always Use Access Tokens to Secure APIs Sept 2019)  Adversaries who steal account API tokens in cloud and containerized environments may be able to access data and perform actions with the permissions of these accounts, which can lead to privilege escalation and further compromise of the environment.

For example, in Kubernetes environments, processes running inside a container may communicate with the Kubernetes API server using service account tokens. If a container is compromised, an adversary may be able to steal the container’s token and thereby gain access to Kubernetes API commands.(Citation: Kubernetes Service Accounts)  

Similarly, instances within continuous-development / continuous-integration (CI/CD) pipelines will often use API tokens to authenticate to other services for testing and deployment.(Citation: Cider Security Top 10 CICD Security Risks) If these pipelines are compromised, adversaries may be able to steal these tokens and leverage their privileges. 

In Azure, an adversary who compromises a resource with an attached Managed Identity, such as an Azure VM, can request short-lived tokens through the Azure Instance Metadata Service (IMDS). These tokens can then facilitate unauthorized actions or further access to other Azure services, bypassing typical credential-based authentication.(Citation: Entra Managed Identities 2025)(Citation: SpecterOps Managed Identity 2022)

Token theft can also occur through social engineering, in which case user action may be required to grant access. OAuth is one commonly implemented framework that issues tokens to users for access to systems. An application desiring access to cloud-based services or protected APIs can gain entry using OAuth 2.0 through a variety of authorization protocols. An example commonly-used sequence is Microsoft's Authorization Code Grant flow.(Citation: Microsoft Identity Platform Protocols May 2019)(Citation: Microsoft - OAuth Code Authorization flow - June 2019) An OAuth access token enables a third-party application to interact with resources containing user data in the ways requested by the application without obtaining user credentials. 
 
Adversaries can leverage OAuth authorization by constructing a malicious application designed to be granted access to resources with the target user's OAuth token.(Citation: Amnesty OAuth Phishing Attacks, August 2019)(Citation: Trend Micro Pawn Storm OAuth 2017) The adversary will need to complete registration of their application with the authorization server, for example Microsoft Identity Platform using Azure Portal, the Visual Studio IDE, the command-line interface, PowerShell, or REST API calls.(Citation: Microsoft - Azure AD App Registration - May 2019) Then, they can send a [Spearphishing Link](https://attack.mitre.org/techniques/T1566/002) to the target user to entice them to grant access to the application. Once the OAuth access token is granted, the application can gain potentially long-term access to features of the user account through [Application Access Token](https://attack.mitre.org/techniques/T1550/001).(Citation: Microsoft - Azure AD Identity Tokens - Aug 2019)

Application access tokens may function within a limited lifetime, limiting how long an adversary can utilize the stolen token. However, in some cases, adversaries can also steal application refresh tokens(Citation: Auth0 Understanding Refresh Tokens), allowing them to obtain new access tokens without prompting the user.

Procedures:

- [G0016] APT29: [APT29](https://attack.mitre.org/groups/G0016) uses stolen tokens to access victim accounts, without needing a password.(Citation: NCSC et al APT29 2024)
- [S0683] Peirates: [Peirates](https://attack.mitre.org/software/S0683) gathers Kubernetes service account tokens using a variety of techniques.(Citation: Peirates GitHub)
- [S0677] AADInternals: [AADInternals](https://attack.mitre.org/software/S0677) can steal users’ access tokens via phishing emails containing malicious links.(Citation: AADInternals Documentation)
- [G0007] APT28: [APT28](https://attack.mitre.org/groups/G0007) has used several malicious applications to steal user OAuth access tokens including applications masquerading as "Google Defender" "Google Email Protection," and "Google Scanner" for Gmail users. They also targeted Yahoo users with applications masquerading as "Delivery Service" and "McAfee Email Protection".(Citation: Trend Micro Pawn Storm OAuth 2017)
- [C0049] Leviathan Australian Intrusions: [Leviathan](https://attack.mitre.org/groups/G0065) abused access to compromised appliances to collect JSON Web Tokens (JWTs), used for creating virtual desktop sessions, during [Leviathan Australian Intrusions](https://attack.mitre.org/campaigns/C0049).(Citation: CISA Leviathan 2024)


### T1539 - Steal Web Session Cookie

Description:

An adversary may steal web application or service session cookies and use them to gain access to web applications or Internet services as an authenticated user without needing credentials. Web applications and services often use session cookies as an authentication token after a user has authenticated to a website.

Cookies are often valid for an extended period of time, even if the web application is not actively used. Cookies can be found on disk, in the process memory of the browser, and in network traffic to remote systems. Additionally, other applications on the targets machine might store sensitive authentication cookies in memory (e.g. apps which authenticate to cloud services). Session cookies can be used to bypasses some multi-factor authentication protocols.(Citation: Pass The Cookie)

There are several examples of malware targeting cookies from web browsers on the local system.(Citation: Kaspersky TajMahal April 2019)(Citation: Unit 42 Mac Crypto Cookies January 2019) Adversaries may also steal cookies by injecting malicious JavaScript content into websites or relying on [User Execution](https://attack.mitre.org/techniques/T1204) by tricking victims into running malicious JavaScript in their browser.(Citation: Talos Roblox Scam 2023)(Citation: Krebs Discord Bookmarks 2023)

There are also open source frameworks such as `Evilginx2` and `Muraena` that can gather session cookies through a malicious proxy (e.g., [Adversary-in-the-Middle](https://attack.mitre.org/techniques/T1557)) that can be set up by an adversary and used in phishing campaigns.(Citation: Github evilginx2)(Citation: GitHub Mauraena)

After an adversary acquires a valid cookie, they can then perform a [Web Session Cookie](https://attack.mitre.org/techniques/T1550/004) technique to login to the corresponding web application.

Procedures:

- [G1014] LuminousMoth: [LuminousMoth](https://attack.mitre.org/groups/G1014) has used an unnamed post-exploitation tool to steal cookies from the Chrome browser.(Citation: Kaspersky LuminousMoth July 2021)
- [G0094] Kimsuky: [Kimsuky](https://attack.mitre.org/groups/G0094) has used malware, such as [TRANSLATEXT](https://attack.mitre.org/software/S1201), to steal and exfiltrate browser cookies.(Citation: Zscaler Kimsuky TRANSLATEXT)(Citation: S2W Troll Stealer 2024)
- [G0034] Sandworm Team: [Sandworm Team](https://attack.mitre.org/groups/G0034) used information stealer malware to collect browser session cookies.(Citation: Leonard TAG 2023)
- [S0531] Grandoreiro: [Grandoreiro](https://attack.mitre.org/software/S0531) can steal the victim's cookies to use for duplicating the active session from another device.(Citation: IBM Grandoreiro April 2020)
- [S1207] XLoader: [XLoader](https://attack.mitre.org/software/S1207) can capture web session cookies and session information from victim browsers.(Citation: Google XLoader 2017)
- [G1015] Scattered Spider: [Scattered Spider](https://attack.mitre.org/groups/G1015) retrieves browser cookies via Raccoon Stealer.(Citation: CISA Scattered Spider Advisory November 2023)
- [G0120] Evilnum: [Evilnum](https://attack.mitre.org/groups/G0120) can steal cookies and session information from browsers.(Citation: ESET EvilNum July 2020)
- [S0492] CookieMiner: [CookieMiner](https://attack.mitre.org/software/S0492) can steal Google Chrome and Apple Safari browser cookies from the victim’s machine. (Citation: Unit42 CookieMiner Jan 2019)
- [G1033] Star Blizzard: [Star Blizzard](https://attack.mitre.org/groups/G1033) has used EvilGinx to steal the session cookies of victims directed to
 phishing domains.(Citation: CISA Star Blizzard Advisory December 2023)
- [G0030] Lotus Blossom: [Lotus Blossom](https://attack.mitre.org/groups/G0030) has used publicly-available tools to steal cookies from browsers such as Chrome.(Citation: Cisco LotusBlossom 2025)
- [S1140] Spica: [Spica](https://attack.mitre.org/software/S1140) has the ability to steal cookies from Chrome, Firefox, Opera, and Edge browsers.(Citation: Google TAG COLDRIVER January 2024)
- [S0650] QakBot: [QakBot](https://attack.mitre.org/software/S0650) has the ability to capture web session cookies.(Citation: Kroll Qakbot June 2020)(Citation: Kaspersky QakBot September 2021)
- [S0568] EVILNUM: [EVILNUM](https://attack.mitre.org/software/S0568) can harvest cookies and upload them to the C2 server.(Citation: Prevailion EvilNum May 2020)
- [S1201] TRANSLATEXT: [TRANSLATEXT](https://attack.mitre.org/software/S1201) has exfiltrated updated cookies from Google, Naver, Kakao or Daum to the C2 server.(Citation: Zscaler Kimsuky TRANSLATEXT)
- [S0631] Chaes: [Chaes](https://attack.mitre.org/software/S0631) has used a script that extracts the web session cookie and sends it to the C2 server.(Citation: Cybereason Chaes Nov 2020)
- [S0657] BLUELIGHT: [BLUELIGHT](https://attack.mitre.org/software/S0657) can harvest cookies from Internet Explorer, Edge, Chrome, and Naver Whale browsers.(Citation: Volexity InkySquid BLUELIGHT August 2021)
- [C0024] SolarWinds Compromise: During the [SolarWinds Compromise](https://attack.mitre.org/campaigns/C0024), [APT29](https://attack.mitre.org/groups/G0016) stole Chrome browser cookies by copying the Chrome profile directories of targeted users.(Citation: CrowdStrike StellarParticle January 2022)
- [S1146] MgBot: [MgBot](https://attack.mitre.org/software/S1146) includes modules that can steal cookies from Firefox, Chrome, and Edge web browsers.(Citation: ESET EvasivePanda 2023)
- [S0658] XCSSET: [XCSSET](https://attack.mitre.org/software/S0658) uses <code>scp</code> to access the <code>~/Library/Cookies/Cookies.binarycookies</code> file.(Citation: trendmicro xcsset xcode project 2020)
- [S0467] TajMahal: [TajMahal](https://attack.mitre.org/software/S0467) has the ability to steal web session cookies from Internet Explorer, Netscape Navigator, FireFox and RealNetworks applications.(Citation: Kaspersky TajMahal April 2019)
- [S1111] DarkGate: [DarkGate](https://attack.mitre.org/software/S1111) attempts to steal Opera cookies, if present, after terminating the related process.(Citation: Rapid7 BlackBasta 2024)
- [S1148] Raccoon Stealer: [Raccoon Stealer](https://attack.mitre.org/software/S1148) attempts to steal cookies and related information in browser history.(Citation: Sekoia Raccoon2 2022)
- [S1213] Lumma Stealer: [Lumma Stealer](https://attack.mitre.org/software/S1213) has harvested cookies from various browsers.(Citation: Cybereason LumaStealer Undated)(Citation: Fortinet LummaStealer 2024)(Citation: TrendMicro LummaStealer 2025)
- [G1044] APT42: [APT42](https://attack.mitre.org/groups/G1044) has used custom malware to steal login and cookie data from common browsers.(Citation: Mandiant APT42-charms)


### T1552 - Unsecured Credentials

Description:

Adversaries may search compromised systems to find and obtain insecurely stored credentials. These credentials can be stored and/or misplaced in many locations on a system, including plaintext files (e.g. [Bash History](https://attack.mitre.org/techniques/T1552/003)), operating system or application-specific repositories (e.g. [Credentials in Registry](https://attack.mitre.org/techniques/T1552/002)),  or other specialized files/artifacts (e.g. [Private Keys](https://attack.mitre.org/techniques/T1552/004)).(Citation: Brining MimiKatz to Unix)

Procedures:

- [C0049] Leviathan Australian Intrusions: [Leviathan](https://attack.mitre.org/groups/G0065) gathered credentials hardcoded in binaries located on victim devices during [Leviathan Australian Intrusions](https://attack.mitre.org/campaigns/C0049).(Citation: CISA Leviathan 2024)
- [S1111] DarkGate: [DarkGate](https://attack.mitre.org/software/S1111) uses NirSoft tools to steal user credentials from the infected machine.(Citation: Ensilo Darkgate 2018) NirSoft tools are executed via process hollowing in a newly-created instance of vbc.exe or regasm.exe.
- [S1091] Pacu: [Pacu](https://attack.mitre.org/software/S1091) can search for sensitive data: for example, in Code Build environment variables, EC2 user data, and Cloud Formation templates.(Citation: GitHub Pacu)
- [S0373] Astaroth: [Astaroth](https://attack.mitre.org/software/S0373) uses an external software known as NetPass to recover passwords. (Citation: Cybereason Astaroth Feb 2019)
- [G1017] Volt Typhoon: [Volt Typhoon](https://attack.mitre.org/groups/G1017) has obtained credentials insecurely stored on targeted network appliances.(Citation: CISA AA24-038A PRC Critical Infrastructure February 2024)
- [S1131] NPPSPY: [NPPSPY](https://attack.mitre.org/software/S1131) captures credentials by recording them through an alternative network listener registered to the <code>mpnotify.exe</code> process, allowing for cleartext recording of logon information.(Citation: Huntress NPPSPY 2022)

#### T1552.001 - Unsecured Credentials: Credentials In Files

Description:

Adversaries may search local file systems and remote file shares for files containing insecurely stored credentials. These can be files created by users to store their own credentials, shared credential stores for a group of individuals, configuration files containing passwords for a system or service, or source code/binary files containing embedded passwords.

It is possible to extract passwords from backups or saved virtual machines through [OS Credential Dumping](https://attack.mitre.org/techniques/T1003).(Citation: CG 2014) Passwords may also be obtained from Group Policy Preferences stored on the Windows Domain Controller.(Citation: SRD GPP)

In cloud and/or containerized environments, authenticated user and service account credentials are often stored in local configuration and credential files.(Citation: Unit 42 Hildegard Malware) They may also be found as parameters to deployment commands in container logs.(Citation: Unit 42 Unsecured Docker Daemons) In some cases, these files can be copied and reused on another machine or the contents can be read and then used to authenticate without needing to copy any files.(Citation: Specter Ops - Cloud Credential Storage)

Procedures:

- [S0117] XTunnel: [XTunnel](https://attack.mitre.org/software/S0117) is capable of accessing locally stored passwords on victims.(Citation: Invincea XTunnel)
- [S0192] Pupy: [Pupy](https://attack.mitre.org/software/S0192) can use Lazagne for harvesting credentials.(Citation: GitHub Pupy)
- [S0367] Emotet: [Emotet](https://attack.mitre.org/software/S0367) has been observed leveraging a module that retrieves passwords stored on a system for the current logged-on user. (Citation: US-CERT Emotet Jul 2018)(Citation: CIS Emotet Dec 2018)
- [S0378] PoshC2: [PoshC2](https://attack.mitre.org/software/S0378) contains modules for searching for passwords in local and remote files.(Citation: GitHub PoshC2)
- [S0226] Smoke Loader: [Smoke Loader](https://attack.mitre.org/software/S0226) searches for files named logins.json to parse for credentials.(Citation: Talos Smoke Loader July 2018)
- [G0064] APT33: [APT33](https://attack.mitre.org/groups/G0064) has used a variety of publicly available tools like [LaZagne](https://attack.mitre.org/software/S0349) to gather credentials.(Citation: Symantec Elfin Mar 2019)(Citation: FireEye APT33 Guardrail)
- [S0331] Agent Tesla: [Agent Tesla](https://attack.mitre.org/software/S0331) has the ability to extract credentials from configuration or support files.(Citation: SentinelLabs Agent Tesla Aug 2020)
- [S0349] LaZagne: [LaZagne](https://attack.mitre.org/software/S0349) can obtain credentials from chats, databases, mail, and WiFi.(Citation: GitHub LaZagne Dec 2018)
- [S0363] Empire: [Empire](https://attack.mitre.org/software/S0363) can use various modules to search for files containing passwords.(Citation: Github PowerShell Empire)
- [C0049] Leviathan Australian Intrusions: [Leviathan](https://attack.mitre.org/groups/G0065) gathered credentials stored in files related to Building Management System (BMS) operations during [Leviathan Australian Intrusions](https://attack.mitre.org/campaigns/C0049).(Citation: CISA Leviathan 2024)
- [S0344] Azorult: [Azorult](https://attack.mitre.org/software/S0344) can steal credentials in files belonging to common software such as Skype, Telegram, and Steam.(Citation: Unit42 Azorult Nov 2018)
- [S0583] Pysa: [Pysa](https://attack.mitre.org/software/S0583) has extracted credentials from the password database before encrypting the files.(Citation: CERT-FR PYSA April 2020)
- [G0117] Fox Kitten: [Fox Kitten](https://attack.mitre.org/groups/G0117) has accessed files to gain valid credentials.(Citation: CISA AA20-259A Iran-Based Actor September 2020)
- [S0601] Hildegard: [Hildegard](https://attack.mitre.org/software/S0601) has searched for SSH keys, Docker credentials, and Kubernetes service tokens.(Citation: Unit 42 Hildegard Malware)
- [G0092] TA505: [TA505](https://attack.mitre.org/groups/G0092) has used malware to gather credentials from FTP clients and Outlook.(Citation: Proofpoint TA505 Sep 2017)
- [S0266] TrickBot: [TrickBot](https://attack.mitre.org/software/S0266) can obtain passwords stored in files from several applications such as Outlook, Filezilla, OpenSSH, OpenVPN and WinSCP.(Citation: Trend Micro Trickbot Nov 2018)(Citation: Cyberreason Anchor December 2019) Additionally, it searches for the ".vnc.lnk" affix to steal VNC credentials.(Citation: TrendMicro Trickbot Feb 2019)
- [S0677] AADInternals: [AADInternals](https://attack.mitre.org/software/S0677) can gather unsecured credentials for Azure AD services, such as Azure AD Connect, from a local machine.(Citation: AADInternals Documentation)
- [G1016] FIN13: [FIN13](https://attack.mitre.org/groups/G1016) has obtained administrative credentials by browsing through local files on a compromised machine.(Citation: Sygnia Elephant Beetle Jan 2022)
- [G0119] Indrik Spider: [Indrik Spider](https://attack.mitre.org/groups/G0119) has searched files to obtain and exfiltrate credentials.(Citation: Mandiant_UNC2165)
- [G0022] APT3: [APT3](https://attack.mitre.org/groups/G0022) has a tool that can locate credentials in files on the file system such as those from Firefox or Chrome.(Citation: Symantec Buckeye)
- [G0077] Leafminer: [Leafminer](https://attack.mitre.org/groups/G0077) used several tools for retrieving login and password information, including LaZagne.(Citation: Symantec Leafminer July 2018)
- [S0262] QuasarRAT: [QuasarRAT](https://attack.mitre.org/software/S0262) can obtain passwords from FTP clients.(Citation: GitHub QuasarRAT)(Citation: Volexity Patchwork June 2018)
- [S0067] pngdowner: If an initial connectivity check fails, [pngdowner](https://attack.mitre.org/software/S0067) attempts to extract proxy details and credentials from Windows Protected Storage and from the IE Credentials Store. This allows the adversary to use the proxy credentials for subsequent requests if they enable outbound HTTP access.(Citation: CrowdStrike Putter Panda)
- [G0094] Kimsuky: [Kimsuky](https://attack.mitre.org/groups/G0094) has used tools that are capable of obtaining credentials from saved mail.(Citation: Netscout Stolen Pencil Dec 2018)
- [S0089] BlackEnergy: [BlackEnergy](https://attack.mitre.org/software/S0089) has used a plug-in to gather credentials stored in files on the host by various software programs, including The Bat! email client, Outlook, and Windows Credential Store.(Citation: F-Secure BlackEnergy 2014)(Citation: Securelist BlackEnergy Nov 2014)
- [S0283] jRAT: [jRAT](https://attack.mitre.org/software/S0283) can capture passwords from common chat applications such as MSN Messenger, AOL, Instant Messenger, and and Google Talk.(Citation: Kaspersky Adwind Feb 2016)
- [G1039] RedCurl: [RedCurl](https://attack.mitre.org/groups/G1039) used [LaZagne](https://attack.mitre.org/software/S0349) to obtain passwords in files.(Citation: group-ib_redcurl1)(Citation: group-ib_redcurl2)
- [G0049] OilRig: [OilRig](https://attack.mitre.org/groups/G0049) has used credential dumping tools such as [LaZagne](https://attack.mitre.org/software/S0349) to steal credentials to accounts logged into the compromised system and to Outlook Web Access.(Citation: Unit42 OilRig Playbook 2023)(Citation: FireEye APT34 Webinar Dec 2017)(Citation: FireEye APT35 2018)(Citation: FireEye APT34 July 2019)
- [G1003] Ember Bear: [Ember Bear](https://attack.mitre.org/groups/G1003) has dumped configuration settings in accessed IP cameras including plaintext credentials.(Citation: CISA GRU29155 2024)
- [S1183] StrelaStealer: [StrelaStealer](https://attack.mitre.org/software/S1183) searches for and if found collects the contents of files such as `logins.json` and `key4.db` in the `$APPDATA%\Thunderbird\Profiles\` directory, associated with the Thunderbird email application.(Citation: DCSO StrelaStealer 2022)(Citation: Fortgale StrelaStealer 2023)
- [G0139] TeamTNT: [TeamTNT](https://attack.mitre.org/groups/G0139) has searched for unsecured AWS credentials and Docker API credentials.(Citation: Cado Security TeamTNT Worm August 2020)(Citation: Trend Micro TeamTNT)(Citation: Cisco Talos Intelligence Group)
- [G0069] MuddyWater: [MuddyWater](https://attack.mitre.org/groups/G0069) has run a tool that steals passwords saved in victim email.(Citation: Symantec MuddyWater Dec 2018)
- [G1015] Scattered Spider: [Scattered Spider](https://attack.mitre.org/groups/G1015) Spider searches for credential storage documentation on a compromised host.(Citation: CISA Scattered Spider Advisory November 2023)

#### T1552.002 - Unsecured Credentials: Credentials in Registry

Description:

Adversaries may search the Registry on compromised systems for insecurely stored credentials. The Windows Registry stores configuration information that can be used by the system or other programs. Adversaries may query the Registry looking for credentials and passwords that have been stored for use by other programs or services. Sometimes these credentials are used for automatic logons.

Example commands to find Registry keys related to password information: (Citation: Pentestlab Stored Credentials)

* Local Machine Hive: <code>reg query HKLM /f password /t REG_SZ /s</code>
* Current User Hive: <code>reg query HKCU /f password /t REG_SZ /s</code>

Procedures:

- [S0075] Reg: [Reg](https://attack.mitre.org/software/S0075) may be used to find credentials in the Windows Registry.(Citation: Pentestlab Stored Credentials)
- [S0194] PowerSploit: [PowerSploit](https://attack.mitre.org/software/S0194) has several modules that search the Windows Registry for stored credentials: <code>Get-UnattendedInstallFile</code>, <code>Get-Webconfig</code>, <code>Get-ApplicationHost</code>, <code>Get-SiteListPassword</code>, <code>Get-CachedGPPPassword</code>, and <code>Get-RegistryAutoLogon</code>.(Citation: Pentestlab Stored Credentials)
- [G0050] APT32: [APT32](https://attack.mitre.org/groups/G0050) used Outlook Credential Dumper to harvest credentials stored in Windows registry.(Citation: Cybereason Oceanlotus May 2017)(Citation: Cybereason Cobalt Kitty 2017)
- [S1022] IceApple: [IceApple](https://attack.mitre.org/software/S1022) can harvest credentials from local and remote host registries.(Citation: CrowdStrike IceApple May 2022)
- [S1183] StrelaStealer: [StrelaStealer](https://attack.mitre.org/software/S1183) enumerates the registry key `HKCU\SOFTWARE\Microsoft\Office\16.0\Outlook\Profiles\Outlook\9375CFF0413111d3B88A00104B2A6676\` to identify the values for "IMAP User," "IMAP Server," and "IMAP Password" associated with the Outlook email application.(Citation: DCSO StrelaStealer 2022)(Citation: Fortgale StrelaStealer 2023)(Citation: IBM StrelaStealer 2024)
- [S0266] TrickBot: [TrickBot](https://attack.mitre.org/software/S0266) has retrieved PuTTY credentials by querying the <code>Software\SimonTatham\Putty\Sessions</code> registry key (Citation: TrendMicro Trickbot Feb 2019)
- [S0476] Valak: [Valak](https://attack.mitre.org/software/S0476) can use the clientgrabber module to steal e-mail credentials from the Registry.(Citation: SentinelOne Valak June 2020)
- [G1039] RedCurl: [RedCurl](https://attack.mitre.org/groups/G1039) used [LaZagne](https://attack.mitre.org/software/S0349) to obtain passwords in the Registry.(Citation: group-ib_redcurl1)(Citation: group-ib_redcurl2)
- [S0331] Agent Tesla: [Agent Tesla](https://attack.mitre.org/software/S0331) has the ability to extract credentials from the Registry.(Citation: SentinelLabs Agent Tesla Aug 2020)

#### T1552.003 - Unsecured Credentials: Bash History

Description:

Adversaries may search the bash command history on compromised systems for insecurely stored credentials. Bash keeps track of the commands users type on the command-line with the "history" utility. Once a user logs out, the history is flushed to the user’s <code>.bash_history</code> file. For each user, this file resides at the same location: <code>~/.bash_history</code>. Typically, this file keeps track of the user’s last 500 commands. Users often type usernames and passwords on the command-line as parameters to programs, which then get saved to this file when they log out. Adversaries can abuse this by looking through the file for potential credentials. (Citation: External to DA, the OS X Way)

Procedures:

- [S0599] Kinsing: [Kinsing](https://attack.mitre.org/software/S0599) has searched <code>bash_history</code> for credentials.(Citation: Aqua Kinsing April 2020)

#### T1552.004 - Unsecured Credentials: Private Keys

Description:

Adversaries may search for private key certificate files on compromised systems for insecurely stored credentials. Private cryptographic keys and certificates are used for authentication, encryption/decryption, and digital signatures.(Citation: Wikipedia Public Key Crypto) Common key and certificate file extensions include: .key, .pgp, .gpg, .ppk., .p12, .pem, .pfx, .cer, .p7b, .asc. 

Adversaries may also look in common key directories, such as <code>~/.ssh</code> for SSH keys on * nix-based systems or <code>C:&#92;Users&#92;(username)&#92;.ssh&#92;</code> on Windows. Adversary tools may also search compromised systems for file extensions relating to cryptographic keys and certificates.(Citation: Kaspersky Careto)(Citation: Palo Alto Prince of Persia)

When a device is registered to Entra ID, a device key and a transport key are generated and used to verify the device’s identity.(Citation: Microsoft Primary Refresh Token) An adversary with access to the device may be able to export the keys in order to impersonate the device.(Citation: AADInternals Azure AD Device Identities)

On network devices, private keys may be exported via [Network Device CLI](https://attack.mitre.org/techniques/T1059/008) commands such as `crypto pki export`.(Citation: cisco_deploy_rsa_keys) 

Some private keys require a password or passphrase for operation, so an adversary may also use [Input Capture](https://attack.mitre.org/techniques/T1056) for keylogging or attempt to [Brute Force](https://attack.mitre.org/techniques/T1110) the passphrase off-line. These private keys can be used to authenticate to [Remote Services](https://attack.mitre.org/techniques/T1021) like SSH or for use in decrypting other collected files such as email.

Procedures:

- [S0409] Machete: [Machete](https://attack.mitre.org/software/S0409) has scanned and looked for cryptographic keys and certificate file extensions.(Citation: ESET Machete July 2019)
- [S0002] Mimikatz: [Mimikatz](https://attack.mitre.org/software/S0002)'s <code>CRYPTO::Extract</code> module can extract keys by interacting with Windows cryptographic application programming interface (API) functions.(Citation: Adsecurity Mimikatz Guide)
- [C0014] Operation Wocao: During [Operation Wocao](https://attack.mitre.org/campaigns/C0014), threat actors used [Mimikatz](https://attack.mitre.org/software/S0002) to dump certificates and private keys from the Windows certificate store.(Citation: FoxIT Wocao December 2019)
- [S0599] Kinsing: [Kinsing](https://attack.mitre.org/software/S0599) has searched for private keys.(Citation: Aqua Kinsing April 2020)
- [S0601] Hildegard: [Hildegard](https://attack.mitre.org/software/S0601) has searched for private keys in .ssh.(Citation: Unit 42 Hildegard Malware)
- [S1060] Mafalda: [Mafalda](https://attack.mitre.org/software/S1060) can collect a Chrome encryption key used to protect browser cookies.(Citation: SentinelLabs Metador Sept 2022)
- [G1015] Scattered Spider: [Scattered Spider](https://attack.mitre.org/groups/G1015) enumerate and exfiltrate code-signing certificates from a compromised host.(Citation: CISA Scattered Spider Advisory November 2023)
- [S1196] Troll Stealer: [Troll Stealer](https://attack.mitre.org/software/S1196) collects all data in victim `.ssh` folders by creating a compressed copy that is subsequently exfiltrated to command and control infrastructure. [Troll Stealer](https://attack.mitre.org/software/S1196) also collects key information associated with the Government Public Key Infrastructure (GPKI) service for South Korean government information systems.(Citation: S2W Troll Stealer 2024)(Citation: Symantec Troll Stealer 2024)
- [C0024] SolarWinds Compromise: During the [SolarWinds Compromise](https://attack.mitre.org/campaigns/C0024), [APT29](https://attack.mitre.org/groups/G0016) obtained PKI keys, certificate files, and the private encryption key from an Active Directory Federation Services (AD FS) container to decrypt corresponding SAML signing certificates.(Citation: Microsoft 365 Defender Solorigate)(Citation: Cybersecurity Advisory SVR TTP May 2021)
- [S0661] FoggyWeb: [FoggyWeb](https://attack.mitre.org/software/S0661) can retrieve token signing certificates and token decryption certificates from a compromised AD FS server.(Citation: MSTIC FoggyWeb September 2021)
- [G0139] TeamTNT: [TeamTNT](https://attack.mitre.org/groups/G0139) has searched for unsecured SSH keys.(Citation: Cado Security TeamTNT Worm August 2020)(Citation: Trend Micro TeamTNT)
- [S0363] Empire: [Empire](https://attack.mitre.org/software/S0363) can use modules like <code>Invoke-SessionGopher</code> to extract private key and session information.(Citation: Github PowerShell Empire)
- [S0677] AADInternals: [AADInternals](https://attack.mitre.org/software/S0677) can gather encryption keys from Azure AD services such as ADSync and Active Directory Federated Services servers.(Citation: AADInternals Documentation)
- [G0106] Rocke: [Rocke](https://attack.mitre.org/groups/G0106) has used SSH private keys on the infected machine to spread its coinminer throughout a network.(Citation: Anomali Rocke March 2019)
- [S0377] Ebury: [Ebury](https://attack.mitre.org/software/S0377) has intercepted unencrypted private keys as well as private key pass-phrases.(Citation: ESET Ebury Feb 2014)
- [G1017] Volt Typhoon: [Volt Typhoon](https://attack.mitre.org/groups/G1017) has accessed a Local State file that contains the AES key used to encrypt passwords stored in the Chrome browser.(Citation: CISA AA24-038A PRC Critical Infrastructure February 2024)
- [S0283] jRAT: [jRAT](https://attack.mitre.org/software/S0283) can steal keys for VPNs and cryptocurrency wallets.(Citation: Kaspersky Adwind Feb 2016)

#### T1552.005 - Unsecured Credentials: Cloud Instance Metadata API

Description:

Adversaries may attempt to access the Cloud Instance Metadata API to collect credentials and other sensitive data.

Most cloud service providers support a Cloud Instance Metadata API which is a service provided to running virtual instances that allows applications to access information about the running virtual instance. Available information generally includes name, security group, and additional metadata including sensitive data such as credentials and UserData scripts that may contain additional secrets. The Instance Metadata API is provided as a convenience to assist in managing applications and is accessible by anyone who can access the instance.(Citation: AWS Instance Metadata API) A cloud metadata API has been used in at least one high profile compromise.(Citation: Krebs Capital One August 2019)

If adversaries have a presence on the running virtual instance, they may query the Instance Metadata API directly to identify credentials that grant access to additional resources. Additionally, adversaries may exploit a Server-Side Request Forgery (SSRF) vulnerability in a public facing web proxy that allows them to gain access to the sensitive information via a request to the Instance Metadata API.(Citation: RedLock Instance Metadata API 2018)

The de facto standard across cloud service providers is to host the Instance Metadata API at <code>http[:]//169.254.169.254</code>.

Procedures:

- [G0139] TeamTNT: [TeamTNT](https://attack.mitre.org/groups/G0139) has queried the AWS instance metadata service for credentials.(Citation: Trend Micro TeamTNT)(Citation: Cisco Talos Intelligence Group)
- [S0683] Peirates: [Peirates](https://attack.mitre.org/software/S0683) can query the query AWS and GCP metadata APIs for secrets.(Citation: Peirates GitHub)
- [S0601] Hildegard: [Hildegard](https://attack.mitre.org/software/S0601) has queried the Cloud Instance Metadata API for cloud credentials.(Citation: Unit 42 Hildegard Malware)

#### T1552.006 - Unsecured Credentials: Group Policy Preferences

Description:

Adversaries may attempt to find unsecured credentials in Group Policy Preferences (GPP). GPP are tools that allow administrators to create domain policies with embedded credentials. These policies allow administrators to set local accounts.(Citation: Microsoft GPP 2016)

These group policies are stored in SYSVOL on a domain controller. This means that any domain user can view the SYSVOL share and decrypt the password (using the AES key that has been made public).(Citation: Microsoft GPP Key)

The following tools and scripts can be used to gather and decrypt the password file from Group Policy Preference XML files:

* Metasploit’s post exploitation module: <code>post/windows/gather/credentials/gpp</code>
* Get-GPPPassword(Citation: Obscuresecurity Get-GPPPassword)
* gpprefdecrypt.py

On the SYSVOL share, adversaries may use the following command to enumerate potential GPP XML files: <code>dir /s * .xml</code>

Procedures:

- [S0692] SILENTTRINITY: [SILENTTRINITY](https://attack.mitre.org/software/S0692) has a module that can extract cached GPP passwords.(Citation: GitHub SILENTTRINITY Modules July 2019)
- [S0194] PowerSploit: [PowerSploit](https://attack.mitre.org/software/S0194) contains a collection of Exfiltration modules that can harvest credentials from Group Policy Preferences.(Citation: GitHub PowerSploit May 2012)(Citation: PowerSploit Documentation)
- [G0064] APT33: [APT33](https://attack.mitre.org/groups/G0064) has used a variety of publicly available tools like Gpppassword to gather credentials.(Citation: Symantec Elfin Mar 2019)(Citation: FireEye APT33 Guardrail)
- [G0102] Wizard Spider: [Wizard Spider](https://attack.mitre.org/groups/G0102) has used PowerShell cmdlets `Get-GPPPassword` and `Find-GPOPassword` to find unsecured credentials in a compromised network group policy.(Citation: Mandiant FIN12 Oct 2021)

#### T1552.007 - Unsecured Credentials: Container API

Description:

Adversaries may gather credentials via APIs within a containers environment. APIs in these environments, such as the Docker API and Kubernetes APIs, allow a user to remotely manage their container resources and cluster components.(Citation: Docker API)(Citation: Kubernetes API)

An adversary may access the Docker API to collect logs that contain credentials to cloud, container, and various other resources in the environment.(Citation: Unit 42 Unsecured Docker Daemons) An adversary with sufficient permissions, such as via a pod's service account, may also use the Kubernetes API to retrieve credentials from the Kubernetes API server. These credentials may include those needed for Docker API authentication or secrets from Kubernetes cluster components.

Procedures:

- [S0683] Peirates: [Peirates](https://attack.mitre.org/software/S0683) can query the Kubernetes API for secrets.(Citation: Peirates GitHub)

#### T1552.008 - Unsecured Credentials: Chat Messages

Description:

Adversaries may directly collect unsecured credentials stored or passed through user communication services. Credentials may be sent and stored in user chat communication applications such as email, chat services like Slack or Teams, collaboration tools like Jira or Trello, and any other services that support user communication. Users may share various forms of credentials (such as usernames and passwords, API keys, or authentication tokens) on private or public corporate internal communications channels.

Rather than accessing the stored chat logs (i.e., [Credentials In Files](https://attack.mitre.org/techniques/T1552/001)), adversaries may directly access credentials within these services on the user endpoint, through servers hosting the services, or through administrator portals for cloud hosted services. Adversaries may also compromise integration tools like Slack Workflows to automatically search through messages to extract user credentials. These credentials may then be abused to perform follow-on activities such as lateral movement or privilege escalation (Citation: Slack Security Risks).

Procedures:

- [G1004] LAPSUS$: [LAPSUS$](https://attack.mitre.org/groups/G1004) has targeted various collaboration tools like Slack, Teams, JIRA, Confluence, and others to hunt for exposed credentials to support privilege escalation and lateral movement.(Citation: MSTIC DEV-0537 Mar 2022)


### T1555 - Credentials from Password Stores

Description:

Adversaries may search for common password storage locations to obtain user credentials.(Citation: F-Secure The Dukes) Passwords are stored in several places on a system, depending on the operating system or application holding the credentials. There are also specific applications and services that store passwords to make them easier for users to manage and maintain, such as password managers and cloud secrets vaults. Once credentials are obtained, they can be used to perform lateral movement and access restricted information.

Procedures:

- [G1001] HEXANE: [HEXANE](https://attack.mitre.org/groups/G1001) has run `cmdkey` on victim machines to identify stored credentials.(Citation: Kaspersky Lyceum October 2021)
- [S0484] Carberp: [Carberp](https://attack.mitre.org/software/S0484)'s passw.plug plugin can gather account information from multiple instant messaging, email, and social media services, as well as FTP, VNC, and VPN clients.(Citation: Prevx Carberp March 2011)
- [S0002] Mimikatz: [Mimikatz](https://attack.mitre.org/software/S0002) performs credential dumping to obtain account and password information useful in gaining access to additional systems and enterprise network resources. It contains functionality to acquire information about credentials in many ways, including from the credential vault and DPAPI.(Citation: Deply Mimikatz)(Citation: GitHub Mimikatz lsadump Module)(Citation: Directory Services Internals DPAPI Backup Keys Oct 2015)(Citation: NCSC Joint Report Public Tools)(Citation: Cobalt Strike Manual 4.3 November 2020)
- [S1207] XLoader: [XLoader](https://attack.mitre.org/software/S1207) can collect credentials stored in email clients.(Citation: Google XLoader 2017)(Citation: Netskope XLoader 2022)
- [S0447] Lokibot: [Lokibot](https://attack.mitre.org/software/S0447) has stolen credentials from multiple applications and data sources including Windows OS credentials, email clients, FTP, and SFTP clients.(Citation: Infoblox Lokibot January 2019)
- [S1146] MgBot: [MgBot](https://attack.mitre.org/software/S1146) includes modules for stealing stored credentials from Outlook and Foxmail email client software.(Citation: ESET EvasivePanda 2023)(Citation: Symantec Daggerfly 2023)
- [S1156] Manjusaka: [Manjusaka](https://attack.mitre.org/software/S1156) extracts credentials from the Windows Registry associated with Premiumsoft Navicat, a utility used to facilitate access to various database types.(Citation: Talos Manjusaka 2022)
- [G1017] Volt Typhoon: [Volt Typhoon](https://attack.mitre.org/groups/G1017) has attempted to obtain credentials from OpenSSH, realvnc, and PuTTY.(Citation: Joint Cybersecurity Advisory Volt Typhoon June 2023)
- [G0077] Leafminer: [Leafminer](https://attack.mitre.org/groups/G0077) used several tools for retrieving login and password information, including LaZagne.(Citation: Symantec Leafminer July 2018)
- [S0167] Matryoshka: [Matryoshka](https://attack.mitre.org/software/S0167) is capable of stealing Outlook passwords.(Citation: ClearSky Wilted Tulip July 2017)(Citation: CopyKittens Nov 2015)
- [G0038] Stealth Falcon: [Stealth Falcon](https://attack.mitre.org/groups/G0038) malware gathers passwords from multiple sources, including Windows Credential Vault and Outlook.(Citation: Citizen Lab Stealth Falcon May 2016)
- [S0050] CosmicDuke: [CosmicDuke](https://attack.mitre.org/software/S0050) collects user credentials, including passwords, for various programs including popular instant messaging applications and email clients as well as WLAN keys.(Citation: F-Secure The Dukes)
- [S0113] Prikormka: A module in [Prikormka](https://attack.mitre.org/software/S0113) collects passwords stored in applications installed on the victim.(Citation: ESET Operation Groundbait)
- [S0435] PLEAD: [PLEAD](https://attack.mitre.org/software/S0435) has the ability to steal saved passwords from Microsoft Outlook.(Citation: ESET PLEAD Malware July 2018)
- [G0087] APT39: [APT39](https://attack.mitre.org/groups/G0087) has used the Smartftp Password Decryptor tool to decrypt FTP passwords.(Citation: BitDefender Chafer May 2020)
- [G0120] Evilnum: [Evilnum](https://attack.mitre.org/groups/G0120) can collect email credentials from victims.(Citation: ESET EvilNum July 2020)
- [S1111] DarkGate: [DarkGate](https://attack.mitre.org/software/S1111) use Nirsoft Network Password Recovery or NetPass tools to steal stored RDP credentials in some malware versions.(Citation: Trellix Darkgate 2023)
- [S0198] NETWIRE: [NETWIRE](https://attack.mitre.org/software/S0198) can retrieve passwords from messaging and mail client applications.(Citation: Red Canary NETWIRE January 2020)
- [G0096] APT41: [APT41](https://attack.mitre.org/groups/G0096) has obtained information about accounts, lists of employees, and plaintext and hashed passwords from databases.(Citation: Rostovcev APT41 2021)
- [G0064] APT33: [APT33](https://attack.mitre.org/groups/G0064) has used a variety of publicly available tools like [LaZagne](https://attack.mitre.org/software/S0349) to gather credentials.(Citation: Symantec Elfin Mar 2019)(Citation: FireEye APT33 Guardrail)
- [G0069] MuddyWater: [MuddyWater](https://attack.mitre.org/groups/G0069) has performed credential dumping with [LaZagne](https://attack.mitre.org/software/S0349) and other tools, including by dumping passwords saved in victim email.(Citation: Unit 42 MuddyWater Nov 2017)(Citation: Symantec MuddyWater Dec 2018)(Citation: Trend Micro Muddy Water March 2021)
- [S0262] QuasarRAT: [QuasarRAT](https://attack.mitre.org/software/S0262) can obtain passwords from common FTP clients.(Citation: GitHub QuasarRAT)(Citation: Volexity Patchwork June 2018)
- [S0373] Astaroth: [Astaroth](https://attack.mitre.org/software/S0373) uses an external software known as NetPass to recover passwords. (Citation: Cybereason Astaroth Feb 2019)
- [S0331] Agent Tesla: [Agent Tesla](https://attack.mitre.org/software/S0331) has the ability to steal credentials from FTP clients and wireless profiles.(Citation: Malwarebytes Agent Tesla April 2020)
- [S0349] LaZagne: [LaZagne](https://attack.mitre.org/software/S0349) can obtain credentials from databases, mail, and WiFi across multiple platforms.(Citation: GitHub LaZagne Dec 2018)
- [S0138] OLDBAIT: [OLDBAIT](https://attack.mitre.org/software/S0138) collects credentials from several email clients.(Citation: FireEye APT28)
- [S0048] PinchDuke: [PinchDuke](https://attack.mitre.org/software/S0048) steals credentials from compromised hosts. [PinchDuke](https://attack.mitre.org/software/S0048)'s credential stealing functionality is believed to be based on the source code of the Pinch credential stealing malware (also known as LdPinch). Credentials targeted by [PinchDuke](https://attack.mitre.org/software/S0048) include ones associated with many sources such as The Bat!, Yahoo!, Mail.ru, Passport.Net, Google Talk, and Microsoft Outlook.(Citation: F-Secure The Dukes)
- [G0049] OilRig: [OilRig](https://attack.mitre.org/groups/G0049) has used credential dumping tools such as [LaZagne](https://attack.mitre.org/software/S0349) to steal credentials to accounts logged into the compromised system and to Outlook Web Access.(Citation: Unit42 OilRig Playbook 2023)(Citation: FireEye APT34 Webinar Dec 2017)(Citation: FireEye APT35 2018)(Citation: FireEye APT34 July 2019)
- [G0037] FIN6: [FIN6](https://attack.mitre.org/groups/G0037) has used the Stealer One credential stealer to target e-mail and file transfer utilities including FTP.(Citation: Visa FIN6 Feb 2019)
- [C0024] SolarWinds Compromise: During the [SolarWinds Compromise](https://attack.mitre.org/campaigns/C0024), [APT29](https://attack.mitre.org/groups/G0016) used account credentials they obtained to attempt access to Group Managed Service Account (gMSA) passwords.(Citation: Microsoft Deep Dive Solorigate January 2021)
- [G1026] Malteiro: [Malteiro](https://attack.mitre.org/groups/G1026) has obtained credentials from mail clients via NirSoft MailPassView.(Citation: SCILabs Malteiro 2021)
- [S1122] Mispadu: [Mispadu](https://attack.mitre.org/software/S1122) has obtained credentials from mail clients via NirSoft MailPassView.(Citation: SCILabs Malteiro 2021)(Citation: Segurança Informática URSA Sophisticated Loader 2020)(Citation: ESET Security Mispadu Facebook Ads 2019)
- [S0192] Pupy: [Pupy](https://attack.mitre.org/software/S0192) can use Lazagne for harvesting credentials.(Citation: GitHub Pupy)
- [S0378] PoshC2: [PoshC2](https://attack.mitre.org/software/S0378) can decrypt passwords stored in the RDCMan configuration file.(Citation: SecureWorks August 2019)
- [S0526] KGH_SPY: [KGH_SPY](https://attack.mitre.org/software/S0526) can collect credentials from WINSCP.(Citation: Cybereason Kimsuky November 2020)

#### T1555.001 - Credentials from Password Stores: Keychain

Description:

Adversaries may acquire credentials from Keychain. Keychain (or Keychain Services) is the macOS credential management system that stores account names, passwords, private keys, certificates, sensitive application data, payment data, and secure notes. There are three types of Keychains: Login Keychain, System Keychain, and Local Items (iCloud) Keychain. The default Keychain is the Login Keychain, which stores user passwords and information. The System Keychain stores items accessed by the operating system, such as items shared among users on a host. The Local Items (iCloud) Keychain is used for items synced with Apple’s iCloud service. 

Keychains can be viewed and edited through the Keychain Access application or using the command-line utility <code>security</code>. Keychain files are located in <code>~/Library/Keychains/</code>, <code>/Library/Keychains/</code>, and <code>/Network/Library/Keychains/</code>.(Citation: Keychain Services Apple)(Citation: Keychain Decryption Passware)(Citation: OSX Keychain Schaumann)

Adversaries may gather user credentials from Keychain storage/memory. For example, the command <code>security dump-keychain –d</code> will dump all Login Keychain credentials from <code>~/Library/Keychains/login.keychain-db</code>. Adversaries may also directly read Login Keychain credentials from the <code>~/Library/Keychains/login.keychain</code> file. Both methods require a password, where the default password for the Login Keychain is the current user’s password to login to the macOS host.(Citation: External to DA, the OS X Way)(Citation: Empire Keychain Decrypt)

Procedures:

- [S1185] LightSpy: [LightSpy](https://attack.mitre.org/software/S1185) performs an in-memory keychain query via `SecItemCopyMatching()` then formats the retrieved data as a JSON blob for exfiltration.(Citation: Huntress LightSpy macOS 2024)
- [S0690] Green Lambert: [Green Lambert](https://attack.mitre.org/software/S0690) can use Keychain Services API functions to find and collect passwords, such as `SecKeychainFindInternetPassword` and `SecKeychainItemCopyAttributesAndData`.(Citation: Objective See Green Lambert for OSX Oct 2021)(Citation: Glitch-Cat Green Lambert ATTCK Oct 2021)
- [S0279] Proton: [Proton](https://attack.mitre.org/software/S0279) gathers credentials in files for keychains.(Citation: objsee mac malware 2017)
- [S1016] MacMa: [MacMa](https://attack.mitre.org/software/S1016) can dump credentials from the macOS keychain.(Citation: ESET DazzleSpy Jan 2022)
- [S0349] LaZagne: [LaZagne](https://attack.mitre.org/software/S0349) can obtain credentials from macOS Keychains.(Citation: GitHub LaZagne Dec 2018)
- [S0274] Calisto: [Calisto](https://attack.mitre.org/software/S0274) collects Keychain storage data and copies those passwords/tokens to a file.(Citation: Securelist Calisto July 2018)(Citation: Symantec Calisto July 2018)
- [S1153] Cuckoo Stealer: [Cuckoo Stealer](https://attack.mitre.org/software/S1153) can capture files from a targeted user's keychain directory.(Citation: Kandji Cuckoo April 2024)
- [S0278] iKitten: [iKitten](https://attack.mitre.org/software/S0278) collects the keychains on the system.(Citation: objsee mac malware 2017)

#### T1555.002 - Credentials from Password Stores: Securityd Memory

Description:

An adversary with root access may gather credentials by reading `securityd`’s memory. `securityd` is a service/daemon responsible for implementing security protocols such as encryption and authorization.(Citation: Apple Dev SecurityD) A privileged adversary may be able to scan through `securityd`'s memory to find the correct sequence of keys to decrypt the user’s logon keychain. This may provide the adversary with various plaintext passwords, such as those for users, WiFi, mail, browsers, certificates, secure notes, etc.(Citation: OS X Keychain)(Citation: OSX Keydnap malware)

In OS X prior to El Capitan, users with root access can read plaintext keychain passwords of logged-in users because Apple’s keychain implementation allows these credentials to be cached so that users are not repeatedly prompted for passwords.(Citation: OS X Keychain)(Citation: External to DA, the OS X Way) Apple’s `securityd` utility takes the user’s logon password, encrypts it with PBKDF2, and stores this master key in memory. Apple also uses a set of keys and algorithms to encrypt the user’s password, but once the master key is found, an adversary need only iterate over the other values to unlock the final password.(Citation: OS X Keychain)

Procedures:

- [S0276] Keydnap: [Keydnap](https://attack.mitre.org/software/S0276) uses the keychaindump project to read securityd memory.(Citation: synack 2016 review)

#### T1555.003 - Credentials from Password Stores: Credentials from Web Browsers

Description:

Adversaries may acquire credentials from web browsers by reading files specific to the target browser.(Citation: Talos Olympic Destroyer 2018) Web browsers commonly save credentials such as website usernames and passwords so that they do not need to be entered manually in the future. Web browsers typically store the credentials in an encrypted format within a credential store; however, methods exist to extract plaintext credentials from web browsers.

For example, on Windows systems, encrypted credentials may be obtained from Google Chrome by reading a database file, <code>AppData\Local\Google\Chrome\User Data\Default\Login Data</code> and executing a SQL query: <code>SELECT action_url, username_value, password_value FROM logins;</code>. The plaintext password can then be obtained by passing the encrypted credentials to the Windows API function <code>CryptUnprotectData</code>, which uses the victim’s cached logon credentials as the decryption key.(Citation: Microsoft CryptUnprotectData April 2018)
 
Adversaries have executed similar procedures for common web browsers such as FireFox, Safari, Edge, etc.(Citation: Proofpoint Vega Credential Stealer May 2018)(Citation: FireEye HawkEye Malware July 2017) Windows stores Internet Explorer and Microsoft Edge credentials in Credential Lockers managed by the [Windows Credential Manager](https://attack.mitre.org/techniques/T1555/004).

Adversaries may also acquire credentials by searching web browser process memory for patterns that commonly match credentials.(Citation: GitHub Mimikittenz July 2016)

After acquiring credentials from web browsers, adversaries may attempt to recycle the credentials across different systems and/or accounts in order to expand access. This can result in significantly furthering an adversary's objective in cases where credentials gained from web browsers overlap with privileged accounts (e.g. domain administrator).

Procedures:

- [S0385] njRAT: [njRAT](https://attack.mitre.org/software/S0385) has a module that steals passwords saved in victim web browsers.(Citation: Fidelis njRAT June 2013)(Citation: Trend Micro njRAT 2018)(Citation: Citizen Lab Group5)
- [S0089] BlackEnergy: [BlackEnergy](https://attack.mitre.org/software/S0089) has used a plug-in to gather credentials from web browsers including FireFox, Google Chrome, and Internet Explorer.(Citation: F-Secure BlackEnergy 2014)(Citation: Securelist BlackEnergy Nov 2014)
- [S0132] H1N1: [H1N1](https://attack.mitre.org/software/S0132) dumps usernames and passwords from Firefox, Internet Explorer, and Outlook.(Citation: Cisco H1N1 Part 2)
- [S1122] Mispadu: [Mispadu](https://attack.mitre.org/software/S1122) can steal credentials from Google Chrome.(Citation: SCILabs Malteiro 2021)(Citation: ESET Security Mispadu Facebook Ads 2019)(Citation: Metabase Q Mispadu Trojan 2023)
- [S0434] Imminent Monitor: [Imminent Monitor](https://attack.mitre.org/software/S0434) has a PasswordRecoveryPacket module for recovering browser passwords.(Citation: QiAnXin APT-C-36 Feb2019)
- [S0365] Olympic Destroyer: [Olympic Destroyer](https://attack.mitre.org/software/S0365) contains a module that tries to obtain stored credentials from web browsers.(Citation: Talos Olympic Destroyer 2018)
- [S0528] Javali: [Javali](https://attack.mitre.org/software/S0528) can capture login credentials from open browsers including Firefox, Chrome, Internet Explorer, and Edge.(Citation: Securelist Brazilian Banking Malware July 2020)
- [S0492] CookieMiner: [CookieMiner](https://attack.mitre.org/software/S0492) can steal saved usernames and passwords in Chrome as well as credit card credentials.(Citation: Unit42 CookieMiner Jan 2019)
- [G0040] Patchwork: [Patchwork](https://attack.mitre.org/groups/G0040) dumped the login data database from <code>\AppData\Local\Google\Chrome\User Data\Default\Login Data</code>.(Citation: Cymmetria Patchwork)
- [S1042] SUGARDUMP: [SUGARDUMP](https://attack.mitre.org/software/S1042) variants have harvested credentials from browsers such as Firefox, Chrome, Opera, and Edge.(Citation: Mandiant UNC3890 Aug 2022)
- [S1213] Lumma Stealer: [Lumma Stealer](https://attack.mitre.org/software/S1213) has gathered credential and other information from multiple browsers.(Citation: Cybereason LumaStealer Undated)(Citation: Fortinet LummaStealer 2024)(Citation: TrendMicro LummaStealer 2025)
- [G0096] APT41: [APT41](https://attack.mitre.org/groups/G0096) used BrowserGhost, a tool designed to obtain credentials from browsers, to retrieve information from password stores.(Citation: Rostovcev APT41 2021)
- [S0670] WarzoneRAT: [WarzoneRAT](https://attack.mitre.org/software/S0670) has the capability to grab passwords from numerous web browsers as well as from Outlook and Thunderbird email clients.(Citation: Check Point Warzone Feb 2020)(Citation: Uptycs Warzone UAC Bypass November 2020)
- [S1201] TRANSLATEXT: [TRANSLATEXT](https://attack.mitre.org/software/S1201) has stolen credentials stored in Chrome.(Citation: Zscaler Kimsuky TRANSLATEXT)
- [G0128] ZIRCONIUM: [ZIRCONIUM](https://attack.mitre.org/groups/G0128) has used a tool to steal credentials from installed web browsers including Microsoft Internet Explorer and Google Chrome.(Citation: Zscaler APT31 Covid-19 October 2020)
- [S0356] KONNI: [KONNI](https://attack.mitre.org/software/S0356) can steal profiles (containing credential information) from Firefox, Chrome, and Opera.(Citation: Talos Konni May 2017)
- [G1026] Malteiro: [Malteiro](https://attack.mitre.org/groups/G1026) has stolen credentials stored in the victim’s browsers via software tool NirSoft WebBrowserPassView.(Citation: SCILabs Malteiro 2021)
- [C0024] SolarWinds Compromise: During the [SolarWinds Compromise](https://attack.mitre.org/campaigns/C0024), [APT29](https://attack.mitre.org/groups/G0016) stole users' saved passwords from Chrome.(Citation: CrowdStrike StellarParticle January 2022)
- [S0240] ROKRAT: [ROKRAT](https://attack.mitre.org/software/S0240) can steal credentials stored in Web browsers by querying the sqlite database.(Citation: Talos Group123)
- [S0262] QuasarRAT: [QuasarRAT](https://attack.mitre.org/software/S0262) can obtain passwords from common web browsers.(Citation: GitHub QuasarRAT)(Citation: Volexity Patchwork June 2018)
- [G0022] APT3: [APT3](https://attack.mitre.org/groups/G0022) has used tools to dump passwords from browsers.(Citation: Symantec Buckeye)
- [S0349] LaZagne: [LaZagne](https://attack.mitre.org/software/S0349) can obtain credentials from web browsers such as Google Chrome, Internet Explorer, and Firefox.(Citation: GitHub LaZagne Dec 2018)
- [G0064] APT33: [APT33](https://attack.mitre.org/groups/G0064) has used a variety of publicly available tools like [LaZagne](https://attack.mitre.org/software/S0349) to gather credentials.(Citation: Symantec Elfin Mar 2019)(Citation: FireEye APT33 Guardrail)
- [S0153] RedLeaves: [RedLeaves](https://attack.mitre.org/software/S0153) can gather browser usernames and passwords.(Citation: Accenture Hogfish April 2018)
- [G0038] Stealth Falcon: [Stealth Falcon](https://attack.mitre.org/groups/G0038) malware gathers passwords from multiple sources, including Internet Explorer, Firefox, and Chrome.(Citation: Citizen Lab Stealth Falcon May 2016)
- [S1146] MgBot: [MgBot](https://attack.mitre.org/software/S1146) includes modules for stealing credentials from various browsers and applications, including Chrome, Opera, Firefox, Foxmail, QQBrowser, FileZilla, and WinSCP.(Citation: ESET EvasivePanda 2023)(Citation: Symantec Daggerfly 2023)
- [S0436] TSCookie: [TSCookie](https://attack.mitre.org/software/S0436) has the ability to steal saved passwords from the Internet Explorer, Edge, Firefox, and Chrome browsers.(Citation: JPCert TSCookie March 2018)
- [S0226] Smoke Loader: [Smoke Loader](https://attack.mitre.org/software/S0226) searches for credentials stored from web browsers.(Citation: Talos Smoke Loader July 2018)
- [S0331] Agent Tesla: [Agent Tesla](https://attack.mitre.org/software/S0331) can gather credentials from a number of browsers.(Citation: Bitdefender Agent Tesla April 2020)
- [S0192] Pupy: [Pupy](https://attack.mitre.org/software/S0192) can use Lazagne for harvesting credentials.(Citation: GitHub Pupy)
- [S0409] Machete: [Machete](https://attack.mitre.org/software/S0409) collects stored credentials from several web browsers.(Citation: ESET Machete July 2019)
- [S0344] Azorult: [Azorult](https://attack.mitre.org/software/S0344) can steal credentials from the victim's browser.(Citation: Unit42 Azorult Nov 2018)
- [S0113] Prikormka: A module in [Prikormka](https://attack.mitre.org/software/S0113) gathers logins and passwords stored in applications on the victims, including Google Chrome, Mozilla Firefox, and several other browsers.(Citation: ESET Operation Groundbait)
- [S0094] Trojan.Karagany: [Trojan.Karagany](https://attack.mitre.org/software/S0094) can steal data and credentials from browsers.(Citation: Secureworks Karagany July 2019)
- [S1156] Manjusaka: [Manjusaka](https://attack.mitre.org/software/S1156) gathers credentials from Chromium-based browsers.(Citation: Talos Manjusaka 2022)
- [S0526] KGH_SPY: [KGH_SPY](https://attack.mitre.org/software/S0526) has the ability to steal data from the Chrome, Edge, Firefox, Thunderbird, and Opera browsers.(Citation: Cybereason Kimsuky November 2020)
- [G0077] Leafminer: [Leafminer](https://attack.mitre.org/groups/G0077) used several tools for retrieving login and password information, including LaZagne.(Citation: Symantec Leafminer July 2018)
- [G0067] APT37: [APT37](https://attack.mitre.org/groups/G0067) has used a credential stealer known as ZUMKONG that can harvest usernames and passwords stored in browsers.(Citation: FireEye APT37 Feb 2018)
- [S0050] CosmicDuke: [CosmicDuke](https://attack.mitre.org/software/S0050) collects user credentials, including passwords, for various programs including Web browsers.(Citation: F-Secure The Dukes)
- [G0034] Sandworm Team: [Sandworm Team](https://attack.mitre.org/groups/G0034)'s CredRaptor tool can collect saved passwords from various internet browsers.(Citation: ESET Telebots Dec 2016)
- [S0138] OLDBAIT: [OLDBAIT](https://attack.mitre.org/software/S0138) collects credentials from Internet Explorer, Mozilla Firefox, and Eudora.(Citation: FireEye APT28)
- [S0629] RainyDay: [RainyDay](https://attack.mitre.org/software/S0629) can use tools to collect credentials from web browsers.(Citation: Bitdefender Naikon April 2021)
- [S0002] Mimikatz: [Mimikatz](https://attack.mitre.org/software/S0002) performs credential dumping to obtain account and password information useful in gaining access to additional systems and enterprise network resources. It contains functionality to acquire information about credentials in many ways, including from DPAPI.(Citation: Deply Mimikatz)(Citation: GitHub Mimikatz lsadump Module)(Citation: Directory Services Internals DPAPI Backup Keys Oct 2015)(Citation: NCSC Joint Report Public Tools)
- [S0367] Emotet: [Emotet](https://attack.mitre.org/software/S0367) has been observed dropping browser password grabber modules. (Citation: Trend Micro Emotet Jan 2019)(Citation: IBM IcedID November 2017)
- [S1148] Raccoon Stealer: [Raccoon Stealer](https://attack.mitre.org/software/S1148) collects passwords, cookies, and autocomplete information from various popular web browsers.(Citation: Sekoia Raccoon2 2022)
- [G0069] MuddyWater: [MuddyWater](https://attack.mitre.org/groups/G0069) has run tools including Browser64 to steal passwords saved in victim web browsers.(Citation: Symantec MuddyWater Dec 2018)(Citation: Trend Micro Muddy Water March 2021)
- [S0283] jRAT: [jRAT](https://attack.mitre.org/software/S0283) can capture passwords from common web browsers such as Internet Explorer, Google Chrome, and Firefox.(Citation: Kaspersky Adwind Feb 2016)
- [S0692] SILENTTRINITY: [SILENTTRINITY](https://attack.mitre.org/software/S0692) can collect clear text web credentials for Internet Explorer/Edge.(Citation: GitHub SILENTTRINITY Modules July 2019)
- [S0198] NETWIRE: [NETWIRE](https://attack.mitre.org/software/S0198) has the ability to steal credentials from web browsers including Internet Explorer, Opera, Yandex, and Chrome.(Citation: FireEye NETWIRE March 2019)(Citation: Red Canary NETWIRE January 2020)(Citation: Proofpoint NETWIRE December 2020)
- [S0530] Melcoz: [Melcoz](https://attack.mitre.org/software/S0530) has the ability to steal credentials from web browsers.(Citation: Securelist Brazilian Banking Malware July 2020)
- [S1207] XLoader: [XLoader](https://attack.mitre.org/software/S1207) can gather credentials from several web browsers.(Citation: Zscaler XLoader 2025)(Citation: Google XLoader 2017)(Citation: Netskope XLoader 2022)
- [G1004] LAPSUS$: [LAPSUS$](https://attack.mitre.org/groups/G1004) has obtained passwords and session tokens with the use of the Redline password stealer.(Citation: MSTIC DEV-0537 Mar 2022)
- [S0657] BLUELIGHT: [BLUELIGHT](https://attack.mitre.org/software/S0657) can collect passwords stored in web browers, including Internet Explorer, Edge, Chrome, and Naver Whale.(Citation: Volexity InkySquid BLUELIGHT August 2021)
- [S0144] ChChes: [ChChes](https://attack.mitre.org/software/S0144) steals credentials stored inside Internet Explorer.(Citation: PWC Cloud Hopper Technical Annex April 2017)
- [S0279] Proton: [Proton](https://attack.mitre.org/software/S0279) gathers credentials for Google Chrome.(Citation: objsee mac malware 2017)
- [G1001] HEXANE: [HEXANE](https://attack.mitre.org/groups/G1001) has used a [Mimikatz](https://attack.mitre.org/software/S0002)-based tool and a PowerShell script to steal passwords from Google Chrome.(Citation: Kaspersky Lyceum October 2021)
- [G0092] TA505: [TA505](https://attack.mitre.org/groups/G0092) has used malware to gather credentials from Internet Explorer.(Citation: Proofpoint TA505 Sep 2017)
- [G0021] Molerats: [Molerats](https://attack.mitre.org/groups/G0021) used the public tool BrowserPasswordDump10 to dump passwords saved in browsers on victims.(Citation: DustySky)
- [S0130] Unknown Logger: [Unknown Logger](https://attack.mitre.org/software/S0130) is capable of stealing usernames and passwords from browsers on the victim machine.(Citation: Forcepoint Monsoon)
- [G0130] Ajax Security Team: [Ajax Security Team](https://attack.mitre.org/groups/G0130) has used FireMalv custom-developed malware, which collected passwords from the Firefox browser storage.(Citation: Check Point Rocket Kitten)
- [G0100] Inception: [Inception](https://attack.mitre.org/groups/G0100) used a browser plugin to steal passwords and sessions from Internet Explorer, Chrome, Opera, Firefox, Torch, and Yandex.(Citation: Symantec Inception Framework March 2018)
- [S0093] Backdoor.Oldrea: Some [Backdoor.Oldrea](https://attack.mitre.org/software/S0093) samples contain a publicly available Web browser password recovery tool.(Citation: Symantec Dragonfly)
- [G1017] Volt Typhoon: [Volt Typhoon](https://attack.mitre.org/groups/G1017) has targeted network administrator browser data including browsing history and stored credentials.(Citation: CISA AA24-038A PRC Critical Infrastructure February 2024)
- [G0094] Kimsuky: [Kimsuky](https://attack.mitre.org/groups/G0094) has used browser extensions including Google Chrome to steal passwords and cookies from browsers. [Kimsuky](https://attack.mitre.org/groups/G0094) has also used Nirsoft's WebBrowserPassView tool to dump the passwords obtained from victims.(Citation: Zdnet Kimsuky Dec 2018)(Citation: CISA AA20-301A Kimsuky)(Citation: Netscout Stolen Pencil Dec 2018)(Citation: Talos Kimsuky Nov 2021)
- [S0363] Empire: [Empire](https://attack.mitre.org/software/S0363) can use modules that extract passwords from common web browsers such as Firefox and Chrome.(Citation: Github PowerShell Empire)
- [S0161] XAgentOSX: [XAgentOSX](https://attack.mitre.org/software/S0161) contains the getFirefoxPassword function to attempt to locate Firefox passwords.(Citation: XAgentOSX 2017)
- [S0681] Lizar: [Lizar](https://attack.mitre.org/software/S0681) has a module to collect usernames and passwords stored in browsers.(Citation: BiZone Lizar May 2021)
- [S0048] PinchDuke: [PinchDuke](https://attack.mitre.org/software/S0048) steals credentials from compromised hosts. [PinchDuke](https://attack.mitre.org/software/S0048)'s credential stealing functionality is believed to be based on the source code of the Pinch credential stealing malware (also known as LdPinch). Credentials targeted by [PinchDuke](https://attack.mitre.org/software/S0048) include ones associated with many sources such as Netscape Navigator, Mozilla Firefox, Mozilla Thunderbird, and Internet Explorer. (Citation: F-Secure The Dukes)
- [G0049] OilRig: [OilRig](https://attack.mitre.org/groups/G0049) has used credential dumping tools such as [LaZagne](https://attack.mitre.org/software/S0349) to steal credentials to accounts logged into the compromised system and to Outlook Web Access.(Citation: Unit42 OilRig Playbook 2023)(Citation: FireEye APT34 Webinar Dec 2017)(Citation: FireEye APT35 2018)(Citation: FireEye APT34 July 2019) [OilRig](https://attack.mitre.org/groups/G0049) has also used tool named PICKPOCKET to dump passwords from web browsers.(Citation: FireEye APT34 July 2019)
- [G1039] RedCurl: [RedCurl](https://attack.mitre.org/groups/G1039) used [LaZagne](https://attack.mitre.org/software/S0349) to obtain passwords from web browsers.(Citation: group-ib_redcurl1)(Citation: group-ib_redcurl2)
- [S0387] KeyBoy: [KeyBoy](https://attack.mitre.org/software/S0387) attempts to collect passwords from browsers.(Citation: Rapid7 KeyBoy Jun 2013)
- [S0531] Grandoreiro: [Grandoreiro](https://attack.mitre.org/software/S0531) can steal cookie data and credentials from Google Chrome.(Citation: IBM Grandoreiro April 2020)(Citation: ESET Grandoreiro April 2020)
- [S0650] QakBot: [QakBot](https://attack.mitre.org/software/S0650) has collected usernames and passwords from Firefox and Chrome.(Citation: Kaspersky QakBot September 2021)
- [S0115] Crimson: [Crimson](https://attack.mitre.org/software/S0115) contains a module to steal credentials from Web browsers on the victim machine.(Citation: Proofpoint Operation Transparent Tribe March 2016)(Citation: Kaspersky Transparent Tribe August 2020)
- [G0037] FIN6: [FIN6](https://attack.mitre.org/groups/G0037) has used the Stealer One credential stealer to target web browsers.(Citation: Visa FIN6 Feb 2019)
- [S0266] TrickBot: [TrickBot](https://attack.mitre.org/software/S0266) can obtain passwords stored in files from web browsers such as Chrome, Firefox, Internet Explorer, and Microsoft Edge, sometimes using [esentutl](https://attack.mitre.org/software/S0404).(Citation: Trend Micro Trickbot Nov 2018)(Citation: Cyberreason Anchor December 2019)(Citation: Bitdefender Trickbot VNC module Whitepaper 2021)
- [S0435] PLEAD: [PLEAD](https://attack.mitre.org/software/S0435) can harvest saved credentials from browsers such as Google Chrome, Microsoft Internet Explorer, and Mozilla Firefox.(Citation: TrendMicro BlackTech June 2017)(Citation: ESET PLEAD Malware July 2018)
- [S0428] PoetRAT: [PoetRAT](https://attack.mitre.org/software/S0428) has used a Python tool named Browdec.exe to steal browser credentials.(Citation: Talos PoetRAT April 2020)
- [S0631] Chaes: [Chaes](https://attack.mitre.org/software/S0631) can steal login credentials and stored financial information from the browser.(Citation: Cybereason Chaes Nov 2020)
- [S0484] Carberp: [Carberp](https://attack.mitre.org/software/S0484)'s passw.plug plugin can gather passwords saved in Opera, Internet Explorer, Safari, Firefox, and Chrome.(Citation: Prevx Carberp March 2011)
- [G1044] APT42: [APT42](https://attack.mitre.org/groups/G1044) has used custom malware to steal credentials.(Citation: Mandiant APT42-charms)
- [S0251] Zebrocy: [Zebrocy](https://attack.mitre.org/software/S0251) has the capability to upload dumper tools that extract credentials from web browsers and store them in database files.(Citation: ESET Zebrocy May 2019)
- [C0044] Juicy Mix: During [Juicy Mix](https://attack.mitre.org/campaigns/C0044), [OilRig](https://attack.mitre.org/groups/G0049) used the CDumper (Chrome browser) and EDumper (Edge browser) to collect credentials.(Citation: ESET OilRig Campaigns Sep 2023)
- [S0447] Lokibot: [Lokibot](https://attack.mitre.org/software/S0447) has demonstrated the ability to steal credentials from multiple applications and data sources including Safari and the Chromium and Mozilla Firefox-based web browsers.(Citation: Infoblox Lokibot January 2019)

#### T1555.004 - Credentials from Password Stores: Windows Credential Manager

Description:

Adversaries may acquire credentials from the Windows Credential Manager. The Credential Manager stores credentials for signing into websites, applications, and/or devices that request authentication through NTLM or Kerberos in Credential Lockers (previously known as Windows Vaults).(Citation: Microsoft Credential Manager store)(Citation: Microsoft Credential Locker)

The Windows Credential Manager separates website credentials from application or network credentials in two lockers. As part of [Credentials from Web Browsers](https://attack.mitre.org/techniques/T1555/003), Internet Explorer and Microsoft Edge website credentials are managed by the Credential Manager and are stored in the Web Credentials locker. Application and network credentials are stored in the Windows Credentials locker.

Credential Lockers store credentials in encrypted `.vcrd` files, located under `%Systemdrive%\Users\\[Username]\AppData\Local\Microsoft\\[Vault/Credentials]\`. The encryption key can be found in a file named <code>Policy.vpol</code>, typically located in the same folder as the credentials.(Citation: passcape Windows Vault)(Citation: Malwarebytes The Windows Vault)

Adversaries may list credentials managed by the Windows Credential Manager through several mechanisms. <code>vaultcmd.exe</code> is a native Windows executable that can be used to enumerate credentials stored in the Credential Locker through a command-line interface. Adversaries may also gather credentials by directly reading files located inside of the Credential Lockers. Windows APIs, such as <code>CredEnumerateA</code>, may also be absued to list credentials managed by the Credential Manager.(Citation: Microsoft CredEnumerate)(Citation: Delpy Mimikatz Crendential Manager)

Adversaries may also obtain credentials from credential backups. Credential backups and restorations may be performed by running <code>rundll32.exe keymgr.dll KRShowKeyMgr</code> then selecting the “Back up...” button on the “Stored User Names and Passwords” GUI.

Password recovery tools may also obtain plain text passwords from the Credential Manager.(Citation: Malwarebytes The Windows Vault)

Procedures:

- [G0049] OilRig: [OilRig](https://attack.mitre.org/groups/G0049) has used credential dumping tool named VALUEVAULT to steal credentials from the Windows Credential Manager.(Citation: FireEye APT34 July 2019)
- [G0038] Stealth Falcon: [Stealth Falcon](https://attack.mitre.org/groups/G0038) malware gathers passwords from the Windows Credential Vault.(Citation: Citizen Lab Stealth Falcon May 2016)
- [S0476] Valak: [Valak](https://attack.mitre.org/software/S0476) can use a .NET compiled module named exchgrabber to enumerate credentials from the Credential Manager.(Citation: SentinelOne Valak June 2020)
- [G0010] Turla: [Turla](https://attack.mitre.org/groups/G0010) has gathered credentials from the Windows Credential Manager tool.(Citation: Symantec Waterbug Jun 2019)
- [S0349] LaZagne: [LaZagne](https://attack.mitre.org/software/S0349) can obtain credentials from Vault files.(Citation: GitHub LaZagne Dec 2018)
- [S0681] Lizar: [Lizar](https://attack.mitre.org/software/S0681) has a plugin that can retrieve credentials from Internet Explorer and Microsoft Edge using `vaultcmd.exe` and another that can collect RDP access credentials using the `CredEnumerateW` function.(Citation: BiZone Lizar May 2021)
- [S0240] ROKRAT: [ROKRAT](https://attack.mitre.org/software/S0240) can steal credentials by leveraging the Windows Vault mechanism.(Citation: Talos Group123)
- [S0629] RainyDay: [RainyDay](https://attack.mitre.org/software/S0629) can use the QuarksPwDump tool to obtain local passwords and domain cached credentials.(Citation: Bitdefender Naikon April 2021)
- [S0692] SILENTTRINITY: [SILENTTRINITY](https://attack.mitre.org/software/S0692) can gather Windows Vault credentials.(Citation: GitHub SILENTTRINITY Modules July 2019)
- [C0044] Juicy Mix: During [Juicy Mix](https://attack.mitre.org/campaigns/C0044), [OilRig](https://attack.mitre.org/groups/G0049) used a Windows Credential Manager stealer for credential access.(Citation: ESET OilRig Campaigns Sep 2023)
- [S0002] Mimikatz: [Mimikatz](https://attack.mitre.org/software/S0002) contains functionality to acquire credentials from the Windows Credential Manager.(Citation: Delpy Mimikatz Crendential Manager)
- [S0526] KGH_SPY: [KGH_SPY](https://attack.mitre.org/software/S0526) can collect credentials from the Windows Credential Manager.(Citation: Cybereason Kimsuky November 2020)
- [S0194] PowerSploit: [PowerSploit](https://attack.mitre.org/software/S0194) contains a collection of Exfiltration modules that can harvest credentials from Windows vault credential objects.(Citation: GitHub PowerSploit May 2012)(Citation: PowerSploit Documentation)
- [G0102] Wizard Spider: [Wizard Spider](https://attack.mitre.org/groups/G0102) has used PowerShell cmdlet `Invoke-WCMDump` to enumerate Windows credentials in the Credential Manager in a compromised network.(Citation: Mandiant FIN12 Oct 2021)

#### T1555.005 - Credentials from Password Stores: Password Managers

Description:

Adversaries may acquire user credentials from third-party password managers.(Citation: ise Password Manager February 2019) Password managers are applications designed to store user credentials, normally in an encrypted database. Credentials are typically accessible after a user provides a master password that unlocks the database. After the database is unlocked, these credentials may be copied to memory. These databases can be stored as files on disk.(Citation: ise Password Manager February 2019)

Adversaries may acquire user credentials from password managers by extracting the master password and/or plain-text credentials from memory.(Citation: FoxIT Wocao December 2019)(Citation: Github KeeThief) Adversaries may extract credentials from memory via [Exploitation for Credential Access](https://attack.mitre.org/techniques/T1212).(Citation: NVD CVE-2019-3610)
 Adversaries may also try brute forcing via [Password Guessing](https://attack.mitre.org/techniques/T1110/001) to obtain the master password of a password manager.(Citation: Cyberreason Anchor December 2019)

Procedures:

- [C0014] Operation Wocao: During [Operation Wocao](https://attack.mitre.org/campaigns/C0014), threat actors accessed and collected credentials from password managers.(Citation: FoxIT Wocao December 2019)
- [G0027] Threat Group-3390: [Threat Group-3390](https://attack.mitre.org/groups/G0027) obtained a KeePass database from a compromised host.(Citation: Trend Micro DRBControl February 2020)
- [G0119] Indrik Spider: [Indrik Spider](https://attack.mitre.org/groups/G0119) has accessed and exported passwords from password managers.(Citation: Mandiant_UNC2165)
- [G0117] Fox Kitten: [Fox Kitten](https://attack.mitre.org/groups/G0117) has used scripts to access credential information from the KeePass database.(Citation: CISA AA20-259A Iran-Based Actor September 2020)
- [S0652] MarkiRAT: [MarkiRAT](https://attack.mitre.org/software/S0652) can gather information from the Keepass password manager.(Citation: Kaspersky Ferocious Kitten Jun 2021)
- [S0279] Proton: [Proton](https://attack.mitre.org/software/S0279) gathers credentials in files for 1password.(Citation: objsee mac malware 2017)
- [S0266] TrickBot: [TrickBot](https://attack.mitre.org/software/S0266) can steal passwords from the KeePass open source password manager.(Citation: Cyberreason Anchor December 2019)
- [G1004] LAPSUS$: [LAPSUS$](https://attack.mitre.org/groups/G1004) has accessed local password managers and databases to obtain further credentials from a compromised network.(Citation: NCC Group LAPSUS Apr 2022)

#### T1555.006 - Credentials from Password Stores: Cloud Secrets Management Stores

Description:

Adversaries may acquire credentials from cloud-native secret management solutions such as AWS Secrets Manager, GCP Secret Manager, Azure Key Vault, and Terraform Vault.  

Secrets managers support the secure centralized management of passwords, API keys, and other credential material. Where secrets managers are in use, cloud services can dynamically acquire credentials via API requests rather than accessing secrets insecurely stored in plain text files or environment variables.  

If an adversary is able to gain sufficient privileges in a cloud environment – for example, by obtaining the credentials of high-privileged [Cloud Accounts](https://attack.mitre.org/techniques/T1078/004) or compromising a service that has permission to retrieve secrets – they may be able to request secrets from the secrets manager. This can be accomplished via commands such as `get-secret-value` in AWS, `gcloud secrets describe` in GCP, and `az key vault secret show` in Azure.(Citation: Permiso Scattered Spider 2023)(Citation: Sysdig ScarletEel 2.0 2023)(Citation: AWS Secrets Manager)(Citation: Google Cloud Secrets)(Citation: Microsoft Azure Key Vault)

**Note:** this technique is distinct from [Cloud Instance Metadata API](https://attack.mitre.org/techniques/T1552/005) in that the credentials are being directly requested from the cloud secrets manager, rather than through the medium of the instance metadata API.

Procedures:

- [G0125] HAFNIUM: [HAFNIUM](https://attack.mitre.org/groups/G0125) has moved laterally from on-premises environments to steal passwords from Azure key vaults.(Citation: Microsoft Silk Typhoon MAR 2025)
- [S1091] Pacu: [Pacu](https://attack.mitre.org/software/S1091) can retrieve secrets from the AWS Secrets Manager via the enum_secrets module.(Citation: GitHub Pacu)


### T1556 - Modify Authentication Process

Description:

Adversaries may modify authentication mechanisms and processes to access user credentials or enable otherwise unwarranted access to accounts. The authentication process is handled by mechanisms, such as the Local Security Authentication Server (LSASS) process and the Security Accounts Manager (SAM) on Windows, pluggable authentication modules (PAM) on Unix-based systems, and authorization plugins on MacOS systems, responsible for gathering, storing, and validating credentials. By modifying an authentication process, an adversary may be able to authenticate to a service or system without using [Valid Accounts](https://attack.mitre.org/techniques/T1078).

Adversaries may maliciously modify a part of this process to either reveal credentials or bypass authentication mechanisms. Compromised credentials or access may be used to bypass access controls placed on various resources on systems within the network and may even be used for persistent access to remote systems and externally available services, such as VPNs, Outlook Web Access and remote desktop.

Procedures:

- [S0377] Ebury: [Ebury](https://attack.mitre.org/software/S0377) can intercept private keys using a trojanized <code>ssh-add</code> function.(Citation: ESET Ebury Feb 2014)
- [S0692] SILENTTRINITY: [SILENTTRINITY](https://attack.mitre.org/software/S0692) can create a backdoor in KeePass using a malicious config file and in TortoiseSVN using a registry hook.(Citation: GitHub SILENTTRINITY Modules July 2019)
- [S0487] Kessel: [Kessel](https://attack.mitre.org/software/S0487) has trojanized the <sode>ssh_login</code> and <code>user-auth_pubkey</code> functions to steal plaintext credentials.(Citation: ESET ForSSHe December 2018)
- [C0046] ArcaneDoor: [ArcaneDoor](https://attack.mitre.org/campaigns/C0046) included modification of the AAA process to bypass authentication mechanisms.(Citation: Cisco ArcaneDoor 2024)
- [G1016] FIN13: [FIN13](https://attack.mitre.org/groups/G1016) has replaced legitimate KeePass binaries with trojanized versions to collect passwords from numerous applications.(Citation: Mandiant FIN13 Aug 2022)

#### T1556.001 - Modify Authentication Process: Domain Controller Authentication

Description:

Adversaries may patch the authentication process on a domain controller to bypass the typical authentication mechanisms and enable access to accounts. 

Malware may be used to inject false credentials into the authentication process on a domain controller with the intent of creating a backdoor used to access any user’s account and/or credentials (ex: [Skeleton Key](https://attack.mitre.org/software/S0007)). Skeleton key works through a patch on an enterprise domain controller authentication process (LSASS) with credentials that adversaries may use to bypass the standard authentication system. Once patched, an adversary can use the injected password to successfully authenticate as any domain user account (until the the skeleton key is erased from memory by a reboot of the domain controller). Authenticated access may enable unfettered access to hosts and/or resources within single-factor authentication environments.(Citation: Dell Skeleton)

Procedures:

- [G0114] Chimera: [Chimera](https://attack.mitre.org/groups/G0114)'s malware has altered the NTLM authentication program on domain controllers to allow [Chimera](https://attack.mitre.org/groups/G0114) to login without a valid credential.(Citation: Cycraft Chimera April 2020)
- [S0007] Skeleton Key: [Skeleton Key](https://attack.mitre.org/software/S0007) is used to patch an enterprise domain controller authentication process with a backdoor password. It allows adversaries to bypass the standard authentication system to use a defined password for all accounts authenticating to that domain controller.(Citation: Dell Skeleton)

#### T1556.002 - Modify Authentication Process: Password Filter DLL

Description:

Adversaries may register malicious password filter dynamic link libraries (DLLs) into the authentication process to acquire user credentials as they are validated. 

Windows password filters are password policy enforcement mechanisms for both domain and local accounts. Filters are implemented as DLLs containing a method to validate potential passwords against password policies. Filter DLLs can be positioned on local computers for local accounts and/or domain controllers for domain accounts. Before registering new passwords in the Security Accounts Manager (SAM), the Local Security Authority (LSA) requests validation from each registered filter. Any potential changes cannot take effect until every registered filter acknowledges validation. 

Adversaries can register malicious password filters to harvest credentials from local computers and/or entire domains. To perform proper validation, filters must receive plain-text credentials from the LSA. A malicious password filter would receive these plain-text credentials every time a password request is made.(Citation: Carnal Ownage Password Filters Sept 2013)

Procedures:

- [S0125] Remsec: [Remsec](https://attack.mitre.org/software/S0125) harvests plain-text credentials as a password filter registered on domain controllers.(Citation: Kaspersky ProjectSauron Full Report)
- [G0049] OilRig: [OilRig](https://attack.mitre.org/groups/G0049) has registered a password filter DLL in order to drop malware.(Citation: Trend Micro Earth Simnavaz October 2024)
- [G0041] Strider: [Strider](https://attack.mitre.org/groups/G0041) has registered its persistence module on domain controllers as a Windows LSA (Local System Authority) password filter to acquire credentials any time a domain, local user, or administrator logs in or changes a password.(Citation: Kaspersky ProjectSauron Full Report)

#### T1556.003 - Modify Authentication Process: Pluggable Authentication Modules

Description:

Adversaries may modify pluggable authentication modules (PAM) to access user credentials or enable otherwise unwarranted access to accounts. PAM is a modular system of configuration files, libraries, and executable files which guide authentication for many services. The most common authentication module is <code>pam_unix.so</code>, which retrieves, sets, and verifies account authentication information in <code>/etc/passwd</code> and <code>/etc/shadow</code>.(Citation: Apple PAM)(Citation: Man Pam_Unix)(Citation: Red Hat PAM)

Adversaries may modify components of the PAM system to create backdoors. PAM components, such as <code>pam_unix.so</code>, can be patched to accept arbitrary adversary supplied values as legitimate credentials.(Citation: PAM Backdoor)

Malicious modifications to the PAM system may also be abused to steal credentials. Adversaries may infect PAM resources with code to harvest user credentials, since the values exchanged with PAM components may be plain-text since PAM does not store passwords.(Citation: PAM Creds)(Citation: Apple PAM)

Procedures:

- [S0377] Ebury: [Ebury](https://attack.mitre.org/software/S0377) can deactivate PAM modules to tamper with the sshd configuration.(Citation: ESET Ebury Oct 2017)
- [S0468] Skidmap: [Skidmap](https://attack.mitre.org/software/S0468) has the ability to replace the pam_unix.so file on an infected machine with its own malicious version that accepts a specific backdoor password for all users.(Citation: Trend Micro Skidmap)

#### T1556.004 - Modify Authentication Process: Network Device Authentication

Description:

Adversaries may use [Patch System Image](https://attack.mitre.org/techniques/T1601/001) to hard code a password in the operating system, thus bypassing of native authentication mechanisms for local accounts on network devices.

[Modify System Image](https://attack.mitre.org/techniques/T1601) may include implanted code to the operating system for network devices to provide access for adversaries using a specific password.  The modification includes a specific password which is implanted in the operating system image via the patch.  Upon authentication attempts, the inserted code will first check to see if the user input is the password. If so, access is granted. Otherwise, the implanted code will pass the credentials on for verification of potentially valid credentials.(Citation: Mandiant - Synful Knock)

Procedures:

- [S1104] SLOWPULSE: [SLOWPULSE](https://attack.mitre.org/software/S1104) can modify LDAP and two factor authentication flows by inspecting login credentials and forcing successful authentication if the provided password matches a chosen backdoor password.(Citation: Mandiant Pulse Secure Zero-Day April 2021)
- [S0519] SYNful Knock: [SYNful Knock](https://attack.mitre.org/software/S0519) has the capability to add its own custom backdoor password when it modifies the operating system of the affected network device.(Citation: Mandiant - Synful Knock)

#### T1556.005 - Modify Authentication Process: Reversible Encryption

Description:

An adversary may abuse Active Directory authentication encryption properties to gain access to credentials on Windows systems. The <code>AllowReversiblePasswordEncryption</code> property specifies whether reversible password encryption for an account is enabled or disabled. By default this property is disabled (instead storing user credentials as the output of one-way hashing functions) and should not be enabled unless legacy or other software require it.(Citation: store_pwd_rev_enc)

If the property is enabled and/or a user changes their password after it is enabled, an adversary may be able to obtain the plaintext of passwords created/changed after the property was enabled. To decrypt the passwords, an adversary needs four components:

1. Encrypted password (<code>G$RADIUSCHAP</code>) from the Active Directory user-structure <code>userParameters</code>
2. 16 byte randomly-generated value (<code>G$RADIUSCHAPKEY</code>) also from <code>userParameters</code>
3. Global LSA secret (<code>G$MSRADIUSCHAPKEY</code>)
4. Static key hardcoded in the Remote Access Subauthentication DLL (<code>RASSFM.DLL</code>)

With this information, an adversary may be able to reproduce the encryption key and subsequently decrypt the encrypted password value.(Citation: how_pwd_rev_enc_1)(Citation: how_pwd_rev_enc_2)

An adversary may set this property at various scopes through Local Group Policy Editor, user properties, Fine-Grained Password Policy (FGPP), or via the ActiveDirectory [PowerShell](https://attack.mitre.org/techniques/T1059/001) module. For example, an adversary may implement and apply a FGPP to users or groups if the Domain Functional Level is set to "Windows Server 2008" or higher.(Citation: dump_pwd_dcsync) In PowerShell, an adversary may make associated changes to user settings using commands similar to <code>Set-ADUser -AllowReversiblePasswordEncryption $true</code>.

#### T1556.006 - Modify Authentication Process: Multi-Factor Authentication

Description:

Adversaries may disable or modify multi-factor authentication (MFA) mechanisms to enable persistent access to compromised accounts.

Once adversaries have gained access to a network by either compromising an account lacking MFA or by employing an MFA bypass method such as [Multi-Factor Authentication Request Generation](https://attack.mitre.org/techniques/T1621), adversaries may leverage their access to modify or completely disable MFA defenses. This can be accomplished by abusing legitimate features, such as excluding users from Azure AD Conditional Access Policies, registering a new yet vulnerable/adversary-controlled MFA method, or by manually patching MFA programs and configuration files to bypass expected functionality.(Citation: Mandiant APT42)(Citation: Azure AD Conditional Access Exclusions)

For example, modifying the Windows hosts file (`C:\windows\system32\drivers\etc\hosts`) to redirect MFA calls to localhost instead of an MFA server may cause the MFA process to fail. If a "fail open" policy is in place, any otherwise successful authentication attempt may be granted access without enforcing MFA. (Citation: Russians Exploit Default MFA Protocol - CISA March 2022) 

Depending on the scope, goals, and privileges of the adversary, MFA defenses may be disabled for individual accounts or for all accounts tied to a larger group, such as all domain accounts in a victim's network environment.(Citation: Russians Exploit Default MFA Protocol - CISA March 2022)

Procedures:

- [G1015] Scattered Spider: After compromising user accounts, [Scattered Spider](https://attack.mitre.org/groups/G1015) registers their own MFA tokens.(Citation: CISA Scattered Spider Advisory November 2023)
- [S1104] SLOWPULSE: [SLOWPULSE](https://attack.mitre.org/software/S1104) can insert malicious logic to bypass RADIUS and ACE two factor authentication (2FA) flows if a designated attacker-supplied password is provided.(Citation: Mandiant Pulse Secure Zero-Day April 2021)
- [S0677] AADInternals: The [AADInternals](https://attack.mitre.org/software/S0677) `Set-AADIntUserMFA` command can be used to disable MFA for a specified user.

#### T1556.007 - Modify Authentication Process: Hybrid Identity

Description:

Adversaries may patch, modify, or otherwise backdoor cloud authentication processes that are tied to on-premises user identities in order to bypass typical authentication mechanisms, access credentials, and enable persistent access to accounts.  

Many organizations maintain hybrid user and device identities that are shared between on-premises and cloud-based environments. These can be maintained in a number of ways. For example, Microsoft Entra ID includes three options for synchronizing identities between Active Directory and Entra ID(Citation: Azure AD Hybrid Identity):

* Password Hash Synchronization (PHS), in which a privileged on-premises account synchronizes user password hashes between Active Directory and Entra ID, allowing authentication to Entra ID to take place entirely in the cloud 
* Pass Through Authentication (PTA), in which Entra ID authentication attempts are forwarded to an on-premises PTA agent, which validates the credentials against Active Directory 
* Active Directory Federation Services (AD FS), in which a trust relationship is established between Active Directory and Entra ID 

AD FS can also be used with other SaaS and cloud platforms such as AWS and GCP, which will hand off the authentication process to AD FS and receive a token containing the hybrid users’ identity and privileges. 

By modifying authentication processes tied to hybrid identities, an adversary may be able to establish persistent privileged access to cloud resources. For example, adversaries who compromise an on-premises server running a PTA agent may inject a malicious DLL into the `AzureADConnectAuthenticationAgentService` process that authorizes all attempts to authenticate to Entra ID, as well as records user credentials.(Citation: Azure AD Connect for Read Teamers)(Citation: AADInternals Azure AD On-Prem to Cloud) In environments using AD FS, an adversary may edit the `Microsoft.IdentityServer.Servicehost` configuration file to load a malicious DLL that generates authentication tokens for any user with any set of claims, thereby bypassing multi-factor authentication and defined AD FS policies.(Citation: MagicWeb)

In some cases, adversaries may be able to modify the hybrid identity authentication process from the cloud. For example, adversaries who compromise a Global Administrator account in an Entra ID tenant may be able to register a new PTA agent via the web console, similarly allowing them to harvest credentials and log into the Entra ID environment as any user.(Citation: Mandiant Azure AD Backdoors)

Procedures:

- [S0677] AADInternals: [AADInternals](https://attack.mitre.org/software/S0677) can inject a malicious DLL (`PTASpy`) into the `AzureADConnectAuthenticationAgentService` to backdoor Azure AD Pass-Through Authentication.(Citation: AADInternals Azure AD On-Prem to Cloud)
- [G0016] APT29: [APT29](https://attack.mitre.org/groups/G0016) has edited the `Microsoft.IdentityServer.Servicehost.exe.config` file to load a malicious DLL into the AD FS process, thereby enabling persistent access to any service federated with AD FS for a user with a specified User Principal Name.(Citation: MagicWeb)

#### T1556.008 - Modify Authentication Process: Network Provider DLL

Description:

Adversaries may register malicious network provider dynamic link libraries (DLLs) to capture cleartext user credentials during the authentication process. Network provider DLLs allow Windows to interface with specific network protocols and can also support add-on credential management functions.(Citation: Network Provider API) During the logon process, Winlogon (the interactive logon module) sends credentials to the local `mpnotify.exe` process via RPC. The `mpnotify.exe` process then shares the credentials in cleartext with registered credential managers when notifying that a logon event is happening.(Citation: NPPSPY - Huntress)(Citation: NPPSPY Video)(Citation: NPLogonNotify) 

Adversaries can configure a malicious network provider DLL to receive credentials from `mpnotify.exe`.(Citation: NPPSPY) Once installed as a credential manager (via the Registry), a malicious DLL can receive and save credentials each time a user logs onto a Windows workstation or domain via the `NPLogonNotify()` function.(Citation: NPLogonNotify)

Adversaries may target planting malicious network provider DLLs on systems known to have increased logon activity and/or administrator logon activity, such as servers and domain controllers.(Citation: NPPSPY - Huntress)

#### T1556.009 - Modify Authentication Process: Conditional Access Policies

Description:

Adversaries may disable or modify conditional access policies to enable persistent access to compromised accounts. Conditional access policies are additional verifications used by identity providers and identity and access management systems to determine whether a user should be granted access to a resource.

For example, in Entra ID, Okta, and JumpCloud, users can be denied access to applications based on their IP address, device enrollment status, and use of multi-factor authentication.(Citation: Microsoft Conditional Access)(Citation: JumpCloud Conditional Access Policies)(Citation: Okta Conditional Access Policies) In some cases, identity providers may also support the use of risk-based metrics to deny sign-ins based on a variety of indicators. In AWS and GCP, IAM policies can contain `condition` attributes that verify arbitrary constraints such as the source IP, the date the request was made, and the nature of the resources or regions being requested.(Citation: AWS IAM Conditions)(Citation: GCP IAM Conditions) These measures help to prevent compromised credentials from resulting in unauthorized access to data or resources, as well as limit user permissions to only those required. 

By modifying conditional access policies, such as adding additional trusted IP ranges, removing [Multi-Factor Authentication](https://attack.mitre.org/techniques/T1556/006) requirements, or allowing additional [Unused/Unsupported Cloud Regions](https://attack.mitre.org/techniques/T1535), adversaries may be able to ensure persistent access to accounts and circumvent defensive measures.

Procedures:

- [G1015] Scattered Spider: [Scattered Spider](https://attack.mitre.org/groups/G1015) has added additional trusted locations to Azure AD conditional access policies. (Citation: MSTIC Octo Tempest Operations October 2023)


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

#### T1557.001 - Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning and SMB Relay

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

#### T1557.002 - Adversary-in-the-Middle: ARP Cache Poisoning

Description:

Adversaries may poison Address Resolution Protocol (ARP) caches to position themselves between the communication of two or more networked devices. This activity may be used to enable follow-on behaviors such as [Network Sniffing](https://attack.mitre.org/techniques/T1040) or [Transmitted Data Manipulation](https://attack.mitre.org/techniques/T1565/002).

The ARP protocol is used to resolve IPv4 addresses to link layer addresses, such as a media access control (MAC) address.(Citation: RFC826 ARP) Devices in a local network segment communicate with each other by using link layer addresses. If a networked device does not have the link layer address of a particular networked device, it may send out a broadcast ARP request to the local network to translate the IP address to a MAC address. The device with the associated IP address directly replies with its MAC address. The networked device that made the ARP request will then use as well as store that information in its ARP cache.

An adversary may passively wait for an ARP request to poison the ARP cache of the requesting device. The adversary may reply with their MAC address, thus deceiving the victim by making them believe that they are communicating with the intended networked device. For the adversary to poison the ARP cache, their reply must be faster than the one made by the legitimate IP address owner. Adversaries may also send a gratuitous ARP reply that maliciously announces the ownership of a particular IP address to all the devices in the local network segment.

The ARP protocol is stateless and does not require authentication. Therefore, devices may wrongly add or update the MAC address of the IP address in their ARP cache.(Citation: Sans ARP Spoofing Aug 2003)(Citation: Cylance Cleaver)

Adversaries may use ARP cache poisoning as a means to intercept network traffic. This activity may be used to collect and/or relay data such as credentials, especially those sent over an insecure, unencrypted protocol.(Citation: Sans ARP Spoofing Aug 2003)

Procedures:

- [G0003] Cleaver: [Cleaver](https://attack.mitre.org/groups/G0003) has used custom tools to facilitate ARP cache poisoning.(Citation: Cylance Cleaver)
- [G1014] LuminousMoth: [LuminousMoth](https://attack.mitre.org/groups/G1014) has used ARP spoofing to redirect a compromised machine to an actor-controlled website.(Citation: Bitdefender LuminousMoth July 2021)

#### T1557.003 - Adversary-in-the-Middle: DHCP Spoofing

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

#### T1557.004 - Adversary-in-the-Middle: Evil Twin

Description:

Adversaries may host seemingly genuine Wi-Fi access points to deceive users into connecting to malicious networks as a way of supporting follow-on behaviors such as [Network Sniffing](https://attack.mitre.org/techniques/T1040), [Transmitted Data Manipulation](https://attack.mitre.org/techniques/T1565/002), or [Input Capture](https://attack.mitre.org/techniques/T1056).(Citation: Australia ‘Evil Twin’)

By using a Service Set Identifier (SSID) of a legitimate Wi-Fi network, fraudulent Wi-Fi access points may trick devices or users into connecting to malicious Wi-Fi networks.(Citation: Kaspersky evil twin)(Citation: medium evil twin)  Adversaries may provide a stronger signal strength or block access to Wi-Fi access points to coerce or entice victim devices into connecting to malicious networks.(Citation: specter ops evil twin)  A Wi-Fi Pineapple – a network security auditing and penetration testing tool – may be deployed in Evil Twin attacks for ease of use and broader range. Custom certificates may be used in an attempt to intercept HTTPS traffic. 

Similarly, adversaries may also listen for client devices sending probe requests for known or previously connected networks (Preferred Network Lists or PNLs). When a malicious access point receives a probe request, adversaries can respond with the same SSID to imitate the trusted, known network.(Citation: specter ops evil twin)  Victim devices are led to believe the responding access point is from their PNL and initiate a connection to the fraudulent network.

Upon logging into the malicious Wi-Fi access point, a user may be directed to a fake login page or captive portal webpage to capture the victim’s credentials. Once a user is logged into the fraudulent Wi-Fi network, the adversary may able to monitor network activity, manipulate data, or steal additional credentials. Locations with high concentrations of public Wi-Fi access, such as airports, coffee shops, or libraries, may be targets for adversaries to set up illegitimate Wi-Fi access points.

Procedures:

- [G0007] APT28: [APT28](https://attack.mitre.org/groups/G0007) has used a Wi-Fi Pineapple to set up Evil Twin Wi-Fi Poisoning for the purposes of capturing victim credentials or planting espionage-oriented malware.(Citation: US District Court Indictment GRU Oct 2018)


### T1558 - Steal or Forge Kerberos Tickets

Description:

Adversaries may attempt to subvert Kerberos authentication by stealing or forging Kerberos tickets to enable [Pass the Ticket](https://attack.mitre.org/techniques/T1550/003). Kerberos is an authentication protocol widely used in modern Windows domain environments. In Kerberos environments, referred to as “realms”, there are three basic participants: client, service, and Key Distribution Center (KDC).(Citation: ADSecurity Kerberos Ring Decoder) Clients request access to a service and through the exchange of Kerberos tickets, originating from KDC, they are granted access after having successfully authenticated. The KDC is responsible for both authentication and ticket granting.  Adversaries may attempt to abuse Kerberos by stealing tickets or forging tickets to enable unauthorized access.

On Windows, the built-in <code>klist</code> utility can be used to list and analyze cached Kerberos tickets.(Citation: Microsoft Klist)

Procedures:

- [G1024] Akira: [Akira](https://attack.mitre.org/groups/G1024) have used scripts to dump Kerberos authentication credentials.(Citation: Cisco Akira Ransomware OCT 2024)

#### T1558.001 - Steal or Forge Kerberos Tickets: Golden Ticket

Description:

Adversaries who have the KRBTGT account password hash may forge Kerberos ticket-granting tickets (TGT), also known as a golden ticket.(Citation: AdSecurity Kerberos GT Aug 2015) Golden tickets enable adversaries to generate authentication material for any account in Active Directory.(Citation: CERT-EU Golden Ticket Protection) 

Using a golden ticket, adversaries are then able to request ticket granting service (TGS) tickets, which enable access to specific resources. Golden tickets require adversaries to interact with the Key Distribution Center (KDC) in order to obtain TGS.(Citation: ADSecurity Detecting Forged Tickets)

The KDC service runs all on domain controllers that are part of an Active Directory domain. KRBTGT is the Kerberos Key Distribution Center (KDC) service account and is responsible for encrypting and signing all Kerberos tickets.(Citation: ADSecurity Kerberos and KRBTGT) The KRBTGT password hash may be obtained using [OS Credential Dumping](https://attack.mitre.org/techniques/T1003) and privileged access to a domain controller.

Procedures:

- [G0004] Ke3chang: [Ke3chang](https://attack.mitre.org/groups/G0004) has used [Mimikatz](https://attack.mitre.org/software/S0002) to generate Kerberos golden tickets.(Citation: NCC Group APT15 Alive and Strong)
- [S0363] Empire: [Empire](https://attack.mitre.org/software/S0363) can leverage its implementation of [Mimikatz](https://attack.mitre.org/software/S0002) to obtain and use golden tickets.(Citation: Github PowerShell Empire)
- [S0002] Mimikatz: [Mimikatz](https://attack.mitre.org/software/S0002)'s kerberos module can create golden tickets.(Citation: GitHub Mimikatz kerberos Module)(Citation: Cobalt Strike Manual 4.3 November 2020)
- [S0633] Sliver: [Sliver](https://attack.mitre.org/software/S0633) incorporates the [Rubeus](https://attack.mitre.org/software/S1071) framework to allow for Kerberos ticket manipulation, specifically for forging Kerberos Golden Tickets.(Citation: Cybereason Sliver Undated)
- [S1071] Rubeus: [Rubeus](https://attack.mitre.org/software/S1071) can forge a ticket-granting ticket.(Citation: GitHub Rubeus March 2023)

#### T1558.002 - Steal or Forge Kerberos Tickets: Silver Ticket

Description:

Adversaries who have the password hash of a target service account (e.g. SharePoint, MSSQL) may forge Kerberos ticket granting service (TGS) tickets, also known as silver tickets. Kerberos TGS tickets are also known as service tickets.(Citation: ADSecurity Silver Tickets)

Silver tickets are more limited in scope in than golden tickets in that they only enable adversaries to access a particular resource (e.g. MSSQL) and the system that hosts the resource; however, unlike golden tickets, adversaries with the ability to forge silver tickets are able to create TGS tickets without interacting with the Key Distribution Center (KDC), potentially making detection more difficult.(Citation: ADSecurity Detecting Forged Tickets)

Password hashes for target services may be obtained using [OS Credential Dumping](https://attack.mitre.org/techniques/T1003) or [Kerberoasting](https://attack.mitre.org/techniques/T1558/003).

Procedures:

- [S1071] Rubeus: [Rubeus](https://attack.mitre.org/software/S1071) can create silver tickets.(Citation: GitHub Rubeus March 2023)
- [S0677] AADInternals: [AADInternals](https://attack.mitre.org/software/S0677) can be used to forge Kerberos tickets using the password hash of the AZUREADSSOACC account.(Citation: AADInternals Documentation)
- [S0002] Mimikatz: [Mimikatz](https://attack.mitre.org/software/S0002)'s kerberos module can create silver tickets.(Citation: GitHub Mimikatz kerberos Module)
- [S0363] Empire: [Empire](https://attack.mitre.org/software/S0363) can leverage its implementation of [Mimikatz](https://attack.mitre.org/software/S0002) to obtain and use silver tickets.(Citation: Github PowerShell Empire)

#### T1558.003 - Steal or Forge Kerberos Tickets: Kerberoasting

Description:

Adversaries may abuse a valid Kerberos ticket-granting ticket (TGT) or sniff network traffic to obtain a ticket-granting service (TGS) ticket that may be vulnerable to [Brute Force](https://attack.mitre.org/techniques/T1110).(Citation: Empire InvokeKerberoast Oct 2016)(Citation: AdSecurity Cracking Kerberos Dec 2015) 

Service principal names (SPNs) are used to uniquely identify each instance of a Windows service. To enable authentication, Kerberos requires that SPNs be associated with at least one service logon account (an account specifically tasked with running a service(Citation: Microsoft Detecting Kerberoasting Feb 2018)).(Citation: Microsoft SPN)(Citation: Microsoft SetSPN)(Citation: SANS Attacking Kerberos Nov 2014)(Citation: Harmj0y Kerberoast Nov 2016)

Adversaries possessing a valid Kerberos ticket-granting ticket (TGT) may request one or more Kerberos ticket-granting service (TGS) service tickets for any SPN from a domain controller (DC).(Citation: Empire InvokeKerberoast Oct 2016)(Citation: AdSecurity Cracking Kerberos Dec 2015) Portions of these tickets may be encrypted with the RC4 algorithm, meaning the Kerberos 5 TGS-REP etype 23 hash of the service account associated with the SPN is used as the private key and is thus vulnerable to offline [Brute Force](https://attack.mitre.org/techniques/T1110) attacks that may expose plaintext credentials.(Citation: AdSecurity Cracking Kerberos Dec 2015)(Citation: Empire InvokeKerberoast Oct 2016) (Citation: Harmj0y Kerberoast Nov 2016)

This same behavior could be executed using service tickets captured from network traffic.(Citation: AdSecurity Cracking Kerberos Dec 2015)

Cracked hashes may enable [Persistence](https://attack.mitre.org/tactics/TA0003), [Privilege Escalation](https://attack.mitre.org/tactics/TA0004), and [Lateral Movement](https://attack.mitre.org/tactics/TA0008) via access to [Valid Accounts](https://attack.mitre.org/techniques/T1078).(Citation: SANS Attacking Kerberos Nov 2014)

Procedures:

- [S1071] Rubeus: [Rubeus](https://attack.mitre.org/software/S1071) can use the `KerberosRequestorSecurityToken.GetRequest` method to request kerberoastable service tickets.(Citation: GitHub Rubeus March 2023)
- [S0357] Impacket: [Impacket](https://attack.mitre.org/software/S0357) modules like GetUserSPNs can be used to get Service Principal Names (SPNs) for user accounts. The output is formatted to be compatible with cracking tools like John the Ripper and Hashcat.(Citation: Impacket Tools)
- [S0363] Empire: [Empire](https://attack.mitre.org/software/S0363) uses [PowerSploit](https://attack.mitre.org/software/S0194)'s <code>Invoke-Kerberoast</code> to request service tickets and return crackable ticket hashes.(Citation: Github PowerShell Empire)
- [C0049] Leviathan Australian Intrusions: [Leviathan](https://attack.mitre.org/groups/G0065) used Kerberoasting techniques during [Leviathan Australian Intrusions](https://attack.mitre.org/campaigns/C0049).(Citation: CISA Leviathan 2024)
- [G0102] Wizard Spider: [Wizard Spider](https://attack.mitre.org/groups/G0102) has used Rubeus, MimiKatz Kerberos module, and the Invoke-Kerberoast cmdlet to steal AES hashes.(Citation: DFIR Ryuk's Return October 2020)(Citation: FireEye KEGTAP SINGLEMALT October 2020)(Citation: DHS/CISA Ransomware Targeting Healthcare October 2020)(Citation: DFIR Ryuk 2 Hour Speed Run November 2020)(Citation: Mandiant FIN12 Oct 2021)
- [C0014] Operation Wocao: During [Operation Wocao](https://attack.mitre.org/campaigns/C0014), threat actors used [PowerSploit](https://attack.mitre.org/software/S0194)'s `Invoke-Kerberoast` module to request encrypted service tickets and bruteforce the passwords of Windows service accounts offline.(Citation: FoxIT Wocao December 2019)
- [S0692] SILENTTRINITY: [SILENTTRINITY](https://attack.mitre.org/software/S0692) contains a module to conduct Kerberoasting.(Citation: GitHub SILENTTRINITY Modules July 2019)
- [C0024] SolarWinds Compromise: During the [SolarWinds Compromise](https://attack.mitre.org/campaigns/C0024), [APT29](https://attack.mitre.org/groups/G0016) obtained Ticket Granting Service (TGS) tickets for Active Directory Service Principle Names to crack offline.(Citation: Microsoft Deep Dive Solorigate January 2021)
- [S0194] PowerSploit: [PowerSploit](https://attack.mitre.org/software/S0194)'s <code>Invoke-Kerberoast</code> module can request service tickets and return crackable ticket hashes.(Citation: PowerSploit Invoke Kerberoast)(Citation: Harmj0y Kerberoast Nov 2016)
- [G0046] FIN7: [FIN7](https://attack.mitre.org/groups/G0046) has used Kerberoasting PowerShell commands such as, `Invoke-Kerberoast` for credential access and to enable lateral movement.(Citation: CrowdStrike Carbon Spider August 2021)(Citation: Mandiant FIN7 Apr 2022)
- [G0119] Indrik Spider: [Indrik Spider](https://attack.mitre.org/groups/G0119) has conducted Kerberoasting attacks using a module from GitHub.(Citation: Mandiant_UNC2165)
- [S1063] Brute Ratel C4: [Brute Ratel C4](https://attack.mitre.org/software/S1063) can decode Kerberos 5 tickets and convert it to hashcat format for subsequent cracking.(Citation: Palo Alto Brute Ratel July 2022)

#### T1558.004 - Steal or Forge Kerberos Tickets: AS-REP Roasting

Description:

Adversaries may reveal credentials of accounts that have disabled Kerberos preauthentication by [Password Cracking](https://attack.mitre.org/techniques/T1110/002) Kerberos messages.(Citation: Harmj0y Roasting AS-REPs Jan 2017) 

Preauthentication offers protection against offline [Password Cracking](https://attack.mitre.org/techniques/T1110/002). When enabled, a user requesting access to a resource initiates communication with the Domain Controller (DC) by sending an Authentication Server Request (AS-REQ) message with a timestamp that is encrypted with the hash of their password. If and only if the DC is able to successfully decrypt the timestamp with the hash of the user’s password, it will then send an Authentication Server Response (AS-REP) message that contains the Ticket Granting Ticket (TGT) to the user. Part of the AS-REP message is signed with the user’s password.(Citation: Microsoft Kerberos Preauth 2014)

For each account found without preauthentication, an adversary may send an AS-REQ message without the encrypted timestamp and receive an AS-REP message with TGT data which may be encrypted with an insecure algorithm such as RC4. The recovered encrypted data may be vulnerable to offline [Password Cracking](https://attack.mitre.org/techniques/T1110/002) attacks similarly to [Kerberoasting](https://attack.mitre.org/techniques/T1558/003) and expose plaintext credentials. (Citation: Harmj0y Roasting AS-REPs Jan 2017)(Citation: Stealthbits Cracking AS-REP Roasting Jun 2019) 

An account registered to a domain, with or without special privileges, can be abused to list all domain accounts that have preauthentication disabled by utilizing Windows tools like [PowerShell](https://attack.mitre.org/techniques/T1059/001) with an LDAP filter. Alternatively, the adversary may send an AS-REQ message for each user. If the DC responds without errors, the account does not require preauthentication and the AS-REP message will already contain the encrypted data. (Citation: Harmj0y Roasting AS-REPs Jan 2017)(Citation: Stealthbits Cracking AS-REP Roasting Jun 2019)

Cracked hashes may enable [Persistence](https://attack.mitre.org/tactics/TA0003), [Privilege Escalation](https://attack.mitre.org/tactics/TA0004), and [Lateral Movement](https://attack.mitre.org/tactics/TA0008) via access to [Valid Accounts](https://attack.mitre.org/techniques/T1078).(Citation: SANS Attacking Kerberos Nov 2014)

Procedures:

- [S1071] Rubeus: [Rubeus](https://attack.mitre.org/software/S1071) can reveal the credentials of accounts that have Kerberos pre-authentication disabled through AS-REP roasting.(Citation: GitHub Rubeus March 2023)(Citation: DFIR Ryuk's Return October 2020)(Citation: DFIR Ryuk 2 Hour Speed Run November 2020)

#### T1558.005 - Steal or Forge Kerberos Tickets: Ccache Files

Description:

Adversaries may attempt to steal Kerberos tickets stored in credential cache files (or ccache). These files are used for short term storage of a user's active session credentials. The ccache file is created upon user authentication and allows for access to multiple services without the user having to re-enter credentials. 

The <code>/etc/krb5.conf</code> configuration file and the <code>KRB5CCNAME</code> environment variable are used to set the storage location for ccache entries. On Linux, credentials are typically stored in the `/tmp` directory with a naming format of `krb5cc_%UID%` or `krb5.ccache`. On macOS, ccache entries are stored by default in memory with an `API:{uuid}` naming scheme. Typically, users interact with ticket storage using <code>kinit</code>, which obtains a Ticket-Granting-Ticket (TGT) for the principal; <code>klist</code>, which lists obtained tickets currently held in the credentials cache; and other built-in binaries.(Citation: Kerberos GNU/Linux)(Citation: Binary Defense Kerberos Linux)

Adversaries can collect tickets from ccache files stored on disk and authenticate as the current user without their password to perform [Pass the Ticket](https://attack.mitre.org/techniques/T1550/003) attacks. Adversaries can also use these tickets to impersonate legitimate users with elevated privileges to perform [Privilege Escalation](https://attack.mitre.org/tactics/TA0004). Tools like Kekeo can also be used by adversaries to convert ccache files to Windows format for further [Lateral Movement](https://attack.mitre.org/tactics/TA0008). On macOS, adversaries may use open-source tools or the Kerberos framework to interact with ccache files and extract TGTs or Service Tickets via lower-level APIs.(Citation: SpectorOps Bifrost Kerberos macOS 2019)(Citation: Linux Kerberos Tickets)(Citation: Brining MimiKatz to Unix)(Citation: Kekeo)

Procedures:

- [S0357] Impacket: [Impacket](https://attack.mitre.org/software/S0357) tools – such as <code>getST.py</code> or <code>ticketer.py</code> – can be used to steal or forge Kerberos tickets using ccache files given a password, hash, aesKey, or TGT.(Citation: Kerberos GNU/Linux)(Citation: on security kerberos linux)


### T1606 - Forge Web Credentials

Description:

Adversaries may forge credential materials that can be used to gain access to web applications or Internet services. Web applications and services (hosted in cloud SaaS environments or on-premise servers) often use session cookies, tokens, or other materials to authenticate and authorize user access.

Adversaries may generate these credential materials in order to gain access to web resources. This differs from [Steal Web Session Cookie](https://attack.mitre.org/techniques/T1539), [Steal Application Access Token](https://attack.mitre.org/techniques/T1528), and other similar behaviors in that the credentials are new and forged by the adversary, rather than stolen or intercepted from legitimate users.

The generation of web credentials often requires secret values, such as passwords, [Private Keys](https://attack.mitre.org/techniques/T1552/004), or other cryptographic seed values.(Citation: GitHub AWS-ADFS-Credential-Generator) Adversaries may also forge tokens by taking advantage of features such as the `AssumeRole` and `GetFederationToken` APIs in AWS, which allow users to request temporary security credentials (i.e., [Temporary Elevated Cloud Access](https://attack.mitre.org/techniques/T1548/005)), or the `zmprov gdpak` command in Zimbra, which generates a pre-authentication key that can be used to generate tokens for any user in the domain.(Citation: AWS Temporary Security Credentials)(Citation: Zimbra Preauth)

Once forged, adversaries may use these web credentials to access resources (ex: [Use Alternate Authentication Material](https://attack.mitre.org/techniques/T1550)), which may bypass multi-factor and other authentication protection mechanisms.(Citation: Pass The Cookie)(Citation: Unit 42 Mac Crypto Cookies January 2019)(Citation: Microsoft SolarWinds Customer Guidance)

#### T1606.001 - Forge Web Credentials: Web Cookies

Description:

Adversaries may forge web cookies that can be used to gain access to web applications or Internet services. Web applications and services (hosted in cloud SaaS environments or on-premise servers) often use session cookies to authenticate and authorize user access.

Adversaries may generate these cookies in order to gain access to web resources. This differs from [Steal Web Session Cookie](https://attack.mitre.org/techniques/T1539) and other similar behaviors in that the cookies are new and forged by the adversary, rather than stolen or intercepted from legitimate users. Most common web applications have standardized and documented cookie values that can be generated using provided tools or interfaces.(Citation: Pass The Cookie) The generation of web cookies often requires secret values, such as passwords, [Private Keys](https://attack.mitre.org/techniques/T1552/004), or other cryptographic seed values.

Once forged, adversaries may use these web cookies to access resources ([Web Session Cookie](https://attack.mitre.org/techniques/T1550/004)), which may bypass multi-factor and other authentication protection mechanisms.(Citation: Volexity SolarWinds)(Citation: Pass The Cookie)(Citation: Unit 42 Mac Crypto Cookies January 2019)

Procedures:

- [C0024] SolarWinds Compromise: During the [SolarWinds Compromise](https://attack.mitre.org/campaigns/C0024), [APT29](https://attack.mitre.org/groups/G0016) bypassed MFA set on OWA accounts by generating a cookie value from a previously stolen secret key.(Citation: Volexity SolarWinds)

#### T1606.002 - Forge Web Credentials: SAML Tokens

Description:

An adversary may forge SAML tokens with any permissions claims and lifetimes if they possess a valid SAML token-signing certificate.(Citation: Microsoft SolarWinds Steps) The default lifetime of a SAML token is one hour, but the validity period can be specified in the <code>NotOnOrAfter</code> value of the <code>conditions ...</code> element in a token. This value can be changed using the <code>AccessTokenLifetime</code> in a <code>LifetimeTokenPolicy</code>.(Citation: Microsoft SAML Token Lifetimes) Forged SAML tokens enable adversaries to authenticate across services that use SAML 2.0 as an SSO (single sign-on) mechanism.(Citation: Cyberark Golden SAML)

An adversary may utilize [Private Keys](https://attack.mitre.org/techniques/T1552/004) to compromise an organization's token-signing certificate to create forged SAML tokens. If the adversary has sufficient permissions to establish a new federation trust with their own Active Directory Federation Services (AD FS) server, they may instead generate their own trusted token-signing certificate.(Citation: Microsoft SolarWinds Customer Guidance) This differs from [Steal Application Access Token](https://attack.mitre.org/techniques/T1528) and other similar behaviors in that the tokens are new and forged by the adversary, rather than stolen or intercepted from legitimate users.

An adversary may gain administrative Entra ID privileges if a SAML token is forged which claims to represent a highly privileged account. This may lead to [Use Alternate Authentication Material](https://attack.mitre.org/techniques/T1550), which may bypass multi-factor and other authentication protection mechanisms.(Citation: Microsoft SolarWinds Customer Guidance)

Procedures:

- [C0024] SolarWinds Compromise: During the [SolarWinds Compromise](https://attack.mitre.org/campaigns/C0024), [APT29](https://attack.mitre.org/groups/G0016) created tokens using compromised SAML signing certificates.(Citation: Microsoft - Customer Guidance on Recent Nation-State Cyber Attacks)(Citation: Secureworks IRON RITUAL Profile)
- [S0677] AADInternals: [AADInternals](https://attack.mitre.org/software/S0677) can be used to create SAML tokens using the AD Federated Services token signing certificate.(Citation: AADInternals Documentation)


### T1621 - Multi-Factor Authentication Request Generation

Description:

Adversaries may attempt to bypass multi-factor authentication (MFA) mechanisms and gain access to accounts by generating MFA requests sent to users.

Adversaries in possession of credentials to [Valid Accounts](https://attack.mitre.org/techniques/T1078) may be unable to complete the login process if they lack access to the 2FA or MFA mechanisms required as an additional credential and security control. To circumvent this, adversaries may abuse the automatic generation of push notifications to MFA services such as Duo Push, Microsoft Authenticator, Okta, or similar services to have the user grant access to their account. If adversaries lack credentials to victim accounts, they may also abuse automatic push notification generation when this option is configured for self-service password reset (SSPR).(Citation: Obsidian SSPR Abuse 2023)

In some cases, adversaries may continuously repeat login attempts in order to bombard users with MFA push notifications, SMS messages, and phone calls, potentially resulting in the user finally accepting the authentication request in response to “MFA fatigue.”(Citation: Russian 2FA Push Annoyance - Cimpanu)(Citation: MFA Fatigue Attacks - PortSwigger)(Citation: Suspected Russian Activity Targeting Government and Business Entities Around the Globe)

Procedures:

- [G0016] APT29: [APT29](https://attack.mitre.org/groups/G0016) has used repeated MFA requests to gain access to victim accounts.(Citation: Suspected Russian Activity Targeting Government and Business Entities Around the Globe)(Citation: NCSC et al APT29 2024)
- [C0027] C0027: During [C0027](https://attack.mitre.org/campaigns/C0027), [Scattered Spider](https://attack.mitre.org/groups/G1015) attempted to gain access by continuously sending MFA messages to the victim until they accept the MFA push challenge.(Citation: Crowdstrike TELCO BPO Campaign December 2022)
- [G1015] Scattered Spider: [Scattered Spider](https://attack.mitre.org/groups/G1015) has used multifactor authentication (MFA) fatigue by sending repeated MFA authentication requests to targets.(Citation: CrowdStrike Scattered Spider BYOVD January 2023)
- [G1004] LAPSUS$: [LAPSUS$](https://attack.mitre.org/groups/G1004) has spammed target users with MFA prompts in the hope that the legitimate user will grant necessary approval.(Citation: MSTIC DEV-0537 Mar 2022)


### T1649 - Steal or Forge Authentication Certificates

Description:

Adversaries may steal or forge certificates used for authentication to access remote systems or resources. Digital certificates are often used to sign and encrypt messages and/or files. Certificates are also used as authentication material. For example, Entra ID device certificates and Active Directory Certificate Services (AD CS) certificates bind to an identity and can be used as credentials for domain accounts.(Citation: O365 Blog Azure AD Device IDs)(Citation: Microsoft AD CS Overview)

Authentication certificates can be both stolen and forged. For example, AD CS certificates can be stolen from encrypted storage (in the Registry or files)(Citation: APT29 Deep Look at Credential Roaming), misplaced certificate files (i.e. [Unsecured Credentials](https://attack.mitre.org/techniques/T1552)), or directly from the Windows certificate store via various crypto APIs.(Citation: SpecterOps Certified Pre Owned)(Citation: GitHub CertStealer)(Citation: GitHub GhostPack Certificates) With appropriate enrollment rights, users and/or machines within a domain can also request and/or manually renew certificates from enterprise certificate authorities (CA). This enrollment process defines various settings and permissions associated with the certificate. Of note, the certificate’s extended key usage (EKU) values define signing, encryption, and authentication use cases, while the certificate’s subject alternative name (SAN) values define the certificate owner’s alternate names.(Citation: Medium Certified Pre Owned)

Abusing certificates for authentication credentials may enable other behaviors such as [Lateral Movement](https://attack.mitre.org/tactics/TA0008). Certificate-related misconfigurations may also enable opportunities for [Privilege Escalation](https://attack.mitre.org/tactics/TA0004), by way of allowing users to impersonate or assume privileged accounts or permissions via the identities (SANs) associated with a certificate. These abuses may also enable [Persistence](https://attack.mitre.org/tactics/TA0003) via stealing or forging certificates that can be used as [Valid Accounts](https://attack.mitre.org/techniques/T1078) for the duration of the certificate's validity, despite user password resets. Authentication certificates can also be stolen and forged for machine accounts.

Adversaries who have access to root (or subordinate) CA certificate private keys (or mechanisms protecting/managing these keys) may also establish [Persistence](https://attack.mitre.org/tactics/TA0003) by forging arbitrary authentication certificates for the victim domain (known as “golden” certificates).(Citation: Medium Certified Pre Owned) Adversaries may also target certificates and related services in order to access other forms of credentials, such as [Golden Ticket](https://attack.mitre.org/techniques/T1558/001) ticket-granting tickets (TGT) or NTLM plaintext.(Citation: Medium Certified Pre Owned)

Procedures:

- [S0677] AADInternals: [AADInternals](https://attack.mitre.org/software/S0677) can create and export various authentication certificates, including those associated with Azure AD joined/registered devices.(Citation: AADInternals Documentation)
- [G0016] APT29: [APT29](https://attack.mitre.org/groups/G0016) has abused misconfigured AD CS certificate templates to impersonate admin users and create additional authentication certificates.(Citation: Mandiant APT29 Trello)
- [S0002] Mimikatz: [Mimikatz](https://attack.mitre.org/software/S0002)'s `CRYPTO` module can create and export various types of authentication certificates.(Citation: Adsecurity Mimikatz Guide)

