### T1078.001 - Valid Accounts: Default Accounts

Procedures:

- [G1016] FIN13: FIN13 has leveraged default credentials for authenticating myWebMethods (WMS) and QLogic web management interface to gain initial access.
- [S0537] HyperStack: HyperStack can use default credentials to connect to IPC$ shares on remote machines.
- [C0038] HomeLand Justice: During HomeLand Justice, threat actors used the built-in administrator account to move laterally using RDP and Impacket.
- [G0059] Magic Hound: Magic Hound enabled and used the default system managed account, DefaultAccount, via `"powershell.exe" /c net user DefaultAccount /active:yes` to connect to a targeted Exchange server over RDP.
- [S0603] Stuxnet: Stuxnet infected WinCC machines via a hardcoded database server password.
- [G1003] Ember Bear: Ember Bear has abused default user names and passwords in externally-accessible IP cameras for initial access.

### T1078.002 - Valid Accounts: Domain Accounts

Procedures:

- [S1024] CreepySnail: CreepySnail can use stolen credentials to authenticate on target networks.
- [C0002] Night Dragon: During Night Dragon, threat actors used domain accounts to gain further access to victim systems.
- [C0023] Operation Ghost: For Operation Ghost, APT29 used stolen administrator credentials for lateral movement on compromised networks.
- [C0048] Operation MidnightEclipse: During Operation MidnightEclipse, threat actors used a compromised domain admin account to move laterally.
- [S0154] Cobalt Strike: Cobalt Strike can use known credentials to run commands and spawn processes as a domain user account.
- [G0019] Naikon: Naikon has used administrator credentials for lateral movement in compromised networks.
- [C0049] Leviathan Australian Intrusions: Leviathan compromised domain credentials during Leviathan Australian Intrusions.
- [C0012] Operation CuckooBees: During Operation CuckooBees, the threat actors used compromised domain administrator credentials as part of their lateral movement.
- [G1030] Agrius: Agrius attempted to acquire valid credentials for victim environments through various means to enable follow-on lateral movement.
- [G0102] Wizard Spider: Wizard Spider has used administrative accounts, including Domain Admin, to move laterally within a victim network.
- [G0034] Sandworm Team: Sandworm Team has used stolen credentials to access administrative accounts within the domain.
- [C0024] SolarWinds Compromise: During the SolarWinds Compromise, APT29 used domain administrators' accounts to help facilitate lateral movement on compromised networks.
- [S0446] Ryuk: Ryuk can use stolen domain admin accounts to move laterally within a victim domain.
- [G0049] OilRig: OilRig has used an exfiltration tool named STEALHOOK to retreive valid domain credentials.
- [S0140] Shamoon: If Shamoon cannot access shares using current privileges, it attempts access using hard coded, domain-specific credentials gathered earlier in the intrusion.

### T1078.003 - Valid Accounts: Local Accounts

Procedures:

- [G0094] Kimsuky: Kimsuky has used a tool called GREASE to add a Windows admin account in order to allow them continued access via RDP.
- [S0367] Emotet: Emotet can brute force a local admin password, then use it to facilitate lateral movement.
- [S0154] Cobalt Strike: Cobalt Strike can use known credentials to run commands and spawn processes as a local user account.
- [G0056] PROMETHIUM: PROMETHIUM has created admin accounts on a compromised host.
- [G0051] FIN10: FIN10 has moved laterally using the Local Administrator account.
- [G1040] Play: Play has used valid local accounts to gain initial access.
- [G0050] APT32: APT32 has used legitimate local admin account credentials.
- [G1041] Sea Turtle: Sea Turtle compromised cPanel accounts in victim environments.
- [G0081] Tropic Trooper: Tropic Trooper has used known administrator account credentials to execute the backdoor directly.
- [G0125] HAFNIUM: HAFNIUM has used the NT AUTHORITY\SYSTEM account to create files on Exchange servers.
- [G0046] FIN7: FIN7 has used compromised credentials for access as SYSTEM on Exchange servers.
- [C0024] SolarWinds Compromise: During the SolarWinds Compromise, APT29 used compromised local accounts to access victims' networks.
- [C0049] Leviathan Australian Intrusions: Leviathan used captured local account information, such as service accounts, for actions during Leviathan Australian Intrusions.
- [G1047] Velvet Ant: Velvet Ant accessed vulnerable Cisco switch devices using accounts with administrator privileges.
- [G0016] APT29: APT29 targets dormant or inactive user accounts, accounts belonging to individuals no longer at the organization but whose accounts remain on the system, for access and persistence.

### T1078.004 - Valid Accounts: Cloud Accounts

Procedures:

- [C0024] SolarWinds Compromise: During the SolarWinds Compromise, APT29 used a compromised O365 administrator account to create a new Service Principal.
- [G0016] APT29: APT29 has gained access to a global administrator account in Azure AD and has used `Service Principal` credentials in Exchange.
- [G1023] APT5: APT5 has accessed Microsoft M365 cloud environments using stolen credentials.
- [S0684] ROADTools: ROADTools leverages valid cloud credentials to perform enumeration operations using the internal Azure AD Graph API.
- [G0007] APT28: APT28 has used compromised Office 365 service accounts with Global Administrator privileges to collect email from user inboxes.
- [C0027] C0027: During C0027, Scattered Spider leveraged compromised credentials from victim users to authenticate to Azure tenants.
- [S0683] Peirates: Peirates can use stolen service account tokens to perform its operations.
- [G0125] HAFNIUM: HAFNIUM has abused service principals in compromised environments to enable data exfiltration.
- [S1091] Pacu: Pacu leverages valid cloud accounts to perform most of its operations.
- [G0064] APT33: APT33 has used compromised Office 365 accounts in tandem with Ruler in an attempt to gain control of endpoints.
- [G1004] LAPSUS$: LAPSUS$ has used compromised credentials to access cloud assets within a target organization.
- [G0004] Ke3chang: Ke3chang has used compromised credentials to sign into victims’ Microsoft 365 accounts.


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


### T1133 - External Remote Services

Procedures:

- [G0139] TeamTNT: TeamTNT has used open-source tools such as Weave Scope to target exposed Docker API ports and gain initial access to victim environments. TeamTNT has also targeted exposed kubelets for Kubernetes environments.
- [G1016] FIN13: FIN13 has gained access to compromised environments via remote access services such as the corporate virtual private network (VPN).
- [C0012] Operation CuckooBees: During Operation CuckooBees, the threat actors enabled WinRM over HTTP/HTTPS as a backup persistence mechanism using the following command: `cscript //nologo "C:\Windows\System32\winrm.vbs" set winrm/config/service@{EnableCompatibilityHttpsListener="true"}`.
- [S0362] Linux Rabbit: Linux Rabbit attempts to gain access to the server via SSH.
- [C0002] Night Dragon: During Night Dragon, threat actors used compromised VPN accounts to gain access to victim systems.
- [S1060] Mafalda: Mafalda can establish an SSH connection from a compromised host to a server.
- [G1003] Ember Bear: Ember Bear have used VPNs both for initial access to victim environments and for persistence within them following compromise.
- [G0026] APT18: APT18 actors leverage legitimate credentials to log into external remote services.
- [G0034] Sandworm Team: Sandworm Team has used Dropbear SSH with a hardcoded backdoor password to maintain persistence within the target network. Sandworm Team has also used VPN tunnels established in legitimate software company infrastructure to gain access to internal networks of that software company's users.
- [G1017] Volt Typhoon: Volt Typhoon has used VPNs to connect to victim environments and enable post-exploitation actions.
- [G1047] Velvet Ant: Velvet Ant has leveraged access to internet-facing remote services to compromise and retain access to victim environments.
- [S0601] Hildegard: Hildegard was executed through an unsecure kubelet that allowed anonymous access to the victim environment.
- [G1015] Scattered Spider: Scattered Spider has leveraged legitimate remote management tools to maintain persistent access.
- [G0096] APT41: APT41 compromised an online billing/payment service using VPN access between a third-party service provider and the targeted payment service.
- [G1004] LAPSUS$: LAPSUS$ has gained access to internet-facing systems and applications, including virtual private network (VPN), remote desktop protocol (RDP), and virtual desktop infrastructure (VDI) including Citrix.


### T1189 - Drive-by Compromise

Procedures:

- [G0134] Transparent Tribe: Transparent Tribe has used websites with malicious hyperlinks and iframes to infect targeted victims with Crimson, njRAT, and other malicious tools.
- [G0048] RTM: RTM has distributed its malware via the RIG and SUNDOWN exploit kits, as well as online advertising network Yandex.Direct.
- [G0068] PLATINUM: PLATINUM has sometimes used drive-by attacks against vulnerable browser plugins.
- [G0112] Windshift: Windshift has used compromised websites to register custom URL schemes on a remote system.
- [S0215] KARAE: KARAE was distributed through torrent file-sharing websites to South Korean victims, using a YouTube video downloader application as a lure.
- [S0483] IcedID: IcedID has cloned legitimate websites/applications to distribute the malware.
- [G1006] Earth Lusca: Earth Lusca has performed watering hole attacks.
- [G0082] APT38: APT38 has conducted watering holes schemes to gain initial access to victims.
- [S0482] Bundlore: Bundlore has been spread through malicious advertisements on websites.
- [G0001] Axiom: Axiom has used watering hole attacks to gain access.
- [G0073] APT19: APT19 performed a watering hole attack on forbes.com in 2014 to compromise targets.
- [G0012] Darkhotel: Darkhotel used embedded iframes on hotel login portals to redirect selected victims to download malware.
- [G0138] Andariel: Andariel has used watering hole attacks, often with zero-day exploits, to gain initial access to victims within a specific IP range.
- [G0007] APT28: APT28 has compromised targets via strategic web compromise utilizing custom exploit kits. APT28 used reflected cross-site scripting (XSS) against government websites to redirect users to phishing webpages.
- [G0035] Dragonfly: Dragonfly has compromised targets via strategic web compromise (SWC) utilizing a custom exploit kit.


### T1190 - Exploit Public-Facing Application

Procedures:

- [C0027] C0027: During C0027, Scattered Spider exploited CVE-2021-35464 in the ForgeRock Open Access Management (OpenAM) application server to gain initial access.
- [G0106] Rocke: Rocke exploited Apache Struts, Oracle WebLogic (CVE-2017-10271), and Adobe ColdFusion (CVE-2017-3066) vulnerabilities to deliver malware.
- [C0039] Versa Director Zero Day Exploitation: Versa Director Zero Day Exploitation involved exploitation of a vulnerability in Versa Director servers, since identified as CVE-2024-39717, for initial access and code execution.
- [C0045] ShadowRay: During ShadowRay, threat actors exploited CVE-2023-48022 on publicly exposed Ray servers to steal computing power and to expose sensitive data.
- [G0027] Threat Group-3390: Threat Group-3390 has exploited the Microsoft SharePoint vulnerability CVE-2019-0604 and CVE-2021-26855, CVE-2021-26857, CVE-2021-26858, and CVE-2021-27065 in Exchange Server.
- [G0046] FIN7: FIN7 has compromised targeted organizations through exploitation of CVE-2021-31207 in Exchange.
- [C0018] C0018: During C0018, the threat actors exploited VMWare Horizon Unified Access Gateways that were vulnerable to several Log4Shell vulnerabilities, including CVE-2021-44228, CVE-2021-45046, CVE-2021-45105, and CVE-2021-44832.
- [S0623] Siloscape: Siloscape is executed after the attacker gains initial access to a Windows container using a known vulnerability.
- [G1017] Volt Typhoon: Volt Typhoon has gained initial access through exploitation of multiple vulnerabilities in internet-facing software and appliances such as Fortinet, Ivanti (formerly Pulse Secure), NETGEAR, Citrix, and Cisco.
- [G0034] Sandworm Team: Sandworm Team exploits public-facing applications for initial access and to acquire infrastructure, such as exploitation of the EXIM mail transfer agent in Linux systems.
- [G0007] APT28: APT28 has used a variety of public exploits, including CVE 2020-0688 and CVE 2020-17144, to gain execution on vulnerable Microsoft Exchange; they have also conducted SQL injection attacks against external websites.
- [G0094] Kimsuky: Kimsuky has exploited various vulnerabilities for initial access, including Microsoft Exchange vulnerability CVE-2020-0688.
- [G1003] Ember Bear: Ember Bear gains initial access to victim environments by exploiting external-facing services. Examples include exploitation of CVE-2021-26084 in Confluence servers; CVE-2022-41040, ProxyShell, and other vulnerabilities in Microsoft Exchange; and multiple vulnerabilities in open-source platforms such as content management systems.
- [C0014] Operation Wocao: During Operation Wocao, threat actors gained initial access by exploiting vulnerabilities in JBoss webservers.
- [C0002] Night Dragon: During Night Dragon, threat actors used SQL injection exploits against extranet web servers to gain access.


### T1195.001 - Supply Chain Compromise: Compromise Software Dependencies and Development Tools

Procedures:

- [S0658] XCSSET: XCSSET adds malicious code to a host's Xcode projects by enumerating CocoaPods target_integrator.rb files under the /Library/Ruby/Gems folder or enumerates all .xcodeproj folders under a given directory. XCSSET then downloads a script and Mach-O file into the Xcode project folder.

### T1195.002 - Supply Chain Compromise: Compromise Software Supply Chain

Procedures:

- [G0096] APT41: APT41 gained access to production environments where they could inject malicious code into legitimate, signed files and widely distribute them to end users.
- [G0080] Cobalt Group: Cobalt Group has compromised legitimate web browser updates to deliver a backdoor.
- [G0115] GOLD SOUTHFIELD: GOLD SOUTHFIELD has distributed ransomware by backdooring software installers via a strategic web compromise of the site hosting Italian WinRAR.
- [S0493] GoldenSpy: GoldenSpy has been packaged with a legitimate tax preparation software.
- [S0562] SUNSPOT: SUNSPOT malware was designed and used to insert SUNBURST into software builds of the SolarWinds Orion IT management product.
- [G0034] Sandworm Team: Sandworm Team has distributed NotPetya by compromising the legitimate Ukrainian accounting software M.E.Doc and replacing a legitimate software update with a malicious one.
- [S0222] CCBkdr: CCBkdr was added to a legitimate, signed version 5.33 of the CCleaner software and distributed on CCleaner's distribution site.
- [G0035] Dragonfly: Dragonfly has placed trojanized installers for control system software on legitimate vendor app stores.
- [G0027] Threat Group-3390: Threat Group-3390 has compromised the Able Desktop installer to gain access to victim's environments.
- [G1034] Daggerfly: Daggerfly is associated with several supply chain compromises using malicious updates to compromise victims.
- [G1036] Moonstone Sleet: Moonstone Sleet has distributed a trojanized version of PuTTY software for initial access to victims.
- [C0024] SolarWinds Compromise: During the SolarWinds Compromise, APT29 gained initial network access to some victims via a trojanized update of SolarWinds Orion software.
- [G0046] FIN7: FIN7 has gained initial access by compromising a victim's software supply chain.

### T1195.003 - Supply Chain Compromise: Compromise Hardware Supply Chain


### T1199 - Trusted Relationship

Procedures:

- [G0115] GOLD SOUTHFIELD: GOLD SOUTHFIELD has breached Managed Service Providers (MSP's) to deliver malware to MSP customers.
- [G0007] APT28: Once APT28 gained access to the DCCC network, the group then proceeded to use that access to compromise the DNC network.
- [G0027] Threat Group-3390: Threat Group-3390 has compromised third party service providers to gain access to victim's environments.
- [G0034] Sandworm Team: Sandworm Team has used dedicated network connections from one victim organization to gain unauthorized access to a separate organization. Additionally, Sandworm Team has accessed Internet service providers and telecommunication entities that provide mobile connectivity.
- [G0045] menuPass: menuPass has used legitimate access granted to Managed Service Providers in order to access victims of interest.
- [C0024] SolarWinds Compromise: During the SolarWinds Compromise, APT29 gained access through compromised accounts at cloud solution partners, and used compromised certificates issued by Mimecast to authenticate to Mimecast customer systems.
- [G1039] RedCurl: RedCurl has gained access to a contractor to pivot to the victim’s infrastructure.
- [G0016] APT29: APT29 has compromised IT, cloud services, and managed services providers to gain broad access to multiple customers for subsequent operations.
- [G1005] POLONIUM: POLONIUM has used compromised credentials from an IT company to target downstream customers including a law firm and aviation company.
- [G0125] HAFNIUM: HAFNIUM has used stolen API keys and credentials associatd with privilege access management (PAM), cloud app providers, and cloud data management companies to access downstream customer environments.
- [G1004] LAPSUS$: LAPSUS$ has accessed internet-facing identity providers such as Azure Active Directory and Okta to target specific organizations.
- [G1041] Sea Turtle: Sea Turtle targeted third-party entities in trusted relationships with primary targets to ultimately achieve access at primary targets. Entities targeted included DNS registrars, telecommunication companies, and internet service providers.


### T1200 - Hardware Additions

Procedures:

- [G0105] DarkVishnya: DarkVishnya physically connected Bash Bunny, Raspberry Pi, netbooks, and inexpensive laptops to the target organization's environment to access the company’s local network.


### T1566.001 - Phishing: Spearphishing Attachment

Procedures:

- [G0080] Cobalt Group: Cobalt Group has sent spearphishing emails with various attachment types to corporate and personal email accounts of victim organizations. Attachment types have included .rtf, .doc, .xls, archives containing LNK files, and password protected archives containing .exe and .scr executables.
- [S0669] KOCTOPUS: KOCTOPUS has been distributed via spearphishing emails with malicious attachments.
- [C0028] 2015 Ukraine Electric Power Attack: During the 2015 Ukraine Electric Power Attack, Sandworm Team obtained their initial foothold into many IT systems using Microsoft Office attachments delivered through phishing emails.
- [S0447] Lokibot: Lokibot is delivered via a malicious XLS attachment contained within a spearhpishing email.
- [G0032] Lazarus Group: Lazarus Group has targeted victims with spearphishing emails containing malicious Microsoft Word documents.
- [G1031] Saint Bear: Saint Bear uses a variety of file formats, such as Microsoft Office documents, ZIP archives, PDF documents, and other items as phishing attachments for initial access.
- [S0331] Agent Tesla: The primary delivered mechanism for Agent Tesla is through email phishing messages.
- [G0081] Tropic Trooper: Tropic Trooper sent spearphishing emails that contained malicious Microsoft Office and fake installer file attachments.
- [G0037] FIN6: FIN6 has targeted victims with e-mails containing malicious attachments.
- [S1064] SVCReady: SVCReady has been distributed via spearphishing campaigns containing malicious Mircrosoft Word documents.
- [G0007] APT28: APT28 sent spearphishing emails containing malicious Microsoft Office and RAR attachments.
- [S1066] DarkTortilla: DarkTortilla has been distributed via spearphishing emails containing archive attachments, with file types such as .iso, .zip, .img, .dmg, and .tar, as well as through malicious documents.
- [G0018] admin@338: admin@338 has sent emails with malicious Microsoft Office documents attached.
- [G0112] Windshift: Windshift has sent spearphishing emails with attachment to harvest credentials and deliver malware.
- [G0060] BRONZE BUTLER: BRONZE BUTLER used spearphishing emails with malicious Microsoft Word attachments to infect victims.

### T1566.002 - Phishing: Spearphishing Link

Procedures:

- [G0098] BlackTech: BlackTech has used spearphishing e-mails with links to cloud services to deliver malware.
- [S0585] Kerrdown: Kerrdown has been distributed via e-mails containing a malicious link.
- [G0069] MuddyWater: MuddyWater has sent targeted spearphishing e-mails with malicious links.
- [G1014] LuminousMoth: LuminousMoth has sent spearphishing emails containing a malicious Dropbox download link.
- [G0142] Confucius: Confucius has sent malicious links to victims through email campaigns.
- [G0103] Mofang: Mofang delivered spearphishing emails with malicious links included.
- [G0094] Kimsuky: Kimsuky has sent spearphishing emails containing a link to a document that contained malicious macros or took the victim to an actor-controlled domain.
- [G0121] Sidewinder: Sidewinder has sent e-mails with malicious links often crafted for specific targets.
- [S0561] GuLoader: GuLoader has been spread in phishing campaigns using malicious web links.
- [S1017] OutSteel: OutSteel has been distributed through malicious links contained within spearphishing emails.
- [C0002] Night Dragon: During Night Dragon, threat actors sent spearphishing emails containing links to compromised websites where malware was downloaded.
- [S0669] KOCTOPUS: KOCTOPUS has been distributed as a malicious link within an email.
- [G0066] Elderwood: Elderwood has delivered zero-day exploits and malware to victims via targeted emails containing a link to malicious content hosted on an uncommon Web server.
- [S0528] Javali: Javali has been delivered via malicious links embedded in e-mails.
- [S1111] DarkGate: DarkGate is distributed in phishing emails containing links to distribute malicious VBS or MSI files. DarkGate uses applications such as Microsoft Teams for distributing links to payloads.

### T1566.003 - Phishing: Spearphishing via Service

Procedures:

- [G1012] CURIUM: CURIUM has used social media to deliver malicious files to victims.
- [G0112] Windshift: Windshift has used fake personas on social media to engage and target victims.
- [G0130] Ajax Security Team: Ajax Security Team has used various social media channels to spearphish victims.
- [G1011] EXOTIC LILY: EXOTIC LILY has used the e-mail notification features of legitimate file sharing services for spearphishing.
- [S1100] Ninja: Ninja has been distributed to victims via the messaging app Telegram.
- [G1022] ToddyCat: ToddyCat has sent loaders configured to run Ninja as zip archives via Telegram.
- [C0022] Operation Dream Job: During Operation Dream Job, Lazarus Group sent victims spearphishing messages via LinkedIn concerning fictitious jobs.
- [G0037] FIN6: FIN6 has used fake job advertisements sent via LinkedIn to spearphish targets.
- [G0016] APT29: APT29 has used the legitimate mailing service Constant Contact to send phishing e-mails.
- [G0049] OilRig: OilRig has used LinkedIn to send spearphishing links.
- [G0070] Dark Caracal: Dark Caracal spearphished victims via Facebook and Whatsapp.
- [G0032] Lazarus Group: Lazarus Group has used social media platforms, including LinkedIn and Twitter, to send spearphishing messages.
- [G1046] Storm-1811: Storm-1811 has used Microsoft Teams to send messages and initiate voice calls to victims posing as IT support personnel.
- [G0059] Magic Hound: Magic Hound used various social media channels (such as LinkedIn) as well as messaging services (such as WhatsApp) to spearphish victims.
- [G1036] Moonstone Sleet: Moonstone Sleet has used social media services to spear phish victims to deliver trojainized software.

### T1566.004 - Phishing: Spearphishing Voice

Procedures:

- [G1046] Storm-1811: Storm-1811 has initiated voice calls with victims posing as IT support to prompt users to download and execute scripts and other tools for initial access.
- [C0027] C0027: During C0027, Scattered Spider impersonated legitimate IT personnel in phone calls to direct victims to download a remote monitoring and management (RMM) tool that would allow the adversary to remotely control their system.


### T1659 - Content Injection

Procedures:

- [S1088] Disco: Disco has achieved initial access and execution through content injection into DNS, HTTP, and SMB replies to targeted hosts that redirect them to download malicious files.
- [G1019] MoustachedBouncer: MoustachedBouncer has injected content into DNS, HTTP, and SMB replies to redirect specifically-targeted victims to a fake Windows Update page to download malware.


### T1669 - Wi-Fi Networks

Procedures:

- [G0007] APT28: APT28 has exploited open Wi-Fi access points for initial access to target devices using the network.
- [C0051] APT28 Nearest Neighbor Campaign: During APT28 Nearest Neighbor Campaign, APT28 established wireless connections to secure, enterprise Wi-Fi networks belonging to a target organization for initial access into the environment.

