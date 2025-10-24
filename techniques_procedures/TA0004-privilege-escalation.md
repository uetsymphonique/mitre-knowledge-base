### T1037.001 - Boot or Logon Initialization Scripts: Logon Script (Windows)

Procedures:

- [G0007] APT28: An APT28 loader Trojan adds the Registry key HKCU\Environment\UserInitMprLogonScript to establish persistence.
- [S0438] Attor: Attor's dispatcher can establish persistence via adding a Registry key with a logon script HKEY_CURRENT_USER\Environment "UserInitMprLogonScript" .
- [S0044] JHUHUGIT: JHUHUGIT has registered a Windows shell script under the Registry key HKCU\Environment\UserInitMprLogonScript to establish persistence.
- [S0526] KGH_SPY: KGH_SPY has the ability to set the HKCU\Environment\UserInitMprLogonScript Registry key to execute logon scripts.
- [S0251] Zebrocy: Zebrocy performs persistence with a logon script via adding to the Registry key HKCU\Environment\UserInitMprLogonScript.
- [G0080] Cobalt Group: Cobalt Group has added persistence by registering the file name for the next stage malware under HKCU\Environment\UserInitMprLogonScript.

### T1037.002 - Boot or Logon Initialization Scripts: Login Hook

### T1037.003 - Boot or Logon Initialization Scripts: Network Logon Script

### T1037.004 - Boot or Logon Initialization Scripts: RC Scripts

Procedures:

- [G1047] Velvet Ant: Velvet Ant used a modified `/etc/rc.local` file on compromised F5 BIG-IP devices to maintain persistence.
- [S0394] HiddenWasp: HiddenWasp installs reboot persistence by adding itself to /etc/rc.local.
- [G0016] APT29: APT29 has installed a run command on a compromised system to enable malware execution on system startup.
- [S0690] Green Lambert: Green Lambert can add init.d and rc.d files in the /etc folder to establish persistence.
- [S0687] Cyclops Blink: Cyclops Blink has the ability to execute on device startup, using a modified RC script named S51armled.
- [S0278] iKitten: iKitten adds an entry to the rc.common file for persistence.

### T1037.005 - Boot or Logon Initialization Scripts: Startup Items

Procedures:

- [S0283] jRAT: jRAT can list and manage startup entries.


### T1053.002 - Scheduled Task/Job: At

Procedures:

- [G0027] Threat Group-3390: Threat Group-3390 actors use at to schedule tasks to run self-extracting RAR archives, which install HTTPBrowser or PlugX on other victims on a network.
- [S0488] CrackMapExec: CrackMapExec can set a scheduled task on the target system to execute commands remotely using at.
- [G0026] APT18: APT18 actors used the native at Windows task scheduler tool to use scheduled tasks for execution on a victim network.
- [G0060] BRONZE BUTLER: BRONZE BUTLER has used at to register a scheduled task to execute malware during lateral movement.
- [S0233] MURKYTOP: MURKYTOP has the capability to schedule remote AT jobs.
- [S0110] at: at can be used to schedule a task on a system to be executed at a specific date or time.

### T1053.003 - Scheduled Task/Job: Cron

Procedures:

- [S0374] SpeakUp: SpeakUp uses cron tasks to ensure persistence.
- [S0504] Anchor: Anchor can install itself as a cron job.
- [S0163] Janicab: Janicab used a cron job for persistence on Mac devices.
- [S0468] Skidmap: Skidmap has installed itself via crontab.
- [G0106] Rocke: Rocke installed a cron job that downloaded and executed files from the C2.
- [S0341] Xbash: Xbash can create a cronjob for persistence if it determines it is on a Linux system.
- [S0198] NETWIRE: NETWIRE can use crontabs to establish persistence.
- [S0588] GoldMax: The GoldMax Linux variant has used a crontab entry with a @reboot line to gain persistence.
- [S1198] Gomir: Gomir will configure a crontab for process execution to start the backdoor on reboot if it is not initially running under group 0 privileges.
- [S0587] Penquin: Penquin can use Cron to create periodic and pre-scheduled background jobs.
- [C0048] Operation MidnightEclipse: During Operation MidnightEclipse, threat actors configured cron jobs to retrieve payloads from actor-controlled infrastructure.
- [G1023] APT5: APT5 has made modifications to the crontab file including in `/var/cron/tabs/`.
- [S0599] Kinsing: Kinsing has used crontab to download and run shell scripts every minute to ensure persistence.
- [G0082] APT38: APT38 has used cron to create pre-scheduled and periodic background jobs on a Linux system.
- [S0401] Exaramel for Linux: Exaramel for Linux uses crontab for persistence if it does not have root privileges.

### T1053.005 - Scheduled Task/Job: Scheduled Task

Procedures:

- [S0588] GoldMax: GoldMax has used scheduled tasks to maintain persistence.
- [S0648] JSS Loader: JSS Loader has the ability to launch scheduled tasks to establish persistence.
- [S0414] BabyShark: BabyShark has used scheduled tasks to maintain persistence.
- [C0024] SolarWinds Compromise: During the SolarWinds Compromise, APT29 used `scheduler` and `schtasks` to create new tasks on remote host as part of their lateral movement. They manipulated scheduled tasks by updating an existing legitimate task to execute their tools and then returned the scheduled task to its original configuration. APT29 also created a scheduled task to maintain SUNSPOT persistence when the host booted.
- [S1014] DanBot: DanBot can use a scheduled task for installation.
- [S0170] Helminth: Helminth has used a scheduled task for persistence.
- [G0022] APT3: An APT3 downloader creates persistence by creating the following scheduled task: schtasks /create /tn "mysc" /tr C:\Users\Public\test.exe /sc ONLOGON /ru "System".
- [S1015] Milan: Milan can establish persistence on a targeted host with scheduled tasks.
- [S0697] HermeticWiper: HermeticWiper has the ability to use scheduled tasks for execution.
- [S1166] Solar: Solar can create scheduled tasks named Earth and Venus, which run every 30 and 40 seconds respectively, to support C2 and exfiltration.
- [S0266] TrickBot: TrickBot creates a scheduled task on the system that provides persistence.
- [S0335] Carbon: Carbon creates several tasks for later execution to continue persistence on the victim’s machine.
- [S0126] ComRAT: ComRAT has used a scheduled task to launch its PowerShell loader.
- [S0044] JHUHUGIT: JHUHUGIT has registered itself as a scheduled task to run each time the current user logs in.
- [G0080] Cobalt Group: Cobalt Group has created Windows tasks to establish persistence.

### T1053.006 - Scheduled Task/Job: Systemd Timers

### T1053.007 - Scheduled Task/Job: Container Orchestration Job


### T1055.001 - Process Injection: Dynamic-link Library Injection

Procedures:

- [S1027] Heyoka Backdoor: Heyoka Backdoor can inject a DLL into rundll32.exe for execution.
- [S1018] Saint Bot: Saint Bot has injected its DLL component into `EhStorAurhn.exe`.
- [S0082] Emissary: Emissary injects its DLL file into a newly spawned Internet Explorer process.
- [S0125] Remsec: Remsec can perform DLL injection.
- [S1066] DarkTortilla: DarkTortilla can use a .NET-based DLL named `RunPe6` for process injection.
- [S0089] BlackEnergy: BlackEnergy injects its DLL component into svchost.exe.
- [G0010] Turla: Turla has used Metasploit to perform reflective DLL injection in order to escalate privileges.
- [S0613] PS1: PS1 can inject its payload DLL Into memory.
- [S0250] Koadic: Koadic can perform process injection by using a reflective DLL.
- [S0055] RARSTONE: After decrypting itself in memory, RARSTONE downloads a DLL file from its C2 server and loads it in the memory space of a hidden Internet Explorer process. This “downloaded” file is actually not dropped onto the system.
- [S0154] Cobalt Strike: Cobalt Strike has the ability to load DLLs via reflective injection.
- [S0461] SDBbot: SDBbot has the ability to inject a downloaded DLL into a newly created rundll32.exe process.
- [S0455] Metamorfo: Metamorfo has injected a malicious DLL into the Windows Media Player process (wmplayer.exe).
- [S0126] ComRAT: ComRAT has injected its orchestrator DLL into explorer.exe. ComRAT has also injected its communications module into the victim's default browser to make C2 connections appear less suspicious as all network connections will be initiated by the browser process.
- [S0273] Socksbot: Socksbot creates a suspended svchost process and injects its DLL into it.

### T1055.002 - Process Injection: Portable Executable Injection

Procedures:

- [S1063] Brute Ratel C4: Brute Ratel C4 has injected Latrodectus into the Explorer.exe process on comrpomised hosts.
- [S0260] InvisiMole: InvisiMole can inject its backdoor as a portable executable into a target process.
- [S0030] Carbanak: Carbanak downloads an executable and injects it directly into a new process.
- [G0106] Rocke: Rocke's miner, "TermsHost.exe", evaded defenses by injecting itself into Windows processes, including Notepad.exe.
- [G0078] Gorgon Group: Gorgon Group malware can download a remote access tool, ShiftyBug, and inject into another process.
- [S0681] Lizar: Lizar can execute PE files in the address space of the specified process.
- [S1138] Gootloader: Gootloader can use its own PE loader to execute payloads in memory.
- [S0342] GreyEnergy: GreyEnergy has a module to inject a PE binary into a remote process.
- [S1158] DUSTPAN: DUSTPAN can inject its decrypted payload into another process.
- [S1145] Pikabot: Pikabot, following payload decryption, creates a process hard-coded into the dropped (e.g., WerFault.exe) and injects the decrypted core modules into it.
- [S0330] Zeus Panda: Zeus Panda checks processes on the system and if they meet the necessary requirements, it injects into that process.

### T1055.003 - Process Injection: Thread Execution Hijacking

Procedures:

- [S1145] Pikabot: Pikabot can create a suspended instance of a legitimate process (e.g., ctfmon.exe), allocate memory within the suspended process corresponding to Pikabot's core module, then redirect execution flow via `SetContextThread` API so that when the thread resumes the Pikabot core module is executed.
- [S0579] Waterbear: Waterbear can use thread injection to inject shellcode into the process of security software.
- [S0168] Gazer: Gazer performs thread execution hijacking to inject its orchestrator into a running thread from a remote process.
- [S0094] Trojan.Karagany: Trojan.Karagany can inject a suspended thread of its own process into a new process and initiate via the ResumeThread API.

### T1055.004 - Process Injection: Asynchronous Procedure Call

Procedures:

- [S0199] TURNEDUP: TURNEDUP is capable of injecting code into the APC queue of a created Rundll32 process as part of an "Early Bird injection."
- [S0517] Pillowmint: Pillowmint has used the NtQueueApcThread syscall to inject code into svchost.exe.
- [S0260] InvisiMole: InvisiMole can inject its code into a trusted process via the APC queue.
- [S1039] Bumblebee: Bumblebee can use asynchronous procedure call (APC) injection to execute commands received from C2.
- [S1018] Saint Bot: Saint Bot has written its payload into a newly-created `EhStorAuthn.exe` process using `ZwWriteVirtualMemory` and executed it using `NtQueueApcThread` and `ZwAlertResumeThread`.
- [S0484] Carberp: Carberp has queued an APC routine to explorer.exe by calling ZwQueueApcThread.
- [S0483] IcedID: IcedID has used ZwQueueApcThread to inject itself into remote processes.
- [S1207] XLoader: XLoader injects code into the APC queue using `NtQueueApcThread` API.
- [S1081] BADHATCH: BADHATCH can inject itself into a new `svchost.exe -k netsvcs` process using the asynchronous procedure call (APC) queue.
- [G0061] FIN8: FIN8 has injected malicious code into a new svchost.exe process.
- [S0438] Attor: Attor performs the injection by attaching its code into the APC queue using NtQueueApcThread API.
- [S1085] Sardonic: Sardonic can use the `QueueUserAPC` API to execute shellcode on a compromised machine.

### T1055.005 - Process Injection: Thread Local Storage

Procedures:

- [S0386] Ursnif: Ursnif has injected code into target processes via thread local storage callbacks.

### T1055.008 - Process Injection: Ptrace System Calls

Procedures:

- [S1109] PACEMAKER: PACEMAKER can use PTRACE to attach to a targeted process to read process memory.

### T1055.009 - Process Injection: Proc Memory

Procedures:

- [C0035] KV Botnet Activity: KV Botnet Activity final payload installation includes mounting and binding to the \/proc\/ filepath on the victim system to enable subsequent operation in memory while also removing on-disk artifacts.

### T1055.011 - Process Injection: Extra Window Memory Injection

Procedures:

- [S0091] Epic: Epic has overwritten the function pointer in the extra window memory of Explorer's Shell_TrayWnd in order to execute malicious code in the context of the explorer.exe process.
- [S0177] Power Loader: Power Loader overwrites Explorer’s Shell_TrayWnd extra window memory to redirect execution to a NTDLL function that is abused to assemble and execute a return-oriented programming (ROP) chain and create a malicious thread within Explorer.exe.

### T1055.012 - Process Injection: Process Hollowing

Procedures:

- [G0078] Gorgon Group: Gorgon Group malware can use process hollowing to inject one of its trojans into another process.
- [S0483] IcedID: IcedID can inject a Cobalt Strike beacon into cmd.exe via process hallowing.
- [S1207] XLoader: XLoader uses process hollowing by injecting itself into the `explorer.exe` process and other files ithin the Windows `SysWOW64` directory.
- [G0027] Threat Group-3390: A Threat Group-3390 tool can spawn `svchost.exe` and inject the payload into that process.
- [S0662] RCSession: RCSession can launch itself from a hollowed svchost.exe process.
- [S0354] Denis: Denis performed process hollowing through the API calls CreateRemoteThread, ResumeThread, and Wow64SetThreadContext.
- [S1065] Woody RAT: Woody RAT can create a suspended notepad process and write shellcode to delete a file into the suspended process using `NtWriteVirtualMemory`.
- [S0344] Azorult: Azorult can decrypt the payload into memory, create a new suspended process of itself, then inject a decrypted payload to the new process and resume new process execution.
- [G0040] Patchwork: A Patchwork payload uses process hollowing to hide the UAC bypass vulnerability exploitation inside svchost.exe.
- [S0650] QakBot: QakBot can use process hollowing to execute its main payload.
- [S0154] Cobalt Strike: Cobalt Strike can use process hollowing for execution.
- [S0447] Lokibot: Lokibot has used process hollowing to inject itself into legitimate Windows process.
- [S1086] Snip3: Snip3 can use RunPE to execute malicious payloads within a hollowed Windows process.
- [S0234] Bandook: Bandook has been launched by starting iexplore.exe and replacing it with Bandook's payload.
- [S1213] Lumma Stealer: Lumma Stealer has used process hollowing leveraging a legitimate program such as “BitLockerToGo.exe” to inject a malicious payload.

### T1055.013 - Process Injection: Process Doppelgänging

Procedures:

- [S0242] SynAck: SynAck abuses NTFS transactions to launch and conceal malicious processes.
- [S0534] Bazar: Bazar can inject into a target process using process doppelgänging.
- [G0077] Leafminer: Leafminer has used Process Doppelgänging to evade security software while deploying tools on compromised systems.

### T1055.014 - Process Injection: VDSO Hijacking

### T1055.015 - Process Injection: ListPlanting

Procedures:

- [S0260] InvisiMole: InvisiMole has used ListPlanting to inject code into a trusted process.


### T1068 - Exploitation for Privilege Escalation

Procedures:

- [G0027] Threat Group-3390: Threat Group-3390 has used CVE-2014-6324 and CVE-2017-0213 to escalate privileges.
- [S0125] Remsec: Remsec has a plugin to drop and execute vulnerable Outpost Sandbox or avast! Virtualization drivers in order to gain kernel mode privileges.
- [S0378] PoshC2: PoshC2 contains modules for local privilege escalation exploits such as CVE-2016-9192 and CVE-2016-0099.
- [G0125] HAFNIUM: HAFNIUM has targeted unpatched applications to elevate access in targeted organizations.
- [G0016] APT29: APT29 has exploited CVE-2021-36934 to escalate privileges on a compromised host.
- [S1151] ZeroCleare: ZeroCleare has used a vulnerable signed VBoxDrv driver to bypass Microsoft Driver Signature Enforcement (DSE) protections and subsequently load the unsigned RawDisk driver.
- [G0010] Turla: Turla has exploited vulnerabilities in the VBoxDrv.sys driver to obtain kernel mode privileges.
- [G0068] PLATINUM: PLATINUM has leveraged a zero-day vulnerability to escalate privileges.
- [S0154] Cobalt Strike: Cobalt Strike can exploit vulnerabilities such as MS14-058.
- [S0363] Empire: Empire can exploit vulnerabilities such as MS16-032 and MS16-135.
- [G0061] FIN8: FIN8 has exploited the CVE-2016-0167 local vulnerability.
- [G0080] Cobalt Group: Cobalt Group has used exploits to increase their levels of rights and privileges.
- [S0664] Pandora: Pandora can use CVE-2017-15303 to bypass Windows Driver Signature Enforcement (DSE) protection and load its driver.
- [S0484] Carberp: Carberp has exploited multiple Windows vulnerabilities (CVE-2010-2743, CVE-2010-3338, CVE-2010-4398, CVE-2008-1084) and a .NET Runtime Optimization vulnerability for privilege escalation.
- [S0050] CosmicDuke: CosmicDuke attempts to exploit privilege escalation vulnerabilities CVE-2010-0232 or CVE-2010-4398.


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


### T1098.001 - Account Manipulation: Additional Cloud Credentials

Procedures:

- [S1091] Pacu: Pacu can generate SSH and API keys for AWS infrastructure and additional API keys for other IAM users.
- [C0027] C0027: During C0027, Scattered Spider used aws_consoler to create temporary federated credentials for fake users in order to obfuscate which AWS credential is compromised and enable pivoting from the AWS CLI to console sessions without MFA.
- [C0024] SolarWinds Compromise: During the SolarWinds Compromise, APT29 added credentials to OAuth Applications and Service Principals.

### T1098.002 - Account Manipulation: Additional Email Delegate Permissions

Procedures:

- [C0038] HomeLand Justice: During HomeLand Justice, threat actors added the `ApplicationImpersonation` management role to accounts under their control to impersonate users and take ownership of targeted mailboxes.
- [C0024] SolarWinds Compromise: During the SolarWinds Compromise, APT29 added their own devices as allowed IDs for active sync using `Set-CASMailbox`, allowing it to obtain copies of victim mailboxes. It also added additional permissions (such as Mail.Read and Mail.ReadWrite) to compromised Application or Service Principals.
- [G0059] Magic Hound: Magic Hound granted compromised email accounts read access to the email boxes of additional targeted accounts. The group then was able to authenticate to the intended victim's OWA (Outlook Web Access) portal and read hundreds of email communications for information on Middle East organizations.
- [G0007] APT28: APT28 has used a Powershell cmdlet to grant the ApplicationImpersonation role to a compromised account.
- [G0016] APT29: APT29 has used a compromised global administrator account in Azure AD to backdoor a service principal with `ApplicationImpersonation` rights to start collecting emails from targeted mailboxes; APT29 has also used compromised accounts holding `ApplicationImpersonation` rights in Exchange to collect emails.

### T1098.003 - Account Manipulation: Additional Cloud Roles

Procedures:

- [C0027] C0027: During C0027, Scattered Spider used IAM manipulation to gain persistence and to assume or elevate privileges.
- [C0024] SolarWinds Compromise: During the SolarWinds Compromise, APT29 granted `company administrator` privileges to a newly created service principle.
- [G1015] Scattered Spider: During C0027, Scattered Spider used IAM manipulation to gain persistence and to assume or elevate privileges. Scattered Spider has also assigned user access admin roles in order to gain Tenant Root Group management permissions in Azure.
- [G1004] LAPSUS$: LAPSUS$ has added the global admin role to accounts they have created in the targeted organization's cloud instances.

### T1098.004 - Account Manipulation: SSH Authorized Keys

Procedures:

- [G1006] Earth Lusca: Earth Lusca has dropped an SSH-authorized key in the `/root/.ssh` folder in order to access a compromised server with SSH.
- [S0468] Skidmap: Skidmap has the ability to add the public key of its handlers to the authorized_keys file to maintain persistence on an infected host.
- [G1045] Salt Typhoon: Salt Typhoon has added SSH authorized_keys under root or other users at the Linux level on compromised network devices.
- [S0658] XCSSET: XCSSET will create an ssh key if necessary with the ssh-keygen -t rsa -f $HOME/.ssh/id_rsa -P command. XCSSET will upload a private key file to the server to remotely access the host without a password.
- [S0482] Bundlore: Bundlore creates a new key pair with ssh-keygen and drops the newly created user key in authorized_keys to enable remote login.
- [G0139] TeamTNT: TeamTNT has added RSA keys in authorized_keys.

### T1098.005 - Account Manipulation: Device Registration

Procedures:

- [G0016] APT29: APT29 has enrolled their own devices into compromised cloud tenants, including enrolling a device in MFA to an Azure AD environment following a successful password guessing attack against a dormant account.
- [S0677] AADInternals: AADInternals can register a device to Azure AD.
- [C0024] SolarWinds Compromise: During the SolarWinds Compromise, APT29 registered devices in order to enable mailbox syncing via the `Set-CASMailbox` command.
- [C0027] C0027: During C0027, Scattered Spider registered devices for MFA to maintain persistence through victims' VPN.

### T1098.006 - Account Manipulation: Additional Container Cluster Roles

### T1098.007 - Account Manipulation: Additional Local or Domain Groups

Procedures:

- [S0649] SMOKEDHAM: SMOKEDHAM has added user accounts to local Admin groups.
- [G0096] APT41: APT41 has added user accounts to the User and Admin groups.
- [G0022] APT3: APT3 has been known to add created accounts to local admin groups to maintain elevated access.
- [S0039] Net: The `net localgroup` and `net group` commands in Net can be used to add existing users to local and domain groups.
- [G0059] Magic Hound: Magic Hound has added a user named DefaultAccount to the Administrators and Remote Desktop Users groups.
- [G1023] APT5: APT5 has created their own accounts with Local Administrator privileges to maintain access to systems with short-cycle credential rotation.
- [G0035] Dragonfly: Dragonfly has added newly created accounts to the administrators group to maintain elevated access.
- [G1016] FIN13: FIN13 has assigned newly created accounts the sysadmin role to maintain persistence.
- [S1111] DarkGate: DarkGate elevates accounts created through the malware to the local administration group during execution.
- [S0382] ServHelper: ServHelper has added a user named "supportaccount" to the Remote Desktop Users and Administrators groups.
- [G0094] Kimsuky: Kimsuky has added accounts to specific groups with net localgroup.


### T1134.001 - Access Token Manipulation: Token Impersonation/Theft

Procedures:

- [S0182] FinFisher: FinFisher uses token manipulation with NtFilterToken as part of UAC bypass.
- [S0367] Emotet: Emotet has the ability to duplicate the user’s token. For example, Emotet may use a variant of Google’s ProtoBuf to send messages that specify how code will be executed.
- [S0603] Stuxnet: Stuxnet attempts to impersonate an anonymous token to enumerate bindings in the service control manager.
- [C0038] HomeLand Justice: During HomeLand Justice, threat actors used custom tooling to acquire tokens using `ImpersonateLoggedOnUser/SetThreadToken`.
- [S0154] Cobalt Strike: Cobalt Strike can steal access tokens from exiting processes.
- [S1011] Tarrask: Tarrask leverages token theft to obtain `lsass.exe` security permissions.
- [S0692] SILENTTRINITY: SILENTTRINITY can find a process owned by a specific user and impersonate the associated token.
- [S0570] BitPaymer: BitPaymer can use the tokens of users to create processes on infected systems.
- [S0140] Shamoon: Shamoon can impersonate tokens using LogonUser, ImpersonateLoggedOnUser, and ImpersonateNamedPipeClient.
- [S0439] Okrum: Okrum can impersonate a logged-on user's security context using a call to the ImpersonateLoggedOnUser API.
- [S0456] Aria-body: Aria-body has the ability to duplicate a token from ntprint.exe.
- [G0007] APT28: APT28 has used CVE-2015-1701 to access the SYSTEM token and copy it into the current process as part of privilege escalation.
- [S0496] REvil: REvil can obtain the token from the user that launched the explorer.exe process to avoid affecting the desktop of the SYSTEM user.
- [S0192] Pupy: Pupy can obtain a list of SIDs and provide the option for selecting process tokens to impersonate.
- [S1081] BADHATCH: BADHATCH can impersonate a `lsass.exe` or `vmtoolsd.exe` token.

### T1134.002 - Access Token Manipulation: Create Process with Token

Procedures:

- [S0344] Azorult: Azorult can call WTSQueryUserToken and CreateProcessAsUser to start a new process with local system privileges.
- [G0010] Turla: Turla RPC backdoors can impersonate or steal process tokens before executing commands.
- [S0501] PipeMon: PipeMon can attempt to gain administrative privileges using token impersonation.
- [G0032] Lazarus Group: Lazarus Group keylogger KiloAlfa obtains user tokens from interactive sessions to execute itself with API call CreateProcessAsUserA under that user's context.
- [S0378] PoshC2: PoshC2 can use Invoke-RunAs to make tokens.
- [S0456] Aria-body: Aria-body has the ability to execute a process using runas.
- [S0496] REvil: REvil can launch an instance of itself with administrative rights using runas.
- [S0412] ZxShell: ZxShell has a command called RunAs, which creates a new process as another user or process context.
- [S0689] WhisperGate: The WhisperGate third stage can use the AdvancedRun.exe tool to execute commands in the context of the Windows TrustedInstaller group via `%TEMP%\AdvancedRun.exe" /EXEFilename "C:\Windows\System32\sc.exe" /WindowState 0 /CommandLine "stop WinDefend" /StartDirectory "" /RunAs 8 /Run`.
- [S0356] KONNI: KONNI has duplicated the token of a high integrity process to spawn an instance of cmd.exe under an impersonated user.
- [S0239] Bankshot: Bankshot grabs a user token using WTSQueryUserToken and then creates a process by impersonating a logged-on user.
- [S0363] Empire: Empire can use Invoke-RunAs to make tokens.

### T1134.003 - Access Token Manipulation: Make and Impersonate Token

Procedures:

- [S1060] Mafalda: Mafalda can create a token for a different user.
- [G1043] BlackByte: BlackByte constructed a valid authentication token following Microsoft Exchange exploitation to allow for follow-on privileged command execution.
- [G1016] FIN13: FIN13 has utilized tools such as Incognito V2 for token manipulation and impersonation.
- [S0692] SILENTTRINITY: SILENTTRINITY can make tokens from known credentials.
- [S0154] Cobalt Strike: Cobalt Strike can make tokens from known credentials.

### T1134.004 - Access Token Manipulation: Parent PID Spoofing

Procedures:

- [S0356] KONNI: KONNI has used parent PID spoofing to spawn a new `cmd` process using `CreateProcessW` and a handle to `Taskmgr.exe`.
- [S0154] Cobalt Strike: Cobalt Strike can spawn processes with alternate PPIDs.
- [S0501] PipeMon: PipeMon can use parent PID spoofing to elevate privileges.
- [S1111] DarkGate: DarkGate relies on parent PID spoofing as part of its "rootkit-like" functionality to evade detection via Task Manager or Process Explorer.

### T1134.005 - Access Token Manipulation: SID-History Injection

Procedures:

- [S0002] Mimikatz: Mimikatz's MISC::AddSid module can append any SID or user/group account to a user's SID-History. Mimikatz also utilizes SID-History Injection to expand the scope of other components such as generated Kerberos Golden Tickets and DCSync beyond a single domain.
- [S0363] Empire: Empire can add a SID-History to a user if on a domain controller.


### T1484.001 - Domain or Tenant Policy Modification: Group Policy Modification

Procedures:

- [S1058] Prestige: Prestige has been deployed using the Default Domain Group Policy Object from an Active Directory Domain Controller.
- [S1202] LockBit 3.0: LockBit 3.0 can enable options for propogation through Group Policy Objects.
- [S0697] HermeticWiper: HermeticWiper has the ability to deploy through an infected system's default domain policy.
- [G1021] Cinnamon Tempest: Cinnamon Tempest has used Group Policy to deploy batch scripts for ransomware deployment.
- [S0363] Empire: Empire can use New-GPOImmediateTask to modify a GPO that will install and execute a malicious Scheduled Task/Job.
- [G0096] APT41: APT41 used scheduled tasks created via Group Policy Objects (GPOs) to deploy ransomware.
- [S1199] LockBit 2.0: LockBit 2.0 can modify Group Policy to disable Windows Defender and to automatically infect devices in Windows domains.
- [G0119] Indrik Spider: Indrik Spider has used Group Policy Objects to deploy batch scripts.
- [S0554] Egregor: Egregor can modify the GPO to evade detection.
- [S0688] Meteor: Meteor can use group policy to push a scheduled task from the AD to all network machines.
- [C0034] 2022 Ukraine Electric Power Attack: During the 2022 Ukraine Electric Power Attack, Sandworm Team leveraged Group Policy Objects (GPOs) to deploy and execute malware.

### T1484.002 - Domain or Tenant Policy Modification: Trust Modification

Procedures:

- [G1015] Scattered Spider: Scattered Spider adds a federated identity provider to the victim’s SSO tenant and activates automatic account linking.
- [S0677] AADInternals: AADInternals can create a backdoor by converting a domain to a federated domain which will be able to authenticate any user across the tenant. AADInternals can also modify DesktopSSO information.
- [C0024] SolarWinds Compromise: During the SolarWinds Compromise, APT29 changed domain federation trust settings using Azure AD administrative permissions to configure the domain to accept authorization tokens signed by their own SAML signing certificate.


### T1543.001 - Create or Modify System Process: Launch Agent

Procedures:

- [S0274] Calisto: Calisto adds a .plist file to the /Library/LaunchAgents folder to maintain persistence.
- [S0279] Proton: Proton persists via Launch Agent.
- [S0282] MacSpy: MacSpy persists via a Launch Agent.
- [S0235] CrossRAT: CrossRAT creates a Launch Agent on macOS.
- [S0281] Dok: Dok installs two LaunchAgents to redirect all network traffic with a randomly generated name for each plist file maintaining the format com.random.name.plist.
- [S0497] Dacls: Dacls can establish persistence via a LaunchAgent.
- [S1016] MacMa: MacMa installs a `com.apple.softwareupdate.plist` file in the `/LaunchAgents` folder with the `RunAtLoad` value set to `true`. Upon user login, MacMa is executed from `/var/root/.local/softwareupdate` with root privileges. Some variations also include the `LimitLoadToSessionType` key with the value `Aqua`, ensuring the MacMa only runs when there is a logged in GUI user.
- [S0352] OSX_OCEANLOTUS.D: OSX_OCEANLOTUS.D can create a persistence file in the folder /Library/LaunchAgents.
- [S0482] Bundlore: Bundlore can persist via a LaunchAgent.
- [S0595] ThiefQuest: ThiefQuest installs a launch item using an embedded encrypted launch agent property list template. The plist file is installed in the ~/Library/LaunchAgents/ folder and configured with the path to the persistent binary located in the ~/Library/ folder.
- [S1048] macOS.OSAMiner: macOS.OSAMiner has placed a Stripped Payloads with a `plist` extension in the Launch Agent's folder.
- [S0369] CoinTicker: CoinTicker creates user launch agents named .espl.plist and com.apple.[random string].plist to establish persistence.
- [S0690] Green Lambert: Green Lambert can create a Launch Agent with the `RunAtLoad` key-value pair set to true, ensuring the `com.apple.GrowlHelper.plist` file runs every time a user logs in.
- [S1153] Cuckoo Stealer: Cuckoo Stealer can achieve persistence by creating launch agents to repeatedly execute malicious payloads.
- [S0492] CookieMiner: CookieMiner has installed multiple new Launch Agents in order to maintain persistence for cryptocurrency mining software.

### T1543.002 - Create or Modify System Process: Systemd Service

Procedures:

- [G0139] TeamTNT: TeamTNT has established persistence through the creation of a cryptocurrency mining system service using systemctl.
- [S1198] Gomir: Gomir creates a systemd service named `syslogd` for persistence.
- [C0034] 2022 Ukraine Electric Power Attack: During the 2022 Ukraine Electric Power Attack, Sandworm Team configured Systemd to maintain persistence of GOGETTER, specifying the `WantedBy=multi-user.target` configuration to run GOGETTER when the system begins accepting user logins.
- [S0192] Pupy: Pupy can be used to establish persistence using a systemd service.
- [S0410] Fysbis: Fysbis has established persistence using a systemd service.
- [S1078] RotaJakiro: Depending on the Linux distribution and when executing with root permissions, RotaJakiro may install persistence using a `.service` file under the `/lib/systemd/system/` folder.
- [S0663] SysUpdate: SysUpdate can copy a script to the user owned `/usr/lib/systemd/system/` directory with a symlink mapped to a `root` owned directory, `/etc/ystem/system`, in the unit configuration file's `ExecStart` directive to establish persistence and elevate privileges.
- [S0401] Exaramel for Linux: Exaramel for Linux has a hardcoded location under systemd that it uses to achieve persistence if it is running as root.
- [G0106] Rocke: Rocke has installed a systemd service script to maintain persistence.
- [S0601] Hildegard: Hildegard has started a monero service.

### T1543.003 - Create or Modify System Process: Windows Service

Procedures:

- [S1090] NightClub: NightClub has created a Windows service named `WmdmPmSp` to establish persistence.
- [S0604] Industroyer: Industroyer can use an arbitrary system service to load at system boot for persistence and replaces the ImagePath registry value of a Windows service with a new backdoor binary.
- [G0081] Tropic Trooper: Tropic Trooper has installed a service pointing to a malicious DLL dropped to disk.
- [S1044] FunnyDream: FunnyDream has established persistence by running `sc.exe` and by setting the `WSearch` service to run automatically.
- [S0141] Winnti for Windows: Winnti for Windows sets its DLL file as a new service in the Registry to establish persistence.
- [S0625] Cuba: Cuba can modify services by using the OpenService and ChangeServiceConfig functions.
- [S0204] Briba: Briba installs a service pointing to a malicious DLL dropped to disk.
- [S1033] DCSrv: DCSrv has created new services for persistence by modifying the Registry.
- [S0612] WastedLocker: WastedLocker created and established a service that runs until the encryption process is complete.
- [S0493] GoldenSpy: GoldenSpy has established persistence by running in the background as an autostart service.
- [C0012] Operation CuckooBees: During Operation CuckooBees, the threat actors modified the `IKEEXT` and `PrintNotify` Windows services for persistence.
- [G0105] DarkVishnya: DarkVishnya created new services for shellcode loaders distribution.
- [S0180] Volgmer: Volgmer installs a copy of itself in a randomly selected service, then overwrites the ServiceDLL entry in the service's Registry entry. Some Volgmer variants also install .dll files as services with names generated by a list of hard-coded strings.
- [S0149] MoonWind: MoonWind installs itself as a new service with automatic startup to establish persistence. The service checks every 60 seconds to determine if the malware is running; if not, it will spawn a new instance.
- [S0050] CosmicDuke: CosmicDuke uses Windows services typically named "javamtsup" for persistence.

### T1543.004 - Create or Modify System Process: Launch Daemon

Procedures:

- [S0690] Green Lambert: Green Lambert can add a plist file in the `Library/LaunchDaemons` to establish persistence.
- [S1105] COATHANGER: COATHANGER will create a daemon for timed check-ins with command and control infrastructure.
- [S0595] ThiefQuest: When running with root privileges after a Launch Agent is installed, ThiefQuest installs a plist file to the /Library/LaunchDaemons/ folder with the RunAtLoad key set to true establishing persistence as a Launch Daemon.
- [S0451] LoudMiner: LoudMiner adds plist files with the naming format com.[random_name].plist in the /Library/LaunchDaemons folder with the RunAtLoad and KeepAlive keys set to true.
- [S0352] OSX_OCEANLOTUS.D: If running with root permissions, OSX_OCEANLOTUS.D can create a persistence file in the folder /Library/LaunchDaemons.
- [S0482] Bundlore: Bundlore can persist via a LaunchDaemon.
- [S0497] Dacls: Dacls can establish persistence via a Launch Daemon.
- [S0658] XCSSET: XCSSET uses the ssh launchdaemon to elevate privileges, bypass system controls, and enable remote access to the victim.
- [S0584] AppleJeus: AppleJeus has placed a plist file within the LaunchDaemons folder and launched it manually.

### T1543.005 - Create or Modify System Process: Container Service


### T1546.001 - Event Triggered Execution: Change Default File Association

Procedures:

- [S0692] SILENTTRINITY: SILENTTRINITY can conduct an image hijack of an `.msc` file extension as part of its UAC bypass process.
- [G0094] Kimsuky: Kimsuky has a HWP document stealer module which changes the default program association in the registry to open HWP documents.

### T1546.002 - Event Triggered Execution: Screensaver

Procedures:

- [S0168] Gazer: Gazer can establish persistence through the system screensaver by configuring it to execute the malware.

### T1546.003 - Event Triggered Execution: Windows Management Instrumentation Event Subscription

Procedures:

- [G0108] Blue Mockingbird: Blue Mockingbird has used mofcomp.exe to establish WMI Event Subscription persistence mechanisms configured from a *.mof file.
- [S1085] Sardonic: Sardonic can use a WMI event filter to invoke a command-line event consumer to gain persistence.
- [G0016] APT29: APT29 has used WMI event subscriptions for persistence.
- [S1059] metaMain: metaMain registered a WMI event subscription consumer called "hard_disk_stat" to establish persistence.
- [G1001] HEXANE: HEXANE has used WMI event subscriptions for persistence.
- [G0061] FIN8: FIN8 has used WMI event subscriptions for persistence.
- [S0511] RegDuke: RegDuke can persist using a WMI consumer that is launched every time a process named WINWORD.EXE is started.
- [S0692] SILENTTRINITY: SILENTTRINITY can create a WMI Event to execute a payload for persistence.
- [G0065] Leviathan: Leviathan has used WMI for persistence.
- [S0376] HOPLIGHT: HOPLIGHT can use WMI event subscriptions to create persistence.
- [C0024] SolarWinds Compromise: During the SolarWinds Compromise, APT29 used a WMI event filter to invoke a command-line event consumer at system boot time to launch a backdoor with `rundll32.exe`.
- [G0010] Turla: Turla has used WMI event filters and consumers to establish persistence.
- [G1013] Metador: Metador has established persistence through the use of a WMI event subscription combined with unusual living-off-the-land binaries such as `cdb.exe`.
- [G0064] APT33: APT33 has attempted to use WMI event subscriptions to establish persistence on compromised hosts.
- [S1081] BADHATCH: BADHATCH can use WMI event subscriptions for persistence.

### T1546.004 - Event Triggered Execution: Unix Shell Configuration Modification

Procedures:

- [S1078] RotaJakiro: When executing with non-root level permissions, RotaJakiro can install persistence by adding a command to the .bashrc file that executes a binary in the `${HOME}/.gvfsd/.profile/` folder.
- [S0362] Linux Rabbit: Linux Rabbit maintains persistence on an infected machine through rc.local and .bashrc files.
- [C0045] ShadowRay: During ShadowRay, threat actors executed commands on interactive and reverse shells.
- [S0690] Green Lambert: Green Lambert can establish persistence on a compromised host through modifying the `profile`, `login`, and run command (rc) files associated with the `bash`, `csh`, and `tcsh` shells.
- [S0658] XCSSET: Using AppleScript, XCSSET adds it's executable to the user's `~/.zshrc_aliases` file (`"echo " & payload & " > ~/zshrc_aliases"`), it then adds a line to the .zshrc file to source the `.zshrc_aliases` file (`[ -f $HOME/.zshrc_aliases ] && . $HOME/.zshrc_aliases`). Each time the user starts a new `zsh` terminal session, the `.zshrc` file executes the `.zshrc_aliases` file.

### T1546.005 - Event Triggered Execution: Trap

### T1546.006 - Event Triggered Execution: LC_LOAD_DYLIB Addition

### T1546.007 - Event Triggered Execution: Netsh Helper DLL

Procedures:

- [S0108] netsh: netsh can be used as a persistence proxy technique to execute a helper DLL when netsh.exe is executed.

### T1546.008 - Event Triggered Execution: Accessibility Features

Procedures:

- [S0363] Empire: Empire can leverage WMI debugging to remotely replace binaries like sethc.exe, Utilman.exe, and Magnify.exe with cmd.exe.
- [G0096] APT41: APT41 leveraged sticky keys to establish persistence.
- [G0022] APT3: APT3 replaces the Sticky Keys binary C:\Windows\System32\sethc.exe for persistence.
- [G0009] Deep Panda: Deep Panda has used the sticky-keys technique to bypass the RDP login screen on remote systems during intrusions.
- [G0001] Axiom: Axiom actors have been known to use the Sticky Keys replacement within RDP sessions to obtain persistence.
- [G0117] Fox Kitten: Fox Kitten has used sticky keys to launch a command prompt.
- [G0016] APT29: APT29 used sticky-keys to obtain unauthenticated, privileged console access.

### T1546.009 - Event Triggered Execution: AppCert DLLs

Procedures:

- [S0196] PUNCHBUGGY: PUNCHBUGGY can establish using a AppCertDLLs Registry key.

### T1546.010 - Event Triggered Execution: AppInit DLLs

Procedures:

- [G0087] APT39: APT39 has used malware to set LoadAppInit_DLLs in the Registry key SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows in order to establish persistence.
- [S0098] T9000: If a victim meets certain criteria, T9000 uses the AppInit_DLL functionality to achieve persistence by ensuring that every user mode process that is spawned will load its malicious DLL, ResN32.dll. It does this by creating the following Registry keys: HKLM\Software\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs – %APPDATA%\Intel\ResN32.dll and HKLM\Software\Microsoft\Windows NT\CurrentVersion\Windows\LoadAppInit_DLLs – 0x1.
- [S0107] Cherry Picker: Some variants of Cherry Picker use AppInit_DLLs to achieve persistence by creating the following Registry key: HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows "AppInit_DLLs"="pserver32.dll"
- [S0458] Ramsay: Ramsay can insert itself into the address space of other applications using the AppInit DLL Registry key.

### T1546.011 - Event Triggered Execution: Application Shimming

Procedures:

- [S0517] Pillowmint: Pillowmint has used a malicious shim database to maintain persistence.
- [S0461] SDBbot: SDBbot has the ability to use application shimming for persistence if it detects it is running as admin on Windows XP or 7, by creating a shim database to patch services.exe.
- [G0046] FIN7: FIN7 has used application shim databases for persistence.
- [S0444] ShimRat: ShimRat has installed shim databases in the AppPatch folder.

### T1546.012 - Event Triggered Execution: Image File Execution Options Injection

Procedures:

- [S0559] SUNBURST: SUNBURST created an Image File Execution Options (IFEO) Debugger registry value for the process dllhost.exe to trigger the installation of Cobalt Strike.
- [S0461] SDBbot: SDBbot has the ability to use image file execution options for persistence if it detects it is running with admin privileges on a Windows version newer than Windows 7.
- [C0032] C0032: During the C0032 campaign, TEMP.Veles modified and added entries within HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options to maintain persistence.

### T1546.013 - Event Triggered Execution: PowerShell Profile

Procedures:

- [G0010] Turla: Turla has used PowerShell profiles to maintain persistence on an infected machine.

### T1546.014 - Event Triggered Execution: Emond

### T1546.015 - Event Triggered Execution: Component Object Model Hijacking

Procedures:

- [S0045] ADVSTORESHELL: Some variants of ADVSTORESHELL achieve persistence by registering the payload as a Shell Icon Overlay handler COM object.
- [S0356] KONNI: KONNI has modified ComSysApp service to load the malicious DLL payload.
- [G0007] APT28: APT28 has used COM hijacking for persistence by replacing the legitimate MMDeviceEnumerator object with a payload.
- [S1050] PcShare: PcShare has created the `HKCU\\Software\\Classes\\CLSID\\{42aedc87-2188-41fd-b9a3-0c966feabec1}\\InprocServer32` Registry key for persistence.
- [S0670] WarzoneRAT: WarzoneRAT can perform COM hijacking by setting the path to itself to the `HKCU\Software\Classes\Folder\shell\open\command` key with a `DelegateExecute` parameter.
- [S0126] ComRAT: ComRAT samples have been seen which hijack COM objects for persistence by replacing the path to shell32.dll in registry location HKCU\Software\Classes\CLSID\{42aedc87-2188-41fd-b9a3-0c966feabec1}\InprocServer32.
- [S1064] SVCReady: SVCReady has created the `HKEY_CURRENT_USER\Software\Classes\CLSID\{E6D34FFC-AD32-4d6a-934C-D387FA873A19}` Registry key for persistence.
- [S0256] Mosquito: Mosquito uses COM hijacking as a method of persistence.
- [S0679] Ferocious: Ferocious can use COM hijacking to establish persistence.
- [S0127] BBSRAT: BBSRAT has been seen persisting via COM hijacking through replacement of the COM object for MruPidlList {42aedc87-2188-41fd-b9a3-0c966feabec1} or Microsoft WBEM New Event Subsystem {F3130CDB-AA52-4C3A-AB32-85FFC23AF9C1} depending on the system's CPU architecture.
- [S0692] SILENTTRINITY: SILENTTRINITY can add a CLSID key for payload execution through `Registry.CurrentUser.CreateSubKey("Software\\Classes\\CLSID\\{" + clsid + "}\\InProcServer32")`.
- [S0044] JHUHUGIT: JHUHUGIT has used COM hijacking to establish persistence by hijacking a class named MMDeviceEnumerator and also by registering the payload as a Shell Icon Overlay handler COM object ({3543619C-D563-43f7-95EA-4DA7E1CC396A}).

### T1546.016 - Event Triggered Execution: Installer Packages

Procedures:

- [S0584] AppleJeus: During AppleJeus's installation process, it uses `postinstall` scripts to extract a hidden plist from the application's `/Resources` folder and execute the `plist` file as a Launch Daemon with elevated permissions.

### T1546.017 - Event Triggered Execution: Udev Rules


### T1547.001 - Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder

Procedures:

- [S0082] Emissary: Variants of Emissary have added Run Registry keys to establish persistence.
- [S0124] Pisloader: Pisloader establishes persistence via a Registry Run key.
- [S0396] EvilBunny: EvilBunny has created Registry keys for persistence in [HKLM|HKCU]\…\CurrentVersion\Run.
- [G0073] APT19: An APT19 HTTP malware variant establishes persistence by setting the Registry key HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Windows Debug Tools-%LOCALAPPDATA%\.
- [G0067] APT37: APT37's has added persistence via the Registry key HKCU\Software\Microsoft\CurrentVersion\Run\.
- [G0087] APT39: APT39 has maintained persistence using the startup folder.
- [S0198] NETWIRE: NETWIRE creates a Registry start-up entry to establish persistence.
- [G1018] TA2541: TA2541 has placed VBS files in the Startup folder and used Registry run keys to establish persistence for malicious payloads.
- [S0386] Ursnif: Ursnif has used Registry Run keys to establish automatic execution at system startup.
- [S0093] Backdoor.Oldrea: Backdoor.Oldrea adds Registry Run keys to achieve persistence.
- [S0028] SHIPSHAPE: SHIPSHAPE achieves persistence by creating a shortcut in the Startup folder.
- [G0048] RTM: RTM has used Registry run keys to establish persistence for the RTM Trojan and other tools, such as a modified version of TeamViewer remote desktop software.
- [G0059] Magic Hound: Magic Hound malware has used Registry Run keys to establish persistence.
- [S1044] FunnyDream: FunnyDream can use a Registry Run Key and the Startup folder to establish persistence.
- [S0331] Agent Tesla: Agent Tesla can add itself to the Registry as a startup program to establish persistence.

### T1547.002 - Boot or Logon Autostart Execution: Authentication Package

Procedures:

- [S0143] Flame: Flame can use Windows Authentication Packages for persistence.

### T1547.003 - Boot or Logon Autostart Execution: Time Providers

### T1547.004 - Boot or Logon Autostart Execution: Winlogon Helper DLL

Procedures:

- [S0168] Gazer: Gazer can establish persistence by setting the value “Shell” with “explorer.exe, %malware_pathfile%” under the Registry key HKCU\Software\Microsoft\Windows NT\CurrentVersion\Winlogon.
- [S1066] DarkTortilla: DarkTortilla has established persistence via the `Software\Microsoft\Windows NT\CurrentVersion\Winlogon` registry key.
- [S0200] Dipsind: A Dipsind variant registers as a Winlogon Event Notify DLL to establish persistence.
- [G0102] Wizard Spider: Wizard Spider has established persistence using Userinit by adding the Registry key HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon.
- [S0534] Bazar: Bazar can use Winlogon Helper DLL to establish persistence.
- [S0375] Remexi: Remexi achieves persistence using Userinit by adding the Registry key HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit.
- [S0379] Revenge RAT: Revenge RAT creates a Registry key at HKCU\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell to survive a system reboot.
- [G0081] Tropic Trooper: Tropic Trooper has created the Registry key HKCU\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell and sets the value to establish persistence.
- [S1202] LockBit 3.0: LockBit 3.0 can enable automatic logon through the `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon` Registry key.
- [G0010] Turla: Turla established persistence by adding a Shell value under the Registry key HKCU\Software\Microsoft\Windows NT\CurrentVersion\Winlogon.
- [S0387] KeyBoy: KeyBoy issues the command reg add “HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon” to achieve persistence.
- [S0351] Cannon: Cannon adds the Registry key HKCU\Software\Microsoft\Windows NT\CurrentVersion\Winlogon to establish persistence.

### T1547.005 - Boot or Logon Autostart Execution: Security Support Provider

Procedures:

- [S0002] Mimikatz: The Mimikatz credential dumper contains an implementation of an SSP.
- [S0363] Empire: Empire can enumerate Security Support Providers (SSPs) as well as utilize PowerSploit's Install-SSP and Invoke-Mimikatz to install malicious SSPs and log authentication events.
- [S0194] PowerSploit: PowerSploit's Install-SSP Persistence module can be used to establish by installing a SSP DLL.

### T1547.006 - Boot or Logon Autostart Execution: Kernel Modules and Extensions

Procedures:

- [S0502] Drovorub: Drovorub can use kernel modules to establish persistence.
- [S0468] Skidmap: Skidmap has the ability to install several loadable kernel modules (LKMs) on infected machines.
- [C0012] Operation CuckooBees: During Operation CuckooBees, attackers used a signed kernel rootkit to establish additional persistence.

### T1547.007 - Boot or Logon Autostart Execution: Re-opened Applications

### T1547.008 - Boot or Logon Autostart Execution: LSASS Driver

Procedures:

- [S0176] Wingbird: Wingbird drops a malicious file (sspisrv.dll) alongside a copy of lsass.exe, which is used to register a service that loads sspisrv.dll as a driver. The payload of the malicious driver (located in its entry-point function) is executed when loaded by lsass.exe before the spoofed service becomes unstable and crashes.
- [S0208] Pasam: Pasam establishes by infecting the Security Accounts Manager (SAM) DLL to load a malicious DLL dropped to disk.

### T1547.009 - Boot or Logon Autostart Execution: Shortcut Modification

Procedures:

- [S0270] RogueRobin: RogueRobin establishes persistence by creating a shortcut (.LNK file) in the Windows startup folder to run a script each time the user logs in.
- [S0153] RedLeaves: RedLeaves attempts to add a shortcut file in the Startup folder to achieve persistence.
- [S0439] Okrum: Okrum can establish persistence by creating a .lnk shortcut to itself in the Startup folder.
- [S0172] Reaver: Reaver creates a shortcut file and saves it in a Startup folder to establish persistence.
- [S0531] Grandoreiro: Grandoreiro can write or modify browser shortcuts to enable launching of malicious browser extensions.
- [G0087] APT39: APT39 has modified LNK shortcuts.
- [S0170] Helminth: Helminth establishes persistence by creating a shortcut.
- [S0652] MarkiRAT: MarkiRAT can modify the shortcut that launches Telegram by replacing its path with the malicious payload to launch with the legitimate executable.
- [S0339] Micropsia: Micropsia creates a shortcut to maintain persistence.
- [G0065] Leviathan: Leviathan has used JavaScript to create a shortcut file in the Startup folder that points to its main backdoor.
- [S0058] SslMM: To establish persistence, SslMM identifies the Start Menu Startup directory and drops a link to its own executable disguised as an “Office Start,” “Yahoo Talk,” “MSN Gaming Z0ne,” or “MSN Talk” shortcut.
- [G0032] Lazarus Group: Lazarus Group malware has maintained persistence on a system by creating a LNK shortcut in the user’s Startup folder.
- [S0244] Comnie: Comnie establishes persistence via a .lnk file in the victim’s startup path.
- [S0168] Gazer: Gazer can establish persistence by creating a .lnk file in the Start menu or by modifying existing .lnk files to execute the malware through cmd.exe.
- [S0089] BlackEnergy: The BlackEnergy 3 variant drops its main DLL component and then creates a .lnk shortcut to that file in the startup folder.

### T1547.010 - Boot or Logon Autostart Execution: Port Monitors

### T1547.012 - Boot or Logon Autostart Execution: Print Processors

Procedures:

- [S0666] Gelsemium: Gelsemium can drop itself in C:\Windows\System32\spool\prtprocs\x64\winprint.dll to be loaded automatically by the spoolsv Windows service.
- [G1006] Earth Lusca: Earth Lusca has added the Registry key `HKLM\SYSTEM\ControlSet001\Control\Print\Environments\Windows x64\Print Processors\UDPrint” /v Driver /d “spool.dll /f` to load malware as a Print Processor.
- [S0501] PipeMon: The PipeMon installer has modified the Registry key HKLM\SYSTEM\CurrentControlSet\Control\Print\Environments\Windows x64\Print Processors to install PipeMon as a Print Processor.

### T1547.013 - Boot or Logon Autostart Execution: XDG Autostart Entries

Procedures:

- [S0198] NETWIRE: NETWIRE can use XDG Autostart Entries to establish persistence on Linux systems.
- [S0192] Pupy: Pupy can use an XDG Autostart to establish persistence.
- [S0235] CrossRAT: CrossRAT can use an XDG Autostart to establish persistence.
- [S1078] RotaJakiro: When executing with user-level permissions, RotaJakiro can install persistence using a .desktop file under the `$HOME/.config/autostart/` folder.
- [S0410] Fysbis: If executing without root privileges, Fysbis adds a `.desktop` configuration file to the user's `~/.config/autostart` directory.

### T1547.014 - Boot or Logon Autostart Execution: Active Setup

Procedures:

- [S0012] PoisonIvy: PoisonIvy creates a Registry key in the Active Setup pointing to a malicious executable.

### T1547.015 - Boot or Logon Autostart Execution: Login Items

Procedures:

- [S0690] Green Lambert: Green Lambert can add Login Items to establish persistence.
- [S0198] NETWIRE: NETWIRE can persist via startup options for Login items.
- [S0281] Dok: Dok uses AppleScript to install a login Item by sending Apple events to the System Events process.


### T1548.001 - Abuse Elevation Control Mechanism: Setuid and Setgid

Procedures:

- [S0276] Keydnap: Keydnap adds the setuid flag to a binary so it can easily elevate in the future.
- [S0401] Exaramel for Linux: Exaramel for Linux can execute commands with high privileges via a specific binary with setuid functionality.

### T1548.002 - Abuse Elevation Control Mechanism: Bypass User Account Control

Procedures:

- [S0089] BlackEnergy: BlackEnergy attempts to bypass default User Access Control (UAC) settings by exploiting a backward-compatibility setting found in Windows 7 and later.
- [S0148] RTM: RTM can attempt to run the program as admin, then show a fake error message and a legitimate UAC bypass prompt to the user in an attempt to socially engineer the user into escalating privileges.
- [S1202] LockBit 3.0: LockBit 3.0 can bypass UAC to execute code with elevated privileges through an elevated Component Object Model (COM) interface.
- [S0154] Cobalt Strike: Cobalt Strike can use a number of known techniques to bypass Windows UAC.
- [S0666] Gelsemium: Gelsemium can bypass UAC to elevate process privileges on a compromised host.
- [S0230] ZeroT: Many ZeroT samples can perform UAC bypass by using eventvwr.exe to execute a malicious file.
- [S1018] Saint Bot: Saint Bot has attempted to bypass UAC using `fodhelper.exe` to escalate privileges.
- [S1111] DarkGate: DarkGate uses two distinct User Account Control (UAC) bypass techniques to escalate privileges.
- [G0082] APT38: APT38 has used the legitimate application `ieinstal.exe` to bypass UAC.
- [S0670] WarzoneRAT: WarzoneRAT can use `sdclt.exe` to bypass UAC in Windows 10 to escalate privileges; for older Windows versions WarzoneRAT can use the IFileOperation exploit to bypass the UAC module.
- [S0192] Pupy: Pupy can bypass Windows UAC through either DLL hijacking, eventvwr, or appPaths.
- [S0378] PoshC2: PoshC2 can utilize multiple methods to bypass UAC.
- [S0356] KONNI: KONNI has bypassed UAC by performing token impersonation as well as an RPC-based method, this included bypassing UAC set to “AlwaysNotify".
- [S0074] Sakula: Sakula contains UAC bypass code for both 32- and 64-bit systems.
- [S0444] ShimRat: ShimRat has hijacked the cryptbase.dll within migwiz.exe to escalate privileges. This prevented the User Access Control window from appearing.

### T1548.003 - Abuse Elevation Control Mechanism: Sudo and Sudo Caching

Procedures:

- [S0154] Cobalt Strike: Cobalt Strike can use sudo to run a command.
- [S0279] Proton: Proton modifies the tty_tickets line in the sudoers file.
- [S0281] Dok: Dok adds admin ALL=(ALL) NOPASSWD: ALL to the /etc/sudoers file.

### T1548.004 - Abuse Elevation Control Mechanism: Elevated Execution with Prompt

Procedures:

- [S0402] OSX/Shlayer: OSX/Shlayer can escalate privileges to root by asking the user for credentials.

### T1548.005 - Abuse Elevation Control Mechanism: Temporary Elevated Cloud Access

### T1548.006 - Abuse Elevation Control Mechanism: TCC Manipulation

Procedures:

- [S0658] XCSSET: For several modules, XCSSET attempts to access or list the contents of user folders such as Desktop, Downloads, and Documents. If the folder does not exist or access is denied, it enters a loop where it resets the TCC database and retries access.


### T1574.001 - Hijack Execution Flow: DLL

Procedures:

- [G0114] Chimera: Chimera has used side loading to place malicious DLLs in memory.
- [G1021] Cinnamon Tempest: Cinnamon Tempest has used search order hijacking to launch Cobalt Strike Beacons. Cinnamon Tempest has also abused legitimate executables to side-load weaponized DLLs.
- [S1041] Chinoxy: Chinoxy can use a digitally signed binary ("Logitech Bluetooth Wizard Host Process") to load its dll into memory.
- [G0069] MuddyWater: MuddyWater maintains persistence on victim networks through side-loading dlls to trick legitimate programs into running malware.
- [S0384] Dridex: Dridex can abuse legitimate Windows executables to side-load malicious DLL files.
- [G1047] Velvet Ant: Velvet Ant has used malicious DLLs executed via legitimate EXE files through DLL search order hijacking to launch follow-on payloads such as PlugX.
- [S0664] Pandora: Pandora can use DLL side-loading to execute malicious payloads.
- [G0048] RTM: RTM has used search order hijacking to force TeamViewer to load a malicious DLL.
- [G0131] Tonto Team: Tonto Team abuses a legitimate and signed Microsoft executable to launch a malicious DLL.
- [G0040] Patchwork: A Patchwork .dll that contains BADNEWS is loaded and executed using DLL side-loading.
- [S0070] HTTPBrowser: HTTPBrowser abuses the Windows DLL load order by using a legitimate Symantec anti-virus binary, VPDN_LU.exe, to load a malicious DLL that mimics a legitimate Symantec DLL, navlu.dll. HTTPBrowser has also used DLL side-loading.
- [S0109] WEBC2: Variants of WEBC2 achieve persistence by using DLL search order hijacking, usually by copying the DLL file to %SYSTEMROOT% (C:\WINDOWS\ntshrui.dll).
- [S0009] Hikit: Hikit has used DLL to load oci.dll as a persistence mechanism.
- [S0176] Wingbird: Wingbird side loads a malicious file, sspisrv.dll, in part of a spoofed lssas.exe service.
- [S0528] Javali: Javali can use DLL side-loading to load malicious DLLs into legitimate executables.

### T1574.004 - Hijack Execution Flow: Dylib Hijacking

Procedures:

- [S0363] Empire: Empire has a dylib hijacker module that generates a malicious dylib given the path to a legitimate dylib of a vulnerable application.

### T1574.005 - Hijack Execution Flow: Executable Installer File Permissions Weakness

### T1574.006 - Hijack Execution Flow: Dynamic Linker Hijacking

Procedures:

- [G0143] Aquatic Panda: Aquatic Panda modified the ld.so preload file in Linux environments to enable persistence for Winnti malware.
- [G0106] Rocke: Rocke has modified /etc/ld.so.preload to hook libc functions in order to hide the installed dropper and mining software in process lists.
- [S0601] Hildegard: Hildegard has modified /etc/ld.so.preload to intercept shared library import functions.
- [S0394] HiddenWasp: HiddenWasp adds itself as a shared object to the LD_PRELOAD environment variable.
- [S0658] XCSSET: XCSSET adds malicious file paths to the DYLD_FRAMEWORK_PATH and DYLD_LIBRARY_PATH environment variables to execute malicious code.
- [G0096] APT41: APT41 has configured payloads to load via LD_PRELOAD.
- [S1105] COATHANGER: COATHANGER copies the malicious file /data2/.bd.key/preload.so to /lib/preload.so, then launches a child process that executes the malicious file /data2/.bd.key/authd as /bin/authd with the arguments /lib/preload.so reboot newreboot 1. This injects the malicious preload.so file into the process with PID 1, and replaces its reboot function with the malicious newreboot function for persistence.
- [S0377] Ebury: When Ebury is running as an OpenSSH server, it uses LD_PRELOAD to inject its malicious shared module in to programs launched by SSH sessions. Ebury hooks the following functions from `libc` to inject into subprocesses; `system`, `popen`, `execve`, `execvpe`, `execv`, `execvp`, and `execl`.

### T1574.007 - Hijack Execution Flow: Path Interception by PATH Environment Variable

Procedures:

- [S0194] PowerSploit: PowerSploit contains a collection of Privesc-PowerUp modules that can discover and exploit path interception opportunities in the PATH environment variable.
- [S0363] Empire: Empire contains modules that can discover and exploit path interception opportunities in the PATH environment variable.
- [S1111] DarkGate: DarkGate overrides the %windir% environment variable by setting a Registry key, HKEY_CURRENT_User\Environment\windir, to an alternate command to execute a malicious AutoIt script. This allows DarkGate to run every time the scheduled task DiskCleanup is executed as this uses the path value %windir%\system32\cleanmgr.exe for execution.

### T1574.008 - Hijack Execution Flow: Path Interception by Search Order Hijacking

Procedures:

- [S0363] Empire: Empire contains modules that can discover and exploit search order hijacking vulnerabilities.
- [S0194] PowerSploit: PowerSploit contains a collection of Privesc-PowerUp modules that can discover and exploit search order hijacking vulnerabilities.

### T1574.009 - Hijack Execution Flow: Path Interception by Unquoted Path

Procedures:

- [S0194] PowerSploit: PowerSploit contains a collection of Privesc-PowerUp modules that can discover and exploit unquoted path vulnerabilities.
- [S0363] Empire: Empire contains modules that can discover and exploit unquoted path vulnerabilities.

### T1574.010 - Hijack Execution Flow: Services File Permissions Weakness

Procedures:

- [S0089] BlackEnergy: One variant of BlackEnergy locates existing driver services that have been disabled and drops its driver component into one of those service's paths, replacing the legitimate executable. The malware then sets the hijacked service to start automatically to establish persistence.

### T1574.011 - Hijack Execution Flow: Services Registry Permissions Weakness

Procedures:

- [C0006] Operation Honeybee: During Operation Honeybee, the threat actors used a batch file that modified the COMSysApp service to load a malicious ipnet.dll payload and to load a DLL into the `svchost.exe` process.

### T1574.012 - Hijack Execution Flow: COR_PROFILER

Procedures:

- [G0108] Blue Mockingbird: Blue Mockingbird has used wmic.exe and Windows Registry modifications to set the COR_PROFILER environment variable to execute a malicious DLL whenever a process loads the .NET CLR.
- [S1066] DarkTortilla: DarkTortilla can detect profilers by verifying the `COR_ENABLE_PROFILING` environment variable is present and active.

### T1574.013 - Hijack Execution Flow: KernelCallbackTable

Procedures:

- [G0032] Lazarus Group: Lazarus Group has abused the KernelCallbackTable to hijack process control flow and execute shellcode.
- [S0182] FinFisher: FinFisher has used the KernelCallbackTable to hijack the execution flow of a process by replacing the __fnDWORD function with the address of a created Asynchronous Procedure Call stub routine.

### T1574.014 - Hijack Execution Flow: AppDomainManager

Procedures:

- [S1152] IMAPLoader: IMAPLoader is executed via the AppDomainManager injection technique.


### T1611 - Escape to Host

Procedures:

- [S0683] Peirates: Peirates can gain a reverse shell on a host node by mounting the Kubernetes hostPath.
- [S0600] Doki: Doki’s container was configured to bind the host root directory.
- [S0623] Siloscape: Siloscape maps the host’s C drive to the container by creating a global symbolic link to the host through the calling of NtSetInformationSymbolicLink.
- [G0139] TeamTNT: TeamTNT has deployed privileged containers that mount the filesystem of victim machine.
- [S0601] Hildegard: Hildegard has used the BOtB tool that can break out of containers.

