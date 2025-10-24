### T1047 - Windows Management Instrumentation

Procedures:

- [S1085] Sardonic: Sardonic can use WMI to execute PowerShell commands on a compromised machine.
- [S0688] Meteor: Meteor can use `wmic.exe` as part of its effort to delete shadow copies.
- [G1021] Cinnamon Tempest: Cinnamon Tempest has used Impacket for lateral movement via WMI.
- [S0270] RogueRobin: RogueRobin uses various WMI queries to check if the sample is running in a sandbox.
- [G0045] menuPass: menuPass has used a modified version of pentesting script wmiexec.vbs, which logs into a remote machine using WMI.
- [S0559] SUNBURST: SUNBURST used the WMI query Select * From Win32_SystemDriver to retrieve a driver listing.
- [C0015] C0015: During C0015, the threat actors used `wmic` and `rundll32` to load Cobalt Strike onto a target host.
- [G1032] INC Ransom: INC Ransom has used WMIC to deploy ransomware.
- [S0089] BlackEnergy: A BlackEnergy 2 plug-in uses WMI to gather victim host details.
- [S1044] FunnyDream: FunnyDream can use WMI to open a Windows command shell on a remote machine.
- [S0283] jRAT: jRAT uses WMIC to identify anti-virus products installed on the victim’s machine and to obtain firewall details.
- [S0367] Emotet: Emotet has used WMI to execute powershell.exe.
- [G0047] Gamaredon Group: Gamaredon Group has used WMI to execute scripts used for discovery and for determining the C2 IP address.
- [S0618] FIVEHANDS: FIVEHANDS can use WMI to delete files on a target machine.
- [S0251] Zebrocy: One variant of Zebrocy uses WMI queries to gather information.


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

Procedures:

- Adversaries may abuse systemd timers to perform task scheduling for initial or recurring execution of malicious code. Systemd timers are unit files with file extension .timer that control services. Timers can be set to run on a calendar event or after a time span relative to a starting point. They can be used as an alternative to Cron in Linux environments. Systemd timers may be activated remotely via the systemctl command line utility, which operates over SSH. Each .timer file must have a corresponding .service file with the same name, e.g., example.timer and example.service. .service files are Systemd Service unit files that are managed by the systemd system and service manager. Privileged timers are written to /etc/systemd/system/ and /usr/lib/systemd/system while user level are written to ~/.config/systemd/user/. An adversary may use systemd timers to execute malicious code at system startup or on a scheduled basis for persistence. Timers installed using privileged paths may be used to maintain root level persistence. Adversaries may also install user level timers to achieve user level persistence.

### T1053.007 - Scheduled Task/Job: Container Orchestration Job

Procedures:

- Adversaries may abuse task scheduling functionality provided by container orchestration tools such as Kubernetes to schedule deployment of containers configured to execute malicious code. Container orchestration jobs run these automated tasks at a specific date and time, similar to cron jobs on a Linux system. Deployments of this type can also be configured to maintain a quantity of containers over time, automating the process of maintaining persistence within a cluster. In Kubernetes, a CronJob may be used to schedule a Job that runs one or more containers to perform specific tasks. An adversary therefore may utilize a CronJob to schedule deployment of a Job that executes malicious code in various nodes within a cluster.


### T1059.001 - Command and Scripting Interpreter: PowerShell

Procedures:

- [G0090] WIRTE: WIRTE has used PowerShell for script execution.
- [S1212] RansomHub: RansomHub can use PowerShell to delete volume shadow copies.
- [G1044] APT42: APT42 has downloaded and executed PowerShell payloads.
- [G1023] APT5: APT5 has used PowerShell to accomplish tasks within targeted environments.
- [C0047] RedDelta Modified PlugX Infection Chain Operations: Mustang Panda used LNK files to execute PowerShell commands leading to eventual PlugX installation during RedDelta Modified PlugX Infection Chain Operations.
- [C0025] 2016 Ukraine Electric Power Attack: During the 2016 Ukraine Electric Power Attack, Sandworm Team used PowerShell scripts to run a credential harvesting tool in memory to evade defenses.
- [G0108] Blue Mockingbird: Blue Mockingbird has used PowerShell reverse TCP shells to issue interactive commands over a network connection.
- [S1081] BADHATCH: BADHATCH can utilize `powershell.exe` to execute commands on a compromised host.
- [S0363] Empire: Empire leverages PowerShell for the majority of its client-side agent tasks. Empire also contains the ability to conduct PowerShell remoting with the Invoke-PSRemoting module.
- [S0330] Zeus Panda: Zeus Panda uses PowerShell to download and execute the payload.
- [G0087] APT39: APT39 has used PowerShell to execute malicious code.
- [G0059] Magic Hound: Magic Hound has used PowerShell for execution and privilege escalation.
- [S0650] QakBot: QakBot can use PowerShell to download and execute payloads.
- [G0073] APT19: APT19 used PowerShell commands to execute payloads.
- [S0622] AppleSeed: AppleSeed has the ability to execute its payload via PowerShell.

### T1059.002 - Command and Scripting Interpreter: AppleScript

Procedures:

- [S0281] Dok: Dok uses AppleScript to create a login item for persistence.
- [S0595] ThiefQuest: ThiefQuest uses AppleScript's osascript -e command to launch ThiefQuest's persistence via Launch Agent and Launch Daemon.
- [S0482] Bundlore: Bundlore can use AppleScript to inject malicious JavaScript into a browser.
- [S1153] Cuckoo Stealer: Cuckoo Stealer can use osascript to generate a password-stealing prompt, duplicate files and folders, and set environmental variables.
- [S1048] macOS.OSAMiner: macOS.OSAMiner has used `osascript` to call itself via the `do shell script` command in the Launch Agent `.plist` file.

### T1059.003 - Command and Scripting Interpreter: Windows Command Shell

Procedures:

- [S0053] SeaDuke: SeaDuke is capable of executing commands.
- [G0032] Lazarus Group: Lazarus Group malware uses cmd.exe to execute commands on a compromised host. A Destover-like variant used by Lazarus Group uses a batch file mechanism to delete its binaries from the system.
- [S0259] InnaputRAT: InnaputRAT launches a shell to execute commands on the victim’s machine.
- [S0187] Daserf: Daserf can execute shell commands.
- [S0046] CozyCar: A module in CozyCar allows arbitrary commands to be executed by invoking C:\Windows\System32\cmd.exe.
- [S1017] OutSteel: OutSteel has used `cmd.exe` to scan a compromised host for specific file extensions.
- [S0229] Orz: Orz can execute shell commands. Orz can execute commands with JavaScript.
- [S0475] BackConfig: BackConfig can download and run batch files to execute commands on a compromised host.
- [S0381] FlawedAmmyy: FlawedAmmyy has used `cmd` to execute commands on a compromised host.
- [S1141] LunarWeb: LunarWeb can run shell commands using a BAT file with a name matching `%TEMP%\.batfile` or through cmd.exe with the `/c` and `/U` option for Unicode output.
- [S0681] Lizar: Lizar has a command to open the command-line on the infected system.
- [S0651] BoxCaon: BoxCaon can execute arbitrary commands and utilize the "ComSpec" environment variable.
- [S0124] Pisloader: Pisloader uses cmd.exe to set the Registry Run key value. It also has a command to spawn a command shell.
- [S0346] OceanSalt: OceanSalt can create a reverse shell on the infected endpoint using cmd.exe. OceanSalt has been executed via malicious macros.
- [S0639] Seth-Locker: Seth-Locker can execute commands via the command line shell.

### T1059.004 - Command and Scripting Interpreter: Unix Shell

Procedures:

- [S1184] BOLDMOVE: BOLDMOVE is capable of spawning a remote command shell.
- [G0143] Aquatic Panda: Aquatic Panda used malicious shell scripts in Linux environments following access via SSH to install Linux versions of Winnti malware.
- [S0377] Ebury: Ebury can use the commands `Xcsh` or `Xcls` to open a shell with Ebury level permissions and `Xxsh` to open a shell with root level.
- [S1107] NKAbuse: NKAbuse is initially installed and executed through an initial shell script.
- [S1163] SnappyTCP: SnappyTCP creates the reverse shell using a pthread spawning a bash shell.
- [S0647] Turian: Turian has the ability to use /bin/sh to execute commands.
- [G0139] TeamTNT: TeamTNT has used shell scripts for execution.
- [C0048] Operation MidnightEclipse: During Operation MidnightEclipse, threat actors piped output from stdout to bash for execution.
- [S0482] Bundlore: Bundlore has leveraged /bin/sh and /bin/bash to execute commands on the victim machine.
- [S0587] Penquin: Penquin can execute remote commands using bash scripts.
- [S0599] Kinsing: Kinsing has used Unix shell scripts to execute commands in the victim environment.
- [S0641] Kobalos: Kobalos can spawn a new pseudo-terminal and execute arbitrary commands at the command prompt.
- [G0106] Rocke: Rocke used shell scripts to run commands which would obtain persistence and execute the cryptocurrency mining malware.
- [S0021] Derusbi: Derusbi is capable of creating a remote Bash shell and executing commands.
- [G1047] Velvet Ant: Velvet Ant used a custom tool, VELVETSTING, to parse encoded inbound commands to compromised F5 BIG-IP devices and then execute them via the Unix shell.

### T1059.005 - Command and Scripting Interpreter: Visual Basic

Procedures:

- [S0447] Lokibot: Lokibot has used VBS scripts and XLS macros for execution.
- [G0040] Patchwork: Patchwork used Visual Basic Scripts (VBS) on victim machines.
- [C0025] 2016 Ukraine Electric Power Attack: During the 2016 Ukraine Electric Power Attack, Sandworm Team created VBScripts to run on an SSH server.
- [S0531] Grandoreiro: Grandoreiro can use VBScript to execute malicious code.
- [S0475] BackConfig: BackConfig has used VBS to install its downloader component and malicious documents with VBA macro code.
- [S1030] Squirrelwaffle: Squirrelwaffle has used malicious VBA macros in Microsoft Word documents and Excel spreadsheets that execute an `AutoOpen` subroutine.
- [S0250] Koadic: Koadic performs most of its operations using Windows Script Host (VBScript) and runs arbitrary shellcode .
- [G0126] Higaisa: Higaisa has used VBScript code on the victim's machine.
- [S0585] Kerrdown: Kerrdown can use a VBS base64 decoder function published by Motobit.
- [S0477] Goopy: Goopy has the ability to use a Microsoft Outlook backdoor macro to communicate with its C2.
- [S1149] CHIMNEYSWEEP: CHIMNEYSWEEP has executed a script named cln.vbs on compromised hosts.
- [G0085] FIN4: FIN4 has used VBA macros to display a dialog box and collect victim credentials.
- [G0090] WIRTE: WIRTE has used VBScript in its operations.
- [G0112] Windshift: Windshift has used Visual Basic 6 (VB6) payloads.
- [G0010] Turla: Turla has used VBS scripts throughout its operations.

### T1059.006 - Command and Scripting Interpreter: Python

Procedures:

- [S0581] IronNetInjector: IronNetInjector can use IronPython scripts to load payloads with the help of a .NET injector.
- [S0547] DropBook: DropBook is a Python-based backdoor compiled with PyInstaller.
- [S0196] PUNCHBUGGY: PUNCHBUGGY has used python scripts.
- [G0067] APT37: APT37 has used Python scripts to execute payloads.
- [G0060] BRONZE BUTLER: BRONZE BUTLER has made use of Python-based remote access tools.
- [S0695] Donut: Donut can generate shellcode outputs that execute via Python.
- [S0374] SpeakUp: SpeakUp uses Python scripts.
- [G0131] Tonto Team: Tonto Team has used Python-based tools for execution.
- [S1187] reGeorg: reGeorg is a Python-based web shell.
- [S1032] PyDCrypt: PyDCrypt, along with its functions, is written in Python.
- [G0128] ZIRCONIUM: ZIRCONIUM has used Python-based implants to interact with compromised hosts.
- [S0583] Pysa: Pysa has used Python scripts to deploy ransomware.
- [S0387] KeyBoy: KeyBoy uses Python scripts for installing files and performing execution.
- [G0106] Rocke: Rocke has used Python-based malware to install and spread their coinminer.
- [G0095] Machete: Machete used multiple compiled Python scripts on the victim’s system. Machete's main backdoor Machete is also written in Python.

### T1059.007 - Command and Scripting Interpreter: JavaScript

Procedures:

- [S0622] AppleSeed: AppleSeed has the ability to use JavaScript to execute PowerShell.
- [S0154] Cobalt Strike: The Cobalt Strike System Profiler can use JavaScript to perform reconnaissance actions.
- [S0455] Metamorfo: Metamorfo includes payloads written in JavaScript.
- [G0010] Turla: Turla has used various JavaScript-based backdoors.
- [S1144] FRP: FRP can support the use of a JSON configuration file.
- [G0050] APT32: APT32 has used JavaScript for drive-by downloads and C2 communications.
- [G1031] Saint Bear: Saint Bear has delivered malicious Microsoft Office files containing an embedded JavaScript object that would, on execution, download and execute OutSteel and Saint Bot.
- [S0228] NanHaiShu: NanHaiShu executes additional Jscript code on the victim's machine.
- [G0037] FIN6: FIN6 has used malicious JavaScript to steal payment card data from e-commerce sites.
- [G0121] Sidewinder: Sidewinder has used JavaScript to drop and execute malware loaders.
- [S0650] QakBot: The QakBot web inject module can inject Java Script into web banking pages visited by the victim.
- [S1180] BlackByte Ransomware: BlackByte Ransomware is distributed as a JavaScript launcher file.
- [G1019] MoustachedBouncer: MoustachedBouncer has used JavaScript to deliver malware hosted on HTML pages.
- [S0640] Avaddon: Avaddon has been executed through a malicious JScript downloader.
- [G0069] MuddyWater: MuddyWater has used JavaScript files to execute its POWERSTATS payload.

### T1059.008 - Command and Scripting Interpreter: Network Device CLI

Procedures:

- [S1186] Line Dancer: Line Dancer can execute native commands in networking device command line interfaces.

### T1059.009 - Command and Scripting Interpreter: Cloud API

Procedures:

- [S1091] Pacu: Pacu leverages the AWS CLI for its operations.
- [G0139] TeamTNT: TeamTNT has leveraged AWS CLI to enumerate cloud environments with compromised credentials.
- [G0016] APT29: APT29 has leveraged the Microsoft Graph API to perform various actions across Azure and M365 environments. They have also utilized AADInternals PowerShell Modules to access the API

### T1059.010 - Command and Scripting Interpreter: AutoHotKey & AutoIT

Procedures:

- [S1213] Lumma Stealer: Lumma Stealer has utilized AutoIt malware scripts and AutoIt executables.
- [S0530] Melcoz: Melcoz has been distributed through an AutoIt loader script.
- [S1207] XLoader: XLoader can use an AutoIT script to decrypt a payload file, load it into victim memory, then execute it on the victim machine.
- [S1017] OutSteel: OutSteel was developed using the AutoIT scripting language.
- [G0087] APT39: APT39 has utilized AutoIt malware scripts embedded in Microsoft Office documents or malicious links.
- [S1111] DarkGate: DarkGate uses AutoIt scripts dropped to a hidden directory during initial installation phases, such as `test.au3`.

### T1059.011 - Command and Scripting Interpreter: Lua

Procedures:

- [S0396] EvilBunny: EvilBunny has used Lua scripts to execute payloads.
- [S0125] Remsec: Remsec can use modules written in Lua for execution.
- [S1188] Line Runner: Line Runner utilizes Lua scripts for command execution.
- [S0428] PoetRAT: PoetRAT has executed a Lua script through a Lua interpreter for Windows.

### T1059.012 - Command and Scripting Interpreter: Hypervisor CLI

Procedures:

- [S1096] Cheerscrypt: Cheerscrypt has leveraged `esxcli` in order to terminate running virtual machines.
- [S1073] Royal: Royal ransomware uses `esxcli` to gather a list of running VMs and terminate them.


### T1072 - Software Deployment Tools

Procedures:

- [G0050] APT32: APT32 compromised McAfee ePO to move laterally by distributing malware as a software deployment task.
- [G0034] Sandworm Team: Sandworm Team has used the commercially available tool RemoteExec for agentless remote code execution.
- [G0091] Silence: Silence has used RAdmin, a remote software tool used to remotely control workstations and ATMs.
- [S0041] Wiper: It is believed that a patch management system for an anti-virus product commonly installed among targeted companies was used to distribute the Wiper malware.
- [G0028] Threat Group-1314: Threat Group-1314 actors used a victim's endpoint management platform, Altiris, for lateral movement.
- [C0018] C0018: During C0018, the threat actors used PDQ Deploy to move AvosLocker and tools across the network.


### T1106 - Native API

Procedures:

- [S0396] EvilBunny: EvilBunny has used various API calls as part of its checks to see if the malware is running in a sandbox.
- [S1179] Exbyte: Exbyte calls `ShellExecuteW` with the `IpOperation` parameter `RunAs` to launch `explorer.exe` with elevated privileges.
- [S0141] Winnti for Windows: Winnti for Windows can use Native API to create a new process and to start services.
- [S0453] Pony: Pony has used several Windows functions for various purposes.
- [S0687] Cyclops Blink: Cyclops Blink can use various Linux API functions including those for execution and discovery.
- [S0268] Bisonal: Bisonal has used the Windows API to communicate with the Service Control Manager to execute a thread.
- [S0084] Mis-Type: Mis-Type has used Windows API calls, including `NetUserAdd` and `NetUserDel`.
- [S0678] Torisma: Torisma has used various Windows API calls.
- [S0627] SodaMaster: SodaMaster can use RegOpenKeyW to access the Registry.
- [S0629] RainyDay: The file collection tool used by RainyDay can utilize native API including ReadDirectoryChangeW for folder monitoring.
- [S0154] Cobalt Strike: Cobalt Strike's Beacon payload is capable of running shell commands without cmd.exe and PowerShell commands without powershell.exe
- [S1013] ZxxZ: ZxxZ has used API functions such as `Process32First`, `Process32Next`, and `ShellExecuteA`.
- [S0610] SideTwist: SideTwist can use GetUserNameW, GetComputerNameW, and GetComputerNameExW to gather information.
- [C0022] Operation Dream Job: During Operation Dream Job, Lazarus Group used Windows API `ObtainUserAgentString` to obtain the victim's User-Agent and used the value to connect to their C2 server.
- [S1087] AsyncRAT: AsyncRAT has the ability to use OS APIs including `CheckRemoteDebuggerPresent`.


### T1129 - Shared Modules

Procedures:

- [S0032] gh0st RAT: gh0st RAT can load DLLs into memory.
- [S0203] Hydraq: Hydraq creates a backdoor through which remote attackers can load and call DLL functions.
- [S0196] PUNCHBUGGY: PUNCHBUGGY can load a DLL using the LoadLibrary API.
- [S0603] Stuxnet: Stuxnet calls LoadLibrary then executes exports from a DLL.
- [S0373] Astaroth: Astaroth uses the LoadLibraryExW() function to load additional modules.
- [S1185] LightSpy: LightSpy's main executable and module `.dylib` binaries are loaded using a combination of `dlopen()` to load the library, `_objc_getClass()` to retrieve the class definition, and `_objec_msgSend()` to invoke/execute the specified method in the loaded class.
- [S0607] KillDisk: KillDisk loads and executes functions from a DLL.
- [S0455] Metamorfo: Metamorfo had used AutoIt to load and execute the DLL payload.
- [S0673] DarkWatchman: DarkWatchman can load DLLs.
- [S0438] Attor: Attor's dispatcher can execute additional plugins by loading the respective DLLs.
- [S0661] FoggyWeb: FoggyWeb's loader can call the load() function to load the FoggyWeb dll into an Application Domain on a compromised AD FS server.
- [S1078] RotaJakiro: RotaJakiro uses dynamically linked shared libraries (`.so` files) to execute additional functionality using `dlopen()` and `dlsym()`.
- [S0520] BLINDINGCAN: BLINDINGCAN has loaded and executed DLLs in memory during runtime on a victim machine.
- [S1039] Bumblebee: Bumblebee can use `LoadLibrary` to attempt to execute GdiPlus.dll.
- [S0467] TajMahal: TajMahal has the ability to inject the LoadLibrary call template DLL into running processes.


### T1203 - Exploitation for Client Execution

Procedures:

- [G0121] Sidewinder: Sidewinder has exploited vulnerabilities to gain execution including CVE-2017-11882 and CVE-2020-0674.
- [G1031] Saint Bear: Saint Bear has leveraged vulnerabilities in client applications such as CVE-2017-11882 in Microsoft Office to enable code execution in victim environments.
- [G0007] APT28: APT28 has exploited Microsoft Office vulnerability CVE-2017-0262 for execution.
- [G0027] Threat Group-3390: Threat Group-3390 has exploited CVE-2018-0798 in Equation Editor.
- [S0331] Agent Tesla: Agent Tesla has exploited Office vulnerabilities such as CVE-2017-11882 and CVE-2017-8570 for execution during delivery.
- [G0034] Sandworm Team: Sandworm Team has exploited vulnerabilities in Microsoft PowerPoint via OLE objects (CVE-2014-4114) and Microsoft Word via crafted TIFF images (CVE-2013-3906).
- [G0035] Dragonfly: Dragonfly has exploited CVE-2011-0611 in Adobe Flash Player to gain execution on a targeted system.
- [G0138] Andariel: Andariel has exploited numerous ActiveX vulnerabilities, including zero-days.
- [S0239] Bankshot: Bankshot leverages a known zero-day vulnerability in Adobe Flash to execute the implant into the victims’ machines.
- [S1154] VersaMem: VersaMem was installed through exploitation of CVE-2024-39717 in Versa Director servers.
- [G0089] The White Company: The White Company has taken advantage of a known vulnerability in Microsoft Word (CVE 2012-0158) to execute code.
- [G1011] EXOTIC LILY: EXOTIC LILY has used malicious documents containing exploits for CVE-2021-40444 affecting Microsoft MSHTML.
- [G0032] Lazarus Group: Lazarus Group has exploited Adobe Flash vulnerability CVE-2018-4878 for execution.
- [G0016] APT29: APT29 has used multiple software exploits for common client software, like Microsoft Word, Exchange, and Adobe Reader, to gain code execution.
- [S1207] XLoader: XLoader has exploited Office vulnerabilities during local execution such as CVE-2017-11882 and CVE-2018-0798.


### T1204.001 - User Execution: Malicious Link

Procedures:

- [G0046] FIN7: FIN7 has used malicious links to lure victims into downloading malware.
- [G0098] BlackTech: BlackTech has used e-mails with malicious links to lure victims into installing malware.
- [S0531] Grandoreiro: Grandoreiro has used malicious links to gain execution on victim machines.
- [S0534] Bazar: Bazar can gain execution after a user clicks on a malicious link to decoy landing pages hosted on Google Docs.
- [C0002] Night Dragon: During Night Dragon, threat actors enticed users to click on links in spearphishing emails to download malware.
- [G0129] Mustang Panda: Mustang Panda has sent malicious links including links directing victims to a Google Drive folder.
- [G0021] Molerats: Molerats has sent malicious links via email trick users into opening a RAR archive and running an executable.
- [G0112] Windshift: Windshift has used links embedded in e-mails to lure victims into executing malicious code.
- [S1017] OutSteel: OutSteel has relied on a user to click a malicious link within a spearphishing email.
- [G0094] Kimsuky: Kimsuky has lured victims into clicking malicious links.
- [G0140] LazyScripter: LazyScripter has relied upon users clicking on links to malicious files.
- [G0142] Confucius: Confucius has lured victims into clicking on a malicious link sent through spearphishing.
- [G1031] Saint Bear: Saint Bear has, in addition to email-based phishing attachments, used malicious websites masquerading as legitimate entities to host links to malicious files for user execution.
- [C0005] Operation Spalax: During Operation Spalax, the threat actors relied on a victim to click on a malicious link distributed via phishing emails.
- [C0016] Operation Dust Storm: During Operation Dust Storm, the threat actors relied on a victim clicking on a malicious link sent via email.

### T1204.002 - User Execution: Malicious File

Procedures:

- [G1026] Malteiro: Malteiro has relied on users to execute .zip file attachments containing malicious URLs.
- [S0669] KOCTOPUS: KOCTOPUS has relied on victims clicking a malicious document for execution.
- [C0037] Water Curupira Pikabot Distribution: Water Curupira Pikabot Distribution delivered Pikabot installers as password-protected ZIP files containing heavily obfuscated JavaScript, or IMG files containing an LNK mimicking a Word document and a malicious DLL.
- [S0356] KONNI: KONNI has relied on a victim to enable malicious macros within an attachment delivered via email.
- [G0005] APT12: APT12 has attempted to get victims to open malicious Microsoft Word and PDF attachment sent via spearphishing.
- [S0453] Pony: Pony has attempted to lure targets into downloading an attached executable (ZIP, RAR, or CAB archives) or document (PDF or other MS Office format).
- [G0094] Kimsuky: Kimsuky has used attempted to lure victims into opening malicious e-mail attachments.
- [G0095] Machete: Machete has relied on users opening malicious attachments delivered through spearphishing to execute malware.
- [S0631] Chaes: Chaes requires the user to click on the malicious Word document to execute the next part of the attack.
- [S1064] SVCReady: SVCReady has relied on users clicking a malicious attachment delivered through spearphishing.
- [G0066] Elderwood: Elderwood has leveraged multiple types of spearphishing in order to attempt to get a user to open attachments.
- [G0134] Transparent Tribe: Transparent Tribe has used weaponized documents in e-mail to compromise targeted systems.
- [G0035] Dragonfly: Dragonfly has used various forms of spearphishing in attempts to get users to open malicious attachments.
- [G0090] WIRTE: WIRTE has attempted to lure users into opening malicious MS Word and Excel files to execute malicious payloads.
- [S0670] WarzoneRAT: WarzoneRAT has relied on a victim to open a malicious attachment within an email for execution.

### T1204.003 - User Execution: Malicious Image

Procedures:

- [G0139] TeamTNT: TeamTNT has relied on users to download and execute malicious Docker images.

### T1204.004 - User Execution: Malicious Copy and Paste

Procedures:

- An adversary may rely upon a user copying and pasting code in order to gain execution. Users may be subjected to social engineering to get them to copy and paste code directly into a Command and Scripting Interpreter. Malicious websites, such as those used in Drive-by Compromise, may present fake error messages or CAPTCHA prompts that instruct users to open a terminal or the Windows Run Dialog box and execute an arbitrary command. These commands may be obfuscated using encoding or other techniques to conceal malicious intent. Once executed, the adversary will typically be able to establish a foothold on the victim's machine. Adversaries may also leverage phishing emails for this purpose. When a user attempts to open an attachment, they may be presented with a fake error and offered a malicious command to paste as a solution. Tricking a user into executing a command themselves may help to bypass email filtering, browser sandboxing, or other mitigations designed to protect users against malicious downloaded files.


### T1559.001 - Inter-Process Communication: Component Object Model

Procedures:

- [S0223] POWERSTATS: POWERSTATS can use DCOM (targeting the 127.0.0.1 loopback address) to execute additional payloads on compromised hosts.
- [S0266] TrickBot: TrickBot used COM to setup scheduled task for persistence.
- [S0260] InvisiMole: InvisiMole can use the ITaskService, ITaskDefinition and ITaskSettings COM interfaces to schedule a task.
- [S1044] FunnyDream: FunnyDream can use com objects identified with `CLSID_ShellLink`(`IShellLink` and `IPersistFile`) and `WScript.Shell`(`RegWrite` method) to enable persistence mechanisms.
- [G0069] MuddyWater: MuddyWater has used malware that has the capability to execute malicious code via COM, DCOM, and Outlook.
- [S0386] Ursnif: Ursnif droppers have used COM objects to execute the malware's full executable payload.
- [S1015] Milan: Milan can use a COM component to generate scheduled tasks.
- [S1160] Latrodectus: Latrodectus can use the Windows Component Object Model (COM) to set scheduled tasks.
- [G0047] Gamaredon Group: Gamaredon Group malware can insert malicious macros into documents using a Microsoft.Office.Interop object.
- [S1130] Raspberry Robin: Raspberry Robin creates an elevated COM object for CMLuaUtil and uses this to set a registry value that points to the malicious LNK file during execution.
- [S0698] HermeticWizard: HermeticWizard can execute files on remote machines using DCOM.
- [S1066] DarkTortilla: DarkTortilla has used the `WshShortcut` COM object to create a .lnk shortcut file in the Windows startup folder.
- [S0691] Neoichor: Neoichor can use the Internet Explorer (IE) COM interface to connect and receive commands from C2.
- [S0692] SILENTTRINITY: SILENTTRINITY can insert malicious shellcode into Excel.exe using a `Microsoft.Office.Interop` object.
- [S1039] Bumblebee: Bumblebee can use a COM object to execute queries to gather system information.

### T1559.002 - Inter-Process Communication: Dynamic Data Exchange

Procedures:

- [S0458] Ramsay: Ramsay has been delivered using OLE objects in malicious documents.
- [C0013] Operation Sharpshooter: During Operation Sharpshooter, threat actors sent malicious Word OLE documents to victims.
- [S0391] HAWKBALL: HAWKBALL has used an OLE object that uses Equation Editor to drop the embedded shellcode.
- [G0080] Cobalt Group: Cobalt Group has sent malicious Word OLE compound documents to victims.
- [G0046] FIN7: FIN7 spear phishing campaigns have included malicious Word documents with DDE execution.
- [G0069] MuddyWater: MuddyWater has used malware that can execute PowerShell scripts via DDE.
- [G0121] Sidewinder: Sidewinder has used the ActiveXObject utility to create OLE objects to obtain execution through Internet Explorer.
- [S0148] RTM: RTM can search for specific strings within browser tabs using a Dynamic Data Exchange mechanism.
- [G0007] APT28: APT28 has delivered JHUHUGIT and Koadic by executing PowerShell commands through DDE in Word documents.
- [S0476] Valak: Valak can execute tasks via OLE.
- [S0428] PoetRAT: PoetRAT was delivered with documents using DDE to execute malicious code.
- [G0067] APT37: APT37 has used Windows DDE for execution of commands and a malicious VBS.
- [S0223] POWERSTATS: POWERSTATS can use DDE to execute additional payloads on compromised hosts.
- [G0084] Gallmaker: Gallmaker attempted to exploit Microsoft’s DDE protocol in order to gain access to victim machines and for execution.
- [G0065] Leviathan: Leviathan has utilized OLE as a method to insert malicious content inside various phishing documents.

### T1559.003 - Inter-Process Communication: XPC Services

Procedures:

- Adversaries can provide malicious content to an XPC service daemon for local code execution. macOS uses XPC services for basic inter-process communication between various processes, such as between the XPC Service daemon and third-party application privileged helper tools. Applications can send messages to the XPC Service daemon, which runs as root, using the low-level XPC Service C API or the high level NSXPCConnection API in order to handle tasks that require elevated privileges (such as network connections). Applications are responsible for providing the protocol definition which serves as a blueprint of the XPC services. Developers typically use XPC Services to provide applications stability and privilege separation between the application client and the daemon. Adversaries can abuse XPC services to execute malicious content. Requests for malicious execution can be passed through the application's XPC Services handler. This may also include identifying and abusing improper XPC client validation and/or poor sanitization of input parameters to conduct Exploitation for Privilege Escalation.


### T1569.001 - System Services: Launchctl

Procedures:

- [S0451] LoudMiner: LoudMiner launched the QEMU services in the /Library/LaunchDaemons/ folder using launchctl. It also uses launchctl to unload all Launch Daemons when updating to a newer version of LoudMiner.
- [S1153] Cuckoo Stealer: Cuckoo Stealer can use `launchctl` to load a LaunchAgent for persistence.
- [S0584] AppleJeus: AppleJeus has loaded a plist file using the launchctl command.
- [S1048] macOS.OSAMiner: macOS.OSAMiner has used `launchctl` to restart the Launch Agent.
- [S0658] XCSSET: XCSSET loads a system level launchdaemon using the launchctl load -w command from /System/Librarby/LaunchDaemons/ssh.plist.
- [S0274] Calisto: Calisto uses launchctl to enable screen sharing on the victim’s machine.

### T1569.002 - System Services: Service Execution

Procedures:

- [S0192] Pupy: Pupy uses PsExec to execute a payload or commands on a remote host.
- [S1111] DarkGate: DarkGate tries to elevate privileges to SYSTEM using PsExec to locally execute as a service, such as cmd /c c:\temp\PsExec.exe -accepteula -j -d -s [Target Binary].
- [S0154] Cobalt Strike: Cobalt Strike can use PsExec to execute a payload on a remote host. It can also use Service Control Manager to start new services.
- [S0260] InvisiMole: InvisiMole has used Windows services as a way to execute its malicious payload.
- [S0203] Hydraq: Hydraq uses svchost.exe to execute a malicious DLL included in a new service group.
- [S1063] Brute Ratel C4: Brute Ratel C4 can create Windows system services for execution.
- [S0368] NotPetya: NotPetya can use PsExec to help propagate itself across a network.
- [G0114] Chimera: Chimera has used PsExec to deploy beacons on compromised systems.
- [S0166] RemoteCMD: RemoteCMD can execute commands remotely by creating a new service on the remote system.
- [S0698] HermeticWizard: HermeticWizard can use `OpenRemoteServiceManager` to create a service.
- [S0668] TinyTurla: TinyTurla can install itself as a service on compromised machines.
- [S0606] Bad Rabbit: Bad Rabbit drops a file named infpub.datinto the Windows directory and is executed through SCManager and rundll.exe.
- [S0481] Ragnar Locker: Ragnar Locker has used sc.exe to execute a service that it creates.
- [G0087] APT39: APT39 has used post-exploitation tools including RemCom and the Non-sucking Service Manager (NSSM) to execute processes.
- [S0378] PoshC2: PoshC2 contains an implementation of PsExec for remote execution.

### T1569.003 - System Services: Systemctl

Procedures:

- [G0139] TeamTNT: TeamTNT has created system services to execute cryptocurrency mining software.


### T1609 - Container Administration Command

Procedures:

- [G0139] TeamTNT: TeamTNT executed Hildegard through the kubelet API run command and by executing commands on running containers.
- [S0683] Peirates: Peirates can use `kubectl` or the Kubernetes API to run commands.
- [S0601] Hildegard: Hildegard was executed through the kubelet API run command and by executing commands on running containers.
- [S0623] Siloscape: Siloscape can send kubectl commands to victim clusters through an IRC channel and can run kubectl locally to spread once within a victim cluster.
- [S0599] Kinsing: Kinsing was executed with an Ubuntu container entry point that runs shell scripts.


### T1610 - Deploy Container

Procedures:

- [S0599] Kinsing: Kinsing was run through a deployed Ubuntu container.
- [G0139] TeamTNT: TeamTNT has deployed different types of containers into victim environments to facilitate execution. TeamTNT has also transferred cryptocurrency mining software to Kubernetes clusters discovered within local IP address ranges.
- [S0683] Peirates: Peirates can deploy a pod that mounts its node’s root file system, then execute a command to create a reverse shell on the node.
- [S0600] Doki: Doki was run through a deployed container.


### T1648 - Serverless Execution

Procedures:

- [S1091] Pacu: Pacu can create malicious Lambda functions.


### T1651 - Cloud Administration Command

Procedures:

- [G0016] APT29: APT29 has used Azure Run Command and Azure Admin-on-Behalf-of (AOBO) to execute code on virtual machines.
- [S0677] AADInternals: AADInternals can execute commands on Azure virtual machines using the VM agent.
- [S1091] Pacu: Pacu can run commands on EC2 instances using AWS Systems Manager Run Command.


### T1674 - Input Injection

Procedures:

- [G0046] FIN7: FIN7 has used malicious USBs to emulate keystrokes to launch PowerShell to download and execute malware from the adversary's server.


### T1675 - ESXi Administration Command

Procedures:

- Adversaries may abuse ESXi administration services to execute commands on guest machines hosted within an ESXi virtual environment. Persistent background services on ESXi-hosted VMs, such as the VMware Tools Daemon Service, allow for remote management from the ESXi server. The tools daemon service runs as `vmtoolsd.exe` on Windows guest operating systems, `vmware-tools-daemon` on macOS, and `vmtoolsd ` on Linux. Adversaries may leverage a variety of tools to execute commands on ESXi-hosted VMs – for example, by using the vSphere Web Services SDK to programmatically execute commands and scripts via APIs such as `StartProgramInGuest`, `ListProcessesInGuest`, `ListFileInGuest`, and `InitiateFileTransferFromGuest`. This may enable follow-on behaviors on the guest VMs, such as File and Directory Discovery, Data from Local System, or OS Credential Dumping.

