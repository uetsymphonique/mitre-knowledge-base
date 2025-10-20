### T1037.001 - Boot or Logon Initialization Scripts: Logon Script (Windows)

Description:

Adversaries may use Windows logon scripts automatically executed at logon initialization to establish persistence. Windows allows logon scripts to be run whenever a specific user or group of users log into a system. This is done via adding a path to a script to the HKCU\Environment\UserInitMprLogonScript Registry key. Adversaries may use these scripts to maintain persistence on a single system. Depending on the access configuration of the logon scripts, either local credentials or an administrator account may be necessary.

Detection:

Monitor for changes to Registry values associated with Windows logon scrips, nameley HKCU\Environment\UserInitMprLogonScript. Monitor running process for actions that could be indicative of abnormal programs or executables running upon logon.

Procedures:

- [G0007] APT28: An APT28 loader Trojan adds the Registry key HKCU\Environment\UserInitMprLogonScript to establish persistence.
- [S0438] Attor: Attor's dispatcher can establish persistence via adding a Registry key with a logon script HKEY_CURRENT_USER\Environment "UserInitMprLogonScript" .
- [S0044] JHUHUGIT: JHUHUGIT has registered a Windows shell script under the Registry key HKCU\Environment\UserInitMprLogonScript to establish persistence.
- [S0526] KGH_SPY: KGH_SPY has the ability to set the HKCU\Environment\UserInitMprLogonScript Registry key to execute logon scripts.
- [S0251] Zebrocy: Zebrocy performs persistence with a logon script via adding to the Registry key HKCU\Environment\UserInitMprLogonScript.
- [G0080] Cobalt Group: Cobalt Group has added persistence by registering the file name for the next stage malware under HKCU\Environment\UserInitMprLogonScript.

### T1037.002 - Boot or Logon Initialization Scripts: Login Hook

Description:

Adversaries may use a Login Hook to establish persistence executed upon user logon. A login hook is a plist file that points to a specific script to execute with root privileges upon user logon. The plist file is located in the /Library/Preferences/com.apple.loginwindow.plist file and can be modified using the defaults command-line utility. This behavior is the same for logout hooks where a script can be executed upon user logout. All hooks require administrator permissions to modify or create hooks. Adversaries can add or insert a path to a malicious script in the com.apple.loginwindow.plist file, using the LoginHook or LogoutHook key-value pair. The malicious script is executed upon the next user login. If a login hook already exists, adversaries can add additional commands to an existing login hook. There can be only one login and logout hook on a system at a time. **Note:** Login hooks were deprecated in 10.11 version of macOS in favor of Launch Daemon and Launch Agent

Detection:

Monitor logon scripts for unusual access by abnormal users or at abnormal times. Look for files added or modified by unusual accounts outside of normal administration duties. Monitor running process for actions that could be indicative of abnormal programs or executables running upon logon.

### T1037.003 - Boot or Logon Initialization Scripts: Network Logon Script

Description:

Adversaries may use network logon scripts automatically executed at logon initialization to establish persistence. Network logon scripts can be assigned using Active Directory or Group Policy Objects. These logon scripts run with the privileges of the user they are assigned to. Depending on the systems within the network, initializing one of these scripts could apply to more than one or potentially all systems. Adversaries may use these scripts to maintain persistence on a network. Depending on the access configuration of the logon scripts, either local credentials or an administrator account may be necessary.

Detection:

Monitor logon scripts for unusual access by abnormal users or at abnormal times. Look for files added or modified by unusual accounts outside of normal administration duties. Monitor running process for actions that could be indicative of abnormal programs or executables running upon logon.

### T1037.004 - Boot or Logon Initialization Scripts: RC Scripts

Description:

Adversaries may establish persistence by modifying RC scripts, which are executed during a Unix-like system’s startup. These files allow system administrators to map and start custom services at startup for different run levels. RC scripts require root privileges to modify. Adversaries may establish persistence by adding a malicious binary path or shell commands to rc.local, rc.common, and other RC scripts specific to the Unix-like distribution. Upon reboot, the system executes the script's contents as root, resulting in persistence. Adversary abuse of RC scripts is especially effective for lightweight Unix-like distributions using the root user as default, such as ESXi hypervisors, IoT, or embedded systems. As ESXi servers store most system files in memory and therefore discard changes on shutdown, leveraging `/etc/rc.local.d/local.sh` is one of the few mechanisms for enabling persistence across reboots. Several Unix-like systems have moved to Systemd and deprecated the use of RC scripts. This is now a deprecated mechanism in macOS in favor of Launchd. This technique can be used on Mac OS X Panther v10.3 and earlier versions which still execute the RC scripts. To maintain backwards compatibility some systems, such as Ubuntu, will execute the RC scripts if they exist with the correct file permissions.

Detection:

Monitor for unexpected changes to RC scripts in the /etc/ directory. Monitor process execution resulting from RC scripts for unusual or unknown applications or behavior. Monitor for /etc/rc.local file creation. Although types of RC scripts vary for each Unix-like distribution, several execute /etc/rc.local if present.

Procedures:

- [G1047] Velvet Ant: Velvet Ant used a modified `/etc/rc.local` file on compromised F5 BIG-IP devices to maintain persistence.
- [S0394] HiddenWasp: HiddenWasp installs reboot persistence by adding itself to /etc/rc.local.
- [G0016] APT29: APT29 has installed a run command on a compromised system to enable malware execution on system startup.
- [S0690] Green Lambert: Green Lambert can add init.d and rc.d files in the /etc folder to establish persistence.
- [S0687] Cyclops Blink: Cyclops Blink has the ability to execute on device startup, using a modified RC script named S51armled.
- [S0278] iKitten: iKitten adds an entry to the rc.common file for persistence.

### T1037.005 - Boot or Logon Initialization Scripts: Startup Items

Description:

Adversaries may use startup items automatically executed at boot initialization to establish persistence. Startup items execute during the final phase of the boot process and contain shell scripts or other executable files along with configuration information used by the system to determine the execution order for all startup items. This is technically a deprecated technology (superseded by Launch Daemon), and thus the appropriate folder, /Library/StartupItems isn’t guaranteed to exist on the system by default, but does appear to exist by default on macOS Sierra. A startup item is a directory whose executable and configuration property list (plist), StartupParameters.plist, reside in the top-level directory. An adversary can create the appropriate folders/files in the StartupItems directory to register their own persistence mechanism. Additionally, since StartupItems run during the bootup phase of macOS, they will run as the elevated root user.

Detection:

The /Library/StartupItems folder can be monitored for changes. Similarly, the programs that are actually executed from this mechanism should be checked against a whitelist. Monitor processes that are executed during the bootup process to check for unusual or unknown applications and behavior.

Procedures:

- [S0283] jRAT: jRAT can list and manage startup entries.


### T1053.002 - Scheduled Task/Job: At

Description:

Adversaries may abuse the at utility to perform task scheduling for initial or recurring execution of malicious code. The at utility exists as an executable within Windows, Linux, and macOS for scheduling tasks at a specified time and date. Although deprecated in favor of Scheduled Task's schtasks in Windows environments, using at requires that the Task Scheduler service be running, and the user to be logged on as a member of the local Administrators group. In addition to explicitly running the `at` command, adversaries may also schedule a task with at by directly leveraging the Windows Management Instrumentation `Win32_ScheduledJob` WMI class. On Linux and macOS, at may be invoked by the superuser as well as any users added to the at.allow file. If the at.allow file does not exist, the at.deny file is checked. Every username not listed in at.deny is allowed to invoke at. If the at.deny exists and is empty, global use of at is permitted. If neither file exists (which is often the baseline) only the superuser is allowed to use at. Adversaries may use at to execute programs at system startup or on a scheduled basis for Persistence. at can also be abused to conduct remote Execution as part of Lateral Movement and/or to run a process under the context of a specified account (such as SYSTEM). In Linux environments, adversaries may also abuse at to break out of restricted environments by using a task to spawn an interactive system shell or to run system commands. Similarly, at may also be used for Privilege Escalation if the binary is allowed to run as superuser via sudo.

Detection:

Monitor process execution from the svchost.exe in Windows 10 and the Windows Task Scheduler taskeng.exe for older versions of Windows. If scheduled tasks are not used for persistence, then the adversary is likely to remove the task when the action is complete. Monitor Windows Task Scheduler stores in %systemroot%\System32\Tasks for change entries related to scheduled tasks that do not correlate with known software, patch cycles, etc. Configure event logging for scheduled task creation and changes by enabling the "Microsoft-Windows-TaskScheduler/Operational" setting within the event logging service. Several events will then be logged on scheduled task activity, including: * Event ID 106 on Windows 7, Server 2008 R2 - Scheduled task registered * Event ID 140 on Windows 7, Server 2008 R2 / 4702 on Windows 10, Server 2016 - Scheduled task updated * Event ID 141 on Windows 7, Server 2008 R2 / 4699 on Windows 10, Server 2016 - Scheduled task deleted * Event ID 4698 on Windows 10, Server 2016 - Scheduled task created * Event ID 4700 on Windows 10, Server 2016 - Scheduled task enabled * Event ID 4701 on Windows 10, Server 2016 - Scheduled task disabled Tools such as Sysinternals Autoruns may also be used to detect system changes that could be attempts at persistence, including listing current scheduled tasks. Remote access tools with built-in features may interact directly with the Windows API to perform these functions outside of typical system utilities. Tasks may also be created through Windows system management tools such as Windows Management Instrumentation and PowerShell, so additional logging may need to be configured to gather the appropriate data. In Linux and macOS environments, monitor scheduled task creation using command-line invocation. Legitimate scheduled tasks may be created during installation of new software or through system administration functions. Look for changes to tasks that do not correlate with known software, patch cycles, etc. Review all jobs using the atq command and ensure IP addresses stored in the SSH_CONNECTION and SSH_CLIENT variables, machines that created the jobs, are trusted hosts. All at jobs are stored in /var/spool/cron/atjobs/. Suspicious program execution through scheduled tasks may show up as outlier processes that have not been seen before when compared against historical data. Data and events should not be viewed in isolation, but as part of a chain of behavior that could lead to other activities, such as network connections made for Command and Control, learning details about the environment through Discovery, and Lateral Movement.

Procedures:

- [G0027] Threat Group-3390: Threat Group-3390 actors use at to schedule tasks to run self-extracting RAR archives, which install HTTPBrowser or PlugX on other victims on a network.
- [S0488] CrackMapExec: CrackMapExec can set a scheduled task on the target system to execute commands remotely using at.
- [G0026] APT18: APT18 actors used the native at Windows task scheduler tool to use scheduled tasks for execution on a victim network.
- [G0060] BRONZE BUTLER: BRONZE BUTLER has used at to register a scheduled task to execute malware during lateral movement.
- [S0233] MURKYTOP: MURKYTOP has the capability to schedule remote AT jobs.
- [S0110] at: at can be used to schedule a task on a system to be executed at a specific date or time.

### T1053.003 - Scheduled Task/Job: Cron

Description:

Adversaries may abuse the cron utility to perform task scheduling for initial or recurring execution of malicious code. The cron utility is a time-based job scheduler for Unix-like operating systems. The crontab file contains the schedule of cron entries to be run and the specified times for execution. Any crontab files are stored in operating system-specific file paths. An adversary may use cron in Linux or Unix environments to execute programs at system startup or on a scheduled basis for Persistence. In ESXi environments, cron jobs must be created directly via the crontab file (e.g., `/var/spool/cron/crontabs/root`).

Detection:

Monitor scheduled task creation from common utilities using command-line invocation. Legitimate scheduled tasks may be created during installation of new software or through system administration functions. Look for changes to tasks that do not correlate with known software, patch cycles, etc. Suspicious program execution through scheduled tasks may show up as outlier processes that have not been seen before when compared against historical data. Data and events should not be viewed in isolation, but as part of a chain of behavior that could lead to other activities, such as network connections made for Command and Control, learning details about the environment through Discovery, and Lateral Movement.

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
- [S1107] NKAbuse: NKAbuse uses a Cron job to establish persistence when infecting Linux hosts.

### T1053.005 - Scheduled Task/Job: Scheduled Task

Description:

Adversaries may abuse the Windows Task Scheduler to perform task scheduling for initial or recurring execution of malicious code. There are multiple ways to access the Task Scheduler in Windows. The schtasks utility can be run directly on the command line, or the Task Scheduler can be opened through the GUI within the Administrator Tools section of the Control Panel. In some cases, adversaries have used a .NET wrapper for the Windows Task Scheduler, and alternatively, adversaries have used the Windows netapi32 library and Windows Management Instrumentation (WMI) to create a scheduled task. Adversaries may also utilize the Powershell Cmdlet `Invoke-CimMethod`, which leverages WMI class `PS_ScheduledTask` to create a scheduled task via an XML path. An adversary may use Windows Task Scheduler to execute programs at system startup or on a scheduled basis for persistence. The Windows Task Scheduler can also be abused to conduct remote Execution as part of Lateral Movement and/or to run a process under the context of a specified account (such as SYSTEM). Similar to System Binary Proxy Execution, adversaries have also abused the Windows Task Scheduler to potentially mask one-time execution under signed/trusted system processes. Adversaries may also create "hidden" scheduled tasks (i.e. Hide Artifacts) that may not be visible to defender tools and manual queries used to enumerate tasks. Specifically, an adversary may hide a task from `schtasks /query` and the Task Scheduler by deleting the associated Security Descriptor (SD) registry value (where deletion of this value must be completed using SYSTEM permissions). Adversaries may also employ alternate methods to hide tasks, such as altering the metadata (e.g., `Index` value) within associated registry keys.

Detection:

Monitor process execution from the svchost.exe in Windows 10 and the Windows Task Scheduler taskeng.exe for older versions of Windows. If scheduled tasks are not used for persistence, then the adversary is likely to remove the task when the action is complete. Monitor Windows Task Scheduler stores in %systemroot%\System32\Tasks for change entries related to scheduled tasks that do not correlate with known software, patch cycles, etc. Configure event logging for scheduled task creation and changes by enabling the "Microsoft-Windows-TaskScheduler/Operational" setting within the event logging service. Several events will then be logged on scheduled task activity, including: * Event ID 106 on Windows 7, Server 2008 R2 - Scheduled task registered * Event ID 140 on Windows 7, Server 2008 R2 / 4702 on Windows 10, Server 2016 - Scheduled task updated * Event ID 141 on Windows 7, Server 2008 R2 / 4699 on Windows 10, Server 2016 - Scheduled task deleted * Event ID 4698 on Windows 10, Server 2016 - Scheduled task created * Event ID 4700 on Windows 10, Server 2016 - Scheduled task enabled * Event ID 4701 on Windows 10, Server 2016 - Scheduled task disabled Tools such as Sysinternals Autoruns may also be used to detect system changes that could be attempts at persistence, including listing current scheduled tasks. Remote access tools with built-in features may interact directly with the Windows API to perform these functions outside of typical system utilities. Tasks may also be created through Windows system management tools such as Windows Management Instrumentation and PowerShell, so additional logging may need to be configured to gather the appropriate data.

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
- [G0091] Silence: Silence has used scheduled tasks to stage its operation.
- [G0114] Chimera: Chimera has used scheduled tasks to invoke Cobalt Strike including through batch script schtasks /create /ru "SYSTEM" /tn "update" /tr "cmd /c c:\windows\temp\update.bat" /sc once /f /st and to maintain persistence.
- [S1199] LockBit 2.0: LockBit 2.0 can be executed via scheduled task.
- [G0040] Patchwork: A Patchwork file stealer can run a TaskScheduler DLL to add persistence.
- [G1034] Daggerfly: Daggerfly has attempted to use scheduled tasks for persistence in victim environments.
- [S0248] yty: yty establishes persistence by creating a scheduled task with the command SchTasks /Create /SC DAILY /TN BigData /TR “ + path_file + “/ST 09:30“.
- [G0046] FIN7: FIN7 malware has created scheduled tasks to establish persistence.
- [S0589] Sibot: Sibot has been executed via a scheduled task.
- [S0504] Anchor: Anchor can create a scheduled task for persistence.
- [S0632] GrimAgent: GrimAgent has the ability to set persistence using the Task Scheduler.
- [G1018] TA2541: TA2541 has used scheduled tasks to establish persistence for installed tools.
- [G0093] GALLIUM: GALLIUM established persistence for PoisonIvy by created a scheduled task.
- [G0034] Sandworm Team: Sandworm Team leveraged SHARPIVORY, a .NET dropper that writes embedded payload to disk and uses scheduled tasks to persist on victim machines.
- [S1064] SVCReady: SVCReady can create a scheduled task named `RecoveryExTask` to gain persistence.
- [G1043] BlackByte: BlackByte created scheduled tasks for payload execution.
- [S0409] Machete: The different components of Machete are executed by Windows Task Scheduler.
- [G1001] HEXANE: HEXANE has used a scheduled task to establish persistence for a keylogger.
- [G0129] Mustang Panda: Mustang Panda has created a scheduled task to execute additional malicious software, as well as maintain persistence.
- [S0546] SharpStage: SharpStage has a persistence component to write a scheduled task for the payload.
- [S0368] NotPetya: NotPetya creates a task to reboot the system one hour after infection.
- [G0059] Magic Hound: Magic Hound has used scheduled tasks to establish persistence and execution.
- [C0034] 2022 Ukraine Electric Power Attack: During the 2022 Ukraine Electric Power Attack, Sandworm Team leveraged Scheduled Tasks through a Group Policy Object (GPO) to execute CaddyWiper at a predetermined time.
- [S1160] Latrodectus: Latrodectus can create scheduled tasks for persistence.
- [S1147] Nightdoor: Nightdoor uses scheduled tasks for persistence to load the final malware payload into memory.
- [S0350] zwShell: zwShell has used SchTasks for execution.
- [S0375] Remexi: Remexi utilizes scheduled tasks as a persistence mechanism.
- [S1058] Prestige: Prestige has been executed on a target system through a scheduled task created by Sandworm Team using Impacket.
- [C0017] C0017: During C0017, APT41 used the following Windows scheduled tasks for DEADEYE dropper persistence on US state government networks: `\Microsoft\Windows\PLA\Server Manager Performance Monitor`, `\Microsoft\Windows\Ras\ManagerMobility`, `\Microsoft\Windows\WDI\SrvSetupResults`, and `\Microsoft\Windows\WDI\USOShared`.
- [G1016] FIN13: FIN13 has created scheduled tasks in the `C:\Windows` directory of the compromised network.
- [C0001] Frankenstein: During Frankenstein, the threat actors established persistence through a scheduled task using the command: `/Create /F /SC DAILY /ST 09:00 /TN WinUpdate /TR`, named "WinUpdate"
- [S1081] BADHATCH: BADHATCH can use `schtasks.exe` to gain persistence.
- [S0384] Dridex: Dridex can maintain persistence via the creation of scheduled tasks within system directories such as `windows\system32\`, `windows\syswow64,` `winnt\system32`, and `winnt\syswow64`.
- [G1022] ToddyCat: ToddyCat has used scheduled tasks to execute discovery commands and scripts for collection.
- [G0108] Blue Mockingbird: Blue Mockingbird has used Windows Scheduled Tasks to establish persistence on local and remote hosts.
- [G0021] Molerats: Molerats has created scheduled tasks to persistently run VBScripts.
- [S0439] Okrum: Okrum's installer can attempt to achieve persistence by creating a scheduled task.
- [S0458] Ramsay: Ramsay can schedule tasks via the Windows COM API to maintain persistence.
- [S0538] Crutch: Crutch has the ability to persist using scheduled tasks.
- [S0671] Tomiris: Tomiris has used `SCHTASKS /CREATE /SC DAILY /TN StartDVL /TR "[path to self]" /ST 10:00` to establish persistence.
- [C0044] Juicy Mix: During Juicy Mix, OilRig used VBS droppers to schedule tasks for persistence.
- [S0606] Bad Rabbit: Bad Rabbit’s infpub.dat file creates a scheduled task to launch a malicious executable.
- [S0483] IcedID: IcedID has created a scheduled task to establish persistence.
- [G0016] APT29: APT29 has used named and hijacked scheduled tasks to establish persistence.
- [S1207] XLoader: XLoader can create scheduled tasks for persistence.
- [S1089] SharpDisco: SharpDisco can create scheduled tasks to execute reverse shells that read and write data to and from specified SMB shares.
- [S0527] CSPY Downloader: CSPY Downloader can use the schtasks utility to bypass UAC.
- [S0128] BADNEWS: BADNEWS creates a scheduled task to establish by executing a malicious payload every subsequent minute.
- [G0087] APT39: APT39 has created scheduled tasks for persistence.
- [G0061] FIN8: FIN8 has used scheduled tasks to maintain RDP backdoors.
- [S0024] Dyre: Dyre has the ability to achieve persistence by adding a new task in the task scheduler to run every minute.
- [G0102] Wizard Spider: Wizard Spider has used scheduled tasks to establish persistence for TrickBot and other malware.
- [S1013] ZxxZ: ZxxZ has used scheduled tasks for persistence and execution.
- [C0030] Triton Safety Instrumented System Attack: In the Triton Safety Instrumented System Attack, TEMP.Veles installed scheduled tasks defined in XML files.
- [S0532] Lucifer: Lucifer has established persistence by creating the following scheduled task schtasks /create /sc minute /mo 1 /tn QQMusic ^ /tr C:Users\%USERPROFILE%\Downloads\spread.exe /F.
- [S1018] Saint Bot: Saint Bot has created a scheduled task named "Maintenance" to establish persistence.
- [G0126] Higaisa: Higaisa dropped and added officeupdate.exe to scheduled tasks.
- [S0237] GravityRAT: GravityRAT creates a scheduled task to ensure it is re-executed everyday.
- [S1182] MagicRAT: MagicRAT can persist via scheduled tasks.
- [S1140] Spica: Spica has created a scheduled task named `CalendarChecker` to establish persistence.
- [S1190] Kapeka: Kapeka persists via scheduled tasks.
- [G0096] APT41: APT41 used a compromised account to create a scheduled task on a system.
- [S1149] CHIMNEYSWEEP: CHIMNEYSWEEP can use the Windows `SilentCleanup` scheduled task to enable payload execution.
- [S0516] SoreFang: SoreFang can gain persistence through use of scheduled tasks.
- [G0075] Rancor: Rancor launched a scheduled task to gain persistence using the schtasks /create /sc command.
- [S0360] BONDUPDATER: BONDUPDATER persists using a scheduled task that executes every minute.
- [S0447] Lokibot: Lokibot embedded the commands schtasks /Run /TN \Microsoft\Windows\DiskCleanup\SilentCleanup /I inside a batch script.
- [G1003] Ember Bear: Ember Bear uses remotely scheduled tasks to facilitate remote command execution on victim machines.
- [S0367] Emotet: Emotet has maintained persistence through a scheduled task, e.g. though a .dll file in the Registry.
- [S0688] Meteor: Meteor execution begins from a scheduled task named `Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeAll` and it creates a separate scheduled task called `mstask` to run the wiper only once at 23:55:00.
- [C0004] CostaRicto: During CostaRicto, the threat actors used scheduled tasks to download backdoor tools.
- [C0022] Operation Dream Job: During Operation Dream Job, Lazarus Group created scheduled tasks to set a periodic execution of a remote XSL script.
- [S1011] Tarrask: Tarrask is able to create “hidden” scheduled tasks for persistence.
- [C0012] Operation CuckooBees: During Operation CuckooBees, the threat actors used scheduled tasks to execute batch scripts for lateral movement with the following command: `SCHTASKS /Create /S /U /p /SC ONCE /TN test /TR /ST /RU SYSTEM.`
- [G0095] Machete: Machete has created scheduled tasks to maintain Machete's persistence.
- [S1180] BlackByte Ransomware: BlackByte Ransomware creates a schedule task to execute remotely deployed ransomware payloads.
- [G1044] APT42: APT42 has used scheduled tasks for persistence.
- [S0148] RTM: RTM tries to add a scheduled task to establish persistence.
- [S1042] SUGARDUMP: SUGARDUMP has created scheduled tasks called `MicrosoftInternetExplorerCrashRepoeterTaskMachineUA` and `MicrosoftEdgeCrashRepoeterTaskMachineUA`, which were configured to execute `CrashReporter.exe` during user logon.
- [G0051] FIN10: FIN10 has established persistence by using S4U tasks as well as the Scheduled Task option in PowerShell Empire.
- [G0019] Naikon: Naikon has used schtasks.exe for lateral movement in compromised networks.
- [S0140] Shamoon: Shamoon copies an executable payload to the target system by using SMB/Windows Admin Shares and then scheduling an unnamed task to execute the malware.
- [S0581] IronNetInjector: IronNetInjector has used a task XML file named mssch.xml to run an IronPython script when a user logs in or when specific system events are created.
- [G1039] RedCurl: RedCurl has created scheduled tasks for persistence.
- [S0194] PowerSploit: PowerSploit's New-UserPersistenceOption Persistence argument can be used to establish via a Scheduled Task/Job.
- [S0331] Agent Tesla: Agent Tesla has achieved persistence via scheduled tasks.
- [G1036] Moonstone Sleet: Moonstone Sleet used scheduled tasks for program execution during initial access to victim machines.
- [G0050] APT32: APT32 has used scheduled tasks to persist on victim systems.
- [S0438] Attor: Attor's installer plugin can schedule a new task that loads the dispatcher on boot/logon.
- [G0117] Fox Kitten: Fox Kitten has used Scheduled Tasks for persistence and to load and execute a reverse proxy binary.
- [G0064] APT33: APT33 has created a scheduled task to execute a .vbe file multiple times a day.
- [S0446] Ryuk: Ryuk can remotely create a scheduled task to execute itself on a system.
- [S0396] EvilBunny: EvilBunny has executed commands via scheduled tasks.
- [G0049] OilRig: OilRig has created scheduled tasks that run a VBScript to execute a payload on victim machines.
- [G0082] APT38: APT38 has used Task Scheduler to run programs at system startup or on a scheduled basis for persistence. Additionally, APT38 has used living-off-the-land scripts to execute a malicious script via a scheduled task.
- [S0449] Maze: Maze has created scheduled tasks using name variants such as "Windows Update Security", "Windows Update Security Patches", and "Google Chrome Security Update", to launch Maze at a specific time.
- [G0045] menuPass: menuPass has used a script (atexec.py) to execute a command on a target machine via Task Scheduler.
- [G0099] APT-C-36: APT-C-36 has used a macro function to set scheduled tasks, disguised as those used by Google.
- [S0166] RemoteCMD: RemoteCMD can execute commands remotely by creating a new schedule task on the remote system
- [S0584] AppleJeus: AppleJeus has created a scheduled SYSTEM task that runs when a user logs in.
- [S0046] CozyCar: One persistence mechanism used by CozyCar is to register itself as a scheduled task.
- [G0037] FIN6: FIN6 has used scheduled tasks to establish persistence for various malware it uses, including downloaders known as HARDTACK and SHIPBREAD and FrameworkPOS.
- [S0629] RainyDay: RainyDay can use scheduled tasks to achieve persistence.
- [G1014] LuminousMoth: LuminousMoth has created scheduled tasks to establish persistence for their tools.
- [S1043] ccf32: ccf32 can run on a daily basis using a scheduled task.
- [C0014] Operation Wocao: During Operation Wocao, threat actors used scheduled tasks to execute malicious PowerShell code on remote systems.
- [S0223] POWERSTATS: POWERSTATS has established persistence through a scheduled task using the command ”C:\Windows\system32\schtasks.exe” /Create /F /SC DAILY /ST 12:00 /TN MicrosoftEdge /TR “c:\Windows\system32\wscript.exe C:\Windows\temp\Windows.vbe”.
- [S0476] Valak: Valak has used scheduled tasks to execute additional payloads and to gain persistence on a compromised host.
- [G0032] Lazarus Group: Lazarus Group has used schtasks for persistence including through the periodic execution of a remote XSL script or a dropped VBS payload.
- [G0060] BRONZE BUTLER: BRONZE BUTLER has used schtasks to register a scheduled task to execute malware during lateral movement.
- [S0500] MCMD: MCMD can use scheduled tasks for persistence.
- [G1035] Winter Vivern: Winter Vivern executed PowerShell scripts that would subsequently attempt to establish persistence by creating scheduled tasks objects to periodically retrieve and execute remotely-hosted payloads.
- [S0038] Duqu: Adversaries can instruct Duqu to spread laterally by copying itself to shares it has enumerated and for which it has obtained legitimate credentials (via keylogging or other means). The remote host is then infected by using the compromised credentials to schedule a task on remote machines that executes the malware.
- [G0035] Dragonfly: Dragonfly has used scheduled tasks to automatically log out of created accounts every 8 hours as well as to execute malicious files.
- [S0475] BackConfig: BackConfig has the ability to use scheduled tasks to repeatedly execute malicious payloads on a compromised host.
- [S0198] NETWIRE: NETWIRE can create a scheduled task to establish persistence.
- [S1133] Apostle: Apostle achieves persistence by creating a scheduled task, such as MicrosoftCrashHandlerUAC.
- [S0363] Empire: Empire has modules to interact with the Windows task scheduler.
- [C0032] C0032: During the C0032 campaign, TEMP.Veles used scheduled task XML triggers.
- [G0069] MuddyWater: MuddyWater has used scheduled tasks to establish persistence.
- [S0390] SQLRat: SQLRat has created scheduled tasks in %appdata%\Roaming\Microsoft\Templates\.
- [S0264] OopsIE: OopsIE creates a scheduled task to run itself every three minutes.
- [S1039] Bumblebee: Bumblebee can achieve persistence by copying its DLL to a subdirectory of %APPDATA% and creating a Visual Basic Script that will load the DLL via a scheduled task.
- [S0534] Bazar: Bazar can create a scheduled task for persistence.
- [S0167] Matryoshka: Matryoshka can establish persistence by adding a Scheduled Task named "Microsoft Boost Kernel Optimization".
- [S0417] GRIFFON: GRIFFON has used sctasks for persistence.
- [S1135] MultiLayer Wiper: MultiLayer Wiper creates a malicious scheduled task that launches a batch file to remove Windows Event Logs.
- [S0382] ServHelper: ServHelper contains modules that will use schtasks to carry out malicious operations.
- [S1088] Disco: Disco can create a scheduled task to run every minute for persistence.
- [G0047] Gamaredon Group: Gamaredon Group has created scheduled tasks to launch executables after a designated number of minutes have passed.
- [S0673] DarkWatchman: DarkWatchman has created a scheduled task for persistence.
- [G0094] Kimsuky: Kimsuky has downloaded additional malware with scheduled tasks.
- [S0147] Pteranodon: Pteranodon schedules tasks to invoke its components in order to establish persistence.
- [S0603] Stuxnet: Stuxnet schedules a network job to execute two minutes after host infection.
- [S0260] InvisiMole: InvisiMole has used scheduled tasks named MSST and \Microsoft\Windows\Autochk\Scheduled to establish persistence.
- [S0050] CosmicDuke: CosmicDuke uses scheduled tasks typically named "Watchmon Service" for persistence.
- [G0038] Stealth Falcon: Stealth Falcon malware creates a scheduled task entitled “IE Web Cache” to execute a malicious file hourly.
- [G1002] BITTER: BITTER has used scheduled tasks for persistence and execution.
- [S0650] QakBot: QakBot has the ability to create scheduled tasks for persistence.
- [S0184] POWRUNER: POWRUNER persists through a scheduled task that executes it every minute.
- [S0379] Revenge RAT: Revenge RAT schedules tasks to run malicious scripts at different intervals.
- [S0168] Gazer: Gazer can establish persistence by creating a scheduled task.
- [G0142] Confucius: Confucius has created scheduled tasks to maintain persistence on a compromised host.
- [S0189] ISMInjector: ISMInjector creates scheduled tasks to establish persistence.
- [S0111] schtasks: schtasks is used to schedule tasks on a Windows system to run at a specific date and time.
- [S0262] QuasarRAT: QuasarRAT contains a .NET wrapper DLL for creating and managing scheduled tasks for maintaining persistence upon reboot.
- [S0477] Goopy: Goopy has the ability to maintain persistence by creating scheduled tasks set to run every hour.
- [S0680] LitePower: LitePower can create a scheduled task to enable persistence mechanisms.
- [S0226] Smoke Loader: Smoke Loader launches a scheduled task.
- [S1152] IMAPLoader: IMAPLoader creates scheduled tasks for persistence based on the operating system version of the victim machine.
- [G0067] APT37: APT37 has created scheduled tasks to run malicious scripts on a compromised host.
- [S0250] Koadic: Koadic has used scheduled tasks to add persistence.
- [S0251] Zebrocy: Zebrocy has a command to create a scheduled task for persistence.
- [S1087] AsyncRAT: AsyncRAT can create a scheduled task to maintain persistence on system start-up.
- [S0431] HotCroissant: HotCroissant has attempted to install a scheduled task named “Java Maintenance64” on startup to establish persistence.
- [S0269] QUADAGENT: QUADAGENT creates a scheduled task to maintain persistence on the victim’s machine.
- [S1169] Mango: Mango can create a scheduled task to run every 32 seconds to communicate with C2 and execute received commands.

### T1053.006 - Scheduled Task/Job: Systemd Timers

Description:

Adversaries may abuse systemd timers to perform task scheduling for initial or recurring execution of malicious code. Systemd timers are unit files with file extension .timer that control services. Timers can be set to run on a calendar event or after a time span relative to a starting point. They can be used as an alternative to Cron in Linux environments. Systemd timers may be activated remotely via the systemctl command line utility, which operates over SSH. Each .timer file must have a corresponding .service file with the same name, e.g., example.timer and example.service. .service files are Systemd Service unit files that are managed by the systemd system and service manager. Privileged timers are written to /etc/systemd/system/ and /usr/lib/systemd/system while user level are written to ~/.config/systemd/user/. An adversary may use systemd timers to execute malicious code at system startup or on a scheduled basis for persistence. Timers installed using privileged paths may be used to maintain root level persistence. Adversaries may also install user level timers to achieve user level persistence.

Detection:

Systemd timer unit files may be detected by auditing file creation and modification events within the /etc/systemd/system, /usr/lib/systemd/system/, and ~/.config/systemd/user/ directories, as well as associated symbolic links. Suspicious processes or scripts spawned in this manner will have a parent process of ‘systemd’, a parent process ID of 1, and will usually execute as the ‘root’ user. Suspicious systemd timers can also be identified by comparing results against a trusted system baseline. Malicious systemd timers may be detected by using the systemctl utility to examine system wide timers: systemctl list-timers –all. Analyze the contents of corresponding .service files present on the file system and ensure that they refer to legitimate, expected executables. Audit the execution and command-line arguments of the 'systemd-run' utility as it may be used to create timers.

### T1053.007 - Scheduled Task/Job: Container Orchestration Job

Description:

Adversaries may abuse task scheduling functionality provided by container orchestration tools such as Kubernetes to schedule deployment of containers configured to execute malicious code. Container orchestration jobs run these automated tasks at a specific date and time, similar to cron jobs on a Linux system. Deployments of this type can also be configured to maintain a quantity of containers over time, automating the process of maintaining persistence within a cluster. In Kubernetes, a CronJob may be used to schedule a Job that runs one or more containers to perform specific tasks. An adversary therefore may utilize a CronJob to schedule deployment of a Job that executes malicious code in various nodes within a cluster.

Detection:

Monitor for the anomalous creation of scheduled jobs in container orchestration environments. Use logging agents on Kubernetes nodes and retrieve logs from sidecar proxies for application and resource pods to monitor malicious container orchestration job deployments.


### T1078.001 - Valid Accounts: Default Accounts

Description:

Adversaries may obtain and abuse credentials of a default account as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion. Default accounts are those that are built-into an OS, such as the Guest or Administrator accounts on Windows systems. Default accounts also include default factory/provider set accounts on other types of systems, software, or devices, including the root user account in AWS, the root user account in ESXi, and the default service account in Kubernetes. Default accounts are not limited to client machines; rather, they also include accounts that are preset for equipment such as network devices and computer applications, whether they are internal, open source, or commercial. Appliances that come preset with a username and password combination pose a serious threat to organizations that do not change it post installation, as they are easy targets for an adversary. Similarly, adversaries may also utilize publicly disclosed or stolen Private Keys or credential materials to legitimately connect to remote environments via Remote Services. Default accounts may be created on a system after initial setup by connecting or integrating it with another application. For example, when an ESXi server is connected to a vCenter server, a default privileged account called `vpxuser` is created on the ESXi server. If a threat actor is able to compromise this account’s credentials (for example, via Exploitation for Credential Access on the vCenter host), they will then have access to the ESXi server.

Detection:

Monitor whether default accounts have been activated or logged into. These audits should also include checks on any appliances and applications for default credentials or SSH keys, and if any are discovered, they should be updated immediately.

Procedures:

- [G1016] FIN13: FIN13 has leveraged default credentials for authenticating myWebMethods (WMS) and QLogic web management interface to gain initial access.
- [S0537] HyperStack: HyperStack can use default credentials to connect to IPC$ shares on remote machines.
- [C0038] HomeLand Justice: During HomeLand Justice, threat actors used the built-in administrator account to move laterally using RDP and Impacket.
- [G0059] Magic Hound: Magic Hound enabled and used the default system managed account, DefaultAccount, via `"powershell.exe" /c net user DefaultAccount /active:yes` to connect to a targeted Exchange server over RDP.
- [S0603] Stuxnet: Stuxnet infected WinCC machines via a hardcoded database server password.
- [G1003] Ember Bear: Ember Bear has abused default user names and passwords in externally-accessible IP cameras for initial access.

### T1078.002 - Valid Accounts: Domain Accounts

Description:

Adversaries may obtain and abuse credentials of a domain account as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion. Domain accounts are those managed by Active Directory Domain Services where access and permissions are configured across systems and services that are part of that domain. Domain accounts can cover users, administrators, and services. Adversaries may compromise domain accounts, some with a high level of privileges, through various means such as OS Credential Dumping or password reuse, allowing access to privileged resources of the domain.

Detection:

Configure robust, consistent account activity audit policies across the enterprise and with externally accessible services. Look for suspicious account behavior across systems that share accounts, either user, admin, or service accounts. Examples: one account logged into multiple systems simultaneously; multiple accounts logged into the same machine simultaneously; accounts logged in at odd times or outside of business hours. Activity may be from interactive login sessions or process ownership from accounts being used to execute binaries on a remote system as a particular account. Correlate other security systems with login information (e.g., a user has an active login session but has not entered the building or does not have VPN access). On Linux, check logs and other artifacts created by use of domain authentication services, such as the System Security Services Daemon (sssd). Perform regular audits of domain accounts to detect accounts that may have been created by an adversary for persistence.

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
- [G1021] Cinnamon Tempest: Cinnamon Tempest has obtained highly privileged credentials such as domain administrator in order to deploy malware.
- [G1022] ToddyCat: ToddyCat has used compromised domain admin credentials to mount local network shares.
- [G0119] Indrik Spider: Indrik Spider has collected credentials from infected systems, including domain accounts.
- [G0022] APT3: APT3 leverages valid accounts after gaining credentials for use within the victim domain.
- [G0114] Chimera: Chimera has used compromised domain accounts to gain access to the target environment.
- [C0014] Operation Wocao: During Operation Wocao, threat actors used domain credentials, including domain admin, for lateral movement and privilege escalation.
- [G1040] Play: Play has used valid domain accounts for access.
- [G0092] TA505: TA505 has used stolen domain admin accounts to compromise additional hosts.
- [G0028] Threat Group-1314: Threat Group-1314 actors used compromised domain credentials for the victim's endpoint management platform, Altiris, to move laterally.
- [G1023] APT5: APT5 has used legitimate account credentials to move laterally through compromised environments.
- [G0059] Magic Hound: Magic Hound has used domain administrator accounts after dumping LSASS process memory.
- [C0029] Cutting Edge: During Cutting Edge, threat actors used compromised VPN accounts for lateral movement on targeted networks.
- [S0603] Stuxnet: Stuxnet attempts to access network resources with a domain account’s credentials.
- [G1017] Volt Typhoon: Volt Typhoon has used compromised domain accounts to authenticate to devices on compromised networks.
- [G1043] BlackByte: BlackByte captured credentials for or impersonated domain administration users.
- [G0143] Aquatic Panda: Aquatic Panda used multiple mechanisms to capture valid user accounts for victim domains to enable lateral movement and access to additional hosts in victim environments.

### T1078.003 - Valid Accounts: Local Accounts

Description:

Adversaries may obtain and abuse credentials of a local account as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion. Local accounts are those configured by an organization for use by users, remote support, services, or for administration on a single system or service. Local Accounts may also be abused to elevate privileges and harvest credentials through OS Credential Dumping. Password reuse may allow the abuse of local accounts across a set of machines on a network for the purposes of Privilege Escalation and Lateral Movement.

Detection:

Perform regular audits of local system accounts to detect accounts that may have been created by an adversary for persistence. Look for suspicious account behavior, such as accounts logged in at odd times or outside of business hours.

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
- [S0368] NotPetya: NotPetya can use valid credentials with PsExec or wmic to spread itself to remote systems.
- [S1202] LockBit 3.0: LockBit 3.0 can use a compromised local account for lateral movement.
- [S0221] Umbreon: Umbreon creates valid local users to provide access to the system.
- [C0014] Operation Wocao: During Operation Wocao, threat actors used local account credentials found during the intrusion for lateral movement and privilege escalation.
- [G0010] Turla: Turla has abused local accounts that have the same password across the victim’s network.

### T1078.004 - Valid Accounts: Cloud Accounts

Description:

Valid accounts in cloud environments may allow adversaries to perform actions to achieve Initial Access, Persistence, Privilege Escalation, or Defense Evasion. Cloud accounts are those created and configured by an organization for use by users, remote support, services, or for administration of resources within a cloud service provider or SaaS application. Cloud Accounts can exist solely in the cloud; alternatively, they may be hybrid-joined between on-premises systems and the cloud through syncing or federation with other identity sources such as Windows Active Directory. Service or user accounts may be targeted by adversaries through Brute Force, Phishing, or various other means to gain access to the environment. Federated or synced accounts may be a pathway for the adversary to affect both on-premises systems and cloud environments - for example, by leveraging shared credentials to log onto Remote Services. High privileged cloud accounts, whether federated, synced, or cloud-only, may also allow pivoting to on-premises environments by leveraging SaaS-based Software Deployment Tools to run commands on hybrid-joined devices. An adversary may create long lasting Additional Cloud Credentials on a compromised cloud account to maintain persistence in the environment. Such credentials may also be used to bypass security controls such as multi-factor authentication. Cloud accounts may also be able to assume Temporary Elevated Cloud Access or other privileges through various means within the environment. Misconfigurations in role assignments or role assumption policies may allow an adversary to use these mechanisms to leverage permissions outside the intended scope of the account. Such over privileged accounts may be used to harvest sensitive data from online storage accounts and databases through Cloud API or other methods. For example, in Azure environments, adversaries may target Azure Managed Identities, which allow associated Azure resources to request access tokens. By compromising a resource with an attached Managed Identity, such as an Azure VM, adversaries may be able to Steal Application Access Tokens to move laterally across the cloud environment.

Detection:

Monitor the activity of cloud accounts to detect abnormal or malicious behavior, such as accessing information outside of the normal function of the account or account usage at atypical hours.

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

Description:

Adversaries may add adversary-controlled credentials to a cloud account to maintain persistent access to victim accounts and instances within the environment. For example, adversaries may add credentials for Service Principals and Applications in addition to existing legitimate credentials in Azure / Entra ID. These credentials include both x509 keys and passwords. With sufficient permissions, there are a variety of ways to add credentials including the Azure Portal, Azure command line interface, and Azure or Az PowerShell modules. In infrastructure-as-a-service (IaaS) environments, after gaining access through Cloud Accounts, adversaries may generate or import their own SSH keys using either the CreateKeyPair or ImportKeyPair API in AWS or the gcloud compute os-login ssh-keys add command in GCP. This allows persistent access to instances within the cloud environment without further usage of the compromised cloud accounts. Adversaries may also use the CreateAccessKey API in AWS or the gcloud iam service-accounts keys create command in GCP to add access keys to an account. Alternatively, they may use the CreateLoginProfile API in AWS to add a password that can be used to log into the AWS Management Console for Cloud Service Dashboard. If the target account has different permissions from the requesting account, the adversary may also be able to escalate their privileges in the environment (i.e. Cloud Accounts). For example, in Entra ID environments, an adversary with the Application Administrator role can add a new set of credentials to their application's service principal. In doing so the adversary would be able to access the service principal’s roles and permissions, which may be different from those of the Application Administrator. In AWS environments, adversaries with the appropriate permissions may also use the `sts:GetFederationToken` API call to create a temporary set of credentials to Forge Web Credentials tied to the permissions of the original user account. These temporary credentials may remain valid for the duration of their lifetime even if the original account’s API credentials are deactivated. In Entra ID environments with the app password feature enabled, adversaries may be able to add an app password to a user account. As app passwords are intended to be used with legacy devices that do not support multi-factor authentication (MFA), adding an app password can allow an adversary to bypass MFA requirements. Additionally, app passwords may remain valid even if the user’s primary password is reset.

Detection:

Monitor Azure Activity Logs for Service Principal and Application modifications. Monitor for the usage of APIs that create or import SSH keys, particularly by unexpected users or accounts such as the root account. Monitor for use of credentials at unusual times or to unusual systems or services. This may also correlate with other suspicious activity.

Procedures:

- [S1091] Pacu: Pacu can generate SSH and API keys for AWS infrastructure and additional API keys for other IAM users.
- [C0027] C0027: During C0027, Scattered Spider used aws_consoler to create temporary federated credentials for fake users in order to obfuscate which AWS credential is compromised and enable pivoting from the AWS CLI to console sessions without MFA.
- [C0024] SolarWinds Compromise: During the SolarWinds Compromise, APT29 added credentials to OAuth Applications and Service Principals.

### T1098.002 - Account Manipulation: Additional Email Delegate Permissions

Description:

Adversaries may grant additional permission levels to maintain persistent access to an adversary-controlled email account. For example, the Add-MailboxPermission PowerShell cmdlet, available in on-premises Exchange and in the cloud-based service Office 365, adds permissions to a mailbox. In Google Workspace, delegation can be enabled via the Google Admin console and users can delegate accounts via their Gmail settings. Adversaries may also assign mailbox folder permissions through individual folder permissions or roles. In Office 365 environments, adversaries may assign the Default or Anonymous user permissions or roles to the Top of Information Store (root), Inbox, or other mailbox folders. By assigning one or both user permissions to a folder, the adversary can utilize any other account in the tenant to maintain persistence to the target user’s mail folders. This may be used in persistent threat incidents as well as BEC (Business Email Compromise) incidents where an adversary can add Additional Cloud Roles to the accounts they wish to compromise. This may further enable use of additional techniques for gaining access to systems. For example, compromised business accounts are often used to send messages to other accounts in the network of the target business while creating inbox rules (ex: Internal Spearphishing), so the messages evade spam/phishing detection mechanisms.

Detection:

Monitor for unusual Exchange and Office 365 email account permissions changes that may indicate excessively broad permissions being granted to compromised accounts. Enable the UpdateFolderPermissions action for all logon types. The mailbox audit log will forward folder permission modification events to the Unified Audit Log. Create rules to alert on ModifyFolderPermissions operations where the Anonymous or Default user is assigned permissions other than None. A larger than normal volume of emails sent from an account and similar phishing emails sent from real accounts within a network may be a sign that an account was compromised and attempts to leverage access with modified email permissions is occurring.

Procedures:

- [C0038] HomeLand Justice: During HomeLand Justice, threat actors added the `ApplicationImpersonation` management role to accounts under their control to impersonate users and take ownership of targeted mailboxes.
- [C0024] SolarWinds Compromise: During the SolarWinds Compromise, APT29 added their own devices as allowed IDs for active sync using `Set-CASMailbox`, allowing it to obtain copies of victim mailboxes. It also added additional permissions (such as Mail.Read and Mail.ReadWrite) to compromised Application or Service Principals.
- [G0059] Magic Hound: Magic Hound granted compromised email accounts read access to the email boxes of additional targeted accounts. The group then was able to authenticate to the intended victim's OWA (Outlook Web Access) portal and read hundreds of email communications for information on Middle East organizations.
- [G0007] APT28: APT28 has used a Powershell cmdlet to grant the ApplicationImpersonation role to a compromised account.
- [G0016] APT29: APT29 has used a compromised global administrator account in Azure AD to backdoor a service principal with `ApplicationImpersonation` rights to start collecting emails from targeted mailboxes; APT29 has also used compromised accounts holding `ApplicationImpersonation` rights in Exchange to collect emails.

### T1098.003 - Account Manipulation: Additional Cloud Roles

Description:

An adversary may add additional roles or permissions to an adversary-controlled cloud account to maintain persistent access to a tenant. For example, adversaries may update IAM policies in cloud-based environments or add a new global administrator in Office 365 environments. With sufficient permissions, a compromised account can gain almost unlimited access to data and settings (including the ability to reset the passwords of other admins). This account modification may immediately follow Create Account or other malicious account activity. Adversaries may also modify existing Valid Accounts that they have compromised. This could lead to privilege escalation, particularly if the roles added allow for lateral movement to additional accounts. For example, in AWS environments, an adversary with appropriate permissions may be able to use the CreatePolicyVersion API to define a new version of an IAM policy or the AttachUserPolicy API to attach an IAM policy with additional or distinct permissions to a compromised user account. In some cases, adversaries may add roles to adversary-controlled accounts outside the victim cloud tenant. This allows these external accounts to perform actions inside the victim tenant without requiring the adversary to Create Account or modify a victim-owned account.

Detection:

Collect activity logs from IAM services and cloud administrator accounts to identify unusual activity in the assignment of roles to those accounts. Monitor for accounts assigned to admin roles that go over a certain threshold of known admins.

Procedures:

- [C0027] C0027: During C0027, Scattered Spider used IAM manipulation to gain persistence and to assume or elevate privileges.
- [C0024] SolarWinds Compromise: During the SolarWinds Compromise, APT29 granted `company administrator` privileges to a newly created service principle.
- [G1015] Scattered Spider: During C0027, Scattered Spider used IAM manipulation to gain persistence and to assume or elevate privileges. Scattered Spider has also assigned user access admin roles in order to gain Tenant Root Group management permissions in Azure.
- [G1004] LAPSUS$: LAPSUS$ has added the global admin role to accounts they have created in the targeted organization's cloud instances.

### T1098.004 - Account Manipulation: SSH Authorized Keys

Description:

Adversaries may modify the SSH authorized_keys file to maintain persistence on a victim host. Linux distributions, macOS, and ESXi hypervisors commonly use key-based authentication to secure the authentication process of SSH sessions for remote management. The authorized_keys file in SSH specifies the SSH keys that can be used for logging into the user account for which the file is configured. This file is usually found in the user's home directory under &lt;user-home&gt;/.ssh/authorized_keys (or, on ESXi, `/etc/ssh/keys-/authorized_keys`). Users may edit the system’s SSH config file to modify the directives `PubkeyAuthentication` and `RSAAuthentication` to the value `yes` to ensure public key and RSA authentication are enabled, as well as modify the directive `PermitRootLogin` to the value `yes` to enable root authentication via SSH. The SSH config file is usually located under /etc/ssh/sshd_config. Adversaries may modify SSH authorized_keys files directly with scripts or shell commands to add their own adversary-supplied public keys. In cloud environments, adversaries may be able to modify the SSH authorized_keys file of a particular virtual machine via the command line interface or rest API. For example, by using the Google Cloud CLI’s “add-metadata” command an adversary may add SSH keys to a user account. Similarly, in Azure, an adversary may update the authorized_keys file of a virtual machine via a PATCH request to the API. This ensures that an adversary possessing the corresponding private key may log in as an existing user via SSH. It may also lead to privilege escalation where the virtual machine or instance has distinct permissions from the requesting user. Where authorized_keys files are modified via cloud APIs or command line interfaces, an adversary may achieve privilege escalation on the target virtual machine if they add a key to a higher-privileged user. SSH keys can also be added to accounts on network devices, such as with the `ip ssh pubkey-chain` Network Device CLI command.

Detection:

Use file integrity monitoring to detect changes made to the authorized_keys file for each user on a system. Monitor for suspicious processes modifying the authorized_keys file. In cloud environments, monitor instances for modification of metadata and configurations. Monitor for changes to and suspicious processes modifiying /etc/ssh/sshd_config. For network infrastructure devices, collect AAA logging to monitor for rogue SSH keys being added to accounts.

Procedures:

- [G1006] Earth Lusca: Earth Lusca has dropped an SSH-authorized key in the `/root/.ssh` folder in order to access a compromised server with SSH.
- [S0468] Skidmap: Skidmap has the ability to add the public key of its handlers to the authorized_keys file to maintain persistence on an infected host.
- [G1045] Salt Typhoon: Salt Typhoon has added SSH authorized_keys under root or other users at the Linux level on compromised network devices.
- [S0658] XCSSET: XCSSET will create an ssh key if necessary with the ssh-keygen -t rsa -f $HOME/.ssh/id_rsa -P command. XCSSET will upload a private key file to the server to remotely access the host without a password.
- [S0482] Bundlore: Bundlore creates a new key pair with ssh-keygen and drops the newly created user key in authorized_keys to enable remote login.
- [G0139] TeamTNT: TeamTNT has added RSA keys in authorized_keys.

### T1098.005 - Account Manipulation: Device Registration

Description:

Adversaries may register a device to an adversary-controlled account. Devices may be registered in a multifactor authentication (MFA) system, which handles authentication to the network, or in a device management system, which handles device access and compliance. MFA systems, such as Duo or Okta, allow users to associate devices with their accounts in order to complete MFA requirements. An adversary that compromises a user’s credentials may enroll a new device in order to bypass initial MFA requirements and gain persistent access to a network. In some cases, the MFA self-enrollment process may require only a username and password to enroll the account's first device or to enroll a device to an inactive account. Similarly, an adversary with existing access to a network may register a device to Entra ID and/or its device management system, Microsoft Intune, in order to access sensitive data or resources while bypassing conditional access policies. Devices registered in Entra ID may be able to conduct Internal Spearphishing campaigns via intra-organizational emails, which are less likely to be treated as suspicious by the email client. Additionally, an adversary may be able to perform a Service Exhaustion Flood on an Entra ID tenant by registering a large number of devices.

Procedures:

- [G0016] APT29: APT29 has enrolled their own devices into compromised cloud tenants, including enrolling a device in MFA to an Azure AD environment following a successful password guessing attack against a dormant account.
- [S0677] AADInternals: AADInternals can register a device to Azure AD.
- [C0024] SolarWinds Compromise: During the SolarWinds Compromise, APT29 registered devices in order to enable mailbox syncing via the `Set-CASMailbox` command.
- [C0027] C0027: During C0027, Scattered Spider registered devices for MFA to maintain persistence through victims' VPN.

### T1098.006 - Account Manipulation: Additional Container Cluster Roles

Description:

An adversary may add additional roles or permissions to an adversary-controlled user or service account to maintain persistent access to a container orchestration system. For example, an adversary with sufficient permissions may create a RoleBinding or a ClusterRoleBinding to bind a Role or ClusterRole to a Kubernetes account. Where attribute-based access control (ABAC) is in use, an adversary with sufficient permissions may modify a Kubernetes ABAC policy to give the target account additional permissions. This account modification may immediately follow Create Account or other malicious account activity. Adversaries may also modify existing Valid Accounts that they have compromised. Note that where container orchestration systems are deployed in cloud environments, as with Google Kubernetes Engine, Amazon Elastic Kubernetes Service, and Azure Kubernetes Service, cloud-based role-based access control (RBAC) assignments or ABAC policies can often be used in place of or in addition to local permission assignments. In these cases, this technique may be used in conjunction with Additional Cloud Roles.

### T1098.007 - Account Manipulation: Additional Local or Domain Groups

Description:

An adversary may add additional local or domain groups to an adversary-controlled account to maintain persistent access to a system or domain. On Windows, accounts may use the `net localgroup` and `net group` commands to add existing users to local and domain groups. On Linux, adversaries may use the `usermod` command for the same purpose. For example, accounts may be added to the local administrators group on Windows devices to maintain elevated privileges. They may also be added to the Remote Desktop Users group, which allows them to leverage Remote Desktop Protocol to log into the endpoints in the future. On Linux, accounts may be added to the sudoers group, allowing them to persistently leverage Sudo and Sudo Caching for elevated privileges. In Windows environments, machine accounts may also be added to domain groups. This allows the local SYSTEM account to gain privileges on the domain.

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


### T1112 - Modify Registry

Description:

Adversaries may interact with the Windows Registry as part of a variety of other techniques to aid in defense evasion, persistence, and execution. Access to specific areas of the Registry depends on account permissions, with some keys requiring administrator-level access. The built-in Windows command-line utility Reg may be used for local or remote Registry modification. Other tools, such as remote access tools, may also contain functionality to interact with the Registry through the Windows API. The Registry may be modified in order to hide configuration information or malicious payloads via Obfuscated Files or Information. The Registry may also be modified to Impair Defenses, such as by enabling macros for all Microsoft Office products, allowing privilege escalation without alerting the user, increasing the maximum number of allowed outbound requests, and/or modifying systems to store plaintext credentials in memory. The Registry of a remote system may be modified to aid in execution of files as part of lateral movement. It requires the remote Registry service to be running on the target system. Often Valid Accounts are required, along with access to the remote system's SMB/Windows Admin Shares for RPC communication. Finally, Registry modifications may also include actions to hide keys, such as prepending key names with a null character, which will cause an error and/or be ignored when read via Reg or other utilities using the Win32 API. Adversaries may abuse these pseudo-hidden keys to conceal payloads/commands used to maintain persistence.

Detection:

Modifications to the Registry are normal and occur throughout typical use of the Windows operating system. Consider enabling Registry Auditing on specific keys to produce an alertable event (Event ID 4657) whenever a value is changed (though this may not trigger when values are created with Reghide or other evasive methods). Changes to Registry entries that load software on Windows startup that do not correlate with known software, patch cycles, etc., are suspicious, as are additions or changes to files within the startup folder. Changes could also include new services and modification of existing binary paths to point to malicious files. If a change to a service-related entry occurs, then it will likely be followed by a local or remote service start or restart to execute the file. Monitor processes and command-line arguments for actions that could be taken to change or delete information in the Registry. Remote access tools with built-in features may interact directly with the Windows API to gather information. The Registry may also be modified through Windows system management tools such as Windows Management Instrumentation and PowerShell, which may require additional logging features to be configured in the operating system to collect necessary information for analysis. Monitor for processes, command-line arguments, and API calls associated with concealing Registry keys, such as Reghide. Inspect and cleanup malicious hidden Registry entries using Native Windows API calls and/or tools such as Autoruns and RegDelNull .

Procedures:

- [S0674] CharmPower: CharmPower can remove persistence-related artifacts from the Registry.
- [C0028] 2015 Ukraine Electric Power Attack: During the 2015 Ukraine Electric Power Attack, Sandworm Team modified in-registry Internet settings to lower internet security before launching `rundll32.exe`, which in-turn launches the malware and communicates with C2 servers over the Internet. .
- [G0010] Turla: Turla has modified Registry values to store payloads.
- [S0013] PlugX: PlugX has a module to create, delete, or modify Registry keys.
- [S0596] ShadowPad: ShadowPad can modify the Registry to store and maintain a configuration block and virtual file system.
- [S0457] Netwalker: Netwalker can add the following registry entry: HKEY_CURRENT_USER\SOFTWARE\{8 random characters}.
- [S0476] Valak: Valak has the ability to modify the Registry key HKCU\Software\ApplicationContainer\Appsw64 to store information regarding the C2 server and downloads.
- [S0240] ROKRAT: ROKRAT can modify the `HKEY_CURRENT_USER\Software\Microsoft\Office\` registry key so it can bypass the VB object model (VBOM) on a compromised host.
- [G0082] APT38: APT38 uses a tool called CLEANTOAD that has the capability to modify Registry keys.
- [S0376] HOPLIGHT: HOPLIGHT has modified Managed Object Format (MOF) files within the Registry to run specific commands and create persistence on the system.
- [S0261] Catchamas: Catchamas creates three Registry keys to establish persistence by adding a Windows Service.
- [S0032] gh0st RAT: gh0st RAT has altered the InstallTime subkey.
- [S0242] SynAck: SynAck can manipulate Registry keys.
- [S0533] SLOTHFULMEDIA: SLOTHFULMEDIA can add, modify, and/or delete registry keys. It has changed the proxy configuration of a victim system by modifying the HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap registry.
- [S0608] Conficker: Conficker adds keys to the Registry at HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services and various other Registry locations.
- [S1033] DCSrv: DCSrv has created Registry keys for persistence.
- [S0559] SUNBURST: SUNBURST had commands that allow an attacker to write or delete registry keys, and was observed stopping services by setting their HKLM\SYSTEM\CurrentControlSet\services\\[service_name]\\Start registry entries to value 4. It also deleted previously-created Image File Execution Options (IFEO) Debugger registry values and registry keys related to HTTP proxy to clean up traces of its activity.
- [G0040] Patchwork: A Patchwork payload deletes Resiliency Registry keys created by Microsoft Office applications in an apparent effort to trick users into thinking there were no issues during application runs.
- [S0569] Explosive: Explosive has a function to write itself to Registry values.
- [S0518] PolyglotDuke: PolyglotDuke can write encrypted JSON configuration files to the Registry.
- [S0012] PoisonIvy: PoisonIvy creates a Registry subkey that registers a new system device.
- [S0669] KOCTOPUS: KOCTOPUS has added and deleted keys from the Registry.
- [S1202] LockBit 3.0: LockBit 3.0 can change the Registry values for Group Policy refresh time, to disable SmartScreen, and to disable Windows Defender.
- [G0119] Indrik Spider: Indrik Spider has modified registry keys to prepare for ransomware execution and to disable common administrative utilities.
- [S0397] LoJax: LoJax has modified the Registry key ‘HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\BootExecute’ from ‘autocheck autochk *’ to ‘autocheck autoche *’.
- [S0158] PHOREAL: PHOREAL is capable of manipulating the Registry.
- [S0428] PoetRAT: PoetRAT has made registry modifications to alter its behavior upon execution.
- [S0496] REvil: REvil can modify the Registry to save encryption parameters and system information.
- [S0031] BACKSPACE: BACKSPACE is capable of deleting Registry keys, sub-keys, and values on a victim system.
- [S0673] DarkWatchman: DarkWatchman can modify Registry values to store configuration strings, keylogger, and output of components.
- [S0531] Grandoreiro: Grandoreiro can modify the Registry to store its configuration at `HKCU\Software\` under frequently changing names including %USERNAME% and ToolTech-RM.
- [S0011] Taidoor: Taidoor has the ability to modify the Registry on compromised hosts using RegDeleteValueA and RegCreateKeyExA.
- [S0603] Stuxnet: Stuxnet can create registry keys to load driver files.
- [S0668] TinyTurla: TinyTurla can set its configuration parameters in the Registry.
- [S0267] FELIXROOT: FELIXROOT deletes the Registry key HKCU\Software\Classes\Applications\rundll32.exe\shell\open.
- [S0649] SMOKEDHAM: SMOKEDHAM has modified registry keys for persistence, to enable credential caching for credential access, and to facilitate lateral movement via RDP.
- [S0517] Pillowmint: Pillowmint has modified the Registry key HKLM\SOFTWARE\Microsoft\DRM to store a malicious payload.
- [S0501] PipeMon: PipeMon has modified the Registry to store its encrypted payload.
- [S1060] Mafalda: Mafalda can manipulate the system registry on a compromised host.
- [G0091] Silence: Silence can create, delete, or modify a specified Registry key or value.
- [G0092] TA505: TA505 has used malware to disable Windows Defender through modification of the Registry.
- [S0023] CHOPSTICK: CHOPSTICK may modify Registry keys to store RC4 encrypted configuration information.
- [S1181] BlackByte 2.0 Ransomware: BlackByte 2.0 Ransomware modifies the victim Registry to allow for elevated execution.
- [S0697] HermeticWiper: HermeticWiper has the ability to modify Registry keys to disable crash dumps, colors for compressed files, and pop-up information about folders and desktop items.
- [S0670] WarzoneRAT: WarzoneRAT can create `HKCU\Software\Classes\Folder\shell\open\command` as a new registry key during privilege escalation.
- [S0154] Cobalt Strike: Cobalt Strike can modify Registry values within HKEY_CURRENT_USER\Software\Microsoft\Office\\Excel\Security\AccessVBOM\ to enable the execution of additional code.
- [G0073] APT19: APT19 uses a Port 22 malware variant to modify several Registry keys.
- [S1201] TRANSLATEXT: TRANSLATEXT has modified the following registry key to install itself as the value, granting permission to install specified extensions: ` HKCU\Software\Policies\Google\Chrome\ExtensionInstallForcelist`.
- [S0527] CSPY Downloader: CSPY Downloader can write to the Registry under the %windir% variable to execute tasks.
- [S0666] Gelsemium: Gelsemium can modify the Registry to store its components.
- [S0612] WastedLocker: WastedLocker can modify registry values within the Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap registry key.
- [S1059] metaMain: metaMain can write the process ID of a target process into the `HKEY_LOCAL_MACHINE\SOFTWARE\DDE\tpid` Registry value as part of its reflective loading activity.
- [S1178] ShrinkLocker: ShrinkLocker modifies various registry keys associated with system logon and BitLocker functionality to effectively lock-out users following disk encryption.
- [S0262] QuasarRAT: QuasarRAT has a command to edit the Registry on the victim’s machine.
- [S0203] Hydraq: Hydraq creates a Registry subkey to register its created service, and can also uninstall itself later by deleting this value. Hydraq's backdoor also enables remote attackers to modify and delete subkeys.
- [S1068] BlackCat: BlackCat has the ability to add the following registry key on compromised networks to maintain persistence: `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services \LanmanServer\Paramenters`
- [G1043] BlackByte: BlackByte performed Registry modifications to escalate privileges and disable security tools.
- [S1131] NPPSPY: NPPSPY modifies the Registry to record the malicious listener for output from the Winlogon process.
- [S1070] Black Basta: Black Basta has modified the Registry to enable itself to run in safe mode, to change the icons and file extensions for encrypted files, and to add the malware path for persistence.
- [S0254] PLAINTEE: PLAINTEE uses reg add to add a Registry Run key for persistence.
- [G0030] Lotus Blossom: Lotus Blossom has installed tools such as Sagerunex by writing them to the Windows registry.
- [S1199] LockBit 2.0: LockBit 2.0 can create Registry keys to bypass UAC and for persistence.
- [G0047] Gamaredon Group: Gamaredon Group has removed security settings for VBA macro execution by changing registry values HKCU\Software\Microsoft\Office\&lt;version&gt;\&lt;product&gt;\Security\VBAWarnings and HKCU\Software\Microsoft\Office\&lt;version&gt;\&lt;product&gt;\Security\AccessVBOM.
- [S0692] SILENTTRINITY: SILENTTRINITY can modify registry keys, including to enable or disable Remote Desktop Protocol (RDP).
- [S1190] Kapeka: Kapeka writes persistent configuration information to the victim host registry.
- [S0022] Uroburos: Uroburos can store configuration information in the Registry including the initialization vector and AES key needed to find and decrypt other Uroburos components.
- [S0579] Waterbear: Waterbear has deleted certain values from the Registry to load a malicious DLL.
- [S0157] SOUNDBITE: SOUNDBITE is capable of modifying the Registry.
- [C0002] Night Dragon: During Night Dragon, threat actors used zwShell to establish full remote control of the connected machine and manipulate the Registry.
- [S0332] Remcos: Remcos has full control of the Registry, including the ability to modify it.
- [S0260] InvisiMole: InvisiMole has a command to create, set, copy, or delete a specified Registry key or value.
- [S0455] Metamorfo: Metamorfo has written process names to the Registry, disabled IE browser features, deleted Registry keys, and changed the ExtendedUIHoverTime key.
- [S0256] Mosquito: Mosquito can modify Registry keys under HKCU\Software\Microsoft\[dllname] to store configuration values. Mosquito also modifies Registry keys under HKCR\CLSID\...\InprocServer32 with a path to the launcher.
- [S0560] TEARDROP: TEARDROP modified the Registry to create a Windows service for itself on a compromised host.
- [S0142] StreamEx: StreamEx has the ability to modify the Registry.
- [S0438] Attor: Attor's dispatcher can modify the Run registry key.
- [S1132] IPsec Helper: IPsec Helper can make arbitrary changes to registry keys based on provided input.
- [S0447] Lokibot: Lokibot has modified the Registry as part of its UAC bypass process.
- [S0412] ZxShell: ZxShell can create Registry entries to enable services to run.
- [S0356] KONNI: KONNI has modified registry keys of ComSysApp, Svchost, and xmlProv on the machine to gain persistence.
- [G0102] Wizard Spider: Wizard Spider has modified the Registry key HKLM\System\CurrentControlSet\Control\SecurityProviders\WDigest by setting the UseLogonCredential registry value to 1 in order to force credentials to be stored in clear text in memory. Wizard Spider has also modified the WDigest registry key to allow plaintext credentials to be cached in memory.
- [G0050] APT32: APT32's backdoor has modified the Windows Registry to store the backdoor's configuration.
- [G0143] Aquatic Panda: Aquatic Panda modified the victim registry to enable the `RestrictedAdmin` mode feature, allowing for pass the hash behaviors to function via RDP.
- [S0583] Pysa: Pysa has modified the registry key “SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System” and added the ransom note.
- [C0006] Operation Honeybee: During Operation Honeybee, the threat actors used batch files that modified registry keys.
- [S0245] BADCALL: BADCALL modifies the firewall Registry key SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfileGloballyOpenPorts\\List.
- [G1006] Earth Lusca: Earth Lusca modified the registry using the command reg add “HKEY_CURRENT_USER\Environment” /v UserInitMprLogonScript /t REG_SZ /d “[file path]” for persistence.
- [S0576] MegaCortex: MegaCortex has added entries to the Registry for ransom contact information.
- [S1058] Prestige: Prestige has the ability to register new registry keys for a new extension handler via `HKCR\.enc` and `HKCR\enc\shell\open\command`.
- [S0511] RegDuke: RegDuke can create seemingly legitimate Registry key to store its encryption key.
- [G0108] Blue Mockingbird: Blue Mockingbird has used Windows Registry modifications to specify a DLL payload.
- [S0691] Neoichor: Neoichor has the ability to configure browser settings by modifying Registry entries under `HKEY_CURRENT_USER\Software\Microsoft\Internet Explorer`.
- [G0049] OilRig: OilRig has used reg.exe to modify system configuration.
- [S1011] Tarrask: Tarrask is able to delete the Security Descriptor (`SD`) registry subkey in order to “hide” scheduled tasks.
- [S0572] Caterpillar WebShell: Caterpillar WebShell has a command to modify a Registry key.
- [S0268] Bisonal: Bisonal has deleted Registry keys to clean up its prior activity.
- [S0467] TajMahal: TajMahal can set the KeepPrintedJobs attribute for configured printers in SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Print\\Printers to enable document stealing.
- [S0537] HyperStack: HyperStack can add the name of its communication pipe to HKLM\SYSTEM\\CurrentControlSet\\Services\\lanmanserver\\parameters\NullSessionPipes.
- [S0115] Crimson: Crimson can set a Registry key to determine how long it has been installed and possibly to indicate the version number.
- [G1003] Ember Bear: Ember Bear modifies registry values for anti-forensics and defense evasion purposes.
- [S0229] Orz: Orz can perform Registry operations.
- [S0148] RTM: RTM can delete all Registry entries created during its execution.
- [G1017] Volt Typhoon: Volt Typhoon has used `netsh` to create a PortProxy Registry modification on a compromised server running the Paessler Router Traffic Grapher (PRTG).
- [S1099] Samurai: The Samurai loader component can create multiple Registry keys to force the svchost.exe process to load the final backdoor.
- [C0014] Operation Wocao: During Operation Wocao, the threat actors enabled Wdigest by changing the `HKLM\SYSTEM\\ControlSet001\\Control\\SecurityProviders\\WDigest` registry value from 0 (disabled) to 1 (enabled).
- [G0035] Dragonfly: Dragonfly has modified the Registry to perform multiple techniques through the use of Reg.
- [S0488] CrackMapExec: CrackMapExec can create a registry key using wdigest.
- [G0078] Gorgon Group: Gorgon Group malware can deactivate security mechanisms in Microsoft Office by editing several keys and values under HKCU\Software\Microsoft\Office\.
- [S0350] zwShell: zwShell can modify the Registry.
- [S0631] Chaes: Chaes can modify Registry values to stored information and establish persistence.
- [S0336] NanoCore: NanoCore has the capability to edit the Registry.
- [S0611] Clop: Clop can make modifications to Registry keys.
- [S0665] ThreatNeedle: ThreatNeedle can modify the Registry to save its configuration data as the following RC4-encrypted Registry key: `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\GameCon`.
- [S0386] Ursnif: Ursnif has used Registry modifications as part of its installation routine.
- [S0441] PowerShower: PowerShower has added a registry key so future powershell.exe instances are spawned off-screen by default, and has removed all registry entries that are left behind during the dropper process.
- [S0045] ADVSTORESHELL: ADVSTORESHELL is capable of setting and deleting Registry values.
- [S0568] EVILNUM: EVILNUM can make modifications to the Regsitry for persistence.
- [S0330] Zeus Panda: Zeus Panda modifies several Registry keys under HKCU\Software\Microsoft\Internet Explorer\ PhishingFilter\ to disable phishing filters.
- [S0343] Exaramel for Windows: Exaramel for Windows adds the configuration to the Registry in XML format.
- [S0205] Naid: Naid creates Registry entries that store information about a created service and point to a malicious DLL dropped to disk.
- [S0140] Shamoon: Once Shamoon has access to a network share, it enables the RemoteRegistry service on the target system. It will then connect to the system with RegConnectRegistryW and modify the Registry to disable UAC remote restrictions by setting SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\LocalAccountTokenFilterPolicy to 1.
- [S0663] SysUpdate: SysUpdate can write its configuration file to Software\Classes\scConfig in either HKEY_LOCAL_MACHINE or HKEY_CURRENT_USER.
- [G1014] LuminousMoth: LuminousMoth has used malware that adds Registry keys for persistence.
- [S0385] njRAT: njRAT can create, delete, or modify a specified Registry key or value.
- [S1047] Mori: Mori can write data to `HKLM\Software\NFC\IPA` and `HKLM\Software\NFC\` and delete Registry values.
- [S0342] GreyEnergy: GreyEnergy modifies conditions in the Registry and adds keys.
- [S0075] Reg: Reg may be used to interact with and modify the Windows Registry of a local or remote system at the command-line interface.
- [S0090] Rover: Rover has functionality to remove Registry Run key persistence as a cleanup procedure.
- [S0180] Volgmer: Volgmer modifies the Registry to store an encoded configuration file in HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\WMI\Security.
- [S0660] Clambling: Clambling can set and delete Registry keys.
- [S0650] QakBot: QakBot can modify the Registry to store its configuration information in a randomly named subkey under HKCU\Software\Microsoft.
- [S0239] Bankshot: Bankshot writes data into the Registry key HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Pniumj.
- [G0094] Kimsuky: Kimsuky has modified Registry settings for default file associations to enable all macros and for persistence.
- [S0126] ComRAT: ComRAT has modified Registry values to store encrypted orchestrator code and payloads.
- [S0640] Avaddon: Avaddon modifies several registry keys for persistence and UAC bypass.
- [S1025] Amadey: Amadey has overwritten registry keys for persistence.
- [S1180] BlackByte Ransomware: BlackByte Ransomware modifies the victim Registry to prevent system recovery.
- [S0266] TrickBot: TrickBot can modify registry entries.
- [G0096] APT41: APT41 used a malware variant called GOODLUCK to modify the registry in order to steal credentials.
- [S0334] DarkComet: DarkComet adds a Registry value for its installation routine to the Registry Key HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\System Enable LUA=”0” and HKEY_CURRENT_USER\Software\DC3_FEXEC.
- [G0059] Magic Hound: Magic Hound has modified Registry settings for security tools.
- [S0263] TYPEFRAME: TYPEFRAME can install encrypted configuration data under the Registry key HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\ShellCompatibility\Applications\laxhost.dll and HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\PrintConfigs.
- [S1050] PcShare: PcShare can delete its persistence mechanisms from the registry.
- [S0271] KEYMARBLE: KEYMARBLE has a command to create Registry entries for storing data under HKEY_CURRENT_USER\SOFTWARE\Microsoft\WABE\DataPath.
- [S0679] Ferocious: Ferocious has the ability to add a Class ID in the current user Registry hive to enable persistence mechanisms.
- [S1066] DarkTortilla: DarkTortilla has modified registry keys for persistence.
- [S0348] Cardinal RAT: Cardinal RAT sets HKCU\Software\Microsoft\Windows NT\CurrentVersion\Windows\Load to point to its executable.
- [S0331] Agent Tesla: Agent Tesla can achieve persistence by modifying Registry key entries.
- [S1090] NightClub: NightClub can modify the Registry to set the ServiceDLL for a service created by the malware for persistence.
- [S0269] QUADAGENT: QUADAGENT modifies an HKCU Registry key to store a session identifier unique to the compromised system as well as a pre-shared key used for encrypting and decrypting C2 communications.
- [S0198] NETWIRE: NETWIRE can modify the Registry to store its configuration information.
- [S0589] Sibot: Sibot has modified the Registry to install a second-stage script in the HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\sibot.
- [S0570] BitPaymer: BitPaymer can set values in the Registry to help in execution.
- [S1149] CHIMNEYSWEEP: CHIMNEYSWEEP can use the Windows Registry Environment key to change the `%windir%` variable to point to `c:\Windows` to enable payload execution.
- [S0662] RCSession: RCSession can write its configuration file to the Registry.
- [G1044] APT42: APT42 has modified Registry keys to maintain persistence.
- [G1031] Saint Bear: Saint Bear will leverage malicious Windows batch scripts to modify registry values associated with Windows Defender functionality.
- [S0210] Nerex: Nerex creates a Registry subkey that registers a new service.
- [S0444] ShimRat: ShimRat has registered two registry keys for shim databases.
- [G0027] Threat Group-3390: A Threat Group-3390 tool has created new Registry keys under `HKEY_CURRENT_USER\Software\Classes\` and `HKLM\SYSTEM\CurrentControlSet\services`.
- [G0061] FIN8: FIN8 has deleted Registry keys during post compromise cleanup activities.
- [S0677] AADInternals: AADInternals can modify registry keys as part of setting a new pass-through authentication agent.
- [S0019] Regin: Regin appears to have functionality to modify remote Registry information.
- [S0664] Pandora: Pandora can write an encrypted token to the Registry to enable processing of remote commands.


### T1133 - External Remote Services

Description:

Adversaries may leverage external-facing remote services to initially access and/or persist within a network. Remote services such as VPNs, Citrix, and other access mechanisms allow users to connect to internal enterprise network resources from external locations. There are often remote service gateways that manage connections and credential authentication for these services. Services such as Windows Remote Management and VNC can also be used externally. Access to Valid Accounts to use the service is often a requirement, which could be obtained through credential pharming or by obtaining the credentials from users after compromising the enterprise network. Access to remote services may be used as a redundant or persistent access mechanism during an operation. Access may also be gained through an exposed service that doesn’t require authentication. In containerized environments, this may include an exposed Docker API, Kubernetes API server, kubelet, or web application such as the Kubernetes dashboard.

Detection:

Follow best practices for detecting adversary use of Valid Accounts for authenticating to remote services. Collect authentication logs and analyze for unusual access patterns, windows of activity, and access outside of normal business hours. When authentication is not required to access an exposed remote service, monitor for follow-on activities such as anomalous external use of the exposed API or application.

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
- [G0049] OilRig: OilRig uses remote services such as VPN, Citrix, or OWA to persist in an environment.
- [G0093] GALLIUM: GALLIUM has used VPN services, including SoftEther VPN, to access and maintain persistence in victim environments.
- [G0004] Ke3chang: Ke3chang has gained access through VPNs including with compromised accounts and stolen VPN certificates.
- [C0028] 2015 Ukraine Electric Power Attack: During the 2015 Ukraine Electric Power Attack, Sandworm Team installed a modified Dropbear SSH client as the backdoor to target systems.
- [G0102] Wizard Spider: Wizard Spider has accessed victim networks by using stolen credentials to access the corporate VPN infrastructure.
- [G0016] APT29: APT29 has used compromised identities to access networks via VPNs and Citrix.
- [C0004] CostaRicto: During CostaRicto, the threat actors set up remote tunneling using an SSH tool to maintain access to a compromised environment.
- [G0094] Kimsuky: Kimsuky has used RDP to establish persistence.
- [G0053] FIN5: FIN5 has used legitimate VPN, Citrix, or VNC credentials to maintain access to a victim environment.
- [C0024] SolarWinds Compromise: For the SolarWinds Compromise, APT29 used compromised identities to access networks via SSH, VPNs, and other remote access tools.
- [G0027] Threat Group-3390: Threat Group-3390 actors look for and use VPN profiles during an operation to access the network using external VPN services. Threat Group-3390 has also obtained OWA account credentials during intrusions that it subsequently used to attempt to regain access when evicted from a victim network.
- [G1041] Sea Turtle: Sea Turtle has used external-facing SSH to achieve initial access to the IT environments of victim organizations.
- [S0599] Kinsing: Kinsing was executed in an Ubuntu container deployed via an open Docker daemon API.
- [C0027] C0027: During C0027, Scattered Spider used Citrix and VPNs to persist in compromised environments.
- [G0115] GOLD SOUTHFIELD: GOLD SOUTHFIELD has used publicly-accessible RDP and remote management and monitoring (RMM) servers to gain access to victim machines.
- [G0114] Chimera: Chimera has used legitimate credentials to login to an external VPN, Citrix, SSH, and other remote services.
- [C0032] C0032: During the C0032 campaign, TEMP.Veles used VPN access to persist in the victim environment.
- [G0035] Dragonfly: Dragonfly has used VPNs and Outlook Web Access (OWA) to maintain access to victim networks.
- [G1024] Akira: Akira uses compromised VPN accounts for initial access to victim networks.
- [G0007] APT28: APT28 has used Tor and a variety of commercial VPN services to route brute force authentication attempts.
- [G1040] Play: Play has used Remote Desktop Protocol (RDP) and Virtual Private Networks (VPN) for initial access.
- [C0014] Operation Wocao: During Operation Wocao, threat actors used stolen credentials to connect to the victim's network via VPN.
- [C0046] ArcaneDoor: ArcaneDoor used WebVPN sessions commonly associated with Clientless SSLVPN services to communicate to compromised devices.
- [S0600] Doki: Doki was executed through an open Docker daemon API port.
- [G0065] Leviathan: Leviathan has used external remote services such as virtual private networks (VPN) to gain initial access.


### T1136.001 - Create Account: Local Account

Description:

Adversaries may create a local account to maintain access to victim systems. Local accounts are those configured by an organization for use by users, remote support, services, or for administration on a single system or service. For example, with a sufficient level of access, the Windows net user /add command can be used to create a local account. In Linux, the `useradd` command can be used, while on macOS systems, the dscl -create command can be used. Local accounts may also be added to network devices, often via common Network Device CLI commands such as username, to ESXi servers via `esxcli system account add`, or to Kubernetes clusters using the `kubectl` utility. Such accounts may be used to establish secondary credentialed access that do not require persistent remote access tools to be deployed on the system.

Detection:

Monitor for processes and command-line parameters associated with local account creation, such as net user /add , useradd , and dscl -create . Collect data on account creation within a network. Event ID 4720 is generated when a user account is created on a Windows system. Perform regular audits of local system accounts to detect suspicious accounts that may have been created by an adversary. For network infrastructure devices, collect AAA logging to monitor for account creations.

Procedures:

- [G0102] Wizard Spider: Wizard Spider has created local administrator accounts to maintain persistence in compromised networks.
- [G1023] APT5: APT5 has created Local Administrator accounts to maintain access to systems with short-cycle credential rotation.
- [S0394] HiddenWasp: HiddenWasp creates a user account as a means to provide initial persistence to the compromised machine.
- [S0493] GoldenSpy: GoldenSpy can create new users on an infected system.
- [S0363] Empire: Empire has a module for creating a local user if permissions allow.
- [G0035] Dragonfly: Dragonfly has created accounts on victims, including administrator accounts, some of which appeared to be tailored to each individual staging target.
- [G0139] TeamTNT: TeamTNT has created local privileged users on victim machines.
- [G0117] Fox Kitten: Fox Kitten has created a local user account with administrator privileges.
- [S0649] SMOKEDHAM: SMOKEDHAM has created user accounts.
- [G0096] APT41: APT41 has created user accounts.
- [G1016] FIN13: FIN13 has created MS-SQL local accounts in a compromised network.
- [S0143] Flame: Flame can create backdoor accounts with login “HelpAssistant” on domain connected systems if appropriate rights are available.
- [S0382] ServHelper: ServHelper has created a new user named "supportaccount".
- [G0094] Kimsuky: Kimsuky has created accounts with net user.
- [S0192] Pupy: Pupy can user PowerView to execute “net user” commands and create local system accounts.
- [S0085] S-Type: S-Type may create a temporary user on the system named `Lost_{Unique Identifier}` with the password `pond~!@6”{Unique Identifier}`.
- [S0039] Net: The net user username \password commands in Net can be used to create a local account.
- [S1111] DarkGate: DarkGate creates a local user account, SafeMode, via net user commands.
- [S0084] Mis-Type: Mis-Type may create a temporary user on the system named `Lost_{Unique Identifier}`.
- [G0059] Magic Hound: Magic Hound has created local accounts named `help` and `DefaultAccount` on compromised machines.
- [S0030] Carbanak: Carbanak can create a Windows account.
- [G0119] Indrik Spider: Indrik Spider has created local system accounts and has added the accounts to privileged groups.
- [G0077] Leafminer: Leafminer used a tool called Imecab to set up a persistent remote access account on the victim machine.
- [G0087] APT39: APT39 has created accounts on multiple compromised hosts to perform actions within the network.
- [S0601] Hildegard: Hildegard has created a user named “monerodaemon”.
- [S0412] ZxShell: ZxShell has a feature to create local user accounts.
- [G1034] Daggerfly: Daggerfly created a local account on victim machines to maintain access.
- [G0022] APT3: APT3 has been known to create or enable accounts, such as support_388945a0.
- [S0274] Calisto: Calisto has the capability to add its own account to the victim's machine.

### T1136.002 - Create Account: Domain Account

Description:

Adversaries may create a domain account to maintain access to victim systems. Domain accounts are those managed by Active Directory Domain Services where access and permissions are configured across systems and services that are part of that domain. Domain accounts can cover user, administrator, and service accounts. With a sufficient level of access, the net user /add /domain command can be used to create a domain account. Such accounts may be used to establish secondary credentialed access that do not require persistent remote access tools to be deployed on the system.

Detection:

Monitor for processes and command-line parameters associated with domain account creation, such as net user /add /domain. Collect data on account creation within a network. Event ID 4720 is generated when a user account is created on a Windows domain controller. Perform regular audits of domain accounts to detect suspicious accounts that may have been created by an adversary.

Procedures:

- [S0192] Pupy: Pupy can user PowerView to execute “net user” commands and create domain accounts.
- [G0093] GALLIUM: GALLIUM created high-privileged domain user accounts to maintain access to victim networks.
- [G1043] BlackByte: BlackByte created privileged domain accounts during intrusions.
- [C0028] 2015 Ukraine Electric Power Attack: During the 2015 Ukraine Electric Power Attack, Sandworm Team created privileged domain accounts to be used for further exploitation and lateral movement.
- [G0102] Wizard Spider: Wizard Spider has created and used new accounts within a victim's Active Directory environment to maintain persistence.
- [S0029] PsExec: PsExec has the ability to remotely create accounts on target systems.
- [S0039] Net: The net user username \password \domain commands in Net can be used to create a domain account.
- [C0025] 2016 Ukraine Electric Power Attack: During the 2016 Ukraine Electric Power Attack, Sandworm Team created two new accounts, “admin” and “система” (System). The accounts were then assigned to a domain matching local operation and were delegated new privileges.
- [G0125] HAFNIUM: HAFNIUM has created domain accounts.
- [S0363] Empire: Empire has a module for creating a new domain user if permissions allow.

### T1136.003 - Create Account: Cloud Account

Description:

Adversaries may create a cloud account to maintain access to victim systems. With a sufficient level of access, such accounts may be used to establish secondary credentialed access that does not require persistent remote access tools to be deployed on the system. In addition to user accounts, cloud accounts may be associated with services. Cloud providers handle the concept of service accounts in different ways. In Azure, service accounts include service principals and managed identities, which can be linked to various resources such as OAuth applications, serverless functions, and virtual machines in order to grant those resources permissions to perform various activities in the environment. In GCP, service accounts can also be linked to specific resources, as well as be impersonated by other accounts for Temporary Elevated Cloud Access. While AWS has no specific concept of service accounts, resources can be directly granted permission to assume roles. Adversaries may create accounts that only have access to specific cloud services, which can reduce the chance of detection. Once an adversary has created a cloud account, they can then manipulate that account to ensure persistence and allow access to additional resources - for example, by adding Additional Cloud Credentials or assigning Additional Cloud Roles.

Detection:

Collect usage logs from cloud user and administrator accounts to identify unusual activity in the creation of new accounts and assignment of roles to those accounts. Monitor for accounts assigned to admin roles that go over a certain threshold of known admins.

Procedures:

- [G0016] APT29: APT29 can create new users through Azure AD.
- [G1004] LAPSUS$: LAPSUS$ has created global admin accounts in the targeted organization's cloud instances to gain persistence.
- [S0677] AADInternals: AADInternals can create new Azure AD users.


### T1137.001 - Office Application Startup: Office Template Macros

Description:

Adversaries may abuse Microsoft Office templates to obtain persistence on a compromised system. Microsoft Office contains templates that are part of common Office applications and are used to customize styles. The base templates within the application are used each time an application starts. Office Visual Basic for Applications (VBA) macros can be inserted into the base template and used to execute code when the respective Office application starts in order to obtain persistence. Examples for both Word and Excel have been discovered and published. By default, Word has a Normal.dotm template created that can be modified to include a malicious macro. Excel does not have a template file created by default, but one can be added that will automatically be loaded. Shared templates may also be stored and pulled from remote locations. Word Normal.dotm location: C:\Users\&lt;username&gt;\AppData\Roaming\Microsoft\Templates\Normal.dotm Excel Personal.xlsb location: C:\Users\&lt;username&gt;\AppData\Roaming\Microsoft\Excel\XLSTART\PERSONAL.XLSB Adversaries may also change the location of the base template to point to their own by hijacking the application's search order, e.g. Word 2016 will first look for Normal.dotm under C:\Program Files (x86)\Microsoft Office\root\Office16\, or by modifying the GlobalDotName registry key. By modifying the GlobalDotName registry key an adversary can specify an arbitrary location, file name, and file extension to use for the template that will be loaded on application startup. To abuse GlobalDotName, adversaries may first need to register the template as a trusted document or place it in a trusted location. An adversary may need to enable macros to execute unrestricted depending on the system or enterprise security policy on use of macros.

Detection:

Many Office-related persistence mechanisms require changes to the Registry and for binaries, files, or scripts to be written to disk or existing files modified to include malicious scripts. Collect events related to Registry key creation and modification for keys that could be used for Office-based persistence. Modification to base templates, like Normal.dotm, should also be investigated since the base templates should likely not contain VBA macros. Changes to the Office macro security settings should also be investigated.

Procedures:

- [G0069] MuddyWater: MuddyWater has used a Word Template, Normal.dotm, for persistence.
- [S0475] BackConfig: BackConfig has the ability to use hidden columns in Excel spreadsheets to store executable files or commands for VBA macros.
- [S0154] Cobalt Strike: Cobalt Strike has the ability to use an Excel Workbook to execute additional code by enabling Office to trust macros and execute code without user permission.

### T1137.002 - Office Application Startup: Office Test

Description:

Adversaries may abuse the Microsoft Office "Office Test" Registry key to obtain persistence on a compromised system. An Office Test Registry location exists that allows a user to specify an arbitrary DLL that will be executed every time an Office application is started. This Registry key is thought to be used by Microsoft to load DLLs for testing and debugging purposes while developing Office applications. This Registry key is not created by default during an Office installation. There exist user and global Registry keys for the Office Test feature, such as: * HKEY_CURRENT_USER\Software\Microsoft\Office test\Special\Perf * HKEY_LOCAL_MACHINE\Software\Microsoft\Office test\Special\Perf Adversaries may add this Registry key and specify a malicious DLL that will be executed whenever an Office application, such as Word or Excel, is started.

Detection:

Monitor for the creation of the Office Test Registry key. Many Office-related persistence mechanisms require changes to the Registry and for binaries, files, or scripts to be written to disk or existing files modified to include malicious scripts. Collect events related to Registry key creation and modification for keys that could be used for Office-based persistence. Since v13.52, Autoruns can detect tasks set up using the Office Test Registry key. Consider monitoring Office processes for anomalous DLL loads.

Procedures:

- [G0007] APT28: APT28 has used the Office Test persistence mechanism within Microsoft Office by adding the Registry key HKCU\Software\Microsoft\Office test\Special\Perf to execute code.

### T1137.003 - Office Application Startup: Outlook Forms

Description:

Adversaries may abuse Microsoft Outlook forms to obtain persistence on a compromised system. Outlook forms are used as templates for presentation and functionality in Outlook messages. Custom Outlook forms can be created that will execute code when a specifically crafted email is sent by an adversary utilizing the same custom Outlook form. Once malicious forms have been added to the user’s mailbox, they will be loaded when Outlook is started. Malicious forms will execute when an adversary sends a specifically crafted email to the user.

Detection:

Microsoft has released a PowerShell script to safely gather mail forwarding rules and custom forms in your mail environment as well as steps to interpret the output. SensePost, whose tool Ruler can be used to carry out malicious rules, forms, and Home Page attacks, has released a tool to detect Ruler usage. Collect process execution information including process IDs (PID) and parent process IDs (PPID) and look for abnormal chains of activity resulting from Office processes. Non-standard process execution trees may also indicate suspicious or malicious behavior.

Procedures:

- [S0358] Ruler: Ruler can be used to automate the abuse of Outlook Forms to establish persistence.

### T1137.004 - Office Application Startup: Outlook Home Page

Description:

Adversaries may abuse Microsoft Outlook's Home Page feature to obtain persistence on a compromised system. Outlook Home Page is a legacy feature used to customize the presentation of Outlook folders. This feature allows for an internal or external URL to be loaded and presented whenever a folder is opened. A malicious HTML page can be crafted that will execute code when loaded by Outlook Home Page. Once malicious home pages have been added to the user’s mailbox, they will be loaded when Outlook is started. Malicious Home Pages will execute when the right Outlook folder is loaded/reloaded.

Detection:

Microsoft has released a PowerShell script to safely gather mail forwarding rules and custom forms in your mail environment as well as steps to interpret the output. SensePost, whose tool Ruler can be used to carry out malicious rules, forms, and Home Page attacks, has released a tool to detect Ruler usage. Collect process execution information including process IDs (PID) and parent process IDs (PPID) and look for abnormal chains of activity resulting from Office processes. Non-standard process execution trees may also indicate suspicious or malicious behavior.

Procedures:

- [G0049] OilRig: OilRig has abused the Outlook Home Page feature for persistence. OilRig has also used CVE-2017-11774 to roll back the initial patch designed to protect against Home Page abuse.
- [S0358] Ruler: Ruler can be used to automate the abuse of Outlook Home Pages to establish persistence.

### T1137.005 - Office Application Startup: Outlook Rules

Description:

Adversaries may abuse Microsoft Outlook rules to obtain persistence on a compromised system. Outlook rules allow a user to define automated behavior to manage email messages. A benign rule might, for example, automatically move an email to a particular folder in Outlook if it contains specific words from a specific sender. Malicious Outlook rules can be created that can trigger code execution when an adversary sends a specifically crafted email to that user. Once malicious rules have been added to the user’s mailbox, they will be loaded when Outlook is started. Malicious rules will execute when an adversary sends a specifically crafted email to the user.

Detection:

Microsoft has released a PowerShell script to safely gather mail forwarding rules and custom forms in your mail environment as well as steps to interpret the output. This PowerShell script is ineffective in gathering rules with modified `PRPR_RULE_MSG_NAME` and `PR_RULE_MSG_PROVIDER` properties caused by adversaries using a Microsoft Exchange Server Messaging API Editor (MAPI Editor), so only examination with the Exchange Administration tool MFCMapi can reveal these mail forwarding rules. SensePost, whose tool Ruler can be used to carry out malicious rules, forms, and Home Page attacks, has released a tool to detect Ruler usage. Collect process execution information including process IDs (PID) and parent process IDs (PPID) and look for abnormal chains of activity resulting from Office processes. Non-standard process execution trees may also indicate suspicious or malicious behavior.

Procedures:

- [S0358] Ruler: Ruler can be used to automate the abuse of Outlook Rules to establish persistence.

### T1137.006 - Office Application Startup: Add-ins

Description:

Adversaries may abuse Microsoft Office add-ins to obtain persistence on a compromised system. Office add-ins can be used to add functionality to Office programs. There are different types of add-ins that can be used by the various Office products; including Word/Excel add-in Libraries (WLL/XLL), VBA add-ins, Office Component Object Model (COM) add-ins, automation add-ins, VBA Editor (VBE), Visual Studio Tools for Office (VSTO) add-ins, and Outlook add-ins. Add-ins can be used to obtain persistence because they can be set to execute code when an Office application starts.

Detection:

Monitor and validate the Office trusted locations on the file system and audit the Registry entries relevant for enabling add-ins. Collect process execution information including process IDs (PID) and parent process IDs (PPID) and look for abnormal chains of activity resulting from Office processes. Non-standard process execution trees may also indicate suspicious or malicious behavior

Procedures:

- [S0268] Bisonal: Bisonal has been loaded through a `.wll` extension added to the ` %APPDATA%\microsoft\word\startup\` repository.
- [G0019] Naikon: Naikon has used the RoyalRoad exploit builder to drop a second stage loader, intel.wll, into the Word Startup folder on the compromised host.
- [S1143] LunarLoader: LunarLoader has the ability to use Microsoft Outlook add-ins to establish persistence.
- [S1142] LunarMail: LunarMail has the ability to use Outlook add-ins for persistence.


### T1176.001 - Software Extensions: Browser Extensions

Description:

Adversaries may abuse internet browser extensions to establish persistent access to victim systems. Browser extensions or plugins are small programs that can add functionality to and customize aspects of internet browsers. They can be installed directly via a local file or custom URL or through a browser's app store - an official online platform where users can browse, install, and manage extensions for a specific web browser. Extensions generally inherit the web browser's permissions previously granted. Malicious extensions can be installed into a browser through malicious app store downloads masquerading as legitimate extensions, through social engineering, or by an adversary that has already compromised a system. Security can be limited on browser app stores, so it may not be difficult for malicious extensions to defeat automated scanners. Depending on the browser, adversaries may also manipulate an extension's update url to install updates from an adversary-controlled server or manipulate the mobile configuration file to silently install additional extensions. Previous to macOS 11, adversaries could silently install browser extensions via the command line using the profiles tool to install malicious .mobileconfig files. In macOS 11+, the use of the profiles tool can no longer install configuration profiles; however, .mobileconfig files can be planted and installed with user interaction. Once the extension is installed, it can browse to websites in the background, steal all information that a user enters into a browser (including credentials), and be used as an installer for a RAT for persistence. There have also been instances of botnets using a persistent backdoor through malicious Chrome extensions for Command and Control. Adversaries may also use browser extensions to modify browser permissions and components, privacy settings, and other security controls for Defense Evasion.

Procedures:

- [S1122] Mispadu: Mispadu utilizes malicious Google Chrome browser extensions to steal financial data.
- [G0094] Kimsuky: Kimsuky has used Google Chrome browser extensions to infect victims and to steal passwords and cookies.
- [S0402] OSX/Shlayer: OSX/Shlayer can install malicious Safari browser extensions to serve ads.
- [S1213] Lumma Stealer: Lumma Stealer has installed a malicious browser extension to target Google Chrome, Microsoft Edge, Opera and Brave browsers for the purpose of stealing data.
- [S1201] TRANSLATEXT: TRANSLATEXT has the ability to capture credentials, cookies, browser screenshots, etc. and to exfiltrate data.
- [S0531] Grandoreiro: Grandoreiro can use malicious browser extensions to steal cookies and other user information.
- [S0482] Bundlore: Bundlore can install malicious browser extensions that are used to hijack user searches.

### T1176.002 - Software Extensions: IDE Extensions

Description:

Adversaries may abuse an integrated development environment (IDE) extension to establish persistent access to victim systems. IDEs such as Visual Studio Code, IntelliJ IDEA, and Eclipse support extensions - software components that add features like code linting, auto-completion, task automation, or integration with tools like Git and Docker. A malicious extension can be installed through an extension marketplace (i.e., Compromise Software Dependencies and Development Tools) or side-loaded directly into the IDE. In addition to installing malicious extensions, adversaries may also leverage benign ones. For example, adversaries may establish persistent SSH tunnels via the use of the VSCode Remote SSH extension (i.e., IDE Tunneling). Trust is typically established through the installation process; once installed, the malicious extension is run every time that the IDE is launched. The extension can then be used to execute arbitrary code, establish a backdoor, mine cryptocurrency, or exfiltrate data.


### T1197 - BITS Jobs

Description:

Adversaries may abuse BITS jobs to persistently execute code and perform various background tasks. Windows Background Intelligent Transfer Service (BITS) is a low-bandwidth, asynchronous file transfer mechanism exposed through Component Object Model (COM). BITS is commonly used by updaters, messengers, and other applications preferred to operate in the background (using available idle bandwidth) without interrupting other networked applications. File transfer tasks are implemented as BITS jobs, which contain a queue of one or more file operations. The interface to create and manage BITS jobs is accessible through PowerShell and the BITSAdmin tool. Adversaries may abuse BITS to download (e.g. Ingress Tool Transfer), execute, and even clean up after running malicious code (e.g. Indicator Removal). BITS tasks are self-contained in the BITS job database, without new files or registry modifications, and often permitted by host firewalls. BITS enabled execution may also enable persistence by creating long-standing jobs (the default maximum lifetime is 90 days and extendable) or invoking an arbitrary program when a job completes or errors (including after system reboots). BITS upload functionalities can also be used to perform Exfiltration Over Alternative Protocol.

Detection:

BITS runs as a service and its status can be checked with the Sc query utility (sc query bits). Active BITS tasks can be enumerated using the BITSAdmin tool (bitsadmin /list /allusers /verbose). Monitor usage of the BITSAdmin tool (especially the ‘Transfer’, 'Create', 'AddFile', 'SetNotifyFlags', 'SetNotifyCmdLine', 'SetMinRetryDelay', 'SetCustomHeaders', and 'Resume' command options) Admin logs, PowerShell logs, and the Windows Event log for BITS activity. Also consider investigating more detailed information about jobs by parsing the BITS job database. Monitor and analyze network activity generated by BITS. BITS jobs use HTTP(S) and SMB for remote connections and are tethered to the creating user and will only function when that user is logged on (this rule applies even if a user attaches the job to a service account).

Procedures:

- [S0652] MarkiRAT: MarkiRAT can use BITS Utility to connect with the C2 server.
- [G0040] Patchwork: Patchwork has used BITS jobs to download malicious payloads.
- [S0534] Bazar: Bazar has been downloaded via Windows BITS functionality.
- [S0154] Cobalt Strike: Cobalt Strike can download a hosted "beacon" payload using BITSAdmin.
- [S0554] Egregor: Egregor has used BITSadmin to download and execute malicious DLLs.
- [S0201] JPIN: A JPIN variant downloads the backdoor payload via the BITS service.
- [S0333] UBoatRAT: UBoatRAT takes advantage of the /SetNotifyCmdLine option in BITSAdmin to ensure it stays running on a system to maintain persistence.
- [S0654] ProLock: ProLock can use BITS jobs to download its malicious payload.
- [G0065] Leviathan: Leviathan has used BITSAdmin to download additional tools.
- [G0087] APT39: APT39 has used the BITS protocol to exfiltrate stolen data from a compromised host.
- [S0190] BITSAdmin: BITSAdmin can be used to create BITS Jobs to launch a malicious process.
- [G0096] APT41: APT41 used BITSAdmin to download and install payloads.
- [G0102] Wizard Spider: Wizard Spider has used batch scripts that utilizes WMIC to execute a BITSAdmin transfer of a ransomware payload to each compromised machine.


### T1205.001 - Traffic Signaling: Port Knocking

Description:

Adversaries may use port knocking to hide open ports used for persistence or command and control. To enable a port, an adversary sends a series of attempted connections to a predefined sequence of closed ports. After the sequence is completed, opening a port is often accomplished by the host based firewall, but could also be implemented by custom software. This technique has been observed both for the dynamic opening of a listening port as well as the initiating of a connection to a listening server on a different system. The observation of the signal packets to trigger the communication can be conducted through different methods. One means, originally implemented by Cd00r , is to use the libpcap libraries to sniff for the packets in question. Another method leverages raw sockets, which enables the malware to use ports that are already open for use by other programs.

Detection:

Record network packets sent to and from the system, looking for extraneous packets that do not belong to established flows.

Procedures:

- [S1060] Mafalda: Mafalda can use port-knocking to authenticate itself to another implant called Cryshell to establish an indirect connection to the C2 server.
- [G0056] PROMETHIUM: PROMETHIUM has used a script that configures the knockd service and firewall to only accept C2 connections from systems that use a specified sequence of knock ports.
- [S1204] cd00r: cd00r can monitor for a single TCP-SYN packet to be sent in series to a configurable set of ports (200, 80, 22, 53 and 3 in the original code) before opening a port for communication.
- [S1059] metaMain: metaMain has authenticated itself to a different implant, Cryshell, through a port knocking and handshake procedure.

### T1205.002 - Traffic Signaling: Socket Filters

Description:

Adversaries may attach filters to a network socket to monitor then activate backdoors used for persistence or command and control. With elevated permissions, adversaries can use features such as the `libpcap` library to open sockets and install filters to allow or disallow certain types of data to come through the socket. The filter may apply to all traffic passing through the specified network interface (or every interface if not specified). When the network interface receives a packet matching the filter criteria, additional actions can be triggered on the host, such as activation of a reverse shell. To establish a connection, an adversary sends a crafted packet to the targeted host that matches the installed filter criteria. Adversaries have used these socket filters to trigger the installation of implants, conduct ping backs, and to invoke command shells. Communication with these socket filters may also be used in conjunction with Protocol Tunneling. Filters can be installed on any Unix-like platform with `libpcap` installed or on Windows hosts using `Winpcap`. Adversaries may use either `libpcap` with `pcap_setfilter` or the standard library function `setsockopt` with `SO_ATTACH_FILTER` options. Since the socket connection is not active until the packet is received, this behavior may be difficult to detect due to the lack of activity on a host, low CPU overhead, and limited visibility into raw socket usage.

Detection:

Identify running processes with raw sockets. Ensure processes listed have a need for an open raw socket and are in accordance with enterprise policy.

Procedures:

- [S1161] BPFDoor: BPFDoor uses BPF bytecode to attach a filter to a network socket to view ICMP, UDP, or TCP packets coming through ports 22 (ssh), 80 (http), and 443 (https). When BPFDoor finds a packet containing its “magic” bytes, it parses out two fields and forks itself. The parent process continues to monitor filtered traffic while the child process executes the instructions from the parsed fields.
- [S1123] PITSTOP: PITSTOP can listen and evaluate incoming commands on the domain socket, created by PITHOOK malware, located at `/data/runtime/cockpit/wd.fd` for a predefined magic byte sequence. PITSTOP can then duplicate the socket for further communication over TLS.
- [S0587] Penquin: Penquin installs a `TCP` and `UDP` filter on the `eth0` interface.


### T1505.001 - Server Software Component: SQL Stored Procedures

Description:

Adversaries may abuse SQL stored procedures to establish persistent access to systems. SQL Stored Procedures are code that can be saved and reused so that database users do not waste time rewriting frequently used SQL queries. Stored procedures can be invoked via SQL statements to the database using the procedure name or via defined events (e.g. when a SQL server application is started/restarted). Adversaries may craft malicious stored procedures that can provide a persistence mechanism in SQL database servers. To execute operating system commands through SQL syntax the adversary may have to enable additional functionality, such as xp_cmdshell for MSSQL Server. Microsoft SQL Server can enable common language runtime (CLR) integration. With CLR integration enabled, application developers can write stored procedures using any .NET framework language (e.g. VB .NET, C#, etc.). Adversaries may craft or modify CLR assemblies that are linked to stored procedures since these CLR assemblies can be made to execute arbitrary commands.

Detection:

On a MSSQL Server, consider monitoring for xp_cmdshell usage. Consider enabling audit features that can log malicious startup activities.

Procedures:

- [C0025] 2016 Ukraine Electric Power Attack: During the 2016 Ukraine Electric Power Attack, Sandworm Team used various MS-SQL stored procedures.
- [S0603] Stuxnet: Stuxnet used xp_cmdshell to store and execute SQL code.

### T1505.002 - Server Software Component: Transport Agent

Description:

Adversaries may abuse Microsoft transport agents to establish persistent access to systems. Microsoft Exchange transport agents can operate on email messages passing through the transport pipeline to perform various tasks such as filtering spam, filtering malicious attachments, journaling, or adding a corporate signature to the end of all outgoing emails. Transport agents can be written by application developers and then compiled to .NET assemblies that are subsequently registered with the Exchange server. Transport agents will be invoked during a specified stage of email processing and carry out developer defined tasks. Adversaries may register a malicious transport agent to provide a persistence mechanism in Exchange Server that can be triggered by adversary-specified email events. Though a malicious transport agent may be invoked for all emails passing through the Exchange transport pipeline, the agent can be configured to only carry out specific tasks in response to adversary defined criteria. For example, the transport agent may only carry out an action like copying in-transit attachments and saving them for later exfiltration if the recipient email address matches an entry on a list provided by the adversary.

Detection:

Consider monitoring application logs for abnormal behavior that may indicate suspicious installation of application software components. Consider monitoring file locations associated with the installation of new application software components such as paths from which applications typically load such extensible components.

Procedures:

- [S0395] LightNeuron: LightNeuron has used a malicious Microsoft Exchange transport agent for persistence.

### T1505.003 - Server Software Component: Web Shell

Description:

Adversaries may backdoor web servers with web shells to establish persistent access to systems. A Web shell is a Web script that is placed on an openly accessible Web server to allow an adversary to access the Web server as a gateway into a network. A Web shell may provide a set of functions to execute or a command-line interface on the system that hosts the Web server. In addition to a server-side script, a Web shell may have a client interface program that is used to talk to the Web server (e.g. China Chopper Web shell client).

Detection:

Web shells can be difficult to detect. Unlike other forms of persistent remote access, they do not initiate connections. The portion of the Web shell that is on the server may be small and innocuous looking. The PHP version of the China Chopper Web shell, for example, is the following short payload: &lt;?php @eval($_POST['password']);&gt; Nevertheless, detection mechanisms exist. Process monitoring may be used to detect Web servers that perform suspicious actions such as spawning cmd.exe or accessing files that are not in the Web directory. File monitoring may be used to detect changes to files in the Web directory of a Web server that do not match with updates to the Web server's content and may indicate implantation of a Web shell script. Log authentication attempts to the server and any unusual traffic patterns to or from the server and internal network.

Procedures:

- [G1012] CURIUM: CURIUM has been linked to web shells following likely server compromise as an initial access vector into victim networks.
- [S0598] P.A.S. Webshell: P.A.S. Webshell can gain remote access and execution on target web servers.
- [S0072] OwaAuth: OwaAuth is a Web shell that appears to be exclusively used by Threat Group-3390. It is installed as an ISAPI filter on Exchange servers and shares characteristics with the China Chopper Web shell.
- [G0035] Dragonfly: Dragonfly has commonly created Web shells on victims' publicly accessible email and web servers, which they used to maintain access to a victim network and download additional malicious files.
- [G0007] APT28: APT28 has used a modified and obfuscated version of the reGeorg web shell to maintain persistence on a target's Outlook Web Access (OWA) server.
- [S1115] WIREFIRE: WIREFIRE is a web shell that can download files to and execute arbitrary commands from compromised Ivanti Connect Secure VPNs.
- [G0049] OilRig: OilRig has used web shells, often to maintain access to a victim network.
- [G1016] FIN13: FIN13 has utilized obfuscated and open-source web shells such as JspSpy, reGeorg, MiniWebCmdShell, and Vonloesch Jsp File Browser 1.2 to enable remote code execution and to execute commands on compromised web server.
- [G0135] BackdoorDiplomacy: BackdoorDiplomacy has used web shells to establish an initial foothold and for lateral movement within a victim's system.
- [S1118] BUSHWALK: BUSHWALK is a web shell that has the ability to execute arbitrary commands or write files.
- [G1030] Agrius: Agrius typically deploys a variant of the ASPXSpy web shell following initial access via exploitation.
- [S1110] SLIGHTPULSE: SLIGHTPULSE is a web shell that can read, write, and execute files on compromised servers.
- [S1119] LIGHTWIRE: LIGHTWIRE is a web shell capable of command execution and establishing persistence on compromised Ivanti Secure Connect VPNs.
- [G0009] Deep Panda: Deep Panda uses Web shells on publicly accessible Web servers to access victim networks.
- [C0017] C0017: During C0017, APT41 deployed JScript web shells through the creation of malicious ViewState objects.
- [C0034] 2022 Ukraine Electric Power Attack: During the 2022 Ukraine Electric Power Attack, Sandworm Team deployed the Neo-REGEORG webshell on an internet-facing server.
- [C0041] FrostyGoop Incident: FrostyGoop Incident deployed a ReGeorg variant web shell to impacted systems following initial access for persistence.
- [C0032] C0032: During the C0032 campaign, TEMP.Veles planted Web shells on Outlook Exchange servers.
- [G0087] APT39: APT39 has installed ANTAK and ASPXSPY web shells.
- [G0123] Volatile Cedar: Volatile Cedar can inject web shell code into a server.
- [G0093] GALLIUM: GALLIUM used Web shells to persist in victim environments and assist in execution and exfiltration.
- [C0029] Cutting Edge: During Cutting Edge, threat actors used multiple web shells to maintain presence on compromised Connect Secure appliances such as WIREFIRE, GLASSTOKEN, BUSHWALK, LIGHTWIRE, and FRAMESTING.
- [S1112] STEADYPULSE: STEADYPULSE is a web shell that can enable the execution of arbitrary commands on compromised web servers.
- [G0027] Threat Group-3390: Threat Group-3390 has used a variety of Web shells.
- [C0040] APT41 DUST: APT41 DUST involved use of web shells such as ANTSWORD and BLUEBEAM for persistence.
- [S0073] ASPXSpy: ASPXSpy is a Web shell. The ASPXTool version used by Threat Group-3390 has been deployed to accessible servers running Internet Information Services (IIS).
- [G0081] Tropic Trooper: Tropic Trooper has started a web service in the target host and wait for the adversary to connect, acting as a web shell.
- [G1003] Ember Bear: Ember Bear deploys web shells following initial access for either follow-on command execution or protocol tunneling. Example web shells used by Ember Bear include P0wnyshell, reGeorg, P.A.S. Webshell, and custom variants of publicly-available web shell examples.
- [G0125] HAFNIUM: HAFNIUM has deployed multiple web shells on compromised servers including SIMPLESEESHARP, SPORTSBALL, China Chopper, and ASPXSpy.
- [S1108] PULSECHECK: PULSECHECK is a web shell that can enable command execution on compromised servers.
- [S1189] Neo-reGeorg: Neo-reGeorg can be installed on compromised web servers to tunnel C2 connections.
- [G1009] Moses Staff: Moses Staff has dropped a web shell onto a compromised system.
- [G0034] Sandworm Team: Sandworm Team has used webshells including P.A.S. Webshell to maintain access to victim networks.
- [S1120] FRAMESTING: FRAMESTING is a web shell capable of enabling arbitrary command execution on compromised Ivanti Connect Secure VPNs.
- [S1113] RAPIDPULSE: RAPIDPULSE is a web shell that is capable of arbitrary file read on targeted web servers to exfiltrate items of interest on the victim device.
- [G0117] Fox Kitten: Fox Kitten has installed web shells on compromised hosts to maintain access.
- [G0131] Tonto Team: Tonto Team has used a first stage web shell after compromising a vulnerable Exchange server.
- [G1017] Volt Typhoon: Volt Typhoon has used webshells, including ones named AuditReport.jspx and iisstart.aspx, in compromised environments.
- [C0038] HomeLand Justice: For HomeLand Justice, threat actors used .aspx webshells named pickers.aspx, error4.aspx, and ClientBin.aspx, to maintain persistence.
- [S1188] Line Runner: Line Runner is a persistent Lua-based web shell.
- [G0082] APT38: APT38 has used web shells for persistence or to ensure redundant access.
- [C0049] Leviathan Australian Intrusions: Leviathan relied extensively on web shell use following initial access for persistence and command execution purposes in victim environments during Leviathan Australian Intrusions.
- [G0016] APT29: APT29 has installed web shells on exploited Microsoft Exchange servers.
- [C0012] Operation CuckooBees: During Operation CuckooBees, the threat actors generated a web shell within a vulnerable Enterprise Resource Planning Web Application Server as a persistence mechanism.
- [S0578] SUPERNOVA: SUPERNOVA is a Web shell.
- [S1163] SnappyTCP: SnappyTCP is a reverse TCP shell with command and control capabilities used for persistence purposes.
- [G0059] Magic Hound: Magic Hound has used multiple web shells to gain execution.
- [G1043] BlackByte: BlackByte has used ASPX web shells following exploitation of vulnerabilities in services such as Microsoft Exchange.
- [S0185] SEASHARPEE: SEASHARPEE is a Web shell.
- [S0020] China Chopper: China Chopper's server component is a Web Shell payload.
- [S1117] GLASSTOKEN: GLASSTOKEN is a web shell capable of tunneling C2 connections and code execution on compromised Ivanti Secure Connect VPNs.
- [G1023] APT5: APT5 has installed multiple web shells on compromised servers including on Pulse Secure VPN appliances.
- [G0050] APT32: APT32 has used Web shells to maintain access to victim websites.
- [G0065] Leviathan: Leviathan relies on web shells for an initial foothold as well as persistence into the victim's systems.
- [S1187] reGeorg: reGeorg is a web shell that has been installed on exposed web servers for access to victim environments.
- [G1041] Sea Turtle: Sea Turtle deployed the SnappyTCP web shell during intrusion operations.
- [C0014] Operation Wocao: During Operation Wocao, threat actors used their own web shells, as well as those previously placed on target systems by other threat actors, for reconnaissance and lateral movement.
- [C0039] Versa Director Zero Day Exploitation: Versa Director Zero Day Exploitation resulted in the deployment of the VersaMem web shell for follow-on activity.
- [G0094] Kimsuky: Kimsuky has used modified versions of open source PHP web shells to maintain access, often adding "Dinosaur" references within the code.

### T1505.004 - Server Software Component: IIS Components

Description:

Adversaries may install malicious components that run on Internet Information Services (IIS) web servers to establish persistence. IIS provides several mechanisms to extend the functionality of the web servers. For example, Internet Server Application Programming Interface (ISAPI) extensions and filters can be installed to examine and/or modify incoming and outgoing IIS web requests. Extensions and filters are deployed as DLL files that export three functions: Get{Extension/Filter}Version, Http{Extension/Filter}Proc, and (optionally) Terminate{Extension/Filter}. IIS modules may also be installed to extend IIS web servers. Adversaries may install malicious ISAPI extensions and filters to observe and/or modify traffic, execute commands on compromised machines, or proxy command and control traffic. ISAPI extensions and filters may have access to all IIS web requests and responses. For example, an adversary may abuse these mechanisms to modify HTTP responses in order to distribute malicious commands/content to previously comprised hosts. Adversaries may also install malicious IIS modules to observe and/or modify traffic. IIS 7.0 introduced modules that provide the same unrestricted access to HTTP requests and responses as ISAPI extensions and filters. IIS modules can be written as a DLL that exports RegisterModule, or as a .NET application that interfaces with ASP.NET APIs to access IIS HTTP requests.

Detection:

Monitor for creation and/or modification of files (especially DLLs on webservers) that could be abused as malicious ISAPI extensions/filters or IIS modules. Changes to %windir%\system32\inetsrv\config\applicationhost.config could indicate an IIS module installation. Monitor execution and command-line arguments of AppCmd.exe, which may be abused to install malicious IIS modules.

Procedures:

- [S0258] RGDoor: RGDoor establishes persistence on webservers as an IIS module.
- [S1022] IceApple: IceApple is an IIS post-exploitation framework, consisting of 18 modules that provide several functionalities.
- [C0022] Operation Dream Job: During Operation Dream Job, Lazarus Group targeted Windows servers running Internet Information Systems (IIS) to install C2 components.
- [S0072] OwaAuth: OwaAuth has been loaded onto Exchange servers and disguised as an ISAPI filter (owaauth.dll). The IIS w3wp.exe process then loads the malicious DLL.

### T1505.005 - Server Software Component: Terminal Services DLL

Description:

Adversaries may abuse components of Terminal Services to enable persistent access to systems. Microsoft Terminal Services, renamed to Remote Desktop Services in some Windows Server OSs as of 2022, enable remote terminal connections to hosts. Terminal Services allows servers to transmit a full, interactive, graphical user interface to clients via RDP. Windows Services that are run as a "generic" process (ex: svchost.exe) load the service's DLL file, the location of which is stored in a Registry entry named ServiceDll. The termsrv.dll file, typically stored in `%SystemRoot%\System32\`, is the default ServiceDll value for Terminal Services in `HKLM\System\CurrentControlSet\services\TermService\Parameters\`. Adversaries may modify and/or replace the Terminal Services DLL to enable persistent access to victimized hosts. Modifications to this DLL could be done to execute arbitrary payloads (while also potentially preserving normal termsrv.dll functionality) as well as to simply enable abusable features of Terminal Services. For example, an adversary may enable features such as concurrent Remote Desktop Protocol sessions by either patching the termsrv.dll file or modifying the ServiceDll value to point to a DLL that provides increased RDP functionality. On a non-server Windows OS this increased functionality may also enable an adversary to avoid Terminal Services prompts that warn/log out users of a system when a new RDP session is created.

Detection:

Monitor for changes to Registry keys associated with ServiceDll and other subkey values under HKLM\System\CurrentControlSet\services\TermService\Parameters\. Monitor unexpected changes and/or interactions with termsrv.dll, which is typically stored in %SystemRoot%\System32\. Monitor commands as well as processes and arguments for potential adversary actions to modify Registry values (ex: reg.exe) or modify/replace the legitimate termsrv.dll. Monitor module loads by the Terminal Services process (ex: svchost.exe -k termsvcs) for unexpected DLLs (the default is %SystemRoot%\System32\termsrv.dll, though an adversary could also use Match Legitimate Resource Name or Location on a malicious payload).

### T1505.006 - Server Software Component: vSphere Installation Bundles

Description:

Adversaries may abuse vSphere Installation Bundles (VIBs) to establish persistent access to ESXi hypervisors. VIBs are collections of files used for software distribution and virtual system management in VMware environments. Since ESXi uses an in-memory filesystem where changes made to most files are stored in RAM rather than in persistent storage, these modifications are lost after a reboot. However, VIBs can be used to create startup tasks, apply custom firewall rules, or deploy binaries that persist across reboots. Typically, administrators use VIBs for updates and system maintenance. VIBs can be broken down into three components: * VIB payload: a `.vgz` archive containing the directories and files to be created and executed on boot when the VIBs are loaded. * Signature file: verifies the host acceptance level of a VIB, indicating what testing and validation has been done by VMware or its partners before publication of a VIB. By default, ESXi hosts require a minimum acceptance level of PartnerSupported for VIB installation, meaning the VIB is published by a trusted VMware partner. However, privileged users can change the default acceptance level using the `esxcli` command line interface. Additionally, VIBs are able to be installed regardless of acceptance level by using the esxcli software vib install --force command. * XML descriptor file: a configuration file containing associated VIB metadata, such as the name of the VIB and its dependencies. Adversaries may leverage malicious VIB packages to maintain persistent access to ESXi hypervisors, allowing system changes to be executed upon each bootup of ESXi – such as using `esxcli` to enable firewall rules for backdoor traffic, creating listeners on hard coded ports, and executing backdoors. Adversaries may also masquerade their malicious VIB files as PartnerSupported by modifying the XML descriptor file.


### T1525 - Implant Internal Image

Description:

Adversaries may implant cloud or container images with malicious code to establish persistence after gaining access to an environment. Amazon Web Services (AWS) Amazon Machine Images (AMIs), Google Cloud Platform (GCP) Images, and Azure Images as well as popular container runtimes such as Docker can be implanted or backdoored. Unlike Upload Malware, this technique focuses on adversaries implanting an image in a registry within a victim’s environment. Depending on how the infrastructure is provisioned, this could provide persistent access if the infrastructure provisioning tool is instructed to always use the latest image. A tool has been developed to facilitate planting backdoors in cloud container images. If an adversary has access to a compromised AWS instance, and permissions to list the available container images, they may implant a backdoor such as a Web Shell.

Detection:

Monitor interactions with images and containers by users to identify ones that are added or modified anomalously. In containerized environments, changes may be detectable by monitoring the Docker daemon logs or setting up and monitoring Kubernetes audit logs depending on registry configuration.


### T1542.001 - Pre-OS Boot: System Firmware

Description:

Adversaries may modify system firmware to persist on systems.The BIOS (Basic Input/Output System) and The Unified Extensible Firmware Interface (UEFI) or Extensible Firmware Interface (EFI) are examples of system firmware that operate as the software interface between the operating system and hardware of a computer. System firmware like BIOS and (U)EFI underly the functionality of a computer and may be modified by an adversary to perform or assist in malicious activity. Capabilities exist to overwrite the system firmware, which may give sophisticated adversaries a means to install malicious firmware updates as a means of persistence on a system that may be difficult to detect.

Detection:

System firmware manipulation may be detected. Dump and inspect BIOS images on vulnerable systems and compare against known good images. Analyze differences to determine if malicious changes have occurred. Log attempts to read/write to BIOS and compare against known patching behavior. Likewise, EFI modules can be collected and compared against a known-clean list of EFI executable binaries to detect potentially malicious modules. The CHIPSEC framework can be used for analysis to determine if firmware modifications have been performed.

Procedures:

- [S0397] LoJax: LoJax is a UEFI BIOS rootkit deployed to persist remote access software on some targeted systems.
- [S0001] Trojan.Mebromi: Trojan.Mebromi performs BIOS modification and can download and execute a file as well as protect itself from removal.
- [S0047] Hacking Team UEFI Rootkit: Hacking Team UEFI Rootkit is a UEFI BIOS rootkit developed by the company Hacking Team to persist remote access software on some targeted systems.

### T1542.002 - Pre-OS Boot: Component Firmware

Description:

Adversaries may modify component firmware to persist on systems. Some adversaries may employ sophisticated means to compromise computer components and install malicious firmware that will execute adversary code outside of the operating system and main system firmware or BIOS. This technique may be similar to System Firmware but conducted upon other system components/devices that may not have the same capability or level of integrity checking. Malicious component firmware could provide both a persistent level of access to systems despite potential typical failures to maintain access and hard disk re-images, as well as a way to evade host software-based defenses and integrity checks.

Detection:

Data and telemetry from use of device drivers (i.e. processes and API calls) and/or provided by SMART (Self-Monitoring, Analysis and Reporting Technology) disk monitoring may reveal malicious manipulations of components. Otherwise, this technique may be difficult to detect since malicious activity is taking place on system components possibly outside the purview of OS security and integrity mechanisms. Disk check and forensic utilities may reveal indicators of malicious firmware such as strings, unexpected disk partition table entries, or blocks of otherwise unusual memory that warrant deeper investigation. Also consider comparing components, including hashes of component firmware and behavior, against known good images.

Procedures:

- [G0020] Equation: Equation is known to have the capability to overwrite the firmware on hard drives from some manufacturers.
- [S0687] Cyclops Blink: Cyclops Blink has maintained persistence by patching legitimate device firmware when it is downloaded, including that of WatchGuard devices.

### T1542.003 - Pre-OS Boot: Bootkit

Description:

Adversaries may use bootkits to persist on systems. A bootkit is a malware variant that modifies the boot sectors of a hard drive, allowing malicious code to execute before a computer's operating system has loaded. Bootkits reside at a layer below the operating system and may make it difficult to perform full remediation unless an organization suspects one was used and can act accordingly. In BIOS systems, a bootkit may modify the Master Boot Record (MBR) and/or Volume Boot Record (VBR). The MBR is the section of disk that is first loaded after completing hardware initialization by the BIOS. It is the location of the boot loader. An adversary who has raw access to the boot drive may overwrite this area, diverting execution during startup from the normal boot loader to adversary code. The MBR passes control of the boot process to the VBR. Similar to the case of MBR, an adversary who has raw access to the boot drive may overwrite the VBR to divert execution during startup to adversary code. In UEFI (Unified Extensible Firmware Interface) systems, a bootkit may instead create or modify files in the EFI system partition (ESP). The ESP is a partition on data storage used by devices containing UEFI that allows the system to boot the OS and other utilities used by the system. An adversary can use the newly created or patched files in the ESP to run malicious kernel code.

Detection:

Perform integrity checking on MBR and VBR. Take snapshots of MBR and VBR and compare against known good samples. Report changes to MBR and VBR as they occur for indicators of suspicious activity and further analysis.

Procedures:

- [S0484] Carberp: Carberp has installed a bootkit on the system to maintain persistence.
- [S0689] WhisperGate: WhisperGate overwrites the MBR with a bootloader component that performs destructive wiping operations on hard drives and displays a fake ransom note when the host boots.
- [S0266] TrickBot: TrickBot can implant malicious code into a compromised device's firmware.
- [S0112] ROCKBOOT: ROCKBOOT is a Master Boot Record (MBR) bootkit that uses the MBR to establish persistence.
- [G0096] APT41: APT41 deployed Master Boot Record bootkits on Windows systems to hide their malware and maintain persistence on victim systems.
- [S0114] BOOTRASH: BOOTRASH is a Volume Boot Record (VBR) bootkit that uses the VBR to maintain persistence.
- [S0182] FinFisher: Some FinFisher variants incorporate an MBR rootkit.
- [G0032] Lazarus Group: Lazarus Group malware WhiskeyAlfa-Three modifies sector 0 of the Master Boot Record (MBR) to ensure that the malware will persist even if a victim machine shuts down.
- [G0007] APT28: APT28 has deployed a bootkit along with Downdelph to ensure its persistence on the victim. The bootkit shares code with some variants of BlackEnergy.

### T1542.004 - Pre-OS Boot: ROMMONkit

Description:

Adversaries may abuse the ROM Monitor (ROMMON) by loading an unauthorized firmware with adversary code to provide persistent access and manipulate device behavior that is difficult to detect. ROMMON is a Cisco network device firmware that functions as a boot loader, boot image, or boot helper to initialize hardware and software when the platform is powered on or reset. Similar to TFTP Boot, an adversary may upgrade the ROMMON image locally or remotely (for example, through TFTP) with adversary code and restart the device in order to overwrite the existing ROMMON image. This provides adversaries with the means to update the ROMMON to gain persistence on a system in a way that may be difficult to detect.

Detection:

There are no documented means for defenders to validate the operation of the ROMMON outside of vendor support. If a network device is suspected of being compromised, contact the vendor to assist in further investigation.

### T1542.005 - Pre-OS Boot: TFTP Boot

Description:

Adversaries may abuse netbooting to load an unauthorized network device operating system from a Trivial File Transfer Protocol (TFTP) server. TFTP boot (netbooting) is commonly used by network administrators to load configuration-controlled network device images from a centralized management server. Netbooting is one option in the boot sequence and can be used to centralize, manage, and control device images. Adversaries may manipulate the configuration on the network device specifying use of a malicious TFTP server, which may be used in conjunction with Modify System Image to load a modified image on device startup or reset. The unauthorized image allows adversaries to modify device configuration, add malicious capabilities to the device, and introduce backdoors to maintain control of the network device while minimizing detection through use of a standard functionality. This technique is similar to ROMMONkit and may result in the network device running a modified image.

Detection:

Consider comparing a copy of the network device configuration and system image against a known-good version to discover unauthorized changes to system boot, startup configuration, or the running OS. The same process can be accomplished through a comparison of the run-time memory, though this is non-trivial and may require assistance from the vendor. Review command history in either the console or as part of the running memory to determine if unauthorized or suspicious commands were used to modify device configuration. Check boot information including system uptime, image booted, and startup configuration to determine if results are consistent with expected behavior in the environment. Monitor unusual connections or connection attempts to the device that may specifically target TFTP or other file-sharing protocols.


### T1543.001 - Create or Modify System Process: Launch Agent

Description:

Adversaries may create or modify launch agents to repeatedly execute malicious payloads as part of persistence. When a user logs in, a per-user launchd process is started which loads the parameters for each launch-on-demand user agent from the property list (.plist) file found in /System/Library/LaunchAgents, /Library/LaunchAgents, and ~/Library/LaunchAgents. Property list files use the Label, ProgramArguments , and RunAtLoad keys to identify the Launch Agent's name, executable location, and execution time. Launch Agents are often installed to perform updates to programs, launch user specified programs at login, or to conduct other developer tasks. Launch Agents can also be executed using the Launchctl command. Adversaries may install a new Launch Agent that executes at login by placing a .plist file into the appropriate folders with the RunAtLoad or KeepAlive keys set to true. The Launch Agent name may be disguised by using a name from the related operating system or benign software. Launch Agents are created with user level privileges and execute with user level permissions.

Detection:

Monitor Launch Agent creation through additional plist files and utilities such as Objective-See’s KnockKnock application. Launch Agents also require files on disk for persistence which can also be monitored via other file monitoring applications. Ensure Launch Agent's ProgramArguments key pointing to executables located in the /tmp or /shared folders are in alignment with enterprise policy. Ensure all Launch Agents with the RunAtLoad key set to true are in alignment with policy.

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
- [S0277] FruitFly: FruitFly persists via a Launch Agent.
- [S0162] Komplex: The Komplex trojan creates a persistent launch agent called with $HOME/Library/LaunchAgents/com.apple.updates.plist with launchctl load -w ~/Library/LaunchAgents/com.apple.updates.plist.
- [S0198] NETWIRE: NETWIRE can use launch agents for persistence.
- [S0276] Keydnap: Keydnap uses a Launch Agent to persist.

### T1543.002 - Create or Modify System Process: Systemd Service

Description:

Adversaries may create or modify systemd services to repeatedly execute malicious payloads as part of persistence. Systemd is a system and service manager commonly used for managing background daemon processes (also known as services) and other system resources. Systemd is the default initialization (init) system on many Linux distributions replacing legacy init systems, including SysVinit and Upstart, while remaining backwards compatible. Systemd utilizes unit configuration files with the `.service` file extension to encode information about a service's process. By default, system level unit files are stored in the `/systemd/system` directory of the root owned directories (`/`). User level unit files are stored in the `/systemd/user` directories of the user owned directories (`$HOME`). Inside the `.service` unit files, the following directives are used to execute commands: * `ExecStart`, `ExecStartPre`, and `ExecStartPost` directives execute when a service is started manually by `systemctl` or on system start if the service is set to automatically start. * `ExecReload` directive executes when a service restarts. * `ExecStop`, `ExecStopPre`, and `ExecStopPost` directives execute when a service is stopped. Adversaries have created new service files, altered the commands a `.service` file’s directive executes, and modified the user directive a `.service` file executes as, which could result in privilege escalation. Adversaries may also place symbolic links in these directories, enabling systemd to find these payloads regardless of where they reside on the filesystem. The `.service` file’s User directive can be used to run service as a specific user, which could result in privilege escalation based on specific user/group permissions. Systemd services can be created via systemd generators, which support the dynamic generation of unit files. Systemd generators are small executables that run during boot or configuration reloads to dynamically create or modify systemd unit files by converting non-native configurations into services, symlinks, or drop-ins (i.e., Boot or Logon Initialization Scripts).

Detection:

Monitor file creation and modification events of Systemd service unit configuration files in the default directory locations for `root` & `user` level permissions. Suspicious processes or scripts spawned in this manner will have a parent process of ‘systemd’, a parent process ID of 1, and will usually execute as the `root` user. Suspicious systemd services can also be identified by comparing results against a trusted system baseline. Malicious systemd services may be detected by using the systemctl utility to examine system wide services: `systemctl list-units -–type=service –all`. Analyze the contents of `.service` files present on the file system and ensure that they refer to legitimate, expected executables, and symbolic links. Auditing the execution and command-line arguments of the `systemctl` utility, as well related utilities such as `/usr/sbin/service` may reveal malicious systemd service execution.

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

Description:

Adversaries may create or modify Windows services to repeatedly execute malicious payloads as part of persistence. When Windows boots up, it starts programs or applications called services that perform background system functions. Windows service configuration information, including the file path to the service's executable or recovery programs/commands, is stored in the Windows Registry. Adversaries may install a new service or modify an existing service to execute at startup in order to persist on a system. Service configurations can be set or modified using system utilities (such as sc.exe), by directly modifying the Registry, or by interacting directly with the Windows API. Adversaries may also use services to install and execute malicious drivers. For example, after dropping a driver file (ex: `.sys`) to disk, the payload can be loaded and registered via Native API functions such as `CreateServiceW()` (or manually via functions such as `ZwLoadDriver()` and `ZwSetValueKey()`), by creating the required service Registry values (i.e. Modify Registry), or by using command-line utilities such as `PnPUtil.exe`. Adversaries may leverage these drivers as Rootkits to hide the presence of malicious activity on a system. Adversaries may also load a signed yet vulnerable driver onto a compromised machine (known as "Bring Your Own Vulnerable Driver" (BYOVD)) as part of Exploitation for Privilege Escalation. Services may be created with administrator privileges but are executed under SYSTEM privileges, so an adversary may also use a service to escalate privileges. Adversaries may also directly start services through Service Execution. To make detection analysis more challenging, malicious services may also incorporate Masquerade Task or Service (ex: using a service and/or payload name related to a legitimate OS or benign software component). Adversaries may also create ‘hidden’ services (i.e., Hide Artifacts), for example by using the `sc sdset` command to set service permissions via the Service Descriptor Definition Language (SDDL). This may hide a Windows service from the view of standard service enumeration methods such as `Get-Service`, `sc query`, and `services.exe`.

Detection:

Monitor processes and command-line arguments for actions that could create or modify services. Command-line invocation of tools capable of adding or modifying services may be unusual, depending on how systems are typically used in a particular environment. Services may also be modified through Windows system management tools such as Windows Management Instrumentation and PowerShell, so additional logging may need to be configured to gather the appropriate data. Remote access tools with built-in features may also interact directly with the Windows API to perform these functions outside of typical system utilities. Collect service utility execution and service binary path arguments used for analysis. Service binary paths may even be changed to execute commands or scripts. Look for changes to service Registry entries that do not correlate with known software, patch cycles, etc. Service information is stored in the Registry at HKLM\SYSTEM\CurrentControlSet\Services. Changes to the binary path and the service startup type changed from manual or disabled to automatic, if it does not typically do so, may be suspicious. Tools such as Sysinternals Autoruns may also be used to detect system service changes that could be attempts at persistence. Creation of new services may generate an alterable event (ex: Event ID 4697 and/or 7045 ). New, benign services may be created during installation of new software. Suspicious program execution through services may show up as outlier processes that have not been seen before when compared against historical data. Look for abnormal process call trees from known services and for execution of other commands that could relate to Discovery or other adversary techniques. Data and events should not be viewed in isolation, but as part of a chain of behavior that could lead to other activities, such as network connections made for Command and Control, learning details about the environment through Discovery, and Lateral Movement.

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
- [S0012] PoisonIvy: PoisonIvy creates a Registry subkey that registers a new service. PoisonIvy also creates a Registry entry modifying the Logical Disk Manager service to point to a malicious DLL dropped to disk.
- [S1037] STARWHALE: STARWHALE has the ability to create the following Windows service to establish persistence on an infected host: `sc create Windowscarpstss binpath= "cmd.exe /c cscript.exe c:\\windows\\system32\\w7_1.wsf humpback_whale" start= "auto" obj= "LocalSystem"`.
- [S0230] ZeroT: ZeroT can add a new service to ensure PlugX persists on the system when delivered as another payload onto the system.
- [S0666] Gelsemium: Gelsemium can drop itself in `C:\Windows\System32\spool\prtprocs\x64\winprint.dll` as an alternative Print Processor to be loaded automatically when the spoolsv Windows service starts.
- [G0143] Aquatic Panda: Aquatic Panda created new Windows services for persistence that masqueraded as legitimate Windows services via name change.
- [G0082] APT38: APT38 has installed a new Windows service to establish persistence.
- [S0650] QakBot: QakBot can remotely create a temporary service on a target host.
- [G0030] Lotus Blossom: Lotus Blossom has configured tools such as Sagerunex to run as Windows services.
- [S0608] Conficker: Conficker copies itself into the %systemroot%\system32 directory and registers as a service.
- [S0342] GreyEnergy: GreyEnergy chooses a service, drops a DLL file, and writes it to that serviceDLL Registry key.
- [G0096] APT41: APT41 modified legitimate Windows services to install malware backdoors. APT41 created the StorSyncSvc service to provide persistence for Cobalt Strike.
- [S0387] KeyBoy: KeyBoy installs a service pointing to a malicious DLL dropped to disk.
- [G0102] Wizard Spider: Wizard Spider has installed TrickBot as a service named ControlServiceA in order to establish persistence.
- [S0081] Elise: Elise configures itself as a service.
- [S0439] Okrum: To establish persistence, Okrum can install itself as a new service named NtmSsvc.
- [G0108] Blue Mockingbird: Blue Mockingbird has made their XMRIG payloads persistent as a Windows Service.
- [G0139] TeamTNT: TeamTNT has used malware that adds cryptocurrency miners as a service.
- [S0584] AppleJeus: AppleJeus can install itself as a service.
- [G1043] BlackByte: BlackByte modified multiple services on victim machines to enable encryption operations. BlackByte has installed tools such as AnyDesk as a service on victim machines.
- [S0567] Dtrack: Dtrack can add a service called WBService to establish persistence.
- [S0603] Stuxnet: Stuxnet uses a driver registered as a boot start service as the main load-point.
- [S0350] zwShell: zwShell has established persistence by adding itself as a new service.
- [S1202] LockBit 3.0: LockBit 3.0 can install system services for persistence.
- [S0692] SILENTTRINITY: SILENTTRINITY can establish persistence by creating a new service.
- [S0086] ZLib: ZLib creates Registry keys to allow itself to run as various services.
- [S0268] Bisonal: Bisonal has been modified to be used as a Windows service.
- [C0040] APT41 DUST: APT41 DUST used Windows Services with names such as `Windows Defend` for persistence of DUSTPAN.
- [S0029] PsExec: PsExec can leverage Windows services to escalate privileges from administrator to SYSTEM with the -s argument.
- [S0665] ThreatNeedle: ThreatNeedle can run in memory and register its payload as a Windows service.
- [S0038] Duqu: Duqu creates a new service that loads a malicious driver when the system starts. When Duqu is active, the operating system believes that the driver is legitimate, as it has been signed with a valid private key.
- [G0073] APT19: An APT19 Port 22 malware variant registers itself as a service.
- [S0140] Shamoon: Shamoon creates a new service named “ntssrv” to execute the payload. Newer versions create the "MaintenaceSrv" and "hdv_725x" services.
- [S0266] TrickBot: TrickBot establishes persistence by creating an autostart service that allows it to run whenever the machine boots.
- [S0142] StreamEx: StreamEx establishes persistence by installing a new service pointing to its DLL and setting the service to auto-start.
- [S0236] Kwampirs: Kwampirs creates a new service named WmiApSrvEx to establish persistence.
- [S0533] SLOTHFULMEDIA: SLOTHFULMEDIA has created a service on victim machines named "TaskFrame" to establish persistence.
- [S0239] Bankshot: Bankshot can terminate a specific process by its process id.
- [S0154] Cobalt Strike: Cobalt Strike can install a new service.
- [S0664] Pandora: Pandora has the ability to gain system privileges through Windows services.
- [S0495] RDAT: RDAT has created a service when it is installed on the victim machine.
- [S0194] PowerSploit: PowerSploit contains a collection of Privesc-PowerUp modules that can discover and replace/modify service binaries, paths, and configs.
- [S0335] Carbon: Carbon establishes persistence by creating a service and naming it based off the operating system version running on the current machine.
- [G0027] Threat Group-3390: Threat Group-3390's malware can create a new service, sometimes naming it after the config information, to gain persistence.
- [S0206] Wiarp: Wiarp creates a backdoor through which remote attackers can create a service.
- [S0210] Nerex: Nerex creates a Registry subkey that registers a new service.
- [S0261] Catchamas: Catchamas adds a new service named NetAdapter to establish persistence.
- [S1099] Samurai: Samurai can create a service at `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SvcHost` to trigger execution and maintain persistence.
- [S0203] Hydraq: Hydraq creates new services to establish persistence.
- [S0013] PlugX: PlugX can be added as a service to establish persistence. PlugX also has a module to change service configurations as well as start, control, and delete services.
- [G0004] Ke3chang: Ke3chang backdoor RoyalDNS established persistence through adding a service called Nwsapagent.
- [S0451] LoudMiner: LoudMiner can automatically launch a Linux virtual machine as a service at startup if the AutoStart option is enabled in the VBoxVmService configuration file.
- [G0056] PROMETHIUM: PROMETHIUM has created new services and modified existing services for persistence.
- [S0438] Attor: Attor's dispatcher can establish persistence by registering a new service.
- [S0265] Kazuar: Kazuar can install itself as a new service.
- [S0386] Ursnif: Ursnif has registered itself as a system service in the Registry for automatic execution at system startup.
- [S1049] SUGARUSH: SUGARUSH has created a service named `Service1` for persistence.
- [C0025] 2016 Ukraine Electric Power Attack: During the 2016 Ukraine Electric Power Attack, Sandworm Team used an arbitrary system service to load at system boot for persistence for Industroyer. They also replaced the ImagePath registry value of a Windows service with a new backdoor binary.
- [S0071] hcdLoader: hcdLoader installs itself as a service for persistence.
- [S0570] BitPaymer: BitPaymer has attempted to install itself as a service to maintain persistence.
- [S1031] PingPull: PingPull has the ability to install itself as a service.
- [S0004] TinyZBot: TinyZBot can install as a Windows service for persistence.
- [S0343] Exaramel for Windows: The Exaramel for Windows dropper creates and starts a Windows service named wsmprovav with the description “Windows Check AV.”
- [S0504] Anchor: Anchor can establish persistence by creating a service.
- [G0049] OilRig: OilRig has used a compromised Domain Controller to create a service on a remote host.
- [S0356] KONNI: KONNI has registered itself as a service using its export function.
- [S0412] ZxShell: ZxShell can create a new service using the service parser function ProcessScCommand.
- [S1211] Hannotog: Hannotog creates a new service for persistence.
- [S0629] RainyDay: RainyDay can use services to establish persistence.
- [S0127] BBSRAT: BBSRAT can modify service configurations.
- [S0260] InvisiMole: InvisiMole can register a Windows service named CsPower as part of its execution chain, and a Windows service named clr_optimization_v2.0.51527_X86 to achieve persistence.
- [G0050] APT32: APT32 modified Windows Services to ensure PowerShell scripts were loaded on the system. APT32 also creates a Windows service to establish persistence.
- [S0560] TEARDROP: TEARDROP ran as a Windows service from the c:\windows\syswow64 folder.
- [S0630] Nebulae: Nebulae can create a service to establish persistence.
- [S0182] FinFisher: FinFisher creates a new Windows service with the malicious executable for persistence.
- [S0491] StrongPity: StrongPity has created new services and modified existing services for persistence.
- [S1070] Black Basta: Black Basta can create a new service to establish persistence.
- [S0345] Seasalt: Seasalt is capable of installing itself as a service.
- [S0176] Wingbird: Wingbird uses services.exe to register a new autostart service named "Audit Service" using a copy of the local lsass.exe file.
- [C0006] Operation Honeybee: During Operation Honeybee, threat actors installed DLLs and backdoors as Windows services.
- [S0032] gh0st RAT: gh0st RAT can create a new service to establish persistence.
- [G0008] Carbanak: Carbanak malware installs itself as a service to provide persistence and SYSTEM privileges.
- [S0022] Uroburos: Uroburos has registered a service, typically named `WerFaultSvc`, to decrypt and find a kernel driver and kernel driver loader to maintain persistence.
- [S0044] JHUHUGIT: JHUHUGIT has registered itself as a service to establish persistence.
- [S0205] Naid: Naid creates a new service to establish.
- [S0481] Ragnar Locker: Ragnar Locker has used sc.exe to create a new service for the VirtualBox driver.
- [S1100] Ninja: Ninja can create the services `httpsvc` and `w3esvc` for persistence .
- [G0022] APT3: APT3 has a tool that creates a new service for persistence.
- [G0046] FIN7: FIN7 created new Windows services and added them to the startup directories for persistence.
- [S0259] InnaputRAT: Some InnaputRAT variants create a new Windows service to establish persistence.
- [G1030] Agrius: Agrius has deployed IPsec Helper malware post-exploitation and registered it as a service for persistence.
- [S0089] BlackEnergy: One variant of BlackEnergy creates a new service using either a hard-coded or randomly generated name.
- [G0094] Kimsuky: Kimsuky has created new services for persistence.
- [S0444] ShimRat: ShimRat has installed a Windows service to maintain persistence on victim machines.
- [S0046] CozyCar: One persistence mechanism used by CozyCar is to register itself as a Windows service.
- [S0660] Clambling: Clambling can register itself as a system service to gain persistence.
- [S0263] TYPEFRAME: TYPEFRAME variants can add malicious DLL modules as new services.TYPEFRAME can also delete services from the victim’s machine.
- [S0697] HermeticWiper: HermeticWiper can load drivers by creating a new service using the `CreateServiceW` API.
- [G1006] Earth Lusca: Earth Lusca created a service using the command sc create “SysUpdate” binpath= “cmd /c start “[file path]””&&sc config “SysUpdate” start= auto&&net start SysUpdate for persistence.
- [S0169] RawPOS: RawPOS installs itself as a service to maintain persistence.
- [G0080] Cobalt Group: Cobalt Group has created new services to establish persistence.
- [S0074] Sakula: Some Sakula samples install themselves as services for persistence by calling WinExec with the net start argument.
- [S0164] TDTESS: If running as administrator, TDTESS installs itself as a new service named bmwappushservice to establish persistence.
- [G0032] Lazarus Group: Several Lazarus Group malware families install themselves as new services.
- [S0347] AuditCred: AuditCred is installed as a new service on the system.
- [S0501] PipeMon: PipeMon can establish persistence by registering a malicious DLL as an alternative Print Processor which is loaded when the print spooler service starts.
- [G1021] Cinnamon Tempest: Cinnamon Tempest has created system services to establish persistence for deployed tooling.
- [S0024] Dyre: Dyre registers itself as a service by adding several Registry keys.
- [S0082] Emissary: Emissary is capable of configuring itself as a service.
- [S0363] Empire: Empire can utilize built-in modules to modify service binaries and restore them to their original state.
- [S0367] Emotet: Emotet has been observed creating new services to maintain persistence.
- [S1158] DUSTPAN: DUSTPAN can persist as a Windows Service in operations.
- [S0172] Reaver: Reaver installs itself as a new service.
- [S0181] FALLCHILL: FALLCHILL has been installed as a Windows service.
- [S0663] SysUpdate: SysUpdate can create a service to establish persistence.
- [S0118] Nidiran: Nidiran can create a new service named msamger (Microsoft Security Accounts Manager).
- [S0366] WannaCry: WannaCry creates the service "mssecsvc2.0" with the display name "Microsoft Security Center (2.0) Service."

### T1543.004 - Create or Modify System Process: Launch Daemon

Description:

Adversaries may create or modify Launch Daemons to execute malicious payloads as part of persistence. Launch Daemons are plist files used to interact with Launchd, the service management framework used by macOS. Launch Daemons require elevated privileges to install, are executed for every user on a system prior to login, and run in the background without the need for user interaction. During the macOS initialization startup, the launchd process loads the parameters for launch-on-demand system-level daemons from plist files found in /System/Library/LaunchDaemons/ and /Library/LaunchDaemons/. Required Launch Daemons parameters include a Label to identify the task, Program to provide a path to the executable, and RunAtLoad to specify when the task is run. Launch Daemons are often used to provide access to shared resources, updates to software, or conduct automation tasks. Adversaries may install a Launch Daemon configured to execute at startup by using the RunAtLoad parameter set to true and the Program parameter set to the malicious executable path. The daemon name may be disguised by using a name from a related operating system or benign software (i.e. Masquerading). When the Launch Daemon is executed, the program inherits administrative permissions. Additionally, system configuration changes (such as the installation of third party package managing software) may cause folders such as usr/local/bin to become globally writeable. So, it is possible for poor configurations to allow an adversary to modify executables referenced by current Launch Daemon's plist files.

Detection:

Monitor for new files added to the /Library/LaunchDaemons/ folder. The System LaunchDaemons are protected by SIP. Some legitimate LaunchDaemons point to unsigned code that could be exploited. For Launch Daemons with the RunAtLoad parameter set to true, ensure the Program parameter points to signed code or executables are in alignment with enterprise policy. Some parameters are interchangeable with others, such as Program and ProgramArguments parameters but one must be present.

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

Description:

Adversaries may create or modify container or container cluster management tools that run as daemons, agents, or services on individual hosts. These include software for creating and managing individual containers, such as Docker and Podman, as well as container cluster node-level agents such as kubelet. By modifying these services, an adversary may be able to achieve persistence or escalate their privileges on a host. For example, by using the `docker run` or `podman run` command with the `restart=always` directive, a container can be configured to persistently restart on the host. A user with access to the (rootful) docker command may also be able to escalate their privileges on the host. In Kubernetes environments, DaemonSets allow an adversary to persistently Deploy Containers on all nodes, including ones added later to the cluster. Pods can also be deployed to specific nodes using the `nodeSelector` or `nodeName` fields in the pod spec. Note that containers can also be configured to run as Systemd Services.


### T1546.001 - Event Triggered Execution: Change Default File Association

Description:

Adversaries may establish persistence by executing malicious content triggered by a file type association. When a file is opened, the default program used to open the file (also called the file association or handler) is checked. File association selections are stored in the Windows Registry and can be edited by users, administrators, or programs that have Registry access or by administrators using the built-in assoc utility. Applications can modify the file association for a given file extension to call an arbitrary program when a file with the given extension is opened. System file associations are listed under HKEY_CLASSES_ROOT\.[extension], for example HKEY_CLASSES_ROOT\.txt. The entries point to a handler for that extension located at HKEY_CLASSES_ROOT\\[handler]. The various commands are then listed as subkeys underneath the shell key at HKEY_CLASSES_ROOT\\[handler]\shell\\[action]\command. For example: * HKEY_CLASSES_ROOT\txtfile\shell\open\command * HKEY_CLASSES_ROOT\txtfile\shell\print\command * HKEY_CLASSES_ROOT\txtfile\shell\printto\command The values of the keys listed are commands that are executed when the handler opens the file extension. Adversaries can modify these values to continually execute arbitrary commands.

Detection:

Collect and analyze changes to Registry keys that associate file extensions to default applications for execution and correlate with unknown process launch activity or unusual file types for that process. User file association preferences are stored under [HKEY_CURRENT_USER]\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts and override associations configured under [HKEY_CLASSES_ROOT]. Changes to a user's preference will occur under this entry's subkeys. Also look for abnormal process call trees for execution of other commands that could relate to Discovery actions or other techniques.

Procedures:

- [S0692] SILENTTRINITY: SILENTTRINITY can conduct an image hijack of an `.msc` file extension as part of its UAC bypass process.
- [G0094] Kimsuky: Kimsuky has a HWP document stealer module which changes the default program association in the registry to open HWP documents.

### T1546.002 - Event Triggered Execution: Screensaver

Description:

Adversaries may establish persistence by executing malicious content triggered by user inactivity. Screensavers are programs that execute after a configurable time of user inactivity and consist of Portable Executable (PE) files with a .scr file extension. The Windows screensaver application scrnsave.scr is located in C:\Windows\System32\, and C:\Windows\sysWOW64\ on 64-bit Windows systems, along with screensavers included with base Windows installations. The following screensaver settings are stored in the Registry (HKCU\Control Panel\Desktop\) and could be manipulated to achieve persistence: * SCRNSAVE.exe - set to malicious PE path * ScreenSaveActive - set to '1' to enable the screensaver * ScreenSaverIsSecure - set to '0' to not require a password to unlock * ScreenSaveTimeout - sets user inactivity timeout before screensaver is executed Adversaries can use screensaver settings to maintain persistence by setting the screensaver to run malware after a certain timeframe of user inactivity.

Detection:

Monitor process execution and command-line parameters of .scr files. Monitor changes to screensaver configuration changes in the Registry that may not correlate with typical user behavior. Tools such as Sysinternals Autoruns can be used to detect changes to the screensaver binary path in the Registry. Suspicious paths and PE files may indicate outliers among legitimate screensavers in a network and should be investigated.

Procedures:

- [S0168] Gazer: Gazer can establish persistence through the system screensaver by configuring it to execute the malware.

### T1546.003 - Event Triggered Execution: Windows Management Instrumentation Event Subscription

Description:

Adversaries may establish persistence and elevate privileges by executing malicious content triggered by a Windows Management Instrumentation (WMI) event subscription. WMI can be used to install event filters, providers, consumers, and bindings that execute code when a defined event occurs. Examples of events that may be subscribed to are the wall clock time, user login, or the computer's uptime. Adversaries may use the capabilities of WMI to subscribe to an event and execute arbitrary code when that event occurs, providing persistence on a system. Adversaries may also compile WMI scripts – using `mofcomp.exe` –into Windows Management Object (MOF) files (.mof extension) that can be used to create a malicious subscription. WMI subscription execution is proxied by the WMI Provider Host process (WmiPrvSe.exe) and thus may result in elevated SYSTEM privileges.

Detection:

Monitor WMI event subscription entries, comparing current WMI event subscriptions to known good subscriptions for each host. Tools such as Sysinternals Autoruns may also be used to detect WMI changes that could be attempts at persistence. Monitor for the creation of new WMI EventFilter, EventConsumer, and FilterToConsumerBinding events. Event ID 5861 is logged on Windows 10 systems when new EventFilterToConsumerBinding events are created. Monitor processes and command-line arguments that can be used to register WMI persistence, such as the Register-WmiEvent PowerShell cmdlet, as well as those that result from the execution of subscriptions (i.e. spawning from the WmiPrvSe.exe WMI Provider Host process).

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
- [S1020] Kevin: Kevin can compile randomly-generated MOF files into the WMI repository to persistently run malware.
- [C0023] Operation Ghost: During Operation Ghost, APT29 used WMI event subscriptions to establish persistence for malware.
- [G0129] Mustang Panda: Mustang Panda's custom ORat tool uses a WMI event consumer to maintain persistence.
- [S0202] adbupd: adbupd can use a WMI script to achieve persistence.
- [G0075] Rancor: Rancor has complied VBScript-generated MOF files into WMI event subscriptions for persistence.
- [S0053] SeaDuke: SeaDuke uses an event filter in WMI code to execute a previously dropped executable shortly after system startup.
- [S0150] POSHSPY: POSHSPY uses a WMI event subscription to establish persistence.
- [S0378] PoshC2: PoshC2 has the ability to persist on a system using WMI events.
- [S0682] TrailBlazer: TrailBlazer has the ability to use WMI for persistence.
- [S0371] POWERTON: POWERTON can use WMI for persistence.

### T1546.004 - Event Triggered Execution: Unix Shell Configuration Modification

Description:

Adversaries may establish persistence through executing malicious commands triggered by a user’s shell. User Unix Shells execute several configuration scripts at different points throughout the session based on events. For example, when a user opens a command-line interface or remotely logs in (such as via SSH) a login shell is initiated. The login shell executes scripts from the system (/etc) and the user’s home directory (~/) to configure the environment. All login shells on a system use /etc/profile when initiated. These configuration scripts run at the permission level of their directory and are often used to set environment variables, create aliases, and customize the user’s environment. When the shell exits or terminates, additional shell scripts are executed to ensure the shell exits appropriately. Adversaries may attempt to establish persistence by inserting commands into scripts automatically executed by shells. Using bash as an example, the default shell for most GNU/Linux systems, adversaries may add commands that launch malicious binaries into the /etc/profile and /etc/profile.d files. These files typically require root permissions to modify and are executed each time any shell on a system launches. For user level permissions, adversaries can insert malicious commands into ~/.bash_profile, ~/.bash_login, or ~/.profile which are sourced when a user opens a command-line interface or connects remotely. Since the system only executes the first existing file in the listed order, adversaries have used ~/.bash_profile to ensure execution. Adversaries have also leveraged the ~/.bashrc file which is additionally executed if the connection is established remotely or an additional interactive shell is opened, such as a new tab in the command-line interface. Some malware targets the termination of a program to trigger execution, adversaries can use the ~/.bash_logout file to execute malicious commands at the end of a session. For macOS, the functionality of this technique is similar but may leverage zsh, the default shell for macOS 10.15+. When the Terminal.app is opened, the application launches a zsh login shell and a zsh interactive shell. The login shell configures the system environment using /etc/profile, /etc/zshenv, /etc/zprofile, and /etc/zlogin. The login shell then configures the user environment with ~/.zprofile and ~/.zlogin. The interactive shell uses the ~/.zshrc to configure the user environment. Upon exiting, /etc/zlogout and ~/.zlogout are executed. For legacy programs, macOS executes /etc/bashrc on startup.

Detection:

While users may customize their shell profile files, there are only certain types of commands that typically appear in these files. Monitor for abnormal commands such as execution of unknown programs, opening network sockets, or reaching out across the network when user profiles are loaded during the login process. Monitor for changes to /etc/profile and /etc/profile.d, these files should only be modified by system administrators. MacOS users can leverage Endpoint Security Framework file events monitoring these specific files. For most Linux and macOS systems, a list of file paths for valid shell options available on a system are located in the /etc/shells file.

Procedures:

- [S1078] RotaJakiro: When executing with non-root level permissions, RotaJakiro can install persistence by adding a command to the .bashrc file that executes a binary in the `${HOME}/.gvfsd/.profile/` folder.
- [S0362] Linux Rabbit: Linux Rabbit maintains persistence on an infected machine through rc.local and .bashrc files.
- [C0045] ShadowRay: During ShadowRay, threat actors executed commands on interactive and reverse shells.
- [S0690] Green Lambert: Green Lambert can establish persistence on a compromised host through modifying the `profile`, `login`, and run command (rc) files associated with the `bash`, `csh`, and `tcsh` shells.
- [S0658] XCSSET: Using AppleScript, XCSSET adds it's executable to the user's `~/.zshrc_aliases` file (`"echo " & payload & " > ~/zshrc_aliases"`), it then adds a line to the .zshrc file to source the `.zshrc_aliases` file (`[ -f $HOME/.zshrc_aliases ] && . $HOME/.zshrc_aliases`). Each time the user starts a new `zsh` terminal session, the `.zshrc` file executes the `.zshrc_aliases` file.

### T1546.005 - Event Triggered Execution: Trap

Description:

Adversaries may establish persistence by executing malicious content triggered by an interrupt signal. The trap command allows programs and shells to specify commands that will be executed upon receiving interrupt signals. A common situation is a script allowing for graceful termination and handling of common keyboard interrupts like ctrl+c and ctrl+d. Adversaries can use this to register code to be executed when the shell encounters specific interrupts as a persistence mechanism. Trap commands are of the following format trap 'command list' signals where "command list" will be executed when "signals" are received.

Detection:

Trap commands must be registered for the shell or programs, so they appear in files. Monitoring files for suspicious or overly broad trap commands can narrow down suspicious behavior during an investigation. Monitor for suspicious processes executed through trap interrupts.

### T1546.006 - Event Triggered Execution: LC_LOAD_DYLIB Addition

Description:

Adversaries may establish persistence by executing malicious content triggered by the execution of tainted binaries. Mach-O binaries have a series of headers that are used to perform certain operations when a binary is loaded. The LC_LOAD_DYLIB header in a Mach-O binary tells macOS and OS X which dynamic libraries (dylibs) to load during execution time. These can be added ad-hoc to the compiled binary as long as adjustments are made to the rest of the fields and dependencies. There are tools available to perform these changes. Adversaries may modify Mach-O binary headers to load and execute malicious dylibs every time the binary is executed. Although any changes will invalidate digital signatures on binaries because the binary is being modified, this can be remediated by simply removing the LC_CODE_SIGNATURE command from the binary so that the signature isn’t checked at load time.

Detection:

Monitor processes for those that may be used to modify binary headers. Monitor file systems for changes to application binaries and invalid checksums/signatures. Changes to binaries that do not line up with application updates or patches are also extremely suspicious.

### T1546.007 - Event Triggered Execution: Netsh Helper DLL

Description:

Adversaries may establish persistence by executing malicious content triggered by Netsh Helper DLLs. Netsh.exe (also referred to as Netshell) is a command-line scripting utility used to interact with the network configuration of a system. It contains functionality to add helper DLLs for extending functionality of the utility. The paths to registered netsh.exe helper DLLs are entered into the Windows Registry at HKLM\SOFTWARE\Microsoft\Netsh. Adversaries can use netsh.exe helper DLLs to trigger execution of arbitrary code in a persistent manner. This execution would take place anytime netsh.exe is executed, which could happen automatically, with another persistence technique, or if other software (ex: VPN) is present on the system that executes netsh.exe as part of its normal functionality.

Detection:

It is likely unusual for netsh.exe to have any child processes in most environments. Monitor process executions and investigate any child processes spawned by netsh.exe for malicious behavior. Monitor the HKLM\SOFTWARE\Microsoft\Netsh registry key for any new or suspicious entries that do not correlate with known system files or benign software.

Procedures:

- [S0108] netsh: netsh can be used as a persistence proxy technique to execute a helper DLL when netsh.exe is executed.

### T1546.008 - Event Triggered Execution: Accessibility Features

Description:

Adversaries may establish persistence and/or elevate privileges by executing malicious content triggered by accessibility features. Windows contains accessibility features that may be launched with a key combination before a user has logged in (ex: when the user is on the Windows logon screen). An adversary can modify the way these programs are launched to get a command prompt or backdoor without logging in to the system. Two common accessibility programs are C:\Windows\System32\sethc.exe, launched when the shift key is pressed five times and C:\Windows\System32\utilman.exe, launched when the Windows + U key combination is pressed. The sethc.exe program is often referred to as "sticky keys", and has been used by adversaries for unauthenticated access through a remote desktop login screen. Depending on the version of Windows, an adversary may take advantage of these features in different ways. Common methods used by adversaries include replacing accessibility feature binaries or pointers/references to these binaries in the Registry. In newer versions of Windows, the replaced binary needs to be digitally signed for x64 systems, the binary must reside in %systemdir%\, and it must be protected by Windows File or Resource Protection (WFP/WRP). The Image File Execution Options Injection debugger method was likely discovered as a potential workaround because it does not require the corresponding accessibility feature binary to be replaced. For simple binary replacement on Windows XP and later as well as and Windows Server 2003/R2 and later, for example, the program (e.g., C:\Windows\System32\utilman.exe) may be replaced with "cmd.exe" (or another program that provides backdoor access). Subsequently, pressing the appropriate key combination at the login screen while sitting at the keyboard or when connected over Remote Desktop Protocol will cause the replaced file to be executed with SYSTEM privileges. Other accessibility features exist that may also be leveraged in a similar fashion: * On-Screen Keyboard: C:\Windows\System32\osk.exe * Magnifier: C:\Windows\System32\Magnify.exe * Narrator: C:\Windows\System32\Narrator.exe * Display Switcher: C:\Windows\System32\DisplaySwitch.exe * App Switcher: C:\Windows\System32\AtBroker.exe

Detection:

Changes to accessibility utility binaries or binary paths that do not correlate with known software, patch cycles, etc., are suspicious. Command line invocation of tools capable of modifying the Registry for associated keys are also suspicious. Utility arguments and the binaries themselves should be monitored for changes. Monitor Registry keys within HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options.

Procedures:

- [S0363] Empire: Empire can leverage WMI debugging to remotely replace binaries like sethc.exe, Utilman.exe, and Magnify.exe with cmd.exe.
- [G0096] APT41: APT41 leveraged sticky keys to establish persistence.
- [G0022] APT3: APT3 replaces the Sticky Keys binary C:\Windows\System32\sethc.exe for persistence.
- [G0009] Deep Panda: Deep Panda has used the sticky-keys technique to bypass the RDP login screen on remote systems during intrusions.
- [G0001] Axiom: Axiom actors have been known to use the Sticky Keys replacement within RDP sessions to obtain persistence.
- [G0117] Fox Kitten: Fox Kitten has used sticky keys to launch a command prompt.
- [G0016] APT29: APT29 used sticky-keys to obtain unauthenticated, privileged console access.

### T1546.009 - Event Triggered Execution: AppCert DLLs

Description:

Adversaries may establish persistence and/or elevate privileges by executing malicious content triggered by AppCert DLLs loaded into processes. Dynamic-link libraries (DLLs) that are specified in the AppCertDLLs Registry key under HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\ are loaded into every process that calls the ubiquitously used application programming interface (API) functions CreateProcess, CreateProcessAsUser, CreateProcessWithLoginW, CreateProcessWithTokenW, or WinExec. Similar to Process Injection, this value can be abused to obtain elevated privileges by causing a malicious DLL to be loaded and run in the context of separate processes on the computer. Malicious AppCert DLLs may also provide persistence by continuously being triggered by API activity.

Detection:

Monitor DLL loads by processes, specifically looking for DLLs that are not recognized or not normally loaded into a process. Monitor the AppCertDLLs Registry value for modifications that do not correlate with known software, patch cycles, etc. Monitor and analyze application programming interface (API) calls that are indicative of Registry edits such as RegCreateKeyEx and RegSetValueEx. Tools such as Sysinternals Autoruns may overlook AppCert DLLs as an auto-starting location. Look for abnormal process behavior that may be due to a process loading a malicious DLL. Data and events should not be viewed in isolation, but as part of a chain of behavior that could lead to other activities, such as making network connections for Command and Control, learning details about the environment through Discovery, and conducting Lateral Movement.

Procedures:

- [S0196] PUNCHBUGGY: PUNCHBUGGY can establish using a AppCertDLLs Registry key.

### T1546.010 - Event Triggered Execution: AppInit DLLs

Description:

Adversaries may establish persistence and/or elevate privileges by executing malicious content triggered by AppInit DLLs loaded into processes. Dynamic-link libraries (DLLs) that are specified in the AppInit_DLLs value in the Registry keys HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Windows or HKEY_LOCAL_MACHINE\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows are loaded by user32.dll into every process that loads user32.dll. In practice this is nearly every program, since user32.dll is a very common library. Similar to Process Injection, these values can be abused to obtain elevated privileges by causing a malicious DLL to be loaded and run in the context of separate processes on the computer. Malicious AppInit DLLs may also provide persistence by continuously being triggered by API activity. The AppInit DLL functionality is disabled in Windows 8 and later versions when secure boot is enabled.

Detection:

Monitor DLL loads by processes that load user32.dll and look for DLLs that are not recognized or not normally loaded into a process. Monitor the AppInit_DLLs Registry values for modifications that do not correlate with known software, patch cycles, etc. Monitor and analyze application programming interface (API) calls that are indicative of Registry edits such as RegCreateKeyEx and RegSetValueEx. Tools such as Sysinternals Autoruns may also be used to detect system changes that could be attempts at persistence, including listing current AppInit DLLs. Look for abnormal process behavior that may be due to a process loading a malicious DLL. Data and events should not be viewed in isolation, but as part of a chain of behavior that could lead to other activities, such as making network connections for Command and Control, learning details about the environment through Discovery, and conducting Lateral Movement.

Procedures:

- [G0087] APT39: APT39 has used malware to set LoadAppInit_DLLs in the Registry key SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows in order to establish persistence.
- [S0098] T9000: If a victim meets certain criteria, T9000 uses the AppInit_DLL functionality to achieve persistence by ensuring that every user mode process that is spawned will load its malicious DLL, ResN32.dll. It does this by creating the following Registry keys: HKLM\Software\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs – %APPDATA%\Intel\ResN32.dll and HKLM\Software\Microsoft\Windows NT\CurrentVersion\Windows\LoadAppInit_DLLs – 0x1.
- [S0107] Cherry Picker: Some variants of Cherry Picker use AppInit_DLLs to achieve persistence by creating the following Registry key: HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows "AppInit_DLLs"="pserver32.dll"
- [S0458] Ramsay: Ramsay can insert itself into the address space of other applications using the AppInit DLL Registry key.

### T1546.011 - Event Triggered Execution: Application Shimming

Description:

Adversaries may establish persistence and/or elevate privileges by executing malicious content triggered by application shims. The Microsoft Windows Application Compatibility Infrastructure/Framework (Application Shim) was created to allow for backward compatibility of software as the operating system codebase changes over time. For example, the application shimming feature allows developers to apply fixes to applications (without rewriting code) that were created for Windows XP so that it will work with Windows 10. Within the framework, shims are created to act as a buffer between the program (or more specifically, the Import Address Table) and the Windows OS. When a program is executed, the shim cache is referenced to determine if the program requires the use of the shim database (.sdb). If so, the shim database uses hooking to redirect the code as necessary in order to communicate with the OS. A list of all shims currently installed by the default Windows installer (sdbinst.exe) is kept in: * %WINDIR%\AppPatch\sysmain.sdb and * hklm\software\microsoft\windows nt\currentversion\appcompatflags\installedsdb Custom databases are stored in: * %WINDIR%\AppPatch\custom & %WINDIR%\AppPatch\AppPatch64\Custom and * hklm\software\microsoft\windows nt\currentversion\appcompatflags\custom To keep shims secure, Windows designed them to run in user mode so they cannot modify the kernel and you must have administrator privileges to install a shim. However, certain shims can be used to Bypass User Account Control (UAC and RedirectEXE), inject DLLs into processes (InjectDLL), disable Data Execution Prevention (DisableNX) and Structure Exception Handling (DisableSEH), and intercept memory addresses (GetProcAddress). Utilizing these shims may allow an adversary to perform several malicious acts such as elevate privileges, install backdoors, disable defenses like Windows Defender, etc. Shims can also be abused to establish persistence by continuously being invoked by affected programs.

Detection:

There are several public tools available that will detect shims that are currently available : * Shim-Process-Scanner - checks memory of every running process for any shim flags * Shim-Detector-Lite - detects installation of custom shim databases * Shim-Guard - monitors registry for any shim installations * ShimScanner - forensic tool to find active shims in memory * ShimCacheMem - Volatility plug-in that pulls shim cache from memory (note: shims are only cached after reboot) Monitor process execution for sdbinst.exe and command-line arguments for potential indications of application shim abuse.

Procedures:

- [S0517] Pillowmint: Pillowmint has used a malicious shim database to maintain persistence.
- [S0461] SDBbot: SDBbot has the ability to use application shimming for persistence if it detects it is running as admin on Windows XP or 7, by creating a shim database to patch services.exe.
- [G0046] FIN7: FIN7 has used application shim databases for persistence.
- [S0444] ShimRat: ShimRat has installed shim databases in the AppPatch folder.

### T1546.012 - Event Triggered Execution: Image File Execution Options Injection

Description:

Adversaries may establish persistence and/or elevate privileges by executing malicious content triggered by Image File Execution Options (IFEO) debuggers. IFEOs enable a developer to attach a debugger to an application. When a process is created, a debugger present in an application’s IFEO will be prepended to the application’s name, effectively launching the new process under the debugger (e.g., C:\dbg\ntsd.exe -g notepad.exe). IFEOs can be set directly via the Registry or in Global Flags via the GFlags tool. IFEOs are represented as Debugger values in the Registry under HKLM\SOFTWARE{\Wow6432Node}\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ where &lt;executable&gt; is the binary on which the debugger is attached. IFEOs can also enable an arbitrary monitor program to be launched when a specified program silently exits (i.e. is prematurely terminated by itself or a second, non kernel-mode process). Similar to debuggers, silent exit monitoring can be enabled through GFlags and/or by directly modifying IFEO and silent process exit Registry values in HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\. Similar to Accessibility Features, on Windows Vista and later as well as Windows Server 2008 and later, a Registry key may be modified that configures "cmd.exe," or another program that provides backdoor access, as a "debugger" for an accessibility program (ex: utilman.exe). After the Registry is modified, pressing the appropriate key combination at the login screen while at the keyboard or when connected with Remote Desktop Protocol will cause the "debugger" program to be executed with SYSTEM privileges. Similar to Process Injection, these values may also be abused to obtain privilege escalation by causing a malicious executable to be loaded and run in the context of separate processes on the computer. Installing IFEO mechanisms may also provide Persistence via continuous triggered invocation. Malware may also use IFEO to Impair Defenses by registering invalid debuggers that redirect and effectively disable various system and security applications.

Detection:

Monitor for abnormal usage of the GFlags tool as well as common processes spawned under abnormal parents and/or with creation flags indicative of debugging such as DEBUG_PROCESS and DEBUG_ONLY_THIS_PROCESS. Monitor Registry values associated with IFEOs, as well as silent process exit monitoring, for modifications that do not correlate with known software, patch cycles, etc. Monitor and analyze application programming interface (API) calls that are indicative of Registry edits such as RegCreateKeyEx and RegSetValueEx.

Procedures:

- [S0559] SUNBURST: SUNBURST created an Image File Execution Options (IFEO) Debugger registry value for the process dllhost.exe to trigger the installation of Cobalt Strike.
- [S0461] SDBbot: SDBbot has the ability to use image file execution options for persistence if it detects it is running with admin privileges on a Windows version newer than Windows 7.
- [C0032] C0032: During the C0032 campaign, TEMP.Veles modified and added entries within HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options to maintain persistence.

### T1546.013 - Event Triggered Execution: PowerShell Profile

Description:

Adversaries may gain persistence and elevate privileges by executing malicious content triggered by PowerShell profiles. A PowerShell profile (profile.ps1) is a script that runs when PowerShell starts and can be used as a logon script to customize user environments. PowerShell supports several profiles depending on the user or host program. For example, there can be different profiles for PowerShell host programs such as the PowerShell console, PowerShell ISE or Visual Studio Code. An administrator can also configure a profile that applies to all users and host programs on the local computer. Adversaries may modify these profiles to include arbitrary commands, functions, modules, and/or PowerShell drives to gain persistence. Every time a user opens a PowerShell session the modified script will be executed unless the -NoProfile flag is used when it is launched. An adversary may also be able to escalate privileges if a script in a PowerShell profile is loaded and executed by an account with higher privileges, such as a domain administrator.

Detection:

Locations where profile.ps1 can be stored should be monitored for new profiles or modifications. Example profile locations (user defaults as well as program-specific) include: * $PsHome\Profile.ps1 * $PsHome\Microsoft.{HostProgram}_profile.ps1 * $Home\\\[My ]Documents\PowerShell\Profile.ps1 * $Home\\\[My ]Documents\PowerShell\Microsoft.{HostProgram}_profile.ps1 Monitor abnormal PowerShell commands, unusual loading of PowerShell drives or modules, and/or execution of unknown programs.

Procedures:

- [G0010] Turla: Turla has used PowerShell profiles to maintain persistence on an infected machine.

### T1546.014 - Event Triggered Execution: Emond

Description:

Adversaries may gain persistence and elevate privileges by executing malicious content triggered by the Event Monitor Daemon (emond). Emond is a Launch Daemon that accepts events from various services, runs them through a simple rules engine, and takes action. The emond binary at /sbin/emond will load any rules from the /etc/emond.d/rules/ directory and take action once an explicitly defined event takes place. The rule files are in the plist format and define the name, event type, and action to take. Some examples of event types include system startup and user authentication. Examples of actions are to run a system command or send an email. The emond service will not launch if there is no file present in the QueueDirectories path /private/var/db/emondClients, specified in the Launch Daemon configuration file at/System/Library/LaunchDaemons/com.apple.emond.plist. Adversaries may abuse this service by writing a rule to execute commands when a defined event occurs, such as system start up or user authentication. Adversaries may also be able to escalate privileges from administrator to root as the emond service is executed with root privileges by the Launch Daemon service.

Detection:

Monitor emond rules creation by checking for files created or modified in /etc/emond.d/rules/ and /private/var/db/emondClients.

### T1546.015 - Event Triggered Execution: Component Object Model Hijacking

Description:

Adversaries may establish persistence by executing malicious content triggered by hijacked references to Component Object Model (COM) objects. COM is a system within Windows to enable interaction between software components through the operating system. References to various COM objects are stored in the Registry. Adversaries can use the COM system to insert malicious code that can be executed in place of legitimate software through hijacking the COM references and relationships as a means for persistence. Hijacking a COM object requires a change in the Registry to replace a reference to a legitimate system component which may cause that component to not work when executed. When that system component is executed through normal system operation the adversary's code will be executed instead. An adversary is likely to hijack objects that are used frequently enough to maintain a consistent level of persistence, but are unlikely to break noticeable functionality within the system as to avoid system instability that could lead to detection.

Detection:

There are opportunities to detect COM hijacking by searching for Registry references that have been replaced and through Registry operations (ex: Reg) replacing known binary paths with unknown paths or otherwise malicious content. Even though some third-party applications define user COM objects, the presence of objects within HKEY_CURRENT_USER\Software\Classes\CLSID\ may be anomalous and should be investigated since user objects will be loaded prior to machine objects in HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\. Registry entries for existing COM objects may change infrequently. When an entry with a known good path and binary is replaced or changed to an unusual value to point to an unknown binary in a new location, then it may indicate suspicious behavior and should be investigated. Likewise, if software DLL loads are collected and analyzed, any unusual DLL load that can be correlated with a COM object Registry modification may indicate COM hijacking has been performed.

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

Description:

Adversaries may establish persistence and elevate privileges by using an installer to trigger the execution of malicious content. Installer packages are OS specific and contain the resources an operating system needs to install applications on a system. Installer packages can include scripts that run prior to installation as well as after installation is complete. Installer scripts may inherit elevated permissions when executed. Developers often use these scripts to prepare the environment for installation, check requirements, download dependencies, and remove files after installation. Using legitimate applications, adversaries have distributed applications with modified installer scripts to execute malicious content. When a user installs the application, they may be required to grant administrative permissions to allow the installation. At the end of the installation process of the legitimate application, content such as macOS `postinstall` scripts can be executed with the inherited elevated permissions. Adversaries can use these scripts to execute a malicious executable or install other malicious components (such as a Launch Daemon) with the elevated permissions. Depending on the distribution, Linux versions of package installer scripts are sometimes called maintainer scripts or post installation scripts. These scripts can include `preinst`, `postinst`, `prerm`, `postrm` scripts and run as root when executed. For Windows, the Microsoft Installer services uses `.msi` files to manage the installing, updating, and uninstalling of applications. These installation routines may also include instructions to perform additional actions that may be abused by adversaries.

Procedures:

- [S0584] AppleJeus: During AppleJeus's installation process, it uses `postinstall` scripts to extract a hidden plist from the application's `/Resources` folder and execute the `plist` file as a Launch Daemon with elevated permissions.

### T1546.017 - Event Triggered Execution: Udev Rules

Description:

Adversaries may maintain persistence through executing malicious content triggered using udev rules. Udev is the Linux kernel device manager that dynamically manages device nodes, handles access to pseudo-device files in the `/dev` directory, and responds to hardware events, such as when external devices like hard drives or keyboards are plugged in or removed. Udev uses rule files with `match keys` to specify the conditions a hardware event must meet and `action keys` to define the actions that should follow. Root permissions are required to create, modify, or delete rule files located in `/etc/udev/rules.d/`, `/run/udev/rules.d/`, `/usr/lib/udev/rules.d/`, `/usr/local/lib/udev/rules.d/`, and `/lib/udev/rules.d/`. Rule priority is determined by both directory and by the digit prefix in the rule filename. Adversaries may abuse the udev subsystem by adding or modifying rules in udev rule files to execute malicious content. For example, an adversary may configure a rule to execute their binary each time the pseudo-device file, such as `/dev/random`, is accessed by an application. Although udev is limited to running short tasks and is restricted by systemd-udevd's sandbox (blocking network and filesystem access), attackers may use scripting commands under the action key `RUN+=` to detach and run the malicious content’s process in the background to bypass these controls.

Detection:

Monitor file creation and modification of Udev rule files in `/etc/udev/rules.d/`, `/lib/udev/rules.d/`, and /usr/lib/udev/rules.d/, specifically the `RUN` action key commands.


### T1547.001 - Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder

Description:

Adversaries may achieve persistence by adding a program to a startup folder or referencing it with a Registry run key. Adding an entry to the "run keys" in the Registry or startup folder will cause the program referenced to be executed when a user logs in. These programs will be executed under the context of the user and will have the account's associated permissions level. The following run keys are created by default on Windows systems: * HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run * HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce * HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run * HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce Run keys may exist under multiple hives. The HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnceEx is also available but is not created by default on Windows Vista and newer. Registry run key entries can reference programs directly or list them as a dependency. For example, it is possible to load a DLL at logon using a "Depend" key with RunOnceEx: reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx\0001\Depend /v 1 /d "C:\temp\evil[.]dll" Placing a program within a startup folder will also cause that program to execute when a user logs in. There is a startup folder location for individual user accounts as well as a system-wide startup folder that will be checked regardless of which user account logs in. The startup folder path for the current user is C:\Users\\[Username]\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup. The startup folder path for all users is C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp. The following Registry keys can be used to set startup folder items for persistence: * HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders * HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders * HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders * HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders The following Registry keys can control automatic startup of services during boot: * HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce * HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce * HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunServices * HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunServices Using policy settings to specify startup programs creates corresponding values in either of two Registry keys: * HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run * HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run Programs listed in the load value of the registry key HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\Windows run automatically for the currently logged-on user. By default, the multistring BootExecute value of the registry key HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager is set to autocheck autochk *. This value causes Windows, at startup, to check the file-system integrity of the hard disks if the system has been shut down abnormally. Adversaries can add other programs or processes to this registry value which will automatically launch at boot. Adversaries can use these configuration locations to execute malware, such as remote access tools, to maintain persistence through system reboots. Adversaries may also use Masquerading to make the Registry entries look as if they are associated with legitimate programs.

Detection:

Monitor Registry for changes to run keys that do not correlate with known software, patch cycles, etc. Monitor the start folder for additions or changes. Tools such as Sysinternals Autoruns may also be used to detect system changes that could be attempts at persistence, including listing the run keys' Registry locations and startup folders. Suspicious program execution as startup programs may show up as outlier processes that have not been seen before when compared against historical data. Changes to these locations typically happen under normal conditions when legitimate software is installed. To increase confidence of malicious activity, data and events should not be viewed in isolation, but as part of a chain of behavior that could lead to other activities, such as network connections made for Command and Control, learning details about the environment through Discovery, and Lateral Movement.

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
- [S1029] AuTo Stealer: AuTo Stealer can place malicious executables in a victim's AutoRun registry key or StartUp directory, depending on the AV product installed, to maintain persistence.
- [G1046] Storm-1811: Storm-1811 has created Windows Registry Run keys that execute various batch scripts to establish persistence on victim devices.
- [S0090] Rover: Rover persists by creating a Registry entry in HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\.
- [S0182] FinFisher: FinFisher establishes persistence by creating the Registry key HKCU\Software\Microsoft\Windows\Run.
- [S0670] WarzoneRAT: WarzoneRAT can add itself to the `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` and `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UIF2IS20VK` Registry keys.
- [S0449] Maze: Maze has created a file named "startup_vrun.bat" in the Startup folder of a virtual machine to establish persistence.
- [S0355] Final1stspy: Final1stspy creates a Registry Run key to establish persistence.
- [S0337] BadPatch: BadPatch establishes a foothold by adding a link to the malware executable in the startup folder.
- [G0100] Inception: Inception has maintained persistence by modifying Registry run key value HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run\.
- [S1199] LockBit 2.0: LockBit 2.0 can use a Registry Run key to establish persistence at startup.
- [C0022] Operation Dream Job: During Operation Dream Job, Lazarus Group placed LNK files into the victims' startup folder for persistence.
- [G0007] APT28: APT28 has deployed malware that has copied itself to the startup directory for persistence.
- [G0139] TeamTNT: TeamTNT has added batch scripts to the startup folder.
- [S0332] Remcos: Remcos can add itself to the Registry key HKCU\Software\Microsoft\Windows\CurrentVersion\Run for persistence.
- [S0265] Kazuar: Kazuar adds a sub-key under several Registry run keys.
- [S0568] EVILNUM: EVILNUM can achieve persistence through the Registry Run key.
- [S0389] JCry: JCry has created payloads in the Startup directory to maintain persistence.
- [S0338] Cobian RAT: Cobian RAT creates an autostart Registry key to ensure persistence.
- [S0012] PoisonIvy: PoisonIvy creates run key Registry entries pointing to a malicious executable dropped to disk.
- [S0484] Carberp: Carberp has maintained persistence by placing itself inside the current user's startup folder.
- [S0532] Lucifer: Lucifer can persist by setting Registry key values HKLM\Software\Microsoft\Windows\CurrentVersion\Run\QQMusic and HKCU\Software\Microsoft\Windows\CurrentVersion\Run\QQMusic.
- [S0632] GrimAgent: GrimAgent can set persistence with a Registry run key.
- [S0070] HTTPBrowser: HTTPBrowser has established persistence by setting the HKCU\Software\Microsoft\Windows\CurrentVersion\Run key value for wdm to the path of the executable. It has also used the Registry entry HKEY_USERS\Software\Microsoft\Windows\CurrentVersion\Run vpdn “%ALLUSERPROFILE%\%APPDATA%\vpdn\VPDN_LU.exe” to establish persistence.
- [S0665] ThreatNeedle: ThreatNeedle can be loaded into the Startup folder (`%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\OneDrives.lnk`) as a Shortcut file for persistence.
- [S1212] RansomHub: RansomHub has created an autorun Registry key through the `-safeboot-instance -pass` command line argument.
- [S0045] ADVSTORESHELL: ADVSTORESHELL achieves persistence by adding itself to the HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run Registry key.
- [G0065] Leviathan: Leviathan has used JavaScript to create a shortcut file in the Startup folder that points to its main backdoor.
- [S0170] Helminth: Helminth establishes persistence by creating a shortcut in the Start Menu folder.
- [G0019] Naikon: Naikon has modified a victim's Windows Run registry to establish persistence.
- [S1066] DarkTortilla: DarkTortilla has established persistence via the `Software\Microsoft\Windows NT\CurrentVersion\Run` registry key and by creating a .lnk shortcut file in the Windows startup folder.
- [S0650] QakBot: QakBot can maintain persistence by creating an auto-run Registry key.
- [G0091] Silence: Silence has used HKCU\Software\Microsoft\Windows\CurrentVersion\Run, HKLM\Software\Microsoft\Windows\CurrentVersion\Run, and the Startup folder to establish persistence.
- [S0666] Gelsemium: Gelsemium can set persistence with a Registry run key.
- [S1130] Raspberry Robin: Raspberry Robin will use a Registry key to achieve persistence through reboot, setting a RunOnce key such as: HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce {random value name} = “rundll32 shell32 ShellExec_RunDLLA REGSVR /u /s “{dropped copy path and file name}”” .
- [S0144] ChChes: ChChes establishes persistence by adding a Registry Run key.
- [S0168] Gazer: Gazer can establish persistence by creating a .lnk file in the Start menu.
- [G0078] Gorgon Group: Gorgon Group malware can create a .lnk file and add a Registry Run key to establish persistence.
- [S0115] Crimson: Crimson can add Registry run keys for persistence.
- [S0367] Emotet: Emotet has been observed adding the downloaded payload to the HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run key to maintain persistence.
- [S0046] CozyCar: One persistence mechanism used by CozyCar is to set itself to be executed at system startup by adding a Registry value under one of the following Registry keys: HKLM\Software\Microsoft\Windows\CurrentVersion\Run\ HKCU\Software\Microsoft\Windows\CurrentVersion\Run\ HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run
- [S0341] Xbash: Xbash can create a Startup item for persistence if it determines it is on a Windows system.
- [S0260] InvisiMole: InvisiMole can place a lnk file in the Startup Folder to achieve persistence.
- [G0016] APT29: APT29 added Registry Run keys to establish persistence.
- [S0546] SharpStage: SharpStage has the ability to create persistence for the malware using the Registry autorun key and startup folder.
- [S0660] Clambling: Clambling can establish persistence by adding a Registry run key.
- [S0148] RTM: RTM tries to add a Registry Run key under the name "Windows Update" to establish persistence.
- [S0074] Sakula: Most Sakula samples maintain persistence by setting the Registry Run key SOFTWARE\Microsoft\Windows\CurrentVersion\Run\ in the HKLM or HKCU hive, with the Registry value and file name varying by sample.
- [G0128] ZIRCONIUM: ZIRCONIUM has created a Registry Run key named Dropbox Update Setup to establish persistence for a malicious Python binary.
- [S0172] Reaver: Reaver creates a shortcut file and saves it in a Startup folder to establish persistence.
- [S0262] QuasarRAT: If the QuasarRAT client process does not have administrator privileges it will add a registry key to `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` for persistence.
- [S0036] FLASHFLOOD: FLASHFLOOD achieves persistence by making an entry in the Registry's Run key.
- [S0397] LoJax: LoJax has modified the Registry key ‘HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\BootExecute’ from ‘autocheck autochk *’ to ‘autocheck autoche *’ in order to execute its payload during Windows startup.
- [G0040] Patchwork: Patchwork has added the path of its second-stage malware to the startup folder to achieve persistence. One of its file stealers has also persisted by adding a Registry Run key.
- [S1138] Gootloader: Gootloader can create an autorun entry for a PowerShell script to run at reboot.
- [S1037] STARWHALE: STARWHALE can establish persistence by installing itself in the startup folder, whereas the GO variant has created a `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\OutlookM` registry key.
- [S0381] FlawedAmmyy: FlawedAmmyy has established persistence via the `HKCU\SOFTWARE\microsoft\windows\currentversion\run` registry key.
- [S0147] Pteranodon: Pteranodon copies itself to the Startup folder to establish persistence.
- [S0652] MarkiRAT: MarkiRAT can drop its payload into the Startup directory to ensure it automatically runs when the compromised system is started.
- [S0167] Matryoshka: Matryoshka can establish persistence by adding Registry Run keys.
- [S1111] DarkGate: DarkGate installation includes AutoIt script execution creating a shortcut to itself as an LNK object, such as bill.lnk, in the victim startup folder. DarkGate installation finishes with the creation of a registry Run key.
- [S0356] KONNI: A version of KONNI has dropped a Windows shortcut into the Startup folder to establish persistence.
- [S0207] Vasport: Vasport copies itself to disk and creates an associated run key Registry entry to establish.
- [S0644] ObliqueRAT: ObliqueRAT can gain persistence by a creating a shortcut in the infected user's Startup directory.
- [S0015] Ixeshe: Ixeshe can achieve persistence by adding itself to the HKCU\Software\Microsoft\Windows\CurrentVersion\Run Registry key.
- [S0127] BBSRAT: BBSRAT has been loaded through DLL side-loading of a legitimate Citrix executable that is set to persist through the Registry Run key location HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\ssonsvr.exe.
- [G0037] FIN6: FIN6 has used Registry Run keys to establish persistence for its downloader tools known as HARDTACK and SHIPBREAD.
- [S0455] Metamorfo: Metamorfo has configured persistence to the Registry key HKCU\Software\Microsoft\Windows\CurrentVersion\Run, Spotify =% APPDATA%\Spotify\Spotify.exe and used .LNK files in the startup folder to achieve persistence.
- [S1053] AvosLocker: AvosLocker has been executed via the `RunOnce` Registry key to run itself on safe mode.
- [S1086] Snip3: Snip3 can create a VBS file in startup to persist after system restarts.
- [S0087] Hi-Zor: Hi-Zor creates a Registry Run key to establish persistence.
- [G0010] Turla: A Turla Javascript backdoor added a local_update_check value under the Registry key HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run to establish persistence. Additionally, a Turla custom executable containing Metasploit shellcode is saved to the Startup folder to gain persistence.
- [S0226] Smoke Loader: Smoke Loader adds a Registry Run key for persistence and adds a script in the Startup folder to deploy the payload.
- [S0471] build_downer: build_downer has the ability to add itself to the Registry Run key for persistence.
- [S0433] Rifdoor: Rifdoor has created a new registry entry at HKEY_CURRENT_USERS\Software\Microsoft\Windows\CurrentVersion\Run\Graphics with a value of C:\ProgramData\Initech\Initech.exe /run.
- [S0630] Nebulae: Nebulae can achieve persistence through a Registry Run key.
- [S0353] NOKKI: NOKKI has established persistence by writing the payload to the Registry key HKCU\Software\Microsoft\Windows\CurrentVersion\Run.
- [S0531] Grandoreiro: Grandoreiro can use run keys and create link files in the startup folder for persistence.
- [G0024] Putter Panda: A dropper used by Putter Panda installs itself into the ASEP Registry key HKCU\Software\Microsoft\Windows\CurrentVersion\Run with a value named McUpdate.
- [S0196] PUNCHBUGGY: PUNCHBUGGY has been observed using a Registry Run key.
- [G0069] MuddyWater: MuddyWater has added Registry Run key KCU\Software\Microsoft\Windows\CurrentVersion\Run\SystemTextEncoding to establish persistence.
- [S0178] Truvasys: Truvasys adds a Registry Run key to establish persistence.
- [S0499] Hancitor: Hancitor has added Registry Run keys to establish persistence.
- [S0094] Trojan.Karagany: Trojan.Karagany can create a link to itself in the Startup folder to automatically start itself upon system restart.
- [S0080] Mivast: Mivast creates the following Registry entry: HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Micromedia.
- [S0136] USBStealer: USBStealer registers itself under a Registry Run key with the name "USB Disk Security."
- [S0141] Winnti for Windows: Winnti for Windows can add a service named wind0ws to the Registry to achieve persistence after reboot.
- [S0044] JHUHUGIT: JHUHUGIT has used a Registry Run key to establish persistence by executing JavaScript code within the rundll32.exe process.
- [S0553] MoleNet: MoleNet can achieve persitence on the infected machine by setting the Registry run key.
- [G0121] Sidewinder: Sidewinder has added paths to executables in the Registry to establish persistence.
- [S0570] BitPaymer: BitPaymer has set the run key HKCU\Software\Microsoft\Windows\CurrentVersion\Run for persistence.
- [S0512] FatDuke: FatDuke has used HKLM\SOFTWARE\Microsoft\CurrentVersion\Run to establish persistence.
- [S0513] LiteDuke: LiteDuke can create persistence by adding a shortcut in the CurrentVersion\Run Registry key.
- [S0034] NETEAGLE: The "SCOUT" variant of NETEAGLE achieves persistence by adding itself to the HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run Registry key.
- [C0047] RedDelta Modified PlugX Infection Chain Operations: Mustang Panda used Run registry keys with names such as `OneNote Update` to execute legitimate executables that would load through search-order hijacking malicious DLLS to ensure persistence during RedDelta Modified PlugX Infection Chain Operations.
- [S0382] ServHelper: ServHelper may attempt to establish persistence via the HKCU\Software\Microsoft\Windows\CurrentVersion\Run\ run key.
- [S0444] ShimRat: ShimRat has installed a registry based start-up key HKCU\Software\microsoft\windows\CurrentVersion\Run to maintain persistence should other methods fail.
- [G0027] Threat Group-3390: Threat Group-3390's malware can add a Registry key to `Software\Microsoft\Windows\CurrentVersion\Run` for persistence.
- [S0375] Remexi: Remexi utilizes Run Registry keys in the HKLM hive as a persistence mechanism.
- [S0035] SPACESHIP: SPACESHIP achieves persistence by creating a shortcut in the current user's Startup folder.
- [G0081] Tropic Trooper: Tropic Trooper has created shortcuts in the Startup folder to establish persistence.
- [G0032] Lazarus Group: Lazarus Group has maintained persistence by loading malicious code into a startup folder or by adding a Registry Run key.
- [G0096] APT41: APT41 created and modified startup files for persistence. APT41 added a registry key in HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Svchost to establish persistence for Cobalt Strike.
- [G0112] Windshift: Windshift has created LNK files in the Startup folder to establish persistence.
- [S1122] Mispadu: Mispadu creates a link in the startup folder for persistence. Mispadu adds persistence via the registry key `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`.
- [S0363] Empire: Empire can modify the registry run keys HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run and HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run for persistence.
- [S1041] Chinoxy: Chinoxy has established persistence via the `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` registry key and by loading a dropper to `(%COMMON_ STARTUP%\\eoffice.exe)`.
- [S1035] Small Sieve: Small Sieve has the ability to add itself to `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\OutlookMicrosift` for persistence.
- [S0649] SMOKEDHAM: SMOKEDHAM has used reg.exe to create a Registry Run key.
- [S0461] SDBbot: SDBbot has the ability to add a value to the Registry Run key to establish persistence if it detects it is running with regular user privilege.
- [G0046] FIN7: FIN7 malware has created Registry Run and RunOnce keys to establish persistence, and has also added items to the Startup folder.
- [G0070] Dark Caracal: Dark Caracal's version of Bandook adds a registry key to HKEY_USERS\Software\Microsoft\Windows\CurrentVersion\Run for persistence.
- [S0249] Gold Dragon: Gold Dragon establishes persistence in the Startup folder.
- [S0131] TINYTYPHON: TINYTYPHON installs itself under Registry Run key to establish persistence.
- [G0051] FIN10: FIN10 has established persistence by using the Registry option in PowerShell Empire to add a Run key.
- [S0456] Aria-body: Aria-body has established persistence via the Startup folder or Run Registry key.
- [G0056] PROMETHIUM: PROMETHIUM has used Registry run keys to establish persistence.
- [S0441] PowerShower: PowerShower sets up persistence with a Registry run key.
- [S0647] Turian: Turian can establish persistence by adding Registry Run keys.
- [S0204] Briba: Briba creates run key Registry entries pointing to malicious DLLs dropped to disk.
- [S0194] PowerSploit: PowerSploit's New-UserPersistenceOption Persistence argument can be used to establish via the HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run Registry key.
- [S0268] Bisonal: Bisonal has added itself to the Registry key HKEY_CURRENT_USER\Software\Microsoft\CurrentVersion\Run\ for persistence.
- [S0253] RunningRAT: RunningRAT adds itself to the Registry key Software\Microsoft\Windows\CurrentVersion\Run to establish persistence upon reboot.
- [S0586] TAINTEDSCRIBE: TAINTEDSCRIBE can copy itself into the current user’s Startup folder as “Narrator.exe” for persistence.
- [S0409] Machete: Machete used the startup folder for persistence.
- [S0235] CrossRAT: CrossRAT uses run keys for persistence on Windows.
- [S0031] BACKSPACE: BACKSPACE achieves persistence by creating a shortcut to itself in the CSIDL_STARTUP directory.
- [S1213] Lumma Stealer: Lumma Stealer has created registry keys to maintain persistence using `HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`.
- [S0186] DownPaper: DownPaper uses PowerShell to add a Registry Run key in order to establish persistence.
- [S0088] Kasidet: Kasidet creates a Registry Run key to establish persistence.
- [S0696] Flagpro: Flagpro has dropped an executable file to the startup directory.
- [S0340] Octopus: Octopus achieved persistence by placing a malicious executable in the startup directory and has added the HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run key to the Registry.
- [S0385] njRAT: njRAT has added persistence via the Registry key HKCU\Software\Microsoft\CurrentVersion\Run\ and dropped a shortcut in %STARTUP%.
- [G1014] LuminousMoth: LuminousMoth has used malicious DLLs that setup persistence in the Registry Key `HKCU\Software\Microsoft\Windows\Current Version\Run`.
- [S1021] DnsSystem: DnsSystem can write itself to the Startup folder to gain persistence.
- [S0251] Zebrocy: Zebrocy creates an entry in a Registry Run key for the malware to execute on startup.
- [S0058] SslMM: To establish persistence, SslMM identifies the Start Menu Startup directory and drops a link to its own executable disguised as an “Office Start,” “Yahoo Talk,” “MSN Gaming Z0ne,” or “MSN Talk” shortcut.
- [S0128] BADNEWS: BADNEWS installs a registry Run key to establish persistence.
- [S0608] Conficker: Conficker adds Registry Run keys to establish persistence.
- [S1074] ANDROMEDA: ANDROMEDA can establish persistence by dropping a sample of itself to `C:\ProgramData\Local Settings\Temp\mskmde.com` and adding a Registry run key to execute every time a user logs on.
- [S0582] LookBack: LookBack sets up a Registry Run key to establish a persistence mechanism.
- [S0458] Ramsay: Ramsay has created Registry Run keys to establish persistence.
- [S1150] ROADSWEEP: ROADSWEEP has been placed in the start up folder to trigger execution upon user login.
- [S0250] Koadic: Koadic has added persistence to the `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run` Registry key.
- [G1016] FIN13: FIN13 has used Windows Registry run keys such as, `HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run\hosts` to maintain persistence.
- [S0062] DustySky: DustySky achieves persistence by creating a Registry entry in HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run.
- [S0030] Carbanak: Carbanak stores a configuration files in the startup directory to automatically execute commands in order to persist across reboots.
- [G1036] Moonstone Sleet: Moonstone Sleet used registry run keys for process execution during initial victim infection.
- [S0442] VBShower: VBShower used HKCU\Software\Microsoft\Windows\CurrentVersion\Run\\[a-f0-9A-F]{8} to maintain persistence.
- [G0106] Rocke: Rocke's miner has created UPX-packed files in the Windows Start Menu Folder.
- [S0013] PlugX: PlugX adds Run key entries in the Registry to establish persistence.
- [S0631] Chaes: Chaes has added persistence via the Registry key software\microsoft\windows\currentversion\run\microsoft windows html help.
- [S1018] Saint Bot: Saint Bot has established persistence by being copied to the Startup directory or through the `\Software\Microsoft\Windows\CurrentVersion\Run` registry key.
- [G0021] Molerats: Molerats saved malicious files within the AppData and Startup folders to maintain persistence.
- [S0662] RCSession: RCSession has the ability to modify a Registry Run key to establish persistence.
- [S0032] gh0st RAT: gh0st RAT has added a Registry Run key to establish persistence.
- [S0414] BabyShark: BabyShark has added a Registry key to ensure all future macros are enabled for Microsoft Word and Excel as well as for additional persistence.
- [S0004] TinyZBot: TinyZBot can create a shortcut in the Windows startup folder for persistence.
- [S0334] DarkComet: DarkComet adds several Registry entries to enable automatic execution at every system startup.
- [S0145] POWERSOURCE: POWERSOURCE achieves persistence by setting a Registry Run key, with the path depending on whether the victim account has user or administrator access.
- [S1182] MagicRAT: MagicRAT can persist using malicious LNK objects in the victim machine Startup folder.
- [S0345] Seasalt: Seasalt creates a Registry entry to ensure infection after reboot under HKLM\Software\Microsoft\Windows\currentVersion\Run.
- [S1027] Heyoka Backdoor: Heyoka Backdoor can establish persistence with the auto start function including using the value `EverNoteTrayUService`.
- [S0247] NavRAT: NavRAT creates a Registry key to ensure a file gets executed upon reboot in order to establish persistence.
- [C0013] Operation Sharpshooter: During Operation Sharpshooter, a first-stage downloader installed Rising Sun to `%Startup%\mssync.exe` on a compromised host.
- [S0254] PLAINTEE: PLAINTEE gains persistence by adding the Registry key HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce.
- [S0259] InnaputRAT: Some InnaputRAT variants establish persistence by modifying the Registry key HKU\\Software\Microsoft\Windows\CurrentVersion\Run:%appdata%\NeutralApp\NeutralApp.exe.
- [S0053] SeaDuke: SeaDuke is capable of persisting via the Registry Run key or a .lnk file stored in the Startup directory.
- [G0080] Cobalt Group: Cobalt Group has used Registry Run keys for persistence. The group has also set a Startup path to launch the PowerShell shell command and download Cobalt Strike.
- [S0417] GRIFFON: GRIFFON has used a persistence module that stores the implant inside the Registry, which executes at logon.
- [G0129] Mustang Panda: Mustang Panda has created the registry key HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run\AdobelmdyU to maintain persistence.
- [G0126] Higaisa: Higaisa added a spoofed binary to the start-up folder for persistence.
- [S0018] Sykipot: Sykipot has been known to establish persistence by adding programs to the Run Registry key.
- [G0094] Kimsuky: Kimsuky has placed scripts in the startup folder for persistence and modified the `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce` Registry key.
- [S0113] Prikormka: Prikormka adds itself to a Registry Run key with the name guidVGA or guidVSA.
- [G0035] Dragonfly: Dragonfly has added the registry value ntdll to the Registry Run key to establish persistence.
- [S0159] SNUGRIDE: SNUGRIDE establishes persistence through a Registry Run key.
- [S0663] SysUpdate: SysUpdate can use a Registry Run key to establish persistence.
- [S0439] Okrum: Okrum establishes persistence by creating a .lnk shortcut to itself in the Startup folder.
- [S0483] IcedID: IcedID has established persistence by creating a Registry run key.
- [G0140] LazyScripter: LazyScripter has achieved persistence via writing a PowerShell script to the autorun registry key.
- [S0228] NanHaiShu: NanHaiShu modifies the %regrun% Registry to point itself to an autostart mechanism.
- [S0635] BoomBox: BoomBox can establish persistence by writing the Registry value MicroNativeCacheSvc to HKCU\Software\Microsoft\Windows\CurrentVersion\Run.
- [G0022] APT3: APT3 places scripts in the startup folder for persistence.
- [S0152] EvilGrab: EvilGrab adds a Registry Run key for ctfmon.exe to establish persistence.
- [S0089] BlackEnergy: The BlackEnergy 3 variant drops its main DLL component and then creates a .lnk shortcut to that file in the startup folder.
- [S1025] Amadey: Amadey has changed the Startup folder to the one containing its executable by overwriting the registry keys.
- [S0640] Avaddon: Avaddon uses registry run keys for persistence.
- [G0012] Darkhotel: Darkhotel has been known to establish persistence by adding programs to the Run Registry key.
- [S0561] GuLoader: GuLoader can establish persistence via the Registry under HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce.
- [S0085] S-Type: S-Type may create a .lnk file to itself that is saved in the Start menu folder. It may also create the Registry key HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\ IMJPMIJ8.1{3 characters of Unique Identifier}.
- [G0064] APT33: APT33 has deployed a tool known as DarkComet to the Startup folder of a victim, and used Registry run keys to gain persistence.
- [G0060] BRONZE BUTLER: BRONZE BUTLER has used a batch script that adds a Registry Run key to establish malware persistence.
- [S0192] Pupy: Pupy adds itself to the startup folder or adds itself to the Registry key SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run for persistence.
- [S0244] Comnie: Comnie achieves persistence by adding a shortcut of itself to the startup path in the Registry.
- [S0491] StrongPity: StrongPity can use the HKCU\Software\Microsoft\Windows\CurrentVersion\Run Registry key for persistence.
- [G1043] BlackByte: BlackByte has used Registry Run keys for persistence.
- [S1160] Latrodectus: Latrodectus can set an AutoRun key to establish persistence.
- [G1039] RedCurl: RedCurl has established persistence by creating entries in `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`.
- [S0330] Zeus Panda: Zeus Panda adds persistence by creating Registry Run keys.
- [G0004] Ke3chang: Several Ke3chang backdoors achieved persistence by adding a Run key.
- [S0137] CORESHELL: CORESHELL has established persistence by creating autostart extensibility point (ASEP) Registry entries in the Run key and other Registry keys, as well as by creating shortcuts in the Internet Explorer Quick Start folder.
- [S0336] NanoCore: NanoCore creates a RunOnce key in the Registry to execute its VBS scripts each time the user logs on to the machine.
- [S0692] SILENTTRINITY: SILENTTRINITY can establish a LNK file in the startup folder for persistence.
- [G0142] Confucius: Confucius has dropped malicious files into the startup folder `%AppData%\Microsoft\Windows\Start Menu\Programs\Startup` on a compromised host in order to maintain persistence.
- [S0348] Cardinal RAT: Cardinal RAT establishes Persistence by setting the HKCU\Software\Microsoft\Windows NT\CurrentVersion\Windows\Load Registry key to point to its executable.
- [S1145] Pikabot: Pikabot maintains persistence following system checks through the Run key in the registry.
- [S1207] XLoader: XLoader establishes persistence by copying its executable in a subdirectory of `%APPDATA%` or `%PROGRAMFILES%`, and then modifies Windows Registry Run keys or policies keys to execute the executable on system start.
- [S0446] Ryuk: Ryuk has used the Windows command line to create a Registry entry under HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Run to establish persistence.
- [S0622] AppleSeed: AppleSeed has the ability to create the Registry key name EstsoftAutoUpdate at HKCU\Software\Microsoft/Windows\CurrentVersion\RunOnce to establish persistence.
- [S0371] POWERTON: POWERTON can install a Registry Run key for persistence.
- [G0026] APT18: APT18 establishes persistence via the HKCU\Software\Microsoft\Windows\CurrentVersion\Run key.
- [S0256] Mosquito: Mosquito establishes persistence under the Registry key HKCU\Software\Run auto_update.
- [S0373] Astaroth: Astaroth creates a startup item for persistence.
- [S0428] PoetRAT: PoetRAT has added a registry key in the hive for persistence.
- [S0266] TrickBot: TrickBot establishes persistence in the Startup folder.
- [S0267] FELIXROOT: FELIXROOT adds a shortcut file to the startup folder for persistence.
- [S0153] RedLeaves: RedLeaves attempts to add a shortcut file in the Startup folder to achieve persistence. If this fails, it attempts to add Registry Run keys.
- [S0139] PowerDuke: PowerDuke achieves persistence by using various Registry Run keys.
- [S0669] KOCTOPUS: KOCTOPUS can set the AutoRun Registry key with a PowerShell command.
- [G0047] Gamaredon Group: Gamaredon Group tools have registered Run keys in the registry to give malicious VBS files persistence.
- [S0199] TURNEDUP: TURNEDUP is capable of writing to a Registry Run key to establish.
- [S0534] Bazar: Bazar can create or add files to Registry Run Keys to establish persistence.
- [S1026] Mongall: Mongall can establish persistence with the auto start function including using the value `EverNoteTrayUService`.
- [G0102] Wizard Spider: Wizard Spider has established persistence via the Registry key HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run and a shortcut within the startup folder.
- [G0050] APT32: APT32 established persistence using Registry Run keys, both to execute PowerShell and VBS scripts as well as to execute their backdoor directly.
- [S0500] MCMD: MCMD can use Registry Run Keys for persistence.
- [S0081] Elise: If establishing persistence by installation as a new service fails, one variant of Elise establishes persistence for the created .exe file by setting the following Registry key: HKCU\Software\Microsoft\Windows\CurrentVersion\Run\svchost : %APPDATA%\Microsoft\Network\svchost.exe. Other variants have set the following Registry keys for persistence: HKCU\Software\Microsoft\Windows\CurrentVersion\Run\imejp : [self] and HKCU\Software\Microsoft\Windows\CurrentVersion\Run\IAStorD.
- [S0011] Taidoor: Taidoor has modified the HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run key for persistence.
- [S0270] RogueRobin: RogueRobin created a shortcut in the Windows startup folder to launch a PowerShell script each time the user logs in to establish persistence.

### T1547.002 - Boot or Logon Autostart Execution: Authentication Package

Description:

Adversaries may abuse authentication packages to execute DLLs when the system boots. Windows authentication package DLLs are loaded by the Local Security Authority (LSA) process at system start. They provide support for multiple logon processes and multiple security protocols to the operating system. Adversaries can use the autostart mechanism provided by LSA authentication packages for persistence by placing a reference to a binary in the Windows Registry location HKLM\SYSTEM\CurrentControlSet\Control\Lsa\ with the key value of "Authentication Packages"=&lt;target binary&gt;. The binary will then be executed by the system when the authentication packages are loaded.

Detection:

Monitor the Registry for changes to the LSA Registry keys. Monitor the LSA process for DLL loads. Windows 8.1 and Windows Server 2012 R2 may generate events when unsigned DLLs try to load into the LSA by setting the Registry key HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\LSASS.exe with AuditLevel = 8.

Procedures:

- [S0143] Flame: Flame can use Windows Authentication Packages for persistence.

### T1547.003 - Boot or Logon Autostart Execution: Time Providers

Description:

Adversaries may abuse time providers to execute DLLs when the system boots. The Windows Time service (W32Time) enables time synchronization across and within domains. W32Time time providers are responsible for retrieving time stamps from hardware/network resources and outputting these values to other network clients. Time providers are implemented as dynamic-link libraries (DLLs) that are registered in the subkeys of `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\W32Time\TimeProviders\`. The time provider manager, directed by the service control manager, loads and starts time providers listed and enabled under this key at system startup and/or whenever parameters are changed. Adversaries may abuse this architecture to establish persistence, specifically by creating a new arbitrarily named subkey pointing to a malicious DLL in the `DllName` value. Administrator privileges are required for time provider registration, though execution will run in context of the Local Service account.

Detection:

Baseline values and monitor/analyze activity related to modifying W32Time information in the Registry, including application programming interface (API) calls such as RegCreateKeyEx and RegSetValueEx as well as execution of the W32tm.exe utility. There is no restriction on the number of custom time providers registrations, though each may require a DLL payload written to disk. The Sysinternals Autoruns tool may also be used to analyze auto-starting locations, including DLLs listed as time providers.

### T1547.004 - Boot or Logon Autostart Execution: Winlogon Helper DLL

Description:

Adversaries may abuse features of Winlogon to execute DLLs and/or executables when a user logs in. Winlogon.exe is a Windows component responsible for actions at logon/logoff as well as the secure attention sequence (SAS) triggered by Ctrl-Alt-Delete. Registry entries in HKLM\Software[\\Wow6432Node\\]\Microsoft\Windows NT\CurrentVersion\Winlogon\ and HKCU\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\ are used to manage additional helper programs and functionalities that support Winlogon. Malicious modifications to these Registry keys may cause Winlogon to load and execute malicious DLLs and/or executables. Specifically, the following subkeys have been known to be possibly vulnerable to abuse: * Winlogon\Notify - points to notification package DLLs that handle Winlogon events * Winlogon\Userinit - points to userinit.exe, the user initialization program executed when a user logs on * Winlogon\Shell - points to explorer.exe, the system shell executed when a user logs on Adversaries may take advantage of these features to repeatedly execute malicious code and establish persistence.

Detection:

Monitor for changes to Registry entries associated with Winlogon that do not correlate with known software, patch cycles, etc. Tools such as Sysinternals Autoruns may also be used to detect system changes that could be attempts at persistence, including listing current Winlogon helper values. New DLLs written to System32 that do not correlate with known good software or patching may also be suspicious. Look for abnormal process behavior that may be due to a process loading a malicious DLL. Data and events should not be viewed in isolation, but as part of a chain of behavior that could lead to other activities, such as network connections made for Command and Control, learning details about the environment through Discovery, and Lateral Movement.

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

Description:

Adversaries may abuse security support providers (SSPs) to execute DLLs when the system boots. Windows SSP DLLs are loaded into the Local Security Authority (LSA) process at system start. Once loaded into the LSA, SSP DLLs have access to encrypted and plaintext passwords that are stored in Windows, such as any logged-on user's Domain password or smart card PINs. The SSP configuration is stored in two Registry keys: HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages and HKLM\SYSTEM\CurrentControlSet\Control\Lsa\OSConfig\Security Packages. An adversary may modify these Registry keys to add new SSPs, which will be loaded the next time the system boots, or when the AddSecurityPackage Windows API function is called.

Detection:

Monitor the Registry for changes to the SSP Registry keys. Monitor the LSA process for DLL loads. Windows 8.1 and Windows Server 2012 R2 may generate events when unsigned SSP DLLs try to load into the LSA by setting the Registry key HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\LSASS.exe with AuditLevel = 8.

Procedures:

- [S0002] Mimikatz: The Mimikatz credential dumper contains an implementation of an SSP.
- [S0363] Empire: Empire can enumerate Security Support Providers (SSPs) as well as utilize PowerSploit's Install-SSP and Invoke-Mimikatz to install malicious SSPs and log authentication events.
- [S0194] PowerSploit: PowerSploit's Install-SSP Persistence module can be used to establish by installing a SSP DLL.

### T1547.006 - Boot or Logon Autostart Execution: Kernel Modules and Extensions

Description:

Adversaries may modify the kernel to automatically execute programs on system boot. Loadable Kernel Modules (LKMs) are pieces of code that can be loaded and unloaded into the kernel upon demand. They extend the functionality of the kernel without the need to reboot the system. For example, one type of module is the device driver, which allows the kernel to access hardware connected to the system. When used maliciously, LKMs can be a type of kernel-mode Rootkit that run with the highest operating system privilege (Ring 0). Common features of LKM based rootkits include: hiding itself, selective hiding of files, processes and network activity, as well as log tampering, providing authenticated backdoors, and enabling root access to non-privileged users. Kernel extensions, also called kext, are used in macOS to load functionality onto a system similar to LKMs for Linux. Since the kernel is responsible for enforcing security and the kernel extensions run as apart of the kernel, kexts are not governed by macOS security policies. Kexts are loaded and unloaded through kextload and kextunload commands. Kexts need to be signed with a developer ID that is granted privileges by Apple allowing it to sign Kernel extensions. Developers without these privileges may still sign kexts but they will not load unless SIP is disabled. If SIP is enabled, the kext signature is verified before being added to the AuxKC. Since macOS Catalina 10.15, kernel extensions have been deprecated in favor of System Extensions. However, kexts are still allowed as "Legacy System Extensions" since there is no System Extension for Kernel Programming Interfaces. Adversaries can use LKMs and kexts to conduct Persistence and/or Privilege Escalation on a system. Examples have been found in the wild, and there are some relevant open source projects as well.

Detection:

Loading, unloading, and manipulating modules on Linux systems can be detected by monitoring for the following commands: modprobe, insmod, lsmod, rmmod, or modinfo LKMs are typically loaded into /lib/modules and have had the extension .ko ("kernel object") since version 2.6 of the Linux kernel. Adversaries may run commands on the target system before loading a malicious module in order to ensure that it is properly compiled. Adversaries may also execute commands to identify the exact version of the running Linux kernel and/or download multiple versions of the same .ko (kernel object) files to use the one appropriate for the running system. Many LKMs require Linux headers (specific to the target kernel) in order to compile properly. These are typically obtained through the operating systems package manager and installed like a normal package. On Ubuntu and Debian based systems this can be accomplished by running: apt-get install linux-headers-$(uname -r) On RHEL and CentOS based systems this can be accomplished by running: yum install kernel-devel-$(uname -r) On macOS, monitor for execution of kextload commands and user installed kernel extensions performing abnormal and/or potentially malicious activity (such as creating network connections). Monitor for new rows added in the kext_policy table. KextPolicy stores a list of user approved (non Apple) kernel extensions and a partial history of loaded kernel modules in a SQLite database, /var/db/SystemPolicyConfiguration/KextPolicy.

Procedures:

- [S0502] Drovorub: Drovorub can use kernel modules to establish persistence.
- [S0468] Skidmap: Skidmap has the ability to install several loadable kernel modules (LKMs) on infected machines.
- [C0012] Operation CuckooBees: During Operation CuckooBees, attackers used a signed kernel rootkit to establish additional persistence.

### T1547.007 - Boot or Logon Autostart Execution: Re-opened Applications

Description:

Adversaries may modify plist files to automatically run an application when a user logs in. When a user logs out or restarts via the macOS Graphical User Interface (GUI), a prompt is provided to the user with a checkbox to "Reopen windows when logging back in". When selected, all applications currently open are added to a property list file named com.apple.loginwindow.[UUID].plist within the ~/Library/Preferences/ByHost directory. Applications listed in this file are automatically reopened upon the user’s next logon. Adversaries can establish Persistence by adding a malicious application path to the com.apple.loginwindow.[UUID].plist file to execute payloads when a user logs in.

Detection:

Monitoring the specific plist files associated with reopening applications can indicate when an application has registered itself to be reopened.

### T1547.008 - Boot or Logon Autostart Execution: LSASS Driver

Description:

Adversaries may modify or add LSASS drivers to obtain persistence on compromised systems. The Windows security subsystem is a set of components that manage and enforce the security policy for a computer or domain. The Local Security Authority (LSA) is the main component responsible for local security policy and user authentication. The LSA includes multiple dynamic link libraries (DLLs) associated with various other security functions, all of which run in the context of the LSA Subsystem Service (LSASS) lsass.exe process. Adversaries may target LSASS drivers to obtain persistence. By either replacing or adding illegitimate drivers (e.g., Hijack Execution Flow), an adversary can use LSA operations to continuously execute malicious payloads.

Detection:

With LSA Protection enabled, monitor the event logs (Events 3033 and 3063) for failed attempts to load LSA plug-ins and drivers. Also monitor DLL load operations in lsass.exe. Utilize the Sysinternals Autoruns/Autorunsc utility to examine loaded drivers associated with the LSA.

Procedures:

- [S0176] Wingbird: Wingbird drops a malicious file (sspisrv.dll) alongside a copy of lsass.exe, which is used to register a service that loads sspisrv.dll as a driver. The payload of the malicious driver (located in its entry-point function) is executed when loaded by lsass.exe before the spoofed service becomes unstable and crashes.
- [S0208] Pasam: Pasam establishes by infecting the Security Accounts Manager (SAM) DLL to load a malicious DLL dropped to disk.

### T1547.009 - Boot or Logon Autostart Execution: Shortcut Modification

Description:

Adversaries may create or modify shortcuts that can execute a program during system boot or user login. Shortcuts or symbolic links are used to reference other files or programs that will be opened or executed when the shortcut is clicked or executed by a system startup process. Adversaries may abuse shortcuts in the startup folder to execute their tools and achieve persistence. Although often used as payloads in an infection chain (e.g. Spearphishing Attachment), adversaries may also create a new shortcut as a means of indirection, while also abusing Masquerading to make the malicious shortcut appear as a legitimate program. Adversaries can also edit the target path or entirely replace an existing shortcut so their malware will be executed instead of the intended legitimate program. Shortcuts can also be abused to establish persistence by implementing other methods. For example, LNK browser extensions may be modified (e.g. Browser Extensions) to persistently launch malware.

Detection:

Since a shortcut's target path likely will not change, modifications to shortcut files that do not correlate with known software changes, patches, removal, etc., may be suspicious. Analysis should attempt to relate shortcut file change or creation events to other potentially suspicious events based on known adversary behavior such as process launches of unknown executables that make network connections. Monitor for LNK files created with a Zone Identifier value greater than 1, which may indicate that the LNK file originated from outside of the network.

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
- [S0035] SPACESHIP: SPACESHIP achieves persistence by creating a shortcut in the current user's Startup folder.
- [S0004] TinyZBot: TinyZBot can create a shortcut in the Windows startup folder for persistence.
- [S0373] Astaroth: Astaroth's initial payload is a malicious .LNK file.
- [S0085] S-Type: S-Type may create the file %HOMEPATH%\Start Menu\Programs\Startup\Realtek {Unique Identifier}.lnk, which points to the malicious `msdtc.exe` file already created in the `%CommonFiles%` directory.
- [S0028] SHIPSHAPE: SHIPSHAPE achieves persistence by creating a shortcut in the Startup folder.
- [G0078] Gorgon Group: Gorgon Group malware can create a .lnk file and add a Registry Run key to establish persistence.
- [S0031] BACKSPACE: BACKSPACE achieves persistence by creating a shortcut to itself in the CSIDL_STARTUP directory.
- [S0053] SeaDuke: SeaDuke is capable of persisting via a .lnk file stored in the Startup directory.
- [S0260] InvisiMole: InvisiMole can use a .lnk shortcut for the Control Panel to establish persistence.
- [S0267] FELIXROOT: FELIXROOT creates a .LNK file for persistence.
- [S0356] KONNI: A version of KONNI drops a Windows shortcut on the victim’s machine to establish persistence.
- [S0534] Bazar: Bazar can establish persistence by writing shortcuts to the Windows Startup folder.
- [S0363] Empire: Empire can persist by modifying a .LNK file to include a backdoor.
- [S0265] Kazuar: Kazuar adds a .lnk file to the Windows startup folder.

### T1547.010 - Boot or Logon Autostart Execution: Port Monitors

Description:

Adversaries may use port monitors to run an adversary supplied DLL during system boot for persistence or privilege escalation. A port monitor can be set through the AddMonitor API call to set a DLL to be loaded at startup. This DLL can be located in C:\Windows\System32 and will be loaded and run by the print spooler service, `spoolsv.exe`, under SYSTEM level permissions on boot. Alternatively, an arbitrary DLL can be loaded if permissions allow writing a fully-qualified pathname for that DLL to the `Driver` value of an existing or new arbitrarily named subkey of HKLM\SYSTEM\CurrentControlSet\Control\Print\Monitors. The Registry key contains entries for the following: * Local Port * Standard TCP/IP Port * USB Monitor * WSD Port

Detection:

Monitor process API calls to AddMonitor. Monitor DLLs that are loaded by spoolsv.exe for DLLs that are abnormal. New DLLs written to the System32 directory that do not correlate with known good software or patching may be suspicious. Monitor Registry writes to HKLM\SYSTEM\CurrentControlSet\Control\Print\Monitors, paying particular attention to changes in the "Driver" subkey. Run the Autoruns utility, which checks for this Registry key as a persistence mechanism.

### T1547.012 - Boot or Logon Autostart Execution: Print Processors

Description:

Adversaries may abuse print processors to run malicious DLLs during system boot for persistence and/or privilege escalation. Print processors are DLLs that are loaded by the print spooler service, `spoolsv.exe`, during boot. Adversaries may abuse the print spooler service by adding print processors that load malicious DLLs at startup. A print processor can be installed through the AddPrintProcessor API call with an account that has SeLoadDriverPrivilege enabled. Alternatively, a print processor can be registered to the print spooler service by adding the HKLM\SYSTEM\\[CurrentControlSet or ControlSet001]\Control\Print\Environments\\[Windows architecture: e.g., Windows x64]\Print Processors\\[user defined]\Driver Registry key that points to the DLL. For the malicious print processor to be correctly installed, the payload must be located in the dedicated system print-processor directory, that can be found with the GetPrintProcessorDirectory API call, or referenced via a relative path from this directory. After the print processors are installed, the print spooler service, which starts during boot, must be restarted in order for them to run. The print spooler service runs under SYSTEM level permissions, therefore print processors installed by an adversary may run under elevated privileges.

Detection:

Monitor process API calls to AddPrintProcessor and GetPrintProcessorDirectory. New print processor DLLs are written to the print processor directory. Also monitor Registry writes to HKLM\SYSTEM\ControlSet001\Control\Print\Environments\\[Windows architecture]\Print Processors\\[user defined]\\Driver or HKLM\SYSTEM\CurrentControlSet\Control\Print\Environments\\[Windows architecture]\Print Processors\\[user defined]\Driver as they pertain to print processor installations. Monitor for abnormal DLLs that are loaded by spoolsv.exe. Print processors that do not correlate with known good software or patching may be suspicious.

Procedures:

- [S0666] Gelsemium: Gelsemium can drop itself in C:\Windows\System32\spool\prtprocs\x64\winprint.dll to be loaded automatically by the spoolsv Windows service.
- [G1006] Earth Lusca: Earth Lusca has added the Registry key `HKLM\SYSTEM\ControlSet001\Control\Print\Environments\Windows x64\Print Processors\UDPrint” /v Driver /d “spool.dll /f` to load malware as a Print Processor.
- [S0501] PipeMon: The PipeMon installer has modified the Registry key HKLM\SYSTEM\CurrentControlSet\Control\Print\Environments\Windows x64\Print Processors to install PipeMon as a Print Processor.

### T1547.013 - Boot or Logon Autostart Execution: XDG Autostart Entries

Description:

Adversaries may add or modify XDG Autostart Entries to execute malicious programs or commands when a user’s desktop environment is loaded at login. XDG Autostart entries are available for any XDG-compliant Linux system. XDG Autostart entries use Desktop Entry files (`.desktop`) to configure the user’s desktop environment upon user login. These configuration files determine what applications launch upon user login, define associated applications to open specific file types, and define applications used to open removable media. Adversaries may abuse this feature to establish persistence by adding a path to a malicious binary or command to the `Exec` directive in the `.desktop` configuration file. When the user’s desktop environment is loaded at user login, the `.desktop` files located in the XDG Autostart directories are automatically executed. System-wide Autostart entries are located in the `/etc/xdg/autostart` directory while the user entries are located in the `~/.config/autostart` directory. Adversaries may combine this technique with Masquerading to blend malicious Autostart entries with legitimate programs.

Detection:

Malicious XDG autostart entries may be detected by auditing file creation and modification events within the /etc/xdg/autostart and ~/.config/autostart directories. Depending on individual configurations, defenders may need to query the environment variables $XDG_CONFIG_HOME or $XDG_CONFIG_DIRS to determine the paths of Autostart entries. Autostart entry files not associated with legitimate packages may be considered suspicious. Suspicious entries can also be identified by comparing entries to a trusted system baseline. Suspicious processes or scripts spawned in this manner will have a parent process of the desktop component implementing the XDG specification and will execute as the logged on user.

Procedures:

- [S0198] NETWIRE: NETWIRE can use XDG Autostart Entries to establish persistence on Linux systems.
- [S0192] Pupy: Pupy can use an XDG Autostart to establish persistence.
- [S0235] CrossRAT: CrossRAT can use an XDG Autostart to establish persistence.
- [S1078] RotaJakiro: When executing with user-level permissions, RotaJakiro can install persistence using a .desktop file under the `$HOME/.config/autostart/` folder.
- [S0410] Fysbis: If executing without root privileges, Fysbis adds a `.desktop` configuration file to the user's `~/.config/autostart` directory.

### T1547.014 - Boot or Logon Autostart Execution: Active Setup

Description:

Adversaries may achieve persistence by adding a Registry key to the Active Setup of the local machine. Active Setup is a Windows mechanism that is used to execute programs when a user logs in. The value stored in the Registry key will be executed after a user logs into the computer. These programs will be executed under the context of the user and will have the account's associated permissions level. Adversaries may abuse Active Setup by creating a key under HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components\ and setting a malicious value for StubPath. This value will serve as the program that will be executed when a user logs into the computer. Adversaries can abuse these components to execute malware, such as remote access tools, to maintain persistence through system reboots. Adversaries may also use Masquerading to make the Registry entries look as if they are associated with legitimate programs.

Detection:

Monitor Registry key additions and/or modifications to HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Active Setup\Installed Components\. Tools such as Sysinternals Autoruns may also be used to detect system changes that could be attempts at persistence, including listing the Active Setup Registry locations and startup folders. Suspicious program execution as startup programs may show up as outlier processes that have not been seen before when compared against historical data.

Procedures:

- [S0012] PoisonIvy: PoisonIvy creates a Registry key in the Active Setup pointing to a malicious executable.

### T1547.015 - Boot or Logon Autostart Execution: Login Items

Description:

Adversaries may add login items to execute upon user login to gain persistence or escalate privileges. Login items are applications, documents, folders, or server connections that are automatically launched when a user logs in. Login items can be added via a shared file list or Service Management Framework. Shared file list login items can be set using scripting languages such as AppleScript, whereas the Service Management Framework uses the API call SMLoginItemSetEnabled. Login items installed using the Service Management Framework leverage launchd, are not visible in the System Preferences, and can only be removed by the application that created them. Login items created using a shared file list are visible in System Preferences, can hide the application when it launches, and are executed through LaunchServices, not launchd, to open applications, documents, or URLs without using Finder. Users and applications use login items to configure their user environment to launch commonly used services or applications, such as email, chat, and music applications. Adversaries can utilize AppleScript and Native API calls to create a login item to spawn malicious executables. Prior to version 10.5 on macOS, adversaries can add login items by using AppleScript to send an Apple events to the “System Events” process, which has an AppleScript dictionary for manipulating login items. Adversaries can use a command such as tell application “System Events” to make login item at end with properties /path/to/executable. This command adds the path of the malicious executable to the login item file list located in ~/Library/Application Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm. Adversaries can also use login items to launch executables that can be used to control the victim system remotely or as a means to gain privilege escalation by prompting for user credentials.

Detection:

All login items created via shared file lists are viewable by using the System Preferences GUI or in the ~/Library/Application Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm file. These locations should be monitored and audited for known good applications. Otherwise, login Items are located in Contents/Library/LoginItems within an application bundle, so these paths should be monitored as well. Monitor applications that leverage login items with either the LSUIElement or LSBackgroundOnly key in the Info.plist file set to true. Monitor processes that start at login for unusual or unknown applications. Usual applications for login items could include what users add to configure their user environment, such as email, chat, or music applications, or what administrators include for organization settings and protections. Check for running applications from login items that also have abnormal behavior,, such as establishing network connections.

Procedures:

- [S0690] Green Lambert: Green Lambert can add Login Items to establish persistence.
- [S0198] NETWIRE: NETWIRE can persist via startup options for Login items.
- [S0281] Dok: Dok uses AppleScript to install a login Item by sending Apple events to the System Events process.


### T1554 - Compromise Host Software Binary

Description:

Adversaries may modify host software binaries to establish persistent access to systems. Software binaries/executables provide a wide range of system commands or services, programs, and libraries. Common software binaries are SSH clients, FTP clients, email clients, web browsers, and many other user or server applications. Adversaries may establish persistence though modifications to host software binaries. For example, an adversary may replace or otherwise infect a legitimate application binary (or support files) with a backdoor. Since these binaries may be routinely executed by applications or the user, the adversary can leverage this for persistent access to the host. An adversary may also modify a software binary such as an SSH client in order to persistently collect credentials during logins (i.e., Modify Authentication Process). An adversary may also modify an existing binary by patching in malicious functionality (e.g., IAT Hooking/Entry point patching) prior to the binary’s legitimate execution. For example, an adversary may modify the entry point of a binary to point to malicious code patched in by the adversary before resuming normal execution flow. After modifying a binary, an adversary may attempt to Impair Defenses by preventing it from updating (e.g., via the `yum-versionlock` command or `versionlock.list` file in Linux systems that use the yum package manager).

Detection:

Collect and analyze signing certificate metadata and check signature validity on software that executes within the environment. Look for changes to client software that do not correlate with known software or patch cycles. Consider monitoring for anomalous behavior from client applications, such as atypical module loads, file reads/writes, or network connections.

Procedures:

- [S1116] WARPWIRE: WARPWIRE can embed itself into a legitimate file on compromised Ivanti Connect Secure VPNs.
- [S0604] Industroyer: Industroyer has used a Trojanized version of the Windows Notepad application for an additional backdoor persistence mechanism.
- [S1136] BFG Agonizer: BFG Agonizer uses DLL unhooking to remove user mode inline hooks that security solutions often implement. BFG Agonizer also uses IAT unhooking to remove user-mode IAT hooks that security solutions also use.
- [C0029] Cutting Edge: During Cutting Edge, threat actors trojanized legitimate files in Ivanti Connect Secure appliances with malicious code.
- [S1118] BUSHWALK: BUSHWALK can embed into the legitimate `querymanifest.cgi` file on compromised Ivanti Connect Secure VPNs.
- [S0641] Kobalos: Kobalos replaced the SSH client with a trojanized SSH client to steal credentials on compromised systems.
- [G1023] APT5: APT5 has modified legitimate binaries and scripts for Pulse Secure VPNs including the legitimate DSUpgrade.pm file to install the ATRIUM webshell for persistence.
- [S0487] Kessel: Kessel has maliciously altered the OpenSSH binary on targeted systems to create a backdoor.
- [S0595] ThiefQuest: ThiefQuest searches through the /Users/ folder looking for executable files. For each executable, ThiefQuest prepends a copy of itself to the beginning of the file. When the file is executed, the ThiefQuest code is executed first. ThiefQuest creates a hidden file, copies the original target executable to the file, then executes the new hidden file to maintain the appearance of normal behavior.
- [S1121] LITTLELAMB.WOOLTEA: LITTLELAMB.WOOLTEA can append malicious components to the `tmp/tmpmnt/bin/samba_upgrade.tar` archive inside the factory reset partition in attempt to persist post reset.
- [S1184] BOLDMOVE: BOLDMOVE contains a watchdog-like feature that monitors a particular file for modification. If modification is detected, the legitimate file is backed up and replaced with a trojanized file to allow for persistence through likely system upgrades.
- [S0377] Ebury: Ebury modifies the `keyutils` library to add malicious behavior to the OpenSSH client and the curl library.
- [S1119] LIGHTWIRE: LIGHTWIRE can imbed itself into the legitimate `compcheckresult.cgi` component of Ivanti Connect Secure VPNs to enable command execution.
- [S0486] Bonadan: Bonadan has maliciously altered the OpenSSH binary on targeted systems to create a backdoor.
- [S0658] XCSSET: XCSSET uses a malicious browser application to replace the legitimate browser in order to continuously capture credentials, monitor web traffic, and download additional modules.
- [C0025] 2016 Ukraine Electric Power Attack: During the 2016 Ukraine Electric Power Attack, Sandworm Team used a trojanized version of Windows Notepad to add a layer of persistence for Industroyer.
- [S1120] FRAMESTING: FRAMESTING can embed itself in the CAV Python package of an Ivanti Connect Secure VPN located in `/home/venv3/lib/python3.6/site-packages/cav-0.1-py3.6.egg/cav/api/resources/category.py.`
- [S1104] SLOWPULSE: SLOWPULSE is applied in compromised environments through modifications to legitimate Pulse Secure files.
- [S1115] WIREFIRE: WIREFIRE can modify the `visits.py` component of Ivanti Connect Secure VPNs for file download and arbitrary command execution.


### T1556.001 - Modify Authentication Process: Domain Controller Authentication

Description:

Adversaries may patch the authentication process on a domain controller to bypass the typical authentication mechanisms and enable access to accounts. Malware may be used to inject false credentials into the authentication process on a domain controller with the intent of creating a backdoor used to access any user’s account and/or credentials (ex: Skeleton Key). Skeleton key works through a patch on an enterprise domain controller authentication process (LSASS) with credentials that adversaries may use to bypass the standard authentication system. Once patched, an adversary can use the injected password to successfully authenticate as any domain user account (until the the skeleton key is erased from memory by a reboot of the domain controller). Authenticated access may enable unfettered access to hosts and/or resources within single-factor authentication environments.

Detection:

Monitor for calls to OpenProcess that can be used to manipulate lsass.exe running on a domain controller as well as for malicious modifications to functions exported from authentication-related system DLLs (such as cryptdll.dll and samsrv.dll). Configure robust, consistent account activity audit policies across the enterprise and with externally accessible services. Look for suspicious account behavior across systems that share accounts, either user, admin, or service accounts. Examples: one account logged into multiple systems simultaneously; multiple accounts logged into the same machine simultaneously; accounts logged in at odd times or outside of business hours. Activity may be from interactive login sessions or process ownership from accounts being used to execute binaries on a remote system as a particular account. Correlate other security systems with login information (e.g. a user has an active login session but has not entered the building or does not have VPN access).

Procedures:

- [G0114] Chimera: Chimera's malware has altered the NTLM authentication program on domain controllers to allow Chimera to login without a valid credential.
- [S0007] Skeleton Key: Skeleton Key is used to patch an enterprise domain controller authentication process with a backdoor password. It allows adversaries to bypass the standard authentication system to use a defined password for all accounts authenticating to that domain controller.

### T1556.002 - Modify Authentication Process: Password Filter DLL

Description:

Adversaries may register malicious password filter dynamic link libraries (DLLs) into the authentication process to acquire user credentials as they are validated. Windows password filters are password policy enforcement mechanisms for both domain and local accounts. Filters are implemented as DLLs containing a method to validate potential passwords against password policies. Filter DLLs can be positioned on local computers for local accounts and/or domain controllers for domain accounts. Before registering new passwords in the Security Accounts Manager (SAM), the Local Security Authority (LSA) requests validation from each registered filter. Any potential changes cannot take effect until every registered filter acknowledges validation. Adversaries can register malicious password filters to harvest credentials from local computers and/or entire domains. To perform proper validation, filters must receive plain-text credentials from the LSA. A malicious password filter would receive these plain-text credentials every time a password request is made.

Detection:

Monitor for new, unfamiliar DLL files written to a domain controller and/or local computer. Monitor for changes to Registry entries for password filters (ex: HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\Notification Packages) and correlate then investigate the DLL files these files reference. Password filters will also show up as an autorun and loaded DLL in lsass.exe.

Procedures:

- [S0125] Remsec: Remsec harvests plain-text credentials as a password filter registered on domain controllers.
- [G0049] OilRig: OilRig has registered a password filter DLL in order to drop malware.
- [G0041] Strider: Strider has registered its persistence module on domain controllers as a Windows LSA (Local System Authority) password filter to acquire credentials any time a domain, local user, or administrator logs in or changes a password.

### T1556.003 - Modify Authentication Process: Pluggable Authentication Modules

Description:

Adversaries may modify pluggable authentication modules (PAM) to access user credentials or enable otherwise unwarranted access to accounts. PAM is a modular system of configuration files, libraries, and executable files which guide authentication for many services. The most common authentication module is pam_unix.so, which retrieves, sets, and verifies account authentication information in /etc/passwd and /etc/shadow. Adversaries may modify components of the PAM system to create backdoors. PAM components, such as pam_unix.so, can be patched to accept arbitrary adversary supplied values as legitimate credentials. Malicious modifications to the PAM system may also be abused to steal credentials. Adversaries may infect PAM resources with code to harvest user credentials, since the values exchanged with PAM components may be plain-text since PAM does not store passwords.

Detection:

Monitor PAM configuration and module paths (ex: /etc/pam.d/) for changes. Use system-integrity tools such as AIDE and monitoring tools such as auditd to monitor PAM files. Look for suspicious account behavior across systems that share accounts, either user, admin, or service accounts. Examples: one account logged into multiple systems simultaneously; multiple accounts logged into the same machine simultaneously; accounts logged in at odd times (ex: when the user is not present) or outside of business hours. Activity may be from interactive login sessions or process ownership from accounts being used to execute binaries on a remote system as a particular account. Correlate other security systems with login information (e.g., a user has an active login session but has not entered the building or does not have VPN access).

Procedures:

- [S0377] Ebury: Ebury can deactivate PAM modules to tamper with the sshd configuration.
- [S0468] Skidmap: Skidmap has the ability to replace the pam_unix.so file on an infected machine with its own malicious version that accepts a specific backdoor password for all users.

### T1556.004 - Modify Authentication Process: Network Device Authentication

Description:

Adversaries may use Patch System Image to hard code a password in the operating system, thus bypassing of native authentication mechanisms for local accounts on network devices. Modify System Image may include implanted code to the operating system for network devices to provide access for adversaries using a specific password. The modification includes a specific password which is implanted in the operating system image via the patch. Upon authentication attempts, the inserted code will first check to see if the user input is the password. If so, access is granted. Otherwise, the implanted code will pass the credentials on for verification of potentially valid credentials.

Detection:

Consider verifying the checksum of the operating system file and verifying the image of the operating system in memory. Detection of this behavior may be difficult, detection efforts may be focused on closely related adversary behaviors, such as Modify System Image.

Procedures:

- [S1104] SLOWPULSE: SLOWPULSE can modify LDAP and two factor authentication flows by inspecting login credentials and forcing successful authentication if the provided password matches a chosen backdoor password.
- [S0519] SYNful Knock: SYNful Knock has the capability to add its own custom backdoor password when it modifies the operating system of the affected network device.

### T1556.005 - Modify Authentication Process: Reversible Encryption

Description:

An adversary may abuse Active Directory authentication encryption properties to gain access to credentials on Windows systems. The AllowReversiblePasswordEncryption property specifies whether reversible password encryption for an account is enabled or disabled. By default this property is disabled (instead storing user credentials as the output of one-way hashing functions) and should not be enabled unless legacy or other software require it. If the property is enabled and/or a user changes their password after it is enabled, an adversary may be able to obtain the plaintext of passwords created/changed after the property was enabled. To decrypt the passwords, an adversary needs four components: 1. Encrypted password (G$RADIUSCHAP) from the Active Directory user-structure userParameters 2. 16 byte randomly-generated value (G$RADIUSCHAPKEY) also from userParameters 3. Global LSA secret (G$MSRADIUSCHAPKEY) 4. Static key hardcoded in the Remote Access Subauthentication DLL (RASSFM.DLL) With this information, an adversary may be able to reproduce the encryption key and subsequently decrypt the encrypted password value. An adversary may set this property at various scopes through Local Group Policy Editor, user properties, Fine-Grained Password Policy (FGPP), or via the ActiveDirectory PowerShell module. For example, an adversary may implement and apply a FGPP to users or groups if the Domain Functional Level is set to "Windows Server 2008" or higher. In PowerShell, an adversary may make associated changes to user settings using commands similar to Set-ADUser -AllowReversiblePasswordEncryption $true.

Detection:

Monitor property changes in Group Policy: Computer Configuration\Windows Settings\Security Settings\Account Policies\Password Policy\Store passwords using reversible encryption. By default, the property should be set to Disabled. Monitor command-line usage for -AllowReversiblePasswordEncryption $true or other actions that could be related to malicious tampering of user settings (i.e. Group Policy Modification). Furthermore, consider monitoring and/or blocking suspicious execution of Active Directory PowerShell modules, such as Set-ADUser and Set-ADAccountControl, that change account configurations. Monitor Fine-Grained Password Policies and regularly audit user accounts and group settings.

### T1556.006 - Modify Authentication Process: Multi-Factor Authentication

Description:

Adversaries may disable or modify multi-factor authentication (MFA) mechanisms to enable persistent access to compromised accounts. Once adversaries have gained access to a network by either compromising an account lacking MFA or by employing an MFA bypass method such as Multi-Factor Authentication Request Generation, adversaries may leverage their access to modify or completely disable MFA defenses. This can be accomplished by abusing legitimate features, such as excluding users from Azure AD Conditional Access Policies, registering a new yet vulnerable/adversary-controlled MFA method, or by manually patching MFA programs and configuration files to bypass expected functionality. For example, modifying the Windows hosts file (`C:\windows\system32\drivers\etc\hosts`) to redirect MFA calls to localhost instead of an MFA server may cause the MFA process to fail. If a "fail open" policy is in place, any otherwise successful authentication attempt may be granted access without enforcing MFA. Depending on the scope, goals, and privileges of the adversary, MFA defenses may be disabled for individual accounts or for all accounts tied to a larger group, such as all domain accounts in a victim's network environment.

Procedures:

- [G1015] Scattered Spider: After compromising user accounts, Scattered Spider registers their own MFA tokens.
- [S1104] SLOWPULSE: SLOWPULSE can insert malicious logic to bypass RADIUS and ACE two factor authentication (2FA) flows if a designated attacker-supplied password is provided.
- [S0677] AADInternals: The AADInternals `Set-AADIntUserMFA` command can be used to disable MFA for a specified user.

### T1556.007 - Modify Authentication Process: Hybrid Identity

Description:

Adversaries may patch, modify, or otherwise backdoor cloud authentication processes that are tied to on-premises user identities in order to bypass typical authentication mechanisms, access credentials, and enable persistent access to accounts. Many organizations maintain hybrid user and device identities that are shared between on-premises and cloud-based environments. These can be maintained in a number of ways. For example, Microsoft Entra ID includes three options for synchronizing identities between Active Directory and Entra ID: * Password Hash Synchronization (PHS), in which a privileged on-premises account synchronizes user password hashes between Active Directory and Entra ID, allowing authentication to Entra ID to take place entirely in the cloud * Pass Through Authentication (PTA), in which Entra ID authentication attempts are forwarded to an on-premises PTA agent, which validates the credentials against Active Directory * Active Directory Federation Services (AD FS), in which a trust relationship is established between Active Directory and Entra ID AD FS can also be used with other SaaS and cloud platforms such as AWS and GCP, which will hand off the authentication process to AD FS and receive a token containing the hybrid users’ identity and privileges. By modifying authentication processes tied to hybrid identities, an adversary may be able to establish persistent privileged access to cloud resources. For example, adversaries who compromise an on-premises server running a PTA agent may inject a malicious DLL into the `AzureADConnectAuthenticationAgentService` process that authorizes all attempts to authenticate to Entra ID, as well as records user credentials. In environments using AD FS, an adversary may edit the `Microsoft.IdentityServer.Servicehost` configuration file to load a malicious DLL that generates authentication tokens for any user with any set of claims, thereby bypassing multi-factor authentication and defined AD FS policies. In some cases, adversaries may be able to modify the hybrid identity authentication process from the cloud. For example, adversaries who compromise a Global Administrator account in an Entra ID tenant may be able to register a new PTA agent via the web console, similarly allowing them to harvest credentials and log into the Entra ID environment as any user.

Procedures:

- [S0677] AADInternals: AADInternals can inject a malicious DLL (`PTASpy`) into the `AzureADConnectAuthenticationAgentService` to backdoor Azure AD Pass-Through Authentication.
- [G0016] APT29: APT29 has edited the `Microsoft.IdentityServer.Servicehost.exe.config` file to load a malicious DLL into the AD FS process, thereby enabling persistent access to any service federated with AD FS for a user with a specified User Principal Name.

### T1556.008 - Modify Authentication Process: Network Provider DLL

Description:

Adversaries may register malicious network provider dynamic link libraries (DLLs) to capture cleartext user credentials during the authentication process. Network provider DLLs allow Windows to interface with specific network protocols and can also support add-on credential management functions. During the logon process, Winlogon (the interactive logon module) sends credentials to the local `mpnotify.exe` process via RPC. The `mpnotify.exe` process then shares the credentials in cleartext with registered credential managers when notifying that a logon event is happening. Adversaries can configure a malicious network provider DLL to receive credentials from `mpnotify.exe`. Once installed as a credential manager (via the Registry), a malicious DLL can receive and save credentials each time a user logs onto a Windows workstation or domain via the `NPLogonNotify()` function. Adversaries may target planting malicious network provider DLLs on systems known to have increased logon activity and/or administrator logon activity, such as servers and domain controllers.

### T1556.009 - Modify Authentication Process: Conditional Access Policies

Description:

Adversaries may disable or modify conditional access policies to enable persistent access to compromised accounts. Conditional access policies are additional verifications used by identity providers and identity and access management systems to determine whether a user should be granted access to a resource. For example, in Entra ID, Okta, and JumpCloud, users can be denied access to applications based on their IP address, device enrollment status, and use of multi-factor authentication. In some cases, identity providers may also support the use of risk-based metrics to deny sign-ins based on a variety of indicators. In AWS and GCP, IAM policies can contain `condition` attributes that verify arbitrary constraints such as the source IP, the date the request was made, and the nature of the resources or regions being requested. These measures help to prevent compromised credentials from resulting in unauthorized access to data or resources, as well as limit user permissions to only those required. By modifying conditional access policies, such as adding additional trusted IP ranges, removing Multi-Factor Authentication requirements, or allowing additional Unused/Unsupported Cloud Regions, adversaries may be able to ensure persistent access to accounts and circumvent defensive measures.

Procedures:

- [G1015] Scattered Spider: Scattered Spider has added additional trusted locations to Azure AD conditional access policies.


### T1574.001 - Hijack Execution Flow: DLL

Description:

Adversaries may abuse dynamic-link library files (DLLs) in order to achieve persistence, escalate privileges, and evade defenses. DLLs are libraries that contain code and data that can be simultaneously utilized by multiple programs. While DLLs are not malicious by nature, they can be abused through mechanisms such as side-loading, hijacking search order, and phantom DLL hijacking. Specific ways DLLs are abused by adversaries include: ### DLL Sideloading Adversaries may execute their own malicious payloads by side-loading DLLs. Side-loading involves hijacking which DLL a program loads by planting and then invoking a legitimate application that executes their payload(s). Side-loading positions both the victim application and malicious payload(s) alongside each other. Adversaries likely use side-loading as a means of masking actions they perform under a legitimate, trusted, and potentially elevated system or software process. Benign executables used to side-load payloads may not be flagged during delivery and/or execution. Adversary payloads may also be encrypted/packed or otherwise obfuscated until loaded into the memory of the trusted process. Adversaries may also side-load other packages, such as BPLs (Borland Package Library). ### DLL Search Order Hijacking Adversaries may execute their own malicious payloads by hijacking the search order that Windows uses to load DLLs. This search order is a sequence of special and standard search locations that a program checks when loading a DLL. An adversary can plant a trojan DLL in a directory that will be prioritized by the DLL search order over the location of a legitimate library. This will cause Windows to load the malicious DLL when it is called for by the victim program. ### DLL Redirection Adversaries may directly modify the search order via DLL redirection, which after being enabled (in the Registry or via the creation of a redirection file) may cause a program to load a DLL from a different location. ### Phantom DLL Hijacking Adversaries may leverage phantom DLL hijacking by targeting references to non-existent DLL files. They may be able to load their own malicious DLL by planting it with the correct name in the location of the missing module. ### DLL Substitution Adversaries may target existing, valid DLL files and substitute them with their own malicious DLLs, planting them with the same name and in the same location as the valid DLL file. Programs that fall victim to DLL hijacking may appear to behave normally because malicious DLLs may be configured to also load the legitimate DLLs they were meant to replace, evading defenses. Remote DLL hijacking can occur when a program sets its current directory to a remote location, such as a Web share, before loading a DLL. If a valid DLL is configured to run at a higher privilege level, then the adversary-controlled DLL that is loaded will also be executed at the higher level. In this case, the technique could be used for privilege escalation.

Detection:

Monitor file systems for moving, renaming, replacing, or modifying DLLs. Changes in the set of DLLs that are loaded by a process (compared with past behavior) that do not correlate with known software, patches, etc., are suspicious. Monitor DLLs loaded into a process and detect DLLs that have the same file name but abnormal paths. Modifications to or creation of `.manifest` and `.local` redirection files that do not correlate with software updates are suspicious.

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
- [S0128] BADNEWS: BADNEWS typically loads its DLL file into a legitimate signed Java or VMware executable.
- [G0107] Whitefly: Whitefly has used search order hijacking to run the loader Vcrodat.
- [C0047] RedDelta Modified PlugX Infection Chain Operations: Mustang Panda used DLL search order hijacking on vulnerable applications to install PlugX payloads during RedDelta Modified PlugX Infection Chain Operations.
- [S0182] FinFisher: FinFisher uses DLL side-loading to load malicious programs. A FinFisher variant also uses DLL search order hijacking.
- [G0143] Aquatic Panda: Aquatic Panda has used DLL search-order hijacking to load `exe`, `dll`, and `dat` files into memory. Aquatic Panda loaded a malicious DLL into the legitimate Windows Security Health Service executable (SecurityHealthService.exe) to execute malicious code on victim systems.
- [S0398] HyperBro: HyperBro has used a legitimate application to sideload a DLL to decrypt, decompress, and run a payload.
- [G0093] GALLIUM: GALLIUM used DLL side-loading to covertly load PoisonIvy into memory on the victim machine.
- [S0153] RedLeaves: RedLeaves is launched through use of DLL search order hijacking to load a malicious dll.
- [G0126] Higaisa: Higaisa’s JavaScript file used a legitimate Microsoft Office 2007 package to side-load the OINFO12.OCX dynamic link library.
- [S0455] Metamorfo: Metamorfo has side-loaded its malicious DLL file.
- [S0579] Waterbear: Waterbear has used DLL side loading to import and load a malicious DLL loader.
- [S0230] ZeroT: ZeroT has used DLL side-loading to load malicious payloads.
- [G0050] APT32: APT32 ran legitimately-signed executables from Symantec and McAfee which load a malicious DLL. The group also side-loads its backdoor by dropping a library and a legitimate, signed executable (AcroTranscoder).
- [S0013] PlugX: PlugX has the ability to use DLL search order hijacking for installation on targeted systems. PlugX has also used DLL side-loading to evade anti-virus.
- [S0458] Ramsay: Ramsay can hijack outdated Windows application dependencies with malicious versions of its own DLL payload.
- [G1046] Storm-1811: Storm-1811 has deployed a malicious DLL (7z.DLL) that is sideloaded by a modified, legitimate installer (7zG.exe) when that installer is executed with an additional command line parameter of `b` at runtime to load a Cobalt Strike beacon payload.
- [S0074] Sakula: Sakula uses DLL side-loading, typically using a digitally signed sample of Kaspersky Anti-Virus (AV) 6.0 for Windows Workstations or McAfee's Outlook Scan About Box to load malicious DLL files.
- [S1213] Lumma Stealer: Lumma Stealer has leveraged legitimate applications to then side-load malicious DLLs during execution.
- [S0098] T9000: During the T9000 installation process, it drops a copy of the legitimate Microsoft binary igfxtray.exe. The executable contains a side-loading weakness which is used to load a portion of the malware.
- [G0120] Evilnum: Evilnum has used the malware variant, TerraTV, to load a malicious DLL placed in the TeamViewer directory, instead of the original Windows DLL located in a system folder.
- [S0032] gh0st RAT: A gh0st RAT variant has used DLL side-loading.
- [S0127] BBSRAT: DLL side-loading has been used to execute BBSRAT through a legitimate Citrix executable, ssonsvr.exe. The Citrix executable was dropped along with BBSRAT by the dropper.
- [S1100] Ninja: Ninja loaders can be side-loaded with legitimate and signed executables including the VLC.exe media player.
- [S0113] Prikormka: Prikormka uses DLL search order hijacking for persistence by saving itself as ntshrui.dll to the Windows directory so it will load before the legitimate ntshrui.dll saved in the System32 subdirectory.
- [S0373] Astaroth: Astaroth can launch itself via DLL Search Order Hijacking.
- [S0650] QakBot: QakBot has the ability to use DLL side-loading for execution.
- [S1130] Raspberry Robin: Raspberry Robin can use legitimate, signed EXE files paired with malicious DLL files to load and run malicious payloads while bypassing defenses.
- [G0081] Tropic Trooper: Tropic Trooper has been known to side-load DLLs using a valid version of a Windows Address Book and Windows Defender executable with one of their tools.
- [G1006] Earth Lusca: Earth Lusca has placed a malicious payload in `%WINDIR%\SYSTEM32\oci.dll` so it would be sideloaded by the MSDTC service.
- [S0585] Kerrdown: Kerrdown can use DLL side-loading to load malicious DLLs.
- [G1014] LuminousMoth: LuminousMoth has used legitimate executables such as `winword.exe` and `igfxem.exe` to side-load their malware.
- [S0530] Melcoz: Melcoz can use DLL hijacking to bypass security controls.
- [S1101] LoFiSe: LoFiSe has been executed as a file named DsNcDiag.dll through side-loading.
- [G0060] BRONZE BUTLER: BRONZE BUTLER has used legitimate applications to side-load malicious DLLs.
- [S0280] MirageFox: MirageFox is likely loaded via DLL hijacking into a legitimate McAfee binary.
- [S1183] StrelaStealer: StrelaStealer has sideloaded a DLL payload using a renamed, legitimate `msinfo32.exe` executable.
- [G0022] APT3: APT3 has been known to side load DLLs with a valid version of Chrome with one of their tools.
- [S0194] PowerSploit: PowerSploit contains a collection of Privesc-PowerUp modules that can discover and exploit DLL hijacking opportunities in services and processes.
- [G0098] BlackTech: BlackTech has used DLL side loading by giving DLLs hardcoded names and placing them in searched directories.
- [S0661] FoggyWeb: FoggyWeb's loader has used DLL Search Order Hijacking to load malicious code instead of the legitimate `version.dll` during the `Microsoft.IdentityServer.ServiceHost.exe` execution process.
- [S0554] Egregor: Egregor has used DLL side-loading to execute its payload.
- [G1016] FIN13: FIN13 has used IISCrack.dll as a side-loading technique to load a malicious version of httpodbc.dll on old IIS Servers (CVE-2001-0507).
- [G0129] Mustang Panda: Mustang Panda has used a legitimately signed executable to execute a malicious payload within a DLL file.
- [S0612] WastedLocker: WastedLocker has performed DLL hijacking before execution.
- [S0538] Crutch: Crutch can persist via DLL search order hijacking on Google Chrome, Mozilla Firefox, or Microsoft OneDrive.
- [S0630] Nebulae: Nebulae can use DLL side-loading to gain execution.
- [G1008] SideCopy: SideCopy has used a malicious loader DLL file to execute the `credwiz.exe` process and side-load the malicious payload `Duser.dll`.
- [S0631] Chaes: Chaes has used search order hijacking to load a malicious DLL.
- [S1046] PowGoop: PowGoop can side-load `Goopdate.dll` into `GoogleUpdate.exe`.
- [S1059] metaMain: metaMain can support an HKCMD sideloading start method.
- [S1111] DarkGate: DarkGate includes one infection vector that leverages a malicious "KeyScramblerE.DLL" library that will load during the execution of the legitimate KeyScrambler application.
- [C0040] APT41 DUST: APT41 DUST involved the use of DLL search order hijacking to execute DUSTTRAP. APT41 DUST used also DLL side-loading to execute DUSTTRAP via an AhnLab uninstaller.
- [G1034] Daggerfly: Daggerfly has used legitimate software to side-load PlugX loaders onto victim systems. Daggerfly is also linked to multiple other instances of side-loading for initial loading activity.
- [S1097] HUI Loader: HUI Loader can be deployed to targeted systems via legitimate programs that are vulnerable to DLL search order hijacking.
- [S0663] SysUpdate: SysUpdate can load DLLs through vulnerable legitimate executables.
- [S0477] Goopy: Goopy has the ability to side-load malicious DLLs with legitimate applications from Kaspersky, Microsoft, and Google.
- [S0624] Ecipekac: Ecipekac can abuse the legitimate application policytool.exe to load a malicious DLL.
- [S1102] Pcexter: Pcexter has been distributed and executed as a DLL file named Vspmsg.dll via DLL side-loading.
- [G0019] Naikon: Naikon has used DLL side-loading to load malicious DLL's into legitimate executables.
- [G0032] Lazarus Group: Lazarus Group has replaced `win_fw.dll`, an internal component that is executed during IDA Pro installation, with a malicious DLL to download and execute a payload. Lazarus Group utilized DLL side-loading to execute malicious payloads through abuse of the legitimate processes `wsmprovhost.exe` and `dfrgui.exe`.
- [C0012] Operation CuckooBees: During Operation CuckooBees, the threat actors used the legitimate Windows services `IKEEXT` and `PrintNotify` to side-load malicious DLLs.
- [S0260] InvisiMole: InvisiMole can be launched by using DLL search order hijacking in which the wrapper DLL is placed in the same folder as explorer.exe and loaded during startup into the Windows Explorer process instead of the legitimate library.
- [S0354] Denis: Denis exploits a security vulnerability to load a fake DLL and execute its code.
- [G0027] Threat Group-3390: Threat Group-3390 has performed DLL search order hijacking to execute their payload. Threat Group-3390 has also used DLL side-loading, including by using legitimate Kaspersky antivirus variants as well as `rc.exe`, a legitimate Microsoft Resource Compiler.
- [G0135] BackdoorDiplomacy: BackdoorDiplomacy has executed DLL search order hijacking.
- [S0629] RainyDay: RainyDay can use side-loading to run malicious executables.
- [S0415] BOOSTWRITE: BOOSTWRITE has exploited the loading of the legitimate Dwrite.dll file by actually loading the gdi library, which then loads the gdiplus library and ultimately loads the local Dwrite dll.
- [S0660] Clambling: Clambling can store a file named `mpsvc.dll`, which opens a malicious `mpsvc.mui` file, in the same folder as the legitimate Microsoft executable `MsMpEng.exe` to gain execution.
- [S0662] RCSession: RCSession can be installed via DLL side-loading.
- [S0363] Empire: Empire contains modules that can discover and exploit various DLL hijacking opportunities.
- [S1063] Brute Ratel C4: Brute Ratel C4 has used search order hijacking to load a malicious payload DLL as a dependency to a benign application packaged in the same ISO. Brute Ratel C4 has loaded a malicious DLL by spoofing the name of the legitimate Version.DLL and placing it in the same folder as the digitally-signed Microsoft binary OneDriveUpdater.exe.
- [G0073] APT19: APT19 launched an HTTP malware variant and a Port 22 malware variant using a legitimate executable that loaded the malicious DLL.
- [S0134] Downdelph: Downdelph uses search order hijacking of the Windows executable sysprep.exe to escalate privileges.
- [S0582] LookBack: LookBack side loads its communications module as a DLL into the libcurl.dll loader.
- [G0121] Sidewinder: Sidewinder has used DLL side-loading to drop and execute malicious payloads including the hijacking of the legitimate Windows application file rekeywiz.exe.
- [G0096] APT41: APT41 has used search order hijacking to execute malicious payloads, such as Winnti for Windows. APT41 has also used legitimate executables to perform DLL side-loading of their malware.
- [G0045] menuPass: menuPass has used DLL side-loading to launch versions of Mimikatz and PwDump6 as well as UPPERCUT. menuPass has also used DLL search order hijacking.

### T1574.004 - Hijack Execution Flow: Dylib Hijacking

Description:

Adversaries may execute their own payloads by placing a malicious dynamic library (dylib) with an expected name in a path a victim application searches at runtime. The dynamic loader will try to find the dylibs based on the sequential order of the search paths. Paths to dylibs may be prefixed with @rpath, which allows developers to use relative paths to specify an array of search paths used at runtime based on the location of the executable. Additionally, if weak linking is used, such as the LC_LOAD_WEAK_DYLIB function, an application will still execute even if an expected dylib is not present. Weak linking enables developers to run an application on multiple macOS versions as new APIs are added. Adversaries may gain execution by inserting malicious dylibs with the name of the missing dylib in the identified path. Dylibs are loaded into an application's address space allowing the malicious dylib to inherit the application's privilege level and resources. Based on the application, this could result in privilege escalation and uninhibited network access. This method may also evade detection from security products since the execution is masked under a legitimate process.

Detection:

Monitor file systems for moving, renaming, replacing, or modifying dylibs. Changes in the set of dylibs that are loaded by a process (compared to past behavior) that do not correlate with known software, patches, etc., are suspicious. Check the system for multiple dylibs with the same name and monitor which versions have historically been loaded into a process. Run path dependent libraries can include LC_LOAD_DYLIB, LC_LOAD_WEAK_DYLIB, and LC_RPATH. Other special keywords are recognized by the macOS loader are @rpath, @loader_path, and @executable_path. These loader instructions can be examined for individual binaries or frameworks using the otool -l command. Objective-See's Dylib Hijacking Scanner can be used to identify applications vulnerable to dylib hijacking.

Procedures:

- [S0363] Empire: Empire has a dylib hijacker module that generates a malicious dylib given the path to a legitimate dylib of a vulnerable application.

### T1574.005 - Hijack Execution Flow: Executable Installer File Permissions Weakness

Description:

Adversaries may execute their own malicious payloads by hijacking the binaries used by an installer. These processes may automatically execute specific binaries as part of their functionality or to perform other actions. If the permissions on the file system directory containing a target binary, or permissions on the binary itself, are improperly set, then the target binary may be overwritten with another binary using user-level permissions and executed by the original process. If the original process and thread are running under a higher permissions level, then the replaced binary will also execute under higher-level permissions, which could include SYSTEM. Another variation of this technique can be performed by taking advantage of a weakness that is common in executable, self-extracting installers. During the installation process, it is common for installers to use a subdirectory within the %TEMP% directory to unpack binaries such as DLLs, EXEs, or other payloads. When installers create subdirectories and files they often do not set appropriate permissions to restrict write access, which allows for execution of untrusted code placed in the subdirectories or overwriting of binaries used in the installation process. This behavior is related to and may take advantage of DLL search order hijacking. Adversaries may use this technique to replace legitimate binaries with malicious ones as a means of executing code at a higher permissions level. Some installers may also require elevated privileges that will result in privilege escalation when executing adversary controlled code. This behavior is related to Bypass User Account Control. Several examples of this weakness in existing common installers have been reported to software vendors. If the executing process is set to run at a specific time or during a certain event (e.g., system bootup) then this technique can also be used for persistence.

Detection:

Look for changes to binaries and service executables that may normally occur during software updates. If an executable is written, renamed, and/or moved to match an existing service executable, it could be detected and correlated with other suspicious behavior. Hashing of binaries and service executables could be used to detect replacement against historical data. Look for abnormal process call trees from typical processes and services and for execution of other commands that could relate to Discovery or other adversary techniques.

### T1574.006 - Hijack Execution Flow: Dynamic Linker Hijacking

Description:

Adversaries may execute their own malicious payloads by hijacking environment variables the dynamic linker uses to load shared libraries. During the execution preparation phase of a program, the dynamic linker loads specified absolute paths of shared libraries from various environment variables and files, such as LD_PRELOAD on Linux or DYLD_INSERT_LIBRARIES on macOS. Libraries specified in environment variables are loaded first, taking precedence over system libraries with the same function name. Each platform's linker uses an extensive list of environment variables at different points in execution. These variables are often used by developers to debug binaries without needing to recompile, deconflict mapped symbols, and implement custom functions in the original library. Hijacking dynamic linker variables may grant access to the victim process's memory, system/network resources, and possibly elevated privileges. On Linux, adversaries may set LD_PRELOAD to point to malicious libraries that match the name of legitimate libraries which are requested by a victim program, causing the operating system to load the adversary's malicious code upon execution of the victim program. For example, adversaries have used `LD_PRELOAD` to inject a malicious library into every descendant process of the `sshd` daemon, resulting in execution under a legitimate process. When the executing sub-process calls the `execve` function, for example, the malicious library’s `execve` function is executed rather than the system function `execve` contained in the system library on disk. This allows adversaries to Hide Artifacts from detection, as hooking system functions such as `execve` and `readdir` enables malware to scrub its own artifacts from the results of commands such as `ls`, `ldd`, `iptables`, and `dmesg`. Hijacking dynamic linker variables may grant access to the victim process's memory, system/network resources, and possibly elevated privileges.

Detection:

Monitor for changes to environment variables and files associated with loading shared libraries such as LD_PRELOAD and DYLD_INSERT_LIBRARIES, as well as the commands to implement these changes. Monitor processes for unusual activity (e.g., a process that does not use the network begins to do so). Track library metadata, such as a hash, and compare libraries that are loaded at process execution time against previous executions to detect differences that do not correlate with patching or updates.

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

Description:

Adversaries may execute their own malicious payloads by hijacking environment variables used to load libraries. The PATH environment variable contains a list of directories (User and System) that the OS searches sequentially through in search of the binary that was called from a script or the command line. Adversaries can place a malicious program in an earlier entry in the list of directories stored in the PATH environment variable, resulting in the operating system executing the malicious binary rather than the legitimate binary when it searches sequentially through that PATH listing. For example, on Windows if an adversary places a malicious program named "net.exe" in `C:\example path`, which by default precedes `C:\Windows\system32\net.exe` in the PATH environment variable, when "net" is executed from the command-line the `C:\example path` will be called instead of the system's legitimate executable at `C:\Windows\system32\net.exe`. Some methods of executing a program rely on the PATH environment variable to determine the locations that are searched when the path for the program is not given, such as executing programs from a Command and Scripting Interpreter. Adversaries may also directly modify the $PATH variable specifying the directories to be searched. An adversary can modify the `$PATH` variable to point to a directory they have write access. When a program using the $PATH variable is called, the OS searches the specified directory and executes the malicious binary. On macOS, this can also be performed through modifying the $HOME variable. These variables can be modified using the command-line, launchctl, Unix Shell Configuration Modification, or modifying the `/etc/paths.d` folder contents.

Detection:

Monitor file creation for files named after partial directories and in locations that may be searched for common processes through the environment variable, or otherwise should not be user writable. Monitor the executing process for process executable paths that are named for partial directories. Monitor file creation for programs that are named after Windows system programs or programs commonly executed without a path (such as "findstr," "net," and "python"). If this activity occurs outside of known administration activity, upgrades, installations, or patches, then it may be suspicious. Data and events should not be viewed in isolation, but as part of a chain of behavior that could lead to other activities, such as network connections made for Command and Control, learning details about the environment through Discovery, and Lateral Movement.

Procedures:

- [S0194] PowerSploit: PowerSploit contains a collection of Privesc-PowerUp modules that can discover and exploit path interception opportunities in the PATH environment variable.
- [S0363] Empire: Empire contains modules that can discover and exploit path interception opportunities in the PATH environment variable.
- [S1111] DarkGate: DarkGate overrides the %windir% environment variable by setting a Registry key, HKEY_CURRENT_User\Environment\windir, to an alternate command to execute a malicious AutoIt script. This allows DarkGate to run every time the scheduled task DiskCleanup is executed as this uses the path value %windir%\system32\cleanmgr.exe for execution.

### T1574.008 - Hijack Execution Flow: Path Interception by Search Order Hijacking

Description:

Adversaries may execute their own malicious payloads by hijacking the search order used to load other programs. Because some programs do not call other programs using the full path, adversaries may place their own file in the directory where the calling program is located, causing the operating system to launch their malicious software at the request of the calling program. Search order hijacking occurs when an adversary abuses the order in which Windows searches for programs that are not given a path. Unlike DLL search order hijacking, the search order differs depending on the method that is used to execute the program. However, it is common for Windows to search in the directory of the initiating program before searching through the Windows system directory. An adversary who finds a program vulnerable to search order hijacking (i.e., a program that does not specify the path to an executable) may take advantage of this vulnerability by creating a program named after the improperly specified program and placing it within the initiating program's directory. For example, "example.exe" runs "cmd.exe" with the command-line argument net user. An adversary may place a program called "net.exe" within the same directory as example.exe, "net.exe" will be run instead of the Windows system utility net. In addition, if an adversary places a program called "net.com" in the same directory as "net.exe", then cmd.exe /C net user will execute "net.com" instead of "net.exe" due to the order of executable extensions defined under PATHEXT. Search order hijacking is also a common practice for hijacking DLL loads and is covered in DLL.

Detection:

Monitor file creation for files named after partial directories and in locations that may be searched for common processes through the environment variable, or otherwise should not be user writable. Monitor the executing process for process executable paths that are named for partial directories. Monitor file creation for programs that are named after Windows system programs or programs commonly executed without a path (such as "findstr," "net," and "python"). If this activity occurs outside of known administration activity, upgrades, installations, or patches, then it may be suspicious. Data and events should not be viewed in isolation, but as part of a chain of behavior that could lead to other activities, such as network connections made for Command and Control, learning details about the environment through Discovery, and Lateral Movement.

Procedures:

- [S0363] Empire: Empire contains modules that can discover and exploit search order hijacking vulnerabilities.
- [S0194] PowerSploit: PowerSploit contains a collection of Privesc-PowerUp modules that can discover and exploit search order hijacking vulnerabilities.

### T1574.009 - Hijack Execution Flow: Path Interception by Unquoted Path

Description:

Adversaries may execute their own malicious payloads by hijacking vulnerable file path references. Adversaries can take advantage of paths that lack surrounding quotations by placing an executable in a higher level directory within the path, so that Windows will choose the adversary's executable to launch. Service paths and shortcut paths may also be vulnerable to path interception if the path has one or more spaces and is not surrounded by quotation marks (e.g., C:\unsafe path with space\program.exe vs. "C:\safe path with space\program.exe"). (stored in Windows Registry keys) An adversary can place an executable in a higher level directory of the path, and Windows will resolve that executable instead of the intended executable. For example, if the path in a shortcut is C:\program files\myapp.exe, an adversary may create a program at C:\program.exe that will be run instead of the intended program. This technique can be used for persistence if executables are called on a regular basis, as well as privilege escalation if intercepted executables are started by a higher privileged process.

Detection:

Monitor file creation for files named after partial directories and in locations that may be searched for common processes through the environment variable, or otherwise should not be user writable. Monitor the executing process for process executable paths that are named for partial directories. Monitor file creation for programs that are named after Windows system programs or programs commonly executed without a path (such as "findstr," "net," and "python"). If this activity occurs outside of known administration activity, upgrades, installations, or patches, then it may be suspicious. Data and events should not be viewed in isolation, but as part of a chain of behavior that could lead to other activities, such as network connections made for Command and Control, learning details about the environment through Discovery, and Lateral Movement.

Procedures:

- [S0194] PowerSploit: PowerSploit contains a collection of Privesc-PowerUp modules that can discover and exploit unquoted path vulnerabilities.
- [S0363] Empire: Empire contains modules that can discover and exploit unquoted path vulnerabilities.

### T1574.010 - Hijack Execution Flow: Services File Permissions Weakness

Description:

Adversaries may execute their own malicious payloads by hijacking the binaries used by services. Adversaries may use flaws in the permissions of Windows services to replace the binary that is executed upon service start. These service processes may automatically execute specific binaries as part of their functionality or to perform other actions. If the permissions on the file system directory containing a target binary, or permissions on the binary itself are improperly set, then the target binary may be overwritten with another binary using user-level permissions and executed by the original process. If the original process and thread are running under a higher permissions level, then the replaced binary will also execute under higher-level permissions, which could include SYSTEM. Adversaries may use this technique to replace legitimate binaries with malicious ones as a means of executing code at a higher permissions level. If the executing process is set to run at a specific time or during a certain event (e.g., system bootup) then this technique can also be used for persistence.

Detection:

Look for changes to binaries and service executables that may normally occur during software updates. If an executable is written, renamed, and/or moved to match an existing service executable, it could be detected and correlated with other suspicious behavior. Hashing of binaries and service executables could be used to detect replacement against historical data. Look for abnormal process call trees from typical processes and services and for execution of other commands that could relate to Discovery or other adversary techniques.

Procedures:

- [S0089] BlackEnergy: One variant of BlackEnergy locates existing driver services that have been disabled and drops its driver component into one of those service's paths, replacing the legitimate executable. The malware then sets the hijacked service to start automatically to establish persistence.

### T1574.011 - Hijack Execution Flow: Services Registry Permissions Weakness

Description:

Adversaries may execute their own malicious payloads by hijacking the Registry entries used by services. Adversaries may use flaws in the permissions for Registry keys related to services to redirect from the originally specified executable to one that they control, in order to launch their own code when a service starts. Windows stores local service configuration information in the Registry under HKLM\SYSTEM\CurrentControlSet\Services. The information stored under a service's Registry keys can be manipulated to modify a service's execution parameters through tools such as the service controller, sc.exe, PowerShell, or Reg. Access to Registry keys is controlled through access control lists and user permissions. If the permissions for users and groups are not properly set and allow access to the Registry keys for a service, adversaries may change the service's binPath/ImagePath to point to a different executable under their control. When the service starts or is restarted, then the adversary-controlled program will execute, allowing the adversary to establish persistence and/or privilege escalation to the account context the service is set to execute under (local/domain account, SYSTEM, LocalService, or NetworkService). Adversaries may also alter other Registry keys in the service’s Registry tree. For example, the FailureCommand key may be changed so that the service is executed in an elevated context anytime the service fails or is intentionally corrupted. The Performance key contains the name of a driver service's performance DLL and the names of several exported functions in the DLL. If the Performance key is not already present and if an adversary-controlled user has the Create Subkey permission, adversaries may create the Performance key in the service’s Registry tree to point to a malicious DLL. Adversaries may also add the Parameters key, which stores driver-specific data, or other custom subkeys for their malicious services to establish persistence or enable other malicious activities. Additionally, If adversaries launch their malicious services using svchost.exe, the service’s file may be identified using HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\servicename\Parameters\ServiceDll.

Detection:

Service changes are reflected in the Registry. Modification to existing services should not occur frequently. If a service binary path or failure parameters are changed to values that are not typical for that service and does not correlate with software updates, then it may be due to malicious activity. Data and events should not be viewed in isolation, but as part of a chain of behavior that could lead to other activities, such as network connections made for Command and Control, learning details about the environment through Discovery, and Lateral Movement. Tools such as Sysinternals Autoruns may also be used to detect system changes that could be attempts at persistence, including listing current service information. Look for changes to services that do not correlate with known software, patch cycles, etc. Suspicious program execution through services may show up as outlier processes that have not been seen before when compared against historical data. Monitor processes and command-line arguments for actions that could be done to modify services. Remote access tools with built-in features may interact directly with the Windows API to perform these functions outside of typical system utilities. Services may also be changed through Windows system management tools such as Windows Management Instrumentation and PowerShell, so additional logging may need to be configured to gather the appropriate data.

Procedures:

- [C0006] Operation Honeybee: During Operation Honeybee, the threat actors used a batch file that modified the COMSysApp service to load a malicious ipnet.dll payload and to load a DLL into the `svchost.exe` process.

### T1574.012 - Hijack Execution Flow: COR_PROFILER

Description:

Adversaries may leverage the COR_PROFILER environment variable to hijack the execution flow of programs that load the .NET CLR. The COR_PROFILER is a .NET Framework feature which allows developers to specify an unmanaged (or external of .NET) profiling DLL to be loaded into each .NET process that loads the Common Language Runtime (CLR). These profilers are designed to monitor, troubleshoot, and debug managed code executed by the .NET CLR. The COR_PROFILER environment variable can be set at various scopes (system, user, or process) resulting in different levels of influence. System and user-wide environment variable scopes are specified in the Registry, where a Component Object Model (COM) object can be registered as a profiler DLL. A process scope COR_PROFILER can also be created in-memory without modifying the Registry. Starting with .NET Framework 4, the profiling DLL does not need to be registered as long as the location of the DLL is specified in the COR_PROFILER_PATH environment variable. Adversaries may abuse COR_PROFILER to establish persistence that executes a malicious DLL in the context of all .NET processes every time the CLR is invoked. The COR_PROFILER can also be used to elevate privileges (ex: Bypass User Account Control) if the victim .NET process executes at a higher permission level, as well as to hook and Impair Defenses provided by .NET processes.

Detection:

For detecting system and user scope abuse of the COR_PROFILER, monitor the Registry for changes to COR_ENABLE_PROFILING, COR_PROFILER, and COR_PROFILER_PATH that correspond to system and user environment variables that do not correlate to known developer tools. Extra scrutiny should be placed on suspicious modification of these Registry keys by command line tools like wmic.exe, setx.exe, and Reg, monitoring for command-line arguments indicating a change to COR_PROFILER variables may aid in detection. For system, user, and process scope abuse of the COR_PROFILER, monitor for new suspicious unmanaged profiling DLLs loading into .NET processes shortly after the CLR causing abnormal process behavior. Consider monitoring for DLL files that are associated with COR_PROFILER environment variables.

Procedures:

- [G0108] Blue Mockingbird: Blue Mockingbird has used wmic.exe and Windows Registry modifications to set the COR_PROFILER environment variable to execute a malicious DLL whenever a process loads the .NET CLR.
- [S1066] DarkTortilla: DarkTortilla can detect profilers by verifying the `COR_ENABLE_PROFILING` environment variable is present and active.

### T1574.013 - Hijack Execution Flow: KernelCallbackTable

Description:

Adversaries may abuse the KernelCallbackTable of a process to hijack its execution flow in order to run their own payloads. The KernelCallbackTable can be found in the Process Environment Block (PEB) and is initialized to an array of graphic functions available to a GUI process once user32.dll is loaded. An adversary may hijack the execution flow of a process using the KernelCallbackTable by replacing an original callback function with a malicious payload. Modifying callback functions can be achieved in various ways involving related behaviors such as Reflective Code Loading or Process Injection into another process. A pointer to the memory address of the KernelCallbackTable can be obtained by locating the PEB (ex: via a call to the NtQueryInformationProcess() Native API function). Once the pointer is located, the KernelCallbackTable can be duplicated, and a function in the table (e.g., fnCOPYDATA) set to the address of a malicious payload (ex: via WriteProcessMemory()). The PEB is then updated with the new address of the table. Once the tampered function is invoked, the malicious payload will be triggered. The tampered function is typically invoked using a Windows message. After the process is hijacked and malicious code is executed, the KernelCallbackTable may also be restored to its original state by the rest of the malicious payload. Use of the KernelCallbackTable to hijack execution flow may evade detection from security products since the execution can be masked under a legitimate process.

Detection:

Analyze process behavior to determine if a process is performing actions it usually does not, such as opening network connections, reading files, or other suspicious behaviors that could relate to post-compromise behavior. Monitoring Windows API calls indicative of the various types of code injection may generate a significant amount of data and may not be directly useful for defense unless collected under specific circumstances. for known bad sequence of calls, since benign use of API functions may be common and difficult to distinguish from malicious behavior. Windows API calls such as WriteProcessMemory() and NtQueryInformationProcess() with the parameter set to ProcessBasicInformation may be used for this technique.

Procedures:

- [G0032] Lazarus Group: Lazarus Group has abused the KernelCallbackTable to hijack process control flow and execute shellcode.
- [S0182] FinFisher: FinFisher has used the KernelCallbackTable to hijack the execution flow of a process by replacing the __fnDWORD function with the address of a created Asynchronous Procedure Call stub routine.

### T1574.014 - Hijack Execution Flow: AppDomainManager

Description:

Adversaries may execute their own malicious payloads by hijacking how the .NET `AppDomainManager` loads assemblies. The .NET framework uses the `AppDomainManager` class to create and manage one or more isolated runtime environments (called application domains) inside a process to host the execution of .NET applications. Assemblies (`.exe` or `.dll` binaries compiled to run as .NET code) may be loaded into an application domain as executable code. Known as "AppDomainManager injection," adversaries may execute arbitrary code by hijacking how .NET applications load assemblies. For example, malware may create a custom application domain inside a target process to load and execute an arbitrary assembly. Alternatively, configuration files (`.config`) or process environment variables that define .NET runtime settings may be tampered with to instruct otherwise benign .NET applications to load a malicious assembly (identified by name) into the target process.

Procedures:

- [S1152] IMAPLoader: IMAPLoader is executed via the AppDomainManager injection technique.


### T1653 - Power Settings

Description:

Adversaries may impair a system's ability to hibernate, reboot, or shut down in order to extend access to infected machines. When a computer enters a dormant state, some or all software and hardware may cease to operate which can disrupt malicious activity. Adversaries may abuse system utilities and configuration settings to maintain access by preventing machines from entering a state, such as standby, that can terminate malicious activity. For example, `powercfg` controls all configurable power system settings on a Windows system and can be abused to prevent an infected host from locking or shutting down. Adversaries may also extend system lock screen timeout settings. Other relevant settings, such as disk and hibernate timeout, can be similarly abused to keep the infected machine running even if no user is active. Aware that some malware cannot survive system reboots, adversaries may entirely delete files used to invoke system shut down or reboot.

Detection:

Command-line invocation of tools capable of modifying services may be unusual and can be monitored for and alerted on, depending on how systems are typically used in a particular environment.

Procedures:

- [C0046] ArcaneDoor: ArcaneDoor involved exploitation of CVE-2024-20353 to force a victim Cisco ASA to reboot, triggering the automated unzipping and execution of the Line Runner implant.
- [S1188] Line Runner: Line Runner used CVE-2024-20353 to trigger victim devices to reboot, in the process unzipping and installing the Line Dancer payload.
- [S1186] Line Dancer: Line Dancer can modify the crash dump process on infected machines to skip crash dump generation and proceed directly to device reboot for both persistence and forensic evasion purposes.


### T1668 - Exclusive Control

Description:

Adversaries who successfully compromise a system may attempt to maintain persistence by “closing the door” behind them – in other words, by preventing other threat actors from initially accessing or maintaining a foothold on the same system. For example, adversaries may patch a vulnerable, compromised system to prevent other threat actors from leveraging that vulnerability in the future. They may “close the door” in other ways, such as disabling vulnerable services, stripping privileges from accounts, or removing other malware already on the compromised device. Hindering other threat actors may allow an adversary to maintain sole access to a compromised system or network. This prevents the threat actor from needing to compete with or even being removed themselves by other threat actors. It also reduces the “noise” in the environment, lowering the possibility of being caught and evicted by defenders. Finally, in the case of Resource Hijacking, leveraging a compromised device’s full power allows the threat actor to maximize profit.


### T1671 - Cloud Application Integration

Description:

Adversaries may achieve persistence by leveraging OAuth application integrations in a software-as-a-service environment. Adversaries may create a custom application, add a legitimate application into the environment, or even co-opt an existing integration to achieve malicious ends. OAuth is an open standard that allows users to authorize applications to access their information on their behalf. In a SaaS environment such as Microsoft 365 or Google Workspace, users may integrate applications to improve their workflow and achieve tasks. Leveraging application integrations may allow adversaries to persist in an environment – for example, by granting consent to an application from a high-privileged adversary-controlled account in order to maintain access to its data, even in the event of losing access to the account. In some cases, integrations may remain valid even after the original consenting user account is disabled. Application integrations may also allow adversaries to bypass multi-factor authentication requirements through the use of Application Access Tokens. Finally, they may enable persistent Automated Exfiltration over time. Creating or adding a new application may require the adversary to create a dedicated Cloud Account for the application and assign it Additional Cloud Roles – for example, in Microsoft 365 environments, an application can only access resources via an associated service principal.

