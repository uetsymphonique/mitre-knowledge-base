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


### T1055.001 - Process Injection: Dynamic-link Library Injection

Description:

Adversaries may inject dynamic-link libraries (DLLs) into processes in order to evade process-based defenses as well as possibly elevate privileges. DLL injection is a method of executing arbitrary code in the address space of a separate live process. DLL injection is commonly performed by writing the path to a DLL in the virtual address space of the target process before loading the DLL by invoking a new thread. The write can be performed with native Windows API calls such as VirtualAllocEx and WriteProcessMemory, then invoked with CreateRemoteThread (which calls the LoadLibrary API responsible for loading the DLL). Variations of this method such as reflective DLL injection (writing a self-mapping DLL into a process) and memory module (map DLL when writing into process) overcome the address relocation issue as well as the additional APIs to invoke execution (since these methods load and execute the files in memory by manually preforming the function of LoadLibrary). Another variation of this method, often referred to as Module Stomping/Overloading or DLL Hollowing, may be leveraged to conceal injected code within a process. This method involves loading a legitimate DLL into a remote process then manually overwriting the module's AddressOfEntryPoint before starting a new thread in the target process. This variation allows attackers to hide malicious injected code by potentially backing its execution with a legitimate DLL file on disk. Running code in the context of another process may allow access to the process's memory, system/network resources, and possibly elevated privileges. Execution via DLL injection may also evade detection from security products since the execution is masked under a legitimate process.

Detection:

Monitoring Windows API calls indicative of the various types of code injection may generate a significant amount of data and may not be directly useful for defense unless collected under specific circumstances for known bad sequences of calls, since benign use of API functions may be common and difficult to distinguish from malicious behavior. Windows API calls such as CreateRemoteThread and those that can be used to modify memory within another process, such as VirtualAllocEx/WriteProcessMemory, may be used for this technique. Monitor DLL/PE file events, specifically creation of these binary files as well as the loading of DLLs into processes. Look for DLLs that are not recognized or not normally loaded into a process. Analyze process behavior to determine if a process is performing actions it usually does not, such as opening network connections, reading files, or other suspicious actions that could relate to post-compromise behavior.

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
- [S1039] Bumblebee: The Bumblebee loader can support the `Dij` command which gives it the ability to inject DLLs into the memory of other processes.
- [S0681] Lizar: Lizar has used the PowerKatz plugin that can be loaded into the address space of a PowerShell process through reflective DLL loading.
- [G1026] Malteiro: Malteiro has injected Mispadu’s DLL into a process.
- [S1044] FunnyDream: The FunnyDream FilepakMonitor component can inject into the Bka.exe process using the `VirtualAllocEx`, `WriteProcessMemory` and `CreateRemoteThread` APIs to load the DLL component.
- [S0449] Maze: Maze has injected the malware DLL into a target process.
- [S0167] Matryoshka: Matryoshka uses reflective DLL injection to inject the malicious library and execute the RAT.
- [S0192] Pupy: Pupy can migrate into another process using reflective DLL injection.
- [S0194] PowerSploit: PowerSploit contains a collection of CodeExecution modules that inject code (DLL, shellcode) into a process.
- [S0182] FinFisher: FinFisher injects itself into various processes depending on whether it is low integrity or high integrity.
- [S0501] PipeMon: PipeMon can inject its modules into various processes using reflective DLL loading.
- [S0024] Dyre: Dyre injects into other processes to load modules.
- [S1210] Sagerunex: Sagerunex is designed to be dynamic link library (DLL) injected into an infected endpoint and executed directly in memory.
- [G0135] BackdoorDiplomacy: BackdoorDiplomacy has dropped legitimate software onto a compromised host and used it to execute malicious DLLs.
- [S0460] Get2: Get2 has the ability to inject DLLs into processes.
- [S0011] Taidoor: Taidoor can perform DLL loading.
- [S0241] RATANKBA: RATANKBA performs a reflective DLL injection using a given pid.
- [S1081] BADHATCH: BADHATCH has the ability to execute a malicious DLL by injecting into `explorer.exe` on a compromised machine.
- [S0576] MegaCortex: MegaCortex loads injecthelper.dll into a newly created rundll32.exe process.
- [S0603] Stuxnet: Stuxnet injects an entire DLL into an existing, newly created, or preselected trusted process.
- [C0015] C0015: During C0015, the threat actors used a DLL named `D8B3.dll` that was injected into the Winlogon process.
- [G0065] Leviathan: Leviathan has utilized techniques like reflective DLL loading to write a DLL into memory and load a shell that provides backdoor access to the victim.
- [S0265] Kazuar: If running in a Windows environment, Kazuar saves a DLL to disk that is injected into the explorer.exe process to execute the payload. Kazuar can also be configured to inject and execute within specific processes.
- [S0038] Duqu: Duqu will inject itself into different processes to evade detection. The selection of the target process is influenced by the security software that is installed on the system (Duqu will inject into different processes depending on which security suite is installed on the infected host).
- [S0012] PoisonIvy: PoisonIvy can inject a malicious DLL into a process.
- [S0021] Derusbi: Derusbi injects itself into the secure shell (SSH) process.
- [S0412] ZxShell: ZxShell is injected into a shared SVCHOST process.
- [G0024] Putter Panda: An executable dropped onto victims by Putter Panda aims to inject the specified DLL into a process that would normally be accessing the network, including Outlook Express (msinm.exe), Outlook (outlook.exe), Internet Explorer (iexplore.exe), and Firefox (firefox.exe).
- [S0666] Gelsemium: Gelsemium has the ability to inject DLLs into specific processes.
- [S0135] HIDEDRV: HIDEDRV injects a DLL for Downdelph into the explorer.exe process.
- [S0335] Carbon: Carbon has a command to inject code into a process.
- [G0032] Lazarus Group: A Lazarus Group malware sample performs reflective DLL injection.
- [G0081] Tropic Trooper: Tropic Trooper has injected a DLL backdoor into dllhost.exe and svchost.exe.
- [S0581] IronNetInjector: IronNetInjector has the ability to inject a DLL into running processes, including the IronNetInjector DLL into explorer.exe.
- [S0467] TajMahal: TajMahal has the ability to inject DLLs for malicious plugins into running processes.
- [S1026] Mongall: Mongall can inject a DLL into `rundll32.exe` for execution.
- [S0575] Conti: Conti has loaded an encrypted DLL into memory and then executes it.
- [S0458] Ramsay: Ramsay can use ImprovedReflectiveDLLInjection to deploy components.
- [S0022] Uroburos: Uroburos can use DLL injection to load embedded files and modules.
- [S0484] Carberp: Carberp's bootkit can inject a malicious DLL into the address space of running processes.
- [S0615] SombRAT: SombRAT can execute loadfromfile, loadfromstorage, and loadfrommem to inject a DLL from disk, storage, or memory respectively.
- [S0018] Sykipot: Sykipot injects itself into running instances of outlook.exe, iexplore.exe, or firefox.exe.
- [S0367] Emotet: Emotet has been observed injecting in to Explorer.exe and other processes.
- [S0456] Aria-body: Aria-body has the ability to inject itself into another process such as rundll32.exe and dllhost.exe.
- [S0457] Netwalker: The Netwalker DLL has been injected reflectively into the memory of a legitimate running process.
- [G0092] TA505: TA505 has been seen injecting a DLL into winword.exe.
- [S0081] Elise: Elise injects DLL files into iexplore.exe.
- [G0102] Wizard Spider: Wizard Spider has injected malicious DLLs into memory with read, write, and execute permissions.
- [S0596] ShadowPad: ShadowPad has injected a DLL into svchost.exe.

### T1055.002 - Process Injection: Portable Executable Injection

Description:

Adversaries may inject portable executables (PE) into processes in order to evade process-based defenses as well as possibly elevate privileges. PE injection is a method of executing arbitrary code in the address space of a separate live process. PE injection is commonly performed by copying code (perhaps without a file on disk) into the virtual address space of the target process before invoking it via a new thread. The write can be performed with native Windows API calls such as VirtualAllocEx and WriteProcessMemory, then invoked with CreateRemoteThread or additional code (ex: shellcode). The displacement of the injected code does introduce the additional requirement for functionality to remap memory references. Running code in the context of another process may allow access to the process's memory, system/network resources, and possibly elevated privileges. Execution via PE injection may also evade detection from security products since the execution is masked under a legitimate process.

Detection:

Monitoring Windows API calls indicative of the various types of code injection may generate a significant amount of data and may not be directly useful for defense unless collected under specific circumstances for known bad sequences of calls, since benign use of API functions may be common and difficult to distinguish from malicious behavior. Windows API calls such as CreateRemoteThread and those that can be used to modify memory within another process, such as VirtualAllocEx/WriteProcessMemory, may be used for this technique. Analyze process behavior to determine if a process is performing actions it usually does not, such as opening network connections, reading files, or other suspicious actions that could relate to post-compromise behavior.

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

Description:

Adversaries may inject malicious code into hijacked processes in order to evade process-based defenses as well as possibly elevate privileges. Thread Execution Hijacking is a method of executing arbitrary code in the address space of a separate live process. Thread Execution Hijacking is commonly performed by suspending an existing process then unmapping/hollowing its memory, which can then be replaced with malicious code or the path to a DLL. A handle to an existing victim process is first created with native Windows API calls such as OpenThread. At this point the process can be suspended then written to, realigned to the injected code, and resumed via SuspendThread , VirtualAllocEx, WriteProcessMemory, SetThreadContext, then ResumeThread respectively. This is very similar to Process Hollowing but targets an existing process rather than creating a process in a suspended state. Running code in the context of another process may allow access to the process's memory, system/network resources, and possibly elevated privileges. Execution via Thread Execution Hijacking may also evade detection from security products since the execution is masked under a legitimate process.

Detection:

Monitoring Windows API calls indicative of the various types of code injection may generate a significant amount of data and may not be directly useful for defense unless collected under specific circumstances for known bad sequences of calls, since benign use of API functions may be common and difficult to distinguish from malicious behavior. Windows API calls such as CreateRemoteThread, SuspendThread/SetThreadContext/ResumeThread, and those that can be used to modify memory within another process, such as VirtualAllocEx/WriteProcessMemory, may be used for this technique. Analyze process behavior to determine if a process is performing actions it usually does not, such as opening network connections, reading files, or other suspicious actions that could relate to post-compromise behavior.

Procedures:

- [S1145] Pikabot: Pikabot can create a suspended instance of a legitimate process (e.g., ctfmon.exe), allocate memory within the suspended process corresponding to Pikabot's core module, then redirect execution flow via `SetContextThread` API so that when the thread resumes the Pikabot core module is executed.
- [S0579] Waterbear: Waterbear can use thread injection to inject shellcode into the process of security software.
- [S0168] Gazer: Gazer performs thread execution hijacking to inject its orchestrator into a running thread from a remote process.
- [S0094] Trojan.Karagany: Trojan.Karagany can inject a suspended thread of its own process into a new process and initiate via the ResumeThread API.

### T1055.004 - Process Injection: Asynchronous Procedure Call

Description:

Adversaries may inject malicious code into processes via the asynchronous procedure call (APC) queue in order to evade process-based defenses as well as possibly elevate privileges. APC injection is a method of executing arbitrary code in the address space of a separate live process. APC injection is commonly performed by attaching malicious code to the APC Queue of a process's thread. Queued APC functions are executed when the thread enters an alterable state. A handle to an existing victim process is first created with native Windows API calls such as OpenThread. At this point QueueUserAPC can be used to invoke a function (such as LoadLibrayA pointing to a malicious DLL). A variation of APC injection, dubbed "Early Bird injection", involves creating a suspended process in which malicious code can be written and executed before the process' entry point (and potentially subsequent anti-malware hooks) via an APC. AtomBombing is another variation that utilizes APCs to invoke malicious code previously written to the global atom table. Running code in the context of another process may allow access to the process's memory, system/network resources, and possibly elevated privileges. Execution via APC injection may also evade detection from security products since the execution is masked under a legitimate process.

Detection:

Monitoring Windows API calls indicative of the various types of code injection may generate a significant amount of data and may not be directly useful for defense unless collected under specific circumstances for known bad sequences of calls, since benign use of API functions may be common and difficult to distinguish from malicious behavior. Windows API calls such as SuspendThread/SetThreadContext/ResumeThread, QueueUserAPC/NtQueueApcThread, and those that can be used to modify memory within another process, such as VirtualAllocEx/WriteProcessMemory, may be used for this technique. Analyze process behavior to determine if a process is performing actions it usually does not, such as opening network connections, reading files, or other suspicious actions that could relate to post-compromise behavior.

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

Description:

Adversaries may inject malicious code into processes via thread local storage (TLS) callbacks in order to evade process-based defenses as well as possibly elevate privileges. TLS callback injection is a method of executing arbitrary code in the address space of a separate live process. TLS callback injection involves manipulating pointers inside a portable executable (PE) to redirect a process to malicious code before reaching the code's legitimate entry point. TLS callbacks are normally used by the OS to setup and/or cleanup data used by threads. Manipulating TLS callbacks may be performed by allocating and writing to specific offsets within a process’ memory space using other Process Injection techniques such as Process Hollowing. Running code in the context of another process may allow access to the process's memory, system/network resources, and possibly elevated privileges. Execution via TLS callback injection may also evade detection from security products since the execution is masked under a legitimate process.

Detection:

Monitoring Windows API calls indicative of the various types of code injection may generate a significant amount of data and may not be directly useful for defense unless collected under specific circumstances for known bad sequences of calls, since benign use of API functions may be common and difficult to distinguish from malicious behavior. Windows API calls such as CreateRemoteThread, SuspendThread/SetThreadContext/ResumeThread, and those that can be used to modify memory within another process, such as VirtualAllocEx/WriteProcessMemory, may be used for this technique. Analyze process behavior to determine if a process is performing actions it usually does not, such as opening network connections, reading files, or other suspicious actions that could relate to post-compromise behavior.

Procedures:

- [S0386] Ursnif: Ursnif has injected code into target processes via thread local storage callbacks.

### T1055.008 - Process Injection: Ptrace System Calls

Description:

Adversaries may inject malicious code into processes via ptrace (process trace) system calls in order to evade process-based defenses as well as possibly elevate privileges. Ptrace system call injection is a method of executing arbitrary code in the address space of a separate live process. Ptrace system call injection involves attaching to and modifying a running process. The ptrace system call enables a debugging process to observe and control another process (and each individual thread), including changing memory and register values. Ptrace system call injection is commonly performed by writing arbitrary code into a running process (ex: malloc) then invoking that memory with PTRACE_SETREGS to set the register containing the next instruction to execute. Ptrace system call injection can also be done with PTRACE_POKETEXT/PTRACE_POKEDATA, which copy data to a specific address in the target processes’ memory (ex: the current address of the next instruction). Ptrace system call injection may not be possible targeting processes that are non-child processes and/or have higher-privileges. Running code in the context of another process may allow access to the process's memory, system/network resources, and possibly elevated privileges. Execution via ptrace system call injection may also evade detection from security products since the execution is masked under a legitimate process.

Detection:

Monitoring for Linux specific calls such as the ptrace system call should not generate large amounts of data due to their specialized nature, and can be a very effective method to detect some of the common process injection methods. Analyze process behavior to determine if a process is performing actions it usually does not, such as opening network connections, reading files, or other suspicious actions that could relate to post-compromise behavior.

Procedures:

- [S1109] PACEMAKER: PACEMAKER can use PTRACE to attach to a targeted process to read process memory.

### T1055.009 - Process Injection: Proc Memory

Description:

Adversaries may inject malicious code into processes via the /proc filesystem in order to evade process-based defenses as well as possibly elevate privileges. Proc memory injection is a method of executing arbitrary code in the address space of a separate live process. Proc memory injection involves enumerating the memory of a process via the /proc filesystem (/proc/[pid]) then crafting a return-oriented programming (ROP) payload with available gadgets/instructions. Each running process has its own directory, which includes memory mappings. Proc memory injection is commonly performed by overwriting the target processes’ stack using memory mappings provided by the /proc filesystem. This information can be used to enumerate offsets (including the stack) and gadgets (or instructions within the program that can be used to build a malicious payload) otherwise hidden by process memory protections such as address space layout randomization (ASLR). Once enumerated, the target processes’ memory map within /proc/[pid]/maps can be overwritten using dd. Other techniques such as Dynamic Linker Hijacking may be used to populate a target process with more available gadgets. Similar to Process Hollowing, proc memory injection may target child processes (such as a backgrounded copy of sleep). Running code in the context of another process may allow access to the process's memory, system/network resources, and possibly elevated privileges. Execution via proc memory injection may also evade detection from security products since the execution is masked under a legitimate process.

Detection:

File system monitoring can determine if /proc files are being modified. Users should not have permission to modify these in most cases. Analyze process behavior to determine if a process is performing actions it usually does not, such as opening network connections, reading files, or other suspicious actions that could relate to post-compromise behavior.

Procedures:

- [C0035] KV Botnet Activity: KV Botnet Activity final payload installation includes mounting and binding to the \/proc\/ filepath on the victim system to enable subsequent operation in memory while also removing on-disk artifacts.

### T1055.011 - Process Injection: Extra Window Memory Injection

Description:

Adversaries may inject malicious code into process via Extra Window Memory (EWM) in order to evade process-based defenses as well as possibly elevate privileges. EWM injection is a method of executing arbitrary code in the address space of a separate live process. Before creating a window, graphical Windows-based processes must prescribe to or register a windows class, which stipulate appearance and behavior (via windows procedures, which are functions that handle input/output of data). Registration of new windows classes can include a request for up to 40 bytes of EWM to be appended to the allocated memory of each instance of that class. This EWM is intended to store data specific to that window and has specific application programming interface (API) functions to set and get its value. Although small, the EWM is large enough to store a 32-bit pointer and is often used to point to a windows procedure. Malware may possibly utilize this memory location in part of an attack chain that includes writing code to shared sections of the process’s memory, placing a pointer to the code in EWM, then invoking execution by returning execution control to the address in the process’s EWM. Execution granted through EWM injection may allow access to both the target process's memory and possibly elevated privileges. Writing payloads to shared sections also avoids the use of highly monitored API calls such as WriteProcessMemory and CreateRemoteThread. More sophisticated malware samples may also potentially bypass protection mechanisms such as data execution prevention (DEP) by triggering a combination of windows procedures and other system functions that will rewrite the malicious payload inside an executable portion of the target process. Running code in the context of another process may allow access to the process's memory, system/network resources, and possibly elevated privileges. Execution via EWM injection may also evade detection from security products since the execution is masked under a legitimate process.

Detection:

Monitor for API calls related to enumerating and manipulating EWM such as GetWindowLong and SetWindowLong . Malware associated with this technique have also used SendNotifyMessage to trigger the associated window procedure and eventual malicious injection.

Procedures:

- [S0091] Epic: Epic has overwritten the function pointer in the extra window memory of Explorer's Shell_TrayWnd in order to execute malicious code in the context of the explorer.exe process.
- [S0177] Power Loader: Power Loader overwrites Explorer’s Shell_TrayWnd extra window memory to redirect execution to a NTDLL function that is abused to assemble and execute a return-oriented programming (ROP) chain and create a malicious thread within Explorer.exe.

### T1055.012 - Process Injection: Process Hollowing

Description:

Adversaries may inject malicious code into suspended and hollowed processes in order to evade process-based defenses. Process hollowing is a method of executing arbitrary code in the address space of a separate live process. Process hollowing is commonly performed by creating a process in a suspended state then unmapping/hollowing its memory, which can then be replaced with malicious code. A victim process can be created with native Windows API calls such as CreateProcess, which includes a flag to suspend the processes primary thread. At this point the process can be unmapped using APIs calls such as ZwUnmapViewOfSection or NtUnmapViewOfSection before being written to, realigned to the injected code, and resumed via VirtualAllocEx, WriteProcessMemory, SetThreadContext, then ResumeThread respectively. This is very similar to Thread Local Storage but creates a new process rather than targeting an existing process. This behavior will likely not result in elevated privileges since the injected process was spawned from (and thus inherits the security context) of the injecting process. However, execution via process hollowing may also evade detection from security products since the execution is masked under a legitimate process.

Detection:

Monitoring Windows API calls indicative of the various types of code injection may generate a significant amount of data and may not be directly useful for defense unless collected under specific circumstances for known bad sequences of calls, since benign use of API functions may be common and difficult to distinguish from malicious behavior. Windows API calls such as CreateRemoteThread, SuspendThread/SetThreadContext/ResumeThread, and those that can be used to modify memory within another process, such as VirtualAllocEx/WriteProcessMemory, may be used for this technique. Processing hollowing commonly involves spawning an otherwise benign victim process. Consider correlating detections of processes created in a suspended state (ex: through API flags or process’ thread metadata) with other malicious activity such as attempts to modify a process' memory, especially by its parent process, or other abnormal process behavior. Analyze process behavior to determine if a process is performing actions it usually does not, such as opening network connections, reading files, or other suspicious actions that could relate to post-compromise behavior.

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
- [G1043] BlackByte: BlackByte used process hollowing for defense evasion purposes.
- [S1130] Raspberry Robin: Raspberry Robin will execute a legitimate process, then suspend it to inject code for a Tor client into the process, followed by resumption of the process to enable Tor client execution.
- [S0226] Smoke Loader: Smoke Loader spawns a new copy of c:\windows\syswow64\explorer.exe and then replaces the executable code in memory with malware.
- [S0373] Astaroth: Astaroth can create a new process in a suspended state from a targeted legitimate process in order to unmap its memory and replace it with malicious code.
- [S0567] Dtrack: Dtrack has used process hollowing shellcode to target a predefined list of processes from %SYSTEM32%.
- [G1018] TA2541: TA2541 has used process hollowing to execute CyberGate malware.
- [S0689] WhisperGate: WhisperGate has the ability to inject its fourth stage into a suspended process created by the legitimate Windows utility `InstallUtil.exe`.
- [S0128] BADNEWS: BADNEWS has a command to download an .exe and use process hollowing to inject it into a new process.
- [S0660] Clambling: Clambling can execute binaries through process hollowing.
- [S1138] Gootloader: Gootloader can inject its Delphi executable into ImagingDevices.exe using a process hollowing technique.
- [G0045] menuPass: menuPass has used process hollowing in iexplore.exe to load the RedLeaves implant.
- [S0189] ISMInjector: ISMInjector hollows out a newly created process RegASM.exe and injects its payload into the hollowed process.
- [S1018] Saint Bot: The Saint Bot loader has used API calls to spawn `MSBuild.exe` in a suspended state before injecting the decrypted Saint Bot binary into it.
- [S0198] NETWIRE: The NETWIRE payload has been injected into benign Microsoft executables via process hollowing.
- [S0367] Emotet: Emotet uses a copy of `certutil.exe` stored in a temporary directory for process hollowing, starting the program in a suspended state before loading malicious code.
- [S0331] Agent Tesla: Agent Tesla has used process hollowing to create and manipulate processes through sections of unmapped memory by reallocating that space with its malicious code.
- [S0229] Orz: Some Orz versions have an embedded DLL known as MockDll that uses process hollowing and Regsvr32 to execute another payload.
- [S0266] TrickBot: TrickBot injects into the svchost.exe process.
- [S0386] Ursnif: Ursnif has used process hollowing to inject into child processes.
- [G0094] Kimsuky: Kimsuky has used a file injector DLL to spawn a benign process on the victim's system and inject the malicious payload into it via process hollowing.
- [S0534] Bazar: Bazar can inject into a target process including Svchost, Explorer, and cmd using process hollowing.
- [S0127] BBSRAT: BBSRAT has been seen loaded into msiexec.exe through process hollowing to hide its execution.
- [S0038] Duqu: Duqu is capable of loading executable code via process hollowing.
- [S1111] DarkGate: DarkGate leverages process hollowing techniques to evade detection, such as decrypting the content of an encrypted PE file and injecting it into the process vbc.exe.

### T1055.013 - Process Injection: Process Doppelgänging

Description:

Adversaries may inject malicious code into process via process doppelgänging in order to evade process-based defenses as well as possibly elevate privileges. Process doppelgänging is a method of executing arbitrary code in the address space of a separate live process. Windows Transactional NTFS (TxF) was introduced in Vista as a method to perform safe file operations. To ensure data integrity, TxF enables only one transacted handle to write to a file at a given time. Until the write handle transaction is terminated, all other handles are isolated from the writer and may only read the committed version of the file that existed at the time the handle was opened. To avoid corruption, TxF performs an automatic rollback if the system or application fails during a write transaction. Although deprecated, the TxF application programming interface (API) is still enabled as of Windows 10. Adversaries may abuse TxF to a perform a file-less variation of Process Injection. Similar to Process Hollowing, process doppelgänging involves replacing the memory of a legitimate process, enabling the veiled execution of malicious code that may evade defenses and detection. Process doppelgänging's use of TxF also avoids the use of highly-monitored API functions such as NtUnmapViewOfSection, VirtualProtectEx, and SetThreadContext. Process Doppelgänging is implemented in 4 steps : * Transact – Create a TxF transaction using a legitimate executable then overwrite the file with malicious code. These changes will be isolated and only visible within the context of the transaction. * Load – Create a shared section of memory and load the malicious executable. * Rollback – Undo changes to original executable, effectively removing malicious code from the file system. * Animate – Create a process from the tainted section of memory and initiate execution. This behavior will likely not result in elevated privileges since the injected process was spawned from (and thus inherits the security context) of the injecting process. However, execution via process doppelgänging may evade detection from security products since the execution is masked under a legitimate process.

Detection:

Monitor and analyze calls to CreateTransaction, CreateFileTransacted, RollbackTransaction, and other rarely used functions indicative of TxF activity. Process Doppelgänging also invokes an outdated and undocumented implementation of the Windows process loader via calls to NtCreateProcessEx and NtCreateThreadEx as well as API calls used to modify memory within another process, such as WriteProcessMemory. Scan file objects reported during the PsSetCreateProcessNotifyRoutine, which triggers a callback whenever a process is created or deleted, specifically looking for file objects with enabled write access. Also consider comparing file objects loaded in memory to the corresponding file on disk. Analyze process behavior to determine if a process is performing actions it usually does not, such as opening network connections, reading files, or other suspicious actions that could relate to post-compromise behavior.

Procedures:

- [S0242] SynAck: SynAck abuses NTFS transactions to launch and conceal malicious processes.
- [S0534] Bazar: Bazar can inject into a target process using process doppelgänging.
- [G0077] Leafminer: Leafminer has used Process Doppelgänging to evade security software while deploying tools on compromised systems.

### T1055.014 - Process Injection: VDSO Hijacking

Description:

Adversaries may inject malicious code into processes via VDSO hijacking in order to evade process-based defenses as well as possibly elevate privileges. Virtual dynamic shared object (vdso) hijacking is a method of executing arbitrary code in the address space of a separate live process. VDSO hijacking involves redirecting calls to dynamically linked shared libraries. Memory protections may prevent writing executable code to a process via Ptrace System Calls. However, an adversary may hijack the syscall interface code stubs mapped into a process from the vdso shared object to execute syscalls to open and map a malicious shared object. This code can then be invoked by redirecting the execution flow of the process via patched memory address references stored in a process' global offset table (which store absolute addresses of mapped library functions). Running code in the context of another process may allow access to the process's memory, system/network resources, and possibly elevated privileges. Execution via VDSO hijacking may also evade detection from security products since the execution is masked under a legitimate process.

Detection:

Monitor for malicious usage of system calls, such as ptrace and mmap, that can be used to attach to, manipulate memory, then redirect a processes' execution path. Monitoring for Linux specific calls such as the ptrace system call should not generate large amounts of data due to their specialized nature, and can be a very effective method to detect some of the common process injection methods. Analyze process behavior to determine if a process is performing actions it usually does not, such as opening network connections, reading files, or other suspicious actions that could relate to post-compromise behavior.

### T1055.015 - Process Injection: ListPlanting

Description:

Adversaries may abuse list-view controls to inject malicious code into hijacked processes in order to evade process-based defenses as well as possibly elevate privileges. ListPlanting is a method of executing arbitrary code in the address space of a separate live process. Code executed via ListPlanting may also evade detection from security products since the execution is masked under a legitimate process. List-view controls are user interface windows used to display collections of items. Information about an application's list-view settings are stored within the process' memory in a SysListView32 control. ListPlanting (a form of message-passing "shatter attack") may be performed by copying code into the virtual address space of a process that uses a list-view control then using that code as a custom callback for sorting the listed items. Adversaries must first copy code into the target process’ memory space, which can be performed various ways including by directly obtaining a handle to the SysListView32 child of the victim process window (via Windows API calls such as FindWindow and/or EnumWindows) or other Process Injection methods. Some variations of ListPlanting may allocate memory in the target process but then use window messages to copy the payload, to avoid the use of the highly monitored WriteProcessMemory function. For example, an adversary can use the PostMessage and/or SendMessage API functions to send LVM_SETITEMPOSITION and LVM_GETITEMPOSITION messages, effectively copying a payload 2 bytes at a time to the allocated memory. Finally, the payload is triggered by sending the LVM_SORTITEMS message to the SysListView32 child of the process window, with the payload within the newly allocated buffer passed and executed as the ListView_SortItems callback.

Detection:

Monitoring Windows API calls indicative of the various types of code injection may generate a significant amount of data and may not be directly useful for defense unless collected under specific circumstances for known bad sequences of calls, since benign use of API functions may be common and difficult to distinguish from malicious behavior. Windows API calls such as FindWindow, FindWindowEx, EnumWindows, EnumChildWindows, and those that can be used to modify memory within another process, such as VirtualAllocEx/WriteProcessMemory, may be abused for this technique. Consider monitoring for excessive use of SendMessage and/or PostMessage API functions with LVM_SETITEMPOSITION and/or LVM_GETITEMPOSITION arguments. Analyze process behavior to determine if a process is performing unusual actions, such as opening network connections, reading files, or other suspicious actions that could relate to post-compromise behavior.

Procedures:

- [S0260] InvisiMole: InvisiMole has used ListPlanting to inject code into a trusted process.


### T1068 - Exploitation for Privilege Escalation

Description:

Adversaries may exploit software vulnerabilities in an attempt to elevate privileges. Exploitation of a software vulnerability occurs when an adversary takes advantage of a programming error in a program, service, or within the operating system software or kernel itself to execute adversary-controlled code. Security constructs such as permission levels will often hinder access to information and use of certain techniques, so adversaries will likely need to perform privilege escalation to include use of software exploitation to circumvent those restrictions. When initially gaining access to a system, an adversary may be operating within a lower privileged process which will prevent them from accessing certain resources on the system. Vulnerabilities may exist, usually in operating system components and software commonly running at higher permissions, that can be exploited to gain higher levels of access on the system. This could enable someone to move from unprivileged or user level permissions to SYSTEM or root permissions depending on the component that is vulnerable. This could also enable an adversary to move from a virtualized environment, such as within a virtual machine or container, onto the underlying host. This may be a necessary step for an adversary compromising an endpoint system that has been properly configured and limits other privilege escalation methods. Adversaries may bring a signed vulnerable driver onto a compromised machine so that they can exploit the vulnerability to execute code in kernel mode. This process is sometimes referred to as Bring Your Own Vulnerable Driver (BYOVD). Adversaries may include the vulnerable driver with files delivered during Initial Access or download it to a compromised system via Ingress Tool Transfer or Lateral Tool Transfer.

Detection:

Detecting software exploitation may be difficult depending on the tools available. Software exploits may not always succeed or may cause the exploited process to become unstable or crash. Also look for behavior on the endpoint system that might indicate successful compromise, such as abnormal behavior of the processes. This could include suspicious files written to disk, evidence of Process Injection for attempts to hide execution or evidence of Discovery. Consider monitoring for the presence or loading (ex: Sysmon Event ID 6) of known vulnerable drivers that adversaries may drop and exploit to execute code in kernel mode. Higher privileges are often necessary to perform additional actions such as some methods of OS Credential Dumping. Look for additional activity that may indicate an adversary has gained higher privileges.

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
- [S1181] BlackByte 2.0 Ransomware: BlackByte 2.0 Ransomware exploits a vulnerability in the RTCore64.sys driver (CVE-2019-16098) to enable privilege escalation and defense evasion when run as a service.
- [S0260] InvisiMole: InvisiMole has exploited CVE-2007-5633 vulnerability in the speedfan.sys driver to obtain kernel mode privileges.
- [G1019] MoustachedBouncer: MoustachedBouncer has exploited CVE-2021-1732 to execute malware components with elevated rights.
- [G1017] Volt Typhoon: Volt Typhoon has gained initial access by exploiting privilege escalation vulnerabilities in the operating system or network services.
- [G0037] FIN6: FIN6 has used tools to exploit Windows vulnerabilities in order to escalate privileges. The tools targeted CVE-2013-3660, CVE-2011-2005, and CVE-2010-4398, all of which could allow local users to access kernel-level privileges.
- [G0107] Whitefly: Whitefly has used an open-source tool to exploit a known Windows privilege escalation vulnerability (CVE-2016-0051) on unpatched computers.
- [G1002] BITTER: BITTER has exploited CVE-2021-1732 for privilege escalation.
- [S0044] JHUHUGIT: JHUHUGIT has exploited CVE-2015-1701 and CVE-2015-2387 to escalate privileges.
- [S0603] Stuxnet: Stuxnet used MS10-073 and an undisclosed Task Scheduler vulnerability to escalate privileges on local Windows machines.
- [G1004] LAPSUS$: LAPSUS$ has exploited unpatched vulnerabilities on internally accessible servers including JIRA, GitLab, and Confluence for privilege escalation.
- [S0623] Siloscape: Siloscape has leveraged a vulnerability in Windows containers to perform an Escape to Host.
- [S0658] XCSSET: XCSSET has used a zero-day exploit in the ssh launchdaemon to elevate privileges and bypass SIP.
- [G1043] BlackByte: BlackByte has exploited CVE-2024-37085 in VMWare ESXi software for authentication bypass and subsequent privilege escalation.
- [S0672] Zox: Zox has the ability to leverage local and remote exploits to escalate privileges.
- [G1015] Scattered Spider: Scattered Spider has deployed a malicious kernel driver through exploitation of CVE-2015-2291 in the Intel Ethernet diagnostics driver for Windows (iqvw64.sys).
- [C0049] Leviathan Australian Intrusions: Leviathan exploited software vulnerabilities in victim environments to escalate privileges during Leviathan Australian Intrusions.
- [G0007] APT28: APT28 has exploited CVE-2014-4076, CVE-2015-2387, CVE-2015-1701, CVE-2017-0263, and CVE-2022-38028 to escalate privileges.
- [G0128] ZIRCONIUM: ZIRCONIUM has exploited CVE-2017-0005 for local privilege escalation.
- [G0131] Tonto Team: Tonto Team has exploited CVE-2019-0803 and MS16-032 to escalate privileges.
- [S0654] ProLock: ProLock can use CVE-2019-0859 to escalate privileges on a compromised host.
- [S0176] Wingbird: Wingbird exploits CVE-2016-4117 to allow an executable to gain escalated privileges.
- [C0045] ShadowRay: During ShadowRay, threat actors downloaded a privilege escalation payload to gain root access.
- [G0050] APT32: APT32 has used CVE-2016-7255 to escalate privileges.
- [G0064] APT33: APT33 has used a publicly available exploit for CVE-2017-0213 to escalate privileges on a local system.
- [S0601] Hildegard: Hildegard has used the BOtB tool which exploits CVE-2019-5736.
- [G0049] OilRig: OilRig has exploited the Windows Kernel Elevation of Privilege vulnerability, CVE-2024-30088.


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


### T1134.001 - Access Token Manipulation: Token Impersonation/Theft

Description:

Adversaries may duplicate then impersonate another user's existing token to escalate privileges and bypass access controls. For example, an adversary can duplicate an existing token using `DuplicateToken` or `DuplicateTokenEx`. The token can then be used with `ImpersonateLoggedOnUser` to allow the calling thread to impersonate a logged on user's security context, or with `SetThreadToken` to assign the impersonated token to a thread. An adversary may perform Token Impersonation/Theft when they have a specific, existing process they want to assign the duplicated token to. For example, this may be useful for when the target user has a non-network logon session on the system. When an adversary would instead use a duplicated token to create a new process rather than attaching to an existing process, they can additionally Create Process with Token using `CreateProcessWithTokenW` or `CreateProcessAsUserW`. Token Impersonation/Theft is also distinct from Make and Impersonate Token in that it refers to duplicating an existing token, rather than creating a new one.

Detection:

If an adversary is using a standard command-line shell, analysts can detect token manipulation by auditing command-line activity. Specifically, analysts should look for use of the runas command. Detailed command-line logging is not enabled by default in Windows. Analysts can also monitor for use of Windows APIs such as DuplicateToken(Ex), ImpersonateLoggedOnUser , and SetThreadToken and correlate activity with other suspicious behavior to reduce false positives that may be due to normal benign use by users and administrators.

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
- [S0623] Siloscape: Siloscape impersonates the main thread of CExecSvc.exe by calling NtImpersonateThread.
- [G0061] FIN8: FIN8 has used a malicious framework designed to impersonate the lsass.exe/vmtoolsd.exe token.

### T1134.002 - Access Token Manipulation: Create Process with Token

Description:

Adversaries may create a new process with an existing token to escalate privileges and bypass access controls. Processes can be created with the token and resulting security context of another user using features such as CreateProcessWithTokenW and runas. Creating processes with a token not associated with the current user may require the credentials of the target user, specific privileges to impersonate that user, or access to the token to be used. For example, the token could be duplicated via Token Impersonation/Theft or created via Make and Impersonate Token before being used to create a process. While this technique is distinct from Token Impersonation/Theft, the techniques can be used in conjunction where a token is duplicated and then used to create a new process.

Detection:

If an adversary is using a standard command-line shell (i.e. Windows Command Shell), analysts may detect token manipulation by auditing command-line activity. Specifically, analysts should look for use of the runas command or similar artifacts. Detailed command-line logging is not enabled by default in Windows. If an adversary is using a payload that calls the Windows token APIs directly, analysts may detect token manipulation only through careful analysis of user activity, examination of running processes, and correlation with other endpoint and network behavior. Analysts can also monitor for use of Windows APIs such as CreateProcessWithTokenW and correlate activity with other suspicious behavior to reduce false positives that may be due to normal benign use by users and administrators.

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

Description:

Adversaries may make new tokens and impersonate users to escalate privileges and bypass access controls. For example, if an adversary has a username and password but the user is not logged onto the system the adversary can then create a logon session for the user using the `LogonUser` function. The function will return a copy of the new session's access token and the adversary can use `SetThreadToken` to assign the token to a thread. This behavior is distinct from Token Impersonation/Theft in that this refers to creating a new user token instead of stealing or duplicating an existing one.

Detection:

If an adversary is using a standard command-line shell, analysts can detect token manipulation by auditing command-line activity. Specifically, analysts should look for use of the runas command. Detailed command-line logging is not enabled by default in Windows. If an adversary is using a payload that calls the Windows token APIs directly, analysts can detect token manipulation only through careful analysis of user network activity, examination of running processes, and correlation with other endpoint and network behavior. Analysts can also monitor for use of Windows APIs such as LogonUser and SetThreadToken and correlate activity with other suspicious behavior to reduce false positives that may be due to normal benign use by users and administrators.

Procedures:

- [S1060] Mafalda: Mafalda can create a token for a different user.
- [G1043] BlackByte: BlackByte constructed a valid authentication token following Microsoft Exchange exploitation to allow for follow-on privileged command execution.
- [G1016] FIN13: FIN13 has utilized tools such as Incognito V2 for token manipulation and impersonation.
- [S0692] SILENTTRINITY: SILENTTRINITY can make tokens from known credentials.
- [S0154] Cobalt Strike: Cobalt Strike can make tokens from known credentials.

### T1134.004 - Access Token Manipulation: Parent PID Spoofing

Description:

Adversaries may spoof the parent process identifier (PPID) of a new process to evade process-monitoring defenses or to elevate privileges. New processes are typically spawned directly from their parent, or calling, process unless explicitly specified. One way of explicitly assigning the PPID of a new process is via the CreateProcess API call, which supports a parameter that defines the PPID to use. This functionality is used by Windows features such as User Account Control (UAC) to correctly set the PPID after a requested elevated process is spawned by SYSTEM (typically via svchost.exe or consent.exe) rather than the current user context. Adversaries may abuse these mechanisms to evade defenses, such as those blocking processes spawning directly from Office documents, and analysis targeting unusual/potentially malicious parent-child process relationships, such as spoofing the PPID of PowerShell/Rundll32 to be explorer.exe rather than an Office document delivered as part of Spearphishing Attachment. This spoofing could be executed via Visual Basic within a malicious Office document or any code that can perform Native API. Explicitly assigning the PPID may also enable elevated privileges given appropriate access rights to the parent process. For example, an adversary in a privileged user context (i.e. administrator) may spawn a new process and assign the parent as a process running as SYSTEM (such as lsass.exe), causing the new process to be elevated via the inherited access token.

Detection:

Look for inconsistencies between the various fields that store PPID information, such as the EventHeader ProcessId from data collected via Event Tracing for Windows (ETW), Creator Process ID/Name from Windows event logs, and the ProcessID and ParentProcessID (which are also produced from ETW and other utilities such as Task Manager and Process Explorer). The ETW provided EventHeader ProcessId identifies the actual parent process. Monitor and analyze API calls to CreateProcess/CreateProcessA, specifically those from user/potentially malicious processes and with parameters explicitly assigning PPIDs (ex: the Process Creation Flags of 0x8XXX, indicating that the process is being created with extended startup information). Malicious use of CreateProcess/CreateProcessA may also be proceeded by a call to UpdateProcThreadAttribute, which may be necessary to update process creation attributes. This may generate false positives from normal UAC elevation behavior, so compare to a system baseline/understanding of normal system activity if possible.

Procedures:

- [S0356] KONNI: KONNI has used parent PID spoofing to spawn a new `cmd` process using `CreateProcessW` and a handle to `Taskmgr.exe`.
- [S0154] Cobalt Strike: Cobalt Strike can spawn processes with alternate PPIDs.
- [S0501] PipeMon: PipeMon can use parent PID spoofing to elevate privileges.
- [S1111] DarkGate: DarkGate relies on parent PID spoofing as part of its "rootkit-like" functionality to evade detection via Task Manager or Process Explorer.

### T1134.005 - Access Token Manipulation: SID-History Injection

Description:

Adversaries may use SID-History Injection to escalate privileges and bypass access controls. The Windows security identifier (SID) is a unique value that identifies a user or group account. SIDs are used by Windows security in both security descriptors and access tokens. An account can hold additional SIDs in the SID-History Active Directory attribute , allowing inter-operable account migration between domains (e.g., all values in SID-History are included in access tokens). With Domain Administrator (or equivalent) rights, harvested or well-known SID values may be inserted into SID-History to enable impersonation of arbitrary users/groups such as Enterprise Administrators. This manipulation may result in elevated access to local resources and/or access to otherwise inaccessible domains via lateral movement techniques such as Remote Services, SMB/Windows Admin Shares, or Windows Remote Management.

Detection:

Examine data in user’s SID-History attributes using the PowerShell Get-ADUser cmdlet , especially users who have SID-History values from the same domain. Also monitor account management events on Domain Controllers for successful and failed changes to SID-History. Monitor for Windows API calls to the DsAddSidHistory function.

Procedures:

- [S0002] Mimikatz: Mimikatz's MISC::AddSid module can append any SID or user/group account to a user's SID-History. Mimikatz also utilizes SID-History Injection to expand the scope of other components such as generated Kerberos Golden Tickets and DCSync beyond a single domain.
- [S0363] Empire: Empire can add a SID-History to a user if on a domain controller.


### T1484.001 - Domain or Tenant Policy Modification: Group Policy Modification

Description:

Adversaries may modify Group Policy Objects (GPOs) to subvert the intended discretionary access controls for a domain, usually with the intention of escalating privileges on the domain. Group policy allows for centralized management of user and computer settings in Active Directory (AD). GPOs are containers for group policy settings made up of files stored within a predictable network path `\\SYSVOL\\Policies\`. Like other objects in AD, GPOs have access controls associated with them. By default all user accounts in the domain have permission to read GPOs. It is possible to delegate GPO access control permissions, e.g. write access, to specific users or groups in the domain. Malicious GPO modifications can be used to implement many other malicious behaviors such as Scheduled Task/Job, Disable or Modify Tools, Ingress Tool Transfer, Create Account, Service Execution, and more. Since GPOs can control so many user and machine settings in the AD environment, there are a great number of potential attacks that can stem from this GPO abuse. For example, publicly available scripts such as New-GPOImmediateTask can be leveraged to automate the creation of a malicious Scheduled Task/Job by modifying GPO settings, in this case modifying &lt;GPO_PATH&gt;\Machine\Preferences\ScheduledTasks\ScheduledTasks.xml. In some cases an adversary might modify specific user rights like SeEnableDelegationPrivilege, set in &lt;GPO_PATH&gt;\MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf, to achieve a subtle AD backdoor with complete control of the domain because the user account under the adversary's control would then be able to modify GPOs.

Detection:

It is possible to detect GPO modifications by monitoring directory service changes using Windows event logs. Several events may be logged for such GPO modifications, including: * Event ID 5136 - A directory service object was modified * Event ID 5137 - A directory service object was created * Event ID 5138 - A directory service object was undeleted * Event ID 5139 - A directory service object was moved * Event ID 5141 - A directory service object was deleted GPO abuse will often be accompanied by some other behavior such as Scheduled Task/Job, which will have events associated with it to detect. Subsequent permission value modifications, like those to SeEnableDelegationPrivilege, can also be searched for in events associated with privileges assigned to new logons (Event ID 4672) and assignment of user rights (Event ID 4704).

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

Description:

Adversaries may add new domain trusts, modify the properties of existing domain trusts, or otherwise change the configuration of trust relationships between domains and tenants to evade defenses and/or elevate privileges.Trust details, such as whether or not user identities are federated, allow authentication and authorization properties to apply between domains or tenants for the purpose of accessing shared resources. These trust objects may include accounts, credentials, and other authentication material applied to servers, tokens, and domains. Manipulating these trusts may allow an adversary to escalate privileges and/or evade defenses by modifying settings to add objects which they control. For example, in Microsoft Active Directory (AD) environments, this may be used to forge SAML Tokens without the need to compromise the signing certificate to forge new credentials. Instead, an adversary can manipulate domain trusts to add their own signing certificate. An adversary may also convert an AD domain to a federated domain using Active Directory Federation Services (AD FS), which may enable malicious trust modifications such as altering the claim issuance rules to log in any valid set of credentials as a specified user. An adversary may also add a new federated identity provider to an identity tenant such as Okta or AWS IAM Identity Center, which may enable the adversary to authenticate as any user of the tenant. This may enable the threat actor to gain broad access into a variety of cloud-based services that leverage the identity tenant. For example, in AWS environments, an adversary that creates a new identity provider for an AWS Organization will be able to federate into all of the AWS Organization member accounts without creating identities for each of the member accounts.

Detection:

Monitor for modifications to domain trust settings, such as when a user or application modifies the federation settings on the domain or updates domain authentication from Managed to Federated via ActionTypes Set federation settings on domain and Set domain authentication. This may also include monitoring for Event ID 307 which can be correlated to relevant Event ID 510 with the same Instance ID for change details. Monitor for PowerShell commands such as: Update-MSOLFederatedDomain –DomainName: "Federated Domain Name", or Update-MSOLFederatedDomain –DomainName: "Federated Domain Name" –supportmultipledomain.

Procedures:

- [G1015] Scattered Spider: Scattered Spider adds a federated identity provider to the victim’s SSO tenant and activates automatic account linking.
- [S0677] AADInternals: AADInternals can create a backdoor by converting a domain to a federated domain which will be able to authenticate any user across the tenant. AADInternals can also modify DesktopSSO information.
- [C0024] SolarWinds Compromise: During the SolarWinds Compromise, APT29 changed domain federation trust settings using Azure AD administrative permissions to configure the domain to accept authorization tokens signed by their own SAML signing certificate.


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


### T1548.001 - Abuse Elevation Control Mechanism: Setuid and Setgid

Description:

An adversary may abuse configurations where an application has the setuid or setgid bits set in order to get code running in a different (and possibly more privileged) user’s context. On Linux or macOS, when the setuid or setgid bits are set for an application binary, the application will run with the privileges of the owning user or group respectively. Normally an application is run in the current user’s context, regardless of which user or group owns the application. However, there are instances where programs need to be executed in an elevated context to function properly, but the user running them may not have the specific required privileges. Instead of creating an entry in the sudoers file, which must be done by root, any user can specify the setuid or setgid flag to be set for their own applications (i.e. Linux and Mac File and Directory Permissions Modification). The chmod command can set these bits with bitmasking, chmod 4777 [file] or via shorthand naming, chmod u+s [file]. This will enable the setuid bit. To enable the setgid bit, chmod 2775 and chmod g+s can be used. Adversaries can use this mechanism on their own malware to make sure they're able to execute in elevated contexts in the future. This abuse is often part of a "shell escape" or other actions to bypass an execution environment with restricted permissions. Alternatively, adversaries may choose to find and target vulnerable binaries with the setuid or setgid bits already enabled (i.e. File and Directory Discovery). The setuid and setguid bits are indicated with an "s" instead of an "x" when viewing a file's attributes via ls -l. The find command can also be used to search for such files. For example, find / -perm +4000 2>/dev/null can be used to find files with setuid set and find / -perm +2000 2>/dev/null may be used for setgid. Binaries that have these bits set may then be abused by adversaries.

Detection:

Monitor the file system for files that have the setuid or setgid bits set. Monitor for execution of utilities, like chmod, and their command-line arguments to look for setuid or setguid bits being set.

Procedures:

- [S0276] Keydnap: Keydnap adds the setuid flag to a binary so it can easily elevate in the future.
- [S0401] Exaramel for Linux: Exaramel for Linux can execute commands with high privileges via a specific binary with setuid functionality.

### T1548.002 - Abuse Elevation Control Mechanism: Bypass User Account Control

Description:

Adversaries may bypass UAC mechanisms to elevate process privileges on system. Windows User Account Control (UAC) allows a program to elevate its privileges (tracked as integrity levels ranging from low to high) to perform a task under administrator-level permissions, possibly by prompting the user for confirmation. The impact to the user ranges from denying the operation under high enforcement to allowing the user to perform the action if they are in the local administrators group and click through the prompt or allowing them to enter an administrator password to complete the action. If the UAC protection level of a computer is set to anything but the highest level, certain Windows programs can elevate privileges or execute some elevated Component Object Model objects without prompting the user through the UAC notification box. An example of this is use of Rundll32 to load a specifically crafted DLL which loads an auto-elevated Component Object Model object and performs a file operation in a protected directory which would typically require elevated access. Malicious software may also be injected into a trusted process to gain elevated privileges without prompting a user. Many methods have been discovered to bypass UAC. The Github readme page for UACME contains an extensive list of methods that have been discovered and implemented, but may not be a comprehensive list of bypasses. Additional bypass methods are regularly discovered and some used in the wild, such as: * eventvwr.exe can auto-elevate and execute a specified binary or script. Another bypass is possible through some lateral movement techniques if credentials for an account with administrator privileges are known, since UAC is a single system security mechanism, and the privilege or integrity of a process running on one system will be unknown on remote systems and default to high integrity.

Detection:

There are many ways to perform UAC bypasses when a user is in the local administrator group on a system, so it may be difficult to target detection on all variations. Efforts should likely be placed on mitigation and collecting enough information on process launches and actions that could be performed before and after a UAC bypass is performed. Monitor process API calls for behavior that may be indicative of Process Injection and unusual loaded DLLs through DLL, which indicate attempts to gain access to higher privileged processes. Some UAC bypass methods rely on modifying specific, user-accessible Registry settings. For example: * The eventvwr.exe bypass uses the [HKEY_CURRENT_USER]\Software\Classes\mscfile\shell\open\command Registry key. * The sdclt.exe bypass uses the [HKEY_CURRENT_USER]\Software\Microsoft\Windows\CurrentVersion\App Paths\control.exe and [HKEY_CURRENT_USER]\Software\Classes\exefile\shell\runas\command\isolatedCommand Registry keys. Analysts should monitor these Registry settings for unauthorized changes.

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
- [S1068] BlackCat: BlackCat can bypass UAC to escalate privileges.
- [S1199] LockBit 2.0: LockBit 2.0 can bypass UAC through creating the Registry key `HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\ICM\Calibration`.
- [G0120] Evilnum: Evilnum has used PowerShell to bypass UAC.
- [G0067] APT37: APT37 has a function in the initial dropper to bypass Windows UAC in order to execute the next payload with higher privileges.
- [G0060] BRONZE BUTLER: BRONZE BUTLER has used a Windows 10 specific tool and xxmm to bypass UAC for privilege escalation.
- [S0129] AutoIt backdoor: AutoIt backdoor attempts to escalate privileges by bypassing User Access Control.
- [S0182] FinFisher: FinFisher performs UAC bypass.
- [S0606] Bad Rabbit: Bad Rabbit has attempted to bypass UAC and gain elevated administrative privileges.
- [S0134] Downdelph: Downdelph bypasses UAC to escalate privileges by using a custom “RedirectEXE” shim database.
- [S0250] Koadic: Koadic has 2 methods for elevating integrity. It can bypass UAC through `eventvwr.exe` and `sdclt.exe`.
- [S0640] Avaddon: Avaddon bypasses UAC using the CMSTPLUA COM interface.
- [S0262] QuasarRAT: QuasarRAT can generate a UAC pop-up Window to prompt the target user to run a command as the administrator.
- [S0141] Winnti for Windows: Winnti for Windows can use a variant of the sysprep UAC bypass.
- [S0612] WastedLocker: WastedLocker can perform a UAC bypass if it is not executed with administrator rights or if the infected host runs Windows Vista or later.
- [G0069] MuddyWater: MuddyWater uses various techniques to bypass UAC.
- [S0501] PipeMon: PipeMon installer can use UAC bypass techniques to install the payload.
- [S0447] Lokibot: Lokibot has utilized multiple techniques to bypass UAC.
- [S0132] H1N1: H1N1 bypasses user access control by using a DLL hijacking vulnerability in the Windows Update Standalone Installer (wusa.exe).
- [G0080] Cobalt Group: Cobalt Group has bypassed UAC.
- [S0254] PLAINTEE: An older variant of PLAINTEE performs UAC bypass.
- [S0332] Remcos: Remcos has a command for UAC bypassing.
- [S0458] Ramsay: Ramsay can use UACMe for privilege escalation.
- [S0570] BitPaymer: BitPaymer can suppress UAC prompts by setting the HKCU\Software\Classes\ms-settings\shell\open\command registry key on Windows 10 or HKCU\Software\Classes\mscfile\shell\open\command on Windows 7 and launching the eventvwr.msc process, which launches BitPaymer with elevated privileges.
- [G1006] Earth Lusca: Earth Lusca has used the Fodhelper UAC bypass technique to gain elevated privileges.
- [C0006] Operation Honeybee: During Operation Honeybee, the threat actors used the malicious NTWDBLIB.DLL and `cliconfig.exe` to bypass UAC protections.
- [S0527] CSPY Downloader: CSPY Downloader can bypass UAC using the SilentCleanup task to execute the binary with elevated privileges.
- [S1039] Bumblebee: Bumblebee has the ability to bypass UAC to deploy post exploitation tools with elevated privileges.
- [G0027] Threat Group-3390: A Threat Group-3390 tool can use a public UAC bypass method to elevate privileges.
- [S0531] Grandoreiro: Grandoreiro can bypass UAC by registering as the default handler for .MSC files.
- [S0660] Clambling: Clambling has the ability to bypass UAC using a `passuac.dll` file.
- [S0140] Shamoon: Shamoon attempts to disable UAC remote restrictions by modifying the Registry.
- [S0692] SILENTTRINITY: SILENTTRINITY contains a number of modules that can bypass UAC, including through Window's Device Manager, Manage Optional Features, and an image hijack on the `.msc` file extension.
- [S0584] AppleJeus: AppleJeus has presented the user with a UAC prompt to elevate privileges while installing.
- [S0260] InvisiMole: InvisiMole can use fileless UAC bypass and create an elevated COM object to escalate privileges.
- [S0669] KOCTOPUS: KOCTOPUS will perform UAC bypass either through fodhelper.exe or eventvwr.exe.
- [S0633] Sliver: Sliver can leverage multiple techniques to bypass User Account Control (UAC) on Windows systems.
- [G0040] Patchwork: Patchwork bypassed User Access Control (UAC).
- [S1149] CHIMNEYSWEEP: CHIMNEYSWEEP can make use of the Windows `SilentCleanup` scheduled task to execute its payload with elevated privileges.
- [S1130] Raspberry Robin: Raspberry Robin will use the legitimate Windows utility fodhelper.exe to run processes at elevated privileges without requiring a User Account Control prompt.
- [S1081] BADHATCH: BADHATCH can utilize the CMSTPLUA COM interface and the SilentCleanup task to bypass UAC.
- [S0116] UACMe: UACMe contains many methods for bypassing Windows User Account Control on multiple versions of the operating system.
- [S0363] Empire: Empire includes various modules to attempt to bypass UAC for escalation of privileges.
- [S0662] RCSession: RCSession can bypass UAC to escalate privileges.
- [G0016] APT29: APT29 has bypassed UAC.

### T1548.003 - Abuse Elevation Control Mechanism: Sudo and Sudo Caching

Description:

Adversaries may perform sudo caching and/or use the sudoers file to elevate privileges. Adversaries may do this to execute commands as other users or spawn processes with higher privileges. Within Linux and MacOS systems, sudo (sometimes referred to as "superuser do") allows users to perform commands from terminals with elevated privileges and to control who can perform these commands on the system. The sudo command "allows a system administrator to delegate authority to give certain users (or groups of users) the ability to run some (or all) commands as root or another user while providing an audit trail of the commands and their arguments." Since sudo was made for the system administrator, it has some useful configuration features such as a timestamp_timeout, which is the amount of time in minutes between instances of sudo before it will re-prompt for a password. This is because sudo has the ability to cache credentials for a period of time. Sudo creates (or touches) a file at /var/db/sudo with a timestamp of when sudo was last run to determine this timeout. Additionally, there is a tty_tickets variable that treats each new tty (terminal session) in isolation. This means that, for example, the sudo timeout of one tty will not affect another tty (you will have to type the password again). The sudoers file, /etc/sudoers, describes which users can run which commands and from which terminals. This also describes which commands users can run as other users or groups. This provides the principle of least privilege such that users are running in their lowest possible permissions for most of the time and only elevate to other users or permissions as needed, typically by prompting for a password. However, the sudoers file can also specify when to not prompt users for passwords with a line like user1 ALL=(ALL) NOPASSWD: ALL. Elevated privileges are required to edit this file though. Adversaries can also abuse poor configurations of these mechanisms to escalate privileges without needing the user's password. For example, /var/db/sudo's timestamp can be monitored to see if it falls within the timestamp_timeout range. If it does, then malware can execute sudo commands without needing to supply the user's password. Additional, if tty_tickets is disabled, adversaries can do this from any tty for that user. In the wild, malware has disabled tty_tickets to potentially make scripting easier by issuing echo \'Defaults !tty_tickets\' >> /etc/sudoers. In order for this change to be reflected, the malware also issued killall Terminal. As of macOS Sierra, the sudoers file has tty_tickets enabled by default.

Detection:

On Linux, auditd can alert every time a user's actual ID and effective ID are different (this is what happens when you sudo). This technique is abusing normal functionality in macOS and Linux systems, but sudo has the ability to log all input and output based on the LOG_INPUT and LOG_OUTPUT directives in the /etc/sudoers file.

Procedures:

- [S0154] Cobalt Strike: Cobalt Strike can use sudo to run a command.
- [S0279] Proton: Proton modifies the tty_tickets line in the sudoers file.
- [S0281] Dok: Dok adds admin ALL=(ALL) NOPASSWD: ALL to the /etc/sudoers file.

### T1548.004 - Abuse Elevation Control Mechanism: Elevated Execution with Prompt

Description:

Adversaries may leverage the AuthorizationExecuteWithPrivileges API to escalate privileges by prompting the user for credentials. The purpose of this API is to give application developers an easy way to perform operations with root privileges, such as for application installation or updating. This API does not validate that the program requesting root privileges comes from a reputable source or has been maliciously modified. Although this API is deprecated, it still fully functions in the latest releases of macOS. When calling this API, the user will be prompted to enter their credentials but no checks on the origin or integrity of the program are made. The program calling the API may also load world writable files which can be modified to perform malicious behavior with elevated privileges. Adversaries may abuse AuthorizationExecuteWithPrivileges to obtain root privileges in order to install malicious software on victims and install persistence mechanisms. This technique may be combined with Masquerading to trick the user into granting escalated privileges to malicious code. This technique has also been shown to work by modifying legitimate programs present on the machine that make use of this API.

Detection:

Consider monitoring for /usr/libexec/security_authtrampoline executions which may indicate that AuthorizationExecuteWithPrivileges is being executed. MacOS system logs may also indicate when AuthorizationExecuteWithPrivileges is being called. Monitoring OS API callbacks for the execution can also be a way to detect this behavior but requires specialized security tooling.

Procedures:

- [S0402] OSX/Shlayer: OSX/Shlayer can escalate privileges to root by asking the user for credentials.

### T1548.005 - Abuse Elevation Control Mechanism: Temporary Elevated Cloud Access

Description:

Adversaries may abuse permission configurations that allow them to gain temporarily elevated access to cloud resources. Many cloud environments allow administrators to grant user or service accounts permission to request just-in-time access to roles, impersonate other accounts, pass roles onto resources and services, or otherwise gain short-term access to a set of privileges that may be distinct from their own. Just-in-time access is a mechanism for granting additional roles to cloud accounts in a granular, temporary manner. This allows accounts to operate with only the permissions they need on a daily basis, and to request additional permissions as necessary. Sometimes just-in-time access requests are configured to require manual approval, while other times the desired permissions are automatically granted. Account impersonation allows user or service accounts to temporarily act with the permissions of another account. For example, in GCP users with the `iam.serviceAccountTokenCreator` role can create temporary access tokens or sign arbitrary payloads with the permissions of a service account, while service accounts with domain-wide delegation permission are permitted to impersonate Google Workspace accounts. In Exchange Online, the `ApplicationImpersonation` role allows a service account to use the permissions associated with specified user accounts. Many cloud environments also include mechanisms for users to pass roles to resources that allow them to perform tasks and authenticate to other services. While the user that creates the resource does not directly assume the role they pass to it, they may still be able to take advantage of the role's access -- for example, by configuring the resource to perform certain actions with the permissions it has been granted. In AWS, users with the `PassRole` permission can allow a service they create to assume a given role, while in GCP, users with the `iam.serviceAccountUser` role can attach a service account to a resource. While users require specific role assignments in order to use any of these features, cloud administrators may misconfigure permissions. This could result in escalation paths that allow adversaries to gain access to resources beyond what was originally intended. **Note:** this technique is distinct from Additional Cloud Roles, which involves assigning permanent roles to accounts rather than abusing existing permissions structures to gain temporarily elevated access to resources. However, adversaries that compromise a sufficiently privileged account may grant another account they control Additional Cloud Roles that would allow them to also abuse these features. This may also allow for greater stealth than would be had by directly using the highly privileged account, especially when logs do not clarify when role impersonation is taking place.

### T1548.006 - Abuse Elevation Control Mechanism: TCC Manipulation

Description:

Adversaries can manipulate or abuse the Transparency, Consent, & Control (TCC) service or database to grant malicious executables elevated permissions. TCC is a Privacy & Security macOS control mechanism used to determine if the running process has permission to access the data or services protected by TCC, such as screen sharing, camera, microphone, or Full Disk Access (FDA). When an application requests to access data or a service protected by TCC, the TCC daemon (`tccd`) checks the TCC database, located at `/Library/Application Support/com.apple.TCC/TCC.db` (and `~/` equivalent), and an overwrites file (if connected to an MDM) for existing permissions. If permissions do not exist, then the user is prompted to grant permission. Once permissions are granted, the database stores the application's permissions and will not prompt the user again unless reset. For example, when a web browser requests permissions to the user's webcam, once granted the web browser may not explicitly prompt the user again. Adversaries may access restricted data or services protected by TCC through abusing applications previously granted permissions through Process Injection or executing a malicious binary using another application. For example, adversaries can use Finder, a macOS native app with FDA permissions, to execute a malicious AppleScript. When executing under the Finder App, the malicious AppleScript inherits access to all files on the system without requiring a user prompt. When System Integrity Protection (SIP) is disabled, TCC protections are also disabled. For a system without SIP enabled, adversaries can manipulate the TCC database to add permissions to their malicious executable through loading an adversary controlled TCC database using environment variables and Launchctl.

Procedures:

- [S0658] XCSSET: For several modules, XCSSET attempts to access or list the contents of user folders such as Desktop, Downloads, and Documents. If the folder does not exist or access is denied, it enters a loop where it resets the TCC database and retries access.


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


### T1611 - Escape to Host

Description:

Adversaries may break out of a container or virtualized environment to gain access to the underlying host. This can allow an adversary access to other containerized or virtualized resources from the host level or to the host itself. In principle, containerized / virtualized resources should provide a clear separation of application functionality and be isolated from the host environment. There are multiple ways an adversary may escape from a container to a host environment. Examples include creating a container configured to mount the host’s filesystem using the bind parameter, which allows the adversary to drop payloads and execute control utilities such as cron on the host; utilizing a privileged container to run commands or load a malicious kernel module on the underlying host; or abusing system calls such as `unshare` and `keyctl` to escalate privileges and steal secrets. Additionally, an adversary may be able to exploit a compromised container with a mounted container management socket, such as `docker.sock`, to break out of the container via a Container Administration Command. Adversaries may also escape via Exploitation for Privilege Escalation, such as exploiting vulnerabilities in global symbolic links in order to access the root directory of a host machine. In ESXi environments, an adversary may exploit a vulnerability in order to escape from a virtual machine into the hypervisor. Gaining access to the host may provide the adversary with the opportunity to achieve follow-on objectives, such as establishing persistence, moving laterally within the environment, accessing other containers or virtual machines running on the host, or setting up a command and control channel on the host.

Detection:

Monitor for the deployment of suspicious or unknown container images and pods in your environment, particularly containers running as root. Additionally, monitor for unexpected usage of syscalls such as mount (as well as resulting process activity) that may indicate an attempt to escape from a privileged container to host. In Kubernetes, monitor for cluster-level events associated with changing containers' volume configurations.

Procedures:

- [S0683] Peirates: Peirates can gain a reverse shell on a host node by mounting the Kubernetes hostPath.
- [S0600] Doki: Doki’s container was configured to bind the host root directory.
- [S0623] Siloscape: Siloscape maps the host’s C drive to the container by creating a global symbolic link to the host through the calling of NtSetInformationSymbolicLink.
- [G0139] TeamTNT: TeamTNT has deployed privileged containers that mount the filesystem of victim machine.
- [S0601] Hildegard: Hildegard has used the BOtB tool that can break out of containers.

