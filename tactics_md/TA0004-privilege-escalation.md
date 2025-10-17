### T1037 - Boot or Logon Initialization Scripts

Description:

Adversaries may use scripts automatically executed at boot or logon initialization to establish persistence.(Citation: Mandiant APT29 Eye Spy Email Nov 22)(Citation: Anomali Rocke March 2019) Initialization scripts can be used to perform administrative functions, which may often execute other programs or send information to an internal logging server. These scripts can vary based on operating system and whether applied locally or remotely.  

Adversaries may use these scripts to maintain persistence on a single system. Depending on the access configuration of the logon scripts, either local credentials or an administrator account may be necessary. 

An adversary may also be able to escalate their privileges since some boot or logon initialization scripts run with higher privileges.

Procedures:

- [C0046] ArcaneDoor: [ArcaneDoor](https://attack.mitre.org/campaigns/C0046) used malicious boot scripts to install the [Line Runner](https://attack.mitre.org/software/S1188) backdoor on victim devices.(Citation: Cisco ArcaneDoor 2024)
- [G0096] APT41: [APT41](https://attack.mitre.org/groups/G0096) used a hidden shell script in `/etc/rc.d/init.d` to leverage the `ADORE.XSEC`backdoor and `Adore-NG` rootkit.(Citation: apt41_mandiant)
- [G0016] APT29: [APT29](https://attack.mitre.org/groups/G0016) has hijacked legitimate application-specific startup scripts to enable malware to execute on system startup.(Citation: Mandiant APT29 Eye Spy Email Nov 22)
- [S1078] RotaJakiro: Depending on the Linux distribution and when executing with root permissions, [RotaJakiro](https://attack.mitre.org/software/S1078) may install persistence using a `.conf` file in the `/etc/init/` folder.(Citation: RotaJakiro 2021 netlab360 analysis)
- [G0106] Rocke: [Rocke](https://attack.mitre.org/groups/G0106) has installed an "init.d" startup script to maintain persistence.(Citation: Anomali Rocke March 2019)

#### T1037.001 - Logon Script (Windows)

Description:

Adversaries may use Windows logon scripts automatically executed at logon initialization to establish persistence. Windows allows logon scripts to be run whenever a specific user or group of users log into a system.(Citation: TechNet Logon Scripts) This is done via adding a path to a script to the <code>HKCU\Environment\UserInitMprLogonScript</code> Registry key.(Citation: Hexacorn Logon Scripts)

Adversaries may use these scripts to maintain persistence on a single system. Depending on the access configuration of the logon scripts, either local credentials or an administrator account may be necessary.

Procedures:

- [G0007] APT28: An [APT28](https://attack.mitre.org/groups/G0007) loader Trojan adds the Registry key <code>HKCU\Environment\UserInitMprLogonScript</code> to establish persistence.(Citation: Unit 42 Playbook Dec 2017)
- [S0438] Attor: [Attor](https://attack.mitre.org/software/S0438)'s dispatcher can establish persistence via adding a Registry key with a logon script <code>HKEY_CURRENT_USER\Environment "UserInitMprLogonScript" </code>.(Citation: ESET Attor Oct 2019)
- [S0044] JHUHUGIT: [JHUHUGIT](https://attack.mitre.org/software/S0044) has registered a Windows shell script under the Registry key <code>HKCU\Environment\UserInitMprLogonScript</code> to establish persistence.(Citation: ESET Sednit Part 1)(Citation: Talos Seduploader Oct 2017)
- [S0526] KGH_SPY: [KGH_SPY](https://attack.mitre.org/software/S0526) has the ability to set the <code>HKCU\Environment\UserInitMprLogonScript</code> Registry key to execute logon scripts.(Citation: Cybereason Kimsuky November 2020)
- [S0251] Zebrocy: [Zebrocy](https://attack.mitre.org/software/S0251) performs persistence with a logon script via adding to the Registry key <code>HKCU\Environment\UserInitMprLogonScript</code>.(Citation: ESET Zebrocy Nov 2018)
- [G0080] Cobalt Group: [Cobalt Group](https://attack.mitre.org/groups/G0080) has added persistence by registering the file name for the next stage malware under <code>HKCU\Environment\UserInitMprLogonScript</code>.(Citation: Morphisec Cobalt Gang Oct 2018)

#### T1037.002 - Login Hook

Description:

Adversaries may use a Login Hook to establish persistence executed upon user logon. A login hook is a plist file that points to a specific script to execute with root privileges upon user logon. The plist file is located in the <code>/Library/Preferences/com.apple.loginwindow.plist</code> file and can be modified using the <code>defaults</code> command-line utility. This behavior is the same for logout hooks where a script can be executed upon user logout. All hooks require administrator permissions to modify or create hooks.(Citation: Login Scripts Apple Dev)(Citation: LoginWindowScripts Apple Dev) 

Adversaries can add or insert a path to a malicious script in the <code>com.apple.loginwindow.plist</code> file, using the <code>LoginHook</code> or <code>LogoutHook</code> key-value pair. The malicious script is executed upon the next user login. If a login hook already exists, adversaries can add additional commands to an existing login hook. There can be only one login and logout hook on a system at a time.(Citation: S1 macOs Persistence)(Citation: Wardle Persistence Chapter)

**Note:** Login hooks were deprecated in 10.11 version of macOS in favor of [Launch Daemon](https://attack.mitre.org/techniques/T1543/004) and [Launch Agent](https://attack.mitre.org/techniques/T1543/001)

#### T1037.003 - Network Logon Script

Description:

Adversaries may use network logon scripts automatically executed at logon initialization to establish persistence. Network logon scripts can be assigned using Active Directory or Group Policy Objects.(Citation: Petri Logon Script AD) These logon scripts run with the privileges of the user they are assigned to. Depending on the systems within the network, initializing one of these scripts could apply to more than one or potentially all systems.  
 
Adversaries may use these scripts to maintain persistence on a network. Depending on the access configuration of the logon scripts, either local credentials or an administrator account may be necessary.

#### T1037.004 - RC Scripts

Description:

Adversaries may establish persistence by modifying RC scripts, which are executed during a Unix-like system’s startup. These files allow system administrators to map and start custom services at startup for different run levels. RC scripts require root privileges to modify.

Adversaries may establish persistence by adding a malicious binary path or shell commands to <code>rc.local</code>, <code>rc.common</code>, and other RC scripts specific to the Unix-like distribution.(Citation: IranThreats Kittens Dec 2017)(Citation: Intezer HiddenWasp Map 2019) Upon reboot, the system executes the script's contents as root, resulting in persistence.

Adversary abuse of RC scripts is especially effective for lightweight Unix-like distributions using the root user as default, such as ESXi hypervisors, IoT, or embedded systems.(Citation: intezer-kaiji-malware) As ESXi servers store most system files in memory and therefore discard changes on shutdown, leveraging `/etc/rc.local.d/local.sh` is one of the few mechanisms for enabling persistence across reboots.(Citation: Juniper Networks ESXi Backdoor 2022)

Several Unix-like systems have moved to Systemd and deprecated the use of RC scripts. This is now a deprecated mechanism in macOS in favor of [Launchd](https://attack.mitre.org/techniques/T1053/004).(Citation: Apple Developer Doco Archive Launchd)(Citation: Startup Items) This technique can be used on Mac OS X Panther v10.3 and earlier versions which still execute the RC scripts.(Citation: Methods of Mac Malware Persistence) To maintain backwards compatibility some systems, such as Ubuntu, will execute the RC scripts if they exist with the correct file permissions.(Citation: Ubuntu Manpage systemd rc)

Procedures:

- [G1047] Velvet Ant: [Velvet Ant](https://attack.mitre.org/groups/G1047) used a modified `/etc/rc.local` file on compromised F5 BIG-IP devices to maintain persistence.(Citation: Sygnia VelvetAnt 2024A)
- [S0394] HiddenWasp: [HiddenWasp](https://attack.mitre.org/software/S0394) installs reboot persistence by adding itself to <code>/etc/rc.local</code>.(Citation: Intezer HiddenWasp Map 2019)
- [G0016] APT29: [APT29](https://attack.mitre.org/groups/G0016) has installed a run command on a compromised system to enable malware execution on system startup.(Citation: Mandiant APT29 Eye Spy Email Nov 22)
- [S0690] Green Lambert: [Green Lambert](https://attack.mitre.org/software/S0690) can add <code>init.d</code> and <code>rc.d</code> files in the <code>/etc</code> folder to establish persistence.(Citation: Objective See Green Lambert for OSX Oct 2021)(Citation: Glitch-Cat Green Lambert ATTCK Oct 2021)
- [S0687] Cyclops Blink: [Cyclops Blink](https://attack.mitre.org/software/S0687) has the ability to execute on device startup, using a modified RC script named S51armled.(Citation: NCSC Cyclops Blink February 2022)
- [S0278] iKitten: [iKitten](https://attack.mitre.org/software/S0278) adds an entry to the rc.common file for persistence.(Citation: objsee mac malware 2017)

#### T1037.005 - Startup Items

Description:

Adversaries may use startup items automatically executed at boot initialization to establish persistence. Startup items execute during the final phase of the boot process and contain shell scripts or other executable files along with configuration information used by the system to determine the execution order for all startup items.(Citation: Startup Items)

This is technically a deprecated technology (superseded by [Launch Daemon](https://attack.mitre.org/techniques/T1543/004)), and thus the appropriate folder, <code>/Library/StartupItems</code> isn’t guaranteed to exist on the system by default, but does appear to exist by default on macOS Sierra. A startup item is a directory whose executable and configuration property list (plist), <code>StartupParameters.plist</code>, reside in the top-level directory. 

An adversary can create the appropriate folders/files in the StartupItems directory to register their own persistence mechanism.(Citation: Methods of Mac Malware Persistence) Additionally, since StartupItems run during the bootup phase of macOS, they will run as the elevated root user.

Procedures:

- [S0283] jRAT: [jRAT](https://attack.mitre.org/software/S0283) can list and manage startup entries.(Citation: Kaspersky Adwind Feb 2016)


### T1053 - Scheduled Task/Job

Description:

Adversaries may abuse task scheduling functionality to facilitate initial or recurring execution of malicious code. Utilities exist within all major operating systems to schedule programs or scripts to be executed at a specified date and time. A task can also be scheduled on a remote system, provided the proper authentication is met (ex: RPC and file and printer sharing in Windows environments). Scheduling a task on a remote system typically may require being a member of an admin or otherwise privileged group on the remote system.(Citation: TechNet Task Scheduler Security)

Adversaries may use task scheduling to execute programs at system startup or on a scheduled basis for persistence. These mechanisms can also be abused to run a process under the context of a specified account (such as one with elevated permissions/privileges). Similar to [System Binary Proxy Execution](https://attack.mitre.org/techniques/T1218), adversaries have also abused task scheduling to potentially mask one-time execution under a trusted system process.(Citation: ProofPoint Serpent)

Procedures:

- [S1034] StrifeWater: [StrifeWater](https://attack.mitre.org/software/S1034) has create a scheduled task named `Mozilla\Firefox Default Browser Agent 409046Z0FF4A39CB` for persistence.(Citation: Cybereason StrifeWater Feb 2022)
- [S1052] DEADEYE: [DEADEYE](https://attack.mitre.org/software/S1052) has used the scheduled tasks `\Microsoft\Windows\PLA\Server Manager Performance Monitor`, `\Microsoft\Windows\Ras\ManagerMobility`, `\Microsoft\Windows\WDI\SrvSetupResults`, and `\Microsoft\Windows\WDI\USOShared`
 to establish persistence.(Citation: Mandiant APT41)
- [G1006] Earth Lusca: [Earth Lusca](https://attack.mitre.org/groups/G1006) used the command <code>schtasks /Create /SC ONLOgon /TN WindowsUpdateCheck /TR “[file path]” /ru system</code> for persistence.(Citation: TrendMicro EarthLusca 2022)
- [S0447] Lokibot: [Lokibot](https://attack.mitre.org/software/S0447)'s second stage DLL has set a timer using “timeSetEvent” to schedule its next execution.(Citation: Talos Lokibot Jan 2021)
- [S0125] Remsec: [Remsec](https://attack.mitre.org/software/S0125) schedules the execution one of its modules by creating a new scheduler task.(Citation: Kaspersky ProjectSauron Technical Analysis)

#### T1053.002 - At

Description:

Adversaries may abuse the [at](https://attack.mitre.org/software/S0110) utility to perform task scheduling for initial or recurring execution of malicious code. The [at](https://attack.mitre.org/software/S0110) utility exists as an executable within Windows, Linux, and macOS for scheduling tasks at a specified time and date. Although deprecated in favor of [Scheduled Task](https://attack.mitre.org/techniques/T1053/005)'s [schtasks](https://attack.mitre.org/software/S0111) in Windows environments, using [at](https://attack.mitre.org/software/S0110) requires that the Task Scheduler service be running, and the user to be logged on as a member of the local Administrators group. In addition to explicitly running the `at` command, adversaries may also schedule a task with [at](https://attack.mitre.org/software/S0110) by directly leveraging the [Windows Management Instrumentation](https://attack.mitre.org/techniques/T1047) `Win32_ScheduledJob` WMI class.(Citation: Malicious Life by Cybereason)

On Linux and macOS, [at](https://attack.mitre.org/software/S0110) may be invoked by the superuser as well as any users added to the <code>at.allow</code> file. If the <code>at.allow</code> file does not exist, the <code>at.deny</code> file is checked. Every username not listed in <code>at.deny</code> is allowed to invoke [at](https://attack.mitre.org/software/S0110). If the <code>at.deny</code> exists and is empty, global use of [at](https://attack.mitre.org/software/S0110) is permitted. If neither file exists (which is often the baseline) only the superuser is allowed to use [at](https://attack.mitre.org/software/S0110).(Citation: Linux at)

Adversaries may use [at](https://attack.mitre.org/software/S0110) to execute programs at system startup or on a scheduled basis for [Persistence](https://attack.mitre.org/tactics/TA0003). [at](https://attack.mitre.org/software/S0110) can also be abused to conduct remote [Execution](https://attack.mitre.org/tactics/TA0002) as part of [Lateral Movement](https://attack.mitre.org/tactics/TA0008) and/or to run a process under the context of a specified account (such as SYSTEM).

In Linux environments, adversaries may also abuse [at](https://attack.mitre.org/software/S0110) to break out of restricted environments by using a task to spawn an interactive system shell or to run system commands. Similarly, [at](https://attack.mitre.org/software/S0110) may also be used for [Privilege Escalation](https://attack.mitre.org/tactics/TA0004) if the binary is allowed to run as superuser via <code>sudo</code>.(Citation: GTFObins at)

Procedures:

- [G0027] Threat Group-3390: [Threat Group-3390](https://attack.mitre.org/groups/G0027) actors use [at](https://attack.mitre.org/software/S0110) to schedule tasks to run self-extracting RAR archives, which install [HTTPBrowser](https://attack.mitre.org/software/S0070) or [PlugX](https://attack.mitre.org/software/S0013) on other victims on a network.(Citation: Dell TG-3390)
- [S0488] CrackMapExec: [CrackMapExec](https://attack.mitre.org/software/S0488) can set a scheduled task on the target system to execute commands remotely using [at](https://attack.mitre.org/software/S0110).(Citation: CME Github September 2018)
- [G0026] APT18: [APT18](https://attack.mitre.org/groups/G0026) actors used the native [at](https://attack.mitre.org/software/S0110) Windows task scheduler tool to use scheduled tasks for execution on a victim network.(Citation: Dell Lateral Movement)
- [G0060] BRONZE BUTLER: [BRONZE BUTLER](https://attack.mitre.org/groups/G0060) has used [at](https://attack.mitre.org/software/S0110) to register a scheduled task to execute malware during lateral movement.(Citation: Secureworks BRONZE BUTLER Oct 2017)
- [S0233] MURKYTOP: [MURKYTOP](https://attack.mitre.org/software/S0233) has the capability to schedule remote AT jobs.(Citation: FireEye Periscope March 2018)
- [S0110] at: [at](https://attack.mitre.org/software/S0110) can be used to schedule a task on a system to be executed at a specific date or time.(Citation: TechNet At)(Citation: Linux at)

#### T1053.003 - Cron

Description:

Adversaries may abuse the <code>cron</code> utility to perform task scheduling for initial or recurring execution of malicious code.(Citation: 20 macOS Common Tools and Techniques) The <code>cron</code> utility is a time-based job scheduler for Unix-like operating systems.  The <code> crontab</code> file contains the schedule of cron entries to be run and the specified times for execution. Any <code>crontab</code> files are stored in operating system-specific file paths.

An adversary may use <code>cron</code> in Linux or Unix environments to execute programs at system startup or on a scheduled basis for [Persistence](https://attack.mitre.org/tactics/TA0003). In ESXi environments, cron jobs must be created directly via the crontab file (e.g., `/var/spool/cron/crontabs/root`).(Citation: CloudSEK ESXiArgs 2023)

Procedures:

- [S0374] SpeakUp: [SpeakUp](https://attack.mitre.org/software/S0374) uses cron tasks to ensure persistence. (Citation: CheckPoint SpeakUp Feb 2019)
- [S0504] Anchor: [Anchor](https://attack.mitre.org/software/S0504) can install itself as a cron job.(Citation: Medium Anchor DNS July 2020)
- [S0163] Janicab: [Janicab](https://attack.mitre.org/software/S0163) used a cron job for persistence on Mac devices.(Citation: Janicab)
- [S0468] Skidmap: [Skidmap](https://attack.mitre.org/software/S0468) has installed itself via crontab.(Citation: Trend Micro Skidmap)
- [G0106] Rocke: [Rocke](https://attack.mitre.org/groups/G0106) installed a cron job that downloaded and executed files from the C2.(Citation: Talos Rocke August 2018)(Citation: Unit 42 Rocke January 2019)(Citation: Anomali Rocke March 2019)
- [S0341] Xbash: [Xbash](https://attack.mitre.org/software/S0341) can create a cronjob for persistence if it determines it is on a Linux system.(Citation: Unit42 Xbash Sept 2018)
- [S0198] NETWIRE: [NETWIRE](https://attack.mitre.org/software/S0198) can use crontabs to establish persistence.(Citation: Red Canary NETWIRE January 2020)
- [S0588] GoldMax: The [GoldMax](https://attack.mitre.org/software/S0588) Linux variant has used a crontab entry with a <code>@reboot</code> line to gain persistence.(Citation: CrowdStrike StellarParticle January 2022)
- [S1198] Gomir: [Gomir](https://attack.mitre.org/software/S1198) will configure a crontab for process execution to start the backdoor on reboot if it is not initially running under group 0 privileges.(Citation: Symantec Troll Stealer 2024)
- [S0587] Penquin: [Penquin](https://attack.mitre.org/software/S0587) can use Cron to create periodic and pre-scheduled background jobs.(Citation: Leonardo Turla Penquin May 2020)
- [C0048] Operation MidnightEclipse: During [Operation MidnightEclipse](https://attack.mitre.org/campaigns/C0048), threat actors configured cron jobs to retrieve payloads from actor-controlled infrastructure.(Citation: Volexity UPSTYLE 2024)(Citation: Palo Alto MidnightEclipse APR 2024)
- [G1023] APT5: [APT5](https://attack.mitre.org/groups/G1023) has made modifications to the crontab file including in `/var/cron/tabs/`.(Citation: NSA APT5 Citrix Threat Hunting December 2022)
- [S0599] Kinsing: [Kinsing](https://attack.mitre.org/software/S0599) has used crontab to download and run shell scripts every minute to ensure persistence.(Citation: Aqua Kinsing April 2020)
- [G0082] APT38: [APT38](https://attack.mitre.org/groups/G0082) has used cron to create pre-scheduled and periodic background jobs on a Linux system.(Citation: CISA AA20-239A BeagleBoyz August 2020)
- [S0401] Exaramel for Linux: [Exaramel for Linux](https://attack.mitre.org/software/S0401) uses crontab for persistence if it does not have root privileges.(Citation: ESET TeleBots Oct 2018)(Citation: ANSSI Sandworm January 2021)
- [S1107] NKAbuse: [NKAbuse](https://attack.mitre.org/software/S1107) uses a Cron job to establish persistence when infecting Linux hosts.(Citation: NKAbuse SL)

#### T1053.005 - Scheduled Task

Description:

Adversaries may abuse the Windows Task Scheduler to perform task scheduling for initial or recurring execution of malicious code. There are multiple ways to access the Task Scheduler in Windows. The [schtasks](https://attack.mitre.org/software/S0111) utility can be run directly on the command line, or the Task Scheduler can be opened through the GUI within the Administrator Tools section of the Control Panel.(Citation: Stack Overflow) In some cases, adversaries have used a .NET wrapper for the Windows Task Scheduler, and alternatively, adversaries have used the Windows netapi32 library and [Windows Management Instrumentation](https://attack.mitre.org/techniques/T1047) (WMI) to create a scheduled task. Adversaries may also utilize the Powershell Cmdlet `Invoke-CimMethod`, which leverages WMI class `PS_ScheduledTask` to create a scheduled task via an XML path.(Citation: Red Canary - Atomic Red Team)

An adversary may use Windows Task Scheduler to execute programs at system startup or on a scheduled basis for persistence. The Windows Task Scheduler can also be abused to conduct remote Execution as part of Lateral Movement and/or to run a process under the context of a specified account (such as SYSTEM). Similar to [System Binary Proxy Execution](https://attack.mitre.org/techniques/T1218), adversaries have also abused the Windows Task Scheduler to potentially mask one-time execution under signed/trusted system processes.(Citation: ProofPoint Serpent)

Adversaries may also create "hidden" scheduled tasks (i.e. [Hide Artifacts](https://attack.mitre.org/techniques/T1564)) that may not be visible to defender tools and manual queries used to enumerate tasks. Specifically, an adversary may hide a task from `schtasks /query` and the Task Scheduler by deleting the associated Security Descriptor (SD) registry value (where deletion of this value must be completed using SYSTEM permissions).(Citation: SigmaHQ)(Citation: Tarrask scheduled task) Adversaries may also employ alternate methods to hide tasks, such as altering the metadata (e.g., `Index` value) within associated registry keys.(Citation: Defending Against Scheduled Task Attacks in Windows Environments)

Procedures:

- [S0588] GoldMax: [GoldMax](https://attack.mitre.org/software/S0588) has used scheduled tasks to maintain persistence.(Citation: MSTIC NOBELIUM Mar 2021)
- [S0648] JSS Loader: [JSS Loader](https://attack.mitre.org/software/S0648) has the ability to launch scheduled tasks to establish persistence.(Citation: CrowdStrike Carbon Spider August 2021)
- [S0414] BabyShark: [BabyShark](https://attack.mitre.org/software/S0414) has used scheduled tasks to maintain persistence.(Citation: Crowdstrike GTR2020 Mar 2020)
- [C0024] SolarWinds Compromise: During the [SolarWinds Compromise](https://attack.mitre.org/campaigns/C0024), [APT29](https://attack.mitre.org/groups/G0016) used `scheduler` and `schtasks` to create new tasks on remote host as part of their lateral movement. They manipulated scheduled tasks by updating an existing legitimate task to execute their tools and then returned the scheduled task to its original configuration. [APT29](https://attack.mitre.org/groups/G0016) also created a scheduled task to maintain [SUNSPOT](https://attack.mitre.org/software/S0562) persistence when the host booted.(Citation: Volexity SolarWinds)(Citation: FireEye SUNBURST Backdoor December 2020)(Citation: CrowdStrike SUNSPOT Implant January 2021)
- [S1014] DanBot: [DanBot](https://attack.mitre.org/software/S1014) can use a scheduled task for installation.(Citation: SecureWorks August 2019)
- [S0170] Helminth: [Helminth](https://attack.mitre.org/software/S0170) has used a scheduled task for persistence.(Citation: ClearSky OilRig Jan 2017)
- [G0022] APT3: An [APT3](https://attack.mitre.org/groups/G0022) downloader creates persistence by creating the following scheduled task: <code>schtasks /create /tn "mysc" /tr C:\Users\Public\test.exe /sc ONLOGON /ru "System"</code>.(Citation: FireEye Operation Double Tap)
- [S1015] Milan: [Milan](https://attack.mitre.org/software/S1015) can establish persistence on a targeted host with scheduled tasks.(Citation: ClearSky Siamesekitten August 2021)(Citation: Accenture Lyceum Targets November 2021)
- [S0697] HermeticWiper: [HermeticWiper](https://attack.mitre.org/software/S0697) has the ability to use scheduled tasks for execution.(Citation: Symantec Ukraine Wipers February 2022)
- [S1166] Solar: [Solar](https://attack.mitre.org/software/S1166) can create scheduled tasks named Earth and Venus, which run every 30 and 40 seconds respectively, to support C2 and exfiltration.(Citation: ESET OilRig Campaigns Sep 2023)
- [S0266] TrickBot: [TrickBot](https://attack.mitre.org/software/S0266) creates a scheduled task on the system that provides persistence.(Citation: S2 Grupo TrickBot June 2017)(Citation: Trend Micro Totbrick Oct 2016)(Citation: Microsoft Totbrick Oct 2017)
- [S0335] Carbon: [Carbon](https://attack.mitre.org/software/S0335) creates several tasks for later execution to continue persistence on the victim’s machine.(Citation: ESET Carbon Mar 2017)
- [S0126] ComRAT: [ComRAT](https://attack.mitre.org/software/S0126) has used a scheduled task to launch its PowerShell loader.(Citation: ESET ComRAT May 2020)(Citation: CISA ComRAT Oct 2020)
- [S0044] JHUHUGIT: [JHUHUGIT](https://attack.mitre.org/software/S0044) has registered itself as a scheduled task to run each time the current user logs in.(Citation: ESET Sednit Part 1)(Citation: ESET Sednit July 2015)
- [G0080] Cobalt Group: [Cobalt Group](https://attack.mitre.org/groups/G0080) has created Windows tasks to establish persistence.(Citation: Group IB Cobalt Aug 2017)
- [G0091] Silence: [Silence](https://attack.mitre.org/groups/G0091) has used scheduled tasks to stage its operation.(Citation: Cyber Forensicator Silence Jan 2019)
- [G0114] Chimera: [Chimera](https://attack.mitre.org/groups/G0114) has used scheduled tasks to invoke Cobalt Strike including through batch script <code>schtasks /create /ru "SYSTEM" /tn "update" /tr "cmd /c c:\windows\temp\update.bat" /sc once /f /st</code> and to maintain persistence.(Citation: Cycraft Chimera April 2020)(Citation: NCC Group Chimera January 2021)
- [S1199] LockBit 2.0: [LockBit 2.0](https://attack.mitre.org/software/S1199) can be executed via scheduled task.(Citation: Palo Alto Lockbit 2.0 JUN 2022)
- [G0040] Patchwork: A [Patchwork](https://attack.mitre.org/groups/G0040) file stealer can run a TaskScheduler DLL to add persistence.(Citation: TrendMicro Patchwork Dec 2017)
- [G1034] Daggerfly: [Daggerfly](https://attack.mitre.org/groups/G1034) has attempted to use scheduled tasks for persistence in victim environments.(Citation: ESET EvasivePanda 2024)
- [S0248] yty: [yty](https://attack.mitre.org/software/S0248) establishes persistence by creating a scheduled task with the command <code>SchTasks /Create /SC DAILY /TN BigData /TR “ + path_file + “/ST 09:30“</code>.(Citation: ASERT Donot March 2018)
- [G0046] FIN7: [FIN7](https://attack.mitre.org/groups/G0046) malware has created scheduled tasks to establish persistence.(Citation: FireEye FIN7 April 2017)(Citation: Morphisec FIN7 June 2017)(Citation: FireEye FIN7 Aug 2018)(Citation: Flashpoint FIN 7 March 2019)
- [S0589] Sibot: [Sibot](https://attack.mitre.org/software/S0589) has been executed via a scheduled task.(Citation: MSTIC NOBELIUM Mar 2021)
- [S0504] Anchor: [Anchor](https://attack.mitre.org/software/S0504) can create a scheduled task for persistence.(Citation: Cyberreason Anchor December 2019)
- [S0632] GrimAgent: [GrimAgent](https://attack.mitre.org/software/S0632) has the ability to set persistence using the Task Scheduler.(Citation: Group IB GrimAgent July 2021)
- [G1018] TA2541: [TA2541](https://attack.mitre.org/groups/G1018) has used scheduled tasks to establish persistence for installed tools.(Citation: Proofpoint TA2541 February 2022)
- [G0093] GALLIUM: [GALLIUM](https://attack.mitre.org/groups/G0093) established persistence for [PoisonIvy](https://attack.mitre.org/software/S0012) by created a scheduled task.(Citation: Cybereason Soft Cell June 2019)
- [G0034] Sandworm Team: [Sandworm Team](https://attack.mitre.org/groups/G0034) leveraged SHARPIVORY, a .NET dropper that writes embedded payload to disk and uses scheduled tasks to persist on victim machines.(Citation: mandiant_apt44_unearthing_sandworm)
- [S1064] SVCReady: [SVCReady](https://attack.mitre.org/software/S1064) can create a scheduled task named `RecoveryExTask` to gain persistence.(Citation: HP SVCReady Jun 2022)
- [G1043] BlackByte: [BlackByte](https://attack.mitre.org/groups/G1043) created scheduled tasks for payload execution.(Citation: FBI BlackByte 2022)(Citation: Picus BlackByte 2022)
- [S0409] Machete: The different components of [Machete](https://attack.mitre.org/software/S0409) are executed by Windows Task Scheduler.(Citation: ESET Machete July 2019)(Citation: Securelist Machete Aug 2014)
- [G1001] HEXANE: [HEXANE](https://attack.mitre.org/groups/G1001) has used a scheduled task to establish persistence for a keylogger.(Citation: Kaspersky Lyceum October 2021)
- [G0129] Mustang Panda: [Mustang Panda](https://attack.mitre.org/groups/G0129) has created a scheduled task to execute additional malicious software, as well as maintain persistence.(Citation: Anomali MUSTANG PANDA October 2019)(Citation: Secureworks BRONZE PRESIDENT December 2019)(Citation: McAfee Dianxun March 2021)
- [S0546] SharpStage: [SharpStage](https://attack.mitre.org/software/S0546) has a persistence component to write a scheduled task for the payload.(Citation: Cybereason Molerats Dec 2020)
- [S0368] NotPetya: [NotPetya](https://attack.mitre.org/software/S0368) creates a task to reboot the system one hour after infection.(Citation: Talos Nyetya June 2017)
- [G0059] Magic Hound: [Magic Hound](https://attack.mitre.org/groups/G0059) has used scheduled tasks to establish persistence and execution.(Citation: DFIR Report APT35 ProxyShell March 2022)(Citation: DFIR Phosphorus November 2021)
- [C0034] 2022 Ukraine Electric Power Attack: During the [2022 Ukraine Electric Power Attack](https://attack.mitre.org/campaigns/C0034), [Sandworm Team](https://attack.mitre.org/groups/G0034) leveraged Scheduled Tasks through a Group Policy Object (GPO) to execute [CaddyWiper](https://attack.mitre.org/software/S0693) at a predetermined time.(Citation: Mandiant-Sandworm-Ukraine-2022)
- [S1160] Latrodectus: [Latrodectus](https://attack.mitre.org/software/S1160) can create scheduled tasks for persistence.(Citation: Latrodectus APR 2024)(Citation: Elastic Latrodectus May 2024)(Citation: Bitsight Latrodectus June 2024)
- [S1147] Nightdoor: [Nightdoor](https://attack.mitre.org/software/S1147) uses scheduled tasks for persistence to load the final malware payload into memory.(Citation: Symantec Daggerfly 2024)
- [S0350] zwShell: [zwShell](https://attack.mitre.org/software/S0350) has used SchTasks for execution.(Citation: McAfee Night Dragon)
- [S0375] Remexi: [Remexi](https://attack.mitre.org/software/S0375) utilizes scheduled tasks as a persistence mechanism.(Citation: Securelist Remexi Jan 2019)
- [S1058] Prestige: [Prestige](https://attack.mitre.org/software/S1058) has been executed on a target system through a scheduled task created by [Sandworm Team](https://attack.mitre.org/groups/G0034) using [Impacket](https://attack.mitre.org/software/S0357).(Citation: Microsoft Prestige ransomware October 2022)
- [C0017] C0017: During [C0017](https://attack.mitre.org/campaigns/C0017), [APT41](https://attack.mitre.org/groups/G0096) used the following Windows scheduled tasks for DEADEYE dropper persistence on US state government networks: `\Microsoft\Windows\PLA\Server Manager Performance Monitor`, `\Microsoft\Windows\Ras\ManagerMobility`, `\Microsoft\Windows\WDI\SrvSetupResults`, and `\Microsoft\Windows\WDI\USOShared`.(Citation: Mandiant APT41)
- [G1016] FIN13: [FIN13](https://attack.mitre.org/groups/G1016) has created scheduled tasks in the `C:\Windows` directory of the compromised network.(Citation: Mandiant FIN13 Aug 2022)
- [C0001] Frankenstein: During [Frankenstein](https://attack.mitre.org/campaigns/C0001), the threat actors established persistence through a scheduled task using the command: `/Create /F /SC DAILY /ST 09:00 /TN WinUpdate /TR`, named "WinUpdate" (Citation: Talos Frankenstein June 2019)
- [S1081] BADHATCH: [BADHATCH](https://attack.mitre.org/software/S1081) can use `schtasks.exe` to gain persistence.(Citation: BitDefender BADHATCH Mar 2021)
- [S0384] Dridex: [Dridex](https://attack.mitre.org/software/S0384) can maintain persistence via the creation of scheduled tasks within system directories such as `windows\system32\`, `windows\syswow64,` `winnt\system32`, and `winnt\syswow64`.(Citation: Red Canary Dridex Threat Report 2021)
- [G1022] ToddyCat: [ToddyCat](https://attack.mitre.org/groups/G1022) has used scheduled tasks to execute discovery commands and scripts for collection.(Citation: Kaspersky ToddyCat Check Logs October 2023)
- [G0108] Blue Mockingbird: [Blue Mockingbird](https://attack.mitre.org/groups/G0108) has used Windows Scheduled Tasks to establish persistence on local and remote hosts.(Citation: RedCanary Mockingbird May 2020)
- [G0021] Molerats: [Molerats](https://attack.mitre.org/groups/G0021) has created scheduled tasks to persistently run VBScripts.(Citation: Unit42 Molerat Mar 2020)
- [S0439] Okrum: [Okrum](https://attack.mitre.org/software/S0439)'s installer can attempt to achieve persistence by creating a scheduled task.(Citation: ESET Okrum July 2019)
- [S0458] Ramsay: [Ramsay](https://attack.mitre.org/software/S0458) can schedule tasks via the Windows COM API to maintain persistence.(Citation: Eset Ramsay May 2020)
- [S0538] Crutch: [Crutch](https://attack.mitre.org/software/S0538) has the ability to persist using scheduled tasks.(Citation: ESET Crutch December 2020)
- [S0671] Tomiris: [Tomiris](https://attack.mitre.org/software/S0671) has used `SCHTASKS /CREATE /SC DAILY /TN StartDVL /TR "[path to self]" /ST 10:00` to establish persistence.(Citation: Kaspersky Tomiris Sep 2021)
- [C0044] Juicy Mix: During [Juicy Mix](https://attack.mitre.org/campaigns/C0044), [OilRig](https://attack.mitre.org/groups/G0049) used VBS droppers to schedule tasks for persistence.(Citation: ESET OilRig Campaigns Sep 2023)
- [S0606] Bad Rabbit: [Bad Rabbit](https://attack.mitre.org/software/S0606)’s <code>infpub.dat</code> file creates a scheduled task to launch a malicious executable.(Citation: Secure List Bad Rabbit)
- [S0483] IcedID: [IcedID](https://attack.mitre.org/software/S0483) has created a scheduled task to establish persistence.(Citation: Juniper IcedID June 2020)(Citation: DFIR_Quantum_Ransomware)(Citation: DFIR_Sodinokibi_Ransomware)
- [G0016] APT29: [APT29](https://attack.mitre.org/groups/G0016) has used named and hijacked scheduled tasks to establish persistence.(Citation: Mandiant No Easy Breach)
- [S1207] XLoader: [XLoader](https://attack.mitre.org/software/S1207) can create scheduled tasks for persistence.(Citation: Netskope XLoader 2022)
- [S1089] SharpDisco: [SharpDisco](https://attack.mitre.org/software/S1089) can create scheduled tasks to execute reverse shells that read and write data to and from specified SMB shares.(Citation: MoustachedBouncer ESET August 2023)
- [S0527] CSPY Downloader: [CSPY Downloader](https://attack.mitre.org/software/S0527) can use the schtasks utility to bypass UAC.(Citation: Cybereason Kimsuky November 2020)
- [S0128] BADNEWS: [BADNEWS](https://attack.mitre.org/software/S0128) creates a scheduled task to establish by executing a malicious payload every subsequent minute.(Citation: PaloAlto Patchwork Mar 2018)
- [G0087] APT39: [APT39](https://attack.mitre.org/groups/G0087) has created scheduled tasks for persistence.(Citation: FireEye APT39 Jan 2019)(Citation: BitDefender Chafer May 2020)(Citation: FBI FLASH APT39 September 2020)
- [G0061] FIN8: [FIN8](https://attack.mitre.org/groups/G0061) has used scheduled tasks to maintain RDP backdoors.(Citation: FireEye Know Your Enemy FIN8 Aug 2016)
- [S0024] Dyre: [Dyre](https://attack.mitre.org/software/S0024) has the ability to achieve persistence by adding a new task in the task scheduler to run every minute.(Citation: Malwarebytes Dyreza November 2015)
- [G0102] Wizard Spider: [Wizard Spider](https://attack.mitre.org/groups/G0102) has used scheduled tasks to establish persistence for [TrickBot](https://attack.mitre.org/software/S0266) and other malware.(Citation: CrowdStrike Grim Spider May 2019)(Citation: DHS/CISA Ransomware Targeting Healthcare October 2020)(Citation: FireEye KEGTAP SINGLEMALT October 2020)(Citation: DFIR Ryuk 2 Hour Speed Run November 2020)(Citation: Mandiant FIN12 Oct 2021)
- [S1013] ZxxZ: [ZxxZ](https://attack.mitre.org/software/S1013) has used scheduled tasks for persistence and execution.(Citation: Cisco Talos Bitter Bangladesh May 2022)
- [C0030] Triton Safety Instrumented System Attack: In the [Triton Safety Instrumented System Attack](https://attack.mitre.org/campaigns/C0030), [TEMP.Veles](https://attack.mitre.org/groups/G0088) installed scheduled tasks defined in XML files.(Citation: FireEye TEMP.Veles 2018)
- [S0532] Lucifer: [Lucifer](https://attack.mitre.org/software/S0532) has established persistence by creating the following scheduled task <code>schtasks /create /sc minute /mo 1 /tn QQMusic ^ /tr C:Users\%USERPROFILE%\Downloads\spread.exe /F</code>.(Citation: Unit 42 Lucifer June 2020)
- [S1018] Saint Bot: [Saint Bot](https://attack.mitre.org/software/S1018) has created a scheduled task named "Maintenance" to establish persistence.(Citation: Malwarebytes Saint Bot April 2021)
- [G0126] Higaisa: [Higaisa](https://attack.mitre.org/groups/G0126) dropped and added <code>officeupdate.exe</code> to scheduled tasks.(Citation: Malwarebytes Higaisa 2020)(Citation: Zscaler Higaisa 2020)
- [S0237] GravityRAT: [GravityRAT](https://attack.mitre.org/software/S0237) creates a scheduled task to ensure it is re-executed everyday.(Citation: Talos GravityRAT)
- [S1182] MagicRAT: [MagicRAT](https://attack.mitre.org/software/S1182) can persist via scheduled tasks.(Citation: Cisco MagicRAT 2022)
- [S1140] Spica: [Spica](https://attack.mitre.org/software/S1140) has created a scheduled task named `CalendarChecker` to establish persistence.(Citation: Google TAG COLDRIVER January 2024)
- [S1190] Kapeka: [Kapeka](https://attack.mitre.org/software/S1190) persists via scheduled tasks.(Citation: Microsoft KnuckleTouch 2024)(Citation: WithSecure Kapeka 2024)
- [G0096] APT41: [APT41](https://attack.mitre.org/groups/G0096) used a compromised account to create a scheduled task on a system.(Citation: FireEye APT41 Aug 2019)(Citation: Crowdstrike GTR2020 Mar 2020)
- [S1149] CHIMNEYSWEEP: [CHIMNEYSWEEP](https://attack.mitre.org/software/S1149) can use the Windows `SilentCleanup` scheduled task to enable payload execution.(Citation: Mandiant ROADSWEEP August 2022)
- [S0516] SoreFang: [SoreFang](https://attack.mitre.org/software/S0516) can gain persistence through use of scheduled tasks.(Citation: CISA SoreFang July 2016)
- [G0075] Rancor: [Rancor](https://attack.mitre.org/groups/G0075) launched a scheduled task to gain persistence using the <code>schtasks /create /sc</code> command.(Citation: Rancor Unit42 June 2018)
- [S0360] BONDUPDATER: [BONDUPDATER](https://attack.mitre.org/software/S0360) persists using a scheduled task that executes every minute.(Citation: Palo Alto OilRig Sep 2018)
- [S0447] Lokibot: [Lokibot](https://attack.mitre.org/software/S0447) embedded the commands <code>schtasks /Run /TN \Microsoft\Windows\DiskCleanup\SilentCleanup /I</code> inside a batch script.(Citation: Talos Lokibot Jan 2021)
- [G1003] Ember Bear: [Ember Bear](https://attack.mitre.org/groups/G1003) uses remotely scheduled tasks to facilitate remote command execution on victim machines.(Citation: Cadet Blizzard emerges as novel threat actor)
- [S0367] Emotet: [Emotet](https://attack.mitre.org/software/S0367) has maintained persistence through a scheduled task, e.g. though a .dll file in the Registry.(Citation: US-CERT Emotet Jul 2018)(Citation: emotet_hc3_nov2023)
- [S0688] Meteor: [Meteor](https://attack.mitre.org/software/S0688) execution begins from a scheduled task named `Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeAll` and it creates a separate scheduled task called `mstask` to run the wiper only once at 23:55:00.(Citation: Check Point Meteor Aug 2021)
- [C0004] CostaRicto: During [CostaRicto](https://attack.mitre.org/campaigns/C0004), the threat actors used scheduled tasks to download backdoor tools.(Citation: BlackBerry CostaRicto November 2020)
- [C0022] Operation Dream Job: During [Operation Dream Job](https://attack.mitre.org/campaigns/C0022), [Lazarus Group](https://attack.mitre.org/groups/G0032) created scheduled tasks to set a periodic execution of a remote XSL script.(Citation: ESET Lazarus Jun 2020)
- [S1011] Tarrask: [Tarrask](https://attack.mitre.org/software/S1011) is able to create “hidden” scheduled tasks for persistence.(Citation: Tarrask scheduled task)
- [C0012] Operation CuckooBees: During [Operation CuckooBees](https://attack.mitre.org/campaigns/C0012), the threat actors used scheduled tasks to execute batch scripts for lateral movement with the following command: `SCHTASKS /Create /S <IP Address> /U <Username> /p <Password> /SC ONCE /TN test /TR <Path to a Batch File> /ST <Time> /RU SYSTEM.`(Citation: Cybereason OperationCuckooBees May 2022)
- [G0095] Machete: [Machete](https://attack.mitre.org/groups/G0095) has created scheduled tasks to maintain [Machete](https://attack.mitre.org/software/S0409)'s persistence.(Citation: 360 Machete Sep 2020)
- [S1180] BlackByte Ransomware: [BlackByte Ransomware](https://attack.mitre.org/software/S1180) creates a schedule task to execute remotely deployed ransomware payloads.(Citation: Trustwave BlackByte 2021)
- [G1044] APT42: [APT42](https://attack.mitre.org/groups/G1044) has used scheduled tasks for persistence.(Citation: Mandiant APT42-charms)
- [S0148] RTM: [RTM](https://attack.mitre.org/software/S0148) tries to add a scheduled task to establish persistence.(Citation: ESET RTM Feb 2017)(Citation: Unit42 Redaman January 2019)
- [S1042] SUGARDUMP: [SUGARDUMP](https://attack.mitre.org/software/S1042) has created scheduled tasks called `MicrosoftInternetExplorerCrashRepoeterTaskMachineUA` and `MicrosoftEdgeCrashRepoeterTaskMachineUA`, which were configured to execute `CrashReporter.exe` during user logon.(Citation: Mandiant UNC3890 Aug 2022)
- [G0051] FIN10: [FIN10](https://attack.mitre.org/groups/G0051) has established persistence by using S4U tasks as well as the Scheduled Task option in PowerShell Empire.(Citation: FireEye FIN10 June 2017)(Citation: Github PowerShell Empire)
- [G0019] Naikon: [Naikon](https://attack.mitre.org/groups/G0019) has used schtasks.exe for lateral movement in compromised networks.(Citation: Bitdefender Naikon April 2021)
- [S0140] Shamoon: [Shamoon](https://attack.mitre.org/software/S0140) copies an executable payload to the target system by using [SMB/Windows Admin Shares](https://attack.mitre.org/techniques/T1021/002) and then scheduling an unnamed task to execute the malware.(Citation: FireEye Shamoon Nov 2016)(Citation: Palo Alto Shamoon Nov 2016)
- [S0581] IronNetInjector: [IronNetInjector](https://attack.mitre.org/software/S0581) has used a task XML file named <code>mssch.xml</code> to run an IronPython script when a user logs in or when specific system events are created.(Citation: Unit 42 IronNetInjector February 2021 )
- [G1039] RedCurl: [RedCurl](https://attack.mitre.org/groups/G1039) has created scheduled tasks for persistence.(Citation: group-ib_redcurl1)(Citation: group-ib_redcurl2)(Citation: trendmicro_redcurl)
- [S0194] PowerSploit: [PowerSploit](https://attack.mitre.org/software/S0194)'s <code>New-UserPersistenceOption</code> Persistence argument can be used to establish via a [Scheduled Task/Job](https://attack.mitre.org/techniques/T1053).(Citation: GitHub PowerSploit May 2012)(Citation: PowerSploit Documentation)
- [S0331] Agent Tesla: [Agent Tesla](https://attack.mitre.org/software/S0331)  has achieved persistence via scheduled tasks.(Citation: SentinelLabs Agent Tesla Aug 2020)
- [G1036] Moonstone Sleet: [Moonstone Sleet](https://attack.mitre.org/groups/G1036) used scheduled tasks for program execution during initial access to victim machines.(Citation: Microsoft Moonstone Sleet 2024)
- [G0050] APT32: [APT32](https://attack.mitre.org/groups/G0050) has used scheduled tasks to persist on victim systems.(Citation: FireEye APT32 May 2017)(Citation: Cybereason Oceanlotus May 2017)(Citation: Cybereason Cobalt Kitty 2017)(Citation: ESET OceanLotus Mar 2019)
- [S0438] Attor: [Attor](https://attack.mitre.org/software/S0438)'s installer plugin can schedule a new task that loads the dispatcher on boot/logon.(Citation: ESET Attor Oct 2019)
- [G0117] Fox Kitten: [Fox Kitten](https://attack.mitre.org/groups/G0117) has used Scheduled Tasks for persistence and to load and execute a reverse proxy binary.(Citation: CISA AA20-259A Iran-Based Actor September 2020)(Citation: ClearSky Pay2Kitten December 2020)
- [G0064] APT33: [APT33](https://attack.mitre.org/groups/G0064) has created a scheduled task to execute a .vbe file multiple times a day.(Citation: Symantec Elfin Mar 2019)
- [S0446] Ryuk: [Ryuk](https://attack.mitre.org/software/S0446) can remotely create a scheduled task to execute itself on a system.(Citation: ANSSI RYUK RANSOMWARE)
- [S0396] EvilBunny: [EvilBunny](https://attack.mitre.org/software/S0396) has executed commands via scheduled tasks.(Citation: Cyphort EvilBunny Dec 2014)
- [G0049] OilRig: [OilRig](https://attack.mitre.org/groups/G0049) has created scheduled tasks that run a VBScript to execute a payload on victim machines.(Citation: Unit 42 OopsIE! Feb 2018)(Citation: Unit 42 QUADAGENT July 2018)(Citation: FireEye APT34 July 2019)(Citation: Check Point APT34 April 2021)
- [G0082] APT38: [APT38](https://attack.mitre.org/groups/G0082) has used Task Scheduler to run programs at system startup or on a scheduled basis for persistence.(Citation: CISA AA20-239A BeagleBoyz August 2020) Additionally, [APT38](https://attack.mitre.org/groups/G0082) has used living-off-the-land scripts to execute a malicious script via a scheduled task.(Citation: 1 - appv)
- [S0449] Maze: [Maze](https://attack.mitre.org/software/S0449) has created scheduled tasks using name variants such as "Windows Update Security", "Windows Update Security Patches", and "Google Chrome Security Update", to launch [Maze](https://attack.mitre.org/software/S0449) at a specific time.(Citation: Sophos Maze VM September 2020)
- [G0045] menuPass: [menuPass](https://attack.mitre.org/groups/G0045) has used a script (atexec.py) to execute a command on a target machine via Task Scheduler.(Citation: PWC Cloud Hopper Technical Annex April 2017)
- [G0099] APT-C-36: [APT-C-36](https://attack.mitre.org/groups/G0099) has used a macro function to set scheduled tasks, disguised as those used by Google.(Citation: QiAnXin APT-C-36 Feb2019)
- [S0166] RemoteCMD: [RemoteCMD](https://attack.mitre.org/software/S0166) can execute commands remotely by creating a new schedule task on the remote system(Citation: Symantec Buckeye)
- [S0584] AppleJeus: [AppleJeus](https://attack.mitre.org/software/S0584) has created a scheduled SYSTEM task that runs when a user logs in.(Citation: CISA AppleJeus Feb 2021)
- [S0046] CozyCar: One persistence mechanism used by [CozyCar](https://attack.mitre.org/software/S0046) is to register itself as a scheduled task.(Citation: F-Secure CozyDuke)
- [G0037] FIN6: [FIN6](https://attack.mitre.org/groups/G0037) has used scheduled tasks to establish persistence for various malware it uses, including downloaders known as HARDTACK and SHIPBREAD and [FrameworkPOS](https://attack.mitre.org/software/S0503).(Citation: FireEye FIN6 April 2016)
- [S0629] RainyDay: [RainyDay](https://attack.mitre.org/software/S0629) can use scheduled tasks to achieve persistence.(Citation: Bitdefender Naikon April 2021)
- [G1014] LuminousMoth: [LuminousMoth](https://attack.mitre.org/groups/G1014) has created scheduled tasks to establish persistence for their tools.(Citation: Bitdefender LuminousMoth July 2021)
- [S1043] ccf32: [ccf32](https://attack.mitre.org/software/S1043) can run on a daily basis using a scheduled task.(Citation: Bitdefender FunnyDream Campaign November 2020)
- [C0014] Operation Wocao: During [Operation Wocao](https://attack.mitre.org/campaigns/C0014), threat actors used scheduled tasks to execute malicious PowerShell code on remote systems.(Citation: FoxIT Wocao December 2019)
- [S0223] POWERSTATS: [POWERSTATS](https://attack.mitre.org/software/S0223) has established persistence through a scheduled task using the command <code>”C:\Windows\system32\schtasks.exe” /Create /F /SC DAILY /ST 12:00 /TN MicrosoftEdge /TR “c:\Windows\system32\wscript.exe C:\Windows\temp\Windows.vbe”</code>.(Citation: ClearSky MuddyWater Nov 2018)
- [S0476] Valak: [Valak](https://attack.mitre.org/software/S0476) has used scheduled tasks to execute additional payloads and to gain persistence on a compromised host.(Citation: Cybereason Valak May 2020)(Citation: Unit 42 Valak July 2020)(Citation: SentinelOne Valak June 2020)
- [G0032] Lazarus Group: [Lazarus Group](https://attack.mitre.org/groups/G0032) has used <code>schtasks</code> for persistence including through the periodic execution of a remote XSL script or a dropped VBS payload.(Citation: Qualys LolZarus)(Citation: ESET Twitter Ida Pro Nov 2021)
- [G0060] BRONZE BUTLER: [BRONZE BUTLER](https://attack.mitre.org/groups/G0060) has used [schtasks](https://attack.mitre.org/software/S0111) to register a scheduled task to execute malware during lateral movement.(Citation: Secureworks BRONZE BUTLER Oct 2017)
- [S0500] MCMD: [MCMD](https://attack.mitre.org/software/S0500) can use scheduled tasks for persistence.(Citation: Secureworks MCMD July 2019)
- [G1035] Winter Vivern: [Winter Vivern](https://attack.mitre.org/groups/G1035) executed PowerShell scripts that would subsequently attempt to establish persistence by creating scheduled tasks objects to periodically retrieve and execute remotely-hosted payloads.(Citation: DomainTools WinterVivern 2021)
- [S0038] Duqu: Adversaries can instruct [Duqu](https://attack.mitre.org/software/S0038) to spread laterally by copying itself to shares it has enumerated and for which it has obtained legitimate credentials (via keylogging or other means). The remote host is then infected by using the compromised credentials to schedule a task on remote machines that executes the malware.(Citation: Symantec W32.Duqu)
- [G0035] Dragonfly: [Dragonfly](https://attack.mitre.org/groups/G0035) has used scheduled tasks to automatically log out of created accounts every 8 hours as well as to execute malicious files.(Citation: US-CERT TA18-074A)
- [S0475] BackConfig: [BackConfig](https://attack.mitre.org/software/S0475) has the ability to use scheduled tasks to repeatedly execute malicious payloads on a compromised host.(Citation: Unit 42 BackConfig May 2020)
- [S0198] NETWIRE: [NETWIRE](https://attack.mitre.org/software/S0198) can create a scheduled task to establish persistence.(Citation: FireEye NETWIRE March 2019)
- [S1133] Apostle: [Apostle](https://attack.mitre.org/software/S1133) achieves persistence by creating a scheduled task, such as <code>MicrosoftCrashHandlerUAC</code>.(Citation: SentinelOne Agrius 2021)
- [S0363] Empire: [Empire](https://attack.mitre.org/software/S0363) has modules to interact with the Windows task scheduler.(Citation: Github PowerShell Empire)
- [C0032] C0032: During the [C0032](https://attack.mitre.org/campaigns/C0032) campaign, [TEMP.Veles](https://attack.mitre.org/groups/G0088) used scheduled task XML triggers.(Citation: FireEye TRITON 2019)
- [G0069] MuddyWater: [MuddyWater](https://attack.mitre.org/groups/G0069) has used scheduled tasks to establish persistence.(Citation: Reaqta MuddyWater November 2017)
- [S0390] SQLRat: [SQLRat](https://attack.mitre.org/software/S0390) has created scheduled tasks in <code>%appdata%\Roaming\Microsoft\Templates\</code>.(Citation: Flashpoint FIN 7 March 2019)
- [S0264] OopsIE: [OopsIE](https://attack.mitre.org/software/S0264) creates a scheduled task to run itself every three minutes.(Citation: Unit 42 OopsIE! Feb 2018)(Citation: Unit 42 OilRig Sept 2018)
- [S1039] Bumblebee: [Bumblebee](https://attack.mitre.org/software/S1039) can achieve persistence by copying its DLL to a subdirectory of %APPDATA% and creating a Visual Basic Script that will load the DLL via a scheduled task.(Citation: Proofpoint Bumblebee April 2022)(Citation: Symantec Bumblebee June 2022)
- [S0534] Bazar: [Bazar](https://attack.mitre.org/software/S0534) can create a scheduled task for persistence.(Citation: Cybereason Bazar July 2020)(Citation: NCC Group Team9 June 2020)
- [S0167] Matryoshka: [Matryoshka](https://attack.mitre.org/software/S0167) can establish persistence by adding a Scheduled Task named "Microsoft Boost Kernel Optimization".(Citation: ClearSky Wilted Tulip July 2017)(Citation: CopyKittens Nov 2015)
- [S0417] GRIFFON: [GRIFFON](https://attack.mitre.org/software/S0417) has used <code>sctasks</code> for persistence. (Citation: SecureList Griffon May 2019)
- [S1135] MultiLayer Wiper: [MultiLayer Wiper](https://attack.mitre.org/software/S1135) creates a malicious scheduled task that launches a batch file to remove Windows Event Logs.(Citation: Unit42 Agrius 2023)
- [S0382] ServHelper: [ServHelper](https://attack.mitre.org/software/S0382) contains modules that will use [schtasks](https://attack.mitre.org/software/S0111) to carry out malicious operations.(Citation: Proofpoint TA505 Jan 2019)
- [S1088] Disco: [Disco](https://attack.mitre.org/software/S1088) can create a scheduled task to run every minute for persistence.(Citation: MoustachedBouncer ESET August 2023)
- [G0047] Gamaredon Group: [Gamaredon Group](https://attack.mitre.org/groups/G0047) has created scheduled tasks to launch executables after a designated number of minutes have passed.(Citation: ESET Gamaredon June 2020)(Citation: CERT-EE Gamaredon January 2021)(Citation: Microsoft Actinium February 2022)(Citation: unit42_gamaredon_dec2022)
- [S0673] DarkWatchman: [DarkWatchman](https://attack.mitre.org/software/S0673) has created a scheduled task for persistence.(Citation: Prevailion DarkWatchman 2021)
- [G0094] Kimsuky: [Kimsuky](https://attack.mitre.org/groups/G0094) has downloaded additional malware with scheduled tasks.(Citation: KISA Operation Muzabi)
- [S0147] Pteranodon: [Pteranodon](https://attack.mitre.org/software/S0147) schedules tasks to invoke its components in order to establish persistence.(Citation: Palo Alto Gamaredon Feb 2017)(Citation: Symantec Shuckworm January 2022)
- [S0603] Stuxnet: [Stuxnet](https://attack.mitre.org/software/S0603) schedules a network job to execute two minutes after host infection.(Citation: Nicolas Falliere, Liam O Murchu, Eric Chien February 2011)
- [S0260] InvisiMole: [InvisiMole](https://attack.mitre.org/software/S0260) has used scheduled tasks named <code>MSST</code> and <code>\Microsoft\Windows\Autochk\Scheduled</code> to establish persistence.(Citation: ESET InvisiMole June 2020)
- [S0050] CosmicDuke: [CosmicDuke](https://attack.mitre.org/software/S0050) uses scheduled tasks typically named "Watchmon Service" for persistence.(Citation: F-Secure Cosmicduke)
- [G0038] Stealth Falcon: [Stealth Falcon](https://attack.mitre.org/groups/G0038) malware creates a scheduled task entitled “IE Web Cache” to execute a malicious file hourly.(Citation: Citizen Lab Stealth Falcon May 2016)
- [G1002] BITTER: [BITTER](https://attack.mitre.org/groups/G1002) has used scheduled tasks for persistence and execution.(Citation: Cisco Talos Bitter Bangladesh May 2022)
- [S0650] QakBot: [QakBot](https://attack.mitre.org/software/S0650) has the ability to create scheduled tasks for persistence.(Citation: Trend Micro Qakbot May 2020)(Citation: Kroll Qakbot June 2020)(Citation: Crowdstrike Qakbot October 2020)(Citation: Trend Micro Qakbot December 2020)(Citation: Red Canary Qbot)(Citation: Cyberint Qakbot May 2021)(Citation: Kaspersky QakBot September 2021)(Citation: Group IB Ransomware September 2020)
- [S0184] POWRUNER: [POWRUNER](https://attack.mitre.org/software/S0184) persists through a scheduled task that executes it every minute.(Citation: FireEye APT34 Dec 2017)
- [S0379] Revenge RAT: [Revenge RAT](https://attack.mitre.org/software/S0379) schedules tasks to run malicious scripts at different intervals.(Citation: Cofense RevengeRAT Feb 2019)
- [S0168] Gazer: [Gazer](https://attack.mitre.org/software/S0168) can establish persistence by creating a scheduled task.(Citation: ESET Gazer Aug 2017)(Citation: Securelist WhiteBear Aug 2017)
- [G0142] Confucius: [Confucius](https://attack.mitre.org/groups/G0142) has created scheduled tasks to maintain persistence on a compromised host.(Citation: TrendMicro Confucius APT Aug 2021)
- [S0189] ISMInjector: [ISMInjector](https://attack.mitre.org/software/S0189) creates scheduled tasks to establish persistence.(Citation: OilRig New Delivery Oct 2017)
- [S0111] schtasks: [schtasks](https://attack.mitre.org/software/S0111) is used to schedule tasks on a Windows system to run at a specific date and time.(Citation: TechNet Schtasks)
- [S0262] QuasarRAT: [QuasarRAT](https://attack.mitre.org/software/S0262) contains a .NET wrapper DLL for creating and managing scheduled tasks for maintaining persistence upon reboot.(Citation: Volexity Patchwork June 2018)(Citation: CISA AR18-352A Quasar RAT December 2018)
- [S0477] Goopy: [Goopy](https://attack.mitre.org/software/S0477) has the ability to maintain persistence by creating scheduled tasks set to run every hour.(Citation: Cybereason Cobalt Kitty 2017)
- [S0680] LitePower: [LitePower](https://attack.mitre.org/software/S0680) can create a scheduled task to enable persistence mechanisms.(Citation: Kaspersky WIRTE November 2021)
- [S0226] Smoke Loader: [Smoke Loader](https://attack.mitre.org/software/S0226) launches a scheduled task.(Citation: Talos Smoke Loader July 2018)
- [S1152] IMAPLoader: [IMAPLoader](https://attack.mitre.org/software/S1152) creates scheduled tasks for persistence based on the operating system version of the victim machine.(Citation: PWC Yellow Liderc 2023)
- [G0067] APT37: [APT37](https://attack.mitre.org/groups/G0067) has created scheduled tasks to run malicious scripts on a compromised host.(Citation: Volexity InkySquid RokRAT August 2021)
- [S0250] Koadic: [Koadic](https://attack.mitre.org/software/S0250) has used scheduled tasks to add persistence.(Citation: MalwareBytes LazyScripter Feb 2021)
- [S0251] Zebrocy: [Zebrocy](https://attack.mitre.org/software/S0251) has a command to create a scheduled task for persistence.(Citation: CISA Zebrocy Oct 2020)
- [S1087] AsyncRAT: [AsyncRAT](https://attack.mitre.org/software/S1087) can create a scheduled task to maintain persistence on system start-up.(Citation: Telefonica Snip3 December 2021)
- [S0431] HotCroissant: [HotCroissant](https://attack.mitre.org/software/S0431) has attempted to install a scheduled task named “Java Maintenance64” on startup to establish persistence.(Citation: Carbon Black HotCroissant April 2020)
- [S0269] QUADAGENT: [QUADAGENT](https://attack.mitre.org/software/S0269) creates a scheduled task to maintain persistence on the victim’s machine.(Citation: Unit 42 QUADAGENT July 2018)
- [S1169] Mango: [Mango](https://attack.mitre.org/software/S1169) can create a scheduled task to run every 32 seconds to communicate with C2 and execute received commands.(Citation: ESET OilRig Campaigns Sep 2023)

#### T1053.006 - Systemd Timers

Description:

Adversaries may abuse systemd timers to perform task scheduling for initial or recurring execution of malicious code. Systemd timers are unit files with file extension <code>.timer</code> that control services. Timers can be set to run on a calendar event or after a time span relative to a starting point. They can be used as an alternative to [Cron](https://attack.mitre.org/techniques/T1053/003) in Linux environments.(Citation: archlinux Systemd Timers Aug 2020) Systemd timers may be activated remotely via the <code>systemctl</code> command line utility, which operates over [SSH](https://attack.mitre.org/techniques/T1021/004).(Citation: Systemd Remote Control)

Each <code>.timer</code> file must have a corresponding <code>.service</code> file with the same name, e.g., <code>example.timer</code> and <code>example.service</code>. <code>.service</code> files are [Systemd Service](https://attack.mitre.org/techniques/T1543/002) unit files that are managed by the systemd system and service manager.(Citation: Linux man-pages: systemd January 2014) Privileged timers are written to <code>/etc/systemd/system/</code> and <code>/usr/lib/systemd/system</code> while user level are written to <code>~/.config/systemd/user/</code>.

An adversary may use systemd timers to execute malicious code at system startup or on a scheduled basis for persistence.(Citation: Arch Linux Package Systemd Compromise BleepingComputer 10JUL2018)(Citation: gist Arch package compromise 10JUL2018)(Citation: acroread package compromised Arch Linux Mail 8JUL2018) Timers installed using privileged paths may be used to maintain root level persistence. Adversaries may also install user level timers to achieve user level persistence.(Citation: Falcon Sandbox smp: 28553b3a9d)

#### T1053.007 - Container Orchestration Job

Description:

Adversaries may abuse task scheduling functionality provided by container orchestration tools such as Kubernetes to schedule deployment of containers configured to execute malicious code. Container orchestration jobs run these automated tasks at a specific date and time, similar to cron jobs on a Linux system. Deployments of this type can also be configured to maintain a quantity of containers over time, automating the process of maintaining persistence within a cluster.

In Kubernetes, a CronJob may be used to schedule a Job that runs one or more containers to perform specific tasks.(Citation: Kubernetes Jobs)(Citation: Kubernetes CronJob) An adversary therefore may utilize a CronJob to schedule deployment of a Job that executes malicious code in various nodes within a cluster.(Citation: Threat Matrix for Kubernetes)


### T1055 - Process Injection

Description:

Adversaries may inject code into processes in order to evade process-based defenses as well as possibly elevate privileges. Process injection is a method of executing arbitrary code in the address space of a separate live process. Running code in the context of another process may allow access to the process's memory, system/network resources, and possibly elevated privileges. Execution via process injection may also evade detection from security products since the execution is masked under a legitimate process. 

There are many different ways to inject code into a process, many of which abuse legitimate functionalities. These implementations exist for every major OS but are typically platform specific. 

More sophisticated samples may perform multiple process injections to segment modules and further evade detection, utilizing named pipes or other inter-process communication (IPC) mechanisms as a communication channel.

Procedures:

- [G0082] APT38: [APT38](https://attack.mitre.org/groups/G0082) has injected malicious payloads into the `explorer.exe` process.(Citation: 1 - appv)
- [S0331] Agent Tesla: [Agent Tesla](https://attack.mitre.org/software/S0331) can inject into known, vulnerable binaries on targeted hosts.(Citation: SentinelLabs Agent Tesla Aug 2020)
- [S0681] Lizar: [Lizar](https://attack.mitre.org/software/S0681) can migrate the loader into another process.(Citation: BiZone Lizar May 2021)
- [S0533] SLOTHFULMEDIA: [SLOTHFULMEDIA](https://attack.mitre.org/software/S0533) can inject into running processes on a compromised host.(Citation: CISA MAR SLOTHFULMEDIA October 2020)
- [S0581] IronNetInjector: [IronNetInjector](https://attack.mitre.org/software/S0581) can use an IronPython scripts to load a .NET injector to inject a payload into its own or a remote process.(Citation: Unit 42 IronNetInjector February 2021 )
- [S1159] DUSTTRAP: [DUSTTRAP](https://attack.mitre.org/software/S1159) compromises the `.text` section of a legitimate system DLL in `%windir%` to hold the contents of retrieved plug-ins.(Citation: Google Cloud APT41 2024)
- [S1081] BADHATCH: [BADHATCH](https://attack.mitre.org/software/S1081) can inject itself into an existing explorer.exe process by using `RtlCreateUserThread`.(Citation: Gigamon BADHATCH Jul 2019)(Citation: BitDefender BADHATCH Mar 2021)
- [S0398] HyperBro: [HyperBro](https://attack.mitre.org/software/S0398) can run shellcode it injects into a newly created process.(Citation: Unit42 Emissary Panda May 2019)
- [S0633] Sliver: [Sliver](https://attack.mitre.org/software/S0633) includes multiple methods to perform process injection to migrate the framework into other, potentially privileged processes on the victim machine.(Citation: Microsoft Sliver 2022)(Citation: Cybereason Sliver Undated)(Citation: Bishop Fox Sliver Framework August 2019)(Citation: GitHub Sliver C2)
- [S0534] Bazar: [Bazar](https://attack.mitre.org/software/S0534) can inject code through calling <code>VirtualAllocExNuma</code>.(Citation: Cybereason Bazar July 2020)
- [G0091] Silence: [Silence](https://attack.mitre.org/groups/G0091) has injected a DLL library containing a Trojan into the fwmain32.exe process.(Citation: Group IB Silence Sept 2018)
- [S0436] TSCookie: [TSCookie](https://attack.mitre.org/software/S0436) has the ability to inject code into the svchost.exe, iexplorer.exe, explorer.exe, and default browser processes.(Citation: JPCert BlackTech Malware September 2019)
- [S0496] REvil: [REvil](https://attack.mitre.org/software/S0496) can inject itself into running processes on a compromised host.(Citation: McAfee REvil October 2019)
- [S0695] Donut: [Donut](https://attack.mitre.org/software/S0695) includes a subproject <code>DonutTest</code> to inject shellcode into a target process.(Citation: Donut Github)
- [S0470] BBK: [BBK](https://attack.mitre.org/software/S0470) has the ability to inject shellcode into svchost.exe.(Citation: Trend Micro Tick November 2019)
- [C0029] Cutting Edge: During [Cutting Edge](https://attack.mitre.org/campaigns/C0029), threat actors used malicious SparkGateway plugins to inject shared objects into web process memory on compromised Ivanti Secure Connect VPNs to enable deployment of backdoors.(Citation: Mandiant Cutting Edge Part 3 February 2024)
- [S0561] GuLoader: [GuLoader](https://attack.mitre.org/software/S0561) has the ability to inject shellcode into a donor processes that is started in a suspended state. [GuLoader](https://attack.mitre.org/software/S0561) has previously used RegAsm as a donor process.(Citation: Medium Eli Salem GuLoader April 2021)
- [G0050] APT32: [APT32](https://attack.mitre.org/groups/G0050) malware has injected a Cobalt Strike beacon into Rundll32.exe.(Citation: Cybereason Cobalt Kitty 2017)
- [G0102] Wizard Spider: [Wizard Spider](https://attack.mitre.org/groups/G0102) has used process injection to execute payloads to escalate privileges.(Citation: Mandiant FIN12 Oct 2021)
- [S1074] ANDROMEDA: [ANDROMEDA](https://attack.mitre.org/software/S1074) can inject into the `wuauclt.exe` process to perform C2 actions.(Citation: Mandiant Suspected Turla Campaign February 2023)
- [S1105] COATHANGER: [COATHANGER](https://attack.mitre.org/software/S1105) includes a binary labeled `authd` that can inject a library into a running process and then hook an existing function within that process with a new function from that library.(Citation: NCSC-NL COATHANGER Feb 2024)
- [S0347] AuditCred: [AuditCred](https://attack.mitre.org/software/S0347) can inject code from files to other running processes.(Citation: TrendMicro Lazarus Nov 2018)
- [S0032] gh0st RAT: [gh0st RAT](https://attack.mitre.org/software/S0032) can inject malicious code into process created by the “Command_Create&Inject” function.(Citation: Gh0stRAT ATT March 2019)
- [S0198] NETWIRE: [NETWIRE](https://attack.mitre.org/software/S0198) can inject code into system processes including notepad.exe, svchost.exe, and vbc.exe.(Citation: Red Canary NETWIRE January 2020)
- [S0093] Backdoor.Oldrea: [Backdoor.Oldrea](https://attack.mitre.org/software/S0093) injects itself into explorer.exe.(Citation: Symantec Dragonfly)(Citation: Gigamon Berserk Bear October 2021)
- [S0332] Remcos: [Remcos](https://attack.mitre.org/software/S0332) has a command to hide itself through injecting into another process.(Citation: Fortinet Remcos Feb 2017)
- [S0579] Waterbear: [Waterbear](https://attack.mitre.org/software/S0579) can inject decrypted shellcode into the LanmanServer service.(Citation: Trend Micro Waterbear December 2019)
- [S0692] SILENTTRINITY: [SILENTTRINITY](https://attack.mitre.org/software/S0692) can inject shellcode directly into Excel.exe or a specific process.(Citation: GitHub SILENTTRINITY Modules July 2019)
- [S0154] Cobalt Strike: [Cobalt Strike](https://attack.mitre.org/software/S0154) can inject a variety of payloads into processes dynamically chosen by the adversary.(Citation: cobaltstrike manual)(Citation: Cobalt Strike Manual 4.3 November 2020)(Citation: DFIR Conti Bazar Nov 2021)
- [S0040] HTRAN: [HTRAN](https://attack.mitre.org/software/S0040) can inject into into running processes.(Citation: NCSC Joint Report Public Tools)
- [S0660] Clambling: [Clambling](https://attack.mitre.org/software/S0660) can inject into the `svchost.exe` process for execution.(Citation: Trend Micro DRBControl February 2020)
- [S0206] Wiarp: [Wiarp](https://attack.mitre.org/software/S0206) creates a backdoor through which remote attackers can inject files into running processes.(Citation: Symantec Wiarp May 2012)
- [G1018] TA2541: [TA2541](https://attack.mitre.org/groups/G1018) has injected malicious code into legitimate .NET related processes including  regsvcs.exe, msbuild.exe, and installutil.exe.(Citation: Proofpoint TA2541 February 2022)(Citation: Cisco Operation Layover September 2021)
- [G0080] Cobalt Group: [Cobalt Group](https://attack.mitre.org/groups/G0080) has injected code into trusted processes.(Citation: Group IB Cobalt Aug 2017)
- [S1122] Mispadu: [Mispadu](https://attack.mitre.org/software/S1122)'s binary is injected into memory via `WriteProcessMemory`.(Citation: Segurança Informática URSA Sophisticated Loader 2020)(Citation: SCILabs Malteiro 2021)
- [S0201] JPIN: [JPIN](https://attack.mitre.org/software/S0201) can inject content into lsass.exe to load a module.(Citation: Microsoft PLATINUM April 2016)
- [S0380] StoneDrill: [StoneDrill](https://attack.mitre.org/software/S0380) has relied on injecting its payload directly into the process memory of the victim's preferred browser.(Citation: Kaspersky StoneDrill 2017)
- [S0247] NavRAT: [NavRAT](https://attack.mitre.org/software/S0247) copies itself into a running Internet Explorer process to evade detection.(Citation: Talos NavRAT May 2018)
- [S0650] QakBot: [QakBot](https://attack.mitre.org/software/S0650) can inject itself into processes including explore.exe, Iexplore.exe, Mobsync.exe., and wermgr.exe.(Citation: Trend Micro Qakbot May 2020)(Citation: Kroll Qakbot June 2020)(Citation: Trend Micro Qakbot December 2020)(Citation: Kaspersky QakBot September 2021)(Citation: Trend Micro Black Basta October 2022)
- [S1039] Bumblebee: [Bumblebee](https://attack.mitre.org/software/S1039) can inject code into multiple processes on infected endpoints.(Citation: Cybereason Bumblebee August 2022)
- [S0363] Empire: [Empire](https://attack.mitre.org/software/S0363) contains multiple modules for injecting into processes, such as <code>Invoke-PSInject</code>.(Citation: Github PowerShell Empire)
- [G0067] APT37: [APT37](https://attack.mitre.org/groups/G0067) injects its malware variant, [ROKRAT](https://attack.mitre.org/software/S0240), into the cmd.exe process.(Citation: Talos Group123)
- [S0168] Gazer: [Gazer](https://attack.mitre.org/software/S0168) injects its communication module into an Internet accessible process through which it performs C2.(Citation: ESET Gazer Aug 2017)(Citation: Securelist WhiteBear Aug 2017)
- [S1065] Woody RAT: [Woody RAT](https://attack.mitre.org/software/S1065) can inject code into a targeted process by writing to the remote memory of an infected system and then create a remote thread.(Citation: MalwareBytes WoodyRAT Aug 2022)
- [S0260] InvisiMole: [InvisiMole](https://attack.mitre.org/software/S0260) can inject itself into another process to avoid detection including use of a technique called ListPlanting that customizes the sorting algorithm in a ListView structure.(Citation: ESET InvisiMole June 2020)
- [C0014] Operation Wocao: During [Operation Wocao](https://attack.mitre.org/campaigns/C0014), threat actors injected code into a selected process, which in turn launches a command as a child process of the original.(Citation: FoxIT Wocao December 2019)
- [S0226] Smoke Loader: [Smoke Loader](https://attack.mitre.org/software/S0226) injects into the Internet Explorer process.(Citation: Talos Smoke Loader July 2018)
- [S0378] PoshC2: [PoshC2](https://attack.mitre.org/software/S0378) contains multiple modules for injecting into processes, such as <code>Invoke-PSInject</code>.(Citation: GitHub PoshC2)
- [S1100] Ninja: [Ninja](https://attack.mitre.org/software/S1100) has the ability to inject an agent module into a new process and arbitrary shellcode into running processes.(Citation: Kaspersky ToddyCat June 2022)(Citation: Kaspersky ToddyCat Check Logs October 2023)
- [S0469] ABK: [ABK](https://attack.mitre.org/software/S0469) has the ability to inject shellcode into svchost.exe.(Citation: Trend Micro Tick November 2019)
- [S0473] Avenger: [Avenger](https://attack.mitre.org/software/S0473) has the ability to inject shellcode into svchost.exe.(Citation: Trend Micro Tick November 2019)
- [C0013] Operation Sharpshooter: During [Operation Sharpshooter](https://attack.mitre.org/campaigns/C0013), threat actors leveraged embedded shellcode to inject a downloader into the memory of Word.(Citation: Threatpost New Op Sharpshooter Data March 2019)
- [S0614] CostaBricks: [CostaBricks](https://attack.mitre.org/software/S0614) can inject a payload into the memory of a compromised host.(Citation: BlackBerry CostaRicto November 2020)
- [S0348] Cardinal RAT: [Cardinal RAT](https://attack.mitre.org/software/S0348) injects into a newly spawned process created from a native Windows executable.(Citation: PaloAlto CardinalRat Apr 2017)
- [S0438] Attor: [Attor](https://attack.mitre.org/software/S0438)'s dispatcher can inject itself into running processes to gain higher privileges and to evade detection.(Citation: ESET Attor Oct 2019)
- [S0446] Ryuk: [Ryuk](https://attack.mitre.org/software/S0446) has injected itself into remote processes to encrypt files using a combination of <code>VirtualAlloc</code>, <code>WriteProcessMemory</code>, and <code>CreateRemoteThread</code>.(Citation: CrowdStrike Ryuk January 2019)
- [S0670] WarzoneRAT: [WarzoneRAT](https://attack.mitre.org/software/S0670) has the ability to inject malicious DLLs into a specific process for privilege escalation.(Citation: Check Point Warzone Feb 2020)
- [G1047] Velvet Ant: [Velvet Ant](https://attack.mitre.org/groups/G1047) initial execution included launching multiple `svchost` processes and injecting code into them.(Citation: Sygnia VelvetAnt 2024A)
- [G0094] Kimsuky: [Kimsuky](https://attack.mitre.org/groups/G0094) has used Win7Elevate to inject malicious code into explorer.exe.(Citation: Securelist Kimsuky Sept 2013)
- [G1023] APT5: [APT5](https://attack.mitre.org/groups/G1023) has used the CLEANPULSE utility to insert command line strings into a targeted process to alter its functionality.(Citation: Mandiant Pulse Secure Update May 2021)
- [G0068] PLATINUM: [PLATINUM](https://attack.mitre.org/groups/G0068) has used various methods of process injection including hot patching.(Citation: Microsoft PLATINUM April 2016)
- [S0596] ShadowPad: [ShadowPad](https://attack.mitre.org/software/S0596) has injected an install module into a newly created process.(Citation: Kaspersky ShadowPad Aug 2017)
- [S0240] ROKRAT: [ROKRAT](https://attack.mitre.org/software/S0240) can use `VirtualAlloc`, `WriteProcessMemory`, and then `CreateRemoteThread` to execute shellcode within the address space of `Notepad.exe`.(Citation: Malwarebytes RokRAT VBA January 2021)
- [S0376] HOPLIGHT: [HOPLIGHT](https://attack.mitre.org/software/S0376) has injected into running processes.(Citation: US-CERT HOPLIGHT Apr 2019)
- [G1043] BlackByte: [BlackByte](https://attack.mitre.org/groups/G1043) has injected [Cobalt Strike](https://attack.mitre.org/software/S0154) into `wuauclt.exe` during intrusions.(Citation: Picus BlackByte 2022) [BlackByte](https://attack.mitre.org/groups/G1043) has injected ransomware into `svchost.exe` before encryption.(Citation: Symantec BlackByte 2022)
- [S0084] Mis-Type: [Mis-Type](https://attack.mitre.org/software/S0084) has been injected directly into a running process, including `explorer.exe`.(Citation: Cylance Dust Storm)
- [S0024] Dyre: [Dyre](https://attack.mitre.org/software/S0024) has the ability to directly inject its code into the web browser process.(Citation: Malwarebytes Dyreza November 2015)
- [S0044] JHUHUGIT: [JHUHUGIT](https://attack.mitre.org/software/S0044) performs code injection injecting its own functions to browser processes.(Citation: F-Secure Sofacy 2015)(Citation: Unit 42 Sofacy Feb 2018)
- [S0664] Pandora: [Pandora](https://attack.mitre.org/software/S0664) can start and inject code into a new `svchost` process.(Citation: Trend Micro Iron Tiger April 2021)
- [S0266] TrickBot: [TrickBot](https://attack.mitre.org/software/S0266) has used <code>Nt*</code> [Native API](https://attack.mitre.org/techniques/T1106) functions to inject code into legitimate processes such as <code>wermgr.exe</code>.(Citation: Joe Sec Trickbot)
- [S1050] PcShare: The [PcShare](https://attack.mitre.org/software/S1050) payload has been injected into the `logagent.exe` and `rdpclip.exe` processes.(Citation: Bitdefender FunnyDream Campaign November 2020)
- [G0096] APT41: [APT41](https://attack.mitre.org/groups/G0096) malware TIDYELF loaded the main WINTERLOVE component by injecting it into the iexplore.exe process.(Citation: FireEye APT41 Aug 2019)
- [S0176] Wingbird: [Wingbird](https://attack.mitre.org/software/S0176) performs multiple process injections to hijack system processes and execute malicious code.(Citation: Microsoft SIR Vol 21)
- [S0554] Egregor: [Egregor](https://attack.mitre.org/software/S0554) can inject its payload into iexplore.exe process.(Citation: Cyble Egregor Oct 2020)
- [S1059] metaMain: [metaMain](https://attack.mitre.org/software/S1059) can inject the loader file, Speech02.db, into a process.(Citation: SentinelLabs Metador Sept 2022)
- [C0028] 2015 Ukraine Electric Power Attack: During the [2015 Ukraine Electric Power Attack](https://attack.mitre.org/campaigns/C0028), [Sandworm Team](https://attack.mitre.org/groups/G0034) loaded [BlackEnergy](https://attack.mitre.org/software/S0089) into svchost.exe, which then launched iexplore.exe for their C2. (Citation: Booz Allen Hamilton)
- [G0010] Turla: [Turla](https://attack.mitre.org/groups/G0010) has also used [PowerSploit](https://attack.mitre.org/software/S0194)'s <code>Invoke-ReflectivePEInjection.ps1</code> to reflectively load a PowerShell payload into a random process on the victim system.(Citation: ESET Turla PowerShell May 2019)
- [C0046] ArcaneDoor: [ArcaneDoor](https://attack.mitre.org/campaigns/C0046) included injecting code into the AAA and Crash Dump processes on infected Cisco ASA devices.(Citation: Cisco ArcaneDoor 2024)
- [S1181] BlackByte 2.0 Ransomware: [BlackByte 2.0 Ransomware](https://attack.mitre.org/software/S1181) injects into a newly-created `svchost.exe` process prior to device encryption.(Citation: Microsoft BlackByte 2023)

#### T1055.001 - Dynamic-link Library Injection

Description:

Adversaries may inject dynamic-link libraries (DLLs) into processes in order to evade process-based defenses as well as possibly elevate privileges. DLL injection is a method of executing arbitrary code in the address space of a separate live process.  

DLL injection is commonly performed by writing the path to a DLL in the virtual address space of the target process before loading the DLL by invoking a new thread. The write can be performed with native Windows API calls such as <code>VirtualAllocEx</code> and <code>WriteProcessMemory</code>, then invoked with <code>CreateRemoteThread</code> (which calls the <code>LoadLibrary</code> API responsible for loading the DLL). (Citation: Elastic Process Injection July 2017) 

Variations of this method such as reflective DLL injection (writing a self-mapping DLL into a process) and memory module (map DLL when writing into process) overcome the address relocation issue as well as the additional APIs to invoke execution (since these methods load and execute the files in memory by manually preforming the function of <code>LoadLibrary</code>).(Citation: Elastic HuntingNMemory June 2017)(Citation: Elastic Process Injection July 2017) 

Another variation of this method, often referred to as Module Stomping/Overloading or DLL Hollowing, may be leveraged to conceal injected code within a process. This method involves loading a legitimate DLL into a remote process then manually overwriting the module's <code>AddressOfEntryPoint</code> before starting a new thread in the target process.(Citation: Module Stomping for Shellcode Injection) This variation allows attackers to hide malicious injected code by potentially backing its execution with a legitimate DLL file on disk.(Citation: Hiding Malicious Code with Module Stomping) 

Running code in the context of another process may allow access to the process's memory, system/network resources, and possibly elevated privileges. Execution via DLL injection may also evade detection from security products since the execution is masked under a legitimate process.

Procedures:

- [S1027] Heyoka Backdoor: [Heyoka Backdoor](https://attack.mitre.org/software/S1027) can inject a DLL into rundll32.exe for execution.(Citation: SentinelOne Aoqin Dragon June 2022)
- [S1018] Saint Bot: [Saint Bot](https://attack.mitre.org/software/S1018) has injected its DLL component into `EhStorAurhn.exe`.(Citation: Malwarebytes Saint Bot April 2021)
- [S0082] Emissary: [Emissary](https://attack.mitre.org/software/S0082) injects its DLL file into a newly spawned Internet Explorer process.(Citation: Lotus Blossom Dec 2015)
- [S0125] Remsec: [Remsec](https://attack.mitre.org/software/S0125) can perform DLL injection.(Citation: Kaspersky ProjectSauron Technical Analysis)
- [S1066] DarkTortilla: [DarkTortilla](https://attack.mitre.org/software/S1066) can use a .NET-based DLL named `RunPe6` for process injection.(Citation: Secureworks DarkTortilla Aug 2022)
- [S0089] BlackEnergy: [BlackEnergy](https://attack.mitre.org/software/S0089) injects its DLL component into svchost.exe.(Citation: F-Secure BlackEnergy 2014)
- [G0010] Turla: [Turla](https://attack.mitre.org/groups/G0010) has used Metasploit to perform reflective DLL injection in order to escalate privileges.(Citation: ESET Turla Mosquito May 2018)(Citation: Github Rapid7 Meterpreter Elevate)
- [S0613] PS1: [PS1](https://attack.mitre.org/software/S0613) can inject its payload DLL Into memory.(Citation: BlackBerry CostaRicto November 2020)
- [S0250] Koadic: [Koadic](https://attack.mitre.org/software/S0250) can perform process injection by using a reflective DLL.(Citation: Github Koadic)
- [S0055] RARSTONE: After decrypting itself in memory, [RARSTONE](https://attack.mitre.org/software/S0055) downloads a DLL file from its C2 server and loads it in the memory space of a hidden Internet Explorer process. This “downloaded” file is actually not dropped onto the system.(Citation: Camba RARSTONE)
- [S0154] Cobalt Strike: [Cobalt Strike](https://attack.mitre.org/software/S0154) has the ability to load DLLs via reflective injection.(Citation: Talos Cobalt Strike September 2020)(Citation: Cobalt Strike Manual 4.3 November 2020)
- [S0461] SDBbot: [SDBbot](https://attack.mitre.org/software/S0461) has the ability to inject a downloaded DLL into a newly created rundll32.exe process.(Citation: Proofpoint TA505 October 2019)
- [S0455] Metamorfo: [Metamorfo](https://attack.mitre.org/software/S0455) has injected a malicious DLL into the Windows Media Player process (wmplayer.exe).(Citation: Medium Metamorfo Apr 2020)
- [S0126] ComRAT: [ComRAT](https://attack.mitre.org/software/S0126) has injected its orchestrator DLL into explorer.exe. [ComRAT](https://attack.mitre.org/software/S0126) has also injected its communications module into the victim's default browser to make C2 connections appear less suspicious as all network connections will be initiated by the browser process.(Citation: ESET ComRAT May 2020)(Citation: CISA ComRAT Oct 2020)
- [S0273] Socksbot: [Socksbot](https://attack.mitre.org/software/S0273) creates a suspended svchost process and injects its DLL into it.(Citation: TrendMicro Patchwork Dec 2017)
- [S1039] Bumblebee: The [Bumblebee](https://attack.mitre.org/software/S1039) loader can support the `Dij` command which gives it the ability to inject DLLs into the memory of other processes.(Citation: Proofpoint Bumblebee April 2022)(Citation: Symantec Bumblebee June 2022)
- [S0681] Lizar: [Lizar](https://attack.mitre.org/software/S0681) has used the PowerKatz plugin that can be loaded into the address space of a PowerShell process through reflective DLL loading.(Citation: BiZone Lizar May 2021)
- [G1026] Malteiro: [Malteiro](https://attack.mitre.org/groups/G1026) has injected [Mispadu](https://attack.mitre.org/software/S1122)’s DLL into a process.(Citation: SCILabs Malteiro 2021)
- [S1044] FunnyDream: The [FunnyDream](https://attack.mitre.org/software/S1044) FilepakMonitor component can inject into the Bka.exe process using the `VirtualAllocEx`, `WriteProcessMemory` and `CreateRemoteThread` APIs to load the DLL component.(Citation: Bitdefender FunnyDream Campaign November 2020)
- [S0449] Maze: [Maze](https://attack.mitre.org/software/S0449) has injected the malware DLL into a target process.(Citation: McAfee Maze March 2020)(Citation: Sophos Maze VM September 2020)
- [S0167] Matryoshka: [Matryoshka](https://attack.mitre.org/software/S0167) uses reflective DLL injection to inject the malicious library and execute the RAT.(Citation: CopyKittens Nov 2015)
- [S0192] Pupy: [Pupy](https://attack.mitre.org/software/S0192) can migrate into another process using reflective DLL injection.(Citation: GitHub Pupy)
- [S0194] PowerSploit: [PowerSploit](https://attack.mitre.org/software/S0194) contains a collection of CodeExecution modules that inject code (DLL, shellcode) into a process.(Citation: GitHub PowerSploit May 2012)(Citation: PowerSploit Documentation)
- [S0182] FinFisher: [FinFisher](https://attack.mitre.org/software/S0182) injects itself into various processes depending on whether it is low integrity or high integrity.(Citation: FinFisher Citation)(Citation: Microsoft FinFisher March 2018)
- [S0501] PipeMon: [PipeMon](https://attack.mitre.org/software/S0501) can inject its modules into various processes using reflective DLL loading.(Citation: ESET PipeMon May 2020)
- [S0024] Dyre: [Dyre](https://attack.mitre.org/software/S0024) injects into other processes to load modules.(Citation: Symantec Dyre June 2015)
- [S1210] Sagerunex: [Sagerunex](https://attack.mitre.org/software/S1210) is designed to be dynamic link library (DLL) injected into an infected endpoint and executed directly in memory.(Citation: Cisco LotusBlossom 2025)
- [G0135] BackdoorDiplomacy: [BackdoorDiplomacy](https://attack.mitre.org/groups/G0135) has dropped legitimate software onto a compromised host and used it to execute malicious DLLs.(Citation: ESET BackdoorDiplomacy Jun 2021)
- [S0460] Get2: [Get2](https://attack.mitre.org/software/S0460) has the ability to inject DLLs into processes.(Citation: Proofpoint TA505 October 2019)
- [S0011] Taidoor: [Taidoor](https://attack.mitre.org/software/S0011) can perform DLL loading.(Citation: TrendMicro Taidoor)(Citation: CISA MAR-10292089-1.v2 TAIDOOR August 2021)
- [S0241] RATANKBA: [RATANKBA](https://attack.mitre.org/software/S0241) performs a reflective DLL injection using a given pid.(Citation: Lazarus RATANKBA)(Citation: RATANKBA)
- [S1081] BADHATCH: [BADHATCH](https://attack.mitre.org/software/S1081) has the ability to execute a malicious DLL by injecting into `explorer.exe` on a compromised machine.(Citation: Gigamon BADHATCH Jul 2019)
- [S0576] MegaCortex: [MegaCortex](https://attack.mitre.org/software/S0576) loads <code>injecthelper.dll</code> into a newly created <code>rundll32.exe</code> process.(Citation: IBM MegaCortex)
- [S0603] Stuxnet: [Stuxnet](https://attack.mitre.org/software/S0603) injects an entire DLL into an existing, newly created, or preselected trusted process.(Citation: Nicolas Falliere, Liam O Murchu, Eric Chien February 2011)
- [C0015] C0015: During [C0015](https://attack.mitre.org/campaigns/C0015), the threat actors used a DLL named `D8B3.dll` that was injected into the Winlogon process.(Citation: DFIR Conti Bazar Nov 2021)
- [G0065] Leviathan: [Leviathan](https://attack.mitre.org/groups/G0065) has utilized techniques like reflective DLL loading to write a DLL into memory and load a shell that provides backdoor access to the victim.(Citation: Accenture MUDCARP March 2019)
- [S0265] Kazuar: If running in a Windows environment, [Kazuar](https://attack.mitre.org/software/S0265) saves a DLL to disk that is injected into the explorer.exe process to execute the payload. [Kazuar](https://attack.mitre.org/software/S0265) can also be configured to inject and execute within specific processes.(Citation: Unit 42 Kazuar May 2017)
- [S0038] Duqu: [Duqu](https://attack.mitre.org/software/S0038) will inject itself into different processes to evade detection. The selection of the target process is influenced by the security software that is installed on the system (Duqu will inject into different processes depending on which security suite is installed on the infected host).(Citation: Symantec W32.Duqu)
- [S0012] PoisonIvy: [PoisonIvy](https://attack.mitre.org/software/S0012) can inject a malicious DLL into a process.(Citation: FireEye Poison Ivy)(Citation: Symantec Darkmoon Aug 2005)
- [S0021] Derusbi: [Derusbi](https://attack.mitre.org/software/S0021) injects itself into the secure shell (SSH) process.(Citation: Airbus Derusbi 2015)
- [S0412] ZxShell: [ZxShell](https://attack.mitre.org/software/S0412) is injected into a shared SVCHOST process.(Citation: Talos ZxShell Oct 2014)
- [G0024] Putter Panda: An executable dropped onto victims by [Putter Panda](https://attack.mitre.org/groups/G0024) aims to inject the specified DLL into a process that would normally be accessing the network, including Outlook Express (msinm.exe), Outlook (outlook.exe), Internet Explorer (iexplore.exe), and Firefox (firefox.exe).(Citation: CrowdStrike Putter Panda)
- [S0666] Gelsemium: [Gelsemium](https://attack.mitre.org/software/S0666) has the ability to inject DLLs into specific processes.(Citation: ESET Gelsemium June 2021)
- [S0135] HIDEDRV: [HIDEDRV](https://attack.mitre.org/software/S0135) injects a DLL for [Downdelph](https://attack.mitre.org/software/S0134) into the explorer.exe process.(Citation: ESET Sednit Part 3)
- [S0335] Carbon: [Carbon](https://attack.mitre.org/software/S0335) has a command to inject code into a process.(Citation: ESET Carbon Mar 2017)
- [G0032] Lazarus Group: A [Lazarus Group](https://attack.mitre.org/groups/G0032) malware sample performs reflective DLL injection.(Citation: McAfee Lazarus Resurfaces Feb 2018)(Citation: Lazarus APT January 2022)
- [G0081] Tropic Trooper: [Tropic Trooper](https://attack.mitre.org/groups/G0081) has injected a DLL backdoor into dllhost.exe and svchost.exe.(Citation: TrendMicro Tropic Trooper Mar 2018)(Citation: TrendMicro Tropic Trooper May 2020)
- [S0581] IronNetInjector: [IronNetInjector](https://attack.mitre.org/software/S0581) has the ability to inject a DLL into running processes, including the [IronNetInjector](https://attack.mitre.org/software/S0581) DLL into explorer.exe.(Citation: Unit 42 IronNetInjector February 2021 )
- [S0467] TajMahal: [TajMahal](https://attack.mitre.org/software/S0467) has the ability to inject DLLs for malicious plugins into running processes.(Citation: Kaspersky TajMahal April 2019)
- [S1026] Mongall: [Mongall](https://attack.mitre.org/software/S1026) can inject a DLL into `rundll32.exe` for execution.(Citation: SentinelOne Aoqin Dragon June 2022)
- [S0575] Conti: [Conti](https://attack.mitre.org/software/S0575) has loaded an encrypted DLL into memory and then executes it.(Citation: Cybereason Conti Jan 2021)(Citation: CarbonBlack Conti July 2020)
- [S0458] Ramsay: [Ramsay](https://attack.mitre.org/software/S0458) can use <code>ImprovedReflectiveDLLInjection</code> to deploy components.(Citation: Eset Ramsay May 2020)
- [S0022] Uroburos: [Uroburos](https://attack.mitre.org/software/S0022) can use DLL injection to load embedded files and modules.(Citation: Joint Cybersecurity Advisory AA23-129A Snake Malware May 2023)
- [S0484] Carberp: [Carberp](https://attack.mitre.org/software/S0484)'s bootkit can inject a malicious DLL into the address space of running processes.(Citation: ESET Carberp March 2012)
- [S0615] SombRAT: [SombRAT](https://attack.mitre.org/software/S0615) can execute <code>loadfromfile</code>, <code>loadfromstorage</code>, and <code>loadfrommem</code> to inject a DLL  from disk, storage, or memory respectively.(Citation: BlackBerry CostaRicto November 2020)
- [S0018] Sykipot: [Sykipot](https://attack.mitre.org/software/S0018) injects itself into running instances of outlook.exe, iexplore.exe, or firefox.exe.(Citation: AlienVault Sykipot 2011)
- [S0367] Emotet: [Emotet](https://attack.mitre.org/software/S0367) has been observed injecting in to Explorer.exe and other processes. (Citation: Picus Emotet Dec 2018)(Citation: Trend Micro Banking Malware Jan 2019)(Citation: US-CERT Emotet Jul 2018)
- [S0456] Aria-body: [Aria-body](https://attack.mitre.org/software/S0456) has the ability to inject itself into another process such as rundll32.exe and dllhost.exe.(Citation: CheckPoint Naikon May 2020)
- [S0457] Netwalker: The [Netwalker](https://attack.mitre.org/software/S0457) DLL has been injected reflectively into the memory of a legitimate running process.(Citation: TrendMicro Netwalker May 2020)
- [G0092] TA505: [TA505](https://attack.mitre.org/groups/G0092) has been seen injecting a DLL into winword.exe.(Citation: IBM TA505 April 2020)
- [S0081] Elise: [Elise](https://attack.mitre.org/software/S0081) injects DLL files into iexplore.exe.(Citation: Lotus Blossom Jun 2015)(Citation: Accenture Dragonfish Jan 2018)
- [G0102] Wizard Spider: [Wizard Spider](https://attack.mitre.org/groups/G0102) has injected malicious DLLs into memory with read, write, and execute permissions.(Citation: DHS/CISA Ransomware Targeting Healthcare October 2020)(Citation: DFIR Ryuk 2 Hour Speed Run November 2020)
- [S0596] ShadowPad: [ShadowPad](https://attack.mitre.org/software/S0596) has injected a DLL into svchost.exe.(Citation: Kaspersky ShadowPad Aug 2017)

#### T1055.002 - Portable Executable Injection

Description:

Adversaries may inject portable executables (PE) into processes in order to evade process-based defenses as well as possibly elevate privileges. PE injection is a method of executing arbitrary code in the address space of a separate live process. 

PE injection is commonly performed by copying code (perhaps without a file on disk) into the virtual address space of the target process before invoking it via a new thread. The write can be performed with native Windows API calls such as <code>VirtualAllocEx</code> and <code>WriteProcessMemory</code>, then invoked with <code>CreateRemoteThread</code> or additional code (ex: shellcode). The displacement of the injected code does introduce the additional requirement for functionality to remap memory references. (Citation: Elastic Process Injection July 2017) 

Running code in the context of another process may allow access to the process's memory, system/network resources, and possibly elevated privileges. Execution via PE injection may also evade detection from security products since the execution is masked under a legitimate process.

Procedures:

- [S1063] Brute Ratel C4: [Brute Ratel C4](https://attack.mitre.org/software/S1063) has injected [Latrodectus](https://attack.mitre.org/software/S1160) into the Explorer.exe process on comrpomised hosts.(Citation: Rapid7 Fake W2 July 2024)
- [S0260] InvisiMole: [InvisiMole](https://attack.mitre.org/software/S0260) can inject its backdoor as a portable executable into a target process.(Citation: ESET InvisiMole June 2020)
- [S0030] Carbanak: [Carbanak](https://attack.mitre.org/software/S0030) downloads an executable and injects it directly into a new process.(Citation: FireEye CARBANAK June 2017)
- [G0106] Rocke: [Rocke](https://attack.mitre.org/groups/G0106)'s miner, "TermsHost.exe", evaded defenses by injecting itself into Windows processes, including Notepad.exe.(Citation: Talos Rocke August 2018)
- [G0078] Gorgon Group: [Gorgon Group](https://attack.mitre.org/groups/G0078) malware can download a remote access tool, [ShiftyBug](https://attack.mitre.org/software/S0294), and inject into another process.(Citation: Unit 42 Gorgon Group Aug 2018)
- [S0681] Lizar: [Lizar](https://attack.mitre.org/software/S0681) can execute PE files in the address space of the specified process.(Citation: BiZone Lizar May 2021)
- [S1138] Gootloader: [Gootloader](https://attack.mitre.org/software/S1138) can use its own PE loader to execute payloads in memory.(Citation: Sophos Gootloader)
- [S0342] GreyEnergy: [GreyEnergy](https://attack.mitre.org/software/S0342) has a module to inject a PE binary into a remote process.(Citation: ESET GreyEnergy Oct 2018)
- [S1158] DUSTPAN: [DUSTPAN](https://attack.mitre.org/software/S1158) can inject its decrypted payload into another process.(Citation: Google Cloud APT41 2024)
- [S1145] Pikabot: [Pikabot](https://attack.mitre.org/software/S1145), following payload decryption, creates a process hard-coded into the dropped (e.g., WerFault.exe) and injects the decrypted core modules into it.(Citation: Zscaler Pikabot 2023)
- [S0330] Zeus Panda: [Zeus Panda](https://attack.mitre.org/software/S0330) checks processes on the system and if they meet the necessary requirements, it injects into that process.(Citation: GDATA Zeus Panda June 2017)

#### T1055.003 - Thread Execution Hijacking

Description:

Adversaries may inject malicious code into hijacked processes in order to evade process-based defenses as well as possibly elevate privileges. Thread Execution Hijacking is a method of executing arbitrary code in the address space of a separate live process. 

Thread Execution Hijacking is commonly performed by suspending an existing process then unmapping/hollowing its memory, which can then be replaced with malicious code or the path to a DLL. A handle to an existing victim process is first created with native Windows API calls such as <code>OpenThread</code>. At this point the process can be suspended then written to, realigned to the injected code, and resumed via <code>SuspendThread </code>, <code>VirtualAllocEx</code>, <code>WriteProcessMemory</code>, <code>SetThreadContext</code>, then <code>ResumeThread</code> respectively.(Citation: Elastic Process Injection July 2017)

This is very similar to [Process Hollowing](https://attack.mitre.org/techniques/T1055/012) but targets an existing process rather than creating a process in a suspended state.  

Running code in the context of another process may allow access to the process's memory, system/network resources, and possibly elevated privileges. Execution via Thread Execution Hijacking may also evade detection from security products since the execution is masked under a legitimate process.

Procedures:

- [S1145] Pikabot: [Pikabot](https://attack.mitre.org/software/S1145) can create a suspended instance of a legitimate process (e.g., ctfmon.exe), allocate memory within the suspended process corresponding to [Pikabot](https://attack.mitre.org/software/S1145)'s core module, then redirect execution flow via `SetContextThread` API so that when the thread resumes the [Pikabot](https://attack.mitre.org/software/S1145) core module is executed.(Citation: Elastic Pikabot 2024)
- [S0579] Waterbear: [Waterbear](https://attack.mitre.org/software/S0579) can use thread injection to inject shellcode into the process of security software.(Citation: Trend Micro Waterbear December 2019)
- [S0168] Gazer: [Gazer](https://attack.mitre.org/software/S0168) performs thread execution hijacking to inject its orchestrator into a running thread from a remote process.(Citation: ESET Gazer Aug 2017)(Citation: Securelist WhiteBear Aug 2017)
- [S0094] Trojan.Karagany: [Trojan.Karagany](https://attack.mitre.org/software/S0094) can inject a suspended thread of its own process into a new process and initiate via the <code>ResumeThread</code> API.(Citation: Secureworks Karagany July 2019)

#### T1055.004 - Asynchronous Procedure Call

Description:

Adversaries may inject malicious code into processes via the asynchronous procedure call (APC) queue in order to evade process-based defenses as well as possibly elevate privileges. APC injection is a method of executing arbitrary code in the address space of a separate live process. 

APC injection is commonly performed by attaching malicious code to the APC Queue (Citation: Microsoft APC) of a process's thread. Queued APC functions are executed when the thread enters an alterable state.(Citation: Microsoft APC) A handle to an existing victim process is first created with native Windows API calls such as <code>OpenThread</code>. At this point <code>QueueUserAPC</code> can be used to invoke a function (such as <code>LoadLibrayA</code> pointing to a malicious DLL). 

A variation of APC injection, dubbed "Early Bird injection", involves creating a suspended process in which malicious code can be written and executed before the process' entry point (and potentially subsequent anti-malware hooks) via an APC. (Citation: CyberBit Early Bird Apr 2018) AtomBombing (Citation: ENSIL AtomBombing Oct 2016) is another variation that utilizes APCs to invoke malicious code previously written to the global atom table.(Citation: Microsoft Atom Table)

Running code in the context of another process may allow access to the process's memory, system/network resources, and possibly elevated privileges. Execution via APC injection may also evade detection from security products since the execution is masked under a legitimate process.

Procedures:

- [S0199] TURNEDUP: [TURNEDUP](https://attack.mitre.org/software/S0199) is capable of injecting code into the APC queue of a created [Rundll32](https://attack.mitre.org/techniques/T1218/011) process as part of an "Early Bird injection."(Citation: CyberBit Early Bird Apr 2018)
- [S0517] Pillowmint: [Pillowmint](https://attack.mitre.org/software/S0517) has used the NtQueueApcThread syscall to inject code into svchost.exe.(Citation: Trustwave Pillowmint June 2020)
- [S0260] InvisiMole: [InvisiMole](https://attack.mitre.org/software/S0260) can inject its code into a trusted process via the APC queue.(Citation: ESET InvisiMole June 2020)
- [S1039] Bumblebee: [Bumblebee](https://attack.mitre.org/software/S1039) can use asynchronous procedure call (APC) injection to execute commands received from C2.(Citation: Proofpoint Bumblebee April 2022)
- [S1018] Saint Bot: [Saint Bot](https://attack.mitre.org/software/S1018) has written its payload into a newly-created `EhStorAuthn.exe` process using `ZwWriteVirtualMemory` and executed it using `NtQueueApcThread` and `ZwAlertResumeThread`.(Citation: Malwarebytes Saint Bot April 2021)
- [S0484] Carberp: [Carberp](https://attack.mitre.org/software/S0484) has queued an APC routine to explorer.exe by calling ZwQueueApcThread.(Citation: Prevx Carberp March 2011)
- [S0483] IcedID: [IcedID](https://attack.mitre.org/software/S0483) has used <code>ZwQueueApcThread</code> to inject itself into remote processes.(Citation: IBM IcedID November 2017)
- [S1207] XLoader: [XLoader](https://attack.mitre.org/software/S1207) injects code into the APC queue using `NtQueueApcThread` API.(Citation: Zscaler XLoader 2025)
- [S1081] BADHATCH: [BADHATCH](https://attack.mitre.org/software/S1081) can inject itself into a new `svchost.exe -k netsvcs` process using the asynchronous procedure call (APC) queue.(Citation: Gigamon BADHATCH Jul 2019)(Citation: BitDefender BADHATCH Mar 2021)
- [G0061] FIN8: [FIN8](https://attack.mitre.org/groups/G0061) has injected malicious code into a new svchost.exe process.(Citation: Bitdefender FIN8 July 2021)
- [S0438] Attor: [Attor](https://attack.mitre.org/software/S0438) performs the injection by attaching its code into the APC queue using NtQueueApcThread API.(Citation: ESET Attor Oct 2019)
- [S1085] Sardonic: [Sardonic](https://attack.mitre.org/software/S1085) can use the `QueueUserAPC` API to execute shellcode on a compromised machine.(Citation: Symantec FIN8 Jul 2023)

#### T1055.005 - Thread Local Storage

Description:

Adversaries may inject malicious code into processes via thread local storage (TLS) callbacks in order to evade process-based defenses as well as possibly elevate privileges. TLS callback injection is a method of executing arbitrary code in the address space of a separate live process. 

TLS callback injection involves manipulating pointers inside a portable executable (PE) to redirect a process to malicious code before reaching the code's legitimate entry point. TLS callbacks are normally used by the OS to setup and/or cleanup data used by threads. Manipulating TLS callbacks may be performed by allocating and writing to specific offsets within a process’ memory space using other [Process Injection](https://attack.mitre.org/techniques/T1055) techniques such as [Process Hollowing](https://attack.mitre.org/techniques/T1055/012).(Citation: FireEye TLS Nov 2017)

Running code in the context of another process may allow access to the process's memory, system/network resources, and possibly elevated privileges. Execution via TLS callback injection may also evade detection from security products since the execution is masked under a legitimate process.

Procedures:

- [S0386] Ursnif: [Ursnif](https://attack.mitre.org/software/S0386) has injected code into target processes via thread local storage callbacks.(Citation: TrendMicro Ursnif Mar 2015)(Citation: TrendMicro PE_URSNIF.A2)(Citation: FireEye Ursnif Nov 2017)

#### T1055.008 - Ptrace System Calls

Description:

Adversaries may inject malicious code into processes via ptrace (process trace) system calls in order to evade process-based defenses as well as possibly elevate privileges. Ptrace system call injection is a method of executing arbitrary code in the address space of a separate live process. 

Ptrace system call injection involves attaching to and modifying a running process. The ptrace system call enables a debugging process to observe and control another process (and each individual thread), including changing memory and register values.(Citation: PTRACE man) Ptrace system call injection is commonly performed by writing arbitrary code into a running process (ex: <code>malloc</code>) then invoking that memory with <code>PTRACE_SETREGS</code> to set the register containing the next instruction to execute. Ptrace system call injection can also be done with <code>PTRACE_POKETEXT</code>/<code>PTRACE_POKEDATA</code>, which copy data to a specific address in the target processes’ memory (ex: the current address of the next instruction). (Citation: PTRACE man)(Citation: Medium Ptrace JUL 2018) 

Ptrace system call injection may not be possible targeting processes that are non-child processes and/or have higher-privileges.(Citation: BH Linux Inject) 

Running code in the context of another process may allow access to the process's memory, system/network resources, and possibly elevated privileges. Execution via ptrace system call injection may also evade detection from security products since the execution is masked under a legitimate process.

Procedures:

- [S1109] PACEMAKER: [PACEMAKER](https://attack.mitre.org/software/S1109) can use PTRACE to attach to a targeted process to read process memory.(Citation: Mandiant Pulse Secure Zero-Day April 2021)

#### T1055.009 - Proc Memory

Description:

Adversaries may inject malicious code into processes via the /proc filesystem in order to evade process-based defenses as well as possibly elevate privileges. Proc memory injection is a method of executing arbitrary code in the address space of a separate live process. 

Proc memory injection involves enumerating the memory of a process via the /proc filesystem (<code>/proc/[pid]</code>) then crafting a return-oriented programming (ROP) payload with available gadgets/instructions. Each running process has its own directory, which includes memory mappings. Proc memory injection is commonly performed by overwriting the target processes’ stack using memory mappings provided by the /proc filesystem. This information can be used to enumerate offsets (including the stack) and gadgets (or instructions within the program that can be used to build a malicious payload) otherwise hidden by process memory protections such as address space layout randomization (ASLR). Once enumerated, the target processes’ memory map within <code>/proc/[pid]/maps</code> can be overwritten using dd.(Citation: Uninformed Needle)(Citation: GDS Linux Injection)(Citation: DD Man) 

Other techniques such as [Dynamic Linker Hijacking](https://attack.mitre.org/techniques/T1574/006) may be used to populate a target process with more available gadgets. Similar to [Process Hollowing](https://attack.mitre.org/techniques/T1055/012), proc memory injection may target child processes (such as a backgrounded copy of sleep).(Citation: GDS Linux Injection) 

Running code in the context of another process may allow access to the process's memory, system/network resources, and possibly elevated privileges. Execution via proc memory injection may also evade detection from security products since the execution is masked under a legitimate process.

Procedures:

- [C0035] KV Botnet Activity: [KV Botnet Activity](https://attack.mitre.org/campaigns/C0035) final payload installation includes mounting and binding to the <code>\/proc\/</code> filepath on the victim system to enable subsequent operation in memory while also removing on-disk artifacts.(Citation: Lumen KVBotnet 2023)

#### T1055.011 - Extra Window Memory Injection

Description:

Adversaries may inject malicious code into process via Extra Window Memory (EWM) in order to evade process-based defenses as well as possibly elevate privileges. EWM injection is a method of executing arbitrary code in the address space of a separate live process. 

Before creating a window, graphical Windows-based processes must prescribe to or register a windows class, which stipulate appearance and behavior (via windows procedures, which are functions that handle input/output of data).(Citation: Microsoft Window Classes) Registration of new windows classes can include a request for up to 40 bytes of EWM to be appended to the allocated memory of each instance of that class. This EWM is intended to store data specific to that window and has specific application programming interface (API) functions to set and get its value. (Citation: Microsoft GetWindowLong function) (Citation: Microsoft SetWindowLong function)

Although small, the EWM is large enough to store a 32-bit pointer and is often used to point to a windows procedure. Malware may possibly utilize this memory location in part of an attack chain that includes writing code to shared sections of the process’s memory, placing a pointer to the code in EWM, then invoking execution by returning execution control to the address in the process’s EWM.

Execution granted through EWM injection may allow access to both the target process's memory and possibly elevated privileges. Writing payloads to shared sections also avoids the use of highly monitored API calls such as <code>WriteProcessMemory</code> and <code>CreateRemoteThread</code>.(Citation: Elastic Process Injection July 2017) More sophisticated malware samples may also potentially bypass protection mechanisms such as data execution prevention (DEP) by triggering a combination of windows procedures and other system functions that will rewrite the malicious payload inside an executable portion of the target process.  (Citation: MalwareTech Power Loader Aug 2013) (Citation: WeLiveSecurity Gapz and Redyms Mar 2013)

Running code in the context of another process may allow access to the process's memory, system/network resources, and possibly elevated privileges. Execution via EWM injection may also evade detection from security products since the execution is masked under a legitimate process.

Procedures:

- [S0091] Epic: [Epic](https://attack.mitre.org/software/S0091) has overwritten the function pointer in the extra window memory of Explorer's Shell_TrayWnd in order to execute malicious code in the context of the explorer.exe process.(Citation: ESET Recon Snake Nest)
- [S0177] Power Loader: [Power Loader](https://attack.mitre.org/software/S0177) overwrites Explorer’s Shell_TrayWnd extra window memory to redirect execution to a NTDLL function that is abused to assemble and execute a return-oriented programming (ROP) chain and create a malicious thread within Explorer.exe.(Citation: MalwareTech Power Loader Aug 2013)(Citation: WeLiveSecurity Gapz and Redyms Mar 2013)

#### T1055.012 - Process Hollowing

Description:

Adversaries may inject malicious code into suspended and hollowed processes in order to evade process-based defenses. Process hollowing is a method of executing arbitrary code in the address space of a separate live process.  

Process hollowing is commonly performed by creating a process in a suspended state then unmapping/hollowing its memory, which can then be replaced with malicious code. A victim process can be created with native Windows API calls such as <code>CreateProcess</code>, which includes a flag to suspend the processes primary thread. At this point the process can be unmapped using APIs calls such as <code>ZwUnmapViewOfSection</code> or <code>NtUnmapViewOfSection</code>  before being written to, realigned to the injected code, and resumed via <code>VirtualAllocEx</code>, <code>WriteProcessMemory</code>, <code>SetThreadContext</code>, then <code>ResumeThread</code> respectively.(Citation: Leitch Hollowing)(Citation: Elastic Process Injection July 2017)

This is very similar to [Thread Local Storage](https://attack.mitre.org/techniques/T1055/005) but creates a new process rather than targeting an existing process. This behavior will likely not result in elevated privileges since the injected process was spawned from (and thus inherits the security context) of the injecting process. However, execution via process hollowing may also evade detection from security products since the execution is masked under a legitimate process.

Procedures:

- [G0078] Gorgon Group: [Gorgon Group](https://attack.mitre.org/groups/G0078) malware can use process hollowing to inject one of its trojans into another process.(Citation: Unit 42 Gorgon Group Aug 2018)
- [S0483] IcedID: [IcedID](https://attack.mitre.org/software/S0483) can inject a [Cobalt Strike](https://attack.mitre.org/software/S0154) beacon into cmd.exe via process hallowing.(Citation: DFIR_Quantum_Ransomware)
- [S1207] XLoader: [XLoader](https://attack.mitre.org/software/S1207) uses process hollowing by injecting itself into the `explorer.exe` process and other files ithin the Windows `SysWOW64` directory.(Citation: Zscaler XLoader 2025)(Citation: Google XLoader 2017)(Citation: ANY.RUN XLoader 2023)
- [G0027] Threat Group-3390: A [Threat Group-3390](https://attack.mitre.org/groups/G0027) tool can spawn `svchost.exe` and inject the payload into that process.(Citation: Nccgroup Emissary Panda May 2018)(Citation: Securelist LuckyMouse June 2018)
- [S0662] RCSession: [RCSession](https://attack.mitre.org/software/S0662) can launch itself from a hollowed svchost.exe process.(Citation: Secureworks BRONZE PRESIDENT December 2019)(Citation: Trend Micro DRBControl February 2020)(Citation: Profero APT27 December 2020)
- [S0354] Denis: [Denis](https://attack.mitre.org/software/S0354) performed process hollowing through the API calls CreateRemoteThread, ResumeThread, and Wow64SetThreadContext.(Citation: Cybereason Cobalt Kitty 2017)
- [S1065] Woody RAT: [Woody RAT](https://attack.mitre.org/software/S1065) can create a suspended notepad process and write shellcode to delete a file into the suspended process using `NtWriteVirtualMemory`.(Citation: MalwareBytes WoodyRAT Aug 2022)
- [S0344] Azorult: [Azorult](https://attack.mitre.org/software/S0344) can decrypt the payload into memory, create a new suspended process of itself, then inject a decrypted payload to the new process and resume new process execution.(Citation: Unit42 Azorult Nov 2018)
- [G0040] Patchwork: A [Patchwork](https://attack.mitre.org/groups/G0040) payload uses process hollowing to hide the UAC bypass vulnerability exploitation inside svchost.exe.(Citation: Cymmetria Patchwork)
- [S0650] QakBot: [QakBot](https://attack.mitre.org/software/S0650) can use process hollowing to execute its main payload.(Citation: ATT QakBot April 2021)
- [S0154] Cobalt Strike: [Cobalt Strike](https://attack.mitre.org/software/S0154) can use process hollowing for execution.(Citation: Cobalt Strike TTPs Dec 2017)(Citation: Cobalt Strike Manual 4.3 November 2020)
- [S0447] Lokibot: [Lokibot](https://attack.mitre.org/software/S0447) has used process hollowing to inject itself into legitimate Windows process.(Citation: Infoblox Lokibot January 2019)(Citation: Talos Lokibot Jan 2021)
- [S1086] Snip3: [Snip3](https://attack.mitre.org/software/S1086) can use RunPE to execute malicious payloads within a hollowed Windows process.(Citation: Morphisec Snip3 May 2021)(Citation: Telefonica Snip3 December 2021)
- [S0234] Bandook: [Bandook](https://attack.mitre.org/software/S0234) has been launched by starting iexplore.exe and replacing it with [Bandook](https://attack.mitre.org/software/S0234)'s payload.(Citation: Lookout Dark Caracal Jan 2018)(Citation: EFF Manul Aug 2016)(Citation: CheckPoint Bandook Nov 2020)
- [S1213] Lumma Stealer: [Lumma Stealer](https://attack.mitre.org/software/S1213) has used process hollowing leveraging a legitimate program such as “BitLockerToGo.exe” to inject a malicious payload.(Citation: Qualys LummaStealer 2024)
- [G1043] BlackByte: [BlackByte](https://attack.mitre.org/groups/G1043) used process hollowing for defense evasion purposes.(Citation: Microsoft BlackByte 2023)
- [S1130] Raspberry Robin: [Raspberry Robin](https://attack.mitre.org/software/S1130) will execute a legitimate process, then suspend it to inject code for a [Tor](https://attack.mitre.org/software/S0183) client into the process, followed by resumption of the process to enable [Tor](https://attack.mitre.org/software/S0183) client execution.(Citation: TrendMicro RaspberryRobin 2022)
- [S0226] Smoke Loader: [Smoke Loader](https://attack.mitre.org/software/S0226) spawns a new copy of c:\windows\syswow64\explorer.exe and then replaces the executable code in memory with malware.(Citation: Malwarebytes SmokeLoader 2016)(Citation: Microsoft Dofoil 2018)
- [S0373] Astaroth: [Astaroth](https://attack.mitre.org/software/S0373) can create a new process in a suspended state from a targeted legitimate process in order to unmap its memory and replace it with malicious code.(Citation: Cybereason Astaroth Feb 2019)(Citation: Securelist Brazilian Banking Malware July 2020)
- [S0567] Dtrack: [Dtrack](https://attack.mitre.org/software/S0567) has used process hollowing shellcode to target a predefined list of processes from <code>%SYSTEM32%</code>.(Citation: Securelist Dtrack)
- [G1018] TA2541: [TA2541](https://attack.mitre.org/groups/G1018) has used process hollowing to execute CyberGate malware.(Citation: Cisco Operation Layover September 2021)
- [S0689] WhisperGate: [WhisperGate](https://attack.mitre.org/software/S0689) has the ability to inject its fourth stage into a suspended process created by the legitimate Windows utility `InstallUtil.exe`.(Citation: Cisco Ukraine Wipers January 2022)(Citation: RecordedFuture WhisperGate Jan 2022)
- [S0128] BADNEWS: [BADNEWS](https://attack.mitre.org/software/S0128) has a command to download an .exe and use process hollowing to inject it into a new process.(Citation: Forcepoint Monsoon)(Citation: TrendMicro Patchwork Dec 2017)
- [S0660] Clambling: [Clambling](https://attack.mitre.org/software/S0660) can execute binaries through process hollowing.(Citation: Trend Micro DRBControl February 2020)
- [S1138] Gootloader: [Gootloader](https://attack.mitre.org/software/S1138) can inject its Delphi executable into ImagingDevices.exe using a process hollowing technique.(Citation: Sophos Gootloader)(Citation: SentinelOne Gootloader June 2021)
- [G0045] menuPass: [menuPass](https://attack.mitre.org/groups/G0045) has used process hollowing in iexplore.exe to load the [RedLeaves](https://attack.mitre.org/software/S0153) implant.(Citation: Accenture Hogfish April 2018)
- [S0189] ISMInjector: [ISMInjector](https://attack.mitre.org/software/S0189) hollows out a newly created process RegASM.exe and injects its payload into the hollowed process.(Citation: OilRig New Delivery Oct 2017)
- [S1018] Saint Bot: The [Saint Bot](https://attack.mitre.org/software/S1018) loader has used API calls to spawn `MSBuild.exe` in a suspended state before injecting the decrypted [Saint Bot](https://attack.mitre.org/software/S1018) binary into it.(Citation: Palo Alto Unit 42 OutSteel SaintBot February 2022 )
- [S0198] NETWIRE: The [NETWIRE](https://attack.mitre.org/software/S0198) payload has been injected into benign Microsoft executables via process hollowing.(Citation: FireEye NETWIRE March 2019)(Citation: Red Canary NETWIRE January 2020)
- [S0367] Emotet: [Emotet](https://attack.mitre.org/software/S0367) uses a copy of `certutil.exe` stored in a temporary directory for process hollowing, starting the program in a suspended state before loading malicious code.(Citation: emotet_trendmicro_mar2023)
- [S0331] Agent Tesla: [Agent Tesla](https://attack.mitre.org/software/S0331) has used process hollowing to create and manipulate processes through sections of unmapped memory by reallocating that space with its malicious code.(Citation: SentinelLabs Agent Tesla Aug 2020)
- [S0229] Orz: Some [Orz](https://attack.mitre.org/software/S0229) versions have an embedded DLL known as MockDll that uses process hollowing and [Regsvr32](https://attack.mitre.org/techniques/T1218/010) to execute another payload.(Citation: Proofpoint Leviathan Oct 2017)
- [S0266] TrickBot: [TrickBot](https://attack.mitre.org/software/S0266) injects into the svchost.exe process.(Citation: S2 Grupo TrickBot June 2017)(Citation: Trend Micro Totbrick Oct 2016)(Citation: Microsoft Totbrick Oct 2017)(Citation: Cyberreason Anchor December 2019)
- [S0386] Ursnif: [Ursnif](https://attack.mitre.org/software/S0386) has used process hollowing to inject into child processes.(Citation: FireEye Ursnif Nov 2017)
- [G0094] Kimsuky: [Kimsuky](https://attack.mitre.org/groups/G0094) has used a file injector DLL to spawn a benign process on the victim's system and inject the malicious payload into it via process hollowing.(Citation: Talos Kimsuky Nov 2021)
- [S0534] Bazar: [Bazar](https://attack.mitre.org/software/S0534) can inject into a target process including Svchost, Explorer, and cmd using process hollowing.(Citation: Cybereason Bazar July 2020)(Citation: NCC Group Team9 June 2020)
- [S0127] BBSRAT: [BBSRAT](https://attack.mitre.org/software/S0127) has been seen loaded into msiexec.exe through process hollowing to hide its execution.(Citation: Palo Alto Networks BBSRAT)
- [S0038] Duqu: [Duqu](https://attack.mitre.org/software/S0038) is capable of loading executable code via process hollowing.(Citation: Symantec W32.Duqu)
- [S1111] DarkGate: [DarkGate](https://attack.mitre.org/software/S1111) leverages process hollowing techniques to evade detection, such as decrypting the content of an encrypted PE file and injecting it into the process vbc.exe.(Citation: Ensilo Darkgate 2018)(Citation: Rapid7 BlackBasta 2024)

#### T1055.013 - Process Doppelgänging

Description:

Adversaries may inject malicious code into process via process doppelgänging in order to evade process-based defenses as well as possibly elevate privileges. Process doppelgänging is a method of executing arbitrary code in the address space of a separate live process. 

Windows Transactional NTFS (TxF) was introduced in Vista as a method to perform safe file operations. (Citation: Microsoft TxF) To ensure data integrity, TxF enables only one transacted handle to write to a file at a given time. Until the write handle transaction is terminated, all other handles are isolated from the writer and may only read the committed version of the file that existed at the time the handle was opened. (Citation: Microsoft Basic TxF Concepts) To avoid corruption, TxF performs an automatic rollback if the system or application fails during a write transaction. (Citation: Microsoft Where to use TxF)

Although deprecated, the TxF application programming interface (API) is still enabled as of Windows 10. (Citation: BlackHat Process Doppelgänging Dec 2017)

Adversaries may abuse TxF to a perform a file-less variation of [Process Injection](https://attack.mitre.org/techniques/T1055). Similar to [Process Hollowing](https://attack.mitre.org/techniques/T1055/012), process doppelgänging involves replacing the memory of a legitimate process, enabling the veiled execution of malicious code that may evade defenses and detection. Process doppelgänging's use of TxF also avoids the use of highly-monitored API functions such as <code>NtUnmapViewOfSection</code>, <code>VirtualProtectEx</code>, and <code>SetThreadContext</code>. (Citation: BlackHat Process Doppelgänging Dec 2017)

Process Doppelgänging is implemented in 4 steps (Citation: BlackHat Process Doppelgänging Dec 2017):

* Transact – Create a TxF transaction using a legitimate executable then overwrite the file with malicious code. These changes will be isolated and only visible within the context of the transaction.
* Load – Create a shared section of memory and load the malicious executable.
* Rollback – Undo changes to original executable, effectively removing malicious code from the file system.
* Animate – Create a process from the tainted section of memory and initiate execution.

This behavior will likely not result in elevated privileges since the injected process was spawned from (and thus inherits the security context) of the injecting process. However, execution via process doppelgänging may evade detection from security products since the execution is masked under a legitimate process.

Procedures:

- [S0242] SynAck: [SynAck](https://attack.mitre.org/software/S0242) abuses NTFS transactions to launch and conceal malicious processes.(Citation: SecureList SynAck Doppelgänging May 2018)(Citation: Kaspersky Lab SynAck May 2018)
- [S0534] Bazar: [Bazar](https://attack.mitre.org/software/S0534) can inject into a target process using process doppelgänging.(Citation: Cybereason Bazar July 2020)(Citation: NCC Group Team9 June 2020)
- [G0077] Leafminer: [Leafminer](https://attack.mitre.org/groups/G0077) has used [Process Doppelgänging](https://attack.mitre.org/techniques/T1055/013) to evade security software while deploying tools on compromised systems.(Citation: Symantec Leafminer July 2018)

#### T1055.014 - VDSO Hijacking

Description:

Adversaries may inject malicious code into processes via VDSO hijacking in order to evade process-based defenses as well as possibly elevate privileges. Virtual dynamic shared object (vdso) hijacking is a method of executing arbitrary code in the address space of a separate live process. 

VDSO hijacking involves redirecting calls to dynamically linked shared libraries. Memory protections may prevent writing executable code to a process via [Ptrace System Calls](https://attack.mitre.org/techniques/T1055/008). However, an adversary may hijack the syscall interface code stubs mapped into a process from the vdso shared object to execute syscalls to open and map a malicious shared object. This code can then be invoked by redirecting the execution flow of the process via patched memory address references stored in a process' global offset table (which store absolute addresses of mapped library functions).(Citation: ELF Injection May 2009)(Citation: Backtrace VDSO)(Citation: VDSO Aug 2005)(Citation: Syscall 2014)

Running code in the context of another process may allow access to the process's memory, system/network resources, and possibly elevated privileges. Execution via VDSO hijacking may also evade detection from security products since the execution is masked under a legitimate process.

#### T1055.015 - ListPlanting

Description:

Adversaries may abuse list-view controls to inject malicious code into hijacked processes in order to evade process-based defenses as well as possibly elevate privileges. ListPlanting is a method of executing arbitrary code in the address space of a separate live process.(Citation: Hexacorn Listplanting) Code executed via ListPlanting may also evade detection from security products since the execution is masked under a legitimate process.

List-view controls are user interface windows used to display collections of items.(Citation: Microsoft List View Controls) Information about an application's list-view settings are stored within the process' memory in a <code>SysListView32</code> control.

ListPlanting (a form of message-passing "shatter attack") may be performed by copying code into the virtual address space of a process that uses a list-view control then using that code as a custom callback for sorting the listed items.(Citation: Modexp Windows Process Injection) Adversaries must first copy code into the target process’ memory space, which can be performed various ways including by directly obtaining a handle to the <code>SysListView32</code> child of the victim process window (via Windows API calls such as <code>FindWindow</code> and/or <code>EnumWindows</code>) or other [Process Injection](https://attack.mitre.org/techniques/T1055) methods.

Some variations of ListPlanting may allocate memory in the target process but then use window messages to copy the payload, to avoid the use of the highly monitored <code>WriteProcessMemory</code> function. For example, an adversary can use the <code>PostMessage</code> and/or <code>SendMessage</code> API functions to send <code>LVM_SETITEMPOSITION</code> and <code>LVM_GETITEMPOSITION</code> messages, effectively copying a payload 2 bytes at a time to the allocated memory.(Citation: ESET InvisiMole June 2020) 

Finally, the payload is triggered by sending the <code>LVM_SORTITEMS</code> message to the <code>SysListView32</code> child of the process window, with the payload within the newly allocated buffer passed and executed as the <code>ListView_SortItems</code> callback.

Procedures:

- [S0260] InvisiMole: [InvisiMole](https://attack.mitre.org/software/S0260) has used ListPlanting to inject code into a trusted process.(Citation: ESET InvisiMole June 2020)


### T1068 - Exploitation for Privilege Escalation

Description:

Adversaries may exploit software vulnerabilities in an attempt to elevate privileges. Exploitation of a software vulnerability occurs when an adversary takes advantage of a programming error in a program, service, or within the operating system software or kernel itself to execute adversary-controlled code. Security constructs such as permission levels will often hinder access to information and use of certain techniques, so adversaries will likely need to perform privilege escalation to include use of software exploitation to circumvent those restrictions.

When initially gaining access to a system, an adversary may be operating within a lower privileged process which will prevent them from accessing certain resources on the system. Vulnerabilities may exist, usually in operating system components and software commonly running at higher permissions, that can be exploited to gain higher levels of access on the system. This could enable someone to move from unprivileged or user level permissions to SYSTEM or root permissions depending on the component that is vulnerable. This could also enable an adversary to move from a virtualized environment, such as within a virtual machine or container, onto the underlying host. This may be a necessary step for an adversary compromising an endpoint system that has been properly configured and limits other privilege escalation methods.

Adversaries may bring a signed vulnerable driver onto a compromised machine so that they can exploit the vulnerability to execute code in kernel mode. This process is sometimes referred to as Bring Your Own Vulnerable Driver (BYOVD).(Citation: ESET InvisiMole June 2020)(Citation: Unit42 AcidBox June 2020) Adversaries may include the vulnerable driver with files delivered during Initial Access or download it to a compromised system via [Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105) or [Lateral Tool Transfer](https://attack.mitre.org/techniques/T1570).

Procedures:

- [G0027] Threat Group-3390: [Threat Group-3390](https://attack.mitre.org/groups/G0027) has used CVE-2014-6324 and CVE-2017-0213 to escalate privileges.(Citation: SecureWorks BRONZE UNION June 2017)(Citation: Profero APT27 December 2020)
- [S0125] Remsec: [Remsec](https://attack.mitre.org/software/S0125) has a plugin to drop and execute vulnerable Outpost Sandbox or avast! Virtualization drivers in order to gain kernel mode privileges.(Citation: Kaspersky ProjectSauron Technical Analysis)
- [S0378] PoshC2: [PoshC2](https://attack.mitre.org/software/S0378) contains modules for local privilege escalation exploits such as CVE-2016-9192 and CVE-2016-0099.(Citation: GitHub PoshC2)
- [G0125] HAFNIUM: [HAFNIUM](https://attack.mitre.org/groups/G0125) has targeted unpatched applications to elevate access in targeted organizations.(Citation: Microsoft Silk Typhoon MAR 2025)
- [G0016] APT29: [APT29](https://attack.mitre.org/groups/G0016) has exploited CVE-2021-36934 to escalate privileges on a compromised host.(Citation: ESET T3 Threat Report 2021)
- [S1151] ZeroCleare: [ZeroCleare](https://attack.mitre.org/software/S1151) has used a vulnerable signed VBoxDrv driver to bypass Microsoft Driver Signature Enforcement (DSE) protections and subsequently load the unsigned [RawDisk](https://attack.mitre.org/software/S0364) driver.(Citation: IBM ZeroCleare Wiper December 2019)
- [G0010] Turla: [Turla](https://attack.mitre.org/groups/G0010) has exploited vulnerabilities in the VBoxDrv.sys driver to obtain kernel mode privileges.(Citation: Unit42 AcidBox June 2020)
- [G0068] PLATINUM: [PLATINUM](https://attack.mitre.org/groups/G0068) has leveraged a zero-day vulnerability to escalate privileges.(Citation: Microsoft PLATINUM April 2016)
- [S0154] Cobalt Strike: [Cobalt Strike](https://attack.mitre.org/software/S0154) can exploit vulnerabilities such as MS14-058.(Citation: Cobalt Strike TTPs Dec 2017)(Citation: Cobalt Strike Manual 4.3 November 2020)
- [S0363] Empire: [Empire](https://attack.mitre.org/software/S0363) can exploit vulnerabilities such as MS16-032 and MS16-135.(Citation: Github PowerShell Empire)
- [G0061] FIN8: [FIN8](https://attack.mitre.org/groups/G0061) has exploited the CVE-2016-0167 local vulnerability.(Citation: FireEye Fin8 May 2016)(Citation: FireEye Know Your Enemy FIN8 Aug 2016)
- [G0080] Cobalt Group: [Cobalt Group](https://attack.mitre.org/groups/G0080) has used exploits to increase their levels of rights and privileges.(Citation: Group IB Cobalt Aug 2017)
- [S0664] Pandora: [Pandora](https://attack.mitre.org/software/S0664) can use CVE-2017-15303 to bypass Windows Driver Signature Enforcement (DSE) protection and load its driver.(Citation: Trend Micro Iron Tiger April 2021)
- [S0484] Carberp: [Carberp](https://attack.mitre.org/software/S0484) has exploited multiple Windows vulnerabilities (CVE-2010-2743, CVE-2010-3338, CVE-2010-4398, CVE-2008-1084) and a .NET Runtime Optimization vulnerability for privilege escalation.(Citation: ESET Carberp March 2012)(Citation: Prevx Carberp March 2011)
- [S0050] CosmicDuke: [CosmicDuke](https://attack.mitre.org/software/S0050) attempts to exploit privilege escalation vulnerabilities CVE-2010-0232 or CVE-2010-4398.(Citation: F-Secure The Dukes)
- [S1181] BlackByte 2.0 Ransomware: [BlackByte 2.0 Ransomware](https://attack.mitre.org/software/S1181) exploits a vulnerability in the RTCore64.sys driver (CVE-2019-16098) to enable privilege escalation and defense evasion when run as a service.(Citation: Microsoft BlackByte 2023)
- [S0260] InvisiMole: [InvisiMole](https://attack.mitre.org/software/S0260) has exploited CVE-2007-5633 vulnerability in the speedfan.sys driver to obtain kernel mode privileges.(Citation: ESET InvisiMole June 2020)
- [G1019] MoustachedBouncer: [MoustachedBouncer](https://attack.mitre.org/groups/G1019) has exploited CVE-2021-1732 to execute malware components with elevated rights.(Citation: MoustachedBouncer ESET August 2023)
- [G1017] Volt Typhoon: [Volt Typhoon](https://attack.mitre.org/groups/G1017) has gained initial access by exploiting privilege escalation vulnerabilities in the operating system or network services.(Citation: CISA AA24-038A PRC Critical Infrastructure February 2024)
- [G0037] FIN6: [FIN6](https://attack.mitre.org/groups/G0037) has used tools to exploit Windows vulnerabilities in order to escalate privileges. The tools targeted CVE-2013-3660, CVE-2011-2005, and CVE-2010-4398, all of which could allow local users to access kernel-level privileges.(Citation: FireEye FIN6 April 2016)
- [G0107] Whitefly: [Whitefly](https://attack.mitre.org/groups/G0107) has used an open-source tool to exploit a known Windows privilege escalation vulnerability (CVE-2016-0051) on unpatched computers.(Citation: Symantec Whitefly March 2019)
- [G1002] BITTER: [BITTER](https://attack.mitre.org/groups/G1002) has exploited CVE-2021-1732 for privilege escalation.(Citation: DBAPPSecurity BITTER zero-day Feb 2021)(Citation: Microsoft CVE-2021-1732 Feb 2021)
- [S0044] JHUHUGIT: [JHUHUGIT](https://attack.mitre.org/software/S0044) has exploited CVE-2015-1701 and CVE-2015-2387 to escalate privileges.(Citation: ESET Sednit Part 1)(Citation: ESET Sednit July 2015)
- [S0603] Stuxnet: [Stuxnet](https://attack.mitre.org/software/S0603) used MS10-073 and an undisclosed Task Scheduler vulnerability to escalate privileges on local Windows machines.(Citation: Nicolas Falliere, Liam O Murchu, Eric Chien February 2011)
- [G1004] LAPSUS$: [LAPSUS$](https://attack.mitre.org/groups/G1004) has exploited unpatched vulnerabilities on internally accessible servers including JIRA, GitLab, and Confluence for privilege escalation.(Citation: MSTIC DEV-0537 Mar 2022)
- [S0623] Siloscape: [Siloscape](https://attack.mitre.org/software/S0623) has leveraged a vulnerability in Windows containers to perform an [Escape to Host](https://attack.mitre.org/techniques/T1611).(Citation: Unit 42 Siloscape Jun 2021)
- [S0658] XCSSET: [XCSSET](https://attack.mitre.org/software/S0658) has used a zero-day exploit in the ssh launchdaemon to elevate privileges and bypass SIP.(Citation: trendmicro xcsset xcode project 2020)
- [G1043] BlackByte: [BlackByte](https://attack.mitre.org/groups/G1043) has exploited CVE-2024-37085 in VMWare ESXi software for authentication bypass and subsequent privilege escalation.(Citation: Cisco BlackByte 2024)
- [S0672] Zox: [Zox](https://attack.mitre.org/software/S0672) has the ability to leverage local and remote exploits to escalate privileges.(Citation: Novetta-Axiom)
- [G1015] Scattered Spider: [Scattered Spider](https://attack.mitre.org/groups/G1015) has deployed a malicious kernel driver through exploitation of CVE-2015-2291 in the Intel Ethernet diagnostics driver for Windows (iqvw64.sys).(Citation: CrowdStrike Scattered Spider BYOVD January 2023)
- [C0049] Leviathan Australian Intrusions: [Leviathan](https://attack.mitre.org/groups/G0065) exploited software vulnerabilities in victim environments to escalate privileges during [Leviathan Australian Intrusions](https://attack.mitre.org/campaigns/C0049).(Citation: CISA Leviathan 2024)
- [G0007] APT28: [APT28](https://attack.mitre.org/groups/G0007) has exploited CVE-2014-4076, CVE-2015-2387, CVE-2015-1701, CVE-2017-0263, and CVE-2022-38028 to escalate privileges.(Citation: Bitdefender APT28 Dec 2015)(Citation: Microsoft SIR Vol 19)(Citation: Securelist Sofacy Feb 2018)(Citation: Nearest Neighbor Volexity)
- [G0128] ZIRCONIUM: [ZIRCONIUM](https://attack.mitre.org/groups/G0128) has exploited CVE-2017-0005 for local privilege escalation.(Citation: Check Point APT31 February 2021)
- [G0131] Tonto Team: [Tonto Team](https://attack.mitre.org/groups/G0131) has exploited CVE-2019-0803 and MS16-032 to escalate privileges.(Citation: TrendMicro Tonto Team October 2020)
- [S0654] ProLock: [ProLock](https://attack.mitre.org/software/S0654) can use CVE-2019-0859 to escalate privileges on a compromised host.(Citation: Group IB Ransomware September 2020)
- [S0176] Wingbird: [Wingbird](https://attack.mitre.org/software/S0176) exploits CVE-2016-4117 to allow an executable to gain escalated privileges.(Citation: Microsoft SIR Vol 21)
- [C0045] ShadowRay: During [ShadowRay](https://attack.mitre.org/campaigns/C0045), threat actors downloaded a privilege escalation payload to gain root access.(Citation: Oligo ShadowRay Campaign MAR 2024)
- [G0050] APT32: [APT32](https://attack.mitre.org/groups/G0050) has used CVE-2016-7255 to escalate privileges.(Citation: FireEye APT32 May 2017)
- [G0064] APT33: [APT33](https://attack.mitre.org/groups/G0064) has used a publicly available exploit for CVE-2017-0213 to escalate privileges on a local system.(Citation: FireEye APT33 Guardrail)
- [S0601] Hildegard: [Hildegard](https://attack.mitre.org/software/S0601) has used the BOtB tool which exploits CVE-2019-5736.(Citation: Unit 42 Hildegard Malware)
- [G0049] OilRig: [OilRig](https://attack.mitre.org/groups/G0049) has exploited the Windows Kernel Elevation of Privilege vulnerability, CVE-2024-30088.(Citation: Trend Micro Earth Simnavaz October 2024)


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

#### T1078.001 - Default Accounts

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

#### T1078.002 - Domain Accounts

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

#### T1078.003 - Local Accounts

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

#### T1078.004 - Cloud Accounts

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


### T1098 - Account Manipulation

Description:

Adversaries may manipulate accounts to maintain and/or elevate access to victim systems. Account manipulation may consist of any action that preserves or modifies adversary access to a compromised account, such as modifying credentials or permission groups.(Citation: FireEye SMOKEDHAM June 2021) These actions could also include account activity designed to subvert security policies, such as performing iterative password updates to bypass password duration policies and preserve the life of compromised credentials. 

In order to create or manipulate accounts, the adversary must already have sufficient permissions on systems or the domain. However, account manipulation may also lead to privilege escalation where modifications grant access to additional roles, permissions, or higher-privileged [Valid Accounts](https://attack.mitre.org/techniques/T1078).

Procedures:

- [G0032] Lazarus Group: [Lazarus Group](https://attack.mitre.org/groups/G0032) malware WhiskeyDelta-Two contains a function that attempts to rename the administrator’s account.(Citation: Novetta Blockbuster)(Citation: Novetta Blockbuster Destructive Malware)
- [S0002] Mimikatz: The [Mimikatz](https://attack.mitre.org/software/S0002) credential dumper has been extended to include Skeleton Key domain controller authentication bypass functionality. The <code>LSADUMP::ChangeNTLM</code> and <code>LSADUMP::SetNTLM</code> modules can also manipulate the password hash of an account without knowing the clear text value.(Citation: Adsecurity Mimikatz Guide)(Citation: Metcalf 2015)
- [C0025] 2016 Ukraine Electric Power Attack: During the [2016 Ukraine Electric Power Attack](https://attack.mitre.org/campaigns/C0025), [Sandworm Team](https://attack.mitre.org/groups/G0034) used the `sp_addlinkedsrvlogin` command in MS-SQL to create a link between a created account and other servers in the network.(Citation: Dragos Crashoverride 2018)
- [G0125] HAFNIUM: [HAFNIUM](https://attack.mitre.org/groups/G0125) has granted privileges to domain accounts and reset the password for default admin accounts.(Citation: Volexity Exchange Marauder March 2021)(Citation: Microsoft Silk Typhoon MAR 2025)
- [S0274] Calisto: [Calisto](https://attack.mitre.org/software/S0274) adds permissions and remote logins to all users.(Citation: Symantec Calisto July 2018)

#### T1098.001 - Additional Cloud Credentials

Description:

Adversaries may add adversary-controlled credentials to a cloud account to maintain persistent access to victim accounts and instances within the environment.

For example, adversaries may add credentials for Service Principals and Applications in addition to existing legitimate credentials in Azure / Entra ID.(Citation: Microsoft SolarWinds Customer Guidance)(Citation: Blue Cloud of Death)(Citation: Blue Cloud of Death Video) These credentials include both x509 keys and passwords.(Citation: Microsoft SolarWinds Customer Guidance) With sufficient permissions, there are a variety of ways to add credentials including the Azure Portal, Azure command line interface, and Azure or Az PowerShell modules.(Citation: Demystifying Azure AD Service Principals)

In infrastructure-as-a-service (IaaS) environments, after gaining access through [Cloud Accounts](https://attack.mitre.org/techniques/T1078/004), adversaries may generate or import their own SSH keys using either the <code>CreateKeyPair</code> or <code>ImportKeyPair</code> API in AWS or the <code>gcloud compute os-login ssh-keys add</code> command in GCP.(Citation: GCP SSH Key Add) This allows persistent access to instances within the cloud environment without further usage of the compromised cloud accounts.(Citation: Expel IO Evil in AWS)(Citation: Expel Behind the Scenes)

Adversaries may also use the <code>CreateAccessKey</code> API in AWS or the <code>gcloud iam service-accounts keys create</code> command in GCP to add access keys to an account. Alternatively, they may use the <code>CreateLoginProfile</code> API in AWS to add a password that can be used to log into the AWS Management Console for [Cloud Service Dashboard](https://attack.mitre.org/techniques/T1538).(Citation: Permiso Scattered Spider 2023)(Citation: Lacework AI Resource Hijacking 2024) If the target account has different permissions from the requesting account, the adversary may also be able to escalate their privileges in the environment (i.e. [Cloud Accounts](https://attack.mitre.org/techniques/T1078/004)).(Citation: Rhino Security Labs AWS Privilege Escalation)(Citation: Sysdig ScarletEel 2.0) For example, in Entra ID environments, an adversary with the Application Administrator role can add a new set of credentials to their application's service principal. In doing so the adversary would be able to access the service principal’s roles and permissions, which may be different from those of the Application Administrator.(Citation: SpecterOps Azure Privilege Escalation) 

In AWS environments, adversaries with the appropriate permissions may also use the `sts:GetFederationToken` API call to create a temporary set of credentials to [Forge Web Credentials](https://attack.mitre.org/techniques/T1606) tied to the permissions of the original user account. These temporary credentials may remain valid for the duration of their lifetime even if the original account’s API credentials are deactivated.
(Citation: Crowdstrike AWS User Federation Persistence)

In Entra ID environments with the app password feature enabled, adversaries may be able to add an app password to a user account.(Citation: Mandiant APT42 Operations 2024) As app passwords are intended to be used with legacy devices that do not support multi-factor authentication (MFA), adding an app password can allow an adversary to bypass MFA requirements. Additionally, app passwords may remain valid even if the user’s primary password is reset.(Citation: Microsoft Entra ID App Passwords)

Procedures:

- [S1091] Pacu: [Pacu](https://attack.mitre.org/software/S1091) can generate SSH and API keys for AWS infrastructure and additional API keys for other IAM users.(Citation: GitHub Pacu)
- [C0027] C0027: During [C0027](https://attack.mitre.org/campaigns/C0027), [Scattered Spider](https://attack.mitre.org/groups/G1015) used aws_consoler  to create temporary federated credentials for fake users in order to obfuscate which AWS credential is compromised and enable pivoting from the AWS CLI to console sessions without MFA.(Citation: Crowdstrike TELCO BPO Campaign December 2022)
- [C0024] SolarWinds Compromise: During the [SolarWinds Compromise](https://attack.mitre.org/campaigns/C0024), [APT29](https://attack.mitre.org/groups/G0016) added credentials to OAuth Applications and Service Principals.(Citation: Microsoft - Customer Guidance on Recent Nation-State Cyber Attacks)(Citation: CrowdStrike StellarParticle January 2022)

#### T1098.002 - Additional Email Delegate Permissions

Description:

Adversaries may grant additional permission levels to maintain persistent access to an adversary-controlled email account. 

For example, the <code>Add-MailboxPermission</code> [PowerShell](https://attack.mitre.org/techniques/T1059/001) cmdlet, available in on-premises Exchange and in the cloud-based service Office 365, adds permissions to a mailbox.(Citation: Microsoft - Add-MailboxPermission)(Citation: FireEye APT35 2018)(Citation: Crowdstrike Hiding in Plain Sight 2018) In Google Workspace, delegation can be enabled via the Google Admin console and users can delegate accounts via their Gmail settings.(Citation: Gmail Delegation)(Citation: Google Ensuring Your Information is Safe) 

Adversaries may also assign mailbox folder permissions through individual folder permissions or roles. In Office 365 environments, adversaries may assign the Default or Anonymous user permissions or roles to the Top of Information Store (root), Inbox, or other mailbox folders. By assigning one or both user permissions to a folder, the adversary can utilize any other account in the tenant to maintain persistence to the target user’s mail folders.(Citation: Mandiant Defend UNC2452 White Paper)

This may be used in persistent threat incidents as well as BEC (Business Email Compromise) incidents where an adversary can add [Additional Cloud Roles](https://attack.mitre.org/techniques/T1098/003) to the accounts they wish to compromise. This may further enable use of additional techniques for gaining access to systems. For example, compromised business accounts are often used to send messages to other accounts in the network of the target business while creating inbox rules (ex: [Internal Spearphishing](https://attack.mitre.org/techniques/T1534)), so the messages evade spam/phishing detection mechanisms.(Citation: Bienstock, D. - Defending O365 - 2019)

Procedures:

- [C0038] HomeLand Justice: During [HomeLand Justice](https://attack.mitre.org/campaigns/C0038), threat actors added the `ApplicationImpersonation` management role to accounts under their control to impersonate users and take ownership of targeted mailboxes.(Citation: Microsoft Albanian Government Attacks September 2022)
- [C0024] SolarWinds Compromise: During the [SolarWinds Compromise](https://attack.mitre.org/campaigns/C0024), [APT29](https://attack.mitre.org/groups/G0016) added their own devices as allowed IDs for active sync using `Set-CASMailbox`, allowing it to obtain copies of victim mailboxes. It also added additional permissions (such as Mail.Read and Mail.ReadWrite) to compromised Application or Service Principals.(Citation: Volexity SolarWinds)(Citation: Microsoft - Customer Guidance on Recent Nation-State Cyber Attacks)(Citation: MSTIC Nobelium Oct 2021)
- [G0059] Magic Hound: [Magic Hound](https://attack.mitre.org/groups/G0059) granted compromised email accounts read access to the email boxes of additional targeted accounts. The group then was able to authenticate to the intended victim's OWA (Outlook Web Access) portal and read hundreds of email communications for information on Middle East organizations.(Citation: FireEye APT35 2018)
- [G0007] APT28: [APT28](https://attack.mitre.org/groups/G0007) has used a Powershell cmdlet to grant the <code>ApplicationImpersonation</code> role to a compromised account.(Citation: Cybersecurity Advisory GRU Brute Force Campaign July 2021)
- [G0016] APT29: [APT29](https://attack.mitre.org/groups/G0016) has used a compromised global administrator account in Azure AD to backdoor a service principal with `ApplicationImpersonation` rights to start collecting emails from targeted mailboxes; [APT29](https://attack.mitre.org/groups/G0016) has also used compromised accounts holding `ApplicationImpersonation` rights in Exchange to collect emails.(Citation: Mandiant APT29 Microsoft 365 2022)(Citation: Mandiant APT29 Eye Spy Email Nov 22)

#### T1098.003 - Additional Cloud Roles

Description:

An adversary may add additional roles or permissions to an adversary-controlled cloud account to maintain persistent access to a tenant. For example, adversaries may update IAM policies in cloud-based environments or add a new global administrator in Office 365 environments.(Citation: AWS IAM Policies and Permissions)(Citation: Google Cloud IAM Policies)(Citation: Microsoft Support O365 Add Another Admin, October 2019)(Citation: Microsoft O365 Admin Roles) With sufficient permissions, a compromised account can gain almost unlimited access to data and settings (including the ability to reset the passwords of other admins).(Citation: Expel AWS Attacker)
(Citation: Microsoft O365 Admin Roles) 

This account modification may immediately follow [Create Account](https://attack.mitre.org/techniques/T1136) or other malicious account activity. Adversaries may also modify existing [Valid Accounts](https://attack.mitre.org/techniques/T1078) that they have compromised. This could lead to privilege escalation, particularly if the roles added allow for lateral movement to additional accounts.

For example, in AWS environments, an adversary with appropriate permissions may be able to use the <code>CreatePolicyVersion</code> API to define a new version of an IAM policy or the <code>AttachUserPolicy</code> API to attach an IAM policy with additional or distinct permissions to a compromised user account.(Citation: Rhino Security Labs AWS Privilege Escalation)

In some cases, adversaries may add roles to adversary-controlled accounts outside the victim cloud tenant. This allows these external accounts to perform actions inside the victim tenant without requiring the adversary to [Create Account](https://attack.mitre.org/techniques/T1136) or modify a victim-owned account.(Citation: Invictus IR DangerDev 2024)

Procedures:

- [C0027] C0027: During [C0027](https://attack.mitre.org/campaigns/C0027), [Scattered Spider](https://attack.mitre.org/groups/G1015) used IAM manipulation to gain persistence and to assume or elevate privileges.(Citation: Crowdstrike TELCO BPO Campaign December 2022)
- [C0024] SolarWinds Compromise: During the [SolarWinds Compromise](https://attack.mitre.org/campaigns/C0024), [APT29](https://attack.mitre.org/groups/G0016) granted `company administrator` privileges to a newly created service principle.(Citation: CrowdStrike StellarParticle January 2022)
- [G1015] Scattered Spider: During [C0027](https://attack.mitre.org/campaigns/C0027), [Scattered Spider](https://attack.mitre.org/groups/G1015) used IAM manipulation to gain persistence and to assume or elevate privileges.(Citation: Crowdstrike TELCO BPO Campaign December 2022)

[Scattered Spider](https://attack.mitre.org/groups/G1015) has also assigned user access admin roles in order to gain Tenant Root Group management permissions in Azure.(Citation: MSTIC Octo Tempest Operations October 2023)
- [G1004] LAPSUS$: [LAPSUS$](https://attack.mitre.org/groups/G1004) has added the global admin role to accounts they have created in the targeted organization's cloud instances.(Citation: MSTIC DEV-0537 Mar 2022)

#### T1098.004 - SSH Authorized Keys

Description:

Adversaries may modify the SSH <code>authorized_keys</code> file to maintain persistence on a victim host. Linux distributions, macOS, and ESXi hypervisors commonly use key-based authentication to secure the authentication process of SSH sessions for remote management. The <code>authorized_keys</code> file in SSH specifies the SSH keys that can be used for logging into the user account for which the file is configured. This file is usually found in the user's home directory under <code>&lt;user-home&gt;/.ssh/authorized_keys</code> (or, on ESXi, `/etc/ssh/keys-<username>/authorized_keys`).(Citation: SSH Authorized Keys) Users may edit the system’s SSH config file to modify the directives `PubkeyAuthentication` and `RSAAuthentication` to the value `yes` to ensure public key and RSA authentication are enabled, as well as modify the directive `PermitRootLogin` to the value `yes` to enable root authentication via SSH.(Citation: Broadcom ESXi SSH) The SSH config file is usually located under <code>/etc/ssh/sshd_config</code>.

Adversaries may modify SSH <code>authorized_keys</code> files directly with scripts or shell commands to add their own adversary-supplied public keys. In cloud environments, adversaries may be able to modify the SSH authorized_keys file of a particular virtual machine via the command line interface or rest API. For example, by using the Google Cloud CLI’s “add-metadata” command an adversary may add SSH keys to a user account.(Citation: Google Cloud Add Metadata)(Citation: Google Cloud Privilege Escalation) Similarly, in Azure, an adversary may update the authorized_keys file of a virtual machine via a PATCH request to the API.(Citation: Azure Update Virtual Machines) This ensures that an adversary possessing the corresponding private key may log in as an existing user via SSH.(Citation: Venafi SSH Key Abuse)(Citation: Cybereason Linux Exim Worm) It may also lead to privilege escalation where the virtual machine or instance has distinct permissions from the requesting user.

Where authorized_keys files are modified via cloud APIs or command line interfaces, an adversary may achieve privilege escalation on the target virtual machine if they add a key to a higher-privileged user. 

SSH keys can also be added to accounts on network devices, such as with the `ip ssh pubkey-chain` [Network Device CLI](https://attack.mitre.org/techniques/T1059/008) command.(Citation: cisco_ip_ssh_pubkey_ch_cmd)

Procedures:

- [G1006] Earth Lusca: [Earth Lusca](https://attack.mitre.org/groups/G1006) has dropped an SSH-authorized key in the `/root/.ssh` folder in order to access a compromised server with SSH.(Citation: TrendMicro EarthLusca 2022)
- [S0468] Skidmap: [Skidmap](https://attack.mitre.org/software/S0468) has the ability to add the public key of its handlers to the <code>authorized_keys</code> file to maintain persistence on an infected host.(Citation: Trend Micro Skidmap)
- [G1045] Salt Typhoon: [Salt Typhoon](https://attack.mitre.org/groups/G1045) has added SSH authorized_keys under root or other users at the Linux level on compromised network devices.(Citation: Cisco Salt Typhoon FEB 2025)
- [S0658] XCSSET: [XCSSET](https://attack.mitre.org/software/S0658) will create an ssh key if necessary with the <code>ssh-keygen -t rsa -f $HOME/.ssh/id_rsa -P</code> command. [XCSSET](https://attack.mitre.org/software/S0658) will upload a private key file to the server to remotely access the host without a password.(Citation: trendmicro xcsset xcode project 2020)
- [S0482] Bundlore: [Bundlore](https://attack.mitre.org/software/S0482) creates a new key pair with <code>ssh-keygen</code> and drops the newly created user key in <code>authorized_keys</code> to enable remote login.(Citation: MacKeeper Bundlore Apr 2019)
- [G0139] TeamTNT: [TeamTNT](https://attack.mitre.org/groups/G0139) has added RSA keys in <code>authorized_keys</code>.(Citation: Aqua TeamTNT August 2020)(Citation: Cisco Talos Intelligence Group)

#### T1098.005 - Device Registration

Description:

Adversaries may register a device to an adversary-controlled account. Devices may be registered in a multifactor authentication (MFA) system, which handles authentication to the network, or in a device management system, which handles device access and compliance.

MFA systems, such as Duo or Okta, allow users to associate devices with their accounts in order to complete MFA requirements. An adversary that compromises a user’s credentials may enroll a new device in order to bypass initial MFA requirements and gain persistent access to a network.(Citation: CISA MFA PrintNightmare)(Citation: DarkReading FireEye SolarWinds) In some cases, the MFA self-enrollment process may require only a username and password to enroll the account's first device or to enroll a device to an inactive account. (Citation: Mandiant APT29 Microsoft 365 2022)

Similarly, an adversary with existing access to a network may register a device to Entra ID and/or its device management system, Microsoft Intune, in order to access sensitive data or resources while bypassing conditional access policies.(Citation: AADInternals - Device Registration)(Citation: AADInternals - Conditional Access Bypass)(Citation: Microsoft DEV-0537) 

Devices registered in Entra ID may be able to conduct [Internal Spearphishing](https://attack.mitre.org/techniques/T1534) campaigns via intra-organizational emails, which are less likely to be treated as suspicious by the email client.(Citation: Microsoft - Device Registration) Additionally, an adversary may be able to perform a [Service Exhaustion Flood](https://attack.mitre.org/techniques/T1499/002) on an Entra ID tenant by registering a large number of devices.(Citation: AADInternals - BPRT)

Procedures:

- [G0016] APT29: [APT29](https://attack.mitre.org/groups/G0016) has enrolled their own devices into compromised cloud tenants, including enrolling a device in MFA to an Azure AD environment following a successful password guessing attack against a dormant account.(Citation: Mandiant APT29 Microsoft 365 2022)(Citation: NCSC et al APT29 2024)
- [S0677] AADInternals: [AADInternals](https://attack.mitre.org/software/S0677) can register a device to Azure AD.(Citation: AADInternals Documentation)
- [C0024] SolarWinds Compromise: During the [SolarWinds Compromise](https://attack.mitre.org/campaigns/C0024), [APT29](https://attack.mitre.org/groups/G0016) registered devices in order to enable mailbox syncing via the `Set-CASMailbox` command.(Citation: Volexity SolarWinds)
- [C0027] C0027: During [C0027](https://attack.mitre.org/campaigns/C0027), [Scattered Spider](https://attack.mitre.org/groups/G1015) registered devices for MFA to maintain persistence through victims' VPN.(Citation: Crowdstrike TELCO BPO Campaign December 2022)

#### T1098.006 - Additional Container Cluster Roles

Description:

An adversary may add additional roles or permissions to an adversary-controlled user or service account to maintain persistent access to a container orchestration system. For example, an adversary with sufficient permissions may create a RoleBinding or a ClusterRoleBinding to bind a Role or ClusterRole to a Kubernetes account.(Citation: Kubernetes RBAC)(Citation: Aquasec Kubernetes Attack 2023) Where attribute-based access control (ABAC) is in use, an adversary with sufficient permissions may modify a Kubernetes ABAC policy to give the target account additional permissions.(Citation: Kuberentes ABAC)
 
This account modification may immediately follow [Create Account](https://attack.mitre.org/techniques/T1136) or other malicious account activity. Adversaries may also modify existing [Valid Accounts](https://attack.mitre.org/techniques/T1078) that they have compromised.  

Note that where container orchestration systems are deployed in cloud environments, as with Google Kubernetes Engine, Amazon Elastic Kubernetes Service, and Azure Kubernetes Service, cloud-based  role-based access control (RBAC) assignments or ABAC policies can often be used in place of or in addition to local permission assignments.(Citation: Google Cloud Kubernetes IAM)(Citation: AWS EKS IAM Roles for Service Accounts)(Citation: Microsoft Azure Kubernetes Service Service Accounts) In these cases, this technique may be used in conjunction with [Additional Cloud Roles](https://attack.mitre.org/techniques/T1098/003).

#### T1098.007 - Additional Local or Domain Groups

Description:

An adversary may add additional local or domain groups to an adversary-controlled account to maintain persistent access to a system or domain.

On Windows, accounts may use the `net localgroup` and `net group` commands to add existing users to local and domain groups.(Citation: Microsoft Net Localgroup)(Citation: Microsoft Net Group) On Linux, adversaries may use the `usermod` command for the same purpose.(Citation: Linux Usermod)

For example, accounts may be added to the local administrators group on Windows devices to maintain elevated privileges. They may also be added to the Remote Desktop Users group, which allows them to leverage [Remote Desktop Protocol](https://attack.mitre.org/techniques/T1021/001) to log into the endpoints in the future.(Citation: Microsoft RDP Logons) On Linux, accounts may be added to the sudoers group, allowing them to persistently leverage [Sudo and Sudo Caching](https://attack.mitre.org/techniques/T1548/003) for elevated privileges. 

In Windows environments, machine accounts may also be added to domain groups. This allows the local SYSTEM account to gain privileges on the domain.(Citation: RootDSE AD Detection 2022)

Procedures:

- [S0649] SMOKEDHAM: [SMOKEDHAM](https://attack.mitre.org/software/S0649) has added user accounts to local Admin groups.(Citation: FireEye SMOKEDHAM June 2021)
- [G0096] APT41: [APT41](https://attack.mitre.org/groups/G0096) has added user accounts to the User and Admin groups.(Citation: FireEye APT41 Aug 2019)
- [G0022] APT3: [APT3](https://attack.mitre.org/groups/G0022) has been known to add created accounts to local admin groups to maintain elevated access.(Citation: aptsim)
- [S0039] Net: The `net localgroup` and `net group` commands in [Net](https://attack.mitre.org/software/S0039) can be used to add existing users to local and domain groups.(Citation: Microsoft Net Localgroup) (Citation: Microsoft Net Group)
- [G0059] Magic Hound: [Magic Hound](https://attack.mitre.org/groups/G0059) has added a user named DefaultAccount to the Administrators and Remote Desktop Users groups.(Citation: DFIR Report APT35 ProxyShell March 2022)
- [G1023] APT5: [APT5](https://attack.mitre.org/groups/G1023) has created their own accounts with Local Administrator privileges to maintain access to systems with short-cycle credential rotation.(Citation: Mandiant Pulse Secure Update May 2021)
- [G0035] Dragonfly: [Dragonfly](https://attack.mitre.org/groups/G0035) has added newly created accounts to the administrators group to maintain elevated access.(Citation: US-CERT TA18-074A)
- [G1016] FIN13: [FIN13](https://attack.mitre.org/groups/G1016) has assigned newly created accounts the sysadmin role to maintain persistence.(Citation: Sygnia Elephant Beetle Jan 2022)
- [S1111] DarkGate: [DarkGate](https://attack.mitre.org/software/S1111) elevates accounts created through the malware to the local administration group during execution.(Citation: Ensilo Darkgate 2018)
- [S0382] ServHelper: [ServHelper](https://attack.mitre.org/software/S0382) has added a user named "supportaccount" to the Remote Desktop Users and Administrators groups.(Citation: Proofpoint TA505 Jan 2019)
- [G0094] Kimsuky: [Kimsuky](https://attack.mitre.org/groups/G0094) has added accounts to specific groups with <code>net localgroup</code>.(Citation: KISA Operation Muzabi)


### T1134 - Access Token Manipulation

Description:

Adversaries may modify access tokens to operate under a different user or system security context to perform actions and bypass access controls. Windows uses access tokens to determine the ownership of a running process. A user can manipulate access tokens to make a running process appear as though it is the child of a different process or belongs to someone other than the user that started the process. When this occurs, the process also takes on the security context associated with the new token.

An adversary can use built-in Windows API functions to copy access tokens from existing processes; this is known as token stealing. These token can then be applied to an existing process (i.e. [Token Impersonation/Theft](https://attack.mitre.org/techniques/T1134/001)) or used to spawn a new process (i.e. [Create Process with Token](https://attack.mitre.org/techniques/T1134/002)). An adversary must already be in a privileged user context (i.e. administrator) to steal a token. However, adversaries commonly use token stealing to elevate their security context from the administrator level to the SYSTEM level. An adversary can then use a token to authenticate to a remote system as the account for that token if the account has appropriate permissions on the remote system.(Citation: Pentestlab Token Manipulation)

Any standard user can use the <code>runas</code> command, and the Windows API functions, to create impersonation tokens; it does not require access to an administrator account. There are also other mechanisms, such as Active Directory fields, that can be used to modify access tokens.

Procedures:

- [S0697] HermeticWiper: [HermeticWiper](https://attack.mitre.org/software/S0697) can use `AdjustTokenPrivileges` to grant itself privileges for debugging with `SeDebugPrivilege`, creating backups with `SeBackupPrivilege`, loading drivers with `SeLoadDriverPrivilege`, and shutting down a local system with `SeShutdownPrivilege`.(Citation: Qualys Hermetic Wiper March 2022)(Citation: Crowdstrike DriveSlayer February 2022)
- [S0562] SUNSPOT: [SUNSPOT](https://attack.mitre.org/software/S0562) modified its security token to grants itself debugging privileges by adding <code>SeDebugPrivilege</code>.(Citation: CrowdStrike SUNSPOT Implant January 2021)
- [G0030] Lotus Blossom: [Lotus Blossom](https://attack.mitre.org/groups/G0030) has retrieved process tokens for processes to adjust the privileges of the launch process or other items.(Citation: Cisco LotusBlossom 2025)
- [S0194] PowerSploit: [PowerSploit](https://attack.mitre.org/software/S0194)'s <code>Invoke-TokenManipulation</code> Exfiltration module can be used to manipulate tokens.(Citation: GitHub PowerSploit May 2012)(Citation: PowerSploit Documentation)
- [S0622] AppleSeed: [AppleSeed](https://attack.mitre.org/software/S0622) can gain system level privilege by passing <code>SeDebugPrivilege</code> to the <code>AdjustTokenPrivilege</code> API.(Citation: Malwarebytes Kimsuky June 2021)
- [S0633] Sliver: [Sliver](https://attack.mitre.org/software/S0633) has the ability to manipulate user tokens on targeted Windows systems.(Citation: Bishop Fox Sliver Framework August 2019)(Citation: GitHub Sliver C2)
- [G0037] FIN6: [FIN6](https://attack.mitre.org/groups/G0037) has used has used Metasploit’s named-pipe impersonation technique to escalate privileges.(Citation: FireEye FIN6 Apr 2019)
- [G0108] Blue Mockingbird: [Blue Mockingbird](https://attack.mitre.org/groups/G0108) has used JuicyPotato to abuse the <code>SeImpersonate</code> token privilege to escalate from web application pool accounts to NT Authority\SYSTEM.(Citation: RedCanary Mockingbird May 2020)
- [S1210] Sagerunex: [Sagerunex](https://attack.mitre.org/software/S1210) finds the `explorer.exe` process after execution and uses it to change the token of its executing thread.(Citation: Symantec Bilbug 2022)
- [S0058] SslMM: [SslMM](https://attack.mitre.org/software/S0058) contains a feature to manipulate process privileges and tokens.(Citation: Baumgartner Naikon 2015)
- [S0038] Duqu: [Duqu](https://attack.mitre.org/software/S0038) examines running system processes for tokens that have specific system privileges. If it finds one, it will copy the token and store it for later use. Eventually it will start new processes with the stored token attached. It can also steal tokens to acquire administrative privileges.(Citation: Kaspersky Duqu 2.0)
- [S0363] Empire: [Empire](https://attack.mitre.org/software/S0363) can use [PowerSploit](https://attack.mitre.org/software/S0194)'s <code>Invoke-TokenManipulation</code> to manipulate access tokens.(Citation: Github PowerShell Empire)
- [S0666] Gelsemium: [Gelsemium](https://attack.mitre.org/software/S0666) can use token manipulation to bypass UAC on Windows7 systems.(Citation: ESET Gelsemium June 2021)
- [S0625] Cuba: [Cuba](https://attack.mitre.org/software/S0625) has used <code>SeDebugPrivilege</code> and <code>AdjustTokenPrivileges</code> to elevate privileges.(Citation: McAfee Cuba April 2021)
- [S1060] Mafalda: [Mafalda](https://attack.mitre.org/software/S1060) can use `AdjustTokenPrivileges()` to elevate privileges.(Citation: SentinelLabs Metador Technical Appendix Sept 2022)
- [C0017] C0017: During [C0017](https://attack.mitre.org/campaigns/C0017), [APT41](https://attack.mitre.org/groups/G0096) used a ConfuserEx obfuscated BADPOTATO exploit to abuse named-pipe impersonation for local `NT AUTHORITY\SYSTEM` privilege escalation.(Citation: Mandiant APT41)
- [S0378] PoshC2: [PoshC2](https://attack.mitre.org/software/S0378) can use Invoke-TokenManipulation for manipulating tokens.(Citation: GitHub PoshC2)
- [S0203] Hydraq: [Hydraq](https://attack.mitre.org/software/S0203) creates a backdoor through which remote attackers can adjust token privileges.(Citation: Symantec Hydraq Jan 2010)
- [S0607] KillDisk: [KillDisk](https://attack.mitre.org/software/S0607) has attempted to get the access token of a process by calling <code>OpenProcessToken</code>. If [KillDisk](https://attack.mitre.org/software/S0607) gets the access token, then it attempt to modify the token privileges with <code>AdjustTokenPrivileges</code>.(Citation: Trend Micro KillDisk 2)
- [S0446] Ryuk: [Ryuk](https://attack.mitre.org/software/S0446) has attempted to adjust its token privileges to have the <code>SeDebugPrivilege</code>.(Citation: CrowdStrike Ryuk January 2019)
- [S0576] MegaCortex: [MegaCortex](https://attack.mitre.org/software/S0576) can enable <code>SeDebugPrivilege</code> and adjust token privileges.(Citation: IBM MegaCortex)
- [S1068] BlackCat: [BlackCat](https://attack.mitre.org/software/S1068) has the ability modify access tokens.(Citation: Microsoft BlackCat Jun 2022)(Citation: Sophos BlackCat Jul 2022)

#### T1134.001 - Token Impersonation/Theft

Description:

Adversaries may duplicate then impersonate another user's existing token to escalate privileges and bypass access controls. For example, an adversary can duplicate an existing token using `DuplicateToken` or `DuplicateTokenEx`.(Citation: DuplicateToken function) The token can then be used with `ImpersonateLoggedOnUser` to allow the calling thread to impersonate a logged on user's security context, or with `SetThreadToken` to assign the impersonated token to a thread.

An adversary may perform [Token Impersonation/Theft](https://attack.mitre.org/techniques/T1134/001) when they have a specific, existing process they want to assign the duplicated token to. For example, this may be useful for when the target user has a non-network logon session on the system.

When an adversary would instead use a duplicated token to create a new process rather than attaching to an existing process, they can additionally [Create Process with Token](https://attack.mitre.org/techniques/T1134/002) using `CreateProcessWithTokenW` or `CreateProcessAsUserW`. [Token Impersonation/Theft](https://attack.mitre.org/techniques/T1134/001) is also distinct from [Make and Impersonate Token](https://attack.mitre.org/techniques/T1134/003) in that it refers to duplicating an existing token, rather than creating a new one.

Procedures:

- [S0182] FinFisher: [FinFisher](https://attack.mitre.org/software/S0182) uses token manipulation with NtFilterToken as part of UAC bypass.(Citation: FinFisher Citation)(Citation: Microsoft FinFisher March 2018)
- [S0367] Emotet: [Emotet](https://attack.mitre.org/software/S0367) has the ability to duplicate the user’s token.(Citation: Binary Defense Emotes Wi-Fi Spreader) For example, [Emotet](https://attack.mitre.org/software/S0367) may use a variant of Google’s ProtoBuf to send messages that specify how code will be executed.(Citation: emotet_hc3_nov2023)
- [S0603] Stuxnet: [Stuxnet](https://attack.mitre.org/software/S0603) attempts to impersonate an anonymous token to enumerate bindings in the service control manager.(Citation: Nicolas Falliere, Liam O Murchu, Eric Chien February 2011)
- [C0038] HomeLand Justice: During [HomeLand Justice](https://attack.mitre.org/campaigns/C0038), threat actors used custom tooling to acquire tokens using `ImpersonateLoggedOnUser/SetThreadToken`.(Citation: Microsoft Albanian Government Attacks September 2022)
- [S0154] Cobalt Strike: [Cobalt Strike](https://attack.mitre.org/software/S0154) can steal access tokens from exiting processes.(Citation: cobaltstrike manual)(Citation: Cobalt Strike Manual 4.3 November 2020)
- [S1011] Tarrask: [Tarrask](https://attack.mitre.org/software/S1011) leverages token theft to obtain `lsass.exe` security permissions.(Citation: Tarrask scheduled task)
- [S0692] SILENTTRINITY: [SILENTTRINITY](https://attack.mitre.org/software/S0692) can find a process owned by a specific user and impersonate the associated token.(Citation: GitHub SILENTTRINITY Modules July 2019)
- [S0570] BitPaymer: [BitPaymer](https://attack.mitre.org/software/S0570) can use the tokens of users to create processes on infected systems.(Citation: Crowdstrike Indrik November 2018)
- [S0140] Shamoon: [Shamoon](https://attack.mitre.org/software/S0140) can impersonate tokens using <code>LogonUser</code>, <code>ImpersonateLoggedOnUser</code>, and <code>ImpersonateNamedPipeClient</code>.(Citation: McAfee Shamoon December 2018)
- [S0439] Okrum: [Okrum](https://attack.mitre.org/software/S0439) can impersonate a logged-on user's security context using a call to the ImpersonateLoggedOnUser API.(Citation: ESET Okrum July 2019)
- [S0456] Aria-body: [Aria-body](https://attack.mitre.org/software/S0456) has the ability to duplicate a token from ntprint.exe.(Citation: CheckPoint Naikon May 2020)
- [G0007] APT28: [APT28](https://attack.mitre.org/groups/G0007) has used CVE-2015-1701 to access the SYSTEM token and copy it into the current process as part of privilege escalation.(Citation: FireEye Op RussianDoll)
- [S0496] REvil: [REvil](https://attack.mitre.org/software/S0496) can obtain the token from the user that launched the explorer.exe process to avoid affecting the desktop of the SYSTEM user.(Citation: McAfee Sodinokibi October 2019)
- [S0192] Pupy: [Pupy](https://attack.mitre.org/software/S0192) can obtain a list of SIDs and provide the option for selecting process tokens to impersonate.(Citation: GitHub Pupy)
- [S1081] BADHATCH: [BADHATCH](https://attack.mitre.org/software/S1081) can impersonate a `lsass.exe` or `vmtoolsd.exe` token.(Citation: BitDefender BADHATCH Mar 2021)
- [S0623] Siloscape: [Siloscape](https://attack.mitre.org/software/S0623) impersonates the main thread of <code>CExecSvc.exe</code> by calling <code>NtImpersonateThread</code>.(Citation: Unit 42 Siloscape Jun 2021)
- [G0061] FIN8: [FIN8](https://attack.mitre.org/groups/G0061) has used a malicious framework designed to impersonate the lsass.exe/vmtoolsd.exe token.(Citation: Bitdefender FIN8 July 2021)(Citation: Symantec FIN8 Jul 2023)

#### T1134.002 - Create Process with Token

Description:

Adversaries may create a new process with an existing token to escalate privileges and bypass access controls. Processes can be created with the token and resulting security context of another user using features such as <code>CreateProcessWithTokenW</code> and <code>runas</code>.(Citation: Microsoft RunAs)

Creating processes with a token not associated with the current user may require the credentials of the target user, specific privileges to impersonate that user, or access to the token to be used. For example, the token could be duplicated via [Token Impersonation/Theft](https://attack.mitre.org/techniques/T1134/001) or created via [Make and Impersonate Token](https://attack.mitre.org/techniques/T1134/003) before being used to create a process.

While this technique is distinct from [Token Impersonation/Theft](https://attack.mitre.org/techniques/T1134/001), the techniques can be used in conjunction where a token is duplicated and then used to create a new process.

Procedures:

- [S0344] Azorult: [Azorult](https://attack.mitre.org/software/S0344) can call WTSQueryUserToken and CreateProcessAsUser to start a new process with local system privileges.(Citation: Unit42 Azorult Nov 2018)
- [G0010] Turla: [Turla](https://attack.mitre.org/groups/G0010) RPC backdoors can impersonate or steal process tokens before executing commands.(Citation: ESET Turla PowerShell May 2019)
- [S0501] PipeMon: [PipeMon](https://attack.mitre.org/software/S0501) can attempt to gain administrative privileges using token impersonation.(Citation: ESET PipeMon May 2020)
- [G0032] Lazarus Group: [Lazarus Group](https://attack.mitre.org/groups/G0032) keylogger KiloAlfa obtains user tokens from interactive sessions to execute itself with API call <code>CreateProcessAsUserA</code> under that user's context.(Citation: Novetta Blockbuster)(Citation: Novetta Blockbuster Tools)
- [S0378] PoshC2: [PoshC2](https://attack.mitre.org/software/S0378) can use Invoke-RunAs to make tokens.(Citation: GitHub PoshC2)
- [S0456] Aria-body: [Aria-body](https://attack.mitre.org/software/S0456) has the ability to execute a process using <code>runas</code>.(Citation: CheckPoint Naikon May 2020)
- [S0496] REvil: [REvil](https://attack.mitre.org/software/S0496) can launch an instance of itself with administrative rights using runas.(Citation: Secureworks REvil September 2019)
- [S0412] ZxShell: [ZxShell](https://attack.mitre.org/software/S0412) has a command called RunAs, which creates a new process as another user or process context.(Citation: Talos ZxShell Oct 2014)
- [S0689] WhisperGate: The [WhisperGate](https://attack.mitre.org/software/S0689) third stage can use the AdvancedRun.exe tool to execute commands in the context of the Windows TrustedInstaller group via `%TEMP%\AdvancedRun.exe" /EXEFilename "C:\Windows\System32\sc.exe" /WindowState 0 /CommandLine "stop WinDefend" /StartDirectory "" /RunAs 8 /Run`.(Citation: Cisco Ukraine Wipers January 2022)
- [S0356] KONNI: [KONNI](https://attack.mitre.org/software/S0356) has duplicated the token of a high integrity process to spawn an instance of cmd.exe under an impersonated user.(Citation: Medium KONNI Jan 2020)(Citation: Malwarebytes Konni Aug 2021)
- [S0239] Bankshot: [Bankshot](https://attack.mitre.org/software/S0239) grabs a user token using WTSQueryUserToken and then creates a process by impersonating a logged-on user.(Citation: McAfee Bankshot)
- [S0363] Empire: [Empire](https://attack.mitre.org/software/S0363) can use <code>Invoke-RunAs</code> to make tokens.(Citation: Github PowerShell Empire)

#### T1134.003 - Make and Impersonate Token

Description:

Adversaries may make new tokens and impersonate users to escalate privileges and bypass access controls. For example, if an adversary has a username and password but the user is not logged onto the system the adversary can then create a logon session for the user using the `LogonUser` function.(Citation: LogonUserW function) The function will return a copy of the new session's access token and the adversary can use `SetThreadToken` to assign the token to a thread.

This behavior is distinct from [Token Impersonation/Theft](https://attack.mitre.org/techniques/T1134/001) in that this refers to creating a new user token instead of stealing or duplicating an existing one.

Procedures:

- [S1060] Mafalda: [Mafalda](https://attack.mitre.org/software/S1060) can create a token for a different user.(Citation: SentinelLabs Metador Technical Appendix Sept 2022)
- [G1043] BlackByte: [BlackByte](https://attack.mitre.org/groups/G1043) constructed a valid authentication token following Microsoft Exchange exploitation to allow for follow-on privileged command execution.(Citation: Microsoft BlackByte 2023)
- [G1016] FIN13: [FIN13](https://attack.mitre.org/groups/G1016) has utilized tools such as Incognito V2 for token manipulation and impersonation.(Citation: Sygnia Elephant Beetle Jan 2022)
- [S0692] SILENTTRINITY: [SILENTTRINITY](https://attack.mitre.org/software/S0692) can make tokens from known credentials.(Citation: Github_SILENTTRINITY)
- [S0154] Cobalt Strike: [Cobalt Strike](https://attack.mitre.org/software/S0154) can make tokens from known credentials.(Citation: cobaltstrike manual)

#### T1134.004 - Parent PID Spoofing

Description:

Adversaries may spoof the parent process identifier (PPID) of a new process to evade process-monitoring defenses or to elevate privileges. New processes are typically spawned directly from their parent, or calling, process unless explicitly specified. One way of explicitly assigning the PPID of a new process is via the <code>CreateProcess</code> API call, which supports a parameter that defines the PPID to use.(Citation: DidierStevens SelectMyParent Nov 2009) This functionality is used by Windows features such as User Account Control (UAC) to correctly set the PPID after a requested elevated process is spawned by SYSTEM (typically via <code>svchost.exe</code> or <code>consent.exe</code>) rather than the current user context.(Citation: Microsoft UAC Nov 2018)

Adversaries may abuse these mechanisms to evade defenses, such as those blocking processes spawning directly from Office documents, and analysis targeting unusual/potentially malicious parent-child process relationships, such as spoofing the PPID of [PowerShell](https://attack.mitre.org/techniques/T1059/001)/[Rundll32](https://attack.mitre.org/techniques/T1218/011) to be <code>explorer.exe</code> rather than an Office document delivered as part of [Spearphishing Attachment](https://attack.mitre.org/techniques/T1566/001).(Citation: CounterCept PPID Spoofing Dec 2018) This spoofing could be executed via [Visual Basic](https://attack.mitre.org/techniques/T1059/005) within a malicious Office document or any code that can perform [Native API](https://attack.mitre.org/techniques/T1106).(Citation: CTD PPID Spoofing Macro Mar 2019)(Citation: CounterCept PPID Spoofing Dec 2018)

Explicitly assigning the PPID may also enable elevated privileges given appropriate access rights to the parent process. For example, an adversary in a privileged user context (i.e. administrator) may spawn a new process and assign the parent as a process running as SYSTEM (such as <code>lsass.exe</code>), causing the new process to be elevated via the inherited access token.(Citation: XPNSec PPID Nov 2017)

Procedures:

- [S0356] KONNI: [KONNI](https://attack.mitre.org/software/S0356) has used parent PID spoofing to spawn a new `cmd` process using `CreateProcessW` and a handle to `Taskmgr.exe`.(Citation: Malwarebytes Konni Aug 2021)
- [S0154] Cobalt Strike: [Cobalt Strike](https://attack.mitre.org/software/S0154) can spawn processes with alternate PPIDs.(Citation: CobaltStrike Daddy May 2017)(Citation: Cobalt Strike Manual 4.3 November 2020)
- [S0501] PipeMon: [PipeMon](https://attack.mitre.org/software/S0501) can use parent PID spoofing to elevate privileges.(Citation: ESET PipeMon May 2020)
- [S1111] DarkGate: [DarkGate](https://attack.mitre.org/software/S1111) relies on parent PID spoofing as part of its "rootkit-like" functionality to evade detection via Task Manager or Process Explorer.(Citation: Trellix Darkgate 2023)

#### T1134.005 - SID-History Injection

Description:

Adversaries may use SID-History Injection to escalate privileges and bypass access controls. The Windows security identifier (SID) is a unique value that identifies a user or group account. SIDs are used by Windows security in both security descriptors and access tokens. (Citation: Microsoft SID) An account can hold additional SIDs in the SID-History Active Directory attribute (Citation: Microsoft SID-History Attribute), allowing inter-operable account migration between domains (e.g., all values in SID-History are included in access tokens).

With Domain Administrator (or equivalent) rights, harvested or well-known SID values (Citation: Microsoft Well Known SIDs Jun 2017) may be inserted into SID-History to enable impersonation of arbitrary users/groups such as Enterprise Administrators. This manipulation may result in elevated access to local resources and/or access to otherwise inaccessible domains via lateral movement techniques such as [Remote Services](https://attack.mitre.org/techniques/T1021), [SMB/Windows Admin Shares](https://attack.mitre.org/techniques/T1021/002), or [Windows Remote Management](https://attack.mitre.org/techniques/T1021/006).

Procedures:

- [S0002] Mimikatz: [Mimikatz](https://attack.mitre.org/software/S0002)'s <code>MISC::AddSid</code> module can append any SID or user/group account to a user's SID-History. [Mimikatz](https://attack.mitre.org/software/S0002) also utilizes [SID-History Injection](https://attack.mitre.org/techniques/T1134/005) to expand the scope of other components such as generated Kerberos Golden Tickets and DCSync beyond a single domain.(Citation: Adsecurity Mimikatz Guide)(Citation: AdSecurity Kerberos GT Aug 2015)
- [S0363] Empire: [Empire](https://attack.mitre.org/software/S0363) can add a SID-History to a user if on a domain controller.(Citation: Github PowerShell Empire)


### T1484 - Domain or Tenant Policy Modification

Description:

Adversaries may modify the configuration settings of a domain or identity tenant to evade defenses and/or escalate privileges in centrally managed environments. Such services provide a centralized means of managing identity resources such as devices and accounts, and often include configuration settings that may apply between domains or tenants such as trust relationships, identity syncing, or identity federation.

Modifications to domain or tenant settings may include altering domain Group Policy Objects (GPOs) in Microsoft Active Directory (AD) or changing trust settings for domains, including federation trusts relationships between domains or tenants.

With sufficient permissions, adversaries can modify domain or tenant policy settings. Since configuration settings for these services apply to a large number of identity resources, there are a great number of potential attacks malicious outcomes that can stem from this abuse. Examples of such abuse include:  

* modifying GPOs to push a malicious [Scheduled Task](https://attack.mitre.org/techniques/T1053/005) to computers throughout the domain environment(Citation: ADSecurity GPO Persistence 2016)(Citation: Wald0 Guide to GPOs)(Citation: Harmj0y Abusing GPO Permissions)
* modifying domain trusts to include an adversary-controlled domain, allowing adversaries to  forge access tokens that will subsequently be accepted by victim domain resources(Citation: Microsoft - Customer Guidance on Recent Nation-State Cyber Attacks)
* changing configuration settings within the AD environment to implement a [Rogue Domain Controller](https://attack.mitre.org/techniques/T1207).
* adding new, adversary-controlled federated identity providers to identity tenants, allowing adversaries to authenticate as any user managed by the victim tenant (Citation: Okta Cross-Tenant Impersonation 2023)

Adversaries may temporarily modify domain or tenant policy, carry out a malicious action(s), and then revert the change to remove suspicious indicators.

#### T1484.001 - Group Policy Modification

Description:

Adversaries may modify Group Policy Objects (GPOs) to subvert the intended discretionary access controls for a domain, usually with the intention of escalating privileges on the domain. Group policy allows for centralized management of user and computer settings in Active Directory (AD). GPOs are containers for group policy settings made up of files stored within a predictable network path `\<DOMAIN>\SYSVOL\<DOMAIN>\Policies\`.(Citation: TechNet Group Policy Basics)(Citation: ADSecurity GPO Persistence 2016) 

Like other objects in AD, GPOs have access controls associated with them. By default all user accounts in the domain have permission to read GPOs. It is possible to delegate GPO access control permissions, e.g. write access, to specific users or groups in the domain.

Malicious GPO modifications can be used to implement many other malicious behaviors such as [Scheduled Task/Job](https://attack.mitre.org/techniques/T1053), [Disable or Modify Tools](https://attack.mitre.org/techniques/T1562/001), [Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105), [Create Account](https://attack.mitre.org/techniques/T1136), [Service Execution](https://attack.mitre.org/techniques/T1569/002),  and more.(Citation: ADSecurity GPO Persistence 2016)(Citation: Wald0 Guide to GPOs)(Citation: Harmj0y Abusing GPO Permissions)(Citation: Mandiant M Trends 2016)(Citation: Microsoft Hacking Team Breach) Since GPOs can control so many user and machine settings in the AD environment, there are a great number of potential attacks that can stem from this GPO abuse.(Citation: Wald0 Guide to GPOs)

For example, publicly available scripts such as <code>New-GPOImmediateTask</code> can be leveraged to automate the creation of a malicious [Scheduled Task/Job](https://attack.mitre.org/techniques/T1053) by modifying GPO settings, in this case modifying <code>&lt;GPO_PATH&gt;\Machine\Preferences\ScheduledTasks\ScheduledTasks.xml</code>.(Citation: Wald0 Guide to GPOs)(Citation: Harmj0y Abusing GPO Permissions) In some cases an adversary might modify specific user rights like SeEnableDelegationPrivilege, set in <code>&lt;GPO_PATH&gt;\MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf</code>, to achieve a subtle AD backdoor with complete control of the domain because the user account under the adversary's control would then be able to modify GPOs.(Citation: Harmj0y SeEnableDelegationPrivilege Right)

Procedures:

- [S1058] Prestige: [Prestige](https://attack.mitre.org/software/S1058) has been deployed using the Default Domain Group Policy Object from an Active Directory Domain Controller.(Citation: Microsoft Prestige ransomware October 2022)
- [S1202] LockBit 3.0: [LockBit 3.0](https://attack.mitre.org/software/S1202) can enable options for propogation through Group Policy Objects.(Citation: Joint Cybersecurity Advisory LockBit 3.0 MAR 2023)
- [S0697] HermeticWiper: [HermeticWiper](https://attack.mitre.org/software/S0697) has the ability to deploy through an infected system's default domain policy.(Citation: ESET Hermetic Wizard March 2022)
- [G1021] Cinnamon Tempest: [Cinnamon Tempest](https://attack.mitre.org/groups/G1021) has used Group Policy to deploy batch scripts for ransomware deployment.(Citation: Microsoft Ransomware as a Service)
- [S0363] Empire: [Empire](https://attack.mitre.org/software/S0363) can use <code>New-GPOImmediateTask</code> to modify a GPO that will install and execute a malicious [Scheduled Task/Job](https://attack.mitre.org/techniques/T1053).(Citation: Github PowerShell Empire)
- [G0096] APT41: [APT41](https://attack.mitre.org/groups/G0096) used scheduled tasks created via Group Policy Objects (GPOs) to deploy ransomware.(Citation: apt41_mandiant)
- [S1199] LockBit 2.0: [LockBit 2.0](https://attack.mitre.org/software/S1199) can modify Group Policy to disable Windows Defender and to automatically infect devices in Windows domains.(Citation: FBI Lockbit 2.0 FEB 2022)(Citation: Palo Alto Lockbit 2.0 JUN 2022)
- [G0119] Indrik Spider: [Indrik Spider](https://attack.mitre.org/groups/G0119) has used Group Policy Objects to deploy batch scripts.(Citation: Crowdstrike Indrik November 2018)(Citation: Mandiant_UNC2165)
- [S0554] Egregor: [Egregor](https://attack.mitre.org/software/S0554) can modify the GPO to evade detection.(Citation: Cybereason Egregor Nov 2020) (Citation: Intrinsec Egregor Nov 2020)
- [S0688] Meteor: [Meteor](https://attack.mitre.org/software/S0688) can use group policy to push a scheduled task from the AD to all network machines.(Citation: Check Point Meteor Aug 2021)
- [C0034] 2022 Ukraine Electric Power Attack: During the [2022 Ukraine Electric Power Attack](https://attack.mitre.org/campaigns/C0034), [Sandworm Team](https://attack.mitre.org/groups/G0034) leveraged Group Policy Objects (GPOs) to deploy and execute malware.(Citation: Mandiant-Sandworm-Ukraine-2022)

#### T1484.002 - Trust Modification

Description:

Adversaries may add new domain trusts, modify the properties of existing domain trusts, or otherwise change the configuration of trust relationships between domains and tenants to evade defenses and/or elevate privileges.Trust details, such as whether or not user identities are federated, allow authentication and authorization properties to apply between domains or tenants for the purpose of accessing shared resources.(Citation: Microsoft - Azure AD Federation) These trust objects may include accounts, credentials, and other authentication material applied to servers, tokens, and domains.

Manipulating these trusts may allow an adversary to escalate privileges and/or evade defenses by modifying settings to add objects which they control. For example, in Microsoft Active Directory (AD) environments, this may be used to forge [SAML Tokens](https://attack.mitre.org/techniques/T1606/002) without the need to compromise the signing certificate to forge new credentials. Instead, an adversary can manipulate domain trusts to add their own signing certificate. An adversary may also convert an AD domain to a federated domain using Active Directory Federation Services (AD FS), which may enable malicious trust modifications such as altering the claim issuance rules to log in any valid set of credentials as a specified user.(Citation: AADInternals zure AD Federated Domain) 

An adversary may also add a new federated identity provider to an identity tenant such as Okta or AWS IAM Identity Center, which may enable the adversary to authenticate as any user of the tenant.(Citation: Okta Cross-Tenant Impersonation 2023) This may enable the threat actor to gain broad access into a variety of cloud-based services that leverage the identity tenant. For example, in AWS environments, an adversary that creates a new identity provider for an AWS Organization will be able to federate into all of the AWS Organization member accounts without creating identities for each of the member accounts.(Citation: AWS RE:Inforce Threat Detection 2024)

Procedures:

- [G1015] Scattered Spider: [Scattered Spider](https://attack.mitre.org/groups/G1015) adds a federated identity provider to the victim’s SSO tenant and activates automatic account linking.(Citation: CISA Scattered Spider Advisory November 2023)
- [S0677] AADInternals: [AADInternals](https://attack.mitre.org/software/S0677) can create a backdoor by converting a domain to a federated domain which will be able to authenticate any user across the tenant. [AADInternals](https://attack.mitre.org/software/S0677) can also modify DesktopSSO information.(Citation: AADInternals Documentation)(Citation: Azure AD Federation Vulnerability)
- [C0024] SolarWinds Compromise: During the [SolarWinds Compromise](https://attack.mitre.org/campaigns/C0024), [APT29](https://attack.mitre.org/groups/G0016) changed domain federation trust settings using Azure AD administrative permissions to configure the domain to accept authorization tokens signed by their own SAML signing certificate.(Citation: Secureworks IRON RITUAL Profile)(Citation: Microsoft 365 Defender Solorigate)


### T1543 - Create or Modify System Process

Description:

Adversaries may create or modify system-level processes to repeatedly execute malicious payloads as part of persistence. When operating systems boot up, they can start processes that perform background system functions. On Windows and Linux, these system processes are referred to as services.(Citation: TechNet Services) On macOS, launchd processes known as [Launch Daemon](https://attack.mitre.org/techniques/T1543/004) and [Launch Agent](https://attack.mitre.org/techniques/T1543/001) are run to finish system initialization and load user specific parameters.(Citation: AppleDocs Launch Agent Daemons) 

Adversaries may install new services, daemons, or agents that can be configured to execute at startup or a repeatable interval in order to establish persistence. Similarly, adversaries may modify existing services, daemons, or agents to achieve the same effect.  

Services, daemons, or agents may be created with administrator privileges but executed under root/SYSTEM privileges. Adversaries may leverage this functionality to create or modify system processes in order to escalate privileges.(Citation: OSX Malware Detection)

Procedures:

- [S1152] IMAPLoader: [IMAPLoader](https://attack.mitre.org/software/S1152) modifies Windows tasks on the victim machine to reference a retrieved PE file through a path modification.(Citation: PWC Yellow Liderc 2023)
- [S1194] Akira _v2: [Akira _v2](https://attack.mitre.org/software/S1194) can create a child process for encryption.(Citation: CISA Akira Ransomware APR 2024)
- [S1184] BOLDMOVE: [BOLDMOVE](https://attack.mitre.org/software/S1184) can free all resources and terminate itself on victim machines.(Citation: Google Cloud BOLDMOVE 2023)
- [S0401] Exaramel for Linux: [Exaramel for Linux](https://attack.mitre.org/software/S0401) has a hardcoded location that it uses to achieve persistence if the startup system is Upstart or System V and it is running as root.(Citation: ANSSI Sandworm January 2021)
- [S1121] LITTLELAMB.WOOLTEA: [LITTLELAMB.WOOLTEA](https://attack.mitre.org/software/S1121) can initialize itself as a daemon to run persistently in the background.(Citation: Mandiant Cutting Edge Part 3 February 2024)
- [S1142] LunarMail: [LunarMail](https://attack.mitre.org/software/S1142) can create an arbitrary process with a specified command line and redirect its output to a staging directory.(Citation: ESET Turla Lunar toolset May 2024)

#### T1543.001 - Launch Agent

Description:

Adversaries may create or modify launch agents to repeatedly execute malicious payloads as part of persistence. When a user logs in, a per-user launchd process is started which loads the parameters for each launch-on-demand user agent from the property list (.plist) file found in <code>/System/Library/LaunchAgents</code>, <code>/Library/LaunchAgents</code>, and <code>~/Library/LaunchAgents</code>.(Citation: AppleDocs Launch Agent Daemons)(Citation: OSX Keydnap malware) (Citation: Antiquated Mac Malware) Property list files use the <code>Label</code>, <code>ProgramArguments </code>, and <code>RunAtLoad</code> keys to identify the Launch Agent's name, executable location, and execution time.(Citation: OSX.Dok Malware) Launch Agents are often installed to perform updates to programs, launch user specified programs at login, or to conduct other developer tasks.

 Launch Agents can also be executed using the [Launchctl](https://attack.mitre.org/techniques/T1569/001) command.
 
Adversaries may install a new Launch Agent that executes at login by placing a .plist file into the appropriate folders with the <code>RunAtLoad</code> or <code>KeepAlive</code> keys set to <code>true</code>.(Citation: Sofacy Komplex Trojan)(Citation: Methods of Mac Malware Persistence) The Launch Agent name may be disguised by using a name from the related operating system or benign software. Launch Agents are created with user level privileges and execute with user level permissions.(Citation: OSX Malware Detection)(Citation: OceanLotus for OS X)

Procedures:

- [S0274] Calisto: [Calisto](https://attack.mitre.org/software/S0274) adds a .plist file to the /Library/LaunchAgents folder to maintain persistence.(Citation: Securelist Calisto July 2018)
- [S0279] Proton: [Proton](https://attack.mitre.org/software/S0279) persists via Launch Agent.(Citation: objsee mac malware 2017)
- [S0282] MacSpy: [MacSpy](https://attack.mitre.org/software/S0282) persists via a Launch Agent.(Citation: objsee mac malware 2017)
- [S0235] CrossRAT: [CrossRAT](https://attack.mitre.org/software/S0235) creates a Launch Agent on macOS.(Citation: Lookout Dark Caracal Jan 2018)
- [S0281] Dok: [Dok](https://attack.mitre.org/software/S0281) installs two LaunchAgents to redirect all network traffic with a randomly generated name for each plist file maintaining the format <code>com.random.name.plist</code>.(Citation: objsee mac malware 2017)(Citation: CheckPoint Dok)
- [S0497] Dacls: [Dacls](https://attack.mitre.org/software/S0497) can establish persistence via a LaunchAgent.(Citation: SentinelOne Lazarus macOS July 2020)(Citation: TrendMicro macOS Dacls May 2020)
- [S1016] MacMa: [MacMa](https://attack.mitre.org/software/S1016) installs a `com.apple.softwareupdate.plist` file in the `/LaunchAgents` folder with the `RunAtLoad` value set to `true`. Upon user login, [MacMa](https://attack.mitre.org/software/S1016) is executed from `/var/root/.local/softwareupdate` with root privileges. Some variations also include the `LimitLoadToSessionType` key with the value `Aqua`, ensuring the [MacMa](https://attack.mitre.org/software/S1016) only runs when there is a logged in GUI user.(Citation: ESET DazzleSpy Jan 2022)(Citation: Objective-See MacMa Nov 2021)
- [S0352] OSX_OCEANLOTUS.D: [OSX_OCEANLOTUS.D](https://attack.mitre.org/software/S0352) can create a persistence file in the folder <code>/Library/LaunchAgents</code>.(Citation: TrendMicro MacOS April 2018)(Citation: Trend Micro MacOS Backdoor November 2020)
- [S0482] Bundlore: [Bundlore](https://attack.mitre.org/software/S0482) can persist via a LaunchAgent.(Citation: MacKeeper Bundlore Apr 2019)
- [S0595] ThiefQuest: [ThiefQuest](https://attack.mitre.org/software/S0595) installs a launch item using an embedded encrypted launch agent property list template. The plist file is installed in the <code>~/Library/LaunchAgents/</code> folder and configured with the path to the persistent binary located in the <code>~/Library/</code> folder.(Citation: wardle evilquest parti)
- [S1048] macOS.OSAMiner: [macOS.OSAMiner](https://attack.mitre.org/software/S1048) has placed a [Stripped Payloads](https://attack.mitre.org/techniques/T1027/008) with a `plist` extension in the [Launch Agent](https://attack.mitre.org/techniques/T1543/001)'s folder. (Citation: SentinelLabs reversing run-only applescripts 2021)
- [S0369] CoinTicker: [CoinTicker](https://attack.mitre.org/software/S0369) creates user launch agents named .espl.plist and com.apple.[random string].plist to establish persistence.(Citation: CoinTicker 2019)
- [S0690] Green Lambert: [Green Lambert](https://attack.mitre.org/software/S0690) can create a [Launch Agent](https://attack.mitre.org/techniques/T1543/001) with the `RunAtLoad` key-value pair set to <code>true</code>, ensuring the `com.apple.GrowlHelper.plist` file runs every time a user logs in.(Citation: Objective See Green Lambert for OSX Oct 2021)(Citation: Glitch-Cat Green Lambert ATTCK Oct 2021)
- [S1153] Cuckoo Stealer: [Cuckoo Stealer](https://attack.mitre.org/software/S1153) can achieve persistence by creating launch agents to repeatedly execute malicious payloads.(Citation: Kandji Cuckoo April 2024)(Citation: SentinelOne Cuckoo Stealer May 2024)
- [S0492] CookieMiner: [CookieMiner](https://attack.mitre.org/software/S0492) has installed multiple new Launch Agents in order to maintain persistence for cryptocurrency mining software.(Citation: Unit42 CookieMiner Jan 2019)
- [S0277] FruitFly: [FruitFly](https://attack.mitre.org/software/S0277) persists via a Launch Agent.(Citation: objsee mac malware 2017)
- [S0162] Komplex: The [Komplex](https://attack.mitre.org/software/S0162) trojan creates a persistent launch agent called with <code>$HOME/Library/LaunchAgents/com.apple.updates.plist</code> with <code>launchctl load -w ~/Library/LaunchAgents/com.apple.updates.plist</code>.(Citation: Sofacy Komplex Trojan)
- [S0198] NETWIRE: [NETWIRE](https://attack.mitre.org/software/S0198) can use launch agents for persistence.(Citation: Red Canary NETWIRE January 2020)
- [S0276] Keydnap: [Keydnap](https://attack.mitre.org/software/S0276) uses a Launch Agent to persist.(Citation: synack 2016 review)

#### T1543.002 - Systemd Service

Description:

Adversaries may create or modify systemd services to repeatedly execute malicious payloads as part of persistence. Systemd is a system and service manager commonly used for managing background daemon processes (also known as services) and other system resources.(Citation: Linux man-pages: systemd January 2014) Systemd is the default initialization (init) system on many Linux distributions replacing legacy init systems, including SysVinit and Upstart, while remaining backwards compatible.  

Systemd utilizes unit configuration files with the `.service` file extension to encode information about a service's process. By default, system level unit files are stored in the `/systemd/system` directory of the root owned directories (`/`). User level unit files are stored in the `/systemd/user` directories of the user owned directories (`$HOME`).(Citation: lambert systemd 2022) 

Inside the `.service` unit files, the following directives are used to execute commands:(Citation: freedesktop systemd.service)  

* `ExecStart`, `ExecStartPre`, and `ExecStartPost` directives execute when a service is started manually by `systemctl` or on system start if the service is set to automatically start.
* `ExecReload` directive executes when a service restarts. 
* `ExecStop`, `ExecStopPre`, and `ExecStopPost` directives execute when a service is stopped.  

Adversaries have created new service files, altered the commands a `.service` file’s directive executes, and modified the user directive a `.service` file executes as, which could result in privilege escalation. Adversaries may also place symbolic links in these directories, enabling systemd to find these payloads regardless of where they reside on the filesystem.(Citation: Anomali Rocke March 2019)(Citation: airwalk backdoor unix systems)(Citation: Rapid7 Service Persistence 22JUNE2016) 

The `.service` file’s User directive can be used to run service as a specific user, which could result in privilege escalation based on specific user/group permissions. 

Systemd services can be created via systemd generators, which support the dynamic generation of unit files. Systemd generators are small executables that run during boot or configuration reloads to dynamically create or modify systemd unit files by converting non-native configurations into services, symlinks, or drop-ins (i.e., [Boot or Logon Initialization Scripts](https://attack.mitre.org/techniques/T1037)).(Citation: Elastic Security Labs Linux Persistence 2024)(Citation: Pepe Berba Systemd 2022)

Procedures:

- [G0139] TeamTNT: [TeamTNT](https://attack.mitre.org/groups/G0139) has established persistence through the creation of a cryptocurrency mining system service using <code>systemctl</code>.(Citation: Trend Micro TeamTNT)(Citation: Cisco Talos Intelligence Group)
- [S1198] Gomir: [Gomir](https://attack.mitre.org/software/S1198) creates a systemd service named `syslogd` for persistence.(Citation: Symantec Troll Stealer 2024)
- [C0034] 2022 Ukraine Electric Power Attack: During the [2022 Ukraine Electric Power Attack](https://attack.mitre.org/campaigns/C0034), [Sandworm Team](https://attack.mitre.org/groups/G0034) configured Systemd to maintain persistence of GOGETTER, specifying the `WantedBy=multi-user.target` configuration to run GOGETTER when the system begins accepting user logins.(Citation: Mandiant-Sandworm-Ukraine-2022)
- [S0192] Pupy: [Pupy](https://attack.mitre.org/software/S0192) can be used to establish persistence using a systemd service.(Citation: GitHub Pupy)
- [S0410] Fysbis: [Fysbis](https://attack.mitre.org/software/S0410) has established persistence using a systemd service.(Citation: Fysbis Dr Web Analysis)
- [S1078] RotaJakiro: Depending on the Linux distribution and when executing with root permissions, [RotaJakiro](https://attack.mitre.org/software/S1078) may install persistence using a `.service` file under the `/lib/systemd/system/` folder.(Citation: RotaJakiro 2021 netlab360 analysis)
- [S0663] SysUpdate: [SysUpdate](https://attack.mitre.org/software/S0663) can copy a script to the user owned `/usr/lib/systemd/system/` directory with a symlink mapped to a `root` owned directory, `/etc/ystem/system`, in the unit configuration file's `ExecStart` directive to establish persistence and elevate privileges.(Citation: Lunghi Iron Tiger Linux)
- [S0401] Exaramel for Linux: [Exaramel for Linux](https://attack.mitre.org/software/S0401) has a hardcoded location under systemd that it uses to achieve persistence if it is running as root.(Citation: ESET TeleBots Oct 2018)(Citation: ANSSI Sandworm January 2021)
- [G0106] Rocke: [Rocke](https://attack.mitre.org/groups/G0106) has installed a systemd service script to maintain persistence.(Citation: Anomali Rocke March 2019)
- [S0601] Hildegard: [Hildegard](https://attack.mitre.org/software/S0601) has started a monero service.(Citation: Unit 42 Hildegard Malware)

#### T1543.003 - Windows Service

Description:

Adversaries may create or modify Windows services to repeatedly execute malicious payloads as part of persistence. When Windows boots up, it starts programs or applications called services that perform background system functions.(Citation: TechNet Services) Windows service configuration information, including the file path to the service's executable or recovery programs/commands, is stored in the Windows Registry.

Adversaries may install a new service or modify an existing service to execute at startup in order to persist on a system. Service configurations can be set or modified using system utilities (such as sc.exe), by directly modifying the Registry, or by interacting directly with the Windows API. 

Adversaries may also use services to install and execute malicious drivers. For example, after dropping a driver file (ex: `.sys`) to disk, the payload can be loaded and registered via [Native API](https://attack.mitre.org/techniques/T1106) functions such as `CreateServiceW()` (or manually via functions such as `ZwLoadDriver()` and `ZwSetValueKey()`), by creating the required service Registry values (i.e. [Modify Registry](https://attack.mitre.org/techniques/T1112)), or by using command-line utilities such as `PnPUtil.exe`.(Citation: Symantec W.32 Stuxnet Dossier)(Citation: Crowdstrike DriveSlayer February 2022)(Citation: Unit42 AcidBox June 2020) Adversaries may leverage these drivers as [Rootkit](https://attack.mitre.org/techniques/T1014)s to hide the presence of malicious activity on a system. Adversaries may also load a signed yet vulnerable driver onto a compromised machine (known as "Bring Your Own Vulnerable Driver" (BYOVD)) as part of [Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1068).(Citation: ESET InvisiMole June 2020)(Citation: Unit42 AcidBox June 2020)

Services may be created with administrator privileges but are executed under SYSTEM privileges, so an adversary may also use a service to escalate privileges. Adversaries may also directly start services through [Service Execution](https://attack.mitre.org/techniques/T1569/002).

To make detection analysis more challenging, malicious services may also incorporate [Masquerade Task or Service](https://attack.mitre.org/techniques/T1036/004) (ex: using a service and/or payload name related to a legitimate OS or benign software component). Adversaries may also create ‘hidden’ services (i.e., [Hide Artifacts](https://attack.mitre.org/techniques/T1564)), for example by using the `sc sdset` command to set service permissions via the Service Descriptor Definition Language (SDDL). This may hide a Windows service from the view of standard service enumeration methods such as `Get-Service`, `sc query`, and `services.exe`.(Citation: SANS 1)(Citation: SANS 2)

Procedures:

- [S1090] NightClub: [NightClub](https://attack.mitre.org/software/S1090) has created a Windows service named `WmdmPmSp` to establish persistence.(Citation: MoustachedBouncer ESET August 2023)
- [S0604] Industroyer: [Industroyer](https://attack.mitre.org/software/S0604) can use an arbitrary system service to load at system boot for persistence and replaces the ImagePath registry value of a Windows service with a new backdoor binary.(Citation: Dragos Crashoverride 2017)
- [G0081] Tropic Trooper: [Tropic Trooper](https://attack.mitre.org/groups/G0081) has installed a service pointing to a malicious DLL dropped to disk.(Citation: PWC KeyBoys Feb 2017)
- [S1044] FunnyDream: [FunnyDream](https://attack.mitre.org/software/S1044) has established persistence by running `sc.exe` and by setting the `WSearch` service to run automatically.(Citation: Bitdefender FunnyDream Campaign November 2020)
- [S0141] Winnti for Windows: [Winnti for Windows](https://attack.mitre.org/software/S0141) sets its DLL file as a new service in the Registry to establish persistence.(Citation: Microsoft Winnti Jan 2017)
- [S0625] Cuba: [Cuba](https://attack.mitre.org/software/S0625) can modify services by using the <code>OpenService</code> and <code>ChangeServiceConfig</code> functions.(Citation: McAfee Cuba April 2021)
- [S0204] Briba: [Briba](https://attack.mitre.org/software/S0204) installs a service pointing to a malicious DLL dropped to disk.(Citation: Symantec Briba May 2012)
- [S1033] DCSrv: [DCSrv](https://attack.mitre.org/software/S1033) has created new services for persistence by modifying the Registry.(Citation: Checkpoint MosesStaff Nov 2021)
- [S0612] WastedLocker: [WastedLocker](https://attack.mitre.org/software/S0612) created and established a service that runs until the encryption process is complete.(Citation: NCC Group WastedLocker June 2020)
- [S0493] GoldenSpy: [GoldenSpy](https://attack.mitre.org/software/S0493) has established persistence by running in the background as an autostart service.(Citation: Trustwave GoldenSpy June 2020)
- [C0012] Operation CuckooBees: During [Operation CuckooBees](https://attack.mitre.org/campaigns/C0012), the threat actors modified the `IKEEXT` and `PrintNotify` Windows services for persistence.(Citation: Cybereason OperationCuckooBees May 2022)
- [G0105] DarkVishnya: [DarkVishnya](https://attack.mitre.org/groups/G0105) created new services for shellcode loaders distribution.(Citation: Securelist DarkVishnya Dec 2018)
- [S0180] Volgmer: [Volgmer](https://attack.mitre.org/software/S0180) installs a copy of itself in a randomly selected service, then overwrites the ServiceDLL entry in the service's Registry entry. Some [Volgmer](https://attack.mitre.org/software/S0180) variants also install .dll files as services with names generated by a list of hard-coded strings.(Citation: US-CERT Volgmer Nov 2017)(Citation: US-CERT Volgmer 2 Nov 2017)(Citation: Symantec Volgmer Aug 2014)
- [S0149] MoonWind: [MoonWind](https://attack.mitre.org/software/S0149) installs itself as a new service with automatic startup to establish persistence. The service checks every 60 seconds to determine if the malware is running; if not, it will spawn a new instance.(Citation: Palo Alto MoonWind March 2017)
- [S0050] CosmicDuke: [CosmicDuke](https://attack.mitre.org/software/S0050) uses Windows services typically named "javamtsup" for persistence.(Citation: F-Secure Cosmicduke)
- [S0012] PoisonIvy: [PoisonIvy](https://attack.mitre.org/software/S0012) creates a Registry subkey that registers a new service. [PoisonIvy](https://attack.mitre.org/software/S0012) also creates a Registry entry modifying the Logical Disk Manager service to point to a malicious DLL dropped to disk.(Citation: Symantec Darkmoon Aug 2005)
- [S1037] STARWHALE: [STARWHALE](https://attack.mitre.org/software/S1037) has the ability to create the following Windows service to establish persistence on an infected host: `sc create Windowscarpstss binpath= "cmd.exe /c cscript.exe c:\\windows\\system32\\w7_1.wsf humpback_whale" start= "auto" obj= "LocalSystem"`.(Citation: Mandiant UNC3313 Feb 2022)
- [S0230] ZeroT: [ZeroT](https://attack.mitre.org/software/S0230) can add a new service to ensure [PlugX](https://attack.mitre.org/software/S0013) persists on the system when delivered as another payload onto the system.(Citation: Proofpoint ZeroT Feb 2017)
- [S0666] Gelsemium: [Gelsemium](https://attack.mitre.org/software/S0666) can drop itself in `C:\Windows\System32\spool\prtprocs\x64\winprint.dll` as an alternative Print Processor to be loaded automatically when the spoolsv Windows service starts.(Citation: ESET Gelsemium June 2021)
- [G0143] Aquatic Panda: [Aquatic Panda](https://attack.mitre.org/groups/G0143) created new Windows services for persistence that masqueraded as legitimate Windows services via name change.(Citation: Crowdstrike HuntReport 2022)
- [G0082] APT38: [APT38](https://attack.mitre.org/groups/G0082) has installed a new Windows service to establish persistence.(Citation: CISA AA20-239A BeagleBoyz August 2020)
- [S0650] QakBot: [QakBot](https://attack.mitre.org/software/S0650) can remotely create a temporary service on a target host.(Citation: NCC Group Black Basta June 2022)
- [G0030] Lotus Blossom: [Lotus Blossom](https://attack.mitre.org/groups/G0030) has configured tools such as [Sagerunex](https://attack.mitre.org/software/S1210) to run as Windows services.(Citation: Cisco LotusBlossom 2025)
- [S0608] Conficker: [Conficker](https://attack.mitre.org/software/S0608) copies itself into the <code>%systemroot%\system32</code> directory and registers as a service.(Citation: SANS Conficker)
- [S0342] GreyEnergy: [GreyEnergy](https://attack.mitre.org/software/S0342) chooses a service, drops a DLL file, and writes it to that serviceDLL Registry key.(Citation: ESET GreyEnergy Oct 2018)
- [G0096] APT41: [APT41](https://attack.mitre.org/groups/G0096) modified legitimate Windows services to install malware backdoors.(Citation: FireEye APT41 Aug 2019)(Citation: Group IB APT 41 June 2021) [APT41](https://attack.mitre.org/groups/G0096) created the StorSyncSvc service to provide persistence for [Cobalt Strike](https://attack.mitre.org/software/S0154).(Citation: FireEye APT41 March 2020)
- [S0387] KeyBoy: [KeyBoy](https://attack.mitre.org/software/S0387) installs a service pointing to a malicious DLL dropped to disk.(Citation: Rapid7 KeyBoy Jun 2013)
- [G0102] Wizard Spider: [Wizard Spider](https://attack.mitre.org/groups/G0102) has installed [TrickBot](https://attack.mitre.org/software/S0266) as a service named ControlServiceA in order to establish persistence.(Citation: CrowdStrike Grim Spider May 2019)(Citation: Mandiant FIN12 Oct 2021)
- [S0081] Elise: [Elise](https://attack.mitre.org/software/S0081) configures itself as a service.(Citation: Lotus Blossom Jun 2015)
- [S0439] Okrum: To establish persistence, [Okrum](https://attack.mitre.org/software/S0439) can install itself as a new service named NtmSsvc.(Citation: ESET Okrum July 2019)
- [G0108] Blue Mockingbird: [Blue Mockingbird](https://attack.mitre.org/groups/G0108) has made their XMRIG payloads persistent as a Windows Service.(Citation: RedCanary Mockingbird May 2020)
- [G0139] TeamTNT: [TeamTNT](https://attack.mitre.org/groups/G0139) has used malware that adds cryptocurrency miners as a service.(Citation: ATT TeamTNT Chimaera September 2020)
- [S0584] AppleJeus: [AppleJeus](https://attack.mitre.org/software/S0584) can install itself as a service.(Citation: CISA AppleJeus Feb 2021)
- [G1043] BlackByte: [BlackByte](https://attack.mitre.org/groups/G1043) modified multiple services on victim machines to enable encryption operations.(Citation: Symantec BlackByte 2022) [BlackByte](https://attack.mitre.org/groups/G1043) has installed tools such as AnyDesk as a service on victim machines.(Citation: Microsoft BlackByte 2023)
- [S0567] Dtrack: [Dtrack](https://attack.mitre.org/software/S0567) can add a service called WBService to establish persistence.(Citation: CyberBit Dtrack)
- [S0603] Stuxnet: [Stuxnet](https://attack.mitre.org/software/S0603) uses a driver registered as a boot start service as the main load-point.(Citation: Nicolas Falliere, Liam O Murchu, Eric Chien February 2011)
- [S0350] zwShell: [zwShell](https://attack.mitre.org/software/S0350) has established persistence by adding itself as a new service.(Citation: McAfee Night Dragon)
- [S1202] LockBit 3.0: [LockBit 3.0](https://attack.mitre.org/software/S1202) can install system services for persistence.(Citation: Sentinel Labs LockBit 3.0 JUL 2022)
- [S0692] SILENTTRINITY: [SILENTTRINITY](https://attack.mitre.org/software/S0692) can establish persistence by creating a new service.(Citation: GitHub SILENTTRINITY Modules July 2019)
- [S0086] ZLib: [ZLib](https://attack.mitre.org/software/S0086) creates Registry keys to allow itself to run as various services.(Citation: Cylance Dust Storm)
- [S0268] Bisonal: [Bisonal](https://attack.mitre.org/software/S0268) has been modified to be used as a Windows service.(Citation: Talos Bisonal Mar 2020)
- [C0040] APT41 DUST: [APT41 DUST](https://attack.mitre.org/campaigns/C0040) used Windows Services with names such as `Windows Defend` for persistence of [DUSTPAN](https://attack.mitre.org/software/S1158).(Citation: Google Cloud APT41 2024)
- [S0029] PsExec: [PsExec](https://attack.mitre.org/software/S0029) can leverage Windows services to escalate privileges from administrator to SYSTEM with the <code>-s</code> argument.(Citation: Russinovich Sysinternals)
- [S0665] ThreatNeedle: [ThreatNeedle](https://attack.mitre.org/software/S0665) can run in memory and register its payload as a Windows service.(Citation: Kaspersky ThreatNeedle Feb 2021)
- [S0038] Duqu: [Duqu](https://attack.mitre.org/software/S0038) creates a new service that loads a malicious driver when the system starts. When Duqu is active, the operating system believes that the driver is legitimate, as it has been signed with a valid private key.(Citation: Symantec W32.Duqu)
- [G0073] APT19: An [APT19](https://attack.mitre.org/groups/G0073) Port 22 malware variant registers itself as a service.(Citation: Unit 42 C0d0so0 Jan 2016)
- [S0140] Shamoon: [Shamoon](https://attack.mitre.org/software/S0140) creates a new service named “ntssrv” to execute the payload. Newer versions create the "MaintenaceSrv" and "hdv_725x" services.(Citation: Palo Alto Shamoon Nov 2016)(Citation: Unit 42 Shamoon3 2018)
- [S0266] TrickBot: [TrickBot](https://attack.mitre.org/software/S0266) establishes persistence by creating an autostart service that allows it to run whenever the machine boots.(Citation: Trend Micro Trickbot Nov 2018)
- [S0142] StreamEx: [StreamEx](https://attack.mitre.org/software/S0142) establishes persistence by installing a new service pointing to its DLL and setting the service to auto-start.(Citation: Cylance Shell Crew Feb 2017)
- [S0236] Kwampirs: [Kwampirs](https://attack.mitre.org/software/S0236) creates a new service named WmiApSrvEx to establish persistence.(Citation: Symantec Orangeworm April 2018)
- [S0533] SLOTHFULMEDIA: [SLOTHFULMEDIA](https://attack.mitre.org/software/S0533) has created a service on victim machines named "TaskFrame" to establish persistence.(Citation: CISA MAR SLOTHFULMEDIA October 2020)
- [S0239] Bankshot: [Bankshot](https://attack.mitre.org/software/S0239) can terminate a specific process by its process id.(Citation: McAfee Bankshot)(Citation: US-CERT Bankshot Dec 2017)
- [S0154] Cobalt Strike: [Cobalt Strike](https://attack.mitre.org/software/S0154) can install a new service.(Citation: Cobalt Strike TTPs Dec 2017)
- [S0664] Pandora: [Pandora](https://attack.mitre.org/software/S0664) has the ability to gain system privileges through Windows services.(Citation: Trend Micro Iron Tiger April 2021)
- [S0495] RDAT: [RDAT](https://attack.mitre.org/software/S0495) has created a service when it is installed on the victim machine.(Citation: Unit42 RDAT July 2020)
- [S0194] PowerSploit: [PowerSploit](https://attack.mitre.org/software/S0194) contains a collection of Privesc-PowerUp modules that can discover and replace/modify service binaries, paths, and configs.(Citation: GitHub PowerSploit May 2012)(Citation: PowerSploit Documentation)
- [S0335] Carbon: [Carbon](https://attack.mitre.org/software/S0335) establishes persistence by creating a service and naming it based off the operating system version running on the current machine.(Citation: ESET Carbon Mar 2017)
- [G0027] Threat Group-3390: [Threat Group-3390](https://attack.mitre.org/groups/G0027)'s malware can create a new service, sometimes naming it after the config information, to gain persistence.(Citation: Nccgroup Emissary Panda May 2018)(Citation: Lunghi Iron Tiger Linux)
- [S0206] Wiarp: [Wiarp](https://attack.mitre.org/software/S0206) creates a backdoor through which remote attackers can create a service.(Citation: Symantec Wiarp May 2012)
- [S0210] Nerex: [Nerex](https://attack.mitre.org/software/S0210) creates a Registry subkey that registers a new service.(Citation: Symantec Nerex May 2012)
- [S0261] Catchamas: [Catchamas](https://attack.mitre.org/software/S0261) adds a new service named NetAdapter to establish persistence.(Citation: Symantec Catchamas April 2018)
- [S1099] Samurai: [Samurai](https://attack.mitre.org/software/S1099) can create a service at `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SvcHost` to trigger execution and maintain persistence.(Citation: Kaspersky ToddyCat June 2022)
- [S0203] Hydraq: [Hydraq](https://attack.mitre.org/software/S0203) creates new services to establish persistence.(Citation: Symantec Trojan.Hydraq Jan 2010)(Citation: Symantec Hydraq Jan 2010)(Citation: Symantec Hydraq Persistence Jan 2010)
- [S0013] PlugX: [PlugX](https://attack.mitre.org/software/S0013) can be added as a service to establish persistence. [PlugX](https://attack.mitre.org/software/S0013) also has a module to change service configurations as well as start, control, and delete services.(Citation: CIRCL PlugX March 2013)(Citation: Lastline PlugX Analysis)(Citation: PWC Cloud Hopper Technical Annex April 2017)(Citation: FireEye APT10 April 2017)(Citation: Proofpoint ZeroT Feb 2017)
- [G0004] Ke3chang: [Ke3chang](https://attack.mitre.org/groups/G0004) backdoor RoyalDNS established persistence through adding a service called <code>Nwsapagent</code>.(Citation: NCC Group APT15 Alive and Strong)
- [S0451] LoudMiner: [LoudMiner](https://attack.mitre.org/software/S0451) can automatically launch a Linux virtual machine as a service at startup if the AutoStart option is enabled in the VBoxVmService configuration file.(Citation: ESET LoudMiner June 2019)
- [G0056] PROMETHIUM: [PROMETHIUM](https://attack.mitre.org/groups/G0056) has created new services and modified existing services for persistence.(Citation: Bitdefender StrongPity June 2020)
- [S0438] Attor: [Attor](https://attack.mitre.org/software/S0438)'s dispatcher can establish persistence by registering a new service.(Citation: ESET Attor Oct 2019)
- [S0265] Kazuar: [Kazuar](https://attack.mitre.org/software/S0265) can install itself as a new service.(Citation: Unit 42 Kazuar May 2017)
- [S0386] Ursnif: [Ursnif](https://attack.mitre.org/software/S0386) has registered itself as a system service in the Registry for automatic execution at system startup.(Citation: TrendMicro PE_URSNIF.A2)
- [S1049] SUGARUSH: [SUGARUSH](https://attack.mitre.org/software/S1049) has created a service named `Service1` for persistence.(Citation: Mandiant UNC3890 Aug 2022)
- [C0025] 2016 Ukraine Electric Power Attack: During the [2016 Ukraine Electric Power Attack](https://attack.mitre.org/campaigns/C0025), [Sandworm Team](https://attack.mitre.org/groups/G0034) used an arbitrary system service to load at system boot for persistence for [Industroyer](https://attack.mitre.org/software/S0604). They also replaced the ImagePath registry value of a Windows service with a new backdoor binary. (Citation: Dragos Crashoverride 2017)
- [S0071] hcdLoader: [hcdLoader](https://attack.mitre.org/software/S0071) installs itself as a service for persistence.(Citation: Dell Lateral Movement)(Citation: ThreatStream Evasion Analysis)
- [S0570] BitPaymer: [BitPaymer](https://attack.mitre.org/software/S0570) has attempted to install itself as a service to maintain persistence.(Citation: Crowdstrike Indrik November 2018)
- [S1031] PingPull: [PingPull](https://attack.mitre.org/software/S1031) has the ability to install itself as a service.(Citation: Unit 42 PingPull Jun 2022)
- [S0004] TinyZBot: [TinyZBot](https://attack.mitre.org/software/S0004) can install as a Windows service for persistence.(Citation: Cylance Cleaver)
- [S0343] Exaramel for Windows: The [Exaramel for Windows](https://attack.mitre.org/software/S0343) dropper creates and starts a Windows service named wsmprovav with the description “Windows Check AV.”(Citation: ESET TeleBots Oct 2018)
- [S0504] Anchor: [Anchor](https://attack.mitre.org/software/S0504) can establish persistence by creating a service.(Citation: Cyberreason Anchor December 2019)
- [G0049] OilRig: [OilRig](https://attack.mitre.org/groups/G0049) has used a compromised Domain Controller to create a service on a remote host.(Citation: Symantec Crambus OCT 2023)
- [S0356] KONNI: [KONNI](https://attack.mitre.org/software/S0356) has registered itself as a service using its export function.(Citation: Malwarebytes Konni Aug 2021)
- [S0412] ZxShell: [ZxShell](https://attack.mitre.org/software/S0412) can create a new service using the service parser function ProcessScCommand.(Citation: Talos ZxShell Oct 2014)
- [S1211] Hannotog: [Hannotog](https://attack.mitre.org/software/S1211) creates a new service for persistence.(Citation: Symantec Bilbug 2022)
- [S0629] RainyDay: [RainyDay](https://attack.mitre.org/software/S0629) can use services to establish persistence.(Citation: Bitdefender Naikon April 2021)
- [S0127] BBSRAT: [BBSRAT](https://attack.mitre.org/software/S0127) can modify service configurations.(Citation: Palo Alto Networks BBSRAT)
- [S0260] InvisiMole: [InvisiMole](https://attack.mitre.org/software/S0260) can register a Windows service named CsPower as part of its execution chain, and a Windows service named clr_optimization_v2.0.51527_X86 to achieve persistence.(Citation: ESET InvisiMole June 2020)
- [G0050] APT32: [APT32](https://attack.mitre.org/groups/G0050) modified Windows Services to ensure PowerShell scripts were loaded on the system. [APT32](https://attack.mitre.org/groups/G0050) also creates a Windows service to establish persistence.(Citation: ESET OceanLotus)(Citation: Cybereason Cobalt Kitty 2017)(Citation: ESET OceanLotus Mar 2019)
- [S0560] TEARDROP: [TEARDROP](https://attack.mitre.org/software/S0560) ran as a Windows service from the <code>c:\windows\syswow64</code> folder.(Citation: Check Point Sunburst Teardrop December 2020)(Citation: FireEye SUNBURST Backdoor December 2020)
- [S0630] Nebulae: [Nebulae](https://attack.mitre.org/software/S0630) can create a service to establish persistence.(Citation: Bitdefender Naikon April 2021)
- [S0182] FinFisher: [FinFisher](https://attack.mitre.org/software/S0182) creates a new Windows service with the malicious executable for persistence.(Citation: FinFisher Citation)(Citation: Microsoft FinFisher March 2018)
- [S0491] StrongPity: [StrongPity](https://attack.mitre.org/software/S0491) has created new services and modified existing services for persistence.(Citation: Talos Promethium June 2020)
- [S1070] Black Basta: [Black Basta](https://attack.mitre.org/software/S1070) can create a new service to establish persistence.(Citation: Minerva Labs Black Basta May 2022)(Citation: Avertium Black Basta June 2022)
- [S0345] Seasalt: [Seasalt](https://attack.mitre.org/software/S0345) is capable of installing itself as a service.(Citation: Mandiant APT1 Appendix)
- [S0176] Wingbird: [Wingbird](https://attack.mitre.org/software/S0176) uses services.exe to register a new autostart service named "Audit Service" using a copy of the local lsass.exe file.(Citation: Microsoft SIR Vol 21)(Citation: Microsoft Wingbird Nov 2017)
- [C0006] Operation Honeybee: During [Operation Honeybee](https://attack.mitre.org/campaigns/C0006), threat actors installed DLLs and backdoors as Windows services.(Citation: McAfee Honeybee)
- [S0032] gh0st RAT: [gh0st RAT](https://attack.mitre.org/software/S0032) can create a new service to establish persistence.(Citation: Nccgroup Gh0st April 2018)(Citation: Gh0stRAT ATT March 2019)
- [G0008] Carbanak: [Carbanak](https://attack.mitre.org/groups/G0008) malware installs itself as a service to provide persistence and SYSTEM privileges.(Citation: Kaspersky Carbanak)
- [S0022] Uroburos: [Uroburos](https://attack.mitre.org/software/S0022) has registered a service, typically named `WerFaultSvc`, to decrypt and find a kernel driver and kernel driver loader to maintain persistence.(Citation: Joint Cybersecurity Advisory AA23-129A Snake Malware May 2023)
- [S0044] JHUHUGIT: [JHUHUGIT](https://attack.mitre.org/software/S0044) has registered itself as a service to establish persistence.(Citation: ESET Sednit Part 1)
- [S0205] Naid: [Naid](https://attack.mitre.org/software/S0205) creates a new service to establish.(Citation: Symantec Naid June 2012)
- [S0481] Ragnar Locker: [Ragnar Locker](https://attack.mitre.org/software/S0481) has used sc.exe to create a new service for the VirtualBox driver.(Citation: Sophos Ragnar May 2020)
- [S1100] Ninja: [Ninja](https://attack.mitre.org/software/S1100) can create the services `httpsvc` and `w3esvc` for persistence .(Citation: Kaspersky ToddyCat June 2022)
- [G0022] APT3: [APT3](https://attack.mitre.org/groups/G0022) has a tool that creates a new service for persistence.(Citation: FireEye Operation Double Tap)
- [G0046] FIN7: [FIN7](https://attack.mitre.org/groups/G0046) created new Windows services and added them to the startup directories for persistence.(Citation: FireEye FIN7 Aug 2018)
- [S0259] InnaputRAT: Some [InnaputRAT](https://attack.mitre.org/software/S0259) variants create a new Windows service to establish persistence.(Citation: ASERT InnaputRAT April 2018)
- [G1030] Agrius: [Agrius](https://attack.mitre.org/groups/G1030) has deployed [IPsec Helper](https://attack.mitre.org/software/S1132) malware post-exploitation and registered it as a service for persistence.(Citation: SentinelOne Agrius 2021)
- [S0089] BlackEnergy: One variant of [BlackEnergy](https://attack.mitre.org/software/S0089) creates a new service using either a hard-coded or randomly generated name.(Citation: F-Secure BlackEnergy 2014)
- [G0094] Kimsuky: [Kimsuky](https://attack.mitre.org/groups/G0094) has created new services for persistence.(Citation: Securelist Kimsuky Sept 2013)(Citation: CISA AA20-301A Kimsuky)
- [S0444] ShimRat: [ShimRat](https://attack.mitre.org/software/S0444) has installed a Windows service to maintain persistence on victim machines.(Citation: FOX-IT May 2016 Mofang)
- [S0046] CozyCar: One persistence mechanism used by [CozyCar](https://attack.mitre.org/software/S0046) is to register itself as a Windows service.(Citation: F-Secure CozyDuke)
- [S0660] Clambling: [Clambling](https://attack.mitre.org/software/S0660) can register itself as a system service to gain persistence.(Citation: Talent-Jump Clambling February 2020)
- [S0263] TYPEFRAME: [TYPEFRAME](https://attack.mitre.org/software/S0263) variants can add malicious DLL modules as new services.[TYPEFRAME](https://attack.mitre.org/software/S0263) can also delete services from the victim’s machine.(Citation: US-CERT TYPEFRAME June 2018)
- [S0697] HermeticWiper: [HermeticWiper](https://attack.mitre.org/software/S0697) can load drivers by creating a new service using the `CreateServiceW` API.(Citation: Crowdstrike DriveSlayer February 2022)
- [G1006] Earth Lusca: [Earth Lusca](https://attack.mitre.org/groups/G1006) created a service using the command <code>sc create “SysUpdate” binpath= “cmd /c start “[file path]””&&sc config “SysUpdate” start= auto&&net
start SysUpdate</code> for persistence.(Citation: TrendMicro EarthLusca 2022)
- [S0169] RawPOS: [RawPOS](https://attack.mitre.org/software/S0169) installs itself as a service to maintain persistence.(Citation: Kroll RawPOS Jan 2017)(Citation: TrendMicro RawPOS April 2015)(Citation: Mandiant FIN5 GrrCON Oct 2016)
- [G0080] Cobalt Group: [Cobalt Group](https://attack.mitre.org/groups/G0080) has created new services to establish persistence.(Citation: Group IB Cobalt Aug 2017)
- [S0074] Sakula: Some [Sakula](https://attack.mitre.org/software/S0074) samples install themselves as services for persistence by calling WinExec with the <code>net start</code> argument.(Citation: Dell Sakula)
- [S0164] TDTESS: If running as administrator, [TDTESS](https://attack.mitre.org/software/S0164) installs itself as a new service named bmwappushservice to establish persistence.(Citation: ClearSky Wilted Tulip July 2017)
- [G0032] Lazarus Group: Several [Lazarus Group](https://attack.mitre.org/groups/G0032) malware families install themselves as new services.(Citation: Novetta Blockbuster)(Citation: Novetta Blockbuster Destructive Malware)
- [S0347] AuditCred: [AuditCred](https://attack.mitre.org/software/S0347) is installed as a new service on the system.(Citation: TrendMicro Lazarus Nov 2018)
- [S0501] PipeMon: [PipeMon](https://attack.mitre.org/software/S0501) can establish persistence by registering a malicious DLL as an alternative Print Processor which is loaded when the print spooler service starts.(Citation: ESET PipeMon May 2020)
- [G1021] Cinnamon Tempest: [Cinnamon Tempest](https://attack.mitre.org/groups/G1021) has created system services to establish persistence for deployed tooling.(Citation: Sygnia Emperor Dragonfly October 2022)
- [S0024] Dyre: [Dyre](https://attack.mitre.org/software/S0024) registers itself as a service by adding several Registry keys.(Citation: Symantec Dyre June 2015)
- [S0082] Emissary: [Emissary](https://attack.mitre.org/software/S0082) is capable of configuring itself as a service.(Citation: Emissary Trojan Feb 2016)
- [S0363] Empire: [Empire](https://attack.mitre.org/software/S0363) can utilize built-in modules to modify service binaries and restore them to their original state.(Citation: Github PowerShell Empire)
- [S0367] Emotet: [Emotet](https://attack.mitre.org/software/S0367) has been observed creating new services to maintain persistence.(Citation: US-CERT Emotet Jul 2018)(Citation: Secureworks Emotet Nov 2018)(Citation: Binary Defense Emotes Wi-Fi Spreader)
- [S1158] DUSTPAN: [DUSTPAN](https://attack.mitre.org/software/S1158) can persist as a Windows Service in operations.(Citation: Google Cloud APT41 2024)
- [S0172] Reaver: [Reaver](https://attack.mitre.org/software/S0172) installs itself as a new service.(Citation: Palo Alto Reaver Nov 2017)
- [S0181] FALLCHILL: [FALLCHILL](https://attack.mitre.org/software/S0181) has been installed as a Windows service.(Citation: CISA AppleJeus Feb 2021)
- [S0663] SysUpdate: [SysUpdate](https://attack.mitre.org/software/S0663) can create a service to establish persistence.(Citation: Trend Micro Iron Tiger April 2021)
- [S0118] Nidiran: [Nidiran](https://attack.mitre.org/software/S0118) can create a new service named msamger (Microsoft Security Accounts Manager).(Citation: Symantec Backdoor.Nidiran)
- [S0366] WannaCry: [WannaCry](https://attack.mitre.org/software/S0366) creates the service "mssecsvc2.0" with the display name "Microsoft Security Center (2.0) Service."(Citation: LogRhythm WannaCry)(Citation: FireEye WannaCry 2017)

#### T1543.004 - Launch Daemon

Description:

Adversaries may create or modify Launch Daemons to execute malicious payloads as part of persistence. Launch Daemons are plist files used to interact with Launchd, the service management framework used by macOS. Launch Daemons require elevated privileges to install, are executed for every user on a system prior to login, and run in the background without the need for user interaction. During the macOS initialization startup, the launchd process loads the parameters for launch-on-demand system-level daemons from plist files found in <code>/System/Library/LaunchDaemons/</code> and <code>/Library/LaunchDaemons/</code>. Required Launch Daemons parameters include a <code>Label</code> to identify the task, <code>Program</code> to provide a path to the executable, and <code>RunAtLoad</code> to specify when the task is run. Launch Daemons are often used to provide access to shared resources, updates to software, or conduct automation tasks.(Citation: AppleDocs Launch Agent Daemons)(Citation: Methods of Mac Malware Persistence)(Citation: launchd Keywords for plists)

Adversaries may install a Launch Daemon configured to execute at startup by using the <code>RunAtLoad</code> parameter set to <code>true</code> and the <code>Program</code> parameter set to the malicious executable path. The daemon name may be disguised by using a name from a related operating system or benign software (i.e. [Masquerading](https://attack.mitre.org/techniques/T1036)). When the Launch Daemon is executed, the program inherits administrative permissions.(Citation: WireLurker)(Citation: OSX Malware Detection)

Additionally, system configuration changes (such as the installation of third party package managing software) may cause folders such as <code>usr/local/bin</code> to become globally writeable. So, it is possible for poor configurations to allow an adversary to modify executables referenced by current Launch Daemon's plist files.(Citation: LaunchDaemon Hijacking)(Citation: sentinelone macos persist Jun 2019)

Procedures:

- [S0690] Green Lambert: [Green Lambert](https://attack.mitre.org/software/S0690) can add a plist file in the `Library/LaunchDaemons` to establish persistence.(Citation: Objective See Green Lambert for OSX Oct 2021)(Citation: Glitch-Cat Green Lambert ATTCK Oct 2021)
- [S1105] COATHANGER: [COATHANGER](https://attack.mitre.org/software/S1105) will create a daemon for timed check-ins with command and control infrastructure.(Citation: NCSC-NL COATHANGER Feb 2024)
- [S0595] ThiefQuest: When running with root privileges after a [Launch Agent](https://attack.mitre.org/techniques/T1543/001) is installed, [ThiefQuest](https://attack.mitre.org/software/S0595) installs a plist file to the <code>/Library/LaunchDaemons/</code> folder with the <code>RunAtLoad</code> key set to <code>true</code> establishing persistence as a Launch Daemon. (Citation: wardle evilquest parti)
- [S0451] LoudMiner: [LoudMiner](https://attack.mitre.org/software/S0451) adds plist files with the naming format <code>com.[random_name].plist</code> in the <code>/Library/LaunchDaemons</code> folder with the RunAtLoad and KeepAlive keys set to <code>true</code>.(Citation: ESET LoudMiner June 2019)
- [S0352] OSX_OCEANLOTUS.D: If running with <code>root</code> permissions, [OSX_OCEANLOTUS.D](https://attack.mitre.org/software/S0352) can create a persistence file in the folder <code>/Library/LaunchDaemons</code>.(Citation: TrendMicro MacOS April 2018)(Citation: sentinelone apt32 macOS backdoor 2020)
- [S0482] Bundlore: [Bundlore](https://attack.mitre.org/software/S0482) can persist via a LaunchDaemon.(Citation: MacKeeper Bundlore Apr 2019)
- [S0497] Dacls: [Dacls](https://attack.mitre.org/software/S0497) can establish persistence via a Launch Daemon.(Citation: SentinelOne Lazarus macOS July 2020)(Citation: TrendMicro macOS Dacls May 2020)
- [S0658] XCSSET: [XCSSET](https://attack.mitre.org/software/S0658) uses the ssh launchdaemon to elevate privileges, bypass system controls, and enable remote access to the victim.(Citation: trendmicro xcsset xcode project 2020)
- [S0584] AppleJeus: [AppleJeus](https://attack.mitre.org/software/S0584) has placed a plist file within the <code>LaunchDaemons</code> folder and launched it manually.(Citation: CISA AppleJeus Feb 2021)(Citation: ObjectiveSee AppleJeus 2019)

#### T1543.005 - Container Service

Description:

Adversaries may create or modify container or container cluster management tools that run as daemons, agents, or services on individual hosts. These include software for creating and managing individual containers, such as Docker and Podman, as well as container cluster node-level agents such as kubelet. By modifying these services, an adversary may be able to achieve persistence or escalate their privileges on a host.

For example, by using the `docker run` or `podman run` command with the `restart=always` directive, a container can be configured to persistently restart on the host.(Citation: AquaSec TeamTNT 2023) A user with access to the (rootful) docker command may also be able to escalate their privileges on the host.(Citation: GTFOBins Docker)

In Kubernetes environments, DaemonSets allow an adversary to persistently [Deploy Container](https://attack.mitre.org/techniques/T1610)s on all nodes, including ones added later to the cluster.(Citation: Aquasec Kubernetes Attack 2023)(Citation: Kubernetes DaemonSet) Pods can also be deployed to specific nodes using the `nodeSelector` or `nodeName` fields in the pod spec.(Citation: Kubernetes Assigning Pods to Nodes)(Citation: AppSecco Kubernetes Namespace Breakout 2020)

Note that containers can also be configured to run as [Systemd Service](https://attack.mitre.org/techniques/T1543/002)s.(Citation: Podman Systemd)(Citation: Docker Systemd)


### T1546 - Event Triggered Execution

Description:

Adversaries may establish persistence and/or elevate privileges using system mechanisms that trigger execution based on specific events. Various operating systems have means to monitor and subscribe to events such as logons or other user activity such as running specific applications/binaries. Cloud environments may also support various functions and services that monitor and can be invoked in response to specific cloud events.(Citation: Backdooring an AWS account)(Citation: Varonis Power Automate Data Exfiltration)(Citation: Microsoft DART Case Report 001)

Adversaries may abuse these mechanisms as a means of maintaining persistent access to a victim via repeatedly executing malicious code. After gaining access to a victim system, adversaries may create/modify event triggers to point to malicious content that will be executed whenever the event trigger is invoked.(Citation: FireEye WMI 2015)(Citation: Malware Persistence on OS X)(Citation: amnesia malware)

Since the execution can be proxied by an account with higher permissions, such as SYSTEM or service accounts, an adversary may be able to abuse these triggered execution mechanisms to escalate their privileges.

Procedures:

- [S1091] Pacu: [Pacu](https://attack.mitre.org/software/S1091) can set up S3 bucket notifications to trigger a malicious Lambda function when a CloudFormation template is uploaded to the bucket. It can also create Lambda functions that trigger upon the creation of users, roles, and groups.(Citation: GitHub Pacu)
- [C0035] KV Botnet Activity: [KV Botnet Activity](https://attack.mitre.org/campaigns/C0035) involves managing events on victim systems via <code>libevent</code> to execute a callback function when any running process contains the following references in their path without also having a reference to <code>bioset</code>: busybox, wget, curl, tftp, telnetd, or lua. If the <code>bioset</code> string is not found, the related process is terminated.(Citation: Lumen KVBotnet 2023)
- [S1164] UPSTYLE: [UPSTYLE](https://attack.mitre.org/software/S1164) creates a `.pth` file beginning with the text `import` so that any time another process or script attempts to reference the modified item the malicious code will also run.(Citation: Volexity UPSTYLE 2024)
- [S0658] XCSSET: [XCSSET](https://attack.mitre.org/software/S0658)'s `dfhsebxzod` module searches for `.xcodeproj` directories within the user’s home folder and subdirectories. For each match, it locates the corresponding `project.pbxproj` file and embeds an encoded payload into a build rule, target configuration, or project setting. The payload is later executed during the build process.(Citation: Microsoft March 2025 XCSSET)(Citation: April 2021 TrendMicro XCSSET)

#### T1546.001 - Change Default File Association

Description:

Adversaries may establish persistence by executing malicious content triggered by a file type association. When a file is opened, the default program used to open the file (also called the file association or handler) is checked. File association selections are stored in the Windows Registry and can be edited by users, administrators, or programs that have Registry access or by administrators using the built-in assoc utility.(Citation: Microsoft Change Default Programs)(Citation: Microsoft File Handlers)(Citation: Microsoft Assoc Oct 2017) Applications can modify the file association for a given file extension to call an arbitrary program when a file with the given extension is opened.

System file associations are listed under <code>HKEY_CLASSES_ROOT\.[extension]</code>, for example <code>HKEY_CLASSES_ROOT\.txt</code>. The entries point to a handler for that extension located at <code>HKEY_CLASSES_ROOT\\[handler]</code>. The various commands are then listed as subkeys underneath the shell key at <code>HKEY_CLASSES_ROOT\\[handler]\shell\\[action]\command</code>. For example: 

* <code>HKEY_CLASSES_ROOT\txtfile\shell\open\command</code>
* <code>HKEY_CLASSES_ROOT\txtfile\shell\print\command</code>
* <code>HKEY_CLASSES_ROOT\txtfile\shell\printto\command</code>

The values of the keys listed are commands that are executed when the handler opens the file extension. Adversaries can modify these values to continually execute arbitrary commands.(Citation: TrendMicro TROJ-FAKEAV OCT 2012)

Procedures:

- [S0692] SILENTTRINITY: [SILENTTRINITY](https://attack.mitre.org/software/S0692) can conduct an image hijack of an `.msc` file extension as part of its UAC bypass process.(Citation: GitHub SILENTTRINITY Modules July 2019)
- [G0094] Kimsuky: [Kimsuky](https://attack.mitre.org/groups/G0094) has a HWP document stealer module which changes the default program association in the registry to open HWP documents.(Citation: Securelist Kimsuky Sept 2013)

#### T1546.002 - Screensaver

Description:

Adversaries may establish persistence by executing malicious content triggered by user inactivity. Screensavers are programs that execute after a configurable time of user inactivity and consist of Portable Executable (PE) files with a .scr file extension.(Citation: Wikipedia Screensaver) The Windows screensaver application scrnsave.scr is located in <code>C:\Windows\System32\</code>, and <code>C:\Windows\sysWOW64\</code>  on 64-bit Windows systems, along with screensavers included with base Windows installations.

The following screensaver settings are stored in the Registry (<code>HKCU\Control Panel\Desktop\</code>) and could be manipulated to achieve persistence:

* <code>SCRNSAVE.exe</code> - set to malicious PE path
* <code>ScreenSaveActive</code> - set to '1' to enable the screensaver
* <code>ScreenSaverIsSecure</code> - set to '0' to not require a password to unlock
* <code>ScreenSaveTimeout</code> - sets user inactivity timeout before screensaver is executed

Adversaries can use screensaver settings to maintain persistence by setting the screensaver to run malware after a certain timeframe of user inactivity.(Citation: ESET Gazer Aug 2017)

Procedures:

- [S0168] Gazer: [Gazer](https://attack.mitre.org/software/S0168) can establish persistence through the system screensaver by configuring it to execute the malware.(Citation: ESET Gazer Aug 2017)

#### T1546.003 - Windows Management Instrumentation Event Subscription

Description:

Adversaries may establish persistence and elevate privileges by executing malicious content triggered by a Windows Management Instrumentation (WMI) event subscription. WMI can be used to install event filters, providers, consumers, and bindings that execute code when a defined event occurs. Examples of events that may be subscribed to are the wall clock time, user login, or the computer's uptime.(Citation: Mandiant M-Trends 2015)

Adversaries may use the capabilities of WMI to subscribe to an event and execute arbitrary code when that event occurs, providing persistence on a system.(Citation: FireEye WMI SANS 2015)(Citation: FireEye WMI 2015) Adversaries may also compile WMI scripts – using `mofcomp.exe`  –into Windows Management Object (MOF) files (.mof extension) that can be used to create a malicious subscription.(Citation: Dell WMI Persistence)(Citation: Microsoft MOF May 2018)

WMI subscription execution is proxied by the WMI Provider Host process (WmiPrvSe.exe) and thus may result in elevated SYSTEM privileges.

Procedures:

- [G0108] Blue Mockingbird: [Blue Mockingbird](https://attack.mitre.org/groups/G0108) has used mofcomp.exe to establish WMI Event Subscription persistence mechanisms configured from a *.mof file.(Citation: RedCanary Mockingbird May 2020)
- [S1085] Sardonic: [Sardonic](https://attack.mitre.org/software/S1085) can use a WMI event filter to invoke a command-line event consumer to gain persistence.(Citation: Bitdefender Sardonic Aug 2021)
- [G0016] APT29: [APT29](https://attack.mitre.org/groups/G0016) has used WMI event subscriptions for persistence.(Citation: Mandiant No Easy Breach)
- [S1059] metaMain: [metaMain](https://attack.mitre.org/software/S1059) registered a WMI event subscription consumer called "hard_disk_stat" to establish persistence.(Citation: SentinelLabs Metador Sept 2022)
- [G1001] HEXANE: [HEXANE](https://attack.mitre.org/groups/G1001) has used WMI event subscriptions for persistence.(Citation: Kaspersky Lyceum October 2021)
- [G0061] FIN8: [FIN8](https://attack.mitre.org/groups/G0061) has used WMI event subscriptions for persistence.(Citation: Bitdefender FIN8 July 2021)
- [S0511] RegDuke: [RegDuke](https://attack.mitre.org/software/S0511) can persist using a WMI consumer that is launched every time a process named WINWORD.EXE is started.(Citation: ESET Dukes October 2019)
- [S0692] SILENTTRINITY: [SILENTTRINITY](https://attack.mitre.org/software/S0692) can create a WMI Event to execute a payload for persistence.(Citation: GitHub SILENTTRINITY Modules July 2019)
- [G0065] Leviathan: [Leviathan](https://attack.mitre.org/groups/G0065) has used WMI for persistence.(Citation: FireEye Periscope March 2018)
- [S0376] HOPLIGHT: [HOPLIGHT](https://attack.mitre.org/software/S0376) can use WMI event subscriptions to create persistence.(Citation: US-CERT HOPLIGHT Apr 2019)
- [C0024] SolarWinds Compromise: During the [SolarWinds Compromise](https://attack.mitre.org/campaigns/C0024), [APT29](https://attack.mitre.org/groups/G0016) used a WMI event filter to invoke a command-line event consumer at system boot time to launch a backdoor with `rundll32.exe`.(Citation: Microsoft Deep Dive Solorigate January 2021)(Citation: Microsoft 365 Defender Solorigate)
- [G0010] Turla: [Turla](https://attack.mitre.org/groups/G0010) has used WMI event filters and consumers to establish persistence.(Citation: ESET Turla PowerShell May 2019)
- [G1013] Metador: [Metador](https://attack.mitre.org/groups/G1013) has established persistence through the use of a WMI event subscription combined with unusual living-off-the-land binaries such as `cdb.exe`.(Citation: SentinelLabs Metador Sept 2022)
- [G0064] APT33: [APT33](https://attack.mitre.org/groups/G0064) has attempted to use WMI event subscriptions to establish persistence on compromised hosts.(Citation: Microsoft Holmium June 2020)
- [S1081] BADHATCH: [BADHATCH](https://attack.mitre.org/software/S1081) can use WMI event subscriptions for persistence.(Citation: BitDefender BADHATCH Mar 2021)
- [S1020] Kevin: [Kevin](https://attack.mitre.org/software/S1020) can compile randomly-generated MOF files into the WMI repository to persistently run malware.(Citation: Kaspersky Lyceum October 2021)
- [C0023] Operation Ghost: During [Operation Ghost](https://attack.mitre.org/campaigns/C0023), [APT29](https://attack.mitre.org/groups/G0016) used WMI event subscriptions to establish persistence for malware.(Citation: ESET Dukes October 2019)
- [G0129] Mustang Panda: [Mustang Panda](https://attack.mitre.org/groups/G0129)'s custom ORat tool uses a WMI event consumer to maintain persistence.(Citation: Secureworks BRONZE PRESIDENT December 2019)
- [S0202] adbupd: [adbupd](https://attack.mitre.org/software/S0202) can use a WMI script to achieve persistence.(Citation: Microsoft PLATINUM April 2016)
- [G0075] Rancor: [Rancor](https://attack.mitre.org/groups/G0075) has complied VBScript-generated MOF files into WMI event subscriptions for persistence.(Citation: Rancor WMI)
- [S0053] SeaDuke: [SeaDuke](https://attack.mitre.org/software/S0053) uses an event filter in WMI code to execute a previously dropped executable shortly after system startup.(Citation: FireEye WMI 2015)
- [S0150] POSHSPY: [POSHSPY](https://attack.mitre.org/software/S0150) uses a WMI event subscription to establish persistence.(Citation: FireEye POSHSPY April 2017)
- [S0378] PoshC2: [PoshC2](https://attack.mitre.org/software/S0378) has the ability to persist on a system using WMI events.(Citation: GitHub PoshC2)
- [S0682] TrailBlazer: [TrailBlazer](https://attack.mitre.org/software/S0682) has the ability to use WMI for persistence.(Citation: CrowdStrike StellarParticle January 2022)
- [S0371] POWERTON: [POWERTON](https://attack.mitre.org/software/S0371) can use WMI for persistence.(Citation: FireEye APT33 Guardrail)

#### T1546.004 - Unix Shell Configuration Modification

Description:

Adversaries may establish persistence through executing malicious commands triggered by a user’s shell. User [Unix Shell](https://attack.mitre.org/techniques/T1059/004)s execute several configuration scripts at different points throughout the session based on events. For example, when a user opens a command-line interface or remotely logs in (such as via SSH) a login shell is initiated. The login shell executes scripts from the system (<code>/etc</code>) and the user’s home directory (<code>~/</code>) to configure the environment. All login shells on a system use /etc/profile when initiated. These configuration scripts run at the permission level of their directory and are often used to set environment variables, create aliases, and customize the user’s environment. When the shell exits or terminates, additional shell scripts are executed to ensure the shell exits appropriately. 

Adversaries may attempt to establish persistence by inserting commands into scripts automatically executed by shells. Using bash as an example, the default shell for most GNU/Linux systems, adversaries may add commands that launch malicious binaries into the <code>/etc/profile</code> and <code>/etc/profile.d</code> files.(Citation: intezer-kaiji-malware)(Citation: bencane blog bashrc) These files typically require root permissions to modify and are executed each time any shell on a system launches. For user level permissions, adversaries can insert malicious commands into <code>~/.bash_profile</code>, <code>~/.bash_login</code>, or <code>~/.profile</code> which are sourced when a user opens a command-line interface or connects remotely.(Citation: anomali-rocke-tactics)(Citation: Linux manual bash invocation) Since the system only executes the first existing file in the listed order, adversaries have used <code>~/.bash_profile</code> to ensure execution. Adversaries have also leveraged the <code>~/.bashrc</code> file which is additionally executed if the connection is established remotely or an additional interactive shell is opened, such as a new tab in the command-line interface.(Citation: Tsunami)(Citation: anomali-rocke-tactics)(Citation: anomali-linux-rabbit)(Citation: Magento) Some malware targets the termination of a program to trigger execution, adversaries can use the <code>~/.bash_logout</code> file to execute malicious commands at the end of a session. 

For macOS, the functionality of this technique is similar but may leverage zsh, the default shell for macOS 10.15+. When the Terminal.app is opened, the application launches a zsh login shell and a zsh interactive shell. The login shell configures the system environment using <code>/etc/profile</code>, <code>/etc/zshenv</code>, <code>/etc/zprofile</code>, and <code>/etc/zlogin</code>.(Citation: ScriptingOSX zsh)(Citation: PersistentJXA_leopitt)(Citation: code_persistence_zsh)(Citation: macOS MS office sandbox escape) The login shell then configures the user environment with <code>~/.zprofile</code> and <code>~/.zlogin</code>. The interactive shell uses the <code>~/.zshrc</code> to configure the user environment. Upon exiting, <code>/etc/zlogout</code> and <code>~/.zlogout</code> are executed. For legacy programs, macOS executes <code>/etc/bashrc</code> on startup.

Procedures:

- [S1078] RotaJakiro: When executing with non-root level permissions, [RotaJakiro](https://attack.mitre.org/software/S1078) can install persistence by adding a command to the .bashrc file that executes a binary in the  `${HOME}/.gvfsd/.profile/` folder.(Citation: RotaJakiro 2021 netlab360 analysis)
- [S0362] Linux Rabbit: [Linux Rabbit](https://attack.mitre.org/software/S0362) maintains persistence on an infected machine through rc.local and .bashrc files. (Citation: Anomali Linux Rabbit 2018)
- [C0045] ShadowRay: During [ShadowRay](https://attack.mitre.org/campaigns/C0045), threat actors executed commands on interactive and reverse shells.(Citation: Oligo ShadowRay Campaign MAR 2024)
- [S0690] Green Lambert: [Green Lambert](https://attack.mitre.org/software/S0690) can establish persistence on a compromised host through modifying the `profile`, `login`, and run command (rc) files associated with the `bash`, `csh`, and `tcsh` shells. (Citation: Objective See Green Lambert for OSX Oct 2021)(Citation: Glitch-Cat Green Lambert ATTCK Oct 2021)
- [S0658] XCSSET: Using [AppleScript](https://attack.mitre.org/techniques/T1059/002), [XCSSET](https://attack.mitre.org/software/S0658) adds it's executable to the user's `~/.zshrc_aliases` file (`"echo " & payload & " > ~/zshrc_aliases"`), it then adds a line to the .zshrc file to source the `.zshrc_aliases` file (`[ -f $HOME/.zshrc_aliases ] && . $HOME/.zshrc_aliases`). Each time the user starts a new `zsh` terminal session, the `.zshrc` file executes the `.zshrc_aliases` file.(Citation: Microsoft March 2025 XCSSET)

#### T1546.005 - Trap

Description:

Adversaries may establish persistence by executing malicious content triggered by an interrupt signal. The <code>trap</code> command allows programs and shells to specify commands that will be executed upon receiving interrupt signals. A common situation is a script allowing for graceful termination and handling of common keyboard interrupts like <code>ctrl+c</code> and <code>ctrl+d</code>.

Adversaries can use this to register code to be executed when the shell encounters specific interrupts as a persistence mechanism. Trap commands are of the following format <code>trap 'command list' signals</code> where "command list" will be executed when "signals" are received.(Citation: Trap Manual)(Citation: Cyberciti Trap Statements)

#### T1546.006 - LC_LOAD_DYLIB Addition

Description:

Adversaries may establish persistence by executing malicious content triggered by the execution of tainted binaries. Mach-O binaries have a series of headers that are used to perform certain operations when a binary is loaded. The LC_LOAD_DYLIB header in a Mach-O binary tells macOS and OS X which dynamic libraries (dylibs) to load during execution time. These can be added ad-hoc to the compiled binary as long as adjustments are made to the rest of the fields and dependencies.(Citation: Writing Bad Malware for OSX) There are tools available to perform these changes.

Adversaries may modify Mach-O binary headers to load and execute malicious dylibs every time the binary is executed. Although any changes will invalidate digital signatures on binaries because the binary is being modified, this can be remediated by simply removing the LC_CODE_SIGNATURE command from the binary so that the signature isn’t checked at load time.(Citation: Malware Persistence on OS X)

#### T1546.007 - Netsh Helper DLL

Description:

Adversaries may establish persistence by executing malicious content triggered by Netsh Helper DLLs. Netsh.exe (also referred to as Netshell) is a command-line scripting utility used to interact with the network configuration of a system. It contains functionality to add helper DLLs for extending functionality of the utility.(Citation: TechNet Netsh) The paths to registered netsh.exe helper DLLs are entered into the Windows Registry at <code>HKLM\SOFTWARE\Microsoft\Netsh</code>.

Adversaries can use netsh.exe helper DLLs to trigger execution of arbitrary code in a persistent manner. This execution would take place anytime netsh.exe is executed, which could happen automatically, with another persistence technique, or if other software (ex: VPN) is present on the system that executes netsh.exe as part of its normal functionality.(Citation: Github Netsh Helper CS Beacon)(Citation: Demaske Netsh Persistence)

Procedures:

- [S0108] netsh: [netsh](https://attack.mitre.org/software/S0108) can be used as a persistence proxy technique to execute a helper DLL when netsh.exe is executed.(Citation: Demaske Netsh Persistence)

#### T1546.008 - Accessibility Features

Description:

Adversaries may establish persistence and/or elevate privileges by executing malicious content triggered by accessibility features. Windows contains accessibility features that may be launched with a key combination before a user has logged in (ex: when the user is on the Windows logon screen). An adversary can modify the way these programs are launched to get a command prompt or backdoor without logging in to the system.

Two common accessibility programs are <code>C:\Windows\System32\sethc.exe</code>, launched when the shift key is pressed five times and <code>C:\Windows\System32\utilman.exe</code>, launched when the Windows + U key combination is pressed. The sethc.exe program is often referred to as "sticky keys", and has been used by adversaries for unauthenticated access through a remote desktop login screen. (Citation: FireEye Hikit Rootkit)

Depending on the version of Windows, an adversary may take advantage of these features in different ways. Common methods used by adversaries include replacing accessibility feature binaries or pointers/references to these binaries in the Registry. In newer versions of Windows, the replaced binary needs to be digitally signed for x64 systems, the binary must reside in <code>%systemdir%\</code>, and it must be protected by Windows File or Resource Protection (WFP/WRP). (Citation: DEFCON2016 Sticky Keys) The [Image File Execution Options Injection](https://attack.mitre.org/techniques/T1546/012) debugger method was likely discovered as a potential workaround because it does not require the corresponding accessibility feature binary to be replaced.

For simple binary replacement on Windows XP and later as well as and Windows Server 2003/R2 and later, for example, the program (e.g., <code>C:\Windows\System32\utilman.exe</code>) may be replaced with "cmd.exe" (or another program that provides backdoor access). Subsequently, pressing the appropriate key combination at the login screen while sitting at the keyboard or when connected over [Remote Desktop Protocol](https://attack.mitre.org/techniques/T1021/001) will cause the replaced file to be executed with SYSTEM privileges. (Citation: Tilbury 2014)

Other accessibility features exist that may also be leveraged in a similar fashion: (Citation: DEFCON2016 Sticky Keys)(Citation: Narrator Accessibility Abuse)

* On-Screen Keyboard: <code>C:\Windows\System32\osk.exe</code>
* Magnifier: <code>C:\Windows\System32\Magnify.exe</code>
* Narrator: <code>C:\Windows\System32\Narrator.exe</code>
* Display Switcher: <code>C:\Windows\System32\DisplaySwitch.exe</code>
* App Switcher: <code>C:\Windows\System32\AtBroker.exe</code>

Procedures:

- [S0363] Empire: [Empire](https://attack.mitre.org/software/S0363) can leverage WMI debugging to remotely replace binaries like sethc.exe, Utilman.exe, and Magnify.exe with cmd.exe.(Citation: Github PowerShell Empire)
- [G0096] APT41: [APT41](https://attack.mitre.org/groups/G0096) leveraged sticky keys to establish persistence.(Citation: FireEye APT41 Aug 2019)
- [G0022] APT3: [APT3](https://attack.mitre.org/groups/G0022) replaces the Sticky Keys binary <code>C:\Windows\System32\sethc.exe</code> for persistence.(Citation: aptsim)
- [G0009] Deep Panda: [Deep Panda](https://attack.mitre.org/groups/G0009) has used the sticky-keys technique to bypass the RDP login screen on remote systems during intrusions.(Citation: RSA Shell Crew)
- [G0001] Axiom: [Axiom](https://attack.mitre.org/groups/G0001) actors have been known to use the Sticky Keys replacement within RDP sessions to obtain persistence.(Citation: Novetta-Axiom)
- [G0117] Fox Kitten: [Fox Kitten](https://attack.mitre.org/groups/G0117) has used sticky keys to launch a command prompt.(Citation: CISA AA20-259A Iran-Based Actor September 2020)
- [G0016] APT29: [APT29](https://attack.mitre.org/groups/G0016) used sticky-keys to obtain unauthenticated, privileged console access.(Citation: Mandiant No Easy Breach)(Citation: FireEye APT29 Domain Fronting)

#### T1546.009 - AppCert DLLs

Description:

Adversaries may establish persistence and/or elevate privileges by executing malicious content triggered by AppCert DLLs loaded into processes. Dynamic-link libraries (DLLs) that are specified in the <code>AppCertDLLs</code> Registry key under <code>HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\</code> are loaded into every process that calls the ubiquitously used application programming interface (API) functions <code>CreateProcess</code>, <code>CreateProcessAsUser</code>, <code>CreateProcessWithLoginW</code>, <code>CreateProcessWithTokenW</code>, or <code>WinExec</code>. (Citation: Elastic Process Injection July 2017)

Similar to [Process Injection](https://attack.mitre.org/techniques/T1055), this value can be abused to obtain elevated privileges by causing a malicious DLL to be loaded and run in the context of separate processes on the computer. Malicious AppCert DLLs may also provide persistence by continuously being triggered by API activity.

Procedures:

- [S0196] PUNCHBUGGY: [PUNCHBUGGY](https://attack.mitre.org/software/S0196) can establish using a AppCertDLLs Registry key.(Citation: FireEye Know Your Enemy FIN8 Aug 2016)

#### T1546.010 - AppInit DLLs

Description:

Adversaries may establish persistence and/or elevate privileges by executing malicious content triggered by AppInit DLLs loaded into processes. Dynamic-link libraries (DLLs) that are specified in the <code>AppInit_DLLs</code> value in the Registry keys <code>HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Windows</code> or <code>HKEY_LOCAL_MACHINE\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows</code> are loaded by user32.dll into every process that loads user32.dll. In practice this is nearly every program, since user32.dll is a very common library. (Citation: Elastic Process Injection July 2017)

Similar to Process Injection, these values can be abused to obtain elevated privileges by causing a malicious DLL to be loaded and run in the context of separate processes on the computer. (Citation: AppInit Registry) Malicious AppInit DLLs may also provide persistence by continuously being triggered by API activity. 

The AppInit DLL functionality is disabled in Windows 8 and later versions when secure boot is enabled. (Citation: AppInit Secure Boot)

Procedures:

- [G0087] APT39: [APT39](https://attack.mitre.org/groups/G0087) has used malware to set <code>LoadAppInit_DLLs</code> in the Registry key <code>SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows</code> in order to establish persistence.(Citation: FBI FLASH APT39 September 2020)
- [S0098] T9000: If a victim meets certain criteria, [T9000](https://attack.mitre.org/software/S0098) uses the AppInit_DLL functionality to achieve persistence by ensuring that every user mode process that is spawned will load its malicious DLL, ResN32.dll. It does this by creating the following Registry keys: <code>HKLM\Software\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs – %APPDATA%\Intel\ResN32.dll</code> and <code>HKLM\Software\Microsoft\Windows NT\CurrentVersion\Windows\LoadAppInit_DLLs – 0x1</code>.(Citation: Palo Alto T9000 Feb 2016)
- [S0107] Cherry Picker: Some variants of [Cherry Picker](https://attack.mitre.org/software/S0107) use AppInit_DLLs to achieve persistence by creating the following Registry key: <code>HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows "AppInit_DLLs"="pserver32.dll"</code>(Citation: Trustwave Cherry Picker)
- [S0458] Ramsay: [Ramsay](https://attack.mitre.org/software/S0458) can insert itself into the address space of other applications using the AppInit DLL Registry key.(Citation: Eset Ramsay May 2020)

#### T1546.011 - Application Shimming

Description:

Adversaries may establish persistence and/or elevate privileges by executing malicious content triggered by application shims. The Microsoft Windows Application Compatibility Infrastructure/Framework (Application Shim) was created to allow for backward compatibility of software as the operating system codebase changes over time. For example, the application shimming feature allows developers to apply fixes to applications (without rewriting code) that were created for Windows XP so that it will work with Windows 10. (Citation: Elastic Process Injection July 2017)

Within the framework, shims are created to act as a buffer between the program (or more specifically, the Import Address Table) and the Windows OS. When a program is executed, the shim cache is referenced to determine if the program requires the use of the shim database (.sdb). If so, the shim database uses hooking to redirect the code as necessary in order to communicate with the OS. 

A list of all shims currently installed by the default Windows installer (sdbinst.exe) is kept in:

* <code>%WINDIR%\AppPatch\sysmain.sdb</code> and
* <code>hklm\software\microsoft\windows nt\currentversion\appcompatflags\installedsdb</code>

Custom databases are stored in:

* <code>%WINDIR%\AppPatch\custom & %WINDIR%\AppPatch\AppPatch64\Custom</code> and
* <code>hklm\software\microsoft\windows nt\currentversion\appcompatflags\custom</code>

To keep shims secure, Windows designed them to run in user mode so they cannot modify the kernel and you must have administrator privileges to install a shim. However, certain shims can be used to [Bypass User Account Control](https://attack.mitre.org/techniques/T1548/002) (UAC and RedirectEXE), inject DLLs into processes (InjectDLL), disable Data Execution Prevention (DisableNX) and Structure Exception Handling (DisableSEH), and intercept memory addresses (GetProcAddress).

Utilizing these shims may allow an adversary to perform several malicious acts such as elevate privileges, install backdoors, disable defenses like Windows Defender, etc. (Citation: FireEye Application Shimming) Shims can also be abused to establish persistence by continuously being invoked by affected programs.

Procedures:

- [S0517] Pillowmint: [Pillowmint](https://attack.mitre.org/software/S0517) has used a malicious shim database to maintain persistence.(Citation: Trustwave Pillowmint June 2020)
- [S0461] SDBbot: [SDBbot](https://attack.mitre.org/software/S0461) has the ability to use application shimming for persistence if it detects it is running as admin on Windows XP or 7, by creating a shim database to patch services.exe.(Citation: Proofpoint TA505 October 2019)
- [G0046] FIN7: [FIN7](https://attack.mitre.org/groups/G0046) has used application shim databases for persistence.(Citation: FireEye FIN7 Shim Databases)
- [S0444] ShimRat: [ShimRat](https://attack.mitre.org/software/S0444) has installed shim databases in the <code>AppPatch</code> folder.(Citation: FOX-IT May 2016 Mofang)

#### T1546.012 - Image File Execution Options Injection

Description:

Adversaries may establish persistence and/or elevate privileges by executing malicious content triggered by Image File Execution Options (IFEO) debuggers. IFEOs enable a developer to attach a debugger to an application. When a process is created, a debugger present in an application’s IFEO will be prepended to the application’s name, effectively launching the new process under the debugger (e.g., <code>C:\dbg\ntsd.exe -g  notepad.exe</code>). (Citation: Microsoft Dev Blog IFEO Mar 2010)

IFEOs can be set directly via the Registry or in Global Flags via the GFlags tool. (Citation: Microsoft GFlags Mar 2017) IFEOs are represented as <code>Debugger</code> values in the Registry under <code>HKLM\SOFTWARE{\Wow6432Node}\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\<executable></code> where <code>&lt;executable&gt;</code> is the binary on which the debugger is attached. (Citation: Microsoft Dev Blog IFEO Mar 2010)

IFEOs can also enable an arbitrary monitor program to be launched when a specified program silently exits (i.e. is prematurely terminated by itself or a second, non kernel-mode process). (Citation: Microsoft Silent Process Exit NOV 2017) (Citation: Oddvar Moe IFEO APR 2018) Similar to debuggers, silent exit monitoring can be enabled through GFlags and/or by directly modifying IFEO and silent process exit Registry values in <code>HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\</code>. (Citation: Microsoft Silent Process Exit NOV 2017) (Citation: Oddvar Moe IFEO APR 2018)

Similar to [Accessibility Features](https://attack.mitre.org/techniques/T1546/008), on Windows Vista and later as well as Windows Server 2008 and later, a Registry key may be modified that configures "cmd.exe," or another program that provides backdoor access, as a "debugger" for an accessibility program (ex: utilman.exe). After the Registry is modified, pressing the appropriate key combination at the login screen while at the keyboard or when connected with [Remote Desktop Protocol](https://attack.mitre.org/techniques/T1021/001) will cause the "debugger" program to be executed with SYSTEM privileges. (Citation: Tilbury 2014)

Similar to [Process Injection](https://attack.mitre.org/techniques/T1055), these values may also be abused to obtain privilege escalation by causing a malicious executable to be loaded and run in the context of separate processes on the computer. (Citation: Elastic Process Injection July 2017) Installing IFEO mechanisms may also provide Persistence via continuous triggered invocation.

Malware may also use IFEO to [Impair Defenses](https://attack.mitre.org/techniques/T1562) by registering invalid debuggers that redirect and effectively disable various system and security applications. (Citation: FSecure Hupigon) (Citation: Symantec Ushedix June 2008)

Procedures:

- [S0559] SUNBURST: [SUNBURST](https://attack.mitre.org/software/S0559) created an Image File Execution Options (IFEO) Debugger registry value for the process <code>dllhost.exe</code> to trigger the installation of [Cobalt Strike](https://attack.mitre.org/software/S0154).(Citation: Microsoft Deep Dive Solorigate January 2021)
- [S0461] SDBbot: [SDBbot](https://attack.mitre.org/software/S0461) has the ability to use image file execution options for persistence if it detects it is running with admin privileges on a Windows version newer than Windows 7.(Citation: Proofpoint TA505 October 2019)
- [C0032] C0032: During the [C0032](https://attack.mitre.org/campaigns/C0032) campaign, [TEMP.Veles](https://attack.mitre.org/groups/G0088) modified and added entries within <code>HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options</code> to maintain persistence.(Citation: FireEye TRITON 2019)

#### T1546.013 - PowerShell Profile

Description:

Adversaries may gain persistence and elevate privileges by executing malicious content triggered by PowerShell profiles. A PowerShell profile  (<code>profile.ps1</code>) is a script that runs when [PowerShell](https://attack.mitre.org/techniques/T1059/001) starts and can be used as a logon script to customize user environments.

[PowerShell](https://attack.mitre.org/techniques/T1059/001) supports several profiles depending on the user or host program. For example, there can be different profiles for [PowerShell](https://attack.mitre.org/techniques/T1059/001) host programs such as the PowerShell console, PowerShell ISE or Visual Studio Code. An administrator can also configure a profile that applies to all users and host programs on the local computer. (Citation: Microsoft About Profiles) 

Adversaries may modify these profiles to include arbitrary commands, functions, modules, and/or [PowerShell](https://attack.mitre.org/techniques/T1059/001) drives to gain persistence. Every time a user opens a [PowerShell](https://attack.mitre.org/techniques/T1059/001) session the modified script will be executed unless the <code>-NoProfile</code> flag is used when it is launched. (Citation: ESET Turla PowerShell May 2019) 

An adversary may also be able to escalate privileges if a script in a PowerShell profile is loaded and executed by an account with higher privileges, such as a domain administrator. (Citation: Wits End and Shady PowerShell Profiles)

Procedures:

- [G0010] Turla: [Turla](https://attack.mitre.org/groups/G0010) has used PowerShell profiles to maintain persistence on an infected machine.(Citation: ESET Turla PowerShell May 2019)

#### T1546.014 - Emond

Description:

Adversaries may gain persistence and elevate privileges by executing malicious content triggered by the Event Monitor Daemon (emond). Emond is a [Launch Daemon](https://attack.mitre.org/techniques/T1543/004) that accepts events from various services, runs them through a simple rules engine, and takes action. The emond binary at <code>/sbin/emond</code> will load any rules from the <code>/etc/emond.d/rules/</code> directory and take action once an explicitly defined event takes place.

The rule files are in the plist format and define the name, event type, and action to take. Some examples of event types include system startup and user authentication. Examples of actions are to run a system command or send an email. The emond service will not launch if there is no file present in the QueueDirectories path <code>/private/var/db/emondClients</code>, specified in the [Launch Daemon](https://attack.mitre.org/techniques/T1543/004) configuration file at<code>/System/Library/LaunchDaemons/com.apple.emond.plist</code>.(Citation: xorrior emond Jan 2018)(Citation: magnusviri emond Apr 2016)(Citation: sentinelone macos persist Jun 2019)

Adversaries may abuse this service by writing a rule to execute commands when a defined event occurs, such as system start up or user authentication.(Citation: xorrior emond Jan 2018)(Citation: magnusviri emond Apr 2016)(Citation: sentinelone macos persist Jun 2019) Adversaries may also be able to escalate privileges from administrator to root as the emond service is executed with root privileges by the [Launch Daemon](https://attack.mitre.org/techniques/T1543/004) service.

#### T1546.015 - Component Object Model Hijacking

Description:

Adversaries may establish persistence by executing malicious content triggered by hijacked references to Component Object Model (COM) objects. COM is a system within Windows to enable interaction between software components through the operating system.(Citation: Microsoft Component Object Model)  References to various COM objects are stored in the Registry. 

Adversaries can use the COM system to insert malicious code that can be executed in place of legitimate software through hijacking the COM references and relationships as a means for persistence. Hijacking a COM object requires a change in the Registry to replace a reference to a legitimate system component which may cause that component to not work when executed. When that system component is executed through normal system operation the adversary's code will be executed instead.(Citation: GDATA COM Hijacking) An adversary is likely to hijack objects that are used frequently enough to maintain a consistent level of persistence, but are unlikely to break noticeable functionality within the system as to avoid system instability that could lead to detection.

Procedures:

- [S0045] ADVSTORESHELL: Some variants of [ADVSTORESHELL](https://attack.mitre.org/software/S0045) achieve persistence by registering the payload as a Shell Icon Overlay handler COM object.(Citation: ESET Sednit Part 2)
- [S0356] KONNI: [KONNI](https://attack.mitre.org/software/S0356) has modified ComSysApp service to load the malicious DLL payload.(Citation: Medium KONNI Jan 2020)
- [G0007] APT28: [APT28](https://attack.mitre.org/groups/G0007) has used COM hijacking for persistence by replacing the legitimate <code>MMDeviceEnumerator</code> object with a payload.(Citation: ESET Sednit Part 1)(Citation: ESET Zebrocy May 2019)
- [S1050] PcShare: [PcShare](https://attack.mitre.org/software/S1050) has created the `HKCU\\Software\\Classes\\CLSID\\{42aedc87-2188-41fd-b9a3-0c966feabec1}\\InprocServer32` Registry key for persistence.(Citation: Bitdefender FunnyDream Campaign November 2020)
- [S0670] WarzoneRAT: [WarzoneRAT](https://attack.mitre.org/software/S0670)  can perform COM hijacking by setting the path to itself to the `HKCU\Software\Classes\Folder\shell\open\command` key with a `DelegateExecute` parameter.(Citation: Check Point Warzone Feb 2020)
- [S0126] ComRAT: [ComRAT](https://attack.mitre.org/software/S0126) samples have been seen which hijack COM objects for persistence by replacing the path to shell32.dll in registry location <code>HKCU\Software\Classes\CLSID\{42aedc87-2188-41fd-b9a3-0c966feabec1}\InprocServer32</code>.(Citation: NorthSec 2015 GData Uroburos Tools)
- [S1064] SVCReady: [SVCReady](https://attack.mitre.org/software/S1064) has created the `HKEY_CURRENT_USER\Software\Classes\CLSID\{E6D34FFC-AD32-4d6a-934C-D387FA873A19}` Registry key for persistence.(Citation: HP SVCReady Jun 2022)
- [S0256] Mosquito: [Mosquito](https://attack.mitre.org/software/S0256) uses COM hijacking as a method of persistence.(Citation: ESET Turla Mosquito Jan 2018)
- [S0679] Ferocious: [Ferocious](https://attack.mitre.org/software/S0679) can use COM hijacking to establish persistence.(Citation: Kaspersky WIRTE November 2021)
- [S0127] BBSRAT: [BBSRAT](https://attack.mitre.org/software/S0127) has been seen persisting via COM hijacking through replacement of the COM object for MruPidlList <code>{42aedc87-2188-41fd-b9a3-0c966feabec1}</code> or Microsoft WBEM New Event Subsystem <code>{F3130CDB-AA52-4C3A-AB32-85FFC23AF9C1}</code> depending on the system's CPU architecture.(Citation: Palo Alto Networks BBSRAT)
- [S0692] SILENTTRINITY: [SILENTTRINITY](https://attack.mitre.org/software/S0692) can add a CLSID key for payload execution through `Registry.CurrentUser.CreateSubKey("Software\\Classes\\CLSID\\{" + clsid + "}\\InProcServer32")`.(Citation: GitHub SILENTTRINITY Modules July 2019)
- [S0044] JHUHUGIT: [JHUHUGIT](https://attack.mitre.org/software/S0044) has used COM hijacking to establish persistence by hijacking a class named MMDeviceEnumerator and also by registering the payload as a Shell Icon Overlay handler COM object ({3543619C-D563-43f7-95EA-4DA7E1CC396A}).(Citation: ESET Sednit Part 1)(Citation: Talos Seduploader Oct 2017)

#### T1546.016 - Installer Packages

Description:

Adversaries may establish persistence and elevate privileges by using an installer to trigger the execution of malicious content. Installer packages are OS specific and contain the resources an operating system needs to install applications on a system. Installer packages can include scripts that run prior to installation as well as after installation is complete. Installer scripts may inherit elevated permissions when executed. Developers often use these scripts to prepare the environment for installation, check requirements, download dependencies, and remove files after installation.(Citation: Installer Package Scripting Rich Trouton)

Using legitimate applications, adversaries have distributed applications with modified installer scripts to execute malicious content. When a user installs the application, they may be required to grant administrative permissions to allow the installation. At the end of the installation process of the legitimate application, content such as macOS `postinstall` scripts can be executed with the inherited elevated permissions. Adversaries can use these scripts to execute a malicious executable or install other malicious components (such as a [Launch Daemon](https://attack.mitre.org/techniques/T1543/004)) with the elevated permissions.(Citation: Application Bundle Manipulation Brandon Dalton)(Citation: wardle evilquest parti)(Citation: Windows AppleJeus GReAT)(Citation: Debian Manual Maintainer Scripts)

Depending on the distribution, Linux versions of package installer scripts are sometimes called maintainer scripts or post installation scripts. These scripts can include `preinst`, `postinst`, `prerm`, `postrm` scripts and run as root when executed.

For Windows, the Microsoft Installer services uses `.msi` files to manage the installing, updating, and uninstalling of applications. These installation routines may also include instructions to perform additional actions that may be abused by adversaries.(Citation: Microsoft Installation Procedures)

Procedures:

- [S0584] AppleJeus: During [AppleJeus](https://attack.mitre.org/software/S0584)'s installation process, it uses `postinstall` scripts to extract a hidden plist from the application's `/Resources` folder and execute the `plist` file as a [Launch Daemon](https://attack.mitre.org/techniques/T1543/004) with elevated permissions.(Citation: ObjectiveSee AppleJeus 2019)

#### T1546.017 - Udev Rules

Description:

Adversaries may maintain persistence through executing malicious content triggered using udev rules. Udev is the Linux kernel device manager that dynamically manages device nodes, handles access to pseudo-device files in the `/dev` directory, and responds to hardware events, such as when external devices like hard drives or keyboards are plugged in or removed. Udev uses rule files with `match keys` to specify the conditions a hardware event must meet and `action keys` to define the actions that should follow. Root permissions are required to create, modify, or delete rule files located in `/etc/udev/rules.d/`, `/run/udev/rules.d/`, `/usr/lib/udev/rules.d/`, `/usr/local/lib/udev/rules.d/`, and `/lib/udev/rules.d/`. Rule priority is determined by both directory and by the digit prefix in the rule filename.(Citation: Ignacio Udev research 2024)(Citation: Elastic Linux Persistence 2024)

Adversaries may abuse the udev subsystem by adding or modifying rules in udev rule files to execute malicious content. For example, an adversary may configure a rule to execute their binary each time the pseudo-device file, such as `/dev/random`, is accessed by an application. Although udev is limited to running short tasks and is restricted by systemd-udevd's sandbox (blocking network and filesystem access), attackers may use scripting commands under the action key `RUN+=` to detach and run the malicious content’s process in the background to bypass these controls.(Citation: Reichert aon sedexp 2024)


### T1547 - Boot or Logon Autostart Execution

Description:

Adversaries may configure system settings to automatically execute a program during system boot or logon to maintain persistence or gain higher-level privileges on compromised systems. Operating systems may have mechanisms for automatically running a program on system boot or account logon.(Citation: Microsoft Run Key)(Citation: MSDN Authentication Packages)(Citation: Microsoft TimeProvider)(Citation: Cylance Reg Persistence Sept 2013)(Citation: Linux Kernel Programming) These mechanisms may include automatically executing programs that are placed in specially designated directories or are referenced by repositories that store configuration information, such as the Windows Registry. An adversary may achieve the same goal by modifying or extending features of the kernel.

Since some boot or logon autostart programs run with higher privileges, an adversary may leverage these to elevate privileges.

Procedures:

- [S0653] xCaon: [xCaon](https://attack.mitre.org/software/S0653) has added persistence via the Registry key <code>HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\Windows\load</code> which causes the malware to run each time any user logs in.(Citation: Checkpoint IndigoZebra July 2021)
- [S0567] Dtrack: [Dtrack](https://attack.mitre.org/software/S0567)’s RAT makes a persistent target file with auto execution on the host start.(Citation: Securelist Dtrack)
- [S0084] Mis-Type: [Mis-Type](https://attack.mitre.org/software/S0084) has created registry keys for persistence, including `HKCU\Software\bkfouerioyou`, `HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components\{6afa8072-b2b1-31a8-b5c1-{Unique Identifier}`, and `HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components\{3BF41072-B2B1-31A8-B5C1-{Unique Identifier}`.(Citation: Cylance Dust Storm)
- [S0651] BoxCaon: [BoxCaon](https://attack.mitre.org/software/S0651) established persistence by setting the <code>HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\Windows\load</code> registry key to point to its executable.(Citation: Checkpoint IndigoZebra July 2021)
- [S0083] Misdat: [Misdat](https://attack.mitre.org/software/S0083) has created registry keys for persistence, including `HKCU\Software\dnimtsoleht\StubPath`, `HKCU\Software\snimtsOleht\StubPath`, `HKCU\Software\Backtsaleht\StubPath`, `HKLM\SOFTWARE\Microsoft\Active Setup\Installed. Components\{3bf41072-b2b1-21c8-b5c1-bd56d32fbda7}`, and `HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components\{3ef41072-a2f1-21c8-c5c1-70c2c3bc7905}`.(Citation: Cylance Dust Storm)
- [G1044] APT42: [APT42](https://attack.mitre.org/groups/G1044) has modified the Registry to maintain persistence.(Citation: Mandiant APT42-charms)

#### T1547.001 - Registry Run Keys / Startup Folder

Description:

Adversaries may achieve persistence by adding a program to a startup folder or referencing it with a Registry run key. Adding an entry to the "run keys" in the Registry or startup folder will cause the program referenced to be executed when a user logs in.(Citation: Microsoft Run Key) These programs will be executed under the context of the user and will have the account's associated permissions level.

The following run keys are created by default on Windows systems:

* <code>HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run</code>
* <code>HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce</code>
* <code>HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run</code>
* <code>HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce</code>

Run keys may exist under multiple hives.(Citation: Microsoft Wow6432Node 2018)(Citation: Malwarebytes Wow6432Node 2016) The <code>HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnceEx</code> is also available but is not created by default on Windows Vista and newer. Registry run key entries can reference programs directly or list them as a dependency.(Citation: Microsoft Run Key) For example, it is possible to load a DLL at logon using a "Depend" key with RunOnceEx: <code>reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx\0001\Depend /v 1 /d "C:\temp\evil[.]dll"</code> (Citation: Oddvar Moe RunOnceEx Mar 2018)

Placing a program within a startup folder will also cause that program to execute when a user logs in. There is a startup folder location for individual user accounts as well as a system-wide startup folder that will be checked regardless of which user account logs in. The startup folder path for the current user is <code>C:\Users\\[Username]\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup</code>. The startup folder path for all users is <code>C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp</code>.

The following Registry keys can be used to set startup folder items for persistence:

* <code>HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders</code>
* <code>HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders</code>
* <code>HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders</code>
* <code>HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders</code>

The following Registry keys can control automatic startup of services during boot:

* <code>HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce</code>
* <code>HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce</code>
* <code>HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunServices</code>
* <code>HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunServices</code>

Using policy settings to specify startup programs creates corresponding values in either of two Registry keys:

* <code>HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run</code>
* <code>HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run</code>

Programs listed in the load value of the registry key <code>HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\Windows</code> run automatically for the currently logged-on user.

By default, the multistring <code>BootExecute</code> value of the registry key <code>HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager</code> is set to <code>autocheck autochk *</code>. This value causes Windows, at startup, to check the file-system integrity of the hard disks if the system has been shut down abnormally. Adversaries can add other programs or processes to this registry value which will automatically launch at boot.

Adversaries can use these configuration locations to execute malware, such as remote access tools, to maintain persistence through system reboots. Adversaries may also use [Masquerading](https://attack.mitre.org/techniques/T1036) to make the Registry entries look as if they are associated with legitimate programs.

Procedures:

- [S0082] Emissary: Variants of [Emissary](https://attack.mitre.org/software/S0082) have added Run Registry keys to establish persistence.(Citation: Emissary Trojan Feb 2016)
- [S0124] Pisloader: [Pisloader](https://attack.mitre.org/software/S0124) establishes persistence via a Registry Run key.(Citation: Palo Alto DNS Requests)
- [S0396] EvilBunny: [EvilBunny](https://attack.mitre.org/software/S0396) has created Registry keys for persistence in <code>[HKLM|HKCU]\…\CurrentVersion\Run</code>.(Citation: Cyphort EvilBunny Dec 2014)
- [G0073] APT19: An [APT19](https://attack.mitre.org/groups/G0073) HTTP malware variant establishes persistence by setting the Registry key <code>HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Windows Debug Tools-%LOCALAPPDATA%\</code>.(Citation: Unit 42 C0d0so0 Jan 2016)
- [G0067] APT37: [APT37](https://attack.mitre.org/groups/G0067)'s has added persistence via the Registry key <code>HKCU\Software\Microsoft\CurrentVersion\Run\</code>.(Citation: FireEye APT37 Feb 2018)(Citation: Talos Group123)
- [G0087] APT39: [APT39](https://attack.mitre.org/groups/G0087) has maintained persistence using the startup folder.(Citation: FireEye APT39 Jan 2019)
- [S0198] NETWIRE: [NETWIRE](https://attack.mitre.org/software/S0198) creates a Registry start-up entry to establish persistence.(Citation: McAfee Netwire Mar 2015)(Citation: Red Canary NETWIRE January 2020)(Citation: Unit 42 NETWIRE April 2020)(Citation: Proofpoint NETWIRE December 2020)
- [G1018] TA2541: [TA2541](https://attack.mitre.org/groups/G1018) has placed VBS files in the Startup folder and used Registry run keys to establish persistence for malicious payloads.(Citation: Proofpoint TA2541 February 2022)
- [S0386] Ursnif: [Ursnif](https://attack.mitre.org/software/S0386) has used Registry Run keys to establish automatic execution at system startup.(Citation: TrendMicro PE_URSNIF.A2)(Citation: TrendMicro BKDR_URSNIF.SM)
- [S0093] Backdoor.Oldrea: [Backdoor.Oldrea](https://attack.mitre.org/software/S0093) adds Registry Run keys to achieve persistence.(Citation: Symantec Dragonfly)(Citation: Gigamon Berserk Bear October 2021)
- [S0028] SHIPSHAPE: [SHIPSHAPE](https://attack.mitre.org/software/S0028) achieves persistence by creating a shortcut in the Startup folder.(Citation: FireEye APT30)
- [G0048] RTM: [RTM](https://attack.mitre.org/groups/G0048) has used Registry run keys to establish persistence for the [RTM](https://attack.mitre.org/software/S0148) Trojan and other tools, such as a modified version of TeamViewer remote desktop software.(Citation: ESET RTM Feb 2017)(Citation: Group IB RTM August 2019)
- [G0059] Magic Hound: [Magic Hound](https://attack.mitre.org/groups/G0059) malware has used Registry Run keys to establish persistence.(Citation: Unit 42 Magic Hound Feb 2017)(Citation: DFIR Phosphorus November 2021)(Citation: Microsoft Iranian Threat Actor Trends November 2021)
- [S1044] FunnyDream: [FunnyDream](https://attack.mitre.org/software/S1044) can use a Registry Run Key and the Startup folder to establish persistence.(Citation: Bitdefender FunnyDream Campaign November 2020)
- [S0331] Agent Tesla: [Agent Tesla](https://attack.mitre.org/software/S0331) can add itself to the Registry as a startup program to establish persistence.(Citation: Fortinet Agent Tesla April 2018)(Citation: SentinelLabs Agent Tesla Aug 2020)
- [S1029] AuTo Stealer: [AuTo Stealer](https://attack.mitre.org/software/S1029) can place malicious executables in a victim's AutoRun registry key or StartUp directory, depending on the AV product installed, to maintain persistence.(Citation: MalwareBytes SideCopy Dec 2021)
- [G1046] Storm-1811: [Storm-1811](https://attack.mitre.org/groups/G1046) has created Windows Registry Run keys that execute various batch scripts to establish persistence on victim devices.(Citation: rapid7-email-bombing)
- [S0090] Rover: [Rover](https://attack.mitre.org/software/S0090) persists by creating a Registry entry in <code>HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\</code>.(Citation: Palo Alto Rover)
- [S0182] FinFisher: [FinFisher](https://attack.mitre.org/software/S0182) establishes persistence by creating the Registry key <code>HKCU\Software\Microsoft\Windows\Run</code>.(Citation: FinFisher Citation)(Citation: Microsoft FinFisher March 2018)
- [S0670] WarzoneRAT: [WarzoneRAT](https://attack.mitre.org/software/S0670) can add itself to the `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` and `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UIF2IS20VK` Registry keys.(Citation: Check Point Warzone Feb 2020)
- [S0449] Maze: [Maze](https://attack.mitre.org/software/S0449) has created a file named "startup_vrun.bat" in the Startup folder of a virtual machine to establish persistence.(Citation: Sophos Maze VM September 2020)
- [S0355] Final1stspy: [Final1stspy](https://attack.mitre.org/software/S0355) creates a Registry Run key to establish persistence.(Citation: Unit 42 Nokki Oct 2018)
- [S0337] BadPatch: [BadPatch](https://attack.mitre.org/software/S0337) establishes a foothold by adding a link to the malware executable in the startup folder.(Citation: Unit 42 BadPatch Oct 2017)
- [G0100] Inception: [Inception](https://attack.mitre.org/groups/G0100) has maintained persistence by modifying Registry run key value 
 <code>HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run\</code>.(Citation: Kaspersky Cloud Atlas December 2014)
- [S1199] LockBit 2.0: [LockBit 2.0](https://attack.mitre.org/software/S1199) can use a Registry Run key to establish persistence at startup.(Citation: FBI Lockbit 2.0 FEB 2022)
- [C0022] Operation Dream Job: During [Operation Dream Job](https://attack.mitre.org/campaigns/C0022), [Lazarus Group](https://attack.mitre.org/groups/G0032) placed LNK files into the victims' startup folder for persistence.(Citation: McAfee Lazarus Jul 2020)
- [G0007] APT28: [APT28](https://attack.mitre.org/groups/G0007) has deployed malware that has copied itself to the startup directory for persistence.(Citation: TrendMicro Pawn Storm Dec 2020)
- [G0139] TeamTNT: [TeamTNT](https://attack.mitre.org/groups/G0139) has added batch scripts to the startup folder.(Citation: ATT TeamTNT Chimaera September 2020)
- [S0332] Remcos: [Remcos](https://attack.mitre.org/software/S0332) can add itself to the Registry key <code>HKCU\Software\Microsoft\Windows\CurrentVersion\Run</code> for persistence.(Citation: Fortinet Remcos Feb 2017)
- [S0265] Kazuar: [Kazuar](https://attack.mitre.org/software/S0265) adds a sub-key under several Registry run keys.(Citation: Unit 42 Kazuar May 2017)
- [S0568] EVILNUM: [EVILNUM](https://attack.mitre.org/software/S0568) can achieve persistence through the Registry Run key.(Citation: ESET EvilNum July 2020)(Citation: Prevailion EvilNum May 2020)
- [S0389] JCry: [JCry](https://attack.mitre.org/software/S0389) has created payloads in the Startup directory to maintain persistence. (Citation: Carbon Black JCry May 2019)
- [S0338] Cobian RAT: [Cobian RAT](https://attack.mitre.org/software/S0338) creates an autostart Registry key to ensure persistence.(Citation: Zscaler Cobian Aug 2017)
- [S0012] PoisonIvy: [PoisonIvy](https://attack.mitre.org/software/S0012) creates run key Registry entries pointing to a malicious executable dropped to disk.(Citation: Symantec Darkmoon Aug 2005)
- [S0484] Carberp: [Carberp](https://attack.mitre.org/software/S0484) has maintained persistence by placing itself inside the current user's startup folder.(Citation: Prevx Carberp March 2011)
- [S0532] Lucifer: [Lucifer](https://attack.mitre.org/software/S0532) can persist by setting Registry key values <code>HKLM\Software\Microsoft\Windows\CurrentVersion\Run\QQMusic</code> and <code>HKCU\Software\Microsoft\Windows\CurrentVersion\Run\QQMusic</code>.(Citation: Unit 42 Lucifer June 2020)
- [S0632] GrimAgent: [GrimAgent](https://attack.mitre.org/software/S0632) can set persistence with a Registry run key.(Citation: Group IB GrimAgent July 2021)
- [S0070] HTTPBrowser: [HTTPBrowser](https://attack.mitre.org/software/S0070) has established persistence by setting the <code>HKCU\Software\Microsoft\Windows\CurrentVersion\Run</code> key value for <code>wdm</code> to the path of the executable. It has also used the Registry entry <code>HKEY_USERS\Software\Microsoft\Windows\CurrentVersion\Run vpdn “%ALLUSERPROFILE%\%APPDATA%\vpdn\VPDN_LU.exe”</code> to establish persistence.(Citation: ZScaler Hacking Team)(Citation: ThreatStream Evasion Analysis)
- [S0665] ThreatNeedle: [ThreatNeedle](https://attack.mitre.org/software/S0665) can be loaded into the Startup folder (`%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\OneDrives.lnk`) as a Shortcut file for persistence.(Citation: Kaspersky ThreatNeedle Feb 2021)
- [S1212] RansomHub: [RansomHub](https://attack.mitre.org/software/S1212) has created an autorun Registry key through the `-safeboot-instance -pass` command line argument.(Citation: Group-IB RansomHub FEB 2025)
- [S0045] ADVSTORESHELL: [ADVSTORESHELL](https://attack.mitre.org/software/S0045) achieves persistence by adding itself to the <code>HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run</code> Registry key.(Citation: Kaspersky Sofacy)(Citation: ESET Sednit Part 2)(Citation: Bitdefender APT28 Dec 2015)
- [G0065] Leviathan: [Leviathan](https://attack.mitre.org/groups/G0065) has used JavaScript to create a shortcut file in the Startup folder that points to its main backdoor.(Citation: Proofpoint Leviathan Oct 2017)(Citation: FireEye Periscope March 2018)
- [S0170] Helminth: [Helminth](https://attack.mitre.org/software/S0170) establishes persistence by creating a shortcut in the Start Menu folder.(Citation: Palo Alto OilRig May 2016)
- [G0019] Naikon: [Naikon](https://attack.mitre.org/groups/G0019) has modified a victim's Windows Run registry to establish persistence.(Citation: Bitdefender Naikon April 2021)
- [S1066] DarkTortilla: [DarkTortilla](https://attack.mitre.org/software/S1066) has established persistence via the `Software\Microsoft\Windows NT\CurrentVersion\Run` registry key and by creating a .lnk shortcut file in the Windows startup folder.(Citation: Secureworks DarkTortilla Aug 2022)
- [S0650] QakBot: [QakBot](https://attack.mitre.org/software/S0650) can maintain persistence by creating an auto-run Registry key.(Citation: Trend Micro Qakbot May 2020)(Citation: Crowdstrike Qakbot October 2020)(Citation: Trend Micro Qakbot December 2020)(Citation: Group IB Ransomware September 2020)
- [G0091] Silence: [Silence](https://attack.mitre.org/groups/G0091) has used <code>HKCU\Software\Microsoft\Windows\CurrentVersion\Run</code>, <code>HKLM\Software\Microsoft\Windows\CurrentVersion\Run</code>, and the Startup folder to establish persistence.(Citation: Group IB Silence Sept 2018)
- [S0666] Gelsemium: [Gelsemium](https://attack.mitre.org/software/S0666) can set persistence with a Registry run key.(Citation: ESET Gelsemium June 2021)
- [S1130] Raspberry Robin: [Raspberry Robin](https://attack.mitre.org/software/S1130) will use a Registry key to achieve persistence through reboot, setting a RunOnce key such as: <code>HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce
{random value name} = “rundll32 shell32 ShellExec_RunDLLA REGSVR /u /s “{dropped copy path and file name}””
</code>.(Citation: TrendMicro RaspberryRobin 2022)
- [S0144] ChChes: [ChChes](https://attack.mitre.org/software/S0144) establishes persistence by adding a Registry Run key.(Citation: PWC Cloud Hopper Technical Annex April 2017)
- [S0168] Gazer: [Gazer](https://attack.mitre.org/software/S0168) can establish persistence by creating a .lnk file in the Start menu.(Citation: ESET Gazer Aug 2017)(Citation: Securelist WhiteBear Aug 2017)
- [G0078] Gorgon Group: [Gorgon Group](https://attack.mitre.org/groups/G0078) malware can create a .lnk file and add a Registry Run key to establish persistence.(Citation: Unit 42 Gorgon Group Aug 2018)
- [S0115] Crimson: [Crimson](https://attack.mitre.org/software/S0115) can add Registry run keys for persistence.(Citation: Proofpoint Operation Transparent Tribe March 2016)(Citation: Kaspersky Transparent Tribe August 2020)
- [S0367] Emotet: [Emotet](https://attack.mitre.org/software/S0367) has been observed adding the downloaded payload to the <code>HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run</code> key to maintain persistence.(Citation: Symantec Emotet Jul 2018)(Citation: US-CERT Emotet Jul 2018)(Citation: Picus Emotet Dec 2018)
- [S0046] CozyCar: One persistence mechanism used by [CozyCar](https://attack.mitre.org/software/S0046) is to set itself to be executed at system startup by adding a Registry value under one of the following Registry keys: <br><code>HKLM\Software\Microsoft\Windows\CurrentVersion\Run\</code> <br><code>HKCU\Software\Microsoft\Windows\CurrentVersion\Run\</code> <br><code>HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run</code> <br><code>HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run</code>(Citation: F-Secure CozyDuke)
- [S0341] Xbash: [Xbash](https://attack.mitre.org/software/S0341) can create a Startup item for persistence if it determines it is on a Windows system.(Citation: Unit42 Xbash Sept 2018)
- [S0260] InvisiMole: [InvisiMole](https://attack.mitre.org/software/S0260) can place a lnk file in the Startup Folder to achieve persistence.(Citation: ESET InvisiMole June 2020)
- [G0016] APT29: [APT29](https://attack.mitre.org/groups/G0016) added Registry Run keys to establish persistence.(Citation: Mandiant No Easy Breach)
- [S0546] SharpStage: [SharpStage](https://attack.mitre.org/software/S0546) has the ability to create persistence for the malware using the Registry autorun key and startup folder.(Citation: Cybereason Molerats Dec 2020)
- [S0660] Clambling: [Clambling](https://attack.mitre.org/software/S0660) can establish persistence by adding a Registry run key.(Citation: Trend Micro DRBControl February 2020)(Citation: Talent-Jump Clambling February 2020)
- [S0148] RTM: [RTM](https://attack.mitre.org/software/S0148) tries to add a Registry Run key under the name "Windows Update" to establish persistence.(Citation: ESET RTM Feb 2017)
- [S0074] Sakula: Most [Sakula](https://attack.mitre.org/software/S0074) samples maintain persistence by setting the Registry Run key <code>SOFTWARE\Microsoft\Windows\CurrentVersion\Run\</code> in the HKLM or HKCU hive, with the Registry value and file name varying by sample.(Citation: Dell Sakula)
- [G0128] ZIRCONIUM: [ZIRCONIUM](https://attack.mitre.org/groups/G0128) has created a Registry Run key named <code>Dropbox Update Setup</code> to establish persistence for a malicious Python binary.(Citation: Zscaler APT31 Covid-19 October 2020)
- [S0172] Reaver: [Reaver](https://attack.mitre.org/software/S0172) creates a shortcut file and saves it in a Startup folder to establish persistence.(Citation: Palo Alto Reaver Nov 2017)
- [S0262] QuasarRAT: If the [QuasarRAT](https://attack.mitre.org/software/S0262) client process does not have administrator privileges it will add a registry key to `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` for persistence.(Citation: GitHub QuasarRAT)(Citation: CISA AR18-352A Quasar RAT December 2018)
- [S0036] FLASHFLOOD: [FLASHFLOOD](https://attack.mitre.org/software/S0036) achieves persistence by making an entry in the Registry's Run key.(Citation: FireEye APT30)
- [S0397] LoJax: [LoJax](https://attack.mitre.org/software/S0397) has modified the Registry key <code>‘HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\BootExecute’</code> from <code>‘autocheck autochk *’</code> to <code>‘autocheck autoche *’</code> in order to execute its payload during Windows startup.(Citation: ESET LoJax Sept 2018)
- [G0040] Patchwork: [Patchwork](https://attack.mitre.org/groups/G0040) has added the path of its second-stage malware to the startup folder to achieve persistence. One of its file stealers has also persisted by adding a Registry Run key.(Citation: Cymmetria Patchwork)(Citation: TrendMicro Patchwork Dec 2017)
- [S1138] Gootloader: [Gootloader](https://attack.mitre.org/software/S1138) can create an autorun entry for a PowerShell script to run at reboot.(Citation: Sophos Gootloader)
- [S1037] STARWHALE: [STARWHALE](https://attack.mitre.org/software/S1037) can establish persistence by installing itself in the startup folder, whereas the GO variant has created a `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\OutlookM` registry key.(Citation: DHS CISA AA22-055A MuddyWater February 2022)(Citation: Mandiant UNC3313 Feb 2022)
- [S0381] FlawedAmmyy: [FlawedAmmyy](https://attack.mitre.org/software/S0381) has established persistence via the `HKCU\SOFTWARE\microsoft\windows\currentversion\run` registry key.(Citation: Korean FSI TA505 2020)
- [S0147] Pteranodon: [Pteranodon](https://attack.mitre.org/software/S0147) copies itself to the Startup folder to establish persistence.(Citation: Palo Alto Gamaredon Feb 2017)
- [S0652] MarkiRAT: [MarkiRAT](https://attack.mitre.org/software/S0652) can drop its payload into the Startup directory to ensure it automatically runs when the compromised system is started.(Citation: Kaspersky Ferocious Kitten Jun 2021)
- [S0167] Matryoshka: [Matryoshka](https://attack.mitre.org/software/S0167) can establish persistence by adding Registry Run keys.(Citation: ClearSky Wilted Tulip July 2017)(Citation: CopyKittens Nov 2015)
- [S1111] DarkGate: [DarkGate](https://attack.mitre.org/software/S1111) installation includes AutoIt script execution creating a shortcut to itself as an LNK object, such as bill.lnk, in the victim startup folder.(Citation: Ensilo Darkgate 2018)(Citation: Rapid7 BlackBasta 2024) [DarkGate](https://attack.mitre.org/software/S1111) installation finishes with the creation of a registry Run key.(Citation: Ensilo Darkgate 2018)
- [S0356] KONNI: A version of [KONNI](https://attack.mitre.org/software/S0356) has dropped a Windows shortcut into the Startup folder to establish persistence.(Citation: Talos Konni May 2017)
- [S0207] Vasport: [Vasport](https://attack.mitre.org/software/S0207) copies itself to disk and creates an associated run key Registry entry to establish.(Citation: Symantec Vasport May 2012)
- [S0644] ObliqueRAT: [ObliqueRAT](https://attack.mitre.org/software/S0644) can gain persistence by a creating a shortcut in the infected user's Startup directory.(Citation: Talos Oblique RAT March 2021)
- [S0015] Ixeshe: [Ixeshe](https://attack.mitre.org/software/S0015) can achieve persistence by adding itself to the <code>HKCU\Software\Microsoft\Windows\CurrentVersion\Run</code> Registry key.(Citation: Trend Micro IXESHE 2012)
- [S0127] BBSRAT: [BBSRAT](https://attack.mitre.org/software/S0127) has been loaded through DLL side-loading of a legitimate Citrix executable that is set to persist through the Registry Run key location <code>HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\ssonsvr.exe</code>.
- [G0037] FIN6: [FIN6](https://attack.mitre.org/groups/G0037) has used Registry Run keys to establish persistence for its downloader tools known as HARDTACK and SHIPBREAD.(Citation: FireEye FIN6 April 2016)
- [S0455] Metamorfo: [Metamorfo](https://attack.mitre.org/software/S0455) has configured persistence to the Registry key <code>HKCU\Software\Microsoft\Windows\CurrentVersion\Run, Spotify =% APPDATA%\Spotify\Spotify.exe</code> and used .LNK files in the startup folder to achieve persistence.(Citation: Medium Metamorfo Apr 2020)(Citation: FireEye Metamorfo Apr 2018)(Citation: Fortinet Metamorfo Feb 2020)(Citation: ESET Casbaneiro Oct 2019)
- [S1053] AvosLocker: [AvosLocker](https://attack.mitre.org/software/S1053) has been executed via the `RunOnce` Registry key to run itself on safe mode.(Citation: Trend Micro AvosLocker Apr 2022)
- [S1086] Snip3: [Snip3](https://attack.mitre.org/software/S1086) can create a VBS file in startup to persist after system restarts.(Citation: Telefonica Snip3 December 2021)
- [S0087] Hi-Zor: [Hi-Zor](https://attack.mitre.org/software/S0087) creates a Registry Run key to establish persistence.(Citation: Fidelis INOCNATION)
- [G0010] Turla: A [Turla](https://attack.mitre.org/groups/G0010) Javascript backdoor added a local_update_check value under the Registry key <code>HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run</code> to establish persistence. Additionally, a [Turla](https://attack.mitre.org/groups/G0010) custom executable containing Metasploit shellcode is saved to the Startup folder to gain persistence.(Citation: ESET Turla Mosquito Jan 2018)(Citation: ESET Turla Mosquito May 2018)(Citation: ESET Turla Lunar toolset May 2024)
- [S0226] Smoke Loader: [Smoke Loader](https://attack.mitre.org/software/S0226) adds a Registry Run key for persistence and adds a script in the Startup folder to deploy the payload.(Citation: Malwarebytes SmokeLoader 2016)
- [S0471] build_downer: [build_downer](https://attack.mitre.org/software/S0471) has the ability to add itself to the Registry Run key for persistence.(Citation: Trend Micro Tick November 2019)
- [S0433] Rifdoor: [Rifdoor](https://attack.mitre.org/software/S0433) has created a new registry entry at <code>HKEY_CURRENT_USERS\Software\Microsoft\Windows\CurrentVersion\Run\Graphics</code> with a value of <code>C:\ProgramData\Initech\Initech.exe /run</code>.(Citation: Carbon Black HotCroissant April 2020)
- [S0630] Nebulae: [Nebulae](https://attack.mitre.org/software/S0630) can achieve persistence through a Registry Run key.(Citation: Bitdefender Naikon April 2021)
- [S0353] NOKKI: [NOKKI](https://attack.mitre.org/software/S0353) has established persistence by writing the payload to the Registry key <code>HKCU\Software\Microsoft\Windows\CurrentVersion\Run</code>.(Citation: Unit 42 NOKKI Sept 2018)
- [S0531] Grandoreiro: [Grandoreiro](https://attack.mitre.org/software/S0531) can use run keys and create link files in the startup folder for persistence.(Citation: IBM Grandoreiro April 2020)(Citation: ESET Grandoreiro April 2020)
- [G0024] Putter Panda: A dropper used by [Putter Panda](https://attack.mitre.org/groups/G0024) installs itself into the ASEP Registry key <code>HKCU\Software\Microsoft\Windows\CurrentVersion\Run</code> with a value named McUpdate.(Citation: CrowdStrike Putter Panda)
- [S0196] PUNCHBUGGY: [PUNCHBUGGY](https://attack.mitre.org/software/S0196) has been observed using a Registry Run key.(Citation: FireEye Know Your Enemy FIN8 Aug 2016)(Citation: Morphisec ShellTea June 2019)
- [G0069] MuddyWater: [MuddyWater](https://attack.mitre.org/groups/G0069) has added Registry Run key <code>KCU\Software\Microsoft\Windows\CurrentVersion\Run\SystemTextEncoding</code> to establish persistence.(Citation: FireEye MuddyWater Mar 2018)(Citation: Securelist MuddyWater Oct 2018)(Citation: Talos MuddyWater May 2019)(Citation: Reaqta MuddyWater November 2017)(Citation: Trend Micro Muddy Water March 2021)(Citation: Talos MuddyWater Jan 2022)
- [S0178] Truvasys: [Truvasys](https://attack.mitre.org/software/S0178) adds a Registry Run key to establish persistence.(Citation: Microsoft Win Defender Truvasys Sep 2017)
- [S0499] Hancitor: [Hancitor](https://attack.mitre.org/software/S0499)  has added Registry Run keys to establish persistence.(Citation: FireEye Hancitor)
- [S0094] Trojan.Karagany: [Trojan.Karagany](https://attack.mitre.org/software/S0094) can create a link to itself in the Startup folder to automatically start itself upon system restart.(Citation: Symantec Dragonfly)(Citation: Secureworks Karagany July 2019)
- [S0080] Mivast: [Mivast](https://attack.mitre.org/software/S0080) creates the following Registry entry: <code>HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Micromedia</code>.(Citation: Symantec Backdoor.Mivast)
- [S0136] USBStealer: [USBStealer](https://attack.mitre.org/software/S0136) registers itself under a Registry Run key with the name "USB Disk Security."(Citation: ESET Sednit USBStealer 2014)
- [S0141] Winnti for Windows: [Winnti for Windows](https://attack.mitre.org/software/S0141) can add a service named <code>wind0ws</code> to the Registry to achieve persistence after reboot.(Citation: Novetta Winnti April 2015)
- [S0044] JHUHUGIT: [JHUHUGIT](https://attack.mitre.org/software/S0044) has used a Registry Run key to establish persistence by executing JavaScript code within the rundll32.exe process.(Citation: ESET Sednit Part 1)
- [S0553] MoleNet: [MoleNet](https://attack.mitre.org/software/S0553) can achieve persitence on the infected machine by setting the Registry run key.(Citation: Cybereason Molerats Dec 2020)
- [G0121] Sidewinder: [Sidewinder](https://attack.mitre.org/groups/G0121) has added paths to executables in the Registry to establish persistence.(Citation: Rewterz Sidewinder APT April 2020)(Citation: Rewterz Sidewinder COVID-19 June 2020)(Citation: Cyble Sidewinder September 2020)
- [S0570] BitPaymer: [BitPaymer](https://attack.mitre.org/software/S0570) has set the run key <code>HKCU\Software\Microsoft\Windows\CurrentVersion\Run</code> for persistence.(Citation: Crowdstrike Indrik November 2018)
- [S0512] FatDuke: [FatDuke](https://attack.mitre.org/software/S0512) has used <code>HKLM\SOFTWARE\Microsoft\CurrentVersion\Run</code> to establish persistence.(Citation: ESET Dukes October 2019)
- [S0513] LiteDuke: [LiteDuke](https://attack.mitre.org/software/S0513) can create persistence by adding a shortcut in the <code>CurrentVersion\Run</code> Registry key.(Citation: ESET Dukes October 2019)
- [S0034] NETEAGLE: The "SCOUT" variant of [NETEAGLE](https://attack.mitre.org/software/S0034) achieves persistence by adding itself to the <code>HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run</code> Registry key.(Citation: FireEye APT30)
- [C0047] RedDelta Modified PlugX Infection Chain Operations: [Mustang Panda](https://attack.mitre.org/groups/G0129) used Run registry keys with names such as `OneNote Update` to execute legitimate executables that would load through search-order hijacking malicious DLLS to ensure persistence during [RedDelta Modified PlugX Infection Chain Operations](https://attack.mitre.org/campaigns/C0047).(Citation: Recorded Future RedDelta 2025)
- [S0382] ServHelper: [ServHelper](https://attack.mitre.org/software/S0382) may attempt to establish persistence via the <code>HKCU\Software\Microsoft\Windows\CurrentVersion\Run\</code> run key.(Citation: Deep Instinct TA505 Apr 2019)
- [S0444] ShimRat: [ShimRat](https://attack.mitre.org/software/S0444) has installed a registry based start-up key <code>HKCU\Software\microsoft\windows\CurrentVersion\Run</code> to maintain persistence should other methods fail.(Citation: FOX-IT May 2016 Mofang)
- [G0027] Threat Group-3390: [Threat Group-3390](https://attack.mitre.org/groups/G0027)'s malware can add a Registry key to `Software\Microsoft\Windows\CurrentVersion\Run` for persistence.(Citation: Nccgroup Emissary Panda May 2018)(Citation: Lunghi Iron Tiger Linux)
- [S0375] Remexi: [Remexi](https://attack.mitre.org/software/S0375) utilizes Run Registry keys in the HKLM hive as a persistence mechanism.(Citation: Securelist Remexi Jan 2019)
- [S0035] SPACESHIP: [SPACESHIP](https://attack.mitre.org/software/S0035) achieves persistence by creating a shortcut in the current user's Startup folder.(Citation: FireEye APT30)
- [G0081] Tropic Trooper: [Tropic Trooper](https://attack.mitre.org/groups/G0081) has created shortcuts in the Startup folder to establish persistence.(Citation: Anomali Pirate Panda April 2020)(Citation: TrendMicro Tropic Trooper May 2020)
- [G0032] Lazarus Group: [Lazarus Group](https://attack.mitre.org/groups/G0032) has maintained persistence by loading malicious code into a startup folder or by adding a Registry Run key.(Citation: Novetta Blockbuster)(Citation: Novetta Blockbuster RATs)(Citation: McAfee Lazarus Resurfaces Feb 2018)(Citation: Lazarus APT January 2022)
- [G0096] APT41: [APT41](https://attack.mitre.org/groups/G0096) created and modified startup files for persistence.(Citation: FireEye APT41 Aug 2019)(Citation: Group IB APT 41 June 2021) [APT41](https://attack.mitre.org/groups/G0096) added a registry key in <code>HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Svchost</code> to establish persistence for [Cobalt Strike](https://attack.mitre.org/software/S0154).(Citation: FireEye APT41 March 2020)
- [G0112] Windshift: [Windshift](https://attack.mitre.org/groups/G0112) has created LNK files in the Startup folder to establish persistence.(Citation: BlackBerry Bahamut)
- [S1122] Mispadu: [Mispadu](https://attack.mitre.org/software/S1122) creates a link in the startup folder for persistence.(Citation: ESET Security Mispadu Facebook Ads 2019) [Mispadu](https://attack.mitre.org/software/S1122) adds persistence via the registry key `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`.(Citation: Metabase Q Mispadu Trojan 2023)
- [S0363] Empire: [Empire](https://attack.mitre.org/software/S0363) can modify the registry run keys <code>HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run</code> and <code>HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run</code> for persistence.(Citation: Github PowerShell Empire)
- [S1041] Chinoxy: [Chinoxy](https://attack.mitre.org/software/S1041) has established persistence via the `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` registry key and by loading a dropper to `(%COMMON_ STARTUP%\\eoffice.exe)`.(Citation: Bitdefender FunnyDream Campaign November 2020)
- [S1035] Small Sieve: [Small Sieve](https://attack.mitre.org/software/S1035) has the ability to add itself to `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\OutlookMicrosift` for persistence.(Citation: NCSC GCHQ Small Sieve Jan 2022)
- [S0649] SMOKEDHAM: [SMOKEDHAM](https://attack.mitre.org/software/S0649) has used <code>reg.exe</code> to create a Registry Run key.(Citation: FireEye SMOKEDHAM June 2021)
- [S0461] SDBbot: [SDBbot](https://attack.mitre.org/software/S0461) has the ability to add a value to the Registry Run key to establish persistence if it detects it is running with regular user privilege. (Citation: Proofpoint TA505 October 2019)(Citation: IBM TA505 April 2020)
- [G0046] FIN7: [FIN7](https://attack.mitre.org/groups/G0046) malware has created Registry Run and RunOnce keys to establish persistence, and has also added items to the Startup folder.(Citation: FireEye FIN7 April 2017)(Citation: FireEye FIN7 Aug 2018)
- [G0070] Dark Caracal: [Dark Caracal](https://attack.mitre.org/groups/G0070)'s version of [Bandook](https://attack.mitre.org/software/S0234) adds a registry key to <code>HKEY_USERS\Software\Microsoft\Windows\CurrentVersion\Run</code> for persistence.(Citation: Lookout Dark Caracal Jan 2018)
- [S0249] Gold Dragon: [Gold Dragon](https://attack.mitre.org/software/S0249) establishes persistence in the Startup folder.(Citation: McAfee Gold Dragon)
- [S0131] TINYTYPHON: [TINYTYPHON](https://attack.mitre.org/software/S0131) installs itself under Registry Run key to establish persistence.(Citation: Forcepoint Monsoon)
- [G0051] FIN10: [FIN10](https://attack.mitre.org/groups/G0051) has established persistence by using the Registry option in PowerShell Empire to add a Run key.(Citation: FireEye FIN10 June 2017)(Citation: Github PowerShell Empire)
- [S0456] Aria-body: [Aria-body](https://attack.mitre.org/software/S0456) has established persistence via the Startup folder or Run Registry key.(Citation: CheckPoint Naikon May 2020)
- [G0056] PROMETHIUM: [PROMETHIUM](https://attack.mitre.org/groups/G0056) has used Registry run keys to establish persistence.(Citation: Talos Promethium June 2020)
- [S0441] PowerShower: [PowerShower](https://attack.mitre.org/software/S0441) sets up persistence with a Registry run key.(Citation: Unit 42 Inception November 2018)
- [S0647] Turian: [Turian](https://attack.mitre.org/software/S0647) can establish persistence by adding Registry Run keys.(Citation: ESET BackdoorDiplomacy Jun 2021)
- [S0204] Briba: [Briba](https://attack.mitre.org/software/S0204) creates run key Registry entries pointing to malicious DLLs dropped to disk.(Citation: Symantec Briba May 2012)
- [S0194] PowerSploit: [PowerSploit](https://attack.mitre.org/software/S0194)'s <code>New-UserPersistenceOption</code> Persistence argument can be used to establish via the <code>HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run</code> Registry key.(Citation: GitHub PowerSploit May 2012)(Citation: PowerSploit Documentation)
- [S0268] Bisonal: [Bisonal](https://attack.mitre.org/software/S0268) has added itself to the Registry key <code>HKEY_CURRENT_USER\Software\Microsoft\CurrentVersion\Run\</code> for persistence.(Citation: Unit 42 Bisonal July 2018)(Citation: Talos Bisonal Mar 2020)
- [S0253] RunningRAT: [RunningRAT](https://attack.mitre.org/software/S0253) adds itself to the Registry key <code>Software\Microsoft\Windows\CurrentVersion\Run</code> to establish persistence upon reboot.(Citation: McAfee Gold Dragon)
- [S0586] TAINTEDSCRIBE: [TAINTEDSCRIBE](https://attack.mitre.org/software/S0586) can copy itself into the current user’s Startup folder as “Narrator.exe” for persistence.(Citation: CISA MAR-10288834-2.v1  TAINTEDSCRIBE MAY 2020)
- [S0409] Machete: [Machete](https://attack.mitre.org/software/S0409) used the startup folder for persistence.(Citation: Securelist Machete Aug 2014)(Citation: Cylance Machete Mar 2017)
- [S0235] CrossRAT: [CrossRAT](https://attack.mitre.org/software/S0235) uses run keys for persistence on Windows.(Citation: Lookout Dark Caracal Jan 2018)
- [S0031] BACKSPACE: [BACKSPACE](https://attack.mitre.org/software/S0031) achieves persistence by creating a shortcut to itself in the CSIDL_STARTUP directory.(Citation: FireEye APT30)
- [S1213] Lumma Stealer: [Lumma Stealer](https://attack.mitre.org/software/S1213) has created registry keys to maintain persistence using `HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`.(Citation: Cybereason LumaStealer Undated)(Citation: Netskope LummaStealer 2025)
- [S0186] DownPaper: [DownPaper](https://attack.mitre.org/software/S0186) uses PowerShell to add a Registry Run key in order to establish persistence.(Citation: ClearSky Charming Kitten Dec 2017)
- [S0088] Kasidet: [Kasidet](https://attack.mitre.org/software/S0088) creates a Registry Run key to establish persistence.(Citation: Zscaler Kasidet)(Citation: Microsoft Kasidet)
- [S0696] Flagpro: [Flagpro](https://attack.mitre.org/software/S0696) has dropped an executable file to the startup directory.(Citation: NTT Security Flagpro new December 2021)
- [S0340] Octopus: [Octopus](https://attack.mitre.org/software/S0340) achieved persistence by placing a malicious executable in the startup directory and has added the <code>HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run</code> key to the Registry.(Citation: Securelist Octopus Oct 2018)
- [S0385] njRAT: [njRAT](https://attack.mitre.org/software/S0385) has added persistence via the Registry key <code>HKCU\Software\Microsoft\CurrentVersion\Run\</code> and dropped a shortcut in <code>%STARTUP%</code>.(Citation: Fidelis njRAT June 2013)(Citation: Trend Micro njRAT 2018)
- [G1014] LuminousMoth: [LuminousMoth](https://attack.mitre.org/groups/G1014) has used malicious DLLs that setup persistence in the Registry Key `HKCU\Software\Microsoft\Windows\Current Version\Run`.(Citation: Kaspersky LuminousMoth July 2021)(Citation: Bitdefender LuminousMoth July 2021)
- [S1021] DnsSystem: [DnsSystem](https://attack.mitre.org/software/S1021) can write itself to the Startup folder to gain persistence.(Citation: Zscaler Lyceum DnsSystem June 2022)
- [S0251] Zebrocy: [Zebrocy](https://attack.mitre.org/software/S0251) creates an entry in a Registry Run key for the malware to execute on startup.(Citation: ESET Zebrocy Nov 2018)(Citation: ESET Zebrocy May 2019)(Citation: Accenture SNAKEMACKEREL Nov 2018)
- [S0058] SslMM: To establish persistence, [SslMM](https://attack.mitre.org/software/S0058) identifies the Start Menu Startup directory and drops a link to its own executable disguised as an “Office Start,” “Yahoo Talk,” “MSN Gaming Z0ne,” or “MSN Talk” shortcut.(Citation: Baumgartner Naikon 2015)
- [S0128] BADNEWS: [BADNEWS](https://attack.mitre.org/software/S0128) installs a registry Run key to establish persistence.(Citation: Forcepoint Monsoon)
- [S0608] Conficker: [Conficker](https://attack.mitre.org/software/S0608) adds Registry Run keys to establish persistence.(Citation: Trend Micro Conficker)
- [S1074] ANDROMEDA: [ANDROMEDA](https://attack.mitre.org/software/S1074) can establish persistence by dropping a sample of itself to `C:\ProgramData\Local Settings\Temp\mskmde.com` and adding a Registry run key to execute every time a user logs on.(Citation: Mandiant Suspected Turla Campaign February 2023)
- [S0582] LookBack: [LookBack](https://attack.mitre.org/software/S0582) sets up a Registry Run key to establish a persistence mechanism.(Citation: Proofpoint LookBack Malware Aug 2019)
- [S0458] Ramsay: [Ramsay](https://attack.mitre.org/software/S0458) has created Registry Run keys to establish persistence.(Citation: Antiy CERT Ramsay April 2020)
- [S1150] ROADSWEEP: [ROADSWEEP](https://attack.mitre.org/software/S1150) has been placed in the start up folder to trigger execution upon user login.(Citation: Microsoft Albanian Government Attacks September 2022)
- [S0250] Koadic: [Koadic](https://attack.mitre.org/software/S0250) has added persistence to the `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run` Registry key.(Citation: MalwareBytes LazyScripter Feb 2021)
- [G1016] FIN13: [FIN13](https://attack.mitre.org/groups/G1016) has used Windows Registry run keys such as, `HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run\hosts` to maintain persistence.(Citation: Mandiant FIN13 Aug 2022)
- [S0062] DustySky: [DustySky](https://attack.mitre.org/software/S0062) achieves persistence by creating a Registry entry in <code>HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run</code>.(Citation: DustySky)
- [S0030] Carbanak: [Carbanak](https://attack.mitre.org/software/S0030) stores a configuration files in the startup directory to automatically execute commands in order to persist across reboots.(Citation: FireEye CARBANAK June 2017)
- [G1036] Moonstone Sleet: [Moonstone Sleet](https://attack.mitre.org/groups/G1036) used registry run keys for process execution during initial victim infection.(Citation: Microsoft Moonstone Sleet 2024)
- [S0442] VBShower: [VBShower](https://attack.mitre.org/software/S0442) used <code>HKCU\Software\Microsoft\Windows\CurrentVersion\Run\\[a-f0-9A-F]{8}</code> to maintain persistence.(Citation: Kaspersky Cloud Atlas August 2019)
- [G0106] Rocke: [Rocke](https://attack.mitre.org/groups/G0106)'s miner has created UPX-packed files in the Windows Start Menu Folder.(Citation: Talos Rocke August 2018)
- [S0013] PlugX: [PlugX](https://attack.mitre.org/software/S0013) adds Run key entries in the Registry to establish persistence.(Citation: Lastline PlugX Analysis)(Citation: PWC Cloud Hopper Technical Annex April 2017)(Citation: CIRCL PlugX March 2013)
- [S0631] Chaes: [Chaes](https://attack.mitre.org/software/S0631) has added persistence via the Registry key <code>software\microsoft\windows\currentversion\run\microsoft windows html help</code>.(Citation: Cybereason Chaes Nov 2020)
- [S1018] Saint Bot: [Saint Bot](https://attack.mitre.org/software/S1018) has established persistence by being copied to the Startup directory or through the `\Software\Microsoft\Windows\CurrentVersion\Run` registry key.(Citation: Malwarebytes Saint Bot April 2021)(Citation: Palo Alto Unit 42 OutSteel SaintBot February 2022 )
- [G0021] Molerats: [Molerats](https://attack.mitre.org/groups/G0021) saved malicious files within the AppData and Startup folders to maintain persistence.(Citation: Kaspersky MoleRATs April 2019)
- [S0662] RCSession: [RCSession](https://attack.mitre.org/software/S0662) has the ability to modify a Registry Run key to establish persistence.(Citation: Trend Micro DRBControl February 2020)(Citation: Profero APT27 December 2020)
- [S0032] gh0st RAT: [gh0st RAT](https://attack.mitre.org/software/S0032) has added a Registry Run key to establish persistence.(Citation: Nccgroup Gh0st April 2018)(Citation: Gh0stRAT ATT March 2019)
- [S0414] BabyShark: [BabyShark](https://attack.mitre.org/software/S0414) has added a Registry key to ensure all future macros are enabled for Microsoft Word and Excel as well as for additional persistence.(Citation: Unit42 BabyShark Feb 2019)(Citation: CISA AA20-301A Kimsuky)
- [S0004] TinyZBot: [TinyZBot](https://attack.mitre.org/software/S0004) can create a shortcut in the Windows startup folder for persistence.(Citation: Cylance Cleaver)
- [S0334] DarkComet: [DarkComet](https://attack.mitre.org/software/S0334) adds several Registry entries to enable automatic execution at every system startup.(Citation: TrendMicro DarkComet Sept 2014)(Citation: Malwarebytes DarkComet March 2018)
- [S0145] POWERSOURCE: [POWERSOURCE](https://attack.mitre.org/software/S0145) achieves persistence by setting a Registry Run key, with the path depending on whether the victim account has user or administrator access.(Citation: Cisco DNSMessenger March 2017)
- [S1182] MagicRAT: [MagicRAT](https://attack.mitre.org/software/S1182) can persist using malicious LNK objects in the victim machine Startup folder.(Citation: Cisco MagicRAT 2022)
- [S0345] Seasalt: [Seasalt](https://attack.mitre.org/software/S0345) creates a Registry entry to ensure infection after reboot under <code>HKLM\Software\Microsoft\Windows\currentVersion\Run</code>.(Citation: McAfee Oceansalt Oct 2018)
- [S1027] Heyoka Backdoor: [Heyoka Backdoor](https://attack.mitre.org/software/S1027) can establish persistence with the auto start function including using the value `EverNoteTrayUService`.(Citation: SentinelOne Aoqin Dragon June 2022)
- [S0247] NavRAT: [NavRAT](https://attack.mitre.org/software/S0247) creates a Registry key to ensure a file gets executed upon reboot in order to establish persistence.(Citation: Talos NavRAT May 2018)
- [C0013] Operation Sharpshooter: During [Operation Sharpshooter](https://attack.mitre.org/campaigns/C0013), a first-stage downloader installed [Rising Sun](https://attack.mitre.org/software/S0448) to `%Startup%\mssync.exe` on a compromised host.(Citation: McAfee Sharpshooter December 2018)
- [S0254] PLAINTEE: [PLAINTEE](https://attack.mitre.org/software/S0254) gains persistence by adding the Registry key <code>HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce</code>.(Citation: Rancor Unit42 June 2018)
- [S0259] InnaputRAT: Some [InnaputRAT](https://attack.mitre.org/software/S0259) variants establish persistence by modifying the Registry key <code>HKU\<SID>\Software\Microsoft\Windows\CurrentVersion\Run:%appdata%\NeutralApp\NeutralApp.exe</code>.(Citation: ASERT InnaputRAT April 2018)
- [S0053] SeaDuke: [SeaDuke](https://attack.mitre.org/software/S0053) is capable of persisting via the Registry Run key or a .lnk file stored in the Startup directory.(Citation: Unit 42 SeaDuke 2015)
- [G0080] Cobalt Group: [Cobalt Group](https://attack.mitre.org/groups/G0080) has used Registry Run keys for persistence. The group has also set a Startup path to launch the PowerShell shell command and download Cobalt Strike.(Citation: Group IB Cobalt Aug 2017)
- [S0417] GRIFFON: [GRIFFON](https://attack.mitre.org/software/S0417) has used a persistence module that stores the implant inside the Registry, which executes at logon.(Citation: SecureList Griffon May 2019)
- [G0129] Mustang Panda: [Mustang Panda](https://attack.mitre.org/groups/G0129) has created the registry key <code>HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run\AdobelmdyU</code> to maintain persistence.(Citation: Proofpoint TA416 November 2020)
- [G0126] Higaisa: [Higaisa](https://attack.mitre.org/groups/G0126) added a spoofed binary to the start-up folder for persistence.(Citation: Malwarebytes Higaisa 2020)(Citation: Zscaler Higaisa 2020)
- [S0018] Sykipot: [Sykipot](https://attack.mitre.org/software/S0018) has been known to establish persistence by adding programs to the Run Registry key.(Citation: Blasco 2013)
- [G0094] Kimsuky: [Kimsuky](https://attack.mitre.org/groups/G0094) has placed scripts in the startup folder for persistence and modified the `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce` Registry key.(Citation: Securelist Kimsuky Sept 2013)(Citation: CISA AA20-301A Kimsuky)(Citation: Crowdstrike GTR2020 Mar 2020)(Citation: Talos Kimsuky Nov 2021)(Citation: KISA Operation Muzabi)
- [S0113] Prikormka: [Prikormka](https://attack.mitre.org/software/S0113) adds itself to a Registry Run key with the name guidVGA or guidVSA.(Citation: ESET Operation Groundbait)
- [G0035] Dragonfly: [Dragonfly](https://attack.mitre.org/groups/G0035) has added the registry value ntdll to the Registry Run key to establish persistence.(Citation: US-CERT TA18-074A)
- [S0159] SNUGRIDE: [SNUGRIDE](https://attack.mitre.org/software/S0159) establishes persistence through a Registry Run key.(Citation: FireEye APT10 April 2017)
- [S0663] SysUpdate: [SysUpdate](https://attack.mitre.org/software/S0663) can use a Registry Run key to establish persistence.(Citation: Trend Micro Iron Tiger April 2021)
- [S0439] Okrum: [Okrum](https://attack.mitre.org/software/S0439) establishes persistence by creating a .lnk shortcut to itself in the Startup folder.(Citation: ESET Okrum July 2019)
- [S0483] IcedID: [IcedID](https://attack.mitre.org/software/S0483) has established persistence by creating a Registry run key.(Citation: IBM IcedID November 2017)
- [G0140] LazyScripter: [LazyScripter](https://attack.mitre.org/groups/G0140) has achieved persistence via writing a PowerShell script to the autorun registry key.(Citation: MalwareBytes LazyScripter Feb 2021)
- [S0228] NanHaiShu: [NanHaiShu](https://attack.mitre.org/software/S0228) modifies the %regrun% Registry to point itself to an autostart mechanism.(Citation: fsecure NanHaiShu July 2016)
- [S0635] BoomBox: [BoomBox](https://attack.mitre.org/software/S0635) can establish persistence by writing the Registry value <code>MicroNativeCacheSvc</code> to <code>HKCU\Software\Microsoft\Windows\CurrentVersion\Run</code>.(Citation: MSTIC Nobelium Toolset May 2021)
- [G0022] APT3: [APT3](https://attack.mitre.org/groups/G0022) places scripts in the startup folder for persistence.(Citation: FireEye Operation Double Tap)
- [S0152] EvilGrab: [EvilGrab](https://attack.mitre.org/software/S0152) adds a Registry Run key for ctfmon.exe to establish persistence.(Citation: PWC Cloud Hopper Technical Annex April 2017)
- [S0089] BlackEnergy: The [BlackEnergy](https://attack.mitre.org/software/S0089) 3 variant drops its main DLL component and then creates a .lnk shortcut to that file in the startup folder.(Citation: F-Secure BlackEnergy 2014)
- [S1025] Amadey: [Amadey](https://attack.mitre.org/software/S1025) has changed the Startup folder to the one containing its executable by overwriting the registry keys.(Citation: Korean FSI TA505 2020)(Citation: BlackBerry Amadey 2020)
- [S0640] Avaddon: [Avaddon](https://attack.mitre.org/software/S0640) uses registry run keys for persistence.(Citation: Arxiv Avaddon Feb 2021)
- [G0012] Darkhotel: [Darkhotel](https://attack.mitre.org/groups/G0012) has been known to establish persistence by adding programs to the Run Registry key.(Citation: Kaspersky Darkhotel)
- [S0561] GuLoader: [GuLoader](https://attack.mitre.org/software/S0561) can establish persistence via the Registry under <code>HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce</code>.(Citation: Unit 42 NETWIRE April 2020)
- [S0085] S-Type: [S-Type](https://attack.mitre.org/software/S0085) may create a .lnk file to itself that is saved in the Start menu folder. It may also create the Registry key <code>HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\ IMJPMIJ8.1{3 characters of Unique Identifier}</code>.(Citation: Cylance Dust Storm)
- [G0064] APT33: [APT33](https://attack.mitre.org/groups/G0064) has deployed a tool known as [DarkComet](https://attack.mitre.org/software/S0334) to the Startup folder of a victim, and used Registry run keys to gain persistence.(Citation: Symantec Elfin Mar 2019)(Citation: Microsoft Holmium June 2020)
- [G0060] BRONZE BUTLER: [BRONZE BUTLER](https://attack.mitre.org/groups/G0060) has used a batch script that adds a Registry Run key to establish malware persistence.(Citation: Secureworks BRONZE BUTLER Oct 2017)
- [S0192] Pupy: [Pupy](https://attack.mitre.org/software/S0192) adds itself to the startup folder or adds itself to the Registry key <code>SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run</code> for persistence.(Citation: GitHub Pupy)
- [S0244] Comnie: [Comnie](https://attack.mitre.org/software/S0244) achieves persistence by adding a shortcut of itself to the startup path in the Registry.(Citation: Palo Alto Comnie)
- [S0491] StrongPity: [StrongPity](https://attack.mitre.org/software/S0491) can use the <code>HKCU\Software\Microsoft\Windows\CurrentVersion\Run</code> Registry key for persistence.(Citation: Talos Promethium June 2020)
- [G1043] BlackByte: [BlackByte](https://attack.mitre.org/groups/G1043) has used Registry Run keys for persistence.(Citation: Microsoft BlackByte 2023)
- [S1160] Latrodectus: [Latrodectus](https://attack.mitre.org/software/S1160) can set an AutoRun key to establish persistence.(Citation: Latrodectus APR 2024)
- [G1039] RedCurl: [RedCurl](https://attack.mitre.org/groups/G1039) has established persistence by creating entries in `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`.(Citation: group-ib_redcurl1)(Citation: group-ib_redcurl2)
- [S0330] Zeus Panda: [Zeus Panda](https://attack.mitre.org/software/S0330) adds persistence by creating Registry Run keys.(Citation: Talos Zeus Panda Nov 2017)(Citation: GDATA Zeus Panda June 2017)
- [G0004] Ke3chang: Several [Ke3chang](https://attack.mitre.org/groups/G0004) backdoors achieved persistence by adding a Run key.(Citation: NCC Group APT15 Alive and Strong)
- [S0137] CORESHELL: [CORESHELL](https://attack.mitre.org/software/S0137) has established persistence by creating autostart extensibility point (ASEP) Registry entries in the Run key and other Registry keys, as well as by creating shortcuts in the Internet Explorer Quick Start folder.(Citation: Microsoft SIR Vol 19)
- [S0336] NanoCore: [NanoCore](https://attack.mitre.org/software/S0336) creates a RunOnce key in the Registry to execute its VBS scripts each time the user logs on to the machine.(Citation: Cofense NanoCore Mar 2018)
- [S0692] SILENTTRINITY: [SILENTTRINITY](https://attack.mitre.org/software/S0692) can establish a LNK file in the startup folder for persistence.(Citation: GitHub SILENTTRINITY Modules July 2019)
- [G0142] Confucius: [Confucius](https://attack.mitre.org/groups/G0142) has dropped malicious files into the startup folder `%AppData%\Microsoft\Windows\Start Menu\Programs\Startup` on a compromised host in order to maintain persistence.(Citation: Uptycs Confucius APT Jan 2021)
- [S0348] Cardinal RAT: [Cardinal RAT](https://attack.mitre.org/software/S0348) establishes Persistence by setting the  <code>HKCU\Software\Microsoft\Windows NT\CurrentVersion\Windows\Load</code> Registry key to point to its executable.(Citation: PaloAlto CardinalRat Apr 2017)
- [S1145] Pikabot: [Pikabot](https://attack.mitre.org/software/S1145) maintains persistence following system checks through the Run key in the registry.(Citation: Zscaler Pikabot 2023)
- [S1207] XLoader: [XLoader](https://attack.mitre.org/software/S1207) establishes persistence by copying its executable in a subdirectory of `%APPDATA%` or `%PROGRAMFILES%`, and then modifies Windows Registry Run keys or policies keys to execute the executable on system start.(Citation: Zscaler XLoader 2025)(Citation: Google XLoader 2017)
- [S0446] Ryuk: [Ryuk](https://attack.mitre.org/software/S0446) has used the Windows command line to create a Registry entry under <code>HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Run</code> to establish persistence.(Citation: CrowdStrike Ryuk January 2019)
- [S0622] AppleSeed: [AppleSeed](https://attack.mitre.org/software/S0622) has the ability to create the Registry key name <code>EstsoftAutoUpdate</code> at <code>HKCU\Software\Microsoft/Windows\CurrentVersion\RunOnce</code> to establish persistence.(Citation: Malwarebytes Kimsuky June 2021)
- [S0371] POWERTON: [POWERTON](https://attack.mitre.org/software/S0371) can install a Registry Run key for persistence.(Citation: FireEye APT33 Guardrail)
- [G0026] APT18: [APT18](https://attack.mitre.org/groups/G0026) establishes persistence via the <code>HKCU\Software\Microsoft\Windows\CurrentVersion\Run</code> key.(Citation: Anomali Evasive Maneuvers July 2015)(Citation: PaloAlto DNS Requests May 2016)
- [S0256] Mosquito: [Mosquito](https://attack.mitre.org/software/S0256) establishes persistence under the Registry key <code>HKCU\Software\Run auto_update</code>.(Citation: ESET Turla Mosquito Jan 2018)
- [S0373] Astaroth: [Astaroth](https://attack.mitre.org/software/S0373) creates a startup item for persistence. (Citation: Cofense Astaroth Sept 2018)
- [S0428] PoetRAT: [PoetRAT](https://attack.mitre.org/software/S0428) has added a registry key in the <RUN> hive for persistence.(Citation: Talos PoetRAT April 2020)
- [S0266] TrickBot: [TrickBot](https://attack.mitre.org/software/S0266) establishes persistence in the Startup folder.(Citation: ESET Trickbot Oct 2020)
- [S0267] FELIXROOT: [FELIXROOT](https://attack.mitre.org/software/S0267) adds a shortcut file to the startup folder for persistence.(Citation: ESET GreyEnergy Oct 2018)
- [S0153] RedLeaves: [RedLeaves](https://attack.mitre.org/software/S0153) attempts to add a shortcut file in the Startup folder to achieve persistence. If this fails, it attempts to add Registry Run keys.(Citation: PWC Cloud Hopper Technical Annex April 2017)(Citation: Accenture Hogfish April 2018)
- [S0139] PowerDuke: [PowerDuke](https://attack.mitre.org/software/S0139) achieves persistence by using various Registry Run keys.(Citation: Volexity PowerDuke November 2016)
- [S0669] KOCTOPUS: [KOCTOPUS](https://attack.mitre.org/software/S0669) can set the AutoRun Registry key with a PowerShell command.(Citation: MalwareBytes LazyScripter Feb 2021)
- [G0047] Gamaredon Group: [Gamaredon Group](https://attack.mitre.org/groups/G0047) tools have registered Run keys in the registry to give malicious VBS files persistence.(Citation: TrendMicro Gamaredon April 2020)(Citation: ESET Gamaredon June 2020)(Citation: CERT-EE Gamaredon January 2021)(Citation: unit42_gamaredon_dec2022)
- [S0199] TURNEDUP: [TURNEDUP](https://attack.mitre.org/software/S0199) is capable of writing to a Registry Run key to establish.(Citation: CyberBit Early Bird Apr 2018)
- [S0534] Bazar: [Bazar](https://attack.mitre.org/software/S0534) can create or add files to Registry Run Keys to establish persistence.(Citation: Cybereason Bazar July 2020)(Citation: NCC Group Team9 June 2020)
- [S1026] Mongall: [Mongall](https://attack.mitre.org/software/S1026) can establish persistence with the auto start function including using the value `EverNoteTrayUService`.(Citation: SentinelOne Aoqin Dragon June 2022)
- [G0102] Wizard Spider: [Wizard Spider](https://attack.mitre.org/groups/G0102) has established persistence via the Registry key <code>HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run</code> and a shortcut within the startup folder.(Citation: DHS/CISA Ransomware Targeting Healthcare October 2020)(Citation: FireEye KEGTAP SINGLEMALT October 2020)
- [G0050] APT32: [APT32](https://attack.mitre.org/groups/G0050) established persistence using Registry Run keys, both to execute PowerShell and VBS scripts as well as to execute their backdoor directly.(Citation: Cybereason Oceanlotus May 2017)(Citation: Cybereason Cobalt Kitty 2017)(Citation: ESET OceanLotus Mar 2019)
- [S0500] MCMD: [MCMD](https://attack.mitre.org/software/S0500) can use Registry Run Keys for persistence.(Citation: Secureworks MCMD July 2019)
- [S0081] Elise: If establishing persistence by installation as a new service fails, one variant of [Elise](https://attack.mitre.org/software/S0081) establishes persistence for the created .exe file by setting the following Registry key: <code>HKCU\Software\Microsoft\Windows\CurrentVersion\Run\svchost : %APPDATA%\Microsoft\Network\svchost.exe</code>. Other variants have set the following Registry keys for persistence: <code>HKCU\Software\Microsoft\Windows\CurrentVersion\Run\imejp : [self]</code> and <code>HKCU\Software\Microsoft\Windows\CurrentVersion\Run\IAStorD</code>.(Citation: Lotus Blossom Jun 2015)(Citation: Accenture Dragonfish Jan 2018)
- [S0011] Taidoor: [Taidoor](https://attack.mitre.org/software/S0011) has modified the <code>HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run</code> key for persistence.(Citation: TrendMicro Taidoor)
- [S0270] RogueRobin: [RogueRobin](https://attack.mitre.org/software/S0270) created a shortcut in the Windows startup folder to launch a PowerShell script each time the user logs in to establish persistence.(Citation: Unit 42 DarkHydrus July 2018)

#### T1547.002 - Authentication Package

Description:

Adversaries may abuse authentication packages to execute DLLs when the system boots. Windows authentication package DLLs are loaded by the Local Security Authority (LSA) process at system start. They provide support for multiple logon processes and multiple security protocols to the operating system.(Citation: MSDN Authentication Packages)

Adversaries can use the autostart mechanism provided by LSA authentication packages for persistence by placing a reference to a binary in the Windows Registry location <code>HKLM\SYSTEM\CurrentControlSet\Control\Lsa\</code> with the key value of <code>"Authentication Packages"=&lt;target binary&gt;</code>. The binary will then be executed by the system when the authentication packages are loaded.

Procedures:

- [S0143] Flame: [Flame](https://attack.mitre.org/software/S0143) can use Windows Authentication Packages for persistence.(Citation: Crysys Skywiper)

#### T1547.003 - Time Providers

Description:

Adversaries may abuse time providers to execute DLLs when the system boots. The Windows Time service (W32Time) enables time synchronization across and within domains.(Citation: Microsoft W32Time Feb 2018) W32Time time providers are responsible for retrieving time stamps from hardware/network resources and outputting these values to other network clients.(Citation: Microsoft TimeProvider)

Time providers are implemented as dynamic-link libraries (DLLs) that are registered in the subkeys of `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\W32Time\TimeProviders\`.(Citation: Microsoft TimeProvider) The time provider manager, directed by the service control manager, loads and starts time providers listed and enabled under this key at system startup and/or whenever parameters are changed.(Citation: Microsoft TimeProvider)

Adversaries may abuse this architecture to establish persistence, specifically by creating a new arbitrarily named subkey  pointing to a malicious DLL in the `DllName` value. Administrator privileges are required for time provider registration, though execution will run in context of the Local Service account.(Citation: Github W32Time Oct 2017)

#### T1547.004 - Winlogon Helper DLL

Description:

Adversaries may abuse features of Winlogon to execute DLLs and/or executables when a user logs in. Winlogon.exe is a Windows component responsible for actions at logon/logoff as well as the secure attention sequence (SAS) triggered by Ctrl-Alt-Delete. Registry entries in <code>HKLM\Software[\\Wow6432Node\\]\Microsoft\Windows NT\CurrentVersion\Winlogon\</code> and <code>HKCU\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\</code> are used to manage additional helper programs and functionalities that support Winlogon.(Citation: Cylance Reg Persistence Sept 2013) 

Malicious modifications to these Registry keys may cause Winlogon to load and execute malicious DLLs and/or executables. Specifically, the following subkeys have been known to be possibly vulnerable to abuse: (Citation: Cylance Reg Persistence Sept 2013)

* Winlogon\Notify - points to notification package DLLs that handle Winlogon events
* Winlogon\Userinit - points to userinit.exe, the user initialization program executed when a user logs on
* Winlogon\Shell - points to explorer.exe, the system shell executed when a user logs on

Adversaries may take advantage of these features to repeatedly execute malicious code and establish persistence.

Procedures:

- [S0168] Gazer: [Gazer](https://attack.mitre.org/software/S0168) can establish persistence by setting the value “Shell” with “explorer.exe, %malware_pathfile%” under the Registry key <code>HKCU\Software\Microsoft\Windows NT\CurrentVersion\Winlogon</code>.(Citation: ESET Gazer Aug 2017)
- [S1066] DarkTortilla: [DarkTortilla](https://attack.mitre.org/software/S1066) has established persistence via the `Software\Microsoft\Windows NT\CurrentVersion\Winlogon` registry key.(Citation: Secureworks DarkTortilla Aug 2022)
- [S0200] Dipsind: A [Dipsind](https://attack.mitre.org/software/S0200) variant registers as a Winlogon Event Notify DLL to establish persistence.(Citation: Microsoft PLATINUM April 2016)
- [G0102] Wizard Spider: [Wizard Spider](https://attack.mitre.org/groups/G0102) has established persistence using Userinit by adding the Registry key HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon.(Citation: FireEye KEGTAP SINGLEMALT October 2020)
- [S0534] Bazar: [Bazar](https://attack.mitre.org/software/S0534) can use Winlogon Helper DLL to establish persistence.(Citation: Zscaler Bazar September 2020)
- [S0375] Remexi: [Remexi](https://attack.mitre.org/software/S0375) achieves persistence using Userinit by adding the Registry key <code>HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit</code>.(Citation: Securelist Remexi Jan 2019)
- [S0379] Revenge RAT: [Revenge RAT](https://attack.mitre.org/software/S0379) creates a Registry key at <code>HKCU\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell</code> to survive a system reboot.(Citation: Cylance Shaheen Nov 2018)
- [G0081] Tropic Trooper: [Tropic Trooper](https://attack.mitre.org/groups/G0081) has created the Registry key <code>HKCU\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell</code> and sets the value to establish persistence.(Citation: Unit 42 Tropic Trooper Nov 2016)(Citation: TrendMicro Tropic Trooper May 2020)
- [S1202] LockBit 3.0: [LockBit 3.0](https://attack.mitre.org/software/S1202) can enable automatic logon through the `SOFTWARE\Microsoft\Windows
NT\CurrentVersion\Winlogon` Registry key.(Citation: Joint Cybersecurity Advisory LockBit 3.0 MAR 2023)
- [G0010] Turla: [Turla](https://attack.mitre.org/groups/G0010) established persistence by adding a Shell value under the Registry key <code>HKCU\Software\Microsoft\Windows NT\CurrentVersion\Winlogon</code>.(Citation: ESET Turla Mosquito Jan 2018)
- [S0387] KeyBoy: [KeyBoy](https://attack.mitre.org/software/S0387) issues the command <code>reg add “HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon”</code> to achieve persistence.(Citation: PWC KeyBoys Feb 2017) (Citation: CitizenLab KeyBoy Nov 2016)
- [S0351] Cannon: [Cannon](https://attack.mitre.org/software/S0351) adds the Registry key <code>HKCU\Software\Microsoft\Windows NT\CurrentVersion\Winlogon</code> to establish persistence.(Citation: Unit42 Cannon Nov 2018)

#### T1547.005 - Security Support Provider

Description:

Adversaries may abuse security support providers (SSPs) to execute DLLs when the system boots. Windows SSP DLLs are loaded into the Local Security Authority (LSA) process at system start. Once loaded into the LSA, SSP DLLs have access to encrypted and plaintext passwords that are stored in Windows, such as any logged-on user's Domain password or smart card PINs.

The SSP configuration is stored in two Registry keys: <code>HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages</code> and <code>HKLM\SYSTEM\CurrentControlSet\Control\Lsa\OSConfig\Security Packages</code>. An adversary may modify these Registry keys to add new SSPs, which will be loaded the next time the system boots, or when the AddSecurityPackage Windows API function is called.(Citation: Graeber 2014)

Procedures:

- [S0002] Mimikatz: The [Mimikatz](https://attack.mitre.org/software/S0002) credential dumper contains an implementation of an SSP.(Citation: Deply Mimikatz)
- [S0363] Empire: [Empire](https://attack.mitre.org/software/S0363) can enumerate Security Support Providers (SSPs) as well as utilize [PowerSploit](https://attack.mitre.org/software/S0194)'s <code>Install-SSP</code> and <code>Invoke-Mimikatz</code> to install malicious SSPs and log authentication events.(Citation: Github PowerShell Empire)
- [S0194] PowerSploit: [PowerSploit](https://attack.mitre.org/software/S0194)'s <code>Install-SSP</code> Persistence module can be used to establish by installing a SSP DLL.(Citation: GitHub PowerSploit May 2012)(Citation: PowerSploit Documentation)

#### T1547.006 - Kernel Modules and Extensions

Description:

Adversaries may modify the kernel to automatically execute programs on system boot. Loadable Kernel Modules (LKMs) are pieces of code that can be loaded and unloaded into the kernel upon demand. They extend the functionality of the kernel without the need to reboot the system. For example, one type of module is the device driver, which allows the kernel to access hardware connected to the system.(Citation: Linux Kernel Programming) 

When used maliciously, LKMs can be a type of kernel-mode [Rootkit](https://attack.mitre.org/techniques/T1014) that run with the highest operating system privilege (Ring 0).(Citation: Linux Kernel Module Programming Guide) Common features of LKM based rootkits include: hiding itself, selective hiding of files, processes and network activity, as well as log tampering, providing authenticated backdoors, and enabling root access to non-privileged users.(Citation: iDefense Rootkit Overview)

Kernel extensions, also called kext, are used in macOS to load functionality onto a system similar to LKMs for Linux. Since the kernel is responsible for enforcing security and the kernel extensions run as apart of the kernel, kexts are not governed by macOS security policies. Kexts are loaded and unloaded through <code>kextload</code> and <code>kextunload</code> commands. Kexts need to be signed with a developer ID that is granted privileges by Apple allowing it to sign Kernel extensions. Developers without these privileges may still sign kexts but they will not load unless SIP is disabled. If SIP is enabled, the kext signature is verified before being added to the AuxKC.(Citation: System and kernel extensions in macOS)

Since macOS Catalina 10.15, kernel extensions have been deprecated in favor of System Extensions. However, kexts are still allowed as "Legacy System Extensions" since there is no System Extension for Kernel Programming Interfaces.(Citation: Apple Kernel Extension Deprecation)

Adversaries can use LKMs and kexts to conduct [Persistence](https://attack.mitre.org/tactics/TA0003) and/or [Privilege Escalation](https://attack.mitre.org/tactics/TA0004) on a system. Examples have been found in the wild, and there are some relevant open source projects as well.(Citation: Volatility Phalanx2)(Citation: CrowdStrike Linux Rootkit)(Citation: GitHub Reptile)(Citation: GitHub Diamorphine)(Citation: RSAC 2015 San Francisco Patrick Wardle)(Citation: Synack Secure Kernel Extension Broken)(Citation: Securelist Ventir)(Citation: Trend Micro Skidmap)

Procedures:

- [S0502] Drovorub: [Drovorub](https://attack.mitre.org/software/S0502) can use kernel modules to establish persistence.(Citation: NSA/FBI Drovorub August 2020)
- [S0468] Skidmap: [Skidmap](https://attack.mitre.org/software/S0468) has the ability to install several loadable kernel modules (LKMs) on infected machines.(Citation: Trend Micro Skidmap)
- [C0012] Operation CuckooBees: During [Operation CuckooBees](https://attack.mitre.org/campaigns/C0012), attackers used a signed kernel rootkit to establish additional persistence.(Citation: Cybereason OperationCuckooBees May 2022)

#### T1547.007 - Re-opened Applications

Description:

Adversaries may modify plist files to automatically run an application when a user logs in. When a user logs out or restarts via the macOS Graphical User Interface (GUI), a prompt is provided to the user with a checkbox to "Reopen windows when logging back in".(Citation: Re-Open windows on Mac) When selected, all applications currently open are added to a property list file named <code>com.apple.loginwindow.[UUID].plist</code> within the <code>~/Library/Preferences/ByHost</code> directory.(Citation: Methods of Mac Malware Persistence)(Citation: Wardle Persistence Chapter) Applications listed in this file are automatically reopened upon the user’s next logon.

Adversaries can establish [Persistence](https://attack.mitre.org/tactics/TA0003) by adding a malicious application path to the <code>com.apple.loginwindow.[UUID].plist</code> file to execute payloads when a user logs in.

#### T1547.008 - LSASS Driver

Description:

Adversaries may modify or add LSASS drivers to obtain persistence on compromised systems. The Windows security subsystem is a set of components that manage and enforce the security policy for a computer or domain. The Local Security Authority (LSA) is the main component responsible for local security policy and user authentication. The LSA includes multiple dynamic link libraries (DLLs) associated with various other security functions, all of which run in the context of the LSA Subsystem Service (LSASS) lsass.exe process.(Citation: Microsoft Security Subsystem)

Adversaries may target LSASS drivers to obtain persistence. By either replacing or adding illegitimate drivers (e.g., [Hijack Execution Flow](https://attack.mitre.org/techniques/T1574)), an adversary can use LSA operations to continuously execute malicious payloads.

Procedures:

- [S0176] Wingbird: [Wingbird](https://attack.mitre.org/software/S0176) drops a malicious file (sspisrv.dll) alongside a copy of lsass.exe, which is used to register a service that loads sspisrv.dll as a driver. The payload of the malicious driver (located in its entry-point function) is executed when loaded by lsass.exe before the spoofed service becomes unstable and crashes.(Citation: Microsoft SIR Vol 21)(Citation: Microsoft Wingbird Nov 2017)
- [S0208] Pasam: [Pasam](https://attack.mitre.org/software/S0208) establishes by infecting the Security Accounts Manager (SAM) DLL to load a malicious DLL dropped to disk.(Citation: Symantec Pasam May 2012)

#### T1547.009 - Shortcut Modification

Description:

Adversaries may create or modify shortcuts that can execute a program during system boot or user login. Shortcuts or symbolic links are used to reference other files or programs that will be opened or executed when the shortcut is clicked or executed by a system startup process.

Adversaries may abuse shortcuts in the startup folder to execute their tools and achieve persistence.(Citation: Shortcut for Persistence ) Although often used as payloads in an infection chain (e.g. [Spearphishing Attachment](https://attack.mitre.org/techniques/T1566/001)), adversaries may also create a new shortcut as a means of indirection, while also abusing [Masquerading](https://attack.mitre.org/techniques/T1036) to make the malicious shortcut appear as a legitimate program. Adversaries can also edit the target path or entirely replace an existing shortcut so their malware will be executed instead of the intended legitimate program.

Shortcuts can also be abused to establish persistence by implementing other methods. For example, LNK browser extensions may be modified (e.g. [Browser Extensions](https://attack.mitre.org/techniques/T1176/001)) to persistently launch malware.

Procedures:

- [S0270] RogueRobin: [RogueRobin](https://attack.mitre.org/software/S0270) establishes persistence by creating a shortcut (.LNK file) in the Windows startup folder to run a script each time the user logs in.(Citation: Unit 42 DarkHydrus July 2018)(Citation: Unit42 DarkHydrus Jan 2019)
- [S0153] RedLeaves: [RedLeaves](https://attack.mitre.org/software/S0153) attempts to add a shortcut file in the Startup folder to achieve persistence.(Citation: PWC Cloud Hopper Technical Annex April 2017)(Citation: Accenture Hogfish April 2018)
- [S0439] Okrum: [Okrum](https://attack.mitre.org/software/S0439) can establish persistence by creating a .lnk shortcut to itself in the Startup folder.(Citation: ESET Okrum July 2019)
- [S0172] Reaver: [Reaver](https://attack.mitre.org/software/S0172) creates a shortcut file and saves it in a Startup folder to establish persistence.(Citation: Palo Alto Reaver Nov 2017)
- [S0531] Grandoreiro: [Grandoreiro](https://attack.mitre.org/software/S0531) can write or modify browser shortcuts to enable launching of malicious browser extensions.(Citation: IBM Grandoreiro April 2020)
- [G0087] APT39: [APT39](https://attack.mitre.org/groups/G0087) has modified LNK shortcuts.(Citation: FireEye APT39 Jan 2019)
- [S0170] Helminth: [Helminth](https://attack.mitre.org/software/S0170) establishes persistence by creating a shortcut.(Citation: Palo Alto OilRig May 2016)
- [S0652] MarkiRAT: [MarkiRAT](https://attack.mitre.org/software/S0652) can modify the shortcut that launches Telegram by replacing its path with the malicious payload to launch with the legitimate executable.(Citation: Kaspersky Ferocious Kitten Jun 2021)
- [S0339] Micropsia: [Micropsia](https://attack.mitre.org/software/S0339) creates a shortcut to maintain persistence.(Citation: Talos Micropsia June 2017)
- [G0065] Leviathan: [Leviathan](https://attack.mitre.org/groups/G0065) has used JavaScript to create a shortcut file in the Startup folder that points to its main backdoor.(Citation: Proofpoint Leviathan Oct 2017)(Citation: FireEye Periscope March 2018)
- [S0058] SslMM: To establish persistence, [SslMM](https://attack.mitre.org/software/S0058) identifies the Start Menu Startup directory and drops a link to its own executable disguised as an “Office Start,” “Yahoo Talk,” “MSN Gaming Z0ne,” or “MSN Talk” shortcut.(Citation: Baumgartner Naikon 2015)
- [G0032] Lazarus Group: [Lazarus Group](https://attack.mitre.org/groups/G0032) malware has maintained persistence on a system by creating a LNK shortcut in the user’s Startup folder.(Citation: McAfee Lazarus Resurfaces Feb 2018)
- [S0244] Comnie: [Comnie](https://attack.mitre.org/software/S0244) establishes persistence via a .lnk file in the victim’s startup path.(Citation: Palo Alto Comnie)
- [S0168] Gazer: [Gazer](https://attack.mitre.org/software/S0168) can establish persistence by creating a .lnk file in the Start menu or by modifying existing .lnk files to execute the malware through cmd.exe.(Citation: ESET Gazer Aug 2017)(Citation: Securelist WhiteBear Aug 2017)
- [S0089] BlackEnergy: The [BlackEnergy](https://attack.mitre.org/software/S0089) 3 variant drops its main DLL component and then creates a .lnk shortcut to that file in the startup folder.(Citation: F-Secure BlackEnergy 2014)
- [S0035] SPACESHIP: [SPACESHIP](https://attack.mitre.org/software/S0035) achieves persistence by creating a shortcut in the current user's Startup folder.(Citation: FireEye APT30)
- [S0004] TinyZBot: [TinyZBot](https://attack.mitre.org/software/S0004) can create a shortcut in the Windows startup folder for persistence.(Citation: Cylance Cleaver)
- [S0373] Astaroth: [Astaroth](https://attack.mitre.org/software/S0373)'s initial payload is a malicious .LNK file. (Citation: Cofense Astaroth Sept 2018)(Citation: Cybereason Astaroth Feb 2019)
- [S0085] S-Type: [S-Type](https://attack.mitre.org/software/S0085) may create the file <code>%HOMEPATH%\Start Menu\Programs\Startup\Realtek {Unique Identifier}.lnk</code>, which points to the malicious `msdtc.exe` file already created in the `%CommonFiles%` directory.(Citation: Cylance Dust Storm)
- [S0028] SHIPSHAPE: [SHIPSHAPE](https://attack.mitre.org/software/S0028) achieves persistence by creating a shortcut in the Startup folder.(Citation: FireEye APT30)
- [G0078] Gorgon Group: [Gorgon Group](https://attack.mitre.org/groups/G0078) malware can create a .lnk file and add a Registry Run key to establish persistence.(Citation: Unit 42 Gorgon Group Aug 2018)
- [S0031] BACKSPACE: [BACKSPACE](https://attack.mitre.org/software/S0031) achieves persistence by creating a shortcut to itself in the CSIDL_STARTUP directory.(Citation: FireEye APT30)
- [S0053] SeaDuke: [SeaDuke](https://attack.mitre.org/software/S0053) is capable of persisting via a .lnk file stored in the Startup directory.(Citation: Unit 42 SeaDuke 2015)
- [S0260] InvisiMole: [InvisiMole](https://attack.mitre.org/software/S0260) can use a .lnk shortcut for the Control Panel to establish persistence.(Citation: ESET InvisiMole June 2020)
- [S0267] FELIXROOT: [FELIXROOT](https://attack.mitre.org/software/S0267) creates a .LNK file for persistence.(Citation: ESET GreyEnergy Oct 2018)
- [S0356] KONNI: A version of [KONNI](https://attack.mitre.org/software/S0356) drops a Windows shortcut on the victim’s machine to establish persistence.(Citation: Talos Konni May 2017)
- [S0534] Bazar: [Bazar](https://attack.mitre.org/software/S0534) can establish persistence by writing shortcuts to the Windows Startup folder.(Citation: Cybereason Bazar July 2020)(Citation: NCC Group Team9 June 2020)
- [S0363] Empire: [Empire](https://attack.mitre.org/software/S0363) can persist by modifying a .LNK file to include a backdoor.(Citation: Github PowerShell Empire)
- [S0265] Kazuar: [Kazuar](https://attack.mitre.org/software/S0265) adds a .lnk file to the Windows startup folder.(Citation: Unit 42 Kazuar May 2017)

#### T1547.010 - Port Monitors

Description:

Adversaries may use port monitors to run an adversary supplied DLL during system boot for persistence or privilege escalation. A port monitor can be set through the <code>AddMonitor</code> API call to set a DLL to be loaded at startup.(Citation: AddMonitor) This DLL can be located in <code>C:\Windows\System32</code> and will be loaded and run by the print spooler service, `spoolsv.exe`, under SYSTEM level permissions on boot.(Citation: Bloxham) 

Alternatively, an arbitrary DLL can be loaded if permissions allow writing a fully-qualified pathname for that DLL to the `Driver` value of an existing or new arbitrarily named subkey of <code>HKLM\SYSTEM\CurrentControlSet\Control\Print\Monitors</code>. The Registry key contains entries for the following:

* Local Port
* Standard TCP/IP Port
* USB Monitor
* WSD Port

#### T1547.012 - Print Processors

Description:

Adversaries may abuse print processors to run malicious DLLs during system boot for persistence and/or privilege escalation. Print processors are DLLs that are loaded by the print spooler service, `spoolsv.exe`, during boot.(Citation: Microsoft Intro Print Processors)

Adversaries may abuse the print spooler service by adding print processors that load malicious DLLs at startup. A print processor can be installed through the <code>AddPrintProcessor</code> API call with an account that has <code>SeLoadDriverPrivilege</code> enabled. Alternatively, a print processor can be registered to the print spooler service by adding the <code>HKLM\SYSTEM\\[CurrentControlSet or ControlSet001]\Control\Print\Environments\\[Windows architecture: e.g., Windows x64]\Print Processors\\[user defined]\Driver</code> Registry key that points to the DLL.

For the malicious print processor to be correctly installed, the payload must be located in the dedicated system print-processor directory, that can be found with the <code>GetPrintProcessorDirectory</code> API call, or referenced via a relative path from this directory.(Citation: Microsoft AddPrintProcessor May 2018) After the print processors are installed, the print spooler service, which starts during boot, must be restarted in order for them to run.(Citation: ESET PipeMon May 2020)

The print spooler service runs under SYSTEM level permissions, therefore print processors installed by an adversary may run under elevated privileges.

Procedures:

- [S0666] Gelsemium: [Gelsemium](https://attack.mitre.org/software/S0666) can drop itself in <code>C:\Windows\System32\spool\prtprocs\x64\winprint.dll</code> to be loaded automatically by the spoolsv Windows service.(Citation: ESET Gelsemium June 2021)
- [G1006] Earth Lusca: [Earth Lusca](https://attack.mitre.org/groups/G1006) has added the Registry key `HKLM\SYSTEM\ControlSet001\Control\Print\Environments\Windows x64\Print Processors\UDPrint” /v Driver /d “spool.dll /f` to load malware as a Print Processor.(Citation: TrendMicro EarthLusca 2022)
- [S0501] PipeMon: The [PipeMon](https://attack.mitre.org/software/S0501) installer has modified the Registry key <code>HKLM\SYSTEM\CurrentControlSet\Control\Print\Environments\Windows x64\Print Processors</code> to install [PipeMon](https://attack.mitre.org/software/S0501) as a Print Processor.(Citation: ESET PipeMon May 2020)

#### T1547.013 - XDG Autostart Entries

Description:

Adversaries may add or modify XDG Autostart Entries to execute malicious programs or commands when a user’s desktop environment is loaded at login. XDG Autostart entries are available for any XDG-compliant Linux system. XDG Autostart entries use Desktop Entry files (`.desktop`) to configure the user’s desktop environment upon user login. These configuration files determine what applications launch upon user login, define associated applications to open specific file types, and define applications used to open removable media.(Citation: Free Desktop Application Autostart Feb 2006)(Citation: Free Desktop Entry Keys)

Adversaries may abuse this feature to establish persistence by adding a path to a malicious binary or command to the `Exec` directive in the `.desktop` configuration file. When the user’s desktop environment is loaded at user login, the `.desktop` files located in the XDG Autostart directories are automatically executed. System-wide Autostart entries are located in the `/etc/xdg/autostart` directory while the user entries are located in the `~/.config/autostart` directory.

Adversaries may combine this technique with [Masquerading](https://attack.mitre.org/techniques/T1036) to blend malicious Autostart entries with legitimate programs.(Citation: Red Canary Netwire Linux 2022)

Procedures:

- [S0198] NETWIRE: [NETWIRE](https://attack.mitre.org/software/S0198) can use XDG Autostart Entries to establish persistence on Linux systems.(Citation: Red Canary NETWIRE January 2020)
- [S0192] Pupy: [Pupy](https://attack.mitre.org/software/S0192) can use an XDG Autostart to establish persistence.(Citation: Red Canary Netwire Linux 2022)
- [S0235] CrossRAT: [CrossRAT](https://attack.mitre.org/software/S0235) can use an XDG Autostart to establish persistence.(Citation: Red Canary Netwire Linux 2022)
- [S1078] RotaJakiro: When executing with user-level permissions, [RotaJakiro](https://attack.mitre.org/software/S1078) can install persistence using a .desktop file under the `$HOME/.config/autostart/` folder.(Citation: RotaJakiro 2021 netlab360 analysis)
- [S0410] Fysbis: If executing without root privileges, [Fysbis](https://attack.mitre.org/software/S0410) adds a `.desktop` configuration file to the user's `~/.config/autostart` directory.(Citation: Red Canary Netwire Linux 2022)(Citation: Fysbis Dr Web Analysis)

#### T1547.014 - Active Setup

Description:

Adversaries may achieve persistence by adding a Registry key to the Active Setup of the local machine. Active Setup is a Windows mechanism that is used to execute programs when a user logs in. The value stored in the Registry key will be executed after a user logs into the computer.(Citation: Klein Active Setup 2010) These programs will be executed under the context of the user and will have the account's associated permissions level.

Adversaries may abuse Active Setup by creating a key under <code> HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components\</code> and setting a malicious value for <code>StubPath</code>. This value will serve as the program that will be executed when a user logs into the computer.(Citation: Mandiant Glyer APT 2010)(Citation: Citizenlab Packrat 2015)(Citation: FireEye CFR Watering Hole 2012)(Citation: SECURELIST Bright Star 2015)(Citation: paloalto Tropic Trooper 2016)

Adversaries can abuse these components to execute malware, such as remote access tools, to maintain persistence through system reboots. Adversaries may also use [Masquerading](https://attack.mitre.org/techniques/T1036) to make the Registry entries look as if they are associated with legitimate programs.

Procedures:

- [S0012] PoisonIvy: [PoisonIvy](https://attack.mitre.org/software/S0012) creates a Registry key in the Active Setup pointing to a malicious executable.(Citation: Microsoft PoisonIvy 2017)(Citation: paloalto Tropic Trooper 2016)(Citation: FireEye Regsvr32 Targeting Mongolian Gov)

#### T1547.015 - Login Items

Description:

Adversaries may add login items to execute upon user login to gain persistence or escalate privileges. Login items are applications, documents, folders, or server connections that are automatically launched when a user logs in.(Citation: Open Login Items Apple) Login items can be added via a shared file list or Service Management Framework.(Citation: Adding Login Items) Shared file list login items can be set using scripting languages such as [AppleScript](https://attack.mitre.org/techniques/T1059/002), whereas the Service Management Framework uses the API call <code>SMLoginItemSetEnabled</code>.

Login items installed using the Service Management Framework leverage <code>launchd</code>, are not visible in the System Preferences, and can only be removed by the application that created them.(Citation: Adding Login Items)(Citation: SMLoginItemSetEnabled Schroeder 2013) Login items created using a shared file list are visible in System Preferences, can hide the application when it launches, and are executed through LaunchServices, not launchd, to open applications, documents, or URLs without using Finder.(Citation: Launch Services Apple Developer) Users and applications use login items to configure their user environment to launch commonly used services or applications, such as email, chat, and music applications.

Adversaries can utilize [AppleScript](https://attack.mitre.org/techniques/T1059/002) and [Native API](https://attack.mitre.org/techniques/T1106) calls to create a login item to spawn malicious executables.(Citation: ELC Running at startup) Prior to version 10.5 on macOS, adversaries can add login items by using [AppleScript](https://attack.mitre.org/techniques/T1059/002) to send an Apple events to the “System Events” process, which has an AppleScript dictionary for manipulating login items.(Citation: Login Items AE) Adversaries can use a command such as <code>tell application “System Events” to make login item at end with properties /path/to/executable</code>.(Citation: Startup Items Eclectic)(Citation: hexed osx.dok analysis 2019)(Citation: Add List Remove Login Items Apple Script) This command adds the path of the malicious executable to the login item file list located in <code>~/Library/Application Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm</code>.(Citation: Startup Items Eclectic) Adversaries can also use login items to launch executables that can be used to control the victim system remotely or as a means to gain privilege escalation by prompting for user credentials.(Citation: objsee mac malware 2017)(Citation: CheckPoint Dok)(Citation: objsee netwire backdoor 2019)

Procedures:

- [S0690] Green Lambert: [Green Lambert](https://attack.mitre.org/software/S0690) can add [Login Items](https://attack.mitre.org/techniques/T1547/015) to establish persistence.(Citation: Objective See Green Lambert for OSX Oct 2021)(Citation: Glitch-Cat Green Lambert ATTCK Oct 2021)
- [S0198] NETWIRE: [NETWIRE](https://attack.mitre.org/software/S0198) can persist via startup options for Login items.(Citation: Red Canary NETWIRE January 2020)
- [S0281] Dok: [Dok](https://attack.mitre.org/software/S0281) uses AppleScript to install a login Item by sending Apple events to the <code>System Events</code> process.(Citation: hexed osx.dok analysis 2019)


### T1548 - Abuse Elevation Control Mechanism

Description:

Adversaries may circumvent mechanisms designed to control elevate privileges to gain higher-level permissions. Most modern systems contain native elevation control mechanisms that are intended to limit privileges that a user can perform on a machine. Authorization has to be granted to specific users in order to perform tasks that can be considered of higher risk.(Citation: TechNet How UAC Works)(Citation: sudo man page 2018) An adversary can perform several methods to take advantage of built-in control mechanisms in order to escalate privileges on a system.(Citation: OSX Keydnap malware)(Citation: Fortinet Fareit)

Procedures:

- [S1130] Raspberry Robin: [Raspberry Robin](https://attack.mitre.org/software/S1130) implements a variation of the <code>ucmDccwCOMMethod</code> technique abusing the Windows AutoElevate backdoor to bypass UAC while elevating privileges.(Citation: TrendMicro RaspberryRobin 2022)

#### T1548.001 - Setuid and Setgid

Description:

An adversary may abuse configurations where an application has the setuid or setgid bits set in order to get code running in a different (and possibly more privileged) user’s context. On Linux or macOS, when the setuid or setgid bits are set for an application binary, the application will run with the privileges of the owning user or group respectively.(Citation: setuid man page) Normally an application is run in the current user’s context, regardless of which user or group owns the application. However, there are instances where programs need to be executed in an elevated context to function properly, but the user running them may not have the specific required privileges.

Instead of creating an entry in the sudoers file, which must be done by root, any user can specify the setuid or setgid flag to be set for their own applications (i.e. [Linux and Mac File and Directory Permissions Modification](https://attack.mitre.org/techniques/T1222/002)). The <code>chmod</code> command can set these bits with bitmasking, <code>chmod 4777 [file]</code> or via shorthand naming, <code>chmod u+s [file]</code>. This will enable the setuid bit. To enable the setgid bit, <code>chmod 2775</code> and <code>chmod g+s</code> can be used.

Adversaries can use this mechanism on their own malware to make sure they're able to execute in elevated contexts in the future.(Citation: OSX Keydnap malware) This abuse is often part of a "shell escape" or other actions to bypass an execution environment with restricted permissions.

Alternatively, adversaries may choose to find and target vulnerable binaries with the setuid or setgid bits already enabled (i.e. [File and Directory Discovery](https://attack.mitre.org/techniques/T1083)). The setuid and setguid bits are indicated with an "s" instead of an "x" when viewing a file's attributes via <code>ls -l</code>. The <code>find</code> command can also be used to search for such files. For example, <code>find / -perm +4000 2>/dev/null</code> can be used to find files with setuid set and <code>find / -perm +2000 2>/dev/null</code> may be used for setgid. Binaries that have these bits set may then be abused by adversaries.(Citation: GTFOBins Suid)

Procedures:

- [S0276] Keydnap: [Keydnap](https://attack.mitre.org/software/S0276) adds the setuid flag to a binary so it can easily elevate in the future.(Citation: OSX Keydnap malware)
- [S0401] Exaramel for Linux: [Exaramel for Linux](https://attack.mitre.org/software/S0401) can execute commands with high privileges via a specific binary with setuid functionality.(Citation: ANSSI Sandworm January 2021)

#### T1548.002 - Bypass User Account Control

Description:

Adversaries may bypass UAC mechanisms to elevate process privileges on system. Windows User Account Control (UAC) allows a program to elevate its privileges (tracked as integrity levels ranging from low to high) to perform a task under administrator-level permissions, possibly by prompting the user for confirmation. The impact to the user ranges from denying the operation under high enforcement to allowing the user to perform the action if they are in the local administrators group and click through the prompt or allowing them to enter an administrator password to complete the action.(Citation: TechNet How UAC Works)

If the UAC protection level of a computer is set to anything but the highest level, certain Windows programs can elevate privileges or execute some elevated [Component Object Model](https://attack.mitre.org/techniques/T1559/001) objects without prompting the user through the UAC notification box.(Citation: TechNet Inside UAC)(Citation: MSDN COM Elevation) An example of this is use of [Rundll32](https://attack.mitre.org/techniques/T1218/011) to load a specifically crafted DLL which loads an auto-elevated [Component Object Model](https://attack.mitre.org/techniques/T1559/001) object and performs a file operation in a protected directory which would typically require elevated access. Malicious software may also be injected into a trusted process to gain elevated privileges without prompting a user.(Citation: Davidson Windows)

Many methods have been discovered to bypass UAC. The Github readme page for UACME contains an extensive list of methods(Citation: Github UACMe) that have been discovered and implemented, but may not be a comprehensive list of bypasses. Additional bypass methods are regularly discovered and some used in the wild, such as:

* <code>eventvwr.exe</code> can auto-elevate and execute a specified binary or script.(Citation: enigma0x3 Fileless UAC Bypass)(Citation: Fortinet Fareit)

Another bypass is possible through some lateral movement techniques if credentials for an account with administrator privileges are known, since UAC is a single system security mechanism, and the privilege or integrity of a process running on one system will be unknown on remote systems and default to high integrity.(Citation: SANS UAC Bypass)

Procedures:

- [S0089] BlackEnergy: [BlackEnergy](https://attack.mitre.org/software/S0089) attempts to bypass default User Access Control (UAC) settings by exploiting a backward-compatibility setting found in Windows 7 and later.(Citation: F-Secure BlackEnergy 2014)
- [S0148] RTM: [RTM](https://attack.mitre.org/software/S0148) can attempt to run the program as admin, then show a fake error message and a legitimate UAC bypass prompt to the user in an attempt to socially engineer the user into escalating privileges.(Citation: ESET RTM Feb 2017)
- [S1202] LockBit 3.0: [LockBit 3.0](https://attack.mitre.org/software/S1202) can bypass UAC to execute code with elevated privileges through an elevated Component Object Model (COM) interface.(Citation: Joint Cybersecurity Advisory LockBit 3.0 MAR 2023)
- [S0154] Cobalt Strike: [Cobalt Strike](https://attack.mitre.org/software/S0154) can use a number of known techniques to bypass Windows UAC.(Citation: cobaltstrike manual)(Citation: Cobalt Strike Manual 4.3 November 2020)
- [S0666] Gelsemium: [Gelsemium](https://attack.mitre.org/software/S0666) can bypass UAC to elevate process privileges on a compromised host.(Citation: ESET Gelsemium June 2021)
- [S0230] ZeroT: Many [ZeroT](https://attack.mitre.org/software/S0230) samples can perform UAC bypass by using eventvwr.exe to execute a malicious file.(Citation: Proofpoint ZeroT Feb 2017)
- [S1018] Saint Bot: [Saint Bot](https://attack.mitre.org/software/S1018) has attempted to bypass UAC using `fodhelper.exe` to escalate privileges.(Citation: Palo Alto Unit 42 OutSteel SaintBot February 2022 )
- [S1111] DarkGate: [DarkGate](https://attack.mitre.org/software/S1111) uses two distinct User Account Control (UAC) bypass techniques to escalate privileges.(Citation: Ensilo Darkgate 2018)
- [G0082] APT38: [APT38](https://attack.mitre.org/groups/G0082) has used the legitimate application `ieinstal.exe` to bypass UAC.(Citation: 1 - appv)
- [S0670] WarzoneRAT: [WarzoneRAT](https://attack.mitre.org/software/S0670) can use `sdclt.exe` to bypass UAC in Windows 10 to escalate privileges; for older Windows versions [WarzoneRAT](https://attack.mitre.org/software/S0670) can use the IFileOperation exploit to bypass the UAC module.(Citation: Check Point Warzone Feb 2020)(Citation: Uptycs Warzone UAC Bypass November 2020)
- [S0192] Pupy: [Pupy](https://attack.mitre.org/software/S0192) can bypass Windows UAC through either DLL hijacking, eventvwr, or appPaths.(Citation: GitHub Pupy)
- [S0378] PoshC2: [PoshC2](https://attack.mitre.org/software/S0378) can utilize multiple methods to bypass UAC.(Citation: GitHub PoshC2)
- [S0356] KONNI: [KONNI](https://attack.mitre.org/software/S0356) has bypassed UAC by performing token impersonation as well as an RPC-based method, this included bypassing UAC set to “AlwaysNotify".(Citation: Medium KONNI Jan 2020)(Citation: Malwarebytes Konni Aug 2021)
- [S0074] Sakula: [Sakula](https://attack.mitre.org/software/S0074) contains UAC bypass code for both 32- and 64-bit systems.(Citation: Dell Sakula)
- [S0444] ShimRat: [ShimRat](https://attack.mitre.org/software/S0444) has hijacked the cryptbase.dll within migwiz.exe to escalate privileges. This prevented the User Access Control window from appearing.(Citation: FOX-IT May 2016 Mofang)
- [S1068] BlackCat: [BlackCat](https://attack.mitre.org/software/S1068) can bypass UAC to escalate privileges.(Citation: Microsoft BlackCat Jun 2022)
- [S1199] LockBit 2.0: [LockBit 2.0](https://attack.mitre.org/software/S1199) can bypass UAC through creating the Registry key  `HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\ICM\Calibration`.(Citation: FBI Lockbit 2.0 FEB 2022)(Citation: Palo Alto Lockbit 2.0 JUN 2022)
- [G0120] Evilnum: [Evilnum](https://attack.mitre.org/groups/G0120) has used PowerShell to bypass UAC.(Citation: ESET EvilNum July 2020)
- [G0067] APT37: [APT37](https://attack.mitre.org/groups/G0067) has a function in the initial dropper to bypass Windows UAC in order to execute the next payload with higher privileges.(Citation: Securelist ScarCruft May 2019)
- [G0060] BRONZE BUTLER: [BRONZE BUTLER](https://attack.mitre.org/groups/G0060) has used a Windows 10 specific tool and xxmm to bypass UAC for privilege escalation.(Citation: Secureworks BRONZE BUTLER Oct 2017)(Citation: Trend Micro Tick November 2019)
- [S0129] AutoIt backdoor: [AutoIt backdoor](https://attack.mitre.org/software/S0129) attempts to escalate privileges by bypassing User Access Control.(Citation: Forcepoint Monsoon)
- [S0182] FinFisher: [FinFisher](https://attack.mitre.org/software/S0182) performs UAC bypass.(Citation: FinFisher Citation)(Citation: Microsoft FinFisher March 2018)
- [S0606] Bad Rabbit: [Bad Rabbit](https://attack.mitre.org/software/S0606) has attempted to bypass UAC and gain elevated administrative privileges.(Citation: Secure List Bad Rabbit)
- [S0134] Downdelph: [Downdelph](https://attack.mitre.org/software/S0134) bypasses UAC to escalate privileges by using a custom “RedirectEXE” shim database.(Citation: ESET Sednit Part 3)
- [S0250] Koadic: [Koadic](https://attack.mitre.org/software/S0250) has 2 methods for elevating integrity. It can bypass UAC through `eventvwr.exe` and `sdclt.exe`.(Citation: Github Koadic)
- [S0640] Avaddon: [Avaddon](https://attack.mitre.org/software/S0640) bypasses UAC using the CMSTPLUA COM interface.(Citation: Arxiv Avaddon Feb 2021)
- [S0262] QuasarRAT: [QuasarRAT](https://attack.mitre.org/software/S0262) can generate a UAC pop-up Window to prompt the target user to run a command as the administrator.(Citation: CISA AR18-352A Quasar RAT December 2018)
- [S0141] Winnti for Windows: [Winnti for Windows](https://attack.mitre.org/software/S0141) can use a variant of the sysprep UAC bypass.(Citation: Novetta Winnti April 2015)
- [S0612] WastedLocker: [WastedLocker](https://attack.mitre.org/software/S0612) can perform a UAC bypass if it is not executed with administrator rights or if the infected host runs Windows Vista or later.(Citation: NCC Group WastedLocker June 2020)
- [G0069] MuddyWater: [MuddyWater](https://attack.mitre.org/groups/G0069) uses various techniques to bypass UAC.(Citation: ClearSky MuddyWater Nov 2018)
- [S0501] PipeMon: [PipeMon](https://attack.mitre.org/software/S0501) installer can use UAC bypass techniques to install the payload.(Citation: ESET PipeMon May 2020)
- [S0447] Lokibot: [Lokibot](https://attack.mitre.org/software/S0447) has utilized multiple techniques to bypass UAC.(Citation: Talos Lokibot Jan 2021)
- [S0132] H1N1: [H1N1](https://attack.mitre.org/software/S0132) bypasses user access control by using a DLL hijacking vulnerability in the Windows Update Standalone Installer (wusa.exe).(Citation: Cisco H1N1 Part 2)
- [G0080] Cobalt Group: [Cobalt Group](https://attack.mitre.org/groups/G0080) has bypassed UAC.(Citation: Group IB Cobalt Aug 2017)
- [S0254] PLAINTEE: An older variant of [PLAINTEE](https://attack.mitre.org/software/S0254) performs UAC bypass.(Citation: Rancor Unit42 June 2018)
- [S0332] Remcos: [Remcos](https://attack.mitre.org/software/S0332) has a command for UAC bypassing.(Citation: Fortinet Remcos Feb 2017)
- [S0458] Ramsay: [Ramsay](https://attack.mitre.org/software/S0458) can use [UACMe](https://attack.mitre.org/software/S0116) for privilege escalation.(Citation: Eset Ramsay May 2020)(Citation: Antiy CERT Ramsay April 2020)
- [S0570] BitPaymer: [BitPaymer](https://attack.mitre.org/software/S0570) can suppress UAC prompts by setting the <code>HKCU\Software\Classes\ms-settings\shell\open\command</code> registry key on Windows 10 or <code>HKCU\Software\Classes\mscfile\shell\open\command</code> on Windows 7 and launching the <code>eventvwr.msc</code> process, which launches [BitPaymer](https://attack.mitre.org/software/S0570) with elevated privileges.(Citation: Crowdstrike Indrik November 2018)
- [G1006] Earth Lusca: [Earth Lusca](https://attack.mitre.org/groups/G1006) has used the Fodhelper UAC bypass technique to gain elevated privileges.(Citation: TrendMicro EarthLusca 2022)
- [C0006] Operation Honeybee: During [Operation Honeybee](https://attack.mitre.org/campaigns/C0006), the threat actors used the malicious NTWDBLIB.DLL and `cliconfig.exe` to bypass UAC protections.(Citation: McAfee Honeybee)
- [S0527] CSPY Downloader: [CSPY Downloader](https://attack.mitre.org/software/S0527) can bypass UAC using the SilentCleanup task to execute the binary with elevated privileges.(Citation: Cybereason Kimsuky November 2020)
- [S1039] Bumblebee: [Bumblebee](https://attack.mitre.org/software/S1039) has the ability to bypass UAC to deploy post exploitation tools with elevated privileges.(Citation: Cybereason Bumblebee August 2022)
- [G0027] Threat Group-3390: A [Threat Group-3390](https://attack.mitre.org/groups/G0027) tool can use a public UAC bypass method to elevate privileges.(Citation: Nccgroup Emissary Panda May 2018)
- [S0531] Grandoreiro: [Grandoreiro](https://attack.mitre.org/software/S0531) can bypass UAC by registering as the default handler for .MSC files.(Citation: ESET Grandoreiro April 2020)
- [S0660] Clambling: [Clambling](https://attack.mitre.org/software/S0660) has the ability to bypass UAC using a `passuac.dll` file.(Citation: Trend Micro DRBControl February 2020)(Citation: Talent-Jump Clambling February 2020)
- [S0140] Shamoon: [Shamoon](https://attack.mitre.org/software/S0140) attempts to disable UAC remote restrictions by modifying the Registry.(Citation: Palo Alto Shamoon Nov 2016)
- [S0692] SILENTTRINITY: [SILENTTRINITY](https://attack.mitre.org/software/S0692) contains a number of modules that can bypass UAC, including through Window's Device Manager, Manage Optional Features, and an image hijack on the `.msc` file extension.(Citation: GitHub SILENTTRINITY Modules July 2019)
- [S0584] AppleJeus: [AppleJeus](https://attack.mitre.org/software/S0584) has presented the user with a UAC prompt to elevate privileges while installing.(Citation: CISA AppleJeus Feb 2021)
- [S0260] InvisiMole: [InvisiMole](https://attack.mitre.org/software/S0260) can use fileless UAC bypass and create an elevated COM object to escalate privileges.(Citation: ESET InvisiMole June 2018)(Citation: ESET InvisiMole June 2020)
- [S0669] KOCTOPUS: [KOCTOPUS](https://attack.mitre.org/software/S0669) will perform UAC bypass either through fodhelper.exe or eventvwr.exe.(Citation: MalwareBytes LazyScripter Feb 2021)
- [S0633] Sliver: [Sliver](https://attack.mitre.org/software/S0633) can leverage multiple techniques to bypass User Account Control (UAC) on Windows systems.(Citation: Cybereason Sliver Undated)
- [G0040] Patchwork: [Patchwork](https://attack.mitre.org/groups/G0040) bypassed User Access Control (UAC).(Citation: Cymmetria Patchwork)
- [S1149] CHIMNEYSWEEP: [CHIMNEYSWEEP](https://attack.mitre.org/software/S1149) can make use of the Windows `SilentCleanup` scheduled task to execute its payload with elevated privileges.(Citation: Mandiant ROADSWEEP August 2022)
- [S1130] Raspberry Robin: [Raspberry Robin](https://attack.mitre.org/software/S1130) will use the legitimate Windows utility fodhelper.exe to run processes at elevated privileges without requiring a User Account Control prompt.(Citation: RedCanary RaspberryRobin 2022)
- [S1081] BADHATCH: [BADHATCH](https://attack.mitre.org/software/S1081) can utilize the CMSTPLUA COM interface and the SilentCleanup task to bypass UAC.(Citation: BitDefender BADHATCH Mar 2021)
- [S0116] UACMe: [UACMe](https://attack.mitre.org/software/S0116) contains many methods for bypassing Windows User Account Control on multiple versions of the operating system.(Citation: Github UACMe)
- [S0363] Empire: [Empire](https://attack.mitre.org/software/S0363) includes various modules to attempt to bypass UAC for escalation of privileges.(Citation: Github PowerShell Empire)
- [S0662] RCSession: [RCSession](https://attack.mitre.org/software/S0662) can bypass UAC to escalate privileges.(Citation: Trend Micro DRBControl February 2020)
- [G0016] APT29: [APT29](https://attack.mitre.org/groups/G0016) has bypassed UAC.(Citation: Mandiant No Easy Breach)

#### T1548.003 - Sudo and Sudo Caching

Description:

Adversaries may perform sudo caching and/or use the sudoers file to elevate privileges. Adversaries may do this to execute commands as other users or spawn processes with higher privileges.

Within Linux and MacOS systems, sudo (sometimes referred to as "superuser do") allows users to perform commands from terminals with elevated privileges and to control who can perform these commands on the system. The <code>sudo</code> command "allows a system administrator to delegate authority to give certain users (or groups of users) the ability to run some (or all) commands as root or another user while providing an audit trail of the commands and their arguments."(Citation: sudo man page 2018) Since sudo was made for the system administrator, it has some useful configuration features such as a <code>timestamp_timeout</code>, which is the amount of time in minutes between instances of <code>sudo</code> before it will re-prompt for a password. This is because <code>sudo</code> has the ability to cache credentials for a period of time. Sudo creates (or touches) a file at <code>/var/db/sudo</code> with a timestamp of when sudo was last run to determine this timeout. Additionally, there is a <code>tty_tickets</code> variable that treats each new tty (terminal session) in isolation. This means that, for example, the sudo timeout of one tty will not affect another tty (you will have to type the password again).

The sudoers file, <code>/etc/sudoers</code>, describes which users can run which commands and from which terminals. This also describes which commands users can run as other users or groups. This provides the principle of least privilege such that users are running in their lowest possible permissions for most of the time and only elevate to other users or permissions as needed, typically by prompting for a password. However, the sudoers file can also specify when to not prompt users for passwords with a line like <code>user1 ALL=(ALL) NOPASSWD: ALL</code>.(Citation: OSX.Dok Malware) Elevated privileges are required to edit this file though.

Adversaries can also abuse poor configurations of these mechanisms to escalate privileges without needing the user's password. For example, <code>/var/db/sudo</code>'s timestamp can be monitored to see if it falls within the <code>timestamp_timeout</code> range. If it does, then malware can execute sudo commands without needing to supply the user's password. Additional, if <code>tty_tickets</code> is disabled, adversaries can do this from any tty for that user.

In the wild, malware has disabled <code>tty_tickets</code> to potentially make scripting easier by issuing <code>echo \'Defaults !tty_tickets\' >> /etc/sudoers</code>.(Citation: cybereason osx proton) In order for this change to be reflected, the malware also issued <code>killall Terminal</code>. As of macOS Sierra, the sudoers file has <code>tty_tickets</code> enabled by default.

Procedures:

- [S0154] Cobalt Strike: [Cobalt Strike](https://attack.mitre.org/software/S0154) can use <code>sudo</code> to run a command.(Citation: Cobalt Strike Manual 4.3 November 2020)
- [S0279] Proton: [Proton](https://attack.mitre.org/software/S0279) modifies the tty_tickets line in the sudoers file.(Citation: objsee mac malware 2017)
- [S0281] Dok: [Dok](https://attack.mitre.org/software/S0281) adds <code>admin  ALL=(ALL) NOPASSWD: ALL</code> to the <code>/etc/sudoers</code> file.(Citation: hexed osx.dok analysis 2019)

#### T1548.004 - Elevated Execution with Prompt

Description:

Adversaries may leverage the <code>AuthorizationExecuteWithPrivileges</code> API to escalate privileges by prompting the user for credentials.(Citation: AppleDocs AuthorizationExecuteWithPrivileges) The purpose of this API is to give application developers an easy way to perform operations with root privileges, such as for application installation or updating. This API does not validate that the program requesting root privileges comes from a reputable source or has been maliciously modified. 

Although this API is deprecated, it still fully functions in the latest releases of macOS. When calling this API, the user will be prompted to enter their credentials but no checks on the origin or integrity of the program are made. The program calling the API may also load world writable files which can be modified to perform malicious behavior with elevated privileges.

Adversaries may abuse <code>AuthorizationExecuteWithPrivileges</code> to obtain root privileges in order to install malicious software on victims and install persistence mechanisms.(Citation: Death by 1000 installers; it's all broken!)(Citation: Carbon Black Shlayer Feb 2019)(Citation: OSX Coldroot RAT) This technique may be combined with [Masquerading](https://attack.mitre.org/techniques/T1036) to trick the user into granting escalated privileges to malicious code.(Citation: Death by 1000 installers; it's all broken!)(Citation: Carbon Black Shlayer Feb 2019) This technique has also been shown to work by modifying legitimate programs present on the machine that make use of this API.(Citation: Death by 1000 installers; it's all broken!)

Procedures:

- [S0402] OSX/Shlayer: [OSX/Shlayer](https://attack.mitre.org/software/S0402) can escalate privileges to root by asking the user for credentials.(Citation: Carbon Black Shlayer Feb 2019)

#### T1548.005 - Temporary Elevated Cloud Access

Description:

Adversaries may abuse permission configurations that allow them to gain temporarily elevated access to cloud resources. Many cloud environments allow administrators to grant user or service accounts permission to request just-in-time access to roles, impersonate other accounts, pass roles onto resources and services, or otherwise gain short-term access to a set of privileges that may be distinct from their own. 

Just-in-time access is a mechanism for granting additional roles to cloud accounts in a granular, temporary manner. This allows accounts to operate with only the permissions they need on a daily basis, and to request additional permissions as necessary. Sometimes just-in-time access requests are configured to require manual approval, while other times the desired permissions are automatically granted.(Citation: Azure Just in Time Access 2023)

Account impersonation allows user or service accounts to temporarily act with the permissions of another account. For example, in GCP users with the `iam.serviceAccountTokenCreator` role can create temporary access tokens or sign arbitrary payloads with the permissions of a service account, while service accounts with domain-wide delegation permission are permitted to impersonate Google Workspace accounts.(Citation: Google Cloud Service Account Authentication Roles)(Citation: Hunters Domain Wide Delegation Google Workspace 2023)(Citation: Google Cloud Just in Time Access 2023)(Citation: Palo Alto Unit 42 Google Workspace Domain Wide Delegation 2023) In Exchange Online, the `ApplicationImpersonation` role allows a service account to use the permissions associated with specified user accounts.(Citation: Microsoft Impersonation and EWS in Exchange) 

Many cloud environments also include mechanisms for users to pass roles to resources that allow them to perform tasks and authenticate to other services. While the user that creates the resource does not directly assume the role they pass to it, they may still be able to take advantage of the role's access -- for example, by configuring the resource to perform certain actions with the permissions it has been granted. In AWS, users with the `PassRole` permission can allow a service they create to assume a given role, while in GCP, users with the `iam.serviceAccountUser` role can attach a service account to a resource.(Citation: AWS PassRole)(Citation: Google Cloud Service Account Authentication Roles)

While users require specific role assignments in order to use any of these features, cloud administrators may misconfigure permissions. This could result in escalation paths that allow adversaries to gain access to resources beyond what was originally intended.(Citation: Rhino Google Cloud Privilege Escalation)(Citation: Rhino Security Labs AWS Privilege Escalation)

**Note:** this technique is distinct from [Additional Cloud Roles](https://attack.mitre.org/techniques/T1098/003), which involves assigning permanent roles to accounts rather than abusing existing permissions structures to gain temporarily elevated access to resources. However, adversaries that compromise a sufficiently privileged account may grant another account they control [Additional Cloud Roles](https://attack.mitre.org/techniques/T1098/003) that would allow them to also abuse these features. This may also allow for greater stealth than would be had by directly using the highly privileged account, especially when logs do not clarify when role impersonation is taking place.(Citation: CrowdStrike StellarParticle January 2022)

#### T1548.006 - TCC Manipulation

Description:

Adversaries can manipulate or abuse the Transparency, Consent, & Control (TCC) service or database to grant malicious executables elevated permissions. TCC is a Privacy & Security macOS control mechanism used to determine if the running process has permission to access the data or services protected by TCC, such as screen sharing, camera, microphone, or Full Disk Access (FDA).

When an application requests to access data or a service protected by TCC, the TCC daemon (`tccd`) checks the TCC database, located at `/Library/Application Support/com.apple.TCC/TCC.db` (and `~/` equivalent), and an overwrites file (if connected to an MDM) for existing permissions. If permissions do not exist, then the user is prompted to grant permission. Once permissions are granted, the database stores the application's permissions and will not prompt the user again unless reset. For example, when a web browser requests permissions to the user's webcam, once granted the web browser may not explicitly prompt the user again.(Citation: welivesecurity TCC)

Adversaries may access restricted data or services protected by TCC through abusing applications previously granted permissions through [Process Injection](https://attack.mitre.org/techniques/T1055) or executing a malicious binary using another application. For example, adversaries can use Finder, a macOS native app with FDA permissions, to execute a malicious [AppleScript](https://attack.mitre.org/techniques/T1059/002). When executing under the Finder App, the malicious [AppleScript](https://attack.mitre.org/techniques/T1059/002) inherits access to all files on the system without requiring a user prompt. When System Integrity Protection (SIP) is disabled, TCC protections are also disabled. For a system without SIP enabled, adversaries can manipulate the TCC database to add permissions to their malicious executable through loading an adversary controlled TCC database using environment variables and [Launchctl](https://attack.mitre.org/techniques/T1569/001).(Citation: TCC macOS bypass)(Citation: TCC Database)

Procedures:

- [S0658] XCSSET: For several modules, [XCSSET](https://attack.mitre.org/software/S0658) attempts to access or list the contents of user folders such as Desktop, Downloads, and Documents. If the folder does not exist or access is denied, it enters a loop where it resets the TCC database and retries access.(Citation: Microsoft March 2025 XCSSET)


### T1574 - Hijack Execution Flow

Description:

Adversaries may execute their own malicious payloads by hijacking the way operating systems run programs. Hijacking execution flow can be for the purposes of persistence, since this hijacked execution may reoccur over time. Adversaries may also use these mechanisms to elevate privileges or evade defenses, such as application control or other restrictions on execution.

There are many ways an adversary may hijack the flow of execution, including by manipulating how the operating system locates programs to be executed. How the operating system locates libraries to be used by a program can also be intercepted. Locations where the operating system looks for programs/resources, such as file directories and in the case of Windows the Registry, could also be poisoned to include malicious payloads.

Procedures:

- [S1111] DarkGate: [DarkGate](https://attack.mitre.org/software/S1111) edits the Registry key <code>HKCU\Software\Classes\mscfile\shell\open\command</code> to execute a malicious AutoIt script.(Citation: Ensilo Darkgate 2018) When eventvwr.exe is executed, this will call the Microsoft Management Console (mmc.exe), which in turn references the modified Registry key.
- [S0567] Dtrack: One of [Dtrack](https://attack.mitre.org/software/S0567) can replace the normal flow of a program execution with malicious code.(Citation: CyberBit Dtrack)
- [S0444] ShimRat: [ShimRat](https://attack.mitre.org/software/S0444) can hijack the cryptbase.dll within migwiz.exe to escalate privileges and bypass UAC controls.(Citation: FOX-IT May 2016 Mofang)
- [S1130] Raspberry Robin: [Raspberry Robin](https://attack.mitre.org/software/S1130) will drop a copy of itself to a subfolder in <code>%Program Data%</code> or <code>%Program Data%\\Microsoft\\</code> to attempt privilege elevation and defense evasion if not running in Session 0.(Citation: TrendMicro RaspberryRobin 2022)
- [C0036] Pikabot Distribution February 2024: [Pikabot Distribution February 2024](https://attack.mitre.org/campaigns/C0036) utilized a tampered legitimate executable, `grepWinNP3.exe`, for its first stage [Pikabot](https://attack.mitre.org/software/S1145) loader, modifying the open-source tool to execute malicious code when launched.(Citation: Elastic Pikabot 2024)
- [S0354] Denis: [Denis](https://attack.mitre.org/software/S0354) replaces the nonexistent Windows DLL "msfte.dll" with its own malicious version, which is loaded by the SearchIndexer.exe and SearchProtocolHost.exe.(Citation: Cybereason Cobalt Kitty 2017)
- [S1147] Nightdoor: [Nightdoor](https://attack.mitre.org/software/S1147) uses a legitimate executable to load a malicious DLL file for installation.(Citation: Symantec Daggerfly 2024)
- [C0017] C0017: During [C0017](https://attack.mitre.org/campaigns/C0017), [APT41](https://attack.mitre.org/groups/G0096) established persistence by loading malicious libraries via modifications to the Import Address Table (IAT) within legitimate Microsoft binaries.(Citation: Mandiant APT41)
- [S1105] COATHANGER: [COATHANGER](https://attack.mitre.org/software/S1105) will remove and write malicious shared objects associated with legitimate system functions such as `read(2)`.(Citation: NCSC-NL COATHANGER Feb 2024)
- [S1018] Saint Bot: [Saint Bot](https://attack.mitre.org/software/S1018) will use the malicious file <code>slideshow.mp4</code> if present to load the core API provided by <code>ntdll.dll</code> to avoid any hooks placed on calls to the original <code>ntdll.dll</code> file by endpoint detection and response or antimalware software.(Citation: Palo Alto Unit 42 OutSteel SaintBot February 2022 )

#### T1574.001 - DLL

Description:

Adversaries may abuse dynamic-link library files (DLLs) in order to achieve persistence, escalate privileges, and evade defenses. DLLs are libraries that contain code and data that can be simultaneously utilized by multiple programs. While DLLs are not malicious by nature, they can be abused through mechanisms such as side-loading, hijacking search order, and phantom DLL hijacking.(Citation: unit 42)

Specific ways DLLs are abused by adversaries include:

### DLL Sideloading
Adversaries may execute their own malicious payloads by side-loading DLLs. Side-loading involves hijacking which DLL a program loads by planting and then invoking a legitimate application that executes their payload(s).

Side-loading positions both the victim application and malicious payload(s) alongside each other. Adversaries likely use side-loading as a means of masking actions they perform under a legitimate, trusted, and potentially elevated system or software process. Benign executables used to side-load payloads may not be flagged during delivery and/or execution. Adversary payloads may also be encrypted/packed or otherwise obfuscated until loaded into the memory of the trusted process.

Adversaries may also side-load other packages, such as BPLs (Borland Package Library).(Citation: kroll bpl)

### DLL Search Order Hijacking
Adversaries may execute their own malicious payloads by hijacking the search order that Windows uses to load DLLs. This search order is a sequence of special and standard search locations that a program checks when loading a DLL. An adversary can plant a trojan DLL in a directory that will be prioritized by the DLL search order over the location of a legitimate library. This will cause Windows to load the malicious DLL when it is called for by the victim program.(Citation: unit 42)

### DLL Redirection
Adversaries may directly modify the search order via DLL redirection, which after being enabled (in the Registry or via the creation of a redirection file) may cause a program to load a DLL from a different location.(Citation: Microsoft redirection)(Citation: Microsoft - manifests/assembly)

### Phantom DLL Hijacking
Adversaries may leverage phantom DLL hijacking by targeting references to non-existent DLL files. They may be able to load their own malicious DLL by planting it with the correct name in the location of the missing module.(Citation: Hexacorn DLL Hijacking)(Citation: Hijack DLLs CrowdStrike)

### DLL Substitution
Adversaries may target existing, valid DLL files and substitute them with their own malicious DLLs, planting them with the same name and in the same location as the valid DLL file.(Citation: Wietze Beukema DLL Hijacking)

Programs that fall victim to DLL hijacking may appear to behave normally because malicious DLLs may be configured to also load the legitimate DLLs they were meant to replace, evading defenses.

Remote DLL hijacking can occur when a program sets its current directory to a remote location, such as a Web share, before loading a DLL.(Citation: dll pre load owasp)(Citation: microsoft remote preloading)

If a valid DLL is configured to run at a higher privilege level, then the adversary-controlled DLL that is loaded will also be executed at the higher level. In this case, the technique could be used for privilege escalation.

Procedures:

- [G0114] Chimera: [Chimera](https://attack.mitre.org/groups/G0114) has used side loading to place malicious DLLs in memory.(Citation: NCC Group Chimera January 2021)
- [G1021] Cinnamon Tempest: [Cinnamon Tempest](https://attack.mitre.org/groups/G1021) has used search order hijacking to launch [Cobalt Strike](https://attack.mitre.org/software/S0154) Beacons.(Citation: Microsoft Ransomware as a Service)(Citation: SecureWorks BRONZE STARLIGHT Ransomware Operations June 2022) [Cinnamon Tempest](https://attack.mitre.org/groups/G1021) has also abused legitimate executables to side-load weaponized DLLs.(Citation: Sygnia Emperor Dragonfly October 2022)
- [S1041] Chinoxy: [Chinoxy](https://attack.mitre.org/software/S1041) can use a digitally signed binary ("Logitech Bluetooth Wizard Host Process") to load its dll into memory.(Citation: Bitdefender FunnyDream Campaign November 2020)
- [G0069] MuddyWater: [MuddyWater](https://attack.mitre.org/groups/G0069) maintains persistence on victim networks through side-loading dlls to trick legitimate programs into running malware.(Citation: DHS CISA AA22-055A MuddyWater February 2022)
- [S0384] Dridex: [Dridex](https://attack.mitre.org/software/S0384) can abuse legitimate Windows executables to side-load malicious DLL files.(Citation: Red Canary Dridex Threat Report 2021)
- [G1047] Velvet Ant: [Velvet Ant](https://attack.mitre.org/groups/G1047) has used malicious DLLs executed via legitimate EXE files through DLL search order hijacking to launch follow-on payloads such as [PlugX](https://attack.mitre.org/software/S0013).(Citation: Sygnia VelvetAnt 2024A)
- [S0664] Pandora: [Pandora](https://attack.mitre.org/software/S0664) can use DLL side-loading to execute malicious payloads.(Citation: Trend Micro Iron Tiger April 2021)
- [G0048] RTM: [RTM](https://attack.mitre.org/groups/G0048) has used search order hijacking to force TeamViewer to load a malicious DLL.(Citation: Group IB RTM August 2019)
- [G0131] Tonto Team: [Tonto Team](https://attack.mitre.org/groups/G0131) abuses a legitimate and signed Microsoft executable to launch a malicious DLL.(Citation: ESET Exchange Mar 2021)
- [G0040] Patchwork: A [Patchwork](https://attack.mitre.org/groups/G0040) .dll that contains [BADNEWS](https://attack.mitre.org/software/S0128) is loaded and executed using DLL side-loading.(Citation: TrendMicro Patchwork Dec 2017)
- [S0070] HTTPBrowser: [HTTPBrowser](https://attack.mitre.org/software/S0070) abuses the Windows DLL load order by using a legitimate Symantec anti-virus binary, VPDN_LU.exe, to load a malicious DLL that mimics a legitimate Symantec DLL, navlu.dll.(Citation: ZScaler Hacking Team) [HTTPBrowser](https://attack.mitre.org/software/S0070) has also used DLL side-loading.(Citation: Dell TG-3390)
- [S0109] WEBC2: Variants of [WEBC2](https://attack.mitre.org/software/S0109) achieve persistence by using DLL search order hijacking, usually by copying the DLL file to <code>%SYSTEMROOT%</code> (<code>C:\WINDOWS\ntshrui.dll</code>).(Citation: Mandiant APT1 Appendix)
- [S0009] Hikit: [Hikit](https://attack.mitre.org/software/S0009) has used [DLL](https://attack.mitre.org/techniques/T1574/001) to load <code>oci.dll</code> as a persistence mechanism.(Citation: FireEye Hikit Rootkit)
- [S0176] Wingbird: [Wingbird](https://attack.mitre.org/software/S0176) side loads a malicious file, sspisrv.dll, in part of a spoofed lssas.exe service.(Citation: Microsoft SIR Vol 21)(Citation: Microsoft Wingbird Nov 2017)
- [S0528] Javali: [Javali](https://attack.mitre.org/software/S0528) can use DLL side-loading to load malicious DLLs into legitimate executables.(Citation: Securelist Brazilian Banking Malware July 2020)
- [S0128] BADNEWS: [BADNEWS](https://attack.mitre.org/software/S0128) typically loads its DLL file into a legitimate signed Java or VMware executable.(Citation: Forcepoint Monsoon)(Citation: PaloAlto Patchwork Mar 2018)
- [G0107] Whitefly: [Whitefly](https://attack.mitre.org/groups/G0107) has used search order hijacking to run the loader Vcrodat.(Citation: Symantec Whitefly March 2019)
- [C0047] RedDelta Modified PlugX Infection Chain Operations: [Mustang Panda](https://attack.mitre.org/groups/G0129) used DLL search order hijacking on vulnerable applications to install [PlugX](https://attack.mitre.org/software/S0013) payloads during [RedDelta Modified PlugX Infection Chain Operations](https://attack.mitre.org/campaigns/C0047).(Citation: Recorded Future RedDelta 2025)
- [S0182] FinFisher: [FinFisher](https://attack.mitre.org/software/S0182) uses DLL side-loading to load malicious programs.(Citation: FinFisher Citation)(Citation: Microsoft FinFisher March 2018) A [FinFisher](https://attack.mitre.org/software/S0182) variant also uses DLL search order hijacking.(Citation: FinFisher Citation)(Citation: Securelist BlackOasis Oct 2017)
- [G0143] Aquatic Panda: [Aquatic Panda](https://attack.mitre.org/groups/G0143) has used DLL search-order hijacking to load `exe`, `dll`, and `dat` files into memory.(Citation: CrowdStrike AQUATIC PANDA December 2021) [Aquatic Panda](https://attack.mitre.org/groups/G0143) loaded a malicious DLL into the legitimate Windows Security Health Service executable (<code>SecurityHealthService.exe</code>) to execute malicious code on victim systems.(Citation: Crowdstrike HuntReport 2022)
- [S0398] HyperBro: [HyperBro](https://attack.mitre.org/software/S0398) has used a legitimate application to sideload a DLL to decrypt, decompress, and run a payload.(Citation: Unit42 Emissary Panda May 2019)(Citation: Trend Micro Iron Tiger April 2021)
- [G0093] GALLIUM: [GALLIUM](https://attack.mitre.org/groups/G0093) used DLL side-loading to covertly load [PoisonIvy](https://attack.mitre.org/software/S0012) into memory on the victim machine.(Citation: Cybereason Soft Cell June 2019)
- [S0153] RedLeaves: [RedLeaves](https://attack.mitre.org/software/S0153) is launched through use of DLL search order hijacking to load a malicious dll.(Citation: FireEye APT10 April 2017)
- [G0126] Higaisa: [Higaisa](https://attack.mitre.org/groups/G0126)’s JavaScript file used a legitimate Microsoft Office 2007 package to side-load the <code>OINFO12.OCX</code> dynamic link library.(Citation: PTSecurity Higaisa 2020)
- [S0455] Metamorfo: [Metamorfo](https://attack.mitre.org/software/S0455) has side-loaded its malicious DLL file.(Citation: Medium Metamorfo Apr 2020)(Citation: FireEye Metamorfo Apr 2018)(Citation: ESET Casbaneiro Oct 2019)
- [S0579] Waterbear: [Waterbear](https://attack.mitre.org/software/S0579) has used DLL side loading to import and load a malicious DLL loader.(Citation: Trend Micro Waterbear December 2019)
- [S0230] ZeroT: [ZeroT](https://attack.mitre.org/software/S0230) has used DLL side-loading to load malicious payloads.(Citation: Proofpoint TA459 April 2017)(Citation: Proofpoint ZeroT Feb 2017)
- [G0050] APT32: [APT32](https://attack.mitre.org/groups/G0050) ran legitimately-signed executables from Symantec and McAfee which load a malicious DLL. The group also side-loads its backdoor by dropping a library and a legitimate, signed executable (AcroTranscoder).(Citation: Cybereason Oceanlotus May 2017)(Citation: Cybereason Cobalt Kitty 2017)(Citation: ESET OceanLotus Mar 2019)
- [S0013] PlugX: [PlugX](https://attack.mitre.org/software/S0013) has the ability to use DLL search order hijacking for installation on targeted systems.(Citation: Proofpoint TA416 Europe March 2022) [PlugX](https://attack.mitre.org/software/S0013) has also used DLL side-loading to evade anti-virus.(Citation: FireEye Clandestine Fox Part 2)(Citation: Dell TG-3390)(Citation: Stewart 2014)(Citation: PWC Cloud Hopper Technical Annex April 2017)(Citation: Palo Alto PlugX June 2017)(Citation: Trend Micro DRBControl February 2020)(Citation: Profero APT27 December 2020)
- [S0458] Ramsay: [Ramsay](https://attack.mitre.org/software/S0458) can hijack outdated Windows application dependencies with malicious versions of its own DLL payload.(Citation: Eset Ramsay May 2020)
- [G1046] Storm-1811: [Storm-1811](https://attack.mitre.org/groups/G1046) has deployed a malicious DLL (7z.DLL) that is sideloaded by a modified, legitimate installer (7zG.exe) when that installer is executed with an additional command line parameter of `b` at runtime to load a [Cobalt Strike](https://attack.mitre.org/software/S0154) beacon payload.(Citation: rapid7-email-bombing)
- [S0074] Sakula: [Sakula](https://attack.mitre.org/software/S0074) uses DLL side-loading, typically using a digitally signed sample of Kaspersky Anti-Virus (AV) 6.0 for Windows Workstations or McAfee's Outlook Scan About Box to load malicious DLL files.(Citation: Dell Sakula)
- [S1213] Lumma Stealer: [Lumma Stealer](https://attack.mitre.org/software/S1213) has leveraged legitimate applications to then side-load malicious DLLs during execution.(Citation: Cybereason LumaStealer Undated)
- [S0098] T9000: During the [T9000](https://attack.mitre.org/software/S0098) installation process, it drops a copy of the legitimate Microsoft binary igfxtray.exe. The executable contains a side-loading weakness which is used to load a portion of the malware.(Citation: Palo Alto T9000 Feb 2016)
- [G0120] Evilnum: [Evilnum](https://attack.mitre.org/groups/G0120) has used the malware variant, TerraTV, to load a malicious DLL placed in the TeamViewer directory, instead of the original Windows DLL located in a system folder.(Citation: ESET EvilNum July 2020)
- [S0032] gh0st RAT: A [gh0st RAT](https://attack.mitre.org/software/S0032) variant has used DLL side-loading.(Citation: Arbor Musical Chairs Feb 2018)
- [S0127] BBSRAT: DLL side-loading has been used to execute [BBSRAT](https://attack.mitre.org/software/S0127) through a legitimate Citrix executable, ssonsvr.exe. The Citrix executable was dropped along with [BBSRAT](https://attack.mitre.org/software/S0127) by the dropper.(Citation: Palo Alto Networks BBSRAT)
- [S1100] Ninja: [Ninja](https://attack.mitre.org/software/S1100) loaders can be side-loaded with legitimate and signed executables including the  VLC.exe media player.(Citation: Kaspersky ToddyCat Check Logs October 2023)
- [S0113] Prikormka: [Prikormka](https://attack.mitre.org/software/S0113) uses DLL search order hijacking for persistence by saving itself as ntshrui.dll to the Windows directory so it will load before the legitimate ntshrui.dll saved in the System32 subdirectory.(Citation: ESET Operation Groundbait)
- [S0373] Astaroth: [Astaroth](https://attack.mitre.org/software/S0373) can launch itself via DLL Search Order Hijacking.(Citation: Securelist Brazilian Banking Malware July 2020)
- [S0650] QakBot: [QakBot](https://attack.mitre.org/software/S0650) has the ability to use DLL side-loading for execution.(Citation: Deep Instinct Black Basta August 2022)
- [S1130] Raspberry Robin: [Raspberry Robin](https://attack.mitre.org/software/S1130) can use legitimate, signed EXE files paired with malicious DLL files to load and run malicious payloads while bypassing defenses.(Citation: HP RaspberryRobin 2024)
- [G0081] Tropic Trooper: [Tropic Trooper](https://attack.mitre.org/groups/G0081) has been known to side-load DLLs using a valid version of a Windows Address Book and Windows Defender executable with one of their tools.(Citation: CitizenLab KeyBoy Nov 2016)(Citation: Anomali Pirate Panda April 2020)
- [G1006] Earth Lusca: [Earth Lusca](https://attack.mitre.org/groups/G1006) has placed a malicious payload in `%WINDIR%\SYSTEM32\oci.dll` so it would be sideloaded by the MSDTC service.(Citation: TrendMicro EarthLusca 2022)
- [S0585] Kerrdown: [Kerrdown](https://attack.mitre.org/software/S0585) can use DLL side-loading to load malicious DLLs.(Citation: Unit 42 KerrDown February 2019)
- [G1014] LuminousMoth: [LuminousMoth](https://attack.mitre.org/groups/G1014) has used legitimate executables such as `winword.exe` and `igfxem.exe` to side-load their malware.(Citation: Kaspersky LuminousMoth July 2021)(Citation: Bitdefender LuminousMoth July 2021)
- [S0530] Melcoz: [Melcoz](https://attack.mitre.org/software/S0530) can use DLL hijacking to bypass security controls.(Citation: Securelist Brazilian Banking Malware July 2020)
- [S1101] LoFiSe: [LoFiSe](https://attack.mitre.org/software/S1101) has been executed as a file named DsNcDiag.dll through side-loading.(Citation: Kaspersky ToddyCat Check Logs October 2023)
- [G0060] BRONZE BUTLER: [BRONZE BUTLER](https://attack.mitre.org/groups/G0060) has used legitimate applications to side-load malicious DLLs.(Citation: Trend Micro Tick November 2019)
- [S0280] MirageFox: [MirageFox](https://attack.mitre.org/software/S0280) is likely loaded via DLL hijacking into a legitimate McAfee binary.(Citation: APT15 Intezer June 2018)
- [S1183] StrelaStealer: [StrelaStealer](https://attack.mitre.org/software/S1183) has sideloaded a DLL payload using a renamed, legitimate `msinfo32.exe` executable.(Citation: DCSO StrelaStealer 2022)
- [G0022] APT3: [APT3](https://attack.mitre.org/groups/G0022) has been known to side load DLLs with a valid version of Chrome with one of their tools.(Citation: FireEye Clandestine Fox)(Citation: FireEye Clandestine Fox Part 2)
- [S0194] PowerSploit: [PowerSploit](https://attack.mitre.org/software/S0194) contains a collection of Privesc-PowerUp modules that can discover and exploit DLL hijacking opportunities in services and processes.(Citation: GitHub PowerSploit May 2012)(Citation: PowerSploit Documentation)
- [G0098] BlackTech: [BlackTech](https://attack.mitre.org/groups/G0098) has used DLL side loading by giving DLLs hardcoded names and placing them in searched directories.(Citation: Trend Micro Waterbear December 2019)
- [S0661] FoggyWeb: [FoggyWeb](https://attack.mitre.org/software/S0661)'s loader has used DLL Search Order Hijacking to load malicious code instead of the legitimate `version.dll` during the `Microsoft.IdentityServer.ServiceHost.exe` execution process.(Citation: MSTIC FoggyWeb September 2021)
- [S0554] Egregor: [Egregor](https://attack.mitre.org/software/S0554) has used DLL side-loading to execute its payload.(Citation: Cyble Egregor Oct 2020)
- [G1016] FIN13: [FIN13](https://attack.mitre.org/groups/G1016) has used IISCrack.dll as a side-loading technique to load a malicious version of httpodbc.dll on old IIS Servers (CVE-2001-0507).(Citation: Sygnia Elephant Beetle Jan 2022)
- [G0129] Mustang Panda: [Mustang Panda](https://attack.mitre.org/groups/G0129) has used a legitimately signed executable to execute a malicious payload within a DLL file.(Citation: Anomali MUSTANG PANDA October 2019)(Citation: Recorded Future REDDELTA July 2020)(Citation: Proofpoint TA416 November 2020)
- [S0612] WastedLocker: [WastedLocker](https://attack.mitre.org/software/S0612) has performed DLL hijacking before execution.(Citation: NCC Group WastedLocker June 2020)
- [S0538] Crutch: [Crutch](https://attack.mitre.org/software/S0538) can persist via DLL search order hijacking on Google Chrome, Mozilla Firefox, or Microsoft OneDrive.(Citation: ESET Crutch December 2020)
- [S0630] Nebulae: [Nebulae](https://attack.mitre.org/software/S0630) can use DLL side-loading to gain execution.(Citation: Bitdefender Naikon April 2021)
- [G1008] SideCopy: [SideCopy](https://attack.mitre.org/groups/G1008) has used a malicious loader DLL file to execute the `credwiz.exe` process and side-load the malicious payload `Duser.dll`.(Citation: MalwareBytes SideCopy Dec 2021)
- [S0631] Chaes: [Chaes](https://attack.mitre.org/software/S0631) has used search order hijacking to load a malicious DLL.(Citation: Cybereason Chaes Nov 2020)
- [S1046] PowGoop: [PowGoop](https://attack.mitre.org/software/S1046) can side-load `Goopdate.dll` into `GoogleUpdate.exe`.(Citation: DHS CISA AA22-055A MuddyWater February 2022)(Citation: CYBERCOM Iranian Intel Cyber January 2022)
- [S1059] metaMain: [metaMain](https://attack.mitre.org/software/S1059) can support an HKCMD sideloading start method.(Citation: SentinelLabs Metador Technical Appendix Sept 2022)
- [S1111] DarkGate: [DarkGate](https://attack.mitre.org/software/S1111) includes one infection vector that leverages a malicious "KeyScramblerE.DLL" library that will load during the execution of the legitimate KeyScrambler application.(Citation: Trellix Darkgate 2023)
- [C0040] APT41 DUST: [APT41 DUST](https://attack.mitre.org/campaigns/C0040) involved the use of DLL search order hijacking to execute [DUSTTRAP](https://attack.mitre.org/software/S1159).(Citation: Google Cloud APT41 2024) [APT41 DUST](https://attack.mitre.org/campaigns/C0040) used also DLL side-loading to execute [DUSTTRAP](https://attack.mitre.org/software/S1159) via an AhnLab uninstaller.(Citation: Google Cloud APT41 2024)
- [G1034] Daggerfly: [Daggerfly](https://attack.mitre.org/groups/G1034) has used legitimate software to side-load [PlugX](https://attack.mitre.org/software/S0013) loaders onto victim systems.(Citation: Symantec Daggerfly 2023) [Daggerfly](https://attack.mitre.org/groups/G1034) is also linked to multiple other instances of side-loading for initial loading activity.(Citation: ESET EvasivePanda 2024)
- [S1097] HUI Loader: [HUI Loader](https://attack.mitre.org/software/S1097) can be deployed to targeted systems via legitimate programs that are vulnerable to DLL search order hijacking.(Citation: SecureWorks BRONZE STARLIGHT Ransomware Operations June 2022)
- [S0663] SysUpdate: [SysUpdate](https://attack.mitre.org/software/S0663) can load DLLs through vulnerable legitimate executables.(Citation: Trend Micro Iron Tiger April 2021)
- [S0477] Goopy: [Goopy](https://attack.mitre.org/software/S0477) has the ability to side-load malicious DLLs with legitimate applications from Kaspersky, Microsoft, and Google.(Citation: Cybereason Cobalt Kitty 2017)
- [S0624] Ecipekac: [Ecipekac](https://attack.mitre.org/software/S0624) can abuse the legitimate application policytool.exe to load a malicious DLL.(Citation: Securelist APT10 March 2021)
- [S1102] Pcexter: [Pcexter](https://attack.mitre.org/software/S1102) has been distributed and executed as a DLL file named Vspmsg.dll via DLL side-loading.(Citation: Kaspersky ToddyCat Check Logs October 2023)
- [G0019] Naikon: [Naikon](https://attack.mitre.org/groups/G0019) has used DLL side-loading to load malicious DLL's into legitimate executables.(Citation: CheckPoint Naikon May 2020)
- [G0032] Lazarus Group: [Lazarus Group](https://attack.mitre.org/groups/G0032) has replaced `win_fw.dll`, an internal component that is executed during IDA Pro installation, with a malicious DLL to download and execute a payload.(Citation: ESET Twitter Ida Pro Nov 2021) [Lazarus Group](https://attack.mitre.org/groups/G0032) utilized DLL side-loading to execute malicious payloads through abuse of the legitimate processes `wsmprovhost.exe` and `dfrgui.exe`.(Citation: ASEC Lazarus 2022)
- [C0012] Operation CuckooBees: During [Operation CuckooBees](https://attack.mitre.org/campaigns/C0012), the threat actors used the legitimate Windows services `IKEEXT` and `PrintNotify` to side-load malicious DLLs.(Citation: Cybereason OperationCuckooBees May 2022)
- [S0260] InvisiMole: [InvisiMole](https://attack.mitre.org/software/S0260) can be launched by using DLL search order hijacking in which the wrapper DLL is placed in the same folder as explorer.exe and loaded during startup into the Windows Explorer process instead of the legitimate library.(Citation: ESET InvisiMole June 2018)
- [S0354] Denis: [Denis](https://attack.mitre.org/software/S0354) exploits a security vulnerability to load a fake DLL and execute its code.(Citation: Cybereason Oceanlotus May 2017)
- [G0027] Threat Group-3390: [Threat Group-3390](https://attack.mitre.org/groups/G0027) has performed DLL search order hijacking to execute their payload.(Citation: Nccgroup Emissary Panda May 2018) [Threat Group-3390](https://attack.mitre.org/groups/G0027) has also used DLL side-loading, including by using legitimate Kaspersky antivirus variants as well as `rc.exe`, a legitimate Microsoft Resource Compiler.(Citation: Dell TG-3390)(Citation: SecureWorks BRONZE UNION June 2017)(Citation: Securelist LuckyMouse June 2018)(Citation: Unit42 Emissary Panda May 2019)(Citation: Lunghi Iron Tiger Linux)
- [G0135] BackdoorDiplomacy: [BackdoorDiplomacy](https://attack.mitre.org/groups/G0135) has executed DLL search order hijacking.(Citation: ESET BackdoorDiplomacy Jun 2021)
- [S0629] RainyDay: [RainyDay](https://attack.mitre.org/software/S0629) can use side-loading to run malicious executables.(Citation: Bitdefender Naikon April 2021)
- [S0415] BOOSTWRITE: [BOOSTWRITE](https://attack.mitre.org/software/S0415) has exploited the loading of the legitimate Dwrite.dll file by actually loading the gdi library, which then loads the gdiplus library and ultimately loads the local Dwrite dll.(Citation: FireEye FIN7 Oct 2019)
- [S0660] Clambling: [Clambling](https://attack.mitre.org/software/S0660) can store a file named `mpsvc.dll`, which opens a malicious `mpsvc.mui` file, in the same folder as the legitimate Microsoft executable `MsMpEng.exe` to gain execution.(Citation: Trend Micro DRBControl February 2020)(Citation: Talent-Jump Clambling February 2020)
- [S0662] RCSession: [RCSession](https://attack.mitre.org/software/S0662) can be installed via DLL side-loading.(Citation: Secureworks BRONZE PRESIDENT December 2019)(Citation: Trend Micro DRBControl February 2020)(Citation: Profero APT27 December 2020)
- [S0363] Empire: [Empire](https://attack.mitre.org/software/S0363) contains modules that can discover and exploit various DLL hijacking opportunities.(Citation: Github PowerShell Empire)
- [S1063] Brute Ratel C4: [Brute Ratel C4](https://attack.mitre.org/software/S1063) has used search order hijacking to load a malicious payload DLL as a dependency to a benign application packaged in the same ISO.(Citation: Palo Alto Brute Ratel July 2022) [Brute Ratel C4](https://attack.mitre.org/software/S1063) has loaded a malicious DLL by spoofing the name of the legitimate Version.DLL and placing it in the same folder as the digitally-signed Microsoft binary OneDriveUpdater.exe.(Citation: Palo Alto Brute Ratel July 2022)
- [G0073] APT19: [APT19](https://attack.mitre.org/groups/G0073) launched an HTTP malware variant and a Port 22 malware variant using a legitimate executable that loaded the malicious DLL.(Citation: Unit 42 C0d0so0 Jan 2016)
- [S0134] Downdelph: [Downdelph](https://attack.mitre.org/software/S0134) uses search order hijacking of the Windows executable sysprep.exe to escalate privileges.(Citation: ESET Sednit Part 3)
- [S0582] LookBack: [LookBack](https://attack.mitre.org/software/S0582) side loads its communications module as a DLL into the <code>libcurl.dll</code> loader.(Citation: Proofpoint LookBack Malware Aug 2019)
- [G0121] Sidewinder: [Sidewinder](https://attack.mitre.org/groups/G0121) has used DLL side-loading to drop and execute malicious payloads including the hijacking of the legitimate Windows application file rekeywiz.exe.(Citation: ATT Sidewinder January 2021)
- [G0096] APT41: [APT41](https://attack.mitre.org/groups/G0096) has used search order hijacking to execute malicious payloads, such as [Winnti for Windows](https://attack.mitre.org/software/S0141).(Citation: Crowdstrike GTR2020 Mar 2020) [APT41](https://attack.mitre.org/groups/G0096) has also used legitimate executables to perform DLL side-loading of their malware.(Citation: FireEye APT41 Aug 2019)
- [G0045] menuPass: [menuPass](https://attack.mitre.org/groups/G0045) has used DLL side-loading to launch versions of Mimikatz and PwDump6 as well as [UPPERCUT](https://attack.mitre.org/software/S0275).(Citation: PWC Cloud Hopper Technical Annex April 2017)(Citation: FireEye APT10 Sept 2018)(Citation: Symantec Cicada November 2020) [menuPass](https://attack.mitre.org/groups/G0045) has also used DLL search order hijacking.(Citation: PWC Cloud Hopper April 2017)

#### T1574.004 - Dylib Hijacking

Description:

Adversaries may execute their own payloads by placing a malicious dynamic library (dylib) with an expected name in a path a victim application searches at runtime. The dynamic loader will try to find the dylibs based on the sequential order of the search paths. Paths to dylibs may be prefixed with <code>@rpath</code>, which allows developers to use relative paths to specify an array of search paths used at runtime based on the location of the executable.  Additionally, if weak linking is used, such as the <code>LC_LOAD_WEAK_DYLIB</code> function, an application will still execute even if an expected dylib is not present. Weak linking enables developers to run an application on multiple macOS versions as new APIs are added.

Adversaries may gain execution by inserting malicious dylibs with the name of the missing dylib in the identified path.(Citation: Wardle Dylib Hijack Vulnerable Apps)(Citation: Wardle Dylib Hijacking OSX 2015)(Citation: Github EmpireProject HijackScanner)(Citation: Github EmpireProject CreateHijacker Dylib) Dylibs are loaded into an application's address space allowing the malicious dylib to inherit the application's privilege level and resources. Based on the application, this could result in privilege escalation and uninhibited network access. This method may also evade detection from security products since the execution is masked under a legitimate process.(Citation: Writing Bad Malware for OSX)(Citation: wardle artofmalware volume1)(Citation: MalwareUnicorn macOS Dylib Injection MachO)

Procedures:

- [S0363] Empire: [Empire](https://attack.mitre.org/software/S0363) has a dylib hijacker module that generates a malicious dylib given the path to a legitimate dylib of a vulnerable application.(Citation: Github PowerShell Empire)

#### T1574.005 - Executable Installer File Permissions Weakness

Description:

Adversaries may execute their own malicious payloads by hijacking the binaries used by an installer. These processes may automatically execute specific binaries as part of their functionality or to perform other actions. If the permissions on the file system directory containing a target binary, or permissions on the binary itself, are improperly set, then the target binary may be overwritten with another binary using user-level permissions and executed by the original process. If the original process and thread are running under a higher permissions level, then the replaced binary will also execute under higher-level permissions, which could include SYSTEM.

Another variation of this technique can be performed by taking advantage of a weakness that is common in executable, self-extracting installers. During the installation process, it is common for installers to use a subdirectory within the <code>%TEMP%</code> directory to unpack binaries such as DLLs, EXEs, or other payloads. When installers create subdirectories and files they often do not set appropriate permissions to restrict write access, which allows for execution of untrusted code placed in the subdirectories or overwriting of binaries used in the installation process. This behavior is related to and may take advantage of [DLL](https://attack.mitre.org/techniques/T1574/001) search order hijacking.

Adversaries may use this technique to replace legitimate binaries with malicious ones as a means of executing code at a higher permissions level. Some installers may also require elevated privileges that will result in privilege escalation when executing adversary controlled code. This behavior is related to [Bypass User Account Control](https://attack.mitre.org/techniques/T1548/002). Several examples of this weakness in existing common installers have been reported to software vendors.(Citation: mozilla_sec_adv_2012)  (Citation: Executable Installers are Vulnerable) If the executing process is set to run at a specific time or during a certain event (e.g., system bootup) then this technique can also be used for persistence.

#### T1574.006 - Dynamic Linker Hijacking

Description:

Adversaries may execute their own malicious payloads by hijacking environment variables the dynamic linker uses to load shared libraries. During the execution preparation phase of a program, the dynamic linker loads specified absolute paths of shared libraries from various environment variables and files, such as <code>LD_PRELOAD</code> on Linux or <code>DYLD_INSERT_LIBRARIES</code> on macOS.(Citation: TheEvilBit DYLD_INSERT_LIBRARIES)(Citation: Timac DYLD_INSERT_LIBRARIES)(Citation: Gabilondo DYLD_INSERT_LIBRARIES Catalina Bypass) Libraries specified in environment variables are loaded first, taking precedence over system libraries with the same function name.(Citation: Man LD.SO)(Citation: TLDP Shared Libraries)(Citation: Apple Doco Archive Dynamic Libraries) Each platform's linker uses an extensive list of environment variables at different points in execution. These variables are often used by developers to debug binaries without needing to recompile, deconflict mapped symbols, and implement custom functions in the original library.(Citation: Baeldung LD_PRELOAD)

Hijacking dynamic linker variables may grant access to the victim process's memory, system/network resources, and possibly elevated privileges. On Linux, adversaries may set <code>LD_PRELOAD</code> to point to malicious libraries that match the name of legitimate libraries which are requested by a victim program, causing the operating system to load the adversary's malicious code upon execution of the victim program. For example, adversaries have used `LD_PRELOAD` to inject a malicious library into every descendant process of the `sshd` daemon, resulting in execution under a legitimate process. When the executing sub-process calls the `execve` function, for example, the malicious library’s `execve` function is executed rather than the system function `execve` contained in the system library on disk. This allows adversaries to [Hide Artifacts](https://attack.mitre.org/techniques/T1564) from detection, as hooking system functions such as `execve` and `readdir` enables malware to scrub its own artifacts from the results of commands such as `ls`, `ldd`, `iptables`, and `dmesg`.(Citation: ESET Ebury Oct 2017)(Citation: Intezer Symbiote 2022)(Citation: Elastic Security Labs Pumakit 2024)

Hijacking dynamic linker variables may grant access to the victim process's memory, system/network resources, and possibly elevated privileges.

Procedures:

- [G0143] Aquatic Panda: [Aquatic Panda](https://attack.mitre.org/groups/G0143) modified the <code>ld.so</code> preload file in Linux environments to enable persistence for Winnti malware.(Citation: Crowdstrike HuntReport 2022)
- [G0106] Rocke: [Rocke](https://attack.mitre.org/groups/G0106) has modified /etc/ld.so.preload to hook libc functions in order to hide the installed dropper and mining software in process lists.(Citation: Anomali Rocke March 2019)
- [S0601] Hildegard: [Hildegard](https://attack.mitre.org/software/S0601) has modified /etc/ld.so.preload to intercept shared library import functions.(Citation: Unit 42 Hildegard Malware)
- [S0394] HiddenWasp: [HiddenWasp](https://attack.mitre.org/software/S0394) adds itself as a shared object to the LD_PRELOAD environment variable.(Citation: Intezer HiddenWasp Map 2019)
- [S0658] XCSSET: [XCSSET](https://attack.mitre.org/software/S0658) adds malicious file paths to the <code>DYLD_FRAMEWORK_PATH</code> and <code>DYLD_LIBRARY_PATH</code> environment variables to execute malicious code.(Citation: trendmicro xcsset xcode project 2020)
- [G0096] APT41: [APT41](https://attack.mitre.org/groups/G0096) has configured payloads to load via LD_PRELOAD.(Citation: Crowdstrike GTR2020 Mar 2020)
- [S1105] COATHANGER: [COATHANGER](https://attack.mitre.org/software/S1105) copies the malicious file <code>/data2/.bd.key/preload.so</code> to <code>/lib/preload.so</code>, then launches a child process that executes the malicious file <code>/data2/.bd.key/authd</code> as <code>/bin/authd</code> with the arguments <code>/lib/preload.so reboot newreboot 1</code>.(Citation: NCSC-NL COATHANGER Feb 2024) This injects the malicious preload.so file into the process with PID 1, and replaces its reboot function with the malicious newreboot function for persistence.
- [S0377] Ebury: When [Ebury](https://attack.mitre.org/software/S0377) is running as an OpenSSH server, it uses LD_PRELOAD to inject its malicious shared module in to programs launched by SSH sessions. [Ebury](https://attack.mitre.org/software/S0377) hooks the following functions from `libc` to inject into subprocesses;  `system`, `popen`, `execve`, `execvpe`, `execv`, `execvp`, and `execl`.(Citation: ESET Ebury Oct 2017)(Citation: ESET Ebury May 2024)

#### T1574.007 - Path Interception by PATH Environment Variable

Description:

Adversaries may execute their own malicious payloads by hijacking environment variables used to load libraries. The PATH environment variable contains a list of directories (User and System) that the OS searches sequentially through in search of the binary that was called from a script or the command line. 

Adversaries can place a malicious program in an earlier entry in the list of directories stored in the PATH environment variable, resulting in the operating system executing the malicious binary rather than the legitimate binary when it searches sequentially through that PATH listing.

For example, on Windows if an adversary places a malicious program named "net.exe" in `C:\example path`, which by default precedes `C:\Windows\system32\net.exe` in the PATH environment variable, when "net" is executed from the command-line the `C:\example path` will be called instead of the system's legitimate executable at `C:\Windows\system32\net.exe`. Some methods of executing a program rely on the PATH environment variable to determine the locations that are searched when the path for the program is not given, such as executing programs from a [Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059).(Citation: ExpressVPN PATH env Windows 2021)

Adversaries may also directly modify the $PATH variable specifying the directories to be searched.  An adversary can modify the `$PATH` variable to point to a directory they have write access. When a program using the $PATH variable is called, the OS searches the specified directory and executes the malicious binary. On macOS, this can also be performed through modifying the $HOME variable. These variables can be modified using the command-line, launchctl, [Unix Shell Configuration Modification](https://attack.mitre.org/techniques/T1546/004), or modifying the `/etc/paths.d` folder contents.(Citation: uptycs Fake POC linux malware 2023)(Citation: nixCraft macOS PATH variables)(Citation: Elastic Rules macOS launchctl 2022)

Procedures:

- [S0194] PowerSploit: [PowerSploit](https://attack.mitre.org/software/S0194) contains a collection of Privesc-PowerUp modules that can discover and exploit path interception opportunities in the PATH environment variable.(Citation: GitHub PowerSploit May 2012)(Citation: PowerSploit Documentation)
- [S0363] Empire: [Empire](https://attack.mitre.org/software/S0363) contains modules that can discover and exploit path interception opportunities in the PATH environment variable.(Citation: Github PowerShell Empire)
- [S1111] DarkGate: [DarkGate](https://attack.mitre.org/software/S1111) overrides the <code>%windir%</code> environment variable by setting a Registry key, <code>HKEY_CURRENT_User\Environment\windir</code>, to an alternate command to execute a malicious AutoIt script. This allows [DarkGate](https://attack.mitre.org/software/S1111) to run every time the scheduled task <code>DiskCleanup</code> is executed as this uses the path value <code>%windir%\system32\cleanmgr.exe</code> for execution.(Citation: Ensilo Darkgate 2018)

#### T1574.008 - Path Interception by Search Order Hijacking

Description:

Adversaries may execute their own malicious payloads by hijacking the search order used to load other programs. Because some programs do not call other programs using the full path, adversaries may place their own file in the directory where the calling program is located, causing the operating system to launch their malicious software at the request of the calling program.

Search order hijacking occurs when an adversary abuses the order in which Windows searches for programs that are not given a path. Unlike [DLL](https://attack.mitre.org/techniques/T1574/001) search order hijacking, the search order differs depending on the method that is used to execute the program. (Citation: Microsoft CreateProcess) (Citation: Windows NT Command Shell) (Citation: Microsoft WinExec) However, it is common for Windows to search in the directory of the initiating program before searching through the Windows system directory. An adversary who finds a program vulnerable to search order hijacking (i.e., a program that does not specify the path to an executable) may take advantage of this vulnerability by creating a program named after the improperly specified program and placing it within the initiating program's directory.

For example, "example.exe" runs "cmd.exe" with the command-line argument <code>net user</code>. An adversary may place a program called "net.exe" within the same directory as example.exe, "net.exe" will be run instead of the Windows system utility net. In addition, if an adversary places a program called "net.com" in the same directory as "net.exe", then <code>cmd.exe /C net user</code> will execute "net.com" instead of "net.exe" due to the order of executable extensions defined under PATHEXT. (Citation: Microsoft Environment Property)

Search order hijacking is also a common practice for hijacking DLL loads and is covered in [DLL](https://attack.mitre.org/techniques/T1574/001).

Procedures:

- [S0363] Empire: [Empire](https://attack.mitre.org/software/S0363) contains modules that can discover and exploit search order hijacking vulnerabilities.(Citation: Github PowerShell Empire)
- [S0194] PowerSploit: [PowerSploit](https://attack.mitre.org/software/S0194) contains a collection of Privesc-PowerUp modules that can discover and exploit search order hijacking vulnerabilities.(Citation: GitHub PowerSploit May 2012)(Citation: PowerSploit Documentation)

#### T1574.009 - Path Interception by Unquoted Path

Description:

Adversaries may execute their own malicious payloads by hijacking vulnerable file path references. Adversaries can take advantage of paths that lack surrounding quotations by placing an executable in a higher level directory within the path, so that Windows will choose the adversary's executable to launch.

Service paths (Citation: Microsoft CurrentControlSet Services) and shortcut paths may also be vulnerable to path interception if the path has one or more spaces and is not surrounded by quotation marks (e.g., <code>C:\unsafe path with space\program.exe</code> vs. <code>"C:\safe path with space\program.exe"</code>). (Citation: Help eliminate unquoted path) (stored in Windows Registry keys) An adversary can place an executable in a higher level directory of the path, and Windows will resolve that executable instead of the intended executable. For example, if the path in a shortcut is <code>C:\program files\myapp.exe</code>, an adversary may create a program at <code>C:\program.exe</code> that will be run instead of the intended program. (Citation: Windows Unquoted Services) (Citation: Windows Privilege Escalation Guide)

This technique can be used for persistence if executables are called on a regular basis, as well as privilege escalation if intercepted executables are started by a higher privileged process.

Procedures:

- [S0194] PowerSploit: [PowerSploit](https://attack.mitre.org/software/S0194) contains a collection of Privesc-PowerUp modules that can discover and exploit unquoted path vulnerabilities.(Citation: GitHub PowerSploit May 2012)(Citation: PowerSploit Documentation)
- [S0363] Empire: [Empire](https://attack.mitre.org/software/S0363) contains modules that can discover and exploit unquoted path vulnerabilities.(Citation: Github PowerShell Empire)

#### T1574.010 - Services File Permissions Weakness

Description:

Adversaries may execute their own malicious payloads by hijacking the binaries used by services. Adversaries may use flaws in the permissions of Windows services to replace the binary that is executed upon service start. These service processes may automatically execute specific binaries as part of their functionality or to perform other actions. If the permissions on the file system directory containing a target binary, or permissions on the binary itself are improperly set, then the target binary may be overwritten with another binary using user-level permissions and executed by the original process. If the original process and thread are running under a higher permissions level, then the replaced binary will also execute under higher-level permissions, which could include SYSTEM.

Adversaries may use this technique to replace legitimate binaries with malicious ones as a means of executing code at a higher permissions level. If the executing process is set to run at a specific time or during a certain event (e.g., system bootup) then this technique can also be used for persistence.

Procedures:

- [S0089] BlackEnergy: One variant of [BlackEnergy](https://attack.mitre.org/software/S0089) locates existing driver services that have been disabled and drops its driver component into one of those service's paths, replacing the legitimate executable. The malware then sets the hijacked service to start automatically to establish persistence.(Citation: F-Secure BlackEnergy 2014)

#### T1574.011 - Services Registry Permissions Weakness

Description:

Adversaries may execute their own malicious payloads by hijacking the Registry entries used by services. Adversaries may use flaws in the permissions for Registry keys related to services to redirect from the originally specified executable to one that they control, in order to launch their own code when a service starts. Windows stores local service configuration information in the Registry under <code>HKLM\SYSTEM\CurrentControlSet\Services</code>. The information stored under a service's Registry keys can be manipulated to modify a service's execution parameters through tools such as the service controller, sc.exe,  [PowerShell](https://attack.mitre.org/techniques/T1059/001), or [Reg](https://attack.mitre.org/software/S0075). Access to Registry keys is controlled through access control lists and user permissions. (Citation: Registry Key Security)(Citation: malware_hides_service)

If the permissions for users and groups are not properly set and allow access to the Registry keys for a service, adversaries may change the service's binPath/ImagePath to point to a different executable under their control. When the service starts or is restarted, then the adversary-controlled program will execute, allowing the adversary to establish persistence and/or privilege escalation to the account context the service is set to execute under (local/domain account, SYSTEM, LocalService, or NetworkService).

Adversaries may also alter other Registry keys in the service’s Registry tree. For example, the <code>FailureCommand</code> key may be changed so that the service is executed in an elevated context anytime the service fails or is intentionally corrupted.(Citation: Kansa Service related collectors)(Citation: Tweet Registry Perms Weakness)

The <code>Performance</code> key contains the name of a driver service's performance DLL and the names of several exported functions in the DLL.(Citation: microsoft_services_registry_tree) If the <code>Performance</code> key is not already present and if an adversary-controlled user has the <code>Create Subkey</code> permission, adversaries may create the <code>Performance</code> key in the service’s Registry tree to point to a malicious DLL.(Citation: insecure_reg_perms)

Adversaries may also add the <code>Parameters</code> key, which stores driver-specific data, or other custom subkeys for their malicious services to establish persistence or enable other malicious activities.(Citation: microsoft_services_registry_tree)(Citation: troj_zegost) Additionally, If adversaries launch their malicious services using svchost.exe, the service’s file may be identified using <code>HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\servicename\Parameters\ServiceDll</code>.(Citation: malware_hides_service)

Procedures:

- [C0006] Operation Honeybee: During [Operation Honeybee](https://attack.mitre.org/campaigns/C0006), the threat actors used a batch file that modified the COMSysApp service to load a malicious ipnet.dll payload and to load a DLL into the `svchost.exe` process.(Citation: McAfee Honeybee)

#### T1574.012 - COR_PROFILER

Description:

Adversaries may leverage the COR_PROFILER environment variable to hijack the execution flow of programs that load the .NET CLR. The COR_PROFILER is a .NET Framework feature which allows developers to specify an unmanaged (or external of .NET) profiling DLL to be loaded into each .NET process that loads the Common Language Runtime (CLR). These profilers are designed to monitor, troubleshoot, and debug managed code executed by the .NET CLR.(Citation: Microsoft Profiling Mar 2017)(Citation: Microsoft COR_PROFILER Feb 2013)

The COR_PROFILER environment variable can be set at various scopes (system, user, or process) resulting in different levels of influence. System and user-wide environment variable scopes are specified in the Registry, where a [Component Object Model](https://attack.mitre.org/techniques/T1559/001) (COM) object can be registered as a profiler DLL. A process scope COR_PROFILER can also be created in-memory without modifying the Registry. Starting with .NET Framework 4, the profiling DLL does not need to be registered as long as the location of the DLL is specified in the COR_PROFILER_PATH environment variable.(Citation: Microsoft COR_PROFILER Feb 2013)

Adversaries may abuse COR_PROFILER to establish persistence that executes a malicious DLL in the context of all .NET processes every time the CLR is invoked. The COR_PROFILER can also be used to elevate privileges (ex: [Bypass User Account Control](https://attack.mitre.org/techniques/T1548/002)) if the victim .NET process executes at a higher permission level, as well as to hook and [Impair Defenses](https://attack.mitre.org/techniques/T1562) provided by .NET processes.(Citation: RedCanary Mockingbird May 2020)(Citation: Red Canary COR_PROFILER May 2020)(Citation: Almond COR_PROFILER Apr 2019)(Citation: GitHub OmerYa Invisi-Shell)(Citation: subTee .NET Profilers May 2017)

Procedures:

- [G0108] Blue Mockingbird: [Blue Mockingbird](https://attack.mitre.org/groups/G0108) has used wmic.exe and Windows Registry modifications to set the COR_PROFILER environment variable to execute a malicious DLL whenever a process loads the .NET CLR.(Citation: RedCanary Mockingbird May 2020)
- [S1066] DarkTortilla: [DarkTortilla](https://attack.mitre.org/software/S1066) can detect profilers by verifying the `COR_ENABLE_PROFILING` environment variable is present and active.(Citation: Secureworks DarkTortilla Aug 2022)

#### T1574.013 - KernelCallbackTable

Description:

Adversaries may abuse the <code>KernelCallbackTable</code> of a process to hijack its execution flow in order to run their own payloads.(Citation: Lazarus APT January 2022)(Citation: FinFisher exposed ) The <code>KernelCallbackTable</code> can be found in the Process Environment Block (PEB) and is initialized to an array of graphic functions available to a GUI process once <code>user32.dll</code> is loaded.(Citation: Windows Process Injection KernelCallbackTable)

An adversary may hijack the execution flow of a process using the <code>KernelCallbackTable</code> by replacing an original callback function with a malicious payload. Modifying callback functions can be achieved in various ways involving related behaviors such as [Reflective Code Loading](https://attack.mitre.org/techniques/T1620) or [Process Injection](https://attack.mitre.org/techniques/T1055) into another process.

A pointer to the memory address of the <code>KernelCallbackTable</code> can be obtained by locating the PEB (ex: via a call to the <code>NtQueryInformationProcess()</code> [Native API](https://attack.mitre.org/techniques/T1106) function).(Citation: NtQueryInformationProcess) Once the pointer is located, the <code>KernelCallbackTable</code> can be duplicated, and a function in the table (e.g., <code>fnCOPYDATA</code>) set to the address of a malicious payload (ex: via <code>WriteProcessMemory()</code>). The PEB is then updated with the new address of the table. Once the tampered function is invoked, the malicious payload will be triggered.(Citation: Lazarus APT January 2022)

The tampered function is typically invoked using a Windows message. After the process is hijacked and malicious code is executed, the <code>KernelCallbackTable</code> may also be restored to its original state by the rest of the malicious payload.(Citation: Lazarus APT January 2022) Use of the <code>KernelCallbackTable</code> to hijack execution flow may evade detection from security products since the execution can be masked under a legitimate process.

Procedures:

- [G0032] Lazarus Group: [Lazarus Group](https://attack.mitre.org/groups/G0032) has abused the <code>KernelCallbackTable</code> to hijack process control flow and execute shellcode.(Citation: Lazarus APT January 2022)(Citation: Qualys LolZarus)
- [S0182] FinFisher: [FinFisher](https://attack.mitre.org/software/S0182) has used the <code>KernelCallbackTable</code> to hijack the execution flow of a process by replacing the <code>__fnDWORD</code> function with the address of a created [Asynchronous Procedure Call](https://attack.mitre.org/techniques/T1055/004) stub routine.(Citation: FinFisher exposed )

#### T1574.014 - AppDomainManager

Description:

Adversaries may execute their own malicious payloads by hijacking how the .NET `AppDomainManager` loads assemblies. The .NET framework uses the `AppDomainManager` class to create and manage one or more isolated runtime environments (called application domains) inside a process to host the execution of .NET applications. Assemblies (`.exe` or `.dll` binaries compiled to run as .NET code) may be loaded into an application domain as executable code.(Citation: Microsoft App Domains) 

Known as "AppDomainManager injection," adversaries may execute arbitrary code by hijacking how .NET applications load assemblies. For example, malware may create a custom application domain inside a target process to load and execute an arbitrary assembly. Alternatively, configuration files (`.config`) or process environment variables that define .NET runtime settings may be tampered with to instruct otherwise benign .NET applications to load a malicious assembly (identified by name) into the target process.(Citation: PenTestLabs AppDomainManagerInject)(Citation: PwC Yellow Liderc)(Citation: Rapid7 AppDomain Manager Injection)

Procedures:

- [S1152] IMAPLoader: [IMAPLoader](https://attack.mitre.org/software/S1152) is executed via the AppDomainManager injection technique.(Citation: PWC Yellow Liderc 2023)


### T1611 - Escape to Host

Description:

Adversaries may break out of a container or virtualized environment to gain access to the underlying host. This can allow an adversary access to other containerized or virtualized resources from the host level or to the host itself. In principle, containerized / virtualized resources should provide a clear separation of application functionality and be isolated from the host environment.(Citation: Docker Overview)

There are multiple ways an adversary may escape from a container to a host environment. Examples include creating a container configured to mount the host’s filesystem using the bind parameter, which allows the adversary to drop payloads and execute control utilities such as cron on the host; utilizing a privileged container to run commands or load a malicious kernel module on the underlying host; or abusing system calls such as `unshare` and `keyctl` to escalate privileges and steal secrets.(Citation: Docker Bind Mounts)(Citation: Trend Micro Privileged Container)(Citation: Intezer Doki July 20)(Citation: Container Escape)(Citation: Crowdstrike Kubernetes Container Escape)(Citation: Keyctl-unmask)

Additionally, an adversary may be able to exploit a compromised container with a mounted container management socket, such as `docker.sock`, to break out of the container via a [Container Administration Command](https://attack.mitre.org/techniques/T1609).(Citation: Container Escape) Adversaries may also escape via [Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1068), such as exploiting vulnerabilities in global symbolic links in order to access the root directory of a host machine.(Citation: Windows Server Containers Are Open)

In ESXi environments, an adversary may exploit a vulnerability in order to escape from a virtual machine into the hypervisor.(Citation: Broadcom VMSA-2025-004)

Gaining access to the host may provide the adversary with the opportunity to achieve follow-on objectives, such as establishing persistence, moving laterally within the environment, accessing other containers or virtual machines running on the host, or setting up a command and control channel on the host.

Procedures:

- [S0683] Peirates: [Peirates](https://attack.mitre.org/software/S0683) can gain a reverse shell on a host node by mounting the Kubernetes hostPath.(Citation: Peirates GitHub)
- [S0600] Doki: [Doki](https://attack.mitre.org/software/S0600)’s container was configured to bind the host root directory.(Citation: Intezer Doki July 20)
- [S0623] Siloscape: [Siloscape](https://attack.mitre.org/software/S0623) maps the host’s C drive to the container by creating a global symbolic link to the host through the calling of <code>NtSetInformationSymbolicLink</code>.(Citation: Unit 42 Siloscape Jun 2021)
- [G0139] TeamTNT: [TeamTNT](https://attack.mitre.org/groups/G0139) has deployed privileged containers that mount the filesystem of victim machine.(Citation: Intezer TeamTNT September 2020)(Citation: Aqua TeamTNT August 2020)
- [S0601] Hildegard: [Hildegard](https://attack.mitre.org/software/S0601) has used the BOtB tool that can break out of containers. (Citation: Unit 42 Hildegard Malware)

