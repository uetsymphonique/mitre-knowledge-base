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

#### T1037.001 - Boot or Logon Initialization Scripts: Logon Script (Windows)

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

#### T1037.002 - Boot or Logon Initialization Scripts: Login Hook

Description:

Adversaries may use a Login Hook to establish persistence executed upon user logon. A login hook is a plist file that points to a specific script to execute with root privileges upon user logon. The plist file is located in the <code>/Library/Preferences/com.apple.loginwindow.plist</code> file and can be modified using the <code>defaults</code> command-line utility. This behavior is the same for logout hooks where a script can be executed upon user logout. All hooks require administrator permissions to modify or create hooks.(Citation: Login Scripts Apple Dev)(Citation: LoginWindowScripts Apple Dev) 

Adversaries can add or insert a path to a malicious script in the <code>com.apple.loginwindow.plist</code> file, using the <code>LoginHook</code> or <code>LogoutHook</code> key-value pair. The malicious script is executed upon the next user login. If a login hook already exists, adversaries can add additional commands to an existing login hook. There can be only one login and logout hook on a system at a time.(Citation: S1 macOs Persistence)(Citation: Wardle Persistence Chapter)

**Note:** Login hooks were deprecated in 10.11 version of macOS in favor of [Launch Daemon](https://attack.mitre.org/techniques/T1543/004) and [Launch Agent](https://attack.mitre.org/techniques/T1543/001)

#### T1037.003 - Boot or Logon Initialization Scripts: Network Logon Script

Description:

Adversaries may use network logon scripts automatically executed at logon initialization to establish persistence. Network logon scripts can be assigned using Active Directory or Group Policy Objects.(Citation: Petri Logon Script AD) These logon scripts run with the privileges of the user they are assigned to. Depending on the systems within the network, initializing one of these scripts could apply to more than one or potentially all systems.  
 
Adversaries may use these scripts to maintain persistence on a network. Depending on the access configuration of the logon scripts, either local credentials or an administrator account may be necessary.

#### T1037.004 - Boot or Logon Initialization Scripts: RC Scripts

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

#### T1037.005 - Boot or Logon Initialization Scripts: Startup Items

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

#### T1053.002 - Scheduled Task/Job: At

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

#### T1053.003 - Scheduled Task/Job: Cron

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

#### T1053.005 - Scheduled Task/Job: Scheduled Task

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

#### T1053.006 - Scheduled Task/Job: Systemd Timers

Description:

Adversaries may abuse systemd timers to perform task scheduling for initial or recurring execution of malicious code. Systemd timers are unit files with file extension <code>.timer</code> that control services. Timers can be set to run on a calendar event or after a time span relative to a starting point. They can be used as an alternative to [Cron](https://attack.mitre.org/techniques/T1053/003) in Linux environments.(Citation: archlinux Systemd Timers Aug 2020) Systemd timers may be activated remotely via the <code>systemctl</code> command line utility, which operates over [SSH](https://attack.mitre.org/techniques/T1021/004).(Citation: Systemd Remote Control)

Each <code>.timer</code> file must have a corresponding <code>.service</code> file with the same name, e.g., <code>example.timer</code> and <code>example.service</code>. <code>.service</code> files are [Systemd Service](https://attack.mitre.org/techniques/T1543/002) unit files that are managed by the systemd system and service manager.(Citation: Linux man-pages: systemd January 2014) Privileged timers are written to <code>/etc/systemd/system/</code> and <code>/usr/lib/systemd/system</code> while user level are written to <code>~/.config/systemd/user/</code>.

An adversary may use systemd timers to execute malicious code at system startup or on a scheduled basis for persistence.(Citation: Arch Linux Package Systemd Compromise BleepingComputer 10JUL2018)(Citation: gist Arch package compromise 10JUL2018)(Citation: acroread package compromised Arch Linux Mail 8JUL2018) Timers installed using privileged paths may be used to maintain root level persistence. Adversaries may also install user level timers to achieve user level persistence.(Citation: Falcon Sandbox smp: 28553b3a9d)

#### T1053.007 - Scheduled Task/Job: Container Orchestration Job

Description:

Adversaries may abuse task scheduling functionality provided by container orchestration tools such as Kubernetes to schedule deployment of containers configured to execute malicious code. Container orchestration jobs run these automated tasks at a specific date and time, similar to cron jobs on a Linux system. Deployments of this type can also be configured to maintain a quantity of containers over time, automating the process of maintaining persistence within a cluster.

In Kubernetes, a CronJob may be used to schedule a Job that runs one or more containers to perform specific tasks.(Citation: Kubernetes Jobs)(Citation: Kubernetes CronJob) An adversary therefore may utilize a CronJob to schedule deployment of a Job that executes malicious code in various nodes within a cluster.(Citation: Threat Matrix for Kubernetes)


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

#### T1098.001 - Account Manipulation: Additional Cloud Credentials

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

#### T1098.002 - Account Manipulation: Additional Email Delegate Permissions

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

#### T1098.003 - Account Manipulation: Additional Cloud Roles

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

#### T1098.004 - Account Manipulation: SSH Authorized Keys

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

#### T1098.005 - Account Manipulation: Device Registration

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

#### T1098.006 - Account Manipulation: Additional Container Cluster Roles

Description:

An adversary may add additional roles or permissions to an adversary-controlled user or service account to maintain persistent access to a container orchestration system. For example, an adversary with sufficient permissions may create a RoleBinding or a ClusterRoleBinding to bind a Role or ClusterRole to a Kubernetes account.(Citation: Kubernetes RBAC)(Citation: Aquasec Kubernetes Attack 2023) Where attribute-based access control (ABAC) is in use, an adversary with sufficient permissions may modify a Kubernetes ABAC policy to give the target account additional permissions.(Citation: Kuberentes ABAC)
 
This account modification may immediately follow [Create Account](https://attack.mitre.org/techniques/T1136) or other malicious account activity. Adversaries may also modify existing [Valid Accounts](https://attack.mitre.org/techniques/T1078) that they have compromised.  

Note that where container orchestration systems are deployed in cloud environments, as with Google Kubernetes Engine, Amazon Elastic Kubernetes Service, and Azure Kubernetes Service, cloud-based  role-based access control (RBAC) assignments or ABAC policies can often be used in place of or in addition to local permission assignments.(Citation: Google Cloud Kubernetes IAM)(Citation: AWS EKS IAM Roles for Service Accounts)(Citation: Microsoft Azure Kubernetes Service Service Accounts) In these cases, this technique may be used in conjunction with [Additional Cloud Roles](https://attack.mitre.org/techniques/T1098/003).

#### T1098.007 - Account Manipulation: Additional Local or Domain Groups

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


### T1112 - Modify Registry

Description:

Adversaries may interact with the Windows Registry as part of a variety of other techniques to aid in defense evasion, persistence, and execution.

Access to specific areas of the Registry depends on account permissions, with some keys requiring administrator-level access. The built-in Windows command-line utility [Reg](https://attack.mitre.org/software/S0075) may be used for local or remote Registry modification.(Citation: Microsoft Reg) Other tools, such as remote access tools, may also contain functionality to interact with the Registry through the Windows API.

The Registry may be modified in order to hide configuration information or malicious payloads via [Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027).(Citation: Unit42 BabyShark Feb 2019)(Citation: Avaddon Ransomware 2021)(Citation: Microsoft BlackCat Jun 2022)(Citation: CISA Russian Gov Critical Infra 2018) The Registry may also be modified to [Impair Defenses](https://attack.mitre.org/techniques/T1562), such as by enabling macros for all Microsoft Office products, allowing privilege escalation without alerting the user, increasing the maximum number of allowed outbound requests, and/or modifying systems to store plaintext credentials in memory.(Citation: CISA LockBit 2023)(Citation: Unit42 BabyShark Feb 2019)

The Registry of a remote system may be modified to aid in execution of files as part of lateral movement. It requires the remote Registry service to be running on the target system.(Citation: Microsoft Remote) Often [Valid Accounts](https://attack.mitre.org/techniques/T1078) are required, along with access to the remote system's [SMB/Windows Admin Shares](https://attack.mitre.org/techniques/T1021/002) for RPC communication.

Finally, Registry modifications may also include actions to hide keys, such as prepending key names with a null character, which will cause an error and/or be ignored when read via [Reg](https://attack.mitre.org/software/S0075) or other utilities using the Win32 API.(Citation: Microsoft Reghide NOV 2006) Adversaries may abuse these pseudo-hidden keys to conceal payloads/commands used to maintain persistence.(Citation: TrendMicro POWELIKS AUG 2014)(Citation: SpectorOps Hiding Reg Jul 2017)

Procedures:

- [S0674] CharmPower: [CharmPower](https://attack.mitre.org/software/S0674) can remove persistence-related artifacts from the Registry.(Citation: Check Point APT35 CharmPower January 2022)
- [C0028] 2015 Ukraine Electric Power Attack: During the [2015 Ukraine Electric Power Attack](https://attack.mitre.org/campaigns/C0028), [Sandworm Team](https://attack.mitre.org/groups/G0034) modified in-registry Internet settings to lower internet security before launching `rundll32.exe`, which in-turn launches the malware and communicates with C2 servers over the Internet. (Citation: Booz Allen Hamilton).
- [G0010] Turla: [Turla](https://attack.mitre.org/groups/G0010) has modified Registry values to store payloads.(Citation: ESET Turla PowerShell May 2019)(Citation: Symantec Waterbug Jun 2019)
- [S0013] PlugX: [PlugX](https://attack.mitre.org/software/S0013) has a module to create, delete, or modify Registry keys.(Citation: CIRCL PlugX March 2013)
- [S0596] ShadowPad: [ShadowPad](https://attack.mitre.org/software/S0596) can modify the Registry to store and maintain a configuration block and virtual file system.(Citation: Kaspersky ShadowPad Aug 2017)(Citation: TrendMicro EarthLusca 2022)
- [S0457] Netwalker: [Netwalker](https://attack.mitre.org/software/S0457) can add the following registry entry: <code>HKEY_CURRENT_USER\SOFTWARE\{8 random characters}</code>.(Citation: TrendMicro Netwalker May 2020)
- [S0476] Valak: [Valak](https://attack.mitre.org/software/S0476) has the ability to modify the Registry key <code>HKCU\Software\ApplicationContainer\Appsw64</code> to store information regarding the C2 server and downloads.(Citation: Cybereason Valak May 2020)(Citation: Unit 42 Valak July 2020)(Citation: SentinelOne Valak June 2020)
- [S0240] ROKRAT: [ROKRAT](https://attack.mitre.org/software/S0240) can modify the `HKEY_CURRENT_USER\Software\Microsoft\Office\` registry key so it can bypass the VB object model (VBOM) on a compromised host.(Citation: Malwarebytes RokRAT VBA January 2021)
- [G0082] APT38: [APT38](https://attack.mitre.org/groups/G0082) uses a tool called CLEANTOAD that has the capability to modify Registry keys.(Citation: FireEye APT38 Oct 2018)
- [S0376] HOPLIGHT: [HOPLIGHT](https://attack.mitre.org/software/S0376) has modified Managed Object Format (MOF) files within the Registry to run specific commands and create persistence on the system.(Citation: US-CERT HOPLIGHT Apr 2019)
- [S0261] Catchamas: [Catchamas](https://attack.mitre.org/software/S0261) creates three Registry keys to establish persistence by adding a [Windows Service](https://attack.mitre.org/techniques/T1543/003).(Citation: Symantec Catchamas April 2018)
- [S0032] gh0st RAT: [gh0st RAT](https://attack.mitre.org/software/S0032) has altered the InstallTime subkey.(Citation: Gh0stRAT ATT March 2019)
- [S0242] SynAck: [SynAck](https://attack.mitre.org/software/S0242) can manipulate Registry keys.(Citation: SecureList SynAck Doppelgänging May 2018)
- [S0533] SLOTHFULMEDIA: [SLOTHFULMEDIA](https://attack.mitre.org/software/S0533) can add, modify, and/or delete registry keys. It has changed the proxy configuration of a victim system by modifying the <code>HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap</code> registry.(Citation: CISA MAR SLOTHFULMEDIA October 2020)
- [S0608] Conficker: [Conficker](https://attack.mitre.org/software/S0608) adds keys to the Registry at <code>HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services</code> and various other Registry locations.(Citation: SANS Conficker)(Citation: Trend Micro Conficker)
- [S1033] DCSrv: [DCSrv](https://attack.mitre.org/software/S1033) has created Registry keys for persistence.(Citation: Checkpoint MosesStaff Nov 2021)
- [S0559] SUNBURST: [SUNBURST](https://attack.mitre.org/software/S0559) had commands that allow an attacker to write or delete registry keys, and was observed stopping services by setting their <code>HKLM\SYSTEM\CurrentControlSet\services\\[service_name]\\Start</code> registry entries to value 4.(Citation: FireEye SUNBURST Backdoor December 2020)(Citation: Microsoft Analyzing Solorigate Dec 2020) It also deleted previously-created Image File Execution Options (IFEO) Debugger registry values and registry keys related to HTTP proxy to clean up traces of its activity.(Citation: Microsoft Deep Dive Solorigate January 2021)
- [G0040] Patchwork: A [Patchwork](https://attack.mitre.org/groups/G0040) payload deletes Resiliency Registry keys created by Microsoft Office applications in an apparent effort to trick users into thinking there were no issues during application runs.(Citation: TrendMicro Patchwork Dec 2017)
- [S0569] Explosive: [Explosive](https://attack.mitre.org/software/S0569) has a function to write itself to Registry values.(Citation: CheckPoint Volatile Cedar March 2015)
- [S0518] PolyglotDuke: [PolyglotDuke](https://attack.mitre.org/software/S0518) can write encrypted JSON configuration files to the Registry.(Citation: ESET Dukes October 2019)
- [S0012] PoisonIvy: [PoisonIvy](https://attack.mitre.org/software/S0012) creates a Registry subkey that registers a new system device.(Citation: Symantec Darkmoon Aug 2005)
- [S0669] KOCTOPUS: [KOCTOPUS](https://attack.mitre.org/software/S0669) has added and deleted keys from the Registry.(Citation: MalwareBytes LazyScripter Feb 2021)
- [S1202] LockBit 3.0: [LockBit 3.0](https://attack.mitre.org/software/S1202) can change the Registry values for Group Policy refresh time, to disable SmartScreen, and to disable Windows Defender.(Citation: Joint Cybersecurity Advisory LockBit 3.0 MAR 2023)(Citation: INCIBE-CERT LockBit MAR 2024)
- [G0119] Indrik Spider: [Indrik Spider](https://attack.mitre.org/groups/G0119) has modified registry keys to prepare for ransomware execution and to disable common administrative utilities.(Citation: Mandiant_UNC2165)
- [S0397] LoJax: [LoJax](https://attack.mitre.org/software/S0397) has modified the Registry key <code>‘HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\BootExecute’</code> from <code>‘autocheck autochk *’</code> to <code>‘autocheck autoche *’</code>.(Citation: ESET LoJax Sept 2018)
- [S0158] PHOREAL: [PHOREAL](https://attack.mitre.org/software/S0158) is capable of manipulating the Registry.(Citation: FireEye APT32 May 2017)
- [S0428] PoetRAT: [PoetRAT](https://attack.mitre.org/software/S0428) has made registry modifications to alter its behavior upon execution.(Citation: Talos PoetRAT April 2020)
- [S0496] REvil: [REvil](https://attack.mitre.org/software/S0496) can modify the Registry to save encryption parameters and system information.(Citation: Cylance Sodinokibi July 2019)(Citation: Secureworks GandCrab and REvil September 2019)(Citation: McAfee Sodinokibi October 2019)(Citation: Intel 471 REvil March 2020)(Citation: Secureworks REvil September 2019)
- [S0031] BACKSPACE: [BACKSPACE](https://attack.mitre.org/software/S0031) is capable of deleting Registry keys, sub-keys, and values on a victim system.(Citation: FireEye APT30)
- [S0673] DarkWatchman: [DarkWatchman](https://attack.mitre.org/software/S0673) can modify Registry values to store configuration strings, keylogger, and output of components.(Citation: Prevailion DarkWatchman 2021)
- [S0531] Grandoreiro: [Grandoreiro](https://attack.mitre.org/software/S0531) can modify the Registry to store its configuration at `HKCU\Software\` under frequently changing names including <code>%USERNAME%</code> and <code>ToolTech-RM</code>.(Citation: ESET Grandoreiro April 2020)
- [S0011] Taidoor: [Taidoor](https://attack.mitre.org/software/S0011) has the ability to modify the Registry on compromised hosts using <code>RegDeleteValueA</code> and <code>RegCreateKeyExA</code>.(Citation: CISA MAR-10292089-1.v2 TAIDOOR August 2021)
- [S0603] Stuxnet: [Stuxnet](https://attack.mitre.org/software/S0603) can create registry keys to load driver files.(Citation: Nicolas Falliere, Liam O Murchu, Eric Chien February 2011)
- [S0668] TinyTurla: [TinyTurla](https://attack.mitre.org/software/S0668) can set its configuration parameters in the Registry.(Citation: Talos TinyTurla September 2021)
- [S0267] FELIXROOT: [FELIXROOT](https://attack.mitre.org/software/S0267) deletes the Registry key <code>HKCU\Software\Classes\Applications\rundll32.exe\shell\open</code>.(Citation: FireEye FELIXROOT July 2018)
- [S0649] SMOKEDHAM: [SMOKEDHAM](https://attack.mitre.org/software/S0649) has modified registry keys for persistence, to enable credential caching for credential access, and to facilitate lateral movement via RDP.(Citation: FireEye SMOKEDHAM June 2021)
- [S0517] Pillowmint: [Pillowmint](https://attack.mitre.org/software/S0517) has modified the Registry key <code>HKLM\SOFTWARE\Microsoft\DRM</code> to store a malicious payload.(Citation: Trustwave Pillowmint June 2020)
- [S0501] PipeMon: [PipeMon](https://attack.mitre.org/software/S0501) has modified the Registry to store its encrypted payload.(Citation: ESET PipeMon May 2020)
- [S1060] Mafalda: [Mafalda](https://attack.mitre.org/software/S1060) can manipulate the system registry on a compromised host.(Citation: SentinelLabs Metador Technical Appendix Sept 2022)
- [G0091] Silence: [Silence](https://attack.mitre.org/groups/G0091) can create, delete, or modify a specified Registry key or value.(Citation: Group IB Silence Sept 2018)
- [G0092] TA505: [TA505](https://attack.mitre.org/groups/G0092) has used malware to disable Windows Defender through modification of the Registry.(Citation: Korean FSI TA505 2020)
- [S0023] CHOPSTICK: [CHOPSTICK](https://attack.mitre.org/software/S0023) may modify Registry keys to store RC4 encrypted configuration information.(Citation: FireEye APT28)
- [S1181] BlackByte 2.0 Ransomware: [BlackByte 2.0 Ransomware](https://attack.mitre.org/software/S1181) modifies the victim Registry to allow for elevated execution.(Citation: Microsoft BlackByte 2023)
- [S0697] HermeticWiper: [HermeticWiper](https://attack.mitre.org/software/S0697) has the ability to modify Registry keys to disable crash dumps, colors for compressed files, and pop-up information about folders and desktop items.(Citation: SentinelOne Hermetic Wiper February 2022)(Citation: Crowdstrike DriveSlayer February 2022)(Citation: Qualys Hermetic Wiper March 2022)
- [S0670] WarzoneRAT: [WarzoneRAT](https://attack.mitre.org/software/S0670) can create `HKCU\Software\Classes\Folder\shell\open\command` as a new registry key during privilege escalation.(Citation: Uptycs Warzone UAC Bypass November 2020)(Citation: Check Point Warzone Feb 2020)
- [S0154] Cobalt Strike: [Cobalt Strike](https://attack.mitre.org/software/S0154) can modify Registry values within <code>HKEY_CURRENT_USER\Software\Microsoft\Office\<Excel Version>\Excel\Security\AccessVBOM\</code> to enable the execution of additional code.(Citation: Talos Cobalt Strike September 2020)
- [G0073] APT19: [APT19](https://attack.mitre.org/groups/G0073) uses a Port 22 malware variant to modify several Registry keys.(Citation: Unit 42 C0d0so0 Jan 2016)
- [S1201] TRANSLATEXT: [TRANSLATEXT](https://attack.mitre.org/software/S1201) has modified the following registry key to install itself as the value, granting permission to install specified extensions: ` HKCU\Software\Policies\Google\Chrome\ExtensionInstallForcelist`.(Citation: Zscaler Kimsuky TRANSLATEXT)
- [S0527] CSPY Downloader: [CSPY Downloader](https://attack.mitre.org/software/S0527) can write to the Registry under the <code>%windir%</code> variable to execute tasks.(Citation: Cybereason Kimsuky November 2020)
- [S0666] Gelsemium: [Gelsemium](https://attack.mitre.org/software/S0666) can modify the Registry to store its components.(Citation: ESET Gelsemium June 2021)
- [S0612] WastedLocker: [WastedLocker](https://attack.mitre.org/software/S0612) can modify registry values within the <code>Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap</code> registry key.(Citation: NCC Group WastedLocker June 2020)
- [S1059] metaMain: [metaMain](https://attack.mitre.org/software/S1059) can write the process ID of a target process into the `HKEY_LOCAL_MACHINE\SOFTWARE\DDE\tpid` Registry value as part of its reflective loading activity.(Citation: SentinelLabs Metador Technical Appendix Sept 2022)
- [S1178] ShrinkLocker: [ShrinkLocker](https://attack.mitre.org/software/S1178) modifies various registry keys associated with system logon and BitLocker functionality to effectively lock-out users following disk encryption.(Citation: Kaspersky ShrinkLocker 2024)(Citation: Splunk ShrinkLocker 2024)
- [S0262] QuasarRAT: [QuasarRAT](https://attack.mitre.org/software/S0262) has a command to edit the Registry on the victim’s machine.(Citation: GitHub QuasarRAT)(Citation: CISA AR18-352A Quasar RAT December 2018)
- [S0203] Hydraq: [Hydraq](https://attack.mitre.org/software/S0203) creates a Registry subkey to register its created service, and can also uninstall itself later by deleting this value. [Hydraq](https://attack.mitre.org/software/S0203)'s backdoor also enables remote attackers to modify and delete subkeys.(Citation: Symantec Trojan.Hydraq Jan 2010)(Citation: Symantec Hydraq Jan 2010)
- [S1068] BlackCat: [BlackCat](https://attack.mitre.org/software/S1068) has the ability to add the following registry key on compromised networks to maintain persistence: `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services \LanmanServer\Paramenters`(Citation: Microsoft BlackCat Jun 2022)
- [G1043] BlackByte: [BlackByte](https://attack.mitre.org/groups/G1043) performed Registry modifications to escalate privileges and disable security tools.(Citation: Picus BlackByte 2022)(Citation: Cisco BlackByte 2024)
- [S1131] NPPSPY: [NPPSPY](https://attack.mitre.org/software/S1131) modifies the Registry to record the malicious listener for output from the Winlogon process.(Citation: Huntress NPPSPY 2022)
- [S1070] Black Basta: [Black Basta](https://attack.mitre.org/software/S1070) has modified the Registry to enable itself to run in safe mode, to change the icons and file extensions for encrypted files, and to add the malware path for persistence.(Citation: Minerva Labs Black Basta May 2022)(Citation: Cyble Black Basta May 2022)(Citation: Trend Micro Black Basta May 2022)(Citation: NCC Group Black Basta June 2022)(Citation: Deep Instinct Black Basta August 2022)(Citation: Palo Alto Networks Black Basta August 2022)
- [S0254] PLAINTEE: [PLAINTEE](https://attack.mitre.org/software/S0254) uses <code>reg add</code> to add a Registry Run key for persistence.(Citation: Rancor Unit42 June 2018)
- [G0030] Lotus Blossom: [Lotus Blossom](https://attack.mitre.org/groups/G0030) has installed tools such as [Sagerunex](https://attack.mitre.org/software/S1210) by writing them to the Windows registry.(Citation: Cisco LotusBlossom 2025)
- [S1199] LockBit 2.0: [LockBit 2.0](https://attack.mitre.org/software/S1199) can create Registry keys to bypass UAC and for persistence.(Citation: FBI Lockbit 2.0 FEB 2022)
- [G0047] Gamaredon Group: [Gamaredon Group](https://attack.mitre.org/groups/G0047) has removed security settings for VBA macro execution by changing registry values <code>HKCU\Software\Microsoft\Office\&lt;version&gt;\&lt;product&gt;\Security\VBAWarnings</code> and <code>HKCU\Software\Microsoft\Office\&lt;version&gt;\&lt;product&gt;\Security\AccessVBOM</code>.(Citation: ESET Gamaredon June 2020)(Citation: CERT-EE Gamaredon January 2021)
- [S0692] SILENTTRINITY: [SILENTTRINITY](https://attack.mitre.org/software/S0692) can modify registry keys, including to enable or disable Remote Desktop Protocol (RDP).(Citation: GitHub SILENTTRINITY Modules July 2019)
- [S1190] Kapeka: [Kapeka](https://attack.mitre.org/software/S1190) writes persistent configuration information to the victim host registry.(Citation: WithSecure Kapeka 2024)
- [S0022] Uroburos: [Uroburos](https://attack.mitre.org/software/S0022) can store configuration information in the Registry including the initialization vector and AES key needed to find and decrypt other [Uroburos](https://attack.mitre.org/software/S0022) components.(Citation: Joint Cybersecurity Advisory AA23-129A Snake Malware May 2023)
- [S0579] Waterbear: [Waterbear](https://attack.mitre.org/software/S0579) has deleted certain values from the Registry to load a malicious DLL.(Citation: Trend Micro Waterbear December 2019)
- [S0157] SOUNDBITE: [SOUNDBITE](https://attack.mitre.org/software/S0157) is capable of modifying the Registry.(Citation: FireEye APT32 May 2017)
- [C0002] Night Dragon: During [Night Dragon](https://attack.mitre.org/campaigns/C0002), threat actors used [zwShell](https://attack.mitre.org/software/S0350) to establish full remote control of the connected machine and manipulate the Registry.(Citation: McAfee Night Dragon)
- [S0332] Remcos: [Remcos](https://attack.mitre.org/software/S0332) has full control of the Registry, including the ability to modify it.(Citation: Riskiq Remcos Jan 2018)
- [S0260] InvisiMole: [InvisiMole](https://attack.mitre.org/software/S0260) has a command to create, set, copy, or delete a specified Registry key or value.(Citation: ESET InvisiMole June 2018)(Citation: ESET InvisiMole June 2020)
- [S0455] Metamorfo: [Metamorfo](https://attack.mitre.org/software/S0455) has written process names to the Registry, disabled IE browser features, deleted Registry keys, and changed the ExtendedUIHoverTime key.(Citation: Medium Metamorfo Apr 2020)(Citation: Fortinet Metamorfo Feb 2020)(Citation: FireEye Metamorfo Apr 2018)(Citation: ESET Casbaneiro Oct 2019)
- [S0256] Mosquito: [Mosquito](https://attack.mitre.org/software/S0256) can modify Registry keys under <code>HKCU\Software\Microsoft\[dllname]</code> to store configuration values. [Mosquito](https://attack.mitre.org/software/S0256) also modifies Registry keys under <code>HKCR\CLSID\...\InprocServer32</code> with a path to the launcher.(Citation: ESET Turla Mosquito Jan 2018)
- [S0560] TEARDROP: [TEARDROP](https://attack.mitre.org/software/S0560) modified the Registry to create a Windows service for itself on a compromised host.(Citation: Check Point Sunburst Teardrop December 2020)
- [S0142] StreamEx: [StreamEx](https://attack.mitre.org/software/S0142) has the ability to modify the Registry.(Citation: Cylance Shell Crew Feb 2017)
- [S0438] Attor: [Attor](https://attack.mitre.org/software/S0438)'s dispatcher can modify the Run registry key.(Citation: ESET Attor Oct 2019)
- [S1132] IPsec Helper: [IPsec Helper](https://attack.mitre.org/software/S1132) can make arbitrary changes to registry keys based on provided input.(Citation: SentinelOne Agrius 2021)
- [S0447] Lokibot: [Lokibot](https://attack.mitre.org/software/S0447) has modified the Registry as part of its UAC bypass process.(Citation: Talos Lokibot Jan 2021)
- [S0412] ZxShell: [ZxShell](https://attack.mitre.org/software/S0412) can create Registry entries to enable services to run.(Citation: Talos ZxShell Oct 2014)
- [S0356] KONNI: [KONNI](https://attack.mitre.org/software/S0356) has modified registry keys of ComSysApp, Svchost, and xmlProv on the machine to gain persistence.(Citation: Medium KONNI Jan 2020)(Citation: Malwarebytes Konni Aug 2021)
- [G0102] Wizard Spider: [Wizard Spider](https://attack.mitre.org/groups/G0102) has modified the Registry key <code>HKLM\System\CurrentControlSet\Control\SecurityProviders\WDigest</code> by setting the <code>UseLogonCredential</code> registry value to <code>1</code> in order to force credentials to be stored in clear text in memory. [Wizard Spider](https://attack.mitre.org/groups/G0102) has also modified the WDigest registry key to allow plaintext credentials to be cached in memory.(Citation: CrowdStrike Grim Spider May 2019)(Citation: Mandiant FIN12 Oct 2021)
- [G0050] APT32: [APT32](https://attack.mitre.org/groups/G0050)'s backdoor has modified the Windows Registry to store the backdoor's configuration. (Citation: ESET OceanLotus Mar 2019)
- [G0143] Aquatic Panda: [Aquatic Panda](https://attack.mitre.org/groups/G0143) modified the victim registry to enable the `RestrictedAdmin` mode feature, allowing for pass the hash behaviors to function via RDP.(Citation: Crowdstrike HuntReport 2022)
- [S0583] Pysa: [Pysa](https://attack.mitre.org/software/S0583) has modified the registry key “SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System” and added the ransom note.(Citation: CERT-FR PYSA April 2020)
- [C0006] Operation Honeybee: During [Operation Honeybee](https://attack.mitre.org/campaigns/C0006), the threat actors used batch files that modified registry keys.(Citation: McAfee Honeybee)
- [S0245] BADCALL: [BADCALL](https://attack.mitre.org/software/S0245) modifies the firewall Registry key <code>SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfileGloballyOpenPorts\\List</code>.(Citation: US-CERT BADCALL)
- [G1006] Earth Lusca: [Earth Lusca](https://attack.mitre.org/groups/G1006) modified the registry using the command <code>reg add “HKEY_CURRENT_USER\Environment” /v UserInitMprLogonScript /t REG_SZ /d “[file path]”</code> for persistence.(Citation: TrendMicro EarthLusca 2022)
- [S0576] MegaCortex: [MegaCortex](https://attack.mitre.org/software/S0576) has added entries to the Registry for ransom contact information.(Citation: IBM MegaCortex)
- [S1058] Prestige: [Prestige](https://attack.mitre.org/software/S1058) has the ability to register new registry keys for a new extension handler via `HKCR\.enc` and `HKCR\enc\shell\open\command`.(Citation: Microsoft Prestige ransomware October 2022)
- [S0511] RegDuke: [RegDuke](https://attack.mitre.org/software/S0511) can create seemingly legitimate Registry key to store its encryption key.(Citation: ESET Dukes October 2019)
- [G0108] Blue Mockingbird: [Blue Mockingbird](https://attack.mitre.org/groups/G0108) has used Windows Registry modifications to specify a DLL payload.(Citation: RedCanary Mockingbird May 2020)
- [S0691] Neoichor: [Neoichor](https://attack.mitre.org/software/S0691) has the ability to configure browser settings by modifying Registry entries under `HKEY_CURRENT_USER\Software\Microsoft\Internet Explorer`.(Citation: Microsoft NICKEL December 2021)
- [G0049] OilRig: [OilRig](https://attack.mitre.org/groups/G0049) has used reg.exe to modify system configuration.(Citation: Symantec Crambus OCT 2023)(Citation: Trend Micro Earth Simnavaz October 2024)
- [S1011] Tarrask: [Tarrask](https://attack.mitre.org/software/S1011) is able to delete the Security Descriptor (`SD`) registry subkey in order to “hide” scheduled tasks.(Citation: Tarrask scheduled task)
- [S0572] Caterpillar WebShell: [Caterpillar WebShell](https://attack.mitre.org/software/S0572) has a command to modify a Registry key.(Citation: ClearSky Lebanese Cedar Jan 2021)
- [S0268] Bisonal: [Bisonal](https://attack.mitre.org/software/S0268) has deleted Registry keys to clean up its prior activity.(Citation: Talos Bisonal Mar 2020)
- [S0467] TajMahal: [TajMahal](https://attack.mitre.org/software/S0467) can set the <code>KeepPrintedJobs</code> attribute for configured printers in <code>SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Print\\Printers</code> to enable document stealing.(Citation: Kaspersky TajMahal April 2019)
- [S0537] HyperStack: [HyperStack](https://attack.mitre.org/software/S0537) can add the name of its communication pipe to <code>HKLM\SYSTEM\\CurrentControlSet\\Services\\lanmanserver\\parameters\NullSessionPipes</code>.(Citation: Accenture HyperStack October 2020)
- [S0115] Crimson: [Crimson](https://attack.mitre.org/software/S0115) can set a Registry key to determine how long it has been installed and possibly to indicate the version number.(Citation: Proofpoint Operation Transparent Tribe March 2016)
- [G1003] Ember Bear: [Ember Bear](https://attack.mitre.org/groups/G1003) modifies registry values for anti-forensics and defense evasion purposes.(Citation: Cadet Blizzard emerges as novel threat actor)
- [S0229] Orz: [Orz](https://attack.mitre.org/software/S0229) can perform Registry operations.(Citation: Proofpoint Leviathan Oct 2017)
- [S0148] RTM: [RTM](https://attack.mitre.org/software/S0148) can delete all Registry entries created during its execution.(Citation: ESET RTM Feb 2017)
- [G1017] Volt Typhoon: [Volt Typhoon](https://attack.mitre.org/groups/G1017) has used `netsh` to create a PortProxy Registry modification on a compromised server running the Paessler Router Traffic Grapher (PRTG).(Citation: CISA AA24-038A PRC Critical Infrastructure February 2024)
- [S1099] Samurai: The [Samurai](https://attack.mitre.org/software/S1099) loader component can create multiple Registry keys to force the svchost.exe process to load the final backdoor.(Citation: Kaspersky ToddyCat June 2022)
- [C0014] Operation Wocao: During [Operation Wocao](https://attack.mitre.org/campaigns/C0014), the threat actors enabled Wdigest by changing the `HKLM\SYSTEM\\ControlSet001\\Control\\SecurityProviders\\WDigest` registry value from 0 (disabled) to 1 (enabled).(Citation: FoxIT Wocao December 2019)
- [G0035] Dragonfly: [Dragonfly](https://attack.mitre.org/groups/G0035) has modified the Registry to perform multiple techniques through the use of [Reg](https://attack.mitre.org/software/S0075).(Citation: US-CERT TA18-074A)
- [S0488] CrackMapExec: [CrackMapExec](https://attack.mitre.org/software/S0488) can create a registry key using wdigest.(Citation: CME Github September 2018)
- [G0078] Gorgon Group: [Gorgon Group](https://attack.mitre.org/groups/G0078) malware can deactivate security mechanisms in Microsoft Office by editing several keys and values under <code>HKCU\Software\Microsoft\Office\</code>.(Citation: Unit 42 Gorgon Group Aug 2018)
- [S0350] zwShell: [zwShell](https://attack.mitre.org/software/S0350) can modify the Registry.(Citation: McAfee Night Dragon)
- [S0631] Chaes: [Chaes](https://attack.mitre.org/software/S0631) can modify Registry values to stored information and establish persistence.(Citation: Cybereason Chaes Nov 2020)
- [S0336] NanoCore: [NanoCore](https://attack.mitre.org/software/S0336) has the capability to edit the Registry.(Citation: DigiTrust NanoCore Jan 2017)(Citation: PaloAlto NanoCore Feb 2016)
- [S0611] Clop: [Clop](https://attack.mitre.org/software/S0611) can make modifications to Registry keys.(Citation: Cybereason Clop Dec 2020)
- [S0665] ThreatNeedle: [ThreatNeedle](https://attack.mitre.org/software/S0665) can modify the Registry to save its configuration data as the following RC4-encrypted Registry key: `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\GameCon`.(Citation: Kaspersky ThreatNeedle Feb 2021)
- [S0386] Ursnif: [Ursnif](https://attack.mitre.org/software/S0386) has used Registry modifications as part of its installation routine.(Citation: TrendMicro BKDR_URSNIF.SM)(Citation: ProofPoint Ursnif Aug 2016)
- [S0441] PowerShower: [PowerShower](https://attack.mitre.org/software/S0441) has added a registry key so future powershell.exe instances are spawned off-screen by default, and has removed all registry entries that are left behind during the dropper process.(Citation: Unit 42 Inception November 2018)
- [S0045] ADVSTORESHELL: [ADVSTORESHELL](https://attack.mitre.org/software/S0045) is capable of setting and deleting Registry values.(Citation: Bitdefender APT28 Dec 2015)
- [S0568] EVILNUM: [EVILNUM](https://attack.mitre.org/software/S0568) can make modifications to the Regsitry for persistence.(Citation: Prevailion EvilNum May 2020)
- [S0330] Zeus Panda: [Zeus Panda](https://attack.mitre.org/software/S0330) modifies several Registry keys under <code>HKCU\Software\Microsoft\Internet Explorer\ PhishingFilter\</code> to disable phishing filters.(Citation: GDATA Zeus Panda June 2017)
- [S0343] Exaramel for Windows: [Exaramel for Windows](https://attack.mitre.org/software/S0343) adds the configuration to the Registry in XML format.(Citation: ESET TeleBots Oct 2018)
- [S0205] Naid: [Naid](https://attack.mitre.org/software/S0205) creates Registry entries that store information about a created service and point to a malicious DLL dropped to disk.(Citation: Symantec Naid June 2012)
- [S0140] Shamoon: Once [Shamoon](https://attack.mitre.org/software/S0140) has access to a network share, it enables the RemoteRegistry service on the target system. It will then connect to the system with RegConnectRegistryW and modify the Registry to disable UAC remote restrictions by setting <code>SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\LocalAccountTokenFilterPolicy</code> to 1.(Citation: FireEye Shamoon Nov 2016)(Citation: Palo Alto Shamoon Nov 2016)(Citation: McAfee Shamoon December 2018)
- [S0663] SysUpdate: [SysUpdate](https://attack.mitre.org/software/S0663) can write its configuration file to <code>Software\Classes\scConfig</code> in either <code>HKEY_LOCAL_MACHINE</code> or <code>HKEY_CURRENT_USER</code>.(Citation: Trend Micro Iron Tiger April 2021)
- [G1014] LuminousMoth: [LuminousMoth](https://attack.mitre.org/groups/G1014) has used malware that adds Registry keys for persistence.(Citation: Kaspersky LuminousMoth July 2021)(Citation: Bitdefender LuminousMoth July 2021)
- [S0385] njRAT: [njRAT](https://attack.mitre.org/software/S0385) can create, delete, or modify a specified Registry key or value.(Citation: Fidelis njRAT June 2013)(Citation: Trend Micro njRAT 2018)
- [S1047] Mori: [Mori](https://attack.mitre.org/software/S1047) can write data to `HKLM\Software\NFC\IPA` and `HKLM\Software\NFC\` and delete Registry values.(Citation: DHS CISA AA22-055A MuddyWater February 2022)(Citation: CYBERCOM Iranian Intel Cyber January 2022)
- [S0342] GreyEnergy: [GreyEnergy](https://attack.mitre.org/software/S0342) modifies conditions in the Registry and adds keys.(Citation: ESET GreyEnergy Oct 2018)
- [S0075] Reg: [Reg](https://attack.mitre.org/software/S0075) may be used to interact with and modify the Windows Registry of a local or remote system at the command-line interface.(Citation: Microsoft Reg)
- [S0090] Rover: [Rover](https://attack.mitre.org/software/S0090) has functionality to remove Registry Run key persistence as a cleanup procedure.(Citation: Palo Alto Rover)
- [S0180] Volgmer: [Volgmer](https://attack.mitre.org/software/S0180) modifies the Registry to store an encoded configuration file in <code>HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\WMI\Security</code>.(Citation: US-CERT Volgmer 2 Nov 2017)(Citation: Symantec Volgmer Aug 2014)
- [S0660] Clambling: [Clambling](https://attack.mitre.org/software/S0660) can set and delete Registry keys.(Citation: Trend Micro DRBControl February 2020)
- [S0650] QakBot: [QakBot](https://attack.mitre.org/software/S0650) can modify the Registry to store its configuration information in a randomly named subkey under <code>HKCU\Software\Microsoft</code>.(Citation: Red Canary Qbot)(Citation: Group IB Ransomware September 2020)
- [S0239] Bankshot: [Bankshot](https://attack.mitre.org/software/S0239) writes data into the Registry key <code>HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Pniumj</code>.(Citation: US-CERT Bankshot Dec 2017)
- [G0094] Kimsuky: [Kimsuky](https://attack.mitre.org/groups/G0094) has modified Registry settings for default file associations to enable all macros and for persistence.(Citation: CISA AA20-301A Kimsuky)(Citation: Crowdstrike GTR2020 Mar 2020)(Citation: Talos Kimsuky Nov 2021)(Citation: KISA Operation Muzabi)
- [S0126] ComRAT: [ComRAT](https://attack.mitre.org/software/S0126) has modified Registry values to store encrypted orchestrator code and payloads.(Citation: ESET ComRAT May 2020)(Citation: CISA ComRAT Oct 2020)
- [S0640] Avaddon: [Avaddon](https://attack.mitre.org/software/S0640) modifies several registry keys for persistence and UAC bypass.(Citation: Arxiv Avaddon Feb 2021)
- [S1025] Amadey: [Amadey](https://attack.mitre.org/software/S1025) has overwritten registry keys for persistence.(Citation: BlackBerry Amadey 2020)
- [S1180] BlackByte Ransomware: [BlackByte Ransomware](https://attack.mitre.org/software/S1180) modifies the victim Registry to prevent system recovery.(Citation: Trustwave BlackByte 2021)
- [S0266] TrickBot: [TrickBot](https://attack.mitre.org/software/S0266) can modify registry entries.(Citation: Trend Micro Trickbot Nov 2018)
- [G0096] APT41: [APT41](https://attack.mitre.org/groups/G0096) used a malware variant called GOODLUCK to modify the registry in order to steal credentials.(Citation: FireEye APT41 Aug 2019)(Citation: Group IB APT 41 June 2021)
- [S0334] DarkComet: [DarkComet](https://attack.mitre.org/software/S0334) adds a Registry value for its installation routine to the Registry Key <code>HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\System Enable LUA=”0”</code> and <code>HKEY_CURRENT_USER\Software\DC3_FEXEC</code>.(Citation: TrendMicro DarkComet Sept 2014)(Citation: Malwarebytes DarkComet March 2018)
- [G0059] Magic Hound: [Magic Hound](https://attack.mitre.org/groups/G0059) has modified Registry settings for security tools.(Citation: DFIR Report APT35 ProxyShell March 2022)
- [S0263] TYPEFRAME: [TYPEFRAME](https://attack.mitre.org/software/S0263) can install encrypted configuration data under the Registry key <code>HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\ShellCompatibility\Applications\laxhost.dll</code> and <code>HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\PrintConfigs</code>.(Citation: US-CERT TYPEFRAME June 2018)
- [S1050] PcShare: [PcShare](https://attack.mitre.org/software/S1050) can delete its persistence mechanisms from the registry.(Citation: Bitdefender FunnyDream Campaign November 2020)
- [S0271] KEYMARBLE: [KEYMARBLE](https://attack.mitre.org/software/S0271) has a command to create Registry entries for storing data under <code>HKEY_CURRENT_USER\SOFTWARE\Microsoft\WABE\DataPath</code>.(Citation: US-CERT KEYMARBLE Aug 2018)
- [S0679] Ferocious: [Ferocious](https://attack.mitre.org/software/S0679) has the ability to add a Class ID in the current user Registry hive to enable persistence mechanisms.(Citation: Kaspersky WIRTE November 2021)
- [S1066] DarkTortilla: [DarkTortilla](https://attack.mitre.org/software/S1066) has modified registry keys for persistence.(Citation: Secureworks DarkTortilla Aug 2022)
- [S0348] Cardinal RAT: [Cardinal RAT](https://attack.mitre.org/software/S0348) sets <code>HKCU\Software\Microsoft\Windows NT\CurrentVersion\Windows\Load</code> to point to its executable.(Citation: PaloAlto CardinalRat Apr 2017)
- [S0331] Agent Tesla: [Agent Tesla](https://attack.mitre.org/software/S0331) can achieve persistence by modifying Registry key entries.(Citation: SentinelLabs Agent Tesla Aug 2020)
- [S1090] NightClub: [NightClub](https://attack.mitre.org/software/S1090) can modify the Registry to set the ServiceDLL for a service created by the malware for persistence.(Citation: MoustachedBouncer ESET August 2023)
- [S0269] QUADAGENT: [QUADAGENT](https://attack.mitre.org/software/S0269) modifies an HKCU Registry key to store a session identifier unique to the compromised system as well as a pre-shared key used for encrypting and decrypting C2 communications.(Citation: Unit 42 QUADAGENT July 2018)
- [S0198] NETWIRE: [NETWIRE](https://attack.mitre.org/software/S0198) can modify the Registry to store its configuration information.(Citation: Red Canary NETWIRE January 2020)
- [S0589] Sibot: [Sibot](https://attack.mitre.org/software/S0589) has modified the Registry to install a second-stage script in the <code>HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\sibot</code>.(Citation: MSTIC NOBELIUM Mar 2021)
- [S0570] BitPaymer: [BitPaymer](https://attack.mitre.org/software/S0570) can set values in the Registry to help in execution.(Citation: Crowdstrike Indrik November 2018)
- [S1149] CHIMNEYSWEEP: [CHIMNEYSWEEP](https://attack.mitre.org/software/S1149) can use the Windows Registry Environment key to change the `%windir%` variable to point to `c:\Windows` to enable payload execution.(Citation: Mandiant ROADSWEEP August 2022)
- [S0662] RCSession: [RCSession](https://attack.mitre.org/software/S0662) can write its configuration file to the Registry.(Citation: Trend Micro DRBControl February 2020)(Citation: Profero APT27 December 2020)
- [G1044] APT42: [APT42](https://attack.mitre.org/groups/G1044) has modified Registry keys to maintain persistence.(Citation: Mandiant APT42-charms)
- [G1031] Saint Bear: [Saint Bear](https://attack.mitre.org/groups/G1031) will leverage malicious Windows batch scripts to modify registry values associated with Windows Defender functionality.(Citation: Palo Alto Unit 42 OutSteel SaintBot February 2022 )
- [S0210] Nerex: [Nerex](https://attack.mitre.org/software/S0210) creates a Registry subkey that registers a new service.(Citation: Symantec Nerex May 2012)
- [S0444] ShimRat: [ShimRat](https://attack.mitre.org/software/S0444) has registered two registry keys for shim databases.(Citation: FOX-IT May 2016 Mofang)
- [G0027] Threat Group-3390: A [Threat Group-3390](https://attack.mitre.org/groups/G0027) tool has created new Registry keys under `HKEY_CURRENT_USER\Software\Classes\` and `HKLM\SYSTEM\CurrentControlSet\services`.(Citation: Nccgroup Emissary Panda May 2018)(Citation: Trend Micro Iron Tiger April 2021)
- [G0061] FIN8: [FIN8](https://attack.mitre.org/groups/G0061) has deleted Registry keys during post compromise cleanup activities.(Citation: FireEye Know Your Enemy FIN8 Aug 2016)
- [S0677] AADInternals: [AADInternals](https://attack.mitre.org/software/S0677) can modify registry keys as part of setting a new pass-through authentication agent.(Citation: AADInternals Documentation)
- [S0019] Regin: [Regin](https://attack.mitre.org/software/S0019) appears to have functionality to modify remote Registry information.(Citation: Kaspersky Regin)
- [S0664] Pandora: [Pandora](https://attack.mitre.org/software/S0664) can write an encrypted token to the Registry to enable processing of remote commands.(Citation: Trend Micro Iron Tiger April 2021)


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


### T1136 - Create Account

Description:

Adversaries may create an account to maintain access to victim systems.(Citation: Symantec WastedLocker June 2020) With a sufficient level of access, creating such accounts may be used to establish secondary credentialed access that do not require persistent remote access tools to be deployed on the system.

Accounts may be created on the local system or within a domain or cloud tenant. In cloud environments, adversaries may create accounts that only have access to specific services, which can reduce the chance of detection.

Procedures:

- [G0119] Indrik Spider: [Indrik Spider](https://attack.mitre.org/groups/G0119) used <code>wmic.exe</code> to add a new user to the system.(Citation: Symantec WastedLocker June 2020)
- [S1199] LockBit 2.0: [LockBit 2.0](https://attack.mitre.org/software/S1199) has been observed creating accounts for persistence using simple names like "a".(Citation: Palo Alto Lockbit 2.0 JUN 2022)
- [C0025] 2016 Ukraine Electric Power Attack: During the [2016 Ukraine Electric Power Attack](https://attack.mitre.org/campaigns/C0025), [Sandworm Team](https://attack.mitre.org/groups/G0034) added a login to a SQL Server with `sp_addlinkedsrvlogin`.(Citation: Dragos Crashoverride 2018)
- [G1015] Scattered Spider: [Scattered Spider](https://attack.mitre.org/groups/G1015) creates new user identities within the compromised organization.(Citation: CISA Scattered Spider Advisory November 2023)
- [G1045] Salt Typhoon: [Salt Typhoon](https://attack.mitre.org/groups/G1045) has created Linux-level users on compromised network devices through modification of `/etc/shadow` and `/etc/passwd`.(Citation: Cisco Salt Typhoon FEB 2025)

#### T1136.001 - Create Account: Local Account

Description:

Adversaries may create a local account to maintain access to victim systems. Local accounts are those configured by an organization for use by users, remote support, services, or for administration on a single system or service. 

For example, with a sufficient level of access, the Windows <code>net user /add</code> command can be used to create a local account.  In Linux, the `useradd` command can be used, while on macOS systems, the <code>dscl -create</code> command can be used. Local accounts may also be added to network devices, often via common [Network Device CLI](https://attack.mitre.org/techniques/T1059/008) commands such as <code>username</code>, to ESXi servers via `esxcli system account add`, or to Kubernetes clusters using the `kubectl` utility.(Citation: cisco_username_cmd)(Citation: Kubernetes Service Accounts Security)

Such accounts may be used to establish secondary credentialed access that do not require persistent remote access tools to be deployed on the system.

Procedures:

- [G0102] Wizard Spider: [Wizard Spider](https://attack.mitre.org/groups/G0102) has created local administrator accounts to maintain persistence in compromised networks.(Citation: Mandiant FIN12 Oct 2021)
- [G1023] APT5: [APT5](https://attack.mitre.org/groups/G1023) has created Local Administrator accounts to maintain access to systems with short-cycle credential rotation.(Citation: Mandiant Pulse Secure Update May 2021)
- [S0394] HiddenWasp: [HiddenWasp](https://attack.mitre.org/software/S0394) creates a user account as a means to provide initial persistence to the compromised machine.(Citation: Intezer HiddenWasp Map 2019)
- [S0493] GoldenSpy: [GoldenSpy](https://attack.mitre.org/software/S0493) can create new users on an infected system.(Citation: Trustwave GoldenSpy June 2020)
- [S0363] Empire: [Empire](https://attack.mitre.org/software/S0363) has a module for creating a local user if permissions allow.(Citation: Github PowerShell Empire)
- [G0035] Dragonfly: [Dragonfly](https://attack.mitre.org/groups/G0035) has created accounts on victims, including administrator accounts, some of which appeared to be tailored to each individual staging target.(Citation: US-CERT TA18-074A)
- [G0139] TeamTNT: [TeamTNT](https://attack.mitre.org/groups/G0139) has created local privileged users on victim machines.(Citation: Intezer TeamTNT September 2020)
- [G0117] Fox Kitten: [Fox Kitten](https://attack.mitre.org/groups/G0117) has created a local user account with administrator privileges.(Citation: ClearSky Pay2Kitten December 2020)
- [S0649] SMOKEDHAM: [SMOKEDHAM](https://attack.mitre.org/software/S0649) has created user accounts.(Citation: FireEye SMOKEDHAM June 2021)
- [G0096] APT41: [APT41](https://attack.mitre.org/groups/G0096) has created user accounts.(Citation: FireEye APT41 Aug 2019)
- [G1016] FIN13: [FIN13](https://attack.mitre.org/groups/G1016) has created MS-SQL local accounts in a compromised network.(Citation: Sygnia Elephant Beetle Jan 2022)
- [S0143] Flame: [Flame](https://attack.mitre.org/software/S0143) can create backdoor accounts with login “HelpAssistant” on domain connected systems if appropriate rights are available.(Citation: Kaspersky Flame)(Citation: Kaspersky Flame Functionality)
- [S0382] ServHelper: [ServHelper](https://attack.mitre.org/software/S0382) has created a new user named "supportaccount".(Citation: Proofpoint TA505 Jan 2019)
- [G0094] Kimsuky: [Kimsuky](https://attack.mitre.org/groups/G0094) has created accounts with <code>net user</code>.(Citation: KISA Operation Muzabi)
- [S0192] Pupy: [Pupy](https://attack.mitre.org/software/S0192) can user PowerView to execute “net user” commands and create local system accounts.(Citation: GitHub Pupy)
- [S0085] S-Type: [S-Type](https://attack.mitre.org/software/S0085) may create a temporary user on the system named `Lost_{Unique Identifier}` with the password `pond~!@6”{Unique Identifier}`.(Citation: Cylance Dust Storm)
- [S0039] Net: The <code>net user username \password</code> commands in [Net](https://attack.mitre.org/software/S0039) can be used to create a local account.(Citation: Savill 1999)
- [S1111] DarkGate: [DarkGate](https://attack.mitre.org/software/S1111) creates a local user account, <code>SafeMode</code>, via <code>net user</code> commands.(Citation: Ensilo Darkgate 2018)
- [S0084] Mis-Type: [Mis-Type](https://attack.mitre.org/software/S0084) may create a temporary user on the system named `Lost_{Unique Identifier}`.(Citation: Cylance Dust Storm)
- [G0059] Magic Hound: [Magic Hound](https://attack.mitre.org/groups/G0059) has created local accounts named `help` and `DefaultAccount` on compromised machines.(Citation: DFIR Report APT35 ProxyShell March 2022)(Citation: Microsoft Iranian Threat Actor Trends November 2021)
- [S0030] Carbanak: [Carbanak](https://attack.mitre.org/software/S0030) can create a Windows account.(Citation: FireEye CARBANAK June 2017)
- [G0119] Indrik Spider: [Indrik Spider](https://attack.mitre.org/groups/G0119) has created local system accounts and has added the accounts to privileged groups.(Citation: Mandiant_UNC2165)
- [G0077] Leafminer: [Leafminer](https://attack.mitre.org/groups/G0077) used a tool called Imecab to set up a persistent remote access account on the victim machine.(Citation: Symantec Leafminer July 2018)
- [G0087] APT39: [APT39](https://attack.mitre.org/groups/G0087) has created accounts on multiple compromised hosts to perform actions within the network.(Citation: BitDefender Chafer May 2020)
- [S0601] Hildegard: [Hildegard](https://attack.mitre.org/software/S0601) has created a user named “monerodaemon”.(Citation: Unit 42 Hildegard Malware)
- [S0412] ZxShell: [ZxShell](https://attack.mitre.org/software/S0412) has a feature to create local user accounts.(Citation: Talos ZxShell Oct 2014)
- [G1034] Daggerfly: [Daggerfly](https://attack.mitre.org/groups/G1034) created a local account on victim machines to maintain access.(Citation: Symantec Daggerfly 2023)
- [G0022] APT3: [APT3](https://attack.mitre.org/groups/G0022) has been known to create or enable accounts, such as <code>support_388945a0</code>.(Citation: aptsim)
- [S0274] Calisto: [Calisto](https://attack.mitre.org/software/S0274) has the capability to add its own account to the victim's machine.(Citation: Symantec Calisto July 2018)

#### T1136.002 - Create Account: Domain Account

Description:

Adversaries may create a domain account to maintain access to victim systems. Domain accounts are those managed by Active Directory Domain Services where access and permissions are configured across systems and services that are part of that domain. Domain accounts can cover user, administrator, and service accounts. With a sufficient level of access, the <code>net user /add /domain</code> command can be used to create a domain account.(Citation: Savill 1999)

Such accounts may be used to establish secondary credentialed access that do not require persistent remote access tools to be deployed on the system.

Procedures:

- [S0192] Pupy: [Pupy](https://attack.mitre.org/software/S0192) can user PowerView to execute “net user” commands and create domain accounts.(Citation: GitHub Pupy)
- [G0093] GALLIUM: [GALLIUM](https://attack.mitre.org/groups/G0093) created high-privileged domain user accounts to maintain access to victim networks.(Citation: Cybereason Soft Cell June 2019)(Citation: Microsoft GALLIUM December 2019)
- [G1043] BlackByte: [BlackByte](https://attack.mitre.org/groups/G1043) created privileged domain accounts during intrusions.(Citation: Cisco BlackByte 2024)
- [C0028] 2015 Ukraine Electric Power Attack: During the [2015 Ukraine Electric Power Attack](https://attack.mitre.org/campaigns/C0028), [Sandworm Team](https://attack.mitre.org/groups/G0034) created privileged domain accounts to be used for further exploitation and lateral movement. (Citation: Booz Allen Hamilton)
- [G0102] Wizard Spider: [Wizard Spider](https://attack.mitre.org/groups/G0102) has created and used new accounts within a victim's Active Directory environment to maintain persistence.(Citation: Mandiant FIN12 Oct 2021)
- [S0029] PsExec: [PsExec](https://attack.mitre.org/software/S0029) has the ability to remotely create accounts on target systems.(Citation: NCC Group Fivehands June 2021)
- [S0039] Net: The <code>net user username \password \domain</code> commands in [Net](https://attack.mitre.org/software/S0039) can be used to create a domain account.(Citation: Savill 1999)
- [C0025] 2016 Ukraine Electric Power Attack: During the [2016 Ukraine Electric Power Attack](https://attack.mitre.org/campaigns/C0025), [Sandworm Team](https://attack.mitre.org/groups/G0034) created two new accounts, “admin” and “система” (System). The accounts were then assigned to a domain matching local operation and were delegated new privileges.(Citation: Dragos Crashoverride 2018)
- [G0125] HAFNIUM: [HAFNIUM](https://attack.mitre.org/groups/G0125) has created domain accounts.(Citation: Volexity Exchange Marauder March 2021)(Citation: Microsoft Silk Typhoon MAR 2025)
- [S0363] Empire: [Empire](https://attack.mitre.org/software/S0363) has a module for creating a new domain user if permissions allow.(Citation: Github PowerShell Empire)

#### T1136.003 - Create Account: Cloud Account

Description:

Adversaries may create a cloud account to maintain access to victim systems. With a sufficient level of access, such accounts may be used to establish secondary credentialed access that does not require persistent remote access tools to be deployed on the system.(Citation: Microsoft O365 Admin Roles)(Citation: Microsoft Support O365 Add Another Admin, October 2019)(Citation: AWS Create IAM User)(Citation: GCP Create Cloud Identity Users)(Citation: Microsoft Azure AD Users)

In addition to user accounts, cloud accounts may be associated with services. Cloud providers handle the concept of service accounts in different ways. In Azure, service accounts include service principals and managed identities, which can be linked to various resources such as OAuth applications, serverless functions, and virtual machines in order to grant those resources permissions to perform various activities in the environment.(Citation: Microsoft Entra ID Service Principals) In GCP, service accounts can also be linked to specific resources, as well as be impersonated by other accounts for [Temporary Elevated Cloud Access](https://attack.mitre.org/techniques/T1548/005).(Citation: GCP Service Accounts) While AWS has no specific concept of service accounts, resources can be directly granted permission to assume roles.(Citation: AWS Instance Profiles)(Citation: AWS Lambda Execution Role)

Adversaries may create accounts that only have access to specific cloud services, which can reduce the chance of detection.

Once an adversary has created a cloud account, they can then manipulate that account to ensure persistence and allow access to additional resources - for example, by adding [Additional Cloud Credentials](https://attack.mitre.org/techniques/T1098/001) or assigning [Additional Cloud Roles](https://attack.mitre.org/techniques/T1098/003).

Procedures:

- [G0016] APT29: [APT29](https://attack.mitre.org/groups/G0016) can create new users through Azure AD.(Citation: MSTIC Nobelium Oct 2021)
- [G1004] LAPSUS$: [LAPSUS$](https://attack.mitre.org/groups/G1004) has created global admin accounts in the targeted organization's cloud instances to gain persistence.(Citation: MSTIC DEV-0537 Mar 2022)
- [S0677] AADInternals: [AADInternals](https://attack.mitre.org/software/S0677) can create new Azure AD users.(Citation: AADInternals Documentation)


### T1137 - Office Application Startup

Description:

Adversaries may leverage Microsoft Office-based applications for persistence between startups. Microsoft Office is a fairly common application suite on Windows-based operating systems within an enterprise network. There are multiple mechanisms that can be used with Office for persistence when an Office-based application is started; this can include the use of Office Template Macros and add-ins.

A variety of features have been discovered in Outlook that can be abused to obtain persistence, such as Outlook rules, forms, and Home Page.(Citation: SensePost Ruler GitHub) These persistence mechanisms can work within Outlook or be used through Office 365.(Citation: TechNet O365 Outlook Rules)

Procedures:

- [G0050] APT32: [APT32](https://attack.mitre.org/groups/G0050) have replaced Microsoft Outlook's VbaProject.OTM file to install a backdoor macro for persistence.(Citation: Cybereason Oceanlotus May 2017)(Citation: Cybereason Cobalt Kitty 2017)
- [G0047] Gamaredon Group: [Gamaredon Group](https://attack.mitre.org/groups/G0047) has inserted malicious macros into existing documents, providing persistence when they are reopened. [Gamaredon Group](https://attack.mitre.org/groups/G0047) has loaded the group's previously delivered VBA project by relaunching Microsoft Outlook with the <code>/altvba</code> option, once the Application.Startup event is received.(Citation: ESET Gamaredon June 2020)

#### T1137.001 - Office Application Startup: Office Template Macros

Description:

Adversaries may abuse Microsoft Office templates to obtain persistence on a compromised system. Microsoft Office contains templates that are part of common Office applications and are used to customize styles. The base templates within the application are used each time an application starts. (Citation: Microsoft Change Normal Template)

Office Visual Basic for Applications (VBA) macros (Citation: MSDN VBA in Office) can be inserted into the base template and used to execute code when the respective Office application starts in order to obtain persistence. Examples for both Word and Excel have been discovered and published. By default, Word has a Normal.dotm template created that can be modified to include a malicious macro. Excel does not have a template file created by default, but one can be added that will automatically be loaded.(Citation: enigma0x3 normal.dotm)(Citation: Hexacorn Office Template Macros) Shared templates may also be stored and pulled from remote locations.(Citation: GlobalDotName Jun 2019) 

Word Normal.dotm location:<br>
<code>C:\Users\&lt;username&gt;\AppData\Roaming\Microsoft\Templates\Normal.dotm</code>

Excel Personal.xlsb location:<br>
<code>C:\Users\&lt;username&gt;\AppData\Roaming\Microsoft\Excel\XLSTART\PERSONAL.XLSB</code>

Adversaries may also change the location of the base template to point to their own by hijacking the application's search order, e.g. Word 2016 will first look for Normal.dotm under <code>C:\Program Files (x86)\Microsoft Office\root\Office16\</code>, or by modifying the GlobalDotName registry key. By modifying the GlobalDotName registry key an adversary can specify an arbitrary location, file name, and file extension to use for the template that will be loaded on application startup. To abuse GlobalDotName, adversaries may first need to register the template as a trusted document or place it in a trusted location.(Citation: GlobalDotName Jun 2019) 

An adversary may need to enable macros to execute unrestricted depending on the system or enterprise security policy on use of macros.

Procedures:

- [G0069] MuddyWater: [MuddyWater](https://attack.mitre.org/groups/G0069) has used a Word Template, Normal.dotm, for persistence.(Citation: Reaqta MuddyWater November 2017)
- [S0475] BackConfig: [BackConfig](https://attack.mitre.org/software/S0475) has the ability to use hidden columns in Excel spreadsheets to store executable files or commands for VBA macros.(Citation: Unit 42 BackConfig May 2020)
- [S0154] Cobalt Strike: [Cobalt Strike](https://attack.mitre.org/software/S0154) has the ability to use an Excel Workbook to execute additional code by enabling Office to trust macros and execute code without user permission.(Citation: Talos Cobalt Strike September 2020)

#### T1137.002 - Office Application Startup: Office Test

Description:

Adversaries may abuse the Microsoft Office "Office Test" Registry key to obtain persistence on a compromised system. An Office Test Registry location exists that allows a user to specify an arbitrary DLL that will be executed every time an Office application is started. This Registry key is thought to be used by Microsoft to load DLLs for testing and debugging purposes while developing Office applications. This Registry key is not created by default during an Office installation.(Citation: Hexacorn Office Test)(Citation: Palo Alto Office Test Sofacy)

There exist user and global Registry keys for the Office Test feature, such as:

* <code>HKEY_CURRENT_USER\Software\Microsoft\Office test\Special\Perf</code>
* <code>HKEY_LOCAL_MACHINE\Software\Microsoft\Office test\Special\Perf</code>

Adversaries may add this Registry key and specify a malicious DLL that will be executed whenever an Office application, such as Word or Excel, is started.

Procedures:

- [G0007] APT28: [APT28](https://attack.mitre.org/groups/G0007) has used the Office Test persistence mechanism within Microsoft Office by adding the Registry key <code>HKCU\Software\Microsoft\Office test\Special\Perf</code> to execute code.(Citation: Palo Alto Office Test Sofacy)

#### T1137.003 - Office Application Startup: Outlook Forms

Description:

Adversaries may abuse Microsoft Outlook forms to obtain persistence on a compromised system. Outlook forms are used as templates for presentation and functionality in Outlook messages. Custom Outlook forms can be created that will execute code when a specifically crafted email is sent by an adversary utilizing the same custom Outlook form.(Citation: SensePost Outlook Forms)

Once malicious forms have been added to the user’s mailbox, they will be loaded when Outlook is started. Malicious forms will execute when an adversary sends a specifically crafted email to the user.(Citation: SensePost Outlook Forms)

Procedures:

- [S0358] Ruler: [Ruler](https://attack.mitre.org/software/S0358) can be used to automate the abuse of Outlook Forms to establish persistence.(Citation: SensePost Ruler GitHub)

#### T1137.004 - Office Application Startup: Outlook Home Page

Description:

Adversaries may abuse Microsoft Outlook's Home Page feature to obtain persistence on a compromised system. Outlook Home Page is a legacy feature used to customize the presentation of Outlook folders. This feature allows for an internal or external URL to be loaded and presented whenever a folder is opened. A malicious HTML page can be crafted that will execute code when loaded by Outlook Home Page.(Citation: SensePost Outlook Home Page)

Once malicious home pages have been added to the user’s mailbox, they will be loaded when Outlook is started. Malicious Home Pages will execute when the right Outlook folder is loaded/reloaded.(Citation: SensePost Outlook Home Page)

Procedures:

- [G0049] OilRig: [OilRig](https://attack.mitre.org/groups/G0049) has abused the Outlook Home Page feature for persistence. [OilRig](https://attack.mitre.org/groups/G0049) has also used CVE-2017-11774 to roll back the initial patch designed to protect against Home Page abuse.(Citation: FireEye Outlook Dec 2019)
- [S0358] Ruler: [Ruler](https://attack.mitre.org/software/S0358) can be used to automate the abuse of Outlook Home Pages to establish persistence.(Citation: SensePost Ruler GitHub)

#### T1137.005 - Office Application Startup: Outlook Rules

Description:

Adversaries may abuse Microsoft Outlook rules to obtain persistence on a compromised system. Outlook rules allow a user to define automated behavior to manage email messages. A benign rule might, for example, automatically move an email to a particular folder in Outlook if it contains specific words from a specific sender. Malicious Outlook rules can be created that can trigger code execution when an adversary sends a specifically crafted email to that user.(Citation: SilentBreak Outlook Rules)

Once malicious rules have been added to the user’s mailbox, they will be loaded when Outlook is started. Malicious rules will execute when an adversary sends a specifically crafted email to the user.(Citation: SilentBreak Outlook Rules)

Procedures:

- [S0358] Ruler: [Ruler](https://attack.mitre.org/software/S0358) can be used to automate the abuse of Outlook Rules to establish persistence.(Citation: SensePost Ruler GitHub)

#### T1137.006 - Office Application Startup: Add-ins

Description:

Adversaries may abuse Microsoft Office add-ins to obtain persistence on a compromised system. Office add-ins can be used to add functionality to Office programs. (Citation: Microsoft Office Add-ins) There are different types of add-ins that can be used by the various Office products; including Word/Excel add-in Libraries (WLL/XLL), VBA add-ins, Office Component Object Model (COM) add-ins, automation add-ins, VBA Editor (VBE), Visual Studio Tools for Office (VSTO) add-ins, and Outlook add-ins. (Citation: MRWLabs Office Persistence Add-ins)(Citation: FireEye Mail CDS 2018)

Add-ins can be used to obtain persistence because they can be set to execute code when an Office application starts.

Procedures:

- [S0268] Bisonal: [Bisonal](https://attack.mitre.org/software/S0268) has been loaded through a `.wll` extension added to the ` %APPDATA%\microsoft\word\startup\` repository.(Citation: Talos Bisonal Mar 2020)
- [G0019] Naikon: [Naikon](https://attack.mitre.org/groups/G0019) has used the RoyalRoad exploit builder to drop a second stage loader, intel.wll, into the Word Startup folder on the compromised host.(Citation: CheckPoint Naikon May 2020)
- [S1143] LunarLoader: [LunarLoader](https://attack.mitre.org/software/S1143) has the ability to use Microsoft Outlook add-ins to establish persistence. (Citation: ESET Turla Lunar toolset May 2024)
- [S1142] LunarMail: [LunarMail](https://attack.mitre.org/software/S1142) has the ability to use Outlook add-ins for persistence.(Citation: ESET Turla Lunar toolset May 2024)


### T1176 - Software Extensions

Description:

Adversaries may abuse software extensions to establish persistent access to victim systems. Software extensions are modular components that enhance or customize the functionality of software applications, including web browsers, Integrated Development Environments (IDEs), and other platforms.(Citation: Chrome Extension C2 Malware)(Citation: Abramovsky VSCode Security) Extensions are typically installed via official marketplaces, app stores, or manually loaded by users, and they often inherit the permissions and access levels of the host application. 

  
Malicious extensions can be introduced through various methods, including social engineering, compromised marketplaces, or direct installation by users or by adversaries who have already gained access to a system. Malicious extensions can be named similarly or identically to benign extensions in marketplaces. Security mechanisms in extension marketplaces may be insufficient to detect malicious components, allowing adversaries to bypass automated scanners or exploit trust established during the installation process. Adversaries may also abuse benign extensions to achieve their objectives, such as using legitimate functionality to tunnel data or bypass security controls. 

The modular nature of extensions and their integration with host applications make them an attractive target for adversaries seeking to exploit trusted software ecosystems. Detection can be challenging due to the inherent trust placed in extensions during installation and their ability to blend into normal application workflows.

#### T1176.001 - Software Extensions: Browser Extensions

Description:

Adversaries may abuse internet browser extensions to establish persistent access to victim systems. Browser extensions or plugins are small programs that can add functionality to and customize aspects of internet browsers. They can be installed directly via a local file or custom URL or through a browser's app store - an official online platform where users can browse, install, and manage extensions for a specific web browser. Extensions generally inherit the web browser's permissions previously granted.(Citation: Wikipedia Browser Extension)(Citation: Chrome Extensions Definition) 
 
Malicious extensions can be installed into a browser through malicious app store downloads masquerading as legitimate extensions, through social engineering, or by an adversary that has already compromised a system. Security can be limited on browser app stores, so it may not be difficult for malicious extensions to defeat automated scanners.(Citation: Malicious Chrome Extension Numbers) Depending on the browser, adversaries may also manipulate an extension's update url to install updates from an adversary-controlled server or manipulate the mobile configuration file to silently install additional extensions. 
  
Previous to macOS 11, adversaries could silently install browser extensions via the command line using the <code>profiles</code> tool to install malicious <code>.mobileconfig</code> files. In macOS 11+, the use of the <code>profiles</code> tool can no longer install configuration profiles; however, <code>.mobileconfig</code> files can be planted and installed with user interaction.(Citation: xorrior chrome extensions macOS) 
 
Once the extension is installed, it can browse to websites in the background, steal all information that a user enters into a browser (including credentials), and be used as an installer for a RAT for persistence.(Citation: Chrome Extension Crypto Miner)(Citation: ICEBRG Chrome Extensions)(Citation: Banker Google Chrome Extension Steals Creds)(Citation: Catch All Chrome Extension) 

There have also been instances of botnets using a persistent backdoor through malicious Chrome extensions for [Command and Control](https://attack.mitre.org/tactics/TA0011).(Citation: Stantinko Botnet)(Citation: Chrome Extension C2 Malware) Adversaries may also use browser extensions to modify browser permissions and components, privacy settings, and other security controls for [Defense Evasion](https://attack.mitre.org/tactics/TA0005).(Citation: Browers FriarFox)(Citation: Browser Adrozek)

Procedures:

- [S1122] Mispadu: [Mispadu](https://attack.mitre.org/software/S1122) utilizes malicious Google Chrome browser extensions to steal financial data.(Citation: ESET Security Mispadu Facebook Ads 2019)
- [G0094] Kimsuky: [Kimsuky](https://attack.mitre.org/groups/G0094) has used Google Chrome browser extensions to infect victims and to steal passwords and cookies.(Citation: Zdnet Kimsuky Dec 2018)(Citation: Netscout Stolen Pencil Dec 2018)
- [S0402] OSX/Shlayer: [OSX/Shlayer](https://attack.mitre.org/software/S0402) can install malicious Safari browser extensions to serve ads.(Citation: Intego Shlayer Apr 2018)(Citation: Malwarebytes Crossrider Apr 2018)
- [S1213] Lumma Stealer: [Lumma Stealer](https://attack.mitre.org/software/S1213) has installed a malicious browser extension to target Google Chrome, Microsoft Edge, Opera and Brave browsers for the purpose of stealing data.(Citation: Cybereason LumaStealer Undated)
- [S1201] TRANSLATEXT: [TRANSLATEXT](https://attack.mitre.org/software/S1201) has the ability to capture credentials, cookies, browser screenshots, etc. and to exfiltrate data.(Citation: Zscaler Kimsuky TRANSLATEXT)
- [S0531] Grandoreiro: [Grandoreiro](https://attack.mitre.org/software/S0531) can use malicious browser extensions to steal cookies and other user information.(Citation: IBM Grandoreiro April 2020)
- [S0482] Bundlore: [Bundlore](https://attack.mitre.org/software/S0482) can install malicious browser extensions that are used to hijack user searches.(Citation: MacKeeper Bundlore Apr 2019)

#### T1176.002 - Software Extensions: IDE Extensions

Description:

Adversaries may abuse an integrated development environment (IDE) extension to establish persistent access to victim systems.(Citation: Mnemonic misuse visual studio) IDEs such as Visual Studio Code, IntelliJ IDEA, and Eclipse support extensions - software components that add features like code linting, auto-completion, task automation, or integration with tools like Git and Docker. A malicious extension can be installed through an extension marketplace (i.e., [Compromise Software Dependencies and Development Tools](https://attack.mitre.org/techniques/T1195/001)) or side-loaded directly into the IDE.(Citation: Abramovsky VSCode Security)(Citation: Lakshmanan Visual Studio Marketplace)   

In addition to installing malicious extensions, adversaries may also leverage benign ones. For example, adversaries may establish persistent SSH tunnels via the use of the VSCode Remote SSH extension (i.e., [IDE Tunneling](https://attack.mitre.org/techniques/T1219/001)).  

Trust is typically established through the installation process; once installed, the malicious extension is run every time that the IDE is launched. The extension can then be used to execute arbitrary code, establish a backdoor, mine cryptocurrency, or exfiltrate data.(Citation: ExtensionTotal VSCode Extensions  2025)


### T1197 - BITS Jobs

Description:

Adversaries may abuse BITS jobs to persistently execute code and perform various background tasks. Windows Background Intelligent Transfer Service (BITS) is a low-bandwidth, asynchronous file transfer mechanism exposed through [Component Object Model](https://attack.mitre.org/techniques/T1559/001) (COM).(Citation: Microsoft COM)(Citation: Microsoft BITS) BITS is commonly used by updaters, messengers, and other applications preferred to operate in the background (using available idle bandwidth) without interrupting other networked applications. File transfer tasks are implemented as BITS jobs, which contain a queue of one or more file operations.

The interface to create and manage BITS jobs is accessible through [PowerShell](https://attack.mitre.org/techniques/T1059/001) and the [BITSAdmin](https://attack.mitre.org/software/S0190) tool.(Citation: Microsoft BITS)(Citation: Microsoft BITSAdmin)

Adversaries may abuse BITS to download (e.g. [Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105)), execute, and even clean up after running malicious code (e.g. [Indicator Removal](https://attack.mitre.org/techniques/T1070)). BITS tasks are self-contained in the BITS job database, without new files or registry modifications, and often permitted by host firewalls.(Citation: CTU BITS Malware June 2016)(Citation: Mondok Windows PiggyBack BITS May 2007)(Citation: Symantec BITS May 2007) BITS enabled execution may also enable persistence by creating long-standing jobs (the default maximum lifetime is 90 days and extendable) or invoking an arbitrary program when a job completes or errors (including after system reboots).(Citation: PaloAlto UBoatRAT Nov 2017)(Citation: CTU BITS Malware June 2016)

BITS upload functionalities can also be used to perform [Exfiltration Over Alternative Protocol](https://attack.mitre.org/techniques/T1048).(Citation: CTU BITS Malware June 2016)

Procedures:

- [S0652] MarkiRAT: [MarkiRAT](https://attack.mitre.org/software/S0652) can use BITS Utility to connect with the C2 server.(Citation: Kaspersky Ferocious Kitten Jun 2021)
- [G0040] Patchwork: [Patchwork](https://attack.mitre.org/groups/G0040) has used BITS jobs to download malicious payloads.(Citation: Unit 42 BackConfig May 2020)
- [S0534] Bazar: [Bazar](https://attack.mitre.org/software/S0534) has been downloaded via Windows BITS functionality.(Citation: NCC Group Team9 June 2020)
- [S0154] Cobalt Strike: [Cobalt Strike](https://attack.mitre.org/software/S0154) can download a hosted "beacon" payload using [BITSAdmin](https://attack.mitre.org/software/S0190).(Citation: CobaltStrike Scripted Web Delivery)(Citation: Talos Cobalt Strike September 2020)(Citation: Cobalt Strike Manual 4.3 November 2020)
- [S0554] Egregor: [Egregor](https://attack.mitre.org/software/S0554) has used BITSadmin to download and execute malicious DLLs.(Citation: Intrinsec Egregor Nov 2020)
- [S0201] JPIN: A [JPIN](https://attack.mitre.org/software/S0201) variant downloads the backdoor payload via the BITS service.(Citation: Microsoft PLATINUM April 2016)
- [S0333] UBoatRAT: [UBoatRAT](https://attack.mitre.org/software/S0333) takes advantage of the /SetNotifyCmdLine option in [BITSAdmin](https://attack.mitre.org/software/S0190) to ensure it stays running on a system to maintain persistence.(Citation: PaloAlto UBoatRAT Nov 2017)
- [S0654] ProLock: [ProLock](https://attack.mitre.org/software/S0654) can use BITS jobs to download its malicious payload.(Citation: Group IB Ransomware September 2020)
- [G0065] Leviathan: [Leviathan](https://attack.mitre.org/groups/G0065) has used [BITSAdmin](https://attack.mitre.org/software/S0190) to download additional tools.(Citation: FireEye Periscope March 2018)
- [G0087] APT39: [APT39](https://attack.mitre.org/groups/G0087) has used the BITS protocol to exfiltrate stolen data from a compromised host.(Citation: FBI FLASH APT39 September 2020)
- [S0190] BITSAdmin: [BITSAdmin](https://attack.mitre.org/software/S0190) can be used to create [BITS Jobs](https://attack.mitre.org/techniques/T1197) to launch a malicious process.(Citation: TrendMicro Tropic Trooper Mar 2018)
- [G0096] APT41: [APT41](https://attack.mitre.org/groups/G0096) used [BITSAdmin](https://attack.mitre.org/software/S0190) to download and install payloads.(Citation: FireEye APT41 March 2020)(Citation: Crowdstrike GTR2020 Mar 2020)
- [G0102] Wizard Spider: [Wizard Spider](https://attack.mitre.org/groups/G0102) has used batch scripts that utilizes WMIC to execute a [BITSAdmin](https://attack.mitre.org/software/S0190) transfer of a ransomware payload to each compromised machine.(Citation: Mandiant FIN12 Oct 2021)


### T1205 - Traffic Signaling

Description:

Adversaries may use traffic signaling to hide open ports or other malicious functionality used for persistence or command and control. Traffic signaling involves the use of a magic value or sequence that must be sent to a system to trigger a special response, such as opening a closed port or executing a malicious task. This may take the form of sending a series of packets with certain characteristics before a port will be opened that the adversary can use for command and control. Usually this series of packets consists of attempted connections to a predefined sequence of closed ports (i.e. [Port Knocking](https://attack.mitre.org/techniques/T1205/001)), but can involve unusual flags, specific strings, or other unique characteristics. After the sequence is completed, opening a port may be accomplished by the host-based firewall, but could also be implemented by custom software.

Adversaries may also communicate with an already open port, but the service listening on that port will only respond to commands or trigger other malicious functionality if passed the appropriate magic value(s).

The observation of the signal packets to trigger the communication can be conducted through different methods. One means, originally implemented by Cd00r (Citation: Hartrell cd00r 2002), is to use the libpcap libraries to sniff for the packets in question. Another method leverages raw sockets, which enables the malware to use ports that are already open for use by other programs.

On network devices, adversaries may use crafted packets to enable [Network Device Authentication](https://attack.mitre.org/techniques/T1556/004) for standard services offered by the device such as telnet.  Such signaling may also be used to open a closed service port such as telnet, or to trigger module modification of malware implants on the device, adding, removing, or changing malicious capabilities.  Adversaries may use crafted packets to attempt to connect to one or more (open or closed) ports, but may also attempt to connect to a router interface, broadcast, and network address IP on the same port in order to achieve their goals and objectives.(Citation: Cisco Synful Knock Evolution)(Citation: Mandiant - Synful Knock)(Citation: Cisco Blog Legacy Device Attacks)  To enable this traffic signaling on embedded devices, adversaries must first achieve and leverage [Patch System Image](https://attack.mitre.org/techniques/T1601/001) due to the monolithic nature of the architecture.

Adversaries may also use the Wake-on-LAN feature to turn on powered off systems. Wake-on-LAN is a hardware feature that allows a powered down system to be powered on, or woken up, by sending a magic packet to it. Once the system is powered on, it may become a target for lateral movement.(Citation: Bleeping Computer - Ryuk WoL)(Citation: AMD Magic Packet)

Procedures:

- [C0029] Cutting Edge: During [Cutting Edge](https://attack.mitre.org/campaigns/C0029), threat actors sent a magic 48-byte sequence to enable the PITSOCK backdoor to communicate via the `/tmp/clientsDownload.sock` socket.(Citation: Mandiant Cutting Edge Part 3 February 2024)
- [S1114] ZIPLINE: [ZIPLINE](https://attack.mitre.org/software/S1114) can identify a specific string in intercepted network traffic, `SSH-2.0-OpenSSH_0.3xx.`, to trigger its command functionality.(Citation: Mandiant Cutting Edge January 2024)
- [S1118] BUSHWALK: [BUSHWALK](https://attack.mitre.org/software/S1118) can modify the `DSUserAgentCap.pm` Perl module on Ivanti Connect Secure VPNs and either activate or deactivate depending on the value of the user agent in incoming HTTP requests.(Citation: Mandiant Cutting Edge Part 3 February 2024)
- [S0587] Penquin: [Penquin](https://attack.mitre.org/software/S0587) will connect to C2 only after sniffing a "magic packet" value in TCP or UDP packets matching specific conditions.(Citation: Leonardo Turla Penquin May 2020)(Citation: Kaspersky Turla Penquin December 2014)
- [S0519] SYNful Knock: [SYNful Knock](https://attack.mitre.org/software/S0519) can be sent instructions via special packets to change its functionality. Code for new functionality can be included in these messages.(Citation: Mandiant - Synful Knock)
- [S0430] Winnti for Linux: [Winnti for Linux](https://attack.mitre.org/software/S0430) has used a passive listener, capable of identifying a specific magic value before executing tasking, as a secondary command and control (C2) mechanism.(Citation: Chronicle Winnti for Linux May 2019)
- [S0220] Chaos: [Chaos](https://attack.mitre.org/software/S0220) provides a reverse shell is triggered upon receipt of a packet with a special string, sent to any port.(Citation: Chaos Stolen Backdoor)
- [S0221] Umbreon: [Umbreon](https://attack.mitre.org/software/S0221) provides additional access using its backdoor Espeon, providing a reverse shell upon receipt of a special packet.(Citation: Umbreon Trend Micro)
- [S0641] Kobalos: [Kobalos](https://attack.mitre.org/software/S0641) is triggered by an incoming TCP connection to a legitimate service from a specific source port.(Citation: ESET Kobalos Feb 2021)(Citation: ESET Kobalos Jan 2021)
- [S0664] Pandora: [Pandora](https://attack.mitre.org/software/S0664) can identify if incoming HTTP traffic contains a token and if so it will intercept the traffic and process the received command.(Citation: Trend Micro Iron Tiger April 2021)
- [S0446] Ryuk: [Ryuk](https://attack.mitre.org/software/S0446) has used Wake-on-Lan to power on turned off systems for lateral movement.(Citation: Bleeping Computer - Ryuk WoL)
- [S1203] J-magic: [J-magic](https://attack.mitre.org/software/S1203) can monitor TCP traffic for packets containing one of five different predefined parameters and will spawn a reverse shell if one of the parameters and the proper response string to a subsequent challenge is received.(Citation: Lumen J-Magic JAN 2025)
- [S1201] TRANSLATEXT: [TRANSLATEXT](https://attack.mitre.org/software/S1201) has redirected clients to legitimate Gmail, Naver or Kakao pages if the clients connect with no parameters.(Citation: Zscaler Kimsuky TRANSLATEXT)
- [S0022] Uroburos: [Uroburos](https://attack.mitre.org/software/S0022) can intercept the first client to server packet in the 3-way TCP handshake to determine if the packet contains the correct unique value for a specific [Uroburos](https://attack.mitre.org/software/S0022) implant. If the value does not match, the packet and the rest of the TCP session are passed to the legitimate listening application.(Citation: Joint Cybersecurity Advisory AA23-129A Snake Malware May 2023)
- [G0094] Kimsuky: [Kimsuky](https://attack.mitre.org/groups/G0094) has used [TRANSLATEXT](https://attack.mitre.org/software/S1201) to redirect clients to legitimate Gmail, Naver or Kakao pages if the clients connect with no parameters.(Citation: Zscaler Kimsuky TRANSLATEXT)

#### T1205.001 - Traffic Signaling: Port Knocking

Description:

Adversaries may use port knocking to hide open ports used for persistence or command and control. To enable a port, an adversary sends a series of attempted connections to a predefined sequence of closed ports. After the sequence is completed, opening a port is often accomplished by the host based firewall, but could also be implemented by custom software.

This technique has been observed both for the dynamic opening of a listening port as well as the initiating of a connection to a listening server on a different system.

The observation of the signal packets to trigger the communication can be conducted through different methods. One means, originally implemented by Cd00r (Citation: Hartrell cd00r 2002), is to use the libpcap libraries to sniff for the packets in question. Another method leverages raw sockets, which enables the malware to use ports that are already open for use by other programs.

Procedures:

- [S1060] Mafalda: [Mafalda](https://attack.mitre.org/software/S1060) can use port-knocking to authenticate itself to another implant called Cryshell to establish an indirect connection to the C2 server.(Citation: SentinelLabs Metador Sept 2022)(Citation: SentinelLabs Metador Technical Appendix Sept 2022)
- [G0056] PROMETHIUM: [PROMETHIUM](https://attack.mitre.org/groups/G0056) has used a script that configures the knockd service and firewall to only accept C2 connections from systems that use a specified sequence of knock ports.(Citation: Bitdefender StrongPity June 2020)
- [S1204] cd00r: [cd00r](https://attack.mitre.org/software/S1204) can monitor for a single TCP-SYN packet to be sent in series to a configurable set of ports (200, 80, 22, 53 and 3 in the original code) before opening a port for communication.(Citation: Hartrell cd00r 2002)(Citation: Lumen J-Magic JAN 2025)
- [S1059] metaMain: [metaMain](https://attack.mitre.org/software/S1059) has authenticated itself to a different implant, Cryshell, through a port knocking and handshake procedure.(Citation: SentinelLabs Metador Sept 2022)

#### T1205.002 - Traffic Signaling: Socket Filters

Description:

Adversaries may attach filters to a network socket to monitor then activate backdoors used for persistence or command and control. With elevated permissions, adversaries can use features such as the `libpcap` library to open sockets and install filters to allow or disallow certain types of data to come through the socket. The filter may apply to all traffic passing through the specified network interface (or every interface if not specified). When the network interface receives a packet matching the filter criteria, additional actions can be triggered on the host, such as activation of a reverse shell.

To establish a connection, an adversary sends a crafted packet to the targeted host that matches the installed filter criteria.(Citation: haking9 libpcap network sniffing) Adversaries have used these socket filters to trigger the installation of implants, conduct ping backs, and to invoke command shells. Communication with these socket filters may also be used in conjunction with [Protocol Tunneling](https://attack.mitre.org/techniques/T1572).(Citation: exatrack bpf filters passive backdoors)(Citation: Leonardo Turla Penquin May 2020)

Filters can be installed on any Unix-like platform with `libpcap` installed or on Windows hosts using `Winpcap`.  Adversaries may use either `libpcap` with `pcap_setfilter` or the standard library function `setsockopt` with `SO_ATTACH_FILTER` options. Since the socket connection is not active until the packet is received, this behavior may be difficult to detect due to the lack of activity on a host, low CPU overhead, and limited visibility into raw socket usage.

Procedures:

- [S1161] BPFDoor: [BPFDoor](https://attack.mitre.org/software/S1161) uses BPF bytecode to attach a filter to a network socket to view ICMP, UDP, or TCP packets coming through ports 22 (ssh), 80 (http), and 443 (https). When [BPFDoor](https://attack.mitre.org/software/S1161)  finds a packet containing its “magic” bytes, it parses out two fields and forks itself. The parent process continues to monitor filtered traffic while the child process executes the instructions from the parsed fields.(Citation: Sandfly BPFDoor 2022)(Citation: Deep Instinct BPFDoor 2023)
- [S1123] PITSTOP: [PITSTOP](https://attack.mitre.org/software/S1123) can listen and evaluate incoming commands on the domain socket, created by PITHOOK malware, located at `/data/runtime/cockpit/wd.fd` for a predefined magic byte sequence. [PITSTOP](https://attack.mitre.org/software/S1123) can then duplicate the socket for further communication over TLS.(Citation: Mandiant Cutting Edge Part 3 February 2024)
- [S0587] Penquin: [Penquin](https://attack.mitre.org/software/S0587) installs a `TCP` and `UDP` filter on the `eth0` interface.(Citation: Leonardo Turla Penquin May 2020)


### T1505 - Server Software Component

Description:

Adversaries may abuse legitimate extensible development features of servers to establish persistent access to systems. Enterprise server applications may include features that allow developers to write and install software or scripts to extend the functionality of the main application. Adversaries may install malicious components to extend and abuse server applications.(Citation: volexity_0day_sophos_FW)

#### T1505.001 - Server Software Component: SQL Stored Procedures

Description:

Adversaries may abuse SQL stored procedures to establish persistent access to systems. SQL Stored Procedures are code that can be saved and reused so that database users do not waste time rewriting frequently used SQL queries. Stored procedures can be invoked via SQL statements to the database using the procedure name or via defined events (e.g. when a SQL server application is started/restarted).

Adversaries may craft malicious stored procedures that can provide a persistence mechanism in SQL database servers.(Citation: NetSPI Startup Stored Procedures)(Citation: Kaspersky MSSQL Aug 2019) To execute operating system commands through SQL syntax the adversary may have to enable additional functionality, such as xp_cmdshell for MSSQL Server.(Citation: NetSPI Startup Stored Procedures)(Citation: Kaspersky MSSQL Aug 2019)(Citation: Microsoft xp_cmdshell 2017) 

Microsoft SQL Server can enable common language runtime (CLR) integration. With CLR integration enabled, application developers can write stored procedures using any .NET framework language (e.g. VB .NET, C#, etc.).(Citation: Microsoft CLR Integration 2017) Adversaries may craft or modify CLR assemblies that are linked to stored procedures since these CLR assemblies can be made to execute arbitrary commands.(Citation: NetSPI SQL Server CLR)

Procedures:

- [C0025] 2016 Ukraine Electric Power Attack: During the [2016 Ukraine Electric Power Attack](https://attack.mitre.org/campaigns/C0025), [Sandworm Team](https://attack.mitre.org/groups/G0034) used various MS-SQL stored procedures.(Citation: Dragos Crashoverride 2018)
- [S0603] Stuxnet: [Stuxnet](https://attack.mitre.org/software/S0603) used xp_cmdshell to store and execute SQL code.(Citation: Nicolas Falliere, Liam O Murchu, Eric Chien February 2011)

#### T1505.002 - Server Software Component: Transport Agent

Description:

Adversaries may abuse Microsoft transport agents to establish persistent access to systems. Microsoft Exchange transport agents can operate on email messages passing through the transport pipeline to perform various tasks such as filtering spam, filtering malicious attachments, journaling, or adding a corporate signature to the end of all outgoing emails.(Citation: Microsoft TransportAgent Jun 2016)(Citation: ESET LightNeuron May 2019) Transport agents can be written by application developers and then compiled to .NET assemblies that are subsequently registered with the Exchange server. Transport agents will be invoked during a specified stage of email processing and carry out developer defined tasks. 

Adversaries may register a malicious transport agent to provide a persistence mechanism in Exchange Server that can be triggered by adversary-specified email events.(Citation: ESET LightNeuron May 2019) Though a malicious transport agent may be invoked for all emails passing through the Exchange transport pipeline, the agent can be configured to only carry out specific tasks in response to adversary defined criteria. For example, the transport agent may only carry out an action like copying in-transit attachments and saving them for later exfiltration if the recipient email address matches an entry on a list provided by the adversary.

Procedures:

- [S0395] LightNeuron: [LightNeuron](https://attack.mitre.org/software/S0395) has used a malicious Microsoft Exchange transport agent for persistence.(Citation: ESET LightNeuron May 2019)

#### T1505.003 - Server Software Component: Web Shell

Description:

Adversaries may backdoor web servers with web shells to establish persistent access to systems. A Web shell is a Web script that is placed on an openly accessible Web server to allow an adversary to access the Web server as a gateway into a network. A Web shell may provide a set of functions to execute or a command-line interface on the system that hosts the Web server.(Citation: volexity_0day_sophos_FW)

In addition to a server-side script, a Web shell may have a client interface program that is used to talk to the Web server (e.g. [China Chopper](https://attack.mitre.org/software/S0020) Web shell client).(Citation: Lee 2013)

Procedures:

- [G1012] CURIUM: [CURIUM](https://attack.mitre.org/groups/G1012) has been linked to web shells following likely server compromise as an initial access vector into victim networks.(Citation: Symantec Tortoiseshell 2019)
- [S0598] P.A.S. Webshell: [P.A.S. Webshell](https://attack.mitre.org/software/S0598) can gain remote access and execution on target web servers.(Citation: ANSSI Sandworm January 2021)
- [S0072] OwaAuth: [OwaAuth](https://attack.mitre.org/software/S0072) is a Web shell that appears to be exclusively used by [Threat Group-3390](https://attack.mitre.org/groups/G0027). It is installed as an ISAPI filter on Exchange servers and shares characteristics with the [China Chopper](https://attack.mitre.org/software/S0020) Web shell.(Citation: Dell TG-3390)
- [G0035] Dragonfly: [Dragonfly](https://attack.mitre.org/groups/G0035) has commonly created Web shells on victims' publicly accessible email and web servers, which they used to maintain access to a victim network and download additional malicious files.(Citation: US-CERT TA18-074A)
- [G0007] APT28: [APT28](https://attack.mitre.org/groups/G0007) has used a modified and obfuscated version of the reGeorg web shell to maintain persistence on a target's Outlook Web Access (OWA) server.(Citation: Cybersecurity Advisory GRU Brute Force Campaign July 2021)
- [S1115] WIREFIRE: [WIREFIRE](https://attack.mitre.org/software/S1115) is a web shell that can download files to and execute arbitrary commands from compromised Ivanti Connect Secure VPNs.(Citation: Mandiant Cutting Edge January 2024)
- [G0049] OilRig: [OilRig](https://attack.mitre.org/groups/G0049) has used web shells, often to maintain access to a victim network.(Citation: Unit42 OilRig Playbook 2023)(Citation: FireEye APT34 Webinar Dec 2017)(Citation: Crowdstrike GTR2020 Mar 2020)(Citation: Trend Micro Earth Simnavaz October 2024)
- [G1016] FIN13: [FIN13](https://attack.mitre.org/groups/G1016) has utilized obfuscated and open-source web shells such as JspSpy, reGeorg, MiniWebCmdShell, and Vonloesch Jsp File Browser 1.2 to enable remote code execution and to execute commands on compromised web server.(Citation: Sygnia Elephant Beetle Jan 2022)
- [G0135] BackdoorDiplomacy: [BackdoorDiplomacy](https://attack.mitre.org/groups/G0135) has used web shells to establish an initial foothold and for lateral movement within a victim's system.(Citation: ESET BackdoorDiplomacy Jun 2021)
- [S1118] BUSHWALK: [BUSHWALK](https://attack.mitre.org/software/S1118) is a web shell that has the ability to execute arbitrary commands or write files.(Citation: Mandiant Cutting Edge Part 2 January 2024)
- [G1030] Agrius: [Agrius](https://attack.mitre.org/groups/G1030) typically deploys a variant of the [ASPXSpy](https://attack.mitre.org/software/S0073) web shell following initial access via exploitation.(Citation: SentinelOne Agrius 2021)
- [S1110] SLIGHTPULSE: [SLIGHTPULSE](https://attack.mitre.org/software/S1110) is a web shell that can read, write, and execute files on compromised servers.(Citation: Mandiant Pulse Secure Zero-Day April 2021)
- [S1119] LIGHTWIRE: [LIGHTWIRE](https://attack.mitre.org/software/S1119) is a web shell capable of command execution and establishing persistence on compromised Ivanti Secure Connect VPNs.(Citation: Mandiant Cutting Edge Part 2 January 2024)
- [G0009] Deep Panda: [Deep Panda](https://attack.mitre.org/groups/G0009) uses Web shells on publicly accessible Web servers to access victim networks.(Citation: CrowdStrike Deep Panda Web Shells)
- [C0017] C0017: During [C0017](https://attack.mitre.org/campaigns/C0017), [APT41](https://attack.mitre.org/groups/G0096) deployed JScript web shells through the creation of malicious ViewState objects.(Citation: Mandiant APT41)
- [C0034] 2022 Ukraine Electric Power Attack: During the [2022 Ukraine Electric Power Attack](https://attack.mitre.org/campaigns/C0034), [Sandworm Team](https://attack.mitre.org/groups/G0034) deployed the Neo-REGEORG webshell on an internet-facing server.(Citation: Mandiant-Sandworm-Ukraine-2022)
- [C0041] FrostyGoop Incident: [FrostyGoop Incident](https://attack.mitre.org/campaigns/C0041) deployed a ReGeorg variant web shell to impacted systems following initial access for persistence.(Citation: Dragos FROSTYGOOP 2024)
- [C0032] C0032: During the [C0032](https://attack.mitre.org/campaigns/C0032) campaign, [TEMP.Veles](https://attack.mitre.org/groups/G0088) planted Web shells on Outlook Exchange servers.(Citation: FireEye TRITON 2019)
- [G0087] APT39: [APT39](https://attack.mitre.org/groups/G0087) has installed ANTAK and ASPXSPY web shells.(Citation: FireEye APT39 Jan 2019)
- [G0123] Volatile Cedar: [Volatile Cedar](https://attack.mitre.org/groups/G0123) can inject web shell code into a server.(Citation: CheckPoint Volatile Cedar March 2015)(Citation: ClearSky Lebanese Cedar Jan 2021)
- [G0093] GALLIUM: [GALLIUM](https://attack.mitre.org/groups/G0093) used Web shells to persist in victim environments and assist in execution and exfiltration.(Citation: Cybereason Soft Cell June 2019)(Citation: Microsoft GALLIUM December 2019)
- [C0029] Cutting Edge: During [Cutting Edge](https://attack.mitre.org/campaigns/C0029), threat actors used multiple web shells to maintain presence on compromised Connect Secure appliances such as [WIREFIRE](https://attack.mitre.org/software/S1115), [GLASSTOKEN](https://attack.mitre.org/software/S1117), [BUSHWALK](https://attack.mitre.org/software/S1118), [LIGHTWIRE](https://attack.mitre.org/software/S1119), and [FRAMESTING](https://attack.mitre.org/software/S1120).(Citation: Mandiant Cutting Edge January 2024)(Citation: Volexity Ivanti Zero-Day Exploitation January 2024)
- [S1112] STEADYPULSE: [STEADYPULSE](https://attack.mitre.org/software/S1112) is a web shell that can enable the execution of arbitrary commands on compromised web servers.(Citation: Mandiant Pulse Secure Zero-Day April 2021)
- [G0027] Threat Group-3390: [Threat Group-3390](https://attack.mitre.org/groups/G0027) has used a variety of Web shells.(Citation: Unit42 Emissary Panda May 2019)
- [C0040] APT41 DUST: [APT41 DUST](https://attack.mitre.org/campaigns/C0040) involved use of web shells such as ANTSWORD and BLUEBEAM for persistence.(Citation: Google Cloud APT41 2024)
- [S0073] ASPXSpy: [ASPXSpy](https://attack.mitre.org/software/S0073) is a Web shell. The ASPXTool version used by [Threat Group-3390](https://attack.mitre.org/groups/G0027) has been deployed to accessible servers running Internet Information Services (IIS).(Citation: Dell TG-3390)
- [G0081] Tropic Trooper: [Tropic Trooper](https://attack.mitre.org/groups/G0081) has started a web service in the target host and wait for the adversary to connect, acting as a web shell.(Citation: TrendMicro Tropic Trooper May 2020)
- [G1003] Ember Bear: [Ember Bear](https://attack.mitre.org/groups/G1003) deploys web shells following initial access for either follow-on command execution or protocol tunneling. Example web shells used by [Ember Bear](https://attack.mitre.org/groups/G1003) include P0wnyshell, reGeorg, [P.A.S. Webshell](https://attack.mitre.org/software/S0598), and custom variants of publicly-available web shell examples.(Citation: Cadet Blizzard emerges as novel threat actor)(Citation: CISA GRU29155 2024)
- [G0125] HAFNIUM: [HAFNIUM](https://attack.mitre.org/groups/G0125) has deployed multiple web shells on compromised servers including SIMPLESEESHARP, SPORTSBALL, [China Chopper](https://attack.mitre.org/software/S0020), and [ASPXSpy](https://attack.mitre.org/software/S0073).(Citation: Microsoft HAFNIUM March 2020)(Citation: Volexity Exchange Marauder March 2021)(Citation: FireEye Exchange Zero Days March 2021)(Citation: Tarrask scheduled task)(Citation: Rapid7 HAFNIUM Mar 2021)(Citation: Microsoft Silk Typhoon MAR 2025)
- [S1108] PULSECHECK: [PULSECHECK](https://attack.mitre.org/software/S1108) is a web shell that can enable command execution on compromised servers.(Citation: Mandiant Pulse Secure Zero-Day April 2021)
- [S1189] Neo-reGeorg: [Neo-reGeorg](https://attack.mitre.org/software/S1189) can be installed on compromised web servers to tunnel C2 connections.(Citation: GitHub Neo-reGeorg 2019)(Citation: Mandiant-Sandworm-Ukraine-2022)
- [G1009] Moses Staff: [Moses Staff](https://attack.mitre.org/groups/G1009) has dropped a web shell onto a compromised system.(Citation: Checkpoint MosesStaff Nov 2021)
- [G0034] Sandworm Team: [Sandworm Team](https://attack.mitre.org/groups/G0034) has used webshells including [P.A.S. Webshell](https://attack.mitre.org/software/S0598) to maintain access to victim networks.(Citation: ANSSI Sandworm January 2021)
- [S1120] FRAMESTING: [FRAMESTING](https://attack.mitre.org/software/S1120) is a web shell capable of enabling arbitrary command execution on compromised Ivanti Connect Secure VPNs.(Citation: Mandiant Cutting Edge Part 2 January 2024)
- [S1113] RAPIDPULSE: [RAPIDPULSE](https://attack.mitre.org/software/S1113) is a web shell that is capable of arbitrary file read on targeted web servers to exfiltrate items of interest on the victim device.(Citation: Mandiant Pulse Secure Update May 2021)
- [G0117] Fox Kitten: [Fox Kitten](https://attack.mitre.org/groups/G0117) has installed web shells on compromised hosts to maintain access.(Citation: CISA AA20-259A Iran-Based Actor September 2020)(Citation: ClearSky Pay2Kitten December 2020)
- [G0131] Tonto Team: [Tonto Team](https://attack.mitre.org/groups/G0131) has used a first stage web shell after compromising a vulnerable Exchange server.(Citation: ESET Exchange Mar 2021)
- [G1017] Volt Typhoon: [Volt Typhoon](https://attack.mitre.org/groups/G1017) has used webshells, including ones named AuditReport.jspx and iisstart.aspx, in compromised environments.(Citation: Secureworks BRONZE SILHOUETTE May 2023)
- [C0038] HomeLand Justice: For [HomeLand Justice](https://attack.mitre.org/campaigns/C0038), threat actors used .aspx webshells named pickers.aspx, error4.aspx, and ClientBin.aspx, to maintain persistence.(Citation: CISA Iran Albanian Attacks September 2022)(Citation: Microsoft Albanian Government Attacks September 2022)
- [S1188] Line Runner: [Line Runner](https://attack.mitre.org/software/S1188) is a persistent Lua-based web shell.(Citation: CCCS ArcaneDoor 2024)
- [G0082] APT38: [APT38](https://attack.mitre.org/groups/G0082) has used web shells for persistence or to ensure redundant access.(Citation: CISA AA20-239A BeagleBoyz August 2020)
- [C0049] Leviathan Australian Intrusions: [Leviathan](https://attack.mitre.org/groups/G0065) relied extensively on web shell use following initial access for persistence and command execution purposes in victim environments during [Leviathan Australian Intrusions](https://attack.mitre.org/campaigns/C0049).(Citation: CISA Leviathan 2024)
- [G0016] APT29: [APT29](https://attack.mitre.org/groups/G0016) has installed web shells on exploited Microsoft Exchange servers.(Citation: Cybersecurity Advisory SVR TTP May 2021)(Citation: Mandiant APT29 Eye Spy Email Nov 22)
- [C0012] Operation CuckooBees: During [Operation CuckooBees](https://attack.mitre.org/campaigns/C0012), the threat actors generated a web shell within a vulnerable Enterprise Resource Planning Web Application Server as a persistence mechanism.(Citation: Cybereason OperationCuckooBees May 2022)
- [S0578] SUPERNOVA: [SUPERNOVA](https://attack.mitre.org/software/S0578) is a Web shell.(Citation: Unit42 SUPERNOVA Dec 2020)(Citation: Guidepoint SUPERNOVA Dec 2020)(Citation: CISA Supernova Jan 2021)
- [S1163] SnappyTCP: [SnappyTCP](https://attack.mitre.org/software/S1163) is a reverse TCP shell with command and control capabilities used for persistence purposes.(Citation: PWC Sea Turtle 2023)
- [G0059] Magic Hound: [Magic Hound](https://attack.mitre.org/groups/G0059) has used multiple web shells to gain execution.(Citation: DFIR Report APT35 ProxyShell March 2022)(Citation: DFIR Phosphorus November 2021)
- [G1043] BlackByte: [BlackByte](https://attack.mitre.org/groups/G1043) has used ASPX web shells following exploitation of vulnerabilities in services such as Microsoft Exchange.(Citation: Picus BlackByte 2022)(Citation: Microsoft BlackByte 2023)
- [S0185] SEASHARPEE: [SEASHARPEE](https://attack.mitre.org/software/S0185) is a Web shell.(Citation: FireEye APT34 Webinar Dec 2017)
- [S0020] China Chopper: [China Chopper](https://attack.mitre.org/software/S0020)'s server component is a Web Shell payload.(Citation: Lee 2013)
- [S1117] GLASSTOKEN: [GLASSTOKEN](https://attack.mitre.org/software/S1117) is a web shell capable of tunneling C2 connections and code execution on compromised Ivanti Secure Connect VPNs.(Citation: Volexity Ivanti Zero-Day Exploitation January 2024)
- [G1023] APT5: [APT5](https://attack.mitre.org/groups/G1023) has installed multiple web shells on compromised servers including on Pulse Secure VPN appliances.(Citation: Mandiant Pulse Secure Zero-Day April 2021)(Citation: Mandiant Pulse Secure Update May 2021)
- [G0050] APT32: [APT32](https://attack.mitre.org/groups/G0050) has used Web shells to maintain access to victim websites.(Citation: Volexity OceanLotus Nov 2017)
- [G0065] Leviathan: [Leviathan](https://attack.mitre.org/groups/G0065) relies on web shells for an initial foothold as well as persistence into the victim's systems.(Citation: FireEye APT40 March 2019)(Citation: CISA AA21-200A APT40 July 2021)(Citation: CISA Leviathan 2024)
- [S1187] reGeorg: [reGeorg](https://attack.mitre.org/software/S1187) is a web shell that has been installed on exposed web servers for access to victim environments.(Citation: Mandiant APT29 Eye Spy Email Nov 22)(Citation: Cadet Blizzard emerges as novel threat actor)
- [G1041] Sea Turtle: [Sea Turtle](https://attack.mitre.org/groups/G1041) deployed the [SnappyTCP](https://attack.mitre.org/software/S1163) web shell during intrusion operations.(Citation: PWC Sea Turtle 2023)(Citation: Hunt Sea Turtle 2024)
- [C0014] Operation Wocao: During [Operation Wocao](https://attack.mitre.org/campaigns/C0014), threat actors used their own web shells, as well as those previously placed on target systems by other threat actors, for reconnaissance and lateral movement.(Citation: FoxIT Wocao December 2019)
- [C0039] Versa Director Zero Day Exploitation: [Versa Director Zero Day Exploitation](https://attack.mitre.org/campaigns/C0039) resulted in the deployment of the VersaMem web shell for follow-on activity.(Citation: Lumen Versa 2024)
- [G0094] Kimsuky: [Kimsuky](https://attack.mitre.org/groups/G0094) has used modified versions of open source PHP web shells to maintain access, often adding "Dinosaur" references within the code.(Citation: CISA AA20-301A Kimsuky)

#### T1505.004 - Server Software Component: IIS Components

Description:

Adversaries may install malicious components that run on Internet Information Services (IIS) web servers to establish persistence. IIS provides several mechanisms to extend the functionality of the web servers. For example, Internet Server Application Programming Interface (ISAPI) extensions and filters can be installed to examine and/or modify incoming and outgoing IIS web requests. Extensions and filters are deployed as DLL files that export three functions: <code>Get{Extension/Filter}Version</code>, <code>Http{Extension/Filter}Proc</code>, and (optionally) <code>Terminate{Extension/Filter}</code>. IIS modules may also be installed to extend IIS web servers.(Citation: Microsoft ISAPI Extension Overview 2017)(Citation: Microsoft ISAPI Filter Overview 2017)(Citation: IIS Backdoor 2011)(Citation: Trustwave IIS Module 2013)

Adversaries may install malicious ISAPI extensions and filters to observe and/or modify traffic, execute commands on compromised machines, or proxy command and control traffic. ISAPI extensions and filters may have access to all IIS web requests and responses. For example, an adversary may abuse these mechanisms to modify HTTP responses in order to distribute malicious commands/content to previously comprised hosts.(Citation: Microsoft ISAPI Filter Overview 2017)(Citation: Microsoft ISAPI Extension Overview 2017)(Citation: Microsoft ISAPI Extension All Incoming 2017)(Citation: Dell TG-3390)(Citation: Trustwave IIS Module 2013)(Citation: MMPC ISAPI Filter 2012)

Adversaries may also install malicious IIS modules to observe and/or modify traffic. IIS 7.0 introduced modules that provide the same unrestricted access to HTTP requests and responses as ISAPI extensions and filters. IIS modules can be written as a DLL that exports <code>RegisterModule</code>, or as a .NET application that interfaces with ASP.NET APIs to access IIS HTTP requests.(Citation: Microsoft IIS Modules Overview 2007)(Citation: Trustwave IIS Module 2013)(Citation: ESET IIS Malware 2021)

Procedures:

- [S0258] RGDoor: [RGDoor](https://attack.mitre.org/software/S0258) establishes persistence on webservers as an IIS module.(Citation: Unit 42 RGDoor Jan 2018)(Citation: ESET IIS Malware 2021)
- [S1022] IceApple: [IceApple](https://attack.mitre.org/software/S1022) is an IIS post-exploitation framework, consisting of 18 modules that provide several functionalities.(Citation: CrowdStrike IceApple May 2022)
- [C0022] Operation Dream Job: During [Operation Dream Job](https://attack.mitre.org/campaigns/C0022), [Lazarus Group](https://attack.mitre.org/groups/G0032) targeted Windows servers running Internet Information Systems (IIS) to install C2 components.(Citation: McAfee Lazarus Jul 2020)
- [S0072] OwaAuth: [OwaAuth](https://attack.mitre.org/software/S0072) has been loaded onto Exchange servers and disguised as an ISAPI filter (owaauth.dll). The IIS w3wp.exe process then loads the malicious DLL.(Citation: Dell TG-3390)

#### T1505.005 - Server Software Component: Terminal Services DLL

Description:

Adversaries may abuse components of Terminal Services to enable persistent access to systems. Microsoft Terminal Services, renamed to Remote Desktop Services in some Windows Server OSs as of 2022, enable remote terminal connections to hosts. Terminal Services allows servers to transmit a full, interactive, graphical user interface to clients via RDP.(Citation: Microsoft Remote Desktop Services)

[Windows Service](https://attack.mitre.org/techniques/T1543/003)s that are run as a "generic" process (ex: <code>svchost.exe</code>) load the service's DLL file, the location of which is stored in a Registry entry named <code>ServiceDll</code>.(Citation: Microsoft System Services Fundamentals) The <code>termsrv.dll</code> file, typically stored in `%SystemRoot%\System32\`, is the default <code>ServiceDll</code> value for Terminal Services in `HKLM\System\CurrentControlSet\services\TermService\Parameters\`.

Adversaries may modify and/or replace the Terminal Services DLL to enable persistent access to victimized hosts.(Citation: James TermServ DLL) Modifications to this DLL could be done to execute arbitrary payloads (while also potentially preserving normal <code>termsrv.dll</code> functionality) as well as to simply enable abusable features of Terminal Services. For example, an adversary may enable features such as concurrent [Remote Desktop Protocol](https://attack.mitre.org/techniques/T1021/001) sessions by either patching the <code>termsrv.dll</code> file or modifying the <code>ServiceDll</code> value to point to a DLL that provides increased RDP functionality.(Citation: Windows OS Hub RDP)(Citation: RDPWrap Github) On a non-server Windows OS this increased functionality may also enable an adversary to avoid Terminal Services prompts that warn/log out users of a system when a new RDP session is created.

#### T1505.006 - Server Software Component: vSphere Installation Bundles

Description:

Adversaries may abuse vSphere Installation Bundles (VIBs) to establish persistent access to ESXi hypervisors. VIBs are collections of files used for software distribution and virtual system management in VMware environments. Since ESXi uses an in-memory filesystem where changes made to most files are stored in RAM rather than in persistent storage, these modifications are lost after a reboot. However, VIBs can be used to create startup tasks, apply custom firewall rules, or deploy binaries that persist across reboots. Typically, administrators use VIBs for updates and system maintenance.

VIBs can be broken down into three components:(Citation: VMware VIBs)

* VIB payload: a `.vgz` archive containing the directories and files to be created and executed on boot when the VIBs are loaded.  
* Signature file: verifies the host acceptance level of a VIB, indicating what testing and validation has been done by VMware or its partners before publication of a VIB. By default, ESXi hosts require a minimum acceptance level of PartnerSupported for VIB installation, meaning the VIB is published by a trusted VMware partner. However, privileged users can change the default acceptance level using the `esxcli` command line interface. Additionally, VIBs are able to be installed regardless of acceptance level by using the <code> esxcli software vib install --force</code> command. 
* XML descriptor file: a configuration file containing associated VIB metadata, such as the name of the VIB and its dependencies.  

Adversaries may leverage malicious VIB packages to maintain persistent access to ESXi hypervisors, allowing system changes to be executed upon each bootup of ESXi – such as using  `esxcli` to enable firewall rules for backdoor traffic, creating listeners on hard coded ports, and executing backdoors.(Citation: Google Cloud Threat Intelligence ESXi VIBs 2022) Adversaries may also masquerade their malicious VIB files as PartnerSupported by modifying the XML descriptor file.(Citation: Google Cloud Threat Intelligence ESXi VIBs 2022)


### T1525 - Implant Internal Image

Description:

Adversaries may implant cloud or container images with malicious code to establish persistence after gaining access to an environment. Amazon Web Services (AWS) Amazon Machine Images (AMIs), Google Cloud Platform (GCP) Images, and Azure Images as well as popular container runtimes such as Docker can be implanted or backdoored. Unlike [Upload Malware](https://attack.mitre.org/techniques/T1608/001), this technique focuses on adversaries implanting an image in a registry within a victim’s environment. Depending on how the infrastructure is provisioned, this could provide persistent access if the infrastructure provisioning tool is instructed to always use the latest image.(Citation: Rhino Labs Cloud Image Backdoor Technique Sept 2019)

A tool has been developed to facilitate planting backdoors in cloud container images.(Citation: Rhino Labs Cloud Backdoor September 2019) If an adversary has access to a compromised AWS instance, and permissions to list the available container images, they may implant a backdoor such as a [Web Shell](https://attack.mitre.org/techniques/T1505/003).(Citation: Rhino Labs Cloud Image Backdoor Technique Sept 2019)


### T1542 - Pre-OS Boot

Description:

Adversaries may abuse Pre-OS Boot mechanisms as a way to establish persistence on a system. During the booting process of a computer, firmware and various startup services are loaded before the operating system. These programs control flow of execution before the operating system takes control.(Citation: Wikipedia Booting)

Adversaries may overwrite data in boot drivers or firmware such as BIOS (Basic Input/Output System) and The Unified Extensible Firmware Interface (UEFI) to persist on systems at a layer below the operating system. This can be particularly difficult to detect as malware at this level will not be detected by host software-based defenses.

#### T1542.001 - Pre-OS Boot: System Firmware

Description:

Adversaries may modify system firmware to persist on systems.The BIOS (Basic Input/Output System) and The Unified Extensible Firmware Interface (UEFI) or Extensible Firmware Interface (EFI) are examples of system firmware that operate as the software interface between the operating system and hardware of a computer.(Citation: Wikipedia BIOS)(Citation: Wikipedia UEFI)(Citation: About UEFI)

System firmware like BIOS and (U)EFI underly the functionality of a computer and may be modified by an adversary to perform or assist in malicious activity. Capabilities exist to overwrite the system firmware, which may give sophisticated adversaries a means to install malicious firmware updates as a means of persistence on a system that may be difficult to detect.

Procedures:

- [S0397] LoJax: [LoJax](https://attack.mitre.org/software/S0397) is a UEFI BIOS rootkit deployed to persist remote access software on some targeted systems.(Citation: ESET LoJax Sept 2018)
- [S0001] Trojan.Mebromi: [Trojan.Mebromi](https://attack.mitre.org/software/S0001) performs BIOS modification and can download and execute a file as well as protect itself from removal.(Citation: Ge 2011)
- [S0047] Hacking Team UEFI Rootkit: [Hacking Team UEFI Rootkit](https://attack.mitre.org/software/S0047) is a UEFI BIOS rootkit developed by the company Hacking Team to persist remote access software on some targeted systems.(Citation: TrendMicro Hacking Team UEFI)

#### T1542.002 - Pre-OS Boot: Component Firmware

Description:

Adversaries may modify component firmware to persist on systems. Some adversaries may employ sophisticated means to compromise computer components and install malicious firmware that will execute adversary code outside of the operating system and main system firmware or BIOS. This technique may be similar to [System Firmware](https://attack.mitre.org/techniques/T1542/001) but conducted upon other system components/devices that may not have the same capability or level of integrity checking.

Malicious component firmware could provide both a persistent level of access to systems despite potential typical failures to maintain access and hard disk re-images, as well as a way to evade host software-based defenses and integrity checks.

Procedures:

- [G0020] Equation: [Equation](https://attack.mitre.org/groups/G0020) is known to have the capability to overwrite the firmware on hard drives from some manufacturers.(Citation: Kaspersky Equation QA)
- [S0687] Cyclops Blink: [Cyclops Blink](https://attack.mitre.org/software/S0687) has maintained persistence by patching legitimate device firmware when it is downloaded, including that of WatchGuard devices.(Citation: NCSC Cyclops Blink February 2022)

#### T1542.003 - Pre-OS Boot: Bootkit

Description:

Adversaries may use bootkits to persist on systems. A bootkit is a malware variant that modifies the boot sectors of a hard drive, allowing malicious code to execute before a computer's operating system has loaded. Bootkits reside at a layer below the operating system and may make it difficult to perform full remediation unless an organization suspects one was used and can act accordingly.

In BIOS systems, a bootkit may modify the Master Boot Record (MBR) and/or Volume Boot Record (VBR).(Citation: Mandiant M Trends 2016) The MBR is the section of disk that is first loaded after completing hardware initialization by the BIOS. It is the location of the boot loader. An adversary who has raw access to the boot drive may overwrite this area, diverting execution during startup from the normal boot loader to adversary code.(Citation: Lau 2011)

The MBR passes control of the boot process to the VBR. Similar to the case of MBR, an adversary who has raw access to the boot drive may overwrite the VBR to divert execution during startup to adversary code.

In UEFI (Unified Extensible Firmware Interface) systems, a bootkit may instead create or modify files in the EFI system partition (ESP). The ESP is a partition on data storage used by devices containing UEFI that allows the system to boot the OS and other utilities used by the system. An adversary can use the newly created or patched files in the ESP to run malicious kernel code.(Citation: Microsoft Security)(Citation: welivesecurity)

Procedures:

- [S0484] Carberp: [Carberp](https://attack.mitre.org/software/S0484) has installed a bootkit on the system to maintain persistence.(Citation: ESET Carberp March 2012)
- [S0689] WhisperGate: [WhisperGate](https://attack.mitre.org/software/S0689) overwrites the MBR with a bootloader component that performs destructive wiping operations on hard drives and displays a fake ransom note when the host boots.(Citation: Crowdstrike WhisperGate January 2022)(Citation: Cybereason WhisperGate February 2022)(Citation: Microsoft WhisperGate January 2022)(Citation: Cisco Ukraine Wipers January 2022)(Citation: Medium S2W WhisperGate January 2022)
- [S0266] TrickBot: [TrickBot](https://attack.mitre.org/software/S0266) can implant malicious code into a compromised device's firmware.(Citation: Eclypsium Trickboot December 2020)
- [S0112] ROCKBOOT: [ROCKBOOT](https://attack.mitre.org/software/S0112) is a Master Boot Record (MBR) bootkit that uses the MBR to establish persistence.(Citation: FireEye Bootkits)
- [G0096] APT41: [APT41](https://attack.mitre.org/groups/G0096) deployed Master Boot Record bootkits on Windows systems to hide their malware and maintain persistence on victim systems.(Citation: FireEye APT41 Aug 2019)
- [S0114] BOOTRASH: [BOOTRASH](https://attack.mitre.org/software/S0114) is a Volume Boot Record (VBR) bootkit that uses the VBR to maintain persistence.(Citation: Mandiant M Trends 2016)(Citation: FireEye Bootkits)(Citation: FireEye BOOTRASH SANS)
- [S0182] FinFisher: Some [FinFisher](https://attack.mitre.org/software/S0182) variants incorporate an MBR rootkit.(Citation: FinFisher Citation)(Citation: Microsoft FinFisher March 2018)
- [G0032] Lazarus Group: [Lazarus Group](https://attack.mitre.org/groups/G0032) malware WhiskeyAlfa-Three modifies sector 0 of the Master Boot Record (MBR) to ensure that the malware will persist even if a victim machine shuts down.(Citation: Novetta Blockbuster)(Citation: Novetta Blockbuster Destructive Malware)
- [G0007] APT28: [APT28](https://attack.mitre.org/groups/G0007) has deployed a bootkit along with [Downdelph](https://attack.mitre.org/software/S0134) to ensure its persistence on the victim. The bootkit shares code with some variants of [BlackEnergy](https://attack.mitre.org/software/S0089).(Citation: ESET Sednit Part 3)

#### T1542.004 - Pre-OS Boot: ROMMONkit

Description:

Adversaries may abuse the ROM Monitor (ROMMON) by loading an unauthorized firmware with adversary code to provide persistent access and manipulate device behavior that is difficult to detect. (Citation: Cisco Synful Knock Evolution)(Citation: Cisco Blog Legacy Device Attacks)


ROMMON is a Cisco network device firmware that functions as a boot loader, boot image, or boot helper to initialize hardware and software when the platform is powered on or reset. Similar to [TFTP Boot](https://attack.mitre.org/techniques/T1542/005), an adversary may upgrade the ROMMON image locally or remotely (for example, through TFTP) with adversary code and restart the device in order to overwrite the existing ROMMON image. This provides adversaries with the means to update the ROMMON to gain persistence on a system in a way that may be difficult to detect.

#### T1542.005 - Pre-OS Boot: TFTP Boot

Description:

Adversaries may abuse netbooting to load an unauthorized network device operating system from a Trivial File Transfer Protocol (TFTP) server. TFTP boot (netbooting) is commonly used by network administrators to load configuration-controlled network device images from a centralized management server. Netbooting is one option in the boot sequence and can be used to centralize, manage, and control device images.

Adversaries may manipulate the configuration on the network device specifying use of a malicious TFTP server, which may be used in conjunction with [Modify System Image](https://attack.mitre.org/techniques/T1601) to load a modified image on device startup or reset. The unauthorized image allows adversaries to modify device configuration, add malicious capabilities to the device, and introduce backdoors to maintain control of the network device while minimizing detection through use of a standard functionality. This technique is similar to [ROMMONkit](https://attack.mitre.org/techniques/T1542/004) and may result in the network device running a modified image. (Citation: Cisco Blog Legacy Device Attacks)


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

#### T1543.001 - Create or Modify System Process: Launch Agent

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

#### T1543.002 - Create or Modify System Process: Systemd Service

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

#### T1543.003 - Create or Modify System Process: Windows Service

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

#### T1543.004 - Create or Modify System Process: Launch Daemon

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

#### T1543.005 - Create or Modify System Process: Container Service

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

#### T1546.001 - Event Triggered Execution: Change Default File Association

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

#### T1546.002 - Event Triggered Execution: Screensaver

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

#### T1546.003 - Event Triggered Execution: Windows Management Instrumentation Event Subscription

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

#### T1546.004 - Event Triggered Execution: Unix Shell Configuration Modification

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

#### T1546.005 - Event Triggered Execution: Trap

Description:

Adversaries may establish persistence by executing malicious content triggered by an interrupt signal. The <code>trap</code> command allows programs and shells to specify commands that will be executed upon receiving interrupt signals. A common situation is a script allowing for graceful termination and handling of common keyboard interrupts like <code>ctrl+c</code> and <code>ctrl+d</code>.

Adversaries can use this to register code to be executed when the shell encounters specific interrupts as a persistence mechanism. Trap commands are of the following format <code>trap 'command list' signals</code> where "command list" will be executed when "signals" are received.(Citation: Trap Manual)(Citation: Cyberciti Trap Statements)

#### T1546.006 - Event Triggered Execution: LC_LOAD_DYLIB Addition

Description:

Adversaries may establish persistence by executing malicious content triggered by the execution of tainted binaries. Mach-O binaries have a series of headers that are used to perform certain operations when a binary is loaded. The LC_LOAD_DYLIB header in a Mach-O binary tells macOS and OS X which dynamic libraries (dylibs) to load during execution time. These can be added ad-hoc to the compiled binary as long as adjustments are made to the rest of the fields and dependencies.(Citation: Writing Bad Malware for OSX) There are tools available to perform these changes.

Adversaries may modify Mach-O binary headers to load and execute malicious dylibs every time the binary is executed. Although any changes will invalidate digital signatures on binaries because the binary is being modified, this can be remediated by simply removing the LC_CODE_SIGNATURE command from the binary so that the signature isn’t checked at load time.(Citation: Malware Persistence on OS X)

#### T1546.007 - Event Triggered Execution: Netsh Helper DLL

Description:

Adversaries may establish persistence by executing malicious content triggered by Netsh Helper DLLs. Netsh.exe (also referred to as Netshell) is a command-line scripting utility used to interact with the network configuration of a system. It contains functionality to add helper DLLs for extending functionality of the utility.(Citation: TechNet Netsh) The paths to registered netsh.exe helper DLLs are entered into the Windows Registry at <code>HKLM\SOFTWARE\Microsoft\Netsh</code>.

Adversaries can use netsh.exe helper DLLs to trigger execution of arbitrary code in a persistent manner. This execution would take place anytime netsh.exe is executed, which could happen automatically, with another persistence technique, or if other software (ex: VPN) is present on the system that executes netsh.exe as part of its normal functionality.(Citation: Github Netsh Helper CS Beacon)(Citation: Demaske Netsh Persistence)

Procedures:

- [S0108] netsh: [netsh](https://attack.mitre.org/software/S0108) can be used as a persistence proxy technique to execute a helper DLL when netsh.exe is executed.(Citation: Demaske Netsh Persistence)

#### T1546.008 - Event Triggered Execution: Accessibility Features

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

#### T1546.009 - Event Triggered Execution: AppCert DLLs

Description:

Adversaries may establish persistence and/or elevate privileges by executing malicious content triggered by AppCert DLLs loaded into processes. Dynamic-link libraries (DLLs) that are specified in the <code>AppCertDLLs</code> Registry key under <code>HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\</code> are loaded into every process that calls the ubiquitously used application programming interface (API) functions <code>CreateProcess</code>, <code>CreateProcessAsUser</code>, <code>CreateProcessWithLoginW</code>, <code>CreateProcessWithTokenW</code>, or <code>WinExec</code>. (Citation: Elastic Process Injection July 2017)

Similar to [Process Injection](https://attack.mitre.org/techniques/T1055), this value can be abused to obtain elevated privileges by causing a malicious DLL to be loaded and run in the context of separate processes on the computer. Malicious AppCert DLLs may also provide persistence by continuously being triggered by API activity.

Procedures:

- [S0196] PUNCHBUGGY: [PUNCHBUGGY](https://attack.mitre.org/software/S0196) can establish using a AppCertDLLs Registry key.(Citation: FireEye Know Your Enemy FIN8 Aug 2016)

#### T1546.010 - Event Triggered Execution: AppInit DLLs

Description:

Adversaries may establish persistence and/or elevate privileges by executing malicious content triggered by AppInit DLLs loaded into processes. Dynamic-link libraries (DLLs) that are specified in the <code>AppInit_DLLs</code> value in the Registry keys <code>HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Windows</code> or <code>HKEY_LOCAL_MACHINE\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows</code> are loaded by user32.dll into every process that loads user32.dll. In practice this is nearly every program, since user32.dll is a very common library. (Citation: Elastic Process Injection July 2017)

Similar to Process Injection, these values can be abused to obtain elevated privileges by causing a malicious DLL to be loaded and run in the context of separate processes on the computer. (Citation: AppInit Registry) Malicious AppInit DLLs may also provide persistence by continuously being triggered by API activity. 

The AppInit DLL functionality is disabled in Windows 8 and later versions when secure boot is enabled. (Citation: AppInit Secure Boot)

Procedures:

- [G0087] APT39: [APT39](https://attack.mitre.org/groups/G0087) has used malware to set <code>LoadAppInit_DLLs</code> in the Registry key <code>SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows</code> in order to establish persistence.(Citation: FBI FLASH APT39 September 2020)
- [S0098] T9000: If a victim meets certain criteria, [T9000](https://attack.mitre.org/software/S0098) uses the AppInit_DLL functionality to achieve persistence by ensuring that every user mode process that is spawned will load its malicious DLL, ResN32.dll. It does this by creating the following Registry keys: <code>HKLM\Software\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs – %APPDATA%\Intel\ResN32.dll</code> and <code>HKLM\Software\Microsoft\Windows NT\CurrentVersion\Windows\LoadAppInit_DLLs – 0x1</code>.(Citation: Palo Alto T9000 Feb 2016)
- [S0107] Cherry Picker: Some variants of [Cherry Picker](https://attack.mitre.org/software/S0107) use AppInit_DLLs to achieve persistence by creating the following Registry key: <code>HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows "AppInit_DLLs"="pserver32.dll"</code>(Citation: Trustwave Cherry Picker)
- [S0458] Ramsay: [Ramsay](https://attack.mitre.org/software/S0458) can insert itself into the address space of other applications using the AppInit DLL Registry key.(Citation: Eset Ramsay May 2020)

#### T1546.011 - Event Triggered Execution: Application Shimming

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

#### T1546.012 - Event Triggered Execution: Image File Execution Options Injection

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

#### T1546.013 - Event Triggered Execution: PowerShell Profile

Description:

Adversaries may gain persistence and elevate privileges by executing malicious content triggered by PowerShell profiles. A PowerShell profile  (<code>profile.ps1</code>) is a script that runs when [PowerShell](https://attack.mitre.org/techniques/T1059/001) starts and can be used as a logon script to customize user environments.

[PowerShell](https://attack.mitre.org/techniques/T1059/001) supports several profiles depending on the user or host program. For example, there can be different profiles for [PowerShell](https://attack.mitre.org/techniques/T1059/001) host programs such as the PowerShell console, PowerShell ISE or Visual Studio Code. An administrator can also configure a profile that applies to all users and host programs on the local computer. (Citation: Microsoft About Profiles) 

Adversaries may modify these profiles to include arbitrary commands, functions, modules, and/or [PowerShell](https://attack.mitre.org/techniques/T1059/001) drives to gain persistence. Every time a user opens a [PowerShell](https://attack.mitre.org/techniques/T1059/001) session the modified script will be executed unless the <code>-NoProfile</code> flag is used when it is launched. (Citation: ESET Turla PowerShell May 2019) 

An adversary may also be able to escalate privileges if a script in a PowerShell profile is loaded and executed by an account with higher privileges, such as a domain administrator. (Citation: Wits End and Shady PowerShell Profiles)

Procedures:

- [G0010] Turla: [Turla](https://attack.mitre.org/groups/G0010) has used PowerShell profiles to maintain persistence on an infected machine.(Citation: ESET Turla PowerShell May 2019)

#### T1546.014 - Event Triggered Execution: Emond

Description:

Adversaries may gain persistence and elevate privileges by executing malicious content triggered by the Event Monitor Daemon (emond). Emond is a [Launch Daemon](https://attack.mitre.org/techniques/T1543/004) that accepts events from various services, runs them through a simple rules engine, and takes action. The emond binary at <code>/sbin/emond</code> will load any rules from the <code>/etc/emond.d/rules/</code> directory and take action once an explicitly defined event takes place.

The rule files are in the plist format and define the name, event type, and action to take. Some examples of event types include system startup and user authentication. Examples of actions are to run a system command or send an email. The emond service will not launch if there is no file present in the QueueDirectories path <code>/private/var/db/emondClients</code>, specified in the [Launch Daemon](https://attack.mitre.org/techniques/T1543/004) configuration file at<code>/System/Library/LaunchDaemons/com.apple.emond.plist</code>.(Citation: xorrior emond Jan 2018)(Citation: magnusviri emond Apr 2016)(Citation: sentinelone macos persist Jun 2019)

Adversaries may abuse this service by writing a rule to execute commands when a defined event occurs, such as system start up or user authentication.(Citation: xorrior emond Jan 2018)(Citation: magnusviri emond Apr 2016)(Citation: sentinelone macos persist Jun 2019) Adversaries may also be able to escalate privileges from administrator to root as the emond service is executed with root privileges by the [Launch Daemon](https://attack.mitre.org/techniques/T1543/004) service.

#### T1546.015 - Event Triggered Execution: Component Object Model Hijacking

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

#### T1546.016 - Event Triggered Execution: Installer Packages

Description:

Adversaries may establish persistence and elevate privileges by using an installer to trigger the execution of malicious content. Installer packages are OS specific and contain the resources an operating system needs to install applications on a system. Installer packages can include scripts that run prior to installation as well as after installation is complete. Installer scripts may inherit elevated permissions when executed. Developers often use these scripts to prepare the environment for installation, check requirements, download dependencies, and remove files after installation.(Citation: Installer Package Scripting Rich Trouton)

Using legitimate applications, adversaries have distributed applications with modified installer scripts to execute malicious content. When a user installs the application, they may be required to grant administrative permissions to allow the installation. At the end of the installation process of the legitimate application, content such as macOS `postinstall` scripts can be executed with the inherited elevated permissions. Adversaries can use these scripts to execute a malicious executable or install other malicious components (such as a [Launch Daemon](https://attack.mitre.org/techniques/T1543/004)) with the elevated permissions.(Citation: Application Bundle Manipulation Brandon Dalton)(Citation: wardle evilquest parti)(Citation: Windows AppleJeus GReAT)(Citation: Debian Manual Maintainer Scripts)

Depending on the distribution, Linux versions of package installer scripts are sometimes called maintainer scripts or post installation scripts. These scripts can include `preinst`, `postinst`, `prerm`, `postrm` scripts and run as root when executed.

For Windows, the Microsoft Installer services uses `.msi` files to manage the installing, updating, and uninstalling of applications. These installation routines may also include instructions to perform additional actions that may be abused by adversaries.(Citation: Microsoft Installation Procedures)

Procedures:

- [S0584] AppleJeus: During [AppleJeus](https://attack.mitre.org/software/S0584)'s installation process, it uses `postinstall` scripts to extract a hidden plist from the application's `/Resources` folder and execute the `plist` file as a [Launch Daemon](https://attack.mitre.org/techniques/T1543/004) with elevated permissions.(Citation: ObjectiveSee AppleJeus 2019)

#### T1546.017 - Event Triggered Execution: Udev Rules

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

#### T1547.001 - Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder

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

#### T1547.002 - Boot or Logon Autostart Execution: Authentication Package

Description:

Adversaries may abuse authentication packages to execute DLLs when the system boots. Windows authentication package DLLs are loaded by the Local Security Authority (LSA) process at system start. They provide support for multiple logon processes and multiple security protocols to the operating system.(Citation: MSDN Authentication Packages)

Adversaries can use the autostart mechanism provided by LSA authentication packages for persistence by placing a reference to a binary in the Windows Registry location <code>HKLM\SYSTEM\CurrentControlSet\Control\Lsa\</code> with the key value of <code>"Authentication Packages"=&lt;target binary&gt;</code>. The binary will then be executed by the system when the authentication packages are loaded.

Procedures:

- [S0143] Flame: [Flame](https://attack.mitre.org/software/S0143) can use Windows Authentication Packages for persistence.(Citation: Crysys Skywiper)

#### T1547.003 - Boot or Logon Autostart Execution: Time Providers

Description:

Adversaries may abuse time providers to execute DLLs when the system boots. The Windows Time service (W32Time) enables time synchronization across and within domains.(Citation: Microsoft W32Time Feb 2018) W32Time time providers are responsible for retrieving time stamps from hardware/network resources and outputting these values to other network clients.(Citation: Microsoft TimeProvider)

Time providers are implemented as dynamic-link libraries (DLLs) that are registered in the subkeys of `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\W32Time\TimeProviders\`.(Citation: Microsoft TimeProvider) The time provider manager, directed by the service control manager, loads and starts time providers listed and enabled under this key at system startup and/or whenever parameters are changed.(Citation: Microsoft TimeProvider)

Adversaries may abuse this architecture to establish persistence, specifically by creating a new arbitrarily named subkey  pointing to a malicious DLL in the `DllName` value. Administrator privileges are required for time provider registration, though execution will run in context of the Local Service account.(Citation: Github W32Time Oct 2017)

#### T1547.004 - Boot or Logon Autostart Execution: Winlogon Helper DLL

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

#### T1547.005 - Boot or Logon Autostart Execution: Security Support Provider

Description:

Adversaries may abuse security support providers (SSPs) to execute DLLs when the system boots. Windows SSP DLLs are loaded into the Local Security Authority (LSA) process at system start. Once loaded into the LSA, SSP DLLs have access to encrypted and plaintext passwords that are stored in Windows, such as any logged-on user's Domain password or smart card PINs.

The SSP configuration is stored in two Registry keys: <code>HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages</code> and <code>HKLM\SYSTEM\CurrentControlSet\Control\Lsa\OSConfig\Security Packages</code>. An adversary may modify these Registry keys to add new SSPs, which will be loaded the next time the system boots, or when the AddSecurityPackage Windows API function is called.(Citation: Graeber 2014)

Procedures:

- [S0002] Mimikatz: The [Mimikatz](https://attack.mitre.org/software/S0002) credential dumper contains an implementation of an SSP.(Citation: Deply Mimikatz)
- [S0363] Empire: [Empire](https://attack.mitre.org/software/S0363) can enumerate Security Support Providers (SSPs) as well as utilize [PowerSploit](https://attack.mitre.org/software/S0194)'s <code>Install-SSP</code> and <code>Invoke-Mimikatz</code> to install malicious SSPs and log authentication events.(Citation: Github PowerShell Empire)
- [S0194] PowerSploit: [PowerSploit](https://attack.mitre.org/software/S0194)'s <code>Install-SSP</code> Persistence module can be used to establish by installing a SSP DLL.(Citation: GitHub PowerSploit May 2012)(Citation: PowerSploit Documentation)

#### T1547.006 - Boot or Logon Autostart Execution: Kernel Modules and Extensions

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

#### T1547.007 - Boot or Logon Autostart Execution: Re-opened Applications

Description:

Adversaries may modify plist files to automatically run an application when a user logs in. When a user logs out or restarts via the macOS Graphical User Interface (GUI), a prompt is provided to the user with a checkbox to "Reopen windows when logging back in".(Citation: Re-Open windows on Mac) When selected, all applications currently open are added to a property list file named <code>com.apple.loginwindow.[UUID].plist</code> within the <code>~/Library/Preferences/ByHost</code> directory.(Citation: Methods of Mac Malware Persistence)(Citation: Wardle Persistence Chapter) Applications listed in this file are automatically reopened upon the user’s next logon.

Adversaries can establish [Persistence](https://attack.mitre.org/tactics/TA0003) by adding a malicious application path to the <code>com.apple.loginwindow.[UUID].plist</code> file to execute payloads when a user logs in.

#### T1547.008 - Boot or Logon Autostart Execution: LSASS Driver

Description:

Adversaries may modify or add LSASS drivers to obtain persistence on compromised systems. The Windows security subsystem is a set of components that manage and enforce the security policy for a computer or domain. The Local Security Authority (LSA) is the main component responsible for local security policy and user authentication. The LSA includes multiple dynamic link libraries (DLLs) associated with various other security functions, all of which run in the context of the LSA Subsystem Service (LSASS) lsass.exe process.(Citation: Microsoft Security Subsystem)

Adversaries may target LSASS drivers to obtain persistence. By either replacing or adding illegitimate drivers (e.g., [Hijack Execution Flow](https://attack.mitre.org/techniques/T1574)), an adversary can use LSA operations to continuously execute malicious payloads.

Procedures:

- [S0176] Wingbird: [Wingbird](https://attack.mitre.org/software/S0176) drops a malicious file (sspisrv.dll) alongside a copy of lsass.exe, which is used to register a service that loads sspisrv.dll as a driver. The payload of the malicious driver (located in its entry-point function) is executed when loaded by lsass.exe before the spoofed service becomes unstable and crashes.(Citation: Microsoft SIR Vol 21)(Citation: Microsoft Wingbird Nov 2017)
- [S0208] Pasam: [Pasam](https://attack.mitre.org/software/S0208) establishes by infecting the Security Accounts Manager (SAM) DLL to load a malicious DLL dropped to disk.(Citation: Symantec Pasam May 2012)

#### T1547.009 - Boot or Logon Autostart Execution: Shortcut Modification

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

#### T1547.010 - Boot or Logon Autostart Execution: Port Monitors

Description:

Adversaries may use port monitors to run an adversary supplied DLL during system boot for persistence or privilege escalation. A port monitor can be set through the <code>AddMonitor</code> API call to set a DLL to be loaded at startup.(Citation: AddMonitor) This DLL can be located in <code>C:\Windows\System32</code> and will be loaded and run by the print spooler service, `spoolsv.exe`, under SYSTEM level permissions on boot.(Citation: Bloxham) 

Alternatively, an arbitrary DLL can be loaded if permissions allow writing a fully-qualified pathname for that DLL to the `Driver` value of an existing or new arbitrarily named subkey of <code>HKLM\SYSTEM\CurrentControlSet\Control\Print\Monitors</code>. The Registry key contains entries for the following:

* Local Port
* Standard TCP/IP Port
* USB Monitor
* WSD Port

#### T1547.012 - Boot or Logon Autostart Execution: Print Processors

Description:

Adversaries may abuse print processors to run malicious DLLs during system boot for persistence and/or privilege escalation. Print processors are DLLs that are loaded by the print spooler service, `spoolsv.exe`, during boot.(Citation: Microsoft Intro Print Processors)

Adversaries may abuse the print spooler service by adding print processors that load malicious DLLs at startup. A print processor can be installed through the <code>AddPrintProcessor</code> API call with an account that has <code>SeLoadDriverPrivilege</code> enabled. Alternatively, a print processor can be registered to the print spooler service by adding the <code>HKLM\SYSTEM\\[CurrentControlSet or ControlSet001]\Control\Print\Environments\\[Windows architecture: e.g., Windows x64]\Print Processors\\[user defined]\Driver</code> Registry key that points to the DLL.

For the malicious print processor to be correctly installed, the payload must be located in the dedicated system print-processor directory, that can be found with the <code>GetPrintProcessorDirectory</code> API call, or referenced via a relative path from this directory.(Citation: Microsoft AddPrintProcessor May 2018) After the print processors are installed, the print spooler service, which starts during boot, must be restarted in order for them to run.(Citation: ESET PipeMon May 2020)

The print spooler service runs under SYSTEM level permissions, therefore print processors installed by an adversary may run under elevated privileges.

Procedures:

- [S0666] Gelsemium: [Gelsemium](https://attack.mitre.org/software/S0666) can drop itself in <code>C:\Windows\System32\spool\prtprocs\x64\winprint.dll</code> to be loaded automatically by the spoolsv Windows service.(Citation: ESET Gelsemium June 2021)
- [G1006] Earth Lusca: [Earth Lusca](https://attack.mitre.org/groups/G1006) has added the Registry key `HKLM\SYSTEM\ControlSet001\Control\Print\Environments\Windows x64\Print Processors\UDPrint” /v Driver /d “spool.dll /f` to load malware as a Print Processor.(Citation: TrendMicro EarthLusca 2022)
- [S0501] PipeMon: The [PipeMon](https://attack.mitre.org/software/S0501) installer has modified the Registry key <code>HKLM\SYSTEM\CurrentControlSet\Control\Print\Environments\Windows x64\Print Processors</code> to install [PipeMon](https://attack.mitre.org/software/S0501) as a Print Processor.(Citation: ESET PipeMon May 2020)

#### T1547.013 - Boot or Logon Autostart Execution: XDG Autostart Entries

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

#### T1547.014 - Boot or Logon Autostart Execution: Active Setup

Description:

Adversaries may achieve persistence by adding a Registry key to the Active Setup of the local machine. Active Setup is a Windows mechanism that is used to execute programs when a user logs in. The value stored in the Registry key will be executed after a user logs into the computer.(Citation: Klein Active Setup 2010) These programs will be executed under the context of the user and will have the account's associated permissions level.

Adversaries may abuse Active Setup by creating a key under <code> HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components\</code> and setting a malicious value for <code>StubPath</code>. This value will serve as the program that will be executed when a user logs into the computer.(Citation: Mandiant Glyer APT 2010)(Citation: Citizenlab Packrat 2015)(Citation: FireEye CFR Watering Hole 2012)(Citation: SECURELIST Bright Star 2015)(Citation: paloalto Tropic Trooper 2016)

Adversaries can abuse these components to execute malware, such as remote access tools, to maintain persistence through system reboots. Adversaries may also use [Masquerading](https://attack.mitre.org/techniques/T1036) to make the Registry entries look as if they are associated with legitimate programs.

Procedures:

- [S0012] PoisonIvy: [PoisonIvy](https://attack.mitre.org/software/S0012) creates a Registry key in the Active Setup pointing to a malicious executable.(Citation: Microsoft PoisonIvy 2017)(Citation: paloalto Tropic Trooper 2016)(Citation: FireEye Regsvr32 Targeting Mongolian Gov)

#### T1547.015 - Boot or Logon Autostart Execution: Login Items

Description:

Adversaries may add login items to execute upon user login to gain persistence or escalate privileges. Login items are applications, documents, folders, or server connections that are automatically launched when a user logs in.(Citation: Open Login Items Apple) Login items can be added via a shared file list or Service Management Framework.(Citation: Adding Login Items) Shared file list login items can be set using scripting languages such as [AppleScript](https://attack.mitre.org/techniques/T1059/002), whereas the Service Management Framework uses the API call <code>SMLoginItemSetEnabled</code>.

Login items installed using the Service Management Framework leverage <code>launchd</code>, are not visible in the System Preferences, and can only be removed by the application that created them.(Citation: Adding Login Items)(Citation: SMLoginItemSetEnabled Schroeder 2013) Login items created using a shared file list are visible in System Preferences, can hide the application when it launches, and are executed through LaunchServices, not launchd, to open applications, documents, or URLs without using Finder.(Citation: Launch Services Apple Developer) Users and applications use login items to configure their user environment to launch commonly used services or applications, such as email, chat, and music applications.

Adversaries can utilize [AppleScript](https://attack.mitre.org/techniques/T1059/002) and [Native API](https://attack.mitre.org/techniques/T1106) calls to create a login item to spawn malicious executables.(Citation: ELC Running at startup) Prior to version 10.5 on macOS, adversaries can add login items by using [AppleScript](https://attack.mitre.org/techniques/T1059/002) to send an Apple events to the “System Events” process, which has an AppleScript dictionary for manipulating login items.(Citation: Login Items AE) Adversaries can use a command such as <code>tell application “System Events” to make login item at end with properties /path/to/executable</code>.(Citation: Startup Items Eclectic)(Citation: hexed osx.dok analysis 2019)(Citation: Add List Remove Login Items Apple Script) This command adds the path of the malicious executable to the login item file list located in <code>~/Library/Application Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm</code>.(Citation: Startup Items Eclectic) Adversaries can also use login items to launch executables that can be used to control the victim system remotely or as a means to gain privilege escalation by prompting for user credentials.(Citation: objsee mac malware 2017)(Citation: CheckPoint Dok)(Citation: objsee netwire backdoor 2019)

Procedures:

- [S0690] Green Lambert: [Green Lambert](https://attack.mitre.org/software/S0690) can add [Login Items](https://attack.mitre.org/techniques/T1547/015) to establish persistence.(Citation: Objective See Green Lambert for OSX Oct 2021)(Citation: Glitch-Cat Green Lambert ATTCK Oct 2021)
- [S0198] NETWIRE: [NETWIRE](https://attack.mitre.org/software/S0198) can persist via startup options for Login items.(Citation: Red Canary NETWIRE January 2020)
- [S0281] Dok: [Dok](https://attack.mitre.org/software/S0281) uses AppleScript to install a login Item by sending Apple events to the <code>System Events</code> process.(Citation: hexed osx.dok analysis 2019)


### T1554 - Compromise Host Software Binary

Description:

Adversaries may modify host software binaries to establish persistent access to systems. Software binaries/executables provide a wide range of system commands or services, programs, and libraries. Common software binaries are SSH clients, FTP clients, email clients, web browsers, and many other user or server applications.

Adversaries may establish persistence though modifications to host software binaries. For example, an adversary may replace or otherwise infect a legitimate application binary (or support files) with a backdoor. Since these binaries may be routinely executed by applications or the user, the adversary can leverage this for persistent access to the host. An adversary may also modify a software binary such as an SSH client in order to persistently collect credentials during logins (i.e., [Modify Authentication Process](https://attack.mitre.org/techniques/T1556)).(Citation: Google Cloud Mandiant UNC3886 2024)

An adversary may also modify an existing binary by patching in malicious functionality (e.g., IAT Hooking/Entry point patching)(Citation: Unit42 Banking Trojans Hooking 2022) prior to the binary’s legitimate execution. For example, an adversary may modify the entry point of a binary to point to malicious code patched in by the adversary before resuming normal execution flow.(Citation: ESET FontOnLake Analysis 2021)

After modifying a binary, an adversary may attempt to [Impair Defenses](https://attack.mitre.org/techniques/T1562) by preventing it from updating (e.g., via the `yum-versionlock` command or `versionlock.list` file in Linux systems that use the yum package manager).(Citation: Google Cloud Mandiant UNC3886 2024)

Procedures:

- [S1116] WARPWIRE: [WARPWIRE](https://attack.mitre.org/software/S1116) can embed itself into a legitimate file on compromised Ivanti Connect Secure VPNs.(Citation: Mandiant Cutting Edge January 2024)
- [S0604] Industroyer: [Industroyer](https://attack.mitre.org/software/S0604) has used a Trojanized version of the Windows Notepad application for an additional backdoor persistence mechanism.(Citation: ESET Industroyer)
- [S1136] BFG Agonizer: [BFG Agonizer](https://attack.mitre.org/software/S1136) uses DLL unhooking to remove user mode inline hooks that security solutions often implement. [BFG Agonizer](https://attack.mitre.org/software/S1136) also uses IAT unhooking to remove user-mode IAT hooks that security solutions also use.(Citation: Unit42 Agrius 2023)
- [C0029] Cutting Edge: During [Cutting Edge](https://attack.mitre.org/campaigns/C0029), threat actors trojanized legitimate files in Ivanti Connect Secure appliances with malicious code.(Citation: Mandiant Cutting Edge January 2024)(Citation: Volexity Ivanti Zero-Day Exploitation January 2024)(Citation: Mandiant Cutting Edge Part 2 January 2024)
- [S1118] BUSHWALK: [BUSHWALK](https://attack.mitre.org/software/S1118) can embed into the legitimate `querymanifest.cgi` file on compromised Ivanti Connect Secure VPNs.(Citation: Mandiant Cutting Edge Part 2 January 2024)(Citation: Mandiant Cutting Edge Part 3 February 2024)
- [S0641] Kobalos: [Kobalos](https://attack.mitre.org/software/S0641) replaced the SSH client with a trojanized SSH client to steal credentials on compromised systems.(Citation: ESET Kobalos Jan 2021)
- [G1023] APT5: [APT5](https://attack.mitre.org/groups/G1023) has modified legitimate binaries and scripts for Pulse Secure VPNs including the legitimate DSUpgrade.pm file to install the ATRIUM webshell for persistence.(Citation: Mandiant Pulse Secure Zero-Day April 2021)(Citation: Mandiant Pulse Secure Update May 2021)
- [S0487] Kessel: [Kessel](https://attack.mitre.org/software/S0487) has maliciously altered the OpenSSH binary on targeted systems to create a backdoor.(Citation: ESET ForSSHe December 2018)
- [S0595] ThiefQuest: [ThiefQuest](https://attack.mitre.org/software/S0595) searches through the <code>/Users/</code> folder looking for executable files. For each executable, [ThiefQuest](https://attack.mitre.org/software/S0595) prepends a copy of itself to the beginning of the file. When the file is executed, the [ThiefQuest](https://attack.mitre.org/software/S0595) code is executed first. [ThiefQuest](https://attack.mitre.org/software/S0595) creates a hidden file, copies the original target executable to the file, then executes the new hidden file to maintain the appearance of normal behavior. (Citation: wardle evilquest partii)(Citation: reed thiefquest ransomware analysis)
- [S1121] LITTLELAMB.WOOLTEA: [LITTLELAMB.WOOLTEA](https://attack.mitre.org/software/S1121) can append malicious components to the `tmp/tmpmnt/bin/samba_upgrade.tar` archive inside the factory reset partition in attempt to persist post reset.(Citation: Mandiant Cutting Edge Part 3 February 2024)
- [S1184] BOLDMOVE: [BOLDMOVE](https://attack.mitre.org/software/S1184) contains a watchdog-like feature that monitors a particular file for modification. If modification is detected, the legitimate file is backed up and replaced with a trojanized file to allow for persistence through likely system upgrades.(Citation: Google Cloud BOLDMOVE 2023)
- [S0377] Ebury: [Ebury](https://attack.mitre.org/software/S0377) modifies the `keyutils` library to add malicious behavior to the OpenSSH client and the curl library.(Citation: ESET Ebury Feb 2014)(Citation: ESET Ebury May 2024)
- [S1119] LIGHTWIRE: [LIGHTWIRE](https://attack.mitre.org/software/S1119) can imbed itself into the legitimate `compcheckresult.cgi` component of Ivanti Connect Secure VPNs to enable command execution.(Citation: Mandiant Cutting Edge January 2024)(Citation: Mandiant Cutting Edge Part 2 January 2024)
- [S0486] Bonadan: [Bonadan](https://attack.mitre.org/software/S0486) has maliciously altered the OpenSSH binary on targeted systems to create a backdoor.(Citation: ESET ForSSHe December 2018)
- [S0658] XCSSET: [XCSSET](https://attack.mitre.org/software/S0658) uses a malicious browser application to replace the legitimate browser in order to continuously capture credentials, monitor web traffic, and download additional modules.(Citation: trendmicro xcsset xcode project 2020)
- [C0025] 2016 Ukraine Electric Power Attack: During the [2016 Ukraine Electric Power Attack](https://attack.mitre.org/campaigns/C0025), [Sandworm Team](https://attack.mitre.org/groups/G0034) used a trojanized version of Windows Notepad to add a layer of persistence for [Industroyer](https://attack.mitre.org/software/S0604).(Citation: ESET Industroyer)
- [S1120] FRAMESTING: [FRAMESTING](https://attack.mitre.org/software/S1120) can embed itself in the CAV Python package of an Ivanti Connect Secure VPN located in `/home/venv3/lib/python3.6/site-packages/cav-0.1-py3.6.egg/cav/api/resources/category.py.`(Citation: Mandiant Cutting Edge Part 2 January 2024)
- [S1104] SLOWPULSE: [SLOWPULSE](https://attack.mitre.org/software/S1104) is applied in compromised environments through modifications to legitimate Pulse Secure files.(Citation: Mandiant Pulse Secure Update May 2021)
- [S1115] WIREFIRE: [WIREFIRE](https://attack.mitre.org/software/S1115) can modify the `visits.py` component of Ivanti Connect Secure VPNs for file download and arbitrary command execution.(Citation: Mandiant Cutting Edge January 2024)(Citation: Volexity Ivanti Zero-Day Exploitation January 2024)


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

#### T1574.001 - Hijack Execution Flow: DLL

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

#### T1574.004 - Hijack Execution Flow: Dylib Hijacking

Description:

Adversaries may execute their own payloads by placing a malicious dynamic library (dylib) with an expected name in a path a victim application searches at runtime. The dynamic loader will try to find the dylibs based on the sequential order of the search paths. Paths to dylibs may be prefixed with <code>@rpath</code>, which allows developers to use relative paths to specify an array of search paths used at runtime based on the location of the executable.  Additionally, if weak linking is used, such as the <code>LC_LOAD_WEAK_DYLIB</code> function, an application will still execute even if an expected dylib is not present. Weak linking enables developers to run an application on multiple macOS versions as new APIs are added.

Adversaries may gain execution by inserting malicious dylibs with the name of the missing dylib in the identified path.(Citation: Wardle Dylib Hijack Vulnerable Apps)(Citation: Wardle Dylib Hijacking OSX 2015)(Citation: Github EmpireProject HijackScanner)(Citation: Github EmpireProject CreateHijacker Dylib) Dylibs are loaded into an application's address space allowing the malicious dylib to inherit the application's privilege level and resources. Based on the application, this could result in privilege escalation and uninhibited network access. This method may also evade detection from security products since the execution is masked under a legitimate process.(Citation: Writing Bad Malware for OSX)(Citation: wardle artofmalware volume1)(Citation: MalwareUnicorn macOS Dylib Injection MachO)

Procedures:

- [S0363] Empire: [Empire](https://attack.mitre.org/software/S0363) has a dylib hijacker module that generates a malicious dylib given the path to a legitimate dylib of a vulnerable application.(Citation: Github PowerShell Empire)

#### T1574.005 - Hijack Execution Flow: Executable Installer File Permissions Weakness

Description:

Adversaries may execute their own malicious payloads by hijacking the binaries used by an installer. These processes may automatically execute specific binaries as part of their functionality or to perform other actions. If the permissions on the file system directory containing a target binary, or permissions on the binary itself, are improperly set, then the target binary may be overwritten with another binary using user-level permissions and executed by the original process. If the original process and thread are running under a higher permissions level, then the replaced binary will also execute under higher-level permissions, which could include SYSTEM.

Another variation of this technique can be performed by taking advantage of a weakness that is common in executable, self-extracting installers. During the installation process, it is common for installers to use a subdirectory within the <code>%TEMP%</code> directory to unpack binaries such as DLLs, EXEs, or other payloads. When installers create subdirectories and files they often do not set appropriate permissions to restrict write access, which allows for execution of untrusted code placed in the subdirectories or overwriting of binaries used in the installation process. This behavior is related to and may take advantage of [DLL](https://attack.mitre.org/techniques/T1574/001) search order hijacking.

Adversaries may use this technique to replace legitimate binaries with malicious ones as a means of executing code at a higher permissions level. Some installers may also require elevated privileges that will result in privilege escalation when executing adversary controlled code. This behavior is related to [Bypass User Account Control](https://attack.mitre.org/techniques/T1548/002). Several examples of this weakness in existing common installers have been reported to software vendors.(Citation: mozilla_sec_adv_2012)  (Citation: Executable Installers are Vulnerable) If the executing process is set to run at a specific time or during a certain event (e.g., system bootup) then this technique can also be used for persistence.

#### T1574.006 - Hijack Execution Flow: Dynamic Linker Hijacking

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

#### T1574.007 - Hijack Execution Flow: Path Interception by PATH Environment Variable

Description:

Adversaries may execute their own malicious payloads by hijacking environment variables used to load libraries. The PATH environment variable contains a list of directories (User and System) that the OS searches sequentially through in search of the binary that was called from a script or the command line. 

Adversaries can place a malicious program in an earlier entry in the list of directories stored in the PATH environment variable, resulting in the operating system executing the malicious binary rather than the legitimate binary when it searches sequentially through that PATH listing.

For example, on Windows if an adversary places a malicious program named "net.exe" in `C:\example path`, which by default precedes `C:\Windows\system32\net.exe` in the PATH environment variable, when "net" is executed from the command-line the `C:\example path` will be called instead of the system's legitimate executable at `C:\Windows\system32\net.exe`. Some methods of executing a program rely on the PATH environment variable to determine the locations that are searched when the path for the program is not given, such as executing programs from a [Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059).(Citation: ExpressVPN PATH env Windows 2021)

Adversaries may also directly modify the $PATH variable specifying the directories to be searched.  An adversary can modify the `$PATH` variable to point to a directory they have write access. When a program using the $PATH variable is called, the OS searches the specified directory and executes the malicious binary. On macOS, this can also be performed through modifying the $HOME variable. These variables can be modified using the command-line, launchctl, [Unix Shell Configuration Modification](https://attack.mitre.org/techniques/T1546/004), or modifying the `/etc/paths.d` folder contents.(Citation: uptycs Fake POC linux malware 2023)(Citation: nixCraft macOS PATH variables)(Citation: Elastic Rules macOS launchctl 2022)

Procedures:

- [S0194] PowerSploit: [PowerSploit](https://attack.mitre.org/software/S0194) contains a collection of Privesc-PowerUp modules that can discover and exploit path interception opportunities in the PATH environment variable.(Citation: GitHub PowerSploit May 2012)(Citation: PowerSploit Documentation)
- [S0363] Empire: [Empire](https://attack.mitre.org/software/S0363) contains modules that can discover and exploit path interception opportunities in the PATH environment variable.(Citation: Github PowerShell Empire)
- [S1111] DarkGate: [DarkGate](https://attack.mitre.org/software/S1111) overrides the <code>%windir%</code> environment variable by setting a Registry key, <code>HKEY_CURRENT_User\Environment\windir</code>, to an alternate command to execute a malicious AutoIt script. This allows [DarkGate](https://attack.mitre.org/software/S1111) to run every time the scheduled task <code>DiskCleanup</code> is executed as this uses the path value <code>%windir%\system32\cleanmgr.exe</code> for execution.(Citation: Ensilo Darkgate 2018)

#### T1574.008 - Hijack Execution Flow: Path Interception by Search Order Hijacking

Description:

Adversaries may execute their own malicious payloads by hijacking the search order used to load other programs. Because some programs do not call other programs using the full path, adversaries may place their own file in the directory where the calling program is located, causing the operating system to launch their malicious software at the request of the calling program.

Search order hijacking occurs when an adversary abuses the order in which Windows searches for programs that are not given a path. Unlike [DLL](https://attack.mitre.org/techniques/T1574/001) search order hijacking, the search order differs depending on the method that is used to execute the program. (Citation: Microsoft CreateProcess) (Citation: Windows NT Command Shell) (Citation: Microsoft WinExec) However, it is common for Windows to search in the directory of the initiating program before searching through the Windows system directory. An adversary who finds a program vulnerable to search order hijacking (i.e., a program that does not specify the path to an executable) may take advantage of this vulnerability by creating a program named after the improperly specified program and placing it within the initiating program's directory.

For example, "example.exe" runs "cmd.exe" with the command-line argument <code>net user</code>. An adversary may place a program called "net.exe" within the same directory as example.exe, "net.exe" will be run instead of the Windows system utility net. In addition, if an adversary places a program called "net.com" in the same directory as "net.exe", then <code>cmd.exe /C net user</code> will execute "net.com" instead of "net.exe" due to the order of executable extensions defined under PATHEXT. (Citation: Microsoft Environment Property)

Search order hijacking is also a common practice for hijacking DLL loads and is covered in [DLL](https://attack.mitre.org/techniques/T1574/001).

Procedures:

- [S0363] Empire: [Empire](https://attack.mitre.org/software/S0363) contains modules that can discover and exploit search order hijacking vulnerabilities.(Citation: Github PowerShell Empire)
- [S0194] PowerSploit: [PowerSploit](https://attack.mitre.org/software/S0194) contains a collection of Privesc-PowerUp modules that can discover and exploit search order hijacking vulnerabilities.(Citation: GitHub PowerSploit May 2012)(Citation: PowerSploit Documentation)

#### T1574.009 - Hijack Execution Flow: Path Interception by Unquoted Path

Description:

Adversaries may execute their own malicious payloads by hijacking vulnerable file path references. Adversaries can take advantage of paths that lack surrounding quotations by placing an executable in a higher level directory within the path, so that Windows will choose the adversary's executable to launch.

Service paths (Citation: Microsoft CurrentControlSet Services) and shortcut paths may also be vulnerable to path interception if the path has one or more spaces and is not surrounded by quotation marks (e.g., <code>C:\unsafe path with space\program.exe</code> vs. <code>"C:\safe path with space\program.exe"</code>). (Citation: Help eliminate unquoted path) (stored in Windows Registry keys) An adversary can place an executable in a higher level directory of the path, and Windows will resolve that executable instead of the intended executable. For example, if the path in a shortcut is <code>C:\program files\myapp.exe</code>, an adversary may create a program at <code>C:\program.exe</code> that will be run instead of the intended program. (Citation: Windows Unquoted Services) (Citation: Windows Privilege Escalation Guide)

This technique can be used for persistence if executables are called on a regular basis, as well as privilege escalation if intercepted executables are started by a higher privileged process.

Procedures:

- [S0194] PowerSploit: [PowerSploit](https://attack.mitre.org/software/S0194) contains a collection of Privesc-PowerUp modules that can discover and exploit unquoted path vulnerabilities.(Citation: GitHub PowerSploit May 2012)(Citation: PowerSploit Documentation)
- [S0363] Empire: [Empire](https://attack.mitre.org/software/S0363) contains modules that can discover and exploit unquoted path vulnerabilities.(Citation: Github PowerShell Empire)

#### T1574.010 - Hijack Execution Flow: Services File Permissions Weakness

Description:

Adversaries may execute their own malicious payloads by hijacking the binaries used by services. Adversaries may use flaws in the permissions of Windows services to replace the binary that is executed upon service start. These service processes may automatically execute specific binaries as part of their functionality or to perform other actions. If the permissions on the file system directory containing a target binary, or permissions on the binary itself are improperly set, then the target binary may be overwritten with another binary using user-level permissions and executed by the original process. If the original process and thread are running under a higher permissions level, then the replaced binary will also execute under higher-level permissions, which could include SYSTEM.

Adversaries may use this technique to replace legitimate binaries with malicious ones as a means of executing code at a higher permissions level. If the executing process is set to run at a specific time or during a certain event (e.g., system bootup) then this technique can also be used for persistence.

Procedures:

- [S0089] BlackEnergy: One variant of [BlackEnergy](https://attack.mitre.org/software/S0089) locates existing driver services that have been disabled and drops its driver component into one of those service's paths, replacing the legitimate executable. The malware then sets the hijacked service to start automatically to establish persistence.(Citation: F-Secure BlackEnergy 2014)

#### T1574.011 - Hijack Execution Flow: Services Registry Permissions Weakness

Description:

Adversaries may execute their own malicious payloads by hijacking the Registry entries used by services. Adversaries may use flaws in the permissions for Registry keys related to services to redirect from the originally specified executable to one that they control, in order to launch their own code when a service starts. Windows stores local service configuration information in the Registry under <code>HKLM\SYSTEM\CurrentControlSet\Services</code>. The information stored under a service's Registry keys can be manipulated to modify a service's execution parameters through tools such as the service controller, sc.exe,  [PowerShell](https://attack.mitre.org/techniques/T1059/001), or [Reg](https://attack.mitre.org/software/S0075). Access to Registry keys is controlled through access control lists and user permissions. (Citation: Registry Key Security)(Citation: malware_hides_service)

If the permissions for users and groups are not properly set and allow access to the Registry keys for a service, adversaries may change the service's binPath/ImagePath to point to a different executable under their control. When the service starts or is restarted, then the adversary-controlled program will execute, allowing the adversary to establish persistence and/or privilege escalation to the account context the service is set to execute under (local/domain account, SYSTEM, LocalService, or NetworkService).

Adversaries may also alter other Registry keys in the service’s Registry tree. For example, the <code>FailureCommand</code> key may be changed so that the service is executed in an elevated context anytime the service fails or is intentionally corrupted.(Citation: Kansa Service related collectors)(Citation: Tweet Registry Perms Weakness)

The <code>Performance</code> key contains the name of a driver service's performance DLL and the names of several exported functions in the DLL.(Citation: microsoft_services_registry_tree) If the <code>Performance</code> key is not already present and if an adversary-controlled user has the <code>Create Subkey</code> permission, adversaries may create the <code>Performance</code> key in the service’s Registry tree to point to a malicious DLL.(Citation: insecure_reg_perms)

Adversaries may also add the <code>Parameters</code> key, which stores driver-specific data, or other custom subkeys for their malicious services to establish persistence or enable other malicious activities.(Citation: microsoft_services_registry_tree)(Citation: troj_zegost) Additionally, If adversaries launch their malicious services using svchost.exe, the service’s file may be identified using <code>HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\servicename\Parameters\ServiceDll</code>.(Citation: malware_hides_service)

Procedures:

- [C0006] Operation Honeybee: During [Operation Honeybee](https://attack.mitre.org/campaigns/C0006), the threat actors used a batch file that modified the COMSysApp service to load a malicious ipnet.dll payload and to load a DLL into the `svchost.exe` process.(Citation: McAfee Honeybee)

#### T1574.012 - Hijack Execution Flow: COR_PROFILER

Description:

Adversaries may leverage the COR_PROFILER environment variable to hijack the execution flow of programs that load the .NET CLR. The COR_PROFILER is a .NET Framework feature which allows developers to specify an unmanaged (or external of .NET) profiling DLL to be loaded into each .NET process that loads the Common Language Runtime (CLR). These profilers are designed to monitor, troubleshoot, and debug managed code executed by the .NET CLR.(Citation: Microsoft Profiling Mar 2017)(Citation: Microsoft COR_PROFILER Feb 2013)

The COR_PROFILER environment variable can be set at various scopes (system, user, or process) resulting in different levels of influence. System and user-wide environment variable scopes are specified in the Registry, where a [Component Object Model](https://attack.mitre.org/techniques/T1559/001) (COM) object can be registered as a profiler DLL. A process scope COR_PROFILER can also be created in-memory without modifying the Registry. Starting with .NET Framework 4, the profiling DLL does not need to be registered as long as the location of the DLL is specified in the COR_PROFILER_PATH environment variable.(Citation: Microsoft COR_PROFILER Feb 2013)

Adversaries may abuse COR_PROFILER to establish persistence that executes a malicious DLL in the context of all .NET processes every time the CLR is invoked. The COR_PROFILER can also be used to elevate privileges (ex: [Bypass User Account Control](https://attack.mitre.org/techniques/T1548/002)) if the victim .NET process executes at a higher permission level, as well as to hook and [Impair Defenses](https://attack.mitre.org/techniques/T1562) provided by .NET processes.(Citation: RedCanary Mockingbird May 2020)(Citation: Red Canary COR_PROFILER May 2020)(Citation: Almond COR_PROFILER Apr 2019)(Citation: GitHub OmerYa Invisi-Shell)(Citation: subTee .NET Profilers May 2017)

Procedures:

- [G0108] Blue Mockingbird: [Blue Mockingbird](https://attack.mitre.org/groups/G0108) has used wmic.exe and Windows Registry modifications to set the COR_PROFILER environment variable to execute a malicious DLL whenever a process loads the .NET CLR.(Citation: RedCanary Mockingbird May 2020)
- [S1066] DarkTortilla: [DarkTortilla](https://attack.mitre.org/software/S1066) can detect profilers by verifying the `COR_ENABLE_PROFILING` environment variable is present and active.(Citation: Secureworks DarkTortilla Aug 2022)

#### T1574.013 - Hijack Execution Flow: KernelCallbackTable

Description:

Adversaries may abuse the <code>KernelCallbackTable</code> of a process to hijack its execution flow in order to run their own payloads.(Citation: Lazarus APT January 2022)(Citation: FinFisher exposed ) The <code>KernelCallbackTable</code> can be found in the Process Environment Block (PEB) and is initialized to an array of graphic functions available to a GUI process once <code>user32.dll</code> is loaded.(Citation: Windows Process Injection KernelCallbackTable)

An adversary may hijack the execution flow of a process using the <code>KernelCallbackTable</code> by replacing an original callback function with a malicious payload. Modifying callback functions can be achieved in various ways involving related behaviors such as [Reflective Code Loading](https://attack.mitre.org/techniques/T1620) or [Process Injection](https://attack.mitre.org/techniques/T1055) into another process.

A pointer to the memory address of the <code>KernelCallbackTable</code> can be obtained by locating the PEB (ex: via a call to the <code>NtQueryInformationProcess()</code> [Native API](https://attack.mitre.org/techniques/T1106) function).(Citation: NtQueryInformationProcess) Once the pointer is located, the <code>KernelCallbackTable</code> can be duplicated, and a function in the table (e.g., <code>fnCOPYDATA</code>) set to the address of a malicious payload (ex: via <code>WriteProcessMemory()</code>). The PEB is then updated with the new address of the table. Once the tampered function is invoked, the malicious payload will be triggered.(Citation: Lazarus APT January 2022)

The tampered function is typically invoked using a Windows message. After the process is hijacked and malicious code is executed, the <code>KernelCallbackTable</code> may also be restored to its original state by the rest of the malicious payload.(Citation: Lazarus APT January 2022) Use of the <code>KernelCallbackTable</code> to hijack execution flow may evade detection from security products since the execution can be masked under a legitimate process.

Procedures:

- [G0032] Lazarus Group: [Lazarus Group](https://attack.mitre.org/groups/G0032) has abused the <code>KernelCallbackTable</code> to hijack process control flow and execute shellcode.(Citation: Lazarus APT January 2022)(Citation: Qualys LolZarus)
- [S0182] FinFisher: [FinFisher](https://attack.mitre.org/software/S0182) has used the <code>KernelCallbackTable</code> to hijack the execution flow of a process by replacing the <code>__fnDWORD</code> function with the address of a created [Asynchronous Procedure Call](https://attack.mitre.org/techniques/T1055/004) stub routine.(Citation: FinFisher exposed )

#### T1574.014 - Hijack Execution Flow: AppDomainManager

Description:

Adversaries may execute their own malicious payloads by hijacking how the .NET `AppDomainManager` loads assemblies. The .NET framework uses the `AppDomainManager` class to create and manage one or more isolated runtime environments (called application domains) inside a process to host the execution of .NET applications. Assemblies (`.exe` or `.dll` binaries compiled to run as .NET code) may be loaded into an application domain as executable code.(Citation: Microsoft App Domains) 

Known as "AppDomainManager injection," adversaries may execute arbitrary code by hijacking how .NET applications load assemblies. For example, malware may create a custom application domain inside a target process to load and execute an arbitrary assembly. Alternatively, configuration files (`.config`) or process environment variables that define .NET runtime settings may be tampered with to instruct otherwise benign .NET applications to load a malicious assembly (identified by name) into the target process.(Citation: PenTestLabs AppDomainManagerInject)(Citation: PwC Yellow Liderc)(Citation: Rapid7 AppDomain Manager Injection)

Procedures:

- [S1152] IMAPLoader: [IMAPLoader](https://attack.mitre.org/software/S1152) is executed via the AppDomainManager injection technique.(Citation: PWC Yellow Liderc 2023)


### T1653 - Power Settings

Description:

Adversaries may impair a system's ability to hibernate, reboot, or shut down in order to extend access to infected machines. When a computer enters a dormant state, some or all software and hardware may cease to operate which can disrupt malicious activity.(Citation: Sleep, shut down, hibernate)

Adversaries may abuse system utilities and configuration settings to maintain access by preventing machines from entering a state, such as standby, that can terminate malicious activity.(Citation: Microsoft: Powercfg command-line options)(Citation: systemdsleep Linux)

For example, `powercfg` controls all configurable power system settings on a Windows system and can be abused to prevent an infected host from locking or shutting down.(Citation: Two New Monero Malware Attacks Target Windows and Android Users) Adversaries may also extend system lock screen timeout settings.(Citation: BATLOADER: The Evasive Downloader Malware) Other relevant settings, such as disk and hibernate timeout, can be similarly abused to keep the infected machine running even if no user is active.(Citation: CoinLoader: A Sophisticated Malware Loader Campaign)

Aware that some malware cannot survive system reboots, adversaries may entirely delete files used to invoke system shut down or reboot.(Citation: Condi-Botnet-binaries)

Procedures:

- [C0046] ArcaneDoor: [ArcaneDoor](https://attack.mitre.org/campaigns/C0046) involved exploitation of CVE-2024-20353 to force a victim Cisco ASA to reboot, triggering the automated unzipping and execution of the [Line Runner](https://attack.mitre.org/software/S1188) implant.(Citation: Cisco ArcaneDoor 2024)
- [S1188] Line Runner: [Line Runner](https://attack.mitre.org/software/S1188) used CVE-2024-20353 to trigger victim devices to reboot, in the process unzipping and installing the [Line Dancer](https://attack.mitre.org/software/S1186) payload.(Citation: Cisco ArcaneDoor 2024)
- [S1186] Line Dancer: [Line Dancer](https://attack.mitre.org/software/S1186) can modify the crash dump process on infected machines to skip crash dump generation and proceed directly to device reboot for both persistence and forensic evasion purposes.(Citation: Cisco ArcaneDoor 2024)


### T1668 - Exclusive Control

Description:

Adversaries who successfully compromise a system may attempt to maintain persistence by “closing the door” behind them  – in other words, by preventing other threat actors from initially accessing or maintaining a foothold on the same system. 

For example, adversaries may patch a vulnerable, compromised system(Citation: Mandiant-iab-control)(Citation: CERT AT Fortinent Ransomware 2025) to prevent other threat actors from leveraging that vulnerability in the future. They may “close the door” in other ways, such as disabling vulnerable services(Citation: sophos-multiple-attackers), stripping privileges from accounts(Citation: aquasec-postgres-processes), or removing other malware already on the compromised device.(Citation: fsecure-netsky)

Hindering other threat actors may allow an adversary to maintain sole access to a compromised system or network. This prevents the threat actor from needing to compete with or even being removed themselves by other threat actors. It also reduces the “noise” in the environment, lowering the possibility of being caught and evicted by defenders. Finally, in the case of [Resource Hijacking](https://attack.mitre.org/techniques/T1496), leveraging a compromised device’s full power allows the threat actor to maximize profit.(Citation: sophos-multiple-attackers)


### T1671 - Cloud Application Integration

Description:

Adversaries may achieve persistence by leveraging OAuth application integrations in a software-as-a-service environment. Adversaries may create a custom application, add a legitimate application into the environment, or even co-opt an existing integration to achieve malicious ends.(Citation: Push Security SaaS Persistence 2022)(Citation: SaaS Attacks GitHub Evil Twin Integrations)

OAuth is an open standard that allows users to authorize applications to access their information on their behalf. In a SaaS environment such as Microsoft 365 or Google Workspace, users may integrate applications to improve their workflow and achieve tasks.  

Leveraging application integrations may allow adversaries to persist in an environment – for example, by granting consent to an application from a high-privileged adversary-controlled account in order to maintain access to its data, even in the event of losing access to the account.(Citation: Wiz Midnight Blizzard 2024)(Citation: Microsoft Malicious OAuth Applications 2022)(Citation: Huntress Persistence Microsoft 365 Compromise 2024) In some cases, integrations may remain valid even after the original consenting user account is disabled.(Citation: Push Security Slack Persistence 2023) Application integrations may also allow adversaries to bypass multi-factor authentication requirements through the use of [Application Access Token](https://attack.mitre.org/techniques/T1550/001)s. Finally, they may enable persistent [Automated Exfiltration](https://attack.mitre.org/techniques/T1020) over time.(Citation: Synes Cyber Corner Malicious Azure Application 2023)

Creating or adding a new application may require the adversary to create a dedicated [Cloud Account](https://attack.mitre.org/techniques/T1136/003) for the application and assign it [Additional Cloud Roles](https://attack.mitre.org/techniques/T1098/003) – for example, in Microsoft 365 environments, an application can only access resources via an associated service principal.(Citation: Microsoft Entra ID Service Principals)

