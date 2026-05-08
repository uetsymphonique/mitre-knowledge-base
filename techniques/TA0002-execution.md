### T1047 - Windows Management Instrumentation
Adversaries may abuse Windows Management Instrumentation (WMI) to execute malicious commands and payloads. WMI is designed for programmers and is the infrastructure for management data and operations on Windows systems. WMI is an administration feature that provides a uniform environment to access Windows system components. The WMI service enables both local and remote access, though the latter is facilitated by Remote Services such as Distributed Component Object Model and Windows Remote Management. Remote WMI over DCOM operates using port 135, whereas WMI over WinRM operates over port 5985 when using HTTP and 5986 for HTTPS. An adversary can use WMI to interact with local and remote systems and use it as a means to execute various behaviors, such as gathering information for Discovery as well as Execution of commands and payloads. For example, `wmic.exe` can be abused by an adversary to delete shadow copies with the command `wmic.exe Shadowcopy Delete` (i.e., Inhibit System Recovery). **Note:** `wmic.exe` is deprecated as of January of 2024, with the WMIC feature being “disabled by default” on Windows 11+. WMIC will be removed from subsequent Windows releases and replaced by PowerShell as the primary WMI interface. In addition to PowerShell and tools like `wbemtool.exe`, COM APIs can also be used to programmatically interact with WMI via C++, .NET, VBScript, etc.
**Detection**
- [AN1031] **[Windows]** Detects adversarial abuse of WMI to execute local or remote commands via WMIC, PowerShell, or COM API through a multi-event chain: process creation, command execution, and corresponding network connection if remote.
  - **Log sources:** `WinEventLog:Sysmon` (EventCode=1) [Process Creation], `WinEventLog:Sysmon` (EventCode=3, 22) [Network Connection Creation], `WinEventLog:WMI` (EventCode=5857, 5858, 5860, 5861) [WMI Creation]
**Procedure Examples**
- [S1085] Sardonic: Sardonic can use WMI to execute PowerShell commands on a compromised machine.
- [S0688] Meteor: Meteor can use `wmic.exe` as part of its effort to delete shadow copies.
- [G1021] Cinnamon Tempest: Cinnamon Tempest has used Impacket for lateral movement via WMI.
- [S0270] RogueRobin: RogueRobin uses various WMI queries to check if the sample is running in a sandbox.
- [G1051] Medusa Group: Medusa Group has utilized Windows Management Instrumentation to query system information.
- [G0045] menuPass: menuPass has used a modified version of pentesting script wmiexec.vbs, which logs into a remote machine using WMI.
- [S0559] SUNBURST: SUNBURST used the WMI query Select * From Win32_SystemDriver to retrieve a driver listing.
- [C0015] C0015: During C0015, the threat actors used `wmic` and `rundll32` to load Cobalt Strike onto a target host.
- [G1032] INC Ransom: INC Ransom has used WMIC to deploy ransomware.
- [S0089] BlackEnergy: A BlackEnergy 2 plug-in uses WMI to gather victim host details.


### T1053 - Scheduled Task/Job
Adversaries may abuse task scheduling functionality to facilitate initial or recurring execution of malicious code. Utilities exist within all major operating systems to schedule programs or scripts to be executed at a specified date and time. A task can also be scheduled on a remote system, provided the proper authentication is met (ex: RPC and file and printer sharing in Windows environments). Scheduling a task on a remote system typically may require being a member of an admin or otherwise privileged group on the remote system. Adversaries may use task scheduling to execute programs at system startup or on a scheduled basis for persistence. These mechanisms can also be abused to run a process under the context of a specified account (such as one with elevated permissions/privileges). Similar to System Binary Proxy Execution, adversaries have also abused task scheduling to potentially mask one-time execution under a trusted system process.
**Detection**
- [AN0259] **[Linux]** Detects creation or modification of cron jobs via crontab, /etc/cron.* directories, or systemd timer units with execution by unusual users or non-standard intervals.
  - **Log sources:** `auditd:SYSCALL` (write, rename) [File Modification], `auditd:SYSCALL` (execve) [Process Creation], `linux:osquery` (crontab, systemd_timers) [Scheduled Job Creation]
- [AN0260] **[macOS]** Detects creation or alteration of LaunchAgents or LaunchDaemons with corresponding plist modification followed by execution of associated binaries.
  - **Log sources:** `macos:unifiedlog` (process launch) [Process Creation], `fs:fsusage` (disk activity on /Library/LaunchAgents or LaunchDaemons) [File Creation], `macos:osquery` (launchd_jobs) [Scheduled Job Creation]
- [AN0258] **[Windows]** Detects creation or modification of scheduled tasks using schtasks.exe, at.exe, or COM objects followed by execution of outlier processes tied to the scheduled job.
  - **Log sources:** `WinEventLog:Security` (EventCode=4698) [Scheduled Job Creation], `WinEventLog:Sysmon` (EventCode=1) [Process Creation], `WinEventLog:Sysmon` (EventCode=2) [File Modification]
- [AN0261] **[Containers]** Detects unusual use of `cron` or `sleep` loops inside containers executing unfamiliar scripts or binaries repeatedly.
  - **Log sources:** `auditd:SYSCALL` (execve) [Process Creation], `containerd:runtime` (file change monitoring within /etc/cron.*, /tmp, or mounted volumes) [File Modification]
- [AN0262] **[ESXi]** Detects modification of ESXi cron jobs, local.sh scripts, or scheduled API calls to persist custom binaries or shell scripts.
  - **Log sources:** `esxi:vmkernel` (Startup script and task execution logs) [Scheduled Job Creation], `esxi:hostd` (shell access or job registration) [Command Execution], `esxi:cron` (manual edits to /etc/rc.local.d/local.sh or cron.d) [File Modification]
**Procedure Examples**
- [S0447] Lokibot: Lokibot's second stage DLL has set a timer using “timeSetEvent” to schedule its next execution.


### T1053.002 - Scheduled Task/Job: At
Adversaries may abuse the at utility to perform task scheduling for initial or recurring execution of malicious code. The at utility exists as an executable within Windows, Linux, and macOS for scheduling tasks at a specified time and date. Although deprecated in favor of Scheduled Task's schtasks in Windows environments, using at requires that the Task Scheduler service be running, and the user to be logged on as a member of the local Administrators group. In addition to explicitly running the `at` command, adversaries may also schedule a task with at by directly leveraging the Windows Management Instrumentation `Win32_ScheduledJob` WMI class. On Linux and macOS, at may be invoked by the superuser as well as any users added to the at.allow file. If the at.allow file does not exist, the at.deny file is checked. Every username not listed in at.deny is allowed to invoke at. If the at.deny exists and is empty, global use of at is permitted. If neither file exists (which is often the baseline) only the superuser is allowed to use at. Adversaries may use at to execute programs at system startup or on a scheduled basis for Persistence. at can also be abused to conduct remote Execution as part of Lateral Movement and/or to run a process under the context of a specified account (such as SYSTEM). In Linux environments, adversaries may also abuse at to break out of restricted environments by using a task to spawn an interactive system shell or to run system commands. Similarly, at may also be used for Privilege Escalation if the binary is allowed to run as superuser via sudo.
**Detection**
- [AN0944] **[Linux]** Detects usage of `at` command to schedule jobs, followed by job execution and modification of job files under /var/spool/cron/atjobs.
  - **Log sources:** `auditd:SYSCALL` (execve) [Process Creation], `auditd:SYSCALL` (write) [File Modification]
- [AN0945] **[macOS]** Detects user or root invocation of `at` command to schedule a job, followed by job execution using LaunchServices and activity in /usr/lib/cron/at.
  - **Log sources:** `macos:unifiedlog` (process: at, job runner) [Command Execution], `fs:fsusage` (file access to /usr/lib/cron/at and job execution path) [File Modification], `macos:osquery` (process_events) [Process Creation]
- [AN0943] **[Windows]** Detects creation of scheduled tasks via `at.exe` or WMI `Win32_ScheduledJob` class, followed by execution of anomalous processes by svchost.exe or taskeng.exe.
  - **Log sources:** `WinEventLog:Security` (EventCode=4698) [Scheduled Job Creation], `WinEventLog:Sysmon` (EventCode=1) [Process Creation]
**Procedure Examples**
- [G0027] Threat Group-3390: Threat Group-3390 actors use at to schedule tasks to run self-extracting RAR archives, which install HTTPBrowser or PlugX on other victims on a network.
- [S0488] CrackMapExec: CrackMapExec can set a scheduled task on the target system to execute commands remotely using at.
- [G0026] APT18: APT18 actors used the native at Windows task scheduler tool to use scheduled tasks for execution on a victim network.
- [G0060] BRONZE BUTLER: BRONZE BUTLER has used at to register a scheduled task to execute malware during lateral movement.
- [S0233] MURKYTOP: MURKYTOP has the capability to schedule remote AT jobs.
- [S0110] at: at can be used to schedule a task on a system to be executed at a specific date or time.


### T1053.003 - Scheduled Task/Job: Cron
Adversaries may abuse the cron utility to perform task scheduling for initial or recurring execution of malicious code. The cron utility is a time-based job scheduler for Unix-like operating systems. The crontab file contains the schedule of cron entries to be run and the specified times for execution. Any crontab files are stored in operating system-specific file paths. An adversary may use cron in Linux or Unix environments to execute programs at system startup or on a scheduled basis for Persistence. In ESXi environments, cron jobs must be created directly via the crontab file (e.g., `/var/spool/cron/crontabs/root`).
**Detection**
- [AN0805] **[Linux]** Detects creation or modification of crontab entries by non-root users or from abnormal parent processes, followed by the execution of uncommon binaries at scheduled intervals.
  - **Log sources:** `auditd:SYSCALL` (write) [File Modification], `auditd:SYSCALL` (execve) [Process Creation]
- [AN0807] **[ESXi]** Detects direct modification of crontab entries in /var/spool/cron/crontabs/root or /etc/rc.local.d/local.sh followed by execution of scripts linked to lateral movement or malware persistence.
  - **Log sources:** `esxi:hostd` (modification of crontab or local.sh entries) [File Modification], `esxi:cron` (execution of scheduled job) [Scheduled Job Creation], `esxi:vmkernel` (spawned shell or execution environment activity) [Process Creation]
- [AN0806] **[macOS]** Detects crontab job additions or modifications via `crontab` utility or direct edits, especially those created by interactive users executing hidden or renamed scripts.
  - **Log sources:** `macos:unifiedlog` (process: crontab edits, launch of cron job) [Scheduled Job Creation], `fs:fsusage` (file access to /usr/lib/cron/tabs/ and cron output files) [File Modification]
**Procedure Examples**
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


### T1053.005 - Scheduled Task/Job: Scheduled Task
Adversaries may abuse the Windows Task Scheduler to perform task scheduling for initial or recurring execution of malicious code. There are multiple ways to access the Task Scheduler in Windows. The schtasks utility can be run directly on the command line, or the Task Scheduler can be opened through the GUI within the Administrator Tools section of the Control Panel. In some cases, adversaries have used a .NET wrapper for the Windows Task Scheduler, and alternatively, adversaries have used the Windows netapi32 library and Windows Management Instrumentation (WMI) to create a scheduled task. Adversaries may also utilize the Powershell Cmdlet `Invoke-CimMethod`, which leverages WMI class `PS_ScheduledTask` to create a scheduled task via an XML path. An adversary may use Windows Task Scheduler to execute programs at system startup or on a scheduled basis for persistence. The Windows Task Scheduler can also be abused to conduct remote Execution as part of Lateral Movement and/or to run a process under the context of a specified account (such as SYSTEM). Similar to System Binary Proxy Execution, adversaries have also abused the Windows Task Scheduler to potentially mask one-time execution under signed/trusted system processes. Adversaries may also create "hidden" scheduled tasks (i.e. Hide Artifacts) that may not be visible to defender tools and manual queries used to enumerate tasks. Specifically, an adversary may hide a task from `schtasks /query` and the Task Scheduler by deleting the associated Security Descriptor (SD) registry value (where deletion of this value must be completed using SYSTEM permissions). Adversaries may also employ alternate methods to hide tasks, such as altering the metadata (e.g., `Index` value) within associated registry keys.
**Detection**
- [AN1221] **[Windows]** Detects the creation, modification, or deletion of scheduled tasks through Task Scheduler, WMI, PowerShell, or API-based methods followed by execution from svchost.exe or taskeng.exe. Includes detection of hidden or anomalous scheduled tasks, especially those created under SYSTEM or suspicious user contexts.
  - **Log sources:** `WinEventLog:Security` (EventCode=4698) [Scheduled Job Creation], `WinEventLog:Security` (EventCode=4702) [Scheduled Job Modification], `WinEventLog:Sysmon` (EventCode=1) [Process Creation], `WinEventLog:Sysmon` (EventCode=11) [File Creation], `WinEventLog:Sysmon` (EventCode=13, 14) [Windows Registry Key Modification]
**Procedure Examples**
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


### T1053.006 - Scheduled Task/Job: Systemd Timers
Adversaries may abuse systemd timers to perform task scheduling for initial or recurring execution of malicious code. Systemd timers are unit files with file extension .timer that control services. Timers can be set to run on a calendar event or after a time span relative to a starting point. They can be used as an alternative to Cron in Linux environments. Systemd timers may be activated remotely via the systemctl command line utility, which operates over SSH. Each .timer file must have a corresponding .service file with the same name, e.g., example.timer and example.service. .service files are Systemd Service unit files that are managed by the systemd system and service manager. Privileged timers are written to /etc/systemd/system/ and /usr/lib/systemd/system while user level are written to ~/.config/systemd/user/. An adversary may use systemd timers to execute malicious code at system startup or on a scheduled basis for persistence. Timers installed using privileged paths may be used to maintain root level persistence. Adversaries may also install user level timers to achieve user level persistence.
**Detection**
- [AN0645] **[Linux]** Detects adversarial abuse of systemd timers by correlating file creation/modification of .timer and .service units in system directories with the execution of abnormal child processes launched by 'systemd' (PID 1), especially as root.
  - **Log sources:** `auditd:SYSCALL` (creat, open, write on /etc/systemd/system and /usr/lib/systemd/system) [File Creation], `auditd:SYSCALL` (execve logging for /usr/bin/systemctl and systemd-run) [Process Creation], `linux:osquery` (file_events) [Scheduled Job Creation]
Adversaries may abuse systemd timers to perform task scheduling for initial or recurring execution of malicious code. Systemd timers are unit files with file extension .timer that control services. Timers can be set to run on a calendar event or after a time span relative to a starting point. They can be used as an alternative to Cron in Linux environments. Systemd timers may be activated remotely via the systemctl command line utility, which operates over SSH. Each .timer file must have a corresponding .service file with the same name, e.g., example.timer and example.service. .service files are Systemd Service unit files that are managed by the systemd system and service manager. Privileged timers are written to /etc/systemd/system/ and /usr/lib/systemd/system while user level are written to ~/.config/systemd/user/. An adversary may use systemd timers to execute malicious code at system startup or on a scheduled basis for persistence. Timers installed using privileged paths may be used to maintain root level persistence. Adversaries may also install user level timers to achieve user level persistence.


### T1053.007 - Scheduled Task/Job: Container Orchestration Job
Adversaries may abuse task scheduling functionality provided by container orchestration tools such as Kubernetes to schedule deployment of containers configured to execute malicious code. Container orchestration jobs run these automated tasks at a specific date and time, similar to cron jobs on a Linux system. Deployments of this type can also be configured to maintain a quantity of containers over time, automating the process of maintaining persistence within a cluster. In Kubernetes, a CronJob may be used to schedule a Job that runs one or more containers to perform specific tasks. An adversary therefore may utilize a CronJob to schedule deployment of a Job that executes malicious code in various nodes within a cluster.
**Detection**
- [AN0582] **[Containers]** Detects abuse of container orchestration platforms (e.g., Kubernetes) where adversaries create CronJobs to maintain persistence or execute malicious Jobs across the cluster.
  - **Log sources:** `kubernetes:apiserver` (verb=create, resource=cronjobs, group=batch) [Scheduled Job Creation], `kubernetes:events` (container start/stop activity via Docker, containerd, or CRI-O) [Container Creation], `container:proxy` (outbound/inbound network activity from spawned pods) [Network Traffic Content]
Adversaries may abuse task scheduling functionality provided by container orchestration tools such as Kubernetes to schedule deployment of containers configured to execute malicious code. Container orchestration jobs run these automated tasks at a specific date and time, similar to cron jobs on a Linux system. Deployments of this type can also be configured to maintain a quantity of containers over time, automating the process of maintaining persistence within a cluster. In Kubernetes, a CronJob may be used to schedule a Job that runs one or more containers to perform specific tasks. An adversary therefore may utilize a CronJob to schedule deployment of a Job that executes malicious code in various nodes within a cluster.


### T1059 - Command and Scripting Interpreter
Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries. These interfaces and languages provide ways of interacting with computer systems and are a common feature across many different platforms. Most systems come with some built-in command-line interface and scripting capabilities, for example, macOS and Linux distributions include some flavor of Unix Shell while Windows installations include the Windows Command Shell and PowerShell. There are also cross-platform interpreters such as Python, as well as those commonly associated with client applications such as JavaScript and Visual Basic. Adversaries may abuse these technologies in various ways as a means of executing arbitrary commands. Commands and scripts can be embedded in Initial Access payloads delivered to victims as lure documents or as secondary payloads downloaded from an existing C2. Adversaries may also execute commands through interactive terminals/shells, as well as utilize various Remote Services in order to achieve remote Execution.
**Detection**
- [AN1429] **[Linux]** Detects use of shell interpreters (e.g., bash, sh, python, perl) initiated by users or processes not normally executing them, especially when chaining suspicious utilities like netcat, curl, or ssh.
  - **Log sources:** `auditd:SYSCALL` (execve) [Process Creation]
- [AN1430] **[macOS]** Detects launch of command-line interpreters via Terminal, Automator, or hidden `osascript`, especially when parent process lineage deviates from user-initiated applications.
  - **Log sources:** `macos:unifiedlog` (log stream --info --predicate 'eventMessage CONTAINS "exec"') [Process Creation]
- [AN1431] **[ESXi]** Detects use of 'esxcli system' or direct interpreter commands (e.g., busybox shell) invoked from SSH or host terminal unexpectedly.
  - **Log sources:** `esxi:vobd` (shell session start) [Command Execution]
- [AN1432] **[Network Devices]** Identifies CLI interpreter access (e.g., Cisco IOS, Juniper JUNOS) via `enable` mode or scripting-capable sessions used by uncommon accounts or from unknown IPs.
  - **Log sources:** `networkdevice:cli` (shell command) [Command Execution], `networkdevice:syslog` (authentication & authorization) [User Account Authentication]
- [AN1428] **[Windows]** Detects the execution of scripting or command interpreters (e.g., powershell.exe, cmd.exe, wscript.exe) outside expected administrative time windows or from abnormal user contexts, often followed by encoded/obfuscated arguments or secondary execution events.
  - **Log sources:** `WinEventLog:Sysmon` (EventCode=1) [Process Creation]
**Procedure Examples**
- [G0117] Fox Kitten: Fox Kitten has used a Perl reverse shell to communicate with C2.
- [G0038] Stealth Falcon: Stealth Falcon malware uses WMI to script data collection and command execution on the victim.
- [G1035] Winter Vivern: Winter Vivern used XLM 4.0 macros for initial code execution for malicious document files.
- [G0046] FIN7: FIN7 used SQL scripts to help perform tasks on the victim's machine.
- [S0334] DarkComet: DarkComet can execute various types of scripts on the victim’s machine.
- [G0037] FIN6: FIN6 has used scripting to iterate through a list of compromised PoS systems, copy data to a log file, and remove the original data files.
- [S1227] StarProxy: StarProxy has used the command line for execution of commands.
- [C0005] Operation Spalax: For Operation Spalax, the threat actors used Nullsoft Scriptable Install System (NSIS) scripts to install malware.
- [S0023] CHOPSTICK: CHOPSTICK is capable of performing remote command execution.
- [S0695] Donut: Donut can generate shellcode outputs that execute via Ruby.


### T1059.001 - Command and Scripting Interpreter: PowerShell
Adversaries may abuse PowerShell commands and scripts for execution. PowerShell is a powerful interactive command-line interface and scripting environment included in the Windows operating system. Adversaries can use PowerShell to perform a number of actions, including discovery of information and execution of code. Examples include the Start-Process cmdlet which can be used to run an executable and the Invoke-Command cmdlet which runs a command locally or on a remote computer (though administrator permissions are required to use PowerShell to connect to remote systems). PowerShell may also be used to download and run executables from the Internet, which can be executed from disk or in memory without touching disk. A number of PowerShell-based offensive testing tools are available, including Empire, PowerSploit, PoshC2, and PSAttack. PowerShell commands/scripts can also be executed without directly invoking the powershell.exe binary through interfaces to PowerShell's underlying System.Management.Automation assembly DLL exposed through the .NET framework and Windows Common Language Interface (CLI).
**Detection**
- [AN1252] **[Windows]** Detects behavioral chains where PowerShell is launched with encoded commands, unusual parent processes, or suspicious modules loaded, potentially followed by network connections or child process spawning. Supports detection of both direct (powershell.exe) and indirect (.NET automation) invocations.
  - **Log sources:** `WinEventLog:Sysmon` (EventCode=1) [Process Creation], `WinEventLog:PowerShell` (EventCode=4103, 4104, 4105, 4106) [Command Execution], `WinEventLog:PowerShell` (EventCode=400, 403) [Process Metadata], `WinEventLog:Sysmon` (EventCode=7) [Module Load]
**Procedure Examples**
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


### T1059.002 - Command and Scripting Interpreter: AppleScript
Adversaries may abuse AppleScript for execution. AppleScript is a macOS scripting language designed to control applications and parts of the OS via inter-application messages called AppleEvents. These AppleEvent messages can be sent independently or easily scripted with AppleScript. These events can locate open windows, send keystrokes, and interact with almost any open application locally or remotely. Scripts can be run from the command-line via osascript /path/to/script or osascript -e "script here". Aside from the command line, scripts can be executed in numerous ways including Mail rules, Calendar.app alarms, and Automator workflows. AppleScripts can also be executed as plain text shell scripts by adding #!/usr/bin/osascript to the start of the script file. AppleScripts do not need to call osascript to execute. However, they may be executed from within mach-O binaries by using the macOS Native APIs NSAppleScript or OSAScript, both of which execute code independent of the /usr/bin/osascript command line utility. Adversaries may abuse AppleScript to execute various behaviors, such as interacting with an open SSH connection, moving to remote machines, and even presenting users with fake dialog boxes. These events cannot start applications remotely (they can start them locally), but they can interact with applications if they're already running remotely. On macOS 10.10 Yosemite and higher, AppleScript has the ability to execute Native APIs, which otherwise would require compilation and execution in a mach-O binary file format. Since this is a scripting language, it can be used to launch more common techniques as well such as a reverse shell via Python.
**Detection**
- [AN1164] **[macOS]** Detects AppleScript execution via 'osascript', NSAppleScript/OSAScript APIs, and abnormal application control events across user sessions. Focuses on causal chains such as osascript spawning child processes, script-induced keystrokes, or API-backed dialog spoofing.
  - **Log sources:** `macos:unifiedlog` (process: spawn, exec) [Process Creation]
**Procedure Examples**
- [S0281] Dok: Dok uses AppleScript to create a login item for persistence.
- [S0595] ThiefQuest: ThiefQuest uses AppleScript's osascript -e command to launch ThiefQuest's persistence via Launch Agent and Launch Daemon.
- [S0482] Bundlore: Bundlore can use AppleScript to inject malicious JavaScript into a browser.
- [S1153] Cuckoo Stealer: Cuckoo Stealer can use osascript to generate a password-stealing prompt, duplicate files and folders, and set environmental variables.
- [S1048] macOS.OSAMiner: macOS.OSAMiner has used `osascript` to call itself via the `do shell script` command in the Launch Agent `.plist` file.


### T1059.003 - Command and Scripting Interpreter: Windows Command Shell
Adversaries may abuse the Windows command shell for execution. The Windows command shell (cmd) is the primary command prompt on Windows systems. The Windows command prompt can be used to control almost any aspect of a system, with various permission levels required for different subsets of commands. The command prompt can be invoked remotely via Remote Services such as SSH. Batch files (ex: .bat or .cmd) also provide the shell with a list of sequential commands to run, as well as normal scripting operations such as conditionals and loops. Common uses of batch files include long or repetitive tasks, or the need to run the same set of commands on multiple systems. Adversaries may leverage cmd to execute various commands and payloads. Common uses include cmd to execute a single command, or abusing cmd interactively with input and output forwarded over a command and control channel.
**Detection**
- [AN0578] **[Windows]** Detects interactive or scripted abuse of cmd.exe, batch files, or shell invocation chains. Focuses on parent-child relationships (e.g., cmd.exe launched from unusual parents), anomalous command-line parameters, and chaining with discovery, credential access, or lateral movement behaviors.
  - **Log sources:** `WinEventLog:Security` (EventCode=4688) [Process Creation], `WinEventLog:Sysmon` (EventCode=7) [Module Load], `EDR:scriptblock` (Process Tree + Script Block Logging) [Script Execution]
**Procedure Examples**
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


### T1059.004 - Command and Scripting Interpreter: Unix Shell
Adversaries may abuse Unix shell commands and scripts for execution. Unix shells are the primary command prompt on Linux, macOS, and ESXi systems, though many variations of the Unix shell exist (e.g. sh, ash, bash, zsh, etc.) depending on the specific OS or distribution. Unix shells can control every aspect of a system, with certain commands requiring elevated privileges. Unix shells also support scripts that enable sequential execution of commands as well as other typical programming operations such as conditionals and loops. Common uses of shell scripts include long or repetitive tasks, or the need to run the same set of commands on multiple systems. Adversaries may abuse Unix shells to execute various commands or payloads. Interactive shells may be accessed through command and control channels or during lateral movement such as with SSH. Adversaries may also leverage shell scripts to deliver and execute multiple commands on victims or as part of payloads used for persistence. Some systems, such as embedded devices, lightweight Linux distributions, and ESXi servers, may leverage stripped-down Unix shells via Busybox, a small executable that contains a variety of tools, including a simple shell.
**Detection**
- [AN1084] **[Network Devices]** Detects Unix shell usage on network appliances (e.g., routers, firewalls, embedded Linux) through rare console commands, CLI interfaces, or script injection via exposed APIs or SSH.
  - **Log sources:** `networkdevice:syslog` (CLI Command Audit) [Command Execution], `NSM:Flow` (remote access) [Network Connection Creation]
- [AN1083] **[ESXi]** Detects BusyBox or Ash shell execution from unauthorized logins or remote connections. Focus is on rare shell invocations from DCUI, SSH sessions, or remote management paths. Also watches for payload droppers or persistence artifacts using shell.
  - **Log sources:** `esxi:vmkernel` (DCUI shell start, BusyBox activity) [Command Execution], `esxi:auth` (Shell login or escalation) [Logon Session Creation]
- [AN1081] **[Linux]** Detects bash, sh, zsh, or BusyBox shell execution initiated via remote sessions, unauthorized users, or embedded within secondary script interpreters. Focus is on chained behavior: shell > suspicious commands > network discovery or persistence indicators.
  - **Log sources:** `auditd:SYSCALL` (execve) [Process Creation], `linux:osquery` (socket_events) [Network Traffic Flow], `linux:syslog` (auth.log / secure.log) [Logon Session Creation]
- [AN1082] **[macOS]** Identifies use of sh/bash/zsh in suspicious context, such as user scripts launched from non-standard apps (e.g., Preview.app), embedded in LaunchDaemons, or executed outside Terminal.app. Looks for misuse in Automator, LaunchAgents, or NSAppleScript-executed shell.
  - **Log sources:** `macos:unifiedlog` (log stream --predicate 'eventMessage contains "exec"') [Process Creation], `macos:osquery` (launchd + process_events) [Command Execution], `macos:syslog` (system.log, asl.log) [Script Execution]
**Procedure Examples**
- [S1184] BOLDMOVE: BOLDMOVE is capable of spawning a remote command shell.
- [S1224] CASTLETAP: CASTLETAP has the ability to spawn BusyBox command shell in victim environments.
- [G0143] Aquatic Panda: Aquatic Panda used malicious shell scripts in Linux environments following access via SSH to install Linux versions of Winnti malware.
- [S0377] Ebury: Ebury can use the commands `Xcsh` or `Xcls` to open a shell with Ebury level permissions and `Xxsh` to open a shell with root level.
- [S1107] NKAbuse: NKAbuse is initially installed and executed through an initial shell script.
- [S1163] SnappyTCP: SnappyTCP creates the reverse shell using a pthread spawning a bash shell.
- [S0647] Turian: Turian has the ability to use /bin/sh to execute commands.
- [G0139] TeamTNT: TeamTNT has used shell scripts for execution.
- [C0048] Operation MidnightEclipse: During Operation MidnightEclipse, threat actors piped output from stdout to bash for execution.
- [S0482] Bundlore: Bundlore has leveraged /bin/sh and /bin/bash to execute commands on the victim machine.


### T1059.005 - Command and Scripting Interpreter: Visual Basic
Adversaries may abuse Visual Basic (VB) for execution. VB is a programming language created by Microsoft with interoperability with many Windows technologies such as Component Object Model and the Native API through the Windows API. Although tagged as legacy with no planned future evolutions, VB is integrated and supported in the .NET Framework and cross-platform .NET Core. Derivative languages based on VB have also been created, such as Visual Basic for Applications (VBA) and VBScript. VBA is an event-driven programming language built into Microsoft Office, as well as several third-party applications. VBA enables documents to contain macros used to automate the execution of tasks and other functionality on the host. VBScript is a default scripting language on Windows hosts and can also be used in place of JavaScript on HTML Application (HTA) webpages served to Internet Explorer (though most modern browsers do not come with VBScript support). Adversaries may use VB payloads to execute malicious commands. Common malicious usage includes automating execution of behaviors with VBScript or embedding VBA content into Spearphishing Attachment payloads (which may also involve Mark-of-the-Web Bypass to enable execution).
**Detection**
- [AN0211] **[Linux]** Detects abuse of Mono/.NET Core environments to execute VB-like scripts, often in environments with Office emulation or WINE. Focus is on rare invocations of scripting hosts like mono.exe or .NET shells, often seen in spam filtering or forensic labs with Office support.
  - **Log sources:** `auditd:SYSCALL` (execve) [Process Creation], `linux:syslog` (/var/log/syslog) [Script Execution]
- [AN0209] **[Windows]** Detects execution of VB-based scripts or macros (VBS/VBA/VBScript) through cscript.exe/wscript.exe, Office-based process chains, or HTA usage. Focuses on chained behavior: Office or HTML container spawns script host > script host spawns PowerShell, network connections, or process injection.
  - **Log sources:** `WinEventLog:Sysmon` (EventCode=1) [Process Creation], `WinEventLog:Sysmon` (EventCode=7) [Module Load]
- [AN0210] **[macOS]** Detects embedded or emulated VBScript/VBA execution via Wine-based apps, Office for Mac abusing cross-platform .NET features, or macros dropped and invoked via AppleScript or third-party automation tools.
  - **Log sources:** `macos:unifiedlog` (log stream --predicate 'eventMessage contains "wscript" OR "vbs"') [Script Execution], `macos:osquery` (process_events) [Process Creation], `macos:syslog` (system.log) [Command Execution]
**Procedure Examples**
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


### T1059.006 - Command and Scripting Interpreter: Python
Adversaries may abuse Python commands and scripts for execution. Python is a very popular scripting/programming language, with capabilities to perform many functions. Python can be executed interactively from the command-line (via the python.exe interpreter) or via scripts (.py) that can be written and distributed to different systems. Python code can also be compiled into binary executables. Python comes with many built-in packages to interact with the underlying system, such as file operations and device I/O. Adversaries can use these libraries to download and execute commands or other scripts as well as perform various malicious behaviors.
**Detection**
- [AN0174] **[Linux]** Detects Python execution from non-standard user contexts or cron jobs that invoke outbound traffic, access sensitive files, or perform process injection (e.g., ptrace or /proc memory maps).
  - **Log sources:** `auditd:SYSCALL` (execve) [Process Creation], `linux:syslog` (/var/log/syslog) [Script Execution]
- [AN0175] **[ESXi]** Detects Python script or interpreter execution on ESXi hosts via embedded BusyBox shells, nested installations, or dropped files via SSH or datastore mount. Flags unusual scripting or post-compromise enumeration behavior.
  - **Log sources:** `esxi:vobd` (/var/log/vobd.log) [Process Creation], `esxi:hostd` (/var/log/hostd.log) [Command Execution]
- [AN0173] **[macOS]** Detects native Python or framework-based execution from Terminal, embedded apps, or launchd jobs. Flags network calls, persistence writes, or system enumeration after Python launch.
  - **Log sources:** `macos:unifiedlog` (log stream --predicate 'eventMessage contains "python"') [Script Execution], `macos:osquery` (process_events) [Process Creation], `macos:syslog` (system.log) [Command Execution]
- [AN0172] **[Windows]** Detects Python execution via python.exe or py.exe with anomalous parent lineage (e.g., Office macros, LOLBAS), execution from unusual directories, or chained network/PowerShell/system-level activity.
  - **Log sources:** `WinEventLog:Sysmon` (EventCode=1) [Process Creation], `EDR:hunting` (Advanced Hunting: DeviceProcessEvents + DeviceNetworkEvents) [Network Traffic Content]
**Procedure Examples**
- [S0581] IronNetInjector: IronNetInjector can use IronPython scripts to load payloads with the help of a .NET injector.
- [S0547] DropBook: DropBook is a Python-based backdoor compiled with PyInstaller.
- [S1218] VIRTUALPIE: VIRTUALPIE is a Python-based backdoor malware.
- [S0196] PUNCHBUGGY: PUNCHBUGGY has used python scripts.
- [G0067] APT37: APT37 has used Python scripts to execute payloads.
- [C0059] Salesforce Data Exfiltration: During Salesforce Data Exfiltration, threat actors used custom applications developed in python.
- [G0060] BRONZE BUTLER: BRONZE BUTLER has made use of Python-based remote access tools.
- [S0695] Donut: Donut can generate shellcode outputs that execute via Python.
- [S0681] Lizar: Lizar has used Python scripts (ps2x.py script and ps2p.py) to execute files on remote hosts using the Impacket library.
- [S1217] VIRTUALPITA: VIRTUALPITA can call a Python script to run commands on a targeted guest virtual machine.


### T1059.007 - Command and Scripting Interpreter: JavaScript
Adversaries may abuse various implementations of JavaScript for execution. JavaScript (JS) is a platform-independent scripting language (compiled just-in-time at runtime) commonly associated with scripts in webpages, though JS can be executed in runtime environments outside the browser. JScript is the Microsoft implementation of the same scripting standard. JScript is interpreted via the Windows Script engine and thus integrated with many components of Windows such as the Component Object Model and Internet Explorer HTML Application (HTA) pages. JavaScript for Automation (JXA) is a macOS scripting language based on JavaScript, included as part of Apple’s Open Scripting Architecture (OSA), that was introduced in OSX 10.10. Apple’s OSA provides scripting capabilities to control applications, interface with the operating system, and bridge access into the rest of Apple’s internal APIs. As of OSX 10.10, OSA only supports two languages, JXA and AppleScript. Scripts can be executed via the command line utility osascript, they can be compiled into applications or script files via osacompile, and they can be compiled and executed in memory of other programs by leveraging the OSAKit Framework. Adversaries may abuse various implementations of JavaScript to execute various behaviors. Common uses include hosting malicious scripts on websites as part of a Drive-by Compromise or downloading and executing these script files as secondary payloads. Since these payloads are text-based, it is also very common for adversaries to obfuscate their content as part of Obfuscated Files or Information.
**Detection**
- [AN0735] **[Linux]** Detects Node.js or JavaScript interpreter execution from web shells, cron jobs, or local users. Correlates execution with reverse shell behavior, file modifications, or abnormal outbound connections.
  - **Log sources:** `auditd:SYSCALL` (execve) [Process Creation], `linux:syslog` (/var/log/syslog) [Script Execution]
- [AN0733] **[Windows]** Detects JavaScript execution through WSH (wscript.exe, cscript.exe) or HTA (mshta.exe), particularly when spawned from Office macros, web browsers, or abnormal user paths. Correlates script execution with outbound network activity or system modification.
  - **Log sources:** `WinEventLog:Sysmon` (EventCode=1) [Process Creation], `m365:defender` (ScriptBlockLogging + AMSI) [Script Execution], `WinEventLog:Sysmon` (EventCode=7) [Module Load]
- [AN0734] **[macOS]** Detects JavaScript for Automation (JXA) via osascript or compiled scripts using OSAKit APIs. Flags execution involving system modification, inter-process scripting, or browser abuse.
  - **Log sources:** `macos:unifiedlog` (log stream with predicate 'eventMessage CONTAINS "osascript"') [Script Execution], `macos:osquery` (process_events) [Process Creation], `macos:syslog` (/var/log/system.log) [Command Execution]
**Procedure Examples**
- [S0622] AppleSeed: AppleSeed has the ability to use JavaScript to execute PowerShell.
- [S0154] Cobalt Strike: The Cobalt Strike System Profiler can use JavaScript to perform reconnaissance actions.
- [S0455] Metamorfo: Metamorfo includes payloads written in JavaScript.
- [S1246] BeaverTail: BeaverTail has executed malicious JavaScript code. BeaverTail has also been compiled with the Qt framework to execute in both Windows and macOS.
- [G0010] Turla: Turla has used various JavaScript-based backdoors.
- [S1144] FRP: FRP can support the use of a JSON configuration file.
- [G0050] APT32: APT32 has used JavaScript for drive-by downloads and C2 communications.
- [G1031] Saint Bear: Saint Bear has delivered malicious Microsoft Office files containing an embedded JavaScript object that would, on execution, download and execute OutSteel and Saint Bot.
- [S0228] NanHaiShu: NanHaiShu executes additional Jscript code on the victim's machine.
- [G0037] FIN6: FIN6 has used malicious JavaScript to steal payment card data from e-commerce sites.


### T1059.008 - Command and Scripting Interpreter: Network Device CLI
Adversaries may abuse scripting or built-in command line interpreters (CLI) on network devices to execute malicious command and payloads. The CLI is the primary means through which users and administrators interact with the device in order to view system information, modify device operations, or perform diagnostic and administrative functions. CLIs typically contain various permission levels required for different commands. Scripting interpreters automate tasks and extend functionality beyond the command set included in the network OS. The CLI and scripting interpreter are accessible through a direct console connection, or through remote means, such as telnet or SSH. Adversaries can use the network CLI to change how network devices behave and operate. The CLI may be used to manipulate traffic flows to intercept or manipulate data, modify startup configuration parameters to load malicious system software, or to disable security features or logging to avoid detection.
**Detection**
- [AN0399] **[Network Devices]** Detects unauthorized or anomalous use of command-line interfaces (CLI) on network devices. Focuses on remote access sessions (e.g., SSH/Telnet), privilege escalation within CLI sessions, execution of high-risk commands (e.g., config replace, terminal monitor, no logging), and configuration changes outside of approved windows.
  - **Log sources:** `networkdevice:syslog` (command_exec) [Command Execution], `NSM:Flow` (remote CLI session detection) [Network Traffic Content], `networkdevice:syslog` (authorization/accounting logs) [User Account Authentication]
**Procedure Examples**
- [C0056] RedPenguin: During RedPenguin, UNC3886 accessed the Junos OS CLI on targeted devices.
- [S1186] Line Dancer: Line Dancer can execute native commands in networking device command line interfaces.


### T1059.009 - Command and Scripting Interpreter: Cloud API
Adversaries may abuse cloud APIs to execute malicious commands. APIs available in cloud environments provide various functionalities and are a feature-rich method for programmatic access to nearly all aspects of a tenant. These APIs may be utilized through various methods such as command line interpreters (CLIs), in-browser Cloud Shells, PowerShell modules like Azure for PowerShell, or software developer kits (SDKs) available for languages such as Python. Cloud API functionality may allow for administrative access across all major services in a tenant such as compute, storage, identity and access management (IAM), networking, and security policies. With proper permissions (often via use of credentials such as Application Access Token and Web Session Cookie), adversaries may abuse cloud APIs to invoke various functions that execute malicious actions. For example, CLI and PowerShell functionality may be accessed through binaries installed on cloud-hosted or on-premises hosts or accessed through a browser-based cloud shell offered by many cloud platforms (such as AWS, Azure, and GCP). These cloud shells are often a packaged unified environment to use CLI and/or scripting modules hosted as a container in the cloud environment.
**Detection**
- [AN0215] **[IaaS]** Detects adversarial use of cloud APIs for command execution, resource control, or reconnaissance. Focuses on CLI/SDK/scripting language abuse via stolen credentials or in-browser Cloud Shells. Monitors for anomalous API calls chained with authentication context shifts (e.g., stolen token -> privileged action) and cross-service impacts.
  - **Log sources:** `AWS:CloudTrail` (eventName: RunInstances, CreateUser, PutRolePolicy, InvokeCommand) [Command Execution], `azure:activity` (operationName: Write, Access Review, RoleAssignment) [Cloud Service Modification], `Okta:SystemLog` (eventType: user.authentication.sso, app.oauth2.token.grant) [User Account Authentication]
**Procedure Examples**
- [G1053] Storm-0501: Storm-0501 has leveraged Cloud CLI to execute commands and exfiltrate data from compromised environments.
- [S1091] Pacu: Pacu leverages the AWS CLI for its operations.
- [G0139] TeamTNT: TeamTNT has leveraged AWS CLI to enumerate cloud environments with compromised credentials.
- [G0016] APT29: APT29 has leveraged the Microsoft Graph API to perform various actions across Azure and M365 environments. They have also utilized AADInternals PowerShell Modules to access the API


### T1059.010 - Command and Scripting Interpreter: AutoHotKey & AutoIT
Adversaries may execute commands and perform malicious tasks using AutoIT and AutoHotKey automation scripts. AutoIT and AutoHotkey (AHK) are scripting languages that enable users to automate Windows tasks. These automation scripts can be used to perform a wide variety of actions, such as clicking on buttons, entering text, and opening and closing programs. Adversaries may use AHK (`.ahk`) and AutoIT (`.au3`) scripts to execute malicious code on a victim's system. For example, adversaries have used for AHK to execute payloads and other modular malware such as keyloggers. Adversaries have also used custom AHK files containing embedded malware as Phishing payloads. These scripts may also be compiled into self-contained executable payloads (`.exe`).
**Detection**
- [AN0942] **[Windows]** Detects execution of AutoHotKey or AutoIT interpreters or compiled scripts used for unauthorized automation, command execution, or payload delivery, correlated with anomalous process lineage, command-line arguments, or script creation events.
  - **Log sources:** `WinEventLog:Sysmon` (EventCode=1) [Process Creation], `WinEventLog:Sysmon` (EventCode=11) [File Creation], `WinEventLog:Sysmon` (EventCode=10) [Process Access]
**Procedure Examples**
- [S1213] Lumma Stealer: Lumma Stealer has utilized AutoIt malware scripts and AutoIt executables.
- [S0530] Melcoz: Melcoz has been distributed through an AutoIt loader script.
- [S1207] XLoader: XLoader can use an AutoIT script to decrypt a payload file, load it into victim memory, then execute it on the victim machine.
- [S1017] OutSteel: OutSteel was developed using the AutoIT scripting language.
- [G0087] APT39: APT39 has utilized AutoIt malware scripts embedded in Microsoft Office documents or malicious links.
- [S1111] DarkGate: DarkGate uses AutoIt scripts dropped to a hidden directory during initial installation phases, such as `test.au3`.


### T1059.011 - Command and Scripting Interpreter: Lua
Adversaries may abuse Lua commands and scripts for execution. Lua is a cross-platform scripting and programming language primarily designed for embedded use in applications. Lua can be executed on the command-line (through the stand-alone lua interpreter), via scripts (.lua), or from Lua-embedded programs (through the struct lua_State). Lua scripts may be executed by adversaries for malicious purposes. Adversaries may incorporate, abuse, or replace existing Lua interpreters to allow for malicious Lua command execution at runtime.
**Detection**
- [AN0280] **[macOS]** Detects Lua script execution via native or 3rd party interpreters, chained with unsigned binaries or unexpected parent lineage.
  - **Log sources:** `macos:unifiedlog` (log stream) [Command Execution]
- [AN0281] **[Network Devices]** Detects embedded Lua interpreter execution or script injection on devices supporting Lua scripting (e.g., routers, firewalls), often seen in modified firmware or abused APIs.
  - **Log sources:** `networkdevice:runtime` (runtime) [Script Execution]
- [AN0278] **[Windows]** Detects execution of Lua interpreters or scripts (.lua), especially when correlated with suspicious parent processes or file drop events, indicating malicious use of embedded scripting.
  - **Log sources:** `WinEventLog:Sysmon` (EventCode=1) [Process Creation], `WinEventLog:Sysmon` (EventCode=11) [File Creation]
- [AN0279] **[Linux]** Detects invocation of lua or luajit interpreters by users or services outside of expected packages, chained with script drop or memory artifacts.
  - **Log sources:** `auditd:SYSCALL` (execve) [Process Creation], `auditd:SYSCALL` (PATH) [File Metadata]
**Procedure Examples**
- [S0396] EvilBunny: EvilBunny has used Lua scripts to execute payloads.
- [S0125] Remsec: Remsec can use modules written in Lua for execution.
- [S1240] RedLine Stealer: RedLine Stealer malware has leveraged Lua bytecode to perform malicious behavior.
- [S1188] Line Runner: Line Runner utilizes Lua scripts for command execution.
- [S0428] PoetRAT: PoetRAT has executed a Lua script through a Lua interpreter for Windows.


### T1059.012 - Command and Scripting Interpreter: Hypervisor CLI
Adversaries may abuse hypervisor command line interpreters (CLIs) to execute malicious commands. Hypervisor CLIs typically enable a wide variety of functionality for managing both the hypervisor itself and the guest virtual machines it hosts. For example, on ESXi systems, tools such as `esxcli` and `vim-cmd` allow administrators to configure firewall rules and log forwarding on the hypervisor, list virtual machines, start and stop virtual machines, and more. Adversaries may be able to leverage these tools in order to support further actions, such as File and Directory Discovery or Data Encrypted for Impact.
**Detection**
- [AN1537] **[ESXi]** Detects suspicious use of ESXi native CLI tools like esxcli and vim-cmd by unauthorized users or outside expected maintenance windows. Focus is on actions such as stopping VMs, reconfiguring network/firewall settings, and enabling SSH or logging.
  - **Log sources:** `esxi:vmkernel` (esxcli, vim-cmd invocation) [Command Execution], `esxi:auth` (SSH session/login) [User Account Authentication]
**Procedure Examples**
- [G1048] UNC3886: UNC3886 has used the esxcli command line utility to modify firewall rules, install malware, and for artifact removal.
- [S1096] Cheerscrypt: Cheerscrypt has leveraged `esxcli` in order to terminate running virtual machines.
- [S1073] Royal: Royal ransomware uses `esxcli` to gather a list of running VMs and terminate them.
- [S1218] VIRTUALPIE: VIRTUALPIE is capable of command line execution on compromised ESXi servers.


### T1059.013 - Command and Scripting Interpreter: Container CLI/API
Adversaries may abuse built-in CLI tools or API calls to execute malicious commands in containerized environments. The Docker CLI is used for managing containers via an exposed API point from the `dockerd` daemon. Some common examples of Docker CLI include Docker Desktop CLI and Docker Compose, but users are also able to use SDKs to interact with the API. For example, Docker SDK for Python can be used to run commands within a Python application. Adversaries may leverage the Docker CLI, API, or SDK to pull or build Docker images (i.e., Ingress Tool Transfer, Build Image on Host), run containers (i.e., Deploy Container), or execute commands inside running containers (i.e., Container Administration Command). In some cases, threat actors may pull legitimate images that include scripts or tools that they can leverage - for example, using an image that includes the `curl` command to download payloads. Adversaries may also utilize `docker inspect` and `docker ps` to scan for cloud environment variables and other running containers (i.e., Container and Resource Discovery). Kubernetes is responsible for the management and orchestration of containers across clusters. The Kubernetes control plane, which manages the state of the cluster and is responsible for scheduling, communication, and resource monitoring, can be invoked directly via the API or indirectly via CLI tools such as `kubectl`. It may also be accessed within client libraries such as Go or Python. By utilizing the API, administrators can interact with resources within the cluster such as listing or creating pods, which is a group of one or more containers. Adversaries call the API server via `curl` or other tools, allowing them to obtain further information about the environment such as pods, deployments, daemonsets, namespaces, or sysvars. They may also run various commands regarding resource management.
**Detection**
- [AN0233] **[Containers]** Execution of container orchestration commands (e.g., `docker exec`, `kubectl exec`) or API-driven interactions with running containers from unauthorized hosts or non-standard user contexts. Defender sees programmatic or interactive command execution within containers outside expected CI/CD tools or automation frameworks, often followed by file writes, privilege escalation, or lateral discovery.
  - **Log sources:** `auditd:SYSCALL` (execve: Execution of container management CLIs (docker, crictl, kubectl) or interpreted shells (sh, bash, python) within container context) [Process Creation], `docker:events` (exec_create: docker exec events targeting running containers from non-CI sources) [Container Start], `kubernetes:apiserver` (create/exec: Kubernetes API calls to exec into containers or create pods from curl, kubectl, or SDK clients) [Container Creation], `AWS:CloudTrail` (CreatePod: Programmatic creation of new pod resources using container images not seen before in the environment) [Pod Creation], `kubernetes:audit` (Shell process (e.g., /bin/sh, /bin/bash) spawned in a container without an interactive session attached (i.e., automation anomaly)) [Command Execution]
**Procedure Examples**
- [G0139] TeamTNT: TeamTNT targeted misconfigured containers and used container CLI tools.


### T1072 - Software Deployment Tools
Adversaries may gain access to and use centralized software suites installed within an enterprise to execute commands and move laterally through the network. Configuration management and software deployment applications may be used in an enterprise network or cloud environment for routine administration purposes. These systems may also be integrated into CI/CD pipelines. Examples of such solutions include: SCCM, HBSS, Altiris, AWS Systems Manager, Microsoft Intune, Azure Arc, and GCP Deployment Manager. Access to network-wide or enterprise-wide endpoint management software may enable an adversary to achieve remote code execution on all connected systems. The access may be used to laterally move to other systems, gather information, or cause a specific effect, such as wiping the hard drives on all endpoints. SaaS-based configuration management services may allow for broad Cloud Administration Command on cloud-hosted instances, as well as the execution of arbitrary commands on on-premises endpoints. For example, Microsoft Configuration Manager allows Global or Intune Administrators to run scripts as SYSTEM on on-premises devices joined to Entra ID. Such services may also utilize Web Protocols to communicate back to adversary owned infrastructure. Network infrastructure devices may also have configuration management tools that can be similarly abused by adversaries. The permissions required for this action vary by system configuration; local credentials may be sufficient with direct access to the third-party system, or specific domain credentials may be required. However, the system may require an administrative account to log in or to access specific functionality.
**Detection**
- [AN0626] **[SaaS]** Detects cloud-native software deployment or management (e.g., SSM Run Command, Intune) initiating script execution on endpoints outside expected org IDs, admin groups, or maintenance windows.
  - **Log sources:** `AWS:CloudTrail` (SSM RunCommand) [Command Execution]
- [AN0623] **[Windows]** Detects SCCM, Intune, or remote push execution spawning scripts or binaries from SYSTEM context or unusual consoles (e.g., cmtrace.exe launching PowerShell or cmd.exe).
  - **Log sources:** `WinEventLog:Security` (EventCode=4688) [Process Creation], `WinEventLog:Application` (SCCM, Intune logs) [Application Log Content]
- [AN0627] **[Network Devices]** Detects central router or switch config management tools (e.g., FortiManager, Cisco Prime) triggering device reboots or config pushes using abnormal accounts or IPs.
  - **Log sources:** `networkdevice:syslog` (config push events) [Application Log Content], `NSM:Flow` (Device-to-Device Deployment Flows) [Network Traffic Flow]
- [AN0625] **[macOS]** Detects script or binary execution initiated via JAMF, Munki, or custom MDM agents outside of baseline, or JAMF launching new Terminal or osascript processes from remote command payloads.
  - **Log sources:** `macos:unifiedlog` (process and signing chain events) [Process Creation], `macos:jamf` (RemoteCommandExecution) [Application Log Content]
- [AN0624] **[Linux]** Detects remote scripts or binaries deployed via Puppet, Chef, Ansible, or shell scripts from orchestration servers executing outside maintenance windows or in unmanaged nodes.
  - **Log sources:** `auditd:SYSCALL` (execve) [Process Creation]
**Procedure Examples**
- [G0050] APT32: APT32 compromised McAfee ePO to move laterally by distributing malware as a software deployment task.
- [G0034] Sandworm Team: Sandworm Team has used the commercially available tool RemoteExec for agentless remote code execution.
- [G0129] Mustang Panda: Mustang Panda has leveraged legitimate software tools such as AntiVirus Agents, Security Services, and App Development tools to execute scripts and to side-load dlls.
- [G0091] Silence: Silence has used RAdmin, a remote software tool used to remotely control workstations and ATMs.
- [S0041] Wiper: It is believed that a patch management system for an anti-virus product commonly installed among targeted companies was used to distribute the Wiper malware.
- [G0028] Threat Group-1314: Threat Group-1314 actors used a victim's endpoint management platform, Altiris, for lateral movement.
- [C0018] C0018: During C0018, the threat actors used PDQ Deploy to move AvosLocker and tools across the network.
- [G1051] Medusa Group: Medusa Group has utilized software deployment and management solutions to deploy their encryption payload to include BigFix and PDQ Deploy.


### T1106 - Native API
Adversaries may interact with the native OS application programming interface (API) to execute behaviors. Native APIs provide a controlled means of calling low-level OS services within the kernel, such as those involving hardware/devices, memory, and processes. These native APIs are leveraged by the OS during system boot (when other system components are not yet initialized) as well as carrying out tasks and requests during routine operations. Adversaries may abuse these OS API functions as a means of executing behaviors. Similar to Command and Scripting Interpreter, the native API and its hierarchy of interfaces provide mechanisms to interact with and utilize various components of a victimized system. Native API functions (such as NtCreateProcess) may be directed invoked via system calls / syscalls, but these features are also often exposed to user-mode applications via interfaces and libraries. For example, functions such as the Windows API CreateProcess() or GNU fork() will allow programs and scripts to start other processes. This may allow API callers to execute a binary, run a CLI command, load modules, etc. as thousands of similar API functions exist for various system operations. Higher level software frameworks, such as Microsoft .NET and macOS Cocoa, are also available to interact with native APIs. These frameworks typically provide language wrappers/abstractions to API functionalities and are designed for ease-of-use/portability of code. Adversaries may use assembly to directly or in-directly invoke syscalls in an attempt to subvert defensive sensors and detection signatures such as user mode API-hooks. Adversaries may also attempt to tamper with sensors and defensive tools associated with API monitoring, such as unhooking monitored functions via Disable or Modify Tools.
**Detection**
- [AN1465] **[Windows]** Unusual or suspicious processes loading critical native API DLLs (e.g., ntdll.dll, kernel32.dll) followed by direct syscall behavior, memory manipulation, or hollowing.
  - **Log sources:** `WinEventLog:Sysmon` (EventCode=7) [Module Load], `WinEventLog:Sysmon` (EventCode=10) [Process Access], `WinEventLog:Sysmon` (EventCode=1) [Process Creation]
- [AN1466] **[Linux]** Userland processes invoking syscall-heavy libraries (libc, glibc) followed by fork, mmap, or ptrace behavior commonly associated with code injection or memory manipulation.
  - **Log sources:** `auditd:SYSCALL` (execve, fork, mmap, ptrace) [Process Access], `auditd:SYSCALL` (module load or memory map path) [Module Load]
- [AN1467] **[macOS]** Execution of processes that link to CoreServices or Foundation APIs followed by creation of memory regions, code execution, or abnormal library injection.
  - **Log sources:** `macos:unifiedlog` (launch and dylib load) [Module Load], `macos:endpointsecurity` (ES_EVENT_TYPE_NOTIFY_EXEC) [Process Creation]
**Procedure Examples**
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


### T1129 - Shared Modules
Adversaries may execute malicious payloads via loading shared modules. Shared modules are executable files that are loaded into processes to provide access to reusable code, such as specific custom functions or invoking OS API functions (i.e., Native API). Adversaries may use this functionality as a way to execute arbitrary payloads on a victim system. For example, adversaries can modularize functionality of their malware into shared objects that perform various functions such as managing C2 network communications or execution of specific actions on objective. The Linux & macOS module loader can load and execute shared objects from arbitrary local paths. This functionality resides in `dlfcn.h` in functions such as `dlopen` and `dlsym`. Although macOS can execute `.so` files, common practice uses `.dylib` files. The Windows module loader can be instructed to load DLLs from arbitrary local paths and arbitrary Universal Naming Convention (UNC) network paths. This functionality resides in `NTDLL.dll` and is part of the Windows Native API which is called from functions like `LoadLibrary` at run time.
**Detection**
- [AN0053] **[Linux]** A process loads a shared object (.so) via dlopen/LD_PRELOAD/open from non-standard or temporary locations (e.g., /tmp, /dev/shm), especially shortly after that .so is written or fetched, or linked via manipulated environment variables (LD_PRELOAD/LD_LIBRARY_PATH).
  - **Log sources:** `auditd:SYSCALL` (openat/read/mmap: Open/mmap .so files from non-standard paths) [Module Load], `auditd:EXECVE` (execve: Processes launched with LD_PRELOAD/LD_LIBRARY_PATH pointing to non-system dirs) [Process Creation], `linux:syslog` (sudo or service accounts invoking loaders with suspicious env vars) [Process Metadata], `NSM:Flow` (http/file-xfer: Inbound/outbound transfer of ELF shared objects) [Network Traffic Content]
- [AN0054] **[macOS]** A process loads a non-system .dylib/.so via dyld (dlopen/dlsym) from user-writable locations (~/Library, /tmp) or after the library was recently created/downloaded, often followed by network egress or persistence.
  - **Log sources:** `macos:unifiedlog` (dyld/unified log entries indicating image load from non-system paths) [Module Load], `macos:endpointsecurity` (exec: Process execution context for loaders calling dlopen/dlsym) [Process Creation], `macos:endpointsecurity` (ES_EVENT_TYPE_NOTIFY_OPEN: Open of .dylib/.so in user-writable locations) [File Access]
- [AN0052] **[Windows]** A process (often LOLBin or user-launched program) loads a DLL from a user-writable/UNC/Temp path or unsigned/invalid signer. Within a short window the DLL is (a) newly written to disk, (b) spawned as follow-on execution (rundll32/regsvr32), or (c) establishes outbound C2.
  - **Log sources:** `WinEventLog:Sysmon` (EventCode=7) [Module Load], `WinEventLog:Sysmon` (EventCode=11) [File Creation], `WinEventLog:Security` (EventCode=4688) [Process Creation], `WinEventLog:Sysmon` (EventCode=3, 22) [Network Connection Creation], `WinEventLog:Microsoft-Windows-CodeIntegrity/Operational` (CodeIntegrity/WDAC events indicating unsigned/invalid DLL loads) [Process Metadata]
**Procedure Examples**
- [S0032] gh0st RAT: gh0st RAT can load DLLs into memory.
- [S0203] Hydraq: Hydraq creates a backdoor through which remote attackers can load and call DLL functions.
- [S0196] PUNCHBUGGY: PUNCHBUGGY can load a DLL using the LoadLibrary API.
- [S0603] Stuxnet: Stuxnet calls LoadLibrary then executes exports from a DLL.
- [S0373] Astaroth: Astaroth uses the LoadLibraryExW() function to load additional modules.
- [S1185] LightSpy: LightSpy's main executable and module `.dylib` binaries are loaded using a combination of `dlopen()` to load the library, `_objc_getClass()` to retrieve the class definition, and `_objec_msgSend()` to invoke/execute the specified method in the loaded class.
- [S0607] KillDisk: KillDisk loads and executes functions from a DLL.
- [S0455] Metamorfo: Metamorfo had used AutoIt to load and execute the DLL payload.
- [G0129] Mustang Panda: Mustang Panda has leveraged `LoadLibrary` to load DLLs.
- [S0673] DarkWatchman: DarkWatchman can load DLLs.


### T1203 - Exploitation for Client Execution
Adversaries may exploit software vulnerabilities in client applications to execute code. Vulnerabilities can exist in software due to unsecure coding practices that can lead to unanticipated behavior. Adversaries can take advantage of certain vulnerabilities through targeted exploitation for the purpose of arbitrary code execution. Oftentimes the most valuable exploits to an offensive toolkit are those that can be used to obtain code execution on a remote system because they can be used to gain access to that system. Users will expect to see files related to the applications they commonly used to do work, so they are a useful target for exploit research and development because of their high utility. Several types exist: ### Browser-based Exploitation Web browsers are a common target through Drive-by Compromise and Spearphishing Link. Endpoint systems may be compromised through normal web browsing or from certain users being targeted by links in spearphishing emails to adversary controlled sites used to exploit the web browser. These often do not require an action by the user for the exploit to be executed. ### Office Applications Common office and productivity applications such as Microsoft Office are also targeted through Phishing. Malicious files will be transmitted directly as attachments or through links to download them. These require the user to open the document or file for the exploit to run. ### Common Third-party Applications Other applications that are commonly seen or are part of the software deployed in a target network may also be used for exploitation. Applications such as Adobe Reader and Flash, which are common in enterprise environments, have been routinely targeted by adversaries attempting to gain access to systems. Depending on the software and nature of the vulnerability, some may be exploited in the browser or require the user to open a file. For instance, some Flash exploits have been delivered as objects within Microsoft Office documents.
**Detection**
- [AN0797] **[Windows]** Cause→effect chain: (1) A client app (browser, Office, PDF/Flash/reader) experiences a crash/abnormal exit or loads from an unusual location, then (2) drops or modifies a file in user-writable paths, and/or (3) spawns an unexpected child (e.g., powershell/cmd/mshta/rundll32/wscript/installer), and (4) establishes outbound C2-like connections shortly after. Correlate application logs, file writes, process lineage, and network egress within a short window.
  - **Log sources:** `WinEventLog:Application` (EventCode=1000) [Application Log Content], `WinEventLog:Sysmon` (EventCode=11) [File Creation], `WinEventLog:Sysmon` (EventCode=1) [Process Creation], `WinEventLog:Sysmon` (EventCode=3, 22) [Network Connection Creation]
- [AN0799] **[macOS]** Cause→effect chain: (1) App crash/abnormal termination in unified logs for Safari/Chrome/Office/Preview, (2) new files/scripts in ~/Library, ~/Downloads, /private/var/folders/*, (3) unexpected child (osascript, zsh, bash, curl) spawned by those apps, (4) new outbound connections.
  - **Log sources:** `macos:unifiedlog` (process crash, abort, code signing violations) [Application Log Content], `fs:fsevents` (create/write/rename under user-writable paths) [File Modification], `macos:osquery` (exec) [Process Creation], `NSM:Connections` (new connections from exploited lineage) [Network Traffic Flow]
- [AN0798] **[Linux]** Cause→effect chain: (1) Browser/Office/reader process logs crash/segfault or abnormal sandbox message, (2) new executable/script/write occurs in $HOME (Downloads, ~/.cache, /tmp), (3) unexpected child like curl/wget/bash/python opens network connections soon after.
  - **Log sources:** `linux:syslog` (browser/office crash, segfault, abnormal termination) [Application Log Content], `auditd:SYSCALL` (open) [File Access], `auditd:SYSCALL` (creat) [File Creation], `auditd:SYSCALL` (rename,chmod) [File Modification], `auditd:SYSCALL` (execve) [Process Creation], `NetFlow:Flow` (new outbound connections from exploited process tree) [Network Traffic Flow]
**Procedure Examples**
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


### T1204 - User Execution
An adversary may rely upon specific actions by a user in order to gain execution. Users may be subjected to social engineering to get them to execute malicious code by, for example, opening a malicious document file or link. These user actions will typically be observed as follow-on behavior from forms of Phishing. While User Execution frequently occurs shortly after Initial Access it may occur at other phases of an intrusion, such as when an adversary places a file in a shared directory or on a user's desktop hoping that a user will click on it. This activity may also be seen shortly after Internal Spearphishing. Adversaries may also deceive users into performing actions such as: * Enabling Remote Access Tools, allowing direct control of the system to the adversary * Running malicious JavaScript in their browser, allowing adversaries to Steal Web Session Cookies * Downloading and executing malware for User Execution * Coerceing users to copy, paste, and execute malicious code manually For example, tech support scams can be facilitated through Phishing, vishing, or various forms of user interaction. Adversaries can use a combination of these methods, such as spoofing and promoting toll-free numbers or call centers that are used to direct victims to malicious websites, to deliver and execute payloads containing malware or Remote Access Tools.
**Detection**
- [AN1317] **[Containers]** Cause→effect chain in CI/dev desktops: (1) user triggers container run/pull after opening a doc/link/script, (2) newly created image/container uses unexpected external registry or entrypoint, (3) container starts and immediately egresses to suspicious destinations.
  - **Log sources:** `docker:events` (created,started: new container from untrusted registry or unexpected entrypoint) [Container Creation], `docker:events` (start) [Container Start], `NSM:Flow` (container egress to unknown IPs/domains) [Network Traffic Content]
- [AN1316] **[macOS]** Cause→effect chain: (1) unified logs show application open/click or crash for Safari/Chrome/Office/Preview/archiver, (2) file write/extraction into ~/Downloads, /private/var/folders/* or ~/Library, (3) parent app spawns osascript/bash/zsh/curl/python or opens a quarantined app with Gatekeeper prompts, (4) network egress from child.
  - **Log sources:** `macos:unifiedlog` (opened document|clicked link|EXC_BAD_ACCESS|abort|LSQuarantine) [Application Log Content], `fs:fileevents` (create/write/rename in user-writable paths) [File Creation], `macos:osquery` (exec) [Process Creation], `NSM:Flow` (new outbound connection from exploited lineage) [Network Connection Creation]
- [AN1315] **[Linux]** Cause→effect chain: (1) User app/browser/archiver logs an open/click or abnormal exit, (2) new executable/script/archive extracted into $HOME/Downloads, /tmp, or ~/.cache, (3) parent app spawns shell/interpreter (bash/sh/python/node/curl/wget) or desktop file, and (4) new outbound connection(s) from the child lineage.
  - **Log sources:** `linux:syslog` (opened document|clicked link|segfault|abnormal termination|sandbox) [Application Log Content], `auditd:SYSCALL` (open) [File Access], `auditd:SYSCALL` (creat) [File Creation], `auditd:SYSCALL` (rename,chmod) [File Modification], `auditd:SYSCALL` (execve) [Process Creation], `NSM:Flow` (new outbound connection from browser/office lineage) [Network Connection Creation]
- [AN1314] **[Windows]** Cause→effect chain: (1) User-facing app (Office/PDF/archiver/browser) records an open/click or abnormal event, then (2) a downloaded file is created in a user-writable path and/or decompressed, (3) the parent user app spawns a living-off-the-land binary (e.g., powershell/cmd/mshta/rundll32/msiexec/wscript/expand/zip) or installer, and (4) immediate outbound HTTP(S)/DNS/SMB from the same lineage.
  - **Log sources:** `WinEventLog:Application` (EventCode=1000) [Application Log Content], `WinEventLog:Sysmon` (EventCode=11) [File Creation], `WinEventLog:Security` (EventCode=4688) [Process Creation], `WinEventLog:Sysmon` (EventCode=3, 22) [Network Connection Creation]
- [AN1318] **[IaaS]** Cause→effect chain in cloud consoles: (1) user clicks link then invokes instance/image creation via API, (2) instance/image originates from external AMI or unknown image, (3) instance immediately egresses or retrieves payloads.
  - **Log sources:** `AWS:CloudTrail` (RunInstances,CreateImage) [Instance Creation], `AWS:CloudTrail` (StartInstances) [Instance Start], `gcp:vpcflow` (first 5m egress to unknown ASNs) [Network Traffic Content]
**Procedure Examples**
- [C0037] Water Curupira Pikabot Distribution: Water Curupira Pikabot Distribution requires users to interact with malicious attachments in order to start Pikabot installation.
- [G1015] Scattered Spider: Scattered Spider has impersonated organization IT and helpdesk staff to instruct victims to execute commercial remote access tools to gain initial access.
- [G1004] LAPSUS$: LAPSUS$ has recruited target organization employees or contractors who provide credentials and approve an associated MFA prompt, or install remote management software onto a corporate workstation, allowing LAPSUS$ to take control of an authenticated system.
- [S1213] Lumma Stealer: Lumma Stealer has been distributed through a fake CAPTCHA that presents instructions to the victim to open Windows Run window (“Windows Button + R”) and paste clipboard contents (“CTRL + V”) and press “Enter” to execute a Base64-encoded PowerShell.
- [S1130] Raspberry Robin: Raspberry Robin execution can rely on users directly interacting with malicious LNK files.


### T1204.001 - User Execution: Malicious Link
An adversary may rely upon a user clicking a malicious link in order to gain execution. Users may be subjected to social engineering to get them to click on a link that will lead to code execution. This user action will typically be observed as follow-on behavior from Spearphishing Link. Clicking on a link may also lead to other execution techniques such as exploitation of a browser or application vulnerability via Exploitation for Client Execution. Links may also lead users to download files that require execution via Malicious File.
**Detection**
- [AN0178] **[Windows]** Behavioral chain: (1) a user-facing app (browser/Office/email client) launches a URL or handles a link, then (2) the same process lineage makes an outbound connection to an untrusted domain/IP, (3) a file is downloaded or unpacked to a user-writable location shortly after the click. Optional enrichment: subsequent child execution by LOLBINs.
  - **Log sources:** `WinEventLog:Security` (EventCode=4688) [Process Creation], `WinEventLog:Sysmon` (EventCode=3, 22) [Network Connection Creation], `WinEventLog:Sysmon` (EventCode=11) [File Creation], `NSM:Flow` (Suspicious URL patterns, uncommon TLDs, short-lived domains, URL shorteners; HTTP method GET/POST) [Network Traffic Content]
- [AN0180] **[macOS]** Behavioral chain: (1) Safari/Chrome/Firefox/Office handles a URL; unified logs show open/click or LSQuarantine assignment, (2) outbound connection to untrusted domain, (3) a new file appears in ~/Downloads or /private/var/folders/* with quarantine flag.
  - **Log sources:** `macos:unifiedlog` (open URL|clicked link|LSQuarantineAttach) [Network Traffic Content], `NSM:Connections` (New outbound connection from Safari/Chrome/Firefox/Word) [Network Connection Creation], `fs:fsevents` (Create in /Users/*/Downloads or /private/var/folders/* with quarantine attribute) [File Creation]
- [AN0179] **[Linux]** Behavioral chain: (1) browser/office/GUI mail client opens a URL, (2) outbound connection to untrusted domain, (3) a new file is saved in $HOME/Downloads, /tmp, or cache immediately after.
  - **Log sources:** `auditd:SYSCALL` (execve: Execs of chromium, google-chrome, firefox, libreoffice with http(s) in cmdline) [Network Connection Creation], `auditd:SYSCALL` (open,creat,rename: Writes in $HOME/Downloads, /tmp, ~/.cache with exe/script/archive/office extensions) [File Creation], `NSM:Flow` (Suspicious URL patterns, uncommon TLDs, URL shorteners) [Network Traffic Content]
**Procedure Examples**
- [G0046] FIN7: FIN7 has used malicious links to lure victims into downloading malware.
- [G0098] BlackTech: BlackTech has used e-mails with malicious links to lure victims into installing malware.
- [S0531] Grandoreiro: Grandoreiro has used malicious links to gain execution on victim machines.
- [S0534] Bazar: Bazar can gain execution after a user clicks on a malicious link to decoy landing pages hosted on Google Docs.
- [C0002] Night Dragon: During Night Dragon, threat actors enticed users to click on links in spearphishing emails to download malware.
- [G0129] Mustang Panda: Mustang Panda has sent malicious links including links directing victims to a Google Drive folder. Mustang Panda has also utilized webpages with Javascript code that downloads malicious payloads to the victim device.
- [G0021] Molerats: Molerats has sent malicious links via email trick users into opening a RAR archive and running an executable.
- [G0112] Windshift: Windshift has used links embedded in e-mails to lure victims into executing malicious code.
- [S1017] OutSteel: OutSteel has relied on a user to click a malicious link within a spearphishing email.
- [G0094] Kimsuky: Kimsuky has lured victims into clicking malicious links.


### T1204.002 - User Execution: Malicious File
An adversary may rely upon a user opening a malicious file in order to gain execution. Users may be subjected to social engineering to get them to open a file that will lead to code execution. This user action will typically be observed as follow-on behavior from Spearphishing Attachment. Adversaries may use several types of files that require a user to execute them, including .doc, .pdf, .xls, .rtf, .scr, .exe, .lnk, .pif, .cpl, .reg, and .iso. Adversaries may employ various forms of Masquerading and Obfuscated Files or Information to increase the likelihood that a user will open and successfully execute a malicious file. These methods may include using a familiar naming convention and/or password protecting the file and supplying instructions to a user on how to open it. While Malicious File frequently occurs shortly after Initial Access it may occur at other phases of an intrusion, such as when an adversary places a file in a shared directory or on a user's desktop hoping that a user will click on it. This activity may also be seen shortly after Internal Spearphishing.
**Detection**
- [AN0819] **[Windows]** User opens a file delivered by email, web, chat, or share. The handler application (Word/PDF reader/archiver) creates a file in user-controlled paths (Downloads, Temp, Desktop) and then spawns a new or unusual child process (e.g., powershell.exe, wscript.exe, cmd.exe, regsvr32.exe, rundll32.exe, msiexec.exe). Optional precursors include FileStreamCreated (URL/UNC) and Office → system32 batch writes.
  - **Log sources:** `WinEventLog:Sysmon` (EventCode=11) [File Creation], `WinEventLog:Sysmon` (EventCode=1) [Process Creation], `WinEventLog:Sysmon` (EventCode=15) [File Metadata]
- [AN0820] **[macOS]** User opens a downloaded document/installer leading to EndpointSecurity file create in ~/Downloads or ~/Library paths then an exec of a suspicious utility (osascript, bash/zsh, curl, chmod, open with -a Terminal). Correlates File Creation with subsequent process exec and, optionally, quarantine/LSQuarantine events.
  - **Log sources:** `macos:unifiedlog` (process_exec: image in {/bin/bash,/bin/zsh,/usr/bin/osascript,/usr/bin/python*,/usr/bin/curl,/usr/bin/ssh,/usr/bin/open} AND parent in {Preview, TextEdit, Microsoft Word, Microsoft Excel, AdobeReader, Archive Utility, Finder}) [Process Creation], `macos:endpointsecurity` (ES_EVENT_TYPE_NOTIFY_CREATE: path under /Users/*/(Downloads|Desktop|Library/*/Containers|Library/Group Containers) AND extension in SuspiciousExtensions) [File Creation]
- [AN0821] **[Linux]** User or desktop application writes a new file to ~/Downloads, /tmp, or mounted removable media followed by execve of a risky interpreter/loader (bash, sh, python, perl, php, node, curl|wget piping to sh, ld.so, rdesktop, xdg-open - with unusual args). Uses auditd PATH+SYSCALL (open/creat/write/rename) with execve event linking.
  - **Log sources:** `auditd:SYSCALL` (open/create/rename: name in (/home/*/Downloads/*|/tmp/*|/run/user/*|/media/*) AND ext in SuspiciousExtensions) [File Creation], `auditd:SYSCALL` (execve: exe in {/bin/bash,/bin/sh,/usr/bin/python*,/usr/bin/perl,/usr/bin/php,/usr/bin/node,/usr/bin/curl,/usr/bin/wget,/usr/bin/xdg-open,/usr/bin/ssh,/usr/bin/rundll32 (wine)} AND ppid process is a document viewer/browser) [Process Creation]
**Procedure Examples**
- [G1026] Malteiro: Malteiro has relied on users to execute .zip file attachments containing malicious URLs.
- [S0669] KOCTOPUS: KOCTOPUS has relied on victims clicking a malicious document for execution.
- [C0037] Water Curupira Pikabot Distribution: Water Curupira Pikabot Distribution delivered Pikabot installers as password-protected ZIP files containing heavily obfuscated JavaScript, or IMG files containing an LNK mimicking a Word document and a malicious DLL.
- [S0356] KONNI: KONNI has relied on a victim to enable malicious macros within an attachment delivered via email.
- [G0005] APT12: APT12 has attempted to get victims to open malicious Microsoft Word and PDF attachment sent via spearphishing.
- [S0453] Pony: Pony has attempted to lure targets into downloading an attached executable (ZIP, RAR, or CAB archives) or document (PDF or other MS Office format).
- [G0094] Kimsuky: Kimsuky has attempted to lure victims into opening malicious e-mail attachments. Kimsuky has also lured victims with tailored filenames and fake extensions that entice victims to open LNK files.
- [G0095] Machete: Machete has relied on users opening malicious attachments delivered through spearphishing to execute malware.
- [S0631] Chaes: Chaes requires the user to click on the malicious Word document to execute the next part of the attack.
- [S1064] SVCReady: SVCReady has relied on users clicking a malicious attachment delivered through spearphishing.


### T1204.003 - User Execution: Malicious Image
Adversaries may rely on a user running a malicious image to facilitate execution. Amazon Web Services (AWS) Amazon Machine Images (AMIs), Google Cloud Platform (GCP) Images, and Azure Images as well as popular container runtimes such as Docker can be backdoored. Backdoored images may be uploaded to a public repository via Upload Malware, and users may then download and deploy an instance or container from the image without realizing the image is malicious, thus bypassing techniques that specifically achieve Initial Access. This can lead to the execution of malicious code, such as code that executes cryptocurrency mining, in the instance or container. Adversaries may also name images a certain way to increase the chance of users mistakenly deploying an instance or container from the image (ex: Match Legitimate Resource Name or Location).
**Detection**
- [AN0691] **[Linux]** CONTAINERS (Docker/K8s/containerd): A user pulls an untrusted image from a public/unknown registry and then creates/starts a container from that image. Shortly after start, the container spawns unexpected utilities (e.g., curl/wget/bash/python), or makes outbound network connections atypical for the namespace/workload. The analytic correlates Image Creation/Download → Container Creation → Container Start → Command Execution/Network activity within a short window and with a consistent image digest.
  - **Log sources:** `containerd:events` (Image pull from untrusted registry (name NOT IN allowlist) or new digest never seen before) [Image Creation], `kubernetes:audit` (create: Pod/Container created with image tag 'latest' or mutable tag; imagePullPolicy=Always; noDigest=true) [Container Creation], `kubernetes:events` (start: ContainerStarted or Pulling image → Started container) [Container Start], `auditd:SYSCALL` (execve: Process in container namespace executes curl|wget|bash|sh|python|nc with outbound args) [Command Execution], `NSM:Flow` (New egress from container IP/namespace to Internet or non-approved CIDRs/ASNs) [Network Traffic Content]
- [AN0692] **[Windows]** IAAS (Cloud images/VMs): A new VM/instance is launched from a non-approved or newly-seen image (AMI/GCP Image/Azure Image). On first boot, cloud-init/user-data or embedded agents download code, spawn system utilities, or open outbound C2/mining traffic. The analytic correlates Instance/Image Creation → Instance Start → in-guest Process/Command Execution and/or anomalous network traffic.
  - **Log sources:** `AWS:CloudTrail` (RunInstances) [Instance Start], `azure:activity` (Microsoft.Compute/virtualMachines/write: imageReference publisher NOT IN allowlist OR plan is new/unknown) [Instance Creation], `WinEventLog:Sysmon` (EventCode=1) [Process Creation], `NSM:Flow` (New VM egress to crypto-mining pools or non-approved Internet ranges within minutes of boot) [Network Traffic Content]
**Procedure Examples**
- [G0139] TeamTNT: TeamTNT has relied on users to download and execute malicious Docker images.


### T1204.004 - User Execution: Malicious Copy and Paste
An adversary may rely upon a user copying and pasting code in order to gain execution. Users may be subjected to social engineering to get them to copy and paste code directly into a Command and Scripting Interpreter. One such strategy is "ClickFix," in which adversaries present users with seemingly helpful solutions—such as prompts to fix errors or complete CAPTCHAs—that instead instruct the user to copy and paste malicious code. Malicious websites, such as those used in Drive-by Compromise, may present fake error messages or CAPTCHA prompts that instruct users to open a terminal or the Windows Run Dialog box and execute an arbitrary command. These commands may be obfuscated using encoding or other techniques to conceal malicious intent. Once executed, the adversary will typically be able to establish a foothold on the victim's machine. Adversaries may also leverage phishing emails for this purpose. When a user attempts to open an attachment, they may be presented with a fake error and offered a malicious command to paste as a solution, consistent with the "ClickFix" strategy. Tricking a user into executing a command themselves may help to bypass email filtering, browser sandboxing, or other mitigations designed to protect users against malicious downloaded files.
**Detection**
- [AN0963] **[Linux]** User pastes a multi-line or one-liner into a terminal (bash/zsh) that downloads/decodes and executes content. Chain: terminal exec of curl/wget/bash/sh with pipe to interpreter or base64-decode → transient file under /tmp|~/.cache → immediate outbound egress.
  - **Log sources:** `auditd:SYSCALL` (execve: exe in (/usr/bin/bash,/usr/bin/sh,/usr/bin/zsh,/usr/bin/python*) AND cmdline matches '(curl|wget).*(\||\|\s*sh|bash)|base64\s*-d|python\s*-c') [Process Creation], `auditd:SYSCALL` (open: File creation under /tmp, /var/tmp, ~/.cache with executable bit or shell shebang) [File Creation], `NSM:Flow` (New egress to Internet by the same UID/host shortly after terminal exec) [Network Connection Creation]
- [AN0962] **[Windows]** A user is socially engineered (web page, email, document) to open Run/PowerShell/CMD and paste an obfuscated one-liner. The chain is: (1) user context active in a browser/email/office app → (2) process creation of a command interpreter with suspicious arguments (base64/Invoke-Expression/web download/pipeline to shell) → (3) optional file drop in %TEMP% or %APPDATA% → (4) outbound network connection to an external domain. Events are correlated within a short window and with consistent user/session.
  - **Log sources:** `WinEventLog:Security` (EventCode=4688) [Process Creation], `WinEventLog:PowerShell` (EventCode=4103, 4104, 4105, 4106) [Command Execution], `WinEventLog:Sysmon` (EventCode=11) [File Creation], `WinEventLog:Sysmon` (EventCode=3, 22) [Network Connection Creation], `NSM:Flow` (HTTP(S) requests with User-Agents typical of PowerShell or curl from desktop; or URIs matching paste-inspired payload hosts) [Network Traffic Content]
- [AN0964] **[macOS]** User pastes an obfuscated command into Terminal.app/iTerm2 that decodes or downloads code and executes. Detects Terminal/iTerm2 spawning bash/zsh/python with suspicious pipeline/base64 patterns followed by file writes in ~/Library or /tmp and outbound network connections.
  - **Log sources:** `macos:unifiedlog` (exec: ParentImage in (Terminal, iTerm2) AND Image in (/bin/zsh,/bin/bash,/usr/bin/python*) AND CommandLine matches '(curl|wget).*(\||\|\s*sh|bash)|base64 -D|python -c') [Process Creation], `macos:osquery` (Interpreter exec with suspicious arguments as above) [Command Execution], `macos:unifiedlog` (create: New files in /tmp or ~/Library/Application Support/* with executable or script extensions) [File Creation], `NSM:Flow` (Egress to non-approved networks from host after terminal exec) [Network Traffic Content]
**Procedure Examples**
- [S1229] Havoc: The Havoc infection chain has been initiated via ClickFix lures in phishing emails.
- [G1052] Contagious Interview: Contagious Interview has leveraged ClickFix type tactics enticing victims to copy and paste malicious code.


### T1204.005 - User Execution: Malicious Library
Adversaries may rely on a user installing a malicious library to facilitate execution. Threat actors may Upload Malware to package managers such as NPM and PyPi, as well as to public code repositories such as GitHub. User may install libraries without realizing they are malicious, thus bypassing techniques that specifically achieve Initial Access. This can lead to the execution of malicious code, such as code that establishes persistence, steals data, or mines cryptocurrency. In some cases, threat actors may compromise and backdoor existing popular libraries (i.e., Compromise Software Dependencies and Development Tools). Alternatively, they may create entirely new packages and leverage behaviors such as typosquatting to encourage users to install them.
**Detection**
- [AN0699] **[Windows]** Execution of `pip.exe`, `npm.cmd`, or MSI installers within user context, followed by script interpreter startup (e.g., python.exe) or PowerShell with unusual child processes or file writes in `%APPDATA%`, `%TEMP%`, or `%LOCALAPPDATA%`. Defender correlates command-line install tools with Sysmon and Event Logs to trace downstream behavior.
  - **Log sources:** `WinEventLog:Sysmon` (EventCode=1) [Process Creation], `WinEventLog:Sysmon` (EventCode=11) [File Creation]
- [AN0698] **[Linux]** User-initiated installation of Python (pip), NodeJS (npm), or other language libraries, followed by unexpected network connections, credential access, or startup file modifications. Defender sees `pip install` or `npm install` commands run by a non-root user, followed shortly by new `.py`, `.sh`, or `.js` files in hidden directories, or interpreter-based execution during boot/login.
  - **Log sources:** `auditd:SYSCALL` (execve: Execution of pip, npm, gem, or similar package managers) [Process Creation], `auditd:PATH` (New .py/.js/.sh files written to ~/.local/, ~/.cache/, or /tmp/ within 5 min of package install) [File Creation], `NSM:Flow` (http::request: Network connection to package registry or C2 from interpreter shortly after install) [Network Traffic Content]
- [AN0700] **[macOS]** Execution of Homebrew, pip3, npm, or manually downloaded PKGs from Terminal or shell, followed by the creation of startup agents, interpreter spawns, or outbound connections to unfamiliar domains. Defender links Terminal commands to plist creation, unsigned binary launches, and `python3` or `node` processes connecting to remote endpoints.
  - **Log sources:** `macos:unifiedlog` (Command line invocation of pip3, brew install, npm install from interactive Terminal) [Process Creation], `macos:unifiedlog` (Creation of new LaunchAgent or LoginItem plist files in ~/Library/LaunchAgents/) [File Metadata], `NSM:Flow` (Outbound HTTP/S initiated by newly installed interpreter process) [Network Connection Creation]
**Procedure Examples**
- [G1052] Contagious Interview: Contagious Interview has relied on users to install a malicious library from a code repository to infect the victim's device and has led to additional payload distribution and theft of sensitive data.


### T1559 - Inter-Process Communication
Adversaries may abuse inter-process communication (IPC) mechanisms for local code or command execution. IPC is typically used by processes to share data, communicate with each other, or synchronize execution. IPC is also commonly used to avoid situations such as deadlocks, which occurs when processes are stuck in a cyclic waiting pattern. Adversaries may abuse IPC to execute arbitrary code or commands. IPC mechanisms may differ depending on OS, but typically exists in a form accessible through programming languages/libraries or native interfaces such as Windows Dynamic Data Exchange or Component Object Model. Linux environments support several different IPC mechanisms, two of which being sockets and pipes. Higher level execution mediums, such as those of Command and Scripting Interpreters, may also leverage underlying IPC mechanisms. Adversaries may also use Remote Services such as Distributed Component Object Model to facilitate remote IPC execution.
**Detection**
- [AN1357] **[Windows]** Detects anomalous use of COM, DDE, or named pipes for execution. Correlates creation or access of IPC mechanisms (e.g., named pipes, COM objects) with unusual parent-child process relationships or code injection patterns (e.g., Office spawning cmd.exe via DDE).
  - **Log sources:** `WinEventLog:Security` (EventCode=4663, 4670, 4656) [Process Access], `WinEventLog:Sysmon` (EventCode=17) [Named Pipe Metadata]
- [AN1359] **[macOS]** Detects anomalous use of Mach ports, Apple Events, or XPC services for inter-process execution or code injection. Focuses on unexpected processes attempting to send privileged Apple Events (e.g., automation scripts injecting into security-sensitive apps).
  - **Log sources:** `macos:unifiedlog` (Unusual Mach port registration or access attempts between unrelated processes) [Process Access], `macos:osquery` (exec: Unexpected execution of osascript or AppleScript targeting sensitive apps) [Script Execution]
- [AN1358] **[Linux]** Detects abuse of UNIX domain sockets, pipes, or message queues for unauthorized code execution. Correlates unexpected socket creation with suspicious binaries, abnormal shell pipelines, or injected processes establishing IPC channels.
  - **Log sources:** `auditd:SYSCALL` (socket: Suspicious creation of AF_UNIX sockets outside expected daemons) [Process Creation], `auditd:SYSCALL` (open: Access to named pipes or FIFO in /tmp or /dev/shm by unexpected processes) [File Access]
**Procedure Examples**
- [S1229] Havoc: The Havoc SMB demon can use named pipes for communication through a parent demon.
- [S1200] StealBit: StealBit can use interprocess communication (IPC) to enable the designation of multiple files for exfiltration in a scalable manner.
- [S1130] Raspberry Robin: Raspberry Robin contains an embedded custom Tor network client that communicates with the primary payload via shared process memory.
- [C0048] Operation MidnightEclipse: During Operation MidnightEclipse, threat actors wrote output to stdout then piped it to bash for execution.
- [C0057] 3CX Supply Chain Attack: During the 3CX Supply Chain Attack, AppleJeus's VEILEDSIGNAL creates and listens on a Windows named pipe to exchange messages between modules.
- [S1150] ROADSWEEP: ROADSWEEP can pipe command output to a targeted process.
- [S1123] PITSTOP: PITSTOP can listen over the Unix domain socket located at `/data/runtime/cockpit/wd.fd`.
- [S0022] Uroburos: Uroburos has the ability to move data between its kernel and user mode components, generally using named pipes.
- [S0537] HyperStack: HyperStack can connect to the IPC$ share on remote machines.
- [S1172] OilBooster: OilBooster can read the results of command line execution via an unnamed pipe connected to the process.


### T1559.001 - Inter-Process Communication: Component Object Model
Adversaries may use the Windows Component Object Model (COM) for local code execution. COM is an inter-process communication (IPC) component of the native Windows application programming interface (API) that enables interaction between software objects, or executable code that implements one or more interfaces. Through COM, a client object can call methods of server objects, which are typically binary Dynamic Link Libraries (DLL) or executables (EXE). Remote COM execution is facilitated by Remote Services such as Distributed Component Object Model (DCOM). Various COM interfaces are exposed that can be abused to invoke arbitrary execution via a variety of programming languages such as C, C++, Java, and Visual Basic. Specific COM objects also exist to directly perform functions beyond code execution, such as creating a Scheduled Task/Job, fileless download/execution, and other adversary behaviors related to privilege escalation and persistence.
**Detection**
- [AN0628] **[Windows]** Detects anomalous use of COM objects for execution, such as Office applications spawning scripting engines, enumeration of COM interfaces via registry queries, or processes loading atypical DLLs through COM activation. Correlates process creation, module loads, and registry queries to flag suspicious COM-based code execution or persistence.
  - **Log sources:** `WinEventLog:Sysmon` (EventCode=1) [Process Creation], `WinEventLog:Sysmon` (EventCode=7) [Module Load], `WinEventLog:Security` (EventCode=4663, 4670, 4656) [Windows Registry Key Access]
**Procedure Examples**
- [S0223] POWERSTATS: POWERSTATS can use DCOM (targeting the 127.0.0.1 loopback address) to execute additional payloads on compromised hosts.
- [S0266] TrickBot: TrickBot used COM to setup scheduled task for persistence.
- [S1236] CLAIMLOADER: CLAIMLOADER has leveraged Component Object Model (COM) objects to create a scheduled task using `ITaskService` interface.
- [S0260] InvisiMole: InvisiMole can use the ITaskService, ITaskDefinition and ITaskSettings COM interfaces to schedule a task.
- [S1044] FunnyDream: FunnyDream can use com objects identified with `CLSID_ShellLink`(`IShellLink` and `IPersistFile`) and `WScript.Shell`(`RegWrite` method) to enable persistence mechanisms.
- [G0069] MuddyWater: MuddyWater has used malware that has the capability to execute malicious code via COM, DCOM, and Outlook.
- [S0386] Ursnif: Ursnif droppers have used COM objects to execute the malware's full executable payload.
- [S1015] Milan: Milan can use a COM component to generate scheduled tasks.
- [S1160] Latrodectus: Latrodectus can use the Windows Component Object Model (COM) to set scheduled tasks.
- [G0047] Gamaredon Group: Gamaredon Group malware can insert malicious macros into documents using a Microsoft.Office.Interop object.


### T1559.002 - Inter-Process Communication: Dynamic Data Exchange
Adversaries may use Windows Dynamic Data Exchange (DDE) to execute arbitrary commands. DDE is a client-server protocol for one-time and/or continuous inter-process communication (IPC) between applications. Once a link is established, applications can autonomously exchange transactions consisting of strings, warm data links (notifications when a data item changes), hot data links (duplications of changes to a data item), and requests for command execution. Object Linking and Embedding (OLE), or the ability to link data between documents, was originally implemented through DDE. Despite being superseded by Component Object Model, DDE may be enabled in Windows 10 and most of Microsoft Office 2016 via Registry keys. Microsoft Office documents can be poisoned with DDE commands, directly or through embedded files, and used to deliver execution via Phishing campaigns or hosted Web content, avoiding the use of Visual Basic for Applications (VBA) macros. Similarly, adversaries may infect payloads to execute applications and/or commands on a victim device by way of embedding DDE formulas within a CSV file intended to be opened through a Windows spreadsheet program. DDE could also be leveraged by an adversary operating on a compromised machine who does not have direct access to a Command and Scripting Interpreter. DDE execution can be invoked remotely via Remote Services such as Distributed Component Object Model (DCOM).
**Detection**
- [AN1393] **[Windows]** Detects anomalous use of Dynamic Data Exchange (DDE) for code execution, such as Office applications (WINWORD.EXE, EXCEL.EXE) spawning command interpreters, or loading unusual modules through DDEAUTO/DDE formulas. Correlates suspicious parent-child process relationships, registry keys enabling DDE, and module loads inconsistent with normal Office usage.
  - **Log sources:** `WinEventLog:Sysmon` (EventCode=1) [Process Creation], `WinEventLog:Sysmon` (EventCode=7) [Module Load], `WinEventLog:Security` (EventCode=4663, 4670, 4656) [Windows Registry Key Access]
**Procedure Examples**
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


### T1559.003 - Inter-Process Communication: XPC Services
Adversaries can provide malicious content to an XPC service daemon for local code execution. macOS uses XPC services for basic inter-process communication between various processes, such as between the XPC Service daemon and third-party application privileged helper tools. Applications can send messages to the XPC Service daemon, which runs as root, using the low-level XPC Service C API or the high level NSXPCConnection API in order to handle tasks that require elevated privileges (such as network connections). Applications are responsible for providing the protocol definition which serves as a blueprint of the XPC services. Developers typically use XPC Services to provide applications stability and privilege separation between the application client and the daemon. Adversaries can abuse XPC services to execute malicious content. Requests for malicious execution can be passed through the application's XPC Services handler. This may also include identifying and abusing improper XPC client validation and/or poor sanitization of input parameters to conduct Exploitation for Privilege Escalation.
**Detection**
- [AN0948] **[macOS]** Detects anomalous use of macOS XPC services for code execution. Monitors for processes invoking privileged XPC daemons with abnormal parameters, unexpected binaries communicating over NSXPCConnection, or helper tools executing code outside of their expected parent process lineage. Correlates process access attempts to system-level daemons, privilege escalations via XPC misconfigurations, and injection of malicious payloads through inter-process communication.
  - **Log sources:** `macos:unifiedlog` (Unexpected NSXPCConnection calls by non-Apple-signed or abnormal binaries) [Process Access], `macos:unifiedlog` (execve: Helper tools invoked through XPC executing unexpected binaries) [Process Creation], `macos:unifiedlog` (XPC messages requesting privileged actions from untrusted or unsigned clients) [Named Pipe Metadata]
Adversaries can provide malicious content to an XPC service daemon for local code execution. macOS uses XPC services for basic inter-process communication between various processes, such as between the XPC Service daemon and third-party application privileged helper tools. Applications can send messages to the XPC Service daemon, which runs as root, using the low-level XPC Service C API or the high level NSXPCConnection API in order to handle tasks that require elevated privileges (such as network connections). Applications are responsible for providing the protocol definition which serves as a blueprint of the XPC services. Developers typically use XPC Services to provide applications stability and privilege separation between the application client and the daemon. Adversaries can abuse XPC services to execute malicious content. Requests for malicious execution can be passed through the application's XPC Services handler. This may also include identifying and abusing improper XPC client validation and/or poor sanitization of input parameters to conduct Exploitation for Privilege Escalation.


### T1569 - System Services
Adversaries may abuse system services or daemons to execute commands or programs. Adversaries can execute malicious content by interacting with or creating services either locally or remotely. Many services are set to run at boot, which can aid in achieving persistence (Create or Modify System Process), but adversaries can also abuse services for one-time or temporary execution.
**Detection**
- [AN0780] **[macOS]** Monitor launchd service definitions and property list (.plist) modifications for non-standard executables. Detect unauthorized processes registered as launch daemons or agents.
  - **Log sources:** `macos:unifiedlog` (Unexpected processes registered with launchd) [Process Creation], `macos:unifiedlog` (Modification of LaunchAgents or LaunchDaemons plist files) [File Modification]
- [AN0779] **[Linux]** Detect unusual invocations of systemctl, service, or init scripts creating or modifying daemons. Monitor audit logs for execution of binaries from unexpected paths linked to service start/stop activity.
  - **Log sources:** `auditd:SYSCALL` (execve) [Process Creation], `linux:syslog` (systemctl start/enable with uncommon binary paths) [Service Creation], `auditd:SYSCALL` (write) [File Modification]
- [AN0778] **[Windows]** Monitor for abnormal creation or modification of Windows services (e.g., via sc.exe, PowerShell, or API calls) that load non-standard executables. Correlate registry changes in service keys with service creation events and process execution to detect service abuse for persistence or execution.
  - **Log sources:** `WinEventLog:Security` (EventCode=4697) [Service Creation], `WinEventLog:Sysmon` (EventCode=1) [Process Creation], `WinEventLog:Sysmon` (EventCode=13, 14) [Windows Registry Key Modification]
Adversaries may abuse system services or daemons to execute commands or programs. Adversaries can execute malicious content by interacting with or creating services either locally or remotely. Many services are set to run at boot, which can aid in achieving persistence (Create or Modify System Process), but adversaries can also abuse services for one-time or temporary execution.


### T1569.001 - System Services: Launchctl
Adversaries may abuse launchctl to execute commands or programs. Launchctl interfaces with launchd, the service management framework for macOS. Launchctl supports taking subcommands on the command-line, interactively, or even redirected from standard input. Adversaries use launchctl to execute commands and programs as Launch Agents or Launch Daemons. Common subcommands include: launchctl load,launchctl unload, and launchctl start. Adversaries can use scripts or manually run the commands launchctl load -w "%s/Library/LaunchAgents/%s" or /bin/launchctl load to execute Launch Agents or Launch Daemons.
**Detection**
- [AN0736] **[macOS]** Abuse of launchctl to execute or manage Launch Agents and Daemons. Defender perspective: correlation of suspicious plist file creation or modification in LaunchAgents/LaunchDaemons directories with subsequent execution of the launchctl command. Abnormal executable paths (e.g., /tmp, /Shared) or launchctl activity followed by network connections are highly suspicious.
  - **Log sources:** `macos:unifiedlog` (execution of launchctl load/unload/start commands) [Command Execution], `macos:unifiedlog` (write of plist files in /Library/LaunchAgents or /Library/LaunchDaemons) [File Modification], `macos:unifiedlog` (launchctl spawning new processes) [Process Creation], `macos:unifiedlog` (creation or loading of new launchd services) [Service Creation]
**Procedure Examples**
- [S0451] LoudMiner: LoudMiner launched the QEMU services in the /Library/LaunchDaemons/ folder using launchctl. It also uses launchctl to unload all Launch Daemons when updating to a newer version of LoudMiner.
- [S1153] Cuckoo Stealer: Cuckoo Stealer can use `launchctl` to load a LaunchAgent for persistence.
- [S0584] AppleJeus: AppleJeus has loaded a plist file using the launchctl command.
- [S1048] macOS.OSAMiner: macOS.OSAMiner has used `launchctl` to restart the Launch Agent.
- [S0658] XCSSET: XCSSET loads a system level launchdaemon using the launchctl load -w command from /System/Librarby/LaunchDaemons/ssh.plist.
- [S0274] Calisto: Calisto uses launchctl to enable screen sharing on the victim’s machine.


### T1569.002 - System Services: Service Execution
Adversaries may abuse the Windows service control manager to execute malicious commands or payloads. The Windows service control manager (services.exe) is an interface to manage and manipulate services. The service control manager is accessible to users via GUI components as well as system utilities such as sc.exe and Net. PsExec can also be used to execute commands or payloads via a temporary Windows service created through the service control manager API. Tools such as PsExec and sc.exe can accept remote servers as arguments and may be used to conduct remote execution. Adversaries may leverage these mechanisms to execute malicious content. This can be done by either executing a new or modified service. This technique is the execution used in conjunction with Windows Service during service persistence or privilege escalation.
**Detection**
- [AN1185] **[Windows]** Detection focuses on abnormal service executions initiated via service control manager APIs, sc.exe, net.exe, or PsExec creating temporary services. Defenders observe process creation of services.exe spawning non-standard binaries, registry changes in service keys followed by rapid execution, and network connections originating from processes tied to transient services. Correlation across process lineage, registry activity, and service logs provides strong signals of malicious service execution.
  - **Log sources:** `WinEventLog:Security` (EventCode=4697) [Service Creation], `WinEventLog:Sysmon` (EventCode=1) [Process Creation], `WinEventLog:Sysmon` (EventCode=13, 14) [Windows Registry Key Modification], `WinEventLog:Sysmon` (EventCode=3, 22) [Network Connection Creation]
**Procedure Examples**
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


### T1569.003 - System Services: Systemctl
Adversaries may abuse systemctl to execute commands or programs. Systemctl is the primary interface for systemd, the Linux init system and service manager. Typically invoked from a shell, Systemctl can also be integrated into scripts or applications. Adversaries may use systemctl to execute commands or programs as Systemd Services. Common subcommands include: `systemctl start`, `systemctl stop`, `systemctl enable`, `systemctl disable`, and `systemctl status`.
**Detection**
- [AN0200] **[Linux]** Abuse of systemctl to execute commands or manage systemd services. Defender perspective: correlate suspicious service creation or modification with execution of systemctl subcommands such as start, enable, or status. Detect cases where systemctl is used to load services from unusual locations (e.g., /tmp, /dev/shm) or where new service units are created outside of expected administrative workflows.
  - **Log sources:** `auditd:EXECVE` (execution of systemctl with subcommands start, stop, enable, disable) [Command Execution], `auditd:SYSCALL` (open/write of .service unit files) [File Modification], `auditd:EXECVE` (systemctl spawning managed processes) [Process Creation], `auditd:CONFIG_CHANGE` (creation or modification of systemd services) [Service Creation]
**Procedure Examples**
- [G0139] TeamTNT: TeamTNT has created system services to execute cryptocurrency mining software.


### T1609 - Container Administration Command
Adversaries may abuse a container administration service to execute commands within a container. A container administration service such as the Docker daemon, the Kubernetes API server, or the kubelet may allow remote management of containers within an environment. In Docker, adversaries may specify an entrypoint during container deployment that executes a script or command, or they may use a command such as docker exec to execute a command within a running container. In Kubernetes, if an adversary has sufficient permissions, they may gain remote execution in a container in the cluster via interaction with the Kubernetes API server, the kubelet, or by running a command such as kubectl exec.
**Detection**
- [AN0177] **[Containers]** Defenders may detect abuse of container administration commands by observing anomalous use of management utilities (`docker exec`, `kubectl exec`, or API calls to kubelet) correlated with unexpected process creation inside containers. Behavioral chains include unauthorized API requests followed by command execution within running pods or containers, often originating from unusual user accounts, automation scripts, or IP addresses outside the expected cluster management plane.
  - **Log sources:** `docker:daemon` (docker exec or docker run with unexpected command/entrypoint) [Command Execution], `kubernetes:apiserver` (kubectl exec or kubelet API calls targeting running pods) [Process Creation]
**Procedure Examples**
- [G0139] TeamTNT: TeamTNT executed Hildegard through the kubelet API run command and by executing commands on running containers.
- [S0683] Peirates: Peirates can use `kubectl` or the Kubernetes API to run commands.
- [S0601] Hildegard: Hildegard was executed through the kubelet API run command and by executing commands on running containers.
- [S0623] Siloscape: Siloscape can send kubectl commands to victim clusters through an IRC channel and can run kubectl locally to spread once within a victim cluster.
- [S0599] Kinsing: Kinsing was executed with an Ubuntu container entry point that runs shell scripts.


### T1610 - Deploy Container
Adversaries may deploy a container into an environment to facilitate execution or evade defenses. In some cases, adversaries may deploy a new container to execute processes associated with a particular image or deployment, such as processes that execute or download malware. In others, an adversary may deploy a new container configured without network rules, user limitations, etc. to bypass existing defenses within the environment. In Kubernetes environments, an adversary may attempt to deploy a privileged or vulnerable container into a specific node in order to Escape to Host and access other containers running on the node. Containers can be deployed by various means, such as via Docker's create and start APIs or via a web application such as the Kubernetes dashboard or Kubeflow. In Kubernetes environments, containers may be deployed through workloads such as ReplicaSets or DaemonSets, which can allow containers to be deployed across multiple nodes. Adversaries may deploy containers based on retrieved or built malicious images or from benign images that download and execute malicious payloads at runtime.
**Detection**
- [AN0693] **[Containers]** Remote/API driven creation **and** start of a container whose image is not on an allow‑list (or is tagged `latest`), executed by a non-admin principal, and/or started with risky runtime attributes (e.g., `--privileged`, host PID/NET namespaces, sensitive host path mounts, capability adds). Correlates *create* ➜ *start* ➜ first network/process actions from that container within a short time window.
  - **Log sources:** `docker:daemon` (container_create,container_start) [Application Log Content], `containerd:runtime` (CRI CreateContainer/StartContainer with privileged=true OR added capabilities OR host* namespaces) [Container Start], `ebpf:syscalls` (process execution or network connect from just-created container PID namespace) [Process Creation], `docker:events` (remote API calls to /containers/create or /containers/{id}/start) [Network Traffic Content]
**Procedure Examples**
- [S0599] Kinsing: Kinsing was run through a deployed Ubuntu container.
- [G0139] TeamTNT: TeamTNT has deployed different types of containers into victim environments to facilitate execution. TeamTNT has also transferred cryptocurrency mining software to Kubernetes clusters discovered within local IP address ranges.
- [S0683] Peirates: Peirates can deploy a pod that mounts its node’s root file system, then execute a command to create a reverse shell on the node.
- [S0600] Doki: Doki was run through a deployed container.


### T1648 - Serverless Execution
Adversaries may abuse serverless computing, integration, and automation services to execute arbitrary code in cloud environments. Many cloud providers offer a variety of serverless resources, including compute engines, application integration services, and web servers. Adversaries may abuse these resources in various ways as a means of executing arbitrary commands. For example, adversaries may use serverless functions to execute malicious code, such as crypto-mining malware (i.e. Resource Hijacking). Adversaries may also create functions that enable further compromise of the cloud environment. For example, an adversary may use the `IAM:PassRole` permission in AWS or the `iam.serviceAccounts.actAs` permission in Google Cloud to add Additional Cloud Roles to a serverless cloud function, which may then be able to perform actions the original user cannot. Serverless functions can also be invoked in response to cloud events (i.e. Event Triggered Execution), potentially enabling persistent execution over time. For example, in AWS environments, an adversary may create a Lambda function that automatically adds Additional Cloud Credentials to a user and a corresponding CloudWatch events rule that invokes that function whenever a new user is created. This is also possible in many cloud-based office application suites. For example, in Microsoft 365 environments, an adversary may create a Power Automate workflow that forwards all emails a user receives or creates anonymous sharing links whenever a user is granted access to a document in SharePoint. In Google Workspace environments, they may instead create an Apps Script that exfiltrates a user's data when they open a file.
**Detection**
- [AN1055] **[SaaS]** Track creation or update of SaaS automation scripts (e.g., Google Workspace Apps Script). Detect when these scripts are bound to user events such as file opens or account modifications, and correlate with subsequent abnormal API calls that exfiltrate or modify user data.
  - **Log sources:** `saas:appsscript` (Create / Update: Deployment of scripts with event-driven triggers) [Cloud Service Modification], `saas:googledrive` (FileOpen / FileAccess: Event-driven script triggering on user file actions) [Application Log Content]
- [AN1053] **[IaaS]** Correlate creation or modification of serverless functions (e.g., AWS Lambda, GCP Cloud Functions, Azure Functions) with anomalous IAM role assignments or permissions escalation events. Detect subsequent executions of newly created functions that perform unexpected actions such as spawning outbound network connections, accessing sensitive resources, or creating additional credentials.
  - **Log sources:** `AWS:CloudTrail` (CreateFunction / UpdateFunctionConfiguration: Function creation, role assignment, or configuration change events) [Cloud Service Modification], `AWS:CloudTrail` (InvokeFunction: Unexpected or repeated invocation of functions not tied to known workflows) [Application Log Content]
- [AN1054] **[Office Suite]** Monitor for creation of new Power Automate flows or equivalent automation scripts that trigger on user or file events. Detect anomalous actions performed by these automations, such as email forwarding, anonymous link creation, or unexpected API calls to external endpoints.
  - **Log sources:** `m365:unified` (AddFlow / UpdateFlow: New automation or workflow creation events) [Cloud Service Modification], `m365:exchange` (New-InboxRule: Automation that triggers abnormal forwarding or external link generation) [Application Log Content]
**Procedure Examples**
- [S1091] Pacu: Pacu can create malicious Lambda functions.


### T1651 - Cloud Administration Command
Adversaries may abuse cloud management services to execute commands within virtual machines. Resources such as AWS Systems Manager, Azure RunCommand, and Runbooks allow users to remotely run scripts in virtual machines by leveraging installed virtual machine agents. If an adversary gains administrative access to a cloud environment, they may be able to abuse cloud management services to execute commands in the environment’s virtual machines. Additionally, an adversary that compromises a service provider or delegated administrator account may similarly be able to leverage a Trusted Relationship to execute commands in connected virtual machines.
**Detection**
- [AN1502] **[IaaS]** Monitor for suspicious use of cloud-native administrative command services (e.g., AWS Systems Manager Run Command, Azure RunCommand, GCP OS Config) to execute code inside VMs. Detect anomalies such as commands/scripts executed by unexpected users, execution outside of maintenance windows, or commands initiated by service accounts not normally tied to administration. Correlate cloud control-plane activity logs with host-level execution (process creation, script execution) to validate if commands materialized inside the guest OS.
  - **Log sources:** `AWS:CloudTrail` (SendCommand, StartSession, ExecuteCommand: Unexpected AWS Systems Manager command execution targeting EC2 instances) [Command Execution], `azure:activity` (Microsoft.Compute/virtualMachines/runCommand/action: Abnormal initiation of Azure RunCommand jobs or PowerShell/Bash payloads) [Script Execution], `azure:vmguest` (Unexpected execution of cloud agent processes (e.g., WindowsAzureGuestAgent.exe, ssm-agent) followed by arbitrary script or binary execution) [Process Creation]
**Procedure Examples**
- [G0016] APT29: APT29 has used Azure Run Command and Azure Admin-on-Behalf-of (AOBO) to execute code on virtual machines.
- [S0677] AADInternals: AADInternals can execute commands on Azure virtual machines using the VM agent.
- [S1091] Pacu: Pacu can run commands on EC2 instances using AWS Systems Manager Run Command.


### T1674 - Input Injection
Adversaries may simulate keystrokes on a victim’s computer by various means to perform any type of action on behalf of the user, such as launching the command interpreter using keyboard shortcuts, typing an inline script to be executed, or interacting directly with a GUI-based application. These actions can be preprogrammed into adversary tooling or executed through physical devices such as Human Interface Devices (HIDs). For example, adversaries have used tooling that monitors the Windows message loop to detect when a user visits bank-specific URLs. If detected, the tool then simulates keystrokes to open the developer console or select the address bar, pastes malicious JavaScript from the clipboard, and executes it - enabling manipulation of content within the browser, such as replacing bank account numbers during transactions. Adversaries have also used malicious USB devices to emulate keystrokes that launch PowerShell, leading to the download and execution of malware from adversary-controlled servers.
**Detection**
- [AN1567] **[Windows]** Detects suspicious USB HID device enumeration and keystroke injection patterns, such as rapid sequences of input with no user context, scripts executed through simulated keystrokes, or rogue devices presenting themselves as keyboards.
  - **Log sources:** `WinEventLog:System` (EventCode=2003) [Drive Creation], `WinEventLog:Security` (EventCode=4688) [Process Creation], `WinEventLog:PowerShell` (EventCode=4103, 4104, 4105, 4106) [Command Execution]
- [AN1569] **[macOS]** Detects abnormal HID device enumeration via I/O Registry (ioreg -p IOUSB) and keystroke injection targeting AppleScript, osascript, or PowerShell equivalents. Defender correlates new USB device connections with rapid script execution.
  - **Log sources:** `macos:unifiedlog` (New IOUSB keyboard/HID device enumerated with suspicious attributes) [Drive Creation], `macos:unifiedlog` (osascript, AppleScript, or Python execution triggered immediately after HID connection) [Script Execution]
- [AN1568] **[Linux]** Detects USB HID device enumeration under `/sys/bus/usb/devices/` and rapid keystroke injection resulting in command execution such as bash or Python scripts launched without interactive user activity.
  - **Log sources:** `auditd:SYSCALL` (execve: parent process is usb/hid device handler, child process bash/python invoked) [Process Creation], `linux:syslog` (New HID device enumeration with type 'keyboard' followed by immediate input injection) [Drive Creation]
**Procedure Examples**
- [G0046] FIN7: FIN7 has used malicious USBs to emulate keystrokes to launch PowerShell to download and execute malware from the adversary's server.


### T1675 - ESXi Administration Command
Adversaries may abuse ESXi administration services to execute commands on guest machines hosted within an ESXi virtual environment. Persistent background services on ESXi-hosted VMs, such as the VMware Tools Daemon Service, allow for remote management from the ESXi server. The tools daemon service runs as `vmtoolsd.exe` on Windows guest operating systems, `vmware-tools-daemon` on macOS, and `vmtoolsd ` on Linux. Adversaries may leverage a variety of tools to execute commands on ESXi-hosted VMs – for example, by using the vSphere Web Services SDK to programmatically execute commands and scripts via APIs such as `StartProgramInGuest`, `ListProcessesInGuest`, `ListFileInGuest`, and `InitiateFileTransferFromGuest`. This may enable follow-on behaviors on the guest VMs, such as File and Directory Discovery, Data from Local System, or OS Credential Dumping.
**Detection**
- [AN0646] **[ESXi]** Detects anomalous usage of ESXi Guest Operations APIs such as StartProgramInGuest, ListProcessesInGuest, ListFileInGuest, or InitiateFileTransferFromGuest. Defender perspective focuses on unusual frequency of guest API calls, invocation from unexpected management accounts, or execution outside of business hours. These correlated signals indicate adversarial abuse of ESXi administrative services to run commands on guest VMs.
  - **Log sources:** `esxi:hostd` (Guest Operations API invocation: StartProgramInGuest, ListProcessesInGuest, ListFileInGuest, InitiateFileTransferFromGuest) [Application Log Content]
**Procedure Examples**
- [S1217] VIRTUALPITA: VIRTUALPITA can execute commands on guest virtual machines from compromised ESXi hypervisors.
- [G1048] UNC3886: UNC3886 used `vmtoolsd.exe` to run commands on guest virtual machines from a compromised ESXi host.


### T1677 - Poisoned Pipeline Execution
Adversaries may manipulate continuous integration / continuous development (CI/CD) processes by injecting malicious code into the build process. There are several mechanisms for poisoning pipelines: * In a Direct Pipeline Execution scenario, the threat actor directly modifies the CI configuration file (e.g., `gitlab-ci.yml` in GitLab). They may include a command to exfiltrate credentials leveraged in the build process to a remote server, or to export them as a workflow artifact. * In an Indirect Pipeline Execution scenario, the threat actor injects malicious code into files referenced by the CI configuration file. These may include makefiles, scripts, unit tests, and linters. * In a Public Pipeline Execution scenario, the threat actor does not have direct access to the repository but instead creates a malicious pull request from a fork that triggers a part of the CI/CD pipeline. For example, in GitHub Actions, the `pull_request_target` trigger allows workflows running from forked repositories to access secrets. If this trigger is combined with an explicit pull request checkout and a location for a threat actor to insert malicious code (e.g., an `npm build` command), a threat actor may be able to leak pipeline credentials. Similarly, threat actors may craft pull requests with malicious inputs (such as branch names) if the build pipeline treats those inputs as trusted. Finally, if a pipeline leverages a self-hosted runner, a threat actor may be able to execute arbitrary code on a host inside the organization’s network. By poisoning CI/CD pipelines, threat actors may be able to gain access to credentials, laterally move to additional hosts, or input malicious components to be shipped further down the pipeline (i.e., Supply Chain Compromise).
**Detection**
- [AN1473] **[SaaS]** Detects anomalous CI/CD workflow execution originating from forked repositories, with pull request (PR) metadata or commit messages containing suspicious patterns (e.g., encoded payloads), coupled with the use of insecure pipeline triggers like `pull_request_target` or excessive API usage of CI/CD secrets. Correlation with unusual artifact generation or secret exfiltration via encoded or external network destination URLs confirms suspicious behavior.
  - **Log sources:** `saas:github` (Workflow triggered via pull_request_target from forked repo) [Cloud Service Modification], `saas:github` (CI/CD secret accessed or exported) [Cloud Service Metadata], `saas:github` (Artifact generated includes base64/encoded exfil payload or URL) [Cloud Storage Access], `saas:RepoEvents` (New file added or modified in PR targeting CI/CD or build config (e.g., `gitlab-ci.yml`, `build.gradle`, `pom.xml`, `.github/workflows/*.yml`)) [File Metadata], `saas:PRMetadata` (Commit message or branch name contains encoded strings or payload indicators) [Command Execution]
Adversaries may manipulate continuous integration / continuous development (CI/CD) processes by injecting malicious code into the build process. There are several mechanisms for poisoning pipelines: * In a Direct Pipeline Execution scenario, the threat actor directly modifies the CI configuration file (e.g., `gitlab-ci.yml` in GitLab). They may include a command to exfiltrate credentials leveraged in the build process to a remote server, or to export them as a workflow artifact. * In an Indirect Pipeline Execution scenario, the threat actor injects malicious code into files referenced by the CI configuration file. These may include makefiles, scripts, unit tests, and linters. * In a Public Pipeline Execution scenario, the threat actor does not have direct access to the repository but instead creates a malicious pull request from a fork that triggers a part of the CI/CD pipeline. For example, in GitHub Actions, the `pull_request_target` trigger allows workflows running from forked repositories to access secrets. If this trigger is combined with an explicit pull request checkout and a location for a threat actor to insert malicious code (e.g., an `npm build` command), a threat actor may be able to leak pipeline credentials. Similarly, threat actors may craft pull requests with malicious inputs (such as branch names) if the build pipeline treats those inputs as trusted. Finally, if a pipeline leverages a self-hosted runner, a threat actor may be able to execute arbitrary code on a host inside the organization’s network. By poisoning CI/CD pipelines, threat actors may be able to gain access to credentials, laterally move to additional hosts, or input malicious components to be shipped further down the pipeline (i.e., Supply Chain Compromise).

