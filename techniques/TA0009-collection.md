### T1005 - Data from Local System
Adversaries may search local system sources, such as file systems, configuration files, local databases, virtual machine files, or process memory, to find files of interest and sensitive data prior to Exfiltration. Adversaries may do this using a Command and Scripting Interpreter, such as cmd as well as a Network Device CLI, which have functionality to interact with the file system to gather information. Adversaries may also use Automated Collection on the local system.
**Detection**
- [AN1074] **[ESXi]** Adversaries accessing datastore or configuration files via `vim-cmd`, `esxcli`, or SCP to extract logs, VMs, or host configurations.
- [AN1071] **[Linux]** Adversaries using bash scripts or tools to recursively enumerate user home directories, config files, or SSH keys.
- [AN1070] **[Windows]** Adversaries collecting local files via PowerShell, WMI, or direct file API calls often include recursive file listings, targeted file reads, and temporary file staging.
- [AN1072] **[macOS]** Adversary use of bash/zsh or AppleScript to locate files and exfil targets like user keychains or documents.
- [AN1073] **[Network Devices]** Collection of device configuration via CLI commands (e.g., `show running-config`, `copy flash`, `more`), often followed by TFTP/SCP transfers.
**Procedure Examples**
- [S1196] Troll Stealer: Troll Stealer gathers information from infected systems such as SSH information from the victim's `.ssh` directory. Troll Stealer collects information from local FileZilla installations and Microsoft Sticky Note.
- [G0094] Kimsuky: Kimsuky has collected Office, PDF, and HWP documents from its victims.
- [G0060] BRONZE BUTLER: BRONZE BUTLER has exfiltrated files stolen from local systems.
- [S0238] Proxysvc: Proxysvc searches the local system and gathers data.
- [S0502] Drovorub: Drovorub can transfer files from the victim machine.
- [S0498] Cryptoistic: Cryptoistic can retrieve files from the local file system.
- [S0653] xCaon: xCaon has uploaded files from victims' machines.
- [G1004] LAPSUS$: LAPSUS$ uploaded sensitive files, information, and credentials from a targeted organization for extortion or public release.
- [C0048] Operation MidnightEclipse: During Operation MidnightEclipse, threat actors stole saved cookies and login data from targeted systems.
- [G0087] APT39: APT39 has used various tools to steal files from the compromised host.


### T1025 - Data from Removable Media
Adversaries may search connected removable media on computers they have compromised to find files of interest. Sensitive data can be collected from any removable media (optical disk drive, USB memory, etc.) connected to the compromised system prior to Exfiltration. Interactive command shells may be in use, and common functionality within cmd may be used to gather information. Some adversaries may also use Automated Collection on removable media.
**Detection**
- [AN1410] **[Windows]** Adversary mounts a USB device and begins enumerating, copying, or compressing files using scripting engines, cmd, or remote access tools.
- [AN1411] **[Linux]** Adversary mounts external drive to /media or /mnt then accesses or copies targeted data via shell, cp, or tar.
- [AN1412] **[macOS]** Adversary attaches USB drive and accesses sensitive files using Finder, cp, or bash scripts.
**Procedure Examples**
- [S0136] USBStealer: Once a removable media device is inserted back into the first victim, USBStealer collects data from it that was exfiltrated from a second victim.
- [S0260] InvisiMole: InvisiMole can collect jpeg files from connected MTP devices.
- [S0456] Aria-body: Aria-body has the ability to collect data from USB devices.
- [G0049] OilRig: OilRig has used Wireshark’s usbcapcmd utility to capture USB traffic.
- [S0569] Explosive: Explosive can scan all .exe files located in the USB drive.
- [S0237] GravityRAT: GravityRAT steals files based on an extension list if a USB drive is connected to the system.
- [S0090] Rover: Rover searches for files on attached removable drives based on a predefined list of file extensions every five seconds.
- [S1146] MgBot: MgBot includes modules capable of gathering information from USB thumb drives and CD-ROMs on the victim machine given a list of provided criteria.
- [G0047] Gamaredon Group: A Gamaredon Group file stealer has the capability to steal data from newly connected logical volumes on a system, including USB drives.
- [G0007] APT28: An APT28 backdoor may collect the entire contents of an inserted USB device.


### T1039 - Data from Network Shared Drive
Adversaries may search network shares on computers they have compromised to find files of interest. Sensitive data can be collected from remote systems via shared network drives (host shared directory, network file server, etc.) that are accessible from the current system prior to Exfiltration. Interactive command shells may be in use, and common functionality within cmd may be used to gather information.
**Detection**
- [AN1146] **[Linux]** Unusual access or copying of files from mounted network drives (e.g., NFS, CIFS/SMB) by user shells or scripts followed by large data transfer.
- [AN1147] **[macOS]** Detection of file access from mounted SMB shares followed by copy or exfil commands from Terminal or script interpreter processes.
- [AN1145] **[Windows]** Monitoring of file access to network shares (e.g., C$, Admin$) followed by unusual read or copy operations by processes not typically associated with such activity (e.g., PowerShell, certutil).
**Procedure Examples**
- [G1039] RedCurl: RedCurl has collected data about network drives.
- [S0050] CosmicDuke: CosmicDuke steals user files from network shared drives with file extensions and keywords that match a predefined list.
- [G0007] APT28: APT28 has collected files from network shared drives.
- [G0047] Gamaredon Group: Gamaredon Group malware has collected Microsoft Office documents from mapped network drives.
- [G0060] BRONZE BUTLER: BRONZE BUTLER has exfiltrated files stolen from file shares.
- [S0554] Egregor: Egregor can collect any files found in the enumerated drivers before sending it to its C2 channel.
- [G0054] Sowbug: Sowbug extracted Word documents from a file server on a victim network.
- [S0458] Ramsay: Ramsay can collect data from network drives and stage it for exfiltration.
- [S0128] BADNEWS: When it first starts, BADNEWS crawls the victim's mapped drives and collects documents with the following extensions: .doc, .docx, .pdf, .ppt, .pptx, and .txt.
- [G0114] Chimera: Chimera has collected data of interest from network shares.


### T1056 - Input Capture
Adversaries may use methods of capturing user input to obtain credentials or collect information. During normal system usage, users often provide credentials to various different locations, such as login pages/portals or system dialog boxes. Input capture mechanisms may be transparent to the user (e.g. Credential API Hooking) or rely on deceiving the user into providing input into what they believe to be a genuine service (e.g. Web Portal Capture).
**Detection**
- [AN0284] **[macOS]** Monitors for TCC-bypassing or unauthorized access to input services like IOHIDSystem or Quartz Event Services used in keylogging or screen monitoring.
- [AN0285] **[Network Devices]** Detects web-based credential phishing by analyzing traffic to suspicious URLs that mimic login portals and POST credential content.
- [AN0283] **[Linux]** Detects use of tools/scripts accessing input devices like /dev/input/* or evdev via suspicious processes lacking GUI context.
- [AN0282] **[Windows]** Monitors for abnormal process behavior and API calls like SetWindowsHookEx, GetAsyncKeyState, or device input polling commonly used for keystroke logging.
**Procedure Examples**
- [S1245] InvisibleFerret: InvisibleFerret has collected mouse and keyboard events using “pyWinhook”.
- [G1044] APT42: APT42 has used credential harvesting websites.
- [G1046] Storm-1811: Storm-1811 has used a PowerShell script to capture user credentials after prompting a user to authenticate to run a malicious script masquerading as a legitimate update item.
- [S1059] metaMain: metaMain can log mouse events.
- [S1060] Mafalda: Mafalda can conduct mouse event logging.
- [C0039] Versa Director Zero Day Exploitation: Versa Director Zero Day Exploitation intercepted and harvested credentials from user logins to compromised devices.
- [S0631] Chaes: Chaes has a module to perform any API hooking it desires.
- [C0049] Leviathan Australian Intrusions: Leviathan captured submitted multfactor authentication codes and other technical artifacts related to remote access sessions during Leviathan Australian Intrusions.
- [S0381] FlawedAmmyy: FlawedAmmyy can collect mouse events.
- [S0641] Kobalos: Kobalos has used a compromised SSH client to capture the hostname, port, username and password used to establish an SSH connection from the compromised host.


### T1056.001 - Input Capture: Keylogging
Adversaries may log user keystrokes to intercept credentials as the user types them. Keylogging is likely to be used to acquire credentials for new access opportunities when OS Credential Dumping efforts are not effective, and may require an adversary to intercept keystrokes on a system for a substantial period of time before credentials can be successfully captured. In order to increase the likelihood of capturing credentials quickly, an adversary may also perform actions such as clearing browser cookies to force users to reauthenticate to systems. Keylogging is the most prevalent type of input capture, with many different ways of intercepting keystrokes. Some methods include: * Hooking API callbacks used for processing keystrokes. Unlike Credential API Hooking, this focuses solely on API functions intended for processing keystroke data. * Reading raw keystroke data from the hardware buffer. * Windows Registry modifications. * Custom drivers. * Modify System Image may provide adversaries with hooks into the operating system of network devices to read raw keystrokes for login sessions.
**Detection**
- [AN0244] **[Linux]** Detects non-system processes accessing /dev/input/* or issuing ptrace/evdev syscalls used for reading keystroke buffers directly.
- [AN0246] **[Network Devices]** Keylogging on legacy network devices via unauthorized system image modification or remote capture of console keystrokes (telnet, SSH) through altered firmware or man-in-the-middle key sniffing.
- [AN0243] **[Windows]** Monitors suspicious usage of Windows API calls like SetWindowsHookEx, GetKeyState, or polling functions within non-UI service processes, combined with Registry or driver modifications.
- [AN0245] **[macOS]** Detects unauthorized TCC access or use of Quartz Event Services (CGEventTapCreate) or IOHID for event tap installation within unexpected processes.
**Procedure Examples**
- [G0059] Magic Hound: Magic Hound malware is capable of keylogging.
- [C0014] Operation Wocao: During Operation Wocao, threat actors obtained the password for the victim's password manager via a custom keylogger.
- [S0021] Derusbi: Derusbi is capable of logging keystrokes.
- [S1012] PowerLess: PowerLess can use a module to log keystrokes.
- [S0643] Peppy: Peppy can log keystrokes on compromised hosts.
- [S0670] WarzoneRAT: WarzoneRAT has the capability to install a live and offline keylogger, including through the use of the `GetAsyncKeyState` Windows API.
- [S0038] Duqu: Duqu can track key presses with a keylogger module.
- [S0283] jRAT: jRAT has the capability to log keystrokes from the victim’s machine, both offline and online.
- [S0455] Metamorfo: Metamorfo has a command to launch a keylogger and capture keystrokes on the victim’s machine.
- [S0045] ADVSTORESHELL: ADVSTORESHELL can perform keylogging.


### T1056.002 - Input Capture: GUI Input Capture
Adversaries may mimic common operating system GUI components to prompt users for credentials with a seemingly legitimate prompt. When programs are executed that need additional privileges than are present in the current user context, it is common for the operating system to prompt the user for proper credentials to authorize the elevated privileges for the task (ex: Bypass User Account Control). Adversaries may mimic this functionality to prompt users for credentials with a seemingly legitimate prompt for a number of reasons that mimic normal usage, such as a fake installer requiring additional access or a fake malware removal suite. This type of prompt can be used to collect credentials via various languages such as AppleScript and PowerShell. On Linux systems adversaries may launch dialog boxes prompting users for credentials from malicious shell scripts or the command line (i.e. Unix Shell). Adversaries may also mimic common software authentication requests, such as those from browsers or email clients. This may also be paired with user activity monitoring (i.e., Browser Information Discovery and/or Application Window Discovery) to spoof prompts when users are naturally accessing sensitive sites/data.
**Detection**
- [AN1442] **[macOS]** Detects AppleScript or Objective-C usage to generate fake authentication windows (e.g., using display dialog or NSAlert) from user-launched or persistence-related processes.
- [AN1441] **[Linux]** Detects GUI-based credential prompts invoked via zenity/kdialog/dialog or X11 APIs from non-user-facing scripts or background shell sessions, often with authentication-related text.
- [AN1440] **[Windows]** Detects suspicious use of PowerShell, .NET, or script interpreters to spawn processes that mimic UAC prompts, often with credential capture dialogue boxes invoked from non-standard parent processes.
**Procedure Examples**
- [S0279] Proton: Proton prompts users for their credentials.
- [S0278] iKitten: iKitten prompts the user for their credentials.
- [S0455] Metamorfo: Metamorfo has displayed fake forms on top of banking sites to intercept credentials from victims.
- [S0274] Calisto: Calisto presents an input prompt asking for the user's login and password.
- [S0276] Keydnap: Keydnap prompts the users for credentials.
- [G1039] RedCurl: RedCurl prompts the user for credentials through a Microsoft Outlook pop-up.
- [S0482] Bundlore: Bundlore prompts the user for their credentials.
- [G0085] FIN4: FIN4 has presented victims with spoofed Windows Authentication prompts to collect their credentials.
- [S0281] Dok: Dok prompts the user for credentials.
- [S1122] Mispadu: Mispadu can monitor browser activity for online banking actions and display full-screen overlay images to block user access to the intended site or present additional data fields.


### T1056.003 - Input Capture: Web Portal Capture
Adversaries may install code on externally facing portals, such as a VPN login page, to capture and transmit credentials of users who attempt to log into the service. For example, a compromised login page may log provided user credentials before logging the user in to the service. This variation on input capture may be conducted post-compromise using legitimate administrative access as a backup measure to maintain network access through External Remote Services and Valid Accounts or as part of the initial compromise by exploitation of the externally facing web service.
**Detection**
- [AN1321] **[Windows]** Detects tampering of IIS-based login pages (e.g., default.aspx, login.aspx) tied to VPN, OWA, or SharePoint via script injection or unexpected editor processes modifying web roots.
- [AN1320] **[Linux]** Detects unauthorized modifications to login-facing web server files (e.g., index.php, login.js) typically tied to VPN, SSO, or intranet portals. Correlates suspicious file changes with remote access artifacts or web shell behavior.
- [AN1322] **[macOS]** Detects unauthorized changes to locally hosted login pages on macOS (common in developer VPN environments) and links file edits to cron jobs, background scripts, or SUID binaries.
**Procedure Examples**
- [G1035] Winter Vivern: Winter Vivern registered and hosted domains to allow for creation of web pages mimicking legitimate government email logon sites to collect logon information.
- [C0030] Triton Safety Instrumented System Attack: In the Triton Safety Instrumented System Attack, TEMP.Veles captured credentials as they were being changed by redirecting text-based login codes to websites they controlled.
- [S1116] WARPWIRE: WARPWIRE can capture credentials submitted during the web logon process in order to access layer seven applications such as RDP.
- [S1022] IceApple: The IceApple OWA credential logger can monitor for OWA authentication requests and log the credentials.
- [C0029] Cutting Edge: During Cutting Edge, threat actors modified the JavaScript loaded by the Ivanti Connect Secure login page to capture credentials entered.


### T1056.004 - Input Capture: Credential API Hooking
Adversaries may hook into Windows application programming interface (API) functions and Linux system functions to collect user credentials. Malicious hooking mechanisms may capture API or function calls that include parameters that reveal user authentication credentials. Unlike Keylogging, this technique focuses specifically on API functions that include parameters that reveal user credentials. In Windows, hooking involves redirecting calls to these functions and can be implemented via: * **Hooks procedures**, which intercept and execute designated code in response to events such as messages, keystrokes, and mouse inputs. * **Import address table (IAT) hooking**, which use modifications to a process’s IAT, where pointers to imported API functions are stored. * **Inline hooking**, which overwrites the first bytes in an API function to redirect code flow. In Linux and macOS, adversaries may hook into system functions via the `LD_PRELOAD` (Linux) or `DYLD_INSERT_LIBRARIES` (macOS) environment variables, which enables loading shared libraries into a program’s address space. For example, an adversary may capture credentials by hooking into the `libc read` function leveraged by SSH or SCP.
**Detection**
- [AN0389] **[Windows]** Detects credential harvesting via userland API hooking (e.g., SetWindowsHookEx, IAT, or inline patching) by correlating memory modifications with hook installation functions and suspicious module loads in credential-sensitive processes like lsass.exe, explorer.exe, or winlogon.exe.
- [AN0391] **[macOS]** Detects DYLD_INSERT_LIBRARIES abuse to hook credential-sensitive applications by correlating process spawns with unauthorized library injection and monitoring changes to the __TEXT segment (code) of credential handling binaries.
- [AN0390] **[Linux]** Detects credential interception via malicious LD_PRELOAD-based shared libraries loaded into ssh, sudo, or scp processes. Correlates environment variable injection, unexpected library loads, and memory patching behavior.
**Procedure Examples**
- [S0330] Zeus Panda: Zeus Panda hooks processes by leveraging its own IAT hooked functions.
- [S1154] VersaMem: VersaMem hooked and overrided Versa's built-in authentication method, `setUserPassword`, to intercept plaintext credentials when submitted to the server.
- [S0484] Carberp: Carberp has hooked several Windows API functions to steal credentials.
- [S0182] FinFisher: FinFisher hooks processes by modifying IAT pointers to CreateWindowEx.
- [S0386] Ursnif: Ursnif has hooked APIs to perform a wide variety of information theft, such as monitoring traffic from browsers.
- [S0412] ZxShell: ZxShell hooks several API functions to spawn system threads.
- [G0068] PLATINUM: PLATINUM is capable of using Windows hook interfaces for information gathering such as credential access.
- [S0251] Zebrocy: Zebrocy installs an application-defined Windows hook to get notified when a network drive has been attached, so it can then use the hook to call its RecordToFile file stealing method.
- [S0416] RDFSNIFFER: RDFSNIFFER hooks several Win32 API functions to hijack elements of the remote system management user-interface.
- [S0363] Empire: Empire contains some modules that leverage API hooking to carry out tasks, such as netripper.


### T1074 - Data Staged
Adversaries may stage collected data in a central location or directory prior to Exfiltration. Data may be kept in separate files or combined into one file through techniques such as Archive Collected Data. Interactive command shells may be used, and common functionality within cmd and bash may be used to copy data into a staging location. In cloud environments, adversaries may stage data within a particular instance or virtual machine before exfiltration. An adversary may Create Cloud Instance and stage data in that instance. Adversaries may choose to stage data from a victim network in a centralized location prior to Exfiltration to minimize the number of connections made to their C2 server and better evade detection.
**Detection**
- [AN0042] **[macOS]** Detects files collected into user temp or shared directories followed by compression with ditto, zip, or custom scripts.
- [AN0040] **[Windows]** Detects staging of sensitive files into temporary or public directories, compression with 7zip/WinRAR, or batch copy prior to exfiltration.
- [AN0044] **[ESXi]** Detects snapshots or data stored in VMFS volumes from root CLI or remote agents.
- [AN0043] **[IaaS]** Detects virtual disk expansion or file copy operations to cloud buckets or mounted volumes from isolated instances.
- [AN0041] **[Linux]** Detects script or user activity copying files to a central temp or /mnt directory followed by archive/compression utilities.
**Procedure Examples**
- [G0102] Wizard Spider: Wizard Spider has collected and staged credentials and network enumeration information, using the networkdll and psfin TrickBot modules.
- [G1017] Volt Typhoon: Volt Typhoon has staged collected data in password-protected archives.
- [G1032] INC Ransom: INC Ransom has staged data on compromised hosts prior to exfiltration.
- [S0641] Kobalos: Kobalos can write captured SSH connection credentials to a file under the /var/run directory with a .pid extension for exfiltration.
- [S1020] Kevin: Kevin can create directories to store logs and other collected data.
- [S1076] QUIETCANARY: QUIETCANARY has the ability to stage data prior to exfiltration.
- [G1015] Scattered Spider: Scattered Spider stages data in a centralized database prior to exfiltration.
- [S1019] Shark: Shark has stored information in folders named `U1` and `U2` prior to exfiltration.


### T1074.001 - Data Staged: Local Data Staging
Adversaries may stage collected data in a central location or directory on the local system prior to Exfiltration. Data may be kept in separate files or combined into one file through techniques such as Archive Collected Data. Interactive command shells may be used, and common functionality within cmd and bash may be used to copy data into a staging location. Adversaries may also stage collected data in various available formats/locations of a system, including local storage databases/repositories or the Windows Registry.
**Detection**
- [AN0726] **[macOS]** Detects staged data aggregated in /Users/Shared, /private/tmp with compression tools like ditto or zip, initiated via Terminal or AppleScript.
- [AN0727] **[ESXi]** Detects local staging behavior via snapshot creation or files written into VMFS partitions by scripts or unauthorized shell access.
- [AN0724] **[Windows]** Detects file reads across locations followed by writes to temp or staging directories, often compressed or encrypted, indicating local staging behavior.
- [AN0725] **[Linux]** Detects aggregation of files from different directories into /tmp, /mnt, or user-specified directories with archiving tools like tar or gzip.
**Procedure Examples**
- [G1046] Storm-1811: Storm-1811 has locally staged captured credentials for subsequent manual exfiltration.
- [S0264] OopsIE: OopsIE stages the output from command execution and collected files in specific folders before exfiltration.
- [S1029] AuTo Stealer: AuTo Stealer can store collected data from an infected host to a file named `Hostname_UserName.txt` prior to exfiltration.
- [S1149] CHIMNEYSWEEP: CHIMNEYSWEEP can store captured screenshots to disk including to a covert store named `APPX.%x%x%x%x%x.tmp` where `%x` is a random value.
- [C0049] Leviathan Australian Intrusions: Leviathan stored captured credential material on local log files on victim systems during Leviathan Australian Intrusions.
- [S1110] SLIGHTPULSE: SLIGHTPULSE has piped the output from executed commands to `/tmp/1`.
- [S0567] Dtrack: Dtrack can save collected data to disk, different file formats, and network shares.
- [S1196] Troll Stealer: Troll Stealer encrypts gathered information on victim devices prior to exfiltrating it through command and control infrastructure.
- [S1015] Milan: Milan has saved files prior to upload from a compromised host to folders beginning with the characters `a9850d2f`.
- [S0247] NavRAT: NavRAT writes multiple outputs to a TMP file using the >> method.


### T1074.002 - Data Staged: Remote Data Staging
Adversaries may stage data collected from multiple systems in a central location or directory on one system prior to Exfiltration. Data may be kept in separate files or combined into one file through techniques such as Archive Collected Data. Interactive command shells may be used, and common functionality within cmd and bash may be used to copy data into a staging location. In cloud environments, adversaries may stage data within a particular instance or virtual machine before exfiltration. An adversary may Create Cloud Instance and stage data in that instance. By staging data on one system prior to Exfiltration, adversaries can minimize the number of connections made to their C2 server and better evade detection.
**Detection**
- [AN0197] **[ESXi]** Detects remote writes or snapshots mounted from other systems into a central ESXi VMFS path or NFS store used for remote staging of files before exfiltration.
- [AN0195] **[Linux]** Detects inbound SCP, rsync, or NFS mounts from remote systems followed by aggregation of files into known staging paths like /mnt/staging or /var/tmp.
- [AN0196] **[macOS]** Detects rsync or scp inbound from other hosts that then aggregate content into /Users/Shared or /private/tmp, often involving compressed files or scripts.
- [AN0198] **[IaaS]** Detects remote write activity across cloud VMs or object storage buckets within the same region/account that correlate with data aggregation across hosts.
- [AN0194] **[Windows]** Detects file transfers or mounting operations from remote hosts followed by write actions into a local staging directory, often using SMB or remote shell activity.
**Procedure Examples**
- [G0114] Chimera: Chimera has staged stolen data on designated servers in the target environment.
- [G1041] Sea Turtle: Sea Turtle staged collected email archives in the public web directory of a website that was accessible from the internet.
- [S1043] ccf32: ccf32 has copied files to a remote machine infected with Chinoxy or another backdoor.
- [C0024] SolarWinds Compromise: During the SolarWinds Compromise, APT29 staged data and files in password-protected archives on a victim's OWA server.
- [G0045] menuPass: menuPass has staged data on remote MSP systems or other victim networks prior to exfiltration.
- [G0061] FIN8: FIN8 aggregates staged data from a network into a single location.
- [G0065] Leviathan: Leviathan has staged data remotely prior to exfiltration.
- [G0007] APT28: APT28 has staged archives of collected data on a target's Outlook Web Access (OWA) server.
- [G1019] MoustachedBouncer: MoustachedBouncer has used plugins to save captured screenshots to `.\AActdata\` on an SMB share.
- [G1022] ToddyCat: ToddyCat manually transferred collected files to an exfiltration host using xcopy.


### T1113 - Screen Capture
Adversaries may attempt to take screen captures of the desktop to gather information over the course of an operation. Screen capturing functionality may be included as a feature of a remote access tool used in post-compromise operations. Taking a screenshot is also typically possible through native utilities or API calls, such as CopyFromScreen, xwd, or screencapture.
**Detection**
- [AN0982] **[Linux]** Use of tools like xwd or import to generate screenshots, especially under non-GUI parent processes.
- [AN0980] **[Windows]** Unusual use of screen capture APIs (e.g., CopyFromScreen) or command-line tools to write image files to disk.
- [AN0981] **[macOS]** Invocation of built-in commands like screencapture or use of undocumented APIs from suspicious parent processes.
**Procedure Examples**
- [S0147] Pteranodon: Pteranodon can capture screenshots at a configurable interval.
- [S0417] GRIFFON: GRIFFON has used a screenshot module that can be used to take a screenshot of the remote system.
- [S0044] JHUHUGIT: A JHUHUGIT variant takes screenshots by simulating the user pressing the "Take Screenshot" key (VK_SCREENSHOT), accessing the screenshot saved in the clipboard, and converting it to a JPG image.
- [S0331] Agent Tesla: Agent Tesla can capture screenshots of the victim’s desktop.
- [G0035] Dragonfly: Dragonfly has performed screen captures of victims, including by using a tool, scr.exe (which matched the hash of ScreenUtil).
- [S0192] Pupy: Pupy can drop a mouse-logger that will take small screenshots around at each click and then send back to the server.
- [S0199] TURNEDUP: TURNEDUP is capable of taking screenshots.
- [S0094] Trojan.Karagany: Trojan.Karagany can take a desktop screenshot and save the file into \ProgramData\Mail\MailAg\shot.png.
- [S0182] FinFisher: FinFisher takes a screenshot of the screen and displays it on top of all other windows for few seconds in an apparent attempt to hide some messages showed by the system during the setup process.
- [S1207] XLoader: XLoader can capture screenshots on compromised hosts.


### T1114 - Email Collection
Adversaries may target user email to collect sensitive information. Emails may contain sensitive data, including trade secrets or personal information, that can prove valuable to adversaries. Emails may also contain details of ongoing incident response operations, which may allow adversaries to adjust their techniques in order to maintain persistence or evade defenses. Adversaries can collect or forward email from mail servers or clients.
**Detection**
- [AN1312] **[Office Suite]** Correlates unusual auto-forwarding rule creation via Exchange Web Services or Outlook rules engine, presence of X-MS-Exchange-Organization-AutoForwarded headers, and logon session anomalies from abnormal IPs.
- [AN1309] **[Windows]** Correlates creation of email forwarding rules or header anomalies (e.g., X-MS-Exchange-Organization-AutoForwarded) with suspicious process execution, file access of .pst/.ost files, and network connections to external SMTP servers.
- [AN1311] **[macOS]** Monitors Mail.app database or maildir file access, automation via AppleScript, and abnormal mail rule creation using scripting or UI automation frameworks.
- [AN1310] **[Linux]** Detects file access to mbox/maildir files in conjunction with curl/wget/postfix execution, or anomalous shell scripts harvesting user mail directories.
**Procedure Examples**
- [G1003] Ember Bear: Ember Bear attempts to collect mail from accessed systems and servers.
- [G0122] Silent Librarian: Silent Librarian has exfiltrated entire mailboxes from compromised accounts.
- [S0367] Emotet: Emotet has been observed leveraging a module that can scrape email addresses from Outlook.
- [G0059] Magic Hound: Magic Hound has compromised email credentials in order to steal sensitive data.
- [S1201] TRANSLATEXT: TRANSLATEXT has exfiltrated collected email addresses to the C2 server.
- [G1015] Scattered Spider: Scattered Spider searched the victim’s Microsoft Exchange for emails about the intrusion and incident response.


### T1114.001 - Email Collection: Local Email Collection
Adversaries may target user email on local systems to collect sensitive information. Files containing email data can be acquired from a user’s local system, such as Outlook storage or cache files. Outlook stores data locally in offline data files with an extension of .ost. Outlook 2010 and later supports .ost file sizes up to 50GB, while earlier versions of Outlook support up to 20GB. IMAP accounts in Outlook 2013 (and earlier) and POP accounts use Outlook Data Files (.pst) as opposed to .ost, whereas IMAP accounts in Outlook 2016 (and later) use .ost files. Both types of Outlook data files are typically stored in `C:\Users\\Documents\Outlook Files` or `C:\Users\\AppData\Local\Microsoft\Outlook`.
**Detection**
- [AN0130] **[Windows]** Detection focuses on processes that attempt to locate, access, or exfiltrate local Outlook data files (.pst/.ost) using file system access, native Windows utilities (e.g., PowerShell, WMI), or remote access tools with file browsing capabilities. The behavior chain includes directory enumeration, file access, optional compression or staging, and network transfer.
**Procedure Examples**
- [S1142] LunarMail: LunarMail can capture the recipients of sent email messages from compromised accounts.
- [G1039] RedCurl: RedCurl has collected emails to use in future phishing campaigns.
- [S0226] Smoke Loader: Smoke Loader searches through Outlook files and directories (e.g., inbox, sent, templates, drafts, archives, etc.).
- [S0650] QakBot: QakBot can target and steal locally stored emails to support thread hijacking phishing campaigns.
- [G1041] Sea Turtle: Sea Turtle collected email archives from victim environments.
- [S0192] Pupy: Pupy can interact with a victim’s Outlook session and look through folders and emails.
- [S0030] Carbanak: Carbanak searches recursively for Outlook personal storage tables (PST) files within user directories and sends them back to the C2 server.
- [G0006] APT1: APT1 uses two utilities, GETMAIL and MAPIGET, to steal email. GETMAIL extracts emails from archived Outlook .pst files.
- [S0115] Crimson: Crimson contains a command to collect and exfiltrate emails from Outlook.
- [C0002] Night Dragon: During Night Dragon, threat actors used RAT malware to exfiltrate email archives.


### T1114.002 - Email Collection: Remote Email Collection
Adversaries may target an Exchange server, Office 365, or Google Workspace to collect sensitive information. Adversaries may leverage a user's credentials and interact directly with the Exchange server to acquire information from within a network. Adversaries may also access externally facing Exchange services, Office 365, or Google Workspace to access email using credentials or access tokens. Tools such as MailSniper can be used to automate searches for specific keywords.
**Detection**
- [AN0132] **[Office Suite]** Monitors programmatic access to user mailboxes in cloud-based email systems (e.g., O365, Exchange Online) using APIs or tokens. Focuses on OAuth misuse, suspicious MailItemsAccessed patterns, scripted keyword searches, and connections from untrusted agents or locations.
- [AN0131] **[Windows]** Detects adversaries accessing remote mail systems (e.g., Exchange Online, O365) using stolen credentials or OAuth tokens, followed by scripted access to mailbox contents via PowerShell, AADInternals, or unattended API queries. Detection focuses on abnormal logon sessions, user agents, IP locations, and scripted or tool-based email data access.
**Procedure Examples**
- [G0004] Ke3chang: Ke3chang has used compromised credentials and a .NET tool to dump data from Microsoft Exchange mailboxes.
- [S0413] MailSniper: MailSniper can be used for searching through email in Exchange and Office 365 environments.
- [C0024] SolarWinds Compromise: During the SolarWinds Compromise, APT29 collected emails from specific individuals, such as executives and IT staff, using `New-MailboxExportRequest` followed by `Get-MailboxExportRequest`.
- [G0007] APT28: APT28 has collected emails from victim Microsoft Exchange servers.
- [G1033] Star Blizzard: Star Blizzard has remotely accessed victims' email accounts to steal messages and attachments.
- [G0006] APT1: APT1 uses two utilities, GETMAIL and MAPIGET, to steal email. MAPIGET steals email still on Exchange servers that has not yet been archived.
- [C0038] HomeLand Justice: During HomeLand Justice, threat actors made multiple HTTP POST requests to the Exchange servers of the victim organization to transfer data.
- [S0395] LightNeuron: LightNeuron collects Exchange emails matching rules specified in its configuration.
- [G0016] APT29: APT29 has collected emails from targeted mailboxes within a compromised Azure AD tenant and compromised Exchange servers, including via Exchange Web Services (EWS) API requests.
- [S0053] SeaDuke: Some SeaDuke samples have a module to extract email from Microsoft Exchange servers using compromised credentials.


### T1114.003 - Email Collection: Email Forwarding Rule
Adversaries may setup email forwarding rules to collect sensitive information. Adversaries may abuse email forwarding rules to monitor the activities of a victim, steal information, and further gain intelligence on the victim or the victim’s organization to use as part of further exploits or operations. Furthermore, email forwarding rules can allow adversaries to maintain persistent access to victim's emails even after compromised credentials are reset by administrators. Most email clients allow users to create inbox rules for various email functions, including forwarding to a different recipient. These rules may be created through a local email application, a web interface, or by command-line interface. Messages can be forwarded to internal or external recipients, and there are no restrictions limiting the extent of this rule. Administrators may also create forwarding rules for user accounts with the same considerations and outcomes. Any user or administrator within the organization (or adversary with valid credentials) can create rules to automatically forward all received messages to another recipient, forward emails to different locations based on the sender, and more. Adversaries may also hide the rule by making use of the Microsoft Messaging API (MAPI) to modify the rule properties, making it hidden and not visible from Outlook, OWA or most Exchange Administration tools. In some environments, administrators may be able to enable email forwarding rules that operate organization-wide rather than on individual inboxes. For example, Microsoft Exchange supports transport rules that evaluate all mail an organization receives against user-specified conditions, then performs a user-specified action on mail that adheres to those conditions. Adversaries that abuse such features may be able to enable forwarding on all or specific mail an organization receives.
**Detection**
- [AN1592] **[Linux]** Modification of Thunderbird message filters file or execution of CLI tools (e.g., formail/procmail) that alter .forward behavior.
- [AN1591] **[Office Suite]** Creation of email forwarding/redirect rules in Exchange Online via New-InboxRule or transport rule cmdlets, including auto-forwarding address field usage.
- [AN1590] **[macOS]** Creation or modification of Apple Mail rules by accessing plist files or GUI automation (AppleScript).
- [AN1589] **[Windows]** Creation of inbox rules via PowerShell (New-InboxRule) or transport rules using Exchange cmdlets. Correlates user behavior, cmdlet usage, and rule properties.
**Procedure Examples**
- [G1015] Scattered Spider: Scattered Spider has redirected emails notifying users of suspicious account activity.
- [G0122] Silent Librarian: Silent Librarian has set up auto forwarding rules on compromised e-mail accounts.
- [G1004] LAPSUS$: LAPSUS$ has set an Office 365 tenant level mail transport rule to send all mail in and out of the targeted organization to the newly created account.
- [G1033] Star Blizzard: Star Blizzard has abused email forwarding rules to monitor the activities of a victim, steal information, and maintain persistent access after compromised credentials are reset.
- [G0094] Kimsuky: Kimsuky has set auto-forward rules on victim's e-mail accounts.


### T1115 - Clipboard Data
Adversaries may collect data stored in the clipboard from users copying information within or between applications. For example, on Windows adversaries can access clipboard data by using clip.exe or Get-Clipboard. Additionally, adversaries may monitor then replace users’ clipboard with their data (e.g., Transmitted Data Manipulation). macOS and Linux also have commands, such as pbpaste, to grab clipboard contents.
**Detection**
- [AN0966] **[macOS]** Detection of pbpaste/pbcopy clipboard access by processes without terminal sessions or linked to launch agents, potentially staged for collection.
- [AN0965] **[Windows]** Detection of clipboard access via OS utilities (e.g., clip.exe, Get-Clipboard) by non-interactive or abnormal parent processes, potentially chained with staging or exfiltration commands.
- [AN0967] **[Linux]** Detection of xclip or xsel access to clipboard buffers outside of user terminal context, especially when chained to staging (gzip, base64) or network exfiltration (curl, scp).
**Procedure Examples**
- [S0331] Agent Tesla: Agent Tesla can steal data from the victim’s clipboard.
- [G0087] APT39: APT39 has used tools capable of stealing contents of the clipboard.
- [S0148] RTM: RTM collects data from the clipboard.
- [S0692] SILENTTRINITY: SILENTTRINITY can monitor Clipboard text and can use `System.Windows.Forms.Clipboard.GetText()` to collect data from the clipboard.
- [S0334] DarkComet: DarkComet can steal data from the clipboard.
- [S0373] Astaroth: Astaroth collects information from the clipboard by using the OpenClipboard() and GetClipboardData() libraries.
- [S0004] TinyZBot: TinyZBot contains functionality to collect information from the clipboard.
- [S0363] Empire: Empire can harvest clipboard data on both Windows and macOS systems.
- [S0438] Attor: Attor has a plugin that collects data stored in the Windows clipboard by using the OpenClipboard and GetClipboardData APIs.
- [S0332] Remcos: Remcos steals and modifies data from the clipboard.


### T1119 - Automated Collection
Once established within a system or network, an adversary may use automated techniques for collecting internal data. Methods for performing this technique could include use of a Command and Scripting Interpreter to search for and copy information fitting set criteria such as file type, location, or name at specific time intervals. In cloud-based environments, adversaries may also use cloud APIs, data pipelines, command line interfaces, or extract, transform, and load (ETL) services to automatically collect data. This functionality could also be built into remote access tools. This technique may incorporate use of other techniques such as File and Directory Discovery and Lateral Tool Transfer to identify and move files, as well as Cloud Service Dashboard and Cloud Storage Object Discovery to identify resources in cloud environments.
**Detection**
- [AN0534] **[SaaS]** Suspicious sign-ins to Graph API or sensitive resources using non-browser scripting agents (e.g., Python, PowerShell), often for programmatic access to mailbox or OneDrive content.
- [AN0531] **[Windows]** Automated execution of native utilities and scripts to discover, enumerate, and exfiltrate files and clipboard content. Focus is on detecting repeated file access, scripting engine use, and use of command-line utilities commonly leveraged by collection scripts.
- [AN0532] **[Linux]** Repeated or automated access to user document directories or clipboard using shell scripts or utilities like xclip/pbpaste. Detectable via auditd syscall logs or osquery file events.
- [AN0533] **[macOS]** Use of pbpaste, AppleScript, or third-party automation frameworks (e.g., Automator) to collect clipboard or file content in bursts. Observable via unified logs.
**Procedure Examples**
- [S0098] T9000: T9000 searches removable storage devices for files with a pre-defined list of file extensions (e.g. * .doc, *.ppt, *.xls, *.docx, *.pptx, *.xlsx). Any matching files are encrypted and written to a local user directory.
- [S0090] Rover: Rover automatically collects files from the local system and removable drives based on a predefined list of file extensions on a regular timeframe.
- [S0339] Micropsia: Micropsia executes an RAR tool to recursively archive files based on a predefined list of file extensions (*.xls, *.xlsx, *.csv, *.odt, *.doc, *.docx, *.ppt, *.pptx, *.pdf, *.mdb, *.accdb, *.accde, *.txt).
- [S1043] ccf32: ccf32 can be used to automatically collect files from a compromised host.
- [S1111] DarkGate: DarkGate searches for stored credentials associated with cryptocurrency wallets and notifies the command and control server when identified.
- [G0047] Gamaredon Group: Gamaredon Group has deployed scripts on compromised systems that automatically scan for interesting documents.
- [S0244] Comnie: Comnie executes a batch script to store discovery information in %TEMP%\info.dat and then uploads the temporarily file to the remote C2 server.
- [C0014] Operation Wocao: During Operation Wocao, threat actors used a script to collect information about the infected system.
- [S0684] ROADTools: ROADTools automatically gathers data from Azure AD environments using the Azure Graph API.
- [S0198] NETWIRE: NETWIRE can automatically archive collected data.


### T1123 - Audio Capture
An adversary can leverage a computer's peripheral devices (e.g., microphones and webcams) or applications (e.g., voice and video call services) to capture audio recordings for the purpose of listening into sensitive conversations to gather information. Malware or scripts may be used to interact with the devices through an available API provided by the operating system or an application to capture audio. Audio files may be written to disk and exfiltrated later.
**Detection**
- [AN0620] **[Linux]** Processes accessing ALSA/PulseAudio devices or executing audio capture binaries like 'arecord', followed by file creation or suspicious child process spawning.
- [AN0619] **[Windows]** Unusual or unauthorized processes accessing microphone APIs (e.g., winmm.dll, avrt.dll) followed by audio file writes to user-accessible or temp directories.
- [AN0621] **[macOS]** Processes invoking AVFoundation or CoreAudio frameworks, accessing input devices via TCC logs or Unified Logs, followed by writing AIFF/WAV/MP3 files to disk.
**Procedure Examples**
- [S0143] Flame: Flame can record audio using any existing hardware recording devices.
- [S0240] ROKRAT: ROKRAT has an audio capture and eavesdropping module.
- [S0234] Bandook: Bandook has modules that are capable of capturing audio.
- [S0194] PowerSploit: PowerSploit's Get-MicrophoneAudio Exfiltration module can record system microphone audio.
- [S0257] VERMIN: VERMIN can perform audio capture.
- [S0467] TajMahal: TajMahal has the ability to capture VoiceIP application audio on an infected host.
- [S0192] Pupy: Pupy can record sound with the microphone.
- [S0152] EvilGrab: EvilGrab has the capability to capture audio from a victim machine.
- [S1185] LightSpy: LightSpy uses Apple's built-in AVFoundation Framework library to capture and manage audio recordings then transform them to JSON blobs for exfiltration.
- [S0454] Cadelspy: Cadelspy has the ability to record audio from the compromised host.


### T1125 - Video Capture
An adversary can leverage a computer's peripheral devices (e.g., integrated cameras or webcams) or applications (e.g., video call services) to capture video recordings for the purpose of gathering information. Images may also be captured from devices or applications, potentially in specified intervals, in lieu of video files. Malware or scripts may be used to interact with the devices through an available API provided by the operating system or an application to capture video or images. Video or image files may be written to disk and exfiltrated later. This technique differs from Screen Capture due to use of specific devices or applications for video recording rather than capturing the victim's screen. In macOS, there are a few different malware samples that record the user's webcam such as FruitFly and Proton.
**Detection**
- [AN0568] **[Windows]** A non-standard process (or script-hosted process) loads camera/video-capture libraries (e.g., avicap32.dll, mf.dll, ksproxy.ax), opens the Camera Frame Server/device, writes video/image artifacts (e.g., .mp4/.avi/.yuv) to unusual locations, and optionally initiates outbound transfer shortly after.
- [AN0570] **[macOS]** A non-whitelisted process receives TCC camera entitlement (kTCCServiceCamera), opens AppleCamera/AVFoundation device handles, writes .mov/.mp4 artifacts to unusual locations, and/or beacons/exfiltrates soon after.
- [AN0569] **[Linux]** A process opens/reads /dev/video* (V4L2), performs ioctl/read loops, writes large/continuous video artifacts to disk, and/or quickly establishes outbound connections for exfiltration.
**Procedure Examples**
- [S0363] Empire: Empire can capture webcam data on Windows and macOS systems.
- [S0660] Clambling: Clambling can record screen content in AVI format.
- [S0115] Crimson: Crimson can capture webcam video on targeted systems.
- [S0467] TajMahal: TajMahal has the ability to capture webcam video.
- [S0338] Cobian RAT: Cobian RAT has a feature to access the webcam on the victim’s machine.
- [S0336] NanoCore: NanoCore can access the victim's webcam and capture data.
- [S0283] jRAT: jRAT has the capability to capture video from a webcam.
- [S0409] Machete: Machete takes photos from the computer’s web camera.
- [S0379] Revenge RAT: Revenge RAT has the ability to access the webcam.
- [S0334] DarkComet: DarkComet can access the victim’s webcam to take pictures.


### T1185 - Browser Session Hijacking
Adversaries may take advantage of security vulnerabilities and inherent functionality in browser software to change content, modify user-behaviors, and intercept information as part of various browser session hijacking techniques. A specific example is when an adversary injects software into a browser that allows them to inherit cookies, HTTP sessions, and SSL client certificates of a user then use the browser as a way to pivot into an authenticated intranet. Executing browser-based behaviors such as pivoting may require specific process permissions, such as SeDebugPrivilege and/or high-integrity/administrator rights. Another example involves pivoting browser traffic from the adversary's browser through the user's browser by setting up a proxy which will redirect web traffic. This does not alter the user's traffic in any way, and the proxy connection can be severed as soon as the browser is closed. The adversary assumes the security context of whichever browser process the proxy is injected into. Browsers typically create a new process for each tab that is opened and permissions and certificates are separated accordingly. With these permissions, an adversary could potentially browse to any resource on an intranet, such as Sharepoint or webmail, that is accessible through the browser and which the browser has sufficient permissions. Browser pivoting may also bypass security provided by 2-factor authentication.
**Detection**
- [AN1398] **[Windows]** Adversary gains high integrity or special privileges (e.g., SeDebugPrivilege), locates a running browser process, opens it with write/inject rights, and modifies it (e.g., CreateRemoteThread / DLL load) to inherit cookies/tokens or establish a browser pivot. Optional step: create a new logon session or use explicit credentials, then drive the victim browser to intranet resources.
**Procedure Examples**
- [S0266] TrickBot: TrickBot uses web injects and browser redirection to trick the user into providing their login credentials on a fake or modified web page.
- [S0384] Dridex: Dridex can perform browser attacks via web injects to steal information such as credentials, certificates, and cookies.
- [S0484] Carberp: Carberp has captured credentials when a user performs login through a SSL session.
- [S1201] TRANSLATEXT: TRANSLATEXT has the ability to use form-grabbing and event-listening to extract data from web data forms.
- [S0530] Melcoz: Melcoz can monitor the victim's browser for online banking sessions and display an overlay window to manipulate the session in the background.
- [S0331] Agent Tesla: Agent Tesla has the ability to use form-grabbing to extract data from web data forms.
- [S0531] Grandoreiro: Grandoreiro can monitor browser activity for online banking actions and display full-screen overlay images to block user access to the intended site or present additional data fields.
- [G0094] Kimsuky: Kimsuky has the ability to use form-grabbing to extract emails and passwords from web data forms.
- [S1207] XLoader: XLoader can conduct form grabbing, steal cookies, and extract data from HTTP sessions.
- [S0650] QakBot: QakBot can use advanced web injects to steal web banking credentials.


### T1213 - Data from Information Repositories
Adversaries may leverage information repositories to mine valuable information. Information repositories are tools that allow for storage of information, typically to facilitate collaboration or information sharing between users, and can store a wide variety of data that may aid adversaries in further objectives, such as Credential Access, Lateral Movement, or Defense Evasion, or direct access to the target information. Adversaries may also abuse external sharing features to share sensitive documents with recipients outside of the organization (i.e., Transfer Data to Cloud Account). The following is a brief list of example information that may hold potential value to an adversary and may also be found on an information repository: * Policies, procedures, and standards * Physical / logical network diagrams * System architecture diagrams * Technical system documentation * Testing / development credentials (i.e., Unsecured Credentials) * Work / project schedules * Source code snippets * Links to network shares and other internal resources * Contact or other sensitive information about business partners and customers, including personally identifiable information (PII) Information stored in a repository may vary based on the specific instance or environment. Specific common information repositories include the following: * Storage services such as IaaS databases, enterprise databases, and more specialized platforms such as customer relationship management (CRM) databases * Collaboration platforms such as SharePoint, Confluence, and code repositories * Messaging platforms such as Slack and Microsoft Teams In some cases, information repositories have been improperly secured, typically by unintentionally allowing for overly-broad access by all users or even public access to unauthenticated users. This is particularly common with cloud-native or cloud-hosted services, such as AWS Relational Database Service (RDS), Redis, or ElasticSearch.
**Detection**
- [AN1162] **[SaaS]** Abuse of SaaS platforms such as Confluence, GitHub, SharePoint Online, or Slack to access excessive internal documentation or export source code/data. Includes use of tokens or browser automation from unapproved IPs.
- [AN1161] **[Linux]** Command-line tools (e.g., curl, rsync, wget, or custom Python scripts) used to scrape documentation systems or internal REST APIs. Unusual access patterns to knowledge base folders or shared team drives.
- [AN1160] **[Windows]** Programmatic or excessive access to file shares, SharePoint, or database repositories by users not typically interacting with them. This includes abnormal access by privileged accounts, enumeration of large numbers of files, or downloads of sensitive content in bursts.
- [AN1163] **[macOS]** Access of mounted cloud shares or document repositories via browser, terminal, or Finder by users not typically interacting with those resources. Includes script-based enumeration or mass download.
**Procedure Examples**
- [C0024] SolarWinds Compromise: During the SolarWinds Compromise, APT29 accessed victims' internal knowledge repositories (wikis) to view sensitive corporate information on products, services, and internal business operations.
- [S1148] Raccoon Stealer: Raccoon Stealer gathers information from repositories associated with cryptocurrency wallets and the Telegram messaging service.
- [S1196] Troll Stealer: Troll Stealer gathers information from the Government Public Key Infrastructure (GPKI) folder, associated with South Korean government public key infrastructure, on infected systems.
- [G0007] APT28: APT28 has collected files from various information repositories.


### T1213.001 - Data from Information Repositories: Confluence
Adversaries may leverage Confluence repositories to mine valuable information. Often found in development environments alongside Atlassian JIRA, Confluence is generally used to store development-related documentation, however, in general may contain more diverse categories of useful information, such as: * Policies, procedures, and standards * Physical / logical network diagrams * System architecture diagrams * Technical system documentation * Testing / development credentials (i.e., Unsecured Credentials) * Work / project schedules * Source code snippets * Links to network shares and other internal resources
**Detection**
- [AN1019] **[SaaS]** Detection of excessive or programmatic access to Confluence spaces or pages, particularly by privileged users, through a combination of access logs, API usage, and identity context. Correlates logon sessions, user roles, and abnormal document viewing or export behavior. Identifies burst access patterns and tools/scripts abusing the Confluence API for mass enumeration or data scraping.
**Procedure Examples**
- [G1004] LAPSUS$: LAPSUS$ has searched a victim's network for collaboration platforms like Confluence and JIRA to discover further high-privilege account credentials.


### T1213.002 - Data from Information Repositories: Sharepoint
Adversaries may leverage the SharePoint repository as a source to mine valuable information. SharePoint will often contain useful information for an adversary to learn about the structure and functionality of the internal network and systems. For example, the following is a list of example information that may hold potential value to an adversary and may also be found on SharePoint: * Policies, procedures, and standards * Physical / logical network diagrams * System architecture diagrams * Technical system documentation * Testing / development credentials (i.e., Unsecured Credentials) * Work / project schedules * Source code snippets * Links to network shares and other internal resources
**Detection**
- [AN1380] **[Windows]** Privileged or rarely used accounts performing bulk access to SharePoint files or metadata over a short time window, indicating potential scripted collection of sensitive internal documents.
**Procedure Examples**
- [G1024] Akira: Akira has accessed and downloaded information stored in SharePoint instances as part of data gathering and exfiltration activity.
- [G0125] HAFNIUM: HAFNIUM has abused compromised credentials to exfiltrate data from SharePoint.
- [G1004] LAPSUS$: LAPSUS$ has searched a victim's network for collaboration platforms like SharePoint to discover further high-privilege account credentials.
- [S0227] spwebmember: spwebmember is used to enumerate and dump information from Microsoft SharePoint.
- [G0114] Chimera: Chimera has collected documents from the victim's SharePoint.
- [G0007] APT28: APT28 has collected information from Microsoft SharePoint services within target networks.
- [C0027] C0027: During C0027, Scattered Spider accessed victim SharePoint environments to search for VPN and MFA enrollment information, help desk instructions, and new hire guides.
- [G0004] Ke3chang: Ke3chang used a SharePoint enumeration and data dumping tool known as spwebmember.


### T1213.003 - Data from Information Repositories: Code Repositories
Adversaries may leverage code repositories to collect valuable information. Code repositories are tools/services that store source code and automate software builds. They may be hosted internally or privately on third party sites such as Github, GitLab, SourceForge, and BitBucket. Users typically interact with code repositories through a web application or command-line utilities such as git. Once adversaries gain access to a victim network or a private code repository, they may collect sensitive information such as proprietary source code or Unsecured Credentials contained within software's source code. Having access to software's source code may allow adversaries to develop Exploits, while credentials may provide access to additional resources using Valid Accounts. **Note:** This is distinct from Code Repositories, which focuses on conducting Reconnaissance via public code repositories.
**Detection**
- [AN0732] **[SaaS]** Anomalous or bulk download activity from private or restricted repositories by non-developer or privileged accounts, often preceded by unusual login behavior (e.g., unfamiliar geo, OAuth token use, elevated API rate).
**Procedure Examples**
- [G1004] LAPSUS$: LAPSUS$ has searched a victim's network for code repositories like GitLab and GitHub to discover further high-privilege account credentials.
- [G1015] Scattered Spider: Scattered Spider enumerates data stored within victim code repositories, such as internal GitHub repositories.
- [C0024] SolarWinds Compromise: During the SolarWinds Compromise, APT29 downloaded source code from code repositories.
- [G0096] APT41: APT41 cloned victim user Git repositories during intrusions.


### T1213.004 - Data from Information Repositories: Customer Relationship Management Software
Adversaries may leverage Customer Relationship Management (CRM) software to mine valuable information. CRM software is used to assist organizations in tracking and managing customer interactions, as well as storing customer data. Once adversaries gain access to a victim organization, they may mine CRM software for customer data. This may include personally identifiable information (PII) such as full names, emails, phone numbers, and addresses, as well as additional details such as purchase histories and IT support interactions. By collecting this data, an adversary may be able to send personalized Phishing emails, engage in SIM swapping, or otherwise target the organization’s customers in ways that enable financial gain or the compromise of additional organizations. CRM software may be hosted on-premises or in the cloud. Information stored in these solutions may vary based on the specific instance or environment. Examples of CRM software include Microsoft Dynamics 365, Salesforce, Zoho, Zendesk, and HubSpot.
**Detection**
- [AN1520] **[SaaS]** Anomalous high-volume access to customer records in CRM software by a non-CRM admin user account, especially following initial authentication from a rare location or device. Behavior includes abnormal access to PII fields or data exports within a short time window.
**Procedure Examples**
- [C0059] Salesforce Data Exfiltration: During Salesforce Data Exfiltration, threat actors accessed and exfiltrated sensitive information from compromised Salesforce instances.


### T1213.005 - Data from Information Repositories: Messaging Applications
Adversaries may leverage chat and messaging applications, such as Microsoft Teams, Google Chat, and Slack, to mine valuable information. The following is a brief list of example information that may hold potential value to an adversary and may also be found on messaging applications: * Testing / development credentials (i.e., Chat Messages) * Source code snippets * Links to network shares and other internal resources * Proprietary data * Discussions about ongoing incident response efforts In addition to exfiltrating data from messaging applications, adversaries may leverage data from chat messages in order to improve their targeting - for example, by learning more about an environment or evading ongoing incident response efforts.
**Detection**
- [AN1566] **[Office Suite]** Suspicious access to Microsoft Teams chat messages via eDiscovery, Graph API, or export methods after rare or compromised sign-in. Often associated with excessive file access, sensitive content review, or anomaly from expected user behavior.
- [AN1565] **[SaaS]** Atypical access to Slack or Teams conversations via APIs, automation tokens, or bulk message export functionality, particularly after an account takeover or rare sign-in pattern. Often includes mass retrieval of chat history, download of message content, or scraping of workspace/channel metadata.
**Procedure Examples**
- [G0117] Fox Kitten: Fox Kitten has accessed victim security and IT environments and Microsoft Teams to mine valuable information.
- [G1015] Scattered Spider: Scattered Spider threat actors search the victim’s Slack and Microsoft Teams for conversations about the intrusion and incident response.
- [G1004] LAPSUS$: LAPSUS$ has searched a victim's network for organization collaboration channels like MS Teams or Slack to discover further high-privilege account credentials.


### T1213.006 - Data from Information Repositories: Databases
Adversaries may leverage databases to mine valuable information. These databases may be hosted on-premises or in the cloud (both in platform-as-a-service and software-as-a-service environments). Examples of databases from which information may be collected include MySQL, PostgreSQL, MongoDB, Amazon Relational Database Service, Azure SQL Database, Google Firebase, and Snowflake. Databases may include a variety of information of interest to adversaries, such as usernames, hashed passwords, personally identifiable information, and financial data. Data collected from databases may be used for Lateral Movement, Command and Control, or Exfiltration. Data exfiltrated from databases may also be used to extort victims or may be sold for profit.
**Detection**
- [AN0679] **[IaaS]** Database enumeration and export activity (e.g., `SELECT * FROM`, `SHOW DATABASES`) issued via ephemeral VMs, admin APIs, or cloud shell from non-monitoring accounts. Defender correlates audit logs (CloudTrail, GCP Admin, AzureDiagnostics), storage write ops, and cross-region transfers by identities not tied to DB operations.
- [AN0676] **[Linux]** Unusual database command-line access (e.g., `psql`, `mysql`, `mongo`) from non-admin users, occurring outside typical automation windows or without known service context. Often followed by data dumps to .sql/.csv files or outbound data transfers. Defender sees CLI tools launched interactively or by unusual parent processes, file writes to dump-like filenames, and external connections shortly after.
- [AN0678] **[macOS]** Execution of Java-based or CLI database tools (e.g., DBeaver, Beekeeper, mysql, psql) from user profiles not tied to dev/admin roles, especially when followed by file writes and cloud sync activity. Defender correlates GUI tool launches, file write events in ~/Downloads or ~/Documents, and outbound API calls to known cloud services.
- [AN0680] **[SaaS]** Unusual or excessive database/table exports from SaaS database platforms (e.g., Snowflake, Firebase, BigQuery, Airtable) by users or apps not in known analytics or dev groups. Defender observes access patterns outside baseline working hours or with new query templates, and correlates those with audit logs or file downloads.
- [AN0677] **[Windows]** Database client execution (e.g., sqlcmd.exe, isql.exe) by users or from locations not tied to enterprise automation or backups. Often followed by creation of .sql/.bak/.csv files, registry artifacts for ODBC/JDBC drivers, or encrypted ZIPs. Defender sees SQL tools launched by explorer.exe, Powershell, or odd parent processes, plus file writes in user temp locations.
**Procedure Examples**
- [C0049] Leviathan Australian Intrusions: Leviathan gathered information from SQL servers and Building Management System (BMS) servers during Leviathan Australian Intrusions.
- [G0034] Sandworm Team: Sandworm Team exfiltrates data of interest from enterprise databases using Adminer.
- [C0040] APT41 DUST: APT41 DUST collected data from victim Oracle databases using SQLULDR2.
- [G0037] FIN6: FIN6 has collected schemas and user accounts from systems running SQL Server.
- [S1146] MgBot: MgBot includes a module capable of stealing content from the Tencent QQ database storing user QQ message history on infected devices.
- [G1041] Sea Turtle: Sea Turtle used the tool Adminer to remotely logon to the MySQL service of victim machines.
- [G0010] Turla: Turla has used a custom .NET tool to collect documents from an organization's internal central database.
- [S0598] P.A.S. Webshell: P.A.S. Webshell has the ability to list and extract data from SQL databases.


### T1530 - Data from Cloud Storage
Adversaries may access data from cloud storage. Many IaaS providers offer solutions for online data object storage such as Amazon S3, Azure Storage, and Google Cloud Storage. Similarly, SaaS enterprise platforms such as Office 365 and Google Workspace provide cloud-based document storage to users through services such as OneDrive and Google Drive, while SaaS application providers such as Slack, Confluence, Salesforce, and Dropbox may provide cloud storage solutions as a peripheral or primary use case of their platform. In some cases, as with IaaS-based cloud storage, there exists no overarching application (such as SQL or Elasticsearch) with which to interact with the stored objects: instead, data from these solutions is retrieved directly though the Cloud API. In SaaS applications, adversaries may be able to collect this data directly from APIs or backend cloud storage objects, rather than through their front-end application or interface (i.e., Data from Information Repositories). Adversaries may collect sensitive data from these cloud storage solutions. Providers typically offer security guides to help end users configure systems, though misconfigurations are a common problem. There have been numerous incidents where cloud storage has been improperly secured, typically by unintentionally allowing public access to unauthenticated users, overly-broad access by all users, or even access for any anonymous person outside the control of the Identity Access Management system without even needing basic user permissions. This open access may expose various types of sensitive data, such as credit cards, personally identifiable information, or medical records. Adversaries may also obtain then abuse leaked credentials from source repositories, logs, or other means as a way to gain access to cloud storage objects.
**Detection**
- [AN1330] **[Office Suite]** Internal user account accesses shared links outside org followed by mass file download
- [AN1329] **[SaaS]** OAuth token granted to external app followed by download of high-volume files in OneDrive/Google Drive
- [AN1328] **[IaaS]** Spike in object access from new IAM user or role followed by data exfiltration to external IPs
**Procedure Examples**
- [G0117] Fox Kitten: Fox Kitten has obtained files from the victim's cloud storage instances.
- [S0683] Peirates: Peirates can dump the contents of AWS S3 buckets. It can also retrieve service account tokens from kOps buckets in Google Cloud Storage or S3.
- [G1053] Storm-0501: Storm-0501 had modified Azure Storage account resources through the `Microsoft.Storage/storageAccounts/write` operation to expose non-remotely accessible accounts for data exfiltration.
- [G1044] APT42: APT42 has collected data from Microsoft 365 environments.
- [G0125] HAFNIUM: HAFNIUM has exfitrated data from OneDrive.
- [G1015] Scattered Spider: Scattered Spider enumerates data stored in cloud resources for collection and exfiltration purposes.
- [S1091] Pacu: Pacu can enumerate and download files stored in AWS storage services, such as S3 buckets.
- [C0027] C0027: During C0027, Scattered Spider accessed victim OneDrive environments to search for VPN and MFA enrollment information, help desk instructions, and new hire guides.
- [S0677] AADInternals: AADInternals can collect files from a user’s OneDrive.


### T1557 - Adversary-in-the-Middle
Adversaries may attempt to position themselves between two or more networked devices using an adversary-in-the-middle (AiTM) technique to support follow-on behaviors such as Network Sniffing, Transmitted Data Manipulation, or replay attacks (Exploitation for Credential Access). By abusing features of common networking protocols that can determine the flow of network traffic (e.g. ARP, DNS, LLMNR, etc.), adversaries may force a device to communicate through an adversary controlled system so they can collect information or perform additional actions. For example, adversaries may manipulate victim DNS settings to enable other malicious activities such as preventing/redirecting users from accessing legitimate sites and/or pushing additional malware. Adversaries may also manipulate DNS and leverage their position in order to intercept user credentials, including access tokens (Steal Application Access Token) and session cookies (Steal Web Session Cookie). Downgrade Attacks can also be used to establish an AiTM position, such as by negotiating a less secure, deprecated, or weaker version of communication protocol (SSL/TLS) or encryption algorithm. Adversaries may also leverage the AiTM position to attempt to monitor and/or modify traffic, such as in Transmitted Data Manipulation. Adversaries can setup a position similar to AiTM to prevent traffic from flowing to the appropriate destination, potentially to Impair Defenses and/or in support of a Network Denial of Service.
**Detection**
- [AN0824] **[Linux]** Detects unauthorized edits to /etc/hosts, /etc/resolv.conf, or suspicious ARP broadcasts. Correlates file modifications with subsequent unexpected network sessions or service creation.
- [AN0825] **[macOS]** Detects unauthorized edits to system configuration profiles, unexpected certificate trust changes, or abnormal ARP/DNS patterns indicative of interception.
- [AN0826] **[Network Devices]** Detects unauthorized firmware or configuration changes enabling adversary-in-the-middle positioning (e.g., route injection, DNS spoofing, SSL downgrade). Behavioral analytics focus on sudden changes to routing tables or image file integrity failures.
- [AN0823] **[Windows]** Detects suspicious DNS/ARP poisoning attempts, unauthorized modifications to registry/network configuration, or abnormal TLS downgrade activity. Correlates changes in system configuration with subsequent unusual network flows or authentication events.
**Procedure Examples**
- [S0281] Dok: Dok proxies web traffic to potentially monitor and alter victim HTTP(S) traffic.
- [G0129] Mustang Panda: Mustang Panda leveraged a captive portal hijack that redirected the victim to a webpage that prompted the victim to download a malicious payload.
- [G0094] Kimsuky: Kimsuky has used modified versions of PHProxy to examine web traffic between the victim and the accessed website.
- [C0046] ArcaneDoor: ArcaneDoor included interception of HTTP traffic to victim devices to identify and parse command and control information sent to the device.
- [S1131] NPPSPY: NPPSPY opens a new network listener for the mpnotify.exe process that is typically contacted by the Winlogon process in Windows. A new, alternative RPC channel is set up with a malicious DLL recording plaintext credentials entered into Winlogon, effectively intercepting and redirecting the logon information.
- [S1188] Line Runner: Line Runner intercepts HTTP requests to the victim Cisco ASA, looking for a request with a 32-character, victim dependent parameter. If that parameter matches a value in the malware, a contained payload is then written to a Lua script and executed.
- [G1041] Sea Turtle: Sea Turtle modified DNS records at service providers to redirect traffic from legitimate resources to Sea Turtle-controlled servers to enable adversary-in-the-middle attacks for credential capture.


### T1557.001 - Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning and SMB Relay
By responding to LLMNR/NBT-NS network traffic, adversaries may spoof an authoritative source for name resolution to force communication with an adversary controlled system. This activity may be used to collect or relay authentication materials. Link-Local Multicast Name Resolution (LLMNR) and NetBIOS Name Service (NBT-NS) are Microsoft Windows components that serve as alternate methods of host identification. LLMNR is based upon the Domain Name System (DNS) format and allows hosts on the same local link to perform name resolution for other hosts. NBT-NS identifies systems on a local network by their NetBIOS name. Adversaries can spoof an authoritative source for name resolution on a victim network by responding to LLMNR (UDP 5355)/NBT-NS (UDP 137) traffic as if they know the identity of the requested host, effectively poisoning the service so that the victims will communicate with the adversary controlled system. If the requested host belongs to a resource that requires identification/authentication, the username and NTLMv2 hash will then be sent to the adversary controlled system. The adversary can then collect the hash information sent over the wire through tools that monitor the ports for traffic or through Network Sniffing and crack the hashes offline through Brute Force to obtain the plaintext passwords. In some cases where an adversary has access to a system that is in the authentication path between systems or when automated scans that use credentials attempt to authenticate to an adversary controlled system, the NTLMv1/v2 hashes can be intercepted and relayed to access and execute code against a target system. The relay step can happen in conjunction with poisoning but may also be independent of it. Additionally, adversaries may encapsulate the NTLMv1/v2 hashes into various protocols, such as LDAP, SMB, MSSQL and HTTP, to expand and use multiple services with the valid NTLM response. Several tools may be used to poison name services within local networks such as NBNSpoof, Metasploit, and Responder.
**Detection**
- [AN1274] **[Windows]** Detects anomalous network traffic on UDP 5355 (LLMNR) and UDP 137 (NBT-NS) combined with unauthorized SMB relay attempts, registry modifications re-enabling multicast name resolution, or suspicious service creation indicative of adversary-in-the-middle credential interception.
**Procedure Examples**
- [S0357] Impacket: Impacket modules like ntlmrelayx and smbrelayx can be used in conjunction with Network Sniffing and LLMNR/NBT-NS Poisoning and SMB Relay to gather NetNTLM credentials for Brute Force or relay attacks that can gain code execution.
- [S0363] Empire: Empire can use Inveigh to conduct name service poisoning for credential theft and associated relay attacks.
- [S0378] PoshC2: PoshC2 can use Inveigh to conduct name service poisoning for credential theft and associated relay attacks.
- [G0032] Lazarus Group: Lazarus Group executed Responder using the command [Responder file path] -i [IP address] -rPv on a compromised host to harvest credentials and move laterally.
- [G0102] Wizard Spider: Wizard Spider has used the Invoke-Inveigh PowerShell cmdlets, likely for name service poisoning.
- [S0192] Pupy: Pupy can sniff plaintext network credentials and use NBNS Spoofing to poison name services.
- [S0174] Responder: Responder is used to poison name services to gather hashes and credentials from systems within a local network.


### T1557.002 - Adversary-in-the-Middle: ARP Cache Poisoning
Adversaries may poison Address Resolution Protocol (ARP) caches to position themselves between the communication of two or more networked devices. This activity may be used to enable follow-on behaviors such as Network Sniffing or Transmitted Data Manipulation. The ARP protocol is used to resolve IPv4 addresses to link layer addresses, such as a media access control (MAC) address. Devices in a local network segment communicate with each other by using link layer addresses. If a networked device does not have the link layer address of a particular networked device, it may send out a broadcast ARP request to the local network to translate the IP address to a MAC address. The device with the associated IP address directly replies with its MAC address. The networked device that made the ARP request will then use as well as store that information in its ARP cache. An adversary may passively wait for an ARP request to poison the ARP cache of the requesting device. The adversary may reply with their MAC address, thus deceiving the victim by making them believe that they are communicating with the intended networked device. For the adversary to poison the ARP cache, their reply must be faster than the one made by the legitimate IP address owner. Adversaries may also send a gratuitous ARP reply that maliciously announces the ownership of a particular IP address to all the devices in the local network segment. The ARP protocol is stateless and does not require authentication. Therefore, devices may wrongly add or update the MAC address of the IP address in their ARP cache. Adversaries may use ARP cache poisoning as a means to intercept network traffic. This activity may be used to collect and/or relay data such as credentials, especially those sent over an insecure, unencrypted protocol.
**Detection**
- [AN1093] **[macOS]** Detects anomalous ARP cache changes and unsolicited ARP broadcasts using unified logs and packet capture. Behavioral detection includes multiple IP addresses mapped to the same MAC address and repeated gratuitous ARP traffic.
- [AN1092] **[Linux]** Detects suspicious gratuitous ARP responses or inconsistent IP-to-MAC mappings using auditd and packet capture. Behavioral focus is on unsolicited replies overriding legitimate ARP ownership.
- [AN1091] **[Windows]** Detects anomalous ARP traffic or cache modifications on Windows endpoints that indicate ARP poisoning. Behavioral focus is on multiple IP addresses resolving to a single MAC, or unsolicited ARP replies from unauthorized devices.
**Procedure Examples**
- [G0003] Cleaver: Cleaver has used custom tools to facilitate ARP cache poisoning.
- [G1014] LuminousMoth: LuminousMoth has used ARP spoofing to redirect a compromised machine to an actor-controlled website.


### T1557.003 - Adversary-in-the-Middle: DHCP Spoofing
Adversaries may redirect network traffic to adversary-owned systems by spoofing Dynamic Host Configuration Protocol (DHCP) traffic and acting as a malicious DHCP server on the victim network. By achieving the adversary-in-the-middle (AiTM) position, adversaries may collect network communications, including passed credentials, especially those sent over insecure, unencrypted protocols. This may also enable follow-on behaviors such as Network Sniffing or Transmitted Data Manipulation. DHCP is based on a client-server model and has two functionalities: a protocol for providing network configuration settings from a DHCP server to a client and a mechanism for allocating network addresses to clients. The typical server-client interaction is as follows: 1. The client broadcasts a `DISCOVER` message. 2. The server responds with an `OFFER` message, which includes an available network address. 3. The client broadcasts a `REQUEST` message, which includes the network address offered. 4. The server acknowledges with an `ACK` message and the client receives the network configuration parameters. Adversaries may spoof as a rogue DHCP server on the victim network, from which legitimate hosts may receive malicious network configurations. For example, malware can act as a DHCP server and provide adversary-owned DNS servers to the victimized computers. Through the malicious network configurations, an adversary may achieve the AiTM position, route client traffic through adversary-controlled systems, and collect information from the client network. DHCPv6 clients can receive network configuration information without being assigned an IP address by sending a INFORMATION-REQUEST (code 11) message to the All_DHCP_Relay_Agents_and_Servers multicast address. Adversaries may use their rogue DHCP server to respond to this request message with malicious network configurations. Rather than establishing an AiTM position, adversaries may also abuse DHCP spoofing to perform a DHCP exhaustion attack (i.e, Service Exhaustion Flood) by generating many broadcast DISCOVER messages to exhaust a network’s DHCP allocation pool.
**Detection**
- [AN1291] **[Linux]** Detects rogue DHCP activity by monitoring syslog for dhclient messages assigning unauthorized DNS/gateway values. Packet capture or IDS can detect multiple competing DHCP OFFERs from non-authorized servers.
- [AN1292] **[macOS]** Detects DHCP spoofing by monitoring unified logs for unexpected DHCP ACK/OFFER parameters and correlating with packet captures for multiple DHCP servers. Behavioral emphasis is on inconsistent DNS and gateway assignments that redirect traffic.
- [AN1290] **[Windows]** Detects rogue DHCP server activity and anomalous DHCP OFFER/ACK messages assigning unexpected DNS or gateway values. Detection correlates DHCP server role changes, DHCP exhaustion warnings, and sudden network configuration changes across endpoints.
Adversaries may redirect network traffic to adversary-owned systems by spoofing Dynamic Host Configuration Protocol (DHCP) traffic and acting as a malicious DHCP server on the victim network. By achieving the adversary-in-the-middle (AiTM) position, adversaries may collect network communications, including passed credentials, especially those sent over insecure, unencrypted protocols. This may also enable follow-on behaviors such as Network Sniffing or Transmitted Data Manipulation. DHCP is based on a client-server model and has two functionalities: a protocol for providing network configuration settings from a DHCP server to a client and a mechanism for allocating network addresses to clients. The typical server-client interaction is as follows: 1. The client broadcasts a `DISCOVER` message. 2. The server responds with an `OFFER` message, which includes an available network address. 3. The client broadcasts a `REQUEST` message, which includes the network address offered. 4. The server acknowledges with an `ACK` message and the client receives the network configuration parameters. Adversaries may spoof as a rogue DHCP server on the victim network, from which legitimate hosts may receive malicious network configurations. For example, malware can act as a DHCP server and provide adversary-owned DNS servers to the victimized computers. Through the malicious network configurations, an adversary may achieve the AiTM position, route client traffic through adversary-controlled systems, and collect information from the client network. DHCPv6 clients can receive network configuration information without being assigned an IP address by sending a INFORMATION-REQUEST (code 11) message to the All_DHCP_Relay_Agents_and_Servers multicast address. Adversaries may use their rogue DHCP server to respond to this request message with malicious network configurations. Rather than establishing an AiTM position, adversaries may also abuse DHCP spoofing to perform a DHCP exhaustion attack (i.e, Service Exhaustion Flood) by generating many broadcast DISCOVER messages to exhaust a network’s DHCP allocation pool.


### T1557.004 - Adversary-in-the-Middle: Evil Twin
Adversaries may host seemingly genuine Wi-Fi access points to deceive users into connecting to malicious networks as a way of supporting follow-on behaviors such as Network Sniffing, Transmitted Data Manipulation, or Input Capture. By using a Service Set Identifier (SSID) of a legitimate Wi-Fi network, fraudulent Wi-Fi access points may trick devices or users into connecting to malicious Wi-Fi networks. Adversaries may provide a stronger signal strength or block access to Wi-Fi access points to coerce or entice victim devices into connecting to malicious networks. A Wi-Fi Pineapple – a network security auditing and penetration testing tool – may be deployed in Evil Twin attacks for ease of use and broader range. Custom certificates may be used in an attempt to intercept HTTPS traffic. Similarly, adversaries may also listen for client devices sending probe requests for known or previously connected networks (Preferred Network Lists or PNLs). When a malicious access point receives a probe request, adversaries can respond with the same SSID to imitate the trusted, known network. Victim devices are led to believe the responding access point is from their PNL and initiate a connection to the fraudulent network. Upon logging into the malicious Wi-Fi access point, a user may be directed to a fake login page or captive portal webpage to capture the victim’s credentials. Once a user is logged into the fraudulent Wi-Fi network, the adversary may able to monitor network activity, manipulate data, or steal additional credentials. Locations with high concentrations of public Wi-Fi access, such as airports, coffee shops, or libraries, may be targets for adversaries to set up illegitimate Wi-Fi access points.
**Detection**
- [AN1069] **[Network Devices]** Detects rogue Wi-Fi access points broadcasting the same SSID as legitimate APs with stronger signal strength, unexpected MAC/BSSID values, or inconsistent encryption settings. Correlates authentication attempts, captive portal redirections, and anomalous traffic flows through unauthorized APs.
**Procedure Examples**
- [G0007] APT28: APT28 has used a Wi-Fi Pineapple to set up Evil Twin Wi-Fi Poisoning for the purposes of capturing victim credentials or planting espionage-oriented malware.


### T1560 - Archive Collected Data
An adversary may compress and/or encrypt data that is collected prior to exfiltration. Compressing the data can help to obfuscate the collected data and minimize the amount of data sent over the network. Encryption can be used to hide information that is being exfiltrated from detection or make exfiltration less conspicuous upon inspection by a defender. Both compression and encryption are done prior to exfiltration, and can be performed using a utility, 3rd party library, or custom method.
**Detection**
- [AN1460] **[macOS]** Detects use of macOS-native archiving or encryption tools (zip, ditto, hdiutil) for staging collected data. Identifies unexpected invocation of archive utilities by Office apps, browsers, or background daemons. Correlates file creation of .zip/.dmg containers with process lineage anomalies.
- [AN1459] **[Linux]** Detects adversarial archiving activity through invocation of utilities like tar, gzip, bzip2, or openssl used in non-administrative or unusual contexts. Correlates command execution patterns with file creation of compressed/encrypted outputs in staging directories (e.g., /tmp, /var/tmp).
- [AN1458] **[Windows]** Detects adversarial archiving of files prior to exfiltration by correlating execution of compression/encryption utilities (e.g., makecab.exe, rar.exe, 7z.exe, powershell Compress-Archive) with subsequent creation of large compressed or encrypted files. Identifies abnormal process lineage involving crypt32.dll usage, command-line arguments invoking compression switches, and file write operations to temporary or staging directories.
**Procedure Examples**
- [G0035] Dragonfly: Dragonfly has compressed data into .zip files prior to exfiltration.
- [S0667] Chrommme: Chrommme can encrypt and store on disk collected data before exfiltration.
- [G0040] Patchwork: Patchwork encrypted the collected files' path with AES and then encoded them with base64.
- [S0343] Exaramel for Windows: Exaramel for Windows automatically encrypts files before sending them to the C2 server.
- [S0586] TAINTEDSCRIBE: TAINTEDSCRIBE has used FileReadZipSend to compress a file and send to C2.
- [G0001] Axiom: Axiom has compressed and encrypted data prior to exfiltration.
- [S1101] LoFiSe: LoFiSe can collect files into password-protected ZIP-archives for exfiltration.
- [S0521] BloodHound: BloodHound can compress data collected by its SharpHound ingestor into a ZIP file to be written to disk.
- [S0045] ADVSTORESHELL: ADVSTORESHELL encrypts with the 3DES algorithm and a hardcoded key prior to exfiltration.
- [G1003] Ember Bear: Ember Bear has compressed collected data prior to exfiltration.


### T1560.001 - Archive Collected Data: Archive via Utility
Adversaries may use utilities to compress and/or encrypt collected data prior to exfiltration. Many utilities include functionalities to compress, encrypt, or otherwise package data into a format that is easier/more secure to transport. Adversaries may abuse various utilities to compress or encrypt data before exfiltration. Some third party utilities may be preinstalled, such as tar on Linux and macOS or zip on Windows systems. On Windows, diantz or makecab may be used to package collected files into a cabinet (.cab) file. diantz may also be used to download and compress files from remote locations (i.e. Remote Data Staging). xcopy on Windows can copy files and directories with a variety of options. Additionally, adversaries may use certutil to Base64 encode collected data before exfiltration. Adversaries may use also third party utilities, such as 7-Zip, WinRAR, and WinZip, to perform similar activities.
**Detection**
- [AN0833] **[macOS]** Detects invocation of macOS-native archiving utilities (zip, ditto, hdiutil) or openssl used for encryption. Correlates execution with archive or encrypted file creation (.zip, .dmg, .tar.gz) in user or temporary directories. Identifies anomalous use of archiving commands by Office applications or daemons.
- [AN0832] **[Linux]** Detects execution of archiving utilities (tar, gzip, bzip2, xz, zip, openssl) followed by suspicious archive file creation. Correlates archive creation in temporary or staging directories with execution of commands involving compression or encryption options.
- [AN0831] **[Windows]** Detects adversarial archiving using built-in or third-party utilities (makecab, diantz, xcopy, certutil, 7z, WinRAR, WinZip). Correlates suspicious process creation events with command-line arguments for compression/encoding, followed by creation of archive files (.cab, .zip, .7z, .rar). Identifies anomalous loading of crypt32.dll for encryption operations or execution of diantz.exe to compress remotely staged files.
**Procedure Examples**
- [S0538] Crutch: Crutch has used the WinRAR utility to compress and encrypt stolen files.
- [S0439] Okrum: Okrum was seen using a RAR archiver tool to compress/decompress data.
- [G0125] HAFNIUM: HAFNIUM has used 7-Zip and WinRAR to compress stolen files for exfiltration.
- [S0160] certutil: certutil may be used to Base64 encode collected data.
- [C0012] Operation CuckooBees: During Operation CuckooBees, the threat actors used the Makecab utility to compress and a version of WinRAR to create password-protected archives of stolen data prior to exfiltration.
- [G0045] menuPass: menuPass has compressed files before exfiltration using TAR and RAR.
- [G0102] Wizard Spider: Wizard Spider has archived data into ZIP files on compromised machines.
- [G0064] APT33: APT33 has used WinRAR to compress data prior to exfil.
- [C0051] APT28 Nearest Neighbor Campaign: During APT28 Nearest Neighbor Campaign, APT28 used built-in PowerShell capabilities (Compress-Archive cmdlet) to compress collected data.
- [S1043] ccf32: ccf32 has used `xcopy \\\c$\users\public\path.7z c:\users\public\bin\.7z /H /Y` to archive collected files.


### T1560.002 - Archive Collected Data: Archive via Library
An adversary may compress or encrypt data that is collected prior to exfiltration using 3rd party libraries. Many libraries exist that can archive data, including Python rarfile , libzip , and zlib . Most libraries include functionality to encrypt and/or compress data. Some archival libraries are preinstalled on systems, such as bzip2 on macOS and Linux, and zip on Windows. Note that the libraries are different from the utilities. The libraries can be linked against when compiling, while the utilities require spawning a subshell, or a similar execution mechanism.
**Detection**
- [AN0747] **[Windows]** Detects adversarial archiving using libraries (zlib, zip APIs) invoked by scripts or binaries. Correlates process executions of Python, PowerShell, or custom .NET binaries with DLL/module loads linked to compression libraries, followed by archive file creation.
- [AN0749] **[macOS]** Detects malicious archiving via system or third-party libraries (libz, libarchive) invoked by Python, Swift, or Objective-C binaries. Correlates unified logs of library loads with creation of compressed or encrypted archives (.zip, .gz, .bz2, .dmg).
- [AN0748] **[Linux]** Detects adversarial archiving by scripts or binaries calling compression libraries (libzip, zlib, bzip2). Correlates execution of Python, Perl, or compiled binaries with dynamic linking to archiving libraries and creation of compressed files in /tmp or user directories.
**Procedure Examples**
- [S0467] TajMahal: TajMahal has the ability to use the open source libraries XZip/Xunzip and zlib to compress files.
- [S1141] LunarWeb: LunarWeb can zlib-compress data prior to exfiltration.
- [S0086] ZLib: The ZLib backdoor compresses communications using the standard Zlib compression library.
- [S0127] BBSRAT: BBSRAT can compress data with ZLIB prior to sending it back to the C2 server.
- [S0260] InvisiMole: InvisiMole can use zlib to compress and decompress data.
- [S0053] SeaDuke: SeaDuke compressed data with zlib prior to sending it over C2.
- [S0354] Denis: Denis compressed collected data using zlib.
- [S0091] Epic: Epic compresses the collected data with bzip2 before sending it to the C2 server.
- [S0642] BADFLICK: BADFLICK has compressed data using the aPLib compression library.
- [S0348] Cardinal RAT: Cardinal RAT applies compression to C2 traffic using the ZLIB library.


### T1560.003 - Archive Collected Data: Archive via Custom Method
An adversary may compress or encrypt data that is collected prior to exfiltration using a custom method. Adversaries may choose to use custom archival methods, such as encryption with XOR or stream ciphers implemented with no external library or utility references. Custom implementations of well-known compression algorithms have also been used.
**Detection**
- [AN1215] **[macOS]** Detects custom archiving by monitoring execution of Swift/Objective-C apps or scripts producing high-entropy files with non-standard headers. Correlates unified logs of abnormal NSFileHandle/NSData operations, memory use of XOR/bitwise operations, and file creation events.
- [AN1214] **[Linux]** Detects custom archive routines by correlating script execution (Python, Perl, Bash) with creation of high-entropy files in temporary or user directories. Flags processes performing unusual bitwise operations or writing files without standard compression headers.
- [AN1213] **[Windows]** Detects suspicious custom compression/encryption routines through anomalous script or binary execution that produces high-entropy files without standard archiving utilities. Correlates script execution, memory API usage (bitwise ops, CryptoAPI calls), and creation of archive-like files with uncommon headers.
**Procedure Examples**
- [S0438] Attor: Attor encrypts collected data with a custom implementation of Blowfish and RSA ciphers.
- [S0657] BLUELIGHT: BLUELIGHT has encoded data into a binary blob using XOR.
- [G0037] FIN6: FIN6 has encoded data gathered from the victim with a simple substitution cipher and single-byte XOR using the 0xAA key, and Base64 with character permutation.
- [S0038] Duqu: Modules can be pushed to and executed by Duqu that copy data to a staging area, compress it, and XOR encrypt it.
- [S0603] Stuxnet: Stuxnet encrypts exfiltrated data via C2 with static 31-byte long XOR keys.
- [S0035] SPACESHIP: Data SPACESHIP copies to the staging area is compressed with zlib. Bytes are rotated by four positions and XOR'ed with 0x23.
- [G0052] CopyKittens: CopyKittens encrypts data with a substitute cipher prior to exfiltration.
- [S0661] FoggyWeb: FoggyWeb can use a dynamic XOR key and a custom XOR methodology to encode data before exfiltration. Also, FoggyWeb can encode C2 command output within a legitimate WebP file.
- [S0198] NETWIRE: NETWIRE has used a custom encryption algorithm to encrypt collected data.
- [S0448] Rising Sun: Rising Sun can archive data using RC4 encryption and Base64 encoding prior to exfiltration.


### T1602 - Data from Configuration Repository
Adversaries may collect data related to managed devices from configuration repositories. Configuration repositories are used by management systems in order to configure, manage, and control data on remote systems. Configuration repositories may also facilitate remote access and administration of devices. Adversaries may target these repositories in order to collect large quantities of sensitive system administration data. Data from configuration repositories may be exposed by various protocols and software and can store a wide variety of data, much of which may align with adversary Discovery objectives.
**Detection**
- [AN1630] **[Network Devices]** Defenders may observe adversary attempts to extract configuration data from management repositories by monitoring for anomalous SNMP queries, API calls, or protocol requests (e.g., NETCONF, RESTCONF) that enumerate system configuration. Suspicious sequences include repeated queries from untrusted IPs, abnormal query types requesting sensitive configuration data, or repository access occurring outside of normal administrative maintenance windows. Abnormal authentication attempts, sudden enumeration of device inventory, or bulk data transfer of configuration files may also be observed.
Adversaries may collect data related to managed devices from configuration repositories. Configuration repositories are used by management systems in order to configure, manage, and control data on remote systems. Configuration repositories may also facilitate remote access and administration of devices. Adversaries may target these repositories in order to collect large quantities of sensitive system administration data. Data from configuration repositories may be exposed by various protocols and software and can store a wide variety of data, much of which may align with adversary Discovery objectives.


### T1602.001 - Data from Configuration Repository: SNMP (MIB Dump)
Adversaries may target the Management Information Base (MIB) to collect and/or mine valuable information in a network managed using Simple Network Management Protocol (SNMP). The MIB is a configuration repository that stores variable information accessible via SNMP in the form of object identifiers (OID). Each OID identifies a variable that can be read or set and permits active management tasks, such as configuration changes, through remote modification of these variables. SNMP can give administrators great insight in their systems, such as, system information, description of hardware, physical location, and software packages. The MIB may also contain device operational information, including running configuration, routing table, and interface details. Adversaries may use SNMP queries to collect MIB content directly from SNMP-managed devices in order to collect network information that allows the adversary to build network maps and facilitate future targeted exploitation.
**Detection**
- [AN1249] **[Network Devices]** Defenders may observe suspicious SNMP MIB enumeration through abnormal queries for large sets of OIDs, repeated SNMP GETBULK/GETNEXT requests, or queries originating from non-administrative IP addresses. Anomalous use of community strings, authentication failures, or enumeration activity outside maintenance windows may also indicate attempts to dump MIB contents. Correlation across syslog, NetFlow, and SNMP audit data can reveal chains of behavior such as repeated authentication failures followed by successful large-scale OID retrieval.
Adversaries may target the Management Information Base (MIB) to collect and/or mine valuable information in a network managed using Simple Network Management Protocol (SNMP). The MIB is a configuration repository that stores variable information accessible via SNMP in the form of object identifiers (OID). Each OID identifies a variable that can be read or set and permits active management tasks, such as configuration changes, through remote modification of these variables. SNMP can give administrators great insight in their systems, such as, system information, description of hardware, physical location, and software packages. The MIB may also contain device operational information, including running configuration, routing table, and interface details. Adversaries may use SNMP queries to collect MIB content directly from SNMP-managed devices in order to collect network information that allows the adversary to build network maps and facilitate future targeted exploitation.


### T1602.002 - Data from Configuration Repository: Network Device Configuration Dump
Adversaries may access network configuration files to collect sensitive data about the device and the network. The network configuration is a file containing parameters that determine the operation of the device. The device typically stores an in-memory copy of the configuration while operating, and a separate configuration on non-volatile storage to load after device reset. Adversaries can inspect the configuration files to reveal information about the target network and its layout, the network device and its software, or identifying legitimate accounts and credentials for later use. Adversaries can use common management tools and protocols, such as Simple Network Management Protocol (SNMP) and Smart Install (SMI), to access network configuration files. These tools may be used to query specific data from a configuration repository or configure the device to export the configuration for later analysis.
**Detection**
- [AN0647] **[Network Devices]** Defenders may observe adversary attempts to collect or export full device configurations by detecting unusual SNMP queries, Smart Install (SMI) activity, or CLI/API commands that request running or startup configuration dumps. Correlated behaviors include high-volume read requests for sensitive OIDs, repeated use of 'show running-config' or equivalent commands from untrusted IPs, or unexpected TFTP/SCP/FTP transfers containing configuration files. These behaviors often appear in sequence: anomalous authentication or privilege escalation, followed by bulk configuration retrieval and outbound transfer.
**Procedure Examples**
- [G1045] Salt Typhoon: Salt Typhoon has attempted to acquire credentials by dumping network device configurations.

