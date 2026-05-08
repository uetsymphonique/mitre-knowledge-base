### T1021 - Remote Services
Adversaries may use Valid Accounts to log into a service that accepts remote connections, such as telnet, SSH, and VNC. The adversary may then perform actions as the logged-on user. In an enterprise environment, servers and workstations can be organized into domains. Domains provide centralized identity management, allowing users to login using one set of credentials across the entire network. If an adversary is able to obtain a set of valid domain credentials, they could login to many different machines using remote access protocols such as secure shell (SSH) or remote desktop protocol (RDP). They could also login to accessible SaaS or IaaS services, such as those that federate their identities to the domain, or management platforms for internal virtualization environments such as VMware vCenter. Legitimate applications (such as Software Deployment Tools and other administrative programs) may utilize Remote Services to access remote hosts. For example, Apple Remote Desktop (ARD) on macOS is native software used for remote management. ARD leverages a blend of protocols, including VNC to send the screen and control buffers and SSH for secure file transfer. Adversaries can abuse applications such as ARD to gain remote code execution and perform lateral movement. In versions of macOS prior to 10.14, an adversary can escalate an SSH session to an ARD session which enables an adversary to accept TCC (Transparency, Consent, and Control) prompts without user interaction and gain access to data.
**Detection**
- [AN0750] **[Windows]** Logon via RDP or WMI by a user account followed by uncommon command execution, file manipulation, or lateral network connections.
  - **Log sources:** `WinEventLog:Security` (EventCode=4624, 4648) [Logon Session Creation], `WinEventLog:Sysmon` (EventCode=1) [Process Creation], `WinEventLog:Sysmon` (EventCode=3, 22) [Network Connection Creation]
- [AN0754] **[ESXi]** vSphere API logins (vimService) or SSH to ESXi host followed by unauthorized shell commands or lateral remote logins from the ESXi host.
  - **Log sources:** `esxi:vmkernel` (vim.fault.*, DCUI login, SSH shell) [Logon Session Creation], `esxi:shell` (Command execution trace) [Command Execution]
- [AN0751] **[Linux]** SSH session from new source IP followed by interactive shell or privilege escalation (e.g., sudo, su) and outbound lateral connection.
  - **Log sources:** `linux:syslog` (sshd: Accepted password/publickey) [Logon Session Creation], `auditd:SYSCALL` (execve, USER_CMD) [Command Execution]
- [AN0753] **[IaaS]** Use of cloud-based bastion or VM console session followed by commands that initiate outbound SSH or RDP sessions from the cloud instance to other environments.
  - **Log sources:** `AWS:CloudTrail` (AWS ConsoleLogin, StartSession) [Logon Session Creation], `AWS:VPCFlowLogs` (Outbound connections to port 22, 3389) [Network Connection Creation]
- [AN0752] **[macOS]** Remote login via ARD or SSH followed by screensharingd process activity or modification of TCC-protected files.
  - **Log sources:** `macos:unifiedlog` (eventMessage CONTAINS 'screensharingd' or 'AuthorizationRefCreate') [Logon Session Creation], `macos:osquery` (process_events) [Process Creation]
**Procedure Examples**
- [G0102] Wizard Spider: Wizard Spider has used the WebDAV protocol to execute Ryuk payloads hosted on network file shares.
- [S1016] MacMa: MacMa can manage remote screen sessions.
- [S1063] Brute Ratel C4: Brute Ratel C4 has the ability to use RPC for lateral movement.
- [S0437] Kivars: Kivars has the ability to remotely trigger keyboard input and mouse clicks.
- [G0143] Aquatic Panda: Aquatic Panda used remote scheduled tasks to install malicious software on victim systems during lateral movement actions.
- [S0603] Stuxnet: Stuxnet can propagate via peer-to-peer communication and updates using RPC.
- [G1003] Ember Bear: Ember Bear uses valid network credentials gathered through credential harvesting to move laterally within victim networks, often employing the Impacket framework to do so.


### T1021.001 - Remote Services: Remote Desktop Protocol
Adversaries may use Valid Accounts to log into a computer using the Remote Desktop Protocol (RDP). The adversary may then perform actions as the logged-on user. Remote desktop is a common feature in operating systems. It allows a user to log into an interactive session with a system desktop graphical user interface on a remote system. Microsoft refers to its implementation of the Remote Desktop Protocol (RDP) as Remote Desktop Services (RDS). Adversaries may connect to a remote system over RDP/RDS to expand access if the service is enabled and allows access to accounts with known credentials. Adversaries will likely use Credential Access techniques to acquire credentials to use with RDP. Adversaries may also use RDP in conjunction with the Accessibility Features or Terminal Services DLL for Persistence.
**Detection**
- [AN0931] **[Windows]** Remote Desktop (RDP) logon by a user followed by unusual process execution, file access, or lateral movement activity within a short timeframe.
  - **Log sources:** `WinEventLog:Security` (EventCode=4624, 4648) [Logon Session Creation], `WinEventLog:Security` (EventCode=4778, EventCode=4779) [Logon Session Metadata], `WinEventLog:Sysmon` (EventCode=3, 22) [Network Connection Creation], `WinEventLog:Sysmon` (EventCode=1) [Process Creation]
**Procedure Examples**
- [G0094] Kimsuky: Kimsuky has used RDP for direct remote point-and-click access.
- [G1032] INC Ransom: INC Ransom has used RDP to move laterally.
- [S0154] Cobalt Strike: Cobalt Strike can start a VNC-based remote desktop server and tunnel the connection through the already established C2 channel.
- [S0262] QuasarRAT: QuasarRAT has a module for performing remote desktop access.
- [G1017] Volt Typhoon: Volt Typhoon has moved laterally to the Domain Controller via RDP using a compromised account with domain administrator privileges.
- [G1023] APT5: APT5 has moved laterally throughout victim environments using RDP.
- [S0350] zwShell: zwShell has used RDP for lateral movement.
- [G0049] OilRig: OilRig has used Remote Desktop Protocol for lateral movement. The group has also used tunneling tools to tunnel RDP into the environment.
- [G0040] Patchwork: Patchwork attempted to use RDP to move laterally.
- [G0061] FIN8: FIN8 has used RDP for lateral movement.


### T1021.002 - Remote Services: SMB/Windows Admin Shares
Adversaries may use Valid Accounts to interact with a remote network share using Server Message Block (SMB). The adversary may then perform actions as the logged-on user. SMB is a file, printer, and serial port sharing protocol for Windows machines on the same network or domain. Adversaries may use SMB to interact with file shares, allowing them to move laterally throughout a network. Linux and macOS implementations of SMB typically use Samba. Windows systems have hidden network shares that are accessible only to administrators and provide the ability for remote file copy and other administrative functions. Example network shares include `C$`, `ADMIN$`, and `IPC$`. Adversaries may use this technique in conjunction with administrator-level Valid Accounts to remotely access a networked system over SMB, to interact with systems using remote procedure calls (RPCs), transfer files, and run transferred binaries through remote Execution. Example execution techniques that rely on authenticated sessions over SMB/RPC are Scheduled Task/Job, Service Execution, and Windows Management Instrumentation. Adversaries can also use NTLM hashes to access administrator shares on systems with Pass the Hash and certain configuration and patch levels.
**Detection**
- [AN1468] **[Windows]** An SMB-based remote file share access followed by lateral movement actions such as remote service creation, task scheduling, or suspicious process execution on the target host using ADMIN$ or C$ shares.
  - **Log sources:** `WinEventLog:Security` (EventCode=4624, 4648) [Logon Session Creation], `WinEventLog:Sysmon` (EventCode=3, 22) [Network Connection Creation], `WinEventLog:Sysmon` (EventCode=1) [Process Creation]
**Procedure Examples**
- [S0575] Conti: Conti can spread via SMB and encrypts files on different hosts, potentially compromising an entire network.
- [G1009] Moses Staff: Moses Staff has used batch scripts that can enable SMB on a compromised host.
- [G0028] Threat Group-1314: Threat Group-1314 actors mapped network drives using net use.
- [C0049] Leviathan Australian Intrusions: Leviathan used remote shares to move laterally through victim networks during Leviathan Australian Intrusions.
- [S0698] HermeticWizard: HermeticWizard can use a list of hardcoded credentials to to authenticate via NTLMSSP to the SMB shares on remote systems.
- [G0143] Aquatic Panda: Aquatic Panda used remote shares to enable lateral movement in victim environments.
- [S0367] Emotet: Emotet has leveraged the Admin$, C$, and IPC$ shares for lateral movement.
- [S0350] zwShell: zwShell has been copied over network shares to move laterally.
- [S0446] Ryuk: Ryuk has used the C$ network share for lateral movement.
- [S0029] PsExec: PsExec, a tool that has been used by adversaries, writes programs to the ADMIN$ network share to execute commands on remote systems.


### T1021.003 - Remote Services: Distributed Component Object Model
Adversaries may use Valid Accounts to interact with remote machines by taking advantage of Distributed Component Object Model (DCOM). The adversary may then perform actions as the logged-on user. The Windows Component Object Model (COM) is a component of the native Windows application programming interface (API) that enables interaction between software objects, or executable code that implements one or more interfaces. Through COM, a client object can call methods of server objects, which are typically Dynamic Link Libraries (DLL) or executables (EXE). Distributed COM (DCOM) is transparent middleware that extends the functionality of COM beyond a local computer using remote procedure call (RPC) technology. Permissions to interact with local and remote server COM objects are specified by access control lists (ACL) in the Registry. By default, only Administrators may remotely activate and launch COM objects through DCOM. Through DCOM, adversaries operating in the context of an appropriately privileged user can remotely obtain arbitrary and even direct shellcode execution through Office applications as well as other Windows objects that contain insecure methods. DCOM can also execute macros in existing documents and may also invoke Dynamic Data Exchange (DDE) execution directly through a COM created instance of a Microsoft Office application, bypassing the need for a malicious document. DCOM can be used as a method of remotely interacting with Windows Management Instrumentation.
**Detection**
- [AN0791] **[Windows]** A remote DCOM invocation by a privileged account using RPC (port 135), followed by abnormal process instantiation or module loading on the remote system indicative of code execution.
  - **Log sources:** `WinEventLog:Security` (EventCode=4624, 4648) [Logon Session Creation], `WinEventLog:Sysmon` (EventCode=3, 22) [Network Connection Creation], `WinEventLog:Sysmon` (EventCode=1) [Process Creation], `WinEventLog:Sysmon` (EventCode=7) [Module Load]
**Procedure Examples**
- [S0363] Empire: Empire can utilize Invoke-DCOM to leverage remote COM execution for lateral movement.
- [S0692] SILENTTRINITY: SILENTTRINITY can use `System` namespace methods to execute lateral movement using DCOM.
- [S0154] Cobalt Strike: Cobalt Strike can deliver Beacon payloads for lateral movement by leveraging remote COM execution.


### T1021.004 - Remote Services: SSH
Adversaries may use Valid Accounts to log into remote machines using Secure Shell (SSH). The adversary may then perform actions as the logged-on user. SSH is a protocol that allows authorized users to open remote shells on other computers. Many Linux and macOS versions come with SSH installed by default, although typically disabled until the user enables it. On ESXi, SSH can be enabled either directly on the host (e.g., via `vim-cmd hostsvc/enable_ssh`) or via vCenter. The SSH server can be configured to use standard password authentication or public-private keypairs in lieu of or in addition to a password. In this authentication scenario, the user’s public key must be in a special file on the computer running the server that lists which keypairs are allowed to login as that user (i.e., SSH Authorized Keys).
**Detection**
- [AN1640] **[ESXi]** SSH login via hostd or `/var/log/auth.log`, followed by CLI access to host shell or file manipulation in restricted areas.
  - **Log sources:** `esxi:auth` (None) [Logon Session Metadata], `esxi:shell` (None) [Command Execution], `esxi:vmkernel` (port 22 access) [Network Traffic Flow]
- [AN1639] **[macOS]** SSH login detected via Unified Logs, followed by unusual process execution, especially outside normal user behavior patterns.
  - **Log sources:** `macos:unifiedlog` (process = 'sshd') [Logon Session Metadata], `macos:unifiedlog` (process = 'ssh' OR eventMessage CONTAINS 'ssh') [Network Traffic Content], `macos:osquery` (process_events) [Process Creation]
- [AN1638] **[Linux]** SSH login from a remote system (via sshd), followed by user context execution of suspicious binaries or privilege escalation behavior.
  - **Log sources:** `auditd:EXECVE` (EXECVE) [Process Creation], `linux:syslog` (None) [Logon Session Creation], `NSM:Flow` (TCP port 22 traffic) [Network Traffic Flow]
**Procedure Examples**
- [G0046] FIN7: FIN7 has used SSH to move laterally through victim environments.
- [G0032] Lazarus Group: Lazarus Group used SSH and the PuTTy PSCP utility to gain access to a restricted segment of a compromised network.
- [G0065] Leviathan: Leviathan used ssh for internal reconnaissance.
- [C0029] Cutting Edge: During Cutting Edge, threat actors used SSH for lateral movement.
- [C0032] C0032: During the C0032 campaign, TEMP.Veles relied on encrypted SSH-based tunnels to transfer tools and for remote command/program execution.
- [G1015] Scattered Spider: Scattered Spider has used SSH to move laterally in victim environments and to access the vSphere vCenter Server GUI.
- [G0098] BlackTech: BlackTech has used Putty for remote access.
- [S0363] Empire: Empire contains modules for executing commands over SSH as well as in-memory VNC agent injection.
- [G0143] Aquatic Panda: Aquatic Panda used SSH with captured user credentials to move laterally in victim environments.
- [S0154] Cobalt Strike: Cobalt Strike can SSH to a remote service.


### T1021.005 - Remote Services: VNC
Adversaries may use Valid Accounts to remotely control machines using Virtual Network Computing (VNC). VNC is a platform-independent desktop sharing system that uses the RFB (“remote framebuffer”) protocol to enable users to remotely control another computer’s display by relaying the screen, mouse, and keyboard inputs over the network. VNC differs from Remote Desktop Protocol as VNC is screen-sharing software rather than resource-sharing software. By default, VNC uses the system's authentication, but it can be configured to use credentials specific to VNC. Adversaries may abuse VNC to perform malicious actions as the logged-on user such as opening documents, downloading files, and running arbitrary commands. An adversary could use VNC to remotely control and monitor a system to collect data and information to pivot to other systems within the network. Specific VNC libraries/implementations have also been susceptible to brute force attacks and memory usage exploitation.
**Detection**
- [AN0504] **[Windows]** Detection of VNC service or executable starting unexpectedly, followed by user session creation and interactive desktop activity (mouse/keyboard simulation).
  - **Log sources:** `WinEventLog:Sysmon` (EventCode=1) [Process Creation], `WinEventLog:Security` (EventCode=4624, 4648) [Logon Session Creation], `NSM:Flow` (port 5900 inbound) [Network Traffic Flow]
- [AN0505] **[Linux]** Spawning of VNC-related processes (e.g., `x11vnc`, `vncserver`) coupled with authentication logs and port listening behavior on TCP 5900.
  - **Log sources:** `auditd:EXECVE` (None) [Process Creation], `linux:syslog` (None) [Logon Session Metadata], `NSM:Flow` (TCP port 5900 open) [Network Traffic Flow]
- [AN0506] **[macOS]** Detection of VNC-based remote control via `screensharingd` activity in Unified Logs along with concurrent remote login activity or suspicious user interaction.
  - **Log sources:** `macos:unifiedlog` (authentication) [Logon Session Creation], `macos:osquery` (process_events) [Process Creation], `NSM:firewall` (inbound connection to port 5900) [Network Traffic Flow]
**Procedure Examples**
- [S0412] ZxShell: ZxShell supports functionality for VNC sessions.
- [G0047] Gamaredon Group: Gamaredon Group has used VNC tools, including UltraVNC, to remotely interact with compromised hosts.
- [G0046] FIN7: FIN7 has used TightVNC to control compromised hosts.
- [S1014] DanBot: DanBot can use VNC for remote access to targeted systems.
- [S0484] Carberp: Carberp can start a remote VNC session by downloading a new plugin.
- [G0036] GCMAN: GCMAN uses VNC for lateral movement.
- [G0117] Fox Kitten: Fox Kitten has installed TightVNC server and client on compromised servers and endpoints for lateral movement.
- [S0266] TrickBot: TrickBot has used a VNC module to monitor the victim and collect information to pivot to valuable systems on the network
- [S0279] Proton: Proton uses VNC to connect into systems.
- [S0670] WarzoneRAT: WarzoneRAT has the ability of performing remote desktop access via a VNC console.


### T1021.006 - Remote Services: Windows Remote Management
Adversaries may use Valid Accounts to interact with remote systems using Windows Remote Management (WinRM). The adversary may then perform actions as the logged-on user. WinRM is the name of both a Windows service and a protocol that allows a user to interact with a remote system (e.g., run an executable, modify the Registry, modify services). It may be called with the `winrm` command or by any number of programs such as PowerShell. WinRM can be used as a method of remotely interacting with Windows Management Instrumentation.
**Detection**
- [AN1313] **[Windows]** Adversaries using WinRM to remotely execute commands, launch child processes, or access WMI. The detection chain includes service use, network activity, remote session logon, and process creation within a short temporal window.
  - **Log sources:** `WinEventLog:Security` (EventCode=4624, 4648) [Logon Session Creation], `WinEventLog:Sysmon` (EventCode=1) [Process Creation], `WinEventLog:WinRM` (EventCode=6) [Service Metadata], `NSM:Connections` (Inbound on ports 5985/5986) [Network Traffic Flow]
**Procedure Examples**
- [G1016] FIN13: FIN13 has leveraged `WMI` to move laterally within a compromised network via application servers and SQL servers.
- [S1063] Brute Ratel C4: Brute Ratel C4 can use WinRM for pivoting.
- [G0114] Chimera: Chimera has used WinRM for lateral movement.
- [G1053] Storm-0501: Storm-0501 has utilized the post-exploitation tool known as Evil-WinRM that uses PowerShell over Windows Remote Management (WinRM) for remote code execution.
- [C0024] SolarWinds Compromise: During the SolarWinds Compromise, APT29 used WinRM via PowerShell to execute commands and payloads on remote hosts.
- [S0154] Cobalt Strike: Cobalt Strike can use WinRM to execute a payload on a remote host.
- [C0048] Operation MidnightEclipse: During Operation MidnightEclipse, threat actors used WinRM to move laterally in targeted networks.
- [S0692] SILENTTRINITY: SILENTTRINITY tracks `TrustedHosts` and can move laterally to these targets via WinRM.
- [G0027] Threat Group-3390: Threat Group-3390 has used WinRM to enable remote execution.
- [G0102] Wizard Spider: Wizard Spider has used Window Remote Management to move laterally through a victim network.


### T1021.007 - Remote Services: Cloud Services
Adversaries may log into accessible cloud services within a compromised environment using Valid Accounts that are synchronized with or federated to on-premises user identities. The adversary may then perform management actions or access cloud-hosted resources as the logged-on user. Many enterprises federate centrally managed user identities to cloud services, allowing users to login with their domain credentials in order to access the cloud control plane. Similarly, adversaries may connect to available cloud services through the web console or through the cloud command line interface (CLI) (e.g., Cloud API), using commands such as Connect-AZAccount for Azure PowerShell, Connect-MgGraph for Microsoft Graph PowerShell, and gcloud auth login for the Google Cloud CLI. In some cases, adversaries may be able to authenticate to these services via Application Access Token instead of a username and password.
**Detection**
- [AN0017] **[IaaS]** Cloud login from atypical geolocation or user-agent string, followed by resource enumeration or infrastructure manipulation using cloud CLI/API
  - **Log sources:** `AWS:CloudTrail` (ConsoleLogin, AssumeRole, ListResources) [Logon Session Creation], `gcp:audit` (None) [Command Execution]
- [AN0019] **[Office Suite]** Login to M365 or Google Workspace from CLI tools or unexpected source IPs, followed by mailbox or document access
  - **Log sources:** `m365:unified` (FileAccessed, MailboxAccessed) [File Access], `m365:unified` (UserLoggedIn) [Logon Session Creation]
- [AN0018] **[Identity Provider]** Federated login using SSO or OAuth grant to cloud control plane, followed by directory or permissions enumeration
  - **Log sources:** `Okta:SystemLog` (user.authentication.sso, app.oauth.grant) [Logon Session Creation]
- [AN0020] **[SaaS]** Remote access to third-party SaaS with OAuth or API tokens post-initial compromise, followed by sensitive data access or configuration changes
  - **Log sources:** `saas:auth` (LoginSuccess, APIKeyUse, AdminAction) [Logon Session Creation]
**Procedure Examples**
- [C0027] C0027: During C0027, Scattered Spider used compromised Azure credentials for credential theft activity and lateral movement to on-premises systems.
- [G1053] Storm-0501: Storm-0501 has used compromised Entra Connect Sync Server to move laterally within the victim environment.
- [G0016] APT29: APT29 has leveraged compromised high-privileged on-premises accounts synced to Office 365 to move laterally into a cloud environment, including through the use of Azure AD PowerShell.
- [G1015] Scattered Spider: Scattered Spider has also leveraged pre-existing AWS EC2 instances for lateral movement and data collection purposes.


### T1021.008 - Remote Services: Direct Cloud VM Connections
Adversaries may leverage Valid Accounts to log directly into accessible cloud hosted compute infrastructure through cloud native methods. Many cloud providers offer interactive connections to virtual infrastructure that can be accessed through the Cloud API, such as Azure Serial Console, AWS EC2 Instance Connect, and AWS System Manager.. Methods of authentication for these connections can include passwords, application access tokens, or SSH keys. These cloud native methods may, by default, allow for privileged access on the host with SYSTEM or root level access. Adversaries may utilize these cloud native methods to directly access virtual infrastructure and pivot through an environment. These connections typically provide direct console access to the VM rather than the execution of scripts (i.e., Cloud Administration Command).
**Detection**
- [AN0594] **[IaaS]** Direct login to cloud-hosted virtual machines via cloud-native access methods (e.g., EC2 Instance Connect, Azure Serial Console, SSM), followed by command execution or privilege escalation on the VM
  - **Log sources:** `AWS:CloudTrail` (SendSSHPublicKey, StartSession (SSM), EC2InstanceConnect) [Logon Session Creation], `WinEventLog:Sysmon` (EventCode=1) [Process Creation]
Adversaries may leverage Valid Accounts to log directly into accessible cloud hosted compute infrastructure through cloud native methods. Many cloud providers offer interactive connections to virtual infrastructure that can be accessed through the Cloud API, such as Azure Serial Console, AWS EC2 Instance Connect, and AWS System Manager.. Methods of authentication for these connections can include passwords, application access tokens, or SSH keys. These cloud native methods may, by default, allow for privileged access on the host with SYSTEM or root level access. Adversaries may utilize these cloud native methods to directly access virtual infrastructure and pivot through an environment. These connections typically provide direct console access to the VM rather than the execution of scripts (i.e., Cloud Administration Command).


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


### T1080 - Taint Shared Content
Adversaries may deliver payloads to remote systems by adding content to shared storage locations, such as network drives or internal code repositories. Content stored on network drives or in other shared locations may be tainted by adding malicious programs, scripts, or exploit code to otherwise valid files. Once a user opens the shared tainted content, the malicious portion can be executed to run the adversary's code on a remote system. Adversaries may use tainted shared content to move laterally. A directory share pivot is a variation on this technique that uses several other techniques to propagate malware when users access a shared network directory. It uses Shortcut Modification of directory .LNK files that use Masquerading to look like the real directories, which are hidden through Hidden Files and Directories. The malicious .LNK-based directories have an embedded command that executes the hidden malware file in the directory and then opens the real intended directory so that the user's expected action still occurs. When used with frequently used network directories, the technique may result in frequent reinfections and broad access to systems and potentially to new and higher privileged accounts. Adversaries may also compromise shared network directories through binary infections by appending or prepending its code to the healthy binary on the shared network directory. The malware may modify the original entry point (OEP) of the healthy binary to ensure that it is executed before the legitimate code. The infection could continue to spread via the newly infected file when it is executed by a remote system. These infections may target both binary and non-binary formats that end with extensions including, but not limited to, .EXE, .DLL, .SCR, .BAT, and/or .VBS.
**Detection**
- [AN1300] **[macOS]** Detects modification of shared network folders via .app bundles or scripting files with hidden extensions (e.g., double extensions like docx.app).
  - **Log sources:** `fs:fsevents` (Directory events (kFSEventStreamEventFlagItemCreated)) [File Creation], `macos:unifiedlog` (file writes) [File Modification]
- [AN1301] **[SaaS]** Detects upload of malicious or unusual file types into cloud-shared folders, followed by user downloads or interactions.
  - **Log sources:** `gcp:workspaceaudit` (drive.activity logs) [File Creation], `m365:unified` (FileUploaded, FileAccessed) [Network Share Access]
- [AN1299] **[Linux]** Detects script or binary modification within shared NFS/SMB directories followed by process execution from those paths.
  - **Log sources:** `auditd:SYSCALL` (write) [File Modification], `NSM:Flow` (smb_files.log) [Network Share Access]
- [AN1298] **[Windows]** Detects adversary tampering of shared directories via file drops (e.g., malicious LNK, EXE, VBS) followed by user execution or suspicious network activity.
  - **Log sources:** `WinEventLog:Sysmon` (EventCode=11) [File Creation], `WinEventLog:Security` (EventCode=5145) [Network Share Access]
- [AN1302] **[Office Suite]** Detects embedded macros or scripts added to shared documents or use of external references to execute code.
  - **Log sources:** `m365:defender` (OfficeTelemetry or DLP) [File Modification]
**Procedure Examples**
- [S0132] H1N1: H1N1 has functionality to copy itself to network shares.
- [G0012] Darkhotel: Darkhotel used a virus that propagates by infecting executables stored on shared drives.
- [G1039] RedCurl: RedCurl has placed modified LNK files on network drives for lateral movement.
- [S0458] Ramsay: Ramsay can spread itself by infecting other portable executable files on networks shared drives.
- [G0047] Gamaredon Group: Gamaredon Group has injected malicious macros into all Word and Excel documents on mapped network drives.
- [G0060] BRONZE BUTLER: BRONZE BUTLER has placed malware on file shares and given it the same name as legitimate documents on the share.
- [S0260] InvisiMole: InvisiMole can replace legitimate software or documents in the compromised network with their trojanized versions, in an attempt to propagate itself within the network.
- [G1021] Cinnamon Tempest: Cinnamon Tempest has deployed ransomware from a batch file in a network share.
- [S0575] Conti: Conti can spread itself by infecting other remote machines via network shared drives.
- [S0133] Miner-C: Miner-C copies itself into the public folder of Network Attached Storage (NAS) devices and infects new victims who open the file.


### T1091 - Replication Through Removable Media
Adversaries may move onto systems, possibly those on disconnected or air-gapped networks, by copying malware to removable media and taking advantage of Autorun features when the media is inserted into a system and executes. In the case of Lateral Movement, this may occur through modification of executable files stored on removable media or by copying malware and renaming it to look like a legitimate file to trick users into executing it on a separate system. In the case of Initial Access, this may occur through manual manipulation of the media, modification of systems used to initially format the media, or modification to the media's firmware itself. Mobile devices may also be used to infect PCs with malware if connected via USB. This infection may be achieved using devices (Android, iOS, etc.) and, in some instances, USB charging cables. For example, when a smartphone is connected to a system, it may appear to be mounted similar to a USB-connected disk drive. If malware that is compatible with the connected system is on the mobile device, the malware could infect the machine (especially if Autorun features are enabled).
**Detection**
- [AN0841] **[Windows]** Execution of files originating from removable media after drive mount, with correlation to file write activity, autorun usage, or lateral spread via staged tools.
  - **Log sources:** `WinEventLog:System` (EventCode=1006) [Drive Creation], `WinEventLog:Sysmon` (EventCode=11) [File Creation], `WinEventLog:Sysmon` (EventCode=1) [Process Creation], `WinEventLog:Microsoft-Windows-Windows Defender/Operational` (Suspicious file execution on removable media path) [File Access]
**Procedure Examples**
- [S0143] Flame: Flame contains modules to infect USB sticks and spread laterally to other Windows systems the stick is plugged into using Autorun functionality.
- [S0028] SHIPSHAPE: APT30 may have used the SHIPSHAPE malware to move onto air-gapped networks. SHIPSHAPE targets removable drives to spread to other systems by modifying the drive to use Autorun to execute or by hiding legitimate document files and copying an executable to the folder with the same name as the legitimate document.
- [S1230] HIUPAN: HIUPAN has periodically checked for removable and hot-plugged drives connected to the infected machine, should one be found HIUPAN will propagate to the removeable drives by copying itself and accompanying malware components to a directory to the new drive in a hidden subdirectory `:\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\` and hides any other existing files to ensure UsbConfig.exe is the only visible file on the device.
- [G0047] Gamaredon Group: Gamaredon Group has replicated to removable media by leveraging the User Assist Reg Key and creating LNKs on all network and removable drives available on the infected host.
- [S0013] PlugX: PlugX has copied itself to infected removable drives for propagation to other victim devices.
- [G1014] LuminousMoth: LuminousMoth has used malicious DLLs to spread malware to connected removable USB drives on infected machines.
- [S0130] Unknown Logger: Unknown Logger is capable of spreading to USB devices.
- [G1007] Aoqin Dragon: Aoqin Dragon has used a dropper that employs a worm infection strategy using a removable device to breach a secure network environment.
- [S0062] DustySky: DustySky searches for removable media and duplicates itself onto it.
- [S0132] H1N1: H1N1 has functionality to copy itself to removable media.


### T1210 - Exploitation of Remote Services
Adversaries may exploit remote services to gain unauthorized access to internal systems once inside of a network. Exploitation of a software vulnerability occurs when an adversary takes advantage of a programming error in a program, service, or within the operating system software or kernel itself to execute adversary-controlled code. A common goal for post-compromise exploitation of remote services is for lateral movement to enable access to a remote system. An adversary may need to determine if the remote system is in a vulnerable state, which may be done through Network Service Discovery or other Discovery methods looking for common, vulnerable software that may be deployed in the network, the lack of certain patches that may indicate vulnerabilities, or security software that may be used to detect or contain remote exploitation. Servers are likely a high value target for lateral movement exploitation, but endpoint systems may also be at risk if they provide an advantage or access to additional resources. There are several well-known vulnerabilities that exist in common services such as SMB and RDP as well as applications that may be used within internal networks such as MySQL and web server services. Additionally, there have been a number of vulnerabilities in VMware vCenter installations, which may enable threat actors to move laterally from the compromised vCenter server to virtual machines or even to ESXi hypervisors. Depending on the permissions level of the vulnerable remote service an adversary may achieve Exploitation for Privilege Escalation as a result of lateral movement exploitation as well.
**Detection**
- [AN0329] **[ESXi]** Detects exploitation targeting ESXi/vCenter by correlating attempts to reach known exploitable endpoints (OpenSLP 427, CIM 5989, Hostd/Vpxa HTTPS 443, ESXi SOAP) with vmkernel/hostd crashes, unexpected hostd/vpxa restarts, or new reverse/outbound connections from ESXi host/vCenter to internal assets.
  - **Log sources:** `esxi:hostd` (Keywords: 'Backtrace','Signal 11','PANIC','hostd restarted','assert' or 'Service terminated unexpectedly' in /var/log/hostd.log, /var/log/vmkernel.log, /var/log/syslog.log.) [Application Log Content], `NSM:Flow` (Inbound to tcp/427 (OpenSLP), tcp/443 (vSphere APIs), tcp/902, tcp/5989 followed by new unexpected outbound sessions from the ESXi/vCenter host.) [Network Traffic Content]
- [AN0330] **[macOS]** Ties inbound access to exposed services (ARD/VNC 5900, SSH 22, ScreenSharing, web services) with process crashes in unified logs and abnormal child processes spawned under those services (e.g., bash, curl) to indicate exploitation.
  - **Log sources:** `macos:unifiedlog` (process 'crashed'|'EXC_BAD_ACCESS' for sshd, screensharingd, httpd; launchd restarts of these daemons.) [Application Log Content], `macos:osquery` (parent_name in ('sshd','httpd','screensharingd') spawning shells or scripting runtimes.) [Process Creation], `NSM:Flow` (Inbound to 22/5900/8080 and follow-on internal connections.) [Network Traffic Content]
- [AN0328] **[Linux]** Links inbound network access to SSHD/SMB/NFS/Databases or custom daemons with subsequent daemon crash/restart, core dump, or spawning of shells/reverse shells from the service context, indicating remote exploitation.
  - **Log sources:** `linux:syslog` (kernel|systemd messages indicating 'segmentation fault'|'core dumped'|'service terminated unexpectedly' for sshd, smbd, vsftpd, mysqld, httpd, etc.) [Application Log Content], `auditd:SYSCALL` (execve of /bin/sh,/bin/bash,/usr/bin/curl,/usr/bin/python by service accounts (e.g., apache, mysql, nobody) immediately after inbound network activity.) [Process Creation], `NSM:Flow` (Inbound connections to monitored service ports from external or unusual internal sources; rapid follow-on lateral connections from the same host.) [Network Traffic Content]
- [AN0327] **[Windows]** Correlates inbound network access to remote service ports (e.g., SMB/RPC 445/135, RDP 3389, WinRM 5985/5986) with near-time instability in the target service (crash, abnormal restart), suspicious child process creation under the service, and post-access lateral-movement behaviors. The chain indicates likely exploitation rather than normal administration.
  - **Log sources:** `WinEventLog:System` (EventCode=1000) [Application Log Content], `WinEventLog:Sysmon` (EventCode=1) [Process Creation], `WinEventLog:Sysmon` (EventCode=3, 22) [Network Connection Creation], `WinEventLog:Sysmon` (EventCode=7) [Module Load], `WinEventLog:Sysmon` (EventCode=10) [Process Access], `WinEventLog:Sysmon` (EventCode=11) [File Creation], `NSM:Flow` (Inbound connections to 445, 3389, 5985-5986 with high error/connection-reset rate, followed by new outbound sessions from the same host to internal assets within short interval.) [Network Traffic Content]
**Procedure Examples**
- [S0143] Flame: Flame can use MS10-061 to exploit a print spooler vulnerability in a remote system with a shared printer in order to move laterally.
- [S0366] WannaCry: WannaCry uses an exploit in SMBv1 to spread itself to other remote systems on a network.
- [G0102] Wizard Spider: Wizard Spider has exploited or attempted to exploit Zerologon (CVE-2020-1472) and EternalBlue (MS17-010) vulnerabilities.
- [G0117] Fox Kitten: Fox Kitten has exploited known vulnerabilities in remote services including RDP.
- [G1006] Earth Lusca: Earth Lusca has used Mimikatz to exploit a domain controller via the ZeroLogon exploit (CVE-2020-1472).
- [S0603] Stuxnet: Stuxnet propagates using the MS10-061 Print Spooler and MS08-067 Windows Server Service vulnerabilities.
- [S0650] QakBot: QakBot can move laterally using worm-like functionality through exploitation of SMB.
- [S0367] Emotet: Emotet has been seen exploiting SMB via a vulnerability exploit like EternalBlue (MS17-010) to achieve lateral movement and propagation.
- [S0363] Empire: Empire has a limited number of built-in modules for exploiting remote SMB, JBoss, and Jenkins servers.
- [S0606] Bad Rabbit: Bad Rabbit used the EternalRomance SMB exploit to spread through victim networks.


### T1534 - Internal Spearphishing
After they already have access to accounts or systems within the environment, adversaries may use internal spearphishing to gain access to additional information or compromise other users within the same organization. Internal spearphishing is multi-staged campaign where a legitimate account is initially compromised either by controlling the user's device or by compromising the account credentials of the user. Adversaries may then attempt to take advantage of the trusted internal account to increase the likelihood of tricking more victims into falling for phish attempts, often incorporating Impersonation. For example, adversaries may leverage Spearphishing Attachment or Spearphishing Link as part of internal spearphishing to deliver a payload or redirect to an external site to capture credentials through Input Capture on sites that mimic login interfaces. Adversaries may also leverage internal chat apps, such as Microsoft Teams, to spread malicious content or engage users in attempts to capture sensitive information and/or credentials.
**Detection**
- [AN0147] **[Windows]** Sequence of internal email sent from a recently compromised user account (preceded by abnormal logon or device activity), with attachments or links leading to execution or credential harvesting. Defender observes: internal mail delivery to peers with high entropy attachments, followed by click events, process initiation, or credential prompts.
  - **Log sources:** `WinEventLog:Security` (EventCode=4624, 4648) [Logon Session Creation], `WinEventLog:Security` (EventCode=4625) [User Account Authentication], `WinEventLog:Security` (EventCode=4672) [Logon Session Metadata], `m365:unified` (SendOnBehalf, MessageSend, ClickThrough, MailItemsAccessed) [Application Log Content], `WinEventLog:Sysmon` (EventCode=1) [Process Creation]
- [AN0150] **[SaaS]** Internal spearphishing via SaaS applications (e.g., Slack, Teams, Gmail): message sent from compromised user with attachment or URL, followed by click and credential access behavior.
  - **Log sources:** `saas:slack` (file_upload, message_send, message_click) [Application Log Content]
- [AN0149] **[macOS]** Abnormal Apple Mail use, including internal email relays followed by file execution or script events (e.g., attachments launched via Preview, terminal triggered from Mail.app)
  - **Log sources:** `macos:unifiedlog` (com.apple.mail.* exec.*) [Process Creation], `macos:unifiedlog` (curl|osascript.*open location) [Network Traffic Content]
- [AN0151] **[Office Suite]** Outlook or Word used to forward suspicious internal attachments with macro content. Defender observes attachment forwarding, auto-opening behaviors, or macro prompt interactions.
  - **Log sources:** `m365:unified` (SendOnBehalf, MessageSend, AttachmentPreviewed) [Application Log Content], `WinEventLog:Security` (EventCode=4103, 4104, 4105, 4106) [Command Execution]
- [AN0148] **[Linux]** Delivery of suspicious internal communication (e.g., Thunderbird, Evolution) using compromised internal accounts. Sequence of: unexpected user activity + mail transfer logs + download or execution of attachments.
  - **Log sources:** `auditd:SYSCALL` (execve) [Process Creation], `Application:Mail` (smtpd$.*$: .*from=[.*@internaldomain.com](mailto:.*@internaldomain.com) to=[.*@internaldomain.com](mailto:.*@internaldomain.com)) [Application Log Content], `linux:syslog` (curl|wget|python .*http) [Network Traffic Content]
**Procedure Examples**
- [G0047] Gamaredon Group: Gamaredon Group has used an Outlook VBA module on infected systems to send phishing emails with malicious attachments to other employees within the organization.
- [G0094] Kimsuky: Kimsuky has sent internal spearphishing emails for lateral movement after stealing victim information.
- [C0022] Operation Dream Job: During Operation Dream Job, Lazarus Group conducted internal spearphishing from within a compromised organization.
- [G0065] Leviathan: Leviathan has conducted internal spearphishing within the victim's environment for lateral movement.
- [G1001] HEXANE: HEXANE has conducted internal spearphishing attacks against executives, HR, and IT personnel to gain information and access.


### T1550 - Use Alternate Authentication Material
Adversaries may use alternate authentication material, such as password hashes, Kerberos tickets, and application access tokens, in order to move laterally within an environment and bypass normal system access controls. Authentication processes generally require a valid identity (e.g., username) along with one or more authentication factors (e.g., password, pin, physical smart card, token generator, etc.). Alternate authentication material is legitimately generated by systems after a user or application successfully authenticates by providing a valid identity and the required authentication factor(s). Alternate authentication material may also be generated during the identity creation process. Caching alternate authentication material allows the system to verify an identity has successfully authenticated without asking the user to reenter authentication factor(s). Because the alternate authentication must be maintained by the system—either in memory or on disk—it may be at risk of being stolen through Credential Access techniques. By stealing alternate authentication material, adversaries are able to bypass system access controls and authenticate to systems without knowing the plaintext password or any additional authentication factors.
**Detection**
- [AN0959] **[Office Suite]** Access token reuse to connect to SharePoint or Outlook APIs without interactive user context.
  - **Log sources:** `m365:unified` (TokenIssued, FileAccessed) [Web Credential Usage]
- [AN0958] **[Containers]** Container process uses mounted cloud credentials or token cache to authenticate without known orchestration.
  - **Log sources:** `docker:runtime` (execution of cloud CLI tool (e.g., aws, az) inside container) [Application Log Content], `AWS:CloudTrail` (AssumeRole) [User Account Metadata]
- [AN0956] **[Identity Provider]** Token replay or impersonation in federated logins without interactive browser session or MFA prompts.
  - **Log sources:** `azure:signinlogs` (TokenIssuanceStart, TokenIssuanceSuccess) [Web Credential Usage], `m365:unified` (login using refresh_token with no preceding authentication context) [User Account Authentication]
- [AN0957] **[SaaS]** Unusual reuse of OAuth access tokens from different geographic regions, without full login events.
  - **Log sources:** `saas:googleworkspace` (access_token issued) [Web Credential Usage], `saas:googleworkspace` (API access without user login) [User Account Authentication]
- [AN0960] **[IaaS]** Use of instance metadata tokens across instances or misuse of short-lived tokens issued for different roles.
  - **Log sources:** `AWS:CloudTrail` (GetCallerIdentity) [Web Credential Usage], `AWS:CloudTrail` (AssumeRole) [User Account Metadata]
- [AN0954] **[Windows]** Use of stolen Kerberos tickets or token impersonation resulting in logon sessions from accounts without expected interactive logon events.
  - **Log sources:** `WinEventLog:Security` (EventCode=4624, 4648) [Logon Session Creation], `WinEventLog:Sysmon` (EventCode=1) [Process Creation]
- [AN0955] **[Linux]** Access tokens or SSH keys used without corresponding login shell or PAM module activity, particularly for remote execution.
  - **Log sources:** `auditd:SYSCALL` (execution of ssh, scp, or sftp using previously unseen credentials or keys) [User Account Authentication], `NSM:Connections` (Accepted publickey for user from unusual IP or without tty) [Logon Session Creation]
**Procedure Examples**
- [C0024] SolarWinds Compromise: During the SolarWinds Compromise, APT29 used forged SAML tokens that allowed the actors to impersonate users and bypass MFA, enabling APT29 to access enterprise cloud applications and services.
- [S0661] FoggyWeb: FoggyWeb can allow abuse of a compromised AD FS server's SAML token.


### T1550.001 - Use Alternate Authentication Material: Application Access Token
Adversaries may use stolen application access tokens to bypass the typical authentication process and access restricted accounts, information, or services on remote systems. These tokens are typically stolen from users or services and used in lieu of login credentials. Application access tokens are used to make authorized API requests on behalf of a user or service and are commonly used to access resources in cloud, container-based applications, and software-as-a-service (SaaS). OAuth is one commonly implemented framework that issues tokens to users for access to systems. These frameworks are used collaboratively to verify the user and determine what actions the user is allowed to perform. Once identity is established, the token allows actions to be authorized, without passing the actual credentials of the user. Therefore, compromise of the token can grant the adversary access to resources of other sites through a malicious application. For example, with a cloud-based email service, once an OAuth access token is granted to a malicious application, it can potentially gain long-term access to features of the user account if a "refresh" token enabling background access is awarded. With an OAuth access token an adversary can use the user-granted REST API to perform functions such as email searching and contact enumeration. Compromised access tokens may be used as an initial step in compromising other services. For example, if a token grants access to a victim’s primary email, the adversary may be able to extend access to all other services which the target subscribes by triggering forgotten password routines. In AWS and GCP environments, adversaries can trigger a request for a short-lived access token with the privileges of another user account. The adversary can then use this token to request data or perform actions the original account could not. If permissions for this feature are misconfigured – for example, by allowing all users to request a token for a particular account - an adversary may be able to gain initial access to a Cloud Account or escalate their privileges. Direct API access through a token negates the effectiveness of a second authentication factor and may be immune to intuitive countermeasures like changing passwords. For example, in AWS environments, an adversary who compromises a user’s AWS API credentials may be able to use the `sts:GetFederationToken` API call to create a federated user session, which will have the same permissions as the original user but may persist even if the original user credentials are deactivated. Additionally, access abuse over an API channel can be difficult to detect even from the service provider end, as the access can still align well with a legitimate workflow.
**Detection**
- [AN0530] **[Containers]** Compromised service account tokens mounted inside containers and reused for external API calls or lateral movement across services.
  - **Log sources:** `kubernetes:apiserver` (serviceAccount token used in API requests not tied to workload identity) [Web Credential Usage], `AWS:CloudTrail` (AssumeRoleWithWebIdentity) [User Account Authentication]
- [AN0526] **[IaaS]** Use of AWS STS or GCP IAM APIs to request temporary tokens or federation sessions inconsistent with normal account activity, including from unexpected principals or regions.
  - **Log sources:** `AWS:CloudTrail` (AssumeRole, GetFederationToken, GetSessionToken) [Web Credential Usage], `AWS:CloudTrail` (sts:GetFederationToken) [User Account Authentication]
- [AN0529] **[Office Suite]** OAuth token usage for Exchange Online or SharePoint API access without preceding login or from unauthorized clients.
  - **Log sources:** `m365:unified` (OAuthTokenIssued, FileAccessed, MailItemsAccessed) [Web Credential Usage]
- [AN0527] **[Identity Provider]** OAuth or SAML access tokens reused across multiple sessions or clients without corresponding MFA or login activity.
  - **Log sources:** `azure:signinlogs` (TokenIssued, RefreshTokenUsed) [Web Credential Usage], `m365:unified` (Delegated permission grants without user login event) [User Account Authentication]
- [AN0528] **[SaaS]** Application access tokens used to call APIs (e.g., Google Workspace, Salesforce) without interactive logins, often with unusual scopes or elevated permissions.
  - **Log sources:** `saas:googleworkspace` (OAuthTokenGranted, APIRequest) [Web Credential Usage], `saas:salesforce` (API login using access_token without login history) [User Account Authentication]
**Procedure Examples**
- [S0683] Peirates: Peirates can use stolen service account tokens to perform its operations. It also enables adversaries to switch between valid service accounts.
- [S1023] CreepyDrive: CreepyDrive can use legitimate OAuth refresh tokens to authenticate with OneDrive.
- [C0024] SolarWinds Compromise: During the SolarWinds Compromise, APT29 used compromised service principals to make changes to the Office 365 environment.
- [G0007] APT28: APT28 has used several malicious applications that abused OAuth access tokens to gain access to target email accounts, including Gmail and Yahoo Mail.
- [G0125] HAFNIUM: HAFNIUM has abused service principals with administrative permissions for data exfiltration.


### T1550.002 - Use Alternate Authentication Material: Pass the Hash
Adversaries may “pass the hash” using stolen password hashes to move laterally within an environment, bypassing normal system access controls. Pass the hash (PtH) is a method of authenticating as a user without having access to the user's cleartext password. This method bypasses standard authentication steps that require a cleartext password, moving directly into the portion of the authentication that uses the password hash. When performing PtH, valid password hashes for the account being used are captured using a Credential Access technique. Captured hashes are used with PtH to authenticate as that user. Once authenticated, PtH may be used to perform actions on local or remote systems. Adversaries may also use stolen password hashes to "overpass the hash." Similar to PtH, this involves using a password hash to authenticate as a user but also uses the password hash to create a valid Kerberos ticket. This ticket can then be used to perform Pass the Ticket attacks.
**Detection**
- [AN1144] **[Windows]** Detects anomalous NTLM LogonType 3 authentications that occur without accompanying domain logon events, especially from lateral systems or involving built-in administrative tools. Monitors for mismatches between source user context and system being accessed. Correlates LogonSession creation, NTLM authentications, and process/service initiation to identify suspicious use of stolen password hashes for remote access or service logon without password entry. Detects overpass-the-hash by combining Kerberos ticket issuance with NTLM-based lateral movement.
  - **Log sources:** `WinEventLog:Security` (EventCode=4624, 4648) [Logon Session Creation], `WinEventLog:Security` (EventCode=4768) [Active Directory Credential Request], `WinEventLog:Sysmon` (EventCode=3, 22) [Network Connection Creation], `WinEventLog:Sysmon` (EventCode=1) [Process Creation]
**Procedure Examples**
- [G0050] APT32: APT32 has used pass the hash for lateral movement.
- [S0154] Cobalt Strike: Cobalt Strike can perform pass the hash.
- [S0122] Pass-The-Hash Toolkit: Pass-The-Hash Toolkit can perform pass the hash.
- [G0007] APT28: APT28 has used pass the hash for lateral movement.
- [G0143] Aquatic Panda: Aquatic Panda used a registry edit to enable a Windows feature called RestrictedAdmin in victim environments. This change allowed Aquatic Panda to leverage "pass the hash" mechanisms as the alteration allows for RDP connections with a valid account name and hash only, without possessing a cleartext password value.
- [G0114] Chimera: Chimera has dumped password hashes for use in pass the hash authentication attacks.
- [G0006] APT1: The APT1 group is known to have used pass the hash.
- [G0102] Wizard Spider: Wizard Spider has used the `Invoke-SMBExec` PowerShell cmdlet to execute the pass-the-hash technique and utilized stolen password hashes to move laterally.
- [S0376] HOPLIGHT: HOPLIGHT has been observed loading several APIs associated with Pass the Hash.
- [S0378] PoshC2: PoshC2 has a number of modules that leverage pass the hash for lateral movement.


### T1550.003 - Use Alternate Authentication Material: Pass the Ticket
Adversaries may “pass the ticket” using stolen Kerberos tickets to move laterally within an environment, bypassing normal system access controls. Pass the ticket (PtT) is a method of authenticating to a system using Kerberos tickets without having access to an account's password. Kerberos authentication can be used as the first step to lateral movement to a remote system. When preforming PtT, valid Kerberos tickets for Valid Accounts are captured by OS Credential Dumping. A user's service tickets or ticket granting ticket (TGT) may be obtained, depending on the level of access. A service ticket allows for access to a particular resource, whereas a TGT can be used to request service tickets from the Ticket Granting Service (TGS) to access any resource the user has privileges to access. A Silver Ticket can be obtained for services that use Kerberos as an authentication mechanism and are used to generate tickets to access that particular resource and the system that hosts the resource (e.g., SharePoint). A Golden Ticket can be obtained for the domain using the Key Distribution Service account KRBTGT account NTLM hash, which enables generation of TGTs for any account in Active Directory. Adversaries may also create a valid Kerberos ticket using other user information, such as stolen password hashes or AES keys. For example, "overpassing the hash" involves using a NTLM password hash to authenticate as a user (i.e. Pass the Hash) while also using the password hash to create a valid Kerberos ticket.
**Detection**
- [AN1000] **[Windows]** Detects unauthorized Kerberos ticket injection by correlating service ticket (TGS - 4769) requests with absent corresponding account logons (4624) and prior Ticket Granting Ticket (TGT - 4768) activity. Highlights anomalous service ticket generation chains involving unexpected users, hosts, or times, and suspicious injection of tickets via mimikatz-like tooling into LSASS memory. Behavior also includes network lateral movement using Kerberos authentication absent expected interactive logon patterns.
  - **Log sources:** `WinEventLog:Security` (EventCode=4769) [User Account Authentication], `WinEventLog:Security` (EventCode=4768) [Active Directory Credential Request], `WinEventLog:Security` (EventCode=4624, 4648) [Logon Session Creation], `WinEventLog:Sysmon` (EventCode=10) [Process Access], `WinEventLog:Sysmon` (EventCode=7) [Module Load]
**Procedure Examples**
- [S0053] SeaDuke: Some SeaDuke samples have a module to use pass the ticket with Kerberos for authentication.
- [G0016] APT29: APT29 used Kerberos ticket attacks for lateral movement.
- [S0002] Mimikatz: Mimikatz’s LSADUMP::DCSync and KERBEROS::PTT modules implement the three steps required to extract the krbtgt account hash and create/use Kerberos tickets.
- [S0192] Pupy: Pupy can also perform pass-the-ticket.
- [G0050] APT32: APT32 successfully gained remote access by using pass the ticket.
- [G0060] BRONZE BUTLER: BRONZE BUTLER has created forged Kerberos Ticket Granting Ticket (TGT) and Ticket Granting Service (TGS) tickets to maintain administrative access.


### T1550.004 - Use Alternate Authentication Material: Web Session Cookie
Adversaries can use stolen session cookies to authenticate to web applications and services. This technique bypasses some multi-factor authentication protocols since the session is already authenticated. Authentication cookies are commonly used in web applications, including cloud-based services, after a user has authenticated to the service so credentials are not passed and re-authentication does not need to occur as frequently. Cookies are often valid for an extended period of time, even if the web application is not actively used. After the cookie is obtained through Steal Web Session Cookie or Web Cookies, the adversary may then import the cookie into a browser they control and is then able to use the site or application as the user for as long as the session cookie is active. Once logged into the site, an adversary can access sensitive information, read email, or perform actions that the victim account has permissions to perform. There have been examples of malware targeting session cookies to bypass multi-factor authentication systems.
**Detection**
- [AN0203] **[Office Suite]** Web session tokens reused in native Office apps (e.g., Outlook, Teams) without associated token refresh or login behavior on the endpoint.
  - **Log sources:** `m365:unified` (UserLoggedIn) [Logon Session Creation]
- [AN0202] **[SaaS]** Session cookie reuse on unmanaged browsers, devices, or client types deviating from user baseline (e.g., switching from Chrome to curl).
  - **Log sources:** `m365:unified` (SessionId reused from different device/browser fingerprint) [Web Credential Usage], `saas:okta` (session.impersonation.start) [User Account Authentication]
- [AN0201] **[IaaS]** Anomalous access to cloud web applications using session tokens without corresponding MFA/credential validation, often from unusual locations or device fingerprints.
  - **Log sources:** `AWS:CloudTrail` (SessionToken used without preceding MFA or login event) [Web Credential Usage], `AWS:CloudTrail` (ConsoleLogin) [Logon Session Creation]
**Procedure Examples**
- [G1033] Star Blizzard: Star Blizzard has bypassed multi-factor authentication on victim email accounts by using session cookies stolen using EvilGinx.
- [C0024] SolarWinds Compromise: During the SolarWinds Compromise, APT29 used stolen cookies to access cloud resources and a forged `duo-sid` cookie to bypass MFA set on an email account.


### T1563 - Remote Service Session Hijacking
Adversaries may take control of preexisting sessions with remote services to move laterally in an environment. Users may use valid credentials to log into a service specifically designed to accept remote connections, such as telnet, SSH, and RDP. When a user logs into a service, a session will be established that will allow them to maintain a continuous interaction with that service. Adversaries may commandeer these sessions to carry out actions on remote systems. Remote Service Session Hijacking differs from use of Remote Services because it hijacks an existing session rather than creating a new session using Valid Accounts.
**Detection**
- [AN0216] **[Windows]** Detection of anomalous RDP or remote service session activity where a logon session is hijacked rather than newly created. Indicators include mismatched user credentials vs. active session tokens, service session takeovers without corresponding successful logon events, or RDP shadowing activity without user consent.
  - **Log sources:** `WinEventLog:Security` (EventCode=4624, 4648) [Logon Session Creation], `WinEventLog:Sysmon` (EventCode=1) [Process Creation], `WinEventLog:Sysmon` (EventCode=3, 22) [Network Connection Creation]
- [AN0218] **[macOS]** Detection of hijacked VNC or SSH sessions on macOS where adversaries take over an existing session rather than authenticating directly. Indicators include process execution from active sessions without new logon events, manipulation of TTY sessions, or anomalous network activity tied to dormant sessions.
  - **Log sources:** `macos:unifiedlog` (Authentication inconsistencies where commands are executed without corresponding login events) [Logon Session Creation], `macos:unifiedlog` (Execution of processes linked to hijacked sessions (e.g., anomalous parent-child process lineage)) [Process Creation], `NSM:Flow` (Suspicious long-lived or reattached remote desktop sessions from unexpected IPs) [Network Traffic Content]
- [AN0217] **[Linux]** Detection of SSH/Telnet session hijacking via discrepancies between authentication logs and active session tables. Adversary behavior includes reusing or stealing active PTY sessions, attaching to screen/tmux, or issuing commands without corresponding login events.
  - **Log sources:** `auditd:SYSCALL` (execve: Commands executed within an SSH session where no matching logon/authentication event exists) [Command Execution], `NSM:Connections` (Mismatch between recorded user logon and active sessions (e.g., wtmp/utmp entries without corresponding authentication in auth.log)) [Logon Session Creation], `NSM:Flow` (Long-lived or hijacked SSH sessions maintained with no active user activity) [Network Traffic Flow]
Adversaries may take control of preexisting sessions with remote services to move laterally in an environment. Users may use valid credentials to log into a service specifically designed to accept remote connections, such as telnet, SSH, and RDP. When a user logs into a service, a session will be established that will allow them to maintain a continuous interaction with that service. Adversaries may commandeer these sessions to carry out actions on remote systems. Remote Service Session Hijacking differs from use of Remote Services because it hijacks an existing session rather than creating a new session using Valid Accounts.


### T1563.001 - Remote Service Session Hijacking: SSH Hijacking
Adversaries may hijack a legitimate user's SSH session to move laterally within an environment. Secure Shell (SSH) is a standard means of remote access on Linux and macOS systems. It allows a user to connect to another system via an encrypted tunnel, commonly authenticating through a password, certificate or the use of an asymmetric encryption key pair. In order to move laterally from a compromised host, adversaries may take advantage of trust relationships established with other systems via public key authentication in active SSH sessions by hijacking an existing connection to another system. This may occur through compromising the SSH agent itself or by having access to the agent's socket. If an adversary is able to obtain root access, then hijacking SSH sessions is likely trivial. SSH Hijacking differs from use of SSH because it hijacks an existing SSH session rather than creating a new session using Valid Accounts.
**Detection**
- [AN0710] **[Linux]** Suspicious reuse of SSH agent sockets across multiple users or processes, anomalous access to ~/.ssh/ or /tmp/ssh-* sockets, and abnormal patterns of lateral movement via SSH without new authentication events. Defender view: detect when one process accesses another user's SSH agent or when an existing SSH connection is used to pivot unexpectedly.
  - **Log sources:** `auditd:SYSCALL` (open or connect syscalls on /tmp/ssh-* or $SSH_AUTH_SOCK) [Network Connection Creation], `auditd:EXECVE` (Execution of ssh/scp/sftp without corresponding authentication log) [Process Creation], `NSM:Connections` (Missing new login event but session activity continues) [Logon Session Creation]
- [AN0711] **[macOS]** Unusual access to SSH agent sockets in /tmp/ or /private/tmp, process access to another user’s $SSH_AUTH_SOCK, and lateral SSH activity without corresponding login events. Defender view: correlation of socket access with anomalous network flows to internal systems.
  - **Log sources:** `macos:unifiedlog` (Process opening SSH_AUTH_SOCK or /tmp/ssh-* socket not owned by same UID) [Process Metadata], `macos:unifiedlog` (Execution of ssh or sftp without corresponding login event) [Process Creation], `macos:unifiedlog` (Session reuse without new auth event) [Logon Session Creation]
**Procedure Examples**
- [S1220] MEDUSA: MEDUSA can be configured to capture SSH credentials via SSH hijacking.


### T1563.002 - Remote Service Session Hijacking: RDP Hijacking
Adversaries may hijack a legitimate user’s remote desktop session to move laterally within an environment. Remote desktop is a common feature in operating systems. It allows a user to log into an interactive session with a system desktop graphical user interface on a remote system. Microsoft refers to its implementation of the Remote Desktop Protocol (RDP) as Remote Desktop Services (RDS). Adversaries may perform RDP session hijacking which involves stealing a legitimate user's remote session. Typically, a user is notified when someone else is trying to steal their session. With System permissions and using Terminal Services Console, `c:\windows\system32\tscon.exe [session number to be stolen]`, an adversary can hijack a session without the need for credentials or prompts to the user. This can be done remotely or locally and with active or disconnected sessions. It can also lead to Remote System Discovery and Privilege Escalation by stealing a Domain Admin or higher privileged account session. All of this can be done by using native Windows commands, but it has also been added as a feature in red teaming tools.
**Detection**
- [AN1620] **[Windows]** Detection of suspicious use of `tscon.exe` or equivalent methods to hijack legitimate RDP sessions. Defenders can observe anomalies such as session reassignments without corresponding authentication, processes spawned in the context of hijacked sessions, or unusual RDP network traffic flows that deviate from expected baselines.
  - **Log sources:** `WinEventLog:Security` (EventCode=4624, 4648) [Logon Session Creation], `WinEventLog:Sysmon` (EventCode=1) [Process Creation], `WinEventLog:Sysmon` (EventCode=3, 22) [Network Connection Creation], `WinEventLog:System` (EventCode=7045) [Service Creation]
**Procedure Examples**
- [S0366] WannaCry: WannaCry enumerates current remote desktop sessions and tries to execute the malware on each session.
- [G0001] Axiom: Axiom has targeted victims with remote administration tools including RDP.


### T1570 - Lateral Tool Transfer
Adversaries may transfer tools or other files between systems in a compromised environment. Once brought into the victim environment (i.e., Ingress Tool Transfer) files may then be copied from one system to another to stage adversary tools or other files over the course of an operation. Adversaries may copy files between internal victim systems to support lateral movement using inherent file sharing protocols such as file sharing over SMB/Windows Admin Shares to connected network shares or with authenticated connections via Remote Desktop Protocol. Files can also be transferred using native or otherwise present tools on the victim system, such as scp, rsync, curl, sftp, and ftp. In some cases, adversaries may be able to leverage Web Services such as Dropbox or OneDrive to copy files from one machine to another via shared, automatically synced folders.
**Detection**
- [AN0517] **[Linux]** Monitor scp, rsync, curl, sftp, or ftp processes initiating transfers to internal systems combined with file creation events in unusual directories. Correlate transfer activity with subsequent execution of those binaries.
  - **Log sources:** `auditd:SYSCALL` (execve: Invocation of scp, rsync, curl, or sftp) [Command Execution], `auditd:FILE` (create: New file created in system binaries or temp directories) [File Creation]
- [AN0518] **[macOS]** Detect anomalous use of scp, rsync, curl, or third-party sync apps transferring executables into user directories. Correlate new file creation with immediate execution events.
  - **Log sources:** `macos:unifiedlog` (Execution of scp, rsync, curl with remote destination) [Process Creation], `macos:unifiedlog` (File created in ~/Library/LaunchAgents or executable directories) [File Creation]
- [AN0516] **[Windows]** Correlate suspicious file transfers over SMB or Admin$ shares with process creation events (e.g., cmd.exe, powershell.exe, certutil.exe) that do not align with normal administrative behavior. Detect remote file writes followed by execution of transferred binaries.
  - **Log sources:** `WinEventLog:Security` (EventCode=5140) [Network Share Access], `WinEventLog:Sysmon` (EventCode=11) [File Creation], `WinEventLog:Sysmon` (EventCode=1) [Process Creation]
- [AN0519] **[ESXi]** Identify lateral transfer via datastore file uploads or internal scp/ssh sessions that result in new VMX/VMDK or script files. Correlate transfer with VM execution or datastore modification.
  - **Log sources:** `esxi:vmkernel` (Upload of file to datastore) [File Metadata], `esxi:hostd` (scp/ssh used to move file across hosts) [Command Execution]
**Procedure Examples**
- [G1051] Medusa Group: Medusa Group has utilized legitimate software services such as PDQ Deploy to transfer malicious binaries and tools to other victimized hosts within the target environment.
- [S0367] Emotet: Emotet has copied itself to remote systems using the `service.exe` filename.
- [S1139] INC Ransomware: INC Ransomware can push its encryption executable to multiple endpoints within compromised infrastructure.
- [S1068] BlackCat: BlackCat can replicate itself across connected servers via `psexec`.
- [S1132] IPsec Helper: IPsec Helper can download additional payloads from command and control nodes and execute them.
- [G0050] APT32: APT32 has deployed tools after moving laterally using administrative accounts.
- [G1007] Aoqin Dragon: Aoqin Dragon has spread malware in target networks by copying modules to folders masquerading as removable devices.
- [S0457] Netwalker: Operators deploying Netwalker have used psexec to copy the Netwalker payload across accessible systems.
- [S0190] BITSAdmin: BITSAdmin can be used to create BITS Jobs to upload and/or download files from SMB file servers.
- [G0051] FIN10: FIN10 has deployed Meterpreter stagers and SplinterRAT instances in the victim network after moving laterally.

