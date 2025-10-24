### T1037.001 - Boot or Logon Initialization Scripts: Logon Script (Windows)

Procedures:

- [G0007] APT28: An APT28 loader Trojan adds the Registry key HKCU\Environment\UserInitMprLogonScript to establish persistence.
- [S0438] Attor: Attor's dispatcher can establish persistence via adding a Registry key with a logon script HKEY_CURRENT_USER\Environment "UserInitMprLogonScript" .
- [S0044] JHUHUGIT: JHUHUGIT has registered a Windows shell script under the Registry key HKCU\Environment\UserInitMprLogonScript to establish persistence.
- [S0526] KGH_SPY: KGH_SPY has the ability to set the HKCU\Environment\UserInitMprLogonScript Registry key to execute logon scripts.
- [S0251] Zebrocy: Zebrocy performs persistence with a logon script via adding to the Registry key HKCU\Environment\UserInitMprLogonScript.
- [G0080] Cobalt Group: Cobalt Group has added persistence by registering the file name for the next stage malware under HKCU\Environment\UserInitMprLogonScript.

### T1037.002 - Boot or Logon Initialization Scripts: Login Hook

Procedures:

- Adversaries may use a Login Hook to establish persistence executed upon user logon. A login hook is a plist file that points to a specific script to execute with root privileges upon user logon. The plist file is located in the /Library/Preferences/com.apple.loginwindow.plist file and can be modified using the defaults command-line utility. This behavior is the same for logout hooks where a script can be executed upon user logout. All hooks require administrator permissions to modify or create hooks. Adversaries can add or insert a path to a malicious script in the com.apple.loginwindow.plist file, using the LoginHook or LogoutHook key-value pair. The malicious script is executed upon the next user login. If a login hook already exists, adversaries can add additional commands to an existing login hook. There can be only one login and logout hook on a system at a time. **Note:** Login hooks were deprecated in 10.11 version of macOS in favor of Launch Daemon and Launch Agent

### T1037.003 - Boot or Logon Initialization Scripts: Network Logon Script

Procedures:

- Adversaries may use network logon scripts automatically executed at logon initialization to establish persistence. Network logon scripts can be assigned using Active Directory or Group Policy Objects. These logon scripts run with the privileges of the user they are assigned to. Depending on the systems within the network, initializing one of these scripts could apply to more than one or potentially all systems. Adversaries may use these scripts to maintain persistence on a network. Depending on the access configuration of the logon scripts, either local credentials or an administrator account may be necessary.

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

Procedures:

- Adversaries may abuse systemd timers to perform task scheduling for initial or recurring execution of malicious code. Systemd timers are unit files with file extension .timer that control services. Timers can be set to run on a calendar event or after a time span relative to a starting point. They can be used as an alternative to Cron in Linux environments. Systemd timers may be activated remotely via the systemctl command line utility, which operates over SSH. Each .timer file must have a corresponding .service file with the same name, e.g., example.timer and example.service. .service files are Systemd Service unit files that are managed by the systemd system and service manager. Privileged timers are written to /etc/systemd/system/ and /usr/lib/systemd/system while user level are written to ~/.config/systemd/user/. An adversary may use systemd timers to execute malicious code at system startup or on a scheduled basis for persistence. Timers installed using privileged paths may be used to maintain root level persistence. Adversaries may also install user level timers to achieve user level persistence.

### T1053.007 - Scheduled Task/Job: Container Orchestration Job

Procedures:

- Adversaries may abuse task scheduling functionality provided by container orchestration tools such as Kubernetes to schedule deployment of containers configured to execute malicious code. Container orchestration jobs run these automated tasks at a specific date and time, similar to cron jobs on a Linux system. Deployments of this type can also be configured to maintain a quantity of containers over time, automating the process of maintaining persistence within a cluster. In Kubernetes, a CronJob may be used to schedule a Job that runs one or more containers to perform specific tasks. An adversary therefore may utilize a CronJob to schedule deployment of a Job that executes malicious code in various nodes within a cluster.


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

Procedures:

- An adversary may add additional roles or permissions to an adversary-controlled user or service account to maintain persistent access to a container orchestration system. For example, an adversary with sufficient permissions may create a RoleBinding or a ClusterRoleBinding to bind a Role or ClusterRole to a Kubernetes account. Where attribute-based access control (ABAC) is in use, an adversary with sufficient permissions may modify a Kubernetes ABAC policy to give the target account additional permissions. This account modification may immediately follow Create Account or other malicious account activity. Adversaries may also modify existing Valid Accounts that they have compromised. Note that where container orchestration systems are deployed in cloud environments, as with Google Kubernetes Engine, Amazon Elastic Kubernetes Service, and Azure Kubernetes Service, cloud-based role-based access control (RBAC) assignments or ABAC policies can often be used in place of or in addition to local permission assignments. In these cases, this technique may be used in conjunction with Additional Cloud Roles.

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


### T1112 - Modify Registry

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


### T1136.001 - Create Account: Local Account

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

### T1136.002 - Create Account: Domain Account

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

Procedures:

- [G0016] APT29: APT29 can create new users through Azure AD.
- [G1004] LAPSUS$: LAPSUS$ has created global admin accounts in the targeted organization's cloud instances to gain persistence.
- [S0677] AADInternals: AADInternals can create new Azure AD users.


### T1137.001 - Office Application Startup: Office Template Macros

Procedures:

- [G0069] MuddyWater: MuddyWater has used a Word Template, Normal.dotm, for persistence.
- [S0475] BackConfig: BackConfig has the ability to use hidden columns in Excel spreadsheets to store executable files or commands for VBA macros.
- [S0154] Cobalt Strike: Cobalt Strike has the ability to use an Excel Workbook to execute additional code by enabling Office to trust macros and execute code without user permission.

### T1137.002 - Office Application Startup: Office Test

Procedures:

- [G0007] APT28: APT28 has used the Office Test persistence mechanism within Microsoft Office by adding the Registry key HKCU\Software\Microsoft\Office test\Special\Perf to execute code.

### T1137.003 - Office Application Startup: Outlook Forms

Procedures:

- [S0358] Ruler: Ruler can be used to automate the abuse of Outlook Forms to establish persistence.

### T1137.004 - Office Application Startup: Outlook Home Page

Procedures:

- [G0049] OilRig: OilRig has abused the Outlook Home Page feature for persistence. OilRig has also used CVE-2017-11774 to roll back the initial patch designed to protect against Home Page abuse.
- [S0358] Ruler: Ruler can be used to automate the abuse of Outlook Home Pages to establish persistence.

### T1137.005 - Office Application Startup: Outlook Rules

Procedures:

- [S0358] Ruler: Ruler can be used to automate the abuse of Outlook Rules to establish persistence.

### T1137.006 - Office Application Startup: Add-ins

Procedures:

- [S0268] Bisonal: Bisonal has been loaded through a `.wll` extension added to the ` %APPDATA%\microsoft\word\startup\` repository.
- [G0019] Naikon: Naikon has used the RoyalRoad exploit builder to drop a second stage loader, intel.wll, into the Word Startup folder on the compromised host.
- [S1143] LunarLoader: LunarLoader has the ability to use Microsoft Outlook add-ins to establish persistence.
- [S1142] LunarMail: LunarMail has the ability to use Outlook add-ins for persistence.


### T1176.001 - Software Extensions: Browser Extensions

Procedures:

- [S1122] Mispadu: Mispadu utilizes malicious Google Chrome browser extensions to steal financial data.
- [G0094] Kimsuky: Kimsuky has used Google Chrome browser extensions to infect victims and to steal passwords and cookies.
- [S0402] OSX/Shlayer: OSX/Shlayer can install malicious Safari browser extensions to serve ads.
- [S1213] Lumma Stealer: Lumma Stealer has installed a malicious browser extension to target Google Chrome, Microsoft Edge, Opera and Brave browsers for the purpose of stealing data.
- [S1201] TRANSLATEXT: TRANSLATEXT has the ability to capture credentials, cookies, browser screenshots, etc. and to exfiltrate data.
- [S0531] Grandoreiro: Grandoreiro can use malicious browser extensions to steal cookies and other user information.
- [S0482] Bundlore: Bundlore can install malicious browser extensions that are used to hijack user searches.

### T1176.002 - Software Extensions: IDE Extensions

Procedures:

- Adversaries may abuse an integrated development environment (IDE) extension to establish persistent access to victim systems. IDEs such as Visual Studio Code, IntelliJ IDEA, and Eclipse support extensions - software components that add features like code linting, auto-completion, task automation, or integration with tools like Git and Docker. A malicious extension can be installed through an extension marketplace (i.e., Compromise Software Dependencies and Development Tools) or side-loaded directly into the IDE. In addition to installing malicious extensions, adversaries may also leverage benign ones. For example, adversaries may establish persistent SSH tunnels via the use of the VSCode Remote SSH extension (i.e., IDE Tunneling). Trust is typically established through the installation process; once installed, the malicious extension is run every time that the IDE is launched. The extension can then be used to execute arbitrary code, establish a backdoor, mine cryptocurrency, or exfiltrate data.


### T1197 - BITS Jobs

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

Procedures:

- [S1060] Mafalda: Mafalda can use port-knocking to authenticate itself to another implant called Cryshell to establish an indirect connection to the C2 server.
- [G0056] PROMETHIUM: PROMETHIUM has used a script that configures the knockd service and firewall to only accept C2 connections from systems that use a specified sequence of knock ports.
- [S1204] cd00r: cd00r can monitor for a single TCP-SYN packet to be sent in series to a configurable set of ports (200, 80, 22, 53 and 3 in the original code) before opening a port for communication.
- [S1059] metaMain: metaMain has authenticated itself to a different implant, Cryshell, through a port knocking and handshake procedure.

### T1205.002 - Traffic Signaling: Socket Filters

Procedures:

- [S1161] BPFDoor: BPFDoor uses BPF bytecode to attach a filter to a network socket to view ICMP, UDP, or TCP packets coming through ports 22 (ssh), 80 (http), and 443 (https). When BPFDoor finds a packet containing its “magic” bytes, it parses out two fields and forks itself. The parent process continues to monitor filtered traffic while the child process executes the instructions from the parsed fields.
- [S1123] PITSTOP: PITSTOP can listen and evaluate incoming commands on the domain socket, created by PITHOOK malware, located at `/data/runtime/cockpit/wd.fd` for a predefined magic byte sequence. PITSTOP can then duplicate the socket for further communication over TLS.
- [S0587] Penquin: Penquin installs a `TCP` and `UDP` filter on the `eth0` interface.


### T1505.001 - Server Software Component: SQL Stored Procedures

Procedures:

- [C0025] 2016 Ukraine Electric Power Attack: During the 2016 Ukraine Electric Power Attack, Sandworm Team used various MS-SQL stored procedures.
- [S0603] Stuxnet: Stuxnet used xp_cmdshell to store and execute SQL code.

### T1505.002 - Server Software Component: Transport Agent

Procedures:

- [S0395] LightNeuron: LightNeuron has used a malicious Microsoft Exchange transport agent for persistence.

### T1505.003 - Server Software Component: Web Shell

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

### T1505.004 - Server Software Component: IIS Components

Procedures:

- [S0258] RGDoor: RGDoor establishes persistence on webservers as an IIS module.
- [S1022] IceApple: IceApple is an IIS post-exploitation framework, consisting of 18 modules that provide several functionalities.
- [C0022] Operation Dream Job: During Operation Dream Job, Lazarus Group targeted Windows servers running Internet Information Systems (IIS) to install C2 components.
- [S0072] OwaAuth: OwaAuth has been loaded onto Exchange servers and disguised as an ISAPI filter (owaauth.dll). The IIS w3wp.exe process then loads the malicious DLL.

### T1505.005 - Server Software Component: Terminal Services DLL

Procedures:

- Adversaries may abuse components of Terminal Services to enable persistent access to systems. Microsoft Terminal Services, renamed to Remote Desktop Services in some Windows Server OSs as of 2022, enable remote terminal connections to hosts. Terminal Services allows servers to transmit a full, interactive, graphical user interface to clients via RDP. Windows Services that are run as a "generic" process (ex: svchost.exe) load the service's DLL file, the location of which is stored in a Registry entry named ServiceDll. The termsrv.dll file, typically stored in `%SystemRoot%\System32\`, is the default ServiceDll value for Terminal Services in `HKLM\System\CurrentControlSet\services\TermService\Parameters\`. Adversaries may modify and/or replace the Terminal Services DLL to enable persistent access to victimized hosts. Modifications to this DLL could be done to execute arbitrary payloads (while also potentially preserving normal termsrv.dll functionality) as well as to simply enable abusable features of Terminal Services. For example, an adversary may enable features such as concurrent Remote Desktop Protocol sessions by either patching the termsrv.dll file or modifying the ServiceDll value to point to a DLL that provides increased RDP functionality. On a non-server Windows OS this increased functionality may also enable an adversary to avoid Terminal Services prompts that warn/log out users of a system when a new RDP session is created.

### T1505.006 - Server Software Component: vSphere Installation Bundles

Procedures:

- Adversaries may abuse vSphere Installation Bundles (VIBs) to establish persistent access to ESXi hypervisors. VIBs are collections of files used for software distribution and virtual system management in VMware environments. Since ESXi uses an in-memory filesystem where changes made to most files are stored in RAM rather than in persistent storage, these modifications are lost after a reboot. However, VIBs can be used to create startup tasks, apply custom firewall rules, or deploy binaries that persist across reboots. Typically, administrators use VIBs for updates and system maintenance. VIBs can be broken down into three components: * VIB payload: a `.vgz` archive containing the directories and files to be created and executed on boot when the VIBs are loaded. * Signature file: verifies the host acceptance level of a VIB, indicating what testing and validation has been done by VMware or its partners before publication of a VIB. By default, ESXi hosts require a minimum acceptance level of PartnerSupported for VIB installation, meaning the VIB is published by a trusted VMware partner. However, privileged users can change the default acceptance level using the `esxcli` command line interface. Additionally, VIBs are able to be installed regardless of acceptance level by using the esxcli software vib install --force command. * XML descriptor file: a configuration file containing associated VIB metadata, such as the name of the VIB and its dependencies. Adversaries may leverage malicious VIB packages to maintain persistent access to ESXi hypervisors, allowing system changes to be executed upon each bootup of ESXi – such as using `esxcli` to enable firewall rules for backdoor traffic, creating listeners on hard coded ports, and executing backdoors. Adversaries may also masquerade their malicious VIB files as PartnerSupported by modifying the XML descriptor file.


### T1525 - Implant Internal Image

Procedures:

- Adversaries may implant cloud or container images with malicious code to establish persistence after gaining access to an environment. Amazon Web Services (AWS) Amazon Machine Images (AMIs), Google Cloud Platform (GCP) Images, and Azure Images as well as popular container runtimes such as Docker can be implanted or backdoored. Unlike Upload Malware, this technique focuses on adversaries implanting an image in a registry within a victim’s environment. Depending on how the infrastructure is provisioned, this could provide persistent access if the infrastructure provisioning tool is instructed to always use the latest image. A tool has been developed to facilitate planting backdoors in cloud container images. If an adversary has access to a compromised AWS instance, and permissions to list the available container images, they may implant a backdoor such as a Web Shell.


### T1542.001 - Pre-OS Boot: System Firmware

Procedures:

- [S0397] LoJax: LoJax is a UEFI BIOS rootkit deployed to persist remote access software on some targeted systems.
- [S0001] Trojan.Mebromi: Trojan.Mebromi performs BIOS modification and can download and execute a file as well as protect itself from removal.
- [S0047] Hacking Team UEFI Rootkit: Hacking Team UEFI Rootkit is a UEFI BIOS rootkit developed by the company Hacking Team to persist remote access software on some targeted systems.

### T1542.002 - Pre-OS Boot: Component Firmware

Procedures:

- [G0020] Equation: Equation is known to have the capability to overwrite the firmware on hard drives from some manufacturers.
- [S0687] Cyclops Blink: Cyclops Blink has maintained persistence by patching legitimate device firmware when it is downloaded, including that of WatchGuard devices.

### T1542.003 - Pre-OS Boot: Bootkit

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

Procedures:

- Adversaries may abuse the ROM Monitor (ROMMON) by loading an unauthorized firmware with adversary code to provide persistent access and manipulate device behavior that is difficult to detect. ROMMON is a Cisco network device firmware that functions as a boot loader, boot image, or boot helper to initialize hardware and software when the platform is powered on or reset. Similar to TFTP Boot, an adversary may upgrade the ROMMON image locally or remotely (for example, through TFTP) with adversary code and restart the device in order to overwrite the existing ROMMON image. This provides adversaries with the means to update the ROMMON to gain persistence on a system in a way that may be difficult to detect.

### T1542.005 - Pre-OS Boot: TFTP Boot

Procedures:

- Adversaries may abuse netbooting to load an unauthorized network device operating system from a Trivial File Transfer Protocol (TFTP) server. TFTP boot (netbooting) is commonly used by network administrators to load configuration-controlled network device images from a centralized management server. Netbooting is one option in the boot sequence and can be used to centralize, manage, and control device images. Adversaries may manipulate the configuration on the network device specifying use of a malicious TFTP server, which may be used in conjunction with Modify System Image to load a modified image on device startup or reset. The unauthorized image allows adversaries to modify device configuration, add malicious capabilities to the device, and introduce backdoors to maintain control of the network device while minimizing detection through use of a standard functionality. This technique is similar to ROMMONkit and may result in the network device running a modified image.


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

Procedures:

- Adversaries may create or modify container or container cluster management tools that run as daemons, agents, or services on individual hosts. These include software for creating and managing individual containers, such as Docker and Podman, as well as container cluster node-level agents such as kubelet. By modifying these services, an adversary may be able to achieve persistence or escalate their privileges on a host. For example, by using the `docker run` or `podman run` command with the `restart=always` directive, a container can be configured to persistently restart on the host. A user with access to the (rootful) docker command may also be able to escalate their privileges on the host. In Kubernetes environments, DaemonSets allow an adversary to persistently Deploy Containers on all nodes, including ones added later to the cluster. Pods can also be deployed to specific nodes using the `nodeSelector` or `nodeName` fields in the pod spec. Note that containers can also be configured to run as Systemd Services.


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

Procedures:

- Adversaries may establish persistence by executing malicious content triggered by an interrupt signal. The trap command allows programs and shells to specify commands that will be executed upon receiving interrupt signals. A common situation is a script allowing for graceful termination and handling of common keyboard interrupts like ctrl+c and ctrl+d. Adversaries can use this to register code to be executed when the shell encounters specific interrupts as a persistence mechanism. Trap commands are of the following format trap 'command list' signals where "command list" will be executed when "signals" are received.

### T1546.006 - Event Triggered Execution: LC_LOAD_DYLIB Addition

Procedures:

- Adversaries may establish persistence by executing malicious content triggered by the execution of tainted binaries. Mach-O binaries have a series of headers that are used to perform certain operations when a binary is loaded. The LC_LOAD_DYLIB header in a Mach-O binary tells macOS and OS X which dynamic libraries (dylibs) to load during execution time. These can be added ad-hoc to the compiled binary as long as adjustments are made to the rest of the fields and dependencies. There are tools available to perform these changes. Adversaries may modify Mach-O binary headers to load and execute malicious dylibs every time the binary is executed. Although any changes will invalidate digital signatures on binaries because the binary is being modified, this can be remediated by simply removing the LC_CODE_SIGNATURE command from the binary so that the signature isn’t checked at load time.

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

Procedures:

- Adversaries may gain persistence and elevate privileges by executing malicious content triggered by the Event Monitor Daemon (emond). Emond is a Launch Daemon that accepts events from various services, runs them through a simple rules engine, and takes action. The emond binary at /sbin/emond will load any rules from the /etc/emond.d/rules/ directory and take action once an explicitly defined event takes place. The rule files are in the plist format and define the name, event type, and action to take. Some examples of event types include system startup and user authentication. Examples of actions are to run a system command or send an email. The emond service will not launch if there is no file present in the QueueDirectories path /private/var/db/emondClients, specified in the Launch Daemon configuration file at/System/Library/LaunchDaemons/com.apple.emond.plist. Adversaries may abuse this service by writing a rule to execute commands when a defined event occurs, such as system start up or user authentication. Adversaries may also be able to escalate privileges from administrator to root as the emond service is executed with root privileges by the Launch Daemon service.

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

Procedures:

- Adversaries may maintain persistence through executing malicious content triggered using udev rules. Udev is the Linux kernel device manager that dynamically manages device nodes, handles access to pseudo-device files in the `/dev` directory, and responds to hardware events, such as when external devices like hard drives or keyboards are plugged in or removed. Udev uses rule files with `match keys` to specify the conditions a hardware event must meet and `action keys` to define the actions that should follow. Root permissions are required to create, modify, or delete rule files located in `/etc/udev/rules.d/`, `/run/udev/rules.d/`, `/usr/lib/udev/rules.d/`, `/usr/local/lib/udev/rules.d/`, and `/lib/udev/rules.d/`. Rule priority is determined by both directory and by the digit prefix in the rule filename. Adversaries may abuse the udev subsystem by adding or modifying rules in udev rule files to execute malicious content. For example, an adversary may configure a rule to execute their binary each time the pseudo-device file, such as `/dev/random`, is accessed by an application. Although udev is limited to running short tasks and is restricted by systemd-udevd's sandbox (blocking network and filesystem access), attackers may use scripting commands under the action key `RUN+=` to detach and run the malicious content’s process in the background to bypass these controls.


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

Procedures:

- Adversaries may abuse time providers to execute DLLs when the system boots. The Windows Time service (W32Time) enables time synchronization across and within domains. W32Time time providers are responsible for retrieving time stamps from hardware/network resources and outputting these values to other network clients. Time providers are implemented as dynamic-link libraries (DLLs) that are registered in the subkeys of `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\W32Time\TimeProviders\`. The time provider manager, directed by the service control manager, loads and starts time providers listed and enabled under this key at system startup and/or whenever parameters are changed. Adversaries may abuse this architecture to establish persistence, specifically by creating a new arbitrarily named subkey pointing to a malicious DLL in the `DllName` value. Administrator privileges are required for time provider registration, though execution will run in context of the Local Service account.

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

Procedures:

- Adversaries may modify plist files to automatically run an application when a user logs in. When a user logs out or restarts via the macOS Graphical User Interface (GUI), a prompt is provided to the user with a checkbox to "Reopen windows when logging back in". When selected, all applications currently open are added to a property list file named com.apple.loginwindow.[UUID].plist within the ~/Library/Preferences/ByHost directory. Applications listed in this file are automatically reopened upon the user’s next logon. Adversaries can establish Persistence by adding a malicious application path to the com.apple.loginwindow.[UUID].plist file to execute payloads when a user logs in.

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

Procedures:

- Adversaries may use port monitors to run an adversary supplied DLL during system boot for persistence or privilege escalation. A port monitor can be set through the AddMonitor API call to set a DLL to be loaded at startup. This DLL can be located in C:\Windows\System32 and will be loaded and run by the print spooler service, `spoolsv.exe`, under SYSTEM level permissions on boot. Alternatively, an arbitrary DLL can be loaded if permissions allow writing a fully-qualified pathname for that DLL to the `Driver` value of an existing or new arbitrarily named subkey of HKLM\SYSTEM\CurrentControlSet\Control\Print\Monitors. The Registry key contains entries for the following: * Local Port * Standard TCP/IP Port * USB Monitor * WSD Port

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


### T1554 - Compromise Host Software Binary

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


### T1556.001 - Modify Authentication Process: Domain Controller Authentication

Procedures:

- [G0114] Chimera: Chimera's malware has altered the NTLM authentication program on domain controllers to allow Chimera to login without a valid credential.
- [S0007] Skeleton Key: Skeleton Key is used to patch an enterprise domain controller authentication process with a backdoor password. It allows adversaries to bypass the standard authentication system to use a defined password for all accounts authenticating to that domain controller.

### T1556.002 - Modify Authentication Process: Password Filter DLL

Procedures:

- [S0125] Remsec: Remsec harvests plain-text credentials as a password filter registered on domain controllers.
- [G0049] OilRig: OilRig has registered a password filter DLL in order to drop malware.
- [G0041] Strider: Strider has registered its persistence module on domain controllers as a Windows LSA (Local System Authority) password filter to acquire credentials any time a domain, local user, or administrator logs in or changes a password.

### T1556.003 - Modify Authentication Process: Pluggable Authentication Modules

Procedures:

- [S0377] Ebury: Ebury can deactivate PAM modules to tamper with the sshd configuration.
- [S0468] Skidmap: Skidmap has the ability to replace the pam_unix.so file on an infected machine with its own malicious version that accepts a specific backdoor password for all users.

### T1556.004 - Modify Authentication Process: Network Device Authentication

Procedures:

- [S1104] SLOWPULSE: SLOWPULSE can modify LDAP and two factor authentication flows by inspecting login credentials and forcing successful authentication if the provided password matches a chosen backdoor password.
- [S0519] SYNful Knock: SYNful Knock has the capability to add its own custom backdoor password when it modifies the operating system of the affected network device.

### T1556.005 - Modify Authentication Process: Reversible Encryption

Procedures:

- An adversary may abuse Active Directory authentication encryption properties to gain access to credentials on Windows systems. The AllowReversiblePasswordEncryption property specifies whether reversible password encryption for an account is enabled or disabled. By default this property is disabled (instead storing user credentials as the output of one-way hashing functions) and should not be enabled unless legacy or other software require it. If the property is enabled and/or a user changes their password after it is enabled, an adversary may be able to obtain the plaintext of passwords created/changed after the property was enabled. To decrypt the passwords, an adversary needs four components: 1. Encrypted password (G$RADIUSCHAP) from the Active Directory user-structure userParameters 2. 16 byte randomly-generated value (G$RADIUSCHAPKEY) also from userParameters 3. Global LSA secret (G$MSRADIUSCHAPKEY) 4. Static key hardcoded in the Remote Access Subauthentication DLL (RASSFM.DLL) With this information, an adversary may be able to reproduce the encryption key and subsequently decrypt the encrypted password value. An adversary may set this property at various scopes through Local Group Policy Editor, user properties, Fine-Grained Password Policy (FGPP), or via the ActiveDirectory PowerShell module. For example, an adversary may implement and apply a FGPP to users or groups if the Domain Functional Level is set to "Windows Server 2008" or higher. In PowerShell, an adversary may make associated changes to user settings using commands similar to Set-ADUser -AllowReversiblePasswordEncryption $true.

### T1556.006 - Modify Authentication Process: Multi-Factor Authentication

Procedures:

- [G1015] Scattered Spider: After compromising user accounts, Scattered Spider registers their own MFA tokens.
- [S1104] SLOWPULSE: SLOWPULSE can insert malicious logic to bypass RADIUS and ACE two factor authentication (2FA) flows if a designated attacker-supplied password is provided.
- [S0677] AADInternals: The AADInternals `Set-AADIntUserMFA` command can be used to disable MFA for a specified user.

### T1556.007 - Modify Authentication Process: Hybrid Identity

Procedures:

- [S0677] AADInternals: AADInternals can inject a malicious DLL (`PTASpy`) into the `AzureADConnectAuthenticationAgentService` to backdoor Azure AD Pass-Through Authentication.
- [G0016] APT29: APT29 has edited the `Microsoft.IdentityServer.Servicehost.exe.config` file to load a malicious DLL into the AD FS process, thereby enabling persistent access to any service federated with AD FS for a user with a specified User Principal Name.

### T1556.008 - Modify Authentication Process: Network Provider DLL

Procedures:

- Adversaries may register malicious network provider dynamic link libraries (DLLs) to capture cleartext user credentials during the authentication process. Network provider DLLs allow Windows to interface with specific network protocols and can also support add-on credential management functions. During the logon process, Winlogon (the interactive logon module) sends credentials to the local `mpnotify.exe` process via RPC. The `mpnotify.exe` process then shares the credentials in cleartext with registered credential managers when notifying that a logon event is happening. Adversaries can configure a malicious network provider DLL to receive credentials from `mpnotify.exe`. Once installed as a credential manager (via the Registry), a malicious DLL can receive and save credentials each time a user logs onto a Windows workstation or domain via the `NPLogonNotify()` function. Adversaries may target planting malicious network provider DLLs on systems known to have increased logon activity and/or administrator logon activity, such as servers and domain controllers.

### T1556.009 - Modify Authentication Process: Conditional Access Policies

Procedures:

- [G1015] Scattered Spider: Scattered Spider has added additional trusted locations to Azure AD conditional access policies.


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

Procedures:

- Adversaries may execute their own malicious payloads by hijacking the binaries used by an installer. These processes may automatically execute specific binaries as part of their functionality or to perform other actions. If the permissions on the file system directory containing a target binary, or permissions on the binary itself, are improperly set, then the target binary may be overwritten with another binary using user-level permissions and executed by the original process. If the original process and thread are running under a higher permissions level, then the replaced binary will also execute under higher-level permissions, which could include SYSTEM. Another variation of this technique can be performed by taking advantage of a weakness that is common in executable, self-extracting installers. During the installation process, it is common for installers to use a subdirectory within the %TEMP% directory to unpack binaries such as DLLs, EXEs, or other payloads. When installers create subdirectories and files they often do not set appropriate permissions to restrict write access, which allows for execution of untrusted code placed in the subdirectories or overwriting of binaries used in the installation process. This behavior is related to and may take advantage of DLL search order hijacking. Adversaries may use this technique to replace legitimate binaries with malicious ones as a means of executing code at a higher permissions level. Some installers may also require elevated privileges that will result in privilege escalation when executing adversary controlled code. This behavior is related to Bypass User Account Control. Several examples of this weakness in existing common installers have been reported to software vendors. If the executing process is set to run at a specific time or during a certain event (e.g., system bootup) then this technique can also be used for persistence.

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


### T1653 - Power Settings

Procedures:

- [C0046] ArcaneDoor: ArcaneDoor involved exploitation of CVE-2024-20353 to force a victim Cisco ASA to reboot, triggering the automated unzipping and execution of the Line Runner implant.
- [S1188] Line Runner: Line Runner used CVE-2024-20353 to trigger victim devices to reboot, in the process unzipping and installing the Line Dancer payload.
- [S1186] Line Dancer: Line Dancer can modify the crash dump process on infected machines to skip crash dump generation and proceed directly to device reboot for both persistence and forensic evasion purposes.


### T1668 - Exclusive Control

Procedures:

- Adversaries who successfully compromise a system may attempt to maintain persistence by “closing the door” behind them – in other words, by preventing other threat actors from initially accessing or maintaining a foothold on the same system. For example, adversaries may patch a vulnerable, compromised system to prevent other threat actors from leveraging that vulnerability in the future. They may “close the door” in other ways, such as disabling vulnerable services, stripping privileges from accounts, or removing other malware already on the compromised device. Hindering other threat actors may allow an adversary to maintain sole access to a compromised system or network. This prevents the threat actor from needing to compete with or even being removed themselves by other threat actors. It also reduces the “noise” in the environment, lowering the possibility of being caught and evicted by defenders. Finally, in the case of Resource Hijacking, leveraging a compromised device’s full power allows the threat actor to maximize profit.


### T1671 - Cloud Application Integration

Procedures:

- Adversaries may achieve persistence by leveraging OAuth application integrations in a software-as-a-service environment. Adversaries may create a custom application, add a legitimate application into the environment, or even co-opt an existing integration to achieve malicious ends. OAuth is an open standard that allows users to authorize applications to access their information on their behalf. In a SaaS environment such as Microsoft 365 or Google Workspace, users may integrate applications to improve their workflow and achieve tasks. Leveraging application integrations may allow adversaries to persist in an environment – for example, by granting consent to an application from a high-privileged adversary-controlled account in order to maintain access to its data, even in the event of losing access to the account. In some cases, integrations may remain valid even after the original consenting user account is disabled. Application integrations may also allow adversaries to bypass multi-factor authentication requirements through the use of Application Access Tokens. Finally, they may enable persistent Automated Exfiltration over time. Creating or adding a new application may require the adversary to create a dedicated Cloud Account for the application and assign it Additional Cloud Roles – for example, in Microsoft 365 environments, an application can only access resources via an associated service principal.

