### T1037 - Boot or Logon Initialization Scripts

Description:

Adversaries may use scripts automatically executed at boot or logon initialization to establish persistence.(Citation: Mandiant APT29 Eye Spy Email Nov 22)(Citation: Anomali Rocke March 2019) Initialization scripts can be used to perform administrative functions, which may often execute other programs or send information to an internal logging server. These scripts can vary based on operating system and whether applied locally or remotely.  

Adversaries may use these scripts to maintain persistence on a single system. Depending on the access configuration of the logon scripts, either local credentials or an administrator account may be necessary. 

An adversary may also be able to escalate their privileges since some boot or logon initialization scripts run with higher privileges.

#### T1037.001 - Boot or Logon Initialization Scripts: Logon Script (Windows)

Description:

Adversaries may use Windows logon scripts automatically executed at logon initialization to establish persistence. Windows allows logon scripts to be run whenever a specific user or group of users log into a system.(Citation: TechNet Logon Scripts) This is done via adding a path to a script to the <code>HKCU\Environment\UserInitMprLogonScript</code> Registry key.(Citation: Hexacorn Logon Scripts)

Adversaries may use these scripts to maintain persistence on a single system. Depending on the access configuration of the logon scripts, either local credentials or an administrator account may be necessary.

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

#### T1037.005 - Boot or Logon Initialization Scripts: Startup Items

Description:

Adversaries may use startup items automatically executed at boot initialization to establish persistence. Startup items execute during the final phase of the boot process and contain shell scripts or other executable files along with configuration information used by the system to determine the execution order for all startup items.(Citation: Startup Items)

This is technically a deprecated technology (superseded by [Launch Daemon](https://attack.mitre.org/techniques/T1543/004)), and thus the appropriate folder, <code>/Library/StartupItems</code> isn’t guaranteed to exist on the system by default, but does appear to exist by default on macOS Sierra. A startup item is a directory whose executable and configuration property list (plist), <code>StartupParameters.plist</code>, reside in the top-level directory. 

An adversary can create the appropriate folders/files in the StartupItems directory to register their own persistence mechanism.(Citation: Methods of Mac Malware Persistence) Additionally, since StartupItems run during the bootup phase of macOS, they will run as the elevated root user.


### T1053 - Scheduled Task/Job

Description:

Adversaries may abuse task scheduling functionality to facilitate initial or recurring execution of malicious code. Utilities exist within all major operating systems to schedule programs or scripts to be executed at a specified date and time. A task can also be scheduled on a remote system, provided the proper authentication is met (ex: RPC and file and printer sharing in Windows environments). Scheduling a task on a remote system typically may require being a member of an admin or otherwise privileged group on the remote system.(Citation: TechNet Task Scheduler Security)

Adversaries may use task scheduling to execute programs at system startup or on a scheduled basis for persistence. These mechanisms can also be abused to run a process under the context of a specified account (such as one with elevated permissions/privileges). Similar to [System Binary Proxy Execution](https://attack.mitre.org/techniques/T1218), adversaries have also abused task scheduling to potentially mask one-time execution under a trusted system process.(Citation: ProofPoint Serpent)

#### T1053.002 - Scheduled Task/Job: At

Description:

Adversaries may abuse the [at](https://attack.mitre.org/software/S0110) utility to perform task scheduling for initial or recurring execution of malicious code. The [at](https://attack.mitre.org/software/S0110) utility exists as an executable within Windows, Linux, and macOS for scheduling tasks at a specified time and date. Although deprecated in favor of [Scheduled Task](https://attack.mitre.org/techniques/T1053/005)'s [schtasks](https://attack.mitre.org/software/S0111) in Windows environments, using [at](https://attack.mitre.org/software/S0110) requires that the Task Scheduler service be running, and the user to be logged on as a member of the local Administrators group. In addition to explicitly running the `at` command, adversaries may also schedule a task with [at](https://attack.mitre.org/software/S0110) by directly leveraging the [Windows Management Instrumentation](https://attack.mitre.org/techniques/T1047) `Win32_ScheduledJob` WMI class.(Citation: Malicious Life by Cybereason)

On Linux and macOS, [at](https://attack.mitre.org/software/S0110) may be invoked by the superuser as well as any users added to the <code>at.allow</code> file. If the <code>at.allow</code> file does not exist, the <code>at.deny</code> file is checked. Every username not listed in <code>at.deny</code> is allowed to invoke [at](https://attack.mitre.org/software/S0110). If the <code>at.deny</code> exists and is empty, global use of [at](https://attack.mitre.org/software/S0110) is permitted. If neither file exists (which is often the baseline) only the superuser is allowed to use [at](https://attack.mitre.org/software/S0110).(Citation: Linux at)

Adversaries may use [at](https://attack.mitre.org/software/S0110) to execute programs at system startup or on a scheduled basis for [Persistence](https://attack.mitre.org/tactics/TA0003). [at](https://attack.mitre.org/software/S0110) can also be abused to conduct remote [Execution](https://attack.mitre.org/tactics/TA0002) as part of [Lateral Movement](https://attack.mitre.org/tactics/TA0008) and/or to run a process under the context of a specified account (such as SYSTEM).

In Linux environments, adversaries may also abuse [at](https://attack.mitre.org/software/S0110) to break out of restricted environments by using a task to spawn an interactive system shell or to run system commands. Similarly, [at](https://attack.mitre.org/software/S0110) may also be used for [Privilege Escalation](https://attack.mitre.org/tactics/TA0004) if the binary is allowed to run as superuser via <code>sudo</code>.(Citation: GTFObins at)

#### T1053.003 - Scheduled Task/Job: Cron

Description:

Adversaries may abuse the <code>cron</code> utility to perform task scheduling for initial or recurring execution of malicious code.(Citation: 20 macOS Common Tools and Techniques) The <code>cron</code> utility is a time-based job scheduler for Unix-like operating systems.  The <code> crontab</code> file contains the schedule of cron entries to be run and the specified times for execution. Any <code>crontab</code> files are stored in operating system-specific file paths.

An adversary may use <code>cron</code> in Linux or Unix environments to execute programs at system startup or on a scheduled basis for [Persistence](https://attack.mitre.org/tactics/TA0003). In ESXi environments, cron jobs must be created directly via the crontab file (e.g., `/var/spool/cron/crontabs/root`).(Citation: CloudSEK ESXiArgs 2023)

#### T1053.005 - Scheduled Task/Job: Scheduled Task

Description:

Adversaries may abuse the Windows Task Scheduler to perform task scheduling for initial or recurring execution of malicious code. There are multiple ways to access the Task Scheduler in Windows. The [schtasks](https://attack.mitre.org/software/S0111) utility can be run directly on the command line, or the Task Scheduler can be opened through the GUI within the Administrator Tools section of the Control Panel.(Citation: Stack Overflow) In some cases, adversaries have used a .NET wrapper for the Windows Task Scheduler, and alternatively, adversaries have used the Windows netapi32 library and [Windows Management Instrumentation](https://attack.mitre.org/techniques/T1047) (WMI) to create a scheduled task. Adversaries may also utilize the Powershell Cmdlet `Invoke-CimMethod`, which leverages WMI class `PS_ScheduledTask` to create a scheduled task via an XML path.(Citation: Red Canary - Atomic Red Team)

An adversary may use Windows Task Scheduler to execute programs at system startup or on a scheduled basis for persistence. The Windows Task Scheduler can also be abused to conduct remote Execution as part of Lateral Movement and/or to run a process under the context of a specified account (such as SYSTEM). Similar to [System Binary Proxy Execution](https://attack.mitre.org/techniques/T1218), adversaries have also abused the Windows Task Scheduler to potentially mask one-time execution under signed/trusted system processes.(Citation: ProofPoint Serpent)

Adversaries may also create "hidden" scheduled tasks (i.e. [Hide Artifacts](https://attack.mitre.org/techniques/T1564)) that may not be visible to defender tools and manual queries used to enumerate tasks. Specifically, an adversary may hide a task from `schtasks /query` and the Task Scheduler by deleting the associated Security Descriptor (SD) registry value (where deletion of this value must be completed using SYSTEM permissions).(Citation: SigmaHQ)(Citation: Tarrask scheduled task) Adversaries may also employ alternate methods to hide tasks, such as altering the metadata (e.g., `Index` value) within associated registry keys.(Citation: Defending Against Scheduled Task Attacks in Windows Environments)

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

#### T1078.001 - Valid Accounts: Default Accounts

Description:

Adversaries may obtain and abuse credentials of a default account as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion. Default accounts are those that are built-into an OS, such as the Guest or Administrator accounts on Windows systems. Default accounts also include default factory/provider set accounts on other types of systems, software, or devices, including the root user account in AWS, the root user account in ESXi, and the default service account in Kubernetes.(Citation: Microsoft Local Accounts Feb 2019)(Citation: AWS Root User)(Citation: Threat Matrix for Kubernetes)

Default accounts are not limited to client machines; rather, they also include accounts that are preset for equipment such as network devices and computer applications, whether they are internal, open source, or commercial. Appliances that come preset with a username and password combination pose a serious threat to organizations that do not change it post installation, as they are easy targets for an adversary. Similarly, adversaries may also utilize publicly disclosed or stolen [Private Keys](https://attack.mitre.org/techniques/T1552/004) or credential materials to legitimately connect to remote environments via [Remote Services](https://attack.mitre.org/techniques/T1021).(Citation: Metasploit SSH Module)

Default accounts may be created on a system after initial setup by connecting or integrating it with another application. For example, when an ESXi server is connected to a vCenter server, a default privileged account called `vpxuser` is created on the ESXi server. If a threat actor is able to compromise this account’s credentials (for example, via [Exploitation for Credential Access](https://attack.mitre.org/techniques/T1212) on the vCenter host), they will then have access to the ESXi server.(Citation: Google Cloud Threat Intelligence VMWare ESXi Zero-Day 2023)(Citation: Pentera vCenter Information Disclosure)

#### T1078.002 - Valid Accounts: Domain Accounts

Description:

Adversaries may obtain and abuse credentials of a domain account as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion.(Citation: TechNet Credential Theft) Domain accounts are those managed by Active Directory Domain Services where access and permissions are configured across systems and services that are part of that domain. Domain accounts can cover users, administrators, and services.(Citation: Microsoft AD Accounts)

Adversaries may compromise domain accounts, some with a high level of privileges, through various means such as [OS Credential Dumping](https://attack.mitre.org/techniques/T1003) or password reuse, allowing access to privileged resources of the domain.

#### T1078.003 - Valid Accounts: Local Accounts

Description:

Adversaries may obtain and abuse credentials of a local account as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion. Local accounts are those configured by an organization for use by users, remote support, services, or for administration on a single system or service.

Local Accounts may also be abused to elevate privileges and harvest credentials through [OS Credential Dumping](https://attack.mitre.org/techniques/T1003). Password reuse may allow the abuse of local accounts across a set of machines on a network for the purposes of Privilege Escalation and Lateral Movement.

#### T1078.004 - Valid Accounts: Cloud Accounts

Description:

Valid accounts in cloud environments may allow adversaries to perform actions to achieve Initial Access, Persistence, Privilege Escalation, or Defense Evasion. Cloud accounts are those created and configured by an organization for use by users, remote support, services, or for administration of resources within a cloud service provider or SaaS application. Cloud Accounts can exist solely in the cloud; alternatively, they may be hybrid-joined between on-premises systems and the cloud through syncing or federation with other identity sources such as Windows Active Directory.(Citation: AWS Identity Federation)(Citation: Google Federating GC)(Citation: Microsoft Deploying AD Federation)

Service or user accounts may be targeted by adversaries through [Brute Force](https://attack.mitre.org/techniques/T1110), [Phishing](https://attack.mitre.org/techniques/T1566), or various other means to gain access to the environment. Federated or synced accounts may be a pathway for the adversary to affect both on-premises systems and cloud environments - for example, by leveraging shared credentials to log onto [Remote Services](https://attack.mitre.org/techniques/T1021). High privileged cloud accounts, whether federated, synced, or cloud-only, may also allow pivoting to on-premises environments by leveraging SaaS-based [Software Deployment Tools](https://attack.mitre.org/techniques/T1072) to run commands on hybrid-joined devices.

An adversary may create long lasting [Additional Cloud Credentials](https://attack.mitre.org/techniques/T1098/001) on a compromised cloud account to maintain persistence in the environment. Such credentials may also be used to bypass security controls such as multi-factor authentication. 

Cloud accounts may also be able to assume [Temporary Elevated Cloud Access](https://attack.mitre.org/techniques/T1548/005) or other privileges through various means within the environment. Misconfigurations in role assignments or role assumption policies may allow an adversary to use these mechanisms to leverage permissions outside the intended scope of the account. Such over privileged accounts may be used to harvest sensitive data from online storage accounts and databases through [Cloud API](https://attack.mitre.org/techniques/T1059/009) or other methods. For example, in Azure environments, adversaries may target Azure Managed Identities, which allow associated Azure resources to request access tokens. By compromising a resource with an attached Managed Identity, such as an Azure VM, adversaries may be able to [Steal Application Access Token](https://attack.mitre.org/techniques/T1528)s to move laterally across the cloud environment.(Citation: SpecterOps Managed Identity 2022)


### T1098 - Account Manipulation

Description:

Adversaries may manipulate accounts to maintain and/or elevate access to victim systems. Account manipulation may consist of any action that preserves or modifies adversary access to a compromised account, such as modifying credentials or permission groups.(Citation: FireEye SMOKEDHAM June 2021) These actions could also include account activity designed to subvert security policies, such as performing iterative password updates to bypass password duration policies and preserve the life of compromised credentials. 

In order to create or manipulate accounts, the adversary must already have sufficient permissions on systems or the domain. However, account manipulation may also lead to privilege escalation where modifications grant access to additional roles, permissions, or higher-privileged [Valid Accounts](https://attack.mitre.org/techniques/T1078).

#### T1098.001 - Account Manipulation: Additional Cloud Credentials

Description:

Adversaries may add adversary-controlled credentials to a cloud account to maintain persistent access to victim accounts and instances within the environment.

For example, adversaries may add credentials for Service Principals and Applications in addition to existing legitimate credentials in Azure / Entra ID.(Citation: Microsoft SolarWinds Customer Guidance)(Citation: Blue Cloud of Death)(Citation: Blue Cloud of Death Video) These credentials include both x509 keys and passwords.(Citation: Microsoft SolarWinds Customer Guidance) With sufficient permissions, there are a variety of ways to add credentials including the Azure Portal, Azure command line interface, and Azure or Az PowerShell modules.(Citation: Demystifying Azure AD Service Principals)

In infrastructure-as-a-service (IaaS) environments, after gaining access through [Cloud Accounts](https://attack.mitre.org/techniques/T1078/004), adversaries may generate or import their own SSH keys using either the <code>CreateKeyPair</code> or <code>ImportKeyPair</code> API in AWS or the <code>gcloud compute os-login ssh-keys add</code> command in GCP.(Citation: GCP SSH Key Add) This allows persistent access to instances within the cloud environment without further usage of the compromised cloud accounts.(Citation: Expel IO Evil in AWS)(Citation: Expel Behind the Scenes)

Adversaries may also use the <code>CreateAccessKey</code> API in AWS or the <code>gcloud iam service-accounts keys create</code> command in GCP to add access keys to an account. Alternatively, they may use the <code>CreateLoginProfile</code> API in AWS to add a password that can be used to log into the AWS Management Console for [Cloud Service Dashboard](https://attack.mitre.org/techniques/T1538).(Citation: Permiso Scattered Spider 2023)(Citation: Lacework AI Resource Hijacking 2024) If the target account has different permissions from the requesting account, the adversary may also be able to escalate their privileges in the environment (i.e. [Cloud Accounts](https://attack.mitre.org/techniques/T1078/004)).(Citation: Rhino Security Labs AWS Privilege Escalation)(Citation: Sysdig ScarletEel 2.0) For example, in Entra ID environments, an adversary with the Application Administrator role can add a new set of credentials to their application's service principal. In doing so the adversary would be able to access the service principal’s roles and permissions, which may be different from those of the Application Administrator.(Citation: SpecterOps Azure Privilege Escalation) 

In AWS environments, adversaries with the appropriate permissions may also use the `sts:GetFederationToken` API call to create a temporary set of credentials to [Forge Web Credentials](https://attack.mitre.org/techniques/T1606) tied to the permissions of the original user account. These temporary credentials may remain valid for the duration of their lifetime even if the original account’s API credentials are deactivated.
(Citation: Crowdstrike AWS User Federation Persistence)

In Entra ID environments with the app password feature enabled, adversaries may be able to add an app password to a user account.(Citation: Mandiant APT42 Operations 2024) As app passwords are intended to be used with legacy devices that do not support multi-factor authentication (MFA), adding an app password can allow an adversary to bypass MFA requirements. Additionally, app passwords may remain valid even if the user’s primary password is reset.(Citation: Microsoft Entra ID App Passwords)

#### T1098.002 - Account Manipulation: Additional Email Delegate Permissions

Description:

Adversaries may grant additional permission levels to maintain persistent access to an adversary-controlled email account. 

For example, the <code>Add-MailboxPermission</code> [PowerShell](https://attack.mitre.org/techniques/T1059/001) cmdlet, available in on-premises Exchange and in the cloud-based service Office 365, adds permissions to a mailbox.(Citation: Microsoft - Add-MailboxPermission)(Citation: FireEye APT35 2018)(Citation: Crowdstrike Hiding in Plain Sight 2018) In Google Workspace, delegation can be enabled via the Google Admin console and users can delegate accounts via their Gmail settings.(Citation: Gmail Delegation)(Citation: Google Ensuring Your Information is Safe) 

Adversaries may also assign mailbox folder permissions through individual folder permissions or roles. In Office 365 environments, adversaries may assign the Default or Anonymous user permissions or roles to the Top of Information Store (root), Inbox, or other mailbox folders. By assigning one or both user permissions to a folder, the adversary can utilize any other account in the tenant to maintain persistence to the target user’s mail folders.(Citation: Mandiant Defend UNC2452 White Paper)

This may be used in persistent threat incidents as well as BEC (Business Email Compromise) incidents where an adversary can add [Additional Cloud Roles](https://attack.mitre.org/techniques/T1098/003) to the accounts they wish to compromise. This may further enable use of additional techniques for gaining access to systems. For example, compromised business accounts are often used to send messages to other accounts in the network of the target business while creating inbox rules (ex: [Internal Spearphishing](https://attack.mitre.org/techniques/T1534)), so the messages evade spam/phishing detection mechanisms.(Citation: Bienstock, D. - Defending O365 - 2019)

#### T1098.003 - Account Manipulation: Additional Cloud Roles

Description:

An adversary may add additional roles or permissions to an adversary-controlled cloud account to maintain persistent access to a tenant. For example, adversaries may update IAM policies in cloud-based environments or add a new global administrator in Office 365 environments.(Citation: AWS IAM Policies and Permissions)(Citation: Google Cloud IAM Policies)(Citation: Microsoft Support O365 Add Another Admin, October 2019)(Citation: Microsoft O365 Admin Roles) With sufficient permissions, a compromised account can gain almost unlimited access to data and settings (including the ability to reset the passwords of other admins).(Citation: Expel AWS Attacker)
(Citation: Microsoft O365 Admin Roles) 

This account modification may immediately follow [Create Account](https://attack.mitre.org/techniques/T1136) or other malicious account activity. Adversaries may also modify existing [Valid Accounts](https://attack.mitre.org/techniques/T1078) that they have compromised. This could lead to privilege escalation, particularly if the roles added allow for lateral movement to additional accounts.

For example, in AWS environments, an adversary with appropriate permissions may be able to use the <code>CreatePolicyVersion</code> API to define a new version of an IAM policy or the <code>AttachUserPolicy</code> API to attach an IAM policy with additional or distinct permissions to a compromised user account.(Citation: Rhino Security Labs AWS Privilege Escalation)

In some cases, adversaries may add roles to adversary-controlled accounts outside the victim cloud tenant. This allows these external accounts to perform actions inside the victim tenant without requiring the adversary to [Create Account](https://attack.mitre.org/techniques/T1136) or modify a victim-owned account.(Citation: Invictus IR DangerDev 2024)

#### T1098.004 - Account Manipulation: SSH Authorized Keys

Description:

Adversaries may modify the SSH <code>authorized_keys</code> file to maintain persistence on a victim host. Linux distributions, macOS, and ESXi hypervisors commonly use key-based authentication to secure the authentication process of SSH sessions for remote management. The <code>authorized_keys</code> file in SSH specifies the SSH keys that can be used for logging into the user account for which the file is configured. This file is usually found in the user's home directory under <code>&lt;user-home&gt;/.ssh/authorized_keys</code> (or, on ESXi, `/etc/ssh/keys-<username>/authorized_keys`).(Citation: SSH Authorized Keys) Users may edit the system’s SSH config file to modify the directives `PubkeyAuthentication` and `RSAAuthentication` to the value `yes` to ensure public key and RSA authentication are enabled, as well as modify the directive `PermitRootLogin` to the value `yes` to enable root authentication via SSH.(Citation: Broadcom ESXi SSH) The SSH config file is usually located under <code>/etc/ssh/sshd_config</code>.

Adversaries may modify SSH <code>authorized_keys</code> files directly with scripts or shell commands to add their own adversary-supplied public keys. In cloud environments, adversaries may be able to modify the SSH authorized_keys file of a particular virtual machine via the command line interface or rest API. For example, by using the Google Cloud CLI’s “add-metadata” command an adversary may add SSH keys to a user account.(Citation: Google Cloud Add Metadata)(Citation: Google Cloud Privilege Escalation) Similarly, in Azure, an adversary may update the authorized_keys file of a virtual machine via a PATCH request to the API.(Citation: Azure Update Virtual Machines) This ensures that an adversary possessing the corresponding private key may log in as an existing user via SSH.(Citation: Venafi SSH Key Abuse)(Citation: Cybereason Linux Exim Worm) It may also lead to privilege escalation where the virtual machine or instance has distinct permissions from the requesting user.

Where authorized_keys files are modified via cloud APIs or command line interfaces, an adversary may achieve privilege escalation on the target virtual machine if they add a key to a higher-privileged user. 

SSH keys can also be added to accounts on network devices, such as with the `ip ssh pubkey-chain` [Network Device CLI](https://attack.mitre.org/techniques/T1059/008) command.(Citation: cisco_ip_ssh_pubkey_ch_cmd)

#### T1098.005 - Account Manipulation: Device Registration

Description:

Adversaries may register a device to an adversary-controlled account. Devices may be registered in a multifactor authentication (MFA) system, which handles authentication to the network, or in a device management system, which handles device access and compliance.

MFA systems, such as Duo or Okta, allow users to associate devices with their accounts in order to complete MFA requirements. An adversary that compromises a user’s credentials may enroll a new device in order to bypass initial MFA requirements and gain persistent access to a network.(Citation: CISA MFA PrintNightmare)(Citation: DarkReading FireEye SolarWinds) In some cases, the MFA self-enrollment process may require only a username and password to enroll the account's first device or to enroll a device to an inactive account. (Citation: Mandiant APT29 Microsoft 365 2022)

Similarly, an adversary with existing access to a network may register a device to Entra ID and/or its device management system, Microsoft Intune, in order to access sensitive data or resources while bypassing conditional access policies.(Citation: AADInternals - Device Registration)(Citation: AADInternals - Conditional Access Bypass)(Citation: Microsoft DEV-0537) 

Devices registered in Entra ID may be able to conduct [Internal Spearphishing](https://attack.mitre.org/techniques/T1534) campaigns via intra-organizational emails, which are less likely to be treated as suspicious by the email client.(Citation: Microsoft - Device Registration) Additionally, an adversary may be able to perform a [Service Exhaustion Flood](https://attack.mitre.org/techniques/T1499/002) on an Entra ID tenant by registering a large number of devices.(Citation: AADInternals - BPRT)

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


### T1112 - Modify Registry

Description:

Adversaries may interact with the Windows Registry as part of a variety of other techniques to aid in defense evasion, persistence, and execution.

Access to specific areas of the Registry depends on account permissions, with some keys requiring administrator-level access. The built-in Windows command-line utility [Reg](https://attack.mitre.org/software/S0075) may be used for local or remote Registry modification.(Citation: Microsoft Reg) Other tools, such as remote access tools, may also contain functionality to interact with the Registry through the Windows API.

The Registry may be modified in order to hide configuration information or malicious payloads via [Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027).(Citation: Unit42 BabyShark Feb 2019)(Citation: Avaddon Ransomware 2021)(Citation: Microsoft BlackCat Jun 2022)(Citation: CISA Russian Gov Critical Infra 2018) The Registry may also be modified to [Impair Defenses](https://attack.mitre.org/techniques/T1562), such as by enabling macros for all Microsoft Office products, allowing privilege escalation without alerting the user, increasing the maximum number of allowed outbound requests, and/or modifying systems to store plaintext credentials in memory.(Citation: CISA LockBit 2023)(Citation: Unit42 BabyShark Feb 2019)

The Registry of a remote system may be modified to aid in execution of files as part of lateral movement. It requires the remote Registry service to be running on the target system.(Citation: Microsoft Remote) Often [Valid Accounts](https://attack.mitre.org/techniques/T1078) are required, along with access to the remote system's [SMB/Windows Admin Shares](https://attack.mitre.org/techniques/T1021/002) for RPC communication.

Finally, Registry modifications may also include actions to hide keys, such as prepending key names with a null character, which will cause an error and/or be ignored when read via [Reg](https://attack.mitre.org/software/S0075) or other utilities using the Win32 API.(Citation: Microsoft Reghide NOV 2006) Adversaries may abuse these pseudo-hidden keys to conceal payloads/commands used to maintain persistence.(Citation: TrendMicro POWELIKS AUG 2014)(Citation: SpectorOps Hiding Reg Jul 2017)


### T1133 - External Remote Services

Description:

Adversaries may leverage external-facing remote services to initially access and/or persist within a network. Remote services such as VPNs, Citrix, and other access mechanisms allow users to connect to internal enterprise network resources from external locations. There are often remote service gateways that manage connections and credential authentication for these services. Services such as [Windows Remote Management](https://attack.mitre.org/techniques/T1021/006) and [VNC](https://attack.mitre.org/techniques/T1021/005) can also be used externally.(Citation: MacOS VNC software for Remote Desktop)

Access to [Valid Accounts](https://attack.mitre.org/techniques/T1078) to use the service is often a requirement, which could be obtained through credential pharming or by obtaining the credentials from users after compromising the enterprise network.(Citation: Volexity Virtual Private Keylogging) Access to remote services may be used as a redundant or persistent access mechanism during an operation.

Access may also be gained through an exposed service that doesn’t require authentication. In containerized environments, this may include an exposed Docker API, Kubernetes API server, kubelet, or web application such as the Kubernetes dashboard.(Citation: Trend Micro Exposed Docker Server)(Citation: Unit 42 Hildegard Malware)


### T1136 - Create Account

Description:

Adversaries may create an account to maintain access to victim systems.(Citation: Symantec WastedLocker June 2020) With a sufficient level of access, creating such accounts may be used to establish secondary credentialed access that do not require persistent remote access tools to be deployed on the system.

Accounts may be created on the local system or within a domain or cloud tenant. In cloud environments, adversaries may create accounts that only have access to specific services, which can reduce the chance of detection.

#### T1136.001 - Create Account: Local Account

Description:

Adversaries may create a local account to maintain access to victim systems. Local accounts are those configured by an organization for use by users, remote support, services, or for administration on a single system or service. 

For example, with a sufficient level of access, the Windows <code>net user /add</code> command can be used to create a local account.  In Linux, the `useradd` command can be used, while on macOS systems, the <code>dscl -create</code> command can be used. Local accounts may also be added to network devices, often via common [Network Device CLI](https://attack.mitre.org/techniques/T1059/008) commands such as <code>username</code>, to ESXi servers via `esxcli system account add`, or to Kubernetes clusters using the `kubectl` utility.(Citation: cisco_username_cmd)(Citation: Kubernetes Service Accounts Security)

Such accounts may be used to establish secondary credentialed access that do not require persistent remote access tools to be deployed on the system.

#### T1136.002 - Create Account: Domain Account

Description:

Adversaries may create a domain account to maintain access to victim systems. Domain accounts are those managed by Active Directory Domain Services where access and permissions are configured across systems and services that are part of that domain. Domain accounts can cover user, administrator, and service accounts. With a sufficient level of access, the <code>net user /add /domain</code> command can be used to create a domain account.(Citation: Savill 1999)

Such accounts may be used to establish secondary credentialed access that do not require persistent remote access tools to be deployed on the system.

#### T1136.003 - Create Account: Cloud Account

Description:

Adversaries may create a cloud account to maintain access to victim systems. With a sufficient level of access, such accounts may be used to establish secondary credentialed access that does not require persistent remote access tools to be deployed on the system.(Citation: Microsoft O365 Admin Roles)(Citation: Microsoft Support O365 Add Another Admin, October 2019)(Citation: AWS Create IAM User)(Citation: GCP Create Cloud Identity Users)(Citation: Microsoft Azure AD Users)

In addition to user accounts, cloud accounts may be associated with services. Cloud providers handle the concept of service accounts in different ways. In Azure, service accounts include service principals and managed identities, which can be linked to various resources such as OAuth applications, serverless functions, and virtual machines in order to grant those resources permissions to perform various activities in the environment.(Citation: Microsoft Entra ID Service Principals) In GCP, service accounts can also be linked to specific resources, as well as be impersonated by other accounts for [Temporary Elevated Cloud Access](https://attack.mitre.org/techniques/T1548/005).(Citation: GCP Service Accounts) While AWS has no specific concept of service accounts, resources can be directly granted permission to assume roles.(Citation: AWS Instance Profiles)(Citation: AWS Lambda Execution Role)

Adversaries may create accounts that only have access to specific cloud services, which can reduce the chance of detection.

Once an adversary has created a cloud account, they can then manipulate that account to ensure persistence and allow access to additional resources - for example, by adding [Additional Cloud Credentials](https://attack.mitre.org/techniques/T1098/001) or assigning [Additional Cloud Roles](https://attack.mitre.org/techniques/T1098/003).


### T1137 - Office Application Startup

Description:

Adversaries may leverage Microsoft Office-based applications for persistence between startups. Microsoft Office is a fairly common application suite on Windows-based operating systems within an enterprise network. There are multiple mechanisms that can be used with Office for persistence when an Office-based application is started; this can include the use of Office Template Macros and add-ins.

A variety of features have been discovered in Outlook that can be abused to obtain persistence, such as Outlook rules, forms, and Home Page.(Citation: SensePost Ruler GitHub) These persistence mechanisms can work within Outlook or be used through Office 365.(Citation: TechNet O365 Outlook Rules)

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

#### T1137.002 - Office Application Startup: Office Test

Description:

Adversaries may abuse the Microsoft Office "Office Test" Registry key to obtain persistence on a compromised system. An Office Test Registry location exists that allows a user to specify an arbitrary DLL that will be executed every time an Office application is started. This Registry key is thought to be used by Microsoft to load DLLs for testing and debugging purposes while developing Office applications. This Registry key is not created by default during an Office installation.(Citation: Hexacorn Office Test)(Citation: Palo Alto Office Test Sofacy)

There exist user and global Registry keys for the Office Test feature, such as:

* <code>HKEY_CURRENT_USER\Software\Microsoft\Office test\Special\Perf</code>
* <code>HKEY_LOCAL_MACHINE\Software\Microsoft\Office test\Special\Perf</code>

Adversaries may add this Registry key and specify a malicious DLL that will be executed whenever an Office application, such as Word or Excel, is started.

#### T1137.003 - Office Application Startup: Outlook Forms

Description:

Adversaries may abuse Microsoft Outlook forms to obtain persistence on a compromised system. Outlook forms are used as templates for presentation and functionality in Outlook messages. Custom Outlook forms can be created that will execute code when a specifically crafted email is sent by an adversary utilizing the same custom Outlook form.(Citation: SensePost Outlook Forms)

Once malicious forms have been added to the user’s mailbox, they will be loaded when Outlook is started. Malicious forms will execute when an adversary sends a specifically crafted email to the user.(Citation: SensePost Outlook Forms)

#### T1137.004 - Office Application Startup: Outlook Home Page

Description:

Adversaries may abuse Microsoft Outlook's Home Page feature to obtain persistence on a compromised system. Outlook Home Page is a legacy feature used to customize the presentation of Outlook folders. This feature allows for an internal or external URL to be loaded and presented whenever a folder is opened. A malicious HTML page can be crafted that will execute code when loaded by Outlook Home Page.(Citation: SensePost Outlook Home Page)

Once malicious home pages have been added to the user’s mailbox, they will be loaded when Outlook is started. Malicious Home Pages will execute when the right Outlook folder is loaded/reloaded.(Citation: SensePost Outlook Home Page)

#### T1137.005 - Office Application Startup: Outlook Rules

Description:

Adversaries may abuse Microsoft Outlook rules to obtain persistence on a compromised system. Outlook rules allow a user to define automated behavior to manage email messages. A benign rule might, for example, automatically move an email to a particular folder in Outlook if it contains specific words from a specific sender. Malicious Outlook rules can be created that can trigger code execution when an adversary sends a specifically crafted email to that user.(Citation: SilentBreak Outlook Rules)

Once malicious rules have been added to the user’s mailbox, they will be loaded when Outlook is started. Malicious rules will execute when an adversary sends a specifically crafted email to the user.(Citation: SilentBreak Outlook Rules)

#### T1137.006 - Office Application Startup: Add-ins

Description:

Adversaries may abuse Microsoft Office add-ins to obtain persistence on a compromised system. Office add-ins can be used to add functionality to Office programs. (Citation: Microsoft Office Add-ins) There are different types of add-ins that can be used by the various Office products; including Word/Excel add-in Libraries (WLL/XLL), VBA add-ins, Office Component Object Model (COM) add-ins, automation add-ins, VBA Editor (VBE), Visual Studio Tools for Office (VSTO) add-ins, and Outlook add-ins. (Citation: MRWLabs Office Persistence Add-ins)(Citation: FireEye Mail CDS 2018)

Add-ins can be used to obtain persistence because they can be set to execute code when an Office application starts.


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


### T1205 - Traffic Signaling

Description:

Adversaries may use traffic signaling to hide open ports or other malicious functionality used for persistence or command and control. Traffic signaling involves the use of a magic value or sequence that must be sent to a system to trigger a special response, such as opening a closed port or executing a malicious task. This may take the form of sending a series of packets with certain characteristics before a port will be opened that the adversary can use for command and control. Usually this series of packets consists of attempted connections to a predefined sequence of closed ports (i.e. [Port Knocking](https://attack.mitre.org/techniques/T1205/001)), but can involve unusual flags, specific strings, or other unique characteristics. After the sequence is completed, opening a port may be accomplished by the host-based firewall, but could also be implemented by custom software.

Adversaries may also communicate with an already open port, but the service listening on that port will only respond to commands or trigger other malicious functionality if passed the appropriate magic value(s).

The observation of the signal packets to trigger the communication can be conducted through different methods. One means, originally implemented by Cd00r (Citation: Hartrell cd00r 2002), is to use the libpcap libraries to sniff for the packets in question. Another method leverages raw sockets, which enables the malware to use ports that are already open for use by other programs.

On network devices, adversaries may use crafted packets to enable [Network Device Authentication](https://attack.mitre.org/techniques/T1556/004) for standard services offered by the device such as telnet.  Such signaling may also be used to open a closed service port such as telnet, or to trigger module modification of malware implants on the device, adding, removing, or changing malicious capabilities.  Adversaries may use crafted packets to attempt to connect to one or more (open or closed) ports, but may also attempt to connect to a router interface, broadcast, and network address IP on the same port in order to achieve their goals and objectives.(Citation: Cisco Synful Knock Evolution)(Citation: Mandiant - Synful Knock)(Citation: Cisco Blog Legacy Device Attacks)  To enable this traffic signaling on embedded devices, adversaries must first achieve and leverage [Patch System Image](https://attack.mitre.org/techniques/T1601/001) due to the monolithic nature of the architecture.

Adversaries may also use the Wake-on-LAN feature to turn on powered off systems. Wake-on-LAN is a hardware feature that allows a powered down system to be powered on, or woken up, by sending a magic packet to it. Once the system is powered on, it may become a target for lateral movement.(Citation: Bleeping Computer - Ryuk WoL)(Citation: AMD Magic Packet)

#### T1205.001 - Traffic Signaling: Port Knocking

Description:

Adversaries may use port knocking to hide open ports used for persistence or command and control. To enable a port, an adversary sends a series of attempted connections to a predefined sequence of closed ports. After the sequence is completed, opening a port is often accomplished by the host based firewall, but could also be implemented by custom software.

This technique has been observed both for the dynamic opening of a listening port as well as the initiating of a connection to a listening server on a different system.

The observation of the signal packets to trigger the communication can be conducted through different methods. One means, originally implemented by Cd00r (Citation: Hartrell cd00r 2002), is to use the libpcap libraries to sniff for the packets in question. Another method leverages raw sockets, which enables the malware to use ports that are already open for use by other programs.

#### T1205.002 - Traffic Signaling: Socket Filters

Description:

Adversaries may attach filters to a network socket to monitor then activate backdoors used for persistence or command and control. With elevated permissions, adversaries can use features such as the `libpcap` library to open sockets and install filters to allow or disallow certain types of data to come through the socket. The filter may apply to all traffic passing through the specified network interface (or every interface if not specified). When the network interface receives a packet matching the filter criteria, additional actions can be triggered on the host, such as activation of a reverse shell.

To establish a connection, an adversary sends a crafted packet to the targeted host that matches the installed filter criteria.(Citation: haking9 libpcap network sniffing) Adversaries have used these socket filters to trigger the installation of implants, conduct ping backs, and to invoke command shells. Communication with these socket filters may also be used in conjunction with [Protocol Tunneling](https://attack.mitre.org/techniques/T1572).(Citation: exatrack bpf filters passive backdoors)(Citation: Leonardo Turla Penquin May 2020)

Filters can be installed on any Unix-like platform with `libpcap` installed or on Windows hosts using `Winpcap`.  Adversaries may use either `libpcap` with `pcap_setfilter` or the standard library function `setsockopt` with `SO_ATTACH_FILTER` options. Since the socket connection is not active until the packet is received, this behavior may be difficult to detect due to the lack of activity on a host, low CPU overhead, and limited visibility into raw socket usage.


### T1505 - Server Software Component

Description:

Adversaries may abuse legitimate extensible development features of servers to establish persistent access to systems. Enterprise server applications may include features that allow developers to write and install software or scripts to extend the functionality of the main application. Adversaries may install malicious components to extend and abuse server applications.(Citation: volexity_0day_sophos_FW)

#### T1505.001 - Server Software Component: SQL Stored Procedures

Description:

Adversaries may abuse SQL stored procedures to establish persistent access to systems. SQL Stored Procedures are code that can be saved and reused so that database users do not waste time rewriting frequently used SQL queries. Stored procedures can be invoked via SQL statements to the database using the procedure name or via defined events (e.g. when a SQL server application is started/restarted).

Adversaries may craft malicious stored procedures that can provide a persistence mechanism in SQL database servers.(Citation: NetSPI Startup Stored Procedures)(Citation: Kaspersky MSSQL Aug 2019) To execute operating system commands through SQL syntax the adversary may have to enable additional functionality, such as xp_cmdshell for MSSQL Server.(Citation: NetSPI Startup Stored Procedures)(Citation: Kaspersky MSSQL Aug 2019)(Citation: Microsoft xp_cmdshell 2017) 

Microsoft SQL Server can enable common language runtime (CLR) integration. With CLR integration enabled, application developers can write stored procedures using any .NET framework language (e.g. VB .NET, C#, etc.).(Citation: Microsoft CLR Integration 2017) Adversaries may craft or modify CLR assemblies that are linked to stored procedures since these CLR assemblies can be made to execute arbitrary commands.(Citation: NetSPI SQL Server CLR)

#### T1505.002 - Server Software Component: Transport Agent

Description:

Adversaries may abuse Microsoft transport agents to establish persistent access to systems. Microsoft Exchange transport agents can operate on email messages passing through the transport pipeline to perform various tasks such as filtering spam, filtering malicious attachments, journaling, or adding a corporate signature to the end of all outgoing emails.(Citation: Microsoft TransportAgent Jun 2016)(Citation: ESET LightNeuron May 2019) Transport agents can be written by application developers and then compiled to .NET assemblies that are subsequently registered with the Exchange server. Transport agents will be invoked during a specified stage of email processing and carry out developer defined tasks. 

Adversaries may register a malicious transport agent to provide a persistence mechanism in Exchange Server that can be triggered by adversary-specified email events.(Citation: ESET LightNeuron May 2019) Though a malicious transport agent may be invoked for all emails passing through the Exchange transport pipeline, the agent can be configured to only carry out specific tasks in response to adversary defined criteria. For example, the transport agent may only carry out an action like copying in-transit attachments and saving them for later exfiltration if the recipient email address matches an entry on a list provided by the adversary.

#### T1505.003 - Server Software Component: Web Shell

Description:

Adversaries may backdoor web servers with web shells to establish persistent access to systems. A Web shell is a Web script that is placed on an openly accessible Web server to allow an adversary to access the Web server as a gateway into a network. A Web shell may provide a set of functions to execute or a command-line interface on the system that hosts the Web server.(Citation: volexity_0day_sophos_FW)

In addition to a server-side script, a Web shell may have a client interface program that is used to talk to the Web server (e.g. [China Chopper](https://attack.mitre.org/software/S0020) Web shell client).(Citation: Lee 2013)

#### T1505.004 - Server Software Component: IIS Components

Description:

Adversaries may install malicious components that run on Internet Information Services (IIS) web servers to establish persistence. IIS provides several mechanisms to extend the functionality of the web servers. For example, Internet Server Application Programming Interface (ISAPI) extensions and filters can be installed to examine and/or modify incoming and outgoing IIS web requests. Extensions and filters are deployed as DLL files that export three functions: <code>Get{Extension/Filter}Version</code>, <code>Http{Extension/Filter}Proc</code>, and (optionally) <code>Terminate{Extension/Filter}</code>. IIS modules may also be installed to extend IIS web servers.(Citation: Microsoft ISAPI Extension Overview 2017)(Citation: Microsoft ISAPI Filter Overview 2017)(Citation: IIS Backdoor 2011)(Citation: Trustwave IIS Module 2013)

Adversaries may install malicious ISAPI extensions and filters to observe and/or modify traffic, execute commands on compromised machines, or proxy command and control traffic. ISAPI extensions and filters may have access to all IIS web requests and responses. For example, an adversary may abuse these mechanisms to modify HTTP responses in order to distribute malicious commands/content to previously comprised hosts.(Citation: Microsoft ISAPI Filter Overview 2017)(Citation: Microsoft ISAPI Extension Overview 2017)(Citation: Microsoft ISAPI Extension All Incoming 2017)(Citation: Dell TG-3390)(Citation: Trustwave IIS Module 2013)(Citation: MMPC ISAPI Filter 2012)

Adversaries may also install malicious IIS modules to observe and/or modify traffic. IIS 7.0 introduced modules that provide the same unrestricted access to HTTP requests and responses as ISAPI extensions and filters. IIS modules can be written as a DLL that exports <code>RegisterModule</code>, or as a .NET application that interfaces with ASP.NET APIs to access IIS HTTP requests.(Citation: Microsoft IIS Modules Overview 2007)(Citation: Trustwave IIS Module 2013)(Citation: ESET IIS Malware 2021)

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

#### T1542.002 - Pre-OS Boot: Component Firmware

Description:

Adversaries may modify component firmware to persist on systems. Some adversaries may employ sophisticated means to compromise computer components and install malicious firmware that will execute adversary code outside of the operating system and main system firmware or BIOS. This technique may be similar to [System Firmware](https://attack.mitre.org/techniques/T1542/001) but conducted upon other system components/devices that may not have the same capability or level of integrity checking.

Malicious component firmware could provide both a persistent level of access to systems despite potential typical failures to maintain access and hard disk re-images, as well as a way to evade host software-based defenses and integrity checks.

#### T1542.003 - Pre-OS Boot: Bootkit

Description:

Adversaries may use bootkits to persist on systems. A bootkit is a malware variant that modifies the boot sectors of a hard drive, allowing malicious code to execute before a computer's operating system has loaded. Bootkits reside at a layer below the operating system and may make it difficult to perform full remediation unless an organization suspects one was used and can act accordingly.

In BIOS systems, a bootkit may modify the Master Boot Record (MBR) and/or Volume Boot Record (VBR).(Citation: Mandiant M Trends 2016) The MBR is the section of disk that is first loaded after completing hardware initialization by the BIOS. It is the location of the boot loader. An adversary who has raw access to the boot drive may overwrite this area, diverting execution during startup from the normal boot loader to adversary code.(Citation: Lau 2011)

The MBR passes control of the boot process to the VBR. Similar to the case of MBR, an adversary who has raw access to the boot drive may overwrite the VBR to divert execution during startup to adversary code.

In UEFI (Unified Extensible Firmware Interface) systems, a bootkit may instead create or modify files in the EFI system partition (ESP). The ESP is a partition on data storage used by devices containing UEFI that allows the system to boot the OS and other utilities used by the system. An adversary can use the newly created or patched files in the ESP to run malicious kernel code.(Citation: Microsoft Security)(Citation: welivesecurity)

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

#### T1543.001 - Create or Modify System Process: Launch Agent

Description:

Adversaries may create or modify launch agents to repeatedly execute malicious payloads as part of persistence. When a user logs in, a per-user launchd process is started which loads the parameters for each launch-on-demand user agent from the property list (.plist) file found in <code>/System/Library/LaunchAgents</code>, <code>/Library/LaunchAgents</code>, and <code>~/Library/LaunchAgents</code>.(Citation: AppleDocs Launch Agent Daemons)(Citation: OSX Keydnap malware) (Citation: Antiquated Mac Malware) Property list files use the <code>Label</code>, <code>ProgramArguments </code>, and <code>RunAtLoad</code> keys to identify the Launch Agent's name, executable location, and execution time.(Citation: OSX.Dok Malware) Launch Agents are often installed to perform updates to programs, launch user specified programs at login, or to conduct other developer tasks.

 Launch Agents can also be executed using the [Launchctl](https://attack.mitre.org/techniques/T1569/001) command.
 
Adversaries may install a new Launch Agent that executes at login by placing a .plist file into the appropriate folders with the <code>RunAtLoad</code> or <code>KeepAlive</code> keys set to <code>true</code>.(Citation: Sofacy Komplex Trojan)(Citation: Methods of Mac Malware Persistence) The Launch Agent name may be disguised by using a name from the related operating system or benign software. Launch Agents are created with user level privileges and execute with user level permissions.(Citation: OSX Malware Detection)(Citation: OceanLotus for OS X)

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

#### T1543.003 - Create or Modify System Process: Windows Service

Description:

Adversaries may create or modify Windows services to repeatedly execute malicious payloads as part of persistence. When Windows boots up, it starts programs or applications called services that perform background system functions.(Citation: TechNet Services) Windows service configuration information, including the file path to the service's executable or recovery programs/commands, is stored in the Windows Registry.

Adversaries may install a new service or modify an existing service to execute at startup in order to persist on a system. Service configurations can be set or modified using system utilities (such as sc.exe), by directly modifying the Registry, or by interacting directly with the Windows API. 

Adversaries may also use services to install and execute malicious drivers. For example, after dropping a driver file (ex: `.sys`) to disk, the payload can be loaded and registered via [Native API](https://attack.mitre.org/techniques/T1106) functions such as `CreateServiceW()` (or manually via functions such as `ZwLoadDriver()` and `ZwSetValueKey()`), by creating the required service Registry values (i.e. [Modify Registry](https://attack.mitre.org/techniques/T1112)), or by using command-line utilities such as `PnPUtil.exe`.(Citation: Symantec W.32 Stuxnet Dossier)(Citation: Crowdstrike DriveSlayer February 2022)(Citation: Unit42 AcidBox June 2020) Adversaries may leverage these drivers as [Rootkit](https://attack.mitre.org/techniques/T1014)s to hide the presence of malicious activity on a system. Adversaries may also load a signed yet vulnerable driver onto a compromised machine (known as "Bring Your Own Vulnerable Driver" (BYOVD)) as part of [Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1068).(Citation: ESET InvisiMole June 2020)(Citation: Unit42 AcidBox June 2020)

Services may be created with administrator privileges but are executed under SYSTEM privileges, so an adversary may also use a service to escalate privileges. Adversaries may also directly start services through [Service Execution](https://attack.mitre.org/techniques/T1569/002).

To make detection analysis more challenging, malicious services may also incorporate [Masquerade Task or Service](https://attack.mitre.org/techniques/T1036/004) (ex: using a service and/or payload name related to a legitimate OS or benign software component). Adversaries may also create ‘hidden’ services (i.e., [Hide Artifacts](https://attack.mitre.org/techniques/T1564)), for example by using the `sc sdset` command to set service permissions via the Service Descriptor Definition Language (SDDL). This may hide a Windows service from the view of standard service enumeration methods such as `Get-Service`, `sc query`, and `services.exe`.(Citation: SANS 1)(Citation: SANS 2)

#### T1543.004 - Create or Modify System Process: Launch Daemon

Description:

Adversaries may create or modify Launch Daemons to execute malicious payloads as part of persistence. Launch Daemons are plist files used to interact with Launchd, the service management framework used by macOS. Launch Daemons require elevated privileges to install, are executed for every user on a system prior to login, and run in the background without the need for user interaction. During the macOS initialization startup, the launchd process loads the parameters for launch-on-demand system-level daemons from plist files found in <code>/System/Library/LaunchDaemons/</code> and <code>/Library/LaunchDaemons/</code>. Required Launch Daemons parameters include a <code>Label</code> to identify the task, <code>Program</code> to provide a path to the executable, and <code>RunAtLoad</code> to specify when the task is run. Launch Daemons are often used to provide access to shared resources, updates to software, or conduct automation tasks.(Citation: AppleDocs Launch Agent Daemons)(Citation: Methods of Mac Malware Persistence)(Citation: launchd Keywords for plists)

Adversaries may install a Launch Daemon configured to execute at startup by using the <code>RunAtLoad</code> parameter set to <code>true</code> and the <code>Program</code> parameter set to the malicious executable path. The daemon name may be disguised by using a name from a related operating system or benign software (i.e. [Masquerading](https://attack.mitre.org/techniques/T1036)). When the Launch Daemon is executed, the program inherits administrative permissions.(Citation: WireLurker)(Citation: OSX Malware Detection)

Additionally, system configuration changes (such as the installation of third party package managing software) may cause folders such as <code>usr/local/bin</code> to become globally writeable. So, it is possible for poor configurations to allow an adversary to modify executables referenced by current Launch Daemon's plist files.(Citation: LaunchDaemon Hijacking)(Citation: sentinelone macos persist Jun 2019)

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

#### T1546.001 - Event Triggered Execution: Change Default File Association

Description:

Adversaries may establish persistence by executing malicious content triggered by a file type association. When a file is opened, the default program used to open the file (also called the file association or handler) is checked. File association selections are stored in the Windows Registry and can be edited by users, administrators, or programs that have Registry access or by administrators using the built-in assoc utility.(Citation: Microsoft Change Default Programs)(Citation: Microsoft File Handlers)(Citation: Microsoft Assoc Oct 2017) Applications can modify the file association for a given file extension to call an arbitrary program when a file with the given extension is opened.

System file associations are listed under <code>HKEY_CLASSES_ROOT\.[extension]</code>, for example <code>HKEY_CLASSES_ROOT\.txt</code>. The entries point to a handler for that extension located at <code>HKEY_CLASSES_ROOT\\[handler]</code>. The various commands are then listed as subkeys underneath the shell key at <code>HKEY_CLASSES_ROOT\\[handler]\shell\\[action]\command</code>. For example: 

* <code>HKEY_CLASSES_ROOT\txtfile\shell\open\command</code>
* <code>HKEY_CLASSES_ROOT\txtfile\shell\print\command</code>
* <code>HKEY_CLASSES_ROOT\txtfile\shell\printto\command</code>

The values of the keys listed are commands that are executed when the handler opens the file extension. Adversaries can modify these values to continually execute arbitrary commands.(Citation: TrendMicro TROJ-FAKEAV OCT 2012)

#### T1546.002 - Event Triggered Execution: Screensaver

Description:

Adversaries may establish persistence by executing malicious content triggered by user inactivity. Screensavers are programs that execute after a configurable time of user inactivity and consist of Portable Executable (PE) files with a .scr file extension.(Citation: Wikipedia Screensaver) The Windows screensaver application scrnsave.scr is located in <code>C:\Windows\System32\</code>, and <code>C:\Windows\sysWOW64\</code>  on 64-bit Windows systems, along with screensavers included with base Windows installations.

The following screensaver settings are stored in the Registry (<code>HKCU\Control Panel\Desktop\</code>) and could be manipulated to achieve persistence:

* <code>SCRNSAVE.exe</code> - set to malicious PE path
* <code>ScreenSaveActive</code> - set to '1' to enable the screensaver
* <code>ScreenSaverIsSecure</code> - set to '0' to not require a password to unlock
* <code>ScreenSaveTimeout</code> - sets user inactivity timeout before screensaver is executed

Adversaries can use screensaver settings to maintain persistence by setting the screensaver to run malware after a certain timeframe of user inactivity.(Citation: ESET Gazer Aug 2017)

#### T1546.003 - Event Triggered Execution: Windows Management Instrumentation Event Subscription

Description:

Adversaries may establish persistence and elevate privileges by executing malicious content triggered by a Windows Management Instrumentation (WMI) event subscription. WMI can be used to install event filters, providers, consumers, and bindings that execute code when a defined event occurs. Examples of events that may be subscribed to are the wall clock time, user login, or the computer's uptime.(Citation: Mandiant M-Trends 2015)

Adversaries may use the capabilities of WMI to subscribe to an event and execute arbitrary code when that event occurs, providing persistence on a system.(Citation: FireEye WMI SANS 2015)(Citation: FireEye WMI 2015) Adversaries may also compile WMI scripts – using `mofcomp.exe`  –into Windows Management Object (MOF) files (.mof extension) that can be used to create a malicious subscription.(Citation: Dell WMI Persistence)(Citation: Microsoft MOF May 2018)

WMI subscription execution is proxied by the WMI Provider Host process (WmiPrvSe.exe) and thus may result in elevated SYSTEM privileges.

#### T1546.004 - Event Triggered Execution: Unix Shell Configuration Modification

Description:

Adversaries may establish persistence through executing malicious commands triggered by a user’s shell. User [Unix Shell](https://attack.mitre.org/techniques/T1059/004)s execute several configuration scripts at different points throughout the session based on events. For example, when a user opens a command-line interface or remotely logs in (such as via SSH) a login shell is initiated. The login shell executes scripts from the system (<code>/etc</code>) and the user’s home directory (<code>~/</code>) to configure the environment. All login shells on a system use /etc/profile when initiated. These configuration scripts run at the permission level of their directory and are often used to set environment variables, create aliases, and customize the user’s environment. When the shell exits or terminates, additional shell scripts are executed to ensure the shell exits appropriately. 

Adversaries may attempt to establish persistence by inserting commands into scripts automatically executed by shells. Using bash as an example, the default shell for most GNU/Linux systems, adversaries may add commands that launch malicious binaries into the <code>/etc/profile</code> and <code>/etc/profile.d</code> files.(Citation: intezer-kaiji-malware)(Citation: bencane blog bashrc) These files typically require root permissions to modify and are executed each time any shell on a system launches. For user level permissions, adversaries can insert malicious commands into <code>~/.bash_profile</code>, <code>~/.bash_login</code>, or <code>~/.profile</code> which are sourced when a user opens a command-line interface or connects remotely.(Citation: anomali-rocke-tactics)(Citation: Linux manual bash invocation) Since the system only executes the first existing file in the listed order, adversaries have used <code>~/.bash_profile</code> to ensure execution. Adversaries have also leveraged the <code>~/.bashrc</code> file which is additionally executed if the connection is established remotely or an additional interactive shell is opened, such as a new tab in the command-line interface.(Citation: Tsunami)(Citation: anomali-rocke-tactics)(Citation: anomali-linux-rabbit)(Citation: Magento) Some malware targets the termination of a program to trigger execution, adversaries can use the <code>~/.bash_logout</code> file to execute malicious commands at the end of a session. 

For macOS, the functionality of this technique is similar but may leverage zsh, the default shell for macOS 10.15+. When the Terminal.app is opened, the application launches a zsh login shell and a zsh interactive shell. The login shell configures the system environment using <code>/etc/profile</code>, <code>/etc/zshenv</code>, <code>/etc/zprofile</code>, and <code>/etc/zlogin</code>.(Citation: ScriptingOSX zsh)(Citation: PersistentJXA_leopitt)(Citation: code_persistence_zsh)(Citation: macOS MS office sandbox escape) The login shell then configures the user environment with <code>~/.zprofile</code> and <code>~/.zlogin</code>. The interactive shell uses the <code>~/.zshrc</code> to configure the user environment. Upon exiting, <code>/etc/zlogout</code> and <code>~/.zlogout</code> are executed. For legacy programs, macOS executes <code>/etc/bashrc</code> on startup.

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

#### T1546.009 - Event Triggered Execution: AppCert DLLs

Description:

Adversaries may establish persistence and/or elevate privileges by executing malicious content triggered by AppCert DLLs loaded into processes. Dynamic-link libraries (DLLs) that are specified in the <code>AppCertDLLs</code> Registry key under <code>HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\</code> are loaded into every process that calls the ubiquitously used application programming interface (API) functions <code>CreateProcess</code>, <code>CreateProcessAsUser</code>, <code>CreateProcessWithLoginW</code>, <code>CreateProcessWithTokenW</code>, or <code>WinExec</code>. (Citation: Elastic Process Injection July 2017)

Similar to [Process Injection](https://attack.mitre.org/techniques/T1055), this value can be abused to obtain elevated privileges by causing a malicious DLL to be loaded and run in the context of separate processes on the computer. Malicious AppCert DLLs may also provide persistence by continuously being triggered by API activity.

#### T1546.010 - Event Triggered Execution: AppInit DLLs

Description:

Adversaries may establish persistence and/or elevate privileges by executing malicious content triggered by AppInit DLLs loaded into processes. Dynamic-link libraries (DLLs) that are specified in the <code>AppInit_DLLs</code> value in the Registry keys <code>HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Windows</code> or <code>HKEY_LOCAL_MACHINE\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows</code> are loaded by user32.dll into every process that loads user32.dll. In practice this is nearly every program, since user32.dll is a very common library. (Citation: Elastic Process Injection July 2017)

Similar to Process Injection, these values can be abused to obtain elevated privileges by causing a malicious DLL to be loaded and run in the context of separate processes on the computer. (Citation: AppInit Registry) Malicious AppInit DLLs may also provide persistence by continuously being triggered by API activity. 

The AppInit DLL functionality is disabled in Windows 8 and later versions when secure boot is enabled. (Citation: AppInit Secure Boot)

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

#### T1546.012 - Event Triggered Execution: Image File Execution Options Injection

Description:

Adversaries may establish persistence and/or elevate privileges by executing malicious content triggered by Image File Execution Options (IFEO) debuggers. IFEOs enable a developer to attach a debugger to an application. When a process is created, a debugger present in an application’s IFEO will be prepended to the application’s name, effectively launching the new process under the debugger (e.g., <code>C:\dbg\ntsd.exe -g  notepad.exe</code>). (Citation: Microsoft Dev Blog IFEO Mar 2010)

IFEOs can be set directly via the Registry or in Global Flags via the GFlags tool. (Citation: Microsoft GFlags Mar 2017) IFEOs are represented as <code>Debugger</code> values in the Registry under <code>HKLM\SOFTWARE{\Wow6432Node}\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\<executable></code> where <code>&lt;executable&gt;</code> is the binary on which the debugger is attached. (Citation: Microsoft Dev Blog IFEO Mar 2010)

IFEOs can also enable an arbitrary monitor program to be launched when a specified program silently exits (i.e. is prematurely terminated by itself or a second, non kernel-mode process). (Citation: Microsoft Silent Process Exit NOV 2017) (Citation: Oddvar Moe IFEO APR 2018) Similar to debuggers, silent exit monitoring can be enabled through GFlags and/or by directly modifying IFEO and silent process exit Registry values in <code>HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\</code>. (Citation: Microsoft Silent Process Exit NOV 2017) (Citation: Oddvar Moe IFEO APR 2018)

Similar to [Accessibility Features](https://attack.mitre.org/techniques/T1546/008), on Windows Vista and later as well as Windows Server 2008 and later, a Registry key may be modified that configures "cmd.exe," or another program that provides backdoor access, as a "debugger" for an accessibility program (ex: utilman.exe). After the Registry is modified, pressing the appropriate key combination at the login screen while at the keyboard or when connected with [Remote Desktop Protocol](https://attack.mitre.org/techniques/T1021/001) will cause the "debugger" program to be executed with SYSTEM privileges. (Citation: Tilbury 2014)

Similar to [Process Injection](https://attack.mitre.org/techniques/T1055), these values may also be abused to obtain privilege escalation by causing a malicious executable to be loaded and run in the context of separate processes on the computer. (Citation: Elastic Process Injection July 2017) Installing IFEO mechanisms may also provide Persistence via continuous triggered invocation.

Malware may also use IFEO to [Impair Defenses](https://attack.mitre.org/techniques/T1562) by registering invalid debuggers that redirect and effectively disable various system and security applications. (Citation: FSecure Hupigon) (Citation: Symantec Ushedix June 2008)

#### T1546.013 - Event Triggered Execution: PowerShell Profile

Description:

Adversaries may gain persistence and elevate privileges by executing malicious content triggered by PowerShell profiles. A PowerShell profile  (<code>profile.ps1</code>) is a script that runs when [PowerShell](https://attack.mitre.org/techniques/T1059/001) starts and can be used as a logon script to customize user environments.

[PowerShell](https://attack.mitre.org/techniques/T1059/001) supports several profiles depending on the user or host program. For example, there can be different profiles for [PowerShell](https://attack.mitre.org/techniques/T1059/001) host programs such as the PowerShell console, PowerShell ISE or Visual Studio Code. An administrator can also configure a profile that applies to all users and host programs on the local computer. (Citation: Microsoft About Profiles) 

Adversaries may modify these profiles to include arbitrary commands, functions, modules, and/or [PowerShell](https://attack.mitre.org/techniques/T1059/001) drives to gain persistence. Every time a user opens a [PowerShell](https://attack.mitre.org/techniques/T1059/001) session the modified script will be executed unless the <code>-NoProfile</code> flag is used when it is launched. (Citation: ESET Turla PowerShell May 2019) 

An adversary may also be able to escalate privileges if a script in a PowerShell profile is loaded and executed by an account with higher privileges, such as a domain administrator. (Citation: Wits End and Shady PowerShell Profiles)

#### T1546.014 - Event Triggered Execution: Emond

Description:

Adversaries may gain persistence and elevate privileges by executing malicious content triggered by the Event Monitor Daemon (emond). Emond is a [Launch Daemon](https://attack.mitre.org/techniques/T1543/004) that accepts events from various services, runs them through a simple rules engine, and takes action. The emond binary at <code>/sbin/emond</code> will load any rules from the <code>/etc/emond.d/rules/</code> directory and take action once an explicitly defined event takes place.

The rule files are in the plist format and define the name, event type, and action to take. Some examples of event types include system startup and user authentication. Examples of actions are to run a system command or send an email. The emond service will not launch if there is no file present in the QueueDirectories path <code>/private/var/db/emondClients</code>, specified in the [Launch Daemon](https://attack.mitre.org/techniques/T1543/004) configuration file at<code>/System/Library/LaunchDaemons/com.apple.emond.plist</code>.(Citation: xorrior emond Jan 2018)(Citation: magnusviri emond Apr 2016)(Citation: sentinelone macos persist Jun 2019)

Adversaries may abuse this service by writing a rule to execute commands when a defined event occurs, such as system start up or user authentication.(Citation: xorrior emond Jan 2018)(Citation: magnusviri emond Apr 2016)(Citation: sentinelone macos persist Jun 2019) Adversaries may also be able to escalate privileges from administrator to root as the emond service is executed with root privileges by the [Launch Daemon](https://attack.mitre.org/techniques/T1543/004) service.

#### T1546.015 - Event Triggered Execution: Component Object Model Hijacking

Description:

Adversaries may establish persistence by executing malicious content triggered by hijacked references to Component Object Model (COM) objects. COM is a system within Windows to enable interaction between software components through the operating system.(Citation: Microsoft Component Object Model)  References to various COM objects are stored in the Registry. 

Adversaries can use the COM system to insert malicious code that can be executed in place of legitimate software through hijacking the COM references and relationships as a means for persistence. Hijacking a COM object requires a change in the Registry to replace a reference to a legitimate system component which may cause that component to not work when executed. When that system component is executed through normal system operation the adversary's code will be executed instead.(Citation: GDATA COM Hijacking) An adversary is likely to hijack objects that are used frequently enough to maintain a consistent level of persistence, but are unlikely to break noticeable functionality within the system as to avoid system instability that could lead to detection.

#### T1546.016 - Event Triggered Execution: Installer Packages

Description:

Adversaries may establish persistence and elevate privileges by using an installer to trigger the execution of malicious content. Installer packages are OS specific and contain the resources an operating system needs to install applications on a system. Installer packages can include scripts that run prior to installation as well as after installation is complete. Installer scripts may inherit elevated permissions when executed. Developers often use these scripts to prepare the environment for installation, check requirements, download dependencies, and remove files after installation.(Citation: Installer Package Scripting Rich Trouton)

Using legitimate applications, adversaries have distributed applications with modified installer scripts to execute malicious content. When a user installs the application, they may be required to grant administrative permissions to allow the installation. At the end of the installation process of the legitimate application, content such as macOS `postinstall` scripts can be executed with the inherited elevated permissions. Adversaries can use these scripts to execute a malicious executable or install other malicious components (such as a [Launch Daemon](https://attack.mitre.org/techniques/T1543/004)) with the elevated permissions.(Citation: Application Bundle Manipulation Brandon Dalton)(Citation: wardle evilquest parti)(Citation: Windows AppleJeus GReAT)(Citation: Debian Manual Maintainer Scripts)

Depending on the distribution, Linux versions of package installer scripts are sometimes called maintainer scripts or post installation scripts. These scripts can include `preinst`, `postinst`, `prerm`, `postrm` scripts and run as root when executed.

For Windows, the Microsoft Installer services uses `.msi` files to manage the installing, updating, and uninstalling of applications. These installation routines may also include instructions to perform additional actions that may be abused by adversaries.(Citation: Microsoft Installation Procedures)

#### T1546.017 - Event Triggered Execution: Udev Rules

Description:

Adversaries may maintain persistence through executing malicious content triggered using udev rules. Udev is the Linux kernel device manager that dynamically manages device nodes, handles access to pseudo-device files in the `/dev` directory, and responds to hardware events, such as when external devices like hard drives or keyboards are plugged in or removed. Udev uses rule files with `match keys` to specify the conditions a hardware event must meet and `action keys` to define the actions that should follow. Root permissions are required to create, modify, or delete rule files located in `/etc/udev/rules.d/`, `/run/udev/rules.d/`, `/usr/lib/udev/rules.d/`, `/usr/local/lib/udev/rules.d/`, and `/lib/udev/rules.d/`. Rule priority is determined by both directory and by the digit prefix in the rule filename.(Citation: Ignacio Udev research 2024)(Citation: Elastic Linux Persistence 2024)

Adversaries may abuse the udev subsystem by adding or modifying rules in udev rule files to execute malicious content. For example, an adversary may configure a rule to execute their binary each time the pseudo-device file, such as `/dev/random`, is accessed by an application. Although udev is limited to running short tasks and is restricted by systemd-udevd's sandbox (blocking network and filesystem access), attackers may use scripting commands under the action key `RUN+=` to detach and run the malicious content’s process in the background to bypass these controls.(Citation: Reichert aon sedexp 2024)


### T1547 - Boot or Logon Autostart Execution

Description:

Adversaries may configure system settings to automatically execute a program during system boot or logon to maintain persistence or gain higher-level privileges on compromised systems. Operating systems may have mechanisms for automatically running a program on system boot or account logon.(Citation: Microsoft Run Key)(Citation: MSDN Authentication Packages)(Citation: Microsoft TimeProvider)(Citation: Cylance Reg Persistence Sept 2013)(Citation: Linux Kernel Programming) These mechanisms may include automatically executing programs that are placed in specially designated directories or are referenced by repositories that store configuration information, such as the Windows Registry. An adversary may achieve the same goal by modifying or extending features of the kernel.

Since some boot or logon autostart programs run with higher privileges, an adversary may leverage these to elevate privileges.

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

#### T1547.002 - Boot or Logon Autostart Execution: Authentication Package

Description:

Adversaries may abuse authentication packages to execute DLLs when the system boots. Windows authentication package DLLs are loaded by the Local Security Authority (LSA) process at system start. They provide support for multiple logon processes and multiple security protocols to the operating system.(Citation: MSDN Authentication Packages)

Adversaries can use the autostart mechanism provided by LSA authentication packages for persistence by placing a reference to a binary in the Windows Registry location <code>HKLM\SYSTEM\CurrentControlSet\Control\Lsa\</code> with the key value of <code>"Authentication Packages"=&lt;target binary&gt;</code>. The binary will then be executed by the system when the authentication packages are loaded.

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

#### T1547.005 - Boot or Logon Autostart Execution: Security Support Provider

Description:

Adversaries may abuse security support providers (SSPs) to execute DLLs when the system boots. Windows SSP DLLs are loaded into the Local Security Authority (LSA) process at system start. Once loaded into the LSA, SSP DLLs have access to encrypted and plaintext passwords that are stored in Windows, such as any logged-on user's Domain password or smart card PINs.

The SSP configuration is stored in two Registry keys: <code>HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages</code> and <code>HKLM\SYSTEM\CurrentControlSet\Control\Lsa\OSConfig\Security Packages</code>. An adversary may modify these Registry keys to add new SSPs, which will be loaded the next time the system boots, or when the AddSecurityPackage Windows API function is called.(Citation: Graeber 2014)

#### T1547.006 - Boot or Logon Autostart Execution: Kernel Modules and Extensions

Description:

Adversaries may modify the kernel to automatically execute programs on system boot. Loadable Kernel Modules (LKMs) are pieces of code that can be loaded and unloaded into the kernel upon demand. They extend the functionality of the kernel without the need to reboot the system. For example, one type of module is the device driver, which allows the kernel to access hardware connected to the system.(Citation: Linux Kernel Programming) 

When used maliciously, LKMs can be a type of kernel-mode [Rootkit](https://attack.mitre.org/techniques/T1014) that run with the highest operating system privilege (Ring 0).(Citation: Linux Kernel Module Programming Guide) Common features of LKM based rootkits include: hiding itself, selective hiding of files, processes and network activity, as well as log tampering, providing authenticated backdoors, and enabling root access to non-privileged users.(Citation: iDefense Rootkit Overview)

Kernel extensions, also called kext, are used in macOS to load functionality onto a system similar to LKMs for Linux. Since the kernel is responsible for enforcing security and the kernel extensions run as apart of the kernel, kexts are not governed by macOS security policies. Kexts are loaded and unloaded through <code>kextload</code> and <code>kextunload</code> commands. Kexts need to be signed with a developer ID that is granted privileges by Apple allowing it to sign Kernel extensions. Developers without these privileges may still sign kexts but they will not load unless SIP is disabled. If SIP is enabled, the kext signature is verified before being added to the AuxKC.(Citation: System and kernel extensions in macOS)

Since macOS Catalina 10.15, kernel extensions have been deprecated in favor of System Extensions. However, kexts are still allowed as "Legacy System Extensions" since there is no System Extension for Kernel Programming Interfaces.(Citation: Apple Kernel Extension Deprecation)

Adversaries can use LKMs and kexts to conduct [Persistence](https://attack.mitre.org/tactics/TA0003) and/or [Privilege Escalation](https://attack.mitre.org/tactics/TA0004) on a system. Examples have been found in the wild, and there are some relevant open source projects as well.(Citation: Volatility Phalanx2)(Citation: CrowdStrike Linux Rootkit)(Citation: GitHub Reptile)(Citation: GitHub Diamorphine)(Citation: RSAC 2015 San Francisco Patrick Wardle)(Citation: Synack Secure Kernel Extension Broken)(Citation: Securelist Ventir)(Citation: Trend Micro Skidmap)

#### T1547.007 - Boot or Logon Autostart Execution: Re-opened Applications

Description:

Adversaries may modify plist files to automatically run an application when a user logs in. When a user logs out or restarts via the macOS Graphical User Interface (GUI), a prompt is provided to the user with a checkbox to "Reopen windows when logging back in".(Citation: Re-Open windows on Mac) When selected, all applications currently open are added to a property list file named <code>com.apple.loginwindow.[UUID].plist</code> within the <code>~/Library/Preferences/ByHost</code> directory.(Citation: Methods of Mac Malware Persistence)(Citation: Wardle Persistence Chapter) Applications listed in this file are automatically reopened upon the user’s next logon.

Adversaries can establish [Persistence](https://attack.mitre.org/tactics/TA0003) by adding a malicious application path to the <code>com.apple.loginwindow.[UUID].plist</code> file to execute payloads when a user logs in.

#### T1547.008 - Boot or Logon Autostart Execution: LSASS Driver

Description:

Adversaries may modify or add LSASS drivers to obtain persistence on compromised systems. The Windows security subsystem is a set of components that manage and enforce the security policy for a computer or domain. The Local Security Authority (LSA) is the main component responsible for local security policy and user authentication. The LSA includes multiple dynamic link libraries (DLLs) associated with various other security functions, all of which run in the context of the LSA Subsystem Service (LSASS) lsass.exe process.(Citation: Microsoft Security Subsystem)

Adversaries may target LSASS drivers to obtain persistence. By either replacing or adding illegitimate drivers (e.g., [Hijack Execution Flow](https://attack.mitre.org/techniques/T1574)), an adversary can use LSA operations to continuously execute malicious payloads.

#### T1547.009 - Boot or Logon Autostart Execution: Shortcut Modification

Description:

Adversaries may create or modify shortcuts that can execute a program during system boot or user login. Shortcuts or symbolic links are used to reference other files or programs that will be opened or executed when the shortcut is clicked or executed by a system startup process.

Adversaries may abuse shortcuts in the startup folder to execute their tools and achieve persistence.(Citation: Shortcut for Persistence ) Although often used as payloads in an infection chain (e.g. [Spearphishing Attachment](https://attack.mitre.org/techniques/T1566/001)), adversaries may also create a new shortcut as a means of indirection, while also abusing [Masquerading](https://attack.mitre.org/techniques/T1036) to make the malicious shortcut appear as a legitimate program. Adversaries can also edit the target path or entirely replace an existing shortcut so their malware will be executed instead of the intended legitimate program.

Shortcuts can also be abused to establish persistence by implementing other methods. For example, LNK browser extensions may be modified (e.g. [Browser Extensions](https://attack.mitre.org/techniques/T1176/001)) to persistently launch malware.

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

#### T1547.013 - Boot or Logon Autostart Execution: XDG Autostart Entries

Description:

Adversaries may add or modify XDG Autostart Entries to execute malicious programs or commands when a user’s desktop environment is loaded at login. XDG Autostart entries are available for any XDG-compliant Linux system. XDG Autostart entries use Desktop Entry files (`.desktop`) to configure the user’s desktop environment upon user login. These configuration files determine what applications launch upon user login, define associated applications to open specific file types, and define applications used to open removable media.(Citation: Free Desktop Application Autostart Feb 2006)(Citation: Free Desktop Entry Keys)

Adversaries may abuse this feature to establish persistence by adding a path to a malicious binary or command to the `Exec` directive in the `.desktop` configuration file. When the user’s desktop environment is loaded at user login, the `.desktop` files located in the XDG Autostart directories are automatically executed. System-wide Autostart entries are located in the `/etc/xdg/autostart` directory while the user entries are located in the `~/.config/autostart` directory.

Adversaries may combine this technique with [Masquerading](https://attack.mitre.org/techniques/T1036) to blend malicious Autostart entries with legitimate programs.(Citation: Red Canary Netwire Linux 2022)

#### T1547.014 - Boot or Logon Autostart Execution: Active Setup

Description:

Adversaries may achieve persistence by adding a Registry key to the Active Setup of the local machine. Active Setup is a Windows mechanism that is used to execute programs when a user logs in. The value stored in the Registry key will be executed after a user logs into the computer.(Citation: Klein Active Setup 2010) These programs will be executed under the context of the user and will have the account's associated permissions level.

Adversaries may abuse Active Setup by creating a key under <code> HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components\</code> and setting a malicious value for <code>StubPath</code>. This value will serve as the program that will be executed when a user logs into the computer.(Citation: Mandiant Glyer APT 2010)(Citation: Citizenlab Packrat 2015)(Citation: FireEye CFR Watering Hole 2012)(Citation: SECURELIST Bright Star 2015)(Citation: paloalto Tropic Trooper 2016)

Adversaries can abuse these components to execute malware, such as remote access tools, to maintain persistence through system reboots. Adversaries may also use [Masquerading](https://attack.mitre.org/techniques/T1036) to make the Registry entries look as if they are associated with legitimate programs.

#### T1547.015 - Boot or Logon Autostart Execution: Login Items

Description:

Adversaries may add login items to execute upon user login to gain persistence or escalate privileges. Login items are applications, documents, folders, or server connections that are automatically launched when a user logs in.(Citation: Open Login Items Apple) Login items can be added via a shared file list or Service Management Framework.(Citation: Adding Login Items) Shared file list login items can be set using scripting languages such as [AppleScript](https://attack.mitre.org/techniques/T1059/002), whereas the Service Management Framework uses the API call <code>SMLoginItemSetEnabled</code>.

Login items installed using the Service Management Framework leverage <code>launchd</code>, are not visible in the System Preferences, and can only be removed by the application that created them.(Citation: Adding Login Items)(Citation: SMLoginItemSetEnabled Schroeder 2013) Login items created using a shared file list are visible in System Preferences, can hide the application when it launches, and are executed through LaunchServices, not launchd, to open applications, documents, or URLs without using Finder.(Citation: Launch Services Apple Developer) Users and applications use login items to configure their user environment to launch commonly used services or applications, such as email, chat, and music applications.

Adversaries can utilize [AppleScript](https://attack.mitre.org/techniques/T1059/002) and [Native API](https://attack.mitre.org/techniques/T1106) calls to create a login item to spawn malicious executables.(Citation: ELC Running at startup) Prior to version 10.5 on macOS, adversaries can add login items by using [AppleScript](https://attack.mitre.org/techniques/T1059/002) to send an Apple events to the “System Events” process, which has an AppleScript dictionary for manipulating login items.(Citation: Login Items AE) Adversaries can use a command such as <code>tell application “System Events” to make login item at end with properties /path/to/executable</code>.(Citation: Startup Items Eclectic)(Citation: hexed osx.dok analysis 2019)(Citation: Add List Remove Login Items Apple Script) This command adds the path of the malicious executable to the login item file list located in <code>~/Library/Application Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm</code>.(Citation: Startup Items Eclectic) Adversaries can also use login items to launch executables that can be used to control the victim system remotely or as a means to gain privilege escalation by prompting for user credentials.(Citation: objsee mac malware 2017)(Citation: CheckPoint Dok)(Citation: objsee netwire backdoor 2019)


### T1554 - Compromise Host Software Binary

Description:

Adversaries may modify host software binaries to establish persistent access to systems. Software binaries/executables provide a wide range of system commands or services, programs, and libraries. Common software binaries are SSH clients, FTP clients, email clients, web browsers, and many other user or server applications.

Adversaries may establish persistence though modifications to host software binaries. For example, an adversary may replace or otherwise infect a legitimate application binary (or support files) with a backdoor. Since these binaries may be routinely executed by applications or the user, the adversary can leverage this for persistent access to the host. An adversary may also modify a software binary such as an SSH client in order to persistently collect credentials during logins (i.e., [Modify Authentication Process](https://attack.mitre.org/techniques/T1556)).(Citation: Google Cloud Mandiant UNC3886 2024)

An adversary may also modify an existing binary by patching in malicious functionality (e.g., IAT Hooking/Entry point patching)(Citation: Unit42 Banking Trojans Hooking 2022) prior to the binary’s legitimate execution. For example, an adversary may modify the entry point of a binary to point to malicious code patched in by the adversary before resuming normal execution flow.(Citation: ESET FontOnLake Analysis 2021)

After modifying a binary, an adversary may attempt to [Impair Defenses](https://attack.mitre.org/techniques/T1562) by preventing it from updating (e.g., via the `yum-versionlock` command or `versionlock.list` file in Linux systems that use the yum package manager).(Citation: Google Cloud Mandiant UNC3886 2024)


### T1556 - Modify Authentication Process

Description:

Adversaries may modify authentication mechanisms and processes to access user credentials or enable otherwise unwarranted access to accounts. The authentication process is handled by mechanisms, such as the Local Security Authentication Server (LSASS) process and the Security Accounts Manager (SAM) on Windows, pluggable authentication modules (PAM) on Unix-based systems, and authorization plugins on MacOS systems, responsible for gathering, storing, and validating credentials. By modifying an authentication process, an adversary may be able to authenticate to a service or system without using [Valid Accounts](https://attack.mitre.org/techniques/T1078).

Adversaries may maliciously modify a part of this process to either reveal credentials or bypass authentication mechanisms. Compromised credentials or access may be used to bypass access controls placed on various resources on systems within the network and may even be used for persistent access to remote systems and externally available services, such as VPNs, Outlook Web Access and remote desktop.

#### T1556.001 - Modify Authentication Process: Domain Controller Authentication

Description:

Adversaries may patch the authentication process on a domain controller to bypass the typical authentication mechanisms and enable access to accounts. 

Malware may be used to inject false credentials into the authentication process on a domain controller with the intent of creating a backdoor used to access any user’s account and/or credentials (ex: [Skeleton Key](https://attack.mitre.org/software/S0007)). Skeleton key works through a patch on an enterprise domain controller authentication process (LSASS) with credentials that adversaries may use to bypass the standard authentication system. Once patched, an adversary can use the injected password to successfully authenticate as any domain user account (until the the skeleton key is erased from memory by a reboot of the domain controller). Authenticated access may enable unfettered access to hosts and/or resources within single-factor authentication environments.(Citation: Dell Skeleton)

#### T1556.002 - Modify Authentication Process: Password Filter DLL

Description:

Adversaries may register malicious password filter dynamic link libraries (DLLs) into the authentication process to acquire user credentials as they are validated. 

Windows password filters are password policy enforcement mechanisms for both domain and local accounts. Filters are implemented as DLLs containing a method to validate potential passwords against password policies. Filter DLLs can be positioned on local computers for local accounts and/or domain controllers for domain accounts. Before registering new passwords in the Security Accounts Manager (SAM), the Local Security Authority (LSA) requests validation from each registered filter. Any potential changes cannot take effect until every registered filter acknowledges validation. 

Adversaries can register malicious password filters to harvest credentials from local computers and/or entire domains. To perform proper validation, filters must receive plain-text credentials from the LSA. A malicious password filter would receive these plain-text credentials every time a password request is made.(Citation: Carnal Ownage Password Filters Sept 2013)

#### T1556.003 - Modify Authentication Process: Pluggable Authentication Modules

Description:

Adversaries may modify pluggable authentication modules (PAM) to access user credentials or enable otherwise unwarranted access to accounts. PAM is a modular system of configuration files, libraries, and executable files which guide authentication for many services. The most common authentication module is <code>pam_unix.so</code>, which retrieves, sets, and verifies account authentication information in <code>/etc/passwd</code> and <code>/etc/shadow</code>.(Citation: Apple PAM)(Citation: Man Pam_Unix)(Citation: Red Hat PAM)

Adversaries may modify components of the PAM system to create backdoors. PAM components, such as <code>pam_unix.so</code>, can be patched to accept arbitrary adversary supplied values as legitimate credentials.(Citation: PAM Backdoor)

Malicious modifications to the PAM system may also be abused to steal credentials. Adversaries may infect PAM resources with code to harvest user credentials, since the values exchanged with PAM components may be plain-text since PAM does not store passwords.(Citation: PAM Creds)(Citation: Apple PAM)

#### T1556.004 - Modify Authentication Process: Network Device Authentication

Description:

Adversaries may use [Patch System Image](https://attack.mitre.org/techniques/T1601/001) to hard code a password in the operating system, thus bypassing of native authentication mechanisms for local accounts on network devices.

[Modify System Image](https://attack.mitre.org/techniques/T1601) may include implanted code to the operating system for network devices to provide access for adversaries using a specific password.  The modification includes a specific password which is implanted in the operating system image via the patch.  Upon authentication attempts, the inserted code will first check to see if the user input is the password. If so, access is granted. Otherwise, the implanted code will pass the credentials on for verification of potentially valid credentials.(Citation: Mandiant - Synful Knock)

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


### T1574 - Hijack Execution Flow

Description:

Adversaries may execute their own malicious payloads by hijacking the way operating systems run programs. Hijacking execution flow can be for the purposes of persistence, since this hijacked execution may reoccur over time. Adversaries may also use these mechanisms to elevate privileges or evade defenses, such as application control or other restrictions on execution.

There are many ways an adversary may hijack the flow of execution, including by manipulating how the operating system locates programs to be executed. How the operating system locates libraries to be used by a program can also be intercepted. Locations where the operating system looks for programs/resources, such as file directories and in the case of Windows the Registry, could also be poisoned to include malicious payloads.

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

#### T1574.004 - Hijack Execution Flow: Dylib Hijacking

Description:

Adversaries may execute their own payloads by placing a malicious dynamic library (dylib) with an expected name in a path a victim application searches at runtime. The dynamic loader will try to find the dylibs based on the sequential order of the search paths. Paths to dylibs may be prefixed with <code>@rpath</code>, which allows developers to use relative paths to specify an array of search paths used at runtime based on the location of the executable.  Additionally, if weak linking is used, such as the <code>LC_LOAD_WEAK_DYLIB</code> function, an application will still execute even if an expected dylib is not present. Weak linking enables developers to run an application on multiple macOS versions as new APIs are added.

Adversaries may gain execution by inserting malicious dylibs with the name of the missing dylib in the identified path.(Citation: Wardle Dylib Hijack Vulnerable Apps)(Citation: Wardle Dylib Hijacking OSX 2015)(Citation: Github EmpireProject HijackScanner)(Citation: Github EmpireProject CreateHijacker Dylib) Dylibs are loaded into an application's address space allowing the malicious dylib to inherit the application's privilege level and resources. Based on the application, this could result in privilege escalation and uninhibited network access. This method may also evade detection from security products since the execution is masked under a legitimate process.(Citation: Writing Bad Malware for OSX)(Citation: wardle artofmalware volume1)(Citation: MalwareUnicorn macOS Dylib Injection MachO)

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

#### T1574.007 - Hijack Execution Flow: Path Interception by PATH Environment Variable

Description:

Adversaries may execute their own malicious payloads by hijacking environment variables used to load libraries. The PATH environment variable contains a list of directories (User and System) that the OS searches sequentially through in search of the binary that was called from a script or the command line. 

Adversaries can place a malicious program in an earlier entry in the list of directories stored in the PATH environment variable, resulting in the operating system executing the malicious binary rather than the legitimate binary when it searches sequentially through that PATH listing.

For example, on Windows if an adversary places a malicious program named "net.exe" in `C:\example path`, which by default precedes `C:\Windows\system32\net.exe` in the PATH environment variable, when "net" is executed from the command-line the `C:\example path` will be called instead of the system's legitimate executable at `C:\Windows\system32\net.exe`. Some methods of executing a program rely on the PATH environment variable to determine the locations that are searched when the path for the program is not given, such as executing programs from a [Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059).(Citation: ExpressVPN PATH env Windows 2021)

Adversaries may also directly modify the $PATH variable specifying the directories to be searched.  An adversary can modify the `$PATH` variable to point to a directory they have write access. When a program using the $PATH variable is called, the OS searches the specified directory and executes the malicious binary. On macOS, this can also be performed through modifying the $HOME variable. These variables can be modified using the command-line, launchctl, [Unix Shell Configuration Modification](https://attack.mitre.org/techniques/T1546/004), or modifying the `/etc/paths.d` folder contents.(Citation: uptycs Fake POC linux malware 2023)(Citation: nixCraft macOS PATH variables)(Citation: Elastic Rules macOS launchctl 2022)

#### T1574.008 - Hijack Execution Flow: Path Interception by Search Order Hijacking

Description:

Adversaries may execute their own malicious payloads by hijacking the search order used to load other programs. Because some programs do not call other programs using the full path, adversaries may place their own file in the directory where the calling program is located, causing the operating system to launch their malicious software at the request of the calling program.

Search order hijacking occurs when an adversary abuses the order in which Windows searches for programs that are not given a path. Unlike [DLL](https://attack.mitre.org/techniques/T1574/001) search order hijacking, the search order differs depending on the method that is used to execute the program. (Citation: Microsoft CreateProcess) (Citation: Windows NT Command Shell) (Citation: Microsoft WinExec) However, it is common for Windows to search in the directory of the initiating program before searching through the Windows system directory. An adversary who finds a program vulnerable to search order hijacking (i.e., a program that does not specify the path to an executable) may take advantage of this vulnerability by creating a program named after the improperly specified program and placing it within the initiating program's directory.

For example, "example.exe" runs "cmd.exe" with the command-line argument <code>net user</code>. An adversary may place a program called "net.exe" within the same directory as example.exe, "net.exe" will be run instead of the Windows system utility net. In addition, if an adversary places a program called "net.com" in the same directory as "net.exe", then <code>cmd.exe /C net user</code> will execute "net.com" instead of "net.exe" due to the order of executable extensions defined under PATHEXT. (Citation: Microsoft Environment Property)

Search order hijacking is also a common practice for hijacking DLL loads and is covered in [DLL](https://attack.mitre.org/techniques/T1574/001).

#### T1574.009 - Hijack Execution Flow: Path Interception by Unquoted Path

Description:

Adversaries may execute their own malicious payloads by hijacking vulnerable file path references. Adversaries can take advantage of paths that lack surrounding quotations by placing an executable in a higher level directory within the path, so that Windows will choose the adversary's executable to launch.

Service paths (Citation: Microsoft CurrentControlSet Services) and shortcut paths may also be vulnerable to path interception if the path has one or more spaces and is not surrounded by quotation marks (e.g., <code>C:\unsafe path with space\program.exe</code> vs. <code>"C:\safe path with space\program.exe"</code>). (Citation: Help eliminate unquoted path) (stored in Windows Registry keys) An adversary can place an executable in a higher level directory of the path, and Windows will resolve that executable instead of the intended executable. For example, if the path in a shortcut is <code>C:\program files\myapp.exe</code>, an adversary may create a program at <code>C:\program.exe</code> that will be run instead of the intended program. (Citation: Windows Unquoted Services) (Citation: Windows Privilege Escalation Guide)

This technique can be used for persistence if executables are called on a regular basis, as well as privilege escalation if intercepted executables are started by a higher privileged process.

#### T1574.010 - Hijack Execution Flow: Services File Permissions Weakness

Description:

Adversaries may execute their own malicious payloads by hijacking the binaries used by services. Adversaries may use flaws in the permissions of Windows services to replace the binary that is executed upon service start. These service processes may automatically execute specific binaries as part of their functionality or to perform other actions. If the permissions on the file system directory containing a target binary, or permissions on the binary itself are improperly set, then the target binary may be overwritten with another binary using user-level permissions and executed by the original process. If the original process and thread are running under a higher permissions level, then the replaced binary will also execute under higher-level permissions, which could include SYSTEM.

Adversaries may use this technique to replace legitimate binaries with malicious ones as a means of executing code at a higher permissions level. If the executing process is set to run at a specific time or during a certain event (e.g., system bootup) then this technique can also be used for persistence.

#### T1574.011 - Hijack Execution Flow: Services Registry Permissions Weakness

Description:

Adversaries may execute their own malicious payloads by hijacking the Registry entries used by services. Adversaries may use flaws in the permissions for Registry keys related to services to redirect from the originally specified executable to one that they control, in order to launch their own code when a service starts. Windows stores local service configuration information in the Registry under <code>HKLM\SYSTEM\CurrentControlSet\Services</code>. The information stored under a service's Registry keys can be manipulated to modify a service's execution parameters through tools such as the service controller, sc.exe,  [PowerShell](https://attack.mitre.org/techniques/T1059/001), or [Reg](https://attack.mitre.org/software/S0075). Access to Registry keys is controlled through access control lists and user permissions. (Citation: Registry Key Security)(Citation: malware_hides_service)

If the permissions for users and groups are not properly set and allow access to the Registry keys for a service, adversaries may change the service's binPath/ImagePath to point to a different executable under their control. When the service starts or is restarted, then the adversary-controlled program will execute, allowing the adversary to establish persistence and/or privilege escalation to the account context the service is set to execute under (local/domain account, SYSTEM, LocalService, or NetworkService).

Adversaries may also alter other Registry keys in the service’s Registry tree. For example, the <code>FailureCommand</code> key may be changed so that the service is executed in an elevated context anytime the service fails or is intentionally corrupted.(Citation: Kansa Service related collectors)(Citation: Tweet Registry Perms Weakness)

The <code>Performance</code> key contains the name of a driver service's performance DLL and the names of several exported functions in the DLL.(Citation: microsoft_services_registry_tree) If the <code>Performance</code> key is not already present and if an adversary-controlled user has the <code>Create Subkey</code> permission, adversaries may create the <code>Performance</code> key in the service’s Registry tree to point to a malicious DLL.(Citation: insecure_reg_perms)

Adversaries may also add the <code>Parameters</code> key, which stores driver-specific data, or other custom subkeys for their malicious services to establish persistence or enable other malicious activities.(Citation: microsoft_services_registry_tree)(Citation: troj_zegost) Additionally, If adversaries launch their malicious services using svchost.exe, the service’s file may be identified using <code>HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\servicename\Parameters\ServiceDll</code>.(Citation: malware_hides_service)

#### T1574.012 - Hijack Execution Flow: COR_PROFILER

Description:

Adversaries may leverage the COR_PROFILER environment variable to hijack the execution flow of programs that load the .NET CLR. The COR_PROFILER is a .NET Framework feature which allows developers to specify an unmanaged (or external of .NET) profiling DLL to be loaded into each .NET process that loads the Common Language Runtime (CLR). These profilers are designed to monitor, troubleshoot, and debug managed code executed by the .NET CLR.(Citation: Microsoft Profiling Mar 2017)(Citation: Microsoft COR_PROFILER Feb 2013)

The COR_PROFILER environment variable can be set at various scopes (system, user, or process) resulting in different levels of influence. System and user-wide environment variable scopes are specified in the Registry, where a [Component Object Model](https://attack.mitre.org/techniques/T1559/001) (COM) object can be registered as a profiler DLL. A process scope COR_PROFILER can also be created in-memory without modifying the Registry. Starting with .NET Framework 4, the profiling DLL does not need to be registered as long as the location of the DLL is specified in the COR_PROFILER_PATH environment variable.(Citation: Microsoft COR_PROFILER Feb 2013)

Adversaries may abuse COR_PROFILER to establish persistence that executes a malicious DLL in the context of all .NET processes every time the CLR is invoked. The COR_PROFILER can also be used to elevate privileges (ex: [Bypass User Account Control](https://attack.mitre.org/techniques/T1548/002)) if the victim .NET process executes at a higher permission level, as well as to hook and [Impair Defenses](https://attack.mitre.org/techniques/T1562) provided by .NET processes.(Citation: RedCanary Mockingbird May 2020)(Citation: Red Canary COR_PROFILER May 2020)(Citation: Almond COR_PROFILER Apr 2019)(Citation: GitHub OmerYa Invisi-Shell)(Citation: subTee .NET Profilers May 2017)

#### T1574.013 - Hijack Execution Flow: KernelCallbackTable

Description:

Adversaries may abuse the <code>KernelCallbackTable</code> of a process to hijack its execution flow in order to run their own payloads.(Citation: Lazarus APT January 2022)(Citation: FinFisher exposed ) The <code>KernelCallbackTable</code> can be found in the Process Environment Block (PEB) and is initialized to an array of graphic functions available to a GUI process once <code>user32.dll</code> is loaded.(Citation: Windows Process Injection KernelCallbackTable)

An adversary may hijack the execution flow of a process using the <code>KernelCallbackTable</code> by replacing an original callback function with a malicious payload. Modifying callback functions can be achieved in various ways involving related behaviors such as [Reflective Code Loading](https://attack.mitre.org/techniques/T1620) or [Process Injection](https://attack.mitre.org/techniques/T1055) into another process.

A pointer to the memory address of the <code>KernelCallbackTable</code> can be obtained by locating the PEB (ex: via a call to the <code>NtQueryInformationProcess()</code> [Native API](https://attack.mitre.org/techniques/T1106) function).(Citation: NtQueryInformationProcess) Once the pointer is located, the <code>KernelCallbackTable</code> can be duplicated, and a function in the table (e.g., <code>fnCOPYDATA</code>) set to the address of a malicious payload (ex: via <code>WriteProcessMemory()</code>). The PEB is then updated with the new address of the table. Once the tampered function is invoked, the malicious payload will be triggered.(Citation: Lazarus APT January 2022)

The tampered function is typically invoked using a Windows message. After the process is hijacked and malicious code is executed, the <code>KernelCallbackTable</code> may also be restored to its original state by the rest of the malicious payload.(Citation: Lazarus APT January 2022) Use of the <code>KernelCallbackTable</code> to hijack execution flow may evade detection from security products since the execution can be masked under a legitimate process.

#### T1574.014 - Hijack Execution Flow: AppDomainManager

Description:

Adversaries may execute their own malicious payloads by hijacking how the .NET `AppDomainManager` loads assemblies. The .NET framework uses the `AppDomainManager` class to create and manage one or more isolated runtime environments (called application domains) inside a process to host the execution of .NET applications. Assemblies (`.exe` or `.dll` binaries compiled to run as .NET code) may be loaded into an application domain as executable code.(Citation: Microsoft App Domains) 

Known as "AppDomainManager injection," adversaries may execute arbitrary code by hijacking how .NET applications load assemblies. For example, malware may create a custom application domain inside a target process to load and execute an arbitrary assembly. Alternatively, configuration files (`.config`) or process environment variables that define .NET runtime settings may be tampered with to instruct otherwise benign .NET applications to load a malicious assembly (identified by name) into the target process.(Citation: PenTestLabs AppDomainManagerInject)(Citation: PwC Yellow Liderc)(Citation: Rapid7 AppDomain Manager Injection)


### T1653 - Power Settings

Description:

Adversaries may impair a system's ability to hibernate, reboot, or shut down in order to extend access to infected machines. When a computer enters a dormant state, some or all software and hardware may cease to operate which can disrupt malicious activity.(Citation: Sleep, shut down, hibernate)

Adversaries may abuse system utilities and configuration settings to maintain access by preventing machines from entering a state, such as standby, that can terminate malicious activity.(Citation: Microsoft: Powercfg command-line options)(Citation: systemdsleep Linux)

For example, `powercfg` controls all configurable power system settings on a Windows system and can be abused to prevent an infected host from locking or shutting down.(Citation: Two New Monero Malware Attacks Target Windows and Android Users) Adversaries may also extend system lock screen timeout settings.(Citation: BATLOADER: The Evasive Downloader Malware) Other relevant settings, such as disk and hibernate timeout, can be similarly abused to keep the infected machine running even if no user is active.(Citation: CoinLoader: A Sophisticated Malware Loader Campaign)

Aware that some malware cannot survive system reboots, adversaries may entirely delete files used to invoke system shut down or reboot.(Citation: Condi-Botnet-binaries)


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

