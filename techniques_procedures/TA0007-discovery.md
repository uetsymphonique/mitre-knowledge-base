### T1007 - System Service Discovery

Description:

Adversaries may try to gather information about registered local system services. Adversaries may obtain information about services using tools as well as OS utility commands such as sc query, tasklist /svc, systemctl --type=service, and net start. Adversaries may use the information from System Service Discovery during automated discovery to shape follow-on behaviors, including whether or not the adversary fully infects the target and/or attempts specific actions.

Procedures:

- [S0386] Ursnif: Ursnif has gathered information about running services.
- [G0060] BRONZE BUTLER: BRONZE BUTLER has used TROJ_GETVERSION to discover system services.
- [S0018] Sykipot: Sykipot may use net start to display running services.


### T1010 - Application Window Discovery

Description:

Adversaries may attempt to get a listing of open application windows. Window listings could convey information about how the system is used. For example, information about application windows could be used identify potential data to collect as well as identifying security tooling (Security Software Discovery) to evade. Adversaries typically abuse system features for this type of enumeration. For example, they may gather information through native system features such as Command and Scripting Interpreter commands and Native API functions.

Procedures:

- [S0438] Attor: Attor can obtain application window titles and then determines which windows to perform Screen Capture on.
- [S0033] NetTraveler: NetTraveler reports window names along with keylogger information to provide application context.
- [S0454] Cadelspy: Cadelspy has the ability to identify open windows on the compromised host.


### T1012 - Query Registry

Description:

Adversaries may interact with the Windows Registry to gather information about the system, configuration, and installed software. The Registry contains a significant amount of information about the operating system, configuration, software, and security. Information can easily be queried using the Reg utility, though other means to access the Registry exist. Some of the information may help adversaries to further their operation within a network. Adversaries may use the information from Query Registry during automated discovery to shape follow-on behaviors, including whether or not the adversary fully infects the target and/or attempts specific actions.

Procedures:

- [C0014] Operation Wocao: During Operation Wocao, the threat actors executed `/c cd /d c:\windows\temp\ & reg query HKEY_CURRENT_USER\Software\\PuTTY\Sessions\` to detect recent PuTTY sessions, likely to further lateral movement.
- [S0091] Epic: Epic uses the rem reg query command to obtain values from Registry keys.
- [S1159] DUSTTRAP: DUSTTRAP can enumerate Registry items.


### T1016.001 - System Network Configuration Discovery: Internet Connection Discovery

Description:

Adversaries may check for Internet connectivity on compromised systems. This may be performed during automated discovery and can be accomplished in numerous ways such as using Ping, tracert, and GET requests to websites. Adversaries may use the results and responses from these requests to determine if the system is capable of communicating with their C2 servers before attempting to connect to them. The results may also be used to identify routes, redirectors, and proxy servers.

Procedures:

- [S0597] GoldFinder: GoldFinder performed HTTP GET requests to check internet connectivity and identify HTTP proxy servers and other redirectors that an HTTP request traveled through.
- [S0284] More_eggs: More_eggs has used HTTP GET requests to check internet connectivity.
- [S0691] Neoichor: Neoichor can check for Internet connectivity by contacting bing[.]com with the request format `bing[.]com?id=`.

### T1016.002 - System Network Configuration Discovery: Wi-Fi Discovery

Description:

Adversaries may search for information about Wi-Fi networks, such as network names and passwords, on compromised systems. Adversaries may use Wi-Fi information as part of Account Discovery, Remote System Discovery, and other discovery or Credential Access activity to support both ongoing and future campaigns. Adversaries may collect various types of information about Wi-Fi networks from hosts. For example, on Windows names and passwords of all Wi-Fi networks a device has previously connected to may be available through `netsh wlan show profiles` to enumerate Wi-Fi names and then `netsh wlan show profile “Wi-Fi name” key=clear` to show a Wi-Fi network’s corresponding password. Additionally, names and other details of locally reachable Wi-Fi networks can be discovered using calls to `wlanAPI.dll` Native API functions. On Linux, names and passwords of all Wi-Fi-networks a device has previously connected to may be available in files under ` /etc/NetworkManager/system-connections/`. On macOS, the password of a known Wi-Fi may be identified with ` security find-generic-password -wa wifiname` (requires admin username/password).

Procedures:

- [G0059] Magic Hound: Magic Hound has collected names and passwords of all Wi-Fi networks to which a device has previously connected.
- [C0051] APT28 Nearest Neighbor Campaign: During APT28 Nearest Neighbor Campaign, APT28 collected information on wireless interfaces within range of a compromised system.
- [S0331] Agent Tesla: Agent Tesla can collect names and passwords of all Wi-Fi networks to which a device has previously connected.


### T1018 - Remote System Discovery

Description:

Adversaries may attempt to get a listing of other systems by IP address, hostname, or other logical identifier on a network that may be used for Lateral Movement from the current system. Functionality could exist within remote access tools to enable this, but utilities available on the operating system could also be used such as Ping, net view using Net, or, on ESXi servers, `esxcli network diag ping`. Adversaries may also analyze data from local host files (ex: C:\Windows\System32\Drivers\etc\hosts or /etc/hosts) or other passive means (such as local Arp cache entries) in order to discover the presence of remote systems in an environment. Adversaries may also target discovery of network infrastructure as well as leverage Network Device CLI commands on network devices to gather detailed information about systems within a network (e.g. show cdp neighbors, show arp).

Procedures:

- [G1003] Ember Bear: Ember Bear has used tools such as Nmap and MASSCAN for remote service discovery.
- [G0045] menuPass: menuPass uses scripts to enumerate IP ranges on the victim network. menuPass has also issued the command net view /domain to a PlugX implant to gather information about remote systems on the network.
- [S0233] MURKYTOP: MURKYTOP has the capability to identify remote hosts on connected networks.


### T1033 - System Owner/User Discovery

Description:

Adversaries may attempt to identify the primary user, currently logged in user, set of users that commonly uses a system, or whether a user is actively using the system. They may do this, for example, by retrieving account usernames or by using OS Credential Dumping. The information may be collected in a number of different ways using other Discovery techniques, because user and username details are prevalent throughout a system and include running process ownership, file/directory ownership, session information, and system logs. Adversaries may use the information from System Owner/User Discovery during automated discovery to shape follow-on behaviors, including whether or not the adversary fully infects the target and/or attempts specific actions. Various utilities and commands may acquire this information, including whoami. In macOS and Linux, the currently logged in user can be identified with w and who. On macOS the dscl . list /Users | grep -v '_' command can also be used to enumerate user accounts. Environment variables, such as %USERNAME% and $USER, may also be used to access this information. On network devices, Network Device CLI commands such as `show users` and `show ssh` can be used to display users currently logged into the device.

Procedures:

- [S0094] Trojan.Karagany: Trojan.Karagany can gather information about the user on a compromised host.
- [S0428] PoetRAT: PoetRAT sent username, computer name, and the previously generated UUID in reply to a "who" command from C2.
- [S0379] Revenge RAT: Revenge RAT gathers the username from the system.


### T1040 - Network Sniffing

Description:

Adversaries may passively sniff network traffic to capture information about an environment, including authentication material passed over the network. Network sniffing refers to using the network interface on a system to monitor or capture information sent over a wired or wireless connection. An adversary may place a network interface into promiscuous mode to passively access data in transit over the network, or use span ports to capture a larger amount of data. Data captured via this technique may include user credentials, especially those sent over an insecure, unencrypted protocol. Techniques for name service resolution poisoning, such as LLMNR/NBT-NS Poisoning and SMB Relay, can also be used to capture credentials to websites, proxies, and internal systems by redirecting traffic to an adversary. Network sniffing may reveal configuration details, such as running services, version numbers, and other network characteristics (e.g. IP addresses, hostnames, VLAN IDs) necessary for subsequent Lateral Movement and/or Defense Evasion activities. Adversaries may likely also utilize network sniffing during Adversary-in-the-Middle (AiTM) to passively gain additional knowledge about the environment. In cloud-based environments, adversaries may still be able to use traffic mirroring services to sniff network traffic from virtual machines. For example, AWS Traffic Mirroring, GCP Packet Mirroring, and Azure vTap allow users to define specified instances to collect traffic from and specified targets to send collected traffic to. Often, much of this traffic will be in cleartext due to the use of TLS termination at the load balancer level to reduce the strain of encrypting and decrypting traffic. The adversary can then use exfiltration techniques such as Transfer Data to Cloud Account in order to access the sniffed traffic. On network devices, adversaries may perform network captures using Network Device CLI commands such as `monitor capture`.

Procedures:

- [G0034] Sandworm Team: Sandworm Team has used intercepter-NG to sniff passwords in network traffic.
- [G0094] Kimsuky: Kimsuky has used the Nirsoft SniffPass network sniffer to obtain passwords sent over non-secure protocols.
- [S0357] Impacket: Impacket can be used to sniff network traffic via an interface or raw socket.


### T1046 - Network Service Discovery

Description:

Adversaries may attempt to get a listing of services running on remote hosts and local network infrastructure devices, including those that may be vulnerable to remote software exploitation. Common methods to acquire this information include port, vulnerability, and/or wordlist scans using tools that are brought onto a system. Within cloud environments, adversaries may attempt to discover services running on other cloud hosts. Additionally, if the cloud environment is connected to a on-premises environment, adversaries may be able to identify services running on non-cloud systems as well. Within macOS environments, adversaries may use the native Bonjour application to discover services running on other macOS hosts within a network. The Bonjour mDNSResponder daemon automatically registers and advertises a host’s registered services on the network. For example, adversaries can use a mDNS query (such as dns-sd -B _ssh._tcp .) to find other systems broadcasting the ssh service.

Procedures:

- [S0192] Pupy: Pupy has a built-in module for port scanning.
- [G1017] Volt Typhoon: Volt Typhoon has used commercial tools, LOTL utilities, and appliances already present on the system for network service discovery.
- [G0087] APT39: APT39 has used CrackMapExec and a custom port scanner known as BLUETORCH for network scanning.


### T1049 - System Network Connections Discovery

Description:

Adversaries may attempt to get a listing of network connections to or from the compromised system they are currently accessing or from remote systems by querying for information over the network. An adversary who gains access to a system that is part of a cloud-based environment may map out Virtual Private Clouds or Virtual Networks in order to determine what systems and services are connected. The actions performed are likely the same types of discovery techniques depending on the operating system, but the resulting information may include details about the networked cloud environment relevant to the adversary's goals. Cloud providers may have different ways in which their virtual networks operate. Similarly, adversaries who gain access to network devices may also perform similar discovery activities to gather information about connected systems and services. Utilities and commands that acquire this information include netstat, "net use," and "net session" with Net. In Mac and Linux, netstat and lsof can be used to list current connections. who -a and w can be used to show which users are currently logged in, similar to "net session". Additionally, built-in features native to network devices and Network Device CLI may be used (e.g. show ip sockets, show tcp brief). On ESXi servers, the command `esxi network ip connection list` can be used to list active network connections.

Procedures:

- [S0532] Lucifer: Lucifer can identify the IP and port numbers for all remote connections from the compromised host.
- [S0094] Trojan.Karagany: Trojan.Karagany can use netstat to collect a list of network connections.
- [S0638] Babuk: Babuk can use “WNetOpenEnumW” and “WNetEnumResourceW” to enumerate files in network resources for encryption.


### T1057 - Process Discovery

Description:

Adversaries may attempt to get information about running processes on a system. Information obtained could be used to gain an understanding of common software/applications running on systems within the network. Administrator or otherwise elevated access may provide better process details. Adversaries may use the information from Process Discovery during automated discovery to shape follow-on behaviors, including whether or not the adversary fully infects the target and/or attempts specific actions. In Windows environments, adversaries could obtain details on running processes using the Tasklist utility via cmd or Get-Process via PowerShell. Information about processes can also be extracted from the output of Native API calls such as CreateToolhelp32Snapshot. In Mac and Linux, this is accomplished with the ps command. Adversaries may also opt to enumerate processes via `/proc`. ESXi also supports use of the `ps` command, as well as `esxcli system process list`. On network devices, Network Device CLI commands such as `show processes` can be used to display current running processes.

Procedures:

- [S0091] Epic: Epic uses the tasklist /v command to obtain a list of processes.
- [S0670] WarzoneRAT: WarzoneRAT can obtain a list of processes on a compromised host.
- [S0267] FELIXROOT: FELIXROOT collects a list of running processes.


### T1069.001 - Permission Groups Discovery: Local Groups

Description:

Adversaries may attempt to find local system groups and permission settings. The knowledge of local system permission groups can help adversaries determine which groups exist and which users belong to a particular group. Adversaries may use this information to determine which users have elevated permissions, such as the users found within the local administrators group. Commands such as net localgroup of the Net utility, dscl . -list /Groups on macOS, and groups on Linux can list local groups.

Procedures:

- [G0010] Turla: Turla has used net localgroup and net localgroup Administrators to enumerate group information, including members of the local administrators group.
- [S0201] JPIN: JPIN can obtain the permissions of the victim user.
- [S0060] Sys10: Sys10 collects the group name of the logged-in user and sends it to the C2.

### T1069.002 - Permission Groups Discovery: Domain Groups

Description:

Adversaries may attempt to find domain-level groups and permission settings. The knowledge of domain-level permission groups can help adversaries determine which groups exist and which users belong to a particular group. Adversaries may use this information to determine which users have elevated permissions, such as domain administrators. Commands such as net group /domain of the Net utility, dscacheutil -q group on macOS, and ldapsearch on Linux can list domain-level groups.

Procedures:

- [S0236] Kwampirs: Kwampirs collects a list of domain groups with the command net localgroup /domain.
- [G1004] LAPSUS$: LAPSUS$ has used the AD Explorer tool to enumerate groups on a victim's network.
- [S0039] Net: Commands such as net group /domain can be used in Net to gather information about and manipulate groups.

### T1069.003 - Permission Groups Discovery: Cloud Groups

Description:

Adversaries may attempt to find cloud groups and permission settings. The knowledge of cloud permission groups can help adversaries determine the particular roles of users and groups within an environment, as well as which users are associated with a particular group. With authenticated access there are several tools that can be used to find permissions groups. The Get-MsolRole PowerShell cmdlet can be used to obtain roles and permissions groups for Exchange and Office 365 accounts . Azure CLI (AZ CLI) and the Google Cloud Identity Provider API also provide interfaces to obtain permissions groups. The command az ad user get-member-groups will list groups associated to a user account for Azure while the API endpoint GET lists group resources available to a user for Google. In AWS, the commands `ListRolePolicies` and `ListAttachedRolePolicies` allow users to enumerate the policies attached to a role. Adversaries may attempt to list ACLs for objects to determine the owner and other accounts with access to the object, for example, via the AWS GetBucketAcl API . Using this information an adversary can target accounts with permissions to a given object or leverage accounts they have already compromised to access the object.

Procedures:

- [C0027] C0027: During C0027, Scattered Spider accessed Azure AD to download bulk lists of group members and their Active Directory attributes.
- [S0684] ROADTools: ROADTools can enumerate Azure AD groups.
- [S0677] AADInternals: AADInternals can enumerate Azure AD groups.


### T1082 - System Information Discovery

Description:

An adversary may attempt to get detailed information about the operating system and hardware, including version, patches, hotfixes, service packs, and architecture. Adversaries may use the information from System Information Discovery during automated discovery to shape follow-on behaviors, including whether or not the adversary fully infects the target and/or attempts specific actions. Tools such as Systeminfo can be used to gather detailed system information. If running with privileged access, a breakdown of system data can be gathered through the systemsetup configuration tool on macOS. As an example, adversaries with user-level access can execute the df -aH command to obtain currently mounted disks and associated freely available space. Adversaries may also leverage a Network Device CLI on network devices to gather detailed system information (e.g. show version). On ESXi servers, threat actors may gather system information from various esxcli utilities, such as `system hostname get`, `system version get`, and `storage filesystem list` (to list storage volumes). Infrastructure as a Service (IaaS) cloud providers such as AWS, GCP, and Azure allow access to instance and virtual machine information via APIs. Successful authenticated API calls can return data such as the operating system platform and status of a particular instance or the model view of a virtual machine. System Information Discovery combined with information gathered from other forms of discovery and reconnaissance can drive payload development and concealment.

Procedures:

- [S0339] Micropsia: Micropsia gathers the hostname and OS version from the victim’s machine.
- [S0385] njRAT: njRAT enumerates the victim operating system and computer name during the initial infection.
- [S1111] DarkGate: DarkGate uses the Delphi methods Sysutils::DiskSize and GlobalMemoryStatusEx to collect disk size and physical memory as part of the malware's anti-analysis checks for running in a virtualized environment. DarkGate will gather various system information such as domain, display adapter description, operating system type and version, processor type, and RAM amount.


### T1083 - File and Directory Discovery

Description:

Adversaries may enumerate files and directories or may search in specific locations of a host or network share for certain information within a file system. Adversaries may use the information from File and Directory Discovery during automated discovery to shape follow-on behaviors, including whether or not the adversary fully infects the target and/or attempts specific actions. Many command shell utilities can be used to obtain this information. Examples include dir, tree, ls, find, and locate. Custom tools may also be used to gather file and directory information and interact with the Native API. Adversaries may also leverage a Network Device CLI on network devices to gather file and directory information (e.g. dir, show flash, and/or nvram). Some files and directories may require elevated or specific user permissions to access.

Procedures:

- [S0069] BLACKCOFFEE: BLACKCOFFEE has the capability to enumerate files.
- [S0229] Orz: Orz can gather victim drive information.
- [S0438] Attor: Attor has a plugin that enumerates files with specific extensions on all hard disk drives and stores file information in encrypted log files.


### T1087.001 - Account Discovery: Local Account

Description:

Adversaries may attempt to get a listing of local system accounts. This information can help adversaries determine which local accounts exist on a system to aid in follow-on behavior. Commands such as net user and net localgroup of the Net utility and id and groups on macOS and Linux can list local users and groups. On Linux, local users can also be enumerated through the use of the /etc/passwd file. On macOS, the dscl . list /Users command can be used to enumerate local accounts. On ESXi servers, the `esxcli system account list` command can list local user accounts.

Procedures:

- [S0452] USBferry: USBferry can use net user to gather information about local accounts.
- [S0331] Agent Tesla: Agent Tesla can collect account information from the victim’s machine.
- [S0236] Kwampirs: Kwampirs collects a list of accounts with the command net users.

### T1087.002 - Account Discovery: Domain Account

Description:

Adversaries may attempt to get a listing of domain accounts. This information can help adversaries determine which domain accounts exist to aid in follow-on behavior such as targeting specific accounts which possess particular privileges. Commands such as net user /domain and net group /domain of the Net utility, dscacheutil -q group on macOS, and ldapsearch on Linux can list domain users and groups. PowerShell cmdlets including Get-ADUser and Get-ADGroupMember may enumerate members of Active Directory groups.

Procedures:

- [S1159] DUSTTRAP: DUSTTRAP can enumerate domain accounts.
- [C0024] SolarWinds Compromise: During the SolarWinds Compromise, APT29 used PowerShell to discover domain accounts by exectuing `Get-ADUser` and `Get-ADGroupMember`.
- [S0516] SoreFang: SoreFang can enumerate domain accounts via net.exe user /domain.

### T1087.003 - Account Discovery: Email Account

Description:

Adversaries may attempt to get a listing of email addresses and accounts. Adversaries may try to dump Exchange address lists such as global address lists (GALs). In on-premises Exchange and Exchange Online, the Get-GlobalAddressList PowerShell cmdlet can be used to obtain email addresses and accounts from a domain using an authenticated session. In Google Workspace, the GAL is shared with Microsoft Outlook users through the Google Workspace Sync for Microsoft Outlook (GWSMO) service. Additionally, the Google Workspace Directory allows for users to get a listing of other users within the organization.

Procedures:

- [G0092] TA505: TA505 has used the tool EmailStealer to steal and send lists of e-mail addresses to a remote server.
- [G0059] Magic Hound: Magic Hound has used Powershell to discover email accounts.
- [S0531] Grandoreiro: Grandoreiro can parse Outlook .pst files to extract e-mail addresses.

### T1087.004 - Account Discovery: Cloud Account

Description:

Adversaries may attempt to get a listing of cloud accounts. Cloud accounts are those created and configured by an organization for use by users, remote support, services, or for administration of resources within a cloud service provider or SaaS application. With authenticated access there are several tools that can be used to find accounts. The Get-MsolRoleMember PowerShell cmdlet can be used to obtain account names given a role or permissions group in Office 365. The Azure CLI (AZ CLI) also provides an interface to obtain user accounts with authenticated access to a domain. The command az ad user list will list all users within a domain. The AWS command aws iam list-users may be used to obtain a list of users in the current account while aws iam list-roles can obtain IAM roles that have a specified path prefix. In GCP, gcloud iam service-accounts list and gcloud projects get-iam-policy may be used to obtain a listing of service accounts and users in a project.

Procedures:

- [C0027] C0027: During C0027, Scattered Spider accessed Azure AD to download bulk lists of group members and to identify privileged users, along with the email addresses and AD attributes.
- [S0684] ROADTools: ROADTools can enumerate Azure AD users.
- [S0677] AADInternals: AADInternals can enumerate Azure AD users.


### T1120 - Peripheral Device Discovery

Description:

Adversaries may attempt to gather information about attached peripheral devices and components connected to a computer system. Peripheral devices could include auxiliary resources that support a variety of functionalities such as keyboards, printers, cameras, smart card readers, or removable storage. The information may be used to enhance their awareness of the system and network environment or may be used for further actions.

Procedures:

- [S1139] INC Ransomware: INC Ransomware can identify external USB and hard drives for encryption and printers to print ransom notes.
- [G0020] Equation: Equation has used tools with the functionality to search for specific information about the attached hard drive that could be used to identify and overwrite the firmware.
- [C0012] Operation CuckooBees: During Operation CuckooBees, the threat actors used the `fsutil fsinfo drives` command as part of their advanced reconnaissance.


### T1124 - System Time Discovery

Description:

An adversary may gather the system time and/or time zone settings from a local or remote system. The system time is set and stored by services, such as the Windows Time Service on Windows or systemsetup on macOS. These time settings may also be synchronized between systems and services in an enterprise network, typically accomplished with a network time server within a domain. System time information may be gathered in a number of ways, such as with Net on Windows by performing net time \\hostname to gather the system time on a remote system. The victim's time zone may also be inferred from the current system time or gathered by using w32tm /tz. In addition, adversaries can discover device uptime through functions such as GetTickCount() to determine how long it has been since the system booted up. On network devices, Network Device CLI commands such as `show clock detail` can be used to see the current time configuration. On ESXi servers, `esxcli system clock get` can be used for the same purpose. In addition, system calls – such as time() – have been used to collect the current time on Linux devices. On macOS systems, adversaries may use commands such as systemsetup -gettimezone or timeIntervalSinceNow to gather current time zone information or current date and time. This information could be useful for performing other techniques, such as executing a file with a Scheduled Task/Job, or to discover locality information based on time zone to assist in victim targeting (i.e. System Location Discovery). Adversaries may also use knowledge of system time as part of a time bomb, or delaying execution until a specified date/time.

Procedures:

- [S0140] Shamoon: Shamoon obtains the system time and will only activate if it is greater than a preset date.
- [S1178] ShrinkLocker: ShrinkLocker retrieves a system timestamp that is used in generating an encryption key.
- [S0373] Astaroth: Astaroth collects the timestamp from the infected machine.


### T1135 - Network Share Discovery

Description:

Adversaries may look for folders and drives shared on remote systems as a means of identifying sources of information to gather as a precursor for Collection and to identify potential systems of interest for Lateral Movement. Networks often contain shared network drives and folders that enable users to access file directories on various systems across a network. File sharing over a Windows network occurs over the SMB protocol. Net can be used to query a remote system for available shared drives using the net view \\\\remotesystem command. It can also be used to query shared drives on the local system using net share. For macOS, the sharing -l command lists all shared points used for smb services.

Procedures:

- [S1081] BADHATCH: BADHATCH can check a user's access to the C$ share on a compromised machine.
- [S1180] BlackByte Ransomware: BlackByte Ransomware can identify network shares connected to the victim machine.
- [S0458] Ramsay: Ramsay can scan for network drives which may contain documents for collection.


### T1201 - Password Policy Discovery

Description:

Adversaries may attempt to access detailed information about the password policy used within an enterprise network or cloud environment. Password policies are a way to enforce complex passwords that are difficult to guess or crack through Brute Force. This information may help the adversary to create a list of common passwords and launch dictionary and/or brute force attacks which adheres to the policy (e.g. if the minimum password length should be 8, then not trying passwords such as 'pass123'; not checking for more than 3-4 passwords per account if the lockout is set to 6 as to not lock out accounts). Password policies can be set and discovered on Windows, Linux, and macOS systems via various command shell utilities such as net accounts (/domain), Get-ADDefaultDomainPasswordPolicy, chage -l , cat /etc/pam.d/common-password, and pwpolicy getaccountpolicies . Adversaries may also leverage a Network Device CLI on network devices to discover password policy information (e.g. show aaa, show aaa common-criteria policy all). Password policies can be discovered in cloud environments using available APIs such as GetAccountPasswordPolicy in AWS .

Procedures:

- [S0039] Net: The net accounts and net accounts /domain commands with Net can be used to obtain password policy information.
- [S0488] CrackMapExec: CrackMapExec can discover the password policies applied to the target system.
- [C0012] Operation CuckooBees: During Operation CuckooBees, the threat actors used the `net accounts` command as part of their advanced reconnaissance.


### T1217 - Browser Information Discovery

Description:

Adversaries may enumerate information about browsers to learn more about compromised environments. Data saved by browsers (such as bookmarks, accounts, and browsing history) may reveal a variety of personal information about users (e.g., banking sites, relationships/interests, social media, etc.) as well as details about internal network resources such as servers, tools/dashboards, or other related infrastructure. Browser information may also highlight additional targets after an adversary has access to valid credentials, especially Credentials In Files associated with logins cached by a browser. Specific storage locations vary based on platform and/or application, but browser information is typically stored in local files and databases (e.g., `%APPDATA%/Google/Chrome`).

Procedures:

- [S0274] Calisto: Calisto collects information on bookmarks from Google Chrome.
- [S0681] Lizar: Lizar can retrieve browser history and database files.
- [C0044] Juicy Mix: During Juicy Mix, OilRig used the CDumper (Chrome browser) and EDumper (Edge browser) data stealers to collect cookies, browsing history, and credentials.


### T1482 - Domain Trust Discovery

Description:

Adversaries may attempt to gather information on domain trust relationships that may be used to identify lateral movement opportunities in Windows multi-domain/forest environments. Domain trusts provide a mechanism for a domain to allow access to resources based on the authentication procedures of another domain. Domain trusts allow the users of the trusted domain to access resources in the trusting domain. The information discovered may help the adversary conduct SID-History Injection, Pass the Ticket, and Kerberoasting. Domain trusts can be enumerated using the `DSEnumerateDomainTrusts()` Win32 API call, .NET methods, and LDAP. The Windows utility Nltest is known to be used by adversaries to enumerate domain trusts.

Procedures:

- [S0363] Empire: Empire has modules for enumerating domain trusts.
- [G1043] BlackByte: BlackByte enumerated Active Directory information and trust relationships during operations.
- [S0534] Bazar: Bazar can use Nltest tools to obtain information about the domain.


### T1497.001 - Virtualization/Sandbox Evasion: System Checks

Description:

Adversaries may employ various system checks to detect and avoid virtualization and analysis environments. This may include changing behaviors based on the results of checks for the presence of artifacts indicative of a virtual machine environment (VME) or sandbox. If the adversary detects a VME, they may alter their malware to disengage from the victim or conceal the core functions of the implant. They may also search for VME artifacts before dropping secondary or additional payloads. Adversaries may use the information learned from Virtualization/Sandbox Evasion during automated discovery to shape follow-on behaviors. Specific checks will vary based on the target and/or adversary, but may involve behaviors such as Windows Management Instrumentation, PowerShell, System Information Discovery, and Query Registry to obtain system information and search for VME artifacts. Adversaries may search for VME artifacts in memory, processes, file system, hardware, and/or the Registry. Adversaries may use scripting to automate these checks into one script and then have the program exit if it determines the system to be a virtual environment. Checks could include generic system properties such as host/domain name and samples of network traffic. Adversaries may also check the network adapters addresses, CPU core count, and available memory/drive size. Once executed, malware may also use File and Directory Discovery to check if it was saved in a folder or file with unexpected or even analysis-related naming artifacts such as `malware`, `sample`, or `hash`. Other common checks may enumerate services running that are unique to these applications, installed programs on the system, manufacturer/product fields for strings relating to virtual machine applications, and VME-specific hardware/processor instructions. In applications like VMWare, adversaries can also use a special I/O port to send commands and receive output. Hardware checks, such as the presence of the fan, temperature, and audio devices, could also be used to gather evidence that can be indicative a virtual environment. Adversaries may also query for specific readings from these devices.

Procedures:

- [S0650] QakBot: QakBot can check the compromised host for the presence of multiple executables associated with analysis tools and halt execution if any are found.
- [S0354] Denis: Denis ran multiple system checks, looking for processor and register characteristics, to evade emulation and analysis.
- [S0627] SodaMaster: SodaMaster can check for the presence of the Registry key HKEY_CLASSES_ROOT\\Applications\\VMwareHostOpen.exe before proceeding to its main functionality.

### T1497.002 - Virtualization/Sandbox Evasion: User Activity Based Checks

Description:

Adversaries may employ various user activity checks to detect and avoid virtualization and analysis environments. This may include changing behaviors based on the results of checks for the presence of artifacts indicative of a virtual machine environment (VME) or sandbox. If the adversary detects a VME, they may alter their malware to disengage from the victim or conceal the core functions of the implant. They may also search for VME artifacts before dropping secondary or additional payloads. Adversaries may use the information learned from Virtualization/Sandbox Evasion during automated discovery to shape follow-on behaviors. Adversaries may search for user activity on the host based on variables such as the speed/frequency of mouse movements and clicks , browser history, cache, bookmarks, or number of files in common directories such as home or the desktop. Other methods may rely on specific user interaction with the system before the malicious code is activated, such as waiting for a document to close before activating a macro or waiting for a user to double click on an embedded image to activate.

Procedures:

- [G0012] Darkhotel: Darkhotel has used malware that repeatedly checks the mouse cursor position to determine if a real user is on the system.
- [S0439] Okrum: Okrum loader only executes the payload after the left mouse button has been pressed at least three times, in order to avoid being executed within virtualized or emulated environments.
- [G0046] FIN7: FIN7 used images embedded into document lures that only activate the payload when a user double clicks to avoid sandboxes.

### T1497.003 - Virtualization/Sandbox Evasion: Time Based Evasion

Description:

Adversaries may employ various time-based methods to detect and avoid virtualization and analysis environments. This may include enumerating time-based properties, such as uptime or the system clock, as well as the use of timers or other triggers to avoid a virtual machine environment (VME) or sandbox, specifically those that are automated or only operate for a limited amount of time. Adversaries may employ various time-based evasions, such as delaying malware functionality upon initial execution using programmatic sleep commands or native system scheduling functionality (ex: Scheduled Task/Job). Delays may also be based on waiting for specific victim conditions to be met (ex: system time, events, etc.) or employ scheduled Multi-Stage Channels to avoid analysis and scrutiny. Benign commands or other operations may also be used to delay malware execution. Loops or otherwise needless repetitions of commands, such as Pings, may be used to delay malware execution and potentially exceed time thresholds of automated analysis environments. Another variation, commonly referred to as API hammering, involves making various calls to Native API functions in order to delay execution (while also potentially overloading analysis environments with junk data). Adversaries may also use time as a metric to detect sandboxes and analysis environments, particularly those that attempt to manipulate time mechanisms to simulate longer elapses of time. For example, an adversary may be able to identify a sandbox accelerating time by sampling and calculating the expected value for an environment's timestamp before and after execution of a sleep function.

Procedures:

- [S0565] Raindrop: After initial installation, Raindrop runs a computation to delay execution.
- [S0626] P8RAT: P8RAT has the ability to "sleep" for a specified time to evade detection.
- [S0559] SUNBURST: SUNBURST remained dormant after initial access for a period of up to two weeks.


### T1518.001 - Software Discovery: Security Software Discovery

Description:

Adversaries may attempt to get a listing of security software, configurations, defensive tools, and sensors that are installed on a system or in a cloud environment. This may include things such as cloud monitoring agents and anti-virus. Adversaries may use the information from Security Software Discovery during automated discovery to shape follow-on behaviors, including whether or not the adversary fully infects the target and/or attempts specific actions. Example commands that can be used to obtain security software information are netsh, reg query with Reg, dir with cmd, and Tasklist, but other indicators of discovery behavior may be more specific to the type of software or security system the adversary is looking for. It is becoming more common to see macOS malware perform checks for LittleSnitch and KnockKnock software. Adversaries may also utilize the Cloud API to discover cloud-native security software installed on compute infrastructure, such as the AWS CloudWatch agent, Azure VM Agent, and Google Cloud Monitor agent. These agents may collect metrics and logs from the VM, which may be centrally aggregated in a cloud-based monitoring platform.

Procedures:

- [G0012] Darkhotel: Darkhotel has searched for anti-malware strings and anti-virus processes running on the system.
- [S1130] Raspberry Robin: Raspberry Robin attempts to identify security software running on the victim machine, such as BitDefender, Avast, and Kaspersky.
- [S0611] Clop: Clop can search for processes with antivirus and antimalware product names.


### T1526 - Cloud Service Discovery

Description:

An adversary may attempt to enumerate the cloud services running on a system after gaining access. These methods can differ from platform-as-a-service (PaaS), to infrastructure-as-a-service (IaaS), or software-as-a-service (SaaS). Many services exist throughout the various cloud providers and can include Continuous Integration and Continuous Delivery (CI/CD), Lambda Functions, Entra ID, etc. They may also include security services, such as AWS GuardDuty and Microsoft Defender for Cloud, and logging services, such as AWS CloudTrail and Google Cloud Audit Logs. Adversaries may attempt to discover information about the services enabled throughout the environment. Azure tools and APIs, such as the Microsoft Graph API and Azure Resource Manager API, can enumerate resources and services, including applications, management groups, resources and policy definitions, and their relationships that are accessible by an identity. For example, Stormspotter is an open source tool for enumerating and constructing a graph for Azure resources and services, and Pacu is an open source AWS exploitation framework that supports several methods for discovering cloud services. Adversaries may use the information gained to shape follow-on behaviors, such as targeting data or credentials from enumerated services or evading identified defenses through Disable or Modify Tools or Disable or Modify Cloud Logs.

Procedures:

- [S0677] AADInternals: AADInternals can enumerate information about a variety of cloud services, such as Office 365 and Sharepoint instances or OpenID Configurations.
- [S0684] ROADTools: ROADTools can enumerate Azure AD applications and service principals.
- [S1091] Pacu: Pacu can enumerate AWS services, such as CloudTrail and CloudWatch.


### T1538 - Cloud Service Dashboard

Description:

An adversary may use a cloud service dashboard GUI with stolen credentials to gain useful information from an operational cloud environment, such as specific services, resources, and features. For example, the GCP Command Center can be used to view all assets, review findings of potential security risks, and run additional queries, such as finding public IP addresses and open ports. Depending on the configuration of the environment, an adversary may be able to enumerate more information via the graphical dashboard than an API. This also allows the adversary to gain information without manually making any API requests.

Procedures:

- [G1015] Scattered Spider: Scattered Spider abused AWS Systems Manager Inventory to identify targets on the compromised network prior to lateral movement.


### T1580 - Cloud Infrastructure Discovery

Description:

An adversary may attempt to discover infrastructure and resources that are available within an infrastructure-as-a-service (IaaS) environment. This includes compute service resources such as instances, virtual machines, and snapshots as well as resources of other services including the storage and database services. Cloud providers offer methods such as APIs and commands issued through CLIs to serve information about infrastructure. For example, AWS provides a DescribeInstances API within the Amazon EC2 API that can return information about one or more instances within an account, the ListBuckets API that returns a list of all buckets owned by the authenticated sender of the request, the HeadBucket API to determine a bucket’s existence along with access permissions of the request sender, or the GetPublicAccessBlock API to retrieve access block configuration for a bucket. Similarly, GCP's Cloud SDK CLI provides the gcloud compute instances list command to list all Google Compute Engine instances in a project , and Azure's CLI command az vm list lists details of virtual machines. In addition to API commands, adversaries can utilize open source tools to discover cloud storage infrastructure through Wordlist Scanning. An adversary may enumerate resources using a compromised user's access keys to determine which are available to that user. The discovery of these available resources may help adversaries determine their next steps in the Cloud environment, such as establishing Persistence.An adversary may also use this information to change the configuration to make the bucket publicly accessible, allowing data to be accessed without authentication. Adversaries have also may use infrastructure discovery APIs such as DescribeDBInstances to determine size, owner, permissions, and network ACLs of database resources. Adversaries can use this information to determine the potential value of databases and discover the requirements to access them. Unlike in Cloud Service Discovery, this technique focuses on the discovery of components of the provided services rather than the services themselves.

Procedures:

- [G1015] Scattered Spider: Scattered Spider enumerates cloud environments to identify server and backup management infrastructure, resource access, databases and storage containers.
- [S1091] Pacu: Pacu can enumerate AWS infrastructure, such as EC2 instances.


### T1613 - Container and Resource Discovery

Description:

Adversaries may attempt to discover containers and other resources that are available within a containers environment. Other resources may include images, deployments, pods, nodes, and other information such as the status of a cluster. These resources can be viewed within web applications such as the Kubernetes dashboard or can be queried via the Docker and Kubernetes APIs. In Docker, logs may leak information about the environment, such as the environment’s configuration, which services are available, and what cloud provider the victim may be utilizing. The discovery of these resources may inform an adversary’s next steps in the environment, such as how to perform lateral movement and which methods to utilize for execution.

Procedures:

- [S0683] Peirates: Peirates can enumerate Kubernetes pods in a given namespace.
- [G0139] TeamTNT: TeamTNT has checked for running containers with docker ps and for specific container names with docker inspect. TeamTNT has also searched for Kubernetes pods running in a local network.
- [S0601] Hildegard: Hildegard has used masscan to search for kubelets and the kubelet API for additional running containers.


### T1614.001 - System Location Discovery: System Language Discovery

Description:

Adversaries may attempt to gather information about the system language of a victim in order to infer the geographical location of that host. This information may be used to shape follow-on behaviors, including whether the adversary infects the target and/or attempts specific actions. This decision may be employed by malware developers and operators to reduce their risk of attracting the attention of specific law enforcement agencies or prosecution/scrutiny from other entities. There are various sources of data an adversary could use to infer system language, such as system defaults and keyboard layouts. Specific checks will vary based on the target and/or adversary, but may involve behaviors such as Query Registry and calls to Native API functions. For example, on a Windows system adversaries may attempt to infer the language of a system by querying the registry key HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Nls\Language or parsing the outputs of Windows API functions GetUserDefaultUILanguage, GetSystemDefaultUILanguage, GetKeyboardLayoutList and GetUserDefaultLangID. On a macOS or Linux system, adversaries may query locale to retrieve the value of the $LANG environment variable.

Procedures:

- [C0022] Operation Dream Job: During Operation Dream Job, Lazarus Group deployed malware designed not to run on computers set to Korean, Japanese, or Chinese in Windows language preferences.
- [S1153] Cuckoo Stealer: Cuckoo Stealer can check the systems `LANG` environmental variable to prevent infecting devices from Armenia (`hy_AM`), Belarus (`be_BY`), Kazakhstan (`kk_KZ`), Russia (`ru_RU`), and Ukraine (`uk_UA`).
- [S0652] MarkiRAT: MarkiRAT can use the GetKeyboardLayout API to check if a compromised host's keyboard is set to Persian.


### T1615 - Group Policy Discovery

Description:

Adversaries may gather information on Group Policy settings to identify paths for privilege escalation, security measures applied within a domain, and to discover patterns in domain objects that can be manipulated or used to blend in the environment. Group Policy allows for centralized management of user and computer settings in Active Directory (AD). Group policy objects (GPOs) are containers for group policy settings made up of files stored within a predictable network path `\\SYSVOL\\Policies\`. Adversaries may use commands such as gpresult or various publicly available PowerShell functions, such as Get-DomainGPO and Get-DomainGPOLocalGroup, to gather information on Group Policy settings. Adversaries may use this information to shape follow-on behaviors, including determining potential attack paths within the target network as well as opportunities to manipulate Group Policy settings (i.e. Domain or Tenant Policy Modification) for their benefit.

Procedures:

- [S1141] LunarWeb: LunarWeb can capture information on group policy settings
- [C0049] Leviathan Australian Intrusions: Leviathan performed extensive Active Directory enumeration of victim environments during Leviathan Australian Intrusions.
- [S1159] DUSTTRAP: DUSTTRAP can identify victim environment Group Policy information.


### T1619 - Cloud Storage Object Discovery

Description:

Adversaries may enumerate objects in cloud storage infrastructure. Adversaries may use this information during automated discovery to shape follow-on behaviors, including requesting all or specific objects from cloud storage. Similar to File and Directory Discovery on a local host, after identifying available storage services (i.e. Cloud Infrastructure Discovery) adversaries may access the contents/objects stored in cloud infrastructure. Cloud service providers offer APIs allowing users to enumerate objects stored within cloud storage. Examples include ListObjectsV2 in AWS and List Blobs in Azure .

Procedures:

- [S1091] Pacu: Pacu can enumerate AWS storage services, such as S3 buckets and Elastic Block Store volumes.
- [S0683] Peirates: Peirates can list AWS S3 buckets.


### T1622 - Debugger Evasion

Description:

Adversaries may employ various means to detect and avoid debuggers. Debuggers are typically used by defenders to trace and/or analyze the execution of potential malware payloads. Debugger evasion may include changing behaviors based on the results of the checks for the presence of artifacts indicative of a debugged environment. Similar to Virtualization/Sandbox Evasion, if the adversary detects a debugger, they may alter their malware to disengage from the victim or conceal the core functions of the implant. They may also search for debugger artifacts before dropping secondary or additional payloads. Specific checks will vary based on the target and/or adversary. On Windows, this may involve Native API function calls such as IsDebuggerPresent() and NtQueryInformationProcess(), or manually checking the BeingDebugged flag of the Process Environment Block (PEB). On Linux, this may involve querying `/proc/self/status` for the `TracerPID` field, which indicates whether or not the process is being traced by dynamic analysis tools. Other checks for debugging artifacts may also seek to enumerate hardware breakpoints, interrupt assembly opcodes, time checks, or measurements if exceptions are raised in the current process (assuming a present debugger would “swallow” or handle the potential error). Malware may also leverage Structured Exception Handling (SEH) to detect debuggers by throwing an exception and detecting whether the process is suspended. SEH handles both hardware and software expectations, providing control over the exceptions including support for debugging. If a debugger is present, the program’s control will be transferred to the debugger, and the execution of the code will be suspended. If the debugger is not present, control will be transferred to the SEH handler, which will automatically handle the exception and allow the program’s execution to continue. Adversaries may use the information learned from these debugger checks during automated discovery to shape follow-on behaviors. Debuggers can also be evaded by detaching the process or flooding debug logs with meaningless data via messages produced by looping Native API function calls such as OutputDebugStringW().

Procedures:

- [S1213] Lumma Stealer: Lumma Stealer has checked for debugger strings by invoking `GetForegroundWindow` and looks for strings containing “x32dbg”, “x64dbg”, “windbg”, “ollydbg”, “dnspy”, “immunity debugger”, “hyperdbg”, “debug”, “debugger”, “cheat engine”, “cheatengine” and “ida”.
- [S1087] AsyncRAT: AsyncRAT can use the `CheckRemoteDebuggerPresent` function to detect the presence of a debugger.
- [S1200] StealBit: StealBit can detect it is being run in the context of a debugger.


### T1652 - Device Driver Discovery

Description:

Adversaries may attempt to enumerate local device drivers on a victim host. Information about device drivers may highlight various insights that shape follow-on behaviors, such as the function/purpose of the host, present security tools (i.e. Security Software Discovery) or other defenses (e.g., Virtualization/Sandbox Evasion), as well as potential exploitable vulnerabilities (e.g., Exploitation for Privilege Escalation). Many OS utilities may provide information about local device drivers, such as `driverquery.exe` and the `EnumDeviceDrivers()` API function on Windows. Information about device drivers (as well as associated services, i.e., System Service Discovery) may also be available in the Registry. On Linux/macOS, device drivers (in the form of kernel modules) may be visible within `/dev` or using utilities such as `lsmod` and `modinfo`.

Procedures:

- [S0376] HOPLIGHT: HOPLIGHT can enumerate device drivers located in the registry at `HKLM\Software\WBEM\WDM`.
- [S1139] INC Ransomware: INC Ransomware can verify the presence of specific drivers on compromised hosts including Microsoft Print to PDF and Microsoft XPS Document Writer.
- [S0125] Remsec: Remsec has a plugin to detect active drivers of some security products.


### T1654 - Log Enumeration

Description:

Adversaries may enumerate system and service logs to find useful data. These logs may highlight various types of valuable insights for an adversary, such as user authentication records (Account Discovery), security or vulnerable software (Software Discovery), or hosts within a compromised network (Remote System Discovery). Host binaries may be leveraged to collect system logs. Examples include using `wevtutil.exe` or PowerShell on Windows to access and/or export security event information. In cloud environments, adversaries may leverage utilities such as the Azure VM Agent’s `CollectGuestLogs.exe` to collect security logs from cloud hosted infrastructure. Adversaries may also target centralized logging infrastructure such as SIEMs. Logs may also be bulk exported and sent to adversary-controlled infrastructure for offline analysis. In addition to gaining a better understanding of the environment, adversaries may also monitor logs in real time to track incident response procedures. This may allow them to adjust their techniques in order to maintain persistence or evade defenses.

Procedures:

- [G1023] APT5: APT5 has used the BLOODMINE utility to parse and extract information from Pulse Secure Connect logs.
- [G1003] Ember Bear: Ember Bear has enumerated SECURITY and SYSTEM log files during intrusions.
- [G1017] Volt Typhoon: Volt Typhoon has used `wevtutil.exe` and the PowerShell command `Get-EventLog security` to enumerate Windows logs to search for successful logons.


### T1673 - Virtual Machine Discovery

Description:

An adversary may attempt to enumerate running virtual machines (VMs) after gaining access to a host or hypervisor. For example, adversaries may enumerate a list of VMs on an ESXi hypervisor using a Hypervisor CLI such as `esxcli` or `vim-cmd` (e.g. `esxcli vm process list or vim-cmd vmsvc/getallvms`). Adversaries may also directly leverage a graphical user interface, such as VMware vCenter, in order to view virtual machines on a host. Adversaries may use the information from Virtual Machine Discovery during discovery to shape follow-on behaviors. Subsequently discovered VMs may be leveraged for follow-on activities such as Service Stop or Data Encrypted for Impact.

Procedures:

- [S1096] Cheerscrypt: Cheerscrypt has leveraged `esxcli vm process list` in order to gather a list of running virtual machines to terminate them.

