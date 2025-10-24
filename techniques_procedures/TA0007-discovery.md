### T1007 - System Service Discovery

Procedures:

- [S0386] Ursnif: Ursnif has gathered information about running services.
- [G0060] BRONZE BUTLER: BRONZE BUTLER has used TROJ_GETVERSION to discover system services.
- [S0018] Sykipot: Sykipot may use net start to display running services.
- [S0244] Comnie: Comnie runs the command: net start >> %TEMP%\info.dat on a victim.
- [S0663] SysUpdate: SysUpdate can collect a list of services on a victim machine.
- [S0039] Net: The net start command can be used in Net to find information about Windows services.
- [G0139] TeamTNT: TeamTNT has searched for services such as Alibaba Cloud Security's aliyun service and BMC Helix Cloud Security's bmc-agent service in order to disable them.
- [S0081] Elise: Elise executes net start after initial communication is made to the remote server.
- [S0378] PoshC2: PoshC2 can enumerate service and service permission information.
- [G0119] Indrik Spider: Indrik Spider has used the win32_service WMI class to retrieve a list of services from the system.
- [S0533] SLOTHFULMEDIA: SLOTHFULMEDIA has the capability to enumerate services.
- [S0236] Kwampirs: Kwampirs collects a list of running services with the command tasklist /svc.
- [S0057] Tasklist: Tasklist can be used to discover services running on a system.
- [S0283] jRAT: jRAT can list local services.
- [S0241] RATANKBA: RATANKBA uses tasklist /svc to display running tasks.


### T1010 - Application Window Discovery

Procedures:

- [S0438] Attor: Attor can obtain application window titles and then determines which windows to perform Screen Capture on.
- [S0033] NetTraveler: NetTraveler reports window names along with keylogger information to provide application context.
- [S0454] Cadelspy: Cadelspy has the ability to identify open windows on the compromised host.
- [S0696] Flagpro: Flagpro can check the name of the window displayed on the system.
- [S0385] njRAT: njRAT gathers information about opened windows during the initial infection.
- [G0032] Lazarus Group: Lazarus Group malware IndiaIndia obtains and sends to its C2 server the title of the window for each running process. The KilaAlfa keylogger also reports the title of the window in the foreground.
- [S0094] Trojan.Karagany: Trojan.Karagany can monitor the titles of open windows to identify specific keywords.
- [S1111] DarkGate: DarkGate will search for cryptocurrency wallets by examining application window names for specific strings. DarkGate extracts information collected via NirSoft tools from the hosting process's memory by first identifying the window through the FindWindow API function.
- [S0673] DarkWatchman: DarkWatchman reports window names along with keylogger information to provide application context.
- [S0139] PowerDuke: PowerDuke has a command to get text of the current foreground window.
- [S0260] InvisiMole: InvisiMole can enumerate windows and child windows on a compromised host.
- [S0456] Aria-body: Aria-body has the ability to identify the titles of running windows on a compromised host.
- [S0531] Grandoreiro: Grandoreiro can identify installed security tools based on window names.
- [S0219] WINERACK: WINERACK can enumerate active windows.
- [S0409] Machete: Machete saves the window names.


### T1012 - Query Registry

Procedures:

- [C0014] Operation Wocao: During Operation Wocao, the threat actors executed `/c cd /d c:\windows\temp\ & reg query HKEY_CURRENT_USER\Software\\PuTTY\Sessions\` to detect recent PuTTY sessions, likely to further lateral movement.
- [S0091] Epic: Epic uses the rem reg query command to obtain values from Registry keys.
- [S1159] DUSTTRAP: DUSTTRAP can enumerate Registry items.
- [S0589] Sibot: Sibot has queried the registry for proxy server information.
- [S0512] FatDuke: FatDuke can get user agent strings for the default browser from HKCU\Software\Classes\http\shell\open\command.
- [S0203] Hydraq: Hydraq creates a backdoor through which remote attackers can retrieve system information, such as CPU speed, from Registry keys.
- [S1064] SVCReady: SVCReady can search for the `HKEY_LOCAL_MACHINE\HARDWARE\DESCRIPTION\System` Registry key to gather system information.
- [G0128] ZIRCONIUM: ZIRCONIUM has used a tool to query the Registry for proxy settings.
- [S0560] TEARDROP: TEARDROP checked that HKU\SOFTWARE\Microsoft\CTF existed before decoding its embedded payload.
- [S0376] HOPLIGHT: A variant of HOPLIGHT hooks lsass.exe, and lsass.exe then checks the Registry for the data value 'rdpproto' under the key SYSTEM\CurrentControlSet\Control\Lsa Name.
- [S1019] Shark: Shark can query `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography MachineGuid` to retrieve the machine GUID.
- [S1180] BlackByte Ransomware: BlackByte Ransomware enumerates the Registry, specifically the `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options` key.
- [S0344] Azorult: Azorult can check for installed software on the system under the Registry key Software\Microsoft\Windows\CurrentVersion\Uninstall.
- [S0660] Clambling: Clambling has the ability to enumerate Registry keys, including KEY_CURRENT_USER\Software\Bitcoin\Bitcoin-Qt\strDataDir to search for a bitcoin wallet.
- [S0180] Volgmer: Volgmer checks the system for certain Registry keys.


### T1016.001 - System Network Configuration Discovery: Internet Connection Discovery

Procedures:

- [S0597] GoldFinder: GoldFinder performed HTTP GET requests to check internet connectivity and identify HTTP proxy servers and other redirectors that an HTTP request traveled through.
- [S0284] More_eggs: More_eggs has used HTTP GET requests to check internet connectivity.
- [S0691] Neoichor: Neoichor can check for Internet connectivity by contacting bing[.]com with the request format `bing[.]com?id=`.
- [C0024] SolarWinds Compromise: During the SolarWinds Compromise, APT29 used GoldFinder to perform HTTP GET requests to check internet connectivity and identify HTTP proxy servers and other redirectors that an HTTP request travels through.
- [G0059] Magic Hound: Magic Hound has conducted a network call out to a specific website as part of their initial discovery activity.
- [S1049] SUGARUSH: SUGARUSH has checked for internet connectivity from an infected host before attempting to establish a new TCP connection.
- [S1107] NKAbuse: NKAbuse utilizes external services such as ifconfig.me to identify the victim machine's IP address.
- [G1001] HEXANE: HEXANE has used tools including BITSAdmin to test internet connectivity from compromised hosts.
- [S0650] QakBot: QakBot can measure the download speed on a targeted host.
- [G0016] APT29: APT29 has ensured web servers in a victim environment are Internet accessible before copying tools or malware to it.
- [S0686] QuietSieve: QuietSieve can check C2 connectivity with a `ping` to 8.8.8.8 (Google public DNS).
- [G0047] Gamaredon Group: Gamaredon Group has tested connectivity between a compromised machine and a C2 server using Ping with commands such as `CSIDL_SYSTEM\cmd.exe /c ping -n 1`.
- [S0663] SysUpdate: SysUpdate can contact the DNS server operated by Google as part of its C2 establishment process.
- [G1018] TA2541: TA2541 has run scripts to check internet connectivity from compromised hosts.
- [C0014] Operation Wocao: During Operation Wocao, threat actors used a Visual Basic script that checked for internet connectivity.

### T1016.002 - System Network Configuration Discovery: Wi-Fi Discovery

Procedures:

- [G0059] Magic Hound: Magic Hound has collected names and passwords of all Wi-Fi networks to which a device has previously connected.
- [C0051] APT28 Nearest Neighbor Campaign: During APT28 Nearest Neighbor Campaign, APT28 collected information on wireless interfaces within range of a compromised system.
- [S0331] Agent Tesla: Agent Tesla can collect names and passwords of all Wi-Fi networks to which a device has previously connected.
- [S0367] Emotet: Emotet can extract names of all locally reachable Wi-Fi networks and then perform a brute-force attack to spread to new networks.


### T1018 - Remote System Discovery

Procedures:

- [G1003] Ember Bear: Ember Bear has used tools such as Nmap and MASSCAN for remote service discovery.
- [G0045] menuPass: menuPass uses scripts to enumerate IP ranges on the victim network. menuPass has also issued the command net view /domain to a PlugX implant to gather information about remote systems on the network.
- [S0233] MURKYTOP: MURKYTOP has the capability to identify remote hosts on connected networks.
- [S0586] TAINTEDSCRIBE: The TAINTEDSCRIBE command and execution module can perform target system enumeration.
- [S0684] ROADTools: ROADTools can enumerate Azure AD systems and devices.
- [S0570] BitPaymer: BitPaymer can use net view to discover remote systems.
- [S0650] QakBot: QakBot can identify remote systems through the net view command.
- [C0012] Operation CuckooBees: During Operation CuckooBees, the threat actors used the `net view` and `ping` commands as part of their advanced reconnaissance.
- [C0014] Operation Wocao: During Operation Wocao, threat actors used `nbtscan` and `ping` to discover remote systems, as well as `dsquery subnet` on a domain controller to retrieve all subnets in the Active Directory.
- [G0117] Fox Kitten: Fox Kitten has used Angry IP Scanner to detect remote systems.
- [S0452] USBferry: USBferry can use net view to gather information about remote systems.
- [S0534] Bazar: Bazar can enumerate remote systems using Net View.
- [S1081] BADHATCH: BADHATCH can use a PowerShell object such as, `System.Net.NetworkInformation.Ping` to ping a computer.
- [G1030] Agrius: Agrius used the tool NBTscan to scan for remote, accessible hosts in victim environments.
- [S1068] BlackCat: BlackCat can broadcasts NetBIOS Name Service (NBNC) messages to search for servers connected to compromised networks.


### T1033 - System Owner/User Discovery

Procedures:

- [S0094] Trojan.Karagany: Trojan.Karagany can gather information about the user on a compromised host.
- [S0428] PoetRAT: PoetRAT sent username, computer name, and the previously generated UUID in reply to a "who" command from C2.
- [S0379] Revenge RAT: Revenge RAT gathers the username from the system.
- [S0694] DRATzarus: DRATzarus can obtain a list of users from an infected machine.
- [S0266] TrickBot: TrickBot can identify the user and groups the user belongs to on a compromised host.
- [S0596] ShadowPad: ShadowPad has collected the username of the victim system.
- [S1030] Squirrelwaffle: Squirrelwaffle can collect the user name from a compromised host.
- [S0367] Emotet: Emotet has enumerated all users connected to network shares.
- [G0082] APT38: APT38 has identified primary users, currently logged in users, sets of users that commonly use a system, or inactive users.
- [S0590] NBTscan: NBTscan can list active users on the system.
- [S0272] NDiskMonitor: NDiskMonitor obtains the victim username and encrypts the information to send over its C2 channel.
- [S0414] BabyShark: BabyShark has executed the whoami command.
- [S0514] WellMess: WellMess can collect the username on the victim machine to send to C2.
- [G1036] Moonstone Sleet: Moonstone Sleet deployed various malware such as YouieLoader that can perform system user discovery actions.
- [S1016] MacMa: MacMa can collect the username from the compromised machine.


### T1040 - Network Sniffing

Procedures:

- [G0034] Sandworm Team: Sandworm Team has used intercepter-NG to sniff passwords in network traffic.
- [G0094] Kimsuky: Kimsuky has used the Nirsoft SniffPass network sniffer to obtain passwords sent over non-secure protocols.
- [S0357] Impacket: Impacket can be used to sniff network traffic via an interface or raw socket.
- [S0590] NBTscan: NBTscan can dump and print whole packet content.
- [S0443] MESSAGETAP: MESSAGETAP uses the libpcap library to listen to all traffic and parses network protocols starting with Ethernet and IP layers. It continues parsing protocol layers including SCTP, SCCP, and TCAP and finally extracts SMS message data and routing metadata.
- [S1206] JumbledPath: JumbledPath has the ability to perform packet capture on remote devices via actor-defined jump-hosts.
- [G1047] Velvet Ant: Velvet Ant has used a custom tool, "VELVETTAP", to perform packet capture from compromised F5 BIG-IP devices.
- [G1045] Salt Typhoon: Salt Typhoon has used a variety of tools and techniques to capture packet data between network interfaces.
- [C0028] 2015 Ukraine Electric Power Attack: During the 2015 Ukraine Electric Power Attack, Sandworm Team used BlackEnergy’s network sniffer module to discover user credentials being sent over the network between the local LAN and the power grid’s industrial control systems.
- [S0587] Penquin: Penquin can sniff network traffic to look for packets matching specific conditions.
- [S0661] FoggyWeb: FoggyWeb can configure custom listeners to passively monitor all incoming HTTP GET and POST requests sent to the AD FS server from the intranet/internet and intercept HTTP requests that match the custom URI patterns defined by the actor.
- [S0363] Empire: Empire can be used to conduct packet captures on target hosts.
- [S0174] Responder: Responder captures hashes and credentials that are sent to the system after the name services have been poisoned.
- [S0367] Emotet: Emotet has been observed to hook network APIs to monitor network traffic.
- [C0046] ArcaneDoor: ArcaneDoor included network packet capture and sniffing for data collection in victim environments.


### T1046 - Network Service Discovery

Procedures:

- [S0192] Pupy: Pupy has a built-in module for port scanning.
- [G1017] Volt Typhoon: Volt Typhoon has used commercial tools, LOTL utilities, and appliances already present on the system for network service discovery.
- [G0087] APT39: APT39 has used CrackMapExec and a custom port scanner known as BLUETORCH for network scanning.
- [C0004] CostaRicto: During CostaRicto, the threat actors employed nmap and pscan to scan target environments.
- [G0098] BlackTech: BlackTech has used the SNScan tool to find other potential targets on victim networks.
- [G1043] BlackByte: BlackByte has used tools such as NetScan to enumerate network services in victim environments.
- [G0045] menuPass: menuPass has used tcping.exe, similar to Ping, to probe port status on systems of interest.
- [S0093] Backdoor.Oldrea: Backdoor.Oldrea can use a network scanning module to identify ICS-related ports.
- [G0027] Threat Group-3390: Threat Group-3390 actors use the Hunter tool to conduct network service discovery for vulnerable systems.
- [S0604] Industroyer: Industroyer uses a custom port scanner to map out a network.
- [S0363] Empire: Empire can perform port scans from an infected host.
- [G1030] Agrius: Agrius used the open-source port scanner WinEggDrop to perform detailed scans of hosts of interest in victim networks.
- [G1016] FIN13: FIN13 has utilized `nmap` for reconnaissance efforts. FIN13 has also scanned for internal MS-SQL servers in a compromised network.
- [S0458] Ramsay: Ramsay can scan for systems that are vulnerable to the EternalBlue exploit.
- [C0038] HomeLand Justice: During HomeLand Justice, threat actors executed the Advanced Port Scanner tool on compromised systems.


### T1049 - System Network Connections Discovery

Procedures:

- [S0532] Lucifer: Lucifer can identify the IP and port numbers for all remote connections from the compromised host.
- [S0094] Trojan.Karagany: Trojan.Karagany can use netstat to collect a list of network connections.
- [S0638] Babuk: Babuk can use “WNetOpenEnumW” and “WNetEnumResourceW” to enumerate files in network resources for encryption.
- [G0082] APT38: APT38 installed a port monitoring tool, MAPMAKER, to print the active TCP connections on the local system.
- [G0045] menuPass: menuPass has used net use to conduct connectivity checks to machines.
- [S0445] ShimRatReporter: ShimRatReporter used the Windows function GetExtendedUdpTable to detect connected UDP endpoints.
- [S0251] Zebrocy: Zebrocy uses netstat -aon to gather network connection information.
- [S0378] PoshC2: PoshC2 contains an implementation of netstat to enumerate TCP and UDP connections.
- [G0033] Poseidon Group: Poseidon Group obtains and saves information about victim network interfaces and addresses.
- [S0125] Remsec: Remsec can obtain a list of active connections and open ports.
- [C0014] Operation Wocao: During Operation Wocao, threat actors collected a list of open connections on the infected system using `netstat` and checks whether it has an internet connection.
- [S0237] GravityRAT: GravityRAT uses the netstat command to find open ports on the victim’s machine.
- [S0104] netstat: netstat can be used to enumerate local network connections, including active TCP connections and other network statistics.
- [S0356] KONNI: KONNI has used net session on the victim's machine.
- [G0139] TeamTNT: TeamTNT has run netstat -anp to search for rival malware connections. TeamTNT has also used `libprocesshider` to modify /etc/ld.so.preload.


### T1057 - Process Discovery

Procedures:

- [S0091] Epic: Epic uses the tasklist /v command to obtain a list of processes.
- [S0670] WarzoneRAT: WarzoneRAT can obtain a list of processes on a compromised host.
- [S0267] FELIXROOT: FELIXROOT collects a list of running processes.
- [C0001] Frankenstein: During Frankenstein, the threat actors used Empire to obtain a list of all running processes.
- [G0112] Windshift: Windshift has used malware to enumerate active processes.
- [S0562] SUNSPOT: SUNSPOT monitored running processes for instances of MsBuild.exe by hashing the name of each running process and comparing it to the corresponding value 0x53D525. It also extracted command-line arguments and individual arguments from the running MsBuild.exe process to identify the directory path of the Orion software Visual Studio solution.
- [S0142] StreamEx: StreamEx has the ability to enumerate processes.
- [S0456] Aria-body: Aria-body has the ability to enumerate loaded modules for a process..
- [G1017] Volt Typhoon: Volt Typhoon has enumerated running processes on targeted systems including through the use of Tasklist.
- [S0149] MoonWind: MoonWind has a command to return a list of running processes.
- [S0251] Zebrocy: Zebrocy uses the tasklist and wmic process get Capture, ExecutablePath commands to gather the processes running on the system.
- [S0581] IronNetInjector: IronNetInjector can identify processes via C# methods such as GetProcessesByName and running Tasklist with the Python os.popen function.
- [S0277] FruitFly: FruitFly has the ability to list processes on the system.
- [S0351] Cannon: Cannon can obtain a list of processes running on the system.
- [S0451] LoudMiner: LoudMiner used the ps command to monitor the running processes on the system.


### T1069.001 - Permission Groups Discovery: Local Groups

Procedures:

- [G0010] Turla: Turla has used net localgroup and net localgroup Administrators to enumerate group information, including members of the local administrators group.
- [S0201] JPIN: JPIN can obtain the permissions of the victim user.
- [S0060] Sys10: Sys10 collects the group name of the logged-in user and sends it to the C2.
- [S0521] BloodHound: BloodHound can collect information about local groups and members.
- [S0692] SILENTTRINITY: SILENTTRINITY can obtain a list of local groups and members.
- [S1179] Exbyte: Exbyte checks whether the process is running with privileged local access during execution.
- [G0131] Tonto Team: Tonto Team has used the ShowLocalGroupDetails command to identify administrator, user, and guest accounts on a compromised host.
- [S0184] POWRUNER: POWRUNER may collect local group information by running net localgroup administrators or a series of other commands on a victim.
- [C0015] C0015: During C0015, the threat actors used the command `net localgroup "adminstrator" ` to identify accounts with local administrator rights.
- [G1001] HEXANE: HEXANE has run `net localgroup` to enumerate local groups.
- [C0014] Operation Wocao: During Operation Wocao, threat actors used the command `net localgroup administrators` to list all administrators part of a local group.
- [S0650] QakBot: QakBot can use net localgroup to enable discovery of local groups.
- [S0154] Cobalt Strike: Cobalt Strike can use net localgroup to list local groups on a system.
- [S0039] Net: Commands such as net group and net localgroup can be used in Net to gather information about and manipulate groups.
- [S0378] PoshC2: PoshC2 contains modules, such as Get-LocAdm for enumerating permission groups.

### T1069.002 - Permission Groups Discovery: Domain Groups

Procedures:

- [S0236] Kwampirs: Kwampirs collects a list of domain groups with the command net localgroup /domain.
- [G1004] LAPSUS$: LAPSUS$ has used the AD Explorer tool to enumerate groups on a victim's network.
- [S0039] Net: Commands such as net group /domain can be used in Net to gather information about and manipulate groups.
- [S0521] BloodHound: BloodHound can collect information about domain groups and members.
- [S0692] SILENTTRINITY: SILENTTRINITY can use `System.DirectoryServices` namespace to retrieve domain group information.
- [C0024] SolarWinds Compromise: During the SolarWinds Compromise, APT29 used AdFind to enumerate domain groups.
- [S1138] Gootloader: Gootloader can determine if a targeted system is part of an Active Directory domain by expanding the %USERDNSDOMAIN% environment variable.
- [G1022] ToddyCat: ToddyCat has executed `net group "domain admins" /dom` for discovery on compromised machines.
- [S0417] GRIFFON: GRIFFON has used a reconnaissance module that can be used to retrieve Windows domain membership information.
- [G1017] Volt Typhoon: Volt Typhoon has run `net group` in compromised environments to discover domain groups.
- [G0049] OilRig: OilRig has used net group /domain, net group “domain admins” /domain, and net group “Exchange Trusted Subsystem” /domain to find domain group permission settings.
- [S0552] AdFind: AdFind can enumerate domain groups.
- [S0154] Cobalt Strike: Cobalt Strike can identify targets by querying account groups on a domain contoller.
- [G0046] FIN7: FIN7 has used the command `net group "domain admins" /domain` to enumerate domain groups.
- [S0184] POWRUNER: POWRUNER may collect domain group information by running net group /domain or a series of other commands on a victim.

### T1069.003 - Permission Groups Discovery: Cloud Groups

Procedures:

- [C0027] C0027: During C0027, Scattered Spider accessed Azure AD to download bulk lists of group members and their Active Directory attributes.
- [S0684] ROADTools: ROADTools can enumerate Azure AD groups.
- [S0677] AADInternals: AADInternals can enumerate Azure AD groups.
- [S1091] Pacu: Pacu can enumerate IAM permissions.


### T1082 - System Information Discovery

Procedures:

- [S0339] Micropsia: Micropsia gathers the hostname and OS version from the victim’s machine.
- [S0385] njRAT: njRAT enumerates the victim operating system and computer name during the initial infection.
- [S1111] DarkGate: DarkGate uses the Delphi methods Sysutils::DiskSize and GlobalMemoryStatusEx to collect disk size and physical memory as part of the malware's anti-analysis checks for running in a virtualized environment. DarkGate will gather various system information such as domain, display adapter description, operating system type and version, processor type, and RAM amount.
- [S0266] TrickBot: TrickBot gathers the OS version, machine name, CPU type, amount of RAM available, and UEFI/BIOS firmware information from the victim’s machine.
- [S0553] MoleNet: MoleNet can collect information about the about the system.
- [S0388] YAHOYAH: YAHOYAH checks for the system’s Windows OS version and hostname.
- [S0464] SYSCON: SYSCON has the ability to use Systeminfo to identify system information.
- [S0130] Unknown Logger: Unknown Logger can obtain information about the victim computer name, physical memory, country, and date.
- [S1151] ZeroCleare: ZeroCleare can use the `IOCTL_DISK_GET_DRIVE_GEOMETRY_EX`, `IOCTL_DISK_GET_DRIVE_GEOMETRY`, and `IOCTL_DISK_GET_LENGTH_INFO` system calls to compute disk size.
- [S1039] Bumblebee: Bumblebee can enumerate the OS version and domain on a targeted system.
- [S0237] GravityRAT: GravityRAT collects the MAC address, computer name, and CPU information.
- [S0211] Linfo: Linfo creates a backdoor through which remote attackers can retrieve system information.
- [S0250] Koadic: Koadic can obtain the OS version and build, computer name, and processor architecture from a compromised host.
- [S0634] EnvyScout: EnvyScout can determine whether the ISO payload was received by a Windows or iOS device.
- [S0674] CharmPower: CharmPower can enumerate the OS version and computer name on a targeted system.


### T1083 - File and Directory Discovery

Procedures:

- [S0069] BLACKCOFFEE: BLACKCOFFEE has the capability to enumerate files.
- [S0229] Orz: Orz can gather victim drive information.
- [S0438] Attor: Attor has a plugin that enumerates files with specific extensions on all hard disk drives and stores file information in encrypted log files.
- [S0136] USBStealer: USBStealer searches victim drives for files matching certain extensions (“.skr”,“.pkr” or “.key”) or names.
- [S0461] SDBbot: SDBbot has the ability to get directory listings or drive information on a compromised host.
- [S0599] Kinsing: Kinsing has used the find command to search for specific files.
- [S1025] Amadey: Amadey has searched for folders associated with antivirus software.
- [S1065] Woody RAT: Woody RAT can list all files and their associated attributes, including filename, type, owner, creation time, last access time, last write time, size, and permissions.
- [S0013] PlugX: PlugX has a module to enumerate drives and find files recursively.
- [S1129] Akira: Akira examines files prior to encryption to determine if they meet requirements for encryption and can be encrypted by the ransomware. These checks are performed through native Windows functions such as GetFileAttributesW.
- [S0180] Volgmer: Volgmer can list directories on a victim.
- [G1017] Volt Typhoon: Volt Typhoon has enumerated directories containing vulnerability testing and cyber related content and facilities data such as construction drawings.
- [S0598] P.A.S. Webshell: P.A.S. Webshell has the ability to list files and file characteristics including extension, size, ownership, and permissions.
- [S0534] Bazar: Bazar can enumerate the victim's desktop.
- [S0115] Crimson: Crimson contains commands to list files and directories, as well as search for files matching certain extensions from a defined list.


### T1087.001 - Account Discovery: Local Account

Procedures:

- [S0452] USBferry: USBferry can use net user to gather information about local accounts.
- [S0331] Agent Tesla: Agent Tesla can collect account information from the victim’s machine.
- [S0236] Kwampirs: Kwampirs collects a list of accounts with the command net users.
- [G0004] Ke3chang: Ke3chang performs account discovery using commands such as net localgroup administrators and net group "REDACTED" /domain on specific permissions groups.
- [S0039] Net: Commands under net user can be used in Net to gather information about and manipulate user accounts.
- [G1009] Moses Staff: Moses Staff has collected the administrator username from a compromised host.
- [S0196] PUNCHBUGGY: PUNCHBUGGY can gather user names.
- [S1146] MgBot: MgBot includes modules for identifying local administrator accounts on victim systems.
- [S0223] POWERSTATS: POWERSTATS can retrieve usernames from compromised hosts.
- [S0038] Duqu: The discovery modules used with Duqu can collect information on accounts and permissions.
- [S0049] GeminiDuke: GeminiDuke collects information on local user accounts from the victim.
- [S0165] OSInfo: OSInfo enumerates local and domain users
- [S0063] SHOTPUT: SHOTPUT has a command to retrieve information about connected users.
- [G0049] OilRig: OilRig has run net user, net user /domain, net group “domain admins” /domain, and net group “Exchange Trusted Subsystem” /domain to get account listings on a victim.
- [S0378] PoshC2: PoshC2 can enumerate local and domain user account information.

### T1087.002 - Account Discovery: Domain Account

Procedures:

- [S1159] DUSTTRAP: DUSTTRAP can enumerate domain accounts.
- [C0024] SolarWinds Compromise: During the SolarWinds Compromise, APT29 used PowerShell to discover domain accounts by exectuing `Get-ADUser` and `Get-ADGroupMember`.
- [S0516] SoreFang: SoreFang can enumerate domain accounts via net.exe user /domain.
- [S0039] Net: Net commands used with the /domain flag can be used to gather information about and manipulate user accounts on the current domain.
- [G1016] FIN13: FIN13 can identify user accounts associated with a Service Principal Name and query Service Principal Names within the domain by utilizing the following scripts: `GetUserSPNs.vbs` and `querySpn.vbs`.
- [S0534] Bazar: Bazar has the ability to identify domain administrator accounts.
- [G0037] FIN6: FIN6 has used Metasploit’s PsExec NTDSGRAB module to obtain a copy of the victim's Active Directory database.
- [S0488] CrackMapExec: CrackMapExec can enumerate the domain user accounts on a targeted system.
- [S1146] MgBot: MgBot includes modules for collecting information on Active Directory domain accounts.
- [G0096] APT41: APT41 used built-in net commands to enumerate domain administrator users.
- [G0004] Ke3chang: Ke3chang performs account discovery using commands such as net localgroup administrators and net group "REDACTED" /domain on specific permissions groups.
- [G1015] Scattered Spider: Scattered Spider leverages legitimate domain accounts to gain access to the target environment.
- [S0018] Sykipot: Sykipot may use net group "domain admins" /domain to display accounts in the "domain admins" permissions group and net localgroup "administrators" to list local system administrator group membership.
- [S0635] BoomBox: BoomBox has the ability to execute an LDAP query to enumerate the distinguished name, SAM account name, and display name for all domain users.
- [G0030] Lotus Blossom: Lotus Blossom has used `net` commands and tools such as AdFind to profile domain accounts associated with victim machines and make Active Directory queries.

### T1087.003 - Account Discovery: Email Account

Procedures:

- [G0092] TA505: TA505 has used the tool EmailStealer to steal and send lists of e-mail addresses to a remote server.
- [G0059] Magic Hound: Magic Hound has used Powershell to discover email accounts.
- [S0531] Grandoreiro: Grandoreiro can parse Outlook .pst files to extract e-mail addresses.
- [G1039] RedCurl: RedCurl has collected information about email accounts.
- [G0034] Sandworm Team: Sandworm Team used malware to enumerate email settings, including usernames and passwords, from the M.E.Doc application.
- [C0027] C0027: During C0027, Scattered Spider accessed Azure AD to identify email addresses.
- [S0093] Backdoor.Oldrea: Backdoor.Oldrea collects address book information from Outlook.
- [S0266] TrickBot: TrickBot collects email addresses from Outlook.
- [S0681] Lizar: Lizar can collect email accounts from Microsoft Outlook and Mozilla Thunderbird.
- [S0358] Ruler: Ruler can be used to enumerate Exchange users and dump the GAL.
- [S0413] MailSniper: MailSniper can be used to obtain account names from Exchange and Office 365 using the Get-GlobalAddressList cmdlet.
- [S0367] Emotet: Emotet has been observed leveraging a module that can scrape email addresses from Outlook.
- [C0038] HomeLand Justice: During HomeLand Justice, threat actors used compromised Exchange accounts to search mailboxes for administrator accounts.
- [S0635] BoomBox: BoomBox can execute an LDAP query to discover e-mail accounts for domain users.

### T1087.004 - Account Discovery: Cloud Account

Procedures:

- [C0027] C0027: During C0027, Scattered Spider accessed Azure AD to download bulk lists of group members and to identify privileged users, along with the email addresses and AD attributes.
- [S0684] ROADTools: ROADTools can enumerate Azure AD users.
- [S0677] AADInternals: AADInternals can enumerate Azure AD users.
- [G0016] APT29: APT29 has conducted enumeration of Azure AD accounts.
- [S1091] Pacu: Pacu can enumerate IAM users, roles, and groups.


### T1120 - Peripheral Device Discovery

Procedures:

- [S1139] INC Ransomware: INC Ransomware can identify external USB and hard drives for encryption and printers to print ransom notes.
- [G0020] Equation: Equation has used tools with the functionality to search for specific information about the attached hard drive that could be used to identify and overwrite the firmware.
- [C0012] Operation CuckooBees: During Operation CuckooBees, the threat actors used the `fsutil fsinfo drives` command as part of their advanced reconnaissance.
- [G0067] APT37: APT37 has a Bluetooth device harvester, which uses Windows Bluetooth APIs to find information on connected Bluetooth devices.
- [S0283] jRAT: jRAT can map UPnP ports.
- [S0538] Crutch: Crutch can monitor for removable drives being plugged into the compromised machine.
- [S1044] FunnyDream: The FunnyDream FilepakMonitor component can detect removable drive insertion.
- [S1149] CHIMNEYSWEEP: CHIMNEYSWEEP can monitor for removable drives.
- [S0385] njRAT: njRAT will attempt to detect if the victim system has a camera during the initial infection. njRAT can also detect any removable drives connected to the system.
- [S1026] Mongall: Mongall can identify removable media attached to compromised hosts.
- [S0113] Prikormka: A module in Prikormka collects information on available printers and disk drives.
- [S0366] WannaCry: WannaCry contains a thread that will attempt to scan for new attached drives every few seconds. If one is identified, it will encrypt the files on the attached device.
- [S0251] Zebrocy: Zebrocy enumerates information about connected storage devices.
- [S0148] RTM: RTM can obtain a list of smart card readers attached to the victim.
- [S0644] ObliqueRAT: ObliqueRAT can discover pluggable/removable drives to extract files from.


### T1124 - System Time Discovery

Procedures:

- [S0140] Shamoon: Shamoon obtains the system time and will only activate if it is greater than a preset date.
- [S1178] ShrinkLocker: ShrinkLocker retrieves a system timestamp that is used in generating an encryption key.
- [S0373] Astaroth: Astaroth collects the timestamp from the infected machine.
- [S0251] Zebrocy: Zebrocy gathers the current time zone and date information from the system.
- [S0596] ShadowPad: ShadowPad has collected the current date and time of the victim system.
- [S0011] Taidoor: Taidoor can use GetLocalTime and GetSystemTime to collect system time.
- [S0396] EvilBunny: EvilBunny has used the API calls NtQuerySystemTime, GetSystemTimeAsFileTime, and GetTickCount to gather time metrics as part of its checks to see if the malware is running in a sandbox.
- [S0098] T9000: T9000 gathers and beacons the system time during installation.
- [S1051] KEYPLUG: KEYPLUG can obtain the current tick count of an infected computer.
- [G0121] Sidewinder: Sidewinder has used tools to obtain the current system time.
- [S0039] Net: The net time command can be used in Net to determine the local or remote system time.
- [S0615] SombRAT: SombRAT can execute getinfo to discover the current time on a compromised host.
- [S0091] Epic: Epic uses the net time command to get the system time from the machine and collect the current date and time zone information.
- [S0678] Torisma: Torisma can collect the current time on a victim machine.
- [C0012] Operation CuckooBees: During Operation CuckooBees, the threat actors used the `net time` command as part of their advanced reconnaissance.


### T1135 - Network Share Discovery

Procedures:

- [S1081] BADHATCH: BADHATCH can check a user's access to the C$ share on a compromised machine.
- [S1180] BlackByte Ransomware: BlackByte Ransomware can identify network shares connected to the victim machine.
- [S0458] Ramsay: Ramsay can scan for network drives which may contain documents for collection.
- [C0015] C0015: During C0015, the threat actors executed the PowerView ShareFinder module to identify open shares.
- [S0575] Conti: Conti can enumerate remote open SMB network shares using NetShareEnum().
- [G0131] Tonto Team: Tonto Team has used tools such as NBTscan to enumerate network shares.
- [S0192] Pupy: Pupy can list local and remote shared drives and folders over SMB.
- [S0534] Bazar: Bazar can enumerate shared drives on the domain.
- [S1160] Latrodectus: Latrodectus can run `C:\Windows\System32\cmd.exe /c net view /all` to discover network shares.
- [S0625] Cuba: Cuba can discover shared resources using the NetShareEnum API call.
- [S0236] Kwampirs: Kwampirs collects a list of network shares with the command net share.
- [S0650] QakBot: QakBot can use net share to identify network shares for use in lateral movement.
- [G0087] APT39: APT39 has used the post exploitation tool CrackMapExec to enumerate network shares.
- [S0692] SILENTTRINITY: SILENTTRINITY can enumerate shares on a compromised host.
- [S0659] Diavol: Diavol has a `ENMDSKS` command to enumerates available network shares.


### T1201 - Password Policy Discovery

Procedures:

- [S0039] Net: The net accounts and net accounts /domain commands with Net can be used to obtain password policy information.
- [S0488] CrackMapExec: CrackMapExec can discover the password policies applied to the target system.
- [C0012] Operation CuckooBees: During Operation CuckooBees, the threat actors used the `net accounts` command as part of their advanced reconnaissance.
- [G0049] OilRig: OilRig has used net.exe in a script with net accounts /domain to find the password policy of a domain.
- [G0114] Chimera: Chimera has used the NtdsAudit utility to collect information related to accounts and passwords.
- [S0236] Kwampirs: Kwampirs collects password policy information with the command net accounts.
- [G0010] Turla: Turla has used net accounts and net accounts /domain to acquire password policy information.
- [S0378] PoshC2: PoshC2 can use Get-PassPol to enumerate the domain password policy.


### T1217 - Browser Information Discovery

Procedures:

- [S0274] Calisto: Calisto collects information on bookmarks from Google Chrome.
- [S0681] Lizar: Lizar can retrieve browser history and database files.
- [C0044] Juicy Mix: During Juicy Mix, OilRig used the CDumper (Chrome browser) and EDumper (Edge browser) data stealers to collect cookies, browsing history, and credentials.
- [S0409] Machete: Machete retrieves the user profile data (e.g., browsers) from Chrome and Firefox browsers.
- [C0042] Outer Space: During Outer Space, OilRig used a Chrome data dumper named MKG.
- [S1122] Mispadu: Mispadu can monitor browser activity for online banking actions and display full-screen overlay images to block user access to the intended site or present additional data fields.
- [S1012] PowerLess: PowerLess has a browser info stealer module that can read Chrome and Edge browser database files.
- [S0567] Dtrack: Dtrack can retrieve browser history.
- [G0117] Fox Kitten: Fox Kitten has used Google Chrome bookmarks to identify internal resources and assets.
- [G1017] Volt Typhoon: Volt Typhoon has targeted the browsing history of network administrators.
- [G0082] APT38: APT38 has collected browser bookmark information to learn more about compromised hosts, obtain personal information about users, and acquire details about internal network resources.
- [S0673] DarkWatchman: DarkWatchman can retrieve browser history.
- [S1060] Mafalda: Mafalda can collect the contents of the `%USERPROFILE%\AppData\Local\Google\Chrome\User Data\LocalState` file.
- [S0363] Empire: Empire has the ability to gather browser data such as bookmarks and visited sites.
- [S1185] LightSpy: To collect data on the host's Wi-Fi connection history, LightSpy reads the `/Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist` file. It also utilizes Apple's `CWWiFiClient` API to scan for nearby Wi-Fi networks and obtain data on the SSID, security type, and RSSI (signal strength) values.


### T1482 - Domain Trust Discovery

Procedures:

- [S0363] Empire: Empire has modules for enumerating domain trusts.
- [G1043] BlackByte: BlackByte enumerated Active Directory information and trust relationships during operations.
- [S0534] Bazar: Bazar can use Nltest tools to obtain information about the domain.
- [S0483] IcedID: IcedID used Nltest during initial discovery.
- [S1145] Pikabot: Pikabot will gather information concerning the Windows Domain the victim machine is a member of during execution.
- [S0552] AdFind: AdFind can gather information about organizational units (OUs) and domain trusts from Active Directory.
- [S1071] Rubeus: Rubeus can gather information about domain trusts.
- [G1024] Akira: Akira uses the built-in Nltest utility or tools such as AdFind to enumerate Active Directory trusts in victim environments.
- [G0114] Chimera: Chimera has nltest /domain_trusts to identify domain trust relationships.
- [S1124] SocGholish: SocGholish can profile compromised systems to identify domain trust relationships.
- [C0049] Leviathan Australian Intrusions: Leviathan performed Active Directory enumeration of victim environments during Leviathan Australian Intrusions.
- [G0030] Lotus Blossom: Lotus Blossom has used tools such as AdFind to make Active Directory queries.
- [S1146] MgBot: MgBot includes modules for collecting information on local domain users and permissions.
- [S0359] Nltest: Nltest may be used to enumerate trusted domains by using commands such as nltest /domain_trusts.
- [S0650] QakBot: QakBot can run nltest /domain_trusts /all_trusts for domain trust discovery.


### T1497.001 - Virtualization/Sandbox Evasion: System Checks

Procedures:

- [S0650] QakBot: QakBot can check the compromised host for the presence of multiple executables associated with analysis tools and halt execution if any are found.
- [S0354] Denis: Denis ran multiple system checks, looking for processor and register characteristics, to evade emulation and analysis.
- [S0627] SodaMaster: SodaMaster can check for the presence of the Registry key HKEY_CLASSES_ROOT\\Applications\\VMwareHostOpen.exe before proceeding to its main functionality.
- [S0439] Okrum: Okrum's loader can check the amount of physical memory and terminates itself if the host has less than 1.5 Gigabytes of physical memory in total.
- [S0260] InvisiMole: InvisiMole can check for artifacts of VirtualBox, Virtual PC and VMware environment, and terminate itself if they are detected.
- [G0120] Evilnum: Evilnum has used a component called TerraLoader to check certain hardware and file information to detect sandboxed environments.
- [S0024] Dyre: Dyre can detect sandbox analysis environments by inspecting the process list and Registry.
- [C0022] Operation Dream Job: During Operation Dream Job, Lazarus Group used tools that conducted a variety of system checks to detect sandboxes or VMware services.
- [S0438] Attor: Attor can detect whether it is executed in some virtualized or emulated environment by searching for specific artifacts, such as communication with I/O ports and using VM-specific instructions.
- [S1039] Bumblebee: Bumblebee has the ability to search for designated file paths and Registry keys that indicate a virtualized environment from multiple products.
- [S0182] FinFisher: FinFisher obtains the hardware device list and checks if the MD5 of the vendor ID is equal to a predefined list in order to check for sandbox/virtualized environments.
- [S0373] Astaroth: Astaroth can check for Windows product ID's used by sandboxes and usernames and disk serial numbers associated with analyst environments.
- [S0242] SynAck: SynAck checks its directory location in an attempt to avoid launching in a sandbox.
- [S0576] MegaCortex: MegaCortex has checked the number of CPUs in the system to avoid being run in a sandbox or emulator.
- [S0352] OSX_OCEANLOTUS.D: OSX_OCEANLOTUS.D checks a number of system parameters to see if it is being run on real hardware or in a virtual machine environment, such as `sysctl hw.model` and the kernel boot time.

### T1497.002 - Virtualization/Sandbox Evasion: User Activity Based Checks

Procedures:

- [G0012] Darkhotel: Darkhotel has used malware that repeatedly checks the mouse cursor position to determine if a real user is on the system.
- [S0439] Okrum: Okrum loader only executes the payload after the left mouse button has been pressed at least three times, in order to avoid being executed within virtualized or emulated environments.
- [G0046] FIN7: FIN7 used images embedded into document lures that only activate the payload when a user double clicks to avoid sandboxes.
- [S0543] Spark: Spark has used a splash screen to check whether an user actively clicks on the screen before running malicious code.

### T1497.003 - Virtualization/Sandbox Evasion: Time Based Evasion

Procedures:

- [S0565] Raindrop: After initial installation, Raindrop runs a computation to delay execution.
- [S0626] P8RAT: P8RAT has the ability to "sleep" for a specified time to evade detection.
- [S0559] SUNBURST: SUNBURST remained dormant after initial access for a period of up to two weeks.
- [S0574] BendyBear: BendyBear can check for analysis environments and signs of debugging using the Windows API kernel32!GetTickCountKernel32 call.
- [S0554] Egregor: Egregor can perform a long sleep (greater than or equal to 3 minutes) to evade detection.
- [S0611] Clop: Clop has used the sleep command to avoid sandbox detection.
- [S0627] SodaMaster: SodaMaster has the ability to put itself to "sleep" for a specified time.
- [S0660] Clambling: Clambling can wait 30 minutes before initiating contact with C2.
- [S0386] Ursnif: Ursnif has used a 30 minute delay after execution to evade sandbox monitoring tools.
- [S0439] Okrum: Okrum's loader can detect presence of an emulator by using two calls to GetTickCount API, and checking whether the time has been accelerated.
- [S0512] FatDuke: FatDuke can turn itself on or off at random intervals.
- [S1066] DarkTortilla: DarkTortilla can implement the `kernel32.dll` Sleep function to delay execution for up to 300 seconds before implementing persistence or processing an addon package.
- [S1141] LunarWeb: LunarWeb can pause for a number of hours before entering its C2 communication loop.
- [S1039] Bumblebee: Bumblebee has the ability to set a hardcoded and randomized sleep interval.
- [S0115] Crimson: Crimson can determine when it has been installed on a host for at least 15 days before downloading the final payload.


### T1518.001 - Software Discovery: Security Software Discovery

Procedures:

- [G0012] Darkhotel: Darkhotel has searched for anti-malware strings and anti-virus processes running on the system.
- [S1130] Raspberry Robin: Raspberry Robin attempts to identify security software running on the victim machine, such as BitDefender, Avast, and Kaspersky.
- [S0611] Clop: Clop can search for processes with antivirus and antimalware product names.
- [S0469] ABK: ABK has the ability to identify the installed anti-virus product on the compromised host.
- [C0014] Operation Wocao: During Operation Wocao, threat actors used scripts to detect security software.
- [G0121] Sidewinder: Sidewinder has used the Windows service winmgmts:\\.\root\SecurityCenter2 to check installed antivirus products.
- [S0455] Metamorfo: Metamorfo collects a list of installed antivirus software from the victim’s system.
- [S0650] QakBot: QakBot can identify the installed antivirus product on a targeted system.
- [S0339] Micropsia: Micropsia searches for anti-virus software and firewall products installed on the victim’s machine using WMI.
- [G1008] SideCopy: SideCopy uses a loader DLL file to collect AV product names from an infected host.
- [S0115] Crimson: Crimson contains a command to collect information about anti-virus software on the victim.
- [S0330] Zeus Panda: Zeus Panda checks to see if anti-virus, anti-spyware, or firewall products are installed in the victim’s environment.
- [G0112] Windshift: Windshift has used malware to identify installed AV and commonly used forensic and malware analysis tools.
- [G0082] APT38: APT38 has identified security software, configurations, defensive tools, and sensors installed on a compromised system.
- [G0061] FIN8: FIN8 has used Registry keys to detect and avoid executing in potential sandboxes.


### T1526 - Cloud Service Discovery

Procedures:

- [S0677] AADInternals: AADInternals can enumerate information about a variety of cloud services, such as Office 365 and Sharepoint instances or OpenID Configurations.
- [S0684] ROADTools: ROADTools can enumerate Azure AD applications and service principals.
- [S1091] Pacu: Pacu can enumerate AWS services, such as CloudTrail and CloudWatch.


### T1538 - Cloud Service Dashboard

Procedures:

- [G1015] Scattered Spider: Scattered Spider abused AWS Systems Manager Inventory to identify targets on the compromised network prior to lateral movement.


### T1580 - Cloud Infrastructure Discovery

Procedures:

- [G1015] Scattered Spider: Scattered Spider enumerates cloud environments to identify server and backup management infrastructure, resource access, databases and storage containers.
- [S1091] Pacu: Pacu can enumerate AWS infrastructure, such as EC2 instances.


### T1613 - Container and Resource Discovery

Procedures:

- [S0683] Peirates: Peirates can enumerate Kubernetes pods in a given namespace.
- [G0139] TeamTNT: TeamTNT has checked for running containers with docker ps and for specific container names with docker inspect. TeamTNT has also searched for Kubernetes pods running in a local network.
- [S0601] Hildegard: Hildegard has used masscan to search for kubelets and the kubelet API for additional running containers.


### T1614.001 - System Location Discovery: System Language Discovery

Procedures:

- [C0022] Operation Dream Job: During Operation Dream Job, Lazarus Group deployed malware designed not to run on computers set to Korean, Japanese, or Chinese in Windows language preferences.
- [S1153] Cuckoo Stealer: Cuckoo Stealer can check the systems `LANG` environmental variable to prevent infecting devices from Armenia (`hy_AM`), Belarus (`be_BY`), Kazakhstan (`kk_KZ`), Russia (`ru_RU`), and Ukraine (`uk_UA`).
- [S0652] MarkiRAT: MarkiRAT can use the GetKeyboardLayout API to check if a compromised host's keyboard is set to Persian.
- [S0658] XCSSET: XCSSET uses AppleScript to check the host's language and location with the command user locale of (get system info).
- [S0625] Cuba: Cuba can check if Russian language is installed on the infected machine by using the function GetKeyboardLayoutList.
- [G0004] Ke3chang: Ke3chang has used implants to collect the system language ID of a compromised machine.
- [S0696] Flagpro: Flagpro can check whether the target system is using Japanese, Taiwanese, or English through detection of specific Windows Security and Internet Explorer dialog.
- [S0483] IcedID: IcedID used the following command to check the country/language of the active console: ` cmd.exe /c chcp >&2`.
- [S0640] Avaddon: Avaddon checks for specific keyboard layouts and OS languages to avoid targeting Commonwealth of Independent States (CIS) entities.
- [S0449] Maze: Maze has checked the language of the machine with function GetUserDefaultUILanguage and terminated execution if the language matches with an entry in the predefined list.
- [S1122] Mispadu: Mispadu checks and will terminate execution if the compromised system’s language ID is not Spanish or Portuguese.
- [S0543] Spark: Spark has checked the results of the GetKeyboardLayoutList and the language name returned by GetLocaleInfoA to make sure they contain the word “Arabic” before executing.
- [G1043] BlackByte: BlackByte identified system language settings to determine follow-on execution.
- [S0446] Ryuk: Ryuk has been observed to query the registry key HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Nls\Language and the value InstallLanguage. If the machine has the value 0x419 (Russian), 0x422 (Ukrainian), or 0x423 (Belarusian), it stops execution.
- [S1138] Gootloader: Gootloader can determine if a victim's computer is running an operating system with specific language preferences.


### T1615 - Group Policy Discovery

Procedures:

- [S1141] LunarWeb: LunarWeb can capture information on group policy settings
- [C0049] Leviathan Australian Intrusions: Leviathan performed extensive Active Directory enumeration of victim environments during Leviathan Australian Intrusions.
- [S1159] DUSTTRAP: DUSTTRAP can identify victim environment Group Policy information.
- [S0521] BloodHound: BloodHound has the ability to collect local admin information via GPO.
- [G0010] Turla: Turla surveys a system upon check-in to discover Group Policy details using the gpresult command.
- [S0363] Empire: Empire includes various modules for enumerating Group Policy.
- [S0082] Emissary: Emissary has the capability to execute gpresult.


### T1619 - Cloud Storage Object Discovery

Procedures:

- [S1091] Pacu: Pacu can enumerate AWS storage services, such as S3 buckets and Elastic Block Store volumes.
- [S0683] Peirates: Peirates can list AWS S3 buckets.


### T1622 - Debugger Evasion

Procedures:

- [S1213] Lumma Stealer: Lumma Stealer has checked for debugger strings by invoking `GetForegroundWindow` and looks for strings containing “x32dbg”, “x64dbg”, “windbg”, “ollydbg”, “dnspy”, “immunity debugger”, “hyperdbg”, “debug”, “debugger”, “cheat engine”, “cheatengine” and “ida”.
- [S1087] AsyncRAT: AsyncRAT can use the `CheckRemoteDebuggerPresent` function to detect the presence of a debugger.
- [S1200] StealBit: StealBit can detect it is being run in the context of a debugger.
- [S1183] StrelaStealer: StrelaStealer variants include functionality to identify and evade debuggers.
- [S1111] DarkGate: DarkGate checks the BeingDebugged flag in the PEB structure during execution to identify if the malware is being debugged.
- [S1145] Pikabot: Pikabot features several methods to evade debugging by analysts, including checks for active debuggers, the use of breakpoints during execution, and checking various system information items such as system memory and the number of processors.
- [S0240] ROKRAT: ROKRAT can check for debugging tools.
- [S0694] DRATzarus: DRATzarus can use `IsDebuggerPresent` to detect whether a debugger is present on a victim.
- [S1070] Black Basta: The Black Basta dropper can check system flags, CPU registers, CPU instructions, process timing, system libraries, and APIs to determine if a debugger is present.
- [S1018] Saint Bot: Saint Bot has used `is_debugger_present` as part of its environmental checks.
- [S1207] XLoader: XLoader uses anti-debugging mechanisms such as calling `NtQueryInformationProcess` with `InfoClass=7`, referencing `ProcessDebugPort`, to determine if it is being analyzed.
- [S1130] Raspberry Robin: Raspberry Robin leverages anti-debugging mechanisms through the use of ThreadHideFromDebugger.
- [S1202] LockBit 3.0: LockBit 3.0 can check heap memory parameters for indications of a debugger and stop the flow of events to the attached debugger in order to hinder dynamic analysis.
- [C0022] Operation Dream Job: During Operation Dream Job, Lazarus Group used tools that used the `IsDebuggerPresent` call to detect debuggers.
- [S1066] DarkTortilla: DarkTortilla can detect debuggers by using functions such as `DebuggerIsAttached` and `DebuggerIsLogging`. DarkTortilla can also detect profilers by verifying the `COR_ENABLE_PROFILING` environment variable is present and active.


### T1652 - Device Driver Discovery

Procedures:

- [S0376] HOPLIGHT: HOPLIGHT can enumerate device drivers located in the registry at `HKLM\Software\WBEM\WDM`.
- [S1139] INC Ransomware: INC Ransomware can verify the presence of specific drivers on compromised hosts including Microsoft Print to PDF and Microsoft XPS Document Writer.
- [S0125] Remsec: Remsec has a plugin to detect active drivers of some security products.


### T1654 - Log Enumeration

Procedures:

- [G1023] APT5: APT5 has used the BLOODMINE utility to parse and extract information from Pulse Secure Connect logs.
- [G1003] Ember Bear: Ember Bear has enumerated SECURITY and SYSTEM log files during intrusions.
- [G1017] Volt Typhoon: Volt Typhoon has used `wevtutil.exe` and the PowerShell command `Get-EventLog security` to enumerate Windows logs to search for successful logons.
- [G0143] Aquatic Panda: Aquatic Panda enumerated logs related to authentication in Linux environments prior to deleting selective entries for defense evasion purposes.
- [S1091] Pacu: Pacu can collect CloudTrail event histories and CloudWatch logs.
- [S1191] Megazord: Megazord has the ability to print the trace, debug, error, info, and warning logs.
- [S1194] Akira _v2: Akira _v2 can enumerate the trace, debug, error, info, and warning logs on targeted systems.
- [S1159] DUSTTRAP: DUSTTRAP can identify infected system log information.


### T1673 - Virtual Machine Discovery

Procedures:

- [S1096] Cheerscrypt: Cheerscrypt has leveraged `esxcli vm process list` in order to gather a list of running virtual machines to terminate them.

