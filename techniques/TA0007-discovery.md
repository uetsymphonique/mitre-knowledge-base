### T1007 - System Service Discovery
Adversaries may try to gather information about registered local system services. Adversaries may obtain information about services using tools as well as OS utility commands such as sc query, tasklist /svc, systemctl --type=service, and net start. Adversaries may also gather information about schedule tasks via commands such as `schtasks` on Windows or `crontab -l` on Linux and macOS. Adversaries may use the information from System Service Discovery during automated discovery to shape follow-on behaviors, including whether or not the adversary fully infects the target and/or attempts specific actions.
**Detection**
- [AN1326] **[Linux]** Execution of service management commands like `systemctl list-units`, `service --status-all`, or direct reading of `/etc/init.d`.
- [AN1325] **[Windows]** Enumeration of services via native CLI tools (e.g., `sc query`, `tasklist /svc`, `net start`) or API calls via PowerShell and WMI.
- [AN1327] **[macOS]** Discovery via launchctl commands, or process enumeration using `ps aux | grep com.apple.` to identify daemons and services.
**Procedure Examples**
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


### T1010 - Application Window Discovery
Adversaries may attempt to get a listing of open application windows. Window listings could convey information about how the system is used. For example, information about application windows could be used identify potential data to collect as well as identifying security tooling (Security Software Discovery) to evade. Adversaries typically abuse system features for this type of enumeration. For example, they may gather information through native system features such as Command and Scripting Interpreter commands and Native API functions.
**Detection**
- [AN0272] **[Linux]** Scripted or binary usage of X11 utilities (e.g., xdotool, wmctrl) or direct /proc/*/window mappings to discover open GUI windows and active desktops.
- [AN0273] **[macOS]** Processes that utilize AppleScript, `CGWindowListCopyWindowInfo`, or `NSRunningApplication` APIs to list active application windows and foreground processes.
- [AN0271] **[Windows]** Processes using Win32 API calls (e.g., EnumWindows, GetForegroundWindow) or scripting tools (e.g., PowerShell, VBScript) to enumerate open windows. These often appear with reconnaissance or data collection TTPs.
**Procedure Examples**
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


### T1012 - Query Registry
Adversaries may interact with the Windows Registry to gather information about the system, configuration, and installed software. The Registry contains a significant amount of information about the operating system, configuration, software, and security. Information can easily be queried using the Reg utility, though other means to access the Registry exist. Some of the information may help adversaries to further their operation within a network. Adversaries may use the information from Query Registry during automated discovery to shape follow-on behaviors, including whether or not the adversary fully infects the target and/or attempts specific actions.
**Detection**
- [AN0589] **[Windows]** Registry read access associated with suspicious or non-interactive processes querying system config, installed software, or security settings.
**Procedure Examples**
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


### T1016 - System Network Configuration Discovery
Adversaries may look for details about the network configuration and settings, such as IP and/or MAC addresses, of systems they access or through information discovery of remote systems. Several operating system administration utilities exist that can be used to gather this information. Examples include Arp, ipconfig/ifconfig, nbtstat, and route. Adversaries may also leverage a Network Device CLI on network devices to gather information about configurations and settings, such as IP addresses of configured interfaces and static/dynamic routes (e.g. show ip route, show ip interface). On ESXi, adversaries may leverage esxcli to gather network configuration information. For example, the command `esxcli network nic list` will retrieve the MAC address, while `esxcli network ip interface ipv4 get` will retrieve the local IPv4 address. Adversaries may use the information from System Network Configuration Discovery during automated discovery to shape follow-on behaviors, including determining certain access within the target network and what actions to do next.
**Detection**
- [AN0560] **[Linux]** Execution of `ifconfig`, `ip a`, or access to `/proc/net/` indicating collection of local interface and route configuration.
- [AN0561] **[macOS]** Execution of `ifconfig`, `networksetup`, or `system_profiler` to query IP/MAC/interface configuration and status.
- [AN0562] **[ESXi]** Use of `esxcli network` commands (e.g., `esxcli network nic list`, `esxcli network ip interface ipv4 get`) via SSH or hostd to enumerate adapter and IP information.
- [AN0563] **[Network Devices]** CLI-based execution of interface and routing discovery commands (e.g., `show ip interface`, `show arp`, `show route`) over Telnet, SSH, or console.
- [AN0559] **[Windows]** Execution of built-in tools (e.g., ipconfig, route, netsh) or PowerShell/WMI queries to enumerate IP, MAC, interface status, or routing configuration.
**Procedure Examples**
- [S0569] Explosive: Explosive has collected the MAC address from the victim's machine.
- [S0667] Chrommme: Chrommme can enumerate the IP address of a compromised host.
- [S0101] ifconfig: ifconfig can be used to display adapter configuration on Unix systems, including information for TCP/IP, DNS, and DHCP.
- [G1001] HEXANE: HEXANE has used Ping and `tracert` for network discovery.
- [S0603] Stuxnet: Stuxnet collects the IP address of a compromised system.
- [G0129] Mustang Panda: Mustang Panda has used ipconfig and arp to determine network configuration information. Mustang Panda has also utilized SharpNBTScan to scan the victim environment.
- [S0024] Dyre: Dyre has the ability to identify network settings on a compromised host.
- [S0365] Olympic Destroyer: Olympic Destroyer uses API calls to enumerate the infected system's ARP table.
- [S0250] Koadic: Koadic can retrieve the contents of the IP routing table as well as information about the Windows domain.
- [S1145] Pikabot: Pikabot gathers victim network information through commands such as ipconfig and ipconfig /all.


### T1016.001 - System Network Configuration Discovery: Internet Connection Discovery
Adversaries may check for Internet connectivity on compromised systems. This may be performed during automated discovery and can be accomplished in numerous ways such as using Ping, tracert, and GET requests to websites, or performing initial speed testing to confirm bandwidth. Adversaries may use the results and responses from these requests to determine if the system is capable of communicating with their C2 servers before attempting to connect to them. The results may also be used to identify routes, redirectors, and proxy servers.
**Detection**
- [AN1017] **[macOS]** Execution of ping, traceroute, or network utility tools to external destinations; may include `scutil` or system_profiler.
- [AN1015] **[Windows]** Execution of utilities (e.g., ping, tracert, Test-NetConnection) or scripted methods to test Internet connectivity by interacting with external IPs/domains.
- [AN1016] **[Linux]** Execution of ping, traceroute, or curl/wget against public IPs/domains to verify Internet reachability.
- [AN1018] **[ESXi]** Execution of `ping`, `vmkping`, or `curl` from shell or through automation jobs/scripts to verify Internet egress.
**Procedure Examples**
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


### T1016.002 - System Network Configuration Discovery: Wi-Fi Discovery
Adversaries may search for information about Wi-Fi networks, such as network names and passwords, on compromised systems. Adversaries may use Wi-Fi information as part of Account Discovery, Remote System Discovery, and other discovery or Credential Access activity to support both ongoing and future campaigns. Adversaries may collect various types of information about Wi-Fi networks from hosts. For example, on Windows names and passwords of all Wi-Fi networks a device has previously connected to may be available through `netsh wlan show profiles` to enumerate Wi-Fi names and then `netsh wlan show profile “Wi-Fi name” key=clear` to show a Wi-Fi network’s corresponding password. Additionally, names and other details of locally reachable Wi-Fi networks can be discovered using calls to `wlanAPI.dll` Native API functions. On Linux, names and passwords of all Wi-Fi-networks a device has previously connected to may be available in files under ` /etc/NetworkManager/system-connections/`. On macOS, the password of a known Wi-Fi may be identified with ` security find-generic-password -wa wifiname` (requires admin username/password).
**Detection**
- [AN1281] **[Linux]** File access to NetworkManager connection configs and attempts to read PSK credentials from `/etc/NetworkManager/system-connections/*`.
- [AN1280] **[Windows]** Enumeration of saved Wi-Fi profiles and cleartext password retrieval using `netsh wlan` or API-level access to `wlanAPI.dll`.
- [AN1282] **[macOS]** Use of the `security` command or Keychain API to extract known Wi-Fi passwords for target SSIDs.
**Procedure Examples**
- [G0059] Magic Hound: Magic Hound has collected names and passwords of all Wi-Fi networks to which a device has previously connected.
- [C0051] APT28 Nearest Neighbor Campaign: During APT28 Nearest Neighbor Campaign, APT28 collected information on wireless interfaces within range of a compromised system.
- [S1228] PUBLOAD: PUBLOAD has collected information on Wi-Fi networks from victim hosts leveraging `netsh wlan show profiles`, `netsh wlan show interface`, and `netsh wlan show`.
- [S0674] CharmPower: CharmPower can use `netsh wlan show profiles` to list specific Wi-Fi profile details.
- [S0409] Machete: Machete uses the netsh wlan show networks mode=bssid and netsh wlan show interfaces commands to list all nearby WiFi networks and connected interfaces.
- [S0331] Agent Tesla: Agent Tesla can collect names and passwords of all Wi-Fi networks to which a device has previously connected.
- [S0367] Emotet: Emotet can extract names of all locally reachable Wi-Fi networks and then perform a brute-force attack to spread to new networks.


### T1018 - Remote System Discovery
Adversaries may attempt to get a listing of other systems by IP address, hostname, or other logical identifier on a network that may be used for Lateral Movement from the current system. Functionality could exist within remote access tools to enable this, but utilities available on the operating system could also be used such as Ping, net view using Net, or, on ESXi servers, `esxcli network diag ping`. Adversaries may also analyze data from local host files (ex: C:\Windows\System32\Drivers\etc\hosts or /etc/hosts) or other passive means (such as local Arp cache entries) in order to discover the presence of remote systems in an environment. Adversaries may also target discovery of network infrastructure as well as leverage Network Device CLI commands on network devices to gather detailed information about systems within a network (e.g. show cdp neighbors, show arp).
**Detection**
- [AN1583] **[Windows]** Execution of network enumeration utilities (e.g., net.exe, ping.exe, tracert.exe) in short succession, often chained with lateral movement tools or system enumeration commands.
- [AN1585] **[macOS]** Execution of built-in or AppleScript-based system enumeration via `arp`, `netstat`, `ping`, and discovery of `/etc/hosts` contents.
- [AN1586] **[ESXi]** ESXi shell or SSH access issuing `esxcli network diag ping` or viewing routing tables to identify connected hosts.
- [AN1587] **[Network Devices]** Execution of discovery commands like `show cdp neighbors`, `show arp`, and other interface-level introspection on Cisco or Juniper devices.
- [AN1584] **[Linux]** Use of bash scripts or interactive shells to issue sequential ping, arp, or traceroute commands to map remote hosts.
**Procedure Examples**
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


### T1033 - System Owner/User Discovery
Adversaries may attempt to identify the primary user, currently logged in user, set of users that commonly uses a system, or whether a user is actively using the system. They may do this, for example, by retrieving account usernames or by using OS Credential Dumping. The information may be collected in a number of different ways using other Discovery techniques, because user and username details are prevalent throughout a system and include running process ownership, file/directory ownership, session information, and system logs. Adversaries may use the information from System Owner/User Discovery during automated discovery to shape follow-on behaviors, including whether or not the adversary fully infects the target and/or attempts specific actions. Various utilities and commands may acquire this information, including whoami. In macOS and Linux, the currently logged in user can be identified with w and who. On macOS the dscl . list /Users | grep -v '_' command can also be used to enumerate user accounts. Environment variables, such as %USERNAME% and $USER, may also be used to access this information. On network devices, Network Device CLI commands such as `show users` and `show ssh` can be used to display users currently logged into the device.
**Detection**
- [AN0256] **[macOS]** Adversary uses `dscl`, `who`, or environment variables like `$USER` to identify accounts or sessions via Terminal or malicious LaunchAgents.
- [AN0254] **[Windows]** Adversary launches built-in system tools (e.g., whoami, query user, net user) or scripts that enumerate user account information via local execution or remote API queries (e.g., WMI, PowerShell).
- [AN0255] **[Linux]** Adversary runs commands like `whoami`, `id`, `w`, or `cat /etc/passwd` from non-interactive or scripting contexts to enumerate system user details.
- [AN0257] **[Network Devices]** Adversary executes CLI commands like `show users`, `show ssh`, or attempts to dump AAA user lists from routers or switches.
**Procedure Examples**
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


### T1040 - Network Sniffing
Adversaries may passively sniff network traffic to capture information about an environment, including authentication material passed over the network. Network sniffing refers to using the network interface on a system to monitor or capture information sent over a wired or wireless connection. An adversary may place a network interface into promiscuous mode to passively access data in transit over the network, or use span ports to capture a larger amount of data. Data captured via this technique may include user credentials, especially those sent over an insecure, unencrypted protocol. Techniques for name service resolution poisoning, such as LLMNR/NBT-NS Poisoning and SMB Relay, can also be used to capture credentials to websites, proxies, and internal systems by redirecting traffic to an adversary. Network sniffing may reveal configuration details, such as running services, version numbers, and other network characteristics (e.g. IP addresses, hostnames, VLAN IDs) necessary for subsequent Lateral Movement and/or Defense Evasion activities. Adversaries may likely also utilize network sniffing during Adversary-in-the-Middle (AiTM) to passively gain additional knowledge about the environment. In cloud-based environments, adversaries may still be able to use traffic mirroring services to sniff network traffic from virtual machines. For example, AWS Traffic Mirroring, GCP Packet Mirroring, and Azure vTap allow users to define specified instances to collect traffic from and specified targets to send collected traffic to. Often, much of this traffic will be in cleartext due to the use of TLS termination at the load balancer level to reduce the strain of encrypting and decrypting traffic. The adversary can then use exfiltration techniques such as Transfer Data to Cloud Account in order to access the sniffed traffic. On network devices, adversaries may perform network captures using Network Device CLI commands such as `monitor capture`.
**Detection**
- [AN0876] **[Linux]** Correlates interface mode changes to promiscuous with execution of sniffing tools like tcpdump, tshark, or custom pcap libraries. Detects abnormal NIC configurations and unauthorized sniffing from non-root sessions.
- [AN0879] **[Network Devices]** Detects execution of capture commands via CLI (`monitor capture`, `debug packet`, etc.) or unauthorized CLI access followed by logging configuration changes on Cisco/Juniper/Arista gear.
- [AN0877] **[macOS]** Detects enabling of interface sniffing via packet capture tools or AppleScript triggering `tcpdump`. Leverages Unified Logs and process lineage to identify suspicious use of `pfctl`, `tcpdump`, or `libpcap` libraries.
- [AN0878] **[IaaS]** Detects creation of traffic mirroring sessions (e.g., AWS VPC Traffic Mirroring, Azure vTAP) that redirect traffic from critical assets to other virtual instances, often followed by file creation or session establishment.
- [AN0875] **[Windows]** Detects suspicious execution of network monitoring tools (e.g., Wireshark, tshark, Microsoft Message Analyzer), driver loading indicative of promiscuous mode, or non-admin user privilege escalation to access NICs for capture.
**Procedure Examples**
- [G0034] Sandworm Team: Sandworm Team has used intercepter-NG to sniff passwords in network traffic.
- [G0094] Kimsuky: Kimsuky has used the Nirsoft SniffPass network sniffer to obtain passwords sent over non-secure protocols.
- [C0056] RedPenguin: During RedPenguin, UNC3886 used a passive backdoor to act as a libpcap-based packet sniffer.
- [S0357] Impacket: Impacket can be used to sniff network traffic via an interface or raw socket.
- [S0590] NBTscan: NBTscan can dump and print whole packet content.
- [S0443] MESSAGETAP: MESSAGETAP uses the libpcap library to listen to all traffic and parses network protocols starting with Ethernet and IP layers. It continues parsing protocol layers including SCTP, SCCP, and TCAP and finally extracts SMS message data and routing metadata.
- [S1206] JumbledPath: JumbledPath has the ability to perform packet capture on remote devices via actor-defined jump-hosts.
- [G1047] Velvet Ant: Velvet Ant has used a custom tool, "VELVETTAP", to perform packet capture from compromised F5 BIG-IP devices.
- [S1224] CASTLETAP: CASTLETAP has the ability to create a raw promiscuous socket to sniff network traffic.
- [G1045] Salt Typhoon: Salt Typhoon has used a variety of tools and techniques to capture packet data between network interfaces.


### T1046 - Network Service Discovery
Adversaries may attempt to get a listing of services running on remote hosts and local network infrastructure devices, including those that may be vulnerable to remote software exploitation. Common methods to acquire this information include port, vulnerability, and/or wordlist scans using tools that are brought onto a system. Within cloud environments, adversaries may attempt to discover services running on other cloud hosts. Additionally, if the cloud environment is connected to a on-premises environment, adversaries may be able to identify services running on non-cloud systems as well. Within macOS environments, adversaries may use the native Bonjour application to discover services running on other macOS hosts within a network. The Bonjour mDNSResponder daemon automatically registers and advertises a host’s registered services on the network. For example, adversaries can use a mDNS query (such as dns-sd -B _ssh._tcp .) to find other systems broadcasting the ssh service.
**Detection**
- [AN1058] **[Linux]** Detects use of network scanning utilities or scripts performing rapid connections to multiple services or hosts using auditd and netflow/pcap telemetry.
- [AN1059] **[macOS]** Detects Bonjour-based mDNS enumeration or use of system tools (e.g., dns-sd, nmap) to find active services via multicast probing or targeted scans.
- [AN1060] **[Containers]** Detects lateral discovery or container breakout attempts using netcat, curl, or custom binaries probing other services within the same namespace or VPC subnet.
- [AN1057] **[Windows]** Detects processes performing network enumeration (e.g., port scans, service probing) by correlating process creation, socket connections, and sequential destination IP probing within a time window.
**Procedure Examples**
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


### T1049 - System Network Connections Discovery
Adversaries may attempt to get a listing of network connections to or from the compromised system they are currently accessing or from remote systems by querying for information over the network. An adversary who gains access to a system that is part of a cloud-based environment may map out Virtual Private Clouds or Virtual Networks in order to determine what systems and services are connected. The actions performed are likely the same types of discovery techniques depending on the operating system, but the resulting information may include details about the networked cloud environment relevant to the adversary's goals. Cloud providers may have different ways in which their virtual networks operate. Similarly, adversaries who gain access to network devices may also perform similar discovery activities to gather information about connected systems and services. Utilities and commands that acquire this information include netstat, "net use," and "net session" with Net. In Mac and Linux, netstat and lsof can be used to list current connections. who -a and w can be used to show which users are currently logged in, similar to "net session". Additionally, built-in features native to network devices and Network Device CLI may be used (e.g. show ip sockets, show tcp brief). On ESXi servers, the command `esxi network ip connection list` can be used to list active network connections.
**Detection**
- [AN0904] **[Linux]** Detects use of netstat, ss, lsof, or custom shell scripts to list current network connections. Often paired with privilege escalation or staging.
- [AN0905] **[macOS]** Detects shell-based enumeration of active connections using `netstat`, `lsof -i`, or AppleScript-based system discovery.
- [AN0908] **[IaaS]** Detects enumeration of cloud network interfaces, VPCs, subnets, or peer connections using CLI or SDKs (e.g., AWS CLI, Azure CLI, GCloud CLI).
- [AN0907] **[Network Devices]** Detects interactive or automated use of CLI commands like `show ip sockets`, `show tcp brief`, or SNMP queries for active sessions on routers/switches.
- [AN0906] **[ESXi]** Detects shell or API usage of `esxcli network ip connection list` or `netstat` to enumerate ESXi host connections.
- [AN0903] **[Windows]** Detects usage of commands or binaries (e.g., netstat, PowerShell Get-NetTCPConnection) and WMI or API calls to enumerate local or remote network connections.
**Procedure Examples**
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


### T1057 - Process Discovery
Adversaries may attempt to get information about running processes on a system. Information obtained could be used to gain an understanding of common software/applications running on systems within the network. Administrator or otherwise elevated access may provide better process details. Adversaries may use the information from Process Discovery during automated discovery to shape follow-on behaviors, including whether or not the adversary fully infects the target and/or attempts specific actions. In Windows environments, adversaries could obtain details on running processes using the Tasklist utility via cmd or Get-Process via PowerShell. Information about processes can also be extracted from the output of Native API calls such as CreateToolhelp32Snapshot. In Mac and Linux, this is accomplished with the ps command. Adversaries may also opt to enumerate processes via `/proc`. ESXi also supports use of the `ps` command, as well as `esxcli system process list`. On network devices, Network Device CLI commands such as `show processes` can be used to display current running processes.
**Detection**
- [AN0096] **[Linux]** Detects execution of common process enumeration utilities (e.g., ps, top, htop) or access to /proc with suspicious ancestry. Correlates command usage with interactive shell context and user role.
- [AN0095] **[Windows]** Identifies adversary behavior that launches commands or invokes APIs to enumerate active processes (e.g., tasklist.exe, Get-Process, or CreateToolhelp32Snapshot). Detects execution combined with parent process lineage, network session context, or remote origin.
- [AN0098] **[ESXi]** Detects process enumeration using `esxcli system process list` or `ps` on ESXi shell or via unauthorized SSH sessions. Correlates with interactive sessions and abnormal user roles.
- [AN0097] **[macOS]** Monitors execution of ps, top, or launchctl with unusual parent processes or from terminal scripts. Also detects AppleScript-based process listing or `system_profiler SPApplicationsDataType` misuse.
- [AN0099] **[Network Devices]** Monitors CLI-based execution of `show process` or equivalent on routers/switches. Correlates unusual device access, unauthorized roles, or config mode changes.
**Procedure Examples**
- [S0091] Epic: Epic uses the tasklist /v command to obtain a list of processes.
- [S0670] WarzoneRAT: WarzoneRAT can obtain a list of processes on a compromised host.
- [S0267] FELIXROOT: FELIXROOT collects a list of running processes.
- [C0056] RedPenguin: During RedPenguin, UNC3886 used malware capable of reading the PID for the Junos OS snmpd daemon.
- [C0001] Frankenstein: During Frankenstein, the threat actors used Empire to obtain a list of all running processes.
- [G0112] Windshift: Windshift has used malware to enumerate active processes.
- [S0562] SUNSPOT: SUNSPOT monitored running processes for instances of MsBuild.exe by hashing the name of each running process and comparing it to the corresponding value 0x53D525. It also extracted command-line arguments and individual arguments from the running MsBuild.exe process to identify the directory path of the Orion software Visual Studio solution.
- [S0142] StreamEx: StreamEx has the ability to enumerate processes.
- [S0456] Aria-body: Aria-body has the ability to enumerate loaded modules for a process..
- [G1017] Volt Typhoon: Volt Typhoon has enumerated running processes on targeted systems including through the use of Tasklist.


### T1069 - Permission Groups Discovery
Adversaries may attempt to discover group and permission settings. This information can help adversaries determine which user accounts and groups are available, the membership of users in particular groups, and which users and groups have elevated permissions. Adversaries may attempt to discover group permission settings in many different ways. This data may provide the adversary with information about the compromised environment that can be used in follow-on activity and targeting.
**Detection**
- [AN0508] **[Linux]** Detection of group enumeration using commands like 'id', 'groups', or 'getent group', often followed by privilege escalation or SSH lateral movement.
- [AN0507] **[Windows]** Detection of adversary enumeration of domain or local group memberships via native tools such as net.exe, PowerShell, or WMI. This activity may precede lateral movement or privilege escalation.
- [AN0509] **[macOS]** Group membership checks via 'dscl', 'dscacheutil', or 'id', typically executed via terminal or automation scripts.
**Procedure Examples**
- [G0096] APT41: APT41 used net group commands to enumerate various Windows user groups and permissions.
- [S0483] IcedID: IcedID has the ability to identify Workgroup membership.
- [S0335] Carbon: Carbon uses the net group command.
- [C0024] SolarWinds Compromise: During the SolarWinds Compromise, APT29 used the `Get-ManagementRoleAssignment` PowerShell cmdlet to enumerate Exchange management role assignments through an Exchange Management Shell.
- [S0266] TrickBot: TrickBot can identify the groups the user on a compromised host belongs to.
- [S0233] MURKYTOP: MURKYTOP has the capability to retrieve information about groups.
- [G1015] Scattered Spider: Scattered Spider has enumerated the vSphere Admins and ESX Admins groups in targeted environments.
- [G0092] TA505: TA505 has used TinyMet to enumerate members of privileged groups. TA505 has also run net group /domain.
- [G1017] Volt Typhoon: Volt Typhoon has used commercial tools, LOTL utilities, and appliances already present on the system for group and user discovery.
- [S0445] ShimRatReporter: ShimRatReporter gathered the local privileges for the infected host.


### T1069.001 - Permission Groups Discovery: Local Groups
Adversaries may attempt to find local system groups and permission settings. The knowledge of local system permission groups can help adversaries determine which groups exist and which users belong to a particular group. Adversaries may use this information to determine which users have elevated permissions, such as the users found within the local administrators group. Commands such as net localgroup of the Net utility, dscl . -list /Groups on macOS, and groups on Linux can list local groups.
**Detection**
- [AN0319] **[macOS]** Detects use of dscl or id/group commands to enumerate local system groups, often by post-exploitation tools or persistence checks.
- [AN0317] **[Windows]** Detects attempts to enumerate local groups via Net.exe, PowerShell, or native API calls that precede lateral movement or privilege abuse.
- [AN0318] **[Linux]** Detects enumeration of local groups using common binaries (groups, getent, cat /etc/group) or scripting with suspicious lineage.
**Procedure Examples**
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


### T1069.002 - Permission Groups Discovery: Domain Groups
Adversaries may attempt to find domain-level groups and permission settings. The knowledge of domain-level permission groups can help adversaries determine which groups exist and which users belong to a particular group. Adversaries may use this information to determine which users have elevated permissions, such as domain administrators. Commands such as net group /domain of the Net utility, dscacheutil -q group on macOS, and ldapsearch on Linux can list domain-level groups.
**Detection**
- [AN1025] **[Windows]** Detection of domain group enumeration through command-line utilities such as 'net group /domain' or PowerShell cmdlets, followed by suspicious access to API calls or LSASS memory.
- [AN1027] **[macOS]** Enumeration of domain groups using dscacheutil or dscl commands, often following initial login or domain trust queries.
- [AN1026] **[Linux]** Behavioral detection of domain group enumeration via ldapsearch or custom scripts leveraging LDAP over the network.
**Procedure Examples**
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


### T1069.003 - Permission Groups Discovery: Cloud Groups
Adversaries may attempt to find cloud groups and permission settings. The knowledge of cloud permission groups can help adversaries determine the particular roles of users and groups within an environment, as well as which users are associated with a particular group. With authenticated access there are several tools that can be used to find permissions groups. The Get-MsolRole PowerShell cmdlet can be used to obtain roles and permissions groups for Exchange and Office 365 accounts . Azure CLI (AZ CLI) and the Google Cloud Identity Provider API also provide interfaces to obtain permissions groups. The command az ad user get-member-groups will list groups associated to a user account for Azure while the API endpoint GET lists group resources available to a user for Google. In AWS, the commands `ListRolePolicies` and `ListAttachedRolePolicies` allow users to enumerate the policies attached to a role. Adversaries may attempt to list ACLs for objects to determine the owner and other accounts with access to the object, for example, via the AWS GetBucketAcl API . Using this information an adversary can target accounts with permissions to a given object or leverage accounts they have already compromised to access the object.
**Detection**
- [AN0697] **[SaaS]** Monitors API calls and service-specific logs for enumeration of organizational roles, permissions, and group structure, particularly outside of normal admin behavior baselines.
- [AN0696] **[Office Suite]** Identifies unauthorized access or enumeration of administrative roles, security groups, or distribution groups via Exchange/SharePoint/Teams APIs or role discovery scripts.
- [AN0695] **[IaaS]** Detects adversarial use of cloud-native APIs (e.g., AWS IAM, Azure RBAC, GCP Identity) to enumerate cloud group memberships or policy mappings via unauthorized sessions or scripts.
**Procedure Examples**
- [C0027] C0027: During C0027, Scattered Spider accessed Azure AD to download bulk lists of group members and their Active Directory attributes.
- [S0684] ROADTools: ROADTools can enumerate Azure AD groups.
- [S0677] AADInternals: AADInternals can enumerate Azure AD groups.
- [S1091] Pacu: Pacu can enumerate IAM permissions.


### T1082 - System Information Discovery
An adversary may attempt to get detailed information about the operating system and hardware, including version, patches, hotfixes, service packs, and architecture. Adversaries may use this information to shape follow-on behaviors, including whether or not the adversary fully infects the target and/or attempts specific actions. This behavior is distinct from Local Storage Discovery which is an adversary's discovery of local drive, disks and/or volumes. Tools such as Systeminfo can be used to gather detailed system information. If running with privileged access, a breakdown of system data can be gathered through the systemsetup configuration tool on macOS. Adversaries may leverage a Network Device CLI on network devices to gather detailed system information (e.g. show version). On ESXi servers, threat actors may gather system information from various esxcli utilities, such as `system hostname get` and `system version get`. Infrastructure as a Service (IaaS) cloud providers such as AWS, GCP, and Azure allow access to instance and virtual machine information via APIs. Successful authenticated API calls can return data such as the operating system platform and status of a particular instance or the model view of a virtual machine. System Information Discovery combined with information gathered from other forms of discovery and reconnaissance can drive payload development and concealment.
**Detection**
- [AN1455] **[ESXi]** Execution of `esxcli system hostname get`, `esxcli system version get`, or `esxcli hardware` commands through SSH or local shell.
- [AN1457] **[Network Devices]** Execution of `show version`, `show hardware`, or `show system` commands through CLI via SSH or console.
- [AN1452] **[Windows]** Process creation and command-line execution of native system discovery utilities such as `systeminfo`, `hostname`, `wmic`, or use of PowerShell/WMI for system enumeration.
- [AN1454] **[macOS]** Execution of system info utilities like `systemsetup`, `sw_vers`, `uname`, or `sysctl` by terminal or scripted processes.
- [AN1456] **[IaaS]** Use of cloud API calls (e.g., AWS EC2 DescribeInstances, Azure VM Inventory) to enumerate system configurations across assets.
- [AN1453] **[Linux]** Execution of system enumeration commands such as `uname`, `df`, `uptime`, `hostname`, `lscpu`, and `cat /etc/os-release` through local terminal or scripts.
**Procedure Examples**
- [S0339] Micropsia: Micropsia gathers the hostname and OS version from the victim’s machine.
- [S0385] njRAT: njRAT enumerates the victim operating system and computer name during the initial infection.
- [S1111] DarkGate: DarkGate will gather various system information such as domain, display adapter description, operating system type and version, processor type, and RAM amount.
- [S1249] HexEval Loader: HexEval Loader has identified the OS and MAC address of victim device through host fingerprinting scripting.
- [S1245] InvisibleFerret: InvisibleFerret has collected OS type, hostname and system version through the "pay" module. InvisibleFerret has also queried the victim device using Python scripts to obtain the User and Hostname.
- [S0266] TrickBot: TrickBot gathers the OS version, machine name, CPU type, amount of RAM available, and UEFI/BIOS firmware information from the victim’s machine.
- [S0553] MoleNet: MoleNet can collect information about the about the system.
- [S0388] YAHOYAH: YAHOYAH checks for the system’s Windows OS version and hostname.
- [S0464] SYSCON: SYSCON has the ability to use Systeminfo to identify system information.
- [S0130] Unknown Logger: Unknown Logger can obtain information about the victim computer name, physical memory, country, and date.


### T1083 - File and Directory Discovery
Adversaries may enumerate files and directories or may search in specific locations of a host or network share for certain information within a file system. Adversaries may use the information from File and Directory Discovery during automated discovery to shape follow-on behaviors, including whether or not the adversary fully infects the target and/or attempts specific actions. Many command shell utilities can be used to obtain this information. Examples include dir, tree, ls, find, and locate. Custom tools may also be used to gather file and directory information and interact with the Native API. Adversaries may also leverage a Network Device CLI on network devices to gather file and directory information (e.g. dir, show flash, and/or nvram). Some files and directories may require elevated or specific user permissions to access.
**Detection**
- [AN1042] **[macOS]** Execution of file or directory discovery commands (e.g., 'ls', 'find') from terminal or script-based tooling, especially outside normal user workflows.
- [AN1040] **[Windows]** Execution of file enumeration commands (e.g., 'dir', 'tree') from non-standard processes or unusual user contexts, followed by recursive directory traversal or access to sensitive locations.
- [AN1043] **[ESXi]** Execution of esxcli commands to enumerate datastore, configuration files, or directory structures by unauthorized or remote users.
- [AN1041] **[Linux]** Use of file enumeration commands (e.g., 'ls', 'find', 'locate') executed by suspicious users or scripts accessing broad file hierarchies or restricted directories.
- [AN1044] **[Network Devices]** Execution of file discovery commands (e.g., 'dir', 'show flash', 'nvram:') from CLI interfaces, especially by unauthorized users or from abnormal source IPs.
**Procedure Examples**
- [S0069] BLACKCOFFEE: BLACKCOFFEE has the capability to enumerate files.
- [S0229] Orz: Orz can gather victim drive information.
- [S0438] Attor: Attor has a plugin that enumerates files with specific extensions on all hard disk drives and stores file information in encrypted log files.
- [S0136] USBStealer: USBStealer searches victim drives for files matching certain extensions (“.skr”,“.pkr” or “.key”) or names.
- [S0461] SDBbot: SDBbot has the ability to get directory listings or drive information on a compromised host.
- [S0599] Kinsing: Kinsing has used the find command to search for specific files.
- [S1025] Amadey: Amadey has searched for folders associated with antivirus software.
- [S1065] Woody RAT: Woody RAT can list all files and their associated attributes, including filename, type, owner, creation time, last access time, last write time, size, and permissions.
- [S0013] PlugX: PlugX has a module to enumerate drives and find files recursively. PlugX has also checked the path from which it is running for specific parameters prior to execution.
- [S1129] Akira: Akira examines files prior to encryption to determine if they meet requirements for encryption and can be encrypted by the ransomware. These checks are performed through native Windows functions such as GetFileAttributesW.


### T1087 - Account Discovery
Adversaries may attempt to get a listing of valid accounts, usernames, or email addresses on a system or within a compromised environment. This information can help adversaries determine which accounts exist, which can aid in follow-on behavior such as brute-forcing, spear-phishing attacks, or account takeovers (e.g., Valid Accounts). Adversaries may use several methods to enumerate accounts, including abuse of existing tools, built-in commands, and potential misconfigurations that leak account names and roles or permissions in the targeted environment. For examples, cloud environments typically provide easily accessible interfaces to obtain user lists. On hosts, adversaries can use default PowerShell and other command line functionality to identify accounts. Information about email addresses and accounts may also be extracted by searching an infected system’s files.
**Detection**
- [AN1619] **[Office Suite]** Account discovery via VBA macros, COM objects, or embedded scripting.
- [AN1614] **[macOS]** Detection of user account enumeration through tools like dscl, dscacheutil, or loginshell enumeration via command-line.
- [AN1615] **[IaaS]** Detection of API calls listing users, IAM roles, or groups in cloud environments.
- [AN1613] **[Linux]** Enumeration of users and groups through suspicious shell commands or unauthorized access to /etc/passwd or /etc/shadow.
- [AN1617] **[ESXi]** Account enumeration via esxcli, vim-cmd, or API calls to vSphere.
- [AN1616] **[Identity Provider]** Enumeration of user or role objects via IdP API endpoints or LDAP queries.
- [AN1618] **[SaaS]** Account enumeration via bulk access to user directory features or hidden APIs.
- [AN1612] **[Windows]** Detection of suspicious enumeration of local or domain accounts via command-line tools, WMI, or scripts.
**Procedure Examples**
- [G0143] Aquatic Panda: Aquatic Panda used the last command in Linux environments to identify recently logged-in users on victim machines.
- [G1015] Scattered Spider: Scattered Spider has identified vSphere administrator accounts.
- [S0445] ShimRatReporter: ShimRatReporter listed all non-privileged and privileged accounts available on the machine.
- [S1065] Woody RAT: Woody RAT can identify administrator accounts on an infected machine.
- [S1229] Havoc: Havoc can identify privileged user accounts on infected systems.
- [S1239] TONESHELL: TONESHELL included functionality to retrieve a list of user accounts.
- [S0658] XCSSET: XCSSET attempts to discover accounts from various locations such as a user's Evernote, AppleID, Telegram, Skype, and WeChat data.
- [C0024] SolarWinds Compromise: During the SolarWinds Compromise, APT29 obtained a list of users and their roles from an Exchange server using `Get-ManagementRoleAssignment`.
- [G1016] FIN13: FIN13 has enumerated all users and their roles from a victim's main treasury system.


### T1087.001 - Account Discovery: Local Account
Adversaries may attempt to get a listing of local system accounts. This information can help adversaries determine which local accounts exist on a system to aid in follow-on behavior. Commands such as net user and net localgroup of the Net utility and id and groups on macOS and Linux can list local users and groups. On Linux, local users can also be enumerated through the use of the /etc/passwd file. On macOS, the dscl . list /Users command can be used to enumerate local accounts. On ESXi servers, the `esxcli system account list` command can list local user accounts.
**Detection**
- [AN0846] **[Windows]** Adversary enumeration of local user accounts using Net.exe, WMI, or PowerShell.
- [AN0847] **[Linux]** Enumeration of local users or groups via file access (/etc/passwd) or commands like id, groups.
- [AN0848] **[macOS]** Enumeration of macOS local users using dscl, id, dscacheutil, or /etc/passwd access.
- [AN0849] **[ESXi]** Enumeration of local ESXi accounts using esxcli or vSphere API from unauthorized sessions.
**Procedure Examples**
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


### T1087.002 - Account Discovery: Domain Account
Adversaries may attempt to get a listing of domain accounts. This information can help adversaries determine which domain accounts exist to aid in follow-on behavior such as targeting specific accounts which possess particular privileges. Commands such as net user /domain and net group /domain of the Net utility, dscacheutil -q group on macOS, and ldapsearch on Linux can list domain users and groups. PowerShell cmdlets including Get-ADUser and Get-ADGroupMember may enumerate members of Active Directory groups.
**Detection**
- [AN0364] **[Linux]** Domain account enumeration using ldapsearch, samba tools (e.g., 'wbinfo -u'), or winbindd lookups.
- [AN0363] **[Windows]** Adversary enumeration of domain accounts using net.exe, PowerShell, WMI, or LDAP queries from non-domain controllers or non-admin endpoints.
- [AN0365] **[macOS]** Domain group and user enumeration via dscl or dscacheutil, or queries to directory services from non-admin endpoints.
**Procedure Examples**
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


### T1087.003 - Account Discovery: Email Account
Adversaries may attempt to get a listing of email addresses and accounts. Adversaries may try to dump Exchange address lists such as global address lists (GALs). In on-premises Exchange and Exchange Online, the Get-GlobalAddressList PowerShell cmdlet can be used to obtain email addresses and accounts from a domain using an authenticated session. In Google Workspace, the GAL is shared with Microsoft Outlook users through the Google Workspace Sync for Microsoft Outlook (GWSMO) service. Additionally, the Google Workspace Directory allows for users to get a listing of other users within the organization.
**Detection**
- [AN0641] **[Windows]** Enumeration of global address lists or email account metadata via PowerShell cmdlets (e.g., Get-GlobalAddressList) or MAPI/RPC from non-admin, non-mailserver systems.
- [AN0642] **[Office Suite]** Suspicious querying of organization-wide directory data via Google Workspace Directory API or Outlook GAL sync in high volume from abnormal users, service accounts, or unknown device contexts.
**Procedure Examples**
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


### T1087.004 - Account Discovery: Cloud Account
Adversaries may attempt to get a listing of cloud accounts. Cloud accounts are those created and configured by an organization for use by users, remote support, services, or for administration of resources within a cloud service provider or SaaS application. With authenticated access there are several tools that can be used to find accounts. The Get-MsolRoleMember PowerShell cmdlet can be used to obtain account names given a role or permissions group in Office 365. The Azure CLI (AZ CLI) also provides an interface to obtain user accounts with authenticated access to a domain. The command az ad user list will list all users within a domain. The AWS command aws iam list-users may be used to obtain a list of users in the current account while aws iam list-roles can obtain IAM roles that have a specified path prefix. In GCP, gcloud iam service-accounts list and gcloud projects get-iam-policy may be used to obtain a listing of service accounts and users in a project.
**Detection**
- [AN1090] **[SaaS]** Access to organizational directories via Google Workspace Directory API, Slack SCIM, or Okta SCIM by apps or identities outside normal roles.
- [AN1089] **[Office Suite]** Bulk enumeration of cloud user email identities through `Get-Recipient`, `Get-Mailbox`, `Get-User`, or Graph API directory listings by abnormal accounts or suspicious sessions.
- [AN1088] **[IaaS]** Use of AWS CLI (`aws iam list-users`, `list-roles`), Azure CLI (`az ad user list`), or GCP CLI (`gcloud iam service-accounts list`) from endpoints or cloud shells where such activity is unexpected.
- [AN1087] **[Identity Provider]** Enumeration of identity roles and users via API calls such as `Get-MsolRoleMember`, `az ad user list`, or Graph API tokens from unauthorized users or automation accounts.
**Procedure Examples**
- [C0027] C0027: During C0027, Scattered Spider accessed Azure AD to download bulk lists of group members and to identify privileged users, along with the email addresses and AD attributes.
- [G1053] Storm-0501: Storm-0501 has conducted enumeration of users, roles, and resources within victim Azure tenants using the tool Azurehound.
- [S0684] ROADTools: ROADTools can enumerate Azure AD users.
- [S0677] AADInternals: AADInternals can enumerate Azure AD users.
- [G0016] APT29: APT29 has conducted enumeration of Azure AD accounts.
- [S1091] Pacu: Pacu can enumerate IAM users, roles, and groups.


### T1120 - Peripheral Device Discovery
Adversaries may attempt to gather information about attached peripheral devices and components connected to a computer system. Peripheral devices could include auxiliary resources that support a variety of functionalities such as keyboards, printers, cameras, smart card readers, or removable storage. The information may be used to enhance their awareness of the system and network environment or may be used for further actions.
**Detection**
- [AN1355] **[macOS]** Execution of system utilities like 'system_profiler' and 'ioreg' to enumerate hardware components or USB devices, particularly if followed by clipboard, file, or network activity.
- [AN1353] **[Windows]** Suspicious enumeration of attached peripherals via WMI, PowerShell, or low-level API calls potentially chained with removable device interactions.
- [AN1354] **[Linux]** Enumeration of USB and other peripheral hardware via udevadm, lshw, or /sys or /proc interfaces in proximity to collection or mounting behavior.
**Procedure Examples**
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


### T1124 - System Time Discovery
An adversary may gather the system time and/or time zone settings from a local or remote system. The system time is set and stored by services, such as the Windows Time Service on Windows or systemsetup on macOS. These time settings may also be synchronized between systems and services in an enterprise network, typically accomplished with a network time server within a domain. System time information may be gathered in a number of ways, such as with Net on Windows by performing net time \\hostname to gather the system time on a remote system. The victim's time zone may also be inferred from the current system time or gathered by using w32tm /tz. In addition, adversaries can discover device uptime through functions such as GetTickCount() to determine how long it has been since the system booted up. On network devices, Network Device CLI commands such as `show clock detail` can be used to see the current time configuration. On ESXi servers, `esxcli system clock get` can be used for the same purpose. In addition, system calls – such as time() – have been used to collect the current time on Linux devices. On macOS systems, adversaries may use commands such as systemsetup -gettimezone or timeIntervalSinceNow to gather current time zone information or current date and time. This information could be useful for performing other techniques, such as executing a file with a Scheduled Task/Job, or to discover locality information based on time zone to assist in victim targeting (i.e. System Location Discovery). Adversaries may also use knowledge of system time as part of a time bomb, or delaying execution until a specified date/time.
**Detection**
- [AN0432] **[macOS]** Process/script execution of systemsetup -gettimezone, date, ioreg, or API usage (timeIntervalSinceNow, gettimeofday) followed by time-based scheduling (launchd plist modification) or sleep-based execution.
- [AN0433] **[ESXi]** Interactive or remote shell/API invocation of esxcli system clock get or querying time parameters via hostd/vpxa shortly followed by time/ntp configuration checks or scheduled task creation, executed by non-standard accounts or outside maintenance windows.
- [AN0434] **[Network Devices]** Non-standard or rare users/locations issue CLI commands like "show clock detail" or "show timezone"; optionally followed by configuration of time/timezone or NTP sources. AAA/TACACS+ accounting and syslog correlate execution to identity, source IP, and privilege level.
- [AN0431] **[Linux]** A process (often spawned by a shell, interpreter, or malware implant) executes time discovery via commands (date, timedatectl, hwclock, cat /etc/timezone, /proc/uptime) or direct syscalls (time(), clock_gettime) and is (optionally) followed by scheduled task creation/modification (crontab, at) or conditional sleep logic.
- [AN0430] **[Windows]** Untrusted or unusual process/script (cmd.exe, powershell.exe, w32tm.exe, net.exe, custom binaries) queries system time/timezone (e.g., w32tm /tz, net time \\host, Get-TimeZone, GetTickCount API) and (optionally) is followed within a short window by time-based scheduling or conditional execution (e.g., schtasks /create, at.exe, PowerShell Start-Sleep with large values).
**Procedure Examples**
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


### T1135 - Network Share Discovery
Adversaries may look for folders and drives shared on remote systems as a means of identifying sources of information to gather as a precursor for Collection and to identify potential systems of interest for Lateral Movement. Networks often contain shared network drives and folders that enable users to access file directories on various systems across a network. File sharing over a Windows network occurs over the SMB protocol. Net can be used to query a remote system for available shared drives using the net view \\\\remotesystem command. It can also be used to query shared drives on the local system using net share. For macOS, the sharing -l command lists all shared points used for smb services.
**Detection**
- [AN0514] **[Linux]** CLI tools (smbclient -L, smbmap, rpcclient, nmblookup) or custom scripts enumerate SMB shares on many internal hosts → corresponding SMB connections (445/139) captured by Zeek/Netflow within a short window.
- [AN0515] **[macOS]** Use of native/mac tools (sharing -l, smbutil view, mount_smbfs) or scripts to enumerate SMB shares across many hosts, followed by outbound SMB connections observed in PF/Zeek logs.
- [AN0513] **[Windows]** Process or script enumerates network shares via CLI (net view/net share, PowerShell Get-SmbShare/WMI) or OS APIs (NetShareEnum/ srvsvc.NetShareEnumAll RPC) → bursts of outbound SMB/RPC connections (445/139, \\host\IPC$ / srvsvc) to many hosts inside a short window → optional follow-on file listing or copy operations.
**Procedure Examples**
- [S1081] BADHATCH: BADHATCH can check a user's access to the C$ share on a compromised machine.
- [S1180] BlackByte Ransomware: BlackByte Ransomware can identify network shares connected to the victim machine.
- [S0458] Ramsay: Ramsay can scan for network drives which may contain documents for collection.
- [C0015] C0015: During C0015, the threat actors executed the PowerView ShareFinder module to identify open shares.
- [S0575] Conti: Conti can enumerate remote open SMB network shares using NetShareEnum().
- [G0131] Tonto Team: Tonto Team has used tools such as NBTscan to enumerate network shares.
- [S1244] Medusa Ransomware: Medusa Ransomware has identified networked drives.
- [S0192] Pupy: Pupy can list local and remote shared drives and folders over SMB.
- [S0534] Bazar: Bazar can enumerate shared drives on the domain.
- [S1160] Latrodectus: Latrodectus can run `C:\Windows\System32\cmd.exe /c net view /all` to discover network shares.


### T1201 - Password Policy Discovery
Adversaries may attempt to access detailed information about the password policy used within an enterprise network or cloud environment. Password policies are a way to enforce complex passwords that are difficult to guess or crack through Brute Force. This information may help the adversary to create a list of common passwords and launch dictionary and/or brute force attacks which adheres to the policy (e.g. if the minimum password length should be 8, then not trying passwords such as 'pass123'; not checking for more than 3-4 passwords per account if the lockout is set to 6 as to not lock out accounts). Password policies can be set and discovered on Windows, Linux, and macOS systems via various command shell utilities such as net accounts (/domain), Get-ADDefaultDomainPasswordPolicy, chage -l , cat /etc/pam.d/common-password, and pwpolicy getaccountpolicies . Adversaries may also leverage a Network Device CLI on network devices to discover password policy information (e.g. show aaa, show aaa common-criteria policy all). Password policies can be discovered in cloud environments using available APIs such as GetAccountPasswordPolicy in AWS .
**Detection**
- [AN0459] **[Identity Provider]** Chain: (1) IdP policy/read operations by a principal (e.g., Microsoft Entra/Graph requests to read password or authentication policies); (2) adjacent risky changes (role assignment, app consent) by same principal. Use IdP audit logs.
- [AN0458] **[IaaS]** Chain: (1) cloud API calls that fetch tenant/organization password policy (e.g., AWS `GetAccountPasswordPolicy`, GCP/OCI equivalents or IAM settings reads); (2) within a short window, the same principal creates users, rotates creds, or changes auth settings. Use cloud audit logs.
- [AN0457] **[macOS]** Chain: (1) execution of `pwpolicy` or MDM/DirectoryService reads of account policies; (2) optional read of `/Library/Preferences/com.apple.loginwindow` or config profiles; (3) follow-on credential probing or lateral movement by same user/session. Use unified logs and process telemetry.
- [AN0455] **[Windows]** Cause→effect chain: (1) a user or service spawns a shell/PowerShell that queries local/domain password policy via commands/cmdlets (e.g., `net accounts`, `Get-ADDefaultDomainPasswordPolicy`, `secedit /export`); (2) optional directory/LDAP reads from DCs; (3) same principal performs adjacent Discovery or credential-related actions within a short window. Correlate sysmon process creation with PowerShell ScriptBlock and Security logs.
- [AN0456] **[Linux]** Chain: (1) interactive/non-interactive `chage -l`, `grep`/`cat` of PAM config (e.g., `/etc/pam.d/common-password`, `/etc/security/pwquality.conf`); (2) optional reads of `/etc/login.defs`; (3) same user performs account enumeration or password change attempts shortly after. Use auditd `execve` and file read events plus shell history collection.
- [AN0460] **[SaaS]** Chain: (1) SaaS admin API or PowerShell remote session reads tenant password/authentication settings (e.g., M365 Unified Audit Log ‘Cmdlet’ with `Get-MsolPasswordPolicy`/`Get-OrganizationConfig` parameters that expose password settings); (2) same session proceeds to mailbox or tenant changes.
- [AN0461] **[Network Devices]** Chain: (1) privileged CLI sessions run read-only commands that dump AAA/password policies (e.g., `show aaa`, `show password-policy`); (2) same account changes AAA or user DB shortly after. Use network device AAA/command accounting or syslog.
**Procedure Examples**
- [S0039] Net: The net accounts and net accounts /domain commands with Net can be used to obtain password policy information.
- [S0488] CrackMapExec: CrackMapExec can discover the password policies applied to the target system.
- [C0012] Operation CuckooBees: During Operation CuckooBees, the threat actors used the `net accounts` command as part of their advanced reconnaissance.
- [G0049] OilRig: OilRig has used net.exe in a script with net accounts /domain to find the password policy of a domain.
- [G0114] Chimera: Chimera has used the NtdsAudit utility to collect information related to accounts and passwords.
- [S0236] Kwampirs: Kwampirs collects password policy information with the command net accounts.
- [G0010] Turla: Turla has used net accounts and net accounts /domain to acquire password policy information.
- [S0378] PoshC2: PoshC2 can use Get-PassPol to enumerate the domain password policy.


### T1217 - Browser Information Discovery
Adversaries may enumerate information about browsers to learn more about compromised environments. Data saved by browsers (such as bookmarks, accounts, and browsing history) may reveal a variety of personal information about users (e.g., banking sites, relationships/interests, social media, etc.) as well as details about internal network resources such as servers, tools/dashboards, or other related infrastructure. Browser information may also highlight additional targets after an adversary has access to valid credentials, especially Credentials In Files associated with logins cached by a browser. Specific storage locations vary based on platform and/or application, but browser information is typically stored in local files and databases (e.g., `%APPDATA%/Google/Chrome`).
**Detection**
- [AN0039] **[macOS]** Scripting or CLI tool access to ~/Library/Application Support/Google/Chrome or ~/Library/Safari bookmarks, cookies, or history databases. Detection relies on unexpected processes accessing or reading from these locations.
- [AN0038] **[Linux]** Unauthorized shell or script-based access to browser config or SQLite history files, typically in ~/.config/google-chrome/, ~/.mozilla/, or ~/.var/app folders, indicating enumeration of bookmarks or saved credentials.
- [AN0037] **[Windows]** Access to browser artifact locations (e.g., Chrome, Edge, Firefox) by processes like PowerShell, cmd.exe, or unknown tools, followed by file reads, decoding, or export operations indicating enumeration of bookmarks, autofill, or history databases.
**Procedure Examples**
- [S0274] Calisto: Calisto collects information on bookmarks from Google Chrome.
- [S0681] Lizar: Lizar can retrieve browser history and database files.
- [C0044] Juicy Mix: During Juicy Mix, OilRig used the CDumper (Chrome browser) and EDumper (Edge browser) data stealers to collect cookies, browsing history, and credentials.
- [S0409] Machete: Machete retrieves the user profile data (e.g., browsers) from Chrome and Firefox browsers.
- [C0042] Outer Space: During Outer Space, OilRig used a Chrome data dumper named MKG.
- [S1122] Mispadu: Mispadu can monitor browser activity for online banking actions and display full-screen overlay images to block user access to the intended site or present additional data fields.
- [S1246] BeaverTail: BeaverTail has searched the victim device for browser extensions including those commonly associated with cryptocurrency wallets.
- [S1012] PowerLess: PowerLess has a browser info stealer module that can read Chrome and Edge browser database files.
- [S0567] Dtrack: Dtrack can retrieve browser history.
- [G0117] Fox Kitten: Fox Kitten has used Google Chrome bookmarks to identify internal resources and assets.


### T1482 - Domain Trust Discovery
Adversaries may attempt to gather information on domain trust relationships that may be used to identify lateral movement opportunities in Windows multi-domain/forest environments. Domain trusts provide a mechanism for a domain to allow access to resources based on the authentication procedures of another domain. Domain trusts allow the users of the trusted domain to access resources in the trusting domain. The information discovered may help the adversary conduct SID-History Injection, Pass the Ticket, and Kerberoasting. Domain trusts can be enumerated using the `DSEnumerateDomainTrusts()` Win32 API call, .NET methods, and LDAP. The Windows utility Nltest is known to be used by adversaries to enumerate domain trusts.
**Detection**
- [AN0016] **[Windows]** Adversary uses nltest, PowerShell, or Win32/.NET API to enumerate domain trust relationships (via DSEnumerateDomainTrusts, GetAllTrustRelationships, or LDAP queries), followed by discovery or authentication staging.
**Procedure Examples**
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


### T1497 - Virtualization/Sandbox Evasion
Adversaries may employ various means to detect and avoid virtualization and analysis environments. This may include changing behaviors based on the results of checks for the presence of artifacts indicative of a virtual machine environment (VME) or sandbox. If the adversary detects a VME, they may alter their malware to disengage from the victim or conceal the core functions of the implant. They may also search for VME artifacts before dropping secondary or additional payloads. Adversaries may use the information learned from Virtualization/Sandbox Evasion during automated discovery to shape follow-on behaviors. Adversaries may use several methods to accomplish Virtualization/Sandbox Evasion such as checking for security monitoring tools (e.g., Sysinternals, Wireshark, etc.) or other system artifacts associated with analysis or virtualization. Adversaries may also check for legitimate user activity to help determine if it is in an analysis environment. Additional methods include use of sleep timers or loops within malware code to avoid operating within a temporary sandbox.
**Detection**
- [AN0128] **[Linux]** Execution of commands to enumerate virtualization-related files or processes (e.g., '/sys/class/dmi/id/product_name', dmesg, lscpu, lspci), or querying hypervisor interfaces prior to malware execution.
- [AN0127] **[Windows]** Execution of discovery commands or API calls for virtualization artifacts (e.g., registry keys, device drivers, services), sleep/skipped execution behavior, or sandbox evasion DLLs before payload deployment.
- [AN0129] **[macOS]** Execution of scripts or binaries that check for virtualization indicators (e.g., system_profiler, ioreg -l, kextstat), combined with delay functions or anomalous launchd activity.
**Procedure Examples**
- [S0380] StoneDrill: StoneDrill has used several anti-emulation techniques to prevent automated analysis by emulators or sandboxes.
- [S0483] IcedID: IcedID has manipulated Keitaro Traffic Direction System to filter researcher and sandbox traffic.
- [S0331] Agent Tesla: Agent Tesla has the ability to perform anti-sandboxing and anti-virtualization checks.
- [G1052] Contagious Interview: Contagious Interview has requested victims to disable Docker and other container environments in attempts to thwart container isolation and ensure device infection.
- [G1031] Saint Bear: Saint Bear contains several anti-analysis and anti-virtualization checks.
- [S0268] Bisonal: Bisonal can check to determine if the compromised system is running on VMware.
- [S0484] Carberp: Carberp has removed various hooks before installing the trojan or bootkit to evade sandbox analysis or other analysis software.
- [S1070] Black Basta: Black Basta can make a random number of calls to the `kernel32.beep` function to hinder log analysis.
- [C0005] Operation Spalax: During Operation Spalax, the threat actors used droppers that would run anti-analysis checks before executing malware on a compromised host.
- [S1130] Raspberry Robin: Raspberry Robin contains real and fake second-stage payloads following initial execution, with the real payload only delivered if the malware determines it is not running in a virtualized environment.


### T1497.001 - Virtualization/Sandbox Evasion: System Checks
Adversaries may employ various system checks to detect and avoid virtualization and analysis environments. This may include changing behaviors based on the results of checks for the presence of artifacts indicative of a virtual machine environment (VME) or sandbox. If the adversary detects a VME, they may alter their malware to disengage from the victim or conceal the core functions of the implant. They may also search for VME artifacts before dropping secondary or additional payloads. Adversaries may use the information learned from Virtualization/Sandbox Evasion during automated discovery to shape follow-on behaviors. Specific checks will vary based on the target and/or adversary, but may involve behaviors such as Windows Management Instrumentation, PowerShell, System Information Discovery, and Query Registry to obtain system information and search for VME artifacts. Adversaries may search for VME artifacts in memory, processes, file system, hardware, and/or the Registry. Adversaries may use scripting to automate these checks into one script and then have the program exit if it determines the system to be a virtual environment. Checks could include generic system properties such as host/domain name and samples of network traffic. Adversaries may also check the network adapters addresses, CPU core count, and available memory/drive size. Once executed, malware may also use File and Directory Discovery to check if it was saved in a folder or file with unexpected or even analysis-related naming artifacts such as `malware`, `sample`, or `hash`. Other common checks may enumerate services running that are unique to these applications, installed programs on the system, manufacturer/product fields for strings relating to virtual machine applications, and VME-specific hardware/processor instructions. In applications like VMWare, adversaries can also use a special I/O port to send commands and receive output. Hardware checks, such as the presence of the fan, temperature, and audio devices, could also be used to gather evidence that can be indicative a virtual environment. Adversaries may also query for specific readings from these devices.
**Detection**
- [AN0478] **[Windows]** Script or binary performs a rapid sequence of system discovery checks (e.g., CPU count, RAM size, registry keys, running processes) indicative of VM detection
- [AN0480] **[macOS]** Bash, Swift, or Objective-C programs enumerate system profile, I/O registry, or inspect kernel extensions to identify VM artifacts
- [AN0479] **[Linux]** Shell script or binary uses multiple system commands (e.g., dmidecode, lscpu, lspci) in quick succession to detect virtualization environment
**Procedure Examples**
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


### T1497.002 - Virtualization/Sandbox Evasion: User Activity Based Checks
Adversaries may employ various user activity checks to detect and avoid virtualization and analysis environments. This may include changing behaviors based on the results of checks for the presence of artifacts indicative of a virtual machine environment (VME) or sandbox. If the adversary detects a VME, they may alter their malware to disengage from the victim or conceal the core functions of the implant. They may also search for VME artifacts before dropping secondary or additional payloads. Adversaries may use the information learned from Virtualization/Sandbox Evasion during automated discovery to shape follow-on behaviors. Adversaries may search for user activity on the host based on variables such as the speed/frequency of mouse movements and clicks , browser history, cache, bookmarks, or number of files in common directories such as home or the desktop. Other methods may rely on specific user interaction with the system before the malicious code is activated, such as waiting for a document to close before activating a macro or waiting for a user to double click on an embedded image to activate.
**Detection**
- [AN1183] **[Linux]** Access to shell history or GUI input state (xdotool, xinput) for presence validation prior to payload execution.
- [AN1182] **[Windows]** Process execution that probes user activity artifacts (e.g., desktop files, registry history) following recent user login/unlock events.
- [AN1184] **[macOS]** API usage or filesystem access revealing user state or browser artifacts (e.g., Safari bookmarks, CGEventState).
**Procedure Examples**
- [G0012] Darkhotel: Darkhotel has used malware that repeatedly checks the mouse cursor position to determine if a real user is on the system.
- [S0439] Okrum: Okrum loader only executes the payload after the left mouse button has been pressed at least three times, in order to avoid being executed within virtualized or emulated environments.
- [S1239] TONESHELL: TONESHELL has leveraged `GetForegroundWindow` to detect virtualization or sandboxes by calling the API twice and comparing each window handle.
- [G0046] FIN7: FIN7 used images embedded into document lures that only activate the payload when a user double clicks to avoid sandboxes.
- [S0543] Spark: Spark has used a splash screen to check whether an user actively clicks on the screen before running malicious code.


### T1497.003 - Virtualization/Sandbox Evasion: Time Based Checks
Adversaries may employ various time-based methods to detect virtualization and analysis environments, particularly those that attempt to manipulate time mechanisms to simulate longer elapses of time. This may include enumerating time-based properties, such as uptime or the system clock. Adversaries may use calls like `GetTickCount` and `GetSystemTimeAsFileTime` to discover if they are operating within a virtual machine or sandbox, or may be able to identify a sandbox accelerating time by sampling and calculating the expected value for an environment's timestamp before and after execution of a sleep function.
**Detection**
- [AN0396] **[Windows]** Process creation involving suspicious delays (e.g., Sleep, ping -n loops, WaitForSingleObject), followed by sensitive system access or lateral movement behaviors.
- [AN0397] **[Linux]** Script-based execution of sleep loops or time delay commands (e.g., sleep, ping delay, while-loops) followed by file creation or network connections.
- [AN0398] **[macOS]** Use of `usleep`, `nanosleep`, or `NSTimer` calls in executables or binaries with no GUI interaction, especially followed by disk/network activity.
**Procedure Examples**
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


### T1518 - Software Discovery
Adversaries may attempt to get a listing of software and software versions that are installed on a system or in a cloud environment. Adversaries may use the information from Software Discovery during automated discovery to shape follow-on behaviors, including whether or not the adversary fully infects the target and/or attempts specific actions. Such software may be deployed widely across the environment for configuration management or security reasons, such as Software Deployment Tools, and may allow adversaries broad access to infect devices or move laterally. Adversaries may attempt to enumerate software for a variety of reasons, such as figuring out what security measures are present or if the compromised system has a version of software that is vulnerable to Exploitation for Privilege Escalation.
**Detection**
- [AN1104] **[ESXi]** Adversary uses 'esxcli software vib list' to enumerate installed VIBs, drivers, and modules.
- [AN1103] **[IaaS]** Adversary uses cloud-native APIs or CLI (e.g., AWS Systems Manager, Azure Resource Graph) to list installed software on cloud workloads.
- [AN1102] **[macOS]** Adversary runs 'system_profiler SPApplicationsDataType' or queries plist files to enumerate software via Terminal or scripts.
- [AN1100] **[Windows]** Adversary spawns a process or script to enumerate installed software using WMI, registry, or PowerShell, potentially followed by additional discovery or evasion behavior.
- [AN1101] **[Linux]** Adversary invokes 'dpkg -l', 'rpm -qa', or other package managers via shell or script to enumerate installed software.
**Procedure Examples**
- [S0455] Metamorfo: Metamorfo has searched the compromised system for banking applications.
- [S0658] XCSSET: XCSSET uses ps aux with the grep command to enumerate common browsers and system processes potentially impacting XCSSET's exfiltration capabilities.
- [S0623] Siloscape: Siloscape searches for the kubectl binary.
- [G1017] Volt Typhoon: Volt Typhoon has queried the Registry on compromised systems for information on installed software.
- [S0674] CharmPower: CharmPower can list the installed applications on a compromised host.
- [S0445] ShimRatReporter: ShimRatReporter gathered a list of installed software on the infected host.
- [S0062] DustySky: DustySky lists all installed software for the infected machine.
- [S1153] Cuckoo Stealer: Cuckoo Stealer has the ability to search systems for installed applications.
- [S1042] SUGARDUMP: SUGARDUMP can identify Chrome, Opera, Edge Chromium, and Firefox browsers, including version number, on a compromised host.
- [S0126] ComRAT: ComRAT can check the victim's default browser to determine which process to inject its communications module into.


### T1518.001 - Software Discovery: Security Software Discovery
Adversaries may attempt to get a listing of security software, configurations, defensive tools, and sensors that are installed on a system or in a cloud environment. This may include things such as cloud monitoring agents and anti-virus. Adversaries may use the information from Security Software Discovery during automated discovery to shape follow-on behaviors, including whether or not the adversary fully infects the target and/or attempts specific actions. Example commands that can be used to obtain security software information are netsh, reg query with Reg, dir with cmd, and Tasklist, but other indicators of discovery behavior may be more specific to the type of software or security system the adversary is looking for. It is becoming more common to see macOS malware perform checks for LittleSnitch and KnockKnock software. Adversaries may also utilize the Cloud API to discover cloud-native security software installed on compute infrastructure, such as the AWS CloudWatch agent, Azure VM Agent, and Google Cloud Monitor agent. These agents may collect metrics and logs from the VM, which may be centrally aggregated in a cloud-based monitoring platform.
**Detection**
- [AN0049] **[Linux]** Adversary runs discovery commands such as `ps aux`, `systemctl status`, or `cat /etc/init.d/` to enumerate security software or services. Often occurs alongside privilege escalation or bash script execution.
- [AN0050] **[macOS]** Adversary attempts to detect monitoring agents such as Little Snitch, KnockKnock, or other system daemons via process listing (`ps -e`), application folder checks, and system extension listing.
- [AN0048] **[Windows]** Adversary executes commands to enumerate installed antivirus, EDR, or firewall agents using WMI, registry queries, and built-in tools (e.g., tasklist, netsh, sc query). Correlated with elevated process privileges or scripting engine usage.
**Procedure Examples**
- [G0012] Darkhotel: Darkhotel has searched for anti-malware strings and anti-virus processes running on the system.
- [S1130] Raspberry Robin: Raspberry Robin attempts to identify security software running on the victim machine, such as BitDefender, Avast, and Kaspersky.
- [S0611] Clop: Clop can search for processes with antivirus and antimalware product names.
- [S0469] ABK: ABK has the ability to identify the installed anti-virus product on the compromised host.
- [C0014] Operation Wocao: During Operation Wocao, threat actors used scripts to detect security software.
- [S1228] PUBLOAD: PUBLOAD has identified AV products on an infected host using the following command: `WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName /Format:List`.
- [G0121] Sidewinder: Sidewinder has used the Windows service winmgmts:\\.\root\SecurityCenter2 to check installed antivirus products.
- [S0455] Metamorfo: Metamorfo collects a list of installed antivirus software from the victim’s system.
- [S1234] SplatCloak: SplatCloak has identified drivers of AV solutions by searching for related filenames, keywords and signed certificates.
- [S1239] TONESHELL: TONESHELL has checked for the presence of ESET antivirus applications `ekrn.exe` and `egui.exe`.


### T1518.002 - Software Discovery: Backup Software Discovery
Adversaries may attempt to get a listing of backup software or configurations that are installed on a system. Adversaries may use this information to shape follow-on behaviors, such as Data Destruction, Inhibit System Recovery, or Data Encrypted for Impact. Commands that can be used to obtain security software information are netsh, `reg query` with Reg, `dir` with cmd, and Tasklist, but other indicators of discovery behavior may be more specific to the type of software or security system the adversary is looking for, such as Veeam, Acronis, Dropbox, or Paragon.
**Detection**
- [AN0241] **[Linux]** Defender observes use of CLI tools (`find`, `grep`, `ls`, `dpkg`, `rpm`, `systemctl`, `ps aux`) to discover backup agents or config files (e.g., rsnapshot, duplicity, veeam). This often includes command lines that recursively search `/etc/`, `/opt/`, or `/var/` directories for keywords like `backup`, and parent-child relationships involving shell or Python scripts.
- [AN0240] **[Windows]** Defender observes execution of commands like `tasklist`, `sc query`, `reg query`, or PowerShell WMI/Registry queries targeting known backup products (e.g., Veeam, Acronis, CrashPlan). Behavior often includes parent-child lineage involving PowerShell or cmd.exe with discovery syntax, and enumeration of services, directories, or registry paths tied to backup software.
- [AN0242] **[macOS]** Defender detects execution of `mdfind`, `launchctl`, or GUI-based enumeration (e.g., `/Applications/Time Machine.app`) along with command-line usage of `find`, `grep`, or `system_profiler` to identify installed backup tools like Time Machine, Carbon Copy Cloner, or Backblaze. Often triggered from Terminal sessions or within post-exploitation scripts.
**Procedure Examples**
- [G0102] Wizard Spider: Wizard Spider has utilized the PowerShell script `Get-DataInfo.ps1` to collect installed backup software information from a compromised machine.


### T1526 - Cloud Service Discovery
An adversary may attempt to enumerate the cloud services running on a system after gaining access. These methods can differ from platform-as-a-service (PaaS), to infrastructure-as-a-service (IaaS), or software-as-a-service (SaaS). Many services exist throughout the various cloud providers and can include Continuous Integration and Continuous Delivery (CI/CD), Lambda Functions, Entra ID, etc. They may also include security services, such as AWS GuardDuty and Microsoft Defender for Cloud, and logging services, such as AWS CloudTrail and Google Cloud Audit Logs. Adversaries may attempt to discover information about the services enabled throughout the environment. Azure tools and APIs, such as the Microsoft Graph API and Azure Resource Manager API, can enumerate resources and services, including applications, management groups, resources and policy definitions, and their relationships that are accessible by an identity. For example, Stormspotter is an open source tool for enumerating and constructing a graph for Azure resources and services, and Pacu is an open source AWS exploitation framework that supports several methods for discovering cloud services. Adversaries may use the information gained to shape follow-on behaviors, such as targeting data or credentials from enumerated services or evading identified defenses through Disable or Modify Tools or Disable or Modify Cloud Logs.
**Detection**
- [AN1129] **[Office Suite]** Discovery of SaaS services connected to productivity platforms (e.g., Microsoft 365, Google Workspace). Defender perspective includes unexpected enumeration of enabled services, API integrations, or OAuth applications tied to user accounts.
- [AN1130] **[SaaS]** Discovery of connected SaaS applications, APIs, or configurations within platforms like Salesforce, Slack, or Zoom. Defender perspective includes enumeration of available integrations, abnormal querying of service metadata, and follow-on attempts to exploit or persist via discovered services.
- [AN1128] **[Identity Provider]** Enumeration of directories, applications, or service principals through APIs such as Microsoft Graph or Okta API. Defender perspective includes unexpected listing of users, roles, applications, and abnormal access to identity management endpoints.
- [AN1127] **[IaaS]** Unusual enumeration of services and resources through cloud APIs such as AWS CLI `describe-*`, Azure Resource Manager queries, or GCP project listings. Defender perspective includes anomalous API calls, unexpected volume of service enumeration, and correlation of discovery with recently compromised sessions.
**Procedure Examples**
- [S0677] AADInternals: AADInternals can enumerate information about a variety of cloud services, such as Office 365 and Sharepoint instances or OpenID Configurations.
- [S0684] ROADTools: ROADTools can enumerate Azure AD applications and service principals.
- [G1053] Storm-0501: Storm-0501 has discovered the victim environment’s protections to include Azure policies, resource locks, and Azure Storage immutability policies.
- [S1091] Pacu: Pacu can enumerate AWS services, such as CloudTrail and CloudWatch.


### T1538 - Cloud Service Dashboard
An adversary may use a cloud service dashboard GUI with stolen credentials to gain useful information from an operational cloud environment, such as specific services, resources, and features. For example, the GCP Command Center can be used to view all assets, review findings of potential security risks, and run additional queries, such as finding public IP addresses and open ports. Depending on the configuration of the environment, an adversary may be able to enumerate more information via the graphical dashboard than an API. This also allows the adversary to gain information without manually making any API requests.
**Detection**
- [AN0809] **[Identity Provider]** Detects successful login to cloud identity portals (e.g., Okta, Azure AD, Google Identity) from atypical geolocations, devices, or user agents immediately followed by dashboard/portal navigation to sensitive pages such as user or app configuration.
- [AN0810] **[Office Suite]** Detects login to admin consoles (e.g., Microsoft 365 Admin Center) from unrecognized users, devices, or geolocations followed by non-API data review or configuration read actions that suggest GUI dashboard use.
- [AN0808] **[IaaS]** Detects web console login events followed by read-only or metadata retrieval activity from GUI sources (e.g., browser session, mobile client) rather than API/CLI sources. Correlates across CloudTrail, IAM identity logs, and user-agent context.
- [AN0811] **[SaaS]** Detects SaaS web login followed by dashboard or web GUI page views from unfamiliar locations, devices, or access patterns. Identifies use of sensitive reporting or configuration consoles accessed from high-risk accounts.
**Procedure Examples**
- [G1015] Scattered Spider: Scattered Spider abused AWS Systems Manager Inventory to identify targets on the compromised network prior to lateral movement.


### T1580 - Cloud Infrastructure Discovery
An adversary may attempt to discover infrastructure and resources that are available within an infrastructure-as-a-service (IaaS) environment. This includes compute service resources such as instances, virtual machines, and snapshots as well as resources of other services including the storage and database services. Cloud providers offer methods such as APIs and commands issued through CLIs to serve information about infrastructure. For example, AWS provides a DescribeInstances API within the Amazon EC2 API that can return information about one or more instances within an account, the ListBuckets API that returns a list of all buckets owned by the authenticated sender of the request, the HeadBucket API to determine a bucket’s existence along with access permissions of the request sender, or the GetPublicAccessBlock API to retrieve access block configuration for a bucket. Similarly, GCP's Cloud SDK CLI provides the gcloud compute instances list command to list all Google Compute Engine instances in a project , and Azure's CLI command az vm list lists details of virtual machines. In addition to API commands, adversaries can utilize open source tools to discover cloud storage infrastructure through Wordlist Scanning. An adversary may enumerate resources using a compromised user's access keys to determine which are available to that user. The discovery of these available resources may help adversaries determine their next steps in the Cloud environment, such as establishing Persistence.An adversary may also use this information to change the configuration to make the bucket publicly accessible, allowing data to be accessed without authentication. Adversaries have also may use infrastructure discovery APIs such as DescribeDBInstances to determine size, owner, permissions, and network ACLs of database resources. Adversaries can use this information to determine the potential value of databases and discover the requirements to access them. Unlike in Cloud Service Discovery, this technique focuses on the discovery of components of the provided services rather than the services themselves.
**Detection**
- [AN0481] **[IaaS]** Defenders should monitor for suspicious enumeration of cloud infrastructure components via APIs or CLI tools. Observable behaviors include repeated listing or description operations for compute instances, snapshots, storage buckets, and volumes. From a defender’s perspective, risky activity is often identified by new or untrusted identities making discovery calls (e.g., DescribeInstances, ListBuckets, az vm list, gcloud compute instances list), enumeration from unusual geolocations or IPs, or rapid multi-service discovery in sequence. Correlating discovery API usage with later snapshot creation or instance modification provides further context of adversary behavior.
**Procedure Examples**
- [G1015] Scattered Spider: Scattered Spider enumerates cloud environments including Amazon Web Services (AWS) S3 buckets to identify server and backup management infrastructure, resource access, databases and storage containers .
- [G1053] Storm-0501: Storm-0501 has enumerated compromised cloud environments to identify critical assets, data stores, and back resources.
- [S1091] Pacu: Pacu can enumerate AWS infrastructure, such as EC2 instances.


### T1613 - Container and Resource Discovery
Adversaries may attempt to discover containers and other resources that are available within a containers environment. Other resources may include images, deployments, pods, nodes, and other information such as the status of a cluster. These resources can be viewed within web applications such as the Kubernetes dashboard or can be queried via the Docker and Kubernetes APIs. In Docker, logs may leak information about the environment, such as the environment’s configuration, which services are available, and what cloud provider the victim may be utilizing. The discovery of these resources may inform an adversary’s next steps in the environment, such as how to perform lateral movement and which methods to utilize for execution.
**Detection**
- [AN1352] **[Containers]** Detection of adversary attempts to enumerate containers, pods, nodes, and related resources within containerized environments. Defenders may observe anomalous API calls to Docker or Kubernetes (e.g., 'docker ps', 'kubectl get pods', 'kubectl get nodes'), unusual account activity against the Kubernetes dashboard, or unexpected queries against container metadata endpoints. These events should be correlated with user context and network activity to reveal resource discovery attempts.
**Procedure Examples**
- [S0683] Peirates: Peirates can enumerate Kubernetes pods in a given namespace.
- [G0139] TeamTNT: TeamTNT has checked for running containers with docker ps and for specific container names with docker inspect. TeamTNT has also searched for Kubernetes pods running in a local network.
- [S0601] Hildegard: Hildegard has used masscan to search for kubelets and the kubelet API for additional running containers.


### T1614 - System Location Discovery
Adversaries may gather information in an attempt to calculate the geographical location of a victim host. Adversaries may use the information from System Location Discovery during automated discovery to shape follow-on behaviors, including whether or not the adversary fully infects the target and/or attempts specific actions. Adversaries may attempt to infer the location of a system using various system checks, such as time zone, keyboard layout, and/or language settings. Windows API functions such as GetLocaleInfoW can also be used to determine the locale of the host. In cloud environments, an instance's availability zone may also be discovered by accessing the instance metadata service from the instance. Adversaries may also attempt to infer the location of a victim host using IP addressing, such as via online geolocation IP-lookup services.
**Detection**
- [AN0121] **[macOS]** Detection of system calls or commands accessing system locale (e.g., 'defaults read -g AppleLocale', 'systemsetup -gettimezone'). Correlate with unusual parent processes or execution contexts.
- [AN0122] **[IaaS]** Detection of queries to instance metadata services (e.g., AWS IMDS, Azure Metadata Service) for availability zone, region, or network geolocation details. Correlation with non-management accounts or non-standard workloads may indicate adversary reconnaissance.
- [AN0119] **[Windows]** Unusual process or API usage attempting to query system locale, timezone, or keyboard layout (e.g., calls to GetLocaleInfoW, GetTimeZoneInformation). Detection can be enhanced by correlating with processes not typically associated with system configuration queries, such as unknown binaries or scripts.
- [AN0120] **[Linux]** Detection of commands accessing locale, timezone, or language settings such as 'locale', 'timedatectl', or parsing /etc/timezone. Anomalous execution by unusual users or automation scripts should be flagged.
**Procedure Examples**
- [S0673] DarkWatchman: DarkWatchman can identity the OS locale of a compromised host.
- [S1138] Gootloader: Gootloader can use IP geolocation to determine if the person browsing to a compromised site is within a targeted territory such as the US, Canada, Germany, and South Korea.
- [S0013] PlugX: PlugX has obtained the location of the victim device by leveraging `GetSystemDefaultLCID`.
- [G1008] SideCopy: SideCopy has identified the country location of a compromised host.
- [S1153] Cuckoo Stealer: Cuckoo Stealer can determine the geographical location of a victim host by checking the language.
- [S1111] DarkGate: DarkGate queries system locale information during execution. Later versions of DarkGate query GetSystemDefaultLCID for locale information to determine if the malware is executing in Russian-speaking countries.
- [S1124] SocGholish: SocGholish can use IP-based geolocation to limit infections to victims in North America, Europe, and a small number of Asian-Pacific nations.
- [S1248] XORIndex Loader: XORIndex Loader can identify the geographical location of a victim host.
- [S0262] QuasarRAT: QuasarRAT can determine the country a victim host is located in.
- [S0461] SDBbot: SDBbot can collected the country code of a compromised machine.


### T1614.001 - System Location Discovery: System Language Discovery
Adversaries may attempt to gather information about the system language of a victim in order to infer the geographical location of that host. This information may be used to shape follow-on behaviors, including whether the adversary infects the target and/or attempts specific actions. This decision may be employed by malware developers and operators to reduce their risk of attracting the attention of specific law enforcement agencies or prosecution/scrutiny from other entities. There are various sources of data an adversary could use to infer system language, such as system defaults and keyboard layouts. Specific checks will vary based on the target and/or adversary, but may involve behaviors such as Query Registry and calls to Native API functions. For example, on a Windows system adversaries may attempt to infer the language of a system by querying the registry key HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Nls\Language or parsing the outputs of Windows API functions GetUserDefaultUILanguage, GetSystemDefaultUILanguage, GetKeyboardLayoutList and GetUserDefaultLangID. On a macOS or Linux system, adversaries may query locale to retrieve the value of the $LANG environment variable.
**Detection**
- [AN1561] **[Windows]** Registry access to system language keys (e.g., HKLM\SYSTEM\CurrentControlSet\Control\Nls\Language) or suspicious processes invoking locale-related APIs (e.g., GetUserDefaultUILanguage, GetSystemDefaultUILanguage, GetKeyboardLayoutList). Defender visibility focuses on anomalous or non-standard processes issuing these queries, especially when run by unknown binaries or scripts.
- [AN1562] **[Linux]** Processes executing commands to query system locale and language settings, such as 'locale', 'echo $LANG', or parsing environment variables. Suspicious activity is indicated by these commands being run by unusual users, automation scripts, or non-administrative processes.
- [AN1563] **[macOS]** Execution of commands to query system locale and language settings, such as 'defaults read -g AppleLocale' or 'systemsetup -gettimezone'. Unusual parent processes or execution contexts of these commands may indicate adversarial discovery.
**Procedure Examples**
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


### T1615 - Group Policy Discovery
Adversaries may gather information on Group Policy settings to identify paths for privilege escalation, security measures applied within a domain, and to discover patterns in domain objects that can be manipulated or used to blend in the environment. Group Policy allows for centralized management of user and computer settings in Active Directory (AD). Group policy objects (GPOs) are containers for group policy settings made up of files stored within a predictable network path `\\SYSVOL\\Policies\`. Adversaries may use commands such as gpresult or various publicly available PowerShell functions, such as Get-DomainGPO and Get-DomainGPOLocalGroup, to gather information on Group Policy settings. Adversaries may use this information to shape follow-on behaviors, including determining potential attack paths within the target network as well as opportunities to manipulate Group Policy settings (i.e. Domain or Tenant Policy Modification) for their benefit.
**Detection**
- [AN0152] **[Windows]** Detection of adversary attempts to enumerate Group Policy settings through suspicious command execution (gpresult), PowerShell enumeration (Get-DomainGPO, Get-DomainGPOLocalGroup), and abnormal LDAP queries targeting groupPolicyContainer objects. Defenders observe unusual process lineage, script execution, or LDAP filter activity against domain controllers.
**Procedure Examples**
- [S1141] LunarWeb: LunarWeb can capture information on group policy settings
- [C0049] Leviathan Australian Intrusions: Leviathan performed extensive Active Directory enumeration of victim environments during Leviathan Australian Intrusions.
- [S1159] DUSTTRAP: DUSTTRAP can identify victim environment Group Policy information.
- [S0521] BloodHound: BloodHound has the ability to collect local admin information via GPO.
- [G0010] Turla: Turla surveys a system upon check-in to discover Group Policy details using the gpresult command.
- [S0363] Empire: Empire includes various modules for enumerating Group Policy.
- [S0082] Emissary: Emissary has the capability to execute gpresult.


### T1619 - Cloud Storage Object Discovery
Adversaries may enumerate objects in cloud storage infrastructure. Adversaries may use this information during automated discovery to shape follow-on behaviors, including requesting all or specific objects from cloud storage. Similar to File and Directory Discovery on a local host, after identifying available storage services (i.e. Cloud Infrastructure Discovery) adversaries may access the contents/objects stored in cloud infrastructure. Cloud service providers offer APIs allowing users to enumerate objects stored within cloud storage. Examples include ListObjectsV2 in AWS and List Blobs in Azure .
**Detection**
- [AN1594] **[IaaS]** Detection of suspicious enumeration of cloud storage objects via API calls such as AWS S3 ListObjectsV2, Azure List Blobs, or GCP ListObjects. Correlate access with account role, user context, and prior authentication activity to identify anomalous usage patterns (e.g., unusual account, unexpected regions, or large-scale enumeration in short time windows).
**Procedure Examples**
- [S1091] Pacu: Pacu can enumerate AWS storage services, such as S3 buckets and Elastic Block Store volumes.
- [S0683] Peirates: Peirates can list AWS S3 buckets.


### T1622 - Debugger Evasion
Adversaries may employ various means to detect and avoid debuggers. Debuggers are typically used by defenders to trace and/or analyze the execution of potential malware payloads. Debugger evasion may include changing behaviors based on the results of the checks for the presence of artifacts indicative of a debugged environment. Similar to Virtualization/Sandbox Evasion, if the adversary detects a debugger, they may alter their malware to disengage from the victim or conceal the core functions of the implant. They may also search for debugger artifacts before dropping secondary or additional payloads. Specific checks will vary based on the target and/or adversary. On Windows, this may involve Native API function calls such as IsDebuggerPresent() and NtQueryInformationProcess(), or manually checking the BeingDebugged flag of the Process Environment Block (PEB). On Linux, this may involve querying `/proc/self/status` for the `TracerPID` field, which indicates whether or not the process is being traced by dynamic analysis tools. Other checks for debugging artifacts may also seek to enumerate hardware breakpoints, interrupt assembly opcodes, time checks, or measurements if exceptions are raised in the current process (assuming a present debugger would “swallow” or handle the potential error). Malware may also leverage Structured Exception Handling (SEH) to detect debuggers by throwing an exception and detecting whether the process is suspended. SEH handles both hardware and software expectations, providing control over the exceptions including support for debugging. If a debugger is present, the program’s control will be transferred to the debugger, and the execution of the code will be suspended. If the debugger is not present, control will be transferred to the SEH handler, which will automatically handle the exception and allow the program’s execution to continue. Adversaries may use the information learned from these debugger checks during automated discovery to shape follow-on behaviors. Debuggers can also be evaded by detaching the process or flooding debug logs with meaningless data via messages produced by looping Native API function calls such as OutputDebugStringW().
**Detection**
- [AN1047] **[macOS]** Detect suspicious calls to sysctl or ptrace API used to determine if a process is being debugged. Monitor for processes that flood OutputDebugString equivalents or generate abnormal exceptions to evade analysis.
- [AN1045] **[Windows]** Monitor for suspicious use of Windows API calls such as IsDebuggerPresent() and NtQueryInformationProcess(), or processes manually checking the BeingDebugged flag in the Process Environment Block (PEB). Detect sequences of OutputDebugStringW() calls in short intervals that may indicate debugger flooding attempts.
- [AN1046] **[Linux]** Monitor access to /proc/self/status where TracerPID field is queried, as this is a common technique for debugger detection. Detect processes that attempt to trigger exceptions intentionally and monitor whether exception handling indicates presence of a debugger.
**Procedure Examples**
- [S1213] Lumma Stealer: Lumma Stealer has checked for debugger strings by invoking `GetForegroundWindow` and looks for strings containing “x32dbg”, “x64dbg”, “windbg”, “ollydbg”, “dnspy”, “immunity debugger”, “hyperdbg”, “debug”, “debugger”, “cheat engine”, “cheatengine” and “ida”.
- [S1087] AsyncRAT: AsyncRAT can use the `CheckRemoteDebuggerPresent` function to detect the presence of a debugger.
- [S0013] PlugX: PlugX has made calls to Windows API `CheckRemoteDebuggerPresent` and exits if it detects a debugger.
- [S1200] StealBit: StealBit can detect it is being run in the context of a debugger.
- [S1183] StrelaStealer: StrelaStealer variants include functionality to identify and evade debuggers.
- [S1111] DarkGate: DarkGate checks the BeingDebugged flag in the PEB structure during execution to identify if the malware is being debugged.
- [S1145] Pikabot: Pikabot features several methods to evade debugging by analysts, including checks for active debuggers, the use of breakpoints during execution, and checking various system information items such as system memory and the number of processors.
- [S0240] ROKRAT: ROKRAT can check for debugging tools.
- [S1228] PUBLOAD: PUBLOAD has embedded debug strings with messages to distract analysts. PUBLOAD has leveraged `OutputDebugStringW` and `OutputDebugStringA` functions.
- [S0694] DRATzarus: DRATzarus can use `IsDebuggerPresent` to detect whether a debugger is present on a victim.


### T1652 - Device Driver Discovery
Adversaries may attempt to enumerate local device drivers on a victim host. Information about device drivers may highlight various insights that shape follow-on behaviors, such as the function/purpose of the host, present security tools (i.e. Security Software Discovery) or other defenses (e.g., Virtualization/Sandbox Evasion), as well as potential exploitable vulnerabilities (e.g., Exploitation for Privilege Escalation). Many OS utilities may provide information about local device drivers, such as `driverquery.exe` and the `EnumDeviceDrivers()` API function on Windows. Information about device drivers (as well as associated services, i.e., System Service Discovery) may also be available in the Registry. On Linux/macOS, device drivers (in the form of kernel modules) may be visible within `/dev` or using utilities such as `lsmod` and `modinfo`.
**Detection**
- [AN1595] **[Windows]** Monitor for suspicious usage of driver enumeration utilities (driverquery.exe) or API calls such as EnumDeviceDrivers(). Registry queries against HKLM\SYSTEM\CurrentControlSet\Services and HardwareProfiles that are abnormal may also indicate attempts to discover installed drivers and services. Correlate command execution, process creation, and registry access to build a behavioral chain of driver discovery.
- [AN1596] **[Linux]** Detect attempts to enumerate kernel modules through lsmod, modinfo, or inspection of /proc/modules and /dev entries. Focus on unusual execution contexts such as unprivileged users or processes outside expected administrative workflows.
- [AN1597] **[macOS]** Detect loading or inspection of kernel extensions (kextstat, kextfind) and file access to /System/Library/Extensions/. Monitor unexpected usage of these utilities by non-administrative users or scripts.
**Procedure Examples**
- [S0376] HOPLIGHT: HOPLIGHT can enumerate device drivers located in the registry at `HKLM\Software\WBEM\WDM`.
- [S1139] INC Ransomware: INC Ransomware can verify the presence of specific drivers on compromised hosts including Microsoft Print to PDF and Microsoft XPS Document Writer.
- [G1051] Medusa Group: Medusa Group has queried drivers on the victim device through the command `driverquery`.
- [S0125] Remsec: Remsec has a plugin to detect active drivers of some security products.


### T1654 - Log Enumeration
Adversaries may enumerate system and service logs to find useful data. These logs may highlight various types of valuable insights for an adversary, such as user authentication records (Account Discovery), security or vulnerable software (Software Discovery), or hosts within a compromised network (Remote System Discovery). Host binaries may be leveraged to collect system logs. Examples include using `wevtutil.exe` or PowerShell on Windows to access and/or export security event information. In cloud environments, adversaries may leverage utilities such as the Azure VM Agent’s `CollectGuestLogs.exe` to collect security logs from cloud hosted infrastructure. Adversaries may also target centralized logging infrastructure such as SIEMs. Logs may also be bulk exported and sent to adversary-controlled infrastructure for offline analysis. In addition to gaining a better understanding of the environment, adversaries may also monitor logs in real time to track incident response procedures. This may allow them to adjust their techniques in order to maintain persistence or evade defenses.
**Detection**
- [AN0705] **[Windows]** Monitor for use of native utilities such as wevtutil.exe or PowerShell cmdlets (Get-WinEvent, Get-EventLog) to enumerate or export logs. Unusual access to security or system event channels, especially by non-administrative users or processes, should be correlated with subsequent file export or network transfer activity.
- [AN0708] **[IaaS]** Monitor for cloud API calls that export or collect guest or system logs. Abnormal use of Azure VM Agent’s CollectGuestLogs.exe or AWS CloudWatch GetLogEvents across multiple instances should be correlated with lateral movement or data staging.
- [AN0707] **[macOS]** Detect abnormal access to unified logs via log show or fs_usage targeting system log files. Monitor for execution of shell utilities (cat, grep) against /var/log/system.log and for plist modifications enabling verbose logging.
- [AN0706] **[Linux]** Monitor for suspicious use of commands such as cat, less, grep, or journalctl accessing /var/log/ files. Abnormal enumeration of authentication logs (auth.log, secure) or bulk access to multiple logs in short time windows should be flagged.
- [AN0709] **[ESXi]** Monitor ESXi shell or API access to host logs under /var/log/. Abnormal enumeration of vmkernel.log, hostd.log, or vpxa.log by unauthorized accounts should be flagged.
**Procedure Examples**
- [S1246] BeaverTail: BeaverTail has identified .ldb and .log files stored in browser extension directories for collection and exfiltration.
- [G1023] APT5: APT5 has used the BLOODMINE utility to parse and extract information from Pulse Secure Connect logs.
- [G1003] Ember Bear: Ember Bear has enumerated SECURITY and SYSTEM log files during intrusions.
- [G1017] Volt Typhoon: Volt Typhoon has used `wevtutil.exe` and the PowerShell command `Get-EventLog security` to enumerate Windows logs to search for successful logons.
- [G0143] Aquatic Panda: Aquatic Panda enumerated logs related to authentication in Linux environments prior to deleting selective entries for defense evasion purposes.
- [S1091] Pacu: Pacu can collect CloudTrail event histories and CloudWatch logs.
- [S1191] Megazord: Megazord has the ability to print the trace, debug, error, info, and warning logs.
- [S1194] Akira _v2: Akira _v2 can enumerate the trace, debug, error, info, and warning logs on targeted systems.
- [G0129] Mustang Panda: Mustang Panda has used Wevtutil to gather Windows Security Event Logs.
- [S1159] DUSTTRAP: DUSTTRAP can identify infected system log information.


### T1673 - Virtual Machine Discovery
An adversary may attempt to enumerate running virtual machines (VMs) after gaining access to a host or hypervisor. For example, adversaries may enumerate a list of VMs on an ESXi hypervisor using a Hypervisor CLI such as `esxcli` or `vim-cmd` (e.g. `esxcli vm process list or vim-cmd vmsvc/getallvms`). Adversaries may also directly leverage a graphical user interface, such as VMware vCenter, in order to view virtual machines on a host. Adversaries may use the information from Virtual Machine Discovery during discovery to shape follow-on behaviors. Subsequently discovered VMs may be leveraged for follow-on activities such as Service Stop or Data Encrypted for Impact.
**Detection**
- [AN0572] **[ESXi]** Monitor for execution of hypervisor management commands such as `esxcli vm process list` or `vim-cmd vmsvc/getallvms` that enumerate virtual machines. Defenders observe unexpected users issuing VM listing commands outside normal administrative workflows.
- [AN0573] **[Linux]** Detects attempts to enumerate VMs via hypervisor tools like `virsh`, `VBoxManage`, or `qemu-img`. Defender correlates suspicious command invocations with parent process lineage and unexpected users.
- [AN0575] **[macOS]** Detects VM enumeration attempts using virtualization utilities such as VirtualBox (`VBoxManage`) or Parallels CLI. Defender observes abnormal invocation of VM listing commands correlated with non-admin users or unusual parent processes.
- [AN0574] **[Windows]** Detects enumeration of VMs using PowerShell (`Get-VM`), VMware Workstation (`vmrun.exe`), or Hyper-V (`VBoxManage.exe`). Defender observes suspicious command lines executed by unexpected users or outside normal administrative sessions.
**Procedure Examples**
- [G1048] UNC3886: UNC3886 has used scripts to enumerate ESXi hypervisors and their guest VMs.
- [S1242] Qilin: Qilin can detect virtual machine environments.
- [S1217] VIRTUALPITA: VIRTUALPITA can target specific guest virtual machines for script execution.
- [S1096] Cheerscrypt: Cheerscrypt has leveraged `esxcli vm process list` in order to gather a list of running virtual machines to terminate them.


### T1680 - Local Storage Discovery
Adversaries may enumerate local drives, disks, and/or volumes and their attributes like total or free space and volume serial number. This can be done to prepare for ransomware-related encryption, to perform Lateral Movement, or as a precursor to Direct Volume Access. On ESXi systems, adversaries may use Hypervisor CLI commands such as `esxcli` to list storage connected to the host as well as `.vmdk` files. On Windows systems, adversaries can use `wmic logicaldisk get` to find information about local network drives. They can also use `Get-PSDrive` in PowerShell to retrieve drives and may additionally use Windows API functions such as `GetDriveType`. Linux has commands such as `parted`, `lsblk`, `fdisk`, `lshw`, and `df` that can list information about disk partitions such as size, type, file system types, and free space. The command `diskutil` on MacOS can be used to list disks while `system_profiler SPStorageDataType` can additionally show information such as a volume’s mount path, file system, and the type of drive in the system. Infrastructure as a Service (IaaS) cloud providers also have commands for storage discovery such as `describe volume` in AWS, `gcloud compute disks list` in GCP, and `az disk list` in Azure.
**Detection**
- [AN0537] **[Linux]** Abnormal use of `lsblk`, `fdisk -l`, `lshw -class disk`, or `parted` by non-admin users or within non-interactive shells suggests suspicious disk enumeration activity.
- [AN0539] **[ESXi]** Use of `esxcli storage` or `vim-cmd vmsvc/getallvms` by unusual sessions or through interactive shells unrelated to administrative maintenance tasks.
- [AN0536] **[Windows]** Drive enumeration using PowerShell (`Get-PSDrive`), `wmic logicaldisk`, or Win32 API indicative of local volume enumeration by non-admin users or executed outside of baseline system inventory scripts.
- [AN0538] **[macOS]** Disk enumeration via `diskutil list` or `system_profiler SPStorageDataType` run outside of user login or not associated with system inventory tools
**Procedure Examples**
- [G0139] TeamTNT: TeamTNT has searched for disk partition and logical volume information.
- [S0533] SLOTHFULMEDIA: SLOTHFULMEDIA has collected disk information from a victim machine.
- [S1151] ZeroCleare: ZeroCleare can use the `IOCTL_DISK_GET_DRIVE_GEOMETRY_EX`, `IOCTL_DISK_GET_DRIVE_GEOMETRY`, and `IOCTL_DISK_GET_LENGTH_INFO` system calls to compute disk size.
- [S1049] SUGARUSH: MoonWind can obtain the number of drives on the victim machine.
- [S0625] Cuba: Cuba can enumerate local drives, disk type, and disk free space.
- [S0253] RunningRAT: RunningRAT gathers logical drives information and volume information.
- [S0678] Torisma: Torisma can use `GetlogicalDrives` to get a bitmask of all drives available on a compromised system. It can also use `GetDriveType` to determine if a new drive is a CD-ROM drive.
- [S0248] yty: yty gathers the the serial number of the main disk volume.
- [S1048] macOS.OSAMiner: macOS.OSAMiner has checked to ensure there is enough disk space using the Unix utility `df`.
- [C0017] C0017: During C0017, APT41 issued `ping -n 1 ((cmd /c dir c:\|findstr Number).split()[-1]+` commands to find the volume serial number of compromised systems.

