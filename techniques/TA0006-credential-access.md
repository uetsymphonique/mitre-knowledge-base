### T1003 - OS Credential Dumping
Adversaries may attempt to dump credentials to obtain account login and credential material, normally in the form of a hash or a clear text password. Credentials can be obtained from OS caches, memory, or structures. Credentials can then be used to perform Lateral Movement and access restricted information. Several of the tools mentioned in associated sub-techniques may be used by both adversaries and professional security testers. Additional custom tools likely exist as well.
**Detection**
- [AN0650] **[macOS]** Unsigned processes accessing system memory or launching known credential scraping tools (e.g., osascript, dylib injections) to access the Keychain or sensitive memory regions.
- [AN0648] **[Windows]** Processes accessing LSASS memory or SAM registry hives outside of trusted security tools, often followed by file creation or lateral movement. Detects unauthorized access to sensitive OS subsystems for credential extraction.
- [AN0649] **[Linux]** Processes opening /proc/*/mem or /proc/*/maps targeting credential-storing services like sshd or login. Behavior often includes high privilege escalation and memory inspection tools such as gcore or gdb.
**Procedure Examples**
- [G1003] Ember Bear: Ember Bear gathers credential material from target systems, such as SSH keys, to facilitate access to victim environments.
- [G0087] APT39: APT39 has used different versions of Mimikatz to obtain credentials.
- [S0030] Carbanak: Carbanak obtains Windows logon password details.
- [S1146] MgBot: MgBot includes modules for dumping and capturing credentials from process memory.
- [S0379] Revenge RAT: Revenge RAT has a plugin for credential harvesting.
- [S0048] PinchDuke: PinchDuke steals credentials from compromised hosts. PinchDuke's credential stealing functionality is believed to be based on the source code of the Pinch credential stealing malware (also known as LdPinch). Credentials targeted by PinchDuke include ones associated many sources such as WinInet Credential Cache, and Lightweight Directory Access Protocol (LDAP).
- [G0033] Poseidon Group: Poseidon Group conducts credential dumping on victims, with a focus on obtaining credentials belonging to domain and database servers.
- [S0052] OnionDuke: OnionDuke steals credentials from its victims.
- [G0129] Mustang Panda: Mustang Panda utilized “Hdump” to dump credentials from memory.
- [G0131] Tonto Team: Tonto Team has used a variety of credential dumping tools.


### T1003.001 - OS Credential Dumping: LSASS Memory
Adversaries may attempt to access credential material stored in the process memory of the Local Security Authority Subsystem Service (LSASS). After a user logs on, the system generates and stores a variety of credential materials in LSASS process memory. These credential materials can be harvested by an administrative user or SYSTEM and used to conduct Lateral Movement using Use Alternate Authentication Material. As well as in-memory techniques, the LSASS process memory can be dumped from the target host and analyzed on a local system. For example, on the target host use procdump: * procdump -ma lsass.exe lsass_dump Locally, mimikatz can be run using: * sekurlsa::Minidump lsassdump.dmp * sekurlsa::logonPasswords Built-in Windows tools such as `comsvcs.dll` can also be used: * rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump PID lsass.dmp full Similar to Image File Execution Options Injection, the silent process exit mechanism can be abused to create a memory dump of `lsass.exe` through Windows Error Reporting (`WerFault.exe`). Windows Security Support Provider (SSP) DLLs are loaded into LSASS process at system start. Once loaded into the LSA, SSP DLLs have access to encrypted and plaintext passwords that are stored in Windows, such as any logged-on user's Domain password or smart card PINs. The SSP configuration is stored in two Registry keys: HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages and HKLM\SYSTEM\CurrentControlSet\Control\Lsa\OSConfig\Security Packages. An adversary may modify these Registry keys to add new SSPs, which will be loaded the next time the system boots, or when the AddSecurityPackage Windows API function is called. The following SSPs can be used to access credentials: * Msv: Interactive logons, batch logons, and service logons are done through the MSV authentication package. * Wdigest: The Digest Authentication protocol is designed for use with Hypertext Transfer Protocol (HTTP) and Simple Authentication Security Layer (SASL) exchanges. * Kerberos: Preferred for mutual client-server domain authentication in Windows 2000 and later. * CredSSP: Provides SSO and Network Level Authentication for Remote Desktop Services.
**Detection**
- [AN1030] **[Windows]** A non-privileged or abnormal process attempts to open a handle with full access (0x1F0FFF) to lsass.exe and subsequently invokes memory dump, file creation, or registry modification indicative of credential scraping. This behavior chain reflects staged credential theft activity.
**Procedure Examples**
- [G0119] Indrik Spider: Indrik Spider used Cobalt Strike to carry out credential dumping using ProcDump.
- [C0014] Operation Wocao: During Operation Wocao, threat actors used ProcDump to dump credentials from memory.
- [G0049] OilRig: OilRig has used credential dumping tools such as Mimikatz to steal credentials to accounts logged into the compromised system and to Outlook Web Access.
- [G0003] Cleaver: Cleaver has been known to dump credentials using Mimikatz and Windows Credential Editor.
- [G0077] Leafminer: Leafminer used several tools for retrieving login and password information, including LaZagne and Mimikatz.
- [G0027] Threat Group-3390: Threat Group-3390 actors have used a modified version of Mimikatz called Wrapikatz to dump credentials. They have also dumped credentials from domain controllers.
- [S0692] SILENTTRINITY: SILENTTRINITY can create a memory dump of LSASS via the `MiniDumpWriteDump Win32` API call.
- [G0006] APT1: APT1 has been known to use credential dumping using Mimikatz.
- [C0029] Cutting Edge: During Cutting Edge, threat actors used Task Manager to dump LSASS memory from Windows devices to disk.
- [G0065] Leviathan: Leviathan has used publicly available tools to dump password hashes, including ProcDump and WCE.


### T1003.002 - OS Credential Dumping: Security Account Manager
Adversaries may attempt to extract credential material from the Security Account Manager (SAM) database either through in-memory techniques or through the Windows Registry where the SAM database is stored. The SAM is a database file that contains local accounts for the host, typically those found with the net user command. Enumerating the SAM database requires SYSTEM level access. A number of tools can be used to retrieve the SAM file through in-memory techniques: * pwdumpx.exe * gsecdump * Mimikatz * secretsdump.py Alternatively, the SAM can be extracted from the Registry with Reg: * reg save HKLM\sam sam * reg save HKLM\system system Creddump7 can then be used to process the SAM database locally to retrieve hashes. Notes: * RID 500 account is the local, built-in administrator. * RID 501 is the guest account. * User accounts start with a RID of 1,000+.
**Detection**
- [AN0235] **[Windows]** An adversary running with SYSTEM-level privileges executes commands or accesses registry keys to dump the SAM hive or directly reads sensitive local files from the config directory. This behavior often involves sequential access to HKLM\SAM, HKLM\SYSTEM, and creation of .save or .dmp files, enabling offline hash extraction.
**Procedure Examples**
- [G1034] Daggerfly: Daggerfly used Reg to dump the Security Account Manager (SAM) hive from victim machines for follow-on credential extraction.
- [S0488] CrackMapExec: CrackMapExec can dump usernames and hashed passwords from the SAM.
- [S0008] gsecdump: gsecdump can dump Windows password hashes from the SAM.
- [G0093] GALLIUM: GALLIUM used reg commands to dump specific hives from the Windows Registry, such as the SAM hive, and obtain password hashes.
- [C0041] FrostyGoop Incident: During FrostyGoop Incident, the adversary retrieved the contents of the Security Account Manager (SAM) hive in the victim environment for credential capture.
- [G0016] APT29: APT29 has used the `reg save` command to save registry hives.
- [S0250] Koadic: Koadic can gather hashed passwords by dumping SAM/SECURITY hive.
- [G1016] FIN13: FIN13 has extracted the SAM and SYSTEM registry hives using the `reg.exe` binary for obtaining password hashes from a compromised machine.
- [C0017] C0017: During C0017, APT41 copied the `SAM` and `SYSTEM` Registry hives for credential harvesting.
- [S0006] pwdump: pwdump can be used to dump credentials from the SAM.


### T1003.003 - OS Credential Dumping: NTDS
Adversaries may attempt to access or create a copy of the Active Directory domain database in order to steal credential information, as well as obtain other information about domain members such as devices, users, and access rights. By default, the NTDS file (NTDS.dit) is located in %SystemRoot%\NTDS\Ntds.dit of a domain controller. In addition to looking for NTDS files on active Domain Controllers, adversaries may search for backups that contain the same or similar information. The following tools and techniques can be used to enumerate the NTDS file and the contents of the entire Active Directory hashes. * Volume Shadow Copy * secretsdump.py * Using the in-built Windows tool, ntdsutil.exe * Invoke-NinjaCopy
**Detection**
- [AN1611] **[Windows]** Detects credential dumping attempts targeting the NTDS.dit database by monitoring shadow copy creation, suspicious file access to %SystemRoot%\NTDS\ntds.dit, and the use of tooling like ntdsutil.exe or volume management APIs.
**Procedure Examples**
- [G0007] APT28: APT28 has used the ntdsutil.exe utility to export the Active Directory database for credential access.
- [C0051] APT28 Nearest Neighbor Campaign: During APT28 Nearest Neighbor Campaign, APT28 dumped NTDS.dit through creating volume shadow copies via vssadmin.
- [C0048] Operation MidnightEclipse: During Operation MidnightEclipse, threat actors obtained active directory credentials via the NTDS.DIT file.
- [S0488] CrackMapExec: CrackMapExec can dump hashed passwords associated with Active Directory using Windows' Directory Replication Services API (DRSUAPI), or Volume Shadow Copy.
- [G1015] Scattered Spider: Scattered Spider has extracted the `NTDS.dit` file by creating volume shadow copies of virtual domain controller disks.
- [G0034] Sandworm Team: Sandworm Team has used `ntdsutil.exe` to back up the Active Directory database, likely for credential access.
- [G1016] FIN13: FIN13 has harvested the NTDS.DIT file and leveraged the Impacket tool on the compromised domain controller to locally decrypt it.
- [S0404] esentutl: esentutl can copy `ntds.dit` using the Volume Shadow Copy service.
- [G0037] FIN6: FIN6 has used Metasploit’s PsExec NTDSGRAB module to obtain a copy of the victim's Active Directory database.
- [G1017] Volt Typhoon: Volt Typhoon has used ntds.util to create domain controller installation media containing usernames and password hashes.


### T1003.004 - OS Credential Dumping: LSA Secrets
Adversaries with SYSTEM access to a host may attempt to access Local Security Authority (LSA) secrets, which can contain a variety of different credential materials, such as credentials for service accounts. LSA secrets are stored in the registry at HKEY_LOCAL_MACHINE\SECURITY\Policy\Secrets. LSA secrets can also be dumped from memory. Reg can be used to extract from the Registry. Mimikatz can be used to extract secrets from memory.
**Detection**
- [AN1212] **[Windows]** Detects adversary activity aimed at accessing LSA Secrets, including registry key export of HKEY_LOCAL_MACHINE\SECURITY\Policy\Secrets or memory scraping via tools such as Mimikatz or PowerSploit's Invoke-Mimikatz.
**Procedure Examples**
- [G0069] MuddyWater: MuddyWater has performed credential dumping with LaZagne.
- [S1022] IceApple: IceApple's Credential Dumper module can dump LSA secrets from registry keys, including: `HKLM\SECURITY\Policy\PolEKList\default`, `HKLM\SECURITY\Policy\Secrets\*\CurrVal`, and `HKLM\SECURITY\Policy\Secrets\*\OldVal`.
- [S0050] CosmicDuke: CosmicDuke collects LSA secrets.
- [S0008] gsecdump: gsecdump can dump LSA secrets.
- [S0349] LaZagne: LaZagne can perform credential dumping from LSA secrets to obtain account and password information.
- [G0027] Threat Group-3390: Threat Group-3390 actors have used gsecdump to dump credentials. They have also dumped credentials from domain controllers.
- [G0049] OilRig: OilRig has used credential dumping tools such as LaZagne to steal credentials to accounts logged into the compromised system and to Outlook Web Access.
- [S0488] CrackMapExec: CrackMapExec can dump hashed passwords from LSA secrets for the targeted system.
- [G0077] Leafminer: Leafminer used several tools for retrieving login and password information, including LaZagne.
- [G0064] APT33: APT33 has used a variety of publicly available tools like LaZagne to gather credentials.


### T1003.005 - OS Credential Dumping: Cached Domain Credentials
Adversaries may attempt to access cached domain credentials used to allow authentication to occur in the event a domain controller is unavailable. On Windows Vista and newer, the hash format is DCC2 (Domain Cached Credentials version 2) hash, also known as MS-Cache v2 hash. The number of default cached credentials varies and can be altered per system. This hash does not allow pass-the-hash style attacks, and instead requires Password Cracking to recover the plaintext password. On Linux systems, Active Directory credentials can be accessed through caches maintained by software like System Security Services Daemon (SSSD) or Quest Authentication Services (formerly VAS). Cached credential hashes are typically located at `/var/lib/sss/db/cache.[domain].ldb` for SSSD or `/var/opt/quest/vas/authcache/vas_auth.vdb` for Quest. Adversaries can use utilities, such as `tdbdump`, on these database files to dump the cached hashes and use Password Cracking to obtain the plaintext password. With SYSTEM or sudo access, the tools/utilities such as Mimikatz, Reg, and secretsdump.py for Windows or Linikatz for Linux can be used to extract the cached credentials. Note: Cached credentials for Windows Vista are derived using PBKDF2.
**Detection**
- [AN1417] **[Windows]** Detects adversary behavior accessing Windows cached domain credential files using tools like Mimikatz, reg.exe, or PowerShell, often combined with registry exports or LSASS memory scraping.
- [AN1418] **[Linux]** Detects access to SSSD or Quest VAS cached credential databases using tdbdump or other file access patterns, requiring sudo/root access.
**Procedure Examples**
- [S0439] Okrum: Okrum was seen using modified Quarks PwDump to perform credential dumping.
- [G0064] APT33: APT33 has used a variety of publicly available tools like LaZagne to gather credentials.
- [G0077] Leafminer: Leafminer used several tools for retrieving login and password information, including LaZagne.
- [S0119] Cachedump: Cachedump can extract cached password hashes from cache entry information.
- [S0349] LaZagne: LaZagne can perform credential dumping from MSCache to obtain account and password information.
- [G0049] OilRig: OilRig has used credential dumping tools such as LaZagne to steal credentials to accounts logged into the compromised system and to Outlook Web Access.
- [S0192] Pupy: Pupy can use Lazagne for harvesting credentials.
- [G0069] MuddyWater: MuddyWater has performed credential dumping with LaZagne.


### T1003.006 - OS Credential Dumping: DCSync
Adversaries may attempt to access credentials and other sensitive information by abusing a Windows Domain Controller's application programming interface (API) to simulate the replication process from a remote domain controller using a technique called DCSync. Members of the Administrators, Domain Admins, and Enterprise Admin groups or computer accounts on the domain controller are able to run DCSync to pull password data from Active Directory, which may include current and historical hashes of potentially useful accounts such as KRBTGT and Administrators. The hashes can then in turn be used to create a Golden Ticket for use in Pass the Ticket or change an account's password as noted in Account Manipulation. DCSync functionality has been included in the "lsadump" module in Mimikatz. Lsadump also includes NetSync, which performs DCSync over a legacy replication protocol.
**Detection**
- [AN1632] **[Windows]** Detects unauthorized invocation of replication operations (DCSync) via Directory Replication Service (DRS), often executed by threat actors using Mimikatz or similar tools from non-DC endpoints.
**Procedure Examples**
- [S0002] Mimikatz: Mimikatz performs credential dumping to obtain account and password information useful in gaining access to additional systems and enterprise network resources. It contains functionality to acquire information about credentials in many ways, including from DCSync/NetSync.
- [G1006] Earth Lusca: Earth Lusca has used a DCSync command with Mimikatz to retrieve credentials from an exploited controller.
- [C0027] C0027: During C0027, Scattered Spider performed domain replication.
- [G0129] Mustang Panda: Mustang Panda has leveraged Mimikatz DCSync feature to obtain user credentials.
- [G1053] Storm-0501: Storm-0501 has utilized DCSync to extract credentials from victims.
- [C0014] Operation Wocao: During Operation Wocao, threat actors used Mimikatz's DCSync to dump credentials from the memory of the targeted system.
- [G1004] LAPSUS$: LAPSUS$ has used DCSync attacks to gather credentials for privilege escalation routines.
- [C0024] SolarWinds Compromise: During the SolarWinds Compromise, APT29 used privileged accounts to replicate directory service data with domain controllers.


### T1003.007 - OS Credential Dumping: Proc Filesystem
Adversaries may gather credentials from the proc filesystem or `/proc`. The proc filesystem is a pseudo-filesystem used as an interface to kernel data structures for Linux based systems managing virtual memory. For each process, the `/proc//maps` file shows how memory is mapped within the process’s virtual address space. And `/proc//mem`, exposed for debugging purposes, provides access to the process’s virtual address space. When executing with root privileges, adversaries can search these memory locations for all processes on a system that contain patterns indicative of credentials. Adversaries may use regex patterns, such as grep -E "^[0-9a-f-]* r" /proc/"$pid"/maps | cut -d' ' -f 1, to look for fixed strings in memory structures or cached hashes. When running without privileged access, processes can still view their own virtual memory locations. Some services or programs may save credentials in clear text inside the process’s memory. If running as or with the permissions of a web browser, a process can search the `/maps` & `/mem` locations for common website credential patterns (that can also be used to find adjacent memory within the same structure) in which hashes or cleartext credentials may be located.
**Detection**
- [AN1631] **[Linux]** Monitoring adversary access to sensitive process memory via the /proc filesystem to extract credential material, often involving multi-step access to /proc/[pid]/mem or /proc/[pid]/maps combined with privilege escalation or credential scraping binaries.
**Procedure Examples**
- [S1109] PACEMAKER: PACEMAKER has the ability to extract credentials from OS memory.
- [S0349] LaZagne: LaZagne can use the `/maps` and `/mem` files to identify regex patterns to dump cleartext passwords from the browser's process memory.
- [S0179] MimiPenguin: MimiPenguin can use the `/maps` and `/mem` file to search for regex patterns and dump the process memory.


### T1003.008 - OS Credential Dumping: /etc/passwd and /etc/shadow
Adversaries may attempt to dump the contents of /etc/passwd and /etc/shadow to enable offline password cracking. Most modern Linux operating systems use a combination of /etc/passwd and /etc/shadow to store user account information, including password hashes in /etc/shadow. By default, /etc/shadow is only readable by the root user. Linux stores user information such as user ID, group ID, home directory path, and login shell in /etc/passwd. A "user" on the system may belong to a person or a service. All password hashes are stored in /etc/shadow - including entries for users with no passwords and users with locked or disabled accounts. Adversaries may attempt to read or dump the /etc/passwd and /etc/shadow files on Linux systems via command line utilities such as the cat command. Additionally, the Linux utility unshadow can be used to combine the two files in a format suited for password cracking utilities such as John the Ripper - for example, via the command /usr/bin/unshadow /etc/passwd /etc/shadow > /tmp/crack.password.db. Since the user information stored in /etc/passwd are linked to the password hashes in /etc/shadow, an adversary would need to have access to both.
**Detection**
- [AN1234] **[Linux]** Adversaries attempt to read sensitive files such as /etc/passwd and /etc/shadow for credential dumping. This may involve access to the files directly via command-line utilities (e.g., cat, less), creation of backup copies, or parsing through post-exploitation frameworks. Multi-event correlation includes elevated process execution, file access/read on sensitive paths, and anomalous read behaviors tied to non-root or unusual users.
**Procedure Examples**
- [S0349] LaZagne: LaZagne can obtain credential information from /etc/shadow using the shadow.py module.
- [C0045] ShadowRay: During ShadowRay, threat actors used `cat /etc/shadow` to steal password hashes.


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


### T1110 - Brute Force
Adversaries may use brute force techniques to gain access to accounts when passwords are unknown or when password hashes are obtained. Without knowledge of the password for an account or set of accounts, an adversary may systematically guess the password using a repetitive or iterative mechanism. Brute forcing passwords can take place via interaction with a service that will check the validity of those credentials or offline against previously acquired credential data, such as password hashes. Brute forcing credentials may take place at various points during a breach. For example, adversaries may attempt to brute force access to Valid Accounts within a victim environment leveraging knowledge gathered from other post-compromise behaviors such as OS Credential Dumping, Account Discovery, or Password Policy Discovery. Adversaries may also combine brute forcing activity with behaviors such as External Remote Services as part of Initial Access. If an adversary guesses the correct password but fails to login to a compromised account due to location-based conditional access policies, they may change their infrastructure until they match the victim’s location and therefore bypass those policies.
**Detection**
- [AN1277] **[Identity Provider]** Password spraying or brute force attempts across user pool within short time intervals
- [AN1279] **[SaaS]** Excessive login attempts followed by success from SaaS apps like O365, Dropbox, etc.
- [AN1278] **[macOS]** Multiple failed authentications in unified logs (e.g., loginwindow or sshd)
- [AN1276] **[Linux]** Multiple authentication failures for valid or invalid users followed by success from same IP/user
- [AN1275] **[Windows]** High volume of failed logon attempts followed by a successful one from a suspicious user, host, or timeframe
**Procedure Examples**
- [G0117] Fox Kitten: Fox Kitten has brute forced RDP credentials.
- [G1001] HEXANE: HEXANE has used brute force attacks to compromise valid credentials.
- [S0220] Chaos: Chaos conducts brute force attacks against SSH services to gain initial access.
- [S0572] Caterpillar WebShell: Caterpillar WebShell has a module to perform brute force attacks on a system.
- [G1003] Ember Bear: Ember Bear used the `su-bruteforce` tool to brute force specific users using the `su` command.
- [G0010] Turla: Turla may attempt to connect to systems within a victim's network using net use commands and a predefined list or collection of passwords.
- [G0105] DarkVishnya: DarkVishnya used brute-force attack to obtain login data.
- [C0022] Operation Dream Job: During Operation Dream Job, Lazarus Group performed brute force attacks against administrator accounts.
- [G0053] FIN5: FIN5 has has used the tool GET2 Penetrator to look for remote login and hard-coded credentials.
- [S0599] Kinsing: Kinsing has attempted to brute force hosts over SSH.


### T1110.001 - Brute Force: Password Guessing
Adversaries with no prior knowledge of legitimate credentials within the system or environment may guess passwords to attempt access to accounts. Without knowledge of the password for an account, an adversary may opt to systematically guess the password using a repetitive or iterative mechanism. An adversary may guess login credentials without prior knowledge of system or environment passwords during an operation by using a list of common passwords. Password guessing may or may not take into account the target's policies on password complexity or use policies that may lock accounts out after a number of failed attempts. Guessing passwords can be a risky option because it could cause numerous authentication failures and account lockouts, depending on the organization's login failure policies. Typically, management services over commonly used ports are used when guessing passwords. Commonly targeted services include the following: * SSH (22/TCP) * Telnet (23/TCP) * FTP (21/TCP) * NetBIOS / SMB / Samba (139/TCP & 445/TCP) * LDAP (389/TCP) * Kerberos (88/TCP) * RDP / Terminal Services (3389/TCP) * HTTP/HTTP Management Services (80/TCP & 443/TCP) * MSSQL (1433/TCP) * Oracle (1521/TCP) * MySQL (3306/TCP) * VNC (5900/TCP) * SNMP (161/UDP and 162/TCP/UDP) In addition to management services, adversaries may "target single sign-on (SSO) and cloud-based applications utilizing federated authentication protocols," as well as externally facing email applications, such as Office 365.. Further, adversaries may abuse network device interfaces (such as `wlanAPI`) to brute force accessible wifi-router(s) via wireless authentication protocols. In default environments, LDAP and Kerberos connection attempts are less likely to trigger events over SMB, which creates Windows "logon failure" event ID 4625.
**Detection**
- [AN1525] **[Network Devices]** Login attempt failures over SNMP, Telnet, or SSH interface, often reflected in logs or syslog events
- [AN1522] **[Linux]** Repeated failed SSH login attempts followed by a possible success from the same remote host
- [AN1526] **[SaaS]** Password guessing attempts against web-based apps (e.g., Dropbox, Google Workspace) reflected in API or sign-in logs
- [AN1521] **[Windows]** Series of authentication failures (Event ID 4625) targeting the same or similar user accounts over time from one or more remote IPs
- [AN1523] **[macOS]** Series of failed logins from loginwindow or sshd with repeated usernames or password prompts
- [AN1524] **[Identity Provider]** Multiple failed sign-in attempts from external sources across many users followed by success from the same IP
**Procedure Examples**
- [S0020] China Chopper: China Chopper's server component can perform brute force password guessing against authentication portals.
- [S0367] Emotet: Emotet has been observed using a hard coded list of passwords to brute force user accounts.
- [S0374] SpeakUp: SpeakUp can perform brute forcing using a pre-defined list of usernames and passwords in an attempt to log in to administrative panels.
- [G0007] APT28: APT28 has used a brute-force/password-spray tooling that operated in two modes: in brute-force mode it typically sent over 300 authentication attempts per hour per targeted account over the course of several hours or days. APT28 has also used a Kubernetes cluster to conduct distributed, large-scale password guessing attacks.
- [S0488] CrackMapExec: CrackMapExec can brute force passwords for a specified user on a single target system or across an entire network.
- [S0698] HermeticWizard: HermeticWizard can use a list of hardcoded credentials in attempt to authenticate to SMB shares.
- [G0016] APT29: APT29 has successfully conducted password guessing attacks against a list of mailboxes.
- [S0532] Lucifer: Lucifer has attempted to brute force TCP ports 135 (RPC) and 1433 (MSSQL) with the default username or list of usernames and passwords.
- [S0453] Pony: Pony has used a small dictionary of common passwords against a collected list of local accounts.
- [S0341] Xbash: Xbash can obtain a list of weak passwords from the C2 server to use for brute forcing as well as attempt to brute force services with open ports.


### T1110.002 - Brute Force: Password Cracking
Adversaries may use password cracking to attempt to recover usable credentials, such as plaintext passwords, when credential material such as password hashes are obtained. OS Credential Dumping can be used to obtain password hashes, this may only get an adversary so far when Pass the Hash is not an option. Further, adversaries may leverage Data from Configuration Repository in order to obtain hashed credentials for network devices. Techniques to systematically guess the passwords used to compute hashes are available, or the adversary may use a pre-computed rainbow table to crack hashes. Cracking hashes is usually done on adversary-controlled systems outside of the target network. The resulting plaintext password resulting from a successfully cracked hash may be used to log into systems, resources, and services in which the account has access.
**Detection**
- [AN0295] **[Identity Provider]** Sudden valid logins from accounts that previously had credentials dumped but had not authenticated successfully in the past; correlated with timeline of suspected hash cracking
- [AN0296] **[Network Devices]** Offline cracking inferred by subsequent successful CLI or web-based authentications into routers or switches from previously dumped accounts
- [AN0294] **[macOS]** Unsigned or scripting-based processes invoking password cracking binaries or accessing hashed credential artifacts post-login
- [AN0293] **[Linux]** Execution of hash cracking binaries or scripts (e.g., john, hashcat) following access to shadow file or dumped hashes
- [AN0292] **[Windows]** Use of hash-cracking tools (e.g., John the Ripper, Hashcat) after credential dumping, combined with high CPU usage or GPU invocation via unsigned binaries accessing password hash files
**Procedure Examples**
- [G0022] APT3: APT3 has been known to brute force password hashes to be able to leverage plain text credentials.
- [S0056] Net Crawler: Net Crawler uses a list of known credentials gathered through credential dumping to guess passwords to accounts as it spreads throughout a network.
- [G0035] Dragonfly: Dragonfly has dropped and executed tools used for password cracking, including Hydra and CrackMapExec.
- [G1045] Salt Typhoon: Salt Typhoon has cracked passwords for accounts with weak encryption obtained from the configuration files of compromised network devices.
- [G0037] FIN6: FIN6 has extracted password hashes from ntds.dit to crack offline.
- [C0002] Night Dragon: During Night Dragon, threat actors used Cain & Abel to crack password hashes.


### T1110.003 - Brute Force: Password Spraying
Adversaries may use a single or small list of commonly used passwords against many different accounts to attempt to acquire valid account credentials. Password spraying uses one password (e.g. 'Password01'), or a small list of commonly used passwords, that may match the complexity policy of the domain. Logins are attempted with that password against many different accounts on a network to avoid account lockouts that would normally occur when brute forcing a single account with many passwords. Typically, management services over commonly used ports are used when password spraying. Commonly targeted services include the following: * SSH (22/TCP) * Telnet (23/TCP) * FTP (21/TCP) * NetBIOS / SMB / Samba (139/TCP & 445/TCP) * LDAP (389/TCP) * Kerberos (88/TCP) * RDP / Terminal Services (3389/TCP) * HTTP/HTTP Management Services (80/TCP & 443/TCP) * MSSQL (1433/TCP) * Oracle (1521/TCP) * MySQL (3306/TCP) * VNC (5900/TCP) In addition to management services, adversaries may "target single sign-on (SSO) and cloud-based applications utilizing federated authentication protocols," as well as externally facing email applications, such as Office 365. In order to avoid detection thresholds, adversaries may deliberately throttle password spraying attempts to avoid triggering security alerting. Additionally, adversaries may leverage LDAP and Kerberos authentication attempts, which are less likely to trigger high-visibility events such as Windows "logon failure" event ID 4625 that is commonly triggered by failed SMB connection attempts.
**Detection**
- [AN1339] **[Identity Provider]** Sign-in failures across enterprise SSO applications or SaaS platforms from same IP address using the same password against multiple user identities
- [AN1337] **[Linux]** Authentication failures across different accounts using a repeated or similar password via SSH or PAM stack within a short window
- [AN1338] **[macOS]** Multiple failed login attempts across different users using common password patterns (e.g., 'Welcome2023')
- [AN1336] **[Windows]** A high volume of authentication failures using a single password (or small set) across many different user accounts within a defined time window
- [AN1341] **[Containers]** Repeated failed authentication attempts to container APIs, control planes, or login shells across many user names using same password
- [AN1340] **[Network Devices]** Authentication failure logs on routers/switches showing repeated use of default or common passwords across multiple accounts
- [AN1343] **[SaaS]** SaaS applications receiving authentication failures for dozens of accounts using same password or login signature
- [AN1342] **[Office Suite]** Failed authentication attempts across user mailboxes using identical or common passwords (e.g., OWA brute attempts)
**Procedure Examples**
- [G0125] HAFNIUM: HAFNIUM has gained initial access through password spray attacks.
- [S0606] Bad Rabbit: Bad Rabbit’s infpub.dat file uses NTLM login credentials to brute force Windows machines.
- [S0488] CrackMapExec: CrackMapExec can brute force credential authentication by using a supplied list of usernames and a single password.
- [S0362] Linux Rabbit: Linux Rabbit brute forces SSH passwords in order to attempt to gain access and install its malware onto the server.
- [C0051] APT28 Nearest Neighbor Campaign: During APT28 Nearest Neighbor Campaign, APT28 performed password-spray attacks against public facing services to validate credentials.
- [G1030] Agrius: Agrius engaged in password spraying via SMB in victim environments.
- [G1003] Ember Bear: Ember Bear has conducted password spraying against Outlook Web Access (OWA) infrastructure to identify valid user names and passwords.
- [G0016] APT29: APT29 has conducted brute force password spray attacks.
- [C0055] Quad7 Activity: Quad7 Activity has conducted a throttled variant of password spraying techniques that only utilized a single attempt to sign in within a 24-hour time period, eluding brute force detection thresholds.
- [G1001] HEXANE: HEXANE has used password spraying attacks to obtain valid credentials.


### T1110.004 - Brute Force: Credential Stuffing
Adversaries may use credentials obtained from breach dumps of unrelated accounts to gain access to target accounts through credential overlap. Occasionally, large numbers of username and password pairs are dumped online when a website or service is compromised and the user account credentials accessed. The information may be useful to an adversary attempting to compromise accounts by taking advantage of the tendency for users to use the same passwords across personal and business accounts. Credential stuffing is a risky option because it could cause numerous authentication failures and account lockouts, depending on the organization's login failure policies. Typically, management services over commonly used ports are used when stuffing credentials. Commonly targeted services include the following: * SSH (22/TCP) * Telnet (23/TCP) * FTP (21/TCP) * NetBIOS / SMB / Samba (139/TCP & 445/TCP) * LDAP (389/TCP) * Kerberos (88/TCP) * RDP / Terminal Services (3389/TCP) * HTTP/HTTP Management Services (80/TCP & 443/TCP) * MSSQL (1433/TCP) * Oracle (1521/TCP) * MySQL (3306/TCP) * VNC (5900/TCP) In addition to management services, adversaries may "target single sign-on (SSO) and cloud-based applications utilizing federated authentication protocols," as well as externally facing email applications, such as Office 365.
**Detection**
- [AN1269] **[Office Suite]** Use of leaked credential pairs against Outlook Web Access (OWA), Microsoft 365, or Exchange from a single client IP with multiple failures
- [AN1268] **[Containers]** Credential stuffing attempts against Kubernetes API or containerized login shells using stolen or leaked user credentials
- [AN1265] **[Identity Provider]** Same source IP performing multiple authentication attempts using known breached username/password combinations across different identities in Azure AD, Okta, or Duo
- [AN1267] **[Network Devices]** Router/firewall/syslog logs showing authentication failures with unique usernames and reused credentials from same source IP
- [AN1263] **[Linux]** Rapid login failures across different users from a single IP address, targeting SSH or PAM login with distinct username-password pairs
- [AN1266] **[SaaS]** Multiple sign-in failures against cloud-based applications using username/password combinations leaked from unrelated domains
- [AN1270] **[IaaS]** Burst of failed login attempts across VM instances using leaked credential pairs from single IP in public cloud environments
- [AN1264] **[macOS]** Burst of failed authentications with rotating usernames against loginwindow or remote management service using reused breached credentials
- [AN1262] **[Windows]** Multiple failed authentication attempts using distinct username/password pairs from a single IP address or session within a short time window, targeting common services like RDP or SMB
**Procedure Examples**
- [G0114] Chimera: Chimera has used credential stuffing against victim's remote services to obtain valid accounts.
- [S0266] TrickBot: TrickBot uses brute-force attack against RDP with rdpscanDll module.


### T1111 - Multi-Factor Authentication Interception
Adversaries may target multi-factor authentication (MFA) mechanisms, (i.e., smart cards, token generators, etc.) to gain access to credentials that can be used to access systems, services, and network resources. Use of MFA is recommended and provides a higher level of security than usernames and passwords alone, but organizations should be aware of techniques that could be used to intercept and bypass these security mechanisms. If a smart card is used for multi-factor authentication, then a keylogger will need to be used to obtain the password associated with a smart card during normal use. With both an inserted card and access to the smart card password, an adversary can connect to a network resource using the infected system to proxy the authentication with the inserted hardware token. Adversaries may also employ a keylogger to similarly target other hardware tokens, such as RSA SecurID. Capturing token input (including a user's personal identification code) may provide temporary access (i.e. replay the one-time passcode until the next value rollover) as well as possibly enabling adversaries to reliably predict future authentication values (given access to both the algorithm and any seed values used to generate appended temporary codes). Other methods of MFA may be intercepted and used by an adversary to authenticate. It is common for one-time codes to be sent via out-of-band communications (email, SMS). If the device and/or service is not secured, then it may be vulnerable to interception. Service providers can also be targeted: for example, an adversary may compromise an SMS messaging service in order to steal MFA codes sent to users’ phones.
**Detection**
- [AN0688] **[Linux]** Detection of unauthorized keylogger behavior through access to `/dev/input`, loading kernel modules (e.g., via insmod), or polling user input devices from non-user shells
- [AN0689] **[macOS]** Processes accessing TCC-protected input APIs or polling HID services without user interaction, or dynamically loaded keylogging frameworks using accessibility privileges
- [AN0687] **[Windows]** Behavior chain involving unexpected API calls to capture keyboard input, driver loads for keyloggers, or remote use of smart card authentication via logon sessions not initiated by local user interaction
**Procedure Examples**
- [S1104] SLOWPULSE: SLOWPULSE can log credentials on compromised Pulse Secure VPNs during the `DSAuth::AceAuthServer::checkUsernamePassword`ACE-2FA authentication procedure.
- [S0018] Sykipot: Sykipot is known to contain functionality that enables targeting of smart card technologies to proxy authentication for connections to restricted network resources using detected hardware tokens.
- [C0014] Operation Wocao: During Operation Wocao, threat actors used a custom collection method to intercept two-factor authentication soft tokens.
- [G0094] Kimsuky: Kimsuky has used a proprietary tool to intercept one time passwords required for two-factor authentication.
- [C0049] Leviathan Australian Intrusions: Leviathan abused compromised appliance access to collect multifactor authentication token values during Leviathan Australian Intrusions.
- [G0114] Chimera: Chimera has registered alternate phone numbers for compromised users to intercept 2FA codes sent via SMS.
- [G1044] APT42: APT42 has intercepted SMS-based one-time passwords and has set up two-factor authentication. Additionally, APT42 has used cloned or fake websites to capture MFA tokens.
- [G1004] LAPSUS$: LAPSUS$ has replayed stolen session token and passwords to trigger simple-approval MFA prompts in hope of the legitimate user will grant necessary approval.


### T1187 - Forced Authentication
Adversaries may gather credential material by invoking or forcing a user to automatically provide authentication information through a mechanism in which they can intercept. The Server Message Block (SMB) protocol is commonly used in Windows networks for authentication and communication between systems for access to resources and file sharing. When a Windows system attempts to connect to an SMB resource it will automatically attempt to authenticate and send credential information for the current user to the remote system. This behavior is typical in enterprise environments so that users do not need to enter credentials to access network resources. Web Distributed Authoring and Versioning (WebDAV) is also typically used by Windows systems as a backup protocol when SMB is blocked or fails. WebDAV is an extension of HTTP and will typically operate over TCP ports 80 and 443. Adversaries may take advantage of this behavior to gain access to user account hashes through forced SMB/WebDAV authentication. An adversary can send an attachment to a user through spearphishing that contains a resource link to an external server controlled by the adversary (i.e. Template Injection), or place a specially crafted file on navigation path for privileged accounts (e.g. .SCF file placed on desktop) or on a publicly accessible share to be accessed by victim(s). When the user's system accesses the untrusted resource, it will attempt authentication and send information, including the user's hashed credentials, over SMB to the adversary-controlled server. With access to the credential hash, an adversary can perform off-line Brute Force cracking to gain access to plaintext credentials. There are several different ways this can occur. Some specifics from in-the-wild use include: * A spearphishing attachment containing a document with a resource that is automatically loaded when the document is opened (i.e. Template Injection). The document can include, for example, a request similar to file[:]//[remote address]/Normal.dotm to trigger the SMB request. * A modified .LNK or .SCF file with the icon filename pointing to an external reference such as \\[remote address]\pic.png that will force the system to load the resource when the icon is rendered to repeatedly gather credentials. Alternatively, by leveraging the EfsRpcOpenFileRaw function, an adversary can send SMB requests to a remote system's MS-EFSRPC interface and force the victim computer to initiate an authentication procedure and share its authentication details. The Encrypting File System Remote Protocol (EFSRPC) is a protocol used in Windows networks for maintenance and management operations on encrypted data that is stored remotely to be accessed over a network. Utilization of EfsRpcOpenFileRaw function in EFSRPC is used to open an encrypted object on the server for backup or restore. Adversaries can collect this data and abuse it as part of a NTLM relay attack to gain access to remote systems on the same internal network.
**Detection**
- [AN0065] **[Windows]** Adversary stages a lure that references a remote resource (e.g., LNK/SCF/Office template). When the user opens/renders the file or a shell enumerates icons, the host automatically attempts SMB or WebDAV authentication to the attacker host. The chain is: (1) lure file is created or modified in a user-exposed location → (2) user or system accesses the lure → (3) host makes outbound NTLM (SMB 139/445 or WebDAV over 80/443) to an untrusted destination → (4) repeated attempts from multiple users/hosts or from privileged workstations.
**Procedure Examples**
- [G0079] DarkHydrus: DarkHydrus used Template Injection to launch an authentication window for users to enter their credentials.
- [G0035] Dragonfly: Dragonfly has gathered hashed user credentials over SMB using spearphishing attachments with external resource links and by modifying .LNK file icon resources to collect credentials from virtualized systems.
- [S0634] EnvyScout: EnvyScout can use protocol handlers to coax the operating system to send NTLMv2 authentication responses to attacker-controlled infrastructure.


### T1212 - Exploitation for Credential Access
Adversaries may exploit software vulnerabilities in an attempt to collect credentials. Exploitation of a software vulnerability occurs when an adversary takes advantage of a programming error in a program, service, or within the operating system software or kernel itself to execute adversary-controlled code. Credentialing and authentication mechanisms may be targeted for exploitation by adversaries as a means to gain access to useful credentials or circumvent the process to gain authenticated access to systems. One example of this is `MS14-068`, which targets Kerberos and can be used to forge Kerberos tickets using domain user permissions. Another example of this is replay attacks, in which the adversary intercepts data packets sent between parties and then later replays these packets. If services don't properly validate authentication requests, these replayed packets may allow an adversary to impersonate one of the parties and gain unauthorized access or privileges. Such exploitation has been demonstrated in cloud environments as well. For example, adversaries have exploited vulnerabilities in public cloud infrastructure that allowed for unintended authentication token creation and renewal. Exploitation for credential access may also result in Privilege Escalation depending on the process targeted or credentials obtained.
**Detection**
- [AN0496] **[Identity Provider]** Detects exploitation of vulnerabilities in cloud identity providers (IdPs) such as Azure AD or Okta for credential access. Defender perspective includes anomalous token creation or renewal, authentication bypass events, and API abuse to mint unauthorized tokens. Correlation highlights exploitation attempts tied to absent or inconsistent audit logs.
- [AN0493] **[Windows]** Detects adversary exploitation of authentication mechanisms or credential validation processes. Defender perspective includes forged Kerberos tickets (e.g., MS14-068), abnormal LSASS memory access, replayed authentication attempts, and unexpected crashes of authentication services. Multi-event correlation ties exploitation attempts to abnormal process creation, service instability, and suspicious authentication events.
- [AN0494] **[Linux]** Detects exploitation of authentication daemons or PAM modules. Defender perspective includes failed or anomalous PAM authentications, abnormal segfaults in authentication services, and exploitation attempts followed by successful unauthorized logins. Correlation identifies memory corruption, replay attempts, and privilege escalation tied to credential services.
- [AN0495] **[macOS]** Detects exploitation attempts against macOS authentication frameworks such as OpenDirectory or Keychain. Defender perspective includes abnormal crashes in opendirectoryd, unauthorized Keychain API usage, and unusual sudo or login events. Correlation links unexpected process behavior with credential access anomalies.
**Procedure Examples**
- [G1048] UNC3886: UNC3886 exploited CVE-2022-22948 in VMware vCenter to obtain encrypted credentials from the vCenter postgresDB.
- [C0049] Leviathan Australian Intrusions: Leviathan exploited vulnerable network appliances during Leviathan Australian Intrusions, leading to the collection and exfiltration of valid credentials.


### T1528 - Steal Application Access Token
Adversaries can steal application access tokens as a means of acquiring credentials to access remote systems and resources. Application access tokens are used to make authorized API requests on behalf of a user or service and are commonly used as a way to access resources in cloud and container-based applications and software-as-a-service (SaaS). Adversaries who steal account API tokens in cloud and containerized environments may be able to access data and perform actions with the permissions of these accounts, which can lead to privilege escalation and further compromise of the environment. For example, in Kubernetes environments, processes running inside a container may communicate with the Kubernetes API server using service account tokens. If a container is compromised, an adversary may be able to steal the container’s token and thereby gain access to Kubernetes API commands. Similarly, instances within continuous-development / continuous-integration (CI/CD) pipelines will often use API tokens to authenticate to other services for testing and deployment. If these pipelines are compromised, adversaries may be able to steal these tokens and leverage their privileges. In Azure, an adversary who compromises a resource with an attached Managed Identity, such as an Azure VM, can request short-lived tokens through the Azure Instance Metadata Service (IMDS). These tokens can then facilitate unauthorized actions or further access to other Azure services, bypassing typical credential-based authentication. Token theft can also occur through social engineering, in which case user action may be required to grant access. OAuth is one commonly implemented framework that issues tokens to users for access to systems. An application desiring access to cloud-based services or protected APIs can gain entry using OAuth 2.0 through a variety of authorization protocols. An example commonly-used sequence is Microsoft's Authorization Code Grant flow. An OAuth access token enables a third-party application to interact with resources containing user data in the ways requested by the application without obtaining user credentials. Adversaries can leverage OAuth authorization by constructing a malicious application designed to be granted access to resources with the target user's OAuth token. The adversary will need to complete registration of their application with the authorization server, for example Microsoft Identity Platform using Azure Portal, the Visual Studio IDE, the command-line interface, PowerShell, or REST API calls. Then, they can send a Spearphishing Link to the target user to entice them to grant access to the application. Once the OAuth access token is granted, the application can gain potentially long-term access to features of the user account through Application Access Token. Application access tokens may function within a limited lifetime, limiting how long an adversary can utilize the stolen token. However, in some cases, adversaries can also steal application refresh tokens, allowing them to obtain new access tokens without prompting the user.
**Detection**
- [AN1427] **[SaaS]** Programmatic access to user content via stolen access tokens in platforms like Slack, GitHub, Google Workspace — especially from new IPs, apps, or excessive resource access.
- [AN1424] **[IaaS]** Token retrieval from instance metadata endpoints such as AWS IMDS or Azure IMDS, followed by API usage using the obtained token from non-standard applications.
- [AN1423] **[Containers]** Access and retrieval of container service account tokens followed by unauthorized API requests using those tokens to interact with the Kubernetes API server or internal services.
- [AN1425] **[Identity Provider]** Unusual OAuth app registration followed by user-granted OAuth tokens and subsequent high-privilege resource access via those tokens.
- [AN1426] **[Office Suite]** Use of OAuth tokens by third-party apps to access user mail, calendar, or SharePoint resources where the token was granted recently or via spearphishing.
**Procedure Examples**
- [G0016] APT29: APT29 uses stolen tokens to access victim accounts, without needing a password.
- [S0683] Peirates: Peirates gathers Kubernetes service account tokens using a variety of techniques.
- [S0677] AADInternals: AADInternals can steal users’ access tokens via phishing emails containing malicious links.
- [G0007] APT28: APT28 has used several malicious applications to steal user OAuth access tokens including applications masquerading as "Google Defender" "Google Email Protection," and "Google Scanner" for Gmail users. They also targeted Yahoo users with applications masquerading as "Delivery Service" and "McAfee Email Protection".
- [C0049] Leviathan Australian Intrusions: Leviathan abused access to compromised appliances to collect JSON Web Tokens (JWTs), used for creating virtual desktop sessions, during Leviathan Australian Intrusions.


### T1539 - Steal Web Session Cookie
An adversary may steal web application or service session cookies and use them to gain access to web applications or Internet services as an authenticated user without needing credentials. Web applications and services often use session cookies as an authentication token after a user has authenticated to a website. Cookies are often valid for an extended period of time, even if the web application is not actively used. Cookies can be found on disk, in the process memory of the browser, and in network traffic to remote systems. Additionally, other applications on the targets machine might store sensitive authentication cookies in memory (e.g. apps which authenticate to cloud services). Session cookies can be used to bypasses some multi-factor authentication protocols. There are several examples of malware targeting cookies from web browsers on the local system. Adversaries may also steal cookies by injecting malicious JavaScript content into websites or relying on User Execution by tricking victims into running malicious JavaScript in their browser. There are also open source frameworks such as `Evilginx2` and `Muraena` that can gather session cookies through a malicious proxy (e.g., Adversary-in-the-Middle) that can be set up by an adversary and used in phishing campaigns. After an adversary acquires a valid cookie, they can then perform a Web Session Cookie technique to login to the corresponding web application.
**Detection**
- [AN1404] **[macOS]** Detects unauthorized access to browser cookie paths (e.g., `~/Library/Application Support/Google/Chrome/Default/Cookies`) or `task_for_pid`/`vm_read` calls to Safari/Chrome memory space.
- [AN1406] **[SaaS]** Detects use of session cookies or authentication tokens from unusual user agents or locations. Identifies token reuse without reauthentication or attempts to bypass MFA using previously stolen cookies.
- [AN1405] **[Office Suite]** Detects automation macros or VBA scripts in documents that access browser file paths, read cookie data, or attempt to exfiltrate browser session tokens over HTTP.
- [AN1403] **[Linux]** Detects access to known browser cookie files (e.g., `~/.mozilla/firefox/*.default/cookies.sqlite`, `~/.config/google-chrome/`) and suspicious reads of browser memory via `/proc/[pid]/mem` or ptrace.
- [AN1402] **[Windows]** Detects suspicious access to browser session cookie storage (e.g., Chrome’s `Cookies` SQLite DB) or memory reads of browser processes. Anomalous injection or memory dump utilities targeting browser processes such as `chrome.exe`, `firefox.exe`, or `msedge.exe`.
**Procedure Examples**
- [G1014] LuminousMoth: LuminousMoth has used an unnamed post-exploitation tool to steal cookies from the Chrome browser.
- [G0094] Kimsuky: Kimsuky has used malware, such as TRANSLATEXT, to steal and exfiltrate browser cookies.
- [G0034] Sandworm Team: Sandworm Team used information stealer malware to collect browser session cookies.
- [S0531] Grandoreiro: Grandoreiro can steal the victim's cookies to use for duplicating the active session from another device.
- [S1207] XLoader: XLoader can capture web session cookies and session information from victim browsers.
- [G1015] Scattered Spider: Scattered Spider retrieves browser cookies via Raccoon Stealer.
- [G0120] Evilnum: Evilnum can steal cookies and session information from browsers.
- [S0492] CookieMiner: CookieMiner can steal Google Chrome and Apple Safari browser cookies from the victim’s machine.
- [G1033] Star Blizzard: Star Blizzard has used EvilGinx to steal the session cookies of victims directed to phishing domains.
- [G0030] Lotus Blossom: Lotus Blossom has used publicly-available tools to steal cookies from browsers such as Chrome.


### T1552 - Unsecured Credentials
Adversaries may search compromised systems to find and obtain insecurely stored credentials. These credentials can be stored and/or misplaced in many locations on a system, including plaintext files (e.g. Shell History), operating system or application-specific repositories (e.g. Credentials in Registry), or other specialized files/artifacts (e.g. Private Keys).
**Detection**
- [AN1156] **[SaaS]** Unusual web-based access or API scraping of password managers, single sign-on sessions, or credential sync services via browser automation or anomalous API tokens.
- [AN1158] **[Containers]** Access to container image layers or mounted secrets (e.g., Docker secrets) by processes not tied to entrypoint or orchestration context.
- [AN1154] **[Linux]** Reading of sensitive files like .bash_history, /etc/shadow, or private key directories by unauthorized users or unusual processes.
- [AN1157] **[Identity Provider]** Unauthorized API or console calls to retrieve or reset password credentials, download key material, or modify SSO settings.
- [AN1155] **[macOS]** Unusual access to ~/Library/Keychains, ~/.bash_history, or Terminal command history by unauthorized processes or users.
- [AN1159] **[Network Devices]** Use of configuration backup utilities or CLI access to dump plaintext passwords, local user hashes, or SNMP strings.
- [AN1153] **[Windows]** Unusual access to bash history, registry credentials paths, or private key files by unauthorized or scripting tools, with correlated file and process activity.
**Procedure Examples**
- [C0049] Leviathan Australian Intrusions: Leviathan gathered credentials hardcoded in binaries located on victim devices during Leviathan Australian Intrusions.
- [S1111] DarkGate: DarkGate uses NirSoft tools to steal user credentials from the infected machine. NirSoft tools are executed via process hollowing in a newly-created instance of vbc.exe or regasm.exe.
- [S1091] Pacu: Pacu can search for sensitive data: for example, in Code Build environment variables, EC2 user data, and Cloud Formation templates.
- [S0373] Astaroth: Astaroth uses an external software known as NetPass to recover passwords.
- [G1017] Volt Typhoon: Volt Typhoon has obtained credentials insecurely stored on targeted network appliances.
- [S1131] NPPSPY: NPPSPY captures credentials by recording them through an alternative network listener registered to the mpnotify.exe process, allowing for cleartext recording of logon information.


### T1552.001 - Unsecured Credentials: Credentials In Files
Adversaries may search local file systems and remote file shares for files containing insecurely stored credentials. These can be files created by users to store their own credentials, shared credential stores for a group of individuals, configuration files containing passwords for a system or service, or source code/binary files containing embedded passwords. It is possible to extract passwords from backups or saved virtual machines through OS Credential Dumping. Passwords may also be obtained from Group Policy Preferences stored on the Windows Domain Controller. In cloud and/or containerized environments, authenticated user and service account credentials are often stored in local configuration and credential files. They may also be found as parameters to deployment commands in container logs. In some cases, these files can be copied and reused on another machine or the contents can be read and then used to authenticate without needing to copy any files.
**Detection**
- [AN0860] **[IaaS]** Access to local credential/config files (e.g., ~/.aws/credentials) followed by metadata API calls or cloud role assumptions.
- [AN0856] **[Windows]** Correlated file access to insecure credential files (e.g., *.env, *.xml, *.ps1) followed by suspicious process execution or authentication using retrieved credentials. Detected through Sysmon logs and Windows Security Event logs.
- [AN0857] **[Linux]** File reads or process executions involving insecurely stored credential files (e.g., config files with password fields) by non-root or anomalous users followed by ssh authentication attempts.
- [AN0859] **[Containers]** Container processes accessing mounted secrets or configuration paths (e.g., /run/secrets, /mnt/config) followed by network access or credential use.
- [AN0858] **[macOS]** Terminal-based grep or open of plist/config files containing credentials, correlated with Keychain or system login attempts.
**Procedure Examples**
- [S0117] XTunnel: XTunnel is capable of accessing locally stored passwords on victims.
- [S0192] Pupy: Pupy can use Lazagne for harvesting credentials.
- [S0367] Emotet: Emotet has been observed leveraging a module that retrieves passwords stored on a system for the current logged-on user.
- [S0378] PoshC2: PoshC2 contains modules for searching for passwords in local and remote files.
- [S0226] Smoke Loader: Smoke Loader searches for files named logins.json to parse for credentials.
- [C0058] SharePoint ToolShell Exploitation: During SharePoint ToolShell Exploitation, threat actors accessed web.config and machine.config to extract MachineKey values, enabling them to forge legitimate VIEWSTATE tokens for future deserialization payloads.
- [G0064] APT33: APT33 has used a variety of publicly available tools like LaZagne to gather credentials.
- [S0331] Agent Tesla: Agent Tesla has the ability to extract credentials from configuration or support files.
- [S0349] LaZagne: LaZagne can obtain credentials from chats, databases, mail, and WiFi.
- [S0363] Empire: Empire can use various modules to search for files containing passwords.


### T1552.002 - Unsecured Credentials: Credentials in Registry
Adversaries may search the Registry on compromised systems for insecurely stored credentials. The Windows Registry stores configuration information that can be used by the system or other programs. Adversaries may query the Registry looking for credentials and passwords that have been stored for use by other programs or services. Sometimes these credentials are used for automatic logons. Example commands to find Registry keys related to password information: * Local Machine Hive: reg query HKLM /f password /t REG_SZ /s * Current User Hive: reg query HKCU /f password /t REG_SZ /s
**Detection**
- [AN0694] **[Windows]** Defenders observe command-line executions or API-based registry reads targeting sensitive paths like HKLM or HKCU with keyword filters such as 'password', 'cred', or 'logon'. Typically performed by Reg.exe, PowerShell, custom binaries, or offensive tools such as Cobalt Strike. Correlation with process ancestry and command-line arguments indicates suspicious credential discovery activity.
**Procedure Examples**
- [S0075] Reg: Reg may be used to find credentials in the Windows Registry.
- [S0194] PowerSploit: PowerSploit has several modules that search the Windows Registry for stored credentials: Get-UnattendedInstallFile, Get-Webconfig, Get-ApplicationHost, Get-SiteListPassword, Get-CachedGPPPassword, and Get-RegistryAutoLogon.
- [G0050] APT32: APT32 used Outlook Credential Dumper to harvest credentials stored in Windows registry.
- [S1022] IceApple: IceApple can harvest credentials from local and remote host registries.
- [S1183] StrelaStealer: StrelaStealer enumerates the registry key `HKCU\SOFTWARE\Microsoft\Office\16.0\Outlook\Profiles\Outlook\9375CFF0413111d3B88A00104B2A6676\` to identify the values for "IMAP User," "IMAP Server," and "IMAP Password" associated with the Outlook email application.
- [S0266] TrickBot: TrickBot has retrieved PuTTY credentials by querying the Software\SimonTatham\Putty\Sessions registry key
- [S0476] Valak: Valak can use the clientgrabber module to steal e-mail credentials from the Registry.
- [G1039] RedCurl: RedCurl used LaZagne to obtain passwords in the Registry.
- [S0331] Agent Tesla: Agent Tesla has the ability to extract credentials from the Registry.


### T1552.003 - Unsecured Credentials: Shell History
Adversaries may search the command history on compromised systems for insecurely stored credentials. On Linux and macOS systems, shells such as Bash and Zsh keep track of the commands users type on the command-line with the "history" utility. Once a user logs out, the history is flushed to the user's history file. For each user, this file resides at the same location: for example, `~/.bash_history` or `~/.zsh_history`. Typically, these files keeps track of the user's last 1000 commands. On Windows, PowerShell has both a command history that is wiped after the session ends, and one that contains commands used in all sessions and is persistent. The default location for persistent history can be found in `%userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt`, but command history can also be accessed with `Get-History`. Command Prompt (CMD) on Windows does not have persistent history. Users often type usernames and passwords on the command-line as parameters to programs, which then get saved to this file when they log out. Adversaries can abuse this by looking through the file for potential credentials.
**Detection**
- [AN1085] **[Linux]** A process outside of interactive shell context reads ~/.bash_history directly (e.g., using cat, less, grep), often shortly after privilege escalation or user switch (su/sudo). This may be followed by credential scanning in memory or file writes to new locations.
- [AN1086] **[macOS]** A process or terminal command outside of standard shell utilities reads the user's .bash_history file. On macOS, unified logs or telemetry tools like EndpointSecurity (ESF) may observe file read APIs or terminal process lineage that shows non-user-initiated access.
**Procedure Examples**
- [S0599] Kinsing: Kinsing has searched bash_history for credentials.


### T1552.004 - Unsecured Credentials: Private Keys
Adversaries may search for private key certificate files on compromised systems for insecurely stored credentials. Private cryptographic keys and certificates are used for authentication, encryption/decryption, and digital signatures. Common key and certificate file extensions include: .key, .pgp, .gpg, .ppk., .p12, .pem, .pfx, .cer, .p7b, .asc. Adversaries may also look in common key directories, such as ~/.ssh for SSH keys on * nix-based systems or C:&#92;Users&#92;(username)&#92;.ssh&#92; on Windows. Adversary tools may also search compromised systems for file extensions relating to cryptographic keys and certificates. When a device is registered to Entra ID, a device key and a transport key are generated and used to verify the device’s identity. An adversary with access to the device may be able to export the keys in order to impersonate the device. On network devices, private keys may be exported via Network Device CLI commands such as `crypto pki export`. Some private keys require a password or passphrase for operation, so an adversary may also use Input Capture for keylogging or attempt to Brute Force the passphrase off-line. These private keys can be used to authenticate to Remote Services like SSH or for use in decrypting other collected files such as email.
**Detection**
- [AN1517] **[Linux]** User or script-based access to ~/.ssh or other directories containing private keys followed by unusual shell activity or network connections.
- [AN1519] **[Network Devices]** CLI-based export of private key material (e.g., 'crypto pki export') with anomalous user session or AAA role escalation.
- [AN1518] **[macOS]** Access to user private key directories (e.g., /Users/*/.ssh) via Terminal, scripting engines, or non-default processes.
- [AN1516] **[Windows]** A process (non-system or user-initiated) accesses private key files in user profile paths or system certificate stores followed by potential network connections or compression activity.
**Procedure Examples**
- [S0409] Machete: Machete has scanned and looked for cryptographic keys and certificate file extensions.
- [S0002] Mimikatz: Mimikatz's CRYPTO::Extract module can extract keys by interacting with Windows cryptographic application programming interface (API) functions.
- [C0014] Operation Wocao: During Operation Wocao, threat actors used Mimikatz to dump certificates and private keys from the Windows certificate store.
- [S0599] Kinsing: Kinsing has searched for private keys.
- [S0601] Hildegard: Hildegard has searched for private keys in .ssh.
- [S1060] Mafalda: Mafalda can collect a Chrome encryption key used to protect browser cookies.
- [G1015] Scattered Spider: Scattered Spider enumerate and exfiltrate code-signing certificates from a compromised host.
- [S1196] Troll Stealer: Troll Stealer collects all data in victim `.ssh` folders by creating a compressed copy that is subsequently exfiltrated to command and control infrastructure. Troll Stealer also collects key information associated with the Government Public Key Infrastructure (GPKI) service for South Korean government information systems.
- [C0024] SolarWinds Compromise: During the SolarWinds Compromise, APT29 obtained PKI keys, certificate files, and the private encryption key from an Active Directory Federation Services (AD FS) container to decrypt corresponding SAML signing certificates.
- [S0661] FoggyWeb: FoggyWeb can retrieve token signing certificates and token decryption certificates from a compromised AD FS server.


### T1552.005 - Unsecured Credentials: Cloud Instance Metadata API
Adversaries may attempt to access the Cloud Instance Metadata API to collect credentials and other sensitive data. Most cloud service providers support a Cloud Instance Metadata API which is a service provided to running virtual instances that allows applications to access information about the running virtual instance. Available information generally includes name, security group, and additional metadata including sensitive data such as credentials and UserData scripts that may contain additional secrets. The Instance Metadata API is provided as a convenience to assist in managing applications and is accessible by anyone who can access the instance. A cloud metadata API has been used in at least one high profile compromise. If adversaries have a presence on the running virtual instance, they may query the Instance Metadata API directly to identify credentials that grant access to additional resources. Additionally, adversaries may exploit a Server-Side Request Forgery (SSRF) vulnerability in a public facing web proxy that allows them to gain access to the sensitive information via a request to the Instance Metadata API. The de facto standard across cloud service providers is to host the Instance Metadata API at http[:]//169.254.169.254.
**Detection**
- [AN0001] **[IaaS]** Detects access attempts to cloud instance metadata endpoints (e.g., 169.254.169.254) from virtual machines or containerized workloads. This includes both direct access and SSRF exploitation patterns.
**Procedure Examples**
- [G0139] TeamTNT: TeamTNT has queried the AWS instance metadata service for credentials.
- [S0683] Peirates: Peirates can query the query AWS and GCP metadata APIs for secrets.
- [S0601] Hildegard: Hildegard has queried the Cloud Instance Metadata API for cloud credentials.


### T1552.006 - Unsecured Credentials: Group Policy Preferences
Adversaries may attempt to find unsecured credentials in Group Policy Preferences (GPP). GPP are tools that allow administrators to create domain policies with embedded credentials. These policies allow administrators to set local accounts. These group policies are stored in SYSVOL on a domain controller. This means that any domain user can view the SYSVOL share and decrypt the password (using the AES key that has been made public). The following tools and scripts can be used to gather and decrypt the password file from Group Policy Preference XML files: * Metasploit’s post exploitation module: post/windows/gather/credentials/gpp * Get-GPPPassword * gpprefdecrypt.py On the SYSVOL share, adversaries may use the following command to enumerate potential GPP XML files: dir /s * .xml
**Detection**
- [AN1075] **[Windows]** Correlates file enumeration of XML files in the SYSVOL share with suspicious process execution that decodes or reads encrypted credentials embedded in Group Policy Preference files (e.g., Get-GPPPassword.ps1, gpprefdecrypt.py, Metasploit). Detects abnormal access to \DOMAIN\SYSVOL combined with XML file parsing or decryption logic.
**Procedure Examples**
- [S0692] SILENTTRINITY: SILENTTRINITY has a module that can extract cached GPP passwords.
- [S0194] PowerSploit: PowerSploit contains a collection of Exfiltration modules that can harvest credentials from Group Policy Preferences.
- [G0064] APT33: APT33 has used a variety of publicly available tools like Gpppassword to gather credentials.
- [G0102] Wizard Spider: Wizard Spider has used PowerShell cmdlets `Get-GPPPassword` and `Find-GPOPassword` to find unsecured credentials in a compromised network group policy.


### T1552.007 - Unsecured Credentials: Container API
Adversaries may gather credentials via APIs within a containers environment. APIs in these environments, such as the Docker API and Kubernetes APIs, allow a user to remotely manage their container resources and cluster components. An adversary may access the Docker API to collect logs that contain credentials to cloud, container, and various other resources in the environment. An adversary with sufficient permissions, such as via a pod's service account, may also use the Kubernetes API to retrieve credentials from the Kubernetes API server. These credentials may include those needed for Docker API authentication or secrets from Kubernetes cluster components.
**Detection**
- [AN0571] **[Containers]** Detection correlates anomalous Docker or Kubernetes API requests with access to logs, secrets, or service accounts. Observes unauthorized use of `docker logs`, `kubectl get secrets`, or direct API calls to Kubernetes API server endpoints. Identifies behavioral patterns where adversaries escalate from basic pod/container interaction to privileged API calls exposing sensitive credential material.
**Procedure Examples**
- [S0683] Peirates: Peirates can query the Kubernetes API for secrets.


### T1552.008 - Unsecured Credentials: Chat Messages
Adversaries may directly collect unsecured credentials stored or passed through user communication services. Credentials may be sent and stored in user chat communication applications such as email, chat services like Slack or Teams, collaboration tools like Jira or Trello, and any other services that support user communication. Users may share various forms of credentials (such as usernames and passwords, API keys, or authentication tokens) on private or public corporate internal communications channels. Rather than accessing the stored chat logs (i.e., Credentials In Files), adversaries may directly access credentials within these services on the user endpoint, through servers hosting the services, or through administrator portals for cloud hosted services. Adversaries may also compromise integration tools like Slack Workflows to automatically search through messages to extract user credentials. These credentials may then be abused to perform follow-on activities such as lateral movement or privilege escalation .
**Detection**
- [AN0309] **[Office Suite]** Detection correlates message events in email and collaboration tools (e.g., Outlook, Teams) that contain regex-like patterns resembling credentials, API keys, or tokens. Anomalous forwarding or bulk copy activity of chat/email content containing secrets is flagged. Suspicious behavior includes users pasting secrets into direct messages or attaching config files with passwords.
- [AN0310] **[SaaS]** Detection monitors SaaS collaboration tools (e.g., Slack, Zoom, Jira) for messages or files containing credential-like patterns, or for suspicious API calls retrieving bulk chat histories by non-admin users. Identifies adversary behavior chains where chat logs are queried via APIs or integration bots to systematically extract sensitive material.
**Procedure Examples**
- [G1004] LAPSUS$: LAPSUS$ has targeted various collaboration tools like Slack, Teams, JIRA, Confluence, and others to hunt for exposed credentials to support privilege escalation and lateral movement.


### T1555 - Credentials from Password Stores
Adversaries may search for common password storage locations to obtain user credentials. Passwords are stored in several places on a system, depending on the operating system or application holding the credentials. There are also specific applications and services that store passwords to make them easier for users to manage and maintain, such as password managers and cloud secrets vaults. Once credentials are obtained, they can be used to perform lateral movement and access restricted information.
**Detection**
- [AN1200] **[macOS]** Monitors Keychain database access and suspicious invocations of security and osascript utilities. Correlates process execution with attempts to dump or unlock Keychain data.
- [AN1201] **[IaaS]** Detects attempts to access or enumerate cloud password/secrets storage services such as AWS Secrets Manager, Azure Key Vault, or GCP Secret Manager. Monitors API calls for abnormal enumeration or bulk retrieval of secrets.
- [AN1199] **[Linux]** Detects access to known password store files (e.g., /etc/shadow, GNOME Keyring, KWallet, browser credential databases). Monitors anomalous process read attempts and suspicious API calls that attempt to extract stored credentials.
- [AN1198] **[Windows]** Monitors suspicious access to password stores such as LSASS, DPAPI, Windows Credential Manager, or browser credential databases. Detects anomalous process-to-process access (e.g., Mimikatz accessing LSASS) and correlation of credential store file reads with execution of non-standard processes.
**Procedure Examples**
- [G1001] HEXANE: HEXANE has run `cmdkey` on victim machines to identify stored credentials.
- [S0484] Carberp: Carberp's passw.plug plugin can gather account information from multiple instant messaging, email, and social media services, as well as FTP, VNC, and VPN clients.
- [S0002] Mimikatz: Mimikatz performs credential dumping to obtain account and password information useful in gaining access to additional systems and enterprise network resources. It contains functionality to acquire information about credentials in many ways, including from the credential vault and DPAPI.
- [S1207] XLoader: XLoader can collect credentials stored in email clients.
- [S0447] Lokibot: Lokibot has stolen credentials from multiple applications and data sources including Windows OS credentials, email clients, FTP, and SFTP clients.
- [S1146] MgBot: MgBot includes modules for stealing stored credentials from Outlook and Foxmail email client software.
- [S1156] Manjusaka: Manjusaka extracts credentials from the Windows Registry associated with Premiumsoft Navicat, a utility used to facilitate access to various database types.
- [G1017] Volt Typhoon: Volt Typhoon has attempted to obtain credentials from OpenSSH, realvnc, and PuTTY.
- [G0077] Leafminer: Leafminer used several tools for retrieving login and password information, including LaZagne.
- [S0167] Matryoshka: Matryoshka is capable of stealing Outlook passwords.


### T1555.001 - Credentials from Password Stores: Keychain
Adversaries may acquire credentials from Keychain. Keychain (or Keychain Services) is the macOS credential management system that stores account names, passwords, private keys, certificates, sensitive application data, payment data, and secure notes. There are three types of Keychains: Login Keychain, System Keychain, and Local Items (iCloud) Keychain. The default Keychain is the Login Keychain, which stores user passwords and information. The System Keychain stores items accessed by the operating system, such as items shared among users on a host. The Local Items (iCloud) Keychain is used for items synced with Apple’s iCloud service. Keychains can be viewed and edited through the Keychain Access application or using the command-line utility security. Keychain files are located in ~/Library/Keychains/, /Library/Keychains/, and /Network/Library/Keychains/. Adversaries may gather user credentials from Keychain storage/memory. For example, the command security dump-keychain –d will dump all Login Keychain credentials from ~/Library/Keychains/login.keychain-db. Adversaries may also directly read Login Keychain credentials from the ~/Library/Keychains/login.keychain file. Both methods require a password, where the default password for the Login Keychain is the current user’s password to login to the macOS host.
**Detection**
- [AN1112] **[macOS]** Detects suspicious access to macOS Keychain files and APIs. Observes processes invoking the 'security' utility or accessing Keychain databases directly, correlates these with abnormal parent process lineage or unexpected user context. Monitors attempts to dump, unlock, or read credential storage beyond normal application workflows.
**Procedure Examples**
- [G1052] Contagious Interview: Contagious Interview has leveraged malware variants configured to dump credentials from the macOS keychain.
- [S1185] LightSpy: LightSpy performs an in-memory keychain query via `SecItemCopyMatching()` then formats the retrieved data as a JSON blob for exfiltration.
- [S0690] Green Lambert: Green Lambert can use Keychain Services API functions to find and collect passwords, such as `SecKeychainFindInternetPassword` and `SecKeychainItemCopyAttributesAndData`.
- [S0363] Empire: Empire uses the command `/usr/bin/security dump-keychain -d` to read the keychain credential.
- [S0279] Proton: Proton gathers credentials in files for keychains.
- [S1016] MacMa: MacMa can dump credentials from the macOS keychain.
- [S0349] LaZagne: LaZagne can obtain credentials from macOS Keychains.
- [S0274] Calisto: Calisto collects Keychain storage data and copies those passwords/tokens to a file.
- [S1153] Cuckoo Stealer: Cuckoo Stealer can capture files from a targeted user's keychain directory.
- [S0278] iKitten: iKitten collects the keychains on the system.


### T1555.002 - Credentials from Password Stores: Securityd Memory
An adversary with root access may gather credentials by reading `securityd`’s memory. `securityd` is a service/daemon responsible for implementing security protocols such as encryption and authorization. A privileged adversary may be able to scan through `securityd`'s memory to find the correct sequence of keys to decrypt the user’s logon keychain. This may provide the adversary with various plaintext passwords, such as those for users, WiFi, mail, browsers, certificates, secure notes, etc. In OS X prior to El Capitan, users with root access can read plaintext keychain passwords of logged-in users because Apple’s keychain implementation allows these credentials to be cached so that users are not repeatedly prompted for passwords. Apple’s `securityd` utility takes the user’s logon password, encrypts it with PBKDF2, and stores this master key in memory. Apple also uses a set of keys and algorithms to encrypt the user’s password, but once the master key is found, an adversary need only iterate over the other values to unlock the final password.
**Detection**
- [AN0156] **[macOS]** Detects suspicious memory access attempts targeting the `securityd` process. Observes tools invoking process memory read operations (e.g., ptrace, task_for_pid) against `securityd`. Correlates with anomalous parent process lineage, root privilege escalation, or repeated unauthorized attempts.
- [AN0157] **[Linux]** Detects adversaries attempting to attach debuggers or memory dump utilities to credential storage daemons analogous to macOS `securityd`. Observes ptrace syscalls, /proc//mem access, or gcore dumps against sensitive processes. Correlates anomalies with privilege escalation or credential dumping attempts.
**Procedure Examples**
- [S0276] Keydnap: Keydnap uses the keychaindump project to read securityd memory.


### T1555.003 - Credentials from Password Stores: Credentials from Web Browsers
Adversaries may acquire credentials from web browsers by reading files specific to the target browser. Web browsers commonly save credentials such as website usernames and passwords so that they do not need to be entered manually in the future. Web browsers typically store the credentials in an encrypted format within a credential store; however, methods exist to extract plaintext credentials from web browsers. For example, on Windows systems, encrypted credentials may be obtained from Google Chrome by reading a database file, AppData\Local\Google\Chrome\User Data\Default\Login Data and executing a SQL query: SELECT action_url, username_value, password_value FROM logins;. The plaintext password can then be obtained by passing the encrypted credentials to the Windows API function CryptUnprotectData, which uses the victim’s cached logon credentials as the decryption key. Adversaries have executed similar procedures for common web browsers such as FireFox, Safari, Edge, etc. Windows stores Internet Explorer and Microsoft Edge credentials in Credential Lockers managed by the Windows Credential Manager. Adversaries may also acquire credentials by searching web browser process memory for patterns that commonly match credentials. After acquiring credentials from web browsers, adversaries may attempt to recycle the credentials across different systems and/or accounts in order to expand access. This can result in significantly furthering an adversary's objective in cases where credentials gained from web browsers overlap with privileged accounts (e.g. domain administrator).
**Detection**
- [AN0107] **[macOS]** Detects abnormal access to Safari credential stores (Keychain-backed) or Chrome/Firefox login databases. Observes processes executing `security dump-keychain` or directly reading credential files in `~/Library/Application Support`. Correlates file access with suspicious process ancestry or unsigned binaries.
- [AN0105] **[Windows]** Detects unauthorized access to web browser credential stores (e.g., Chrome Login Data, Edge Credential Locker) by processes other than the browser itself. Correlates file reads of credential databases with subsequent API calls to `CryptUnprotectData` or memory inspection attempts.
- [AN0106] **[Linux]** Detects attempts to access browser credential stores (e.g., Firefox `logins.json`, Chrome SQLite DB) or processes (e.g., gnome-keyring-daemon). Observes unauthorized file reads and memory inspection of browser processes using ptrace or gdb.
**Procedure Examples**
- [S0385] njRAT: njRAT has a module that steals passwords saved in victim web browsers.
- [S1246] BeaverTail: BeaverTail has stolen passwords saved in web browsers. BeaverTail has also been known to collect login data from Firefox within key3.db, key4.db and logins.json from `/.mozilla/firefox/` for exfiltration.
- [S0089] BlackEnergy: BlackEnergy has used a plug-in to gather credentials from web browsers including FireFox, Google Chrome, and Internet Explorer.
- [S0132] H1N1: H1N1 dumps usernames and passwords from Firefox, Internet Explorer, and Outlook.
- [S1122] Mispadu: Mispadu can steal credentials from Google Chrome.
- [S0434] Imminent Monitor: Imminent Monitor has a PasswordRecoveryPacket module for recovering browser passwords.
- [S0365] Olympic Destroyer: Olympic Destroyer contains a module that tries to obtain stored credentials from web browsers.
- [S0528] Javali: Javali can capture login credentials from open browsers including Firefox, Chrome, Internet Explorer, and Edge.
- [S0492] CookieMiner: CookieMiner can steal saved usernames and passwords in Chrome as well as credit card credentials.
- [G0040] Patchwork: Patchwork dumped the login data database from \AppData\Local\Google\Chrome\User Data\Default\Login Data.


### T1555.004 - Credentials from Password Stores: Windows Credential Manager
Adversaries may acquire credentials from the Windows Credential Manager. The Credential Manager stores credentials for signing into websites, applications, and/or devices that request authentication through NTLM or Kerberos in Credential Lockers (previously known as Windows Vaults). The Windows Credential Manager separates website credentials from application or network credentials in two lockers. As part of Credentials from Web Browsers, Internet Explorer and Microsoft Edge website credentials are managed by the Credential Manager and are stored in the Web Credentials locker. Application and network credentials are stored in the Windows Credentials locker. Credential Lockers store credentials in encrypted `.vcrd` files, located under `%Systemdrive%\Users\\[Username]\AppData\Local\Microsoft\\[Vault/Credentials]\`. The encryption key can be found in a file named Policy.vpol, typically located in the same folder as the credentials. Adversaries may list credentials managed by the Windows Credential Manager through several mechanisms. vaultcmd.exe is a native Windows executable that can be used to enumerate credentials stored in the Credential Locker through a command-line interface. Adversaries may also gather credentials by directly reading files located inside of the Credential Lockers. Windows APIs, such as CredEnumerateA, may also be absued to list credentials managed by the Credential Manager. Adversaries may also obtain credentials from credential backups. Credential backups and restorations may be performed by running rundll32.exe keymgr.dll KRShowKeyMgr then selecting the “Back up...” button on the “Stored User Names and Passwords” GUI. Password recovery tools may also obtain plain text passwords from the Credential Manager.
**Detection**
- [AN0378] **[Windows]** Detects unauthorized access to Windows Credential Manager through anomalous process execution (vaultcmd.exe, rundll32.exe keymgr.dll), suspicious API calls (CredEnumerateA), or direct file access to Credential Locker files. Correlates process creation with subsequent file reads of .vcrd/.vpol files under user Credential Locker directories.
**Procedure Examples**
- [G0049] OilRig: OilRig has used credential dumping tool named VALUEVAULT to steal credentials from the Windows Credential Manager.
- [G0038] Stealth Falcon: Stealth Falcon malware gathers passwords from the Windows Credential Vault.
- [S0476] Valak: Valak can use a .NET compiled module named exchgrabber to enumerate credentials from the Credential Manager.
- [G0010] Turla: Turla has gathered credentials from the Windows Credential Manager tool.
- [S0349] LaZagne: LaZagne can obtain credentials from Vault files.
- [S0681] Lizar: Lizar has a plugin that can retrieve credentials from Internet Explorer and Microsoft Edge using `vaultcmd.exe` and another that can collect RDP access credentials using the `CredEnumerateW` function.
- [S0240] ROKRAT: ROKRAT can steal credentials by leveraging the Windows Vault mechanism.
- [S0629] RainyDay: RainyDay can use the QuarksPwDump tool to obtain local passwords and domain cached credentials.
- [S0692] SILENTTRINITY: SILENTTRINITY can gather Windows Vault credentials.
- [C0044] Juicy Mix: During Juicy Mix, OilRig used a Windows Credential Manager stealer for credential access.


### T1555.005 - Credentials from Password Stores: Password Managers
Adversaries may acquire user credentials from third-party password managers. Password managers are applications designed to store user credentials, normally in an encrypted database. Credentials are typically accessible after a user provides a master password that unlocks the database. After the database is unlocked, these credentials may be copied to memory. These databases can be stored as files on disk. Adversaries may acquire user credentials from password managers by extracting the master password and/or plain-text credentials from memory. Adversaries may extract credentials from memory via Exploitation for Credential Access. Adversaries may also try brute forcing via Password Guessing to obtain the master password of a password manager.
**Detection**
- [AN1641] **[Windows]** Detection of suspicious access to password manager processes (KeePass, 1Password, LastPass, Bitwarden) through abnormal process injection, memory reads, or command-line usage of vault-related DLLs. Correlates process creation with OS API calls and file access to vault databases (.kdbx, .opvault, .ldb).
- [AN1642] **[Linux]** Suspicious access to password manager vaults (KeePassXC, gnome-keyring, pass) via memory scraping or unauthorized file reads. Detects unusual command execution involving gdb/strace attached to password manager processes.
- [AN1643] **[macOS]** Detection of password manager database access (1Password .opvault, LastPass caches, KeePass .kdbx) outside expected parent processes. Identifies memory scraping attempts via suspicious API calls or tools attaching to password manager processes.
**Procedure Examples**
- [C0014] Operation Wocao: During Operation Wocao, threat actors accessed and collected credentials from password managers.
- [G0027] Threat Group-3390: Threat Group-3390 obtained a KeePass database from a compromised host.
- [G0119] Indrik Spider: Indrik Spider has accessed and exported passwords from password managers.
- [G0117] Fox Kitten: Fox Kitten has used scripts to access credential information from the KeePass database.
- [S0652] MarkiRAT: MarkiRAT can gather information from the Keepass password manager.
- [G1048] UNC3886: UNC3886 has targeted KeyPass password database files for credential access.
- [G1053] Storm-0501: Storm-0501 has stolen credentials contained in the password manager Keepass by utilizing Find-KeePassConfig.ps1.
- [S0279] Proton: Proton gathers credentials in files for 1password.
- [S0266] TrickBot: TrickBot can steal passwords from the KeePass open source password manager.
- [G1015] Scattered Spider: Scattered Spider has searched for credentials in password vaults and Privileged Access Management (PAM) solutions including HashiCorp Vault.


### T1555.006 - Credentials from Password Stores: Cloud Secrets Management Stores
Adversaries may acquire credentials from cloud-native secret management solutions such as AWS Secrets Manager, GCP Secret Manager, Azure Key Vault, and Terraform Vault. Secrets managers support the secure centralized management of passwords, API keys, and other credential material. Where secrets managers are in use, cloud services can dynamically acquire credentials via API requests rather than accessing secrets insecurely stored in plain text files or environment variables. If an adversary is able to gain sufficient privileges in a cloud environment – for example, by obtaining the credentials of high-privileged Cloud Accounts or compromising a service that has permission to retrieve secrets – they may be able to request secrets from the secrets manager. This can be accomplished via commands such as `get-secret-value` in AWS, `gcloud secrets describe` in GCP, and `az key vault secret show` in Azure. **Note:** this technique is distinct from Cloud Instance Metadata API in that the credentials are being directly requested from the cloud secrets manager, rather than through the medium of the instance metadata API.
**Detection**
- [AN0366] **[IaaS]** Detection of suspicious access to cloud-native secret management systems (AWS Secrets Manager, GCP Secret Manager, Azure Key Vault, HashiCorp Vault). Focuses on abnormal secret retrieval activity, such as secrets being accessed by unusual identities, from unexpected regions, outside business hours, or at high volume. Correlates API calls to secret retrieval with surrounding authentication events, role assumptions, and anomalous execution patterns.
**Procedure Examples**
- [G0125] HAFNIUM: HAFNIUM has moved laterally from on-premises environments to steal passwords from Azure key vaults.
- [G1053] Storm-0501: Storm-0501 has utilized Azure Key Vault to store the encryption key using the operation `Microsoft.KeyVault/Vaults/write`.
- [S1091] Pacu: Pacu can retrieve secrets from the AWS Secrets Manager via the enum_secrets module.


### T1556 - Modify Authentication Process
Adversaries may modify authentication mechanisms and processes to access user credentials or enable otherwise unwarranted access to accounts. The authentication process is handled by mechanisms, such as the Local Security Authentication Server (LSASS) process and the Security Accounts Manager (SAM) on Windows, pluggable authentication modules (PAM) on Unix-based systems, and authorization plugins on MacOS systems, responsible for gathering, storing, and validating credentials. By modifying an authentication process, an adversary may be able to authenticate to a service or system without using Valid Accounts. Adversaries may maliciously modify a part of this process to either reveal credentials or bypass authentication mechanisms. Compromised credentials or access may be used to bypass access controls placed on various resources on systems within the network and may even be used for persistent access to remote systems and externally available services, such as VPNs, Outlook Web Access and remote desktop.
**Detection**
- [AN0291] **[IaaS]** Detects unauthorized changes to IAM authentication configurations such as disabling MFA, creating backdoor access keys, or altering trust policies. Correlates identity policy updates with unusual login behavior.
- [AN0288] **[Linux]** Detects modification of PAM configuration files, unauthorized new PAM modules, and suspicious process execution accessing PAM-related binaries. Correlates file modification events in /etc/pam.d/ with process execution of unauthorized binaries.
- [AN0287] **[Windows]** Detects modification of LSASS and authentication DLLs, suspicious registry changes to password filter packages, and abnormal process access to lsass.exe. Correlates registry modifications, DLL loads, and process handle access events.
- [AN0290] **[Identity Provider]** Detects suspicious configuration changes in IdP authentication flows such as enabling reversible password encryption, MFA bypass, or policy weakening. Correlates policy modification events with unusual administrative activity.
- [AN0289] **[macOS]** Detects unauthorized additions or changes to /Library/Security/SecurityAgentPlugins and suspicious process activity attempting to hook authentication APIs. Correlates file modifications with abnormal plugin loads in authentication flows.
**Procedure Examples**
- [S0377] Ebury: Ebury can intercept private keys using a trojanized ssh-add function.
- [S0692] SILENTTRINITY: SILENTTRINITY can create a backdoor in KeePass using a malicious config file and in TortoiseSVN using a registry hook.
- [S0487] Kessel: Kessel has trojanized the ssh_login and user-auth_pubkey functions to steal plaintext credentials.
- [C0046] ArcaneDoor: ArcaneDoor included modification of the AAA process to bypass authentication mechanisms.
- [G1016] FIN13: FIN13 has replaced legitimate KeePass binaries with trojanized versions to collect passwords from numerous applications.


### T1556.001 - Modify Authentication Process: Domain Controller Authentication
Adversaries may patch the authentication process on a domain controller to bypass the typical authentication mechanisms and enable access to accounts. Malware may be used to inject false credentials into the authentication process on a domain controller with the intent of creating a backdoor used to access any user’s account and/or credentials (ex: Skeleton Key). Skeleton key works through a patch on an enterprise domain controller authentication process (LSASS) with credentials that adversaries may use to bypass the standard authentication system. Once patched, an adversary can use the injected password to successfully authenticate as any domain user account (until the the skeleton key is erased from memory by a reboot of the domain controller). Authenticated access may enable unfettered access to hosts and/or resources within single-factor authentication environments.
**Detection**
- [AN0757] **[Windows]** Detects anomalous process access to LSASS on domain controllers, suspicious module loads of authentication DLLs, and registry or file modifications indicative of Skeleton Key–style patching. Correlates LSASS access attempts with subsequent abnormal logon activity patterns.
**Procedure Examples**
- [G0114] Chimera: Chimera's malware has altered the NTLM authentication program on domain controllers to allow Chimera to login without a valid credential.
- [S0007] Skeleton Key: Skeleton Key is used to patch an enterprise domain controller authentication process with a backdoor password. It allows adversaries to bypass the standard authentication system to use a defined password for all accounts authenticating to that domain controller.


### T1556.002 - Modify Authentication Process: Password Filter DLL
Adversaries may register malicious password filter dynamic link libraries (DLLs) into the authentication process to acquire user credentials as they are validated. Windows password filters are password policy enforcement mechanisms for both domain and local accounts. Filters are implemented as DLLs containing a method to validate potential passwords against password policies. Filter DLLs can be positioned on local computers for local accounts and/or domain controllers for domain accounts. Before registering new passwords in the Security Accounts Manager (SAM), the Local Security Authority (LSA) requests validation from each registered filter. Any potential changes cannot take effect until every registered filter acknowledges validation. Adversaries can register malicious password filters to harvest credentials from local computers and/or entire domains. To perform proper validation, filters must receive plain-text credentials from the LSA. A malicious password filter would receive these plain-text credentials every time a password request is made.
**Detection**
- [AN1303] **[Windows]** Detects suspicious registration of new password filter DLLs into the authentication process. Correlates registry modifications to LSASS Notification Packages with subsequent DLL creation and loading events. Observes anomalous file placement of DLLs in system directories followed by LSASS loading the new filter during logon/password change activity.
**Procedure Examples**
- [S0125] Remsec: Remsec harvests plain-text credentials as a password filter registered on domain controllers.
- [G0049] OilRig: OilRig has registered a password filter DLL in order to drop malware.
- [G0041] Strider: Strider has registered its persistence module on domain controllers as a Windows LSA (Local System Authority) password filter to acquire credentials any time a domain, local user, or administrator logs in or changes a password.


### T1556.003 - Modify Authentication Process: Pluggable Authentication Modules
Adversaries may modify pluggable authentication modules (PAM) to access user credentials or enable otherwise unwarranted access to accounts. PAM is a modular system of configuration files, libraries, and executable files which guide authentication for many services. The most common authentication module is pam_unix.so, which retrieves, sets, and verifies account authentication information in /etc/passwd and /etc/shadow. Adversaries may modify components of the PAM system to create backdoors. PAM components, such as pam_unix.so, can be patched to accept arbitrary adversary supplied values as legitimate credentials. Malicious modifications to the PAM system may also be abused to steal credentials. Adversaries may infect PAM resources with code to harvest user credentials, since the values exchanged with PAM components may be plain-text since PAM does not store passwords.
**Detection**
- [AN1251] **[macOS]** Detects suspicious changes to macOS authorization and PAM plugin files. Correlates file modifications under /etc/pam.d/ or /Library/Security/SecurityAgentPlugins with unexpected authentication attempts or anomalous account usage.
- [AN1250] **[Linux]** Detects unauthorized modifications to PAM configuration files or shared object modules. Correlates file modification events under /etc/pam.d/ or /lib/security/ with unusual authentication activity such as multiple simultaneous logins, off-hours logins, or logons without corresponding physical/VPN access.
**Procedure Examples**
- [S0377] Ebury: Ebury can deactivate PAM modules to tamper with the sshd configuration.
- [S0468] Skidmap: Skidmap has the ability to replace the pam_unix.so file on an infected machine with its own malicious version that accepts a specific backdoor password for all users.


### T1556.004 - Modify Authentication Process: Network Device Authentication
Adversaries may use Patch System Image to hard code a password in the operating system, thus bypassing of native authentication mechanisms for local accounts on network devices. Modify System Image may include implanted code to the operating system for network devices to provide access for adversaries using a specific password. The modification includes a specific password which is implanted in the operating system image via the patch. Upon authentication attempts, the inserted code will first check to see if the user input is the password. If so, access is granted. Otherwise, the implanted code will pass the credentials on for verification of potentially valid credentials.
**Detection**
- [AN0758] **[Network Devices]** Detects unauthorized modification of network device authentication by correlating OS image file changes, checksum mismatches, or memory verification failures with anomalous authentication events. Focus is on behaviors where patched images introduce hardcoded passwords or bypass native authentication.
**Procedure Examples**
- [S1104] SLOWPULSE: SLOWPULSE can modify LDAP and two factor authentication flows by inspecting login credentials and forcing successful authentication if the provided password matches a chosen backdoor password.
- [S0519] SYNful Knock: SYNful Knock has the capability to add its own custom backdoor password when it modifies the operating system of the affected network device.


### T1556.005 - Modify Authentication Process: Reversible Encryption
An adversary may abuse Active Directory authentication encryption properties to gain access to credentials on Windows systems. The AllowReversiblePasswordEncryption property specifies whether reversible password encryption for an account is enabled or disabled. By default this property is disabled (instead storing user credentials as the output of one-way hashing functions) and should not be enabled unless legacy or other software require it. If the property is enabled and/or a user changes their password after it is enabled, an adversary may be able to obtain the plaintext of passwords created/changed after the property was enabled. To decrypt the passwords, an adversary needs four components: 1. Encrypted password (G$RADIUSCHAP) from the Active Directory user-structure userParameters 2. 16 byte randomly-generated value (G$RADIUSCHAPKEY) also from userParameters 3. Global LSA secret (G$MSRADIUSCHAPKEY) 4. Static key hardcoded in the Remote Access Subauthentication DLL (RASSFM.DLL) With this information, an adversary may be able to reproduce the encryption key and subsequently decrypt the encrypted password value. An adversary may set this property at various scopes through Local Group Policy Editor, user properties, Fine-Grained Password Policy (FGPP), or via the ActiveDirectory PowerShell module. For example, an adversary may implement and apply a FGPP to users or groups if the Domain Functional Level is set to "Windows Server 2008" or higher. In PowerShell, an adversary may make associated changes to user settings using commands similar to Set-ADUser -AllowReversiblePasswordEncryption $true.
**Detection**
- [AN1621] **[Windows]** Detects enabling of reversible password encryption in Active Directory or Group Policy, suspicious PowerShell commands modifying AD user properties, and unusual account configuration changes correlated with policy modifications. Multi-event correlation links Group Policy edits, PowerShell command execution, and user account property changes to identify tampering with authentication encryption settings.
An adversary may abuse Active Directory authentication encryption properties to gain access to credentials on Windows systems. The AllowReversiblePasswordEncryption property specifies whether reversible password encryption for an account is enabled or disabled. By default this property is disabled (instead storing user credentials as the output of one-way hashing functions) and should not be enabled unless legacy or other software require it. If the property is enabled and/or a user changes their password after it is enabled, an adversary may be able to obtain the plaintext of passwords created/changed after the property was enabled. To decrypt the passwords, an adversary needs four components: 1. Encrypted password (G$RADIUSCHAP) from the Active Directory user-structure userParameters 2. 16 byte randomly-generated value (G$RADIUSCHAPKEY) also from userParameters 3. Global LSA secret (G$MSRADIUSCHAPKEY) 4. Static key hardcoded in the Remote Access Subauthentication DLL (RASSFM.DLL) With this information, an adversary may be able to reproduce the encryption key and subsequently decrypt the encrypted password value. An adversary may set this property at various scopes through Local Group Policy Editor, user properties, Fine-Grained Password Policy (FGPP), or via the ActiveDirectory PowerShell module. For example, an adversary may implement and apply a FGPP to users or groups if the Domain Functional Level is set to "Windows Server 2008" or higher. In PowerShell, an adversary may make associated changes to user settings using commands similar to Set-ADUser -AllowReversiblePasswordEncryption $true.


### T1556.006 - Modify Authentication Process: Multi-Factor Authentication
Adversaries may disable or modify multi-factor authentication (MFA) mechanisms to enable persistent access to compromised accounts. Once adversaries have gained access to a network by either compromising an account lacking MFA or by employing an MFA bypass method such as Multi-Factor Authentication Request Generation, adversaries may leverage their access to modify or completely disable MFA defenses. This can be accomplished by abusing legitimate features, such as excluding users from Azure AD Conditional Access Policies, registering a new yet vulnerable/adversary-controlled MFA method, or by manually patching MFA programs and configuration files to bypass expected functionality. For example, modifying the Windows hosts file (`C:\windows\system32\drivers\etc\hosts`) to redirect MFA calls to localhost instead of an MFA server may cause the MFA process to fail. If a "fail open" policy is in place, any otherwise successful authentication attempt may be granted access without enforcing MFA. Depending on the scope, goals, and privileges of the adversary, MFA defenses may be disabled for individual accounts or for all accounts tied to a larger group, such as all domain accounts in a victim's network environment.
**Detection**
- [AN0549] **[Office Suite]** Detects MFA bypass attempts by modifying tenant-wide authentication policies or excluding high-value accounts from MFA enforcement.
- [AN0545] **[IaaS]** Detects API calls to cloud secrets/MFA configurations where MFA enforcement policies are disabled or bypassed.
- [AN0544] **[Identity Provider]** Detects conditional access policy changes, exclusion of accounts from MFA enforcement, or registration of new MFA factors by non-admin or anomalous users.
- [AN0547] **[macOS]** Detects modifications to authorization plugins responsible for MFA enforcement and correlates with suspicious login sessions missing MFA prompts.
- [AN0548] **[SaaS]** Detects suspicious MFA method changes, such as registration of weaker factors (e.g., SMS), or removal of MFA requirements for specific accounts or groups.
- [AN0543] **[Windows]** Detects registry and Group Policy modifications that disable or weaken MFA, suspicious PowerShell usage modifying MFA-related attributes, and anomalous login sessions succeeding without expected MFA challenge.
- [AN0546] **[Linux]** Detects PAM module modifications or removal of MFA hooks in /etc/pam.d/ configurations, correlated with successful authentications lacking MFA prompts.
**Procedure Examples**
- [G1015] Scattered Spider: After compromising user accounts, Scattered Spider registers their own MFA tokens.
- [S1104] SLOWPULSE: SLOWPULSE can insert malicious logic to bypass RADIUS and ACE two factor authentication (2FA) flows if a designated attacker-supplied password is provided.
- [S0677] AADInternals: The AADInternals `Set-AADIntUserMFA` command can be used to disable MFA for a specified user.


### T1556.007 - Modify Authentication Process: Hybrid Identity
Adversaries may patch, modify, or otherwise backdoor cloud authentication processes that are tied to on-premises user identities in order to bypass typical authentication mechanisms, access credentials, and enable persistent access to accounts. Many organizations maintain hybrid user and device identities that are shared between on-premises and cloud-based environments. These can be maintained in a number of ways. For example, Microsoft Entra ID includes three options for synchronizing identities between Active Directory and Entra ID: * Password Hash Synchronization (PHS), in which a privileged on-premises account synchronizes user password hashes between Active Directory and Entra ID, allowing authentication to Entra ID to take place entirely in the cloud * Pass Through Authentication (PTA), in which Entra ID authentication attempts are forwarded to an on-premises PTA agent, which validates the credentials against Active Directory * Active Directory Federation Services (AD FS), in which a trust relationship is established between Active Directory and Entra ID AD FS can also be used with other SaaS and cloud platforms such as AWS and GCP, which will hand off the authentication process to AD FS and receive a token containing the hybrid users’ identity and privileges. By modifying authentication processes tied to hybrid identities, an adversary may be able to establish persistent privileged access to cloud resources. For example, adversaries who compromise an on-premises server running a PTA agent may inject a malicious DLL into the `AzureADConnectAuthenticationAgentService` process that authorizes all attempts to authenticate to Entra ID, as well as records user credentials. In environments using AD FS, an adversary may edit the `Microsoft.IdentityServer.Servicehost` configuration file to load a malicious DLL that generates authentication tokens for any user with any set of claims, thereby bypassing multi-factor authentication and defined AD FS policies. In some cases, adversaries may be able to modify the hybrid identity authentication process from the cloud. For example, adversaries who compromise a Global Administrator account in an Entra ID tenant may be able to register a new PTA agent via the web console, similarly allowing them to harvest credentials and log into the Entra ID environment as any user.
**Detection**
- [AN0817] **[Office Suite]** Detects tenant-wide authentication or conditional access changes that weaken hybrid identity enforcement, including disabling AD FS or bypassing hybrid MFA policies.
- [AN0814] **[Windows]** Detects injection or tampering of DLLs in hybrid identity agents (e.g., AzureADConnectAuthenticationAgentService), registry or configuration changes tied to PTA/AD FS, and anomalous LSASS or AD FS module loads correlated with authentication anomalies.
- [AN0816] **[IaaS]** Detects API calls registering or updating hybrid identity connectors, modification of cloud-to-on-premises federation trust, and unusual token issuance logs.
- [AN0818] **[SaaS]** Detects suspicious changes to SAML/OAuth federation configurations, such as new signing certificates, altered endpoints, or claims issuance rules granting elevated privileges.
- [AN0815] **[Identity Provider]** Detects registration of new PTA agents, conditional access changes disabling hybrid MFA enforcement, or suspicious updates to AD FS token-signing configurations.
**Procedure Examples**
- [S0677] AADInternals: AADInternals can inject a malicious DLL (`PTASpy`) into the `AzureADConnectAuthenticationAgentService` to backdoor Azure AD Pass-Through Authentication.
- [G0016] APT29: APT29 has edited the `Microsoft.IdentityServer.Servicehost.exe.config` file to load a malicious DLL into the AD FS process, thereby enabling persistent access to any service federated with AD FS for a user with a specified User Principal Name.


### T1556.008 - Modify Authentication Process: Network Provider DLL
Adversaries may register malicious network provider dynamic link libraries (DLLs) to capture cleartext user credentials during the authentication process. Network provider DLLs allow Windows to interface with specific network protocols and can also support add-on credential management functions. During the logon process, Winlogon (the interactive logon module) sends credentials to the local `mpnotify.exe` process via RPC. The `mpnotify.exe` process then shares the credentials in cleartext with registered credential managers when notifying that a logon event is happening. Adversaries can configure a malicious network provider DLL to receive credentials from `mpnotify.exe`. Once installed as a credential manager (via the Registry), a malicious DLL can receive and save credentials each time a user logs onto a Windows workstation or domain via the `NPLogonNotify()` function. Adversaries may target planting malicious network provider DLLs on systems known to have increased logon activity and/or administrator logon activity, such as servers and domain controllers.
**Detection**
- [AN1598] **[Windows]** Detects registration of new or modified network provider DLLs via registry changes, anomalous file creation of DLLs in system directories, and suspicious process activity (mpnotify.exe interacting with non-standard DLLs). Multi-event correlation ties registry modification events to subsequent DLL loads during user logon activity.
Adversaries may register malicious network provider dynamic link libraries (DLLs) to capture cleartext user credentials during the authentication process. Network provider DLLs allow Windows to interface with specific network protocols and can also support add-on credential management functions. During the logon process, Winlogon (the interactive logon module) sends credentials to the local `mpnotify.exe` process via RPC. The `mpnotify.exe` process then shares the credentials in cleartext with registered credential managers when notifying that a logon event is happening. Adversaries can configure a malicious network provider DLL to receive credentials from `mpnotify.exe`. Once installed as a credential manager (via the Registry), a malicious DLL can receive and save credentials each time a user logs onto a Windows workstation or domain via the `NPLogonNotify()` function. Adversaries may target planting malicious network provider DLLs on systems known to have increased logon activity and/or administrator logon activity, such as servers and domain controllers.


### T1556.009 - Modify Authentication Process: Conditional Access Policies
Adversaries may disable or modify conditional access policies to enable persistent access to compromised accounts. Conditional access policies are additional verifications used by identity providers and identity and access management systems to determine whether a user should be granted access to a resource. For example, in Entra ID, Okta, and JumpCloud, users can be denied access to applications based on their IP address, device enrollment status, and use of multi-factor authentication. In some cases, identity providers may also support the use of risk-based metrics to deny sign-ins based on a variety of indicators. In AWS and GCP, IAM policies can contain `condition` attributes that verify arbitrary constraints such as the source IP, the date the request was made, and the nature of the resources or regions being requested. These measures help to prevent compromised credentials from resulting in unauthorized access to data or resources, as well as limit user permissions to only those required. By modifying conditional access policies, such as adding additional trusted IP ranges, removing Multi-Factor Authentication requirements, or allowing additional Unused/Unsupported Cloud Regions, adversaries may be able to ensure persistent access to accounts and circumvent defensive measures.
**Detection**
- [AN0088] **[Identity Provider]** Detects suspicious updates to conditional access or MFA enforcement policies in identity providers such as Entra ID, Okta, or JumpCloud. Focus is on removal of policy blocks, addition of broad exclusions, or registration of adversary-controlled MFA methods, followed by anomalous login activity that takes advantage of the modified policies.
- [AN0087] **[IaaS]** Detects modifications to IAM conditions or policies that alter authentication behavior, such as adding permissive trusted IPs, removing MFA requirements, or changing regional access restrictions. Behavioral detection focuses on anomalous policy updates tied to privileged accounts and subsequent suspicious logon activity from previously blocked regions or devices.
**Procedure Examples**
- [G1015] Scattered Spider: Scattered Spider has added additional trusted locations to Azure AD conditional access policies.
- [G1053] Storm-0501: Storm-0501 has registered their own MFA method, and leveraged a victim hybrid joined server to circumvent Conditional Access Policies.


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


### T1558 - Steal or Forge Kerberos Tickets
Adversaries may attempt to subvert Kerberos authentication by stealing or forging Kerberos tickets to enable Pass the Ticket. Kerberos is an authentication protocol widely used in modern Windows domain environments. In Kerberos environments, referred to as “realms”, there are three basic participants: client, service, and Key Distribution Center (KDC). Clients request access to a service and through the exchange of Kerberos tickets, originating from KDC, they are granted access after having successfully authenticated. The KDC is responsible for both authentication and ticket granting. Adversaries may attempt to abuse Kerberos by stealing tickets or forging tickets to enable unauthorized access. On Windows, the built-in klist utility can be used to list and analyze cached Kerberos tickets.
**Detection**
- [AN1443] **[Windows]** Detects anomalous Kerberos activity such as forged or stolen tickets by correlating malformed fields in logon events, RC4-encrypted TGTs, or TGS requests without corresponding TGT requests. Also detects suspicious processes accessing LSASS memory for ticket extraction.
- [AN1445] **[macOS]** Detects attempts to forge or replay Kerberos tickets by monitoring Unified Logs for anomalous kinit/klist activity and correlating unusual authentication sequences.
- [AN1444] **[Linux]** Detects suspicious access to SSSD secrets database and Kerberos key material indicating ticket theft or replay attempts. Correlates anomalous file access with unusual Kerberos service ticket requests.
**Procedure Examples**
- [G1024] Akira: Akira have used scripts to dump Kerberos authentication credentials.


### T1558.001 - Steal or Forge Kerberos Tickets: Golden Ticket
Adversaries who have the KRBTGT account password hash may forge Kerberos ticket-granting tickets (TGT), also known as a golden ticket. Golden tickets enable adversaries to generate authentication material for any account in Active Directory. Using a golden ticket, adversaries are then able to request ticket granting service (TGS) tickets, which enable access to specific resources. Golden tickets require adversaries to interact with the Key Distribution Center (KDC) in order to obtain TGS. The KDC service runs all on domain controllers that are part of an Active Directory domain. KRBTGT is the Kerberos Key Distribution Center (KDC) service account and is responsible for encrypting and signing all Kerberos tickets. The KRBTGT password hash may be obtained using OS Credential Dumping and privileged access to a domain controller.
**Detection**
- [AN0405] **[Windows]** Detects forged Kerberos Golden Tickets by correlating anomalous Kerberos ticket lifetimes, unexpected encryption types (e.g., RC4 in modern domains), malformed fields in logon/logoff events, and TGS requests without preceding TGT requests. Also monitors for abnormal patterns of access associated with elevated privileges across multiple systems.
**Procedure Examples**
- [G0004] Ke3chang: Ke3chang has used Mimikatz to generate Kerberos golden tickets.
- [S0363] Empire: Empire can leverage its implementation of Mimikatz to obtain and use golden tickets.
- [S0002] Mimikatz: Mimikatz's kerberos module can create golden tickets.
- [S0633] Sliver: Sliver incorporates the Rubeus framework to allow for Kerberos ticket manipulation, specifically for forging Kerberos Golden Tickets.
- [S1071] Rubeus: Rubeus can forge a ticket-granting ticket.


### T1558.002 - Steal or Forge Kerberos Tickets: Silver Ticket
Adversaries who have the password hash of a target service account (e.g. SharePoint, MSSQL) may forge Kerberos ticket granting service (TGS) tickets, also known as silver tickets. Kerberos TGS tickets are also known as service tickets. Silver tickets are more limited in scope in than golden tickets in that they only enable adversaries to access a particular resource (e.g. MSSQL) and the system that hosts the resource; however, unlike golden tickets, adversaries with the ability to forge silver tickets are able to create TGS tickets without interacting with the Key Distribution Center (KDC), potentially making detection more difficult. Password hashes for target services may be obtained using OS Credential Dumping or Kerberoasting.
**Detection**
- [AN0675] **[Windows]** Detects forged Kerberos Silver Tickets by identifying anomalous Kerberos service ticket activity such as malformed fields in logon events, TGS requests without interaction with the KDC, and access attempts using service accounts outside expected hosts/resources. Also monitors suspicious processes accessing LSASS memory for credential dumping.
**Procedure Examples**
- [S1071] Rubeus: Rubeus can create silver tickets.
- [S0677] AADInternals: AADInternals can be used to forge Kerberos tickets using the password hash of the AZUREADSSOACC account.
- [S0002] Mimikatz: Mimikatz's kerberos module can create silver tickets.
- [S0363] Empire: Empire can leverage its implementation of Mimikatz to obtain and use silver tickets.


### T1558.003 - Steal or Forge Kerberos Tickets: Kerberoasting
Adversaries may abuse a valid Kerberos ticket-granting ticket (TGT) or sniff network traffic to obtain a ticket-granting service (TGS) ticket that may be vulnerable to Brute Force. Service principal names (SPNs) are used to uniquely identify each instance of a Windows service. To enable authentication, Kerberos requires that SPNs be associated with at least one service logon account (an account specifically tasked with running a service). Adversaries possessing a valid Kerberos ticket-granting ticket (TGT) may request one or more Kerberos ticket-granting service (TGS) service tickets for any SPN from a domain controller (DC). Portions of these tickets may be encrypted with the RC4 algorithm, meaning the Kerberos 5 TGS-REP etype 23 hash of the service account associated with the SPN is used as the private key and is thus vulnerable to offline Brute Force attacks that may expose plaintext credentials. This same behavior could be executed using service tickets captured from network traffic. Cracked hashes may enable Persistence, Privilege Escalation, and Lateral Movement via access to Valid Accounts.
**Detection**
- [AN0444] **[Windows]** Detects Kerberoasting attempts by monitoring for anomalous Kerberos TGS requests (Event ID 4769) with RC4 encryption (etype 0x17), accounts requesting an unusual number of service tickets in a short period, or service accounts targeted outside normal usage baselines. Also correlates suspicious process activity (e.g., Mimikatz invoking LSASS access) with Kerberos ticket anomalies.
**Procedure Examples**
- [S1071] Rubeus: Rubeus can use the `KerberosRequestorSecurityToken.GetRequest` method to request kerberoastable service tickets.
- [S0357] Impacket: Impacket modules like GetUserSPNs can be used to get Service Principal Names (SPNs) for user accounts. The output is formatted to be compatible with cracking tools like John the Ripper and Hashcat.
- [S0363] Empire: Empire uses PowerSploit's Invoke-Kerberoast to request service tickets and return crackable ticket hashes.
- [C0049] Leviathan Australian Intrusions: Leviathan used Kerberoasting techniques during Leviathan Australian Intrusions.
- [G0102] Wizard Spider: Wizard Spider has used Rubeus, MimiKatz Kerberos module, and the Invoke-Kerberoast cmdlet to steal AES hashes.
- [C0014] Operation Wocao: During Operation Wocao, threat actors used PowerSploit's `Invoke-Kerberoast` module to request encrypted service tickets and bruteforce the passwords of Windows service accounts offline.
- [S0692] SILENTTRINITY: SILENTTRINITY contains a module to conduct Kerberoasting.
- [C0024] SolarWinds Compromise: During the SolarWinds Compromise, APT29 obtained Ticket Granting Service (TGS) tickets for Active Directory Service Principle Names to crack offline.
- [S0194] PowerSploit: PowerSploit's Invoke-Kerberoast module can request service tickets and return crackable ticket hashes.
- [G0046] FIN7: FIN7 has used Kerberoasting PowerShell commands such as, `Invoke-Kerberoast` for credential access and to enable lateral movement.


### T1558.004 - Steal or Forge Kerberos Tickets: AS-REP Roasting
Adversaries may reveal credentials of accounts that have disabled Kerberos preauthentication by Password Cracking Kerberos messages. Preauthentication offers protection against offline Password Cracking. When enabled, a user requesting access to a resource initiates communication with the Domain Controller (DC) by sending an Authentication Server Request (AS-REQ) message with a timestamp that is encrypted with the hash of their password. If and only if the DC is able to successfully decrypt the timestamp with the hash of the user’s password, it will then send an Authentication Server Response (AS-REP) message that contains the Ticket Granting Ticket (TGT) to the user. Part of the AS-REP message is signed with the user’s password. For each account found without preauthentication, an adversary may send an AS-REQ message without the encrypted timestamp and receive an AS-REP message with TGT data which may be encrypted with an insecure algorithm such as RC4. The recovered encrypted data may be vulnerable to offline Password Cracking attacks similarly to Kerberoasting and expose plaintext credentials. An account registered to a domain, with or without special privileges, can be abused to list all domain accounts that have preauthentication disabled by utilizing Windows tools like PowerShell with an LDAP filter. Alternatively, the adversary may send an AS-REQ message for each user. If the DC responds without errors, the account does not require preauthentication and the AS-REP message will already contain the encrypted data. Cracked hashes may enable Persistence, Privilege Escalation, and Lateral Movement via access to Valid Accounts.
**Detection**
- [AN0316] **[Windows]** Detects AS-REP roasting attempts by monitoring for Kerberos AS-REQ/AS-REP authentication patterns where preauthentication is disabled (Event ID 4768 with Pre-Auth Type 0). Correlates these requests with subsequent service ticket activity (Event ID 4769) and anomalies such as requests using weak RC4 encryption (etype 0x17). Excessive enumeration of accounts with 'Do not require Kerberos preauthentication' set in Active Directory is another key detection point.
**Procedure Examples**
- [S1071] Rubeus: Rubeus can reveal the credentials of accounts that have Kerberos pre-authentication disabled through AS-REP roasting.


### T1558.005 - Steal or Forge Kerberos Tickets: Ccache Files
Adversaries may attempt to steal Kerberos tickets stored in credential cache files (or ccache). These files are used for short term storage of a user's active session credentials. The ccache file is created upon user authentication and allows for access to multiple services without the user having to re-enter credentials. The /etc/krb5.conf configuration file and the KRB5CCNAME environment variable are used to set the storage location for ccache entries. On Linux, credentials are typically stored in the `/tmp` directory with a naming format of `krb5cc_%UID%` or `krb5.ccache`. On macOS, ccache entries are stored by default in memory with an `API:{uuid}` naming scheme. Typically, users interact with ticket storage using kinit, which obtains a Ticket-Granting-Ticket (TGT) for the principal; klist, which lists obtained tickets currently held in the credentials cache; and other built-in binaries. Adversaries can collect tickets from ccache files stored on disk and authenticate as the current user without their password to perform Pass the Ticket attacks. Adversaries can also use these tickets to impersonate legitimate users with elevated privileges to perform Privilege Escalation. Tools like Kekeo can also be used by adversaries to convert ccache files to Windows format for further Lateral Movement. On macOS, adversaries may use open-source tools or the Kerberos framework to interact with ccache files and extract TGTs or Service Tickets via lower-level APIs.
**Detection**
- [AN0070] **[macOS]** Detects abnormal interaction with memory-based Kerberos ccache (API:{uuid}) or file-based overrides. Focus on processes attempting to enumerate or extract Kerberos tickets outside of built-in utilities. Detects use of open-source tools (e.g., Bifrost, modified Mimikatz ports) that interact with the Kerberos framework APIs.
- [AN0069] **[Linux]** Detects unauthorized access, copying, or modification of Kerberos ccache files (krb5cc_%UID% or krb5.ccache) in /tmp or custom paths defined by KRB5CCNAME. Correlates file access with suspicious processes (e.g., credential dumping tools) and subsequent anomalous Kerberos authentication requests from non-standard processes.
**Procedure Examples**
- [S0357] Impacket: Impacket tools – such as getST.py or ticketer.py – can be used to steal or forge Kerberos tickets using ccache files given a password, hash, aesKey, or TGT.


### T1606 - Forge Web Credentials
Adversaries may forge credential materials that can be used to gain access to web applications or Internet services. Web applications and services (hosted in cloud SaaS environments or on-premise servers) often use session cookies, tokens, or other materials to authenticate and authorize user access. Adversaries may generate these credential materials in order to gain access to web resources. This differs from Steal Web Session Cookie, Steal Application Access Token, and other similar behaviors in that the credentials are new and forged by the adversary, rather than stolen or intercepted from legitimate users. The generation of web credentials often requires secret values, such as passwords, Private Keys, or other cryptographic seed values. Adversaries may also forge tokens by taking advantage of features such as the `AssumeRole` and `GetFederationToken` APIs in AWS, which allow users to request temporary security credentials (i.e., Temporary Elevated Cloud Access), or the `zmprov gdpak` command in Zimbra, which generates a pre-authentication key that can be used to generate tokens for any user in the domain. Once forged, adversaries may use these web credentials to access resources (ex: Use Alternate Authentication Material), which may bypass multi-factor and other authentication protection mechanisms.
**Detection**
- [AN0722] **[SaaS]** SaaS platforms may show forged credentials as unusual API keys, tokens, or session cookies being used without corresponding authentication. Correlated patterns include simultaneous valid sessions from multiple geographies, unusual API calls with new tokens, or bypass of expected MFA enforcement.
- [AN0720] **[Linux]** On Linux systems, forged credentials may be injected into browser session files, curl/wget headers, or token caches in memory. Detection can leverage auditd to track processes accessing sensitive files (~/.mozilla, ~/.config/chromium, ~/.aws/credentials) and correlate with suspicious outbound connections.
- [AN0723] **[Office Suite]** Forged web credentials in Office Suite contexts may appear as abnormal authentication headers in Outlook or Teams traffic, or unexplained OAuth grants in M365/Azure logs. Defenders should correlate token usage events with missing authentication flows and mismatched device/user context.
- [AN0721] **[macOS]** Forged credentials on macOS may be visible through Unified Logs showing abnormal access to Keychain or browser session files. Correlated with anomalous web session usage from Safari or Chrome processes outside typical user context.
- [AN0718] **[Identity Provider]** Forged web credentials may manifest as anomalous SAML token issuance, OpenID Connect token minting, or Zimbra pre-auth key usage. Defenders may see tokens issued without normal authentication events, multiple valid tokens generated simultaneously, or signing anomalies in IdP logs.
- [AN0717] **[IaaS]** Defenders may detect adversaries forging web credentials in IaaS environments by monitoring for anomalous API activity such as AssumeRole or GetFederationToken being executed by unusual principals. These events often correlate with sudden logon sessions from unfamiliar IP addresses or regions. The chain is usually secret material misuse (stolen private key or password) → API request generating a new token → access to high-value resources.
- [AN0719] **[Windows]** Forged web credentials on Windows endpoints may be detected by anomalous browser cookie files, local token cache manipulations, or tools injecting tokens into sessions. Defenders may observe processes accessing LSASS or browser credential stores unexpectedly, followed by unusual logon sessions.
Adversaries may forge credential materials that can be used to gain access to web applications or Internet services. Web applications and services (hosted in cloud SaaS environments or on-premise servers) often use session cookies, tokens, or other materials to authenticate and authorize user access. Adversaries may generate these credential materials in order to gain access to web resources. This differs from Steal Web Session Cookie, Steal Application Access Token, and other similar behaviors in that the credentials are new and forged by the adversary, rather than stolen or intercepted from legitimate users. The generation of web credentials often requires secret values, such as passwords, Private Keys, or other cryptographic seed values. Adversaries may also forge tokens by taking advantage of features such as the `AssumeRole` and `GetFederationToken` APIs in AWS, which allow users to request temporary security credentials (i.e., Temporary Elevated Cloud Access), or the `zmprov gdpak` command in Zimbra, which generates a pre-authentication key that can be used to generate tokens for any user in the domain. Once forged, adversaries may use these web credentials to access resources (ex: Use Alternate Authentication Material), which may bypass multi-factor and other authentication protection mechanisms.


### T1606.001 - Forge Web Credentials: Web Cookies
Adversaries may forge web cookies that can be used to gain access to web applications or Internet services. Web applications and services (hosted in cloud SaaS environments or on-premise servers) often use session cookies to authenticate and authorize user access. Adversaries may generate these cookies in order to gain access to web resources. This differs from Steal Web Session Cookie and other similar behaviors in that the cookies are new and forged by the adversary, rather than stolen or intercepted from legitimate users. Most common web applications have standardized and documented cookie values that can be generated using provided tools or interfaces. The generation of web cookies often requires secret values, such as passwords, Private Keys, or other cryptographic seed values. Once forged, adversaries may use these web cookies to access resources (Web Session Cookie), which may bypass multi-factor and other authentication protection mechanisms.
**Detection**
- [AN0486] **[macOS]** Forged cookies on macOS may show up as abnormal access to Safari/Chrome cookie databases in ~/Library/Cookies, combined with unexpected logon sessions authenticated by those cookies. Unified Logs may show cookie injection events or abnormal access patterns to Keychain when linked to browser authentication flows.
- [AN0484] **[Windows]** Forged web cookies on Windows endpoints can be detected by monitoring unusual modifications of browser cookie stores (e.g., Chrome SQLite DB, Edge cache) by processes outside of browsers, followed by authentication events to SaaS or IaaS services. Defenders may observe processes writing directly to cookie storage paths or injecting tokens into browser sessions.
- [AN0485] **[Linux]** On Linux, defenders may observe forged cookie activity as unauthorized modifications to browser cookie databases (e.g., ~/.mozilla/firefox/*/cookies.sqlite, ~/.config/chromium/Default/Cookies) or scripted injection of session tokens. Suspicious usage includes curl/wget commands embedding forged cookies in headers, correlated with abnormal session activity in SaaS or IaaS logs.
- [AN0483] **[IaaS]** Forged cookies in IaaS environments may appear as authentication attempts that bypass MFA, leveraging AssumeRole or session APIs with cookies that were never legitimately issued. Defenders should correlate cloud logs for cookie-based sessions without prior valid authentication, often followed by resource access from unfamiliar IP addresses.
- [AN0487] **[SaaS]** Forged cookies in SaaS environments manifest as valid web sessions without matching login activity, MFA enforcement bypass, or cookies reused across multiple devices/IPs. Defenders should look for cookie replay, concurrent sessions from multiple geographies, or session tokens generated by unrecognized apps.
**Procedure Examples**
- [C0024] SolarWinds Compromise: During the SolarWinds Compromise, APT29 bypassed MFA set on OWA accounts by generating a cookie value from a previously stolen secret key.


### T1606.002 - Forge Web Credentials: SAML Tokens
An adversary may forge SAML tokens with any permissions claims and lifetimes if they possess a valid SAML token-signing certificate. The default lifetime of a SAML token is one hour, but the validity period can be specified in the NotOnOrAfter value of the conditions ... element in a token. This value can be changed using the AccessTokenLifetime in a LifetimeTokenPolicy. Forged SAML tokens enable adversaries to authenticate across services that use SAML 2.0 as an SSO (single sign-on) mechanism. An adversary may utilize Private Keys to compromise an organization's token-signing certificate to create forged SAML tokens. If the adversary has sufficient permissions to establish a new federation trust with their own Active Directory Federation Services (AD FS) server, they may instead generate their own trusted token-signing certificate. This differs from Steal Application Access Token and other similar behaviors in that the tokens are new and forged by the adversary, rather than stolen or intercepted from legitimate users. An adversary may gain administrative Entra ID privileges if a SAML token is forged which claims to represent a highly privileged account. This may lead to Use Alternate Authentication Material, which may bypass multi-factor and other authentication protection mechanisms.
**Detection**
- [AN0418] **[Identity Provider]** Forged SAML tokens can be observed as authentication attempts with valid signatures but missing expected preceding Kerberos or authentication events. Defenders may correlate SAML assertions with absent Event IDs 4769, 1200, or 1202, or tokens issued with abnormal lifetimes, issuers, or claims compared to baseline.
- [AN0419] **[IaaS]** Forged SAML tokens in IaaS environments often manifest as cross-cloud or cross-account authentication without matching STS events. Defenders may see AssumeRole or GetFederationToken API usage without a corresponding SAML assertion log from the trusted IdP.
- [AN0420] **[Windows]** Forged SAML tokens may be used on Windows systems to authenticate to federated apps without normal Kerberos activity. Defenders may detect anomalous event correlation, where access to SaaS/O365 via SAML occurs without prior TGT requests or user logons.
- [AN0422] **[Office Suite]** Forged SAML tokens may be leveraged to access O365 apps such as Outlook or SharePoint. Defenders should monitor for token replay across multiple clients or access attempts to privileged mailboxes without prior interactive login.
- [AN0421] **[SaaS]** Forged SAML tokens can appear as SaaS logins where authentication succeeded without MFA, or where tokens contain claims inconsistent with the user profile. Look for concurrent sessions across different geographies with the same SAML assertion ID.
**Procedure Examples**
- [C0024] SolarWinds Compromise: During the SolarWinds Compromise, APT29 created tokens using compromised SAML signing certificates.
- [S0677] AADInternals: AADInternals can be used to create SAML tokens using the AD Federated Services token signing certificate.


### T1621 - Multi-Factor Authentication Request Generation
Adversaries may attempt to bypass multi-factor authentication (MFA) mechanisms and gain access to accounts by generating MFA requests sent to users. Adversaries in possession of credentials to Valid Accounts may be unable to complete the login process if they lack access to the 2FA or MFA mechanisms required as an additional credential and security control. To circumvent this, adversaries may abuse the automatic generation of push notifications to MFA services such as Duo Push, Microsoft Authenticator, Okta, or similar services to have the user grant access to their account. If adversaries lack credentials to victim accounts, they may also abuse automatic push notification generation when this option is configured for self-service password reset (SSPR). In some cases, adversaries may continuously repeat login attempts in order to bombard users with MFA push notifications, SMS messages, and phone calls, potentially resulting in the user finally accepting the authentication request in response to “MFA fatigue.”
**Detection**
- [AN0451] **[Windows]** Detect repeated failed login events followed by MFA challenges triggered in rapid succession, especially if originating from service accounts or anomalous IP addresses.
- [AN0454] **[macOS]** Detect user account logon attempts that trigger multiple MFA challenges through enterprise identity integrations, especially if MFA push requests are generated without successful interactive login.
- [AN0450] **[IaaS]** Detect abnormal MFA activity within cloud service provider logs, such as repeated generation of MFA challenges for the same user session or mismatched MFA device and login origin.
- [AN0452] **[Linux]** Monitor PAM and syslog entries for unusual frequency of login attempts that trigger MFA prompts, particularly when MFA challenges do not match expected user behavior.
- [AN0453] **[SaaS]** Detect anomalous OAuth or SSO logins that repeatedly generate MFA challenges, particularly where MFA approvals are denied or timed out by the user.
- [AN0449] **[Identity Provider]** Monitor for excessive or anomalous MFA push notifications or token requests, especially when login attempts originate from unusual IPs or geolocations and do not correspond to legitimate user-initiated sessions.
**Procedure Examples**
- [G0016] APT29: APT29 has used repeated MFA requests to gain access to victim accounts.
- [C0027] C0027: During C0027, Scattered Spider attempted to gain access by continuously sending MFA messages to the victim until they accept the MFA push challenge.
- [G1015] Scattered Spider: Scattered Spider has used multifactor authentication (MFA) fatigue by sending repeated MFA authentication requests to targets.
- [G1004] LAPSUS$: LAPSUS$ has spammed target users with MFA prompts in the hope that the legitimate user will grant necessary approval.


### T1649 - Steal or Forge Authentication Certificates
Adversaries may steal or forge certificates used for authentication to access remote systems or resources. Digital certificates are often used to sign and encrypt messages and/or files. Certificates are also used as authentication material. For example, Entra ID device certificates and Active Directory Certificate Services (AD CS) certificates bind to an identity and can be used as credentials for domain accounts. Authentication certificates can be both stolen and forged. For example, AD CS certificates can be stolen from encrypted storage (in the Registry or files), misplaced certificate files (i.e. Unsecured Credentials), or directly from the Windows certificate store via various crypto APIs. With appropriate enrollment rights, users and/or machines within a domain can also request and/or manually renew certificates from enterprise certificate authorities (CA). This enrollment process defines various settings and permissions associated with the certificate. Of note, the certificate’s extended key usage (EKU) values define signing, encryption, and authentication use cases, while the certificate’s subject alternative name (SAN) values define the certificate owner’s alternate names. Abusing certificates for authentication credentials may enable other behaviors such as Lateral Movement. Certificate-related misconfigurations may also enable opportunities for Privilege Escalation, by way of allowing users to impersonate or assume privileged accounts or permissions via the identities (SANs) associated with a certificate. These abuses may also enable Persistence via stealing or forging certificates that can be used as Valid Accounts for the duration of the certificate's validity, despite user password resets. Authentication certificates can also be stolen and forged for machine accounts. Adversaries who have access to root (or subordinate) CA certificate private keys (or mechanisms protecting/managing these keys) may also establish Persistence by forging arbitrary authentication certificates for the victim domain (known as “golden” certificates). Adversaries may also target certificates and related services in order to access other forms of credentials, such as Golden Ticket ticket-granting tickets (TGT) or NTLM plaintext.
**Detection**
- [AN0672] **[Linux]** Monitor for file access to certificate directories, commands invoking OpenSSL or PKCS#12 utilities to export or modify certificates, and processes accessing sensitive key storage paths.
- [AN0673] **[macOS]** Monitor for security commands and API calls interacting with the Keychain, as well as file access attempts to stored certificates and private keys in ~/Library/Keychains or /Library/Keychains.
- [AN0674] **[Identity Provider]** Monitor for abnormal certificate enrollment events in identity platforms, unexpected use of token-signing certificates, and unusual CA configuration modifications.
- [AN0671] **[Windows]** Monitor for abnormal certificate enrollment and usage activity in Active Directory Certificate Services (AD CS), registry access to certificate storage locations, and unusual process executions that attempt to export or access private keys.
**Procedure Examples**
- [S0677] AADInternals: AADInternals can create and export various authentication certificates, including those associated with Azure AD joined/registered devices.
- [G0016] APT29: APT29 has abused misconfigured AD CS certificate templates to impersonate admin users and create additional authentication certificates.
- [S0002] Mimikatz: Mimikatz's `CRYPTO` module can create and export various types of authentication certificates.

