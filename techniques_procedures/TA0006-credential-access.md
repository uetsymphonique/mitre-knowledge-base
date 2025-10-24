### T1003.001 - OS Credential Dumping: LSASS Memory

Procedures:

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
- [G0061] FIN8: FIN8 harvests credentials using Invoke-Mimikatz or Windows Credentials Editor (WCE).
- [S0349] LaZagne: LaZagne can perform credential dumping from memory to obtain account and password information.
- [G0125] HAFNIUM: HAFNIUM has used procdump to dump the LSASS process memory.
- [G0108] Blue Mockingbird: Blue Mockingbird has used Mimikatz to retrieve credentials from LSASS memory.
- [S0121] Lslsass: Lslsass can dump active logon session password hashes from the lsass process.

### T1003.002 - OS Credential Dumping: Security Account Manager

Procedures:

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
- [G0035] Dragonfly: Dragonfly has dropped and executed SecretsDump to dump password hashes.
- [G0004] Ke3chang: Ke3chang has dumped credentials, including by using gsecdump.
- [S0376] HOPLIGHT: HOPLIGHT has the capability to harvest credentials and passwords from the SAM database.
- [G1030] Agrius: Agrius dumped the SAM file on victim machines to capture credentials.
- [C0002] Night Dragon: During Night Dragon, threat actors dumped account hashes using gsecdump.

### T1003.003 - OS Credential Dumping: NTDS

Procedures:

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
- [G0045] menuPass: menuPass has used Ntdsutil to dump credentials.
- [G0114] Chimera: Chimera has gathered the SYSTEM registry and ntds.dit files from target systems. Chimera specifically has used the NtdsAudit tool to dump the password hashes of domain users via msadcs.exe "NTDS.dit" -s "SYSTEM" -p RecordedTV_pdmp.txt --users-csv RecordedTV_users.csv and used ntdsutil to copy the Active Directory database.
- [S0357] Impacket: SecretsDump and Mimikatz modules within Impacket can perform credential dumping to obtain account and password information from NTDS.dit.
- [G0117] Fox Kitten: Fox Kitten has used Volume Shadow Copy to access credential information from NTDS.
- [C0029] Cutting Edge: During Cutting Edge, threat actors accessed and mounted virtual hard disk backups to extract ntds.dit.

### T1003.004 - OS Credential Dumping: LSA Secrets

Procedures:

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
- [G0016] APT29: APT29 has used the `reg save` command to extract LSA secrets offline.
- [G0045] menuPass: menuPass has used a modified version of pentesting tools wmiexec.vbs and secretsdump.py to dump credentials.
- [G0035] Dragonfly: Dragonfly has dropped and executed SecretsDump to dump password hashes.
- [S0677] AADInternals: AADInternals can dump secrets from the Local Security Authority.
- [S0357] Impacket: SecretsDump and Mimikatz modules within Impacket can perform credential dumping to obtain account and password information.

### T1003.005 - OS Credential Dumping: Cached Domain Credentials

Procedures:

- [S0439] Okrum: Okrum was seen using modified Quarks PwDump to perform credential dumping.
- [G0064] APT33: APT33 has used a variety of publicly available tools like LaZagne to gather credentials.
- [G0077] Leafminer: Leafminer used several tools for retrieving login and password information, including LaZagne.
- [S0119] Cachedump: Cachedump can extract cached password hashes from cache entry information.
- [S0349] LaZagne: LaZagne can perform credential dumping from MSCache to obtain account and password information.
- [G0049] OilRig: OilRig has used credential dumping tools such as LaZagne to steal credentials to accounts logged into the compromised system and to Outlook Web Access.
- [S0192] Pupy: Pupy can use Lazagne for harvesting credentials.
- [G0069] MuddyWater: MuddyWater has performed credential dumping with LaZagne.

### T1003.006 - OS Credential Dumping: DCSync

Procedures:

- [S0002] Mimikatz: Mimikatz performs credential dumping to obtain account and password information useful in gaining access to additional systems and enterprise network resources. It contains functionality to acquire information about credentials in many ways, including from DCSync/NetSync.
- [G1006] Earth Lusca: Earth Lusca has used a DCSync command with Mimikatz to retrieve credentials from an exploited controller.
- [C0027] C0027: During C0027, Scattered Spider performed domain replication.
- [C0014] Operation Wocao: During Operation Wocao, threat actors used Mimikatz's DCSync to dump credentials from the memory of the targeted system.
- [G1004] LAPSUS$: LAPSUS$ has used DCSync attacks to gather credentials for privilege escalation routines.
- [C0024] SolarWinds Compromise: During the SolarWinds Compromise, APT29 used privileged accounts to replicate directory service data with domain controllers.

### T1003.007 - OS Credential Dumping: Proc Filesystem

Procedures:

- [S1109] PACEMAKER: PACEMAKER has the ability to extract credentials from OS memory.
- [S0349] LaZagne: LaZagne can use the `/maps` and `/mem` files to identify regex patterns to dump cleartext passwords from the browser's process memory.
- [S0179] MimiPenguin: MimiPenguin can use the `/maps` and `/mem` file to search for regex patterns and dump the process memory.

### T1003.008 - OS Credential Dumping: /etc/passwd and /etc/shadow

Procedures:

- [S0349] LaZagne: LaZagne can obtain credential information from /etc/shadow using the shadow.py module.
- [C0045] ShadowRay: During ShadowRay, threat actors used `cat /etc/shadow` to steal password hashes.


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


### T1056.001 - Input Capture: Keylogging

Procedures:

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
- [S1146] MgBot: MgBot includes keylogger payloads focused on the QQ chat application.
- [G0087] APT39: APT39 has used tools for capturing keystrokes.
- [S0149] MoonWind: MoonWind has a keylogger.
- [S0152] EvilGrab: EvilGrab has the capability to capture keystrokes.
- [S0161] XAgentOSX: XAgentOSX contains keylogging functionality that will monitor for active application windows and write them to the log, it can handle special characters, and it will buffer by default 50 characters before sending them out over the C2 infrastructure.

### T1056.002 - Input Capture: GUI Input Capture

Procedures:

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
- [S0658] XCSSET: XCSSET prompts the user to input credentials using a native macOS dialog box leveraging the system process /Applications/Safari.app/Contents/MacOS/SafariForWebKitDevelopment.
- [S0692] SILENTTRINITY: SILENTTRINITY's `credphisher.py` module can prompt a current user for their credentials.
- [S1153] Cuckoo Stealer: Cuckoo Stealer has captured passwords by prompting victims with a “macOS needs to access System Settings” GUI window.

### T1056.003 - Input Capture: Web Portal Capture

Procedures:

- [G1035] Winter Vivern: Winter Vivern registered and hosted domains to allow for creation of web pages mimicking legitimate government email logon sites to collect logon information.
- [C0030] Triton Safety Instrumented System Attack: In the Triton Safety Instrumented System Attack, TEMP.Veles captured credentials as they were being changed by redirecting text-based login codes to websites they controlled.
- [S1116] WARPWIRE: WARPWIRE can capture credentials submitted during the web logon process in order to access layer seven applications such as RDP.
- [S1022] IceApple: The IceApple OWA credential logger can monitor for OWA authentication requests and log the credentials.
- [C0029] Cutting Edge: During Cutting Edge, threat actors modified the JavaScript loaded by the Ivanti Connect Secure login page to capture credentials entered.

### T1056.004 - Input Capture: Credential API Hooking

Procedures:

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
- [S0266] TrickBot: TrickBot has the ability to capture RDP credentials by capturing the CredEnumerateA API
- [S0353] NOKKI: NOKKI uses the Windows call SetWindowsHookEx and begins injecting it into every GUI process running on the victim's machine.


### T1110.001 - Brute Force: Password Guessing

Procedures:

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
- [S0598] P.A.S. Webshell: P.A.S. Webshell can use predefined users and passwords to execute brute force attacks against SSH, FTP, POP3, MySQL, MSSQL, and PostgreSQL services.

### T1110.002 - Brute Force: Password Cracking

Procedures:

- [G0022] APT3: APT3 has been known to brute force password hashes to be able to leverage plain text credentials.
- [S0056] Net Crawler: Net Crawler uses a list of known credentials gathered through credential dumping to guess passwords to accounts as it spreads throughout a network.
- [G0035] Dragonfly: Dragonfly has dropped and executed tools used for password cracking, including Hydra and CrackMapExec.
- [G1045] Salt Typhoon: Salt Typhoon has cracked passwords for accounts with weak encryption obtained from the configuration files of compromised network devices.
- [G0037] FIN6: FIN6 has extracted password hashes from ntds.dit to crack offline.
- [C0002] Night Dragon: During Night Dragon, threat actors used Cain & Abel to crack password hashes.

### T1110.003 - Brute Force: Password Spraying

Procedures:

- [G0125] HAFNIUM: HAFNIUM has gained initial access through password spray attacks.
- [S0606] Bad Rabbit: Bad Rabbit’s infpub.dat file uses NTLM login credentials to brute force Windows machines.
- [S0488] CrackMapExec: CrackMapExec can brute force credential authentication by using a supplied list of usernames and a single password.
- [S0362] Linux Rabbit: Linux Rabbit brute forces SSH passwords in order to attempt to gain access and install its malware onto the server.
- [C0051] APT28 Nearest Neighbor Campaign: During APT28 Nearest Neighbor Campaign, APT28 performed password-spray attacks against public facing services to validate credentials.
- [G1030] Agrius: Agrius engaged in password spraying via SMB in victim environments.
- [G1003] Ember Bear: Ember Bear has conducted password spraying against Outlook Web Access (OWA) infrastructure to identify valid user names and passwords.
- [G0016] APT29: APT29 has conducted brute force password spray attacks.
- [G1001] HEXANE: HEXANE has used password spraying attacks to obtain valid credentials.
- [G0032] Lazarus Group: Lazarus Group malware attempts to connect to Windows shares for lateral movement by using a generated list of usernames, which center around permutations of the username Administrator, and weak passwords.
- [G0064] APT33: APT33 has used password spraying to gain access to target systems.
- [G0122] Silent Librarian: Silent Librarian has used collected lists of names and e-mail accounts to use in password spraying attacks against private sector targets.
- [G0114] Chimera: Chimera has used multiple password spraying attacks against victim's remote services to obtain valid user and administrator accounts.
- [S0413] MailSniper: MailSniper can be used for password spraying against Exchange and Office 365.
- [G0077] Leafminer: Leafminer used a tool called Total SMB BruteForcer to perform internal password spraying.

### T1110.004 - Brute Force: Credential Stuffing

Procedures:

- [G0114] Chimera: Chimera has used credential stuffing against victim's remote services to obtain valid accounts.
- [S0266] TrickBot: TrickBot uses brute-force attack against RDP with rdpscanDll module.


### T1111 - Multi-Factor Authentication Interception

Procedures:

- [S1104] SLOWPULSE: SLOWPULSE can log credentials on compromised Pulse Secure VPNs during the `DSAuth::AceAuthServer::checkUsernamePassword`ACE-2FA authentication procedure.
- [S0018] Sykipot: Sykipot is known to contain functionality that enables targeting of smart card technologies to proxy authentication for connections to restricted network resources using detected hardware tokens.
- [C0014] Operation Wocao: During Operation Wocao, threat actors used a custom collection method to intercept two-factor authentication soft tokens.
- [G0094] Kimsuky: Kimsuky has used a proprietary tool to intercept one time passwords required for two-factor authentication.
- [C0049] Leviathan Australian Intrusions: Leviathan abused compromised appliance access to collect multifactor authentication token values during Leviathan Australian Intrusions.
- [G0114] Chimera: Chimera has registered alternate phone numbers for compromised users to intercept 2FA codes sent via SMS.
- [G1044] APT42: APT42 has intercepted SMS-based one-time passwords and has set up two-factor authentication. Additionally, APT42 has used cloned or fake websites to capture MFA tokens.
- [G1004] LAPSUS$: LAPSUS$ has replayed stolen session token and passwords to trigger simple-approval MFA prompts in hope of the legitimate user will grant necessary approval.


### T1187 - Forced Authentication

Procedures:

- [G0079] DarkHydrus: DarkHydrus used Template Injection to launch an authentication window for users to enter their credentials.
- [G0035] Dragonfly: Dragonfly has gathered hashed user credentials over SMB using spearphishing attachments with external resource links and by modifying .LNK file icon resources to collect credentials from virtualized systems.
- [S0634] EnvyScout: EnvyScout can use protocol handlers to coax the operating system to send NTLMv2 authentication responses to attacker-controlled infrastructure.


### T1212 - Exploitation for Credential Access

Procedures:

- [C0049] Leviathan Australian Intrusions: Leviathan exploited vulnerable network appliances during Leviathan Australian Intrusions, leading to the collection and exfiltration of valid credentials.


### T1528 - Steal Application Access Token

Procedures:

- [G0016] APT29: APT29 uses stolen tokens to access victim accounts, without needing a password.
- [S0683] Peirates: Peirates gathers Kubernetes service account tokens using a variety of techniques.
- [S0677] AADInternals: AADInternals can steal users’ access tokens via phishing emails containing malicious links.
- [G0007] APT28: APT28 has used several malicious applications to steal user OAuth access tokens including applications masquerading as "Google Defender" "Google Email Protection," and "Google Scanner" for Gmail users. They also targeted Yahoo users with applications masquerading as "Delivery Service" and "McAfee Email Protection".
- [C0049] Leviathan Australian Intrusions: Leviathan abused access to compromised appliances to collect JSON Web Tokens (JWTs), used for creating virtual desktop sessions, during Leviathan Australian Intrusions.


### T1539 - Steal Web Session Cookie

Procedures:

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
- [S1140] Spica: Spica has the ability to steal cookies from Chrome, Firefox, Opera, and Edge browsers.
- [S0650] QakBot: QakBot has the ability to capture web session cookies.
- [S0568] EVILNUM: EVILNUM can harvest cookies and upload them to the C2 server.
- [S1201] TRANSLATEXT: TRANSLATEXT has exfiltrated updated cookies from Google, Naver, Kakao or Daum to the C2 server.
- [S0631] Chaes: Chaes has used a script that extracts the web session cookie and sends it to the C2 server.


### T1552.001 - Unsecured Credentials: Credentials In Files

Procedures:

- [S0117] XTunnel: XTunnel is capable of accessing locally stored passwords on victims.
- [S0192] Pupy: Pupy can use Lazagne for harvesting credentials.
- [S0367] Emotet: Emotet has been observed leveraging a module that retrieves passwords stored on a system for the current logged-on user.
- [S0378] PoshC2: PoshC2 contains modules for searching for passwords in local and remote files.
- [S0226] Smoke Loader: Smoke Loader searches for files named logins.json to parse for credentials.
- [G0064] APT33: APT33 has used a variety of publicly available tools like LaZagne to gather credentials.
- [S0331] Agent Tesla: Agent Tesla has the ability to extract credentials from configuration or support files.
- [S0349] LaZagne: LaZagne can obtain credentials from chats, databases, mail, and WiFi.
- [S0363] Empire: Empire can use various modules to search for files containing passwords.
- [C0049] Leviathan Australian Intrusions: Leviathan gathered credentials stored in files related to Building Management System (BMS) operations during Leviathan Australian Intrusions.
- [S0344] Azorult: Azorult can steal credentials in files belonging to common software such as Skype, Telegram, and Steam.
- [S0583] Pysa: Pysa has extracted credentials from the password database before encrypting the files.
- [G0117] Fox Kitten: Fox Kitten has accessed files to gain valid credentials.
- [S0601] Hildegard: Hildegard has searched for SSH keys, Docker credentials, and Kubernetes service tokens.
- [G0092] TA505: TA505 has used malware to gather credentials from FTP clients and Outlook.

### T1552.002 - Unsecured Credentials: Credentials in Registry

Procedures:

- [S0075] Reg: Reg may be used to find credentials in the Windows Registry.
- [S0194] PowerSploit: PowerSploit has several modules that search the Windows Registry for stored credentials: Get-UnattendedInstallFile, Get-Webconfig, Get-ApplicationHost, Get-SiteListPassword, Get-CachedGPPPassword, and Get-RegistryAutoLogon.
- [G0050] APT32: APT32 used Outlook Credential Dumper to harvest credentials stored in Windows registry.
- [S1022] IceApple: IceApple can harvest credentials from local and remote host registries.
- [S1183] StrelaStealer: StrelaStealer enumerates the registry key `HKCU\SOFTWARE\Microsoft\Office\16.0\Outlook\Profiles\Outlook\9375CFF0413111d3B88A00104B2A6676\` to identify the values for "IMAP User," "IMAP Server," and "IMAP Password" associated with the Outlook email application.
- [S0266] TrickBot: TrickBot has retrieved PuTTY credentials by querying the Software\SimonTatham\Putty\Sessions registry key
- [S0476] Valak: Valak can use the clientgrabber module to steal e-mail credentials from the Registry.
- [G1039] RedCurl: RedCurl used LaZagne to obtain passwords in the Registry.
- [S0331] Agent Tesla: Agent Tesla has the ability to extract credentials from the Registry.

### T1552.003 - Unsecured Credentials: Bash History

Procedures:

- [S0599] Kinsing: Kinsing has searched bash_history for credentials.

### T1552.004 - Unsecured Credentials: Private Keys

Procedures:

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
- [G0139] TeamTNT: TeamTNT has searched for unsecured SSH keys.
- [S0363] Empire: Empire can use modules like Invoke-SessionGopher to extract private key and session information.
- [S0677] AADInternals: AADInternals can gather encryption keys from Azure AD services such as ADSync and Active Directory Federated Services servers.
- [G0106] Rocke: Rocke has used SSH private keys on the infected machine to spread its coinminer throughout a network.
- [S0377] Ebury: Ebury has intercepted unencrypted private keys as well as private key pass-phrases.

### T1552.005 - Unsecured Credentials: Cloud Instance Metadata API

Procedures:

- [G0139] TeamTNT: TeamTNT has queried the AWS instance metadata service for credentials.
- [S0683] Peirates: Peirates can query the query AWS and GCP metadata APIs for secrets.
- [S0601] Hildegard: Hildegard has queried the Cloud Instance Metadata API for cloud credentials.

### T1552.006 - Unsecured Credentials: Group Policy Preferences

Procedures:

- [S0692] SILENTTRINITY: SILENTTRINITY has a module that can extract cached GPP passwords.
- [S0194] PowerSploit: PowerSploit contains a collection of Exfiltration modules that can harvest credentials from Group Policy Preferences.
- [G0064] APT33: APT33 has used a variety of publicly available tools like Gpppassword to gather credentials.
- [G0102] Wizard Spider: Wizard Spider has used PowerShell cmdlets `Get-GPPPassword` and `Find-GPOPassword` to find unsecured credentials in a compromised network group policy.

### T1552.007 - Unsecured Credentials: Container API

Procedures:

- [S0683] Peirates: Peirates can query the Kubernetes API for secrets.

### T1552.008 - Unsecured Credentials: Chat Messages

Procedures:

- [G1004] LAPSUS$: LAPSUS$ has targeted various collaboration tools like Slack, Teams, JIRA, Confluence, and others to hunt for exposed credentials to support privilege escalation and lateral movement.


### T1555.001 - Credentials from Password Stores: Keychain

Procedures:

- [S1185] LightSpy: LightSpy performs an in-memory keychain query via `SecItemCopyMatching()` then formats the retrieved data as a JSON blob for exfiltration.
- [S0690] Green Lambert: Green Lambert can use Keychain Services API functions to find and collect passwords, such as `SecKeychainFindInternetPassword` and `SecKeychainItemCopyAttributesAndData`.
- [S0279] Proton: Proton gathers credentials in files for keychains.
- [S1016] MacMa: MacMa can dump credentials from the macOS keychain.
- [S0349] LaZagne: LaZagne can obtain credentials from macOS Keychains.
- [S0274] Calisto: Calisto collects Keychain storage data and copies those passwords/tokens to a file.
- [S1153] Cuckoo Stealer: Cuckoo Stealer can capture files from a targeted user's keychain directory.
- [S0278] iKitten: iKitten collects the keychains on the system.

### T1555.002 - Credentials from Password Stores: Securityd Memory

Procedures:

- [S0276] Keydnap: Keydnap uses the keychaindump project to read securityd memory.

### T1555.003 - Credentials from Password Stores: Credentials from Web Browsers

Procedures:

- [S0385] njRAT: njRAT has a module that steals passwords saved in victim web browsers.
- [S0089] BlackEnergy: BlackEnergy has used a plug-in to gather credentials from web browsers including FireFox, Google Chrome, and Internet Explorer.
- [S0132] H1N1: H1N1 dumps usernames and passwords from Firefox, Internet Explorer, and Outlook.
- [S1122] Mispadu: Mispadu can steal credentials from Google Chrome.
- [S0434] Imminent Monitor: Imminent Monitor has a PasswordRecoveryPacket module for recovering browser passwords.
- [S0365] Olympic Destroyer: Olympic Destroyer contains a module that tries to obtain stored credentials from web browsers.
- [S0528] Javali: Javali can capture login credentials from open browsers including Firefox, Chrome, Internet Explorer, and Edge.
- [S0492] CookieMiner: CookieMiner can steal saved usernames and passwords in Chrome as well as credit card credentials.
- [G0040] Patchwork: Patchwork dumped the login data database from \AppData\Local\Google\Chrome\User Data\Default\Login Data.
- [S1042] SUGARDUMP: SUGARDUMP variants have harvested credentials from browsers such as Firefox, Chrome, Opera, and Edge.
- [S1213] Lumma Stealer: Lumma Stealer has gathered credential and other information from multiple browsers.
- [G0096] APT41: APT41 used BrowserGhost, a tool designed to obtain credentials from browsers, to retrieve information from password stores.
- [S0670] WarzoneRAT: WarzoneRAT has the capability to grab passwords from numerous web browsers as well as from Outlook and Thunderbird email clients.
- [S1201] TRANSLATEXT: TRANSLATEXT has stolen credentials stored in Chrome.
- [G0128] ZIRCONIUM: ZIRCONIUM has used a tool to steal credentials from installed web browsers including Microsoft Internet Explorer and Google Chrome.

### T1555.004 - Credentials from Password Stores: Windows Credential Manager

Procedures:

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
- [S0002] Mimikatz: Mimikatz contains functionality to acquire credentials from the Windows Credential Manager.
- [S0526] KGH_SPY: KGH_SPY can collect credentials from the Windows Credential Manager.
- [S0194] PowerSploit: PowerSploit contains a collection of Exfiltration modules that can harvest credentials from Windows vault credential objects.
- [G0102] Wizard Spider: Wizard Spider has used PowerShell cmdlet `Invoke-WCMDump` to enumerate Windows credentials in the Credential Manager in a compromised network.

### T1555.005 - Credentials from Password Stores: Password Managers

Procedures:

- [C0014] Operation Wocao: During Operation Wocao, threat actors accessed and collected credentials from password managers.
- [G0027] Threat Group-3390: Threat Group-3390 obtained a KeePass database from a compromised host.
- [G0119] Indrik Spider: Indrik Spider has accessed and exported passwords from password managers.
- [G0117] Fox Kitten: Fox Kitten has used scripts to access credential information from the KeePass database.
- [S0652] MarkiRAT: MarkiRAT can gather information from the Keepass password manager.
- [S0279] Proton: Proton gathers credentials in files for 1password.
- [S0266] TrickBot: TrickBot can steal passwords from the KeePass open source password manager.
- [G1004] LAPSUS$: LAPSUS$ has accessed local password managers and databases to obtain further credentials from a compromised network.

### T1555.006 - Credentials from Password Stores: Cloud Secrets Management Stores

Procedures:

- [G0125] HAFNIUM: HAFNIUM has moved laterally from on-premises environments to steal passwords from Azure key vaults.
- [S1091] Pacu: Pacu can retrieve secrets from the AWS Secrets Manager via the enum_secrets module.


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


### T1557.001 - Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning and SMB Relay

Procedures:

- [S0357] Impacket: Impacket modules like ntlmrelayx and smbrelayx can be used in conjunction with Network Sniffing and LLMNR/NBT-NS Poisoning and SMB Relay to gather NetNTLM credentials for Brute Force or relay attacks that can gain code execution.
- [S0363] Empire: Empire can use Inveigh to conduct name service poisoning for credential theft and associated relay attacks.
- [S0378] PoshC2: PoshC2 can use Inveigh to conduct name service poisoning for credential theft and associated relay attacks.
- [G0032] Lazarus Group: Lazarus Group executed Responder using the command [Responder file path] -i [IP address] -rPv on a compromised host to harvest credentials and move laterally.
- [G0102] Wizard Spider: Wizard Spider has used the Invoke-Inveigh PowerShell cmdlets, likely for name service poisoning.
- [S0192] Pupy: Pupy can sniff plaintext network credentials and use NBNS Spoofing to poison name services.
- [S0174] Responder: Responder is used to poison name services to gather hashes and credentials from systems within a local network.

### T1557.002 - Adversary-in-the-Middle: ARP Cache Poisoning

Procedures:

- [G0003] Cleaver: Cleaver has used custom tools to facilitate ARP cache poisoning.
- [G1014] LuminousMoth: LuminousMoth has used ARP spoofing to redirect a compromised machine to an actor-controlled website.

### T1557.003 - Adversary-in-the-Middle: DHCP Spoofing

Procedures:

- Adversaries may redirect network traffic to adversary-owned systems by spoofing Dynamic Host Configuration Protocol (DHCP) traffic and acting as a malicious DHCP server on the victim network. By achieving the adversary-in-the-middle (AiTM) position, adversaries may collect network communications, including passed credentials, especially those sent over insecure, unencrypted protocols. This may also enable follow-on behaviors such as Network Sniffing or Transmitted Data Manipulation. DHCP is based on a client-server model and has two functionalities: a protocol for providing network configuration settings from a DHCP server to a client and a mechanism for allocating network addresses to clients. The typical server-client interaction is as follows: 1. The client broadcasts a `DISCOVER` message. 2. The server responds with an `OFFER` message, which includes an available network address. 3. The client broadcasts a `REQUEST` message, which includes the network address offered. 4. The server acknowledges with an `ACK` message and the client receives the network configuration parameters. Adversaries may spoof as a rogue DHCP server on the victim network, from which legitimate hosts may receive malicious network configurations. For example, malware can act as a DHCP server and provide adversary-owned DNS servers to the victimized computers. Through the malicious network configurations, an adversary may achieve the AiTM position, route client traffic through adversary-controlled systems, and collect information from the client network. DHCPv6 clients can receive network configuration information without being assigned an IP address by sending a INFORMATION-REQUEST (code 11) message to the All_DHCP_Relay_Agents_and_Servers multicast address. Adversaries may use their rogue DHCP server to respond to this request message with malicious network configurations. Rather than establishing an AiTM position, adversaries may also abuse DHCP spoofing to perform a DHCP exhaustion attack (i.e, Service Exhaustion Flood) by generating many broadcast DISCOVER messages to exhaust a network’s DHCP allocation pool.

### T1557.004 - Adversary-in-the-Middle: Evil Twin

Procedures:

- [G0007] APT28: APT28 has used a Wi-Fi Pineapple to set up Evil Twin Wi-Fi Poisoning for the purposes of capturing victim credentials or planting espionage-oriented malware.


### T1558.001 - Steal or Forge Kerberos Tickets: Golden Ticket

Procedures:

- [G0004] Ke3chang: Ke3chang has used Mimikatz to generate Kerberos golden tickets.
- [S0363] Empire: Empire can leverage its implementation of Mimikatz to obtain and use golden tickets.
- [S0002] Mimikatz: Mimikatz's kerberos module can create golden tickets.
- [S0633] Sliver: Sliver incorporates the Rubeus framework to allow for Kerberos ticket manipulation, specifically for forging Kerberos Golden Tickets.
- [S1071] Rubeus: Rubeus can forge a ticket-granting ticket.

### T1558.002 - Steal or Forge Kerberos Tickets: Silver Ticket

Procedures:

- [S1071] Rubeus: Rubeus can create silver tickets.
- [S0677] AADInternals: AADInternals can be used to forge Kerberos tickets using the password hash of the AZUREADSSOACC account.
- [S0002] Mimikatz: Mimikatz's kerberos module can create silver tickets.
- [S0363] Empire: Empire can leverage its implementation of Mimikatz to obtain and use silver tickets.

### T1558.003 - Steal or Forge Kerberos Tickets: Kerberoasting

Procedures:

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
- [G0119] Indrik Spider: Indrik Spider has conducted Kerberoasting attacks using a module from GitHub.
- [S1063] Brute Ratel C4: Brute Ratel C4 can decode Kerberos 5 tickets and convert it to hashcat format for subsequent cracking.

### T1558.004 - Steal or Forge Kerberos Tickets: AS-REP Roasting

Procedures:

- [S1071] Rubeus: Rubeus can reveal the credentials of accounts that have Kerberos pre-authentication disabled through AS-REP roasting.

### T1558.005 - Steal or Forge Kerberos Tickets: Ccache Files

Procedures:

- [S0357] Impacket: Impacket tools – such as getST.py or ticketer.py – can be used to steal or forge Kerberos tickets using ccache files given a password, hash, aesKey, or TGT.


### T1606.001 - Forge Web Credentials: Web Cookies

Procedures:

- [C0024] SolarWinds Compromise: During the SolarWinds Compromise, APT29 bypassed MFA set on OWA accounts by generating a cookie value from a previously stolen secret key.

### T1606.002 - Forge Web Credentials: SAML Tokens

Procedures:

- [C0024] SolarWinds Compromise: During the SolarWinds Compromise, APT29 created tokens using compromised SAML signing certificates.
- [S0677] AADInternals: AADInternals can be used to create SAML tokens using the AD Federated Services token signing certificate.


### T1621 - Multi-Factor Authentication Request Generation

Procedures:

- [G0016] APT29: APT29 has used repeated MFA requests to gain access to victim accounts.
- [C0027] C0027: During C0027, Scattered Spider attempted to gain access by continuously sending MFA messages to the victim until they accept the MFA push challenge.
- [G1015] Scattered Spider: Scattered Spider has used multifactor authentication (MFA) fatigue by sending repeated MFA authentication requests to targets.
- [G1004] LAPSUS$: LAPSUS$ has spammed target users with MFA prompts in the hope that the legitimate user will grant necessary approval.


### T1649 - Steal or Forge Authentication Certificates

Procedures:

- [S0677] AADInternals: AADInternals can create and export various authentication certificates, including those associated with Azure AD joined/registered devices.
- [G0016] APT29: APT29 has abused misconfigured AD CS certificate templates to impersonate admin users and create additional authentication certificates.
- [S0002] Mimikatz: Mimikatz's `CRYPTO` module can create and export various types of authentication certificates.

