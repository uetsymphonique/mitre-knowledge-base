### T1005 - Data from Local System

Procedures:

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
- [S0650] QakBot: QakBot can use a variety of commands, including esentutl.exe to steal sensitive data from Internet Explorer and Microsoft Edge, to acquire information that is subsequently exfiltrated.
- [S1043] ccf32: ccf32 can collect files from a compromised host.
- [S0567] Dtrack: Dtrack can collect a variety of information from victim machines.
- [S0239] Bankshot: Bankshot collects files from the local system.
- [S0128] BADNEWS: When it first starts, BADNEWS crawls the victim's local drives and collects documents with the following extensions: .doc, .docx, .pdf, .ppt, .pptx, and .txt.


### T1025 - Data from Removable Media

Procedures:

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
- [S0125] Remsec: Remsec has a package that collects documents from any inserted USB sticks.
- [S0128] BADNEWS: BADNEWS copies files with certain extensions from USB devices to a predefined directory.
- [S0113] Prikormka: Prikormka contains a module that collects documents with certain extensions from removable media or fixed drives connected via USB.
- [S0538] Crutch: Crutch can monitor removable drives and exfiltrate files matching a given extension list.
- [S0115] Crimson: Crimson contains a module to collect data from removable drives.


### T1039 - Data from Network Shared Drive

Procedures:

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
- [G0045] menuPass: menuPass has collected data from remote systems by mounting network shares with net use and using Robocopy to transfer data.
- [C0015] C0015: During C0015, the threat actors collected files from network shared drives prior to network encryption.
- [G0117] Fox Kitten: Fox Kitten has searched network shares to access sensitive documents.


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


### T1074.001 - Data Staged: Local Data Staging

Procedures:

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
- [G0027] Threat Group-3390: Threat Group-3390 has locally staged encrypted archives for later exfiltration efforts.
- [G0121] Sidewinder: Sidewinder has collected stolen files in a temporary folder in preparation for exfiltration.
- [S0386] Ursnif: Ursnif has used tmp files to stage gathered information.
- [S1044] FunnyDream: FunnyDream can stage collected information including screen captures and logged keystrokes locally.
- [C0032] C0032: During the C0032 campaign, TEMP.Veles used staging folders that are infrequently used by legitimate users or processes to store data for exfiltration and tool deployment.

### T1074.002 - Data Staged: Remote Data Staging

Procedures:

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
- [G0037] FIN6: FIN6 actors have compressed data from remote systems and moved it to another staging system before exfiltration.
- [C0002] Night Dragon: During Night Dragon, threat actors copied files to company web servers and subsequently downloaded them.
- [G0027] Threat Group-3390: Threat Group-3390 has moved staged encrypted archives to Internet-facing servers that had previously been compromised with China Chopper prior to exfiltration.


### T1113 - Screen Capture

Procedures:

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
- [S0338] Cobian RAT: Cobian RAT has a feature to perform screen capture.
- [S0128] BADNEWS: BADNEWS has a command to take a screenshot and send it to the C2 server.
- [S0458] Ramsay: Ramsay can take screenshots every 30 seconds as well as when an external removable storage device is connected.
- [S0089] BlackEnergy: BlackEnergy is capable of taking screenshots.
- [S1196] Troll Stealer: Troll Stealer can capture screenshots from victim machines.


### T1114.001 - Email Collection: Local Email Collection

Procedures:

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
- [S0363] Empire: Empire has the ability to collect emails on a target system.
- [G0114] Chimera: Chimera has harvested data from victim's e-mail including through execution of wmic /node: process call create "cmd /c copy c:\Users\\\backup.pst c:\windows\temp\backup.pst" copy "i:\\\My Documents\.pst" copy.
- [S0526] KGH_SPY: KGH_SPY can harvest data from mail clients.
- [G0059] Magic Hound: Magic Hound has collected .PST archives.
- [S0050] CosmicDuke: CosmicDuke searches for Microsoft Outlook data files with extensions .pst and .ost for collection and exfiltration.

### T1114.002 - Email Collection: Remote Email Collection

Procedures:

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
- [G0125] HAFNIUM: HAFNIUM has used web shells and MSGraph to export mailbox data.
- [S0476] Valak: Valak can collect sensitive mailing information from Exchange servers, including credentials and the domain certificate of an enterprise.
- [G0059] Magic Hound: Magic Hound has exported emails from compromised Exchange servers including through use of the cmdlet `New-MailboxExportRequest.`
- [G0114] Chimera: Chimera has harvested data from remote mailboxes including through execution of \\\c$\Users\\AppData\Local\Microsoft\Outlook*.ost.
- [G0035] Dragonfly: Dragonfly has accessed email accounts using Outlook Web Access.

### T1114.003 - Email Collection: Email Forwarding Rule

Procedures:

- [G0122] Silent Librarian: Silent Librarian has set up auto forwarding rules on compromised e-mail accounts.
- [G1004] LAPSUS$: LAPSUS$ has set an Office 365 tenant level mail transport rule to send all mail in and out of the targeted organization to the newly created account.
- [G1033] Star Blizzard: Star Blizzard has abused email forwarding rules to monitor the activities of a victim, steal information, and maintain persistent access after compromised credentials are reset.
- [G0094] Kimsuky: Kimsuky has set auto-forward rules on victim's e-mail accounts.


### T1115 - Clipboard Data

Procedures:

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
- [S0257] VERMIN: VERMIN collects data stored in the clipboard.
- [C0014] Operation Wocao: During Operation Wocao, threat actors collected clipboard data in plaintext.
- [S1149] CHIMNEYSWEEP: CHIMNEYSWEEP can capture content from the clipboard.
- [S0356] KONNI: KONNI had a feature to steal data from the clipboard.
- [S0375] Remexi: Remexi collects text from the clipboard.


### T1119 - Automated Collection

Procedures:

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
- [G1003] Ember Bear: Ember Bear engages in mass collection from compromised systems during intrusions.
- [G1039] RedCurl: RedCurl has used batch scripts to collect data.
- [S0378] PoshC2: PoshC2 contains a module for recursively parsing through files and directories to gather valid credit card numbers.
- [S0428] PoetRAT: PoetRAT used file system monitoring to track modification and enable automatic exfiltration.
- [S0363] Empire: Empire can automatically gather the username, domain name, machine name, and other information from a compromised system.


### T1123 - Audio Capture

Procedures:

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
- [S0336] NanoCore: NanoCore can capture audio feeds from the system.
- [S0115] Crimson: Crimson can perform audio surveillance using microphones.
- [S1016] MacMa: MacMa has the ability to record audio.
- [S0098] T9000: T9000 uses the Skype API to record audio and video calls. It writes encrypted data to %APPDATA%\Intel\Skype.
- [S0409] Machete: Machete captures audio from the computer’s microphone.


### T1125 - Video Capture

Procedures:

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
- [S0385] njRAT: njRAT can access the victim's webcam.
- [S0331] Agent Tesla: Agent Tesla can access the victim’s webcam and record video.
- [G1003] Ember Bear: Ember Bear has exfiltrated images from compromised IP cameras.
- [S0428] PoetRAT: PoetRAT has used a Python tool named Bewmac to record the webcam on compromised hosts.
- [G0091] Silence: Silence has been observed making videos of victims to observe bank employees day to day activities.


### T1185 - Browser Session Hijacking

Procedures:

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
- [S0154] Cobalt Strike: Cobalt Strike can perform browser pivoting and inject into a user's browser to inherit cookies, authenticated HTTP sessions, and client SSL certificates.
- [S0483] IcedID: IcedID has used web injection attacks to redirect victims to spoofed sites designed to harvest banking and other credentials. IcedID can use a self signed TLS certificate in connection with the spoofed site and simultaneously maintains a live connection with the legitimate site to display the correct URL and certificates in the browser.
- [S0631] Chaes: Chaes has used the Puppeteer module to hook and monitor the Chrome web browser to collect user information from infected hosts.
- [S0386] Ursnif: Ursnif has injected HTML codes into banking sites to steal sensitive online banking information (ex: usernames and passwords).


### T1213.001 - Data from Information Repositories: Confluence

Procedures:

- [G1004] LAPSUS$: LAPSUS$ has searched a victim's network for collaboration platforms like Confluence and JIRA to discover further high-privilege account credentials.

### T1213.002 - Data from Information Repositories: Sharepoint

Procedures:

- [G1024] Akira: Akira has accessed and downloaded information stored in SharePoint instances as part of data gathering and exfiltration activity.
- [G0125] HAFNIUM: HAFNIUM has abused compromised credentials to exfiltrate data from SharePoint.
- [G1004] LAPSUS$: LAPSUS$ has searched a victim's network for collaboration platforms like SharePoint to discover further high-privilege account credentials.
- [S0227] spwebmember: spwebmember is used to enumerate and dump information from Microsoft SharePoint.
- [G0114] Chimera: Chimera has collected documents from the victim's SharePoint.
- [G0007] APT28: APT28 has collected information from Microsoft SharePoint services within target networks.
- [C0027] C0027: During C0027, Scattered Spider accessed victim SharePoint environments to search for VPN and MFA enrollment information, help desk instructions, and new hire guides.
- [G0004] Ke3chang: Ke3chang used a SharePoint enumeration and data dumping tool known as spwebmember.

### T1213.003 - Data from Information Repositories: Code Repositories

Procedures:

- [G1004] LAPSUS$: LAPSUS$ has searched a victim's network for code repositories like GitLab and GitHub to discover further high-privilege account credentials.
- [G1015] Scattered Spider: Scattered Spider enumerates data stored within victim code repositories, such as internal GitHub repositories.
- [C0024] SolarWinds Compromise: During the SolarWinds Compromise, APT29 downloaded source code from code repositories.
- [G0096] APT41: APT41 cloned victim user Git repositories during intrusions.

### T1213.004 - Data from Information Repositories: Customer Relationship Management Software

Procedures:

- Adversaries may leverage Customer Relationship Management (CRM) software to mine valuable information. CRM software is used to assist organizations in tracking and managing customer interactions, as well as storing customer data. Once adversaries gain access to a victim organization, they may mine CRM software for customer data. This may include personally identifiable information (PII) such as full names, emails, phone numbers, and addresses, as well as additional details such as purchase histories and IT support interactions. By collecting this data, an adversary may be able to send personalized Phishing emails, engage in SIM swapping, or otherwise target the organization’s customers in ways that enable financial gain or the compromise of additional organizations. CRM software may be hosted on-premises or in the cloud. Information stored in these solutions may vary based on the specific instance or environment. Examples of CRM software include Microsoft Dynamics 365, Salesforce, Zoho, Zendesk, and HubSpot.

### T1213.005 - Data from Information Repositories: Messaging Applications

Procedures:

- [G0117] Fox Kitten: Fox Kitten has accessed victim security and IT environments and Microsoft Teams to mine valuable information.
- [G1015] Scattered Spider: Scattered Spider threat actors search the victim’s Slack and Microsoft Teams for conversations about the intrusion and incident response.
- [G1004] LAPSUS$: LAPSUS$ has searched a victim's network for organization collaboration channels like MS Teams or Slack to discover further high-privilege account credentials.


### T1530 - Data from Cloud Storage

Procedures:

- [G0117] Fox Kitten: Fox Kitten has obtained files from the victim's cloud storage instances.
- [S0683] Peirates: Peirates can dump the contents of AWS S3 buckets. It can also retrieve service account tokens from kOps buckets in Google Cloud Storage or S3.
- [G1044] APT42: APT42 has collected data from Microsoft 365 environments.
- [G0125] HAFNIUM: HAFNIUM has exfitrated data from OneDrive.
- [G1015] Scattered Spider: Scattered Spider enumerates data stored in cloud resources for collection and exfiltration purposes.
- [S1091] Pacu: Pacu can enumerate and download files stored in AWS storage services, such as S3 buckets.
- [C0027] C0027: During C0027, Scattered Spider accessed victim OneDrive environments to search for VPN and MFA enrollment information, help desk instructions, and new hire guides.
- [S0677] AADInternals: AADInternals can collect files from a user’s OneDrive.


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


### T1560.001 - Archive Collected Data: Archive via Utility

Procedures:

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
- [G0117] Fox Kitten: Fox Kitten has used 7-Zip to archive data.
- [G0052] CopyKittens: CopyKittens uses ZPP, a .NET console program, to compress files with ZIP.
- [G1017] Volt Typhoon: Volt Typhoon has archived the ntds.dit database as a multi-volume password-protected archive with 7-Zip.
- [S0260] InvisiMole: InvisiMole uses WinRAR to compress data that is intended to be exfiltrated.
- [G0006] APT1: APT1 has used RAR to compress files before moving them outside of the victim network.

### T1560.002 - Archive Collected Data: Archive via Library

Procedures:

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
- [S0352] OSX_OCEANLOTUS.D: OSX_OCEANLOTUS.D scrambles and encrypts data using AES256 before sending it to the C2 server.
- [G0032] Lazarus Group: Lazarus Group malware IndiaIndia saves information gathered about the victim to a file that is compressed with Zlib, encrypted, and uploaded to a C2 server.
- [S0661] FoggyWeb: FoggyWeb can invoke the `Common.Compress` method to compress data with the C# GZipStream compression class.
- [S1044] FunnyDream: FunnyDream has compressed collected files with zLib.
- [G0027] Threat Group-3390: Threat Group-3390 has used RAR to compress, encrypt, and password-protect files prior to exfiltration.

### T1560.003 - Archive Collected Data: Archive via Custom Method

Procedures:

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
- [S0491] StrongPity: StrongPity can compress and encrypt archived files into multiple .sft files with a repeated xor encryption scheme.
- [S0258] RGDoor: RGDoor encrypts files with XOR before sending them back to the C2 server.
- [S0169] RawPOS: RawPOS encodes credit card data it collected from the victim with XOR.
- [S1059] metaMain: metaMain has used XOR-based encryption for collected files before exfiltration.
- [S0458] Ramsay: Ramsay can store collected documents in a custom container after encrypting and compressing them using RC4 and WinRAR.


### T1602.001 - Data from Configuration Repository: SNMP (MIB Dump)

Procedures:

- Adversaries may target the Management Information Base (MIB) to collect and/or mine valuable information in a network managed using Simple Network Management Protocol (SNMP). The MIB is a configuration repository that stores variable information accessible via SNMP in the form of object identifiers (OID). Each OID identifies a variable that can be read or set and permits active management tasks, such as configuration changes, through remote modification of these variables. SNMP can give administrators great insight in their systems, such as, system information, description of hardware, physical location, and software packages. The MIB may also contain device operational information, including running configuration, routing table, and interface details. Adversaries may use SNMP queries to collect MIB content directly from SNMP-managed devices in order to collect network information that allows the adversary to build network maps and facilitate future targeted exploitation.

### T1602.002 - Data from Configuration Repository: Network Device Configuration Dump

Procedures:

- [G1045] Salt Typhoon: Salt Typhoon has attempted to acquire credentials by dumping network device configurations.

