### T1006 - Direct Volume Access

Procedures:

- [S0404] esentutl: esentutl can use the Volume Shadow Copy service to copy locked files such as `ntds.dit`.
- [G1015] Scattered Spider: Scattered Spider has created volume shadow copies of virtual domain controller disks to extract the `NTDS.dit` file.
- [G1017] Volt Typhoon: Volt Typhoon has executed the Windows-native `vssadmin` command to create volume shadow copies.
- [C0051] APT28 Nearest Neighbor Campaign: During APT28 Nearest Neighbor Campaign, APT28 accessed volume shadow copies through executing vssadmin in order to dump the NTDS.dit file.


### T1014 - Rootkit

Procedures:

- [S0377] Ebury: Ebury acts as a user land rootkit using the SSH service.
- [G0044] Winnti Group: Winnti Group used a rootkit to modify typical server functionality.
- [G0096] APT41: APT41 deployed rootkits on Linux systems.
- [G0106] Rocke: Rocke has modified /etc/ld.so.preload to hook libc functions in order to hide the installed dropper and mining software in process lists.
- [S0484] Carberp: Carberp has used user mode rootkit techniques to remain hidden on the system.
- [S0458] Ramsay: Ramsay has included a rootkit to evade defenses.
- [S0502] Drovorub: Drovorub has used a kernel module rootkit to hide processes, files, executables, and network artifacts from user space view.
- [S0040] HTRAN: HTRAN can install a rootkit to hide network connections from the host OS.
- [S0135] HIDEDRV: HIDEDRV is a rootkit that hides certain operating system artifacts.
- [G0139] TeamTNT: TeamTNT has used rootkits such as the open-source Diamorphine rootkit and their custom bots to hide cryptocurrency mining activities on the machine.
- [S0468] Skidmap: Skidmap is a kernel-mode rootkit that has the ability to hook system calls to hide specific files and fake network and CPU-related statistics to make the CPU load of the infected machine always appear low.
- [S0221] Umbreon: Umbreon hides from defenders by hooking libc function calls, hiding artifacts that would reveal its presence, such as the user account it creates to provide access and undermining strace, a tool often used to identify malware.
- [S0603] Stuxnet: Stuxnet uses a Windows rootkit to mask its binaries and other relevant files.
- [S1105] COATHANGER: COATHANGER hooks or replaces multiple legitimate processes and other functions on victim devices.
- [S0047] Hacking Team UEFI Rootkit: Hacking Team UEFI Rootkit is a UEFI BIOS rootkit developed by the company Hacking Team to persist remote access software on some targeted systems.


### T1027.001 - Obfuscated Files or Information: Binary Padding

Procedures:

- [S0586] TAINTEDSCRIBE: TAINTEDSCRIBE can execute FileRecvWriteRand to append random bytes to the end of a file received from C2.
- [S0367] Emotet: Emotet inflates malicious files and malware as an evasion technique.
- [S0528] Javali: Javali can use large obfuscated libraries to hinder detection and analysis.
- [S0650] QakBot: QakBot can use large file sizes to evade detection.
- [S0433] Rifdoor: Rifdoor has added four additional bytes of data upon launching, then saved the changed version as C:\ProgramData\Initech\Initech.exe.
- [G0065] Leviathan: Leviathan has inserted garbage characters into code, presumably to avoid anti-virus detection.
- [S1149] CHIMNEYSWEEP: The CHIMNEYSWEEP installer has been padded with null bytes to inflate its size.
- [S0531] Grandoreiro: Grandoreiro has added BMP images to the resources section of its Portable Executable (PE) file increasing each binary to at least 300MB in size.
- [G0016] APT29: APT29 used large size files to avoid detection by security solutions with hardcoded size limits.
- [G0002] Moafee: Moafee has been known to employ binary padding.
- [S0614] CostaBricks: CostaBricks has added the entire unobfuscated code of the legitimate open source application Blink to its code.
- [S1185] LightSpy: LightSpy's configuration file is appended to the end of the binary. For example, the last `0x1d0` bytes of one sample is an AES encrypted configuration file with a static key of `3e2717e8b3873b29`.
- [S0268] Bisonal: Bisonal has appended random binary data to the end of itself to generate a large binary.
- [G0126] Higaisa: Higaisa performed padding with null bytes before calculating its hash.
- [S0236] Kwampirs: Before writing to disk, Kwampirs inserts a randomly generated string into the middle of the decrypted payload in an attempt to evade hash-based detections.

### T1027.002 - Obfuscated Files or Information: Software Packing

Procedures:

- [S0588] GoldMax: GoldMax has been packed for obfuscation.
- [S0447] Lokibot: Lokibot has used several packing methods for obfuscation.
- [S0625] Cuba: Cuba has a packed payload when delivered.
- [S0257] VERMIN: VERMIN is initially packed.
- [S0020] China Chopper: China Chopper's client component is packed with UPX.
- [C0017] C0017: During C0017, APT41 used VMProtect to slow the reverse engineering of malicious binaries.
- [S1130] Raspberry Robin: Raspberry Robin contains multiple payloads that are packed for defense evasion purposes and unpacked on runtime.
- [S0565] Raindrop: Raindrop used a custom packer for its Cobalt Strike payload, which was compressed using the LZMA algorithm.
- [S1196] Troll Stealer: Troll Stealer has been delivered as a VMProtect-packed binary.
- [G0089] The White Company: The White Company has obfuscated their payloads through packing.
- [S0022] Uroburos: Uroburos uses a custom packer.
- [S0543] Spark: Spark has been packed with Enigma Protector to obfuscate its contents.
- [G1018] TA2541: TA2541 has used a .NET packer to obfuscate malicious files.
- [S0198] NETWIRE: NETWIRE has used .NET packer tools to evade detection.
- [S0409] Machete: Machete has been packed with NSIS.

### T1027.003 - Obfuscated Files or Information: Steganography

Procedures:

- [G1006] Earth Lusca: Earth Lusca has used steganography to hide shellcode in a BMP image file.
- [S0495] RDAT: RDAT can also embed data within a BMP image prior to exfiltration.
- [S0139] PowerDuke: PowerDuke uses steganography to hide backdoors in PNG files, which are also encrypted using the Tiny Encryption Algorithm (TEA).
- [C0005] Operation Spalax: For Operation Spalax, the threat actors used packers that read pixel data from images contained in PE files' resource sections and build the next layer of execution from the data.
- [G0067] APT37: APT37 uses steganography to send images to users that are embedded with shellcode.
- [S0513] LiteDuke: LiteDuke has used image files to hide its loader component.
- [S0470] BBK: BBK can extract a malicious Portable Executable (PE) from a photo.
- [S0511] RegDuke: RegDuke can hide data in images, including use of the Least Significant Bit (LSB).
- [S0471] build_downer: build_downer can extract malware from a downloaded JPEG.
- [S0439] Okrum: Okrum's payload is encrypted and embedded within its loader, or within a legitimate PNG file.
- [S0234] Bandook: Bandook has used .PNG images within a zip file to build the executable.
- [G0127] TA551: TA551 has hidden encoded data for malware DLLs in a PNG.
- [S0659] Diavol: Diavol has obfuscated its main code routines within bitmap images as part of its anti-analysis techniques.
- [G0065] Leviathan: Leviathan has used steganography to hide stolen data inside other files stored on Github.
- [S0458] Ramsay: Ramsay has PE data embedded within JPEG files contained within Word documents.

### T1027.004 - Obfuscated Files or Information: Compile After Delivery

Procedures:

- [G0047] Gamaredon Group: Gamaredon Group has compiled the source code for a downloader directly on the infected system using the built-in Microsoft.CSharp.CSharpCodeProvider class.
- [S0633] Sliver: Sliver includes functionality to retrieve source code and compile locally prior to execution in victim environments.
- [S0661] FoggyWeb: FoggyWeb can compile and execute source code sent to the compromised AD FS server via a specific HTTP POST.
- [G0106] Rocke: Rocke has compiled malware, delivered to victims as .c files, with the GNU Compiler Collection (GCC).
- [G0069] MuddyWater: MuddyWater has used the .NET csc.exe tool to compile executables from downloaded C# code.
- [S0385] njRAT: njRAT has used AutoIt to compile the payload and main script into a single executable after delivery.
- [S0348] Cardinal RAT: Cardinal RAT and its watchdog component are compiled and executed after being delivered to victims as embedded, uncompiled source code.
- [S1099] Samurai: Samurai can compile and execute downloaded modules at runtime.
- [G1041] Sea Turtle: Sea Turtle downloaded source code files from remote addresses then compiled them locally via GCC in victim environments.
- [S0673] DarkWatchman: DarkWatchman has used the csc.exe tool to compile a C# executable.

### T1027.005 - Obfuscated Files or Information: Indicator Removal from Tools

Procedures:

- [S0237] GravityRAT: The author of GravityRAT submitted samples to VirusTotal for testing, showing that the author modified the code to try to hide the DDE object in a different part of the document.
- [S0154] Cobalt Strike: Cobalt Strike includes a capability to modify the Beacon payload to eliminate known signatures or unpacking methods.
- [G0040] Patchwork: Patchwork apparently altered NDiskMonitor samples by adding four bytes of random letters in a likely attempt to change the file hashes.
- [S0194] PowerSploit: PowerSploit's Find-AVSignature AntivirusBypass module can be used to locate single byte anti-virus signatures.
- [G0009] Deep Panda: Deep Panda has updated and modified its malware, resulting in different hash values that evade detection.
- [G0093] GALLIUM: GALLIUM ensured each payload had a unique hash, including by using different types of packers.
- [S0587] Penquin: Penquin can remove strings from binaries.
- [C0014] Operation Wocao: During Operation Wocao, threat actors edited variable names within the Impacket suite to avoid automated detection.
- [S0650] QakBot: QakBot can make small changes to itself in order to change its checksum and hash value.
- [C0030] Triton Safety Instrumented System Attack: In the Triton Safety Instrumented System Attack, TEMP.Veles modified files based on the open-source project cryptcat in an apparent attempt to decrease anti-virus detection rates.
- [S0579] Waterbear: Waterbear can scramble functions not to be executed again with random values.
- [S0187] Daserf: Analysis of Daserf has shown that it regularly undergoes technical improvements to evade anti-virus detection.
- [S0559] SUNBURST: SUNBURST source code used generic variable names and pre-obfuscated strings, and was likely sanitized of developer comments before being added to SUNSPOT.
- [S0260] InvisiMole: InvisiMole has undergone regular technical improvements in an attempt to evade detection.
- [G0049] OilRig: OilRig has tested malware samples to determine AV detection and subsequently modified the samples to ensure AV evasion.

### T1027.006 - Obfuscated Files or Information: HTML Smuggling

Procedures:

- [S0650] QakBot: QakBot has been delivered in ZIP files via HTML smuggling.
- [G0016] APT29: APT29 has embedded an ISO file within an HTML attachment that contained JavaScript code to initiate malware execution.
- [S0634] EnvyScout: EnvyScout contains JavaScript code that can extract an encoded blob from its HTML body and write it to disk.

### T1027.007 - Obfuscated Files or Information: Dynamic API Resolution

Procedures:

- [S1160] Latrodectus: Latrodectus can resolve Windows APIs dynamically by hash.
- [S0534] Bazar: Bazar can hash then resolve API calls at runtime.
- [S1053] AvosLocker: AvosLocker has used obfuscated API calls that are retrieved by their checksums.
- [S1148] Raccoon Stealer: Raccoon Stealer dynamically links key WinApi functions during execution.
- [G0032] Lazarus Group: Lazarus Group has used a custom hashing method to resolve APIs used in shellcode.
- [S0147] Pteranodon: Pteranodon can use a dynamic Windows hashing algorithm to map API components.
- [S1149] CHIMNEYSWEEP: CHIMNEYSWEEP can use `LoadLibrary` and `GetProcAddress` to resolve Windows API function strings at run time.
- [S1063] Brute Ratel C4: Brute Ratel C4 can call and dynamically resolve hashed APIs.
- [S1099] Samurai: Samurai can encrypt API name strings with an XOR-based algorithm.

### T1027.008 - Obfuscated Files or Information: Stripped Payloads

Procedures:

- [S1048] macOS.OSAMiner: macOS.OSAMiner has used run-only Applescripts, a compiled and stripped version of AppleScript, to remove human readable indicators to evade detection.
- [S1153] Cuckoo Stealer: Cuckoo Stealer is a stripped binary payload.

### T1027.009 - Obfuscated Files or Information: Embedded Payloads

Procedures:

- [S1137] Moneybird: Moneybird contains a configuration blob embedded in the malware itself.
- [S1052] DEADEYE: The DEADEYE.EMBED variant of DEADEYE has the ability to embed payloads inside of a compiled binary.
- [G0032] Lazarus Group: Lazarus Group has distributed malicious payloads embedded in PNG files.
- [S1081] BADHATCH: BADHATCH has an embedded second stage DLL payload within the first stage of the malware.
- [S1149] CHIMNEYSWEEP: CHIMNEYSWEEP can extract RC4 encrypted embedded payloads for privilege escalation.
- [S1134] DEADWOOD: DEADWOOD contains an embedded, AES-encrypted payload labeled METADATA that provides configuration information for follow-on execution.
- [S0367] Emotet: Emotet has dropped an embedded executable at `%Temp%\setup.exe`. Additionally, Emotet may embed entire code into other files.
- [S1048] macOS.OSAMiner: macOS.OSAMiner has embedded Stripped Payloads within another run-only Stripped Payloads.
- [S0567] Dtrack: Dtrack has used a dropper that embeds an encrypted payload as extra data.
- [S0483] IcedID: IcedID has embedded malicious functionality in a legitimate DLL file.
- [S0457] Netwalker: Netwalker's DLL has been embedded within the PowerShell script in hex format.
- [S1135] MultiLayer Wiper: MultiLayer Wiper contains two binaries in its resources section, MultiList and MultiWip. MultiLayer Wiper drops and executes each of these items when run, then deletes them after execution.
- [S0649] SMOKEDHAM: The SMOKEDHAM source code is embedded in the dropper as an encrypted string.
- [S1145] Pikabot: Pikabot further decrypts information embedded via steganography using AES-CBC with the same 32 bit key as initial XOR operations combined with the first 16 bytes of the encrypted data as an initialization vector. Other Pikabot variants include encrypted, chunked sections of the stage 2 payload in the initial loader .text section before decrypting and assembling these during execution.
- [G1037] TA577: TA577 has used LNK files to execute embedded DLLs.

### T1027.010 - Obfuscated Files or Information: Command Obfuscation

Procedures:

- [G0143] Aquatic Panda: Aquatic Panda has encoded PowerShell commands in Base64.
- [S1085] Sardonic: Sardonic PowerShell scripts can be encrypted with RC4 and compressed using Gzip.
- [G0034] Sandworm Team: Sandworm Team has used ROT13 encoding, AES encryption and compression with the zlib library for their Python-based backdoor.
- [G1001] HEXANE: HEXANE has used Base64-encoded scripts.
- [S0428] PoetRAT: PoetRAT has `pyminifier` to obfuscate scripts.
- [G0077] Leafminer: Leafminer obfuscated scripts that were used on victim machines.
- [G0080] Cobalt Group: Cobalt Group obfuscated several scriptlets and code used on the victim’s machine, including through use of XOR and RC4.
- [S0451] LoudMiner: LoudMiner has obfuscated various scripts.
- [S0363] Empire: Empire has the ability to obfuscate commands using Invoke-Obfuscation.
- [S1022] IceApple: IceApple can use Base64 and "junk" JavaScript code to obfuscate information.
- [S0685] PowerPunch: PowerPunch can use Base64-encoded scripts.
- [G0117] Fox Kitten: Fox Kitten has base64 encoded scripts to avoid detection.
- [C0001] Frankenstein: During Frankenstein, the threat actors ran encoded commands from the command line.
- [G0037] FIN6: FIN6 has used encoded PowerShell commands.
- [C0021] C0021: During C0021, the threat actors used encoded PowerShell commands.

### T1027.011 - Obfuscated Files or Information: Fileless Storage

Procedures:

- [S0673] DarkWatchman: DarkWatchman can store configuration strings, keylogger, and output of components in the Registry.
- [S0518] PolyglotDuke: PolyglotDuke can store encrypted JSON configuration files in the Registry.
- [S0650] QakBot: QakBot can store its configuration information in a randomly named subkey under HKCU\Software\Microsoft.
- [S0263] TYPEFRAME: TYPEFRAME can install and store encrypted configuration data under the Registry key HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\ShellCompatibility\Applications\laxhost.dll and HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\PrintConfigs.
- [S0126] ComRAT: ComRAT has stored encrypted orchestrator code and payloads in the Registry.
- [S0596] ShadowPad: ShadowPad maintains a configuration block and virtual file system in the Registry.
- [S0666] Gelsemium: Gelsemium can store its components in the Registry.
- [S0022] Uroburos: Uroburos can store configuration information for the kernel driver and kernel driver loader components in an encrypted blob typically found at `HKLM:\SOFTWARE\Classes\.wav\OpenWithProgIds.`
- [S0663] SysUpdate: SysUpdate can store its encoded configuration file within Software\Classes\scConfig in either HKEY_LOCAL_MACHINE or HKEY_CURRENT_USER.
- [S0343] Exaramel for Windows: Exaramel for Windows stores the backdoor's configuration in the Registry in XML format.
- [S0531] Grandoreiro: Grandoreiro can store its configuration in the Registry at `HKCU\Software\` under frequently changing names including %USERNAME% and ToolTech-RM.
- [S0198] NETWIRE: NETWIRE can store its configuration information in the Registry under `HKCU:\Software\Netwire`.
- [S0517] Pillowmint: Pillowmint has stored a compressed payload in the Registry key HKLM\SOFTWARE\Microsoft\DRM.
- [S0668] TinyTurla: TinyTurla can save its configuration parameters in the Registry.
- [S0023] CHOPSTICK: CHOPSTICK may store RC4 encrypted configuration information in the Windows Registry.

### T1027.012 - Obfuscated Files or Information: LNK Icon Smuggling

### T1027.013 - Obfuscated Files or Information: Encrypted/Encoded File

Procedures:

- [S1052] DEADEYE: DEADEYE has encrypted its payload.
- [S0678] Torisma: Torisma has been Base64 encoded and AES encrypted.
- [S0352] OSX_OCEANLOTUS.D: OSX_OCEANLOTUS.D encrypts its strings in RSA256 and encodes them in a custom base64 scheme and XOR.
- [G0100] Inception: Inception has encrypted malware payloads dropped on victim machines with AES and RC4 encryption.
- [S0136] USBStealer: Most strings in USBStealer are encrypted using 3DES and XOR and reversed.
- [S0082] Emissary: Variants of Emissary encrypt payloads using various XOR ciphers, as well as a custom algorithm that uses the "srand" and "rand" functions.
- [S1153] Cuckoo Stealer: Cuckoo Stealer strings are XOR-encrypted.
- [S0487] Kessel: Kessel's configuration is hardcoded and RC4 encrypted within the binary.
- [S0565] Raindrop: Raindrop encrypted its payload using a simple XOR algorithm with a single-byte key.
- [S0433] Rifdoor: Rifdoor has encrypted strings with a single byte XOR algorithm.
- [G0070] Dark Caracal: Dark Caracal has obfuscated strings in Bandook by base64 encoding, and then encrypting them.
- [G0066] Elderwood: Elderwood has encrypted documents and malicious executables.
- [S1019] Shark: Shark can use encrypted and encoded files for C2 configuration.
- [S0386] Ursnif: Ursnif has used an XOR-based algorithm to encrypt Tor clients dropped to disk. Ursnif droppers have also been delivered as password-protected zip files that execute base64 encoded PowerShell commands.
- [S1150] ROADSWEEP: The ROADSWEEP binary contains RC4 encrypted embedded scripts.

### T1027.014 - Obfuscated Files or Information: Polymorphic Code

Procedures:

- [S0574] BendyBear: BendyBear changes its runtime footprint during code execution to evade signature-based defenses.

### T1027.015 - Obfuscated Files or Information: Compression

Procedures:

- [S0453] Pony: Pony attachments have been delivered via compressed archive files.
- [S0673] DarkWatchman: DarkWatchman has been delivered as compressed RAR payloads in ZIP files to victims.
- [S0499] Hancitor: Hancitor has delivered compressed payloads in ZIP files to victims.
- [S0148] RTM: RTM has been delivered to targets as various archive files including ZIP, 7-ZIP, and RAR.
- [G0021] Molerats: Molerats has delivered compressed executables within ZIP files to victims.
- [S1188] Line Runner: Line Runner uses a ZIP payload that is automatically extracted with its contents, a LUA script, executed for initial execution via CVE-2024-20359.
- [G0027] Threat Group-3390: Threat Group-3390 malware is compressed with LZNT1 compression.
- [S1050] PcShare: PcShare has been compressed with LZW algorithm.
- [S0517] Pillowmint: Pillowmint has been compressed and stored within a registry key.
- [S0466] WindTail: WindTail can be delivered as a compressed, encrypted, and encoded payload.
- [S1183] StrelaStealer: StrelaStealer has been delivered via JScript files in a ZIP archive.
- [S0559] SUNBURST: SUNBURST strings were compressed and encoded in Base64.
- [S0665] ThreatNeedle: ThreatNeedle has been compressed and obfuscated.
- [S1099] Samurai: Samurai can deliver its final payload as a compressed, encrypted and base64-encoded blob.
- [S0141] Winnti for Windows: Winnti for Windows has the ability to encrypt and compress its payload.

### T1027.016 - Obfuscated Files or Information: Junk Code Insertion

Procedures:

- [S0449] Maze: Maze has inserted large blocks of junk code, including some components to decrypt strings and other important information for later in the encryption process.
- [S0117] XTunnel: A version of XTunnel introduced in July 2015 inserted junk code into the binary in a likely attempt to obfuscate it and bypass security products.
- [S1183] StrelaStealer: StrelaStealer variants have included excessive mathematical functions padding the binary and slowing execution for anti-analysis and sandbox evasion purposes.
- [G0046] FIN7: FIN7 has used random junk code to obfuscate malware code.
- [G0047] Gamaredon Group: Gamaredon Group has obfuscated .NET executables by inserting junk code.
- [S0248] yty: yty contains junk code in its binary, likely to confuse malware analysts.
- [S0230] ZeroT: ZeroT has obfuscated DLLs and functions using dummy API calls inserted between real instructions.
- [S0453] Pony: Pony obfuscates memory flow by adding junk instructions when executing to make analysis more difficult.
- [S0370] SamSam: SamSam has used garbage code to pad some of its malware components.
- [S0477] Goopy: Goopy's decrypter have been inflated with junk code in between legitimate API functions, and also included infinite loops to avoid analysis.
- [S0612] WastedLocker: WastedLocker contains junk code to increase its entropy and hide the actual code.
- [S0137] CORESHELL: CORESHELL contains unused machine instructions in a likely attempt to hinder analysis.
- [S0182] FinFisher: FinFisher contains junk code in its functions in an effort to confuse disassembly programs.
- [G0050] APT32: APT32 includes garbage code to mislead anti-malware software and researchers.
- [G0129] Mustang Panda: Mustang Panda has used junk code within their DLL files to hinder analysis.

### T1027.017 - Obfuscated Files or Information: SVG Smuggling


### T1036.001 - Masquerading: Invalid Code Signature

Procedures:

- [S0466] WindTail: WindTail has been incompletely signed with revoked certificates.
- [S0128] BADNEWS: BADNEWS is sometimes signed with an invalid Authenticode certificate in an apparent effort to make it look more legitimate.
- [S0019] Regin: Regin stage 1 modules for 64-bit systems have been found to be signed with fake certificates masquerading as originating from Microsoft Corporation and Broadcom Corporation.
- [G0067] APT37: APT37 has signed its malware with an invalid digital certificates listed as “Tencent Technology (Shenzhen) Company Limited.”
- [G0112] Windshift: Windshift has used revoked certificates to sign malware.
- [S0198] NETWIRE: The NETWIRE client has been signed by fake and invalid digital certificates.
- [S1050] PcShare: PcShare has used an invalid certificate in attempt to appear legitimate.
- [S0666] Gelsemium: Gelsemium has used unverified signatures on malicious DLLs.

### T1036.002 - Masquerading: Right-to-Left Override

Procedures:

- [G0137] Ferocious Kitten: Ferocious Kitten has used right-to-left override to reverse executables’ names to make them appear to have different file extensions, rather than their real ones.
- [G0098] BlackTech: BlackTech has used right-to-left-override to obfuscate the filenames of malicious e-mail attachments.
- [G0004] Ke3chang: Ke3chang has used the right-to-left override character in spearphishing attachment names to trick targets into executing .scr and .exe files.
- [G0029] Scarlet Mimic: Scarlet Mimic has used the left-to-right override character in self-extracting RAR archive spearphishing attachment file names.
- [G0060] BRONZE BUTLER: BRONZE BUTLER has used Right-to-Left Override to deceive victims into executing several strains of malware.

### T1036.003 - Masquerading: Rename Legitimate Utilities

Procedures:

- [S1183] StrelaStealer: StrelaStealer has used a renamed, legitimate `msinfo32.exe` executable to sideload the StrelaStealer payload during initial installation.
- [G0045] menuPass: menuPass has renamed certutil and moved it to a different location on the system to avoid detection based on use of the tool.
- [G0032] Lazarus Group: Lazarus Group has renamed system utilities such as wscript.exe and mshta.exe.
- [S1111] DarkGate: DarkGate executes a Windows Batch script during installation that creases a randomly-named directory in the C:\\ root directory that copies and renames the legitimate Windows curl command to this new location.
- [G1034] Daggerfly: Daggerfly used a renamed version of rundll32.exe, such as "dbengin.exe" located in the `ProgramData\Microsoft\PlayReady` directory, to proxy malicious DLL execution.
- [G0050] APT32: APT32 has moved and renamed pubprn.vbs to a .txt file to avoid detection.
- [G0082] APT38: APT38 has renamed system utilities, such as `rundll32.exe` and `mshta.exe`, to avoid detection.
- [S0046] CozyCar: The CozyCar dropper has masqueraded a copy of the infected system's rundll32.exe executable that was moved to the malware's install directory and renamed according to a predefined configuration file.
- [S1020] Kevin: Kevin has renamed an image of `cmd.exe` with a random name followed by a `.tmpl` extension.
- [G0093] GALLIUM: GALLIUM used a renamed cmd.exe file to evade detection.

### T1036.004 - Masquerading: Masquerade Task or Service

Procedures:

- [S1033] DCSrv: DCSrv has masqueraded its service as a legitimate svchost.exe process.
- [S0013] PlugX: In one instance, menuPass added PlugX as a service with a display name of "Corel Writing Tools Utility."
- [G0143] Aquatic Panda: Aquatic Panda created new, malicious services using names such as Windows User Service to attempt to blend in with legitimate items on victim systems.
- [S1064] SVCReady: SVCReady has named a task `RecoveryExTask` as part of its persistence activity.
- [C0034] 2022 Ukraine Electric Power Attack: During the 2022 Ukraine Electric Power Attack, Sandworm Team leveraged Systemd service units to masquerade GOGETTER malware as legitimate or seemingly legitimate services.
- [C0017] C0017: During C0017, APT41 used `SCHTASKS /Change` to modify legitimate scheduled tasks to run malicious code.
- [S0438] Attor: Attor's dispatcher disguises itself as a legitimate task (i.e., the task name and description appear legitimate).
- [S0449] Maze: Maze operators have created scheduled tasks masquerading as "Windows Update Security", "Windows Update Security Patches", and "Google Chrome Security Update" designed to launch the ransomware.
- [S0495] RDAT: RDAT has used Windows Video Service as a name for malicious services.
- [G0094] Kimsuky: Kimsuky has disguised services to appear as benign software or related to operating system functions.
- [G0008] Carbanak: Carbanak has copied legitimate service names to use for malicious services.
- [S1042] SUGARDUMP: SUGARDUMP's scheduled task has been named `MicrosoftInternetExplorerCrashRepoeterTaskMachineUA` or `MicrosoftEdgeCrashRepoeterTaskMachineUA`, depending on the Windows OS version.
- [S0223] POWERSTATS: POWERSTATS has created a scheduled task named "MicrosoftEdge" to establish persistence.
- [S0410] Fysbis: Fysbis has masqueraded as the rsyncd and dbus-inotifier services.
- [S0688] Meteor: Meteor has been disguised as the Windows Power Efficiency Diagnostics report tool.

### T1036.005 - Masquerading: Match Legitimate Resource Name or Location

Procedures:

- [S0083] Misdat: Misdat saves itself as a file named `msdtc.exe`, which is also the name of the legitimate Microsoft Distributed Transaction Coordinator service binary.
- [S0629] RainyDay: RainyDay has used names to mimic legitimate software including "vmtoolsd.exe" to spoof Vmtools.
- [G0139] TeamTNT: TeamTNT has replaced .dockerd and .dockerenv with their own scripts and cryptocurrency mining software.
- [S0459] MechaFlounder: MechaFlounder has been downloaded as a file named lsass.exe, which matches the legitimate Windows file.
- [S1050] PcShare: PcShare has been named `wuauclt.exe` to appear as the legitimate Windows Update AutoUpdate Client.
- [S0533] SLOTHFULMEDIA: SLOTHFULMEDIA has mimicked the names of known executables, such as mediaplayer.exe.
- [S0081] Elise: If installing itself as a service fails, Elise instead writes itself as a file named svchost.exe saved in %APPDATA%\Microsoft\Network.
- [S0072] OwaAuth: OwaAuth uses the filename owaauth.dll, which is a legitimate file that normally resides in %ProgramFiles%\Microsoft\Exchange Server\ClientAccess\Owa\Auth\; the malicious file by the same name is saved in %ProgramFiles%\Microsoft\Exchange Server\ClientAccess\Owa\bin\.
- [C0025] 2016 Ukraine Electric Power Attack: During the 2016 Ukraine Electric Power Attack, DLLs and EXEs with filenames associated with common electric power sector protocols were used to masquerade files.
- [S0482] Bundlore: Bundlore has disguised a malicious .app file as a Flash Player update.
- [S0085] S-Type: S-Type may save itself as a file named `msdtc.exe`, which is also the name of the legitimate Microsoft Distributed Transaction Coordinator service binary.
- [S1014] DanBot: DanBot files have been named `UltraVNC.exe` and `WINVNC.exe` to appear as legitimate VNC tools.
- [S0687] Cyclops Blink: Cyclops Blink can rename its running process to [kworker:0/1] to masquerade as a Linux kernel thread. Cyclops Blink has also named RC scripts used for persistence after WatchGuard artifacts.
- [G0047] Gamaredon Group: Gamaredon Group has used legitimate process names to hide malware including svchosst.
- [S0668] TinyTurla: TinyTurla has been deployed as `w64time.dll` to appear legitimate.

### T1036.006 - Masquerading: Space after Filename

Procedures:

- [G0082] APT38: APT38 has put several spaces before a file extension to avoid detection and suspicion.
- [S0276] Keydnap: Keydnap puts a space after a false .jpg extension so that execution actually goes through the Terminal.app program.

### T1036.007 - Masquerading: Double File Extension

Procedures:

- [S1111] DarkGate: DarkGate masquerades malicious LNK files as PDF objects using the double extension .pdf.lnk.
- [S0534] Bazar: The Bazar loader has used dual-extension executable files such as PreviewReport.DOC.exe.
- [G0129] Mustang Panda: Mustang Panda has used an additional filename extension to hide the true file type.
- [S1015] Milan: Milan has used an executable named `companycatalog.exe.config` to appear benign.

### T1036.008 - Masquerading: Masquerade File Type

Procedures:

- [C0025] 2016 Ukraine Electric Power Attack: During the 2016 Ukraine Electric Power Attack, Sandworm Team masqueraded executables as `.txt` files.
- [C0022] Operation Dream Job: During Operation Dream Job, Lazarus Group disguised malicious template files as JPEG files to avoid detection.
- [G1017] Volt Typhoon: Volt Typhoon has appended copies of the ntds.dit database with a .gif file extension.
- [S1190] Kapeka: Kapeka masquerades as a Microsoft Word Add-In file, with the extension `.wll`, but is a malicious DLL file.
- [G1043] BlackByte: BlackByte masqueraded configuration files containing encryption keys as PNG files.
- [S0650] QakBot: The QakBot payload has been disguised as a PNG file and hidden within LNK files using a Microsoft File Explorer icon.
- [S1130] Raspberry Robin: Raspberry Robin has historically been delivered via infected USB drives containing a malicious LNK object masquerading as a legitimate folder.
- [S1074] ANDROMEDA: ANDROMEDA has been delivered through a LNK file disguised as a folder.
- [S1063] Brute Ratel C4: Brute Ratel C4 has used Microsoft Word icons to hide malicious LNK files.
- [S1213] Lumma Stealer: Lumma Stealer has used payloads that resemble benign file extensions such as .mp3, .accdb, and .pub, though the files contained malicious JavaScript content.
- [S1053] AvosLocker: AvosLocker has been disguised as a .jpg file.
- [S1182] MagicRAT: MagicRAT can download additional executable payloads that masquerade as GIF files.
- [S0352] OSX_OCEANLOTUS.D: OSX_OCEANLOTUS.D has disguised it's true file structure as an application bundle by adding special characters to the filename and using the icon for legitimate Word documents.
- [S1183] StrelaStealer: StrelaStealer has been distributed as a DLL/HTML polyglot file.

### T1036.009 - Masquerading: Break Process Trees

Procedures:

- [S1161] BPFDoor: After initial execution, BPFDoor forks itself and runs the fork with the `--init` flag, which allows it to execute secondary clean up operations. The parent process terminates leaving the forked process to be inherited by the legitimate process init.

### T1036.010 - Masquerading: Masquerade Account Name

Procedures:

- [S0143] Flame: Flame can create backdoor accounts with login `HelpAssistant` on domain connected systems if appropriate rights are available.
- [G1046] Storm-1811: Storm-1811 has created Microsoft Teams accounts that spoof IT support and helpdesk members for use in application and voice phishing.
- [G0059] Magic Hound: Magic Hound has created local accounts named `help` and `DefaultAccount` on compromised machines.
- [G0035] Dragonfly: Dragonfly has created accounts disguised as legitimate backup and service accounts as well as an email administration account.
- [S0382] ServHelper: ServHelper has created a new user named `supportaccount`.
- [C0025] 2016 Ukraine Electric Power Attack: During the 2016 Ukraine Electric Power Attack, Sandworm Team created two new accounts, “admin” and “система” (System).
- [G0022] APT3: APT3 has been known to create or enable accounts, such as support_388945a0.

### T1036.011 - Masquerading: Overwrite Process Arguments

Procedures:

- [S1161] BPFDoor: BPFDoor overwrites the `argv[0]` value used by the Linux `/proc` filesystem to determine the command line and command name to display for each process. BPFDoor selects a name from 10 hardcoded names that resemble Linux system daemons, such as; `/sbin/udevd -d`, `dbus-daemon --system`, `avahi-daemon: chroot helper`, `/sbin/auditd -n`, and `/usr/lib/systemd/systemd-journald`.


### T1055.001 - Process Injection: Dynamic-link Library Injection

Procedures:

- [S1027] Heyoka Backdoor: Heyoka Backdoor can inject a DLL into rundll32.exe for execution.
- [S1018] Saint Bot: Saint Bot has injected its DLL component into `EhStorAurhn.exe`.
- [S0082] Emissary: Emissary injects its DLL file into a newly spawned Internet Explorer process.
- [S0125] Remsec: Remsec can perform DLL injection.
- [S1066] DarkTortilla: DarkTortilla can use a .NET-based DLL named `RunPe6` for process injection.
- [S0089] BlackEnergy: BlackEnergy injects its DLL component into svchost.exe.
- [G0010] Turla: Turla has used Metasploit to perform reflective DLL injection in order to escalate privileges.
- [S0613] PS1: PS1 can inject its payload DLL Into memory.
- [S0250] Koadic: Koadic can perform process injection by using a reflective DLL.
- [S0055] RARSTONE: After decrypting itself in memory, RARSTONE downloads a DLL file from its C2 server and loads it in the memory space of a hidden Internet Explorer process. This “downloaded” file is actually not dropped onto the system.
- [S0154] Cobalt Strike: Cobalt Strike has the ability to load DLLs via reflective injection.
- [S0461] SDBbot: SDBbot has the ability to inject a downloaded DLL into a newly created rundll32.exe process.
- [S0455] Metamorfo: Metamorfo has injected a malicious DLL into the Windows Media Player process (wmplayer.exe).
- [S0126] ComRAT: ComRAT has injected its orchestrator DLL into explorer.exe. ComRAT has also injected its communications module into the victim's default browser to make C2 connections appear less suspicious as all network connections will be initiated by the browser process.
- [S0273] Socksbot: Socksbot creates a suspended svchost process and injects its DLL into it.

### T1055.002 - Process Injection: Portable Executable Injection

Procedures:

- [S1063] Brute Ratel C4: Brute Ratel C4 has injected Latrodectus into the Explorer.exe process on comrpomised hosts.
- [S0260] InvisiMole: InvisiMole can inject its backdoor as a portable executable into a target process.
- [S0030] Carbanak: Carbanak downloads an executable and injects it directly into a new process.
- [G0106] Rocke: Rocke's miner, "TermsHost.exe", evaded defenses by injecting itself into Windows processes, including Notepad.exe.
- [G0078] Gorgon Group: Gorgon Group malware can download a remote access tool, ShiftyBug, and inject into another process.
- [S0681] Lizar: Lizar can execute PE files in the address space of the specified process.
- [S1138] Gootloader: Gootloader can use its own PE loader to execute payloads in memory.
- [S0342] GreyEnergy: GreyEnergy has a module to inject a PE binary into a remote process.
- [S1158] DUSTPAN: DUSTPAN can inject its decrypted payload into another process.
- [S1145] Pikabot: Pikabot, following payload decryption, creates a process hard-coded into the dropped (e.g., WerFault.exe) and injects the decrypted core modules into it.
- [S0330] Zeus Panda: Zeus Panda checks processes on the system and if they meet the necessary requirements, it injects into that process.

### T1055.003 - Process Injection: Thread Execution Hijacking

Procedures:

- [S1145] Pikabot: Pikabot can create a suspended instance of a legitimate process (e.g., ctfmon.exe), allocate memory within the suspended process corresponding to Pikabot's core module, then redirect execution flow via `SetContextThread` API so that when the thread resumes the Pikabot core module is executed.
- [S0579] Waterbear: Waterbear can use thread injection to inject shellcode into the process of security software.
- [S0168] Gazer: Gazer performs thread execution hijacking to inject its orchestrator into a running thread from a remote process.
- [S0094] Trojan.Karagany: Trojan.Karagany can inject a suspended thread of its own process into a new process and initiate via the ResumeThread API.

### T1055.004 - Process Injection: Asynchronous Procedure Call

Procedures:

- [S0199] TURNEDUP: TURNEDUP is capable of injecting code into the APC queue of a created Rundll32 process as part of an "Early Bird injection."
- [S0517] Pillowmint: Pillowmint has used the NtQueueApcThread syscall to inject code into svchost.exe.
- [S0260] InvisiMole: InvisiMole can inject its code into a trusted process via the APC queue.
- [S1039] Bumblebee: Bumblebee can use asynchronous procedure call (APC) injection to execute commands received from C2.
- [S1018] Saint Bot: Saint Bot has written its payload into a newly-created `EhStorAuthn.exe` process using `ZwWriteVirtualMemory` and executed it using `NtQueueApcThread` and `ZwAlertResumeThread`.
- [S0484] Carberp: Carberp has queued an APC routine to explorer.exe by calling ZwQueueApcThread.
- [S0483] IcedID: IcedID has used ZwQueueApcThread to inject itself into remote processes.
- [S1207] XLoader: XLoader injects code into the APC queue using `NtQueueApcThread` API.
- [S1081] BADHATCH: BADHATCH can inject itself into a new `svchost.exe -k netsvcs` process using the asynchronous procedure call (APC) queue.
- [G0061] FIN8: FIN8 has injected malicious code into a new svchost.exe process.
- [S0438] Attor: Attor performs the injection by attaching its code into the APC queue using NtQueueApcThread API.
- [S1085] Sardonic: Sardonic can use the `QueueUserAPC` API to execute shellcode on a compromised machine.

### T1055.005 - Process Injection: Thread Local Storage

Procedures:

- [S0386] Ursnif: Ursnif has injected code into target processes via thread local storage callbacks.

### T1055.008 - Process Injection: Ptrace System Calls

Procedures:

- [S1109] PACEMAKER: PACEMAKER can use PTRACE to attach to a targeted process to read process memory.

### T1055.009 - Process Injection: Proc Memory

Procedures:

- [C0035] KV Botnet Activity: KV Botnet Activity final payload installation includes mounting and binding to the \/proc\/ filepath on the victim system to enable subsequent operation in memory while also removing on-disk artifacts.

### T1055.011 - Process Injection: Extra Window Memory Injection

Procedures:

- [S0091] Epic: Epic has overwritten the function pointer in the extra window memory of Explorer's Shell_TrayWnd in order to execute malicious code in the context of the explorer.exe process.
- [S0177] Power Loader: Power Loader overwrites Explorer’s Shell_TrayWnd extra window memory to redirect execution to a NTDLL function that is abused to assemble and execute a return-oriented programming (ROP) chain and create a malicious thread within Explorer.exe.

### T1055.012 - Process Injection: Process Hollowing

Procedures:

- [G0078] Gorgon Group: Gorgon Group malware can use process hollowing to inject one of its trojans into another process.
- [S0483] IcedID: IcedID can inject a Cobalt Strike beacon into cmd.exe via process hallowing.
- [S1207] XLoader: XLoader uses process hollowing by injecting itself into the `explorer.exe` process and other files ithin the Windows `SysWOW64` directory.
- [G0027] Threat Group-3390: A Threat Group-3390 tool can spawn `svchost.exe` and inject the payload into that process.
- [S0662] RCSession: RCSession can launch itself from a hollowed svchost.exe process.
- [S0354] Denis: Denis performed process hollowing through the API calls CreateRemoteThread, ResumeThread, and Wow64SetThreadContext.
- [S1065] Woody RAT: Woody RAT can create a suspended notepad process and write shellcode to delete a file into the suspended process using `NtWriteVirtualMemory`.
- [S0344] Azorult: Azorult can decrypt the payload into memory, create a new suspended process of itself, then inject a decrypted payload to the new process and resume new process execution.
- [G0040] Patchwork: A Patchwork payload uses process hollowing to hide the UAC bypass vulnerability exploitation inside svchost.exe.
- [S0650] QakBot: QakBot can use process hollowing to execute its main payload.
- [S0154] Cobalt Strike: Cobalt Strike can use process hollowing for execution.
- [S0447] Lokibot: Lokibot has used process hollowing to inject itself into legitimate Windows process.
- [S1086] Snip3: Snip3 can use RunPE to execute malicious payloads within a hollowed Windows process.
- [S0234] Bandook: Bandook has been launched by starting iexplore.exe and replacing it with Bandook's payload.
- [S1213] Lumma Stealer: Lumma Stealer has used process hollowing leveraging a legitimate program such as “BitLockerToGo.exe” to inject a malicious payload.

### T1055.013 - Process Injection: Process Doppelgänging

Procedures:

- [S0242] SynAck: SynAck abuses NTFS transactions to launch and conceal malicious processes.
- [S0534] Bazar: Bazar can inject into a target process using process doppelgänging.
- [G0077] Leafminer: Leafminer has used Process Doppelgänging to evade security software while deploying tools on compromised systems.

### T1055.014 - Process Injection: VDSO Hijacking

### T1055.015 - Process Injection: ListPlanting

Procedures:

- [S0260] InvisiMole: InvisiMole has used ListPlanting to inject code into a trusted process.


### T1070.001 - Indicator Removal: Clear Windows Event Logs

Procedures:

- [S1202] LockBit 3.0: LockBit 3.0 can delete log files on targeted systems.
- [S0688] Meteor: Meteor can use Wevtutil to remove Security, System and Application Event Viewer logs.
- [G0061] FIN8: FIN8 has cleared logs during post compromise cleanup activities.
- [S0242] SynAck: SynAck clears event logs.
- [S0368] NotPetya: NotPetya uses wevtutil to clear the Windows event logs.
- [S1212] RansomHub: RansomHub can delete events from the Security, System, and Application logs.
- [S1178] ShrinkLocker: ShrinkLocker calls Wevtutil to clear the Windows PowerShell and Microsoft-Windows-Powershell/Operational logs.
- [S1060] Mafalda: Mafalda can delete Windows Event logs by invoking the `OpenEventLogW` and `ClearEventLogW` functions.
- [G1017] Volt Typhoon: Volt Typhoon has selectively cleared Windows Event Logs, system logs, and other technical artifacts to remove evidence of intrusion activity.
- [S0645] Wevtutil: Wevtutil can be used to clear system and security event logs from the system.
- [G0114] Chimera: Chimera has cleared event logs on compromised hosts.
- [G0143] Aquatic Panda: Aquatic Panda clears Windows Event Logs following activity to evade defenses.
- [G0007] APT28: APT28 has cleared event logs, including by using the commands wevtutil cl System and wevtutil cl Security.
- [G0096] APT41: APT41 attempted to remove evidence of some of its activity by clearing Windows security and system events.
- [S0532] Lucifer: Lucifer can clear and remove event logs.

### T1070.002 - Indicator Removal: Clear Linux or Mac System Logs

Procedures:

- [S1164] UPSTYLE: UPSTYLE clears error logs after reading embedded commands for execution.
- [S1206] JumbledPath: JumbledPath can clear logs on all devices used along its connection path to compromised network infrastructure.
- [G1041] Sea Turtle: Sea Turtle has overwritten Linux system logs and unsets the Bash history file (effectively removing logging) during intrusions.
- [S1016] MacMa: MacMa can clear possible malware traces such as application logs.
- [G0139] TeamTNT: TeamTNT has removed system logs from /var/log/syslog.
- [G1045] Salt Typhoon: Salt Typhoon has cleared logs including .bash_history, auth.log, lastlog, wtmp, and btmp.
- [G0106] Rocke: Rocke has cleared log files within the /var/log/ folder.
- [S0279] Proton: Proton removes logs from /var/logs and /Library/logs.

### T1070.003 - Indicator Removal: Clear Command History

Procedures:

- [G0143] Aquatic Panda: Aquatic Panda cleared command history in Linux environments to remove traces of activity after operations.
- [S1203] J-magic: J-magic can overwrite previously executed command line arguments.
- [G0139] TeamTNT: TeamTNT has cleared command history with history -c.
- [S0641] Kobalos: Kobalos can remove all command history on compromised hosts.
- [S0601] Hildegard: Hildegard has used history -c to clear script shell logs.
- [G0045] menuPass: menuPass has used Wevtutil to remove PowerShell execution logs.
- [G0059] Magic Hound: Magic Hound has removed mailbox export requests from compromised Exchange servers.
- [G0032] Lazarus Group: Lazarus Group has routinely deleted log files on a compromised router, including automatic log deletion through the use of the logrotate utility.
- [G1023] APT5: APT5 has cleared the command history on targeted ESXi servers.
- [G0096] APT41: APT41 attempted to remove evidence of some of its activity by deleting Bash histories.

### T1070.004 - Indicator Removal: File Deletion

Procedures:

- [S0164] TDTESS: TDTESS creates then deletes log files during installation of itself as a service.
- [S0395] LightNeuron: LightNeuron has a function to delete files.
- [S1150] ROADSWEEP: ROADSWEEP can use embedded scripts to remove itself from the infected host.
- [S0654] ProLock: ProLock can remove files containing its payload after they are executed.
- [G0143] Aquatic Panda: Aquatic Panda has deleted malicious executables from compromised machines.
- [S1212] RansomHub: RansomHub has the ability to self-delete.
- [S0354] Denis: Denis has a command to delete files from the victim’s machine.
- [S0448] Rising Sun: Rising Sun can delete files and artifacts it creates.
- [G0051] FIN10: FIN10 has used batch scripts and scheduled tasks to delete critical system files.
- [S0593] ECCENTRICBANDWAGON: ECCENTRICBANDWAGON can delete log files generated from the malware stored at C:\windows\temp\tmp0207.
- [S0370] SamSam: SamSam has been seen deleting its own files and payloads to make analysis of the attack more difficult.
- [S0390] SQLRat: SQLRat has used been observed deleting scripts once used.
- [G0045] menuPass: A menuPass macro deletes files after it has decoded and decompressed them.
- [S1027] Heyoka Backdoor: Heyoka Backdoor has the ability to delete folders and files from a targeted system.
- [G0060] BRONZE BUTLER: The BRONZE BUTLER uploader or malware the uploader uses command to delete the RAR archives after they have been exfiltrated.

### T1070.005 - Indicator Removal: Network Share Connection Removal

Procedures:

- [S0039] Net: The net use \\system\share /delete command can be used in Net to remove an established connection to a network share.
- [S0400] RobbinHood: RobbinHood disconnects all network shares from the computer with the command net use * /DELETE /Y.
- [S1159] DUSTTRAP: DUSTTRAP can remove network shares from infected systems.
- [S0260] InvisiMole: InvisiMole can disconnect previously connected remote drives.
- [G0027] Threat Group-3390: Threat Group-3390 has detached network shares after exfiltrating files, likely to evade detection.

### T1070.006 - Indicator Removal: Timestomp

Procedures:

- [S0586] TAINTEDSCRIBE: TAINTEDSCRIBE can change the timestamp of specified filenames.
- [G0007] APT28: APT28 has performed timestomping on victim files.
- [S0687] Cyclops Blink: Cyclops Blink has the ability to use the Linux API function `utime` to change the timestamps of modified firmware update images.
- [G1023] APT5: APT5 has modified file timestamps.
- [S0168] Gazer: For early Gazer versions, the compilation timestamp was faked.
- [S0603] Stuxnet: Stuxnet extracts and writes driver files that match the times of other legitimate files.
- [S0239] Bankshot: Bankshot modifies the time of a file as specified by the control server.
- [S0181] FALLCHILL: FALLCHILL can modify file or directory timestamps.
- [S1181] BlackByte 2.0 Ransomware: BlackByte 2.0 Ransomware can timestomp files for defense evasion and anti-forensics purposes.
- [S0072] OwaAuth: OwaAuth has a command to timestop a file or directory.
- [C0029] Cutting Edge: During Cutting Edge, threat actors changed timestamps of multiple files on compromised Ivanti Secure Connect VPNs to conceal malicious activity.
- [S1090] NightClub: NightClub can modify the Creation, Access, and Write timestamps for malicious DLLs to match those of the genuine Windows DLL user32.dll.
- [S0136] USBStealer: USBStealer sets the timestamps of its dropper files to the last-access and last-write timestamps of a standard Windows library chosen on the system.
- [S0570] BitPaymer: BitPaymer can modify the timestamp of an executable so that it can be identified and restored by the decryption tool.
- [S0021] Derusbi: The Derusbi malware supports timestomping.

### T1070.007 - Indicator Removal: Clear Network Connection History and Configurations

Procedures:

- [S0559] SUNBURST: SUNBURST also removed the firewall rules it created during execution.
- [G1017] Volt Typhoon: Volt Typhoon has inspected server logs to remove their IPs.

### T1070.008 - Indicator Removal: Clear Mailbox Data

Procedures:

- [S1142] LunarMail: LunarMail can set the `PR_DELETE_AFTER_SUBMIT` flag to delete messages sent for data exfiltration.
- [G1044] APT42: APT42 has deleted login notification emails and has cleared the Sent folder to cover their tracks.
- [S0477] Goopy: Goopy has the ability to delete emails used for C2 once the content has been copied.
- [C0024] SolarWinds Compromise: During the SolarWinds Compromise, APT29 removed evidence of email export requests using `Remove-MailboxExportRequest`.

### T1070.009 - Indicator Removal: Clear Persistence

Procedures:

- [S0559] SUNBURST: SUNBURST removed IFEO registry values to clean up traces of persistence.
- [S0500] MCMD: MCMD has the ability to remove set Registry Keys, including those used for persistence.
- [S0534] Bazar: Bazar's loader can delete scheduled tasks created by a previous instance of the malware.
- [S1132] IPsec Helper: IPsec Helper can delete various service traces related to persistent execution when commanded.
- [S0517] Pillowmint: Pillowmint can uninstall the malicious service from an infected machine.
- [S0083] Misdat: Misdat is capable of deleting Registry keys used for persistence.
- [S1190] Kapeka: Kapeka will clear registry values used for persistent configuration storage when uninstalled.
- [S0085] S-Type: S-Type has deleted accounts it has created.
- [S0385] njRAT: njRAT is capable of manipulating and deleting registry keys, including those used for persistence.
- [S0669] KOCTOPUS: KOCTOPUS can delete created registry keys used for persistence as part of its cleanup procedure.
- [S0632] GrimAgent: GrimAgent can delete previously created tasks on a compromised host.
- [S1130] Raspberry Robin: Raspberry Robin uses a RunOnce Registry key for persistence, where the key is removed after its use on reboot then re-added by the malware after it resumes execution.
- [S0148] RTM: RTM has the ability to remove Registry entries that it created for persistence.

### T1070.010 - Indicator Removal: Relocate Malware


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


### T1127.001 - Trusted Developer Utilities Proxy Execution: MSBuild

Procedures:

- [S0013] PlugX: A version of PlugX loads as shellcode within a .NET Framework project using msbuild.exe, presumably to bypass application control techniques.
- [S0363] Empire: Empire can use built-in modules to abuse trusted utilities like MSBuild.exe.
- [C0001] Frankenstein: During Frankenstein, the threat actors used MSbuild to execute an actor-created file.

### T1127.002 - Trusted Developer Utilities Proxy Execution: ClickOnce

### T1127.003 - Trusted Developer Utilities Proxy Execution: JamPlus


### T1134.001 - Access Token Manipulation: Token Impersonation/Theft

Procedures:

- [S0182] FinFisher: FinFisher uses token manipulation with NtFilterToken as part of UAC bypass.
- [S0367] Emotet: Emotet has the ability to duplicate the user’s token. For example, Emotet may use a variant of Google’s ProtoBuf to send messages that specify how code will be executed.
- [S0603] Stuxnet: Stuxnet attempts to impersonate an anonymous token to enumerate bindings in the service control manager.
- [C0038] HomeLand Justice: During HomeLand Justice, threat actors used custom tooling to acquire tokens using `ImpersonateLoggedOnUser/SetThreadToken`.
- [S0154] Cobalt Strike: Cobalt Strike can steal access tokens from exiting processes.
- [S1011] Tarrask: Tarrask leverages token theft to obtain `lsass.exe` security permissions.
- [S0692] SILENTTRINITY: SILENTTRINITY can find a process owned by a specific user and impersonate the associated token.
- [S0570] BitPaymer: BitPaymer can use the tokens of users to create processes on infected systems.
- [S0140] Shamoon: Shamoon can impersonate tokens using LogonUser, ImpersonateLoggedOnUser, and ImpersonateNamedPipeClient.
- [S0439] Okrum: Okrum can impersonate a logged-on user's security context using a call to the ImpersonateLoggedOnUser API.
- [S0456] Aria-body: Aria-body has the ability to duplicate a token from ntprint.exe.
- [G0007] APT28: APT28 has used CVE-2015-1701 to access the SYSTEM token and copy it into the current process as part of privilege escalation.
- [S0496] REvil: REvil can obtain the token from the user that launched the explorer.exe process to avoid affecting the desktop of the SYSTEM user.
- [S0192] Pupy: Pupy can obtain a list of SIDs and provide the option for selecting process tokens to impersonate.
- [S1081] BADHATCH: BADHATCH can impersonate a `lsass.exe` or `vmtoolsd.exe` token.

### T1134.002 - Access Token Manipulation: Create Process with Token

Procedures:

- [S0344] Azorult: Azorult can call WTSQueryUserToken and CreateProcessAsUser to start a new process with local system privileges.
- [G0010] Turla: Turla RPC backdoors can impersonate or steal process tokens before executing commands.
- [S0501] PipeMon: PipeMon can attempt to gain administrative privileges using token impersonation.
- [G0032] Lazarus Group: Lazarus Group keylogger KiloAlfa obtains user tokens from interactive sessions to execute itself with API call CreateProcessAsUserA under that user's context.
- [S0378] PoshC2: PoshC2 can use Invoke-RunAs to make tokens.
- [S0456] Aria-body: Aria-body has the ability to execute a process using runas.
- [S0496] REvil: REvil can launch an instance of itself with administrative rights using runas.
- [S0412] ZxShell: ZxShell has a command called RunAs, which creates a new process as another user or process context.
- [S0689] WhisperGate: The WhisperGate third stage can use the AdvancedRun.exe tool to execute commands in the context of the Windows TrustedInstaller group via `%TEMP%\AdvancedRun.exe" /EXEFilename "C:\Windows\System32\sc.exe" /WindowState 0 /CommandLine "stop WinDefend" /StartDirectory "" /RunAs 8 /Run`.
- [S0356] KONNI: KONNI has duplicated the token of a high integrity process to spawn an instance of cmd.exe under an impersonated user.
- [S0239] Bankshot: Bankshot grabs a user token using WTSQueryUserToken and then creates a process by impersonating a logged-on user.
- [S0363] Empire: Empire can use Invoke-RunAs to make tokens.

### T1134.003 - Access Token Manipulation: Make and Impersonate Token

Procedures:

- [S1060] Mafalda: Mafalda can create a token for a different user.
- [G1043] BlackByte: BlackByte constructed a valid authentication token following Microsoft Exchange exploitation to allow for follow-on privileged command execution.
- [G1016] FIN13: FIN13 has utilized tools such as Incognito V2 for token manipulation and impersonation.
- [S0692] SILENTTRINITY: SILENTTRINITY can make tokens from known credentials.
- [S0154] Cobalt Strike: Cobalt Strike can make tokens from known credentials.

### T1134.004 - Access Token Manipulation: Parent PID Spoofing

Procedures:

- [S0356] KONNI: KONNI has used parent PID spoofing to spawn a new `cmd` process using `CreateProcessW` and a handle to `Taskmgr.exe`.
- [S0154] Cobalt Strike: Cobalt Strike can spawn processes with alternate PPIDs.
- [S0501] PipeMon: PipeMon can use parent PID spoofing to elevate privileges.
- [S1111] DarkGate: DarkGate relies on parent PID spoofing as part of its "rootkit-like" functionality to evade detection via Task Manager or Process Explorer.

### T1134.005 - Access Token Manipulation: SID-History Injection

Procedures:

- [S0002] Mimikatz: Mimikatz's MISC::AddSid module can append any SID or user/group account to a user's SID-History. Mimikatz also utilizes SID-History Injection to expand the scope of other components such as generated Kerberos Golden Tickets and DCSync beyond a single domain.
- [S0363] Empire: Empire can add a SID-History to a user if on a domain controller.


### T1140 - Deobfuscate/Decode Files or Information

Procedures:

- [C0044] Juicy Mix: During Juicy Mix, OilRig used a script to concatenate and deobfuscate encoded strings in Mango.
- [S0230] ZeroT: ZeroT shellcode decrypts and decompresses its RC4-encrypted payload.
- [S0584] AppleJeus: AppleJeus has decoded files received from a C2.
- [S1028] Action RAT: Action RAT can use Base64 to decode actor-controlled C2 server communications.
- [G0060] BRONZE BUTLER: BRONZE BUTLER downloads encoded payloads and decodes them on the victim.
- [S0669] KOCTOPUS: KOCTOPUS has deobfuscated itself before executing its commands.
- [S1086] Snip3: Snip3 can decode its second-stage PowerShell script prior to execution.
- [S0574] BendyBear: BendyBear has decrypted function blocks using a XOR key during runtime to evade detection.
- [S0513] LiteDuke: LiteDuke has the ability to decrypt and decode multiple layers of obfuscation.
- [S0598] P.A.S. Webshell: P.A.S. Webshell can use a decryption mechanism to process a user supplied password and allow execution.
- [S0356] KONNI: KONNI has used certutil to download and decode base64 encoded strings and has also devoted a custom section to performing all the components of the deobfuscation process.
- [G0010] Turla: Turla has used a custom decryption routine, which pulls key and salt values from other artifacts such as a WMI filter or PowerShell Profile, to decode encrypted PowerShell payloads.
- [S0409] Machete: Machete’s downloaded data is decrypted using AES.
- [S0415] BOOSTWRITE: BOOSTWRITE has used a a 32-byte long multi-XOR key to decode data inside its payload.
- [S1202] LockBit 3.0: The LockBit 3.0 payload is decrypted at runtime.


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


### T1202 - Indirect Command Execution

Procedures:

- [G0032] Lazarus Group: Lazarus Group persistence mechanisms have used forfiles.exe to execute .htm files.
- [S0193] Forfiles: Forfiles can be used to subvert controls and possibly conceal command execution by not directly invoking cmd.
- [S0379] Revenge RAT: Revenge RAT uses the Forfiles utility to execute commands on the system.
- [G1039] RedCurl: RedCurl has used pcalua.exe to obfuscate binary execution and remote connections.


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


### T1207 - Rogue Domain Controller

Procedures:

- [S0002] Mimikatz: Mimikatz’s LSADUMP::DCShadow module can be used to make AD updates by temporarily setting a computer to be a DC.


### T1211 - Exploitation for Defense Evasion

Procedures:

- [G1047] Velvet Ant: Velvet Ant exploited CVE-2024-20399 in Cisco Switches to which the threat actor was already able to authenticate in order to escape the NX-OS command line interface and gain access to the underlying operating system for arbitrary command execution.
- [G0007] APT28: APT28 has used CVE-2015-4902 to bypass security features.


### T1216.001 - System Script Proxy Execution: PubPrn

Procedures:

- [G0050] APT32: APT32 has used PubPrn.vbs within execution scripts to execute malware, possibly bypassing defenses.

### T1216.002 - System Script Proxy Execution: SyncAppvPublishingServer


### T1218.001 - System Binary Proxy Execution: Compiled HTML File

Procedures:

- [G0049] OilRig: OilRig has used a CHM payload to load and execute another malicious file once delivered to a victim.
- [G0070] Dark Caracal: Dark Caracal leveraged a compiled HTML file that contained a command to download and run an executable.
- [G0091] Silence: Silence has weaponized CHM files in their phishing campaigns.
- [G0096] APT41: APT41 used compiled HTML (.chm) files for targeting.
- [G0082] APT38: APT38 has used CHM files to move concealed payloads.
- [S0373] Astaroth: Astaroth uses ActiveX objects for file execution and manipulation.

### T1218.002 - System Binary Proxy Execution: Control Panel

Procedures:

- [S0260] InvisiMole: InvisiMole can register itself for execution and persistence via the Control Panel.
- [S0172] Reaver: Reaver drops and executes a malicious CPL file as its payload.

### T1218.003 - System Binary Proxy Execution: CMSTP

Procedures:

- [S1149] CHIMNEYSWEEP: CHIMNEYSWEEP can use CMSTP.exe to install a malicious Microsoft Connection Manager Profile.
- [G0069] MuddyWater: MuddyWater has used CMSTP.exe and a malicious INF to execute its POWERSTATS payload.
- [S1202] LockBit 3.0: LockBit 3.0 can attempt a CMSTP UAC bypass if it does not have administrative privileges.
- [G0080] Cobalt Group: Cobalt Group has used the command cmstp.exe /s /ns C:\Users\ADMINI~W\AppData\Local\Temp\XKNqbpzl.txt to bypass AppLocker and launch a malicious script.

### T1218.004 - System Binary Proxy Execution: InstallUtil

Procedures:

- [S0631] Chaes: Chaes has used Installutill to download content.
- [G0129] Mustang Panda: Mustang Panda has used InstallUtil.exe to execute a malicious Beacon stager.
- [S0689] WhisperGate: WhisperGate has used `InstallUtil.exe` as part of its process to disable Windows Defender.
- [S1155] Covenant: Covenant can create launchers via an InstallUtil XML file to install new Grunt listeners.
- [G0045] menuPass: menuPass has used InstallUtil.exe to execute malicious software.
- [S1018] Saint Bot: Saint Bot had used `InstallUtil.exe` to download and deploy executables.

### T1218.005 - System Binary Proxy Execution: Mshta

Procedures:

- [G0121] Sidewinder: Sidewinder has used mshta.exe to execute malicious payloads.
- [G0032] Lazarus Group: Lazarus Group has used mshta.exe to execute HTML pages downloaded by initial access documents.
- [S0250] Koadic: Koadic can use mshta to serve additional payloads and to help schedule tasks for persistence.
- [G0069] MuddyWater: MuddyWater has used mshta.exe to execute its POWERSTATS payload and to pass a PowerShell one-liner for execution.
- [S0341] Xbash: Xbash can use mshta for executing scripts.
- [G0129] Mustang Panda: Mustang Panda has used mshta.exe to launch collection scripts.
- [S0414] BabyShark: BabyShark has used mshta.exe to download and execute applications from a remote server.
- [G0140] LazyScripter: LazyScripter has used `mshta.exe` to execute Koadic stagers.
- [S0223] POWERSTATS: POWERSTATS can use Mshta.exe to execute additional payloads on compromised hosts.
- [G1018] TA2541: TA2541 has used `mshta` to execute scripts including VBS.
- [S1213] Lumma Stealer: Lumma Stealer has used mshta.exe to execute additional content.
- [G0082] APT38: APT38 has used a renamed version of `mshta.exe` to execute malicious HTML files.
- [S0455] Metamorfo: Metamorfo has used mshta.exe to execute a HTA payload.
- [G0100] Inception: Inception has used malicious HTA files to drop and execute malware.
- [G0094] Kimsuky: Kimsuky has used mshta.exe to run malicious scripts on the system.

### T1218.007 - System Binary Proxy Execution: Msiexec

Procedures:

- [S0631] Chaes: Chaes has used .MSI files as an initial way to start the infection chain.
- [G0021] Molerats: Molerats has used msiexec.exe to execute an MSI payload.
- [S0038] Duqu: Duqu has used msiexec to execute malicious Windows Installer packages. Additionally, a PROPERTY=VALUE pair containing a 56-bit encryption key has been used to decrypt the main payload from the installer packages.
- [S0455] Metamorfo: Metamorfo has used MsiExec.exe to automatically execute files.
- [S1160] Latrodectus: Latrodectus has called `msiexec` to install remotely-hosted MSI files.
- [S1052] DEADEYE: DEADEYE can use `msiexec.exe` for execution of malicious DLL.
- [S0483] IcedID: IcedID can inject itself into a suspended msiexec.exe process to send beacons to C2 while appearing as a normal msi application. IcedID has also used msiexec.exe to deploy the IcedID loader.
- [S1122] Mispadu: Mispadu has been installed via MSI installer.
- [S0662] RCSession: RCSession has the ability to execute inside the msiexec.exe process.
- [G0092] TA505: TA505 has used msiexec to download and execute malicious Windows Installer files.
- [S0530] Melcoz: Melcoz can use MSI files with embedded VBScript for execution.
- [S0650] QakBot: QakBot can use MSIExec to spawn multiple cmd.exe processes.
- [S0531] Grandoreiro: Grandoreiro can use MSI files to execute DLLs.
- [S0584] AppleJeus: AppleJeus has been installed via MSI installer.
- [S0528] Javali: Javali has used the MSI installer to download and execute malicious payloads.

### T1218.008 - System Binary Proxy Execution: Odbcconf

Procedures:

- [G0080] Cobalt Group: Cobalt Group has used odbcconf to proxy the execution of malicious DLL files.
- [S1039] Bumblebee: Bumblebee can use `odbcconf.exe` to run DLLs on targeted hosts.
- [S1130] Raspberry Robin: Raspberry Robin uses the Windows utility odbcconf.exe to execute malicious commands, using the regsvr flag to execute DLLs and bypass application control mechanisms that are not monitoring for odbcconf.exe abuse.

### T1218.009 - System Binary Proxy Execution: Regsvcs/Regasm

Procedures:

- [S0331] Agent Tesla: Agent Tesla has dropped RegAsm.exe onto systems for performing malicious activity.

### T1218.010 - System Binary Proxy Execution: Regsvr32

Procedures:

- [S1018] Saint Bot: Saint Bot has used `regsvr32` to execute scripts.
- [S0650] QakBot: QakBot can use Regsvr32 to execute malicious DLLs.
- [G0127] TA551: TA551 has used regsvr32.exe to load malicious DLLs.
- [S0367] Emotet: Emotet uses RegSvr32 to execute the DLL payload.
- [S0229] Orz: Some Orz versions have an embedded DLL known as MockDll that uses Process Hollowing and regsvr32 to execute another payload.
- [S0250] Koadic: Koadic can use Regsvr32 to execute additional payloads.
- [S0476] Valak: Valak has used regsvr32.exe to launch malicious DLLs.
- [S1030] Squirrelwaffle: Squirrelwaffle has been executed using `regsvr32.exe`.
- [S1047] Mori: Mori can use `regsvr32.exe` for DLL execution.
- [S1155] Covenant: Covenant can create SCT files for installation via `Regsvr32` to deploy new Grunt listeners.
- [S0373] Astaroth: Astaroth can be loaded through regsvr32.exe.
- [S0384] Dridex: Dridex can use `regsvr32.exe` to initiate malicious code.
- [S1130] Raspberry Robin: Raspberry Robin uses regsvr32.exe execution without any command line parameters for command and control requests to IP addresses associated with Tor nodes.
- [S0021] Derusbi: Derusbi variants have been seen that use Registry persistence to proxy execution through regsvr32.exe.
- [G0009] Deep Panda: Deep Panda has used regsvr32.exe to execute a server variant of Derusbi in victim networks.

### T1218.011 - System Binary Proxy Execution: Rundll32

Procedures:

- [C0022] Operation Dream Job: During Operation Dream Job, Lazarus Group executed malware with `C:\\windows\system32\rundll32.exe "C:\ProgramData\ThumbNail\thumbnail.db"`, `CtrlPanel S-6-81-3811-75432205-060098-6872 0 0 905`.
- [S0260] InvisiMole: InvisiMole has used rundll32.exe for execution.
- [C0021] C0021: During C0021, the threat actors used `rundll32.exe` to execute the Cobalt Strike Beacon loader DLL.
- [S1160] Latrodectus: Latrodectus can use rundll32.exe to execute downloaded DLLs.
- [S0196] PUNCHBUGGY: PUNCHBUGGY can load a DLL using Rundll32.
- [S0635] BoomBox: BoomBox can use RunDLL32 for execution.
- [S0045] ADVSTORESHELL: ADVSTORESHELL has used rundll32.exe in a Registry value to establish persistence.
- [S0204] Briba: Briba uses rundll32 within Registry Run Keys / Startup Folder entries to execute malicious DLLs.
- [S0576] MegaCortex: MegaCortex has used rundll32.exe to load a DLL for file encryption.
- [S1064] SVCReady: SVCReady has used `rundll32.exe` for execution.
- [S0342] GreyEnergy: GreyEnergy uses PsExec locally in order to execute rundll32.exe at the highest privileges (NTAUTHORITY\SYSTEM).
- [S0142] StreamEx: StreamEx uses rundll32 to call an exported function.
- [S0082] Emissary: Variants of Emissary have used rundll32.exe in Registry values added to establish persistence.
- [S0139] PowerDuke: PowerDuke uses rundll32.exe to load.
- [S1190] Kapeka: Kapeka is a Windows DLL file executed via ordinal by `rundll32.exe`.

### T1218.012 - System Binary Proxy Execution: Verclsid

Procedures:

- [S0499] Hancitor: Hancitor has used verclsid.exe to download and execute a malicious script.

### T1218.013 - System Binary Proxy Execution: Mavinject

### T1218.014 - System Binary Proxy Execution: MMC

Procedures:

- [C0047] RedDelta Modified PlugX Infection Chain Operations: Mustang Panda used Microsoft Management Console Snap-In Control files, or MSC files, executed via MMC to run follow-on PowerShell commands during RedDelta Modified PlugX Infection Chain Operations.

### T1218.015 - System Binary Proxy Execution: Electron Applications

Procedures:

- [S1213] Lumma Stealer: Lumma Stealer as leveraged Electron Applications to disable GPU sandboxing to avoid detection by security software.


### T1220 - XSL Script Processing

Procedures:

- [S0373] Astaroth: Astaroth executes embedded JScript or VBScript in an XSL stylesheet located on a remote domain.
- [G0080] Cobalt Group: Cobalt Group used msxsl.exe to bypass AppLocker and to invoke Jscript code from an XSL file.
- [G0126] Higaisa: Higaisa used an XSL file to run VBScript code.
- [C0022] Operation Dream Job: During Operation Dream Job, Lazarus Group used a remote XSL script to download a Base64-encoded DLL custom downloader.


### T1221 - Template Injection

Procedures:

- [G0035] Dragonfly: Dragonfly has injected SMB URLs into malicious Word spearphishing attachments to initiate Forced Authentication.
- [G0142] Confucius: Confucius has used a weaponized Microsoft Word document with an embedded RTF exploit.
- [C0022] Operation Dream Job: During Operation Dream Job, Lazarus Group used DOCX files to retrieve a malicious document template/DOTM file.
- [G0081] Tropic Trooper: Tropic Trooper delivered malicious documents with the XLSX extension, typically used by OpenXML documents, but the file itself was actually an OLE (XLS) document.
- [G0007] APT28: APT28 used weaponized Microsoft Word documents abusing the remote template function to retrieve a malicious macro.
- [C0001] Frankenstein: During Frankenstein, the threat actors used trojanized documents that retrieved remote templates from an adversary-controlled website.
- [G0047] Gamaredon Group: Gamaredon Group has used DOCX files to download malicious DOT document templates and has used RTF template injection to download malicious payloads. Gamaredon Group can also inject malicious macros or remote templates into documents already present on compromised systems.
- [S0631] Chaes: Chaes changed the template target of the settings.xml file embedded in the Word document and populated that field with the downloaded URL of the next payload.
- [G0100] Inception: Inception has used decoy documents to load malicious remote payloads via HTTP.
- [S0670] WarzoneRAT: WarzoneRAT has been install via template injection through a malicious DLL embedded within a template RTF in a Word document.
- [G0079] DarkHydrus: DarkHydrus used an open-source tool, Phishery, to inject malicious remote template URLs into Microsoft Word documents and then sent them to victims to enable Forced Authentication.


### T1222.001 - File and Directory Permissions Modification: Windows File and Directory Permissions Modification

Procedures:

- [S0201] JPIN: JPIN can use the command-line utility cacls.exe to change file permissions.
- [S0570] BitPaymer: BitPaymer can use icacls /reset and takeown /F to reset a targeted executable's permissions and then take ownership.
- [S0531] Grandoreiro: Grandoreiro can modify the binary ACL to prevent security tools from running.
- [G0102] Wizard Spider: Wizard Spider has used the icacls command to modify access control to backup servers, providing them with full control of all the system folders.
- [S0693] CaddyWiper: CaddyWiper can modify ACL entries to take ownership of files.
- [S0446] Ryuk: Ryuk can launch icacls /grant Everyone:F /T /C /Q to delete every access-based restrictions on files and directories.
- [S1068] BlackCat: BlackCat can use Windows commands such as `fsutil behavior set SymLinkEvaluation R2L:1` to redirect file system access to a different location after gaining access into compromised networks.
- [S0366] WannaCry: WannaCry uses attrib +h and icacls . /grant Everyone:F /T /C /Q to make some of its files hidden and grant all users full access controls.
- [S1180] BlackByte Ransomware: BlackByte Ransomware uses the `mountvol.exe` command to mount volume names and leverages the Microsoft Discretionary Access Control List tool, `icacls.exe`, to grant the group to “Everyone” full access to the root of the drive.
- [S0612] WastedLocker: WastedLocker has a command to take ownership of a file and reset the ACL permissions using the takeown.exe /F filepath command.
- [G1046] Storm-1811: Storm-1811 has used `cacls.exe` via batch script to modify file and directory permissions in victim environments.

### T1222.002 - File and Directory Permissions Modification: Linux and Mac File and Directory Permissions Modification

Procedures:

- [G0139] TeamTNT: TeamTNT has modified the permissions on binaries with chattr.
- [S0352] OSX_OCEANLOTUS.D: OSX_OCEANLOTUS.D has changed permissions of a second-stage payload to an executable via chmod.
- [S0598] P.A.S. Webshell: P.A.S. Webshell has the ability to modify file permissions.
- [S0599] Kinsing: Kinsing has used chmod to modify permissions on key files for use.
- [S0402] OSX/Shlayer: OSX/Shlayer can use the chmod utility to set a file as executable, such as chmod 777 or chmod +x.
- [S1105] COATHANGER: COATHANGER will set the GID of `httpsd` to 90 when infected.
- [S1070] Black Basta: The Black Basta binary can use `chmod` to gain full permissions to targeted files.
- [S0281] Dok: Dok gives all users execute permissions for the application using the command chmod +x /Users/Shared/AppStore.app.
- [C0035] KV Botnet Activity: KV Botnet Activity altered permissions on downloaded tools and payloads to enable execution on victim machines.
- [S0658] XCSSET: XCSSET uses the chmod +x command to grant executable permissions to the malicious file.
- [G0106] Rocke: Rocke has changed file permissions of files so they could not be modified.
- [G0050] APT32: APT32's macOS backdoor changes the permission of the file it wants to execute to 755.
- [S0587] Penquin: Penquin can add the executable flag to a downloaded file.
- [S0482] Bundlore: Bundlore changes the permissions of a payload using the command chmod -R 755.


### T1480.001 - Execution Guardrails: Environmental Keying

Procedures:

- [G0020] Equation: Equation has been observed utilizing environmental keying in payload delivery.
- [G0096] APT41: APT41 has encrypted payloads using the Data Protection API (DPAPI), which relies on keys tied to specific user accounts on specific machines. APT41 has also environmentally keyed second stage malware with an RC5 key derived in part from the infected system's volume serial number.
- [S0240] ROKRAT: ROKRAT relies on a specific victim hostname to execute and decrypt important strings.
- [S1100] Ninja: Ninja can store its final payload in the Registry under `$HKLM\SOFTWARE\Classes\Interface\` encrypted with a dynamically generated key based on the drive’s serial number.
- [S0260] InvisiMole: InvisiMole can use Data Protection API to encrypt its components on the victim’s computer, to evade detection, and to make sure the payload can only be decrypted and loaded on one specific compromised computer.
- [S1145] Pikabot: Pikabot stops execution if the infected system language matches one of several languages, with various versions referencing: Georgian, Kazakh, Uzbek, Tajik, Russian, Ukrainian, Belarussian, and Slovenian.
- [S0685] PowerPunch: PowerPunch can use the volume serial number from a target host to generate a unique XOR key for the next stage payload.
- [S0141] Winnti for Windows: The Winnti for Windows dropper component can verify the existence of a single command line parameter and either terminate if it is not found or later use it as a decryption key.

### T1480.002 - Execution Guardrails: Mutual Exclusion

Procedures:

- [S1161] BPFDoor: When executed, BPFDoor attempts to create and lock a runtime file, `/var/run/initd.lock`, and exits if it fails using the specified file, resulting in a makeshift mutex.
- [S1202] LockBit 3.0: LockBit 3.0 can create and check for a mutex containing a hash of the `MachineGUID` value at execution to prevent running more than one instance.
- [S0632] GrimAgent: GrimAgent uses the last 64 bytes of the binary to compute a mutex name. If the generated name is invalid, it will default to the generic `mymutex`.
- [S0496] REvil: REvil attempts to create a mutex using a hard-coded value to ensure that no other instances of itself are running on the host.
- [S0012] PoisonIvy: PoisonIvy creates a mutex using either a custom or default value.
- [S1196] Troll Stealer: Troll Stealer creates a mutex during installation to prevent duplicate execution.
- [S0562] SUNSPOT: SUNSPOT creates a mutex using the hard-coded value ` {12d61a41-4b74-7610-a4d8-3028d2f56395}` to ensure that only one instance of itself is running.
- [S1183] StrelaStealer: StrelaStealer variants include the use of mutex values based on the victim system name to prevent reinfection.
- [S0168] Gazer: Gazer creates a mutex using the hard-coded value `{531511FA-190D-5D85-8A4A-279F2F592CC7}` to ensure that only one instance of itself is running.
- [G0082] APT38: APT38 has created a mutex to avoid duplicate execution.
- [S1070] Black Basta: Black Basta will check for the presence of a hard-coded mutex `dsajdhas.0` before executing.


### T1484.001 - Domain or Tenant Policy Modification: Group Policy Modification

Procedures:

- [S1058] Prestige: Prestige has been deployed using the Default Domain Group Policy Object from an Active Directory Domain Controller.
- [S1202] LockBit 3.0: LockBit 3.0 can enable options for propogation through Group Policy Objects.
- [S0697] HermeticWiper: HermeticWiper has the ability to deploy through an infected system's default domain policy.
- [G1021] Cinnamon Tempest: Cinnamon Tempest has used Group Policy to deploy batch scripts for ransomware deployment.
- [S0363] Empire: Empire can use New-GPOImmediateTask to modify a GPO that will install and execute a malicious Scheduled Task/Job.
- [G0096] APT41: APT41 used scheduled tasks created via Group Policy Objects (GPOs) to deploy ransomware.
- [S1199] LockBit 2.0: LockBit 2.0 can modify Group Policy to disable Windows Defender and to automatically infect devices in Windows domains.
- [G0119] Indrik Spider: Indrik Spider has used Group Policy Objects to deploy batch scripts.
- [S0554] Egregor: Egregor can modify the GPO to evade detection.
- [S0688] Meteor: Meteor can use group policy to push a scheduled task from the AD to all network machines.
- [C0034] 2022 Ukraine Electric Power Attack: During the 2022 Ukraine Electric Power Attack, Sandworm Team leveraged Group Policy Objects (GPOs) to deploy and execute malware.

### T1484.002 - Domain or Tenant Policy Modification: Trust Modification

Procedures:

- [G1015] Scattered Spider: Scattered Spider adds a federated identity provider to the victim’s SSO tenant and activates automatic account linking.
- [S0677] AADInternals: AADInternals can create a backdoor by converting a domain to a federated domain which will be able to authenticate any user across the tenant. AADInternals can also modify DesktopSSO information.
- [C0024] SolarWinds Compromise: During the SolarWinds Compromise, APT29 changed domain federation trust settings using Azure AD administrative permissions to configure the domain to accept authorization tokens signed by their own SAML signing certificate.


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


### T1535 - Unused/Unsupported Cloud Regions


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

### T1542.005 - Pre-OS Boot: TFTP Boot


### T1548.001 - Abuse Elevation Control Mechanism: Setuid and Setgid

Procedures:

- [S0276] Keydnap: Keydnap adds the setuid flag to a binary so it can easily elevate in the future.
- [S0401] Exaramel for Linux: Exaramel for Linux can execute commands with high privileges via a specific binary with setuid functionality.

### T1548.002 - Abuse Elevation Control Mechanism: Bypass User Account Control

Procedures:

- [S0089] BlackEnergy: BlackEnergy attempts to bypass default User Access Control (UAC) settings by exploiting a backward-compatibility setting found in Windows 7 and later.
- [S0148] RTM: RTM can attempt to run the program as admin, then show a fake error message and a legitimate UAC bypass prompt to the user in an attempt to socially engineer the user into escalating privileges.
- [S1202] LockBit 3.0: LockBit 3.0 can bypass UAC to execute code with elevated privileges through an elevated Component Object Model (COM) interface.
- [S0154] Cobalt Strike: Cobalt Strike can use a number of known techniques to bypass Windows UAC.
- [S0666] Gelsemium: Gelsemium can bypass UAC to elevate process privileges on a compromised host.
- [S0230] ZeroT: Many ZeroT samples can perform UAC bypass by using eventvwr.exe to execute a malicious file.
- [S1018] Saint Bot: Saint Bot has attempted to bypass UAC using `fodhelper.exe` to escalate privileges.
- [S1111] DarkGate: DarkGate uses two distinct User Account Control (UAC) bypass techniques to escalate privileges.
- [G0082] APT38: APT38 has used the legitimate application `ieinstal.exe` to bypass UAC.
- [S0670] WarzoneRAT: WarzoneRAT can use `sdclt.exe` to bypass UAC in Windows 10 to escalate privileges; for older Windows versions WarzoneRAT can use the IFileOperation exploit to bypass the UAC module.
- [S0192] Pupy: Pupy can bypass Windows UAC through either DLL hijacking, eventvwr, or appPaths.
- [S0378] PoshC2: PoshC2 can utilize multiple methods to bypass UAC.
- [S0356] KONNI: KONNI has bypassed UAC by performing token impersonation as well as an RPC-based method, this included bypassing UAC set to “AlwaysNotify".
- [S0074] Sakula: Sakula contains UAC bypass code for both 32- and 64-bit systems.
- [S0444] ShimRat: ShimRat has hijacked the cryptbase.dll within migwiz.exe to escalate privileges. This prevented the User Access Control window from appearing.

### T1548.003 - Abuse Elevation Control Mechanism: Sudo and Sudo Caching

Procedures:

- [S0154] Cobalt Strike: Cobalt Strike can use sudo to run a command.
- [S0279] Proton: Proton modifies the tty_tickets line in the sudoers file.
- [S0281] Dok: Dok adds admin ALL=(ALL) NOPASSWD: ALL to the /etc/sudoers file.

### T1548.004 - Abuse Elevation Control Mechanism: Elevated Execution with Prompt

Procedures:

- [S0402] OSX/Shlayer: OSX/Shlayer can escalate privileges to root by asking the user for credentials.

### T1548.005 - Abuse Elevation Control Mechanism: Temporary Elevated Cloud Access

### T1548.006 - Abuse Elevation Control Mechanism: TCC Manipulation

Procedures:

- [S0658] XCSSET: For several modules, XCSSET attempts to access or list the contents of user folders such as Desktop, Downloads, and Documents. If the folder does not exist or access is denied, it enters a loop where it resets the TCC database and retries access.


### T1550.001 - Use Alternate Authentication Material: Application Access Token

Procedures:

- [S0683] Peirates: Peirates can use stolen service account tokens to perform its operations. It also enables adversaries to switch between valid service accounts.
- [S1023] CreepyDrive: CreepyDrive can use legitimate OAuth refresh tokens to authenticate with OneDrive.
- [C0024] SolarWinds Compromise: During the SolarWinds Compromise, APT29 used compromised service principals to make changes to the Office 365 environment.
- [G0007] APT28: APT28 has used several malicious applications that abused OAuth access tokens to gain access to target email accounts, including Gmail and Yahoo Mail.
- [G0125] HAFNIUM: HAFNIUM has abused service principals with administrative permissions for data exfiltration.

### T1550.002 - Use Alternate Authentication Material: Pass the Hash

Procedures:

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
- [S0002] Mimikatz: Mimikatz's SEKURLSA::Pth module can impersonate a user, with only a password hash, to execute arbitrary commands.
- [G0096] APT41: APT41 uses tools such as Mimikatz to enable lateral movement via captured password hashes.
- [G0094] Kimsuky: Kimsuky has used pass the hash for authentication to remote access software used in C2.
- [S0363] Empire: Empire can perform pass the hash attacks.
- [G1016] FIN13: FIN13 has used the PowerShell utility `Invoke-SMBExec` to execute the pass the hash method for lateral movement within an compromised environment.

### T1550.003 - Use Alternate Authentication Material: Pass the Ticket

Procedures:

- [S0053] SeaDuke: Some SeaDuke samples have a module to use pass the ticket with Kerberos for authentication.
- [G0016] APT29: APT29 used Kerberos ticket attacks for lateral movement.
- [S0002] Mimikatz: Mimikatz’s LSADUMP::DCSync and KERBEROS::PTT modules implement the three steps required to extract the krbtgt account hash and create/use Kerberos tickets.
- [S0192] Pupy: Pupy can also perform pass-the-ticket.
- [G0050] APT32: APT32 successfully gained remote access by using pass the ticket.
- [G0060] BRONZE BUTLER: BRONZE BUTLER has created forged Kerberos Ticket Granting Ticket (TGT) and Ticket Granting Service (TGS) tickets to maintain administrative access.

### T1550.004 - Use Alternate Authentication Material: Web Session Cookie

Procedures:

- [G1033] Star Blizzard: Star Blizzard has bypassed multi-factor authentication on victim email accounts by using session cookies stolen using EvilGinx.
- [C0024] SolarWinds Compromise: During the SolarWinds Compromise, APT29 used stolen cookies to access cloud resources and a forged `duo-sid` cookie to bypass MFA set on an email account.


### T1553.001 - Subvert Trust Controls: Gatekeeper Bypass

Procedures:

- [S0658] XCSSET: XCSSET has dropped a malicious applet into an app's `.../Contents/MacOS/` folder of a previously launched app to bypass Gatekeeper's security checks on first launch apps (prior to macOS 13).
- [S0402] OSX/Shlayer: If running with elevated privileges, OSX/Shlayer has used the spctl command to disable Gatekeeper protection for a downloaded file. OSX/Shlayer can also leverage system links pointing to bash scripts in the downloaded DMG file to bypass Gatekeeper, a flaw patched in macOS 11.3 and later versions. OSX/Shlayer has been Notarized by Apple, resulting in successful passing of additional Gatekeeper checks.
- [S1153] Cuckoo Stealer: Cuckoo Stealer can use `xattr -d com.apple.quarantine` to remove the quarantine flag attribute.
- [S1016] MacMa: MacMa has removed the `com.apple.quarantineattribute` from the dropped file, `$TMPDIR/airportpaird`.
- [S0352] OSX_OCEANLOTUS.D: OSX_OCEANLOTUS.D uses the command xattr -d com.apple.quarantine to remove the quarantine file attribute used by Gatekeeper.
- [S0369] CoinTicker: CoinTicker downloads the EggShell mach-o binary using curl, which does not set the quarantine flag.

### T1553.002 - Subvert Trust Controls: Code Signing

Procedures:

- [S0154] Cobalt Strike: Cobalt Strike can use self signed Java applets to execute signed applet attacks.
- [S0475] BackConfig: BackConfig has been signed with self signed digital certificates mimicking a legitimate software company.
- [G0046] FIN7: FIN7 has signed Carbanak payloads with legally purchased code signing certificates. FIN7 has also digitally signed their phishing documents, backdoors and other staging tools to bypass security controls.
- [G1015] Scattered Spider: Scattered Spider has used self-signed and stolen certificates originally issued to NVIDIA and Global Software LLC.
- [S0187] Daserf: Some Daserf samples were signed with a stolen digital certificate.
- [G0040] Patchwork: Patchwork has signed malware with self-signed certificates from fictitious and spoofed legitimate software companies.
- [C0047] RedDelta Modified PlugX Infection Chain Operations: Mustang Panda used legitimate, signed binaries such as `inkform.exe` or `ExcelRepairToolboxLauncher.exe` for follow-on execution of malicious DLLs through DLL search order hijacking in RedDelta Modified PlugX Infection Chain Operations.
- [S0698] HermeticWizard: HermeticWizard has been signed by valid certificates assigned to Hermetica Digital.
- [G0094] Kimsuky: Kimsuky has signed files with the name EGIS CO,. Ltd. and has stolen a valid certificate that is used to sign the malware and the dropper.
- [S0170] Helminth: Helminth samples have been signed with legitimate, compromised code signing certificates owned by software company AI Squared.
- [S1070] Black Basta: The Black Basta dropper has been digitally signed with a certificate issued by Akeo Consulting for legitimate executables used for creating bootable USB drives.
- [S1016] MacMa: MacMa has been delivered using ad hoc Apple Developer code signing certificates.
- [S1183] StrelaStealer: StrelaStealer variants have used valid code signing certificates.
- [G0093] GALLIUM: GALLIUM has used stolen certificates to sign its tools including those from Whizzimo LLC.
- [G1031] Saint Bear: Saint Bear has used an initial loader malware featuring a legitimate code signing certificate associated with "Electrum Technologies GmbH."

### T1553.003 - Subvert Trust Controls: SIP and Trust Provider Hijacking

### T1553.004 - Subvert Trust Controls: Install Root Certificate

Procedures:

- [S0160] certutil: certutil can be used to install browser root certificates as a precursor to performing Adversary-in-the-Middle between connections to banking websites. Example command: certutil -addstore -f -user ROOT ProgramData\cert512121.der.
- [S0281] Dok: Dok installs a root certificate to aid in Adversary-in-the-Middle actions using the command add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain /tmp/filename.
- [S0009] Hikit: Hikit installs a self-generated certificate to the local trust store as a root CA and Trusted Publisher.
- [S0148] RTM: RTM can add a certificate to the Windows store.

### T1553.005 - Subvert Trust Controls: Mark-of-the-Web Bypass

Procedures:

- [G0092] TA505: TA505 has used .iso files to deploy malicious .lnk files.
- [S1025] Amadey: Amadey has modified the `:Zone.Identifier` in the ADS area to zero.
- [G0082] APT38: APT38 has used ISO and VHD files to deploy malware and to bypass Mark-of-the-Web (MOTW) security measures.
- [S0650] QakBot: QakBot has been packaged in ISO files in order to bypass Mark of the Web (MOTW) security measures.
- [G0016] APT29: APT29 has embedded ISO images and VHDX files in HTML to evade Mark-of-the-Web.

### T1553.006 - Subvert Trust Controls: Code Signing Policy Modification

Procedures:

- [G0087] APT39: APT39 has used malware to turn off the RequireSigned feature which ensures only signed DLLs can be run on Windows.
- [S0089] BlackEnergy: BlackEnergy has enabled the TESTSIGNING boot configuration option to facilitate loading of a driver component.
- [S0009] Hikit: Hikit has attempted to disable driver signing verification by tampering with several Registry keys prior to the loading of a rootkit driver component.
- [S0664] Pandora: Pandora can use CVE-2017-15303 to disable Windows Driver Signature Enforcement (DSE) protection and load its driver.
- [G0010] Turla: Turla has modified variables in kernel memory to turn off Driver Signature Enforcement after exploiting vulnerabilities that obtained kernel mode privileges.


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

### T1556.009 - Modify Authentication Process: Conditional Access Policies

Procedures:

- [G1015] Scattered Spider: Scattered Spider has added additional trusted locations to Azure AD conditional access policies.


### T1562.001 - Impair Defenses: Disable or Modify Tools

Procedures:

- [S0253] RunningRAT: RunningRAT kills antimalware running process.
- [S0559] SUNBURST: SUNBURST attempted to disable software security services following checks against a FNV-1a + XOR hashed hardcoded blocklist.
- [G1032] INC Ransom: INC Ransom can use SystemSettingsAdminFlows.exe, a native Windows utility, to disable Windows Defender.
- [S0659] Diavol: Diavol can attempt to stop security software.
- [G1018] TA2541: TA2541 has attempted to disable built-in security protections such as Windows AMSI.
- [S0132] H1N1: H1N1 kills and disables services for Windows Security Center, and Windows Defender.
- [G0010] Turla: Turla has used a AMSI bypass, which patches the in-memory amsi.dll, in PowerShell scripts to bypass Windows antimalware products.
- [S0446] Ryuk: Ryuk has stopped services related to anti-virus.
- [S0457] Netwalker: Netwalker can detect and terminate active security software-related processes on infected systems.
- [C0035] KV Botnet Activity: KV Botnet Activity used various scripts to remove or disable security tools, such as http_watchdog and firewallsd, as well as tools related to other botnet infections, such as mips_ff, on victim devices.
- [S0692] SILENTTRINITY: SILENTTRINITY's `amsiPatch.py` module can disable Antimalware Scan Interface (AMSI) functions.
- [S0496] REvil: REvil can connect to and disable the Symantec server on the victim's network.
- [S0154] Cobalt Strike: Cobalt Strike has the ability to use Smart Applet attacks to disable the Java SecurityManager sandbox.
- [S0223] POWERSTATS: POWERSTATS can disable Microsoft Office Protected View by changing Registry keys.
- [S0372] LockerGoga: LockerGoga installation has been immediately preceded by a "task kill" command in order to disable anti-virus.

### T1562.002 - Impair Defenses: Disable Windows Event Logging

Procedures:

- [S0645] Wevtutil: Wevtutil can be used to disable specific event logs on the system.
- [G0027] Threat Group-3390: Threat Group-3390 has used appcmd.exe to disable logging on a victim server.
- [G0059] Magic Hound: Magic Hound has executed scripts to disable the event log service.
- [C0024] SolarWinds Compromise: During the SolarWinds Compromise, APT29, used `AUDITPOL` to prevent the collection of audit logs.
- [C0038] HomeLand Justice: During HomeLand Justice, threat actors deleted Windows events and application logs.
- [C0025] 2016 Ukraine Electric Power Attack: During the 2016 Ukraine Electric Power Attack, Sandworm Team disabled event logging on compromised systems.

### T1562.003 - Impair Defenses: Impair Command History Logging

Procedures:

- [S1186] Line Dancer: Line Dancer can disable syslog on compromised devices.
- [G1041] Sea Turtle: Sea Turtle unset the Bash and MySQL history files on victim systems.
- [S1161] BPFDoor: BPFDoor sets the `MYSQL_HISTFILE` and `HISTFILE` to `/dev/null` preventing the shell and MySQL from logging history in `/proc//environ`.
- [C0046] ArcaneDoor: ArcaneDoor included disabling logging on targeted Cisco ASA appliances.
- [G0082] APT38: APT38 has prepended a space to all of their terminal commands to operate without leaving traces in the HISTCONTROL environment.
- [S0692] SILENTTRINITY: SILENTTRINITY can bypass ScriptBlock logging to execute unmanaged PowerShell code from memory.

### T1562.004 - Impair Defenses: Disable or Modify System Firewall

Procedures:

- [S0260] InvisiMole: InvisiMole has a command to disable routing and the Firewall on the victim’s machine.
- [S1211] Hannotog: Hannotog can modify local firewall settings via `netsh` commands to open a listening UDP port.
- [G0008] Carbanak: Carbanak may use netsh to add local firewall rule exceptions.
- [G1045] Salt Typhoon: Salt Typhoon has made changes to the Access Control List (ACL) and loopback interface address on compromised devices.
- [S0336] NanoCore: NanoCore can modify the victim's firewall.
- [S0245] BADCALL: BADCALL disables the Windows firewall before binding to a port.
- [G0106] Rocke: Rocke used scripts which killed processes and added firewall rules to block traffic related to other cryptominers.
- [G0139] TeamTNT: TeamTNT has disabled iptables.
- [S1181] BlackByte 2.0 Ransomware: BlackByte 2.0 Ransomware modifies the Windows firewall during execution.
- [S1178] ShrinkLocker: ShrinkLocker turns on the system firewall and deletes all of its rules during execution.
- [S0132] H1N1: H1N1 kills and disables services for Windows Firewall.
- [S0263] TYPEFRAME: TYPEFRAME can open the Windows Firewall on the victim’s machine to allow incoming connections.
- [G0035] Dragonfly: Dragonfly has disabled host-based firewalls. The group has also globally opened port 3389.
- [C0051] APT28 Nearest Neighbor Campaign: During APT28 Nearest Neighbor Campaign, APT28 added rules to a victim's Windows firewall to set up a series of port-forwards allowing traffic to target systems.
- [S0108] netsh: netsh can be used to disable local firewall settings.

### T1562.006 - Impair Defenses: Indicator Blocking

Procedures:

- [S0697] HermeticWiper: HermeticWiper has the ability to set the `HKLM:\SYSTEM\\CurrentControlSet\\Control\\CrashControl\CrashDumpEnabled` Registry key to `0` in order to disable crash dumps.
- [G0096] APT41: APT41 developed a custom injector that enables an Event Tracing for Windows (ETW) bypass, making malicious processes invisible to Windows logging.
- [S1065] Woody RAT: Woody RAT has suppressed all error reporting by calling `SetErrorMode` with 0x8007 as a parameter.
- [G1023] APT5: APT5 has used the CLEANPULSE utility to insert command line strings into a targeted process to prevent certain log events from occurring.
- [S1097] HUI Loader: HUI Loader has the ability to disable Windows Event Tracing for Windows (ETW) and Antimalware Scan Interface (AMSI) functions.
- [S1063] Brute Ratel C4: Brute Ratel C4 has the ability to hide memory artifacts and to patch Event Tracing for Windows (ETW) and the Anti Malware Scan Interface (AMSI).
- [S0377] Ebury: Ebury hooks system functions to prevent the user from seeing malicious files (`readdir`, `realpath`, `readlink`, `stat`, `open`, and variants), hide process activity (`ps` and `readdir64`), and socket activity (`open` and `fopen`).
- [S1184] BOLDMOVE: BOLDMOVE can disable the Fortinet daemons `moglogd` and `syslogd` to evade detection and logging.
- [S1200] StealBit: StealBit can configure processes to not display certain Windows error messages by through use of the `NtSetInformationProcess`.
- [S0579] Waterbear: Waterbear can hook the ZwOpenProcess and GetExtendedTcpTable APIs called by the process of a security product to hide PIDs and TCP records from detection.

### T1562.007 - Impair Defenses: Disable or Modify Cloud Firewall

Procedures:

- [S1091] Pacu: Pacu can allowlist IP addresses in AWS GuardDuty.

### T1562.008 - Impair Defenses: Disable or Modify Cloud Logs

Procedures:

- [S1091] Pacu: Pacu can disable or otherwise restrict various AWS logging services, such as AWS CloudTrail and VPC flow logs.
- [G0016] APT29: APT29 has disabled Purview Audit on targeted accounts prior to stealing emails from Microsoft 365 tenants.

### T1562.009 - Impair Defenses: Safe Mode Boot

Procedures:

- [S0496] REvil: REvil can force a reboot in safe mode with networking.
- [S1212] RansomHub: RansomHub can reboot targeted systems into Safe Mode prior to encryption.
- [S1070] Black Basta: Black Basta can reboot victim machines in safe mode with networking via `bcdedit /set safeboot network`.
- [S1202] LockBit 3.0: LockBit 3.0 can reboot the infected host into Safe Mode.
- [S1053] AvosLocker: AvosLocker can restart a compromised machine in safe mode.

### T1562.010 - Impair Defenses: Downgrade Attack

Procedures:

- [C0041] FrostyGoop Incident: During FrostyGoop Incident, the adversary downgraded firmware on victim devices in order to impair visibility into the process environment.
- [S1180] BlackByte Ransomware: BlackByte Ransomware enables SMBv1 during execution.
- [S0692] SILENTTRINITY: SILENTTRINITY can downgrade NTLM to capture NTLM hashes.

### T1562.011 - Impair Defenses: Spoof Security Alerting

### T1562.012 - Impair Defenses: Disable or Modify Linux Audit System

Procedures:

- [S0377] Ebury: Ebury disables OpenSSH, system (`systemd`), and audit logs (`/sbin/auditd`) when the backdoor is active.


### T1564.001 - Hide Artifacts: Hidden Files and Directories

Procedures:

- [S0650] QakBot: QakBot has placed its payload in hidden subdirectories.
- [S0658] XCSSET: XCSSET uses a hidden folder named .xcassets and .git to embed itself in Xcode.
- [G0007] APT28: APT28 has saved files with hidden file attributes.
- [G1039] RedCurl: RedCurl added the “hidden” file attribute to original files, manipulating victims to click on malicious LNK files.
- [S1153] Cuckoo Stealer: Cuckoo Stealer has copied its binary and the victim's scraped password into a hidden folder in the `/Users` directory.
- [S0660] Clambling: Clambling has the ability to set its file attributes to hidden.
- [G1014] LuminousMoth: LuminousMoth has used malware to store malicious binaries in hidden directories on victim's USB drives.
- [S0612] WastedLocker: WastedLocker has copied a random file from the Windows System32 folder to the %APPDATA% location under a different hidden filename.
- [S0013] PlugX: PlugX can modify the characteristics of folders to hide them from the compromised user.
- [G0032] Lazarus Group: Lazarus Group has used a VBA Macro to set its file attributes to System and Hidden and has named files with a dot prefix to hide them from the Finder application.
- [S0369] CoinTicker: CoinTicker downloads the following hidden files to evade detection and maintain persistence: /private/tmp/.info.enc, /private/tmp/.info.py, /private/tmp/.server.sh, ~/Library/LaunchAgents/.espl.plist, ~/Library/Containers/.[random string]/[random string].
- [G0129] Mustang Panda: Mustang Panda's PlugX variant has created a hidden folder on USB drives named RECYCLE.BIN to store malicious executables and collected data.
- [S0428] PoetRAT: PoetRAT has the ability to hide and unhide files.
- [S0584] AppleJeus: AppleJeus has added a leading . to plist filenames, unlisting them from the Finder app and default Terminal directory listings.
- [S0402] OSX/Shlayer: OSX/Shlayer has executed a .command script from a hidden directory in a mounted DMG.

### T1564.002 - Hide Artifacts: Hidden Users

Procedures:

- [G0035] Dragonfly: Dragonfly has modified the Registry to hide created user accounts.
- [S0649] SMOKEDHAM: SMOKEDHAM has modified the Registry to hide created user accounts from the Windows logon screen.
- [G0094] Kimsuky: Kimsuky has run reg add ‘HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList’ /v to hide a newly created user.

### T1564.003 - Hide Artifacts: Hidden Window

Procedures:

- [S0373] Astaroth: Astaroth loads its module with the XSL script parameter vShow set to zero, which opens the application with a hidden window.
- [S0686] QuietSieve: QuietSieve has the ability to execute payloads in a hidden window.
- [S0491] StrongPity: StrongPity has the ability to hide the console window for its document search module from the user.
- [S1199] LockBit 2.0: LockBit 2.0 can execute command line arguments in a hidden window.
- [S1020] Kevin: Kevin can hide the current window from the targeted user via the `ShowWindow` API function.
- [G0022] APT3: APT3 has been known to use -WindowStyle Hidden to conceal PowerShell windows.
- [G0007] APT28: APT28 has used the WindowStyle parameter to conceal PowerShell windows.
- [G0073] APT19: APT19 used -W Hidden to conceal PowerShell windows by setting the WindowStyle parameter to hidden.
- [S0250] Koadic: Koadic has used the command Powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden to hide its window.
- [S0037] HAMMERTOSS: HAMMERTOSS has used -WindowStyle hidden to conceal PowerShell windows.
- [S0692] SILENTTRINITY: SILENTTRINITY has the ability to set its window state to hidden.
- [S0262] QuasarRAT: QuasarRAT can hide process windows and make web requests invisible to the compromised user. Requests marked as invisible have been sent with user-agent string `Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_3) AppleWebKit/537.75.14 (KHTML, like Gecko) Version/7.0.3 Safari/7046A194A` though QuasarRAT can only be run on Windows systems.
- [S0387] KeyBoy: KeyBoy uses -w Hidden to conceal a PowerShell window that downloads a payload.
- [S1089] SharpDisco: SharpDisco can hide windows using `ProcessWindowStyle.Hidden`.
- [S0500] MCMD: MCMD can modify processes to prevent them from being visible on the desktop.

### T1564.004 - Hide Artifacts: NTFS File Attributes

Procedures:

- [S0019] Regin: The Regin malware platform uses Extended Attributes to store encrypted executables.
- [G0050] APT32: APT32 used NTFS alternate data streams to hide their payloads.
- [S0476] Valak: Valak has the ability save and execute files as alternate data streams (ADS).
- [S0397] LoJax: LoJax has loaded an embedded NTFS DXE driver to be able to access and write to NTFS partitions.
- [S0404] esentutl: esentutl can be used to read and write alternate data streams.
- [S0361] Expand: Expand can be used to download or copy a file into an alternate data stream.
- [S0139] PowerDuke: PowerDuke hides many of its backdoor payloads in an alternate data stream (ADS).
- [S1052] DEADEYE: The DEADEYE.EMBED variant of DEADEYE can embed its payload in an alternate data stream of a local file.
- [S0145] POWERSOURCE: If the victim is using PowerShell 3.0 or later, POWERSOURCE writes its decoded payload to an alternate data stream (ADS) named kernel32.dll that is saved in %PROGRAMDATA%\Windows\.
- [S1160] Latrodectus: Latrodectus can delete itself while its process is still running through the use of an alternate data stream.
- [S0612] WastedLocker: WastedLocker has the ability to save and execute files as an alternate data stream (ADS).
- [S0570] BitPaymer: BitPaymer has copied itself to the :bin alternate data stream of a newly created file.
- [S0373] Astaroth: Astaroth can abuse alternate data streams (ADS) to store content for malicious payloads.
- [S0168] Gazer: Gazer stores configuration items in alternate data streams (ADSs) if the Registry is not accessible.
- [S0027] Zeroaccess: Some variants of the Zeroaccess Trojan have been known to store data in Extended Attributes.

### T1564.005 - Hide Artifacts: Hidden File System

Procedures:

- [G0020] Equation: Equation has used an encrypted virtual file system stored in the Windows Registry.
- [S0126] ComRAT: ComRAT has used a portable FAT16 partition image placed in %TEMP% as a hidden file system.
- [S0019] Regin: Regin has used a hidden file system to store some of its components.
- [S0114] BOOTRASH: BOOTRASH has used unallocated disk space between partitions for a hidden file system that stores components of the Nemesis bootkit.
- [S0022] Uroburos: Uroburos can use concealed storage mechanisms including an NTFS or FAT-16 filesystem encrypted with CAST-128 in CBC mode.
- [G0041] Strider: Strider has used a hidden file system that is stored as a file on disk.

### T1564.006 - Hide Artifacts: Run Virtual Instance

Procedures:

- [S0449] Maze: Maze operators have used VirtualBox and a Windows 7 virtual machine to run the ransomware; the virtual machine's configuration file mapped the shared network drives of the target company, presumably so Maze can encrypt files on the shared drives as well as the local machine.
- [S0481] Ragnar Locker: Ragnar Locker has used VirtualBox and a stripped Windows XP virtual machine to run itself. The use of a shared folder specified in the configuration enables Ragnar Locker to encrypt files on the host operating system, including files on any mapped drives.
- [S0451] LoudMiner: LoudMiner has used QEMU and VirtualBox to run a Tiny Core Linux virtual machine, which runs XMRig and makes connections to the C2 server for updates.

### T1564.007 - Hide Artifacts: VBA Stomping

### T1564.008 - Hide Artifacts: Email Hiding Rules

Procedures:

- [G1015] Scattered Spider: Scattered Spider creates inbound rules on the compromised email accounts of security personnel to automatically delete emails from vendor security products.
- [G0085] FIN4: FIN4 has created rules in victims' Microsoft Outlook accounts to automatically delete emails containing words such as “hacked," "phish," and “malware" in a likely attempt to prevent organizations from communicating about their activities.

### T1564.009 - Hide Artifacts: Resource Forking

Procedures:

- [S0276] Keydnap: Keydnap uses a resource fork to present a macOS JPEG or text file icon rather than the executable's icon assigned by the operating system.
- [S0402] OSX/Shlayer: OSX/Shlayer has used a resource fork to hide a compressed binary file of itself from the terminal, Finder, and potentially evade traditional scanners.

### T1564.010 - Hide Artifacts: Process Argument Spoofing

Procedures:

- [S0154] Cobalt Strike: Cobalt Strike can use spoof arguments in spawned processes that execute beacon commands.
- [S0615] SombRAT: SombRAT has the ability to modify its process memory to hide process command-line arguments.

### T1564.011 - Hide Artifacts: Ignore Process Interrupts

Procedures:

- [S0588] GoldMax: The GoldMax Linux variant has been executed with the `nohup` command to ignore hangup signals and continue to run if the terminal session was terminated.
- [S1184] BOLDMOVE: BOLDMOVE calls the signal function to ignore the signals SIGCHLD, SIGHIP, and SIGPIPE prior to starting primary logic.
- [G1041] Sea Turtle: Sea Turtle executed SnappyTCP using the tool NoHup, which keeps the malware running on a system after exiting the shell or terminal.
- [S0402] OSX/Shlayer: OSX/Shlayer has used the `nohup` command to instruct executed payloads to ignore hangup signals.
- [S1161] BPFDoor: BPFDoor set's it's process to ignore the following signals; `SIGHUP`, `SIGINT`, `SIGQUIT`, `SIGPIPE`, `SIGCHLD`, `SIGTTIN`, and `SIGTTOU`.

### T1564.012 - Hide Artifacts: File/Path Exclusions

Procedures:

- [G0010] Turla: Turla has placed LunarWeb install files into directories that are excluded from scanning.

### T1564.013 - Hide Artifacts: Bind Mounts

Procedures:

- [C0035] KV Botnet Activity: KV Botnet Activity leveraged a bind mount to bind itself to the `/proc/` file path before deleting its files from the `/tmp/` directory.

### T1564.014 - Hide Artifacts: Extended Attributes


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


### T1578.001 - Modify Cloud Compute Infrastructure: Create Snapshot

Procedures:

- [S1091] Pacu: Pacu can create snapshots of EBS volumes and RDS instances.

### T1578.002 - Modify Cloud Compute Infrastructure: Create Cloud Instance

Procedures:

- [C0027] C0027: During C0027, Scattered Spider used access to the victim's Azure tenant to create Azure VMs.
- [G1004] LAPSUS$: LAPSUS$ has created new virtual machines within the target's cloud environment after leveraging credential access to cloud assets.
- [G1015] Scattered Spider: During C0027, Scattered Spider used access to the victim's Azure tenant to create Azure VMs. Scattered Spider has also created Amazon EC2 instances within the victim's environment.

### T1578.003 - Modify Cloud Compute Infrastructure: Delete Cloud Instance

Procedures:

- [G1004] LAPSUS$: LAPSUS$ has deleted the target's systems and resources in the cloud to trigger the organization's incident and crisis response process.

### T1578.004 - Modify Cloud Compute Infrastructure: Revert Cloud Instance

### T1578.005 - Modify Cloud Compute Infrastructure: Modify Cloud Compute Configurations


### T1599.001 - Network Boundary Bridging: Network Address Translation Traversal


### T1600.001 - Weaken Encryption: Reduce Key Space

### T1600.002 - Weaken Encryption: Disable Crypto Hardware


### T1601.001 - Modify System Image: Patch System Image

Procedures:

- [S0519] SYNful Knock: SYNful Knock is malware that is inserted into a network device by patching the operating system image.

### T1601.002 - Modify System Image: Downgrade System Image


### T1610 - Deploy Container

Procedures:

- [S0599] Kinsing: Kinsing was run through a deployed Ubuntu container.
- [G0139] TeamTNT: TeamTNT has deployed different types of containers into victim environments to facilitate execution. TeamTNT has also transferred cryptocurrency mining software to Kubernetes clusters discovered within local IP address ranges.
- [S0683] Peirates: Peirates can deploy a pod that mounts its node’s root file system, then execute a command to create a reverse shell on the node.
- [S0600] Doki: Doki was run through a deployed container.


### T1612 - Build Image on Host


### T1620 - Reflective Code Loading

Procedures:

- [S1081] BADHATCH: BADHATCH can copy a large byte array of 64-bit shellcode into process memory and execute it with a call to `CreateThread`.
- [S0689] WhisperGate: WhisperGate's downloader can reverse its third stage file bytes and reflectively load the file as a .NET assembly.
- [S0022] Uroburos: Uroburos has the ability to load new modules directly into memory using its `Load Modules Mem` command.
- [S0692] SILENTTRINITY: SILENTTRINITY can run a .NET executable within the memory of a sacrificial process by loading the CLR.
- [S0194] PowerSploit: PowerSploit reflectively loads a Windows PE file into a process.
- [S0447] Lokibot: Lokibot has reflectively loaded the decoded DLL into memory.
- [S0666] Gelsemium: Gelsemium can use custom shellcode to map embedded DLLs into memory.
- [S1059] metaMain: metaMain has reflectively loaded a DLL to read, decrypt, and load an orchestrator file.
- [G0032] Lazarus Group: Lazarus Group has changed memory protection permissions then overwritten in memory DLL function code with shellcode, which was later executed via KernelCallbackTable hijacking. Lazarus Group has also used shellcode within macros to decrypt and manually map DLLs into memory at runtime.
- [G0094] Kimsuky: Kimsuky has used the Invoke-Mimikatz PowerShell script to reflectively load a Mimikatz credential stealing DLL into memory.
- [S0625] Cuba: Cuba loaded the payload into memory using PowerShell.
- [S0154] Cobalt Strike: Cobalt Strike's execute-assembly command can run a .NET executable within the memory of a sacrificial process by loading the CLR.
- [S1063] Brute Ratel C4: Brute Ratel C4 has used reflective loading to execute malicious DLLs.
- [S1022] IceApple: IceApple can use reflective code loading to load .NET assemblies into `MSExchangeOWAAppPool` on targeted Exchange servers.
- [S1145] Pikabot: Pikabot reflectively loads stored, previously encrypted components of the PE file into memory of the currently executing process to avoid writing content to disk on the executing machine.


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


### T1647 - Plist File Modification

Procedures:

- [S1153] Cuckoo Stealer: Cuckoo Stealer can create and populate property list (plist) files to enable execution.
- [S0658] XCSSET: In older versions, XCSSET uses the plutil command to modify the LSUIElement, DFBundleDisplayName, and CFBundleIdentifier keys in the /Contents/Info.plist file to change how XCSSET is visible on the system. In later versions, XCSSET leverages a third-party notarized `dockutil` tool to modify the `.plist` file responsible for presenting applications to the user in the Dock and LaunchPad to point to a malicious application.


### T1656 - Impersonation

Procedures:

- [G1046] Storm-1811: Storm-1811 impersonates help desk and IT support personnel for phishing and social engineering purposes during initial access to victim environments.
- [G1004] LAPSUS$: LAPSUS$ has called victims' help desk and impersonated legitimate users with previously gathered information in order to gain access to privileged accounts.
- [G1031] Saint Bear: Saint Bear has impersonated government and related entities in both phishing activity and developing web sites with malicious links that mimic legitimate resources.
- [G1044] APT42: APT42 has impersonated legitimate people in phishing emails to gain credentials.
- [C0022] Operation Dream Job: During Operation Dream Job, Lazarus Group impersonated HR hiring personnel through LinkedIn messages and conducted interviews with victims in order to deceive them into downloading malware.
- [G0094] Kimsuky: Kimsuky has impersonated academic institutions and NGOs in order to gain information related to North Korea.
- [C0027] C0027: During C0027, Scattered Spider impersonated legitimate IT personnel in phone calls and text messages either to direct victims to a credential harvesting site or getting victims to run commercial remote monitoring and management (RMM) tools.
- [G0096] APT41: APT41 impersonated an employee at a video game developer company to send phishing emails.
- [S1131] NPPSPY: NPPSPY creates a network listener using the misspelled label logincontroll recorded to the Registry key HKLM\\SYSTEM\\CurrentControlSet\\Control\\NetworkProvider\\Order.
- [G1015] Scattered Spider: During C0027, Scattered Spider impersonated legitimate IT personnel in phone calls and text messages either to direct victims to a credential harvesting site or getting victims to run commercial remote monitoring and management (RMM) tools. Scattered Spider utilized social engineering to compel IT help desk personnel to reset passwords and MFA tokens.


### T1666 - Modify Cloud Resource Hierarchy


### T1672 - Email Spoofing

