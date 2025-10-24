### T1001.001 - Data Obfuscation: Junk Data

Procedures:

- [S0016] P2P ZeuS: P2P ZeuS added junk data to outgoing UDP packets to peer implants.
- [S0134] Downdelph: Downdelph inserts pseudo-random characters between each original character during encoding of C2 network requests, making it difficult to write signatures on them.
- [S1047] Mori: Mori has obfuscated the FML.dll with 200MB of junk data.
- [S0574] BendyBear: BendyBear has used byte randomization to obscure its behavior.
- [S0682] TrailBlazer: TrailBlazer has used random identifier strings to obscure its C2 operations and result codes.
- [S0022] Uroburos: Uroburos can add extra characters in encoded strings to help mimic DNS legitimate requests.
- [S0626] P8RAT: P8RAT can send randomly-generated data as part of its C2 communication.
- [S0435] PLEAD: PLEAD samples were found to be highly obfuscated with junk code.
- [S1164] UPSTYLE: UPSTYLE retrieves a non-existent webpage from the command and control server then parses commands from the resulting error logs to decode commands to the web shell.
- [S1020] Kevin: Kevin can generate a sequence of dummy HTTP C2 requests to obscure traffic.
- [S0588] GoldMax: GoldMax has used decoy traffic to surround its malicious network traffic to avoid detection.
- [S0559] SUNBURST: SUNBURST added junk bytes to its C2 over HTTP.
- [S0647] Turian: Turian can insert pseudo-random characters into its network encryption setup.
- [S0632] GrimAgent: GrimAgent can pad C2 messages with random generated values.
- [G0007] APT28: APT28 added "junk data" to each encoded string, preventing trivial decoding without knowledge of the junk removal algorithm. Each implant was given a "junk length" value when created, tracked by the controller software to allow seamless communication but prevent analysis of the command protocol on the wire.

### T1001.002 - Data Obfuscation: Steganography

Procedures:

- [S1141] LunarWeb: LunarWeb can receive C2 commands hidden in the structure of .jpg and .gif images.
- [G0001] Axiom: Axiom has used steganography to hide its C2 communications.
- [S0037] HAMMERTOSS: HAMMERTOSS is controlled via commands that are appended to image files.
- [S0633] Sliver: Sliver can encode binary data into a .PNG file for C2 communication.
- [C0023] Operation Ghost: During Operation Ghost, APT29 used steganography to hide the communications between the implants and their C&C servers.
- [S0672] Zox: Zox has used the .PNG file format for C2 communications.
- [S0395] LightNeuron: LightNeuron is controlled via commands that are embedded into PDFs and JPGs using steganographic methods.
- [S0230] ZeroT: ZeroT has retrieved stage 2 payloads as Bitmap images that use Least Significant Bit (LSB) steganography.
- [S0187] Daserf: Daserf can use steganography to hide malicious code downloaded to the victim.
- [S0495] RDAT: RDAT can process steganographic images attached to email messages to send and receive C2 commands. RDAT can also embed additional messages within BMP images to communicate with the RDAT operator.
- [S1142] LunarMail: LunarMail can parse IDAT chunks from .png files to look for zlib-compressed and AES encrypted C2 commands.
- [S0038] Duqu: When the Duqu command and control is operating over HTTP or HTTPS, Duqu uploads data to its controller by appending it to a blank JPG file.
- [S0559] SUNBURST: SUNBURST C2 data attempted to appear as benign XML related to .NET assemblies or as a faux JSON blob.

### T1001.003 - Data Obfuscation: Protocol or Service Impersonation

Procedures:

- [G0032] Lazarus Group: Lazarus Group malware also uses a unique form of communication encryption known as FakeTLS that mimics TLS but uses a different encryption method, potentially evading SSL traffic inspection/decryption.
- [S1120] FRAMESTING: FRAMESTING uses a cookie named `DSID` to mimic the name of a cookie used by Ivanti Connect Secure appliances for maintaining VPN sessions.
- [S0154] Cobalt Strike: Cobalt Strike can leverage the HTTP protocol for C2 communication, while hiding the actual data in either an HTTP header, URI parameter, the transaction body, or appending it to the URI.
- [S0245] BADCALL: BADCALL uses a FakeTLS method during C2.
- [S0387] KeyBoy: KeyBoy uses custom SSL libraries to impersonate SSL in C2 traffic.
- [G0126] Higaisa: Higaisa used a FakeTLS session for C2 communications.
- [S0586] TAINTEDSCRIBE: TAINTEDSCRIBE has used FakeTLS for session authentication.
- [S0239] Bankshot: Bankshot generates a false TLS handshake using a public certificate to disguise C2 network communications.
- [S0246] HARDRAIN: HARDRAIN uses FakeTLS to communicate with its C2 server.
- [S0022] Uroburos: Uroburos can use custom communication methodologies that ride over common protocols including TCP, UDP, HTTP, SMTP, and DNS in order to blend with normal network traffic.
- [S0559] SUNBURST: SUNBURST masqueraded its network traffic as the Orion Improvement Program (OIP) protocol.
- [C0017] C0017: During C0017, APT41 frequently configured the URL endpoints of their stealthy passive backdoor LOWKEY.PASSIVE to masquerade as normal web application traffic on an infected server.
- [S0260] InvisiMole: InvisiMole can mimic HTTP protocol with custom HTTP “verbs” HIDE, ZVVP, and NOP.
- [S1100] Ninja: Ninja has the ability to mimic legitimate services with customized HTTP URL paths and headers to hide malicious traffic.
- [S0076] FakeM: FakeM C2 traffic attempts to evade detection by resembling data generated by legitimate messenger applications, such as MSN and Yahoo! messengers. Additionally, some variants of FakeM use modified SSL code for communications back to C2 servers, making SSL decryption ineffective.


### T1008 - Fallback Channels

Procedures:

- [S0044] JHUHUGIT: JHUHUGIT tests if it can reach its C2 server by first attempting a direct connection, and if it fails, obtaining proxy settings and sending the connection through a proxy, and finally injecting code into a running browser if the proxy method fails.
- [S0211] Linfo: Linfo creates a backdoor through which remote attackers can change C2 servers.
- [S0023] CHOPSTICK: CHOPSTICK can switch to a new C2 channel if the current one is broken.
- [G0049] OilRig: OilRig malware ISMAgent falls back to its DNS tunneling mechanism if it is unable to reach the C2 server over HTTP.
- [S0376] HOPLIGHT: HOPLIGHT has multiple C2 channels in place in case one fails.
- [S0260] InvisiMole: InvisiMole has been configured with several servers available for alternate C2 communications.
- [S0058] SslMM: SslMM has a hard-coded primary and backup C2 string.
- [S0377] Ebury: Ebury has implemented a fallback mechanism to begin using a DGA when the attacker hasn't connected to the infected system for three days.
- [S0017] BISCUIT: BISCUIT malware contains a secondary fallback command and control server that is contacted after the primary command and control server.
- [S0266] TrickBot: TrickBot can use secondary C2 servers for communication after establishing connectivity and relaying victim information to primary C2 servers.
- [S0476] Valak: Valak can communicate over multiple C2 hosts.
- [S0085] S-Type: S-Type primarily uses port 80 for C2, but falls back to ports 443 or 8080 if initial communication fails.
- [S0512] FatDuke: FatDuke has used several C2 servers per targeted organization.
- [S1084] QUIETEXIT: QUIETEXIT can attempt to connect to a second hard-coded C2 if the first hard-coded C2 address fails.
- [S1019] Shark: Shark can update its configuration to use a different C2 server.


### T1071.001 - Application Layer Protocol: Web Protocols

Procedures:

- [S1047] Mori: Mori can communicate using HTTP over IPv4 or IPv6 depending on a flag set.
- [S0275] UPPERCUT: UPPERCUT has used HTTP for C2, including sending error codes in Cookie headers.
- [S0495] RDAT: RDAT can use HTTP communications for C2, as well as using the WinHTTP library to make requests to the Exchange Web Services API.
- [S1108] PULSECHECK: PULSECHECK can check HTTP request headers for a specific backdoor key and if found will output the result of the command in the variable `HTTP_X_CMD.`
- [S0207] Vasport: Vasport creates a backdoor by making a connection using a HTTP POST.
- [S0502] Drovorub: Drovorub can use the WebSocket protocol and has initiated communication with C2 servers with an HTTP Upgrade request.
- [S0144] ChChes: ChChes communicates to its C2 server over HTTP and embeds data within the Cookie HTTP header.
- [S1023] CreepyDrive: CreepyDrive can use HTTPS for C2 using the Microsoft Graph API.
- [S0091] Epic: Epic uses HTTP and HTTPS for C2 communications.
- [S1026] Mongall: Mongall can use HTTP for C2 communication.
- [S0341] Xbash: Xbash uses HTTP for C2 communications.
- [S0578] SUPERNOVA: SUPERNOVA had to receive an HTTP GET request containing a specific set of parameters in order to execute.
- [S1119] LIGHTWIRE: LIGHTWIRE can use HTTP for C2 communications.
- [S0653] xCaon: xCaon has communicated with the C2 server by sending POST requests over HTTP.
- [G0075] Rancor: Rancor has used HTTP for C2.

### T1071.002 - Application Layer Protocol: File Transfer Protocols

Procedures:

- [S0428] PoetRAT: PoetRAT has used FTP for C2 communications.
- [G0096] APT41: APT41 used exploit payloads that initiate download via ftp.
- [S0699] Mythic: Mythic supports SMB-based peer-to-peer C2 profiles.
- [S0465] CARROTBALL: CARROTBALL has the ability to use FTP in C2 communications.
- [S0019] Regin: The Regin malware platform supports many standard protocols, including SMB.
- [S0409] Machete: Machete uses FTP for Command & Control.
- [S0161] XAgentOSX: XAgentOSX contains the ftpUpload function to use the FTPManager:uploadFile method to upload files from the target system.
- [S0201] JPIN: JPIN can communicate over FTP.
- [S0265] Kazuar: Kazuar uses FTP and FTPS to communicate with the C2 server.
- [S0438] Attor: Attor has used FTP protocol for C2 communication.
- [S1089] SharpDisco: SharpDisco has the ability to transfer data between SMB shares.
- [C0006] Operation Honeybee: During Operation Honeybee, the threat actors had the ability to use FTP for C2.
- [S0412] ZxShell: ZxShell has used FTP for C2 connections.
- [S0596] ShadowPad: ShadowPad has used FTP for C2 communications.
- [G0035] Dragonfly: Dragonfly has used SMB for C2.

### T1071.003 - Application Layer Protocol: Mail Protocols

Procedures:

- [S0126] ComRAT: ComRAT can use email attachments for command and control.
- [S0395] LightNeuron: LightNeuron uses SMTP for C2.
- [S0137] CORESHELL: CORESHELL can communicate over SMTP and POP3 for C2.
- [S0337] BadPatch: BadPatch uses SMTP for C2.
- [S0023] CHOPSTICK: Various implementations of CHOPSTICK communicate with C2 over SMTP and POP3.
- [G0010] Turla: Turla has used multiple backdoors which communicate with a C2 server via email attachments.
- [S0022] Uroburos: Uroburos can use custom communications protocols that ride over SMTP.
- [S0201] JPIN: JPIN can send email over SMTP.
- [S0125] Remsec: Remsec is capable of using SMTP for C2.
- [S0247] NavRAT: NavRAT uses the email platform, Naver, for C2 communications, leveraging SMTP.
- [G0083] SilverTerrier: SilverTerrier uses SMTP for C2 communications.
- [S0351] Cannon: Cannon uses SMTP/S and POP3/S for C2 communications by sending and receiving emails.
- [S0251] Zebrocy: Zebrocy uses SMTP and POP3 for C2.
- [S0138] OLDBAIT: OLDBAIT can use SMTP for C2.
- [G0050] APT32: APT32 has used email for C2 via an Office macro.

### T1071.004 - Application Layer Protocol: DNS

Procedures:

- [S0477] Goopy: Goopy has the ability to communicate with its C2 over DNS.
- [S0269] QUADAGENT: QUADAGENT uses DNS for C2 communications.
- [S0354] Denis: Denis has used DNS tunneling for C2 communications.
- [S0663] SysUpdate: SysUpdate has used DNS TXT requests as for its C2 communication.
- [S1111] DarkGate: DarkGate can cloak command and control traffic in DNS records from legitimate services to avoid reputation-based detection techniques.
- [S0146] TEXTMATE: TEXTMATE uses DNS TXT records for C2.
- [S1020] Kevin: Variants of Kevin can communicate over DNS through queries to the server for constructed domain names with embedded information.
- [S1015] Milan: Milan has the ability to use DNS for C2 communications.
- [S0377] Ebury: Ebury has used DNS requests over UDP port 53 for C2.
- [S0170] Helminth: Helminth can use DNS for C2.
- [S0699] Mythic: Mythic supports DNS-based C2 profiles.
- [S0495] RDAT: RDAT has used DNS to communicate with the C2.
- [G0114] Chimera: Chimera has used Cobalt Strike to encapsulate C2 in DNS traffic.
- [S0184] POWRUNER: POWRUNER can use DNS for C2 communications.
- [C0029] Cutting Edge: During Cutting Edge, threat actors used DNS to tunnel IPv4 C2 traffic.

### T1071.005 - Application Layer Protocol: Publish/Subscribe Protocols

Procedures:

- [S0026] GLOOXMAIL: GLOOXMAIL communicates to servers operated by Google using the Jabber/XMPP protocol for C2.


### T1090.001 - Proxy: Internal Proxy

Procedures:

- [G1047] Velvet Ant: Velvet Ant has tunneled traffic from victims through an internal, compromised host to proxy communications to command and control nodes.
- [S0556] Pay2Key: Pay2Key has designated machines in the compromised network to serve as reverse proxy pivot points to channel communications with C2.
- [S0038] Duqu: Duqu can be configured to have commands relayed over a peer-to-peer network of infected hosts if some of the hosts do not have Internet access.
- [C0024] SolarWinds Compromise: During the SolarWinds Compromise, APT29 used SSH port forwarding capabilities on public-facing systems, and configured at least one instance of Cobalt Strike to use a network pipe over SMB.
- [S0023] CHOPSTICK: CHOPSTICK used a proxy server between victims and the C2 server.
- [G1016] FIN13: FIN13 has utilized a proxy tool to communicate between compromised assets.
- [S0502] Drovorub: Drovorub can use a port forwarding rule on its agent module to relay network traffic through the client module to a remote host on the same network.
- [S0154] Cobalt Strike: Cobalt Strike can be configured to have commands relayed over a peer-to-peer network of infected hosts. This can be used to limit the number of egress points, or provide access to a host without direct internet access.
- [G0126] Higaisa: Higaisa discovered system proxy settings and used them if available.
- [S1060] Mafalda: Mafalda can create a named pipe to listen for and send data to a named pipe-based C2 server.
- [S0699] Mythic: Mythic can leverage a peer-to-peer C2 profile between agents.
- [G0030] Lotus Blossom: Lotus Blossom has used publicly available tools such as the Venom proxy tool to proxy traffic out of victim environments.
- [S0141] Winnti for Windows: The Winnti for Windows HTTP/S C2 mode can make use of a local proxy.
- [G0041] Strider: Strider has used local servers with both local network and Internet access to act as internal proxy nodes to exfiltrate data from other parts of the network without direct Internet access.
- [S0051] MiniDuke: MiniDuke can can use a named pipe to forward communications from one compromised machine with internet access to other compromised machines.

### T1090.002 - Proxy: External Proxy

Procedures:

- [S1084] QUIETEXIT: QUIETEXIT can proxy traffic via SOCKS.
- [G0087] APT39: APT39 has used various tools to proxy C2 communications.
- [S0444] ShimRat: ShimRat can use pre-configured HTTP proxies.
- [S0650] QakBot: QakBot has a module that can proxy C2 communications.
- [G0007] APT28: APT28 used other victims as proxies to relay command traffic, for instance using a compromised Georgian military email server as a hop point to NATO victims. The group has also used a tool that acts as a proxy to allow C2 even if the victim is behind a router. APT28 has also used a machine to relay and obscure communications between CHOPSTICK and their server.
- [G0053] FIN5: FIN5 maintains access to victim environments by using FLIPSIDE to create a proxy for a backup RDP tunnel.
- [G0131] Tonto Team: Tonto Team has routed their traffic through an external server in order to obfuscate their location.
- [S0699] Mythic: Mythic can leverage a modified SOCKS5 proxy to tunnel egress C2 traffic.
- [S0141] Winnti for Windows: The Winnti for Windows HTTP/S C2 mode can make use of an external proxy.
- [G0032] Lazarus Group: Lazarus Group has used multiple proxies to obfuscate network traffic from victims.
- [G0045] menuPass: menuPass has used a global service provider's IP as a proxy for C2 traffic from a victim.
- [G0022] APT3: An APT3 downloader establishes SOCKS5 connections for its initial C2.
- [S0019] Regin: Regin leveraged several compromised universities as proxies to obscure its origin.
- [S0223] POWERSTATS: POWERSTATS has connected to C2 servers through proxies.
- [G0091] Silence: Silence has used ProxyBot, which allows the attacker to redirect traffic from the current node to the backconnect server via Sock4\Socks5.

### T1090.003 - Proxy: Multi-hop Proxy

Procedures:

- [S0276] Keydnap: Keydnap uses a copy of tor2web proxy for HTTPS communications.
- [S0282] MacSpy: MacSpy uses Tor for command and control.
- [S0342] GreyEnergy: GreyEnergy has used Tor relays for Command and Control servers.
- [G1003] Ember Bear: Ember Bear has configured multi-hop proxies via ProxyChains within victim environments.
- [S0386] Ursnif: Ursnif has used Tor for C2.
- [S0438] Attor: Attor has used Tor for C2 communication.
- [G0007] APT28: APT28 has routed traffic over Tor and VPN servers to obfuscate their activities.
- [C0004] CostaRicto: During CostaRicto, the threat actors used a layer of proxies to manage C2 communications.
- [G0100] Inception: Inception used chains of compromised routers to proxy C2 communications between them and cloud service providers.
- [G0065] Leviathan: Leviathan has used multi-hop proxies to disguise the source of their malicious traffic.
- [C0014] Operation Wocao: During Operation Wocao, threat actors executed commands through the installed web shell via Tor exit nodes.
- [S0022] Uroburos: Uroburos can use implants on multiple compromised machines to proxy communications through its worldwide P2P network.
- [G0085] FIN4: FIN4 has used Tor to log in to victims' email accounts.
- [S0623] Siloscape: Siloscape uses Tor to communicate with C2.
- [G0016] APT29: A backdoor used by APT29 created a Tor hidden service to forward traffic from the Tor client to local ports 3389 (RDP), 139 (Netbios), and 445 (SMB) enabling full remote access from outside the network and has also used TOR.

### T1090.004 - Proxy: Domain Fronting

Procedures:

- [S0154] Cobalt Strike: Cobalt Strike has the ability to accept a value for HTTP Host Header to enable domain fronting.
- [G0016] APT29: APT29 has used the meek domain fronting plugin for Tor to hide the destination of C2 traffic.
- [S0175] meek: meek uses Domain Fronting to disguise the destination of network traffic as another server that is hosted in the same Content Delivery Network (CDN) as the intended destination.
- [S0699] Mythic: Mythic supports domain fronting via custom request headers.
- [S0649] SMOKEDHAM: SMOKEDHAM has used a fronted domain to obfuscate its hard-coded C2 server domain.


### T1092 - Communication Through Removable Media

Procedures:

- [S0023] CHOPSTICK: Part of APT28's operation involved using CHOPSTICK modules to copy itself to air-gapped machines, using files written to USB sticks to transfer data and command traffic.
- [G0007] APT28: APT28 uses a tool that captures information from air-gapped computers via an infected USB and transfers it to network-connected computer when the USB is inserted.
- [S0136] USBStealer: USBStealer drops commands for a second victim onto a removable media drive inserted into the first victim, and commands are executed when the drive is inserted into the second victim.


### T1095 - Non-Application Layer Protocol

Procedures:

- [S1144] FRP: FRP can communicate over TCP, TCP stream multiplexing, KERN Communications Protocol (KCP), QUIC, and UDP.
- [S0352] OSX_OCEANLOTUS.D: OSX_OCEANLOTUS.D has used a custom binary protocol over port 443 for C2 traffic.
- [S0504] Anchor: Anchor has used ICMP in C2 communications.
- [S0076] FakeM: Some variants of FakeM use SSL to communicate with C2 servers.
- [S0456] Aria-body: Aria-body has used TCP in C2 communications.
- [S0660] Clambling: Clambling has the ability to use TCP and UDP for communication.
- [S1016] MacMa: MacMa has used a custom JSON-based protocol for its C&C communications.
- [S0155] WINDSHIELD: WINDSHIELD C2 traffic can communicate via TCP raw sockets.
- [S0666] Gelsemium: Gelsemium has the ability to use TCP and UDP in C2 communications.
- [S1204] cd00r: cd00r can monitor incoming C2 communications sent over TCP to the compromised host.
- [S0436] TSCookie: TSCookie can use ICMP to receive information on the destination server.
- [S1100] Ninja: Ninja can forward TCP packets between the C2 and a remote host.
- [S1203] J-magic: J-magic can monitor incoming C2 communications sent over TCP to the compromised host.
- [S0013] PlugX: PlugX can be configured to use raw TCP or UDP for command and control.
- [S1029] AuTo Stealer: AuTo Stealer can use TCP to communicate with command and control servers.


### T1102.001 - Web Service: Dead Drop Resolver

Procedures:

- [S0373] Astaroth: Astaroth can store C2 information on cloud hosting services such as AWS and CloudFlare and websites like YouTube and Facebook.
- [S0128] BADNEWS: BADNEWS collects C2 information via a dead drop resolver.
- [S1051] KEYPLUG: The KEYPLUG Windows variant has retrieved C2 addresses from encoded data in posts on tech community forums.
- [S0051] MiniDuke: Some MiniDuke components use Twitter to initially obtain the address of a C2 server or as a backup if no hard-coded C2 server responds.
- [S0531] Grandoreiro: Grandoreiro can obtain C2 information from Google Docs.
- [S0455] Metamorfo: Metamorfo has used YouTube to store and hide C&C server domains.
- [S0013] PlugX: PlugX uses Pastebin to store C2 addresses.
- [S0674] CharmPower: CharmPower can retrieve C2 domain information from actor-controlled S3 buckets.
- [S1201] TRANSLATEXT: TRANSLATEXT has used a dead drop resolver to retrieve configurations and commands from a public blog site.
- [G0106] Rocke: Rocke has used Pastebin to check the version of beaconing malware and redirect to another Pastebin hosting updated malware.
- [C0017] C0017: During C0017, APT41 used dead drop resolvers on two separate tech community forums for their KEYPLUG Windows-version backdoor; notably APT41 updated the community forum posts frequently with new dead drop resolvers during the campaign.
- [S0069] BLACKCOFFEE: BLACKCOFFEE uses Microsoft’s TechNet Web portal to obtain a dead drop resolver containing an encoded tag with the IP address of a command and control server.
- [S0148] RTM: RTM has used an RSS feed on Livejournal to update a list of encrypted C2 server names. RTM has also hidden Pony C2 server IP addresses within transactions on the Bitcoin and Namecoin blockchain.
- [G0096] APT41: APT41 used legitimate websites for C2 through dead drop resolvers (DDR), including GitHub, Pastebin, and Microsoft TechNet.
- [S0518] PolyglotDuke: PolyglotDuke can use Twitter, Reddit, Imgur and other websites to get a C2 URL.

### T1102.002 - Web Service: Bidirectional Communication

Procedures:

- [S0393] PowerStallion: PowerStallion uses Microsoft OneDrive as a C2 server via a network drive mapped with net use.
- [S0651] BoxCaon: BoxCaon has used DropBox for C2 communications.
- [C0023] Operation Ghost: For Operation Ghost, APT29 used social media platforms to hide communications to C2 servers.
- [S0538] Crutch: Crutch can use Dropbox to receive commands and upload stolen data.
- [S0660] Clambling: Clambling can use Dropbox to download malicious payloads, send commands, and receive information.
- [S0229] Orz: Orz has used Technet and Pastebin web pages for command and control.
- [S0025] CALENDAR: The CALENDAR malware communicates through the use of events in Google Calendar.
- [S0046] CozyCar: CozyCar uses Twitter as a backup C2 channel to Twitter accounts specified in its configuration file.
- [S0248] yty: yty communicates to the C2 server by retrieving a Google Doc.
- [G0094] Kimsuky: Kimsuky has used Blogspot pages and a Github repository for C2.
- [S0218] SLOWDRIFT: SLOWDRIFT uses cloud based services for C2.
- [S1170] ODAgent: ODAgent can use the Microsoft Graph API to access an attacker-controlled OneDrive account and retrieve payloads and backdoor commands.
- [S0531] Grandoreiro: Grandoreiro can utilize web services including Google sites to send and receive C2 data.
- [G1005] POLONIUM: POLONIUM has used OneDrive and DropBox for C2.
- [G0067] APT37: APT37 leverages social networking sites and cloud platforms (AOL, Twitter, Yandex, Mediafire, pCloud, Dropbox, and Box) for C2.

### T1102.003 - Web Service: One-Way Communication

Procedures:

- [C0046] ArcaneDoor: ArcaneDoor utilized HTTP command and control traffic where commands are intercepted from HTTP traffic to the device, parsed for appropriate identifiers and commands, and then executed.
- [S0568] EVILNUM: EVILNUM has used a one-way communication method via GitLab and Digital Point to perform C2.
- [G0065] Leviathan: Leviathan has received C2 instructions from user profiles created on legitimate websites such as Github and TechNet.
- [G0047] Gamaredon Group: Gamaredon Group has used Telegram Messenger content to discover the IP address for C2 communications.
- [S1210] Sagerunex: Sagerunex has used web services such as Twitter for command and control purposes.
- [S0455] Metamorfo: Metamorfo has downloaded a zip file for execution on the system.
- [S0052] OnionDuke: OnionDuke uses Twitter as a backup C2.
- [S1164] UPSTYLE: UPSTYLE parses encoded commands from error logs after attempting to resolve a non-existing webpage from the command and control server.
- [S0037] HAMMERTOSS: The "tDiscoverer" variant of HAMMERTOSS establishes a C2 channel by downloading resources from Web services like Twitter and GitHub. HAMMERTOSS binaries contain an algorithm that generates a different Twitter handle for the malware to check for instructions every day.


### T1104 - Multi-Stage Channels

Procedures:

- [G0022] APT3: An APT3 downloader first establishes a SOCKS5 connection to 192.157.198[.]103 using TCP port 1913; once the server response is verified, it then requests a connection to 192.184.60[.]229 on TCP port 81.
- [S1141] LunarWeb: LunarWeb can use one C2 URL for first contact and to upload information about the host computer and two additional C2 URLs for getting commands.
- [S0069] BLACKCOFFEE: BLACKCOFFEE uses Microsoft’s TechNet Web portal to obtain an encoded tag containing the IP address of a command and control server and then communicates separately with that IP address for C2. If the C2 server is discovered or shut down, the threat actors can update the encoded IP address on TechNet to maintain control of the victims’ machines.
- [G0032] Lazarus Group: Lazarus Group has used multi-stage malware components that inject later stages into separate processes.
- [S0476] Valak: Valak can download additional modules and malware capable of using separate C2 channels.
- [S1206] JumbledPath: JumbledPath can communicate over a unique series of connections to send and retrieve data from exploited devices.
- [S0534] Bazar: The Bazar loader is used to download and execute the Bazar backdoor.
- [S1086] Snip3: Snip3 can download and execute additional payloads and modules over separate communication channels.
- [S1160] Latrodectus: Latrodectus has used a two-tiered C2 configuration with tier one nodes connecting to the victim and tier two nodes connecting to backend infrastructure.
- [S0022] Uroburos: Individual Uroburos implants can use multiple communication channels based on one of four available modes of operation.
- [G0069] MuddyWater: MuddyWater has used one C2 to obtain enumeration scripts and monitor web logs, but a different C2 to send data back.
- [S0031] BACKSPACE: BACKSPACE attempts to avoid detection by checking a first stage command and control server to determine if it should connect to the second stage server, which performs "louder" interactions with the malware.
- [S0220] Chaos: After initial compromise, Chaos will download a second stage to establish a more permanent presence on the affected system.
- [G0096] APT41: APT41 used the storescyncsvc.dll BEACON backdoor to download a secondary backdoor.


### T1105 - Ingress Tool Transfer

Procedures:

- [G0117] Fox Kitten: Fox Kitten has downloaded additional tools including PsExec directly to endpoints.
- [S0396] EvilBunny: EvilBunny has downloaded additional Lua scripts from the C2.
- [S0664] Pandora: Pandora can load additional drivers and files onto a victim machine.
- [S0444] ShimRat: ShimRat can download additional files.
- [S1118] BUSHWALK: BUSHWALK can write malicious payloads sent through a web request’s command parameter.
- [S1066] DarkTortilla: DarkTortilla can download additional packages for keylogging, cryptocurrency mining, and other capabilities; it can also retrieve malicious payloads such as Agent Tesla, AsyncRat, NanoCore, RedLine, Cobalt Strike, and Metasploit.
- [S0627] SodaMaster: SodaMaster has the ability to download additional payloads from C2 to the targeted system.
- [G1002] BITTER: BITTER has downloaded additional malware and tools onto a compromised host.
- [S1019] Shark: Shark can download additional files from its C2 via HTTP or DNS.
- [S0284] More_eggs: More_eggs can download and launch additional payloads.
- [S0185] SEASHARPEE: SEASHARPEE can download remote files onto victims.
- [S0515] WellMail: WellMail can receive data and executable scripts from C2.
- [G0125] HAFNIUM: HAFNIUM has downloaded malware and tools--including Nishang and PowerCat--onto a compromised host.
- [G0080] Cobalt Group: Cobalt Group has used public sites such as github.com and sendspace.com to upload files and then download them to victim computers. The group's JavaScript backdoor is also capable of downloading files.
- [S0255] DDKONG: DDKONG downloads and uploads files on the victim’s machine.


### T1132.001 - Data Encoding: Standard Encoding

Procedures:

- [S0610] SideTwist: SideTwist has used Base64 for encoded C2 traffic.
- [S0410] Fysbis: Fysbis can use Base64 to encode its C2 traffic.
- [S1021] DnsSystem: DnsSystem can Base64 encode data sent to C2.
- [S0045] ADVSTORESHELL: C2 traffic from ADVSTORESHELL is encrypted, then encoded with Base64 encoding.
- [S0696] Flagpro: Flagpro has encoded bidirectional data communications between a target system and C2 server using Base64.
- [S0603] Stuxnet: Stuxnet transforms encrypted binary data into an ASCII string in order to use it as a URL parameter value.
- [S0053] SeaDuke: SeaDuke C2 traffic is base64-encoded.
- [S1160] Latrodectus: Latrodectus has Base64-encoded the message body of a HTTP request sent to C2.
- [S1196] Troll Stealer: Troll Stealer performs XOR encryption and Base64 encoding of data prior to sending to command and control infrastructure.
- [G0034] Sandworm Team: Sandworm Team's BCS-server tool uses base64 encoding and HTML tags for the communication traffic between the C2 server.
- [S0663] SysUpdate: SysUpdate has used Base64 to encode its C2 traffic.
- [S0631] Chaes: Chaes has used Base64 to encode C2 communications.
- [S1020] Kevin: Kevin can Base32 encode chunks of output files during exfiltration.
- [S0472] down_new: down_new has the ability to base64 encode C2 communications.
- [G0040] Patchwork: Patchwork used Base64 to encode C2 traffic.

### T1132.002 - Data Encoding: Non-Standard Encoding

Procedures:

- [S0346] OceanSalt: OceanSalt can encode data with a NOT operation before sending the data to the control server.
- [S1035] Small Sieve: Small Sieve can use a custom hex byte swapping encoding scheme to obfuscate tasking traffic.
- [S1090] NightClub: NightClub has used a non-standard encoding in DNS tunneling removing any `=` from the result of base64 encoding, and replacing `/` characters with `-s` and `+` characters with `-p`.
- [S0495] RDAT: RDAT can communicate with the C2 via subdomains that utilize base64 with character substitutions.
- [S0260] InvisiMole: InvisiMole can use a modified base32 encoding to encode data within the subdomain of C2 requests.
- [S0022] Uroburos: Uroburos can use a custom base62 and a de-facto base32 encoding that uses digits 0-9 and lowercase letters a-z in C2 communications.
- [S1189] Neo-reGeorg: Neo-reGeorg can use modified Base64 encoding to obfuscate communications.
- [S0031] BACKSPACE: Newer variants of BACKSPACE will encode C2 communications with a custom system.
- [S1149] CHIMNEYSWEEP: CHIMNEYSWEEP can use a custom Base64 alphabet for encoding C2.
- [S0239] Bankshot: Bankshot encodes commands from the control server using a range of characters and gzip.
- [S0596] ShadowPad: ShadowPad has encoded data as readable Latin characters.
- [S0687] Cyclops Blink: Cyclops Blink can use a custom binary scheme to encode messages with specific commands and parameters to be executed.
- [S1100] Ninja: Ninja can encode C2 communications with a base64 algorithm using a custom alphabet.
- [S1046] PowGoop: PowGoop can use a modified Base64 encoding mechanism to send data to and from the C2 server.


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


### T1219.001 - Remote Access Tools: IDE Tunneling

### T1219.002 - Remote Access Tools: Remote Desktop Software

Procedures:

- [G0120] Evilnum: EVILNUM has used the malware variant, TerraTV, to run a legitimate TeamViewer application to connect to compromised machines.
- [G1046] Storm-1811: Storm-1811 has abused multiple types of legitimate remote access software and tools, such as ScreenConnect, NetSupport Manager, and AnyDesk.
- [G0129] Mustang Panda: Mustang Panda has installed TeamViewer on targeted systems.
- [C0018] C0018: During C0018, the threat actors used AnyDesk to transfer tools between systems.
- [G0094] Kimsuky: Kimsuky has used a modified TeamViewer client as a command and control channel.
- [G0076] Thrip: Thrip used a cloud-based remote access software called LogMeIn for their attacks.
- [G0048] RTM: RTM has used a modified version of TeamViewer and Remote Utilities for remote access.
- [C0015] C0015: During C0015, the threat actors installed the AnyDesk remote desktop application onto the compromised network.

### T1219.003 - Remote Access Tools: Remote Access Hardware


### T1568.001 - Dynamic Resolution: Fast Flux DNS

Procedures:

- [S1025] Amadey: Amadey has used fast flux DNS for its C2.
- [G0045] menuPass: menuPass has used dynamic DNS service providers to host malicious domains.
- [G0092] TA505: TA505 has used fast flux to mask botnets by distributing payloads across multiple IPs.
- [S0032] gh0st RAT: gh0st RAT operators have used dynamic DNS to mask the true location of their C2 behind rapidly changing IP addresses.
- [G0047] Gamaredon Group: Gamaredon Group has used fast flux DNS to mask their command and control channel behind rotating IP addresses.
- [S0385] njRAT: njRAT has used a fast flux DNS for C2 IP resolution.

### T1568.002 - Dynamic Resolution: Domain Generation Algorithms

Procedures:

- [S0456] Aria-body: Aria-body has the ability to use a DGA for C2 communications.
- [S0650] QakBot: QakBot can use domain generation algorithms in C2 communication.
- [S0600] Doki: Doki has used the DynDNS service and a DGA based on the Dogecoin blockchain to generate C2 domains.
- [S0051] MiniDuke: MiniDuke can use DGA to generate new Twitter URLs for C2.
- [S0150] POSHSPY: POSHSPY uses a DGA to derive command and control URLs from a word list.
- [S0673] DarkWatchman: DarkWatchman has used a DGA to generate a domain name for C2.
- [S0360] BONDUPDATER: BONDUPDATER uses a DGA to communicate with command and control servers.
- [G0096] APT41: APT41 has used DGAs to change their C2 servers monthly.
- [G0127] TA551: TA551 has used a DGA to generate URLs from executed macros.
- [S0608] Conficker: Conficker has used a DGA that seeds with the current UTC victim system date to generate domains.
- [S0023] CHOPSTICK: CHOPSTICK can use a DGA for Fallback Channels, domains are generated by concatenating words from lists.
- [S0508] ngrok: ngrok can provide DGA for C2 servers through the use of random URL strings that change every 12 hours.
- [S0386] Ursnif: Ursnif has used a DGA to generate domain names for C2.
- [S1015] Milan: Milan can use hardcoded domains as an input for domain generation algorithms.
- [S0615] SombRAT: SombRAT can use a custom DGA to generate a subdomain for C2.

### T1568.003 - Dynamic Resolution: DNS Calculation

Procedures:

- [G0005] APT12: APT12 has used multiple variants of DNS Calculation including multiplying the first two octets of an IP address and adding the third octet to that value in order to get a resulting command and control port.


### T1571 - Non-Standard Port

Procedures:

- [G0090] WIRTE: WIRTE has used HTTPS over ports 2083 and 2087 for C2.
- [S1211] Hannotog: Hannotog uses non-standard listening ports, such as UDP 5900, for command and control purposes.
- [G0091] Silence: Silence has used port 444 when sending data about the system from the client to the server.
- [S1031] PingPull: PingPull can use HTTPS over port 8080 for C2.
- [G1042] RedEcho: RedEcho has used non-standard ports such as TCP 8080 for HTTP communication.
- [S0367] Emotet: Emotet has used HTTP over ports such as 20, 22, 443, 7080, and 50000, in addition to using ports commonly associated with HTTP/S.
- [S0491] StrongPity: StrongPity has used HTTPS over port 1402 in C2 communication.
- [S0428] PoetRAT: PoetRAT used TLS to encrypt communications over port 143
- [S0493] GoldenSpy: GoldenSpy has used HTTP over ports 9005 and 9006 for network traffic, 9002 for C2 requests, 33666 as a WebSocket, and 8090 to download files.
- [S1155] Covenant: Covenant listeners and controllers can be configured to use non-standard ports.
- [S1049] SUGARUSH: SUGARUSH has used port 4585 for a TCP connection to its C2.
- [S1130] Raspberry Robin: Raspberry Robin will communicate via HTTP over port 8080 for command and control traffic.
- [C0014] Operation Wocao: During Operation Wocao, the threat actors used uncommon high ports for its backdoor C2, including ports 25667 and 47000.
- [S0515] WellMail: WellMail has been observed using TCP port 25, without using SMTP, to leverage an open port for secure command and control communications.
- [S0376] HOPLIGHT: HOPLIGHT has connected outbound over TCP port 443 with a FakeTLS method.


### T1572 - Protocol Tunneling

Procedures:

- [C0027] C0027: During C0027, Scattered Spider used SSH tunneling in targeted environments.
- [S1189] Neo-reGeorg: Neo-reGeorg can tunnel data in and out of targeted networks.
- [G1016] FIN13: FIN13 has utilized web shells and Java tools for tunneling capabilities to and from compromised assets.
- [C0032] C0032: During the C0032 campaign, TEMP.Veles used encrypted SSH-based PLINK tunnels to transfer tools and enable RDP connections throughout the environment.
- [S1027] Heyoka Backdoor: Heyoka Backdoor can use spoofed DNS requests to create a bidirectional tunnel between a compromised host and its C2 servers.
- [G0059] Magic Hound: Magic Hound has used Plink to tunnel RDP over SSH.
- [G0037] FIN6: FIN6 used the Plink command-line utility to create SSH tunnels to C2 servers.
- [G1045] Salt Typhoon: Salt Typhoon has modified device configurations to create and use Generic Routing Encapsulation (GRE) tunnels.
- [S1187] reGeorg: reGeorg can tunnel TCP sessions including RDP, SSH, and SMB through HTTP.
- [S1141] LunarWeb: LunarWeb can run a custom binary protocol under HTTPS for C2.
- [S0038] Duqu: Duqu uses a custom command and control protocol that communicates over commonly used ports, and is frequently encapsulated by application layer protocols.
- [S1044] FunnyDream: FunnyDream can connect to HTTP proxies via TCP to create a tunnel to C2.
- [G1003] Ember Bear: Ember Bear has used ProxyChains to tunnel protocols to internal networks.
- [S1020] Kevin: Kevin can use a custom protocol tunneled through DNS or HTTP.
- [S0604] Industroyer: Industroyer attempts to perform an HTTP CONNECT via an internal proxy to establish a tunnel.


### T1573.001 - Encrypted Channel: Symmetric Cryptography

Procedures:

- [S0384] Dridex: Dridex has encrypted traffic with RC4.
- [S0649] SMOKEDHAM: SMOKEDHAM has encrypted its C2 traffic with RC4.
- [S0260] InvisiMole: InvisiMole uses variations of a simple XOR encryption routine for C&C communications.
- [S0663] SysUpdate: SysUpdate has used DES to encrypt all C2 communications.
- [S0367] Emotet: Emotet is known to use RSA keys for encrypting C2 traffic.
- [S0113] Prikormka: Prikormka encrypts some C2 traffic with the Blowfish cipher.
- [S0066] 3PARA RAT: 3PARA RAT command and control commands are encrypted within the HTTP C2 channel using the DES algorithm in CBC mode with a key derived from the MD5 hash of the string HYF54&%9&jkMCXuiS. 3PARA RAT will use an 8-byte XOR key derived from the string HYF54&%9&jkMCXuiS if the DES decoding fails
- [S1202] LockBit 3.0: LockBit 3.0 can encrypt C2 communications with AES.
- [S0034] NETEAGLE: NETEAGLE will decrypt resources it downloads with HTTP requests by using RC4 with the key "ScoutEagle."
- [S0409] Machete: Machete has used AES to exfiltrate documents.
- [S0344] Azorult: Azorult can encrypt C2 traffic using XOR.
- [S0268] Bisonal: Bisonal variants reported on in 2014 and 2015 used a simple XOR cipher for C2. Some Bisonal samples encrypt C2 communications with RC4.
- [S0060] Sys10: Sys10 uses an XOR 0x1 loop to encrypt its C2 domain.
- [S0081] Elise: Elise encrypts exfiltrated data with RC4.
- [S0141] Winnti for Windows: Winnti for Windows can XOR encrypt C2 traffic.

### T1573.002 - Encrypted Channel: Asymmetric Cryptography

Procedures:

- [S0615] SombRAT: SombRAT can SSL encrypt C2 traffic.
- [S0022] Uroburos: Uroburos has used a combination of a Diffie-Hellman key exchange mixed with a pre-shared key (PSK) to encrypt its top layer of C2 communications.
- [S0687] Cyclops Blink: Cyclops Blink can encrypt C2 messages with AES-256-CBC sent underneath TLS. OpenSSL library functions are also used to encrypt each message using a randomly generated key and IV, which are then encrypted using a hard-coded RSA public key.
- [S1123] PITSTOP: PITSTOP has the ability to communicate over TLS.
- [G1018] TA2541: TA2541 has used TLS encrypted C2 communications including for campaigns using AsyncRAT.
- [C0014] Operation Wocao: During Operation Wocao, threat actors' proxy implementation "Agent" upgraded the socket in use to a TLS socket.
- [S0455] Metamorfo: Metamorfo's C2 communication has been encrypted using OpenSSL.
- [S0018] Sykipot: Sykipot uses SSL for encrypting C2 communications.
- [S0534] Bazar: Bazar can use TLS in C2 communications.
- [S0668] TinyTurla: TinyTurla has the ability to encrypt C2 traffic with SSL/TLS.
- [S1141] LunarWeb: LunarWeb can send short C2 commands, up to 512 bytes, encrypted with RSA-4096.
- [S0627] SodaMaster: SodaMaster can use a hardcoded RSA key to encrypt some of its C2 traffic.
- [S0126] ComRAT: ComRAT can use SSL/TLS encryption for its HTTP-based C2 channel. ComRAT has used public key cryptography with RSA and AES encrypted email attachments for its Gmail C2 channel.
- [S0496] REvil: REvil has encrypted C2 communications with the ECIES algorithm.
- [S0168] Gazer: Gazer uses custom encryption for C2 that uses RSA.


### T1659 - Content Injection

Procedures:

- [S1088] Disco: Disco has achieved initial access and execution through content injection into DNS, HTTP, and SMB replies to targeted hosts that redirect them to download malicious files.
- [G1019] MoustachedBouncer: MoustachedBouncer has injected content into DNS, HTTP, and SMB replies to redirect specifically-targeted victims to a fake Windows Update page to download malware.


### T1665 - Hide Infrastructure

Procedures:

- [G0128] ZIRCONIUM: ZIRCONIUM has utilized an ORB (operational relay box) network – consisting compromised devices such as small office and home office (SOHO) routers, IoT devices, and leased virtual private servers (VPS) – to obfuscate the origin of C2 traffic.
- [C0024] SolarWinds Compromise: During the SolarWinds Compromise, APT29 set the hostnames of their C2 infrastructure to match legitimate hostnames in the victim environment. They also used IP addresses originating from the same country as the victim for their VPN infrastructure.
- [S1206] JumbledPath: JumbledPath can use a chain of jump hosts to communicate with compromised devices to obscure actor infrastructure.
- [S1111] DarkGate: DarkGate command and control includes hard-coded domains in the malware masquerading as legitimate services such as Akamai CDN or Amazon Web Services.
- [G0016] APT29: APT29 uses compromised residential endpoints, typically within the same ISP IP address range, as proxies to hide the true source of C2 traffic.
- [S1164] UPSTYLE: UPSTYLE attempts to retrieve a non-existent webpage from the command and control server resulting in hidden commands sent via resulting error messages.

