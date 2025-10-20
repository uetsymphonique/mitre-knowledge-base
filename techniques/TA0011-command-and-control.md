### T1001.001 - Data Obfuscation: Junk Data

Description:

Adversaries may add junk data to protocols used for command and control to make detection more difficult. By adding random or meaningless data to the protocols used for command and control, adversaries can prevent trivial methods for decoding, deciphering, or otherwise analyzing the traffic. Examples may include appending/prepending data with junk characters or writing junk characters between significant characters.

Detection:

Analyze network data for uncommon data flows (e.g., a client sending significantly more data than it receives from a server). Processes utilizing the network that do not normally have network communication or have never been seen before are suspicious. Analyze packet contents to detect communications that do not follow the expected protocol behavior for the port that is being used.

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
- [S0514] WellMess: WellMess can use junk data in the Base64 string for additional obfuscation.

### T1001.002 - Data Obfuscation: Steganography

Description:

Adversaries may use steganographic techniques to hide command and control traffic to make detection efforts more difficult. Steganographic techniques can be used to hide data in digital messages that are transferred between systems. This hidden information can be used for command and control of compromised systems. In some cases, the passing of files embedded using steganography, such as image or document files, can be used for command and control.

Detection:

Analyze network data for uncommon data flows (e.g., a client sending significantly more data than it receives from a server). Processes utilizing the network that do not normally have network communication or have never been seen before are suspicious. Analyze packet contents to detect communications that do not follow the expected protocol behavior for the port that is being used.

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

Description:

Adversaries may impersonate legitimate protocols or web service traffic to disguise command and control activity and thwart analysis efforts. By impersonating legitimate protocols or web services, adversaries can make their command and control traffic blend in with legitimate network traffic. Adversaries may impersonate a fake SSL/TLS handshake to make it look like subsequent traffic is SSL/TLS encrypted, potentially interfering with some security tooling, or to make the traffic look like it is related with a trusted entity. Adversaries may also leverage legitimate protocols to impersonate expected web traffic or trusted services. For example, adversaries may manipulate HTTP headers, URI endpoints, SSL certificates, and transmitted data to disguise C2 communications or mimic legitimate services such as Gmail, Google Drive, and Yahoo Messenger.

Detection:

Analyze network data for uncommon data flows (e.g., a client sending significantly more data than it receives from a server). Processes utilizing the network that do not normally have network communication or have never been seen before are suspicious. Analyze packet contents to detect communications that do not follow the expected protocol behavior for the port that is being used.

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
- [S0181] FALLCHILL: FALLCHILL uses fake Transport Layer Security (TLS) to communicate with its C2 server.
- [S0439] Okrum: Okrum leverages the HTTP protocol for C2 communication, while hiding the actual messages in the Cookie and Set-Cookie headers of the HTTP requests.


### T1008 - Fallback Channels

Description:

Adversaries may use fallback or alternate communication channels if the primary channel is compromised or inaccessible in order to maintain reliable command and control and to avoid data transfer thresholds.

Detection:

Analyze network data for uncommon data flows (e.g., a client sending significantly more data than it receives from a server). Processes utilizing the network that do not normally have network communication or have never been seen before are suspicious. Analyze packet contents to detect communications that do not follow the expected protocol behavior for the port that is being used.

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
- [S0051] MiniDuke: MiniDuke uses Google Search to identify C2 servers if its primary C2 method via Twitter is not working.
- [S0059] WinMM: WinMM is usually configured with primary and backup domains for C2 communications.
- [S1039] Bumblebee: Bumblebee can use backup C2 servers if the primary server fails.
- [S0401] Exaramel for Linux: Exaramel for Linux can attempt to find a new C2 server if it receives an error.
- [S0629] RainyDay: RainyDay has the ability to switch between TCP and HTTP for C2 if one method is not working.
- [S0603] Stuxnet: Stuxnet has the ability to generate new C2 domains.
- [S0674] CharmPower: CharmPower can change its C2 channel once every 360 loops by retrieving a new domain from the actors’ S3 bucket.
- [S0265] Kazuar: Kazuar can accept multiple URLs for C2 servers.
- [G0096] APT41: APT41 used the Steam community page as a fallback mechanism for C2.
- [S0622] AppleSeed: AppleSeed can use a second channel for C2 when the primary channel is in upload mode.
- [C0002] Night Dragon: During Night Dragon, threat actors used company extranet servers as secondary C2 servers.
- [S0666] Gelsemium: Gelsemium can use multiple domains and protocols in C2.
- [S0444] ShimRat: ShimRat has used a secondary C2 location if the first was unavailable.
- [S0084] Mis-Type: Mis-Type first attempts to use a Base64-encoded network protocol over a raw TCP socket for C2, and if that method fails, falls back to a secondary HTTP-based protocol to communicate to an alternate C2 server.
- [S0022] Uroburos: Uroburos can use up to 10 channels to communicate between implants.
- [S0034] NETEAGLE: NETEAGLE will attempt to detect if the infected host is configured to a proxy. If so, NETEAGLE will send beacons via an HTTP POST request; otherwise it will send beacons via UDP/6000.
- [G0032] Lazarus Group: Lazarus Group malware SierraAlfa sends data to one of the hard-coded C2 servers chosen at random, and if the transmission fails, chooses a new C2 server to attempt the transmission again.
- [S0610] SideTwist: SideTwist has primarily used port 443 for C2 but can use port 80 as a fallback.
- [S0062] DustySky: DustySky has two hard-coded domains for C2 servers; if the first does not respond, it will try the second.
- [S0668] TinyTurla: TinyTurla can go through a list of C2 server IPs and will try to register with each until one responds.
- [S1020] Kevin: Kevin can assign hard-coded fallback domains for C2.
- [S0021] Derusbi: Derusbi uses a backup communication method with an HTTP beacon.
- [S0409] Machete: Machete has sent data over HTTP if FTP failed, and has also used a fallback server.
- [S0534] Bazar: Bazar has the ability to use an alternative C2 server if the primary server fails.
- [S0538] Crutch: Crutch has used a hardcoded GitHub repository as a fallback channel.
- [S0586] TAINTEDSCRIBE: TAINTEDSCRIBE can randomly pick one of five hard-coded IP addresses for C2 communication; if one of the IP fails, it will wait 60 seconds and then try another IP address.
- [S0348] Cardinal RAT: Cardinal RAT can communicate over multiple C2 host and port combinations.
- [S0495] RDAT: RDAT has used HTTP if DNS C2 communications were not functioning.
- [S0269] QUADAGENT: QUADAGENT uses multiple protocols (HTTPS, HTTP, DNS) for its C2 server as fallback channels if communication with one is unsuccessful.
- [G0046] FIN7: FIN7's Harpy backdoor malware can use DNS as a backup channel for C2 if HTTP fails.
- [S0236] Kwampirs: Kwampirs uses a large list of C2 servers that it cycles through until a successful connection is established.
- [S1172] OilBooster: OilBooster can use a backup channel to request a new refresh token from its C2 server after 10 consecutive unsuccessful connections to the primary OneDrive C2 server.
- [S0117] XTunnel: The C2 server used by XTunnel provides a port number to the victim to use as a fallback in case the connection closes on the currently used port.
- [S0501] PipeMon: PipeMon can switch to an alternate C2 domain when a particular date has been reached.
- [S0699] Mythic: Mythic can use a list of C2 URLs as fallback mechanisms in case one IP or domain gets blocked.
- [S0089] BlackEnergy: BlackEnergy has the capability to communicate over a backup channel via plus.google.com.
- [S0504] Anchor: Anchor can use secondary C2 servers for communication after establishing connectivity and relaying victim information to primary C2 servers.


### T1071.001 - Application Layer Protocol: Web Protocols

Description:

Adversaries may communicate using application layer protocols associated with web traffic to avoid detection/network filtering by blending in with existing traffic. Commands to the remote system, and often the results of those commands, will be embedded within the protocol traffic between the client and server. Protocols such as HTTP/S and WebSocket that carry web traffic may be very common in environments. HTTP/S packets have many fields and headers in which data can be concealed. An adversary may abuse these protocols to communicate with systems under their control within a victim network while also mimicking normal, expected traffic.

Detection:

Analyze network data for uncommon data flows (e.g., a client sending significantly more data than it receives from a server). Processes utilizing the network that do not normally have network communication or have never been seen before are suspicious. Analyze packet contents to detect application layer protocols that do not follow the expected protocol standards regarding syntax, structure, or any other variable adversaries could leverage to conceal data. Monitor for web traffic to/from known-bad or suspicious domains.

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
- [S1051] KEYPLUG: KEYPLUG has the ability to communicate over HTTP and WebSocket Protocol (WSS) for C2.
- [S0269] QUADAGENT: QUADAGENT uses HTTPS and HTTP for C2 communications.
- [G1013] Metador: Metador has used HTTP for C2.
- [S0599] Kinsing: Kinsing has communicated with C2 over HTTP.
- [C0047] RedDelta Modified PlugX Infection Chain Operations: Mustang Panda used HTTP POST messages for command and control from PlugX installations during RedDelta Modified PlugX Infection Chain Operations.
- [G1042] RedEcho: RedEcho network activity is associated with SSL traffic via TCP 443 and proxied HTTP traffic over non-standard ports.
- [S0128] BADNEWS: BADNEWS establishes a backdoor over HTTP.
- [G1002] BITTER: BITTER has used HTTP POST requests for C2.
- [S0239] Bankshot: Bankshot uses HTTP for command and control communication.
- [G1036] Moonstone Sleet: Moonstone Sleet used curl to connect to adversary-controlled infrastructure and retrieve additional payloads.
- [S0282] MacSpy: MacSpy uses HTTP for command and control.
- [S0042] LOWBALL: LOWBALL command and control occurs via HTTPS over port 443.
- [S0686] QuietSieve: QuietSieve can use HTTPS in C2 communications.
- [S0184] POWRUNER: POWRUNER can use HTTP for C2 communications.
- [G0049] OilRig: OilRig has used HTTP for C2.
- [S0137] CORESHELL: CORESHELL can communicate over HTTP for C2.
- [S0455] Metamorfo: Metamorfo has used HTTP for C2.
- [S0378] PoshC2: PoshC2 can use protocols like HTTP/HTTPS for command and control traffic.
- [S0126] ComRAT: ComRAT has used HTTP requests for command and control.
- [S0520] BLINDINGCAN: BLINDINGCAN has used HTTPS over port 443 for command and control.
- [S0284] More_eggs: More_eggs uses HTTPS for C2.
- [S0238] Proxysvc: Proxysvc uses HTTP over SSL to communicate commands with the control server.
- [S0538] Crutch: Crutch has conducted C2 communications with a Dropbox account using the HTTP API.
- [S1050] PcShare: PcShare has used HTTP for C2 communication.
- [G0071] Orangeworm: Orangeworm has used HTTP for C2.
- [S1183] StrelaStealer: StrelaStealer communicates externally via HTTP POST with encrypted content.
- [S0594] Out1: Out1 can use HTTP and HTTPS in communications with remote hosts.
- [G0067] APT37: APT37 uses HTTPS to conceal C2 communications.
- [S0030] Carbanak: The Carbanak malware communicates to its command server using HTTP with an encrypted payload.
- [S0159] SNUGRIDE: SNUGRIDE communicates with its C2 server over HTTP.
- [S0435] PLEAD: PLEAD has used HTTP for communications with command and control (C2) servers.
- [S0257] VERMIN: VERMIN uses HTTP for C2 communications.
- [S0046] CozyCar: CozyCar's main method of communicating with its C2 servers is using HTTP or HTTPS.
- [G1035] Winter Vivern: Winter Vivern uses HTTP and HTTPS protocols for exfiltration and command and control activity.
- [G0070] Dark Caracal: Dark Caracal's version of Bandook communicates with their server over a TCP port using HTTP payloads Base64 encoded and suffixed with the string “&&&”.
- [S0533] SLOTHFULMEDIA: SLOTHFULMEDIA has used HTTP and HTTPS for C2 communications.
- [S1210] Sagerunex: Sagerunex communicates via HTTPS, at times using a hard-coded User Agent of `Mozilla/5.0 (compatible; MSIE 7.0; Win32)`.
- [S0396] EvilBunny: EvilBunny has executed C2 commands directly via HTTP.
- [S1201] TRANSLATEXT: TRANSLATEXT has used HTTP to communicate with the C2 server.
- [G1034] Daggerfly: Daggerfly uses HTTP for command and control communication.
- [S0020] China Chopper: China Chopper's server component executes code sent via HTTP POST commands.
- [S0512] FatDuke: FatDuke can be controlled via a custom C2 protocol over HTTP.
- [S0087] Hi-Zor: Hi-Zor communicates with its C2 server over HTTPS.
- [S0067] pngdowner: pngdowner uses HTTP for command and control.
- [S0015] Ixeshe: Ixeshe uses HTTP for command and control.
- [S0062] DustySky: DustySky has used both HTTP and HTTPS for C2.
- [S0436] TSCookie: TSCookie can multiple protocols including HTTP and HTTPS in communication with command and control (C2) servers.
- [S0043] BUBBLEWRAP: BUBBLEWRAP can communicate using HTTP or HTTPS.
- [S0066] 3PARA RAT: 3PARA RAT uses HTTP for command and control.
- [S0564] BlackMould: BlackMould can send commands to C2 in the body of HTTP POST requests.
- [G0059] Magic Hound: Magic Hound has used HTTP for C2.
- [S0643] Peppy: Peppy can use HTTP to communicate with C2.
- [S0659] Diavol: Diavol has used HTTP GET and POST requests for C2.
- [S0430] Winnti for Linux: Winnti for Linux has used HTTP in outbound communications.
- [S0019] Regin: The Regin malware platform supports many standard protocols, including HTTP and HTTPS.
- [S0595] ThiefQuest: ThiefQuest uploads files via unencrypted HTTP.
- [S0671] Tomiris: Tomiris can use HTTP to establish C2 communications.
- [S0458] Ramsay: Ramsay has used HTTP for C2.
- [S1120] FRAMESTING: FRAMESTING can retrieve C2 commands from values stored in the `DSID` cookie from the current HTTP request or from decompressed zlib data within the request's `POST` data.
- [S0629] RainyDay: RainyDay can use HTTP in C2 communications.
- [G0081] Tropic Trooper: Tropic Trooper has used HTTP in communication with the C2.
- [S0011] Taidoor: Taidoor has used HTTP GET and POST requests for C2.
- [S0412] ZxShell: ZxShell has used HTTP for C2 connections.
- [S1028] Action RAT: Action RAT can use HTTP to communicate with C2 servers.
- [S1149] CHIMNEYSWEEP: CHIMNEYSWEEP can send `HTTP GET` requests to C2.
- [S1024] CreepySnail: CreepySnail can use HTTP for C2.
- [S1196] Troll Stealer: Troll Stealer uses HTTP to communicate to command and control infrastructure.
- [S0513] LiteDuke: LiteDuke can use HTTP GET requests in C2 communications.
- [S0356] KONNI: KONNI has used HTTP POST for C2.
- [S0337] BadPatch: BadPatch uses HTTP for C2.
- [S0345] Seasalt: Seasalt uses HTTP for C2 communications.
- [S0276] Keydnap: Keydnap uses HTTPS for command and control.
- [S1031] PingPull: A PingPull variant can communicate with its C2 servers by using HTTPS.
- [G0114] Chimera: Chimera has used HTTPS for C2 communications.
- [S0439] Okrum: Okrum uses HTTP for communication with its C2.
- [S0023] CHOPSTICK: Various implementations of CHOPSTICK communicate with C2 over HTTP.
- [S0048] PinchDuke: PinchDuke transfers files from the compromised host via HTTP or HTTPS to a C2 server.
- [S0497] Dacls: Dacls can use HTTPS in C2 communications.
- [S0074] Sakula: Sakula uses HTTP for C2.
- [S1018] Saint Bot: Saint Bot has used HTTP for C2 communications.
- [S0371] POWERTON: POWERTON has used HTTP/HTTPS for C2 traffic.
- [S0699] Mythic: Mythic supports HTTP-based C2 profiles.
- [S0382] ServHelper: ServHelper uses HTTP for C2.
- [S1202] LockBit 3.0: LockBit 3.0 can use HTTP to send victim host information to C2.
- [S1148] Raccoon Stealer: Raccoon Stealer uses HTTP, and particularly HTTP POST requests, for command and control actions.
- [S0476] Valak: Valak has used HTTP in communications with C2.
- [S0054] CloudDuke: One variant of CloudDuke uses HTTP and HTTPS for C2.
- [C0048] Operation MidnightEclipse: During Operation MidnightEclipse, threat actors used `wget` via HTTP to retrieve payloads.
- [S0237] GravityRAT: GravityRAT uses HTTP for C2.
- [S0616] DEATHRANSOM: DEATHRANSOM can use HTTPS to download files.
- [S0384] Dridex: Dridex has used POST requests and HTTPS for C2 communications.
- [S0584] AppleJeus: AppleJeus has sent data to its C2 server via POST requests.
- [S1074] ANDROMEDA: ANDROMEDA has the ability to make GET requests to download files from C2.
- [S1189] Neo-reGeorg: Neo-reGeorg can use customized HTTP headers.
- [S0401] Exaramel for Linux: Exaramel for Linux uses HTTPS for C2 communications.
- [S0065] 4H RAT: 4H RAT uses HTTP for command and control.
- [S0037] HAMMERTOSS: The "Uploader" variant of HAMMERTOSS visits a hard-coded server over HTTP/S to download the images HAMMERTOSS uses to receive commands.
- [C0014] Operation Wocao: During Operation Wocao, threat actors’ XServer tool communicated using HTTP and HTTPS.
- [S0391] HAWKBALL: HAWKBALL has used HTTP to communicate with a single hard-coded C2 server.
- [S0226] Smoke Loader: Smoke Loader uses HTTP for C2.
- [G1014] LuminousMoth: LuminousMoth has used HTTP for C2.
- [S1075] KOPILUWAK: KOPILUWAK has used HTTP POST requests to send data to C2.
- [S0022] Uroburos: Uroburos can use a custom HTTP-based protocol for large data communications that can blend with normal network traffic by riding on top of standard HTTP.
- [S0171] Felismus: Felismus uses HTTP for C2.
- [S0635] BoomBox: BoomBox has used HTTP POST requests for C2.
- [S0598] P.A.S. Webshell: P.A.S. Webshell can issue commands via HTTP POST.
- [S0342] GreyEnergy: GreyEnergy uses HTTP and HTTPS for C2 communications.
- [S0456] Aria-body: Aria-body has used HTTP in C2 communications.
- [S0170] Helminth: Helminth can use HTTP for C2.
- [S0044] JHUHUGIT: JHUHUGIT variants have communicated with C2 servers over HTTP and HTTPS.
- [G0073] APT19: APT19 used HTTP for C2 communications. APT19 also used an HTTP malware variant to communicate over HTTP for C2.
- [G0096] APT41: APT41 used HTTP to download payloads for CVE-2019-19781 and CVE-2020-10189 exploits.
- [S0516] SoreFang: SoreFang can use HTTP in C2 communications.
- [G0129] Mustang Panda: Mustang Panda has communicated with its C2 via HTTP POST requests.
- [S0085] S-Type: S-Type uses HTTP for C2.
- [S1209] Quick Assist: Quick Assist communicates over TCP 443 via HTTPS to a remote session server, under which RDP traffic is transferred.
- [S0398] HyperBro: HyperBro has used HTTPS for C2 communications.
- [S0258] RGDoor: RGDoor uses HTTP for C2 communications.
- [S0367] Emotet: Emotet has used HTTP for command and control.
- [S0147] Pteranodon: Pteranodon can use HTTP for C2.
- [S0469] ABK: ABK has the ability to use HTTP in communications with C2.
- [S0267] FELIXROOT: FELIXROOT uses HTTP and HTTPS to communicate with the C2 server.
- [S1081] BADHATCH: BADHATCH can use HTTP and HTTPS over port 443 to communicate with actor-controlled C2 servers.
- [S0250] Koadic: Koadic has used HTTP for C2 communications.
- [G0082] APT38: APT38 used a backdoor, QUICKRIDE, to communicate to the C2 server over HTTP and HTTPS.
- [S0031] BACKSPACE: BACKSPACE uses HTTP as a transport to communicate with its command server.
- [S0241] RATANKBA: RATANKBA uses HTTP/HTTPS for command and control communication.
- [S0470] BBK: BBK has the ability to use HTTP in communications with C2.
- [S0078] Psylo: Psylo uses HTTPS for C2.
- [G0060] BRONZE BUTLER: BRONZE BUTLER malware has used HTTP for C2.
- [S1185] LightSpy: LightSpy's C2 communication is performed over WebSockets using the open source library SocketRocket with functionality such as, heartbeat, receiving commands, and updating command status.
- [S1064] SVCReady: SVCReady can communicate with its C2 servers via HTTP.
- [S0466] WindTail: WindTail has the ability to use HTTP for C2 communications.
- [S0459] MechaFlounder: MechaFlounder has the ability to use HTTP in communication with C2.
- [S0661] FoggyWeb: FoggyWeb has the ability to communicate with C2 servers over HTTP GET/POST requests.
- [S0650] QakBot: QakBot has the ability to use HTTP and HTTPS in communication with C2 servers.
- [S0331] Agent Tesla: Agent Tesla has used HTTP for C2 communications.
- [S0115] Crimson: Crimson can use a HTTP GET request to download its final payload.
- [G0121] Sidewinder: Sidewinder has used HTTP in C2 communications.
- [S0168] Gazer: Gazer communicates with its C2 servers over HTTP.
- [S0034] NETEAGLE: NETEAGLE will attempt to detect if the infected host is configured to a proxy. If so, NETEAGLE will send beacons via an HTTP POST request. NETEAGLE will also use HTTP to download resources that contain an IP address and Port Number pair to connect to for further C2.
- [S0689] WhisperGate: WhisperGate can make an HTTPS connection to download additional files.
- [S0333] UBoatRAT: UBoatRAT has used HTTP for C2 communications.
- [S0527] CSPY Downloader: CSPY Downloader can use GET requests to download additional payloads from C2.
- [G0094] Kimsuky: Kimsuky has used HTTP GET and POST requests for C2.
- [S1037] STARWHALE: STARWHALE has the ability to contact actor-controlled C2 servers via HTTP.
- [C0001] Frankenstein: During Frankenstein, the threat actors used HTTP GET requests for C2.
- [G0032] Lazarus Group: Lazarus Group has conducted C2 over HTTP and HTTPS.
- [S1130] Raspberry Robin: Raspberry Robin uses outbound HTTP requests containing victim information for retrieving second stage payloads. Variants of Raspberry Robin can download archive files (such as 7-Zip files) via the victim web browser for second stage execution.
- [S0473] Avenger: Avenger has the ability to use HTTP in communication with C2.
- [S1029] AuTo Stealer: AuTo Stealer can use HTTP to communicate with its C2 servers.
- [S0375] Remexi: Remexi uses BITSAdmin to communicate with the C2 server over HTTP.
- [S0013] PlugX: PlugX can be configured to use HTTP for command and control.
- [S0352] OSX_OCEANLOTUS.D: OSX_OCEANLOTUS.D can also use use HTTP POST and GET requests to send and receive C2 information.
- [S0264] OopsIE: OopsIE uses HTTP for C2 communications.
- [G1043] BlackByte: BlackByte collected victim device information then transmitted this via HTTP POST to command and control infrastructure.
- [S0251] Zebrocy: Zebrocy uses HTTP for C2.
- [S0428] PoetRAT: PoetRAT has used HTTP and HTTPs for C2 communications.
- [S0649] SMOKEDHAM: SMOKEDHAM has communicated with its C2 servers via HTTPS and HTTP POST requests.
- [S0491] StrongPity: StrongPity can use HTTP and HTTPS in C2 communications.
- [S0664] Pandora: Pandora can communicate over HTTP.
- [S0695] Donut: Donut can use HTTP to download previously staged shellcode payloads.
- [S1190] Kapeka: Kapeka utilizes HTTP for command and control.
- [S0374] SpeakUp: SpeakUp uses POST and GET requests over HTTP to communicate with its main C&C server.
- [G0126] Higaisa: Higaisa used HTTP and HTTPS to send data back to its C2 server.
- [S1163] SnappyTCP: SnappyTCP connects to the command and control server via a TCP socket using HTTP.
- [S1015] Milan: Milan can use HTTPS for communication with C2.
- [S0082] Emissary: Emissary uses HTTP or HTTPS for C2.
- [S0504] Anchor: Anchor has used HTTP and HTTPS in C2 communications.
- [G1039] RedCurl: RedCurl has used HTTP, HTTPS and Webdav protocls for C2 communications.
- [C0017] C0017: During C0017, APT41 ran `wget to download malicious payloads.
- [S1182] MagicRAT: MagicRAT uses HTTP POST communication for command and control.
- [S0500] MCMD: MCMD can use HTTPS in communication with C2 web servers.
- [S0064] ELMER: ELMER uses HTTP for command and control.
- [G0069] MuddyWater: MuddyWater has used HTTP for C2 communications.
- [C0044] Juicy Mix: During Juicy Mix, OilRig used a VBS script to send POST requests to register installed malware with C2.
- [S1060] Mafalda: Mafalda can use HTTP for C2.
- [G0038] Stealth Falcon: Stealth Falcon malware communicates with its C2 server via HTTPS.
- [S1160] Latrodectus: Latrodectus can send registration information to C2 via HTTP `POST`.
- [S0582] LookBack: LookBack’s C2 proxy tool sends data to a C2 server over HTTP.
- [S0388] YAHOYAH: YAHOYAH uses HTTP for C2.
- [G0050] APT32: APT32 has used JavaScript that communicates over HTTP or HTTPS to attacker controlled domains to download additional frameworks. The group has also used downloaded encrypted payloads over HTTP.
- [S1030] Squirrelwaffle: Squirrelwaffle has used HTTP POST requests for C2 communications.
- [S0172] Reaver: Some Reaver variants use HTTP for C2.
- [S1014] DanBot: DanBot can use HTTP in C2 communication.
- [S0448] Rising Sun: Rising Sun has used HTTP and HTTPS for command and control.
- [C0043] Indian Critical Infrastructure Intrusions: During Indian Critical Infrastructure Intrusions, RedEcho network activity included SSL traffic over TCP 443 and HTTP traffic over non-standard ports.
- [C0002] Night Dragon: During Night Dragon, threat actors used HTTP for C2.
- [S1106] NGLite: NGLite will initially beacon out to the NKN network via an HTTP POST over TCP 30003.
- [S0662] RCSession: RCSession can use HTTP in C2 communications.
- [S0244] Comnie: Comnie uses HTTP for C2 communication.
- [C0042] Outer Space: During Outer Space, OilRig used HTTP to communicate between installed backdoors and compromised servers including via the Microsoft Exchange Web Services API.
- [G0100] Inception: Inception has used HTTP, HTTPS, and WebDav in network communications.
- [S0127] BBSRAT: BBSRAT uses GET and POST requests over HTTP or HTTPS for command and control to obtain commands and send ZLIB compressed data back to the C2 server.
- [G0090] WIRTE: WIRTE has used HTTP for network communication.
- [S0444] ShimRat: ShimRat communicated over HTTP and HTTPS with C2 servers.
- [S0024] Dyre: Dyre uses HTTPS for C2 communications.
- [S0603] Stuxnet: Stuxnet uses HTTP to communicate with a command and control server.
- [S1141] LunarWeb: LunarWeb can use `POST` to send victim identification to C2 and `GET` to retrieve commands.
- [G0010] Turla: Turla has used HTTP and HTTPS for C2 communications.
- [S1153] Cuckoo Stealer: Cuckoo Stealer can use the curl API for C2 communications.
- [S0200] Dipsind: Dipsind uses HTTP for C2.
- [S0192] Pupy: Pupy can communicate over HTTP for C2.
- [S0696] Flagpro: Flagpro can communicate with its C2 using HTTP.
- [S1187] reGeorg: reGeorg can use HTTP to tunnel connections in and out of targeted networks.
- [G1016] FIN13: FIN13 has used HTTP requests to chain multiple web shells and to contact actor-controlled C2 servers prior to exfiltrating stolen data.
- [S1168] SampleCheck5000: SampleCheck5000 can use the Exchange Web Services API for C2 communication.
- [S1188] Line Runner: Line Runner utilizes an HTTP-based Lua backdoor on victim machines.
- [S1110] SLIGHTPULSE: SLIGHTPULSE has the ability to process HTTP GET requests as a normal web server and to insert logic that will read or write files or execute commands in response to HTTP POST requests.
- [S0409] Machete: Machete uses HTTP for Command & Control.
- [G0083] SilverTerrier: SilverTerrier uses HTTP for C2 communications.
- [G0007] APT28: Later implants used by APT28, such as CHOPSTICK, use a blend of HTTP, HTTPS, and other legitimate channels for C2, depending on module configuration.
- [C0021] C0021: During C0021, the threat actors used HTTP for some of their C2 communications.
- [S0678] Torisma: Torisma can use HTTP and HTTPS for C2 communications.
- [S0268] Bisonal: Bisonal has used HTTP for C2 communications.
- [S1198] Gomir: Gomir periodically communicates to its command and control infrastructure through HTTP POST requests.
- [S0610] SideTwist: SideTwist has used HTTP GET and POST requests over port 443 for C2.
- [S0477] Goopy: Goopy has the ability to communicate with its C2 over HTTP.
- [S0009] Hikit: Hikit has used HTTP for C2.
- [S0633] Sliver: Sliver has the ability to support C2 communications over HTTP and HTTPS.
- [S0355] Final1stspy: Final1stspy uses HTTP for C2.
- [S0493] GoldenSpy: GoldenSpy has used the Ryeol HTTP Client to facilitate HTTP internet communication.
- [S1186] Line Dancer: Line Dancer uses HTTP POST requests to interact with compromised devices.
- [S0682] TrailBlazer: TrailBlazer has used HTTP requests for C2.
- [S1020] Kevin: Variants of Kevin can communicate with C2 over HTTP.
- [S0674] CharmPower: CharmPower can use HTTP to communicate with C2.
- [G0102] Wizard Spider: Wizard Spider has used HTTP for network communications.
- [S0673] DarkWatchman: DarkWatchman uses HTTPS for command and control.
- [S0386] Ursnif: Ursnif has used HTTPS for C2.
- [S1169] Mango: Mango can retrieve C2 commands sent in HTTP responses.
- [S0363] Empire: Empire can conduct command and control over protocols like HTTP and HTTPS.
- [S0045] ADVSTORESHELL: ADVSTORESHELL connects to port 80 of a C2 server using Wininet API. Data is exchanged via HTTP POSTs.
- [S0381] FlawedAmmyy: FlawedAmmyy has used HTTP for C2.
- [S0084] Mis-Type: Mis-Type network traffic can communicate over HTTP.
- [S0600] Doki: Doki has communicated with C2 over HTTPS.
- [S1155] Covenant: Covenant can establish command and control via HTTP.
- [S0449] Maze: Maze has communicated to hard-coded IP addresses via HTTP.
- [S1059] metaMain: metaMain can use HTTP for C2 communications.
- [S0680] LitePower: LitePower can use HTTP and HTTPS for C2 communications.
- [S0059] WinMM: WinMM uses HTTP for C2.
- [S1065] Woody RAT: Woody RAT can communicate with its C2 server using HTTP requests.
- [S0053] SeaDuke: SeaDuke uses HTTP and HTTPS for C2.
- [S0385] njRAT: njRAT has used HTTP for C2 communications.
- [S0339] Micropsia: Micropsia uses HTTP and HTTPS for C2 network communications.
- [G0061] FIN8: FIN8 has used HTTPS for command and control.
- [S0526] KGH_SPY: KGH_SPY can send data to C2 with HTTP POST requests.
- [S0518] PolyglotDuke: PolyglotDuke has has used HTTP GET requests in C2 communications.
- [S0154] Cobalt Strike: Cobalt Strike can use a custom command and control protocol that can be encapsulated in HTTP or HTTPS. All protocols use their standard assigned ports.
- [S0441] PowerShower: PowerShower has sent HTTP GET and POST requests to C2 servers to send information and receive instructions.
- [S0068] httpclient: httpclient uses HTTP for command and control.
- [S0230] ZeroT: ZeroT has used HTTP for C2.
- [G0142] Confucius: Confucius has used HTTP for C2 communications.
- [S0453] Pony: Pony has sent collected information to the C2 via HTTP POST request.
- [S1132] IPsec Helper: IPsec Helper connects to command and control servers via HTTP POST requests based on parameters hard-coded into the malware.
- [S1046] PowGoop: PowGoop can send HTTP GET requests to malicious servers.
- [S0604] Industroyer: Industroyer’s main backdoor connected to a remote C2 server using HTTPS.
- [S0050] CosmicDuke: CosmicDuke can use HTTP or HTTPS for command and control to hard-coded C2 servers.
- [S0335] Carbon: Carbon can use HTTP in C2 communications.
- [S0569] Explosive: Explosive has used HTTP for communication.
- [S1105] COATHANGER: COATHANGER uses an HTTP GET request to initialize a follow-on TLS tunnel for command and control.
- [S0265] Kazuar: Kazuar uses HTTP and HTTPS to communicate with the C2 server. Kazuar can also act as a webserver and listen for inbound HTTP requests through an exposed API.
- [G0112] Windshift: Windshift has used tools that communicate with C2 over HTTP.
- [S0196] PUNCHBUGGY: PUNCHBUGGY enables remote interaction and can obtain additional code over HTTPS GET and POST requests.
- [S0070] HTTPBrowser: HTTPBrowser has used HTTP and HTTPS for command and control.
- [C0039] Versa Director Zero Day Exploitation: Versa Director Zero Day Exploitation established HTTPS communications from adversary-controlled SOHO devices over port 443 with compromised Versa Director servers.
- [S0148] RTM: RTM has initiated connections to external domains using HTTPS.
- [C0028] 2015 Ukraine Electric Power Attack: During the 2015 Ukraine Electric Power Attack, Sandworm Team used BlackEnergy to communicate between compromised hosts and their command-and-control servers via HTTP post requests.
- [G0080] Cobalt Group: Cobalt Group has used HTTPS for C2.
- [S0330] Zeus Panda: Zeus Panda uses HTTP for C2 communications.
- [S0588] GoldMax: GoldMax has used HTTPS and HTTP GET requests with custom HTTP cookies for C2.
- [S0052] OnionDuke: OnionDuke uses HTTP and HTTPS for C2.
- [S0334] DarkComet: DarkComet can use HTTP for C2 communications.
- [S0340] Octopus: Octopus has used HTTP GET and POST requests for C2 communications.
- [S0049] GeminiDuke: GeminiDuke uses HTTP and HTTPS for command and control.
- [S0561] GuLoader: GuLoader can use HTTP to retrieve additional binaries.
- [S0631] Chaes: Chaes has used HTTP for C2 communications.
- [S0647] Turian: Turian has the ability to use HTTP for its C2.
- [C0012] Operation CuckooBees: During Operation CuckooBees, the threat actors enabled HTTP and HTTPS listeners.
- [C0022] Operation Dream Job: During Operation Dream Job, Lazarus Group uses HTTP and HTTPS to contact actor-controlled C2 servers.
- [S0694] DRATzarus: DRATzarus can use HTTP or HTTPS for C2 communications.
- [S0483] IcedID: IcedID has used HTTPS in communications with C2.
- [S0496] REvil: REvil has used HTTP and HTTPS in communication with C2.
- [S1207] XLoader: XLoader uses HTTP and HTTPS for command and control communication.
- [S0081] Elise: Elise communicates over HTTP or HTTPS for C2.
- [S0472] down_new: down_new has the ability to use HTTP in C2 communications.
- [S0657] BLUELIGHT: BLUELIGHT can use HTTP/S for C2 using the Microsoft Graph API.
- [G0064] APT33: APT33 has used HTTP for command and control.
- [S1184] BOLDMOVE: BOLDMOVE uses web services for command and control communication.
- [G0127] TA551: TA551 has used HTTP for C2 communications.
- [S1076] QUIETCANARY: QUIETCANARY can use HTTPS for C2 communications.
- [S0554] Egregor: Egregor has communicated with its C2 servers via HTTPS protocol.
- [S0442] VBShower: VBShower has attempted to obtain a VBS script from command and control (C2) nodes over HTTP.
- [S1022] IceApple: IceApple can use HTTP GET to request and pull information from C2.
- [S1019] Shark: Shark has the ability to use HTTP in C2 communications.
- [S0622] AppleSeed: AppleSeed has the ability to communicate with C2 over HTTP.
- [S0249] Gold Dragon: Gold Dragon uses HTTP for communication to the control servers.
- [G1044] APT42: APT42 has used tools such as NICECURL with command and control communication taking place over HTTPS.
- [S0534] Bazar: Bazar can use HTTP and HTTPS over ports 80 and 443 in C2 communications.
- [S0475] BackConfig: BackConfig has the ability to use HTTPS for C2 communiations.
- [S0153] RedLeaves: RedLeaves can communicate to its C2 over HTTP and HTTPS if directed.
- [S1172] OilBooster: OilBooster can send HTTP `GET`, `POST`, `PUT`, and `DELETE` requests to the Microsoft Graph API over port 443 for C2 communication.
- [S0484] Carberp: Carberp has connected to C2 servers via HTTP.
- [S0660] Clambling: Clambling has the ability to communicate over HTTP.
- [S0003] RIPTIDE: APT12 has used RIPTIDE, a RAT that uses HTTP to communicate.
- [S0353] NOKKI: NOKKI has used HTTP for C2 communications.
- [G0047] Gamaredon Group: Gamaredon Group has used HTTP and HTTPS for C2 communications.
- [S1156] Manjusaka: Manjusaka has used HTTP for command and control communication.
- [S0596] ShadowPad: ShadowPad communicates over HTTP to retrieve a string that is decoded into a C2 server URL.
- [S0060] Sys10: Sys10 uses HTTP for C2.
- [C0018] C0018: During C0018, the threat actors used HTTP for C2 communications.
- [S0652] MarkiRAT: MarkiRAT can initiate communication over HTTP/HTTPS for its C2 server.
- [S0138] OLDBAIT: OLDBAIT can use HTTP for C2.
- [G0004] Ke3chang: Ke3chang malware including RoyalCli and BS2005 have communicated over HTTP with the C2 server through Internet Explorer (IE) by using the COM interface IWebBrowser2.
- [S0162] Komplex: The Komplex C2 channel uses HTTP POST requests.
- [S0666] Gelsemium: Gelsemium can use HTTP/S in C2 communications.
- [C0040] APT41 DUST: APT41 DUST used HTTPS for command and control.
- [G0085] FIN4: FIN4 has used HTTP POST requests to transmit data.
- [S1042] SUGARDUMP: A SUGARDUMP variant has used HTTP for C2.
- [S0348] Cardinal RAT: Cardinal RAT is downloaded using HTTP over port 443.
- [S0072] OwaAuth: OwaAuth uses incoming HTTP requests with a username keyword and commands and handles them as instructions to perform actions.
- [S1017] OutSteel: OutSteel has used HTTP for C2 communications.
- [S0187] Daserf: Daserf uses HTTP for C2.
- [S0198] NETWIRE: NETWIRE has the ability to communicate over HTTP.
- [S1100] Ninja: Ninja can use HTTP for C2 communications.
- [S0186] DownPaper: DownPaper communicates to its C2 server over HTTP.
- [G0026] APT18: APT18 uses HTTP for C2 communications.
- [S0125] Remsec: Remsec is capable of using HTTP and HTTPS for C2.
- [G0087] APT39: APT39 has used HTTP in communications with C2.
- [S0051] MiniDuke: MiniDuke uses HTTP and HTTPS for command and control.
- [G0027] Threat Group-3390: Threat Group-3390 malware has used HTTP for C2.
- [S0460] Get2: Get2 has the ability to use HTTP to send information collected from an infected host to C2.
- [S0141] Winnti for Windows: Winnti for Windows has the ability to use encapsulated HTTP/S in C2 communications.
- [G0125] HAFNIUM: HAFNIUM has used open-source C2 frameworks, including Covenant.
- [S1115] WIREFIRE: WIREFIRE can respond to specific HTTP `POST` requests to `/api/v1/cav/client/visits`.
- [S1112] STEADYPULSE: STEADYPULSE can parse web requests made to a targeted server to determine the next stage of execution.
- [S1099] Samurai: Samurai can use a .NET HTTPListener class to receive and handle HTTP POST requests.
- [S0447] Lokibot: Lokibot has used HTTP for C2 communications.
- [S1035] Small Sieve: Small Sieve can contact actor-controlled C2 servers by using the Telegram API over HTTPS.
- [S0260] InvisiMole: InvisiMole uses HTTP for C2 communications.
- [S0445] ShimRatReporter: ShimRatReporter communicated over HTTP with preconfigured C2 servers.
- [C0046] ArcaneDoor: ArcaneDoor command and control activity was conducted through HTTP.
- [S0531] Grandoreiro: Grandoreiro has the ability to use HTTP in C2 communications.
- [S0597] GoldFinder: GoldFinder has used HTTP for C2.
- [S0691] Neoichor: Neoichor can use HTTP for C2 communications.
- [S1213] Lumma Stealer: Lumma Stealer has used HTTP and HTTP for command and control communication.
- [S0687] Cyclops Blink: Cyclops Blink can download files via HTTP and HTTPS.
- [S1025] Amadey: Amadey has used HTTP for C2 communications.
- [S0668] TinyTurla: TinyTurla can use HTTPS in C2 communications.
- [G0139] TeamTNT: TeamTNT has the `curl` command to send credentials over HTTP and the `curl` and `wget` commands to download new software. TeamTNT has also used a custom user agent HTTP header in shell scripts.
- [G0106] Rocke: Rocke has executed wget and curl commands to Pastebin over the HTTPS protocol.
- [S0266] TrickBot: TrickBot uses HTTPS to communicate with its C2 servers, to get malware updates, modules that perform most of the malware logic and various configuration files.
- [S0094] Trojan.Karagany: Trojan.Karagany can communicate with C2 via HTTP POST requests.
- [S1200] StealBit: StealBit can use HTTP to exfiltrate files to actor-controlled infrastructure.
- [G1041] Sea Turtle: Sea Turtle connected over TCP using HTTP to establish command and control channels.
- [S0636] VaporRage: VaporRage can use HTTP to download shellcode from compromised websites.
- [S0559] SUNBURST: SUNBURST communicated via HTTP GET or HTTP POST requests to third party servers for C2.
- [S0632] GrimAgent: GrimAgent has the ability to use HTTP for C2 communications.
- [S0140] Shamoon: Shamoon has used HTTP for C2.
- [S0514] WellMess: WellMess can use HTTP and HTTPS in C2 communications.
- [S0243] DealersChoice: DealersChoice uses HTTP for communication with the C2 server.
- [S0543] Spark: Spark has used HTTP POST requests to communicate with its C2 server to receive commands.
- [S0240] ROKRAT: ROKRAT can use HTTP and HTTPS for command and control communication.
- [S0089] BlackEnergy: BlackEnergy communicates with its C2 server over HTTP.
- [G0034] Sandworm Team: Sandworm Team's BCS-server tool connects to the designated C2 server via HTTP.
- [S1193] TAMECAT: TAMECAT has used HTTP for C2 communications.
- [S1178] ShrinkLocker: ShrinkLocker uses HTTP POST requests to communicate victim information back to the threat actor.
- [G0092] TA505: TA505 has used HTTP to communicate with C2 nodes.
- [S0086] ZLib: ZLib communicates over HTTP for C2.
- [S0482] Bundlore: Bundlore uses HTTP requests for C2.
- [S0589] Sibot: Sibot communicated with its C2 server via HTTP GET requests.
- [S1144] FRP: FRP has the ability to use HTTP and HTTPS to enable the forwarding of requests for internal services via domain name.
- [C0024] SolarWinds Compromise: During the SolarWinds Compromise, APT29 used HTTP for C2 and data exfiltration.
- [S1192] NICECURL: NICECURL has used HTTPS for C2 communications.
- [S1063] Brute Ratel C4: Brute Ratel C4 can use HTTPS and HTTPS for C2 communication.
- [S1066] DarkTortilla: DarkTortilla has used HTTP and HTTPS for C2.

### T1071.002 - Application Layer Protocol: File Transfer Protocols

Description:

Adversaries may communicate using application layer protocols associated with transferring files to avoid detection/network filtering by blending in with existing traffic. Commands to the remote system, and often the results of those commands, will be embedded within the protocol traffic between the client and server. Protocols such as SMB, FTP, FTPS, and TFTP that transfer files may be very common in environments. Packets produced from these protocols may have many fields and headers in which data can be concealed. Data could also be concealed within the transferred files. An adversary may abuse these protocols to communicate with systems under their control within a victim network while also mimicking normal, expected traffic.

Detection:

Analyze network data for uncommon data flows (e.g., a client sending significantly more data than it receives from a server). Processes utilizing the network that do not normally have network communication or have never been seen before are suspicious. Analyze packet contents to detect application layer protocols that do not follow the expected protocol for the port that is being used.

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
- [S0464] SYSCON: SYSCON has the ability to use FTP in C2 communications.
- [G0083] SilverTerrier: SilverTerrier uses FTP for C2 communications.
- [S1081] BADHATCH: BADHATCH can emulate an FTP server to connect to actor-controlled C2 servers.
- [S0154] Cobalt Strike: Cobalt Strike can conduct peer-to-peer communication over Windows named pipes encapsulated in the SMB protocol. All protocols use their standard assigned ports.
- [S1088] Disco: Disco can use SMB to transfer files.
- [G0094] Kimsuky: Kimsuky has used FTP to download additional malware to the target machine.
- [S0353] NOKKI: NOKKI has used FTP for C2 communications.

### T1071.003 - Application Layer Protocol: Mail Protocols

Description:

Adversaries may communicate using application layer protocols associated with electronic mail delivery to avoid detection/network filtering by blending in with existing traffic. Commands to the remote system, and often the results of those commands, will be embedded within the protocol traffic between the client and server. Protocols such as SMTP/S, POP3/S, and IMAP that carry electronic mail may be very common in environments. Packets produced from these protocols may have many fields and headers in which data can be concealed. Data could also be concealed within the email messages themselves. An adversary may abuse these protocols to communicate with systems under their control within a victim network while also mimicking normal, expected traffic.

Detection:

Analyze network data for uncommon data flows (e.g., a client sending significantly more data than it receives from a server). Processes utilizing the network that do not normally have network communication or have never been seen before are suspicious. Analyze packet contents to detect application layer protocols that do not follow the expected protocol standards regarding syntax, structure, or any other variable adversaries could leverage to conceal data.

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
- [S0495] RDAT: RDAT can use email attachments for C2 communications.
- [S1090] NightClub: NightClub can use emails for C2 communications.
- [G0007] APT28: APT28 has used IMAP, POP3, and SMTP for a communication channel in various implants, including using self-registered Google Mail accounts and later compromised email servers of its victims.
- [G0094] Kimsuky: Kimsuky has used e-mail to send exfiltrated data to C2 servers.
- [S1173] PowerExchange: PowerExchange can receive and send back the results of executed C2 commands through email.
- [S0331] Agent Tesla: Agent Tesla has used SMTP for C2 communications.
- [S0477] Goopy: Goopy has the ability to use a Microsoft Outlook backdoor macro to communicate with its C2.
- [S1152] IMAPLoader: IMAPLoader uses the IMAP email protocol for command and control purposes.
- [S1042] SUGARDUMP: A SUGARDUMP variant used SMTP for C2.
- [S1142] LunarMail: LunarMail can communicates with C2 using email messages via the Outlook Messaging API (MAPI).

### T1071.004 - Application Layer Protocol: DNS

Description:

Adversaries may communicate using the Domain Name System (DNS) application layer protocol to avoid detection/network filtering by blending in with existing traffic. Commands to the remote system, and often the results of those commands, will be embedded within the protocol traffic between the client and server. The DNS protocol serves an administrative function in computer networking and thus may be very common in environments. DNS traffic may also be allowed even before network authentication is completed. DNS packets contain many fields and headers in which data can be concealed. Often known as DNS tunneling, adversaries may abuse DNS to communicate with systems under their control within a victim network while also mimicking normal, expected traffic.

Detection:

Analyze network data for uncommon data flows (e.g., a client sending significantly more data than it receives from a server). Processes utilizing the network that do not normally have network communication or have never been seen before are suspicious. Analyze packet contents to detect application layer protocols that do not follow the expected protocol standards regarding syntax, structure, or any other variable adversaries could leverage to conceal data. Monitor for DNS traffic to/from known-bad or suspicious domains.

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
- [S0514] WellMess: WellMess has the ability to use DNS tunneling for C2 communications.
- [S1090] NightClub: NightClub can use a DNS tunneling plugin to exfiltrate data by adding it to the subdomain portion of a DNS request.
- [S0124] Pisloader: Pisloader uses DNS as its C2 protocol.
- [S1014] DanBot: DanBot can use use IPv4 A records and IPv6 AAAA DNS records in C2 communications.
- [S1027] Heyoka Backdoor: Heyoka Backdoor can use DNS tunneling for C2 communications.
- [S1021] DnsSystem: DnsSystem can direct queries to custom DNS servers and return C2 commands using TXT records.
- [S0154] Cobalt Strike: Cobalt Strike can use a custom command and control protocol that can be encapsulated in DNS. All protocols use their standard assigned ports.
- [S0666] Gelsemium: Gelsemium has the ability to use DNS in communication with C2.
- [S0360] BONDUPDATER: BONDUPDATER can use DNS and TXT records within its DNS tunneling protocol for command and control.
- [S0633] Sliver: Sliver can support C2 communications over DNS.
- [S0690] Green Lambert: Green Lambert can use DNS for C2 communications.
- [S0070] HTTPBrowser: HTTPBrowser has used DNS for command and control.
- [S1047] Mori: Mori can use DNS tunneling to communicate with C2.
- [G0140] LazyScripter: LazyScripter has leveraged dynamic DNS providers for C2 communications.
- [G0096] APT41: APT41 used DNS for C2 communications.
- [S0504] Anchor: Variants of Anchor can use DNS tunneling to communicate with C2.
- [G0080] Cobalt Group: Cobalt Group has used DNS tunneling for C2.
- [G0049] OilRig: OilRig has used DNS for C2 including the publicly available requestbin.net tunneling service.
- [S0596] ShadowPad: ShadowPad has used DNS tunneling for C2 communications.
- [S0338] Cobian RAT: Cobian RAT uses DNS for C2.
- [G0004] Ke3chang: Ke3chang malware RoyalDNS has used DNS for C2.
- [G0087] APT39: APT39 has used remote access tools that leverage DNS in communications with C2.
- [S0615] SombRAT: SombRAT can communicate over DNS with the C2 server.
- [S0260] InvisiMole: InvisiMole has used a custom implementation of DNS tunneling to embed C2 communications in DNS requests and replies.
- [G1003] Ember Bear: Ember Bear has used DNS tunnelling tools, such as dnscat/2 and Iodine, for C2 purposes.
- [S0157] SOUNDBITE: SOUNDBITE communicates via DNS for C2.
- [S0228] NanHaiShu: NanHaiShu uses DNS for the C2 communications.
- [G0081] Tropic Trooper: Tropic Trooper's backdoor has communicated to the C2 over the DNS protocol.
- [S0013] PlugX: PlugX can be configured to use DNS for command and control.
- [S0559] SUNBURST: SUNBURST used DNS for C2 traffic designed to mimic normal SolarWinds API communications.
- [G0026] APT18: APT18 uses DNS for C2 communications.
- [S1063] Brute Ratel C4: Brute Ratel C4 can use DNS over HTTPS for C2.
- [S0167] Matryoshka: Matryoshka uses DNS for C2.
- [S0145] POWERSOURCE: POWERSOURCE uses DNS TXT records for C2.
- [G0046] FIN7: FIN7 has performed C2 using DNS via A, OPT, and TXT records.
- [S1019] Shark: Shark can use DNS in C2 communications.
- [S0125] Remsec: Remsec is capable of using DNS for C2.
- [S0022] Uroburos: Uroburos has encoded outbound C2 communications in DNS requests consisting of character strings made to resemble standard domain names. The actual information transmitted by Uroburos is contained in the part of the character string prior to the first ‘.’ character.

### T1071.005 - Application Layer Protocol: Publish/Subscribe Protocols

Description:

Adversaries may communicate using publish/subscribe (pub/sub) application layer protocols to avoid detection/network filtering by blending in with existing traffic. Commands to the remote system, and often the results of those commands, will be embedded within the protocol traffic between the client and server. Protocols such as MQTT, XMPP, AMQP, and STOMP use a publish/subscribe design, with message distribution managed by a centralized broker. Publishers categorize their messages by topics, while subscribers receive messages according to their subscribed topics. An adversary may abuse publish/subscribe protocols to communicate with systems under their control from behind a message broker while also mimicking normal, expected traffic.

Procedures:

- [S0026] GLOOXMAIL: GLOOXMAIL communicates to servers operated by Google using the Jabber/XMPP protocol for C2.


### T1090.001 - Proxy: Internal Proxy

Description:

Adversaries may use an internal proxy to direct command and control traffic between two or more systems in a compromised environment. Many tools exist that enable traffic redirection through proxies or port redirection, including HTRAN, ZXProxy, and ZXPortMap. Adversaries use internal proxies to manage command and control communications inside a compromised environment, to reduce the number of simultaneous outbound network connections, to provide resiliency in the face of connection loss, or to ride over existing trusted communications paths between infected systems to avoid suspicion. Internal proxy connections may use common peer-to-peer (p2p) networking protocols, such as SMB, to better blend in with the environment. By using a compromised internal system as a proxy, adversaries may conceal the true destination of C2 traffic while reducing the need for numerous connections to external systems.

Detection:

Analyze network data for uncommon data flows between clients that should not or often do not communicate with one another. Processes utilizing the network that do not normally have network communication or have never been seen before are suspicious. Analyze packet contents to detect communications that do not follow the expected protocol behavior for the port that is being used.

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
- [S0512] FatDuke: FatDuke can used pipes to connect machines with restricted internet access to remote machines via other infected hosts.
- [S0265] Kazuar: Kazuar has used internal nodes on the compromised network for C2 communications.
- [S0031] BACKSPACE: The "ZJ" variant of BACKSPACE allows "ZJ link" infections with Internet access to relay traffic from "ZJ listen" to a command server.
- [S0633] Sliver: Sliver has a built-in SOCKS5 proxying capability allowing for Sliver clients to proxy network traffic through other clients within a victim network.
- [G1017] Volt Typhoon: Volt Typhoon has used the built-in netsh `port proxy` command to create proxies on compromised systems to facilitate access.
- [S1100] Ninja: Ninja can proxy C2 communications including to and from internal agents without internet connectivity.
- [G0010] Turla: Turla has compromised internal network systems to act as a proxy to forward traffic to C2.
- [S0260] InvisiMole: InvisiMole can function as a proxy to create a server that relays communication between the client and C&C server, or between two clients.
- [G0032] Lazarus Group: Lazarus Group has used a compromised router to serve as a proxy between a victim network's corporate and restricted segments.
- [C0014] Operation Wocao: During Operation Wocao, threat actors proxied traffic through multiple infected systems.
- [S1059] metaMain: metaMain can create a named pipe to listen for and send data to a named pipe-based C2 server.
- [S1198] Gomir: Gomir can start a reverse proxy to initiate connections to arbitrary endpoints in victim networks.
- [S0009] Hikit: Hikit supports peer connections.
- [G0087] APT39: APT39 used custom tools to create SOCK5 and custom protocol proxies between infected hosts.
- [S0603] Stuxnet: Stuxnet installs an RPC server for P2P communications.
- [C0051] APT28 Nearest Neighbor Campaign: During APT28 Nearest Neighbor Campaign, APT28 used the built-in netsh portproxy command to create internal proxies on compromised systems.

### T1090.002 - Proxy: External Proxy

Description:

Adversaries may use an external proxy to act as an intermediary for network communications to a command and control server to avoid direct connections to their infrastructure. Many tools exist that enable traffic redirection through proxies or port redirection, including HTRAN, ZXProxy, and ZXPortMap. Adversaries use these types of proxies to manage command and control communications, to provide resiliency in the face of connection loss, or to ride over existing trusted communications paths to avoid suspicion. External connection proxies are used to mask the destination of C2 traffic and are typically implemented with port redirectors. Compromised systems outside of the victim environment may be used for these purposes, as well as purchased infrastructure such as cloud-based resources or virtual private servers. Proxies may be chosen based on the low likelihood that a connection to them from a compromised system would be investigated. Victim systems would communicate directly with the external proxy on the Internet and then the proxy would forward communications to the C2 server.

Detection:

Analyze network data for uncommon data flows, such as a client sending significantly more data than it receives from an external server. Processes utilizing the network that do not normally have network communication or have never been seen before are suspicious. Analyze packet contents to detect communications that do not follow the expected protocol behavior for the port that is being used.

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
- [S0439] Okrum: Okrum can identify proxy servers configured and used by the victim, and use it to make HTTP requests to C2 its server.
- [G0093] GALLIUM: GALLIUM used a modified version of HTRAN to redirect connections between networks.
- [G0016] APT29: APT29 uses compromised residential endpoints as proxies for defense evasion and network access.
- [G0069] MuddyWater: MuddyWater has controlled POWERSTATS from behind a proxy network to obfuscate the C2 location. MuddyWater has used a series of compromised websites that victims connected to randomly to relay information to command and control (C2).
- [S0266] TrickBot: TrickBot has been known to reach a command and control server via one of nine proxy IP addresses.
- [S0260] InvisiMole: InvisiMole InvisiMole can identify proxy servers used by the victim and use them for C2 communication.

### T1090.003 - Proxy: Multi-hop Proxy

Description:

Adversaries may chain together multiple proxies to disguise the source of malicious traffic. Typically, a defender will be able to identify the last proxy traffic traversed before it enters their network; the defender may or may not be able to identify any previous proxies before the last-hop proxy. This technique makes identifying the original source of the malicious traffic even more difficult by requiring the defender to trace malicious traffic through several proxies to identify its source. For example, adversaries may construct or use onion routing networks – such as the publicly available Tor network – to transport encrypted C2 traffic through a compromised population, allowing communication with any device within the network. Adversaries may also use operational relay box (ORB) networks composed of virtual private servers (VPS), Internet of Things (IoT) devices, smart devices, and end-of-life routers to obfuscate their operations. In the case of network infrastructure, it is possible for an adversary to leverage multiple compromised devices to create a multi-hop proxy chain (i.e., Network Devices). By leveraging Patch System Image on routers, adversaries can add custom code to the affected network devices that will implement onion routing between those nodes. This method is dependent upon the Network Boundary Bridging method allowing the adversaries to cross the protected network boundary of the Internet perimeter and into the organization’s Wide-Area Network (WAN). Protocols such as ICMP may be used as a transport. Similarly, adversaries may abuse peer-to-peer (P2P) and blockchain-oriented infrastructure to implement routing between a decentralized network of peers.

Detection:

When observing use of Multi-hop proxies, network data from the actual command and control servers could allow correlating incoming and outgoing flows to trace malicious traffic back to its source. Multi-hop proxies can also be detected by alerting on traffic to known anonymity networks (such as Tor) or known adversary infrastructure that uses this technique. In context of network devices, monitor traffic for encrypted communications from the Internet that is addressed to border routers. Compare this traffic with the configuration to determine whether it matches with any configured site-to-site Virtual Private Network (VPN) connections the device was intended to have. Monitor traffic for encrypted communications originating from potentially breached routers that is addressed to other routers within the organization. Compare the source and destination with the configuration of the device to determine if these channels are an authorized Virtual Private Network (VPN) connections or other encrypted modes of communication. Monitor ICMP traffic from the Internet that is addressed to border routers and is encrypted. Few if any legitimate use cases exist for sending encrypted data to a network device via ICMP.

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
- [C0052] SPACEHOP Activity: SPACEHOP Activity has routed traffic through chains of compromised network devices to proxy C2 communications.
- [C0053] FLORAHOX Activity: FLORAHOX Activity has routed traffic through a customized Tor relay network layer.
- [S1100] Ninja: Ninja has the ability to use a proxy chain with up to 255 hops when using TCP.
- [G0030] Lotus Blossom: Lotus Blossom has used tools such as the publicly available HTran tool for proxying traffic in victim environments.
- [G0128] ZIRCONIUM: ZIRCONIUM has utilized an ORB (operational relay box) network – consisting compromised devices such as small office and home office (SOHO) routers, IoT devices, and leased virtual private servers (VPS) – to proxy traffic.
- [G1017] Volt Typhoon: Volt Typhoon has used multi-hop proxies for command-and-control infrastructure.
- [S0183] Tor: Traffic traversing the Tor network will be forwarded to multiple nodes before exiting the Tor network and continuing on to its intended destination.
- [S1107] NKAbuse: NKAbuse has abused the NKN public blockchain protocol for its C2 communications.
- [S1144] FRP: The FRP client can be configured to connect to the server through a proxy.
- [S0281] Dok: Dok downloads and installs Tor via homebrew.
- [S0687] Cyclops Blink: Cyclops Blink has used Tor nodes for C2 traffic.
- [S1106] NGLite: NGLite has abused NKN infrastructure for its C2 communication.
- [S0491] StrongPity: StrongPity can use multiple layers of proxy servers to hide terminal nodes in its infrastructure.
- [S0604] Industroyer: Industroyer used Tor nodes for C2.
- [S0366] WannaCry: WannaCry uses Tor for command and control traffic.
- [S0384] Dridex: Dridex can use multiple layers of proxy servers to hide terminal nodes in its infrastructure.
- [S1184] BOLDMOVE: BOLDMOVE is capable of relaying traffic from command and control servers to follow-on systems.
- [S0641] Kobalos: Kobalos can chain together multiple compromised machines as proxies to reach their final targets.

### T1090.004 - Proxy: Domain Fronting

Description:

Adversaries may take advantage of routing schemes in Content Delivery Networks (CDNs) and other services which host multiple domains to obfuscate the intended destination of HTTPS traffic or traffic tunneled through HTTPS. Domain fronting involves using different domain names in the SNI field of the TLS header and the Host field of the HTTP header. If both domains are served from the same CDN, then the CDN may route to the address specified in the HTTP header after unwrapping the TLS header. A variation of the the technique, "domainless" fronting, utilizes a SNI field that is left blank; this may allow the fronting to work even when the CDN attempts to validate that the SNI and HTTP Host fields match (if the blank SNI fields are ignored). For example, if domain-x and domain-y are customers of the same CDN, it is possible to place domain-x in the TLS header and domain-y in the HTTP header. Traffic will appear to be going to domain-x, however the CDN may route it to domain-y.

Detection:

If SSL inspection is in place or the traffic is not encrypted, the Host field of the HTTP header can be checked if it matches the HTTPS SNI or against a blocklist or allowlist of domain names.

Procedures:

- [S0154] Cobalt Strike: Cobalt Strike has the ability to accept a value for HTTP Host Header to enable domain fronting.
- [G0016] APT29: APT29 has used the meek domain fronting plugin for Tor to hide the destination of C2 traffic.
- [S0175] meek: meek uses Domain Fronting to disguise the destination of network traffic as another server that is hosted in the same Content Delivery Network (CDN) as the intended destination.
- [S0699] Mythic: Mythic supports domain fronting via custom request headers.
- [S0649] SMOKEDHAM: SMOKEDHAM has used a fronted domain to obfuscate its hard-coded C2 server domain.


### T1092 - Communication Through Removable Media

Description:

Adversaries can perform command and control between compromised hosts on potentially disconnected networks using removable media to transfer commands from system to system. Both systems would need to be compromised, with the likelihood that an Internet-connected system was compromised first and the second through lateral movement by Replication Through Removable Media. Commands and files would be relayed from the disconnected system to the Internet-connected system to which the adversary has direct access.

Detection:

Monitor file access on removable media. Detect processes that execute when removable media is mounted.

Procedures:

- [S0023] CHOPSTICK: Part of APT28's operation involved using CHOPSTICK modules to copy itself to air-gapped machines, using files written to USB sticks to transfer data and command traffic.
- [G0007] APT28: APT28 uses a tool that captures information from air-gapped computers via an infected USB and transfers it to network-connected computer when the USB is inserted.
- [S0136] USBStealer: USBStealer drops commands for a second victim onto a removable media drive inserted into the first victim, and commands are executed when the drive is inserted into the second victim.


### T1095 - Non-Application Layer Protocol

Description:

Adversaries may use an OSI non-application layer protocol for communication between host and C2 server or among infected hosts within a network. The list of possible protocols is extensive. Specific examples include use of network layer protocols, such as the Internet Control Message Protocol (ICMP), transport layer protocols, such as the User Datagram Protocol (UDP), session layer protocols, such as Socket Secure (SOCKS), as well as redirected/tunneled protocols, such as Serial over LAN (SOL). ICMP communication between hosts is one example. Because ICMP is part of the Internet Protocol Suite, it is required to be implemented by all IP-compatible hosts. However, it is not as commonly monitored as other Internet Protocols such as TCP or UDP and may be used by adversaries to hide communications. In ESXi environments, adversaries may leverage the Virtual Machine Communication Interface (VMCI) for communication between guest virtual machines and the ESXi host. This traffic is similar to client-server communications on traditional network sockets but is localized to the physical machine running the ESXi host, meaning it does not traverse external networks (routers, switches). This results in communications that are invisible to external monitoring and standard networking tools like tcpdump, netstat, nmap, and Wireshark. By adding a VMCI backdoor to a compromised ESXi host, adversaries may persistently regain access from any guest VM to the compromised ESXi host’s backdoor, regardless of network segmentation or firewall rules in place.

Detection:

Analyze network traffic for ICMP messages or other protocols that contain abnormal data or are not normally seen within or exiting the network. Analyze network data for uncommon data flows (e.g., a client sending significantly more data than it receives from a server). Processes utilizing the network that do not normally have network communication or have never been seen before are suspicious. Analyze packet contents to detect communications that do not follow the expected protocol behavior for the port that is being used. Monitor and investigate API calls to functions associated with enabling and/or utilizing alternative communication channels.

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
- [S1105] COATHANGER: COATHANGER uses ICMP for transmitting configuration information to and from its command and control server.
- [S1121] LITTLELAMB.WOOLTEA: LITTLELAMB.WOOLTEA can function as a stand-alone backdoor communicating over the `/tmp/clientsDownload.sock` socket.
- [S1189] Neo-reGeorg: Neo-reGeorg can create multiple TCP connections for a single session.
- [S0055] RARSTONE: RARSTONE uses SSL to encrypt its communication with its C2 server.
- [S0022] Uroburos: Uroburos can communicate through custom methodologies for UDP, ICMP, and TCP that use distinct sessions to ride over the legitimate protocols.
- [S0502] Drovorub: Drovorub can use TCP to communicate between its agent and client modules.
- [S0260] InvisiMole: InvisiMole has used TCP to download additional modules.
- [C0047] RedDelta Modified PlugX Infection Chain Operations: Mustang Panda communicated over TCP 5000 from adversary administrative servers to adversary command and control nodes during RedDelta Modified PlugX Infection Chain Operations.
- [S1060] Mafalda: Mafalda can use raw TCP for C2.
- [S0430] Winnti for Linux: Winnti for Linux has used ICMP, custom TCP, and UDP in outbound communications.
- [G1003] Ember Bear: Ember Bear uses socket-based tunneling utilities for command and control purposes such as NetCat and Go Simple Tunnel (GOST). These tunnels are used to push interactive command prompts over the created sockets. Ember Bear has also used reverse TCP connections from Meterpreter installations to communicate back with C2 infrastructure.
- [S1114] ZIPLINE: ZIPLINE can communicate with C2 using a custom binary protocol.
- [S1059] metaMain: metaMain can establish an indirect and raw TCP socket-based connection to the C2 server.
- [S0630] Nebulae: Nebulae can use TCP in C2 communications.
- [S0455] Metamorfo: Metamorfo has used raw TCP for C2.
- [S0125] Remsec: Remsec is capable of using ICMP, TCP, and UDP for C2.
- [S0141] Winnti for Windows: Winnti for Windows can communicate using custom TCP.
- [S0149] MoonWind: MoonWind completes network communication via raw sockets.
- [S0394] HiddenWasp: HiddenWasp communicates with a simple network protocol over TCP.
- [C0029] Cutting Edge: During Cutting Edge, threat actors used the Unix socket and a reverse TCP shell for C2 communications.
- [C0034] 2022 Ukraine Electric Power Attack: During the 2022 Ukraine Electric Power Attack, Sandworm Team proxied C2 communications within a TLS-based tunnel.
- [S0515] WellMail: WellMail can use TCP for C2 communications.
- [S0699] Mythic: Mythic supports WebSocket and TCP-based C2 profiles.
- [S0083] Misdat: Misdat network traffic communicates over a raw socket.
- [S1084] QUIETEXIT: QUIETEXIT can establish a TCP connection as part of its initial connection to the C2.
- [S0556] Pay2Key: Pay2Key has sent its public key to the C2 server over TCP.
- [S0172] Reaver: Some Reaver variants use raw TCP for C2.
- [S0615] SombRAT: SombRAT has the ability to use TCP sockets to send data and ICMP to ping the C2 server.
- [S1099] Samurai: Samurai can use a proxy module to forward TCP packets to external hosts.
- [C0021] C0021: During C0021, the threat actors used TCP for some C2 communications.
- [G1022] ToddyCat: ToddyCat has used a passive backdoor that receives commands with UDP packets.
- [S0501] PipeMon: The PipeMon communication module can use a custom protocol based on TLS over TCP.
- [S0234] Bandook: Bandook has a command built in to use a raw TCP socket.
- [S0262] QuasarRAT: QuasarRAT can use TCP for C2 communication.
- [C0035] KV Botnet Activity: KV Botnet Activity command and control traffic uses a non-standard, likely custom protocol for communication.
- [S0032] gh0st RAT: gh0st RAT has used an encrypted protocol within TCP segments to communicate with the C2.
- [S0596] ShadowPad: ShadowPad has used UDP for C2 communications.
- [S0461] SDBbot: SDBbot has the ability to communicate with C2 with TCP over port 443.
- [S1031] PingPull: PingPull variants have the ability to communicate with C2 servers using ICMP or TCP.
- [S0335] Carbon: Carbon uses TCP and UDP for C2.
- [S0629] RainyDay: RainyDay can use TCP in C2 communications.
- [S0034] NETEAGLE: If NETEAGLE does not detect a proxy configured on the infected machine, it will send beacons via UDP/6000. Also, after retrieving a C2 IP address and Port Number, NETEAGLE will initiate a TCP connection to this socket. The ensuing connection is a plaintext C2 channel in which commands are specified by DWORDs.
- [S0582] LookBack: LookBack uses a custom binary protocol over sockets for C2 communications.
- [S0268] Bisonal: Bisonal has used raw sockets for network communication.
- [S0650] QakBot: QakBot has the ability use TCP to send or receive C2 packets.
- [S1153] Cuckoo Stealer: Cuckoo Stealer can use sockets for communications to its C2 server.
- [S1078] RotaJakiro: RotaJakiro uses a custom binary protocol using a type, length, value format over TCP.
- [S1142] LunarMail: LunarMail can ping a specific C2 URL with the ID of a victim machine in the subdomain.
- [S0043] BUBBLEWRAP: BUBBLEWRAP can communicate using SOCKS.
- [S1163] SnappyTCP: SnappyTCP spawns a reverse TCP shell following an HTTP-based negotiation.
- [S0221] Umbreon: Umbreon provides access to the system via SSH or any other protocol that uses PAM to authenticate.
- [S0021] Derusbi: Derusbi binds to a raw socket on a random source port between 31800 and 31900 for C2.
- [G1013] Metador: Metador has used TCP for C2.
- [G0068] PLATINUM: PLATINUM has used the Intel® Active Management Technology (AMT) Serial-over-LAN (SOL) channel for command and control.
- [S0154] Cobalt Strike: Cobalt Strike can be configured to use TCP, ICMP, and UDP for C2 communications.
- [S1200] StealBit: StealBit can use the Windows Socket networking library to communicate with attacker-controlled endpoints.
- [S0662] RCSession: RCSession has the ability to use TCP and UDP in C2 communications.
- [C0014] Operation Wocao: During Operation Wocao, threat actors used a custom protocol for command and control.
- [S0587] Penquin: The Penquin C2 mechanism is based on TCP and UDP packets.
- [S0084] Mis-Type: Mis-Type network traffic can communicate over a raw socket.
- [S0670] WarzoneRAT: WarzoneRAT can communicate with its C2 server via TCP over port 5200.
- [S1063] Brute Ratel C4: Brute Ratel C4 has the ability to use TCP for external C2.
- [S0115] Crimson: Crimson uses a custom TCP protocol for C2.
- [G0037] FIN6: FIN6 has used Metasploit Bind and Reverse TCP stagers.
- [G0135] BackdoorDiplomacy: BackdoorDiplomacy has used EarthWorm for network tunneling with a SOCKS5 server and port transfer functionalities.
- [S1073] Royal: Royal establishes a TCP socket for C2 communication using the API `WSASocketW`.
- [S1140] Spica: Spica can use JSON over WebSockets for C2 communications.
- [S0498] Cryptoistic: Cryptoistic can use TCP in communications with C2.
- [G0022] APT3: An APT3 downloader establishes SOCKS5 connections for its initial C2.
- [S0019] Regin: The Regin malware platform can use ICMP to communicate between infected computers.
- [G1002] BITTER: BITTER has used TCP for C2 communications.
- [S1187] reGeorg: reGeorg can tunnel TCP sessions into targeted networks.
- [C0039] Versa Director Zero Day Exploitation: Versa Director Zero Day Exploitation used a non-standard TCP session to initialize communication prior to establishing HTTPS command and control.
- [S1051] KEYPLUG: KEYPLUG can use TCP and KCP (KERN Communications Protocol) over UDP for C2 communication.
- [S0198] NETWIRE: NETWIRE can use TCP in C2 communications.
- [G0125] HAFNIUM: HAFNIUM has used TCP for C2.
- [S1044] FunnyDream: FunnyDream can communicate with C2 over TCP and UDP.
- [S0158] PHOREAL: PHOREAL communicates via ICMP for C2.
- [S1049] SUGARUSH: SUGARUSH has used TCP for C2.
- [S0011] Taidoor: Taidoor can use TCP for C2 communications.
- [S1085] Sardonic: Sardonic can communicate with actor-controlled C2 servers by using a custom little-endian binary protocol.


### T1102.001 - Web Service: Dead Drop Resolver

Description:

Adversaries may use an existing, legitimate external Web service to host information that points to additional command and control (C2) infrastructure. Adversaries may post content, known as a dead drop resolver, on Web services with embedded (and often obfuscated/encoded) domains or IP addresses. Once infected, victims will reach out to and be redirected by these resolvers. Popular websites and social media acting as a mechanism for C2 may give a significant amount of cover due to the likelihood that hosts within a network are already communicating with them prior to a compromise. Using common services, such as those offered by Google or Twitter, makes it easier for adversaries to hide in expected noise. Web service providers commonly use SSL/TLS encryption, giving adversaries an added level of protection. Use of a dead drop resolver may also protect back-end C2 infrastructure from discovery through malware binary analysis while also enabling operational resiliency (since this infrastructure may be dynamically changed).

Detection:

Host data that can relate unknown or suspicious process activity using a network connection is important to supplement any existing indicators of compromise based on malware command and control signatures and infrastructure or the presence of strong encryption. Packet capture analysis will require SSL/TLS inspection if data is encrypted. User behavior monitoring may help to detect abnormal patterns of activity.

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
- [G0048] RTM: RTM has used an RSS feed on Livejournal to update a list of encrypted C2 server names.
- [G0060] BRONZE BUTLER: BRONZE BUTLER's MSGET downloader uses a dead drop resolver to access malicious payloads.
- [G0094] Kimsuky: Kimsuky has used TRANSLATEXT and a dead drop resolver to retrieve configurations and commands from a public blog site.
- [G0040] Patchwork: Patchwork hides base64-encoded and encrypted C2 server locations in comments on legitimate websites.
- [S0528] Javali: Javali can read C2 information from Google Documents and YouTube.
- [S0341] Xbash: Xbash can obtain a webpage hosted on Pastebin to update its C2 domain list.

### T1102.002 - Web Service: Bidirectional Communication

Description:

Adversaries may use an existing, legitimate external Web service as a means for sending commands to and receiving output from a compromised system over the Web service channel. Compromised systems may leverage popular websites and social media to host command and control (C2) instructions. Those infected systems can then send the output from those commands back over that Web service channel. The return traffic may occur in a variety of ways, depending on the Web service being utilized. For example, the return traffic may take the form of the compromised system posting a comment on a forum, issuing a pull request to development project, updating a document hosted on a Web service, or by sending a Tweet. Popular websites and social media acting as a mechanism for C2 may give a significant amount of cover due to the likelihood that hosts within a network are already communicating with them prior to a compromise. Using common services, such as those offered by Google or Twitter, makes it easier for adversaries to hide in expected noise. Web service providers commonly use SSL/TLS encryption, giving adversaries an added level of protection.

Detection:

Host data that can relate unknown or suspicious process activity using a network connection is important to supplement any existing indicators of compromise based on malware command and control signatures and infrastructure or the presence of strong encryption. Packet capture analysis will require SSL/TLS inspection if data is encrypted. Analyze network data for uncommon data flows (e.g., a client sending significantly more data than it receives from a server). User behavior monitoring may help to detect abnormal patterns of activity.

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
- [S0244] Comnie: Comnie uses blogs and third-party sites (GitHub, tumbler, and BlogSpot) to avoid DNS-based blocking of their communication to the command and control server.
- [S0128] BADNEWS: BADNEWS can use multiple C2 channels, including RSS feeds, Github, forums, and blogs.
- [S1168] SampleCheck5000: SampleCheck5000 can use the Microsoft Office Exchange Web Services API to access an actor-controlled account and retrieve C2 commands and payloads placed in Draft messages.
- [S0333] UBoatRAT: UBoatRAT has used GitHub and a public blog service in Hong Kong for C2 communications.
- [G0032] Lazarus Group: Lazarus Group has used GitHub as C2, pulling hosted image payloads then committing command execution output to files in specific directories.
- [G0005] APT12: APT12 has used blogs and WordPress for C2 infrastructure.
- [S1023] CreepyDrive: CreepyDrive can use OneDrive for C2.
- [G0087] APT39: APT39 has communicated with C2 through files uploaded to and downloaded from DropBox.
- [S0054] CloudDuke: One variant of CloudDuke uses a Microsoft OneDrive account to exchange commands and stolen data with its operators.
- [S0126] ComRAT: ComRAT has the ability to use the Gmail web UI to receive commands and exfiltrate information.
- [S1172] OilBooster: OilBooster uses the Microsoft Graph API to connect to an actor-controlled OneDrive account to download and execute files and shell commands, and to create directories to share exfiltrated data.
- [S0379] Revenge RAT: Revenge RAT used blogpost.com as its primary command and control server during a campaign.
- [G0059] Magic Hound: Magic Hound malware can use a SOAP Web service to communicate with its C2 server.
- [G0010] Turla: A Turla JavaScript backdoor has used Google Apps Script as its C2 server.
- [G1001] HEXANE: HEXANE has used cloud services, including OneDrive, for C2.
- [S0270] RogueRobin: RogueRobin has used Google Drive as a Command and Control channel.
- [S0042] LOWBALL: LOWBALL uses the Dropbox cloud storage service for command and control.
- [S0657] BLUELIGHT: BLUELIGHT can use different cloud providers for its C2.
- [S0265] Kazuar: Kazuar has used compromised WordPress blogs as C2 servers.
- [G0008] Carbanak: Carbanak has used a VBScript named "ggldr" that uses Google Apps Script, Sheets, and Forms services for C2.
- [S0511] RegDuke: RegDuke can use Dropbox as its C2 server.
- [S0363] Empire: Empire can use Dropbox and GitHub for C2.
- [G0046] FIN7: FIN7 used legitimate services like Google Docs, Google Scripts, and Pastebin for C2.
- [S0240] ROKRAT: ROKRAT has used legitimate social networking sites and cloud platforms (including but not limited to Twitter, Yandex, Dropbox, and Mediafire) for C2 communications.
- [S1171] OilCheck: OilCheck can use a REST-based Microsoft Graph API to access draft messages in a shared Microsoft Office 365 Outlook email account used for C2 communication.
- [S0026] GLOOXMAIL: GLOOXMAIL communicates to servers operated by Google using the Jabber/XMPP protocol.
- [S1201] TRANSLATEXT: TRANSLATEXT has used a Github repository for C2.
- [S0215] KARAE: KARAE can use public cloud-based storage providers for command and control.
- [S0213] DOGCALL: DOGCALL is capable of leveraging cloud storage APIs such as Cloud, Box, Dropbox, and Yandex for C2.
- [S0216] POORAIM: POORAIM has used AOL Instant Messenger for C2.
- [G0034] Sandworm Team: Sandworm Team has used the Telegram Bot API from Telegram Messenger to send and receive commands to its Python backdoor. Sandworm Team also used legitimate M.E.Doc software update check requests for sending and receiving commands and hosted malicious payloads on putdrive.com.
- [G0007] APT28: APT28 has used Google Drive for C2.
- [S1035] Small Sieve: Small Sieve has the ability to use the Telegram Bot API from Telegram Messenger to send and receive messages.
- [S1210] Sagerunex: Sagerunex has used virtual private servers (VPS) for command and control traffic as well as third-party cloud services in more recent variants.
- [G0069] MuddyWater: MuddyWater has used web services including OneHub to distribute remote access tools.
- [G0128] ZIRCONIUM: ZIRCONIUM has used Dropbox for C2 allowing upload and download of files as well as execution of arbitrary commands.
- [S0069] BLACKCOFFEE: BLACKCOFFEE has also obfuscated its C2 traffic as normal traffic to sites such as Github.

### T1102.003 - Web Service: One-Way Communication

Description:

Adversaries may use an existing, legitimate external Web service as a means for sending commands to a compromised system without receiving return output over the Web service channel. Compromised systems may leverage popular websites and social media to host command and control (C2) instructions. Those infected systems may opt to send the output from those commands back over a different C2 channel, including to another distinct Web service. Alternatively, compromised systems may return no output at all in cases where adversaries want to send instructions to systems and do not want a response. Popular websites and social media acting as a mechanism for C2 may give a significant amount of cover due to the likelihood that hosts within a network are already communicating with them prior to a compromise. Using common services, such as those offered by Google or Twitter, makes it easier for adversaries to hide in expected noise. Web service providers commonly use SSL/TLS encryption, giving adversaries an added level of protection.

Detection:

Host data that can relate unknown or suspicious process activity using a network connection is important to supplement any existing indicators of compromise based on malware command and control signatures and infrastructure or the presence of strong encryption. Packet capture analysis will require SSL/TLS inspection if data is encrypted. Analyze network data for uncommon data flows. User behavior monitoring may help to detect abnormal patterns of activity.

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

Description:

Adversaries may create multiple stages for command and control that are employed under different conditions or for certain functions. Use of multiple stages may obfuscate the command and control channel to make detection more difficult. Remote access tools will call back to the first-stage command and control server for instructions. The first stage may have automated capabilities to collect basic host information, update tools, and upload additional files. A second remote access tool (RAT) could be uploaded at that point to redirect the host to the second-stage command and control server. The second stage will likely be more fully featured and allow the adversary to interact with the system through a reverse shell and additional RAT features. The different stages will likely be hosted separately with no overlapping infrastructure. The loader may also have backup first-stage callbacks or Fallback Channels in case the original first-stage communication path is discovered and blocked.

Detection:

Host data that can relate unknown or suspicious process activity using a network connection is important to supplement any existing indicators of compromise based on malware command and control signatures and infrastructure. Relating subsequent actions that may result from Discovery of the system and network information or Lateral Movement to the originating process may also yield useful data.

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

Description:

Adversaries may transfer tools or other files from an external system into a compromised environment. Tools or files may be copied from an external adversary-controlled system to the victim network through the command and control channel or through alternate protocols such as ftp. Once present, adversaries may also transfer/spread tools between victim devices within a compromised environment (i.e. Lateral Tool Transfer). On Windows, adversaries may use various utilities to download tools, such as `copy`, `finger`, certutil, and PowerShell commands such as IEX(New-Object Net.WebClient).downloadString() and Invoke-WebRequest. On Linux and macOS systems, a variety of utilities also exist, such as `curl`, `scp`, `sftp`, `tftp`, `rsync`, `finger`, and `wget`. A number of these tools, such as `wget`, `curl`, and `scp`, also exist on ESXi. After downloading a file, a threat actor may attempt to verify its integrity by checking its hash value (e.g., via `certutil -hashfile`). Adversaries may also abuse installers and package managers, such as `yum` or `winget`, to download tools to victim hosts. Adversaries have also abused file application features, such as the Windows `search-ms` protocol handler, to deliver malicious files to victims through remote file searches invoked by User Execution (typically after interacting with Phishing lures). Files can also be transferred using various Web Services as well as native or otherwise present tools on the victim system. In some cases, adversaries may be able to leverage services that sync between a web-based and an on-premises client, such as Dropbox or OneDrive, to transfer files onto victim systems. For example, by compromising a cloud account and logging into the service's web portal, an adversary may be able to trigger an automatic syncing process that transfers the file onto the victim's machine.

Detection:

Monitor for file creation and files transferred into the network. Unusual processes with external network connections creating files on-system may be suspicious. Use of utilities, such as ftp, that does not normally occur may also be suspicious. Analyze network data for uncommon data flows (e.g., a client sending significantly more data than it receives from a server). Processes utilizing the network that do not normally have network communication or have never been seen before are suspicious. Specifically, for the finger utility on Windows and Linux systems, monitor command line or terminal execution for the finger command. Monitor network activity for TCP port 79, which is used by the finger utility, and Windows netsh interface portproxy modifications to well-known ports such as 80 and 443. Furthermore, monitor file system for the download/creation and execution of suspicious files, which may indicate adversary-downloaded payloads. Analyze packet contents to detect communications that do not follow the expected protocol behavior for the port that is being used.

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
- [S1048] macOS.OSAMiner: macOS.OSAMiner has used `curl` to download a Stripped Payloads from a public facing adversary-controlled webpage.
- [S0516] SoreFang: SoreFang can download additional payloads from C2.
- [S1074] ANDROMEDA: ANDROMEDA can download additional payloads from C2.
- [S1013] ZxxZ: ZxxZ can download and execute additional files.
- [G1021] Cinnamon Tempest: Cinnamon Tempest has downloaded files, including Cobalt Strike, to compromised hosts.
- [S0386] Ursnif: Ursnif has dropped payload and configuration files to disk. Ursnif has also been used to download and execute additional payloads.
- [S1189] Neo-reGeorg: Neo-reGeorg has the ability to download files to targeted systems.
- [S0070] HTTPBrowser: HTTPBrowser is capable of writing a file to the compromised system from the C2 server.
- [G1043] BlackByte: BlackByte has transferred tools such as Cobalt Strike to victim environments from file sharing and hosting websites.
- [S1028] Action RAT: Action RAT has the ability to download additional payloads onto an infected machine.
- [S0207] Vasport: Vasport can download files.
- [S0472] down_new: down_new has the ability to download files to the compromised host.
- [G0081] Tropic Trooper: Tropic Trooper has used a delivered trojan to download additional files.
- [S0574] BendyBear: BendyBear is designed to download an implant from a C2 server.
- [S0206] Wiarp: Wiarp creates a backdoor through which remote attackers can download files.
- [S0210] Nerex: Nerex creates a backdoor through which remote attackers can download files onto a compromised host.
- [S0613] PS1: CostaBricks can download additional payloads onto a compromised host.
- [S0336] NanoCore: NanoCore has the capability to download and activate additional modules for execution.
- [S0380] StoneDrill: StoneDrill has downloaded and dropped temporary files containing scripts; it additionally has a function to upload files from the victims machine.
- [G0032] Lazarus Group: Lazarus Group has downloaded files, malware, and tools from its C2 onto a compromised host.
- [S0504] Anchor: Anchor can download additional payloads.
- [S0354] Denis: Denis deploys additional backdoors and hacking tools to the system.
- [S0199] TURNEDUP: TURNEDUP is capable of downloading additional files.
- [G0068] PLATINUM: PLATINUM has transferred files using the Intel® Active Management Technology (AMT) Serial-over-LAN (SOL) channel.
- [S1088] Disco: Disco can download files to targeted systems via SMB.
- [S0445] ShimRatReporter: ShimRatReporter had the ability to download additional payloads.
- [S0081] Elise: Elise can download additional files from the C2 server for execution.
- [S0439] Okrum: Okrum has built-in commands for uploading, downloading, and executing files to the system.
- [S0192] Pupy: Pupy can upload and download to/from a victim machine.
- [G0004] Ke3chang: Ke3chang has used tools to download files to compromised machines.
- [S0630] Nebulae: Nebulae can download files from C2.
- [S0401] Exaramel for Linux: Exaramel for Linux has a command to download a file from and to a remote C2 server.
- [S1173] PowerExchange: PowerExchange can decode Base64-encoded files and call `WriteAllBytes` to write the files to compromised hosts.
- [S0686] QuietSieve: QuietSieve can download and execute payloads on a target host.
- [S0385] njRAT: njRAT can download files to the victim’s machine.
- [C0004] CostaRicto: During CostaRicto, the threat actors downloaded malware and tools onto a compromised host.
- [S0639] Seth-Locker: Seth-Locker has the ability to download and execute files on a compromised host.
- [S0388] YAHOYAH: YAHOYAH uses HTTP GET requests to download other files that are executed in memory.
- [S0087] Hi-Zor: Hi-Zor has the ability to upload and download files from its C2 server.
- [G0107] Whitefly: Whitefly has the ability to download additional tools from the C2.
- [S0414] BabyShark: BabyShark has downloaded additional files from the C2.
- [S1182] MagicRAT: MagicRAT can import and execute additional payloads.
- [G0067] APT37: APT37 has downloaded second stage malware from compromised websites.
- [S0475] BackConfig: BackConfig can download and execute additional payloads on a compromised host.
- [S0692] SILENTTRINITY: SILENTTRINITY can load additional files and tools, including Mimikatz.
- [S0268] Bisonal: Bisonal has the capability to download files to execute on the victim’s machine.
- [S0520] BLINDINGCAN: BLINDINGCAN has downloaded files to a victim machine.
- [S0374] SpeakUp: SpeakUp downloads and executes additional files from a remote server.
- [S0390] SQLRat: SQLRat can make a direct SQL connection to a Microsoft database controlled by the attackers, retrieve an item from the bindata table, then write and execute the file on disk.
- [G1008] SideCopy: SideCopy has delivered trojanized executables via spearphishing emails that contacts actor-controlled servers to download malicious payloads.
- [S0436] TSCookie: TSCookie has the ability to upload and download files to and from the infected host.
- [S0468] Skidmap: Skidmap has the ability to download files on an infected host.
- [S0379] Revenge RAT: Revenge RAT has the ability to upload and download files.
- [G1018] TA2541: TA2541 has used malicious scripts and macros with the ability to download additional payloads.
- [G0094] Kimsuky: Kimsuky has downloaded additional scripts, tools, and malware onto victim systems.
- [S0688] Meteor: Meteor has the ability to download additional files for execution on the victim's machine.
- [S0086] ZLib: ZLib has the ability to download files.
- [G0010] Turla: Turla has used shellcode to download Meterpreter after compromising a victim.
- [S0531] Grandoreiro: Grandoreiro can download its second stage from a hardcoded URL within the loader's code.
- [S0657] BLUELIGHT: BLUELIGHT can download additional files onto the host.
- [S0270] RogueRobin: RogueRobin can save a new file to the system from the C2 server.
- [S0265] Kazuar: Kazuar downloads additional plug-ins to load on the victim’s machine, including the ability to upgrade and replace its own binary.
- [S0691] Neoichor: Neoichor can download additional files onto a compromised host.
- [S0651] BoxCaon: BoxCaon can download files.
- [C0042] Outer Space: During Outer Space, OilRig downloaded additional tools to comrpomised infrastructure.
- [S1149] CHIMNEYSWEEP: CHIMNEYSWEEP can download additional files from C2.
- [S0187] Daserf: Daserf can download remote files.
- [S0251] Zebrocy: Zebrocy obtains additional code to execute on the victim's machine, including the downloading of a secondary payload.
- [G0047] Gamaredon Group: Gamaredon Group has downloaded additional malware and tools onto a compromised host. For example, Gamaredon Group uses a backdoor script to retrieve and decode additional payloads once in victim environments.
- [S0042] LOWBALL: LOWBALL uses the Dropbox API to request two files, one of which is the same file as the one dropped by the malicious email attachment. This is most likely meant to be a mechanism to update the compromised host with a new version of the LOWBALL malware.
- [S0487] Kessel: Kessel can download additional modules from the C2 server.
- [G0065] Leviathan: Leviathan has downloaded additional scripts and files from adversary-controlled servers.
- [C0022] Operation Dream Job: During Operation Dream Job, Lazarus Group downloaded multistage malware and tools onto a compromised host.
- [S0518] PolyglotDuke: PolyglotDuke can retrieve payloads from the C2 server.
- [S0200] Dipsind: Dipsind can download remote files.
- [S1193] TAMECAT: TAMECAT has used `wget` and `curl` to download additional content.
- [S0643] Peppy: Peppy can download and execute remote files.
- [S0106] cmd: cmd can be used to copy files to/from a remotely connected external system.
- [G0045] menuPass: menuPass has installed updates and new malware on victims.
- [S0629] RainyDay: RainyDay can download files to a compromised host.
- [S0348] Cardinal RAT: Cardinal RAT can download and execute additional payloads.
- [S0670] WarzoneRAT: WarzoneRAT can download and execute additional files.
- [S0652] MarkiRAT: MarkiRAT can download additional files and tools from its C2 server, including through the use of BITSAdmin.
- [C0027] C0027: During C0027, Scattered Spider downloaded tools using victim organization systems.
- [S0215] KARAE: KARAE can upload and download files, including second-stage malware.
- [G0021] Molerats: Molerats used executables to download malicious files from different sources.
- [S1035] Small Sieve: Small Sieve has the ability to download files.
- [S0020] China Chopper: China Chopper's server component can download remote files.
- [S0658] XCSSET: XCSSET downloads browser specific AppleScript modules using a constructed URL with the curl command, & domain & "/agent/scripts/" & moduleName & ".applescript.
- [S0271] KEYMARBLE: KEYMARBLE can upload files to the victim’s machine and can download additional payloads.
- [S0484] Carberp: Carberp can download and execute new plugins from the C2 server.
- [S0130] Unknown Logger: Unknown Logger is capable of downloading remote files.
- [S0532] Lucifer: Lucifer can download and execute a replica of itself using certutil.
- [S0074] Sakula: Sakula has the capability to download files.
- [S0428] PoetRAT: PoetRAT has the ability to copy files and download/upload files into C2 channels using FTP and HTTPS.
- [S0032] gh0st RAT: gh0st RAT can download files to the victim’s machine.
- [S0635] BoomBox: BoomBox has the ability to download next stage malware components to a compromised system.
- [S0511] RegDuke: RegDuke can download files from C2.
- [S1185] LightSpy: On macOS, LightSpy downloads a `.json` file from the C2 server. The `.json` file contains metadata about the plugins to be downloaded, including their URL, name, version, and MD5 hash. LightSpy retrieves the plugins specified in the `.json` file, which are compiled `.dylib` files. These `.dylib` files provide task and platform specific functionality. LightSpy also imports open-source libraries to manage socket connections.
- [S0272] NDiskMonitor: NDiskMonitor can download and execute a file from given URL.
- [S0680] LitePower: LitePower has the ability to download payloads containing system commands to a compromised host.
- [S0147] Pteranodon: Pteranodon can download and execute additional files.
- [S0204] Briba: Briba downloads files onto infected hosts.
- [S0497] Dacls: Dacls can download its payload from a C2 server.
- [S1018] Saint Bot: Saint Bot can download additional files onto a compromised host.
- [S0628] FYAnti: FYAnti can download additional payloads to a compromised host.
- [S1115] WIREFIRE: WIREFIRE has the ability to download files to compromised devices.
- [S1166] Solar: Solar has the ability to download and execute files.
- [G0016] APT29: APT29 has downloaded additional tools and malware onto compromised networks.
- [S0499] Hancitor: Hancitor has the ability to download additional files from C2.
- [S0140] Shamoon: Shamoon can download an executable to run on the victim.
- [G0106] Rocke: Rocke used malware to download additional malicious files to the target system.
- [S0501] PipeMon: PipeMon can install additional modules via C2 commands.
- [S0453] Pony: Pony can download additional files onto the infected system.
- [S1064] SVCReady: SVCReady has the ability to download additional tools such as the RedLine Stealer to an infected host.
- [S1020] Kevin: Kevin can download files to the compromised host.
- [G0121] Sidewinder: Sidewinder has used LNK files to download remote files to the victim's network.
- [S0274] Calisto: Calisto has the capability to upload and download files to the victim's machine.
- [S0331] Agent Tesla: Agent Tesla can download additional files for execution on the victim’s machine.
- [S0250] Koadic: Koadic can download additional files and tools.
- [S0084] Mis-Type: Mis-Type has downloaded additional malware and files onto a compromised host.
- [S0667] Chrommme: Chrommme can download its code from C2.
- [S0263] TYPEFRAME: TYPEFRAME can upload and download files to the victim’s machine.
- [S0382] ServHelper: ServHelper may download additional files to execute.
- [S0118] Nidiran: Nidiran can download and execute files.
- [S1124] SocGholish: SocGholish can download additional malware to infected hosts.
- [S0649] SMOKEDHAM: SMOKEDHAM has used Powershell to download UltraVNC and ngrok from third-party file sharing sites.
- [S1170] ODAgent: ODAgent has the ability to download and execute files on compromised systems.
- [S0249] Gold Dragon: Gold Dragon can download additional components from the C2 server.
- [S0234] Bandook: Bandook can download files to the system.
- [S0024] Dyre: Dyre has a command to download and executes additional files.
- [G0059] Magic Hound: Magic Hound has downloaded additional code and files from servers onto victims.
- [C0040] APT41 DUST: APT41 DUST involved execution of `certutil.exe` via web shell to download the DUSTPAN dropper.
- [S0228] NanHaiShu: NanHaiShu can download additional files from URLs.
- [S0614] CostaBricks: CostaBricks has been used to load SombRAT onto a compromised host.
- [S0632] GrimAgent: GrimAgent has the ability to download and execute additional payloads.
- [S1085] Sardonic: Sardonic has the ability to upload additional malicious files to a compromised machine.
- [S0262] QuasarRAT: QuasarRAT can download files to the victim’s machine and execute them.
- [S0085] S-Type: S-Type can download additional files onto a compromised host.
- [S0226] Smoke Loader: Smoke Loader downloads a new version of itself once it has installed. It also downloads additional plugins.
- [S1012] PowerLess: PowerLess can download additional payloads to a compromised host.
- [S0055] RARSTONE: RARSTONE downloads its backdoor component from a C2 server and loads it directly into memory.
- [S0330] Zeus Panda: Zeus Panda can download additional malware plug-in modules and execute them on the victim’s machine.
- [C0001] Frankenstein: During Frankenstein, the threat actors downloaded files and tools onto a victim machine.
- [S0218] SLOWDRIFT: SLOWDRIFT downloads additional payloads.
- [S0347] AuditCred: AuditCred can download files and additional malware.
- [S1015] Milan: Milan has received files from C2 and stored them in log folders beginning with the character sequence `a9850d2f`.
- [S0665] ThreatNeedle: ThreatNeedle can download additional tools to enable lateral movement.
- [S0604] Industroyer: Industroyer downloads a shellcode payload from a remote C2 server and loads it into memory.
- [G0143] Aquatic Panda: Aquatic Panda has downloaded additional malware onto compromised hosts.
- [S1130] Raspberry Robin: Raspberry Robin retrieves its second stage payload in a variety of ways such as through msiexec.exe abuse, or running the curl command to download the payload to the victim's %AppData% folder.
- [S1168] SampleCheck5000: SampleCheck5000 can download additional payloads to compromised hosts.
- [C0037] Water Curupira Pikabot Distribution: Water Curupira Pikabot Distribution used Curl.exe to download the Pikabot payload from an external server, saving the file to the victim machine's temporary directory.
- [G0082] APT38: APT38 used a backdoor, NESTEGG, that has the capability to download and upload files to and from a victim’s machine. Additionally, APT38 has downloaded other payloads onto a victim’s machine.
- [S0672] Zox: Zox can download files to a compromised machine.
- [S0079] MobileOrder: MobileOrder has a command to download a file from the C2 server to the victim mobile device's SD card.
- [S0470] BBK: BBK has the ability to download files from C2 to the infected host.
- [S0438] Attor: Attor can download additional plugins, updates and other files.
- [S0530] Melcoz: Melcoz has the ability to download additional files to a compromised host.
- [S1140] Spica: Spica can upload and download files to and from compromised hosts.
- [G1014] LuminousMoth: LuminousMoth has downloaded additional malware and tools onto a compromised host.
- [S0053] SeaDuke: SeaDuke is capable of uploading and downloading files.
- [S0247] NavRAT: NavRAT can download files remotely.
- [S0211] Linfo: Linfo creates a backdoor through which remote attackers can download files onto compromised hosts.
- [S0579] Waterbear: Waterbear can receive and load executables from remote C2 servers.
- [S0352] OSX_OCEANLOTUS.D: OSX_OCEANLOTUS.D has a command to download and execute a file on the victim’s machine.
- [S0203] Hydraq: Hydraq creates a backdoor through which remote attackers can download files and additional malware components.
- [S1110] SLIGHTPULSE: RAPIDPULSE can transfer files to and from compromised hosts.
- [S1187] reGeorg: reGeorg has the ability to download files to targeted systems.
- [S0615] SombRAT: SombRAT has the ability to download and execute additional payloads.
- [G0078] Gorgon Group: Gorgon Group malware can download additional files from C2 servers.
- [S1021] DnsSystem: DnsSystem can download files to compromised systems after receiving a command with the string `downloaddd`.
- [G0087] APT39: APT39 has downloaded tools to compromised hosts.
- [S0514] WellMess: WellMess can write files to a compromised host.
- [S0527] CSPY Downloader: CSPY Downloader can download additional tools to a compromised host.
- [S0367] Emotet: Emotet can download follow-on payloads and items via malicious `url` parameters in obfuscated PowerShell code.
- [S1099] Samurai: Samurai has been used to deploy other malware including Ninja.
- [S0625] Cuba: Cuba can download files from its C2 server.
- [S0669] KOCTOPUS: KOCTOPUS has executed a PowerShell command to download a file to the system.
- [G0007] APT28: APT28 has downloaded additional files, including by using a first-stage downloader to contact the C2 server to obtain the second-stage implant.
- [S0353] NOKKI: NOKKI has downloaded a remote module for execution.
- [S0011] Taidoor: Taidoor has downloaded additional files onto a compromised host.
- [S1030] Squirrelwaffle: Squirrelwaffle has downloaded and executed additional encoded payloads.
- [S0694] DRATzarus: DRATzarus can deploy additional tools onto an infected machine.
- [S0662] RCSession: RCSession has the ability to drop additional files to an infected machine.
- [S0051] MiniDuke: MiniDuke can download additional encrypted backdoors onto the victim via GIF files.
- [S1148] Raccoon Stealer: Raccoon Stealer downloads various library files enabling interaction with various data stores and structures to facilitate follow-on information theft.
- [C0015] C0015: During C0015, the threat actors downloaded additional tools and files onto a compromised network.
- [G0027] Threat Group-3390: Threat Group-3390 has downloaded additional malware and tools, including through the use of `certutil`, onto a compromised host .
- [S0600] Doki: Doki has downloaded scripts from C2.
- [S0610] SideTwist: SideTwist has the ability to download additional files.
- [S0482] Bundlore: Bundlore can download and execute new versions of itself.
- [S1014] DanBot: DanBot can download additional files to a targeted system.
- [S0256] Mosquito: Mosquito can upload and download files to the victim.
- [S0465] CARROTBALL: CARROTBALL has the ability to download and install a remote payload.
- [S0344] Azorult: Azorult can download and execute additional files. Azorult has also downloaded a ransomware payload called Hermes.
- [C0035] KV Botnet Activity: KV Botnet Activity included the use of scripts to download additional payloads when compromising network nodes.
- [S1039] Bumblebee: Bumblebee can download and execute additional payloads including through the use of a `Dex` command.
- [S1160] Latrodectus: Latrodectus can download and execute PEs, DLLs, and shellcode from C2.
- [S0180] Volgmer: Volgmer can download remote files and additional payloads to the victim's machine.
- [S0094] Trojan.Karagany: Trojan.Karagany can upload, download, and execute files on the victim.
- [S0587] Penquin: Penquin can execute the command code do_download to retrieve remote files from C2.
- [S0214] HAPPYWORK: can download and execute a second-stage payload.
- [S0546] SharpStage: SharpStage has the ability to download and execute additional payloads via a DropBox API.
- [S0668] TinyTurla: TinyTurla has the ability to act as a second-stage dropper used to infect the system with additional malware.
- [S0283] jRAT: jRAT can download and execute files.
- [S0023] CHOPSTICK: CHOPSTICK is capable of performing remote file transmission.
- [S0229] Orz: Orz can download files onto the victim.
- [S0160] certutil: certutil can be used to download files from a given URL.
- [G0075] Rancor: Rancor has downloaded additional malware, including by using certutil.
- [S0201] JPIN: JPIN can download files and upgrade itself.
- [S0663] SysUpdate: SysUpdate has the ability to download files to a compromised host.
- [S0345] Seasalt: Seasalt has a command to download additional files.
- [S0334] DarkComet: DarkComet can load any files onto the infected machine to execute.
- [G1016] FIN13: FIN13 has downloaded additional tools and malware to compromised systems.
- [S1081] BADHATCH: BADHATCH has the ability to load a second stage malicious DLL file onto a compromised machine.
- [C0048] Operation MidnightEclipse: During Operation MidnightEclipse, threat actors downloaded additional payloads on compromised devices.
- [S0015] Ixeshe: Ixeshe can download and execute additional files.
- [S1159] DUSTTRAP: DUSTTRAP can retrieve and load additional payloads.
- [S0616] DEATHRANSOM: DEATHRANSOM can download files to a compromised host.
- [S0013] PlugX: PlugX has a module to download and execute files on the compromised machine.
- [C0028] 2015 Ukraine Electric Power Attack: During the 2015 Ukraine Electric Power Attack, Sandworm Team pushed additional malicious tools onto an infected system to steal user credentials, move laterally, and destroy data.
- [S0339] Micropsia: Micropsia can download and execute an executable from the C2 server.
- [S0461] SDBbot: SDBbot has the ability to download a DLL from C2 to a compromised host.
- [S0492] CookieMiner: CookieMiner can download additional scripts from a web server.
- [S0646] SpicyOmelette: SpicyOmelette can download malicious files from threat actor controlled AWS URL's.
- [S0054] CloudDuke: CloudDuke downloads and executes additional malware from either a Web address or a Microsoft OneDrive account.
- [S0208] Pasam: Pasam creates a backdoor through which remote attackers can upload files.
- [S0341] Xbash: Xbash can download additional malicious files from its C2 server.
- [S0395] LightNeuron: LightNeuron has the ability to download and execute additional files.
- [S0125] Remsec: Remsec contains a network loader to receive executable modules from remote attackers and run them on the local victim. It can also upload and download files over HTTP and HTTPS.
- [S0696] Flagpro: Flagpro can download additional malware from the C2 server.
- [G0069] MuddyWater: MuddyWater has used malware that can upload additional files to the victim’s machine.
- [S1171] OilCheck: OilCheck can download staged payloads from an actor-controlled infrastructure.
- [S0082] Emissary: Emissary has the capability to download files from the C2 server.
- [S0547] DropBook: DropBook can download and execute additional files.
- [S0170] Helminth: Helminth can download additional files.
- [S0476] Valak: Valak has downloaded a variety of modules and payloads to the compromised host, including IcedID and NetSupport Manager RAT-based malware.
- [S0554] Egregor: Egregor has the ability to download files from its C2 server.
- [S0356] KONNI: KONNI can download files and execute them on the victim’s machine.
- [S0685] PowerPunch: PowerPunch can download payloads from adversary infrastructure.
- [G0026] APT18: APT18 can upload a file to the victim’s machine.
- [S0387] KeyBoy: KeyBoy has a download and upload functionality.
- [S1065] Woody RAT: Woody RAT can download files from its C2 server, including the .NET DLLs, `WoodySharpExecutor` and `WoodyPowerSession`.
- [S1111] DarkGate: DarkGate retrieves cryptocurrency mining payloads and commands in encrypted traffic from its command and control server. DarkGate uses Windows Batch scripts executing the curl command to retrieve follow-on payloads. DarkGate has stolen `sitemanager.xml` and `recentservers.xml` from `%APPDATA%\FileZilla\` if present.
- [S0636] VaporRage: VaporRage has the ability to download malicious shellcode to compromised systems.
- [G0139] TeamTNT: TeamTNT has the curl and wget commands as well as batch scripts to download new tools.
- [C0029] Cutting Edge: During Cutting Edge, threat actors leveraged exploits to download remote files to Ivanti Connect Secure VPNs.
- [S0168] Gazer: Gazer can execute a task to download a file.
- [S0196] PUNCHBUGGY: PUNCHBUGGY can download additional files and payloads to compromised hosts.
- [G0049] OilRig: OilRig had downloaded remote files onto victim infrastructure.
- [S0139] PowerDuke: PowerDuke has a command to download a file.
- [G1046] Storm-1811: Storm-1811 has used scripted `cURL` commands, BITSAdmin, and other mechanisms to retrieve follow-on batch scripts and tools for execution on victim devices.
- [S0450] SHARPSTATS: SHARPSTATS has the ability to upload and download files.
- [S0213] DOGCALL: DOGCALL can download and execute additional payloads.
- [S0451] LoudMiner: LoudMiner used SCP to update the miner from the C2.
- [S0526] KGH_SPY: KGH_SPY has the ability to download and execute code from remote servers.
- [S0589] Sibot: Sibot can download and execute a payload onto a compromised system.
- [S0435] PLEAD: PLEAD has the ability to upload and download files to and from an infected host.
- [S0430] Winnti for Linux: Winnti for Linux has the ability to deploy modules directly from command and control (C2) servers, possibly for remote command execution, file exfiltration, and socks5 proxying on the infected host.
- [G1034] Daggerfly: Daggerfly has used PowerShell and BITSAdmin to retrieve follow-on payloads from external locations for execution on victim machines.
- [G1040] Play: Play has used Cobalt Strike to download files to compromised machines.
- [S0337] BadPatch: BadPatch can download and execute or update malware.
- [S0240] ROKRAT: ROKRAT can retrieve additional malicious payloads from its C2 server.
- [G0140] LazyScripter: LazyScripter had downloaded additional tools to a compromised host.
- [S0144] ChChes: ChChes is capable of downloading files, including additional modules.
- [S0437] Kivars: Kivars has the ability to download and execute files.
- [G0050] APT32: APT32 has added JavaScript to victim websites to download additional frameworks that profile and compromise website visitors.
- [G0091] Silence: Silence has downloaded additional modules and malware to victim’s machines.
- [S0633] Sliver: Sliver can download additional content and files from the Sliver server to the client residing on the victim machine using the upload command.
- [S0666] Gelsemium: Gelsemium can download additional plug-ins to a compromised host.
- [G0142] Confucius: Confucius has downloaded additional files and payloads onto a compromised host following initial access.
- [C0021] C0021: During C0021, the threat actors downloaded additional tools and files onto victim machines.
- [S0431] HotCroissant: HotCroissant has the ability to upload a file from the command and control (C2) server to the victim machine.
- [S0626] P8RAT: P8RAT can download additional payloads to a target system.
- [S0473] Avenger: Avenger has the ability to download files from C2 to a compromised host.
- [C0007] FunnyDream: During FunnyDream, the threat actors downloaded additional droppers and backdoors onto a compromised system.
- [S0264] OopsIE: OopsIE can download files from its C2 server to the victim's machine.
- [S0093] Backdoor.Oldrea: Backdoor.Oldrea can download additional modules from C2.
- [S0586] TAINTEDSCRIBE: TAINTEDSCRIBE can download additional modules from its C2 server.
- [S0409] Machete: Machete can download additional files for execution on the victim’s machine.
- [S1086] Snip3: Snip3 can download additional payloads to compromised systems.
- [S1060] Mafalda: Mafalda can download additional files onto the compromised host.
- [S0661] FoggyWeb: FoggyWeb can receive additional malicious components from an actor controlled C2 server and execute them on a compromised AD FS server.
- [S0533] SLOTHFULMEDIA: SLOTHFULMEDIA has downloaded files onto a victim machine.
- [S0369] CoinTicker: CoinTicker executes a Python script to download its second stage.
- [S0236] Kwampirs: Kwampirs downloads additional files from C2 servers.
- [S0561] GuLoader: GuLoader can download further malware for execution on the victim's machine.
- [S1044] FunnyDream: FunnyDream can download additional files onto a compromised host.
- [S0134] Downdelph: After downloading its main config file, Downdelph downloads multiple payloads from C2 servers.
- [S1172] OilBooster: OilBooster can download and execute files from an actor-controlled OneDrive account.
- [S0671] Tomiris: Tomiris can download files and execute them on a victim's system.
- [S0462] CARROTBAT: CARROTBAT has the ability to download and execute a remote file via certutil.
- [S0190] BITSAdmin: BITSAdmin can be used to create BITS Jobs to upload and/or download files.
- [C0045] ShadowRay: During ShadowRay, threat actors downloaded and executed the XMRig miner on targeted hosts.
- [S0381] FlawedAmmyy: FlawedAmmyy can transfer files from C2.
- [S0585] Kerrdown: Kerrdown can download specific payloads to a compromised host based on OS architecture.
- [S0469] ABK: ABK has the ability to download files from C2.
- [S0115] Crimson: Crimson contains a command to retrieve files from its C2 server.
- [G0064] APT33: APT33 has downloaded additional files and programs from its C2 server.
- [G0102] Wizard Spider: Wizard Spider can transfer malicious payloads such as ransomware to compromised machines.
- [S0239] Bankshot: Bankshot uploads files and secondary payloads to the victim's machine.
- [S0681] Lizar: Lizar can download additional plugins, files, and tools.
- [S0078] Psylo: Psylo has a command to download a file to the system from its C2 server.
- [S0342] GreyEnergy: GreyEnergy can download additional modules and payloads.
- [S0275] UPPERCUT: UPPERCUT can download and upload files to and from the victim’s machine.
- [S1025] Amadey: Amadey can download and execute files to further infect a host machine with additional malware.
- [S0109] WEBC2: WEBC2 can download and execute a file.
- [S0513] LiteDuke: LiteDuke has the ability to download files.
- [S0569] Explosive: Explosive has a function to download a file to the infected system.
- [S0132] H1N1: H1N1 contains a command to download and execute a file from a remotely hosted URL using WinINet HTTP requests.
- [S0483] IcedID: IcedID has the ability to download additional modules and a configuration file from C2.
- [S1090] NightClub: NightClub can load multiple additional plugins on an infected host.
- [C0026] C0026: During C0026, the threat actors downloaded malicious payloads onto select compromised hosts.
- [S0496] REvil: REvil can download a copy of itself from an attacker controlled IP address to the victim machine.
- [S0650] QakBot: QakBot has the ability to download additional components and malware.
- [G0123] Volatile Cedar: Volatile Cedar can deploy additional tools.
- [S0495] RDAT: RDAT can download files via DNS.
- [S1026] Mongall: Mongall can download files to targeted systems.
- [S1023] CreepyDrive: CreepyDrive can download files to the compromised host.
- [G0120] Evilnum: Evilnum can deploy additional components or tools as needed.
- [S0141] Winnti for Windows: The Winnti for Windows dropper can place malicious payloads on targeted systems.
- [S0373] Astaroth: Astaroth uses certutil and BITSAdmin to download additional malware.
- [S0332] Remcos: Remcos can upload and download files to and from the victim’s machine.
- [G1036] Moonstone Sleet: Moonstone Sleet retrieved a final stage payload from command and control infrastructure during initial installation on victim systems.
- [S0083] Misdat: Misdat is capable of downloading files from the C2.
- [S0012] PoisonIvy: PoisonIvy creates a backdoor through which remote attackers can upload files.
- [S0653] xCaon: xCaon has a command to download files to the victim's machine.
- [S0164] TDTESS: TDTESS has a command to download and execute an additional file.
- [S0017] BISCUIT: BISCUIT has a command to download a file from the C2 server.
- [G0046] FIN7: FIN7 has downloaded additional malware to execute on the victim's machine, including by using a PowerShell script to launch shellcode that retrieves an additional payload.
- [G1035] Winter Vivern: Winter Vivern executed PowerShell scripts to create scheduled tasks to retrieve remotely-hosted payloads.
- [S0022] Uroburos: Uroburos can use a `Put` command to write files to an infected machine.
- [G0092] TA505: TA505 has downloaded additional malware to execute on victim systems.
- [S0166] RemoteCMD: RemoteCMD copies a file over to the remote system before execution.
- [S0568] EVILNUM: EVILNUM can download and upload files to the victim's computer.
- [S0128] BADNEWS: BADNEWS is capable of downloading additional files through C2 channels, including a new version of itself.
- [G0096] APT41: APT41 used certutil to download additional files. APT41 downloaded post-exploitation tools such as Cobalt Strike via command shell following initial access. APT41 has uploaded Procdump and NATBypass to a staging directory and has used these tools in follow-on activities.
- [S0376] HOPLIGHT: HOPLIGHT has the ability to connect to a remote host in order to upload and download files.
- [C0024] SolarWinds Compromise: During the SolarWinds Compromise, APT29 downloaded additional malware, such as TEARDROP and Cobalt Strike, onto a compromised host following initial access.
- [G0133] Nomadic Octopus: Nomadic Octopus has used malicious macros to download additional files to the victim's machine.
- [G0135] BackdoorDiplomacy: BackdoorDiplomacy has downloaded additional files and tools onto a compromised host.
- [S0493] GoldenSpy: GoldenSpy constantly attempts to download and execute files from the remote C2, including GoldenSpy itself if not found on the system.
- [S0260] InvisiMole: InvisiMole can upload files to the victim's machine for operations.
- [C0010] C0010: During C0010, UNC3890 actors downloaded tools and malware onto a compromised host.
- [S0459] MechaFlounder: MechaFlounder has the ability to upload and download files to and from a compromised host.
- [C0013] Operation Sharpshooter: During Operation Sharpshooter, additional payloads were downloaded after a target was infected with a first-stage downloader.
- [S0564] BlackMould: BlackMould has the ability to download files to the victim's machine.
- [S0588] GoldMax: GoldMax can download and execute additional files.
- [S0095] ftp: ftp may be abused by adversaries to transfer tools or files from an external system into a compromised environment.
- [S0404] esentutl: esentutl can be used to copy files from a given URL.
- [G1001] HEXANE: HEXANE has downloaded additional payloads and malicious scripts onto a compromised host.
- [S1059] metaMain: metaMain can download files onto compromised systems.
- [S0402] OSX/Shlayer: OSX/Shlayer can download payloads, and extract bytes from files. OSX/Shlayer uses the curl -fsL "$url" >$tmp_path command to download malicious payloads into a temporary directory.
- [S0077] CallMe: CallMe has the capability to download a file to the victim from the C2 server.
- [S0150] POSHSPY: POSHSPY downloads and executes additional PowerShell code and Windows binaries.
- [S0394] HiddenWasp: HiddenWasp downloads a tar compressed archive from a download server to the system.
- [S0647] Turian: Turian can download additional files and tools from its C2.
- [S0230] ZeroT: ZeroT can download additional payloads onto the victim.
- [S0642] BADFLICK: BADFLICK has download files from its C2 server.
- [G0044] Winnti Group: Winnti Group has downloaded an auxiliary program named ff.exe to infected machines.
- [S0088] Kasidet: Kasidet has the ability to download and execute additional files.
- [G0099] APT-C-36: APT-C-36 has downloaded binary data from a specified domain after the malicious document is opened.
- [G0061] FIN8: FIN8 has used remote code execution to download subsequent payloads.
- [G0112] Windshift: Windshift has used tools to deploy additional payloads to compromised hosts.
- [G0127] TA551: TA551 has retrieved DLLs and installer binaries for malware execution from C2.
- [S0217] SHUTTERSPEED: SHUTTERSPEED can download and execute an arbitary executable.
- [S0184] POWRUNER: POWRUNER can download or upload files from its C2 server.
- [G0129] Mustang Panda: Mustang Panda has downloaded additional executables following the initial infection stage.
- [S0534] Bazar: Bazar can download and deploy additional payloads, including ransomware and post-exploitation frameworks such as Cobalt Strike.
- [S0695] Donut: Donut can download and execute previously staged shellcode payloads.
- [S0340] Octopus: Octopus can download additional files and tools onto the victim’s machine.
- [S0491] StrongPity: StrongPity can download files to specified targets.
- [S0148] RTM: RTM can download additional files.
- [S0398] HyperBro: HyperBro has the ability to download additional files.
- [C0006] Operation Honeybee: During Operation Honeybee, the threat actors downloaded additional malware and malicious scripts onto a compromised host.
- [S1087] AsyncRAT: AsyncRAT has the ability to download files over SFTP.
- [S0687] Cyclops Blink: Cyclops Blink has the ability to download files to target systems.
- [G0035] Dragonfly: Dragonfly has copied and installed tools for operations once in the victim environment.
- [S0456] Aria-body: Aria-body has the ability to download additional payloads from C2.
- [S0553] MoleNet: MoleNet can download additional payloads from the C2.
- [S0601] Hildegard: Hildegard has downloaded additional scripts that build and run Monero cryptocurrency miners.
- [G1009] Moses Staff: Moses Staff has downloaded and installed web shells to following path C:\inetpub\wwwroot\aspnet_client\system_web\IISpool.aspx.
- [G0012] Darkhotel: Darkhotel has used first-stage payloads that download additional malware from C2 servers.
- [G1017] Volt Typhoon: Volt Typhoon has downloaded an outdated version of comsvcs.dll to a compromised domain controller in a non-standard folder.
- [S0124] Pisloader: Pisloader has a command to upload a file to the victim machine.
- [S0223] POWERSTATS: POWERSTATS can retrieve and execute additional PowerShell payloads from the C2 server.
- [S0500] MCMD: MCMD can upload additional files to a compromised host.
- [S0154] Cobalt Strike: Cobalt Strike can deliver additional payloads to victim machines.
- [G0090] WIRTE: WIRTE has downloaded PowerShell code from the C2 server to be executed.
- [S0145] POWERSOURCE: POWERSOURCE has been observed being used to download TEXTMATE and the Cobalt Strike Beacon payload onto victims.
- [S1138] Gootloader: Gootloader can fetch second stage code from hardcoded web domains.
- [S1183] StrelaStealer: StrelaStealer installers have used obfuscated PowerShell scripts to retrieve follow-on payloads from WebDAV servers.
- [S0572] Caterpillar WebShell: Caterpillar WebShell has a module to download and upload files to the system.
- [S0659] Diavol: Diavol can receive configuration updates and additional payloads including wscpy.exe from C2.
- [S0257] VERMIN: VERMIN can download and upload files to the victim's machine.
- [S1063] Brute Ratel C4: Brute Ratel C4 can download files to compromised hosts.
- [S0080] Mivast: Mivast has the capability to download and execute .exe files.
- [G0060] BRONZE BUTLER: BRONZE BUTLER has used various tools to download files, including DGet (a similar tool to wget).
- [S0471] build_downer: build_downer has the ability to download files from C2 to the infected host.
- [S0241] RATANKBA: RATANKBA uploads and downloads information.
- [S0266] TrickBot: TrickBot downloads several additional files and saves them to the victim's machine.
- [G0119] Indrik Spider: Indrik Spider has downloaded additional scripts, malware, and tools onto a compromised host.
- [G0040] Patchwork: Patchwork payloads download additional files from the C2 server.
- [S0486] Bonadan: Bonadan can download additional modules from the C2 server.
- [S1211] Hannotog: Hannotog can download additional files to the victim machine.
- [S0498] Cryptoistic: Cryptoistic has the ability to send and receive files.
- [S0599] Kinsing: Kinsing has downloaded additional lateral movement scripts from C2.
- [S0360] BONDUPDATER: BONDUPDATER can download or upload files from its C2 server.
- [G0128] ZIRCONIUM: ZIRCONIUM has used tools to download malicious files to compromised hosts.
- [C0038] HomeLand Justice: During HomeLand Justice, threat actors used web shells to download files to compromised infrastructure.
- [S0455] Metamorfo: Metamorfo has used MSI files to download additional files to execute.
- [G1032] INC Ransom: INC Ransom has downloaded tools to compromised servers including Advanced IP Scanner.
- [S0674] CharmPower: CharmPower has the ability to download additional modules to a compromised host.
- [G0093] GALLIUM: GALLIUM dropped additional tools to victims during their operation, including portqry.exe, a renamed cmd.exe file, winrar, and HTRAN.
- [S1017] OutSteel: OutSteel can download files from its C2 server.
- [S1016] MacMa: MacMa has downloaded additional files, including an exploit for used privilege escalation.
- [S1114] ZIPLINE: ZIPLINE can download files to be saved on the compromised system.
- [S0592] RemoteUtilities: RemoteUtilities can upload and download files to and from a target machine.
- [S0631] Chaes: Chaes can download additional files onto an infected machine.
- [G1013] Metador: Metador has downloaded tools and malware onto a compromised system.
- [S0137] CORESHELL: CORESHELL downloads another dropper from its C2 server.
- [S0267] FELIXROOT: FELIXROOT downloads and uploads files to and from the victim’s machine.
- [C0018] C0018: During C0018, the threat actors downloaded additional tools, such as Mimikatz and Sliver, as well as Cobalt Strike and AvosLocker ransomware onto the victim network.
- [S1152] IMAPLoader: IMAPLoader is a loader used to retrieve follow-on payload encoded in email messages for execution on victim systems.
- [S0559] SUNBURST: SUNBURST delivered different payloads, including TEARDROP in at least one instance.
- [S0171] Felismus: Felismus can download files from remote servers.
- [S0595] ThiefQuest: ThiefQuest can download and execute payloads in-memory or from disk.
- [G0034] Sandworm Team: Sandworm Team has pushed additional malicious tools onto an infected system to steal user credentials, move laterally, and destroy data.
- [S0333] UBoatRAT: UBoatRAT can upload and download files to the victim’s machine.
- [S0457] Netwalker: Operators deploying Netwalker have used psexec and certutil to retrieve the Netwalker payload.
- [S0624] Ecipekac: Ecipekac can download additional payloads to a compromised host.
- [S0258] RGDoor: RGDoor uploads and downloads files to and from the victim’s machine.
- [C0002] Night Dragon: During Night Dragon, threat actors used administrative utilities to deliver Trojan components to remote systems.
- [G1020] Mustard Tempest: Mustard Tempest has deployed secondary payloads and third stage implants to compromised hosts.
- [C0014] Operation Wocao: During Operation Wocao, threat actors downloaded additional files to the infected system.
- [S0567] Dtrack: Dtrack’s can download and upload a file to the victim’s computer.
- [G0138] Andariel: Andariel has downloaded additional tools and malware onto compromised hosts.
- [S1112] STEADYPULSE: STEADYPULSE can add lines to a Perl script on a targeted server to import additional Perl modules.
- [G0130] Ajax Security Team: Ajax Security Team has used Wrapper/Gholee, custom-developed malware, which downloaded additional malware to the infected system.
- [S0363] Empire: Empire can upload and download to and from a victim machine.
- [S1089] SharpDisco: SharpDisco has been used to download a Python interpreter to `C:\Users\Public\WinTN\WinTN.exe` as well as other plugins from external sources.
- [S0689] WhisperGate: WhisperGate can download additional stages of malware from a Discord CDN channel.
- [G0066] Elderwood: The Ritsol backdoor trojan used by Elderwood can download files onto a compromised host from a remote location.
- [S1034] StrifeWater: StrifeWater can download updates and auxiliary modules.
- [S0351] Cannon: Cannon can download a payload for execution.
- [S0044] JHUHUGIT: JHUHUGIT can retrieve an additional payload from its C2 server. JHUHUGIT has a command to download files to the victim’s machine.
- [S0502] Drovorub: Drovorub can download files to a compromised host.
- [S1192] NICECURL: NICECURL has the ability to download additional content onto an infected machine, e.g. by using `curl`.
- [S0153] RedLeaves: RedLeaves is capable of downloading a file from a specified URL.
- [S0648] JSS Loader: JSS Loader has the ability to download malicious executables to a compromised host.
- [S0198] NETWIRE: NETWIRE can downloaded payloads from C2 to the compromised host.
- [G0022] APT3: APT3 has a tool that can copy files to remote machines.
- [S0596] ShadowPad: ShadowPad has downloaded code from a C2 server.
- [S0447] Lokibot: Lokibot downloaded several staged items onto the victim's machine.
- [S0598] P.A.S. Webshell: P.A.S. Webshell can upload and download files to and from compromised hosts.
- [G0114] Chimera: Chimera has remotely copied tools and malware onto targeted systems.
- [S0608] Conficker: Conficker downloads an HTTP server to the infected machine.
- [S0009] Hikit: Hikit has the ability to download files to a compromised host.
- [G0131] Tonto Team: Tonto Team has downloaded malicious DLLs which served as a ShadowPad loader.
- [C0017] C0017: During C0017, APT41 downloaded malicious payloads onto compromised systems.
- [S0092] Agent.btz: Agent.btz attempts to download an encrypted binary from a specified domain.
- [S0254] PLAINTEE: PLAINTEE has downloaded and executed additional plugins.
- [S0442] VBShower: VBShower has the ability to download VBS files to the target computer.
- [S0528] Javali: Javali can download payloads from remote C2 servers.
- [G0136] IndigoZebra: IndigoZebra has downloaded additional files and tools from its C2 server.
- [S0412] ZxShell: ZxShell has a command to transfer files from a remote host.


### T1132.001 - Data Encoding: Standard Encoding

Description:

Adversaries may encode data with a standard data encoding system to make the content of command and control traffic more difficult to detect. Command and control (C2) information can be encoded using a standard data encoding system that adheres to existing protocol specifications. Common data encoding schemes include ASCII, Unicode, hexadecimal, Base64, and MIME. Some data encoding systems may also result in data compression, such as gzip.

Detection:

Analyze network data for uncommon data flows (e.g., a client sending significantly more data than it receives from a server). Processes utilizing the network that do not normally have network communication or have never been seen before are suspicious. Analyze packet contents to detect communications that do not follow the expected protocol behavior for the port that is being used.

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
- [S0678] Torisma: Torisma has encoded C2 communications with Base64.
- [S0044] JHUHUGIT: A JHUHUGIT variant encodes C2 POST data base64.
- [S0559] SUNBURST: SUNBURST used Base64 encoding in its C2 traffic.
- [S1060] Mafalda: Mafalda can encode data using Base64 prior to exfiltration.
- [S0649] SMOKEDHAM: SMOKEDHAM has encoded its C2 traffic with Base64.
- [S1110] SLIGHTPULSE: SLIGHTPULSE can base64 encode all incoming and outgoing C2 messages.
- [S0137] CORESHELL: CORESHELL C2 messages are Base64-encoded.
- [S0269] QUADAGENT: QUADAGENT encodes C2 communications with base64.
- [S0373] Astaroth: Astaroth encodes data using Base64 before sending it to the C2 server.
- [G1044] APT42: APT42 has encoded C2 traffic with Base64.
- [S0144] ChChes: ChChes can encode C2 data with a custom technique that utilizes Base64.
- [S1078] RotaJakiro: RotaJakiro uses ZLIB Compression to compresses data sent to the C2 server in the `payload` section network communication packet.
- [S0520] BLINDINGCAN: BLINDINGCAN has encoded its C2 traffic with Base64.
- [S1193] TAMECAT: TAMECAT has encoded C2 traffic with Base64.
- [S0367] Emotet: Emotet has used Google’s Protobufs to serialize data sent to and from the C2 server. Additionally, Emotet has used Base64 to encode data before sending to the C2 server.
- [S0340] Octopus: Octopus has encoded C2 communications in Base64.
- [S0187] Daserf: Daserf uses custom base64 encoding to obfuscate HTTP traffic.
- [S0495] RDAT: RDAT can communicate with the C2 via base32-encoded subdomains.
- [S0124] Pisloader: Responses from the Pisloader C2 server are base32-encoded.
- [S0632] GrimAgent: GrimAgent can base64 encode C2 replies.
- [S1112] STEADYPULSE: STEADYPULSE can transmit URL encoded data over C2.
- [G0060] BRONZE BUTLER: Several BRONZE BUTLER tools encode data with base64 when posting it to a C2 server.
- [S0543] Spark: Spark has encoded communications with the C2 server with base64.
- [S0459] MechaFlounder: MechaFlounder has the ability to use base16 encoded strings in C2.
- [S0354] Denis: Denis encodes the data sent to the server in Base64.
- [S0264] OopsIE: OopsIE encodes data in hexadecimal format over the C2 channel.
- [S0265] Kazuar: Kazuar encodes communications to the C2 server in Base64.
- [S0409] Machete: Machete has used base64 encoding.
- [S1031] PingPull: PingPull can encode C2 traffic with Base64.
- [C0044] Juicy Mix: During Juicy Mix, OilRig used a VBS script to send the Base64-encoded name of the compromised computer to C2.
- [G0127] TA551: TA551 has used encoded ASCII text for initial C2 communications.
- [S0379] Revenge RAT: Revenge RAT uses Base64 to encode information sent to the C2 server.
- [S1198] Gomir: Gomir uses Base64-encoded content in HTTP communications to command and control infrastructure.
- [S0352] OSX_OCEANLOTUS.D: OSX_OCEANLOTUS.D has used `zlib` to compress all data after 0x52 for the custom TCP C2 protocol.
- [S0223] POWERSTATS: POWERSTATS encoded C2 traffic with base64.
- [S0093] Backdoor.Oldrea: Some Backdoor.Oldrea samples use standard Base64 + bzip2, and some use standard Base64 + reverse XOR + RSA-2048 to decrypt data received from C2 servers.
- [S0376] HOPLIGHT: HOPLIGHT has utilized Zlib compression to obfuscate the communications payload.
- [S0439] Okrum: Okrum has used base64 to encode C2 communication.
- [S1030] Squirrelwaffle: Squirrelwaffle has encoded its communications to C2 servers using Base64.
- [S0128] BADNEWS: BADNEWS encodes C2 traffic with base64.
- [S1039] Bumblebee: Bumblebee has the ability to base64 encode C2 server responses.
- [S0385] njRAT: njRAT uses Base64 encoding for C2 traffic.
- [S0266] TrickBot: TrickBot can Base64-encode C2 commands.
- [S0084] Mis-Type: Mis-Type uses Base64 encoding for C2 traffic.
- [S0129] AutoIt backdoor: AutoIt backdoor has sent a C2 response that was base64-encoded.
- [S0085] S-Type: S-Type uses Base64 encoding for C2 traffic.
- [G0032] Lazarus Group: A Lazarus Group malware sample encodes data with base64.
- [S0673] DarkWatchman: DarkWatchman encodes data using hexadecimal representation before sending it to the C2 server.
- [S0200] Dipsind: Dipsind encodes C2 traffic with base64.
- [S0270] RogueRobin: RogueRobin base64 encodes strings that are sent to the C2 over its DNS tunnel.
- [S0514] WellMess: WellMess has used Base64 encoding to uniquely identify communication to and from the C2.
- [S1108] PULSECHECK: PULSECHECK can base-64 encode encrypted data sent through C2.
- [S1183] StrelaStealer: StrelaStealer utilizes a hard-coded XOR key to encrypt the content of HTTP POST requests to command and control infrastructure.
- [S0487] Kessel: Kessel has exfiltrated data via hexadecimal-encoded subdomain fields of DNS queries.
- [G0081] Tropic Trooper: Tropic Trooper has used base64 encoding to hide command strings delivered from the C2.
- [S0414] BabyShark: BabyShark has encoded data using certutil before exfiltration.
- [S0015] Ixeshe: Ixeshe uses custom Base64 encoding schemes to obfuscate command and control traffic in the message body of HTTP requests.
- [S1190] Kapeka: Kapeka utilizes JSON objects to send and receive information from command and control nodes.
- [S1024] CreepySnail: CreepySnail can use Base64 to encode its C2 traffic.
- [S0441] PowerShower: PowerShower has the ability to encode C2 communications with base64 encoding.
- [S0113] Prikormka: Prikormka encodes C2 traffic with Base64.
- [S0356] KONNI: KONNI has used a custom base64 key to encode stolen data before exfiltration.
- [S0268] Bisonal: Bisonal has encoded binary data with Base64 and ASCII.
- [S1202] LockBit 3.0: LockBit 3.0 can Base64-encode C2 communication.
- [S0083] Misdat: Misdat network traffic is Base64-encoded plaintext.
- [G0069] MuddyWater: MuddyWater has used tools to encode C2 communications including Base64 encoding.
- [S1166] Solar: Solar can Base64-encode and gzip compress C2 communications including command outputs.
- [S0338] Cobian RAT: Cobian RAT obfuscates communications with the C2 server using Base64 encoding.
- [S0014] BS2005: BS2005 uses Base64 encoding for communication in the message body of an HTTP request.
- [S1026] Mongall: Mongall can use Base64 to encode information sent to its C2.
- [S0284] More_eggs: More_eggs has used basE91 encoding, along with encryption, for C2 communication.
- [S1085] Sardonic: Sardonic can encode client ID data in 32 uppercase hex characters and transfer to the actor-controlled C2 server.
- [S1138] Gootloader: Gootloader can retrieve a Base64 encoded stager from C2.
- [S1099] Samurai: Samurai can base64 encode data sent in C2 communications prior to its encryption.
- [S1145] Pikabot: Pikabot uses base64 encoding in conjunction with symmetric encryption mechanisms to obfuscate command and control communications.
- [S1156] Manjusaka: Manjusaka communication includes a client-created session cookie with base64-encoded information representing information from the victim system.
- [S0653] xCaon: xCaon has used Base64 to encode its C2 traffic.
- [S1115] WIREFIRE: WIREFIRE can Base64 encode process output sent to C2.
- [S0184] POWRUNER: POWRUNER can use base64 encoded C2 communications.
- [S0171] Felismus: Some Felismus samples use a custom method for C2 traffic that utilizes Base64.
- [S0476] Valak: Valak has returned C2 data as encoded ASCII.
- [S0374] SpeakUp: SpeakUp encodes C&C communication using Base64.
- [S1047] Mori: Mori can use Base64 encoded JSON libraries used in C2.
- [S0377] Ebury: Ebury has encoded C2 traffic in hexadecimal format.
- [S1169] Mango: Mango can receive Base64-encoded commands from C2.
- [S0032] gh0st RAT: gh0st RAT has used Zlib to compress C2 communications data before encrypting it.
- [S0081] Elise: Elise exfiltrates data using cookie values that are Base64-encoded.
- [S0154] Cobalt Strike: Cobalt Strike can use Base64, URL-safe Base64, or NetBIOS encoding in its C2 traffic.
- [G0073] APT19: An APT19 HTTP malware variant used Base64 to encode communications to the C2 server.
- [S0650] QakBot: QakBot can Base64 encode system information sent to C2.
- [S0251] Zebrocy: Zebrocy has used URL/Percent Encoding on data exfiltrated via HTTP POST requests.
- [S0030] Carbanak: Carbanak encodes the message body of HTTP traffic with Base64.
- [S0633] Sliver: Sliver can use standard encoding techniques like gzip and hex to ASCII to encode the C2 communication payload.
- [S1116] WARPWIRE: WARPWIRE can Base64 encode captured credentials with `btoa()` prior to sending to C2.
- [G0064] APT33: APT33 has used base64 to encode command and control traffic.
- [S1141] LunarWeb: LunarWeb can use Base64 encoding to obfuscate C2 commands.
- [S1037] STARWHALE: STARWHALE has the ability to hex-encode collected data from an infected host.
- [S0674] CharmPower: CharmPower can send additional modules over C2 encoded with base64.
- [S0170] Helminth: For C2 over HTTP, Helminth encodes data with base64 and sends it via the "Cookie" field of HTTP requests. For C2 over DNS, Helminth converts ASCII characters into their hexadecimal values and sends the data in cleartext.
- [S1018] Saint Bot: Saint Bot has used Base64 to encode its C2 communications.
- [S1076] QUIETCANARY: QUIETCANARY can base64 encode C2 communications.
- [S0458] Ramsay: Ramsay has used base64 to encode its C2 traffic.
- [G0125] HAFNIUM: HAFNIUM has used ASCII encoding for C2 traffic.
- [S1117] GLASSTOKEN: GLASSTOKEN has hexadecimal and Base64 encoded C2 content.

### T1132.002 - Data Encoding: Non-Standard Encoding

Description:

Adversaries may encode data with a non-standard data encoding system to make the content of command and control traffic more difficult to detect. Command and control (C2) information can be encoded using a non-standard data encoding system that diverges from existing protocol specifications. Non-standard data encoding schemes may be based on or related to standard data encoding schemes, such as a modified Base64 encoding for the message body of an HTTP request.

Detection:

Analyze network data for uncommon data flows (e.g., a client sending significantly more data than it receives from a server). Processes utilizing the network that do not normally have network communication or have never been seen before are suspicious. Analyze packet contents to detect communications that do not follow the expected protocol behavior for the port that is being used.

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

Description:

Adversaries may use port knocking to hide open ports used for persistence or command and control. To enable a port, an adversary sends a series of attempted connections to a predefined sequence of closed ports. After the sequence is completed, opening a port is often accomplished by the host based firewall, but could also be implemented by custom software. This technique has been observed both for the dynamic opening of a listening port as well as the initiating of a connection to a listening server on a different system. The observation of the signal packets to trigger the communication can be conducted through different methods. One means, originally implemented by Cd00r , is to use the libpcap libraries to sniff for the packets in question. Another method leverages raw sockets, which enables the malware to use ports that are already open for use by other programs.

Detection:

Record network packets sent to and from the system, looking for extraneous packets that do not belong to established flows.

Procedures:

- [S1060] Mafalda: Mafalda can use port-knocking to authenticate itself to another implant called Cryshell to establish an indirect connection to the C2 server.
- [G0056] PROMETHIUM: PROMETHIUM has used a script that configures the knockd service and firewall to only accept C2 connections from systems that use a specified sequence of knock ports.
- [S1204] cd00r: cd00r can monitor for a single TCP-SYN packet to be sent in series to a configurable set of ports (200, 80, 22, 53 and 3 in the original code) before opening a port for communication.
- [S1059] metaMain: metaMain has authenticated itself to a different implant, Cryshell, through a port knocking and handshake procedure.

### T1205.002 - Traffic Signaling: Socket Filters

Description:

Adversaries may attach filters to a network socket to monitor then activate backdoors used for persistence or command and control. With elevated permissions, adversaries can use features such as the `libpcap` library to open sockets and install filters to allow or disallow certain types of data to come through the socket. The filter may apply to all traffic passing through the specified network interface (or every interface if not specified). When the network interface receives a packet matching the filter criteria, additional actions can be triggered on the host, such as activation of a reverse shell. To establish a connection, an adversary sends a crafted packet to the targeted host that matches the installed filter criteria. Adversaries have used these socket filters to trigger the installation of implants, conduct ping backs, and to invoke command shells. Communication with these socket filters may also be used in conjunction with Protocol Tunneling. Filters can be installed on any Unix-like platform with `libpcap` installed or on Windows hosts using `Winpcap`. Adversaries may use either `libpcap` with `pcap_setfilter` or the standard library function `setsockopt` with `SO_ATTACH_FILTER` options. Since the socket connection is not active until the packet is received, this behavior may be difficult to detect due to the lack of activity on a host, low CPU overhead, and limited visibility into raw socket usage.

Detection:

Identify running processes with raw sockets. Ensure processes listed have a need for an open raw socket and are in accordance with enterprise policy.

Procedures:

- [S1161] BPFDoor: BPFDoor uses BPF bytecode to attach a filter to a network socket to view ICMP, UDP, or TCP packets coming through ports 22 (ssh), 80 (http), and 443 (https). When BPFDoor finds a packet containing its “magic” bytes, it parses out two fields and forks itself. The parent process continues to monitor filtered traffic while the child process executes the instructions from the parsed fields.
- [S1123] PITSTOP: PITSTOP can listen and evaluate incoming commands on the domain socket, created by PITHOOK malware, located at `/data/runtime/cockpit/wd.fd` for a predefined magic byte sequence. PITSTOP can then duplicate the socket for further communication over TLS.
- [S0587] Penquin: Penquin installs a `TCP` and `UDP` filter on the `eth0` interface.


### T1219.001 - Remote Access Tools: IDE Tunneling

Description:

Adversaries may abuse Integrated Development Environment (IDE) software with remote development features to establish an interactive command and control channel on target systems within a network. IDE tunneling combines SSH, port forwarding, file sharing, and debugging into a single secure connection, letting developers work on remote systems as if they were local. Unlike SSH and port forwarding, IDE tunneling encapsulates an entire session and may use proprietary tunneling protocols alongside SSH, allowing adversaries to blend in with legitimate development workflows. Some IDEs, like Visual Studio Code, also provide CLI tools (e.g., `code tunnel`) that adversaries may use to programmatically establish tunnels and generate web-accessible URLs for remote access. These tunnels can be authenticated through accounts such as GitHub, enabling the adversary to control the compromised system via a legitimate developer portal. Additionally, adversaries may use IDE tunneling for persistence. Some IDEs, such as Visual Studio Code and JetBrains, support automatic reconnection. Adversaries may configure the IDE to auto-launch at startup, re-establishing the tunnel upon execution. Compromised developer machines may also be exploited as jump hosts to move further into the network. IDE tunneling tools may be built-in or installed as IDE Extensions.

### T1219.002 - Remote Access Tools: Remote Desktop Software

Description:

An adversary may use legitimate desktop support software to establish an interactive command and control channel to target systems within networks. Desktop support software provides a graphical interface for remotely controlling another computer, transmitting the display output, keyboard input, and mouse control between devices using various protocols. Desktop support software, such as `VNC`, `Team Viewer`, `AnyDesk`, `ScreenConnect`, `LogMein`, `AmmyyAdmin`, and other remote monitoring and management (RMM) tools, are commonly used as legitimate technical support software and may be allowed by application control within a target environment. Remote access modules/features may also exist as part of otherwise existing software such as Zoom or Google Chrome’s Remote Desktop.

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

Description:

An adversary may use legitimate remote access hardware to establish an interactive command and control channel to target systems within networks. These services, including IP-based keyboard, video, or mouse (KVM) devices such as TinyPilot and PiKVM, are commonly used as legitimate tools and may be allowed by peripheral device policies within a target environment. Remote access hardware may be physically installed and used post-compromise as an alternate communications channel for redundant access or as a way to establish an interactive remote session with the target system. Using hardware-based remote access tools may allow threat actors to bypass software security solutions and gain more control over the compromised device(s).


### T1568.001 - Dynamic Resolution: Fast Flux DNS

Description:

Adversaries may use Fast Flux DNS to hide a command and control channel behind an array of rapidly changing IP addresses linked to a single domain resolution. This technique uses a fully qualified domain name, with multiple IP addresses assigned to it which are swapped with high frequency, using a combination of round robin IP addressing and short Time-To-Live (TTL) for a DNS resource record. The simplest, "single-flux" method, involves registering and de-registering an addresses as part of the DNS A (address) record list for a single DNS name. These registrations have a five-minute average lifespan, resulting in a constant shuffle of IP address resolution. In contrast, the "double-flux" method registers and de-registers an address as part of the DNS Name Server record list for the DNS zone, providing additional resilience for the connection. With double-flux additional hosts can act as a proxy to the C2 host, further insulating the true source of the C2 channel.

Detection:

In general, detecting usage of fast flux DNS is difficult due to web traffic load balancing that services client requests quickly. In single flux cases only IP addresses change for static domain names. In double flux cases, nothing is static. Defenders such as domain registrars and service providers are likely in the best position for detection.

Procedures:

- [S1025] Amadey: Amadey has used fast flux DNS for its C2.
- [G0045] menuPass: menuPass has used dynamic DNS service providers to host malicious domains.
- [G0092] TA505: TA505 has used fast flux to mask botnets by distributing payloads across multiple IPs.
- [S0032] gh0st RAT: gh0st RAT operators have used dynamic DNS to mask the true location of their C2 behind rapidly changing IP addresses.
- [G0047] Gamaredon Group: Gamaredon Group has used fast flux DNS to mask their command and control channel behind rotating IP addresses.
- [S0385] njRAT: njRAT has used a fast flux DNS for C2 IP resolution.

### T1568.002 - Dynamic Resolution: Domain Generation Algorithms

Description:

Adversaries may make use of Domain Generation Algorithms (DGAs) to dynamically identify a destination domain for command and control traffic rather than relying on a list of static IP addresses or domains. This has the advantage of making it much harder for defenders to block, track, or take over the command and control channel, as there potentially could be thousands of domains that malware can check for instructions. DGAs can take the form of apparently random or “gibberish” strings (ex: istgmxdejdnxuyla.ru) when they construct domain names by generating each letter. Alternatively, some DGAs employ whole words as the unit by concatenating words together instead of letters (ex: cityjulydish.net). Many DGAs are time-based, generating a different domain for each time period (hourly, daily, monthly, etc). Others incorporate a seed value as well to make predicting future domains more difficult for defenders. Adversaries may use DGAs for the purpose of Fallback Channels. When contact is lost with the primary command and control server malware may employ a DGA as a means to reestablishing command and control.

Detection:

Detecting dynamically generated domains can be challenging due to the number of different DGA algorithms, constantly evolving malware families, and the increasing complexity of the algorithms. There is a myriad of approaches for detecting a pseudo-randomly generated domain name, including using frequency analysis, Markov chains, entropy, proportion of dictionary words, ratio of vowels to other characters, and more. CDN domains may trigger these detections due to the format of their domain names. In addition to detecting a DGA domain based on the name, another more general approach for detecting a suspicious domain is to check for recently registered names or for rarely visited domains. Machine learning approaches to detecting DGA domains have been developed and have seen success in applications. One approach is to use N-Gram methods to determine a randomness score for strings used in the domain name. If the randomness score is high, and the domains are not whitelisted (CDN, etc), then it may be determined if a domain is related to a legitimate host or DGA. Another approach is to use deep learning to classify domains as DGA-generated.

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
- [S0222] CCBkdr: CCBkdr can use a DGA for Fallback Channels if communications with the primary command and control server are lost.
- [S0531] Grandoreiro: Grandoreiro can use a DGA for hiding C2 addresses, including use of an algorithm with a user-specific key that changes daily.
- [S0596] ShadowPad: ShadowPad uses a DGA that is based on the day of the month for C2 servers.
- [S0373] Astaroth: Astaroth has used a DGA in C2 communications.
- [S0534] Bazar: Bazar can implement DGA using the current date as a seed variable.
- [S1019] Shark: Shark can send DNS C2 communications using a unique domain generation algorithm.
- [S0377] Ebury: Ebury has used a DGA to generate a domain name for C2.

### T1568.003 - Dynamic Resolution: DNS Calculation

Description:

Adversaries may perform calculations on addresses returned in DNS results to determine which port and IP address to use for command and control, rather than relying on a predetermined port number or the actual returned IP address. A IP and/or port number calculation can be used to bypass egress filtering on a C2 channel. One implementation of DNS Calculation is to take the first three octets of an IP address in a DNS response and use those values to calculate the port for command and control traffic.

Detection:

Detection for this technique is difficult because it would require knowledge of the specific implementation of the port calculation algorithm. Detection may be possible by analyzing DNS records if the algorithm is known.

Procedures:

- [G0005] APT12: APT12 has used multiple variants of DNS Calculation including multiplying the first two octets of an IP address and adding the third octet to that value in order to get a resulting command and control port.


### T1571 - Non-Standard Port

Description:

Adversaries may communicate using a protocol and port pairing that are typically not associated. For example, HTTPS over port 8088 or port 587 as opposed to the traditional port 443. Adversaries may make changes to the standard port used by a protocol to bypass filtering or muddle analysis/parsing of network data. Adversaries may also make changes to victim systems to abuse non-standard ports. For example, Registry keys and other configuration settings can be used to modify protocol and port pairings.

Detection:

Analyze packet contents to detect communications that do not follow the expected protocol behavior for the port that is being used. Analyze network data for uncommon data flows (e.g., a client sending significantly more data than it receives from a server). Processes utilizing the network that do not normally have network communication or have never been seen before are suspicious.

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
- [S0412] ZxShell: ZxShell can use ports 1985 and 1986 in HTTP/S communication.
- [G1003] Ember Bear: Ember Bear has used various non-standard ports for C2 communication.
- [S0149] MoonWind: MoonWind communicates over ports 80, 443, 53, and 8080 via raw sockets instead of the protocols usually associated with the ports.
- [G0050] APT32: An APT32 backdoor can use HTTP over a non-standard TCP port (e.g 14146) which is specified in the backdoor configuration.
- [C0018] C0018: During C0018, the threat actors opened a variety of ports, including ports 28035, 32467, 41578, and 46892, to establish RDP connections.
- [G1047] Velvet Ant: Velvet Ant has used random high number ports for PlugX listeners on victim devices.
- [S0246] HARDRAIN: HARDRAIN binds and listens on port 443 with a FakeTLS method.
- [S1145] Pikabot: Pikabot uses non-standard ports, such as 2967, 2223, and others, for HTTPS command and control communication.
- [S0352] OSX_OCEANLOTUS.D: OSX_OCEANLOTUS.D has used a custom binary protocol over TCP port 443 for C2.
- [S0455] Metamorfo: Metamorfo has communicated with hosts over raw TCP on port 9999.
- [C0032] C0032: During the C0032 campaign, TEMP.Veles used port-protocol mismatches on ports such as 443, 4444, 8531, and 50501 during C2.
- [S0574] BendyBear: BendyBear has used a custom RC4 and XOR encrypted protocol over port 443 for C2.
- [G0034] Sandworm Team: Sandworm Team has used port 6789 to accept connections on the group's SSH server.
- [G0032] Lazarus Group: Some Lazarus Group malware uses a list of ordered port numbers to choose a port for C2 traffic, creating port-protocol mismatches.
- [S0385] njRAT: njRAT has used port 1177 for HTTP C2 communications.
- [G0046] FIN7: FIN7 has used port-protocol mismatches on ports such as 53, 80, 443, and 8080 during C2.
- [S1085] Sardonic: Sardonic has the ability to connect with actor-controlled C2 servers using a custom binary protocol over port 443.
- [S1016] MacMa: MacMa has used TCP port 5633 for C2 Communication.
- [S0021] Derusbi: Derusbi has used unencrypted HTTP on port 443 for C2.
- [S1078] RotaJakiro: RotaJakiro uses a custom binary protocol over TCP port 443.
- [S0148] RTM: RTM used Port 44443 for its VNC module.
- [G0059] Magic Hound: Magic Hound malware has communicated with its C2 server over TCP ports 4443 and 10151 using HTTP.
- [S0266] TrickBot: Some TrickBot samples have used HTTP over ports 447 and 8082 for C2. Newer versions of TrickBot have been known to use a custom communication protocol which sends the data unencrypted over port 443.
- [S0262] QuasarRAT: QuasarRAT can use port 4782 on the compromised host for TCP callbacks.
- [S0245] BADCALL: BADCALL communicates on ports 443 and 8000 with a FakeTLS method.
- [S0013] PlugX: PlugX has used random, high-number, non-standard ports to listen for subsequent actions and C2 activities.
- [G0105] DarkVishnya: DarkVishnya used ports 5190 and 7900 for shellcode listeners, and 4444, 4445, 31337 for shellcode C2.
- [C0043] Indian Critical Infrastructure Intrusions: During Indian Critical Infrastructure Intrusions, RedEcho used non-standard ports such as TCP 8080 for HTTP communication.
- [S0263] TYPEFRAME: TYPEFRAME has used ports 443, 8080, and 8443 with a FakeTLS method.
- [C0035] KV Botnet Activity: KV Botnet Activity generates a random port number greater than 30,000 to serve as the listener for subsequent command and control activity.
- [G0099] APT-C-36: APT-C-36 has used port 4050 for C2 communications.
- [S0237] GravityRAT: GravityRAT has used HTTP over a non-standard port, such as TCP port 46769.
- [G0064] APT33: APT33 has used HTTP over TCP ports 808 and 880 for command and control.
- [S0239] Bankshot: Bankshot binds and listens on port 1058 for HTTP traffic while also utilizing a FakeTLS method.
- [S0153] RedLeaves: RedLeaves can use HTTP over non-standard ports, such as 995, for C2.
- [S0687] Cyclops Blink: Cyclops Blink can use non-standard ports for C2 not typically associated with HTTP or HTTPS traffic.
- [G0106] Rocke: Rocke's miner connects to a C2 server using port 51640.


### T1572 - Protocol Tunneling

Description:

Adversaries may tunnel network communications to and from a victim system within a separate protocol to avoid detection/network filtering and/or enable access to otherwise unreachable systems. Tunneling involves explicitly encapsulating a protocol within another. This behavior may conceal malicious traffic by blending in with existing traffic and/or provide an outer layer of encryption (similar to a VPN). Tunneling could also enable routing of network packets that would otherwise not reach their intended destination, such as SMB, RDP, or other traffic that would be filtered by network appliances or not routed over the Internet. There are various means to encapsulate a protocol within another protocol. For example, adversaries may perform SSH tunneling (also known as SSH port forwarding), which involves forwarding arbitrary data over an encrypted SSH tunnel. Protocol Tunneling may also be abused by adversaries during Dynamic Resolution. Known as DNS over HTTPS (DoH), queries to resolve C2 infrastructure may be encapsulated within encrypted HTTPS packets. Adversaries may also leverage Protocol Tunneling in conjunction with Proxy and/or Protocol or Service Impersonation to further conceal C2 communications and infrastructure.

Detection:

Monitoring for systems listening and/or establishing external connections using ports/protocols commonly associated with tunneling, such as SSH (port 22). Also monitor for processes commonly associated with tunneling, such as Plink and the OpenSSH client. Analyze network data for uncommon data flows (e.g., a client sending significantly more data than it receives from a server). Processes utilizing the network that do not normally have network communication or have never been seen before are suspicious. Analyze packet contents to detect application layer protocols that do not follow the expected protocol standards regarding syntax, structure, or any other variable adversaries could leverage to conceal data.

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
- [S1144] FRP: FRP can tunnel SSH and Unix Domain Socket communications over TCP between external nodes and exposed resources behind firewalls or NAT.
- [C0034] 2022 Ukraine Electric Power Attack: During the 2022 Ukraine Electric Power Attack, Sandworm Team deployed the GOGETTER tunneler software to establish a “Yamux” TLS-based C2 channel with an external server(s).
- [S1063] Brute Ratel C4: Brute Ratel C4 can use DNS over HTTPS for C2.
- [G0114] Chimera: Chimera has encapsulated Cobalt Strike's C2 protocol in DNS and HTTPS.
- [S1015] Milan: Milan can use a custom protocol tunneled through DNS or HTTP.
- [C0029] Cutting Edge: During Cutting Edge, threat actors used Iodine to tunnel IPv4 traffic over DNS.
- [S0022] Uroburos: Uroburos has the ability to communicate over custom communications methodologies that ride over common network protocols including raw TCP and UDP sockets, HTTP, SMTP, and DNS.
- [G0049] OilRig: OilRig has used the Plink utility and other tools to create tunnels to C2 servers.
- [S0154] Cobalt Strike: Cobalt Strike uses a custom command and control protocol that is encapsulated in HTTP, HTTPS, or DNS. In addition, it conducts peer-to-peer communication over Windows named pipes encapsulated in the SMB protocol. All protocols use their standard assigned ports.
- [G0117] Fox Kitten: Fox Kitten has used protocol tunneling for communication and RDP activity on compromised hosts through the use of open source tools such as ngrok and custom tool SSHMinion.
- [G0080] Cobalt Group: Cobalt Group has used the Plink utility to create SSH tunnels.
- [G1021] Cinnamon Tempest: Cinnamon Tempest has used the Iox and NPS proxy and tunneling tools in combination create multiple connections through a single tunnel.
- [S0508] ngrok: ngrok can tunnel RDP and other services securely over internet connections.
- [S0699] Mythic: Mythic can use SOCKS proxies to tunnel traffic through another protocol.
- [C0004] CostaRicto: During CostaRicto, the threat actors set up remote SSH tunneling into the victim's environment from a malicious domain.
- [S0173] FLIPSIDE: FLIPSIDE uses RDP to tunnel traffic from a victim environment.
- [S0650] QakBot: The QakBot proxy module can encapsulate SOCKS5 protocol within its own proxy protocol.
- [S0687] Cyclops Blink: Cyclops Blink can use DNS over HTTPS (DoH) to resolve C2 nodes.
- [G0065] Leviathan: Leviathan has used protocol tunneling to further conceal C2 communications and infrastructure.


### T1573.001 - Encrypted Channel: Symmetric Cryptography

Description:

Adversaries may employ a known symmetric encryption algorithm to conceal command and control traffic rather than relying on any inherent protections provided by a communication protocol. Symmetric encryption algorithms use the same key for plaintext encryption and ciphertext decryption. Common symmetric encryption algorithms include AES, DES, 3DES, Blowfish, and RC4.

Detection:

With symmetric encryption, it may be possible to obtain the algorithm and key from samples and use them to decode network traffic to detect malware communications signatures. In general, analyze network data for uncommon data flows (e.g., a client sending significantly more data than it receives from a server). Processes utilizing the network that do not normally have network communication or have never been seen before are suspicious. Analyze packet contents to detect communications that do not follow the expected protocol behavior for the port that is being used.

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
- [S0664] Pandora: Pandora has the ability to encrypt communications with D3DES.
- [S0128] BADNEWS: BADNEWS encrypts C2 data with a ROR by 3 and an XOR by 0x23.
- [S0272] NDiskMonitor: NDiskMonitor uses AES to encrypt certain information sent over its C2 channel.
- [G0129] Mustang Panda: Mustang Panda has encrypted C2 communications with RC4.
- [S1076] QUIETCANARY: QUIETCANARY can RC4 encrypt C2 communications.
- [S1085] Sardonic: Sardonic has the ability to use an RC4 key to encrypt communications to and from actor-controlled C2 servers.
- [G0012] Darkhotel: Darkhotel has used AES-256 and 3DES for C2 communications.
- [S0438] Attor: Attor has encrypted data symmetrically using a randomly generated Blowfish (OFB) key which is encrypted with a public RSA key.
- [S0010] Lurid: Lurid performs XOR encryption.
- [S1034] StrifeWater: StrifeWater can encrypt C2 traffic using XOR with a hard coded key.
- [S0220] Chaos: Chaos provides a reverse shell connection on 8338/TCP, encrypted via AES.
- [S0371] POWERTON: POWERTON has used AES for encrypting C2 traffic.
- [S0559] SUNBURST: SUNBURST encrypted C2 traffic using a single-byte-XOR cipher.
- [S0284] More_eggs: More_eggs has used an RC4-based encryption method for its C2 communications.
- [S0009] Hikit: Hikit performs XOR encryption.
- [S0198] NETWIRE: NETWIRE can use AES encryption for C2 data transferred.
- [S0170] Helminth: Helminth encrypts data sent to its C2 server over HTTP with RC4.
- [S0262] QuasarRAT: QuasarRAT uses AES with a hardcoded pre-shared key to encrypt network communication.
- [S0431] HotCroissant: HotCroissant has compressed network communications and encrypted them with a custom stream cipher.
- [S0486] Bonadan: Bonadan can XOR-encrypt C2 communications.
- [S0532] Lucifer: Lucifer can perform a decremental-xor encryption on the initial C2 request before sending it over the wire.
- [S0011] Taidoor: Taidoor uses RC4 to encrypt the message body of HTTP content.
- [S0087] Hi-Zor: Hi-Zor encrypts C2 traffic with a double XOR using two distinct single-byte keys.
- [S0181] FALLCHILL: FALLCHILL encrypts C2 data with RC4 encryption.
- [C0022] Operation Dream Job: During Operation Dream Job, Lazarus Group used an AES key to communicate with their C2 server.
- [S0256] Mosquito: Mosquito uses a custom encryption algorithm, which consists of XOR and a stream that is similar to the Blum Blum Shub algorithm.
- [S0200] Dipsind: Dipsind encrypts C2 data with AES256 in ECB mode.
- [S0674] CharmPower: CharmPower can send additional modules over C2 encrypted with a simple substitution cipher.
- [S0245] BADCALL: BADCALL encrypts C2 traffic using an XOR/ADD cipher.
- [S0670] WarzoneRAT: WarzoneRAT can encrypt its C2 with RC4 with the password `warzone160\x00`.
- [S0037] HAMMERTOSS: Before being appended to image files, HAMMERTOSS commands are encrypted with a key composed of both a hard-coded value and a string contained on that day's tweet. To decrypt the commands, an investigator would need access to the intended malware sample, the day's tweet, and the image file containing the command.
- [S1169] Mango: Mango can receive XOR-encrypted commands from C2.
- [S1141] LunarWeb: LunarWeb can send AES encrypted C2 commands.
- [S0022] Uroburos: Uroburos can encrypt the data beneath its http2 or tcp encryption at the session layer with CAST-128, using a different key for incoming and outgoing data.
- [S0610] SideTwist: SideTwist can encrypt C2 communications with a randomly generated key.
- [S0352] OSX_OCEANLOTUS.D: OSX_OCEANLOTUS.D encrypts data sent back to the C2 using AES in CBC mode with a null initialization vector (IV) and a key sent from the server that is padded to 32 bytes.
- [S0082] Emissary: The C2 server response to a beacon sent by a variant of Emissary contains a 36-character GUID value that is used as an encryption key for subsequent network communications. Some variants of Emissary use various XOR operations to encrypt C2 data.
- [S0076] FakeM: The original variant of FakeM encrypts C2 traffic using a custom encryption cipher that uses an XOR key of “YHCRA” and bit rotation between each XOR operation. Some variants of FakeM use RC4 to encrypt C2 traffic.
- [S0650] QakBot: QakBot can RC4 encrypt strings in C2 communication.
- [G0032] Lazarus Group: Several Lazarus Group malware families encrypt C2 traffic using custom code that uses XOR with an ADD operation and XOR with a SUB operation. Another Lazarus Group malware sample XORs C2 traffic. Other Lazarus Group malware uses Caracachs encryption to encrypt C2 payloads. Lazarus Group has also used AES to encrypt C2 traffic.
- [S1026] Mongall: Mongall has the ability to RC4 encrypt C2 communications.
- [S0348] Cardinal RAT: Cardinal RAT uses a secret key with a series of XOR and addition operations to encrypt C2 traffic.
- [S0074] Sakula: Sakula encodes C2 traffic with single-byte XOR keys.
- [G0128] ZIRCONIUM: ZIRCONIUM has used AES encrypted communications in C2.
- [S1193] TAMECAT: TAMECAT has used AES to encrypt C2 traffic.
- [G1017] Volt Typhoon: Volt Typhoon has used a version of the Awen web shell that employed AES encryption and decryption for C2 communications.
- [S0180] Volgmer: Volgmer uses a simple XOR cipher to encrypt traffic and files.
- [S0068] httpclient: httpclient encrypts C2 content with XOR using a single byte, 0x12.
- [S1119] LIGHTWIRE: LIGHTWIRE can RC4 encrypt C2 commands.
- [S0394] HiddenWasp: HiddenWasp uses an RC4-like algorithm with an already computed PRGA generated key-stream for network communication.
- [S0149] MoonWind: MoonWind encrypts C2 traffic using RC4 with a static key.
- [S1100] Ninja: Ninja can XOR and AES encrypt C2 messages.
- [S1145] Pikabot: Earlier Pikabot variants use a custom encryption procedure leveraging multiple mechanisms including AES with multiple rounds of Base64 encoding for its command and control communication. Later Pikabot variants eliminate the use of AES and instead use RC4 encryption for transmitted information.
- [S0632] GrimAgent: GrimAgent can use an AES key to encrypt C2 communications.
- [S0275] UPPERCUT: Some versions of UPPERCUT have used the hard-coded string “this is the encrypt key” for Blowfish encryption when communicating with a C2. Later versions have hard-coded keys uniquely for each C2 address.
- [S0065] 4H RAT: 4H RAT obfuscates C2 communication using a 1-byte XOR with the key 0xBE.
- [S0430] Winnti for Linux: Winnti for Linux has used a custom TCP protocol with four-byte XOR for command and control (C2).
- [G1039] RedCurl: RedCurl has used AES-128 CBC to encrypt C2 communications.
- [S0266] TrickBot: TrickBot uses a custom crypter leveraging Microsoft’s CryptoAPI to encrypt C2 traffic.Newer versions of TrickBot have been known to use `bcrypt` to encrypt and digitally sign responses to their C2 server.
- [G0038] Stealth Falcon: Stealth Falcon malware encrypts C2 traffic using RC4 with a hard-coded key.
- [S0603] Stuxnet: Stuxnet encodes the payload of system information sent to the command and control servers using a one byte 0xFF XOR key. Stuxnet also uses a 31-byte long static byte string to XOR data sent to command and control servers. The servers use a different static key to encrypt replies to the implant.
- [S0678] Torisma: Torisma has encrypted its C2 communications using XOR and VEST-32.
- [S0377] Ebury: Ebury has encrypted C2 traffic using the client IP address, then encoded it as a hexadecimal string.
- [S0495] RDAT: RDAT has used AES ciphertext to encode C2 communications.
- [S0658] XCSSET: XCSSET uses RC4 encryption over TCP to communicate with its C2 server.
- [S1099] Samurai: Samurai can encrypt C2 communications with AES.
- [S1114] ZIPLINE: ZIPLINE can use AES-128-CBC to encrypt data for both upload and download.
- [S0534] Bazar: Bazar can send C2 communications with XOR encryption.
- [S0038] Duqu: The Duqu command and control protocol's data stream can be encrypted with AES-CBC.
- [S0433] Rifdoor: Rifdoor has encrypted command and control (C2) communications with a stream cipher.
- [S0203] Hydraq: Hydraq C2 traffic is encrypted using bitwise NOT and XOR operations.
- [S0127] BBSRAT: BBSRAT uses a custom encryption algorithm on data sent back to the C2 server over HTTP.
- [G0069] MuddyWater: MuddyWater has used AES to encrypt C2 responses.
- [S0045] ADVSTORESHELL: A variant of ADVSTORESHELL encrypts some C2 with 3DES.
- [S0395] LightNeuron: LightNeuron uses AES to encrypt C2 traffic.
- [S0569] Explosive: Explosive has encrypted communications with the RC4 method.
- [S0148] RTM: RTM encrypts C2 traffic with a custom RC4 variant.
- [S1166] Solar: Solar can XOR encrypt C2 communications.
- [S0582] LookBack: LookBack uses a modified version of RC4 for data transfer.
- [S0586] TAINTEDSCRIBE: TAINTEDSCRIBE uses a Linear Feedback Shift Register (LFSR) algorithm for network encryption.
- [S0641] Kobalos: Kobalos's post-authentication communication channel uses a 32-byte-long password with RC4 for inbound and outbound traffic.
- [S0032] gh0st RAT: gh0st RAT uses RC4 and XOR to encrypt C2 traffic.
- [S1060] Mafalda: Mafalda can encrypt its C2 traffic with RC4.
- [S0615] SombRAT: SombRAT has encrypted its C2 communications with AES.
- [S0514] WellMess: WellMess can encrypt HTTP POST data using RC6 and a dynamically generated AES key encrypted with a hard coded RSA public key.
- [S0134] Downdelph: Downdelph uses RC4 to encrypt C2 responses.
- [S0244] Comnie: Comnie encrypts command and control communications with RC4.
- [S0574] BendyBear: BendyBear communicates to a C2 server over port 443 using modified RC4 and XOR-encrypted chunks.
- [S0501] PipeMon: PipeMon communications are RC4 encrypted.
- [S0537] HyperStack: HyperStack has used RSA encryption for C2 communications.
- [S0168] Gazer: Gazer uses custom encryption for C2 that uses 3DES.
- [S1144] FRP: FRP can use STCP (Secret TCP) with a preshared key to encrypt services exposed to public networks.
- [S1106] NGLite: NGLite will use an AES encrypted channel for command and control purposes, in one case using the key WHATswrongwithUu.
- [S0336] NanoCore: NanoCore uses DES to encrypt the C2 traffic.
- [S0021] Derusbi: Derusbi obfuscates C2 traffic with variable 4-byte XOR keys.
- [S1110] SLIGHTPULSE: SLIGHTPULSE can RC4 encrypt all incoming and outgoing C2 messages.
- [S0030] Carbanak: Carbanak encrypts the message body of HTTP traffic with RC2 (in CBC mode). Carbanak also uses XOR with random keys for its communications.
- [S0653] xCaon: xCaon has encrypted data sent to the C2 server using a XOR key.
- [S0439] Okrum: Okrum uses AES to encrypt network traffic. The key can be hardcoded or negotiated with the C2 server in the registration phase.
- [G0126] Higaisa: Higaisa used AES-128 to encrypt C2 traffic.
- [S0012] PoisonIvy: PoisonIvy uses the Camellia cipher to encrypt communications.
- [S1039] Bumblebee: Bumblebee can encrypt C2 requests and responses with RC4
- [S0342] GreyEnergy: GreyEnergy encrypts communications using AES256.
- [S0633] Sliver: Sliver can use AES-GCM-256 to encrypt a session key for C2 message exchange.
- [S0627] SodaMaster: SodaMaster can use RC4 to encrypt C2 communications.
- [S0153] RedLeaves: RedLeaves has encrypted C2 traffic with RC4, previously using keys of 88888888 and babybear.
- [S0381] FlawedAmmyy: FlawedAmmyy has used SEAL encryption during the initial C2 handshake.
- [S0091] Epic: Epic encrypts commands from the C2 server using a hardcoded key.
- [S1160] Latrodectus: Latrodectus can send RC4 encrypted data over C2 channels.
- [S0077] CallMe: CallMe uses AES to encrypt C2 traffic.
- [S0436] TSCookie: TSCookie has encrypted network communications with RC4.
- [S0162] Komplex: The Komplex C2 channel uses an 11-byte XOR algorithm to hide data.
- [S0013] PlugX: PlugX can use RC4 encryption in C2 communications.
- [S1115] WIREFIRE: WIREFIRE can AES encrypt process output sent from compromised devices to C2.
- [S0154] Cobalt Strike: Cobalt Strike has the ability to use AES-256 symmetric encryption in CBC mode with HMAC-SHA-256 to encrypt task commands and XOR to encrypt shell code and configuration data.
- [S0053] SeaDuke: SeaDuke C2 traffic has been encrypted with RC4 and AES.
- [S0003] RIPTIDE: APT12 has used the RIPTIDE RAT, which communicates over HTTP with a payload encrypted with RC4.
- [S0132] H1N1: H1N1 encrypts C2 traffic using an RC4 key.
- [G0100] Inception: Inception has encrypted network communications with AES.
- [S0356] KONNI: KONNI has used AES to encrypt C2 traffic.
- [S0187] Daserf: Daserf uses RC4 encryption to obfuscate HTTP traffic.
- [S0230] ZeroT: ZeroT has used RC4 to encrypt C2 traffic.
- [S1196] Troll Stealer: Troll Stealer encrypts data sent to command and control infrastructure using a combination of RC4 and RSA-4096 algorithms.
- [S0512] FatDuke: FatDuke can AES encrypt C2 communications.
- [S0271] KEYMARBLE: KEYMARBLE uses a customized XOR algorithm to encrypt C2 communications.
- [S0234] Bandook: Bandook has used AES encryption for C2 communication.
- [S1022] IceApple: The IceApple Result Retriever module can AES encrypt C2 responses.
- [G0064] APT33: APT33 has used AES for encryption of command and control traffic.
- [S0629] RainyDay: RainyDay can use RC4 to encrypt C2 communications.
- [S0254] PLAINTEE: PLAINTEE encodes C2 beacons using XOR.
- [S0661] FoggyWeb: FoggyWeb has used a dynamic XOR key and custom XOR methodology for C2 communications.
- [S0520] BLINDINGCAN: BLINDINGCAN has encrypted its C2 traffic with RC4.
- [S0144] ChChes: ChChes can encrypt C2 traffic with AES or RC4.
- [S1059] metaMain: metaMain can encrypt the data that it sends and receives from the C2 server using an RC4 encryption algorithm.
- [S0333] UBoatRAT: UBoatRAT encrypts instructions in its C2 network payloads using a simple XOR cipher.
- [G0007] APT28: APT28 installed a Delphi backdoor that used a custom algorithm for C2 communications.
- [G0060] BRONZE BUTLER: BRONZE BUTLER has used RC4 encryption (for Datper malware) and AES (for xxmm malware) to obfuscate HTTP traffic. BRONZE BUTLER has also used a tool called RarStar that encodes data with a custom XOR algorithm when posting it to a C2 server.
- [S0455] Metamorfo: Metamorfo has encrypted C2 commands with AES-256.
- [S0159] SNUGRIDE: SNUGRIDE encrypts C2 traffic using AES with a static key.
- [S0435] PLEAD: PLEAD has used RC4 encryption to download modules.
- [S0023] CHOPSTICK: CHOPSTICK encrypts C2 communications with RC4.
- [S0137] CORESHELL: CORESHELL C2 messages are encrypted with custom stream ciphers using six-byte or eight-byte keys.
- [S1078] RotaJakiro: RotaJakiro encrypts C2 communication using a combination of AES, XOR, ROTATE encryption, and ZLIB compression.
- [S0472] down_new: down_new has the ability to AES encrypt C2 communications.
- [S0171] Felismus: Some Felismus samples use a custom encryption method for C2 traffic that utilizes AES and multiple keys.
- [C0001] Frankenstein: During Frankenstein, the threat actors communicated with C2 via an encrypted RC4 byte stream and AES-CBC.
- [S0630] Nebulae: Nebulae can use RC4 and XOR to encrypt C2 communications.
- [S1065] Woody RAT: Woody RAT can use AES-CBC to encrypt data sent to its C2 server.
- [S0050] CosmicDuke: CosmicDuke contains a custom version of the RC4 algorithm that includes a programming error.
- [S1031] PingPull: PingPull can use AES, in cipher block chaining (CBC) mode padded with PKCS5, to encrypt C2 server communications.

### T1573.002 - Encrypted Channel: Asymmetric Cryptography

Description:

Adversaries may employ a known asymmetric encryption algorithm to conceal command and control traffic rather than relying on any inherent protections provided by a communication protocol. Asymmetric cryptography, also known as public key cryptography, uses a keypair per party: one public that can be freely distributed, and one private. Due to how the keys are generated, the sender encrypts data with the receiver’s public key and the receiver decrypts the data with their private key. This ensures that only the intended recipient can read the encrypted data. Common public key encryption algorithms include RSA and ElGamal. For efficiency, many protocols (including SSL/TLS) use symmetric cryptography once a connection is established, but use asymmetric cryptography to establish or transmit a key. As such, these protocols are classified as Asymmetric Cryptography.

Detection:

SSL/TLS inspection is one way of detecting command and control traffic within some encrypted communication channels. SSL/TLS inspection does come with certain risks that should be considered before implementing to avoid potential security issues such as incomplete certificate validation. In general, analyze network data for uncommon data flows (e.g., a client sending significantly more data than it receives from a server). Processes utilizing the network that do not normally have network communication or have never been seen before are suspicious. Analyze packet contents to detect communications that do not follow the expected protocol behavior for the port that is being used.

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
- [S0556] Pay2Key: Pay2Key has used RSA encrypted communications with C2.
- [S0531] Grandoreiro: Grandoreiro can use SSL in C2 communication.
- [S0192] Pupy: Pupy's default encryption for its C2 communication channel is SSL, but it also has transport options for RSA and AES.
- [S0382] ServHelper: ServHelper may set up a reverse SSH tunnel to give the attacker access to services running on the victim, such as RDP.
- [S0699] Mythic: Mythic supports SSL encrypted C2.
- [S0632] GrimAgent: GrimAgent can use a hardcoded server public RSA key to encrypt the first request to C2.
- [S0438] Attor: Attor's Blowfish key is encrypted with a public RSA key.
- [S0600] Doki: Doki has used the embedTLS library for network communications.
- [S1169] Mango: Mango can use TLS to encrypt C2 communications.
- [S1203] J-magic: J-magic can communicate back to send a challenge to C2 infrastructure over SSL.
- [G1047] Velvet Ant: Velvet Ant has used a reverse SSH shell to securely communicate with victim devices.
- [S0384] Dridex: Dridex has encrypted traffic with RSA.
- [S0514] WellMess: WellMess can communicate to C2 with mutual TLS where client and server mutually check certificates.
- [G0081] Tropic Trooper: Tropic Trooper has used SSL to connect to C2 servers.
- [S1035] Small Sieve: Small Sieve can use SSL/TLS for its HTTPS Telegram Bot API-based C2 channel.
- [C0039] Versa Director Zero Day Exploitation: Versa Director Zero Day Exploitation used HTTPS for command and control of compromised Versa Director servers.
- [S1121] LITTLELAMB.WOOLTEA: LITTLELAMB.WOOLTEA can communicate over SSL using the private key from the Ivanti Connect Secure web server.
- [S0335] Carbon: Carbon has used RSA encryption for C2 communications.
- [S0183] Tor: Tor encapsulates traffic in multiple layers of encryption, using TLS by default.
- [S1144] FRP: FRP can be configured to only accept TLS connections.
- [S0588] GoldMax: GoldMax has RSA-encrypted its communication with the C2 server.
- [S0633] Sliver: Sliver can use mutual TLS and RSA cryptography to exchange a session key.
- [G1039] RedCurl: RedCurl has used HTTPS for C2 communication.
- [S1184] BOLDMOVE: BOLDMOVE uses the WolfSSL library to implement SSL encryption for command and control communication.
- [S1065] Woody RAT: Woody RAT can use RSA-4096 to encrypt data sent to its C2 server.
- [S1163] SnappyTCP: SnappyTCP can use OpenSSL and TLS certificates to encrypt traffic.
- [S0342] GreyEnergy: GreyEnergy encrypts communications using RSA-2048.
- [S1081] BADHATCH: BADHATCH can beacon to a hardcoded C2 IP address using TLS encryption every 5 minutes.
- [S0673] DarkWatchman: DarkWatchman can use TLS to encrypt its C2 channel.
- [S1105] COATHANGER: COATHANGER connects to command and control infrastructure using SSL.
- [G1042] RedEcho: RedEcho uses SSL for network communication.
- [S0094] Trojan.Karagany: Trojan.Karagany can secure C2 communications with SSL and TLS.
- [G0049] OilRig: OilRig used the PowerExchange utility and other tools to create tunnels to C2 servers.
- [S0587] Penquin: Penquin can encrypt communications using the BlowFish algorithm and a symmetric key exchanged with Diffie Hellman.
- [S0409] Machete: Machete has used TLS-encrypted FTP to exfiltrate data.
- [S0154] Cobalt Strike: Cobalt Strike can use RSA asymmetric encryption with PKCS1 padding to encrypt data sent to the C2 server.
- [S0180] Volgmer: Some Volgmer variants use SSL to encrypt C2 communications.
- [S0087] Hi-Zor: Hi-Zor encrypts C2 traffic with TLS.
- [S0491] StrongPity: StrongPity has encrypted C2 traffic using SSL/TLS.
- [S0448] Rising Sun: Rising Sun variants can use SSL for encrypting C2 communications.
- [S0150] POSHSPY: POSHSPY encrypts C2 traffic with AES and RSA.
- [S0117] XTunnel: XTunnel uses SSL/TLS and RC4 to encrypt traffic.
- [C0043] Indian Critical Infrastructure Intrusions: During Indian Critical Infrastructure Intrusions, RedEcho used SSL for network communication.
- [S1210] Sagerunex: Sagerunex uses HTTPS for command and control communication.
- [C0021] C0021: During C0021, the threat actors used SSL via TCP port 443 for C2 communications.
- [S1051] KEYPLUG: KEYPLUG can use TLS-encrypted WebSocket Protocol (WSS) for C2.
- [S0223] POWERSTATS: POWERSTATS has encrypted C2 traffic with RSA.
- [S0251] Zebrocy: Zebrocy uses SSL and AES ECB for encrypting C2 communications.
- [S0428] PoetRAT: PoetRAT used TLS to encrypt command and control (C2) communications.
- [G0080] Cobalt Group: Cobalt Group has used the Plink utility to create SSH tunnels.
- [S1192] NICECURL: NICECURL has used HTTPS for C2 communications.
- [G1044] APT42: APT42 has used tools such as NICECURL with command and control communication taking place over HTTPS.
- [S0045] ADVSTORESHELL: A variant of ADVSTORESHELL encrypts some C2 with RSA.
- [S1122] Mispadu: Mispadu contains a copy of the OpenSSL library to encrypt C2 traffic.
- [S1085] Sardonic: Sardonic has the ability to send a random 64-byte RC4 key to communicate with actor-controlled C2 servers by using an RSA public key.
- [S0250] Koadic: Koadic can use SSL and TLS for communications.
- [S0366] WannaCry: WannaCry uses Tor for command and control traffic and routes a custom cryptographic protocol over the Tor circuit.
- [S1213] Lumma Stealer: Lumma Stealer has used HTTPS for command and control purposes.
- [G0037] FIN6: FIN6 used the Plink command-line utility to create SSH tunnels to C2 servers.
- [C0040] APT41 DUST: APT41 DUST used HTTPS for command and control.
- [S0363] Empire: Empire can use TLS to encrypt its C2 channel.
- [G0061] FIN8: FIN8 has used the Plink utility to tunnel RDP back to C2 infrastructure.
- [S0017] BISCUIT: BISCUIT uses SSL for encrypting C2 communications.
- [S0202] adbupd: adbupd contains a copy of the OpenSSL library to encrypt C2 traffic.
- [S0641] Kobalos: Kobalos's authentication and key exchange is performed using RSA-512.
- [S1155] Covenant: Covenant can utilize SSL to encrypt command and control traffic.
- [S0515] WellMail: WellMail can use hard coded client and certificate authority certificates to communicate with C2 over mutual TLS.
- [S1172] OilBooster: OilBooster can use the OpenSSL library to encrypt C2 communications.
- [S0023] CHOPSTICK: CHOPSTICK encrypts C2 communications with TLS.
- [S0483] IcedID: IcedID has used SSL and TLS in communications with C2.
- [S1198] Gomir: Gomir uses reverse proxy functionality that employs SSL to encrypt communications.


### T1659 - Content Injection

Description:

Adversaries may gain access and continuously communicate with victims by injecting malicious content into systems through online network traffic. Rather than luring victims to malicious payloads hosted on a compromised website (i.e., Drive-by Target followed by Drive-by Compromise), adversaries may initially access victims through compromised data-transfer channels where they can manipulate traffic and/or inject their own content. These compromised online network channels may also be used to deliver additional payloads (i.e., Ingress Tool Transfer) and other data to already compromised systems. Adversaries may inject content to victim systems in various ways, including: * From the middle, where the adversary is in-between legitimate online client-server communications (**Note:** this is similar but distinct from Adversary-in-the-Middle, which describes AiTM activity solely within an enterprise environment) * From the side, where malicious content is injected and races to the client as a fake response to requests of a legitimate online server Content injection is often the result of compromised upstream communication channels, for example at the level of an internet service provider (ISP) as is the case with "lawful interception."

Procedures:

- [S1088] Disco: Disco has achieved initial access and execution through content injection into DNS, HTTP, and SMB replies to targeted hosts that redirect them to download malicious files.
- [G1019] MoustachedBouncer: MoustachedBouncer has injected content into DNS, HTTP, and SMB replies to redirect specifically-targeted victims to a fake Windows Update page to download malware.


### T1665 - Hide Infrastructure

Description:

Adversaries may manipulate network traffic in order to hide and evade detection of their C2 infrastructure. This can be accomplished in various ways including by identifying and filtering traffic from defensive tools, masking malicious domains to obfuscate the true destination from both automated scanning tools and security researchers, and otherwise hiding malicious artifacts to delay discovery and prolong the effectiveness of adversary infrastructure that could otherwise be identified, blocked, or taken down entirely. C2 networks may include the use of Proxy or VPNs to disguise IP addresses, which can allow adversaries to blend in with normal network traffic and bypass conditional access policies or anti-abuse protections. For example, an adversary may use a virtual private cloud to spoof their IP address to closer align with a victim's IP address ranges. This may also bypass security measures relying on geolocation of the source IP address. Adversaries may also attempt to filter network traffic in order to evade defensive tools in numerous ways, including blocking/redirecting common incident responder or security appliance user agents. Filtering traffic based on IP and geo-fencing may also avoid automated sandboxing or researcher activity (i.e., Virtualization/Sandbox Evasion). Hiding C2 infrastructure may also be supported by Resource Development activities such as Acquire Infrastructure and Compromise Infrastructure. For example, using widely trusted hosting services or domains such as prominent URL shortening providers or marketing services for C2 networks may enable adversaries to present benign content that later redirects victims to malicious web pages or infrastructure once specific conditions are met.

Procedures:

- [G0128] ZIRCONIUM: ZIRCONIUM has utilized an ORB (operational relay box) network – consisting compromised devices such as small office and home office (SOHO) routers, IoT devices, and leased virtual private servers (VPS) – to obfuscate the origin of C2 traffic.
- [C0024] SolarWinds Compromise: During the SolarWinds Compromise, APT29 set the hostnames of their C2 infrastructure to match legitimate hostnames in the victim environment. They also used IP addresses originating from the same country as the victim for their VPN infrastructure.
- [S1206] JumbledPath: JumbledPath can use a chain of jump hosts to communicate with compromised devices to obscure actor infrastructure.
- [S1111] DarkGate: DarkGate command and control includes hard-coded domains in the malware masquerading as legitimate services such as Akamai CDN or Amazon Web Services.
- [G0016] APT29: APT29 uses compromised residential endpoints, typically within the same ISP IP address range, as proxies to hide the true source of C2 traffic.
- [S1164] UPSTYLE: UPSTYLE attempts to retrieve a non-existent webpage from the command and control server resulting in hidden commands sent via resulting error messages.

