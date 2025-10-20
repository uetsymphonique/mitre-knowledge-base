### T1583 - Acquire Infrastructure

Description:

Adversaries may buy, lease, rent, or obtain infrastructure that can be used during targeting. A wide variety of infrastructure exists for hosting and orchestrating adversary operations. Infrastructure solutions include physical or cloud servers, domains, and third-party web services.(Citation: TrendmicroHideoutsLease) Some infrastructure providers offer free trial periods, enabling infrastructure acquisition at limited to no cost.(Citation: Free Trial PurpleUrchin) Additionally, botnets are available for rent or purchase.

Use of these infrastructure solutions allows adversaries to stage, launch, and execute operations. Solutions may help adversary operations blend in with traffic that is seen as normal, such as contacting third-party web services or acquiring infrastructure to support [Proxy](https://attack.mitre.org/techniques/T1090), including from residential proxy services.(Citation: amnesty_nso_pegasus)(Citation: FBI Proxies Credential Stuffing)(Citation: Mandiant APT29 Microsoft 365 2022) Depending on the implementation, adversaries may use infrastructure that makes it difficult to physically tie back to them as well as utilize infrastructure that can be rapidly provisioned, modified, and shut down.

Procedures:

- [G0094] Kimsuky: [Kimsuky](https://attack.mitre.org/groups/G0094) has used funds from stolen and laundered cryptocurrency to acquire operational infrastructure.(Citation: Mandiant APT43 March 2024)
- [G1041] Sea Turtle: [Sea Turtle](https://attack.mitre.org/groups/G1041) accessed victim networks from VPN service provider networks.(Citation: Hunt Sea Turtle 2024)
- [G1003] Ember Bear: [Ember Bear](https://attack.mitre.org/groups/G1003) uses services such as IVPN, SurfShark, and Tor to add anonymization to operations.(Citation: Cadet Blizzard emerges as novel threat actor)
- [G0119] Indrik Spider: [Indrik Spider](https://attack.mitre.org/groups/G0119) has purchased access to victim VPNs to facilitate access to victim environments.(Citation: Mandiant_UNC2165)
- [G1030] Agrius: [Agrius](https://attack.mitre.org/groups/G1030) typically uses commercial VPN services for anonymizing last-hop traffic to victim networks, such as ProtonVPN.(Citation: SentinelOne Agrius 2021)
- [G0034] Sandworm Team: [Sandworm Team](https://attack.mitre.org/groups/G0034) used various third-party email campaign management services to deliver phishing emails.(Citation: Leonard TAG 2023)
- [G1033] Star Blizzard: [Star Blizzard](https://attack.mitre.org/groups/G1033) has used HubSpot and MailerLite marketing platform services to hide the true sender of phishing emails.(Citation: StarBlizzard)

#### T1583.001 - Acquire Infrastructure: Domains

Description:

Adversaries may acquire domains that can be used during targeting. Domain names are the human readable names used to represent one or more IP addresses. They can be purchased or, in some cases, acquired for free.

Adversaries may use acquired domains for a variety of purposes, including for [Phishing](https://attack.mitre.org/techniques/T1566), [Drive-by Compromise](https://attack.mitre.org/techniques/T1189), and Command and Control.(Citation: CISA MSS Sep 2020) Adversaries may choose domains that are similar to legitimate domains, including through use of homoglyphs or use of a different top-level domain (TLD).(Citation: FireEye APT28)(Citation: PaypalScam) Typosquatting may be used to aid in delivery of payloads via [Drive-by Compromise](https://attack.mitre.org/techniques/T1189). Adversaries may also use internationalized domain names (IDNs) and different character sets (e.g. Cyrillic, Greek, etc.) to execute "IDN homograph attacks," creating visually similar lookalike domains used to deliver malware to victim machines.(Citation: CISA IDN ST05-016)(Citation: tt_httrack_fake_domains)(Citation: tt_obliqueRAT)(Citation: httrack_unhcr)(Citation: lazgroup_idn_phishing)

Different URIs/URLs may also be dynamically generated to uniquely serve malicious content to victims (including one-time, single use domain names).(Citation: iOS URL Scheme)(Citation: URI)(Citation: URI Use)(Citation: URI Unique)

Adversaries may also acquire and repurpose expired domains, which may be potentially already allowlisted/trusted by defenders based on an existing reputation/history.(Citation: Categorisation_not_boundary)(Citation: Domain_Steal_CC)(Citation: Redirectors_Domain_Fronting)(Citation: bypass_webproxy_filtering)

Domain registrars each maintain a publicly viewable database that displays contact information for every registered domain. Private WHOIS services display alternative information, such as their own company data, rather than the owner of the domain. Adversaries may use such private WHOIS services to obscure information about who owns a purchased domain. Adversaries may further interrupt efforts to track their infrastructure by using varied registration information and purchasing domains with different domain registrars.(Citation: Mandiant APT1)

In addition to legitimately purchasing a domain, an adversary may register a new domain in a compromised environment. For example, in AWS environments, adversaries may leverage the Route53 domain service to register a domain and create hosted zones pointing to resources of the threat actor’s choosing.(Citation: Invictus IR DangerDev 2024)

Procedures:

- [C0021] C0021: For [C0021](https://attack.mitre.org/campaigns/C0021), the threat actors registered domains for use in C2.(Citation: FireEye APT29 Nov 2018)
- [G0007] APT28: [APT28](https://attack.mitre.org/groups/G0007) registered domains imitating NATO, OSCE security websites, Caucasus information resources, and other organizations.(Citation: FireEye APT28)(Citation: US District Court Indictment GRU Oct 2018)(Citation: Google TAG Ukraine Threat Landscape March 2022)
- [G0092] TA505: [TA505](https://attack.mitre.org/groups/G0092) has registered domains to impersonate services such as Dropbox to distribute malware.(Citation: Korean FSI TA505 2020)
- [C0005] Operation Spalax: For [Operation Spalax](https://attack.mitre.org/campaigns/C0005), the threat actors registered hundreds of domains using Duck DNS and DNS Exit.(Citation: ESET Operation Spalax Jan 2021)
- [G1046] Storm-1811: [Storm-1811](https://attack.mitre.org/groups/G1046) has created domains for use with RMM tools.(Citation: rapid7-email-bombing)
- [G1001] HEXANE: [HEXANE](https://attack.mitre.org/groups/G1001) has registered and operated domains for campaigns, often using a security or web technology theme or impersonating the targeted organization.(Citation: SecureWorks August 2019)(Citation: Dragos Hexane)(Citation: ClearSky Siamesekitten August 2021)
- [G1033] Star Blizzard: [Star Blizzard](https://attack.mitre.org/groups/G1033) has registered domains using randomized words and with names resembling legitimate organizations.(Citation: CISA Star Blizzard Advisory December 2023)(Citation: StarBlizzard)
- [C0043] Indian Critical Infrastructure Intrusions: During [Indian Critical Infrastructure Intrusions](https://attack.mitre.org/campaigns/C0043), [RedEcho](https://attack.mitre.org/groups/G1042) registered domains spoofing Indian critical infrastructure entities.(Citation: RecordedFuture RedEcho 2021)
- [G1044] APT42: [APT42](https://attack.mitre.org/groups/G1044) has registered domains, several of which masqueraded as news outlets and login services, for use in operations.(Citation: Mandiant APT42-charms)(Citation: TAG APT42)
- [G0006] APT1: [APT1](https://attack.mitre.org/groups/G0006) has registered hundreds of domains for use in operations.(Citation: Mandiant APT1)
- [C0006] Operation Honeybee: During [Operation Honeybee](https://attack.mitre.org/campaigns/C0006), threat actors registered domains for C2.(Citation: McAfee Honeybee)
- [G0050] APT32: [APT32](https://attack.mitre.org/groups/G0050) has set up and operated websites to gather information and deliver malware.(Citation: Volexity Ocean Lotus November 2020)
- [G0136] IndigoZebra: [IndigoZebra](https://attack.mitre.org/groups/G0136) has established domains, some of which were designed to look like official government domains, for their operations.(Citation: Checkpoint IndigoZebra July 2021)
- [C0016] Operation Dust Storm: For [Operation Dust Storm](https://attack.mitre.org/campaigns/C0016), the threat actors established domains as part of their operational infrastructure.(Citation: Cylance Dust Storm)
- [G0065] Leviathan: [Leviathan](https://attack.mitre.org/groups/G0065) has established domains that impersonate legitimate entities to use for targeting efforts. (Citation: CISA AA21-200A APT40 July 2021)(Citation: Accenture MUDCARP March 2019)
- [C0022] Operation Dream Job: During [Operation Dream Job](https://attack.mitre.org/campaigns/C0022), [Lazarus Group](https://attack.mitre.org/groups/G0032) registered a domain name identical to that of a compromised company as part of their BEC effort.(Citation: ESET Lazarus Jun 2020)
- [G1006] Earth Lusca: [Earth Lusca](https://attack.mitre.org/groups/G1006) has registered domains, intended to look like legitimate target domains, that have been used in watering hole attacks.(Citation: TrendMicro EarthLusca 2022)
- [G0094] Kimsuky: [Kimsuky](https://attack.mitre.org/groups/G0094) has registered domains to spoof targeted organizations and trusted third parties including search engines, web platforms, and cryptocurrency exchanges.(Citation: ThreatConnect Kimsuky September 2020)(Citation: Zdnet Kimsuky Group September 2020)(Citation: CISA AA20-301A Kimsuky)(Citation: Cybereason Kimsuky November 2020)(Citation: Malwarebytes Kimsuky June 2021)(Citation: KISA Operation Muzabi)(Citation: Mandiant APT43 March 2024)(Citation: Mandiant APT43 Full PDF Report)
- [G0035] Dragonfly: [Dragonfly](https://attack.mitre.org/groups/G0035) has registered domains for targeting intended victims.(Citation: CISA AA20-296A Berserk Bear December 2020)
- [G1018] TA2541: [TA2541](https://attack.mitre.org/groups/G1018) has registered domains often containing the keywords “kimjoy,” “h0pe,” and “grace,” using domain registrars including Netdorm and No-IP DDNS, and hosting providers including xTom GmbH and Danilenko, Artyom.(Citation: Proofpoint TA2541 February 2022)(Citation: Cisco Operation Layover September 2021)
- [G0140] LazyScripter: [LazyScripter](https://attack.mitre.org/groups/G0140) has used dynamic DNS providers to create legitimate-looking subdomains for C2.(Citation: MalwareBytes LazyScripter Feb 2021)
- [G0134] Transparent Tribe: [Transparent Tribe](https://attack.mitre.org/groups/G0134) has registered domains to mimic file sharing, government, defense, and research websites for use in targeted campaigns.(Citation: Proofpoint Operation Transparent Tribe March 2016)(Citation: Talos Transparent Tribe May 2021)
- [G0128] ZIRCONIUM: [ZIRCONIUM](https://attack.mitre.org/groups/G0128) has purchased domains for use in targeted campaigns.(Citation: Microsoft Targeting Elections September 2020)
- [S1130] Raspberry Robin: [Raspberry Robin](https://attack.mitre.org/software/S1130) uses newly-registered domains containing only a few characters for command and controll purposes, such as "<code>v0[.]cx</code>".(Citation: RedCanary RaspberryRobin 2022)
- [C0023] Operation Ghost: For [Operation Ghost](https://attack.mitre.org/campaigns/C0023), [APT29](https://attack.mitre.org/groups/G0016) registered domains for use in C2 including some crafted to appear as existing legitimate domains.(Citation: ESET Dukes October 2019)
- [G0027] Threat Group-3390: [Threat Group-3390](https://attack.mitre.org/groups/G0027) has registered domains for C2.(Citation: Lunghi Iron Tiger Linux)
- [S1111] DarkGate: [DarkGate](https://attack.mitre.org/software/S1111) command and control includes hard-coded domains in the malware chosen to masquerade as legitimate services such as Akamai CDN or Amazon Web Services.(Citation: Trellix Darkgate 2023)
- [C0026] C0026: For [C0026](https://attack.mitre.org/campaigns/C0026), the threat actors re-registered expired C2 domains previously used for [ANDROMEDA](https://attack.mitre.org/software/S1074) malware.(Citation: Mandiant Suspected Turla Campaign February 2023)
- [C0004] CostaRicto: For [CostaRicto](https://attack.mitre.org/campaigns/C0004), the threat actors established domains, some of which appeared to spoof legitimate domains.(Citation: BlackBerry CostaRicto November 2020)
- [G1042] RedEcho: [RedEcho](https://attack.mitre.org/groups/G1042) has registered domains spoofing Indian critical infrastructure entities.(Citation: RecordedFuture RedEcho 2021)
- [G0049] OilRig: [OilRig](https://attack.mitre.org/groups/G0049) has set up fake VPN portals, conference sign ups, and job application websites to target victims.(Citation: ClearSky OilRig Jan 2017)
- [G0129] Mustang Panda: [Mustang Panda](https://attack.mitre.org/groups/G0129) have acquired C2 domains prior to operations.(Citation: Secureworks BRONZE PRESIDENT December 2019)(Citation: Recorded Future REDDELTA July 2020)(Citation: McAfee Dianxun March 2021)
- [C0010] C0010: For [C0010](https://attack.mitre.org/campaigns/C0010), UNC3890 actors established domains that appeared to be legitimate services and entities, such as LinkedIn, Facebook, Office 365, and Pfizer.(Citation: Mandiant UNC3890 Aug 2022)
- [G0032] Lazarus Group: [Lazarus Group](https://attack.mitre.org/groups/G0032) has acquired domains related to their campaigns to act as distribution points and C2 channels.(Citation: CISA AppleJeus Feb 2021)(Citation: Google TAG Lazarus Jan 2021)
- [G1011] EXOTIC LILY: [EXOTIC LILY](https://attack.mitre.org/groups/G1011) has registered domains to spoof targeted organizations by changing the top-level domain (TLD) to “.us”, “.co” or “.biz”.(Citation: Google EXOTIC LILY March 2022)
- [G0122] Silent Librarian: [Silent Librarian](https://attack.mitre.org/groups/G0122) has acquired domains to establish credential harvesting pages, often spoofing the target organization and using free top level domains .TK, .ML, .GA, .CF, and .GQ.(Citation: DOJ Iran Indictments March 2018)(Citation: Phish Labs Silent Librarian)(Citation: Secureworks COBALT DICKENS August 2018)(Citation: Proofpoint TA407 September 2019)(Citation: Secureworks COBALT DICKENS September 2019)(Citation: Malwarebytes Silent Librarian October 2020)
- [G0046] FIN7: [FIN7](https://attack.mitre.org/groups/G0046) has registered look-alike domains for use in phishing campaigns.(Citation: eSentire FIN7 July 2021)
- [C0011] C0011: For [C0011](https://attack.mitre.org/campaigns/C0011), [Transparent Tribe](https://attack.mitre.org/groups/G0134) registered domains likely designed to appear relevant to student targets in India.(Citation: Cisco Talos Transparent Tribe Education Campaign July 2022)
- [C0007] FunnyDream: For [FunnyDream](https://attack.mitre.org/campaigns/C0007), the threat actors registered a variety of domains.(Citation: Bitdefender FunnyDream Campaign November 2020)
- [G1041] Sea Turtle: [Sea Turtle](https://attack.mitre.org/groups/G1041) registered domains for authoritative name servers used in DNS hijacking activity and for command and control servers.(Citation: Talos Sea Turtle 2019_2)(Citation: Hunt Sea Turtle 2024)
- [G0059] Magic Hound: [Magic Hound](https://attack.mitre.org/groups/G0059) has registered fraudulent domains such as "mail-newyorker.com" and "news12.com.recover-session-service.site" to target specific victims with phishing attacks.(Citation: Certfa Charming Kitten January 2021)
- [G0082] APT38: [APT38](https://attack.mitre.org/groups/G0082) has created fake domains to imitate legitimate venture capital or bank domains.(Citation: 1 - appv)
- [S1207] XLoader: [XLoader](https://attack.mitre.org/software/S1207) can utilize hardcoded command and control domain configurations created by the XLoader authors. These are designed to mimic domain registrars and hosting service providers such as Hostinger and Namecheap.(Citation: CheckPoint XLoader 2022)
- [G0047] Gamaredon Group: [Gamaredon Group](https://attack.mitre.org/groups/G0047) has registered multiple domains to facilitate payload staging and C2.(Citation: Microsoft Actinium February 2022)(Citation: Unit 42 Gamaredon February 2022)
- [G1035] Winter Vivern: [Winter Vivern](https://attack.mitre.org/groups/G1035) registered domains mimicking other entities throughout various campaigns.(Citation: DomainTools WinterVivern 2021)
- [G1036] Moonstone Sleet: [Moonstone Sleet](https://attack.mitre.org/groups/G1036) registered domains to develop effective personas for fake companies used in phishing activity.(Citation: Microsoft Moonstone Sleet 2024)
- [G1002] BITTER: [BITTER](https://attack.mitre.org/groups/G1002) has registered a variety of domains to host malicious payloads and for C2.(Citation: Forcepoint BITTER Pakistan Oct 2016)
- [G0139] TeamTNT: [TeamTNT](https://attack.mitre.org/groups/G0139) has obtained domains to host their payloads.(Citation: Palo Alto Black-T October 2020)
- [G0034] Sandworm Team: [Sandworm Team](https://attack.mitre.org/groups/G0034) has registered domain names and created URLs that are often designed to mimic or spoof legitimate websites, such as email login pages, online file sharing and storage websites, and password reset pages, while also hosting these items on legitimate, compromised network infrastructure.(Citation: US District Court Indictment GRU Unit 74455 October 2020)(Citation: Slowik Sandworm 2021)
- [C0047] RedDelta Modified PlugX Infection Chain Operations: [Mustang Panda](https://attack.mitre.org/groups/G0129) registered adversary-controlled domains during [RedDelta Modified PlugX Infection Chain Operations](https://attack.mitre.org/campaigns/C0047) that were re-registrations of expired domains.(Citation: Recorded Future RedDelta 2025)
- [G0044] Winnti Group: [Winnti Group](https://attack.mitre.org/groups/G0044) has registered domains for C2 that mimicked sites of their intended targets.(Citation: Kaspersky Winnti April 2013)
- [G0137] Ferocious Kitten: [Ferocious Kitten](https://attack.mitre.org/groups/G0137) has acquired domains imitating legitimate sites.(Citation: Kaspersky Ferocious Kitten Jun 2021)
- [G1012] CURIUM: [CURIUM](https://attack.mitre.org/groups/G1012) created domains to facilitate strategic website compromise and credential capture activities.(Citation: PWC Yellow Liderc 2023)
- [C0024] SolarWinds Compromise: For the [SolarWinds Compromise](https://attack.mitre.org/campaigns/C0024), [APT29](https://attack.mitre.org/groups/G0016) acquired C2 domains, sometimes through resellers.(Citation: MSTIC NOBELIUM Mar 2021)(Citation: FireEye SUNSHUTTLE Mar 2021)
- [G0045] menuPass: [menuPass](https://attack.mitre.org/groups/G0045) has registered malicious domains for use in intrusion campaigns.(Citation: DOJ APT10 Dec 2018)(Citation: District Court of NY APT10 Indictment December 2018)

#### T1583.002 - Acquire Infrastructure: DNS Server

Description:

Adversaries may set up their own Domain Name System (DNS) servers that can be used during targeting. During post-compromise activity, adversaries may utilize DNS traffic for various tasks, including for Command and Control (ex: [Application Layer Protocol](https://attack.mitre.org/techniques/T1071)). Instead of hijacking existing DNS servers, adversaries may opt to configure and run their own DNS servers in support of operations.

By running their own DNS servers, adversaries can have more control over how they administer server-side DNS C2 traffic ([DNS](https://attack.mitre.org/techniques/T1071/004)). With control over a DNS server, adversaries can configure DNS applications to provide conditional responses to malware and, generally, have more flexibility in the structure of the DNS-based C2 channel.(Citation: Unit42 DNS Mar 2019)

Procedures:

- [G1041] Sea Turtle: [Sea Turtle](https://attack.mitre.org/groups/G1041) built adversary-in-the-middle DNS servers to impersonate legitimate services that were later used to capture credentials.(Citation: Talos Sea Turtle 2019_2)(Citation: Talos Sea Turtle 2019)
- [G0001] Axiom: [Axiom](https://attack.mitre.org/groups/G0001) has acquired dynamic DNS services for use in the targeting of intended victims.(Citation: Novetta-Axiom)
- [G1001] HEXANE: [HEXANE](https://attack.mitre.org/groups/G1001) has set up custom DNS servers to send commands to compromised hosts via TXT records.(Citation: Zscaler Lyceum DnsSystem June 2022)

#### T1583.003 - Acquire Infrastructure: Virtual Private Server

Description:

Adversaries may rent Virtual Private Servers (VPSs) that can be used during targeting. There exist a variety of cloud service providers that will sell virtual machines/containers as a service. By utilizing a VPS, adversaries can make it difficult to physically tie back operations to them. The use of cloud infrastructure can also make it easier for adversaries to rapidly provision, modify, and shut down their infrastructure.

Acquiring a VPS for use in later stages of the adversary lifecycle, such as Command and Control, can allow adversaries to benefit from the ubiquity and trust associated with higher reputation cloud service providers. Adversaries may also acquire infrastructure from VPS service providers that are known for renting VPSs with minimal registration information, allowing for more anonymous acquisitions of infrastructure.(Citation: TrendmicroHideoutsLease)

Procedures:

- [G0047] Gamaredon Group: [Gamaredon Group](https://attack.mitre.org/groups/G0047) has used VPS hosting providers for infrastructure outside of Russia.(Citation: unit42_gamaredon_dec2022)
- [G0007] APT28: [APT28](https://attack.mitre.org/groups/G0007) hosted phishing domains on free services for brief periods of time during campaigns.(Citation: Leonard TAG 2023)
- [C0053] FLORAHOX Activity: [FLORAHOX Activity](https://attack.mitre.org/campaigns/C0053) has used acquired Virtual Private Servers as control systems for the ORB network.(Citation: ORB Mandiant)
- [C0050] J-magic Campaign: During the [J-magic Campaign](https://attack.mitre.org/campaigns/C0050), threat actors acquired VPS for use in C2.(Citation: Lumen J-Magic JAN 2025)
- [C0032] C0032: During the [C0032](https://attack.mitre.org/campaigns/C0032) campaign, [TEMP.Veles](https://attack.mitre.org/groups/G0088) used Virtual Private Server (VPS) infrastructure.(Citation: FireEye TRITON 2019)
- [G1003] Ember Bear: [Ember Bear](https://attack.mitre.org/groups/G1003) has used virtual private servers (VPSs) to host tools, perform reconnaissance, exploit victim infrastructure, and as a destination for data exfiltration.(Citation: CISA GRU29155 2024)
- [C0046] ArcaneDoor: [ArcaneDoor](https://attack.mitre.org/campaigns/C0046) included the use of dedicated, adversary-controlled virtual private servers for command and control.(Citation: Cisco ArcaneDoor 2024)
- [G1004] LAPSUS$: [LAPSUS$](https://attack.mitre.org/groups/G1004) has used VPS hosting providers for infrastructure.(Citation: MSTIC DEV-0537 Mar 2022)
- [G1041] Sea Turtle: [Sea Turtle](https://attack.mitre.org/groups/G1041) created adversary-in-the-middle servers to impersonate legitimate services and enable credential capture.(Citation: Talos Sea Turtle 2019)
- [G1035] Winter Vivern: [Winter Vivern](https://attack.mitre.org/groups/G1035) used adversary-owned and -controlled servers to host web vulnerability scanning applications.(Citation: SentinelOne WinterVivern 2023)
- [G1012] CURIUM: [CURIUM](https://attack.mitre.org/groups/G1012) created virtual private server instances to facilitate use of malicious domains and other items.(Citation: PWC Yellow Liderc 2023)
- [G1043] BlackByte: [BlackByte](https://attack.mitre.org/groups/G1043) staged encryption keys on virtual private servers operated by the adversary.(Citation: FBI BlackByte 2022)
- [C0035] KV Botnet Activity: [KV Botnet Activity](https://attack.mitre.org/campaigns/C0035) used acquired Virtual Private Servers as control systems for devices infected with KV Botnet malware.(Citation: Lumen KVBotnet 2023)
- [G0001] Axiom: [Axiom](https://attack.mitre.org/groups/G0001) has used VPS hosting providers in targeting of intended victims.(Citation: Novetta-Axiom)
- [G1036] Moonstone Sleet: [Moonstone Sleet](https://attack.mitre.org/groups/G1036) registered virtual private servers to host payloads for download.(Citation: Microsoft Moonstone Sleet 2024)
- [G0035] Dragonfly: [Dragonfly](https://attack.mitre.org/groups/G0035) has acquired VPS infrastructure for use in malicious campaigns.(Citation: Gigamon Berserk Bear October 2021)
- [G1044] APT42: [APT42](https://attack.mitre.org/groups/G1044) has used anonymized infrastructure and Virtual Private Servers (VPSs) to interact with the victim’s environment.(Citation: Mandiant APT42-charms)(Citation: Mandiant APT42-untangling)
- [C0052] SPACEHOP Activity: [SPACEHOP Activity](https://attack.mitre.org/campaigns/C0052) has used acquired Virtual Private Servers as control systems for devices within the ORB network.(Citation: ORB Mandiant)
- [G0125] HAFNIUM: [HAFNIUM](https://attack.mitre.org/groups/G0125) has operated from leased virtual private servers (VPS) in the United States.(Citation: Microsoft HAFNIUM March 2020)

#### T1583.004 - Acquire Infrastructure: Server

Description:

Adversaries may buy, lease, rent, or obtain physical servers that can be used during targeting. Use of servers allows an adversary to stage, launch, and execute an operation. During post-compromise activity, adversaries may utilize servers for various tasks, such as watering hole operations in [Drive-by Compromise](https://attack.mitre.org/techniques/T1189), enabling [Phishing](https://attack.mitre.org/techniques/T1566) operations, or facilitating [Command and Control](https://attack.mitre.org/tactics/TA0011). Instead of compromising a third-party [Server](https://attack.mitre.org/techniques/T1584/004) or renting a [Virtual Private Server](https://attack.mitre.org/techniques/T1583/003), adversaries may opt to configure and run their own servers in support of operations. Free trial periods of cloud servers may also be abused.(Citation: Free Trial PurpleUrchin)(Citation: Freejacked) 

Adversaries may only need a lightweight setup if most of their activities will take place using online infrastructure. Or, they may need to build extensive infrastructure if they want to test, communicate, and control other aspects of their activities on their own systems.(Citation: NYTStuxnet)

Procedures:

- [C0022] Operation Dream Job: During [Operation Dream Job](https://attack.mitre.org/campaigns/C0022), [Lazarus Group](https://attack.mitre.org/groups/G0032) acquired servers to host their malicious tools.(Citation: ESET Lazarus Jun 2020)
- [G0093] GALLIUM: [GALLIUM](https://attack.mitre.org/groups/G0093) has used Taiwan-based servers that appear to be exclusive to [GALLIUM](https://attack.mitre.org/groups/G0093).(Citation: Microsoft GALLIUM December 2019)
- [G0094] Kimsuky: [Kimsuky](https://attack.mitre.org/groups/G0094) has purchased hosting servers with virtual currency and prepaid cards.(Citation: KISA Operation Muzabi)
- [C0014] Operation Wocao: For [Operation Wocao](https://attack.mitre.org/campaigns/C0014), the threat actors purchased servers with Bitcoin to use during the operation.(Citation: FoxIT Wocao December 2019)
- [G0034] Sandworm Team: [Sandworm Team](https://attack.mitre.org/groups/G0034) has leased servers from resellers instead of leasing infrastructure directly from hosting companies to enable its operations.(Citation: US District Court Indictment GRU Unit 74455 October 2020)
- [C0002] Night Dragon: During [Night Dragon](https://attack.mitre.org/campaigns/C0002), threat actors purchased hosted services to use for C2.(Citation: McAfee Night Dragon)
- [C0006] Operation Honeybee: For [Operation Honeybee](https://attack.mitre.org/campaigns/C0006), at least one identified persona was used to register for a free account for a control server.(Citation: McAfee Honeybee)
- [G1006] Earth Lusca: [Earth Lusca](https://attack.mitre.org/groups/G1006) has acquired multiple servers for some of their operations, using each server for a different role.(Citation: TrendMicro EarthLusca 2022)
- [G1020] Mustard Tempest: [Mustard Tempest](https://attack.mitre.org/groups/G1020) has acquired servers to host second-stage payloads that remain active for a period of either days, weeks, or months.(Citation: SentinelOne SocGholish Infrastructure November 2022)
- [G1012] CURIUM: [CURIUM](https://attack.mitre.org/groups/G1012) has created dedicated servers for command and control and exfiltration purposes.(Citation: PWC Yellow Liderc 2023)

#### T1583.005 - Acquire Infrastructure: Botnet

Description:

Adversaries may buy, lease, or rent a network of compromised systems that can be used during targeting. A botnet is a network of compromised systems that can be instructed to perform coordinated tasks.(Citation: Norton Botnet) Adversaries may purchase a subscription to use an existing botnet from a booter/stresser service. 

Internet-facing edge devices and related network appliances that are end-of-life (EOL) and unsupported by their manufacturers are commonly acquired for botnet activities. Adversaries may lease operational relay box (ORB) networks – consisting of virtual private servers (VPS), small office/home office (SOHO) routers, or Internet of Things (IoT) devices – to serve as a botnet.(Citation: ORB Mandiant) 

With a botnet at their disposal, adversaries may perform follow-on activity such as large-scale [Phishing](https://attack.mitre.org/techniques/T1566) or Distributed Denial of Service (DDoS).(Citation: Imperva DDoS for Hire)(Citation: Krebs-Anna)(Citation: Krebs-Bazaar)(Citation: Krebs-Booter) Acquired botnets may also be used to support Command and Control activity, such as [Hide Infrastructure](https://attack.mitre.org/techniques/T1665) through an established [Proxy](https://attack.mitre.org/techniques/T1090) network.

Procedures:

- [G0125] HAFNIUM: [HAFNIUM](https://attack.mitre.org/groups/G0125) has incorporated leased devices into covert networks to obfuscate communications.(Citation: Microsoft Silk Typhoon MAR 2025)
- [G1023] APT5: [APT5](https://attack.mitre.org/groups/G1023) has acquired a network of compromised systems – specifically an ORB (operational relay box) network – for follow on activities.(Citation: ORB Mandiant)
- [G0004] Ke3chang: [Ke3chang](https://attack.mitre.org/groups/G0004) has utilized an ORB (operational relay box) network for reconnaissance and vulnerability exploitation.(Citation: ORB Mandiant)

#### T1583.006 - Acquire Infrastructure: Web Services

Description:

Adversaries may register for web services that can be used during targeting. A variety of popular websites exist for adversaries to register for a web-based service that can be abused during later stages of the adversary lifecycle, such as during Command and Control ([Web Service](https://attack.mitre.org/techniques/T1102)), [Exfiltration Over Web Service](https://attack.mitre.org/techniques/T1567), or [Phishing](https://attack.mitre.org/techniques/T1566). Using common services, such as those offered by Google, GitHub, or Twitter, makes it easier for adversaries to hide in expected noise.(Citation: FireEye APT29)(Citation: Hacker News GitHub Abuse 2024) By utilizing a web service, adversaries can make it difficult to physically tie back operations to them.

Procedures:

- [G1006] Earth Lusca: [Earth Lusca](https://attack.mitre.org/groups/G1006) has established GitHub accounts to host their malware.(Citation: TrendMicro EarthLusca 2022)
- [G0125] HAFNIUM: [HAFNIUM](https://attack.mitre.org/groups/G0125) has acquired web services for use in C2 and exfiltration.(Citation: Microsoft HAFNIUM March 2020)
- [G0010] Turla: [Turla](https://attack.mitre.org/groups/G0010) has created web accounts including Dropbox and GitHub for C2 and document exfiltration.(Citation: ESET Crutch December 2020)
- [G0128] ZIRCONIUM: [ZIRCONIUM](https://attack.mitre.org/groups/G0128) has used GitHub to host malware linked in spearphishing e-mails.(Citation: Google Election Threats October 2020)(Citation: Zscaler APT31 Covid-19 October 2020)
- [G0025] APT17: [APT17](https://attack.mitre.org/groups/G0025) has created profile pages in Microsoft TechNet that were used as C2 infrastructure.(Citation: FireEye APT17)
- [G0069] MuddyWater: [MuddyWater](https://attack.mitre.org/groups/G0069) has used file sharing services including OneHub, Sync, and TeraBox to distribute tools.(Citation: Anomali Static Kitten February 2021)(Citation: Trend Micro Muddy Water March 2021)(Citation: Proofpoint TA450 Phishing March 2024)
- [G0007] APT28: [APT28](https://attack.mitre.org/groups/G0007) has used newly-created Blogspot pages for credential harvesting operations.(Citation: Google TAG Ukraine Threat Landscape March 2022)
- [G0016] APT29: [APT29](https://attack.mitre.org/groups/G0016) has registered algorithmically generated Twitter handles that are used for C2 by malware, such as [HAMMERTOSS](https://attack.mitre.org/software/S0037). [APT29](https://attack.mitre.org/groups/G0016) has also used legitimate web services such as Dropbox and Constant Contact in their operations.(Citation: FireEye APT29)(Citation: MSTIC NOBELIUM May 2021)
- [C0046] ArcaneDoor: [ArcaneDoor](https://attack.mitre.org/campaigns/C0046) included the use of OpenConnect VPN Server instances for conducting actions on victim devices.(Citation: Cisco ArcaneDoor 2024)
- [G0046] FIN7: [FIN7](https://attack.mitre.org/groups/G0046) has set up Amazon S3 buckets to host trojanized digital products.(Citation: Mandiant FIN7 Apr 2022)
- [C0013] Operation Sharpshooter: For [Operation Sharpshooter](https://attack.mitre.org/campaigns/C0013), the threat actors used Dropbox to host lure documents and their first-stage downloader.(Citation: McAfee Sharpshooter December 2018)
- [C0022] Operation Dream Job: During [Operation Dream Job](https://attack.mitre.org/campaigns/C0022), [Lazarus Group](https://attack.mitre.org/groups/G0032) used file hosting services like DropBox and OneDrive.(Citation: ClearSky Lazarus Aug 2020)
- [G0032] Lazarus Group: [Lazarus Group](https://attack.mitre.org/groups/G0032) has hosted malicious downloads on Github.(Citation: CISA AppleJeus Feb 2021)
- [G0142] Confucius: [Confucius](https://attack.mitre.org/groups/G0142) has obtained cloud storage service accounts to host stolen data.(Citation: TrendMicro Confucius APT Feb 2018)
- [G0136] IndigoZebra: [IndigoZebra](https://attack.mitre.org/groups/G0136) created Dropbox accounts for their operations.(Citation: HackerNews IndigoZebra July 2021)(Citation: Checkpoint IndigoZebra July 2021)
- [G1031] Saint Bear: [Saint Bear](https://attack.mitre.org/groups/G1031) has leveraged the Discord content delivery network to host malicious content for retrieval during initial access operations.(Citation: Palo Alto Unit 42 OutSteel SaintBot February 2022 )
- [G1005] POLONIUM: [POLONIUM](https://attack.mitre.org/groups/G1005) has created and used legitimate Microsoft OneDrive accounts for their operations.(Citation: Microsoft POLONIUM June 2022)
- [G0050] APT32: [APT32](https://attack.mitre.org/groups/G0050) has set up Dropbox, Amazon S3, and Google Drive to host malicious downloads.(Citation: Volexity Ocean Lotus November 2020)
- [G0094] Kimsuky: [Kimsuky](https://attack.mitre.org/groups/G0094) has hosted content used for targeting efforts via web services such as Blogspot.(Citation: Talos Kimsuky Nov 2021)
- [G1038] TA578: [TA578](https://attack.mitre.org/groups/G1038) has used Google Firebase to host malicious scripts.(Citation: Latrodectus APR 2024)
- [G1018] TA2541: [TA2541](https://attack.mitre.org/groups/G1018) has hosted malicious files on various platforms including Google Drive, OneDrive, Discord, PasteText, ShareText, and GitHub.(Citation: Proofpoint TA2541 February 2022)
- [G0059] Magic Hound: [Magic Hound](https://attack.mitre.org/groups/G0059) has acquired Amazon S3 buckets to use in C2.(Citation: Check Point APT35 CharmPower January 2022)
- [G0140] LazyScripter: [LazyScripter](https://attack.mitre.org/groups/G0140) has established GitHub accounts to host its toolsets.(Citation: MalwareBytes LazyScripter Feb 2021)

#### T1583.007 - Acquire Infrastructure: Serverless

Description:

Adversaries may purchase and configure serverless cloud infrastructure, such as Cloudflare Workers, AWS Lambda functions, or Google Apps Scripts, that can be used during targeting. By utilizing serverless infrastructure, adversaries can make it more difficult to attribute infrastructure used during operations back to them.

Once acquired, the serverless runtime environment can be leveraged to either respond directly to infected machines or to [Proxy](https://attack.mitre.org/techniques/T1090) traffic to an adversary-owned command and control server.(Citation: BlackWater Malware Cloudflare Workers)(Citation: AWS Lambda Redirector)(Citation: GWS Apps Script Abuse 2021) As traffic generated by these functions will appear to come from subdomains of common cloud providers, it may be difficult to distinguish from ordinary traffic to these providers - making it easier to [Hide Infrastructure](https://attack.mitre.org/techniques/T1665).(Citation: Detecting Command & Control in the Cloud)(Citation: BlackWater Malware Cloudflare Workers)

Procedures:

- [C0040] APT41 DUST: [APT41 DUST](https://attack.mitre.org/campaigns/C0040) used infrastructure hosted behind Cloudflare or utilized Cloudflare Workers for command and control.(Citation: Google Cloud APT41 2024)

#### T1583.008 - Acquire Infrastructure: Malvertising

Description:

Adversaries may purchase online advertisements that can be abused to distribute malware to victims. Ads can be purchased to plant as well as favorably position artifacts in specific locations  online, such as prominently placed within search engine results. These ads may make it more difficult for users to distinguish between actual search results and advertisements.(Citation: spamhaus-malvertising) Purchased ads may also target specific audiences using the advertising network’s capabilities, potentially further taking advantage of the trust inherently given to search engines and popular websites. 

Adversaries may purchase ads and other resources to help distribute artifacts containing malicious code to victims. Purchased ads may attempt to impersonate or spoof well-known brands. For example, these spoofed ads may trick victims into clicking the ad which could then send them to a malicious domain that may be a clone of official websites containing trojanized versions of the advertised software.(Citation: Masquerads-Guardio)(Citation: FBI-search) Adversary’s efforts to create malicious domains and purchase advertisements may also be automated at scale to better resist cleanup efforts.(Citation: sentinelone-malvertising) 

Malvertising may be used to support [Drive-by Target](https://attack.mitre.org/techniques/T1608/004) and [Drive-by Compromise](https://attack.mitre.org/techniques/T1189), potentially requiring limited interaction from the user if the ad contains code/exploits that infect the target system's web browser.(Citation: BBC-malvertising)

Adversaries may also employ several techniques to evade detection by the advertising network. For example, adversaries may dynamically route ad clicks to send automated crawler/policy enforcer traffic to benign sites while validating potential targets then sending victims referred from real ad clicks to malicious pages. This infection vector may therefore remain hidden from the ad network as well as any visitor not reaching the malicious sites with a valid identifier from clicking on the advertisement.(Citation: Masquerads-Guardio) Other tricks, such as intentional typos to avoid brand reputation monitoring, may also be used to evade automated detection.(Citation: spamhaus-malvertising)

Procedures:

- [G1020] Mustard Tempest: [Mustard Tempest](https://attack.mitre.org/groups/G1020) has posted false advertisements including for software packages and browser updates in order to distribute malware.(Citation: Microsoft Ransomware as a Service)
- [S1130] Raspberry Robin: [Raspberry Robin](https://attack.mitre.org/software/S1130) variants have been delivered via malicious advertising items that, when interacted with, download a malicious archive file containing the initial payload, hosted on services such as Discord.(Citation: HP RaspberryRobin 2024)


### T1584 - Compromise Infrastructure

Description:

Adversaries may compromise third-party infrastructure that can be used during targeting. Infrastructure solutions include physical or cloud servers, domains, network devices, and third-party web and DNS services. Instead of buying, leasing, or renting infrastructure an adversary may compromise infrastructure and use it during other phases of the adversary lifecycle.(Citation: Mandiant APT1)(Citation: ICANNDomainNameHijacking)(Citation: Talos DNSpionage Nov 2018)(Citation: FireEye EPS Awakens Part 2) Additionally, adversaries may compromise numerous machines to form a botnet they can leverage.

Use of compromised infrastructure allows adversaries to stage, launch, and execute operations. Compromised infrastructure can help adversary operations blend in with traffic that is seen as normal, such as contact with high reputation or trusted sites. For example, adversaries may leverage compromised infrastructure (potentially also in conjunction with [Digital Certificates](https://attack.mitre.org/techniques/T1588/004)) to further blend in and support staged information gathering and/or [Phishing](https://attack.mitre.org/techniques/T1566) campaigns.(Citation: FireEye DNS Hijack 2019) Adversaries may also compromise numerous machines to support [Proxy](https://attack.mitre.org/techniques/T1090) and/or proxyware services or to form a botnet.(Citation: amnesty_nso_pegasus)(Citation: Sysdig Proxyjacking) Additionally, adversaries may compromise infrastructure residing in close proximity to a target in order to gain [Initial Access](https://attack.mitre.org/tactics/TA0001) via [Wi-Fi Networks](https://attack.mitre.org/techniques/T1669).(Citation: Nearest Neighbor Volexity)

By using compromised infrastructure, adversaries may enable follow-on malicious operations. Prior to targeting, adversaries may also compromise the infrastructure of other adversaries.(Citation: NSA NCSC Turla OilRig)

Procedures:

- [C0043] Indian Critical Infrastructure Intrusions: [Indian Critical Infrastructure Intrusions](https://attack.mitre.org/campaigns/C0043) included the use of compromised infrastructure, such as DVR and IP camera devices, for command and control purposes in [ShadowPad](https://attack.mitre.org/software/S0596) activity.(Citation: RecordedFuture RedEcho 2022)
- [C0051] APT28 Nearest Neighbor Campaign: During [APT28 Nearest Neighbor Campaign](https://attack.mitre.org/campaigns/C0051), [APT28](https://attack.mitre.org/groups/G0007) compromised third-party infrastructure in physical proximity to targets of interest for follow-on activities.(Citation: Nearest Neighbor Volexity)

#### T1584.001 - Compromise Infrastructure: Domains

Description:

Adversaries may hijack domains and/or subdomains that can be used during targeting. Domain registration hijacking is the act of changing the registration of a domain name without the permission of the original registrant.(Citation: ICANNDomainNameHijacking) Adversaries may gain access to an email account for the person listed as the owner of the domain. The adversary can then claim that they forgot their password in order to make changes to the domain registration. Other possibilities include social engineering a domain registration help desk to gain access to an account, taking advantage of renewal process gaps, or compromising a cloud service that enables managing domains (e.g., AWS Route53).(Citation: Krebs DNS Hijack 2019)

Subdomain hijacking can occur when organizations have DNS entries that point to non-existent or deprovisioned resources. In such cases, an adversary may take control of a subdomain to conduct operations with the benefit of the trust associated with that domain.(Citation: Microsoft Sub Takeover 2020)

Adversaries who compromise a domain may also engage in domain shadowing by creating malicious subdomains under their control while keeping any existing DNS records. As service will not be disrupted, the malicious subdomains may go unnoticed for long periods of time.(Citation: Palo Alto Unit 42 Domain Shadowing 2022)

Procedures:

- [G0059] Magic Hound: [Magic Hound](https://attack.mitre.org/groups/G0059) has used compromised domains to host links targeted to specific phishing victims.(Citation: ClearSky Kittens Back 3 August 2020)(Citation: Proofpoint TA453 July2021)(Citation: Certfa Charming Kitten January 2021)(Citation: Google Iran Threats October 2021)
- [G1008] SideCopy: [SideCopy](https://attack.mitre.org/groups/G1008) has compromised domains for some of their infrastructure, including for C2 and staging malware.(Citation: MalwareBytes SideCopy Dec 2021)
- [C0024] SolarWinds Compromise: For the [SolarWinds Compromise](https://attack.mitre.org/campaigns/C0024), [APT29](https://attack.mitre.org/groups/G0016) compromised domains to use for C2.(Citation: MSTIC NOBELIUM Mar 2021)
- [G0134] Transparent Tribe: [Transparent Tribe](https://attack.mitre.org/groups/G0134) has compromised domains for use in targeted malicious campaigns.(Citation: Proofpoint Operation Transparent Tribe March 2016)
- [C0022] Operation Dream Job: For [Operation Dream Job](https://attack.mitre.org/campaigns/C0022), [Lazarus Group](https://attack.mitre.org/groups/G0032) compromised domains in Italy and other countries for their C2 infrastructure.(Citation: McAfee Lazarus Jul 2020)(Citation: McAfee Lazarus Nov 2020)
- [S1138] Gootloader: [Gootloader](https://attack.mitre.org/software/S1138) has used compromised legitimate domains to as a delivery network for malicious payloads.(Citation: SentinelOne Gootloader June 2021)
- [C0021] C0021: For [C0021](https://attack.mitre.org/campaigns/C0021), the threat actors used legitimate but compromised domains to host malicious payloads.(Citation: Microsoft Unidentified Dec 2018)
- [C0010] C0010: During [C0010](https://attack.mitre.org/campaigns/C0010), UNC3890 actors likely compromised the domain of a legitimate Israeli shipping company.(Citation: Mandiant UNC3890 Aug 2022)
- [G1020] Mustard Tempest: [Mustard Tempest](https://attack.mitre.org/groups/G1020) operates a global network of compromised websites that redirect into a traffic distribution system (TDS) to select victims for a fake browser update page.(Citation: Secureworks Gold Prelude Profile)(Citation: SocGholish-update)(Citation: SentinelOne SocGholish Infrastructure November 2022)(Citation: Red Canary SocGholish March 2024)
- [G0094] Kimsuky: [Kimsuky](https://attack.mitre.org/groups/G0094) has compromised legitimate sites and used them to distribute malware.(Citation: KISA Operation Muzabi)(Citation: Mandiant APT43 March 2024)(Citation: Mandiant APT43 Full PDF Report)
- [G0006] APT1: [APT1](https://attack.mitre.org/groups/G0006) hijacked FQDNs associated with legitimate websites hosted by hop points.(Citation: Mandiant APT1)

#### T1584.002 - Compromise Infrastructure: DNS Server

Description:

Adversaries may compromise third-party DNS servers that can be used during targeting. During post-compromise activity, adversaries may utilize DNS traffic for various tasks, including for Command and Control (ex: [Application Layer Protocol](https://attack.mitre.org/techniques/T1071)). Instead of setting up their own DNS servers, adversaries may compromise third-party DNS servers in support of operations.

By compromising DNS servers, adversaries can alter DNS records. Such control can allow for redirection of an organization's traffic, facilitating Collection and Credential Access efforts for the adversary.(Citation: Talos DNSpionage Nov 2018)(Citation: FireEye DNS Hijack 2019)  Additionally, adversaries may leverage such control in conjunction with [Digital Certificates](https://attack.mitre.org/techniques/T1588/004) to redirect traffic to adversary-controlled infrastructure, mimicking normal trusted network communications.(Citation: FireEye DNS Hijack 2019)(Citation: Crowdstrike DNS Hijack 2019) Adversaries may also be able to silently create subdomains pointed at malicious servers without tipping off the actual owner of the DNS server.(Citation: CiscoAngler)(Citation: Proofpoint Domain Shadowing)

Procedures:

- [G1041] Sea Turtle: [Sea Turtle](https://attack.mitre.org/groups/G1041) modified Name Server (NS) items to refer to [Sea Turtle](https://attack.mitre.org/groups/G1041)-controlled DNS servers to provide responses for all DNS lookups.(Citation: Talos Sea Turtle 2019)(Citation: Talos Sea Turtle 2019_2)
- [G1004] LAPSUS$: [LAPSUS$](https://attack.mitre.org/groups/G1004) has reconfigured a victim's DNS records to actor-controlled domains and websites.(Citation: NCC Group LAPSUS Apr 2022)

#### T1584.003 - Compromise Infrastructure: Virtual Private Server

Description:

Adversaries may compromise third-party Virtual Private Servers (VPSs) that can be used during targeting. There exist a variety of cloud service providers that will sell virtual machines/containers as a service. Adversaries may compromise VPSs purchased by third-party entities. By compromising a VPS to use as infrastructure, adversaries can make it difficult to physically tie back operations to themselves.(Citation: NSA NCSC Turla OilRig)

Compromising a VPS for use in later stages of the adversary lifecycle, such as Command and Control, can allow adversaries to benefit from the ubiquity and trust associated with higher reputation cloud service providers as well as that added by the compromised third-party.

Procedures:

- [C0048] Operation MidnightEclipse: During [Operation MidnightEclipse](https://attack.mitre.org/campaigns/C0048), threat actors abused Virtual Private Servers to store malicious files.(Citation: Volexity UPSTYLE 2024)
- [G1017] Volt Typhoon: [Volt Typhoon](https://attack.mitre.org/groups/G1017) has compromised Virtual Private Servers (VPS) to proxy C2 traffic.(Citation: CISA AA24-038A PRC Critical Infrastructure February 2024)
- [G0010] Turla: [Turla](https://attack.mitre.org/groups/G0010) has used the VPS infrastructure of compromised Iranian threat actors.(Citation: NSA NCSC Turla OilRig)

#### T1584.004 - Compromise Infrastructure: Server

Description:

Adversaries may compromise third-party servers that can be used during targeting. Use of servers allows an adversary to stage, launch, and execute an operation. During post-compromise activity, adversaries may utilize servers for various tasks, including for Command and Control.(Citation: TrendMicro EarthLusca 2022) Instead of purchasing a [Server](https://attack.mitre.org/techniques/T1583/004) or [Virtual Private Server](https://attack.mitre.org/techniques/T1583/003), adversaries may compromise third-party servers in support of operations.

Adversaries may also compromise web servers to support watering hole operations, as in [Drive-by Compromise](https://attack.mitre.org/techniques/T1189), or email servers to support [Phishing](https://attack.mitre.org/techniques/T1566) operations.

Procedures:

- [G0032] Lazarus Group: [Lazarus Group](https://attack.mitre.org/groups/G0032) has compromised servers to stage malicious tools.(Citation: Kaspersky ThreatNeedle Feb 2021)
- [G1017] Volt Typhoon: [Volt Typhoon](https://attack.mitre.org/groups/G1017) has used compromised Paessler Router Traffic Grapher (PRTG) servers from other organizations for C2.(Citation: Secureworks BRONZE SILHOUETTE May 2023)(Citation: CISA AA24-038A PRC Critical Infrastructure February 2024)
- [G0035] Dragonfly: [Dragonfly](https://attack.mitre.org/groups/G0035) has compromised legitimate websites to host C2 and malware modules.(Citation: Gigamon Berserk Bear October 2021)
- [C0013] Operation Sharpshooter: For [Operation Sharpshooter](https://attack.mitre.org/campaigns/C0013), the threat actors compromised a server they used as part of the campaign's infrastructure.(Citation: Bleeping Computer Op Sharpshooter March 2019)
- [C0042] Outer Space: During [Outer Space](https://attack.mitre.org/campaigns/C0042), [OilRig](https://attack.mitre.org/groups/G0049) compromised an Israeli human resources site to use as a C2 server.(Citation: ESET OilRig Campaigns Sep 2023)
- [G0010] Turla: [Turla](https://attack.mitre.org/groups/G0010) has used compromised servers as infrastructure.(Citation: Recorded Future Turla Infra 2020)(Citation: Accenture HyperStack October 2020)(Citation: Talos TinyTurla September 2021)
- [G0065] Leviathan: [Leviathan](https://attack.mitre.org/groups/G0065) has used compromised legitimate websites as command and control nodes for operations.(Citation: CISA Leviathan 2024)
- [G0023] APT16: [APT16](https://attack.mitre.org/groups/G0023) has compromised otherwise legitimate sites as staging servers for second-stage payloads.(Citation: FireEye EPS Awakens Part 2)
- [G0034] Sandworm Team: [Sandworm Team](https://attack.mitre.org/groups/G0034) compromised legitimate Linux servers running the EXIM mail transfer agent for use in subsequent campaigns.(Citation: NSA Sandworm 2020)(Citation: Leonard TAG 2023)
- [G1034] Daggerfly: [Daggerfly](https://attack.mitre.org/groups/G1034) compromised web servers hosting updates for software as part of a supply chain intrusion.(Citation: ESET EvasivePanda 2024)
- [C0002] Night Dragon: During [Night Dragon](https://attack.mitre.org/campaigns/C0002), threat actors compromised web servers to use for C2.(Citation: McAfee Night Dragon)
- [C0022] Operation Dream Job: For [Operation Dream Job](https://attack.mitre.org/campaigns/C0022), [Lazarus Group](https://attack.mitre.org/groups/G0032) compromised servers to host their malicious tools.(Citation: ClearSky Lazarus Aug 2020)(Citation: ESET Lazarus Jun 2020)(Citation: McAfee Lazarus Jul 2020)
- [G0119] Indrik Spider: [Indrik Spider](https://attack.mitre.org/groups/G0119) has served fake updates via legitimate websites that have been compromised.(Citation: Crowdstrike Indrik November 2018)
- [C0044] Juicy Mix: During [Juicy Mix](https://attack.mitre.org/campaigns/C0044), [OilRig](https://attack.mitre.org/groups/G0049) compromised an Israeli job portal to use for a C2 server.(Citation: ESET OilRig Campaigns Sep 2023)
- [G1006] Earth Lusca: [Earth Lusca](https://attack.mitre.org/groups/G1006) has used compromised web servers as part of their operational infrastructure.(Citation: TrendMicro EarthLusca 2022)

#### T1584.005 - Compromise Infrastructure: Botnet

Description:

Adversaries may compromise numerous third-party systems to form a botnet that can be used during targeting. A botnet is a network of compromised systems that can be instructed to perform coordinated tasks.(Citation: Norton Botnet) Instead of purchasing/renting a botnet from a booter/stresser service, adversaries may build their own botnet by compromising numerous third-party systems.(Citation: Imperva DDoS for Hire) Adversaries may also conduct a takeover of an existing botnet, such as redirecting bots to adversary-controlled C2 servers.(Citation: Dell Dridex Oct 2015) With a botnet at their disposal, adversaries may perform follow-on activity such as large-scale [Phishing](https://attack.mitre.org/techniques/T1566) or Distributed Denial of Service (DDoS).

Procedures:

- [G0125] HAFNIUM: [HAFNIUM](https://attack.mitre.org/groups/G0125) has used compromised devices in covert networks to obfuscate communications.(Citation: Microsoft Silk Typhoon MAR 2025)
- [G0001] Axiom: [Axiom](https://attack.mitre.org/groups/G0001) has used large groups of compromised machines for use as proxy nodes.(Citation: Novetta-Axiom)
- [G0034] Sandworm Team: [Sandworm Team](https://attack.mitre.org/groups/G0034) has used a large-scale botnet to target Small Office/Home Office (SOHO) network devices.(Citation: NCSC Cyclops Blink February 2022)
- [G1017] Volt Typhoon: [Volt Typhoon](https://attack.mitre.org/groups/G1017) Volt Typhoon has used compromised Cisco and NETGEAR end-of-life SOHO routers implanted with KV Botnet malware to support operations.(Citation: CISA AA24-038A PRC Critical Infrastructure February 2024)

#### T1584.006 - Compromise Infrastructure: Web Services

Description:

Adversaries may compromise access to third-party web services that can be used during targeting. A variety of popular websites exist for legitimate users to register for web-based services, such as GitHub, Twitter, Dropbox, Google, SendGrid, etc. Adversaries may try to take ownership of a legitimate user's access to a web service and use that web service as infrastructure in support of cyber operations. Such web services can be abused during later stages of the adversary lifecycle, such as during Command and Control ([Web Service](https://attack.mitre.org/techniques/T1102)), [Exfiltration Over Web Service](https://attack.mitre.org/techniques/T1567), or [Phishing](https://attack.mitre.org/techniques/T1566).(Citation: Recorded Future Turla Infra 2020) Using common services, such as those offered by Google or Twitter, makes it easier for adversaries to hide in expected noise. By utilizing a web service, particularly when access is stolen from legitimate users, adversaries can make it difficult to physically tie back operations to them. Additionally, leveraging compromised web-based email services may allow adversaries to leverage the trust associated with legitimate domains.

Procedures:

- [G0010] Turla: [Turla](https://attack.mitre.org/groups/G0010) has frequently used compromised WordPress sites for C2 infrastructure.(Citation: Recorded Future Turla Infra 2020)
- [G1006] Earth Lusca: [Earth Lusca](https://attack.mitre.org/groups/G1006) has compromised Google Drive repositories.(Citation: TrendMicro EarthLusca 2022)
- [S1138] Gootloader: [Gootloader](https://attack.mitre.org/software/S1138) can insert malicious scripts to compromise vulnerable content management systems (CMS).(Citation: SentinelOne Gootloader June 2021)
- [G1012] CURIUM: [CURIUM](https://attack.mitre.org/groups/G1012) has compromised legitimate websites to enable strategic website compromise attacks.(Citation: PWC Yellow Liderc 2023)
- [G1035] Winter Vivern: [Winter Vivern](https://attack.mitre.org/groups/G1035) has used compromised WordPress sites to host malicious payloads for download.(Citation: SentinelOne WinterVivern 2023)
- [C0048] Operation MidnightEclipse: During [Operation MidnightEclipse](https://attack.mitre.org/campaigns/C0048), threat actors abused compromised AWS buckets to store files.(Citation: Volexity UPSTYLE 2024)

#### T1584.007 - Compromise Infrastructure: Serverless

Description:

Adversaries may compromise serverless cloud infrastructure, such as Cloudflare Workers, AWS Lambda functions, or Google Apps Scripts, that can be used during targeting. By utilizing serverless infrastructure, adversaries can make it more difficult to attribute infrastructure used during operations back to them. 

Once compromised, the serverless runtime environment can be leveraged to either respond directly to infected machines or to [Proxy](https://attack.mitre.org/techniques/T1090) traffic to an adversary-owned command and control server.(Citation: BlackWater Malware Cloudflare Workers)(Citation: AWS Lambda Redirector)(Citation: GWS Apps Script Abuse 2021) As traffic generated by these functions will appear to come from subdomains of common cloud providers, it may be difficult to distinguish from ordinary traffic to these providers - making it easier to [Hide Infrastructure](https://attack.mitre.org/techniques/T1665).(Citation: Detecting Command & Control in the Cloud)(Citation: BlackWater Malware Cloudflare Workers)

#### T1584.008 - Compromise Infrastructure: Network Devices

Description:

Adversaries may compromise third-party network devices that can be used during targeting. Network devices, such as small office/home office (SOHO) routers, may be compromised where the adversary's ultimate goal is not [Initial Access](https://attack.mitre.org/tactics/TA0001) to that environment -- instead leveraging these devices to support additional targeting.

Once an adversary has control, compromised network devices can be used to launch additional operations, such as hosting payloads for [Phishing](https://attack.mitre.org/techniques/T1566) campaigns (i.e., [Link Target](https://attack.mitre.org/techniques/T1608/005)) or enabling the required access to execute [Content Injection](https://attack.mitre.org/techniques/T1659) operations. Adversaries may also be able to harvest reusable credentials (i.e., [Valid Accounts](https://attack.mitre.org/techniques/T1078)) from compromised network devices.

Adversaries often target Internet-facing edge devices and related network appliances that specifically do not support robust host-based defenses.(Citation: Mandiant Fortinet Zero Day)(Citation: Wired Russia Cyberwar)

Compromised network devices may be used to support subsequent [Command and Control](https://attack.mitre.org/tactics/TA0011) activity, such as [Hide Infrastructure](https://attack.mitre.org/techniques/T1665) through an established [Proxy](https://attack.mitre.org/techniques/T1090) and/or [Botnet](https://attack.mitre.org/techniques/T1584/005) network.(Citation: Justice GRU 2024)

Procedures:

- [C0053] FLORAHOX Activity: [FLORAHOX Activity](https://attack.mitre.org/campaigns/C0053) has compromised network routers and IoT devices for the ORB network.(Citation: ORB Mandiant)
- [G1017] Volt Typhoon: [Volt Typhoon](https://attack.mitre.org/groups/G1017) has compromised small office and home office (SOHO) network edge devices, many of which were located in the same geographic area as the victim, to proxy network traffic.(Citation: Microsoft Volt Typhoon May 2023)(Citation: Joint Cybersecurity Advisory Volt Typhoon June 2023)
- [G0007] APT28: [APT28](https://attack.mitre.org/groups/G0007) compromised Ubiquiti network devices to act as collection devices for credentials compromised via phishing webpages.(Citation: Leonard TAG 2023)
- [G0128] ZIRCONIUM: [ZIRCONIUM](https://attack.mitre.org/groups/G0128) has compromised network devices such as small office and home office (SOHO) routers and IoT devices for ORB (operational relay box) [Proxy](https://attack.mitre.org/techniques/T1090) networks.(Citation: ORB APT31)(Citation: ORB Mandiant)
- [C0035] KV Botnet Activity: [KV Botnet Activity](https://attack.mitre.org/campaigns/C0035) focuses on compromise of small office-home office (SOHO) network devices to build the subsequent botnet.(Citation: Lumen KVBotnet 2023)
- [C0039] Versa Director Zero Day Exploitation: [Versa Director Zero Day Exploitation](https://attack.mitre.org/campaigns/C0039) used compromised small office/home office (SOHO) devices to interact with vulnerable Versa Director servers.(Citation: Lumen Versa 2024)
- [C0029] Cutting Edge: During [Cutting Edge](https://attack.mitre.org/campaigns/C0029), threat actors used compromised and out-of-support Cyberoam VPN appliances for C2.(Citation: Mandiant Cutting Edge January 2024)(Citation: Volexity Ivanti Global Exploitation January 2024)
- [G0065] Leviathan: [Leviathan](https://attack.mitre.org/groups/G0065) has used compromised networking devices, such as small office/home office (SOHO) devices, as operational command and control infrastructure.(Citation: CISA Leviathan 2024)


### T1585 - Establish Accounts

Description:

Adversaries may create and cultivate accounts with services that can be used during targeting. Adversaries can create accounts that can be used to build a persona to further operations. Persona development consists of the development of public information, presence, history and appropriate affiliations. This development could be applied to social media, website, or other publicly available information that could be referenced and scrutinized for legitimacy over the course of an operation using that persona or identity.(Citation: NEWSCASTER2014)(Citation: BlackHatRobinSage)

For operations incorporating social engineering, the utilization of an online persona may be important. These personas may be fictitious or impersonate real people. The persona may exist on a single site or across multiple sites (ex: Facebook, LinkedIn, Twitter, Google, GitHub, Docker Hub, etc.). Establishing a persona may require development of additional documentation to make them seem real. This could include filling out profile information, developing social networks, or incorporating photos.(Citation: NEWSCASTER2014)(Citation: BlackHatRobinSage)

Establishing accounts can also include the creation of accounts with email providers, which may be directly leveraged for [Phishing for Information](https://attack.mitre.org/techniques/T1598) or [Phishing](https://attack.mitre.org/techniques/T1566).(Citation: Mandiant APT1) In addition, establishing accounts may allow adversaries to abuse free services, such as registering for trial periods to [Acquire Infrastructure](https://attack.mitre.org/techniques/T1583) for malicious purposes.(Citation: Free Trial PurpleUrchin)

Procedures:

- [G0117] Fox Kitten: [Fox Kitten](https://attack.mitre.org/groups/G0117) has created KeyBase accounts to communicate with ransomware victims.(Citation: ClearSky Pay2Kitten December 2020)(Citation: Check Point Pay2Key November 2020)
- [G0094] Kimsuky: [Kimsuky](https://attack.mitre.org/groups/G0094) has leveraged stolen PII to create accounts.(Citation: Mandiant APT43 Full PDF Report)
- [G1003] Ember Bear: [Ember Bear](https://attack.mitre.org/groups/G1003) has created accounts on dark web forums to obtain various tools and malware.(Citation: CISA GRU29155 2024)
- [G0025] APT17: [APT17](https://attack.mitre.org/groups/G0025) has created and cultivated profile pages in Microsoft TechNet. To make profile pages appear more legitimate, [APT17](https://attack.mitre.org/groups/G0025) has created biographical sections and posted in forum threads.(Citation: FireEye APT17)

#### T1585.001 - Establish Accounts: Social Media Accounts

Description:

Adversaries may create and cultivate social media accounts that can be used during targeting. Adversaries can create social media accounts that can be used to build a persona to further operations. Persona development consists of the development of public information, presence, history and appropriate affiliations.(Citation: NEWSCASTER2014)(Citation: BlackHatRobinSage)

For operations incorporating social engineering, the utilization of a persona on social media may be important. These personas may be fictitious or impersonate real people. The persona may exist on a single social media site or across multiple sites (ex: Facebook, LinkedIn, Twitter, etc.). Establishing a persona  on social media may require development of additional documentation to make them seem real. This could include filling out profile information, developing social networks, or incorporating photos. 

Once a persona has been developed an adversary can use it to create connections to targets of interest. These connections may be direct or may include trying to connect through others.(Citation: NEWSCASTER2014)(Citation: BlackHatRobinSage) These accounts may be leveraged during other phases of the adversary lifecycle, such as during Initial Access (ex: [Spearphishing via Service](https://attack.mitre.org/techniques/T1566/003)).

Procedures:

- [G0034] Sandworm Team: [Sandworm Team](https://attack.mitre.org/groups/G0034) has established social media accounts to disseminate victim internal-only documents and other sensitive data.(Citation: US District Court Indictment GRU Unit 74455 October 2020)
- [C0022] Operation Dream Job: For [Operation Dream Job](https://attack.mitre.org/campaigns/C0022), [Lazarus Group](https://attack.mitre.org/groups/G0032) created fake LinkedIn accounts for their targeting efforts.(Citation: ClearSky Lazarus Aug 2020)(Citation: ESET Lazarus Jun 2020)
- [G1011] EXOTIC LILY: [EXOTIC LILY](https://attack.mitre.org/groups/G1011) has established social media profiles to mimic employees of targeted companies.(Citation: Google EXOTIC LILY March 2022)
- [G1001] HEXANE: [HEXANE](https://attack.mitre.org/groups/G1001) has established fraudulent LinkedIn accounts impersonating HR department employees to target potential victims with fake job offers.(Citation: ClearSky Siamesekitten August 2021)
- [G0094] Kimsuky: [Kimsuky](https://attack.mitre.org/groups/G0094) has created social media accounts to monitor news and security trends as well as potential targets.(Citation: KISA Operation Muzabi)
- [G0065] Leviathan: [Leviathan](https://attack.mitre.org/groups/G0065) has created new social media accounts for targeting efforts.(Citation: CISA AA21-200A APT40 July 2021)
- [G1012] CURIUM: [CURIUM](https://attack.mitre.org/groups/G1012) has established a network of fictitious social media accounts, including on Facebook and LinkedIn, to establish relationships with victims, often posing as an attractive woman.(Citation: Microsoft Iranian Threat Actor Trends November 2021)
- [G0003] Cleaver: [Cleaver](https://attack.mitre.org/groups/G0003) has created fake LinkedIn profiles that included profile photos, details, and connections.(Citation: Dell Threat Group 2889)
- [C0023] Operation Ghost: For [Operation Ghost](https://attack.mitre.org/campaigns/C0023), [APT29](https://attack.mitre.org/groups/G0016) registered Twitter accounts to host C2 nodes.(Citation: ESET Dukes October 2019)
- [G0032] Lazarus Group: [Lazarus Group](https://attack.mitre.org/groups/G0032) has created new Twitter accounts to conduct social engineering against potential victims.(Citation: Google TAG Lazarus Jan 2021)
- [G0050] APT32: [APT32](https://attack.mitre.org/groups/G0050) has set up Facebook pages in tandem with fake websites.(Citation: Volexity Ocean Lotus November 2020)
- [G0117] Fox Kitten: [Fox Kitten](https://attack.mitre.org/groups/G0117) has used a Twitter account to communicate with ransomware victims.(Citation: ClearSky Pay2Kitten December 2020)
- [G0059] Magic Hound: [Magic Hound](https://attack.mitre.org/groups/G0059) has created fake LinkedIn and other social media accounts to contact targets and convince them--through messages and voice communications--to open malicious links.(Citation: ClearSky Kittens Back 3 August 2020)
- [G1033] Star Blizzard: [Star Blizzard](https://attack.mitre.org/groups/G1033) has established fraudulent profiles on professional networking sites to conduct reconnaissance.(Citation: Microsoft Star Blizzard August 2022)(Citation: CISA Star Blizzard Advisory December 2023)
- [G1036] Moonstone Sleet: [Moonstone Sleet](https://attack.mitre.org/groups/G1036) has created social media accounts to interact with victims.(Citation: Microsoft Moonstone Sleet 2024)

#### T1585.002 - Establish Accounts: Email Accounts

Description:

Adversaries may create email accounts that can be used during targeting. Adversaries can use accounts created with email providers to further their operations, such as leveraging them to conduct [Phishing for Information](https://attack.mitre.org/techniques/T1598) or [Phishing](https://attack.mitre.org/techniques/T1566).(Citation: Mandiant APT1) Establishing email accounts may also allow adversaries to abuse free services – such as trial periods – to [Acquire Infrastructure](https://attack.mitre.org/techniques/T1583) for follow-on purposes.(Citation: Free Trial PurpleUrchin)

Adversaries may also take steps to cultivate a persona around the email account, such as through use of [Social Media Accounts](https://attack.mitre.org/techniques/T1585/001), to increase the chance of success of follow-on behaviors. Created email accounts can also be used in the acquisition of infrastructure (ex: [Domains](https://attack.mitre.org/techniques/T1583/001)).(Citation: Mandiant APT1)

To decrease the chance of physically tying back operations to themselves, adversaries may make use of disposable email services.(Citation: Trend Micro R980 2016)

Procedures:

- [C0006] Operation Honeybee: During [Operation Honeybee](https://attack.mitre.org/campaigns/C0006), attackers created email addresses to register for a free account for a control server used for the implants.(Citation: McAfee Honeybee)
- [G0094] Kimsuky: [Kimsuky](https://attack.mitre.org/groups/G0094) has created email accounts for phishing operations.(Citation: KISA Operation Muzabi)(Citation: Mandiant APT43 March 2024)(Citation: Proofpoint TA427 April 2024)
- [G1036] Moonstone Sleet: [Moonstone Sleet](https://attack.mitre.org/groups/G1036) has created email accounts to interact with victims, including for phishing purposes.(Citation: Microsoft Moonstone Sleet 2024)
- [G0059] Magic Hound: [Magic Hound](https://attack.mitre.org/groups/G0059) has established email accounts using fake personas for spearphishing operations.(Citation: IBM ITG18 2020)(Citation: Proofpoint TA453 March 2021)
- [C0014] Operation Wocao: For [Operation Wocao](https://attack.mitre.org/campaigns/C0014), the threat actors registered email accounts to use during the campaign.(Citation: FoxIT Wocao December 2019)
- [C0022] Operation Dream Job: During [Operation Dream Job](https://attack.mitre.org/campaigns/C0022), [Lazarus Group](https://attack.mitre.org/groups/G0032) created fake email accounts to correspond with fake LinkedIn personas; [Lazarus Group](https://attack.mitre.org/groups/G0032) also established email accounts to match those of the victim as part of their BEC attempt.(Citation: ESET Lazarus Jun 2020)
- [G0129] Mustang Panda: [Mustang Panda](https://attack.mitre.org/groups/G0129) has leveraged the legitimate email marketing service SMTP2Go for phishing campaigns.(Citation: Proofpoint TA416 Europe March 2022)
- [G0065] Leviathan: [Leviathan](https://attack.mitre.org/groups/G0065) has created new email accounts for targeting efforts.(Citation: CISA AA21-200A APT40 July 2021)
- [G1033] Star Blizzard: [Star Blizzard](https://attack.mitre.org/groups/G1033) has registered impersonation email accounts to spoof experts in a particular field or individuals and organizations affiliated with the intended target.(Citation: Microsoft Star Blizzard August 2022)(Citation: CISA Star Blizzard Advisory December 2023)(Citation: Google TAG COLDRIVER January 2024)
- [G1044] APT42: [APT42](https://attack.mitre.org/groups/G1044) has created email accounts to use in spearphishing operations.(Citation: TAG APT42)
- [G1012] CURIUM: [CURIUM](https://attack.mitre.org/groups/G1012) has created dedicated email accounts for use with tools such as [IMAPLoader](https://attack.mitre.org/software/S1152).(Citation: PWC Yellow Liderc 2023)
- [G0122] Silent Librarian: [Silent Librarian](https://attack.mitre.org/groups/G0122) has established e-mail accounts to receive e-mails forwarded from compromised accounts.(Citation: DOJ Iran Indictments March 2018)
- [G1011] EXOTIC LILY: [EXOTIC LILY](https://attack.mitre.org/groups/G1011) has created e-mail accounts to spoof targeted organizations.(Citation: Google EXOTIC LILY March 2022)
- [G0006] APT1: [APT1](https://attack.mitre.org/groups/G0006) has created email accounts for later use in social engineering, phishing, and when registering domains.(Citation: Mandiant APT1)
- [G0102] Wizard Spider: [Wizard Spider](https://attack.mitre.org/groups/G0102) has leveraged ProtonMail email addresses in ransom notes when delivering [Ryuk](https://attack.mitre.org/software/S0446) ransomware.(Citation: Mandiant FIN12 Oct 2021)
- [G1001] HEXANE: [HEXANE](https://attack.mitre.org/groups/G1001) has established email accounts for use in domain registration including for ProtonMail addresses.(Citation: Kaspersky Lyceum October 2021)
- [G0119] Indrik Spider: [Indrik Spider](https://attack.mitre.org/groups/G0119) has created email accounts to communicate with their ransomware victims, to include providing payment and decryption details.(Citation: Crowdstrike Indrik November 2018)
- [G0034] Sandworm Team: [Sandworm Team](https://attack.mitre.org/groups/G0034) has created email accounts that mimic legitimate organizations for its spearphishing operations.(Citation: US District Court Indictment GRU Unit 74455 October 2020)
- [C0007] FunnyDream: For [FunnyDream](https://attack.mitre.org/campaigns/C0007), the threat actors likely established an identified email account to register a variety of domains that were used during the campaign.(Citation: Bitdefender FunnyDream Campaign November 2020)
- [C0016] Operation Dust Storm: For [Operation Dust Storm](https://attack.mitre.org/campaigns/C0016), the threat actors established email addresses to register domains for their operations.(Citation: Cylance Dust Storm)
- [G0032] Lazarus Group: [Lazarus Group](https://attack.mitre.org/groups/G0032) has created new email accounts for spearphishing operations.(Citation: Kaspersky ThreatNeedle Feb 2021)

#### T1585.003 - Establish Accounts: Cloud Accounts

Description:

Adversaries may create accounts with cloud providers that can be used during targeting. Adversaries can use cloud accounts to further their operations, including leveraging cloud storage services such as Dropbox, MEGA, Microsoft OneDrive, or AWS S3 buckets for [Exfiltration to Cloud Storage](https://attack.mitre.org/techniques/T1567/002) or to [Upload Tool](https://attack.mitre.org/techniques/T1608/002)s. Cloud accounts can also be used in the acquisition of infrastructure, such as [Virtual Private Server](https://attack.mitre.org/techniques/T1583/003)s or [Serverless](https://attack.mitre.org/techniques/T1583/007) infrastructure. Establishing cloud accounts may allow adversaries to develop sophisticated capabilities without managing their own servers.(Citation: Awake Security C2 Cloud)

Creating [Cloud Accounts](https://attack.mitre.org/techniques/T1585/003) may also require adversaries to establish [Email Accounts](https://attack.mitre.org/techniques/T1585/002) to register with the cloud provider.

Procedures:

- [G1046] Storm-1811: [Storm-1811](https://attack.mitre.org/groups/G1046) has created malicious accounts to enable activity via Microsoft Teams, typically spoofing various IT support and helpdesk themes.(Citation: Microsoft Storm-1811 2024)
- [C0042] Outer Space: During [Outer Space](https://attack.mitre.org/campaigns/C0042), [OilRig](https://attack.mitre.org/groups/G0049) created M365 email accounts to be used as part of C2.(Citation: ESET OilRig Campaigns Sep 2023)


### T1586 - Compromise Accounts

Description:

Adversaries may compromise accounts with services that can be used during targeting. For operations incorporating social engineering, the utilization of an online persona may be important. Rather than creating and cultivating accounts (i.e. [Establish Accounts](https://attack.mitre.org/techniques/T1585)), adversaries may compromise existing accounts. Utilizing an existing persona may engender a level of trust in a potential victim if they have a relationship, or knowledge of, the compromised persona. 

A variety of methods exist for compromising accounts, such as gathering credentials via [Phishing for Information](https://attack.mitre.org/techniques/T1598), purchasing credentials from third-party sites, brute forcing credentials (ex: password reuse from breach credential dumps), or paying employees, suppliers or business partners for access to credentials.(Citation: AnonHBGary)(Citation: Microsoft DEV-0537) Prior to compromising accounts, adversaries may conduct Reconnaissance to inform decisions about which accounts to compromise to further their operation.

Personas may exist on a single site or across multiple sites (ex: Facebook, LinkedIn, Twitter, Google, etc.). Compromised accounts may require additional development, this could include filling out or modifying profile information, further developing social networks, or incorporating photos.

Adversaries may directly leverage compromised email accounts for [Phishing for Information](https://attack.mitre.org/techniques/T1598) or [Phishing](https://attack.mitre.org/techniques/T1566).

#### T1586.001 - Compromise Accounts: Social Media Accounts

Description:

Adversaries may compromise social media accounts that can be used during targeting. For operations incorporating social engineering, the utilization of an online persona may be important. Rather than creating and cultivating social media profiles (i.e. [Social Media Accounts](https://attack.mitre.org/techniques/T1585/001)), adversaries may compromise existing social media accounts. Utilizing an existing persona may engender a level of trust in a potential victim if they have a relationship, or knowledge of, the compromised persona. 

A variety of methods exist for compromising social media accounts, such as gathering credentials via [Phishing for Information](https://attack.mitre.org/techniques/T1598), purchasing credentials from third-party sites, or by brute forcing credentials (ex: password reuse from breach credential dumps).(Citation: AnonHBGary) Prior to compromising social media accounts, adversaries may conduct Reconnaissance to inform decisions about which accounts to compromise to further their operation.

Personas may exist on a single site or across multiple sites (ex: Facebook, LinkedIn, Twitter, etc.). Compromised social media accounts may require additional development, this could include filling out or modifying profile information, further developing social networks, or incorporating photos.

Adversaries can use a compromised social media profile to create new, or hijack existing, connections to targets of interest. These connections may be direct or may include trying to connect through others.(Citation: NEWSCASTER2014)(Citation: BlackHatRobinSage) Compromised profiles may be leveraged during other phases of the adversary lifecycle, such as during Initial Access (ex: [Spearphishing via Service](https://attack.mitre.org/techniques/T1566/003)).

Procedures:

- [G0034] Sandworm Team: [Sandworm Team](https://attack.mitre.org/groups/G0034) creates credential capture webpages to compromise existing, legitimate social media accounts.(Citation: Slowik Sandworm 2021)
- [G0065] Leviathan: [Leviathan](https://attack.mitre.org/groups/G0065) has compromised social media accounts to conduct social engineering attacks.(Citation: CISA AA21-200A APT40 July 2021)

#### T1586.002 - Compromise Accounts: Email Accounts

Description:

Adversaries may compromise email accounts that can be used during targeting. Adversaries can use compromised email accounts to further their operations, such as leveraging them to conduct [Phishing for Information](https://attack.mitre.org/techniques/T1598), [Phishing](https://attack.mitre.org/techniques/T1566), or large-scale spam email campaigns. Utilizing an existing persona with a compromised email account may engender a level of trust in a potential victim if they have a relationship with, or knowledge of, the compromised persona. Compromised email accounts can also be used in the acquisition of infrastructure (ex: [Domains](https://attack.mitre.org/techniques/T1583/001)).

A variety of methods exist for compromising email accounts, such as gathering credentials via [Phishing for Information](https://attack.mitre.org/techniques/T1598), purchasing credentials from third-party sites, brute forcing credentials (ex: password reuse from breach credential dumps), or paying employees, suppliers or business partners for access to credentials.(Citation: AnonHBGary)(Citation: Microsoft DEV-0537) Prior to compromising email accounts, adversaries may conduct Reconnaissance to inform decisions about which accounts to compromise to further their operation. Adversaries may target compromising well-known email accounts or domains from which malicious spam or [Phishing](https://attack.mitre.org/techniques/T1566) emails may evade reputation-based email filtering rules.

Adversaries can use a compromised email account to hijack existing email threads with targets of interest.

Procedures:

- [G0007] APT28: [APT28](https://attack.mitre.org/groups/G0007) has used compromised email accounts to send credential phishing emails.(Citation: Google TAG Ukraine Threat Landscape March 2022)
- [G0059] Magic Hound: [Magic Hound](https://attack.mitre.org/groups/G0059) has compromised personal email accounts through the use of legitimate credentials and gathered additional victim information.(Citation: IBM ITG18 2020)
- [G0049] OilRig: [OilRig](https://attack.mitre.org/groups/G0049) has compromised email accounts to send phishing emails.(Citation: ClearSky OilRig Jan 2017)
- [G1001] HEXANE: [HEXANE](https://attack.mitre.org/groups/G1001) has used compromised accounts to send spearphishing emails.(Citation: SecureWorks August 2019)
- [G0094] Kimsuky: [Kimsuky](https://attack.mitre.org/groups/G0094) has compromised email accounts to send spearphishing e-mails.(Citation: VirusBulletin Kimsuky October 2019)(Citation: Malwarebytes Kimsuky June 2021)
- [G1004] LAPSUS$: [LAPSUS$](https://attack.mitre.org/groups/G1004) has payed employees, suppliers, and business partners of target organizations for credentials.(Citation: MSTIC DEV-0537 Mar 2022)(Citation: NCC Group LAPSUS Apr 2022)
- [G0136] IndigoZebra: [IndigoZebra](https://attack.mitre.org/groups/G0136) has compromised legitimate email accounts to use in their spearphishing operations.(Citation: Checkpoint IndigoZebra July 2021)
- [G1037] TA577: [TA577](https://attack.mitre.org/groups/G1037) has sent thread hijacked messages from compromised emails.(Citation: Latrodectus APR 2024)
- [G0016] APT29: [APT29](https://attack.mitre.org/groups/G0016) has compromised email accounts to further enable phishing campaigns and taken control of dormant accounts.(Citation: ANSSI Nobelium Phishing December 2021)(Citation: Mandiant APT29 Microsoft 365 2022)
- [G1033] Star Blizzard: [Star Blizzard](https://attack.mitre.org/groups/G1033) has used compromised email accounts to conduct spearphishing against
 contacts of the original victim.(Citation: CISA Star Blizzard Advisory December 2023)
- [G0065] Leviathan: [Leviathan](https://attack.mitre.org/groups/G0065) has compromised email accounts to conduct social engineering attacks.(Citation: CISA AA21-200A APT40 July 2021)

#### T1586.003 - Compromise Accounts: Cloud Accounts

Description:

Adversaries may compromise cloud accounts that can be used during targeting. Adversaries can use compromised cloud accounts to further their operations, including leveraging cloud storage services such as Dropbox, Microsoft OneDrive, or AWS S3 buckets for [Exfiltration to Cloud Storage](https://attack.mitre.org/techniques/T1567/002) or to [Upload Tool](https://attack.mitre.org/techniques/T1608/002)s. Cloud accounts can also be used in the acquisition of infrastructure, such as [Virtual Private Server](https://attack.mitre.org/techniques/T1583/003)s or [Serverless](https://attack.mitre.org/techniques/T1583/007) infrastructure. Additionally, cloud-based messaging services such as Twilio, SendGrid, AWS End User Messaging, AWS SNS (Simple Notification Service), or AWS SES (Simple Email Service) may be leveraged for spam or [Phishing](https://attack.mitre.org/techniques/T1566).(Citation: Palo Alto Unit 42 Compromised Cloud Compute Credentials 2022)(Citation: Netcraft SendGrid 2024) Compromising cloud accounts may allow adversaries to develop sophisticated capabilities without managing their own servers.(Citation: Awake Security C2 Cloud)

A variety of methods exist for compromising cloud accounts, such as gathering credentials via [Phishing for Information](https://attack.mitre.org/techniques/T1598), purchasing credentials from third-party sites, conducting [Password Spraying](https://attack.mitre.org/techniques/T1110/003) attacks, or attempting to [Steal Application Access Token](https://attack.mitre.org/techniques/T1528)s.(Citation: MSTIC Nobelium Oct 2021) Prior to compromising cloud accounts, adversaries may conduct Reconnaissance to inform decisions about which accounts to compromise to further their operation. In some cases, adversaries may target privileged service provider accounts with the intent of leveraging a [Trusted Relationship](https://attack.mitre.org/techniques/T1199) between service providers and their customers.(Citation: MSTIC Nobelium Oct 2021)

Procedures:

- [C0040] APT41 DUST: [APT41 DUST](https://attack.mitre.org/campaigns/C0040) used compromised Google Workspace accounts for command and control.(Citation: Google Cloud APT41 2024)
- [G0016] APT29: [APT29](https://attack.mitre.org/groups/G0016) has used residential proxies, including Azure Virtual Machines, to obfuscate their access to victim environments.(Citation: Mandiant APT29 Microsoft 365 2022)


### T1587 - Develop Capabilities

Description:

Adversaries may build capabilities that can be used during targeting. Rather than purchasing, freely downloading, or stealing capabilities, adversaries may develop their own capabilities in-house. This is the process of identifying development requirements and building solutions such as malware, exploits, and self-signed certificates. Adversaries may develop capabilities to support their operations throughout numerous phases of the adversary lifecycle.(Citation: Mandiant APT1)(Citation: Kaspersky Sofacy)(Citation: Bitdefender StrongPity June 2020)(Citation: Talos Promethium June 2020)

As with legitimate development efforts, different skill sets may be required for developing capabilities. The skills needed may be located in-house, or may need to be contracted out. Use of a contractor may be considered an extension of that adversary's development capabilities, provided the adversary plays a role in shaping requirements and maintains a degree of exclusivity to the capability.

Procedures:

- [G0094] Kimsuky: [Kimsuky](https://attack.mitre.org/groups/G0094) created and used a mailing toolkit to use in spearphishing attacks.(Citation: VirusBulletin Kimsuky October 2019)
- [G1036] Moonstone Sleet: [Moonstone Sleet](https://attack.mitre.org/groups/G1036) developed malicious npm packages for delivery to or retrieval by victims.(Citation: Microsoft Moonstone Sleet 2024)

#### T1587.001 - Develop Capabilities: Malware

Description:

Adversaries may develop malware and malware components that can be used during targeting. Building malicious software can include the development of payloads, droppers, post-compromise tools, backdoors (including backdoored images), packers, C2 protocols, and the creation of infected removable media. Adversaries may develop malware to support their operations, creating a means for maintaining control of remote machines, evading defenses, and executing post-compromise behaviors.(Citation: Mandiant APT1)(Citation: Kaspersky Sofacy)(Citation: ActiveMalwareEnergy)(Citation: FBI Flash FIN7 USB)

As with legitimate development efforts, different skill sets may be required for developing malware. The skills needed may be located in-house, or may need to be contracted out. Use of a contractor may be considered an extension of that adversary's malware development capabilities, provided the adversary plays a role in shaping requirements and maintains a degree of exclusivity to the malware.

Some aspects of malware development, such as C2 protocol development, may require adversaries to obtain additional infrastructure. For example, malware developed that will communicate with Twitter for C2, may require use of [Web Services](https://attack.mitre.org/techniques/T1583/006).(Citation: FireEye APT29)

Procedures:

- [G0094] Kimsuky: [Kimsuky](https://attack.mitre.org/groups/G0094) has developed its own unique malware such as MailFetch.py for use in operations.(Citation: KISA Operation Muzabi)(Citation: Talos Kimsuky Nov 2021)(Citation: Mandiant APT43 March 2024)
- [G1016] FIN13: [FIN13](https://attack.mitre.org/groups/G1016) has utilized custom malware to maintain persistence in a compromised environment.(Citation: Mandiant FIN13 Aug 2022)(Citation: Sygnia Elephant Beetle Jan 2022)
- [G1036] Moonstone Sleet: [Moonstone Sleet](https://attack.mitre.org/groups/G1036) has developed custom malware, including a malware delivery mechanism masquerading as a legitimate game.(Citation: Microsoft Moonstone Sleet 2024)
- [G0119] Indrik Spider: [Indrik Spider](https://attack.mitre.org/groups/G0119) has developed malware for their operations, including ransomware such as [BitPaymer](https://attack.mitre.org/software/S0570) and [WastedLocker](https://attack.mitre.org/software/S0612).(Citation: Crowdstrike Indrik November 2018)
- [C0014] Operation Wocao: During [Operation Wocao](https://attack.mitre.org/campaigns/C0014), threat actors developed their own custom webshells to upload to compromised servers.(Citation: FoxIT Wocao December 2019)
- [G0032] Lazarus Group: [Lazarus Group](https://attack.mitre.org/groups/G0032) has developed custom malware for use in their operations.(Citation: CISA AppleJeus Feb 2021)(Citation: Google TAG Lazarus Jan 2021)
- [G0049] OilRig: [OilRig](https://attack.mitre.org/groups/G0049) actively developed and used a series of downloaders during 2022.(Citation: ESET OilRig Downloaders DEC 2023)
- [G1014] LuminousMoth: [LuminousMoth](https://attack.mitre.org/groups/G1014) has used unique malware for information theft and exfiltration.(Citation: Kaspersky LuminousMoth July 2021)(Citation: Bitdefender LuminousMoth July 2021)
- [G0034] Sandworm Team: [Sandworm Team](https://attack.mitre.org/groups/G0034) has developed malware for its operations, including malicious mobile applications and destructive malware such as [NotPetya](https://attack.mitre.org/software/S0368) and [Olympic Destroyer](https://attack.mitre.org/software/S0365).(Citation: US District Court Indictment GRU Unit 74455 October 2020)
- [G1045] Salt Typhoon: [Salt Typhoon](https://attack.mitre.org/groups/G1045) has used custom tooling including [JumbledPath](https://attack.mitre.org/software/S1206).(Citation: Cisco Salt Typhoon FEB 2025)
- [G0016] APT29: [APT29](https://attack.mitre.org/groups/G0016) has used unique malware in many of their operations.(Citation: F-Secure The Dukes)(Citation: Mandiant No Easy Breach)(Citation: MSTIC Nobelium Toolset May 2021)(Citation: Mandiant APT29 Eye Spy Email Nov 22)
- [G1040] Play: [Play](https://attack.mitre.org/groups/G1040) developed and employ [Playcrypt](https://attack.mitre.org/software/S1162) ransomware.(Citation: Trend Micro Ransomware Spotlight Play July 2023)(Citation: CISA Play Ransomware Advisory December 2023)
- [G1007] Aoqin Dragon: [Aoqin Dragon](https://attack.mitre.org/groups/G1007) has used custom malware, including [Mongall](https://attack.mitre.org/software/S1026) and [Heyoka Backdoor](https://attack.mitre.org/software/S1027), in their operations.(Citation: SentinelOne Aoqin Dragon June 2022)
- [C0024] SolarWinds Compromise: For the [SolarWinds Compromise](https://attack.mitre.org/campaigns/C0024), [APT29](https://attack.mitre.org/groups/G0016) used numerous pieces of malware that were likely developed for or by the group, including [SUNBURST](https://attack.mitre.org/software/S0559), [SUNSPOT](https://attack.mitre.org/software/S0562), [Raindrop](https://attack.mitre.org/software/S0565), and [TEARDROP](https://attack.mitre.org/software/S0560).(Citation: FireEye SUNBURST Backdoor December 2020)(Citation: CrowdStrike SUNSPOT Implant January 2021)(Citation: Microsoft Deep Dive Solorigate January 2021)
- [G1039] RedCurl: [RedCurl](https://attack.mitre.org/groups/G1039) has created its own tools to use during operations.(Citation: therecord_redcurl)
- [G0003] Cleaver: [Cleaver](https://attack.mitre.org/groups/G0003) has created customized tools and payloads for functions including ARP poisoning, encryption, credential dumping, ASP.NET shells, web backdoors, process enumeration, WMI querying, HTTP and SMB communications, network interface sniffing, and keystroke logging.(Citation: Cylance Cleaver)
- [C0023] Operation Ghost: For [Operation Ghost](https://attack.mitre.org/campaigns/C0023), [APT29](https://attack.mitre.org/groups/G0016) used new strains of malware including [FatDuke](https://attack.mitre.org/software/S0512), [MiniDuke](https://attack.mitre.org/software/S0051), [RegDuke](https://attack.mitre.org/software/S0511), and [PolyglotDuke](https://attack.mitre.org/software/S0518).(Citation: ESET Dukes October 2019)
- [G1009] Moses Staff: [Moses Staff](https://attack.mitre.org/groups/G1009) has built malware, such as [DCSrv](https://attack.mitre.org/software/S1033) and [PyDCrypt](https://attack.mitre.org/software/S1032), for targeting victims' machines.(Citation: Checkpoint MosesStaff Nov 2021)
- [C0030] Triton Safety Instrumented System Attack: In the [Triton Safety Instrumented System Attack](https://attack.mitre.org/campaigns/C0030), [TEMP.Veles](https://attack.mitre.org/groups/G0088) developed, prior to the attack, malware capabilities that would require access to specific and specialized hardware and software.(Citation: FireEye TRITON Dec 2017)
- [C0046] ArcaneDoor: [ArcaneDoor](https://attack.mitre.org/campaigns/C0046) featured the development and deployment of two unique malware types, [Line Dancer](https://attack.mitre.org/software/S1186) and [Line Runner](https://attack.mitre.org/software/S1188).(Citation: CCCS ArcaneDoor 2024)(Citation: Cisco ArcaneDoor 2024)
- [C0010] C0010: For [C0010](https://attack.mitre.org/campaigns/C0010), UNC3890 actors used unique malware, including [SUGARUSH](https://attack.mitre.org/software/S1049) and [SUGARDUMP](https://attack.mitre.org/software/S1042).(Citation: Mandiant UNC3890 Aug 2022)
- [G0010] Turla: [Turla](https://attack.mitre.org/groups/G0010) has developed its own unique malware for use in operations.(Citation: Recorded Future Turla Infra 2020)
- [C0044] Juicy Mix: For [Juicy Mix](https://attack.mitre.org/campaigns/C0044), [OilRig](https://attack.mitre.org/groups/G0049) improved on [Solar](https://attack.mitre.org/software/S1166) by developing the [Mango](https://attack.mitre.org/software/S1169) backdoor.(Citation: ESET OilRig Campaigns Sep 2023)
- [C0004] CostaRicto: For [CostaRicto](https://attack.mitre.org/campaigns/C0004), the threat actors used custom malware, including [PS1](https://attack.mitre.org/software/S0613), [CostaBricks](https://attack.mitre.org/software/S0614), and [SombRAT](https://attack.mitre.org/software/S0615).(Citation: BlackBerry CostaRicto November 2020)
- [C0042] Outer Space: For [Outer Space](https://attack.mitre.org/campaigns/C0042), [OilRig](https://attack.mitre.org/groups/G0049) created new implants including the [Solar](https://attack.mitre.org/software/S1166) backdoor.(Citation: ESET OilRig Campaigns Sep 2023)
- [C0013] Operation Sharpshooter: For [Operation Sharpshooter](https://attack.mitre.org/campaigns/C0013), the threat actors used the [Rising Sun](https://attack.mitre.org/software/S0448) modular backdoor.(Citation: McAfee Sharpshooter December 2018)
- [G0004] Ke3chang: [Ke3chang](https://attack.mitre.org/groups/G0004) has developed custom malware that allowed them to maintain persistence on victim networks.(Citation: Microsoft NICKEL December 2021)
- [C0039] Versa Director Zero Day Exploitation: [Versa Director Zero Day Exploitation](https://attack.mitre.org/campaigns/C0039) involved the development of a new web shell variant, [VersaMem](https://attack.mitre.org/software/S1154).(Citation: Lumen Versa 2024)
- [C0022] Operation Dream Job: For [Operation Dream Job](https://attack.mitre.org/campaigns/C0022), [Lazarus Group](https://attack.mitre.org/groups/G0032) developed custom tools such as Sumarta, DBLL Dropper, [Torisma](https://attack.mitre.org/software/S0678), and [DRATzarus](https://attack.mitre.org/software/S0694) for their operations.(Citation: ClearSky Lazarus Aug 2020)(Citation: ESET Lazarus Jun 2020)(Citation: McAfee Lazarus Jul 2020)(Citation: McAfee Lazarus Nov 2020)
- [G0139] TeamTNT: [TeamTNT](https://attack.mitre.org/groups/G0139) has developed custom malware such as [Hildegard](https://attack.mitre.org/software/S0601).(Citation: Unit 42 Hildegard Malware)
- [G0046] FIN7: [FIN7](https://attack.mitre.org/groups/G0046) has developed malware for use in operations, including the creation of infected removable media.(Citation: FBI Flash FIN7 USB)(Citation: FireEye FIN7 Oct 2019)

#### T1587.002 - Develop Capabilities: Code Signing Certificates

Description:

Adversaries may create self-signed code signing certificates that can be used during targeting. Code signing is the process of digitally signing executables and scripts to confirm the software author and guarantee that the code has not been altered or corrupted. Code signing provides a level of authenticity for a program from the developer and a guarantee that the program has not been tampered with.(Citation: Wikipedia Code Signing) Users and/or security tools may trust a signed piece of code more than an unsigned piece of code even if they don't know who issued the certificate or who the author is.

Prior to [Code Signing](https://attack.mitre.org/techniques/T1553/002), adversaries may develop self-signed code signing certificates for use in operations.

Procedures:

- [G1034] Daggerfly: [Daggerfly](https://attack.mitre.org/groups/G1034) created code signing certificates to sign malicious macOS files.(Citation: ESET EvasivePanda 2024)
- [G0056] PROMETHIUM: [PROMETHIUM](https://attack.mitre.org/groups/G0056) has created self-signed certificates to sign malicious installers.(Citation: Bitdefender StrongPity June 2020)
- [G0040] Patchwork: [Patchwork](https://attack.mitre.org/groups/G0040) has created self-signed certificates from fictitious and spoofed legitimate software companies that were later used to sign malware.(Citation: Unit 42 BackConfig May 2020)
- [C0022] Operation Dream Job: During [Operation Dream Job](https://attack.mitre.org/campaigns/C0022), [Lazarus Group](https://attack.mitre.org/groups/G0032) digitally signed their malware and the dbxcli utility.(Citation: ESET Lazarus Jun 2020)

#### T1587.003 - Develop Capabilities: Digital Certificates

Description:

Adversaries may create self-signed SSL/TLS certificates that can be used during targeting. SSL/TLS certificates are designed to instill trust. They include information about the key, information about its owner's identity, and the digital signature of an entity that has verified the certificate's contents are correct. If the signature is valid, and the person examining the certificate trusts the signer, then they know they can use that key to communicate with its owner. In the case of self-signing, digital certificates will lack the element of trust associated with the signature of a third-party certificate authority (CA).

Adversaries may create self-signed SSL/TLS certificates that can be used to further their operations, such as encrypting C2 traffic (ex: [Asymmetric Cryptography](https://attack.mitre.org/techniques/T1573/002) with [Web Protocols](https://attack.mitre.org/techniques/T1071/001)) or even enabling [Adversary-in-the-Middle](https://attack.mitre.org/techniques/T1557) if added to the root of trust (i.e. [Install Root Certificate](https://attack.mitre.org/techniques/T1553/004)).

After creating a digital certificate, an adversary may then install that certificate (see [Install Digital Certificate](https://attack.mitre.org/techniques/T1608/003)) on infrastructure under their control.

Procedures:

- [G0016] APT29: [APT29](https://attack.mitre.org/groups/G0016) has created self-signed digital certificates to enable mutual TLS authentication for malware.(Citation: PWC WellMess July 2020)(Citation: PWC WellMess C2 August 2020)
- [C0046] ArcaneDoor: [ArcaneDoor](https://attack.mitre.org/campaigns/C0046) included acquiring digital certificates mimicking patterns associated with Cisco ASA appliances for command and control infrastructure.(Citation: Cisco ArcaneDoor 2024)
- [G0056] PROMETHIUM: [PROMETHIUM](https://attack.mitre.org/groups/G0056) has created self-signed digital certificates for use in HTTPS C2 traffic.(Citation: Talos Promethium June 2020)
- [C0050] J-magic Campaign: During the [J-magic Campaign](https://attack.mitre.org/campaigns/C0050), threat actors used self-signed certificates on VPS C2 infrastructure.(Citation: Lumen J-Magic JAN 2025)
- [C0011] C0011: For [C0011](https://attack.mitre.org/campaigns/C0011), [Transparent Tribe](https://attack.mitre.org/groups/G0134) established SSL certificates on the typo-squatted domains the group registered.(Citation: Cisco Talos Transparent Tribe Education Campaign July 2022)

#### T1587.004 - Develop Capabilities: Exploits

Description:

Adversaries may develop exploits that can be used during targeting. An exploit takes advantage of a bug or vulnerability in order to cause unintended or unanticipated behavior to occur on computer hardware or software. Rather than finding/modifying exploits from online or purchasing them from exploit vendors, an adversary may develop their own exploits.(Citation: NYTStuxnet) Adversaries may use information acquired via [Vulnerabilities](https://attack.mitre.org/techniques/T1588/006) to focus exploit development efforts. As part of the exploit development process, adversaries may uncover exploitable vulnerabilities through methods such as fuzzing and patch analysis.(Citation: Irongeek Sims BSides 2017)

As with legitimate development efforts, different skill sets may be required for developing exploits. The skills needed may be located in-house, or may need to be contracted out. Use of a contractor may be considered an extension of that adversary's exploit development capabilities, provided the adversary plays a role in shaping requirements and maintains an initial degree of exclusivity to the exploit.

Adversaries may use exploits during various phases of the adversary lifecycle (i.e. [Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190), [Exploitation for Client Execution](https://attack.mitre.org/techniques/T1203), [Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1068), [Exploitation for Defense Evasion](https://attack.mitre.org/techniques/T1211), [Exploitation for Credential Access](https://attack.mitre.org/techniques/T1212), [Exploitation of Remote Services](https://attack.mitre.org/techniques/T1210), and [Application or System Exploitation](https://attack.mitre.org/techniques/T1499/004)).

Procedures:

- [G1017] Volt Typhoon: [Volt Typhoon](https://attack.mitre.org/groups/G1017) has exploited zero-day vulnerabilities for initial access.(Citation: CISA AA24-038A PRC Critical Infrastructure February 2024)
- [G0065] Leviathan: [Leviathan](https://attack.mitre.org/groups/G0065) has rapidly transformed and adapted public exploit proof-of-concept code for new vulnerabilities and utilized them against target networks.(Citation: CISA Leviathan 2024)


### T1588 - Obtain Capabilities

Description:

Adversaries may buy and/or steal capabilities that can be used during targeting. Rather than developing their own capabilities in-house, adversaries may purchase, freely download, or steal them. Activities may include the acquisition of malware, software (including licenses), exploits, certificates, and information relating to vulnerabilities. Adversaries may obtain capabilities to support their operations throughout numerous phases of the adversary lifecycle.

In addition to downloading free malware, software, and exploits from the internet, adversaries may purchase these capabilities from third-party entities. Third-party entities can include technology companies that specialize in malware and exploits, criminal marketplaces, or from individuals.(Citation: NationsBuying)(Citation: PegasusCitizenLab)

In addition to purchasing capabilities, adversaries may steal capabilities from third-party entities (including other adversaries). This can include stealing software licenses, malware, SSL/TLS and code-signing certificates, or raiding closed databases of vulnerabilities or exploits.(Citation: DiginotarCompromise)

#### T1588.001 - Obtain Capabilities: Malware

Description:

Adversaries may buy, steal, or download malware that can be used during targeting. Malicious software can include payloads, droppers, post-compromise tools, backdoors, packers, and C2 protocols. Adversaries may acquire malware to support their operations, obtaining a means for maintaining control of remote machines, evading defenses, and executing post-compromise behaviors.

In addition to downloading free malware from the internet, adversaries may purchase these capabilities from third-party entities. Third-party entities can include technology companies that specialize in malware development, criminal marketplaces (including Malware-as-a-Service, or MaaS), or from individuals. In addition to purchasing malware, adversaries may steal and repurpose malware from third-party entities (including other adversaries).

Procedures:

- [G1014] LuminousMoth: [LuminousMoth](https://attack.mitre.org/groups/G1014) has obtained and used malware such as [Cobalt Strike](https://attack.mitre.org/software/S0154).(Citation: Kaspersky LuminousMoth July 2021)(Citation: Bitdefender LuminousMoth July 2021)
- [C0002] Night Dragon: During [Night Dragon](https://attack.mitre.org/campaigns/C0002), threat actors used Trojans from underground hacker websites.(Citation: McAfee Night Dragon)
- [C0005] Operation Spalax: For [Operation Spalax](https://attack.mitre.org/campaigns/C0005), the threat actors obtained malware, including [Remcos](https://attack.mitre.org/software/S0332), [njRAT](https://attack.mitre.org/software/S0385), and AsyncRAT.(Citation: ESET Operation Spalax Jan 2021)
- [G1018] TA2541: [TA2541](https://attack.mitre.org/groups/G1018) has used multiple strains of malware available for purchase on criminal forums or in open-source repositories.(Citation: Proofpoint TA2541 February 2022)
- [G1003] Ember Bear: [Ember Bear](https://attack.mitre.org/groups/G1003) has acquired malware and related tools from dark web forums.(Citation: CISA GRU29155 2024)
- [G1004] LAPSUS$: [LAPSUS$](https://attack.mitre.org/groups/G1004) acquired and used the Redline password stealer in their operations.(Citation: MSTIC DEV-0537 Mar 2022)
- [G1013] Metador: [Metador](https://attack.mitre.org/groups/G1013) has used unique malware in their operations, including [metaMain](https://attack.mitre.org/software/S1059) and [Mafalda](https://attack.mitre.org/software/S1060).(Citation: SentinelLabs Metador Sept 2022)
- [C0050] J-magic Campaign: During the [J-magic Campaign](https://attack.mitre.org/campaigns/C0050) campaign, threat actors used open-source malware post-compromise including a custom variant of the cd00r backdoor.(Citation: Lumen J-Magic JAN 2025)
- [G0006] APT1: [APT1](https://attack.mitre.org/groups/G0006) used publicly available malware for privilege escalation.(Citation: Mandiant APT1)
- [G0143] Aquatic Panda: [Aquatic Panda](https://attack.mitre.org/groups/G0143) has acquired and used [njRAT](https://attack.mitre.org/software/S0385) in its operations.(Citation: CrowdStrike AQUATIC PANDA December 2021)
- [G0140] LazyScripter: [LazyScripter](https://attack.mitre.org/groups/G0140) has used a variety of open-source remote access Trojans for its operations.(Citation: MalwareBytes LazyScripter Feb 2021)
- [C0007] FunnyDream: For [FunnyDream](https://attack.mitre.org/campaigns/C0007), the threat actors used a new backdoor named [FunnyDream](https://attack.mitre.org/software/S1044).(Citation: Bitdefender FunnyDream Campaign November 2020)
- [G0138] Andariel: [Andariel](https://attack.mitre.org/groups/G0138) has used a variety of publicly-available remote access Trojans (RATs) for its operations.(Citation: FSI Andariel Campaign Rifle July 2017)
- [G0092] TA505: [TA505](https://attack.mitre.org/groups/G0092) has used malware such as [Azorult](https://attack.mitre.org/software/S0344) and [Cobalt Strike](https://attack.mitre.org/software/S0154) in their operations.(Citation: NCC Group TA505)
- [G0010] Turla: [Turla](https://attack.mitre.org/groups/G0010) has used malware obtained after compromising other threat actors, such as [OilRig](https://attack.mitre.org/groups/G0049).(Citation: NSA NCSC Turla OilRig)(Citation: Recorded Future Turla Infra 2020)
- [C0015] C0015: For [C0015](https://attack.mitre.org/campaigns/C0015), the threat actors used [Cobalt Strike](https://attack.mitre.org/software/S0154) and [Conti](https://attack.mitre.org/software/S0575) ransomware.(Citation: DFIR Conti Bazar Nov 2021)
- [G1006] Earth Lusca: [Earth Lusca](https://attack.mitre.org/groups/G1006) has acquired and used a variety of malware, including [Cobalt Strike](https://attack.mitre.org/software/S0154).(Citation: TrendMicro EarthLusca 2022)
- [G0135] BackdoorDiplomacy: [BackdoorDiplomacy](https://attack.mitre.org/groups/G0135) has obtained and used leaked malware, including DoublePulsar, EternalBlue, EternalRocks, and EternalSynergy, in its operations.(Citation: ESET BackdoorDiplomacy Jun 2021)

#### T1588.002 - Obtain Capabilities: Tool

Description:

Adversaries may buy, steal, or download software tools that can be used during targeting. Tools can be open or closed source, free or commercial. A tool can be used for malicious purposes by an adversary, but (unlike malware) were not intended to be used for those purposes (ex: [PsExec](https://attack.mitre.org/software/S0029)). Tool acquisition can involve the procurement of commercial software licenses, including for red teaming tools such as [Cobalt Strike](https://attack.mitre.org/software/S0154). Commercial software may be obtained through purchase, stealing licenses (or licensed copies of the software), or cracking trial versions.(Citation: Recorded Future Beacon 2019)

Adversaries may obtain tools to support their operations, including to support execution of post-compromise behaviors. In addition to freely downloading or purchasing software, adversaries may steal software and/or software licenses from third-party entities (including other adversaries).

Procedures:

- [G0105] DarkVishnya: [DarkVishnya](https://attack.mitre.org/groups/G0105) has obtained and used tools such as [Impacket](https://attack.mitre.org/software/S0357), [Winexe](https://attack.mitre.org/software/S0191), and [PsExec](https://attack.mitre.org/software/S0029).(Citation: Securelist DarkVishnya Dec 2018)
- [G0010] Turla: [Turla](https://attack.mitre.org/groups/G0010) has obtained and customized publicly-available tools like [Mimikatz](https://attack.mitre.org/software/S0002).(Citation: Symantec Waterbug Jun 2019)
- [C0032] C0032: During the [C0032](https://attack.mitre.org/campaigns/C0032) campaign, [TEMP.Veles](https://attack.mitre.org/groups/G0088) obtained and used tools such as Mimikatz and PsExec.(Citation: FireEye TRITON 2019)
- [G0100] Inception: [Inception](https://attack.mitre.org/groups/G0100) has obtained and used open-source tools such as [LaZagne](https://attack.mitre.org/software/S0349).(Citation: Kaspersky Cloud Atlas August 2019)
- [G0059] Magic Hound: [Magic Hound](https://attack.mitre.org/groups/G0059) has obtained and used tools like [Havij](https://attack.mitre.org/software/S0224), [sqlmap](https://attack.mitre.org/software/S0225), Metasploit, [Mimikatz](https://attack.mitre.org/software/S0002), and Plink.(Citation: Check Point Rocket Kitten)(Citation: FireEye APT35 2018)(Citation: Check Point APT35 CharmPower January 2022)(Citation: DFIR Phosphorus November 2021)(Citation: Microsoft Iranian Threat Actor Trends November 2021)
- [C0005] Operation Spalax: For [Operation Spalax](https://attack.mitre.org/campaigns/C0005), the threat actors obtained packers such as CyaX.(Citation: ESET Operation Spalax Jan 2021)
- [G1002] BITTER: [BITTER](https://attack.mitre.org/groups/G1002) has obtained tools such as PuTTY for use in their operations.(Citation: Forcepoint BITTER Pakistan Oct 2016)
- [G0094] Kimsuky: [Kimsuky](https://attack.mitre.org/groups/G0094) has obtained and used tools such as Nirsoft WebBrowserPassVIew, [Mimikatz](https://attack.mitre.org/software/S0002), and [PsExec](https://attack.mitre.org/software/S0029).(Citation: Netscout Stolen Pencil Dec 2018)(Citation: Talos Kimsuky Nov 2021)(Citation: Mandiant APT43 March 2024)
- [G0098] BlackTech: [BlackTech](https://attack.mitre.org/groups/G0098) has obtained and used tools such as Putty, SNScan, and [PsExec](https://attack.mitre.org/software/S0029) for its operations.(Citation: Symantec Palmerworm Sep 2020)
- [G0069] MuddyWater: MuddyWater has used legitimate tools [ConnectWise](https://attack.mitre.org/software/S0591), [RemoteUtilities](https://attack.mitre.org/software/S0592), and SimpleHelp to gain access to the target environment.(Citation: Anomali Static Kitten February 2021)(Citation: group-ib_muddywater_infra)
- [G1004] LAPSUS$: [LAPSUS$](https://attack.mitre.org/groups/G1004) has obtained tools such as RVTools and AD Explorer for their operations.(Citation: MSTIC DEV-0537 Mar 2022)(Citation: NCC Group LAPSUS Apr 2022)
- [C0030] Triton Safety Instrumented System Attack: In the [Triton Safety Instrumented System Attack](https://attack.mitre.org/campaigns/C0030), [TEMP.Veles](https://attack.mitre.org/groups/G0088) used tools such as Mimikatz and other open-source software.(Citation: FireEye TEMP.Veles 2018)
- [G0077] Leafminer: [Leafminer](https://attack.mitre.org/groups/G0077) has obtained and used tools such as [LaZagne](https://attack.mitre.org/software/S0349), [Mimikatz](https://attack.mitre.org/software/S0002), [PsExec](https://attack.mitre.org/software/S0029), and [MailSniper](https://attack.mitre.org/software/S0413).(Citation: Symantec Leafminer July 2018)
- [G0016] APT29: [APT29](https://attack.mitre.org/groups/G0016) has obtained and used a variety of tools including [Mimikatz](https://attack.mitre.org/software/S0002), [SDelete](https://attack.mitre.org/software/S0195), [Tor](https://attack.mitre.org/software/S0183), [meek](https://attack.mitre.org/software/S0175), and [Cobalt Strike](https://attack.mitre.org/software/S0154).(Citation: Mandiant No Easy Breach)(Citation: F-Secure The Dukes)(Citation: Mandiant APT29 Eye Spy Email Nov 22)
- [G0007] APT28: [APT28](https://attack.mitre.org/groups/G0007) has obtained and used open-source tools like [Koadic](https://attack.mitre.org/software/S0250), [Mimikatz](https://attack.mitre.org/software/S0002), and [Responder](https://attack.mitre.org/software/S0174).(Citation: Palo Alto Sofacy 06-2018)(Citation: Securelist Sofacy Feb 2018)(Citation: FireEye APT28 Hospitality Aug 2017)
- [G0102] Wizard Spider: [Wizard Spider](https://attack.mitre.org/groups/G0102) has utilized tools such as [Empire](https://attack.mitre.org/software/S0363), [Cobalt Strike](https://attack.mitre.org/software/S0154), [Cobalt Strike](https://attack.mitre.org/software/S0154), [Rubeus](https://attack.mitre.org/software/S1071), [AdFind](https://attack.mitre.org/software/S0552), [BloodHound](https://attack.mitre.org/software/S0521), Metasploit, Advanced IP Scanner, Nirsoft PingInfoView, and SoftPerfect Network Scanner for targeting efforts.(Citation: FireEye KEGTAP SINGLEMALT October 2020)(Citation: Mandiant FIN12 Oct 2021)
- [G1046] Storm-1811: [Storm-1811](https://attack.mitre.org/groups/G1046) acquired various legitimate and malicious tools, such as RMM software and commodity malware packages, for operations.(Citation: Microsoft Storm-1811 2024)(Citation: rapid7-email-bombing)
- [G0060] BRONZE BUTLER: [BRONZE BUTLER](https://attack.mitre.org/groups/G0060) has obtained and used open-source tools such as [Mimikatz](https://attack.mitre.org/software/S0002), [gsecdump](https://attack.mitre.org/software/S0008), and [Windows Credential Editor](https://attack.mitre.org/software/S0005).(Citation: Symantec Tick Apr 2016)
- [G0045] menuPass: [menuPass](https://attack.mitre.org/groups/G0045) has used and modified open-source tools like [Impacket](https://attack.mitre.org/software/S0357), [Mimikatz](https://attack.mitre.org/software/S0002), and [pwdump](https://attack.mitre.org/software/S0006).(Citation: PWC Cloud Hopper Technical Annex April 2017)
- [G0096] APT41: [APT41](https://attack.mitre.org/groups/G0096) has obtained and used tools such as [Mimikatz](https://attack.mitre.org/software/S0002), [pwdump](https://attack.mitre.org/software/S0006), [PowerSploit](https://attack.mitre.org/software/S0194), and [Windows Credential Editor](https://attack.mitre.org/software/S0005).(Citation: FireEye APT41 Aug 2019)
- [G0061] FIN8: [FIN8](https://attack.mitre.org/groups/G0061) has used open-source tools such as [Impacket](https://attack.mitre.org/software/S0357) for targeting efforts.(Citation: Bitdefender Sardonic Aug 2021)
- [G0092] TA505: [TA505](https://attack.mitre.org/groups/G0092) has used a variety of tools in their operations, including [AdFind](https://attack.mitre.org/software/S0552), [BloodHound](https://attack.mitre.org/software/S0521), [Mimikatz](https://attack.mitre.org/software/S0002), and [PowerSploit](https://attack.mitre.org/software/S0194).(Citation: NCC Group TA505)
- [G0087] APT39: [APT39](https://attack.mitre.org/groups/G0087) has modified and used customized versions of publicly-available tools like PLINK and [Mimikatz](https://attack.mitre.org/software/S0002).(Citation: BitDefender Chafer May 2020)(Citation: IBM ITG07 June 2019)
- [G0093] GALLIUM: [GALLIUM](https://attack.mitre.org/groups/G0093) has used a variety of widely-available tools, which in some cases they modified to add functionality and/or subvert antimalware solutions.(Citation: Microsoft GALLIUM December 2019)
- [G0003] Cleaver: [Cleaver](https://attack.mitre.org/groups/G0003) has obtained and used open-source tools such as [PsExec](https://attack.mitre.org/software/S0029), [Windows Credential Editor](https://attack.mitre.org/software/S0005), and [Mimikatz](https://attack.mitre.org/software/S0002).(Citation: Cylance Cleaver)
- [G0135] BackdoorDiplomacy: [BackdoorDiplomacy](https://attack.mitre.org/groups/G0135) has obtained a variety of open-source reconnaissance and red team tools for discovery and lateral movement.(Citation: ESET BackdoorDiplomacy Jun 2021)
- [G1021] Cinnamon Tempest: [Cinnamon Tempest](https://attack.mitre.org/groups/G1021) has used open-source tools including customized versions of the Iox proxy tool, NPS tunneling tool, Meterpreter, and a keylogger that uploads data to Alibaba cloud storage.(Citation: Sygnia Emperor Dragonfly October 2022)(Citation: SecureWorks BRONZE STARLIGHT Ransomware Operations June 2022)
- [G0049] OilRig: [OilRig](https://attack.mitre.org/groups/G0049) has made use of the publicly available tools including Plink and [Mimikatz](https://attack.mitre.org/software/S0002).(Citation: Symantec Crambus OCT 2023)(Citation: Trend Micro Earth Simnavaz October 2024)
- [G1018] TA2541: [TA2541](https://attack.mitre.org/groups/G1018) has used commodity remote access tools.(Citation: Cisco Operation Layover September 2021)
- [G0037] FIN6: [FIN6](https://attack.mitre.org/groups/G0037) has obtained and used tools such as [Mimikatz](https://attack.mitre.org/software/S0002), [Cobalt Strike](https://attack.mitre.org/software/S0154), and [AdFind](https://attack.mitre.org/software/S0552).(Citation: Security Intelligence More Eggs Aug 2019)(Citation: FireEye FIN6 Apr 2019)
- [G0034] Sandworm Team: [Sandworm Team](https://attack.mitre.org/groups/G0034) has acquired open-source tools for their operations, including [Invoke-PSImage](https://attack.mitre.org/software/S0231), which was used to establish an encrypted channel from a compromised host to [Sandworm Team](https://attack.mitre.org/groups/G0034)'s C2 server in preparation for the 2018 Winter Olympics attack, as well as [Impacket](https://attack.mitre.org/software/S0357) and RemoteExec, which were used in their 2022 [Prestige](https://attack.mitre.org/software/S1058) operations.(Citation: US District Court Indictment GRU Unit 74455 October 2020)(Citation: Microsoft Prestige ransomware October 2022) Additionally, [Sandworm Team](https://attack.mitre.org/groups/G0034) has used [Empire](https://attack.mitre.org/software/S0363), [Cobalt Strike](https://attack.mitre.org/software/S0154) and [PoshC2](https://attack.mitre.org/software/S0378).(Citation: mandiant_apt44_unearthing_sandworm)
- [G0040] Patchwork: [Patchwork](https://attack.mitre.org/groups/G0040) has obtained and used open-source tools such as [QuasarRAT](https://attack.mitre.org/software/S0262).(Citation: Volexity Patchwork June 2018)
- [G0046] FIN7: [FIN7](https://attack.mitre.org/groups/G0046) has utilized a variety of tools such as [Cobalt Strike](https://attack.mitre.org/software/S0154), [PowerSploit](https://attack.mitre.org/software/S0194), and the remote management tool, Atera for targeting efforts.(Citation: Mandiant FIN7 Apr 2022)
- [C0012] Operation CuckooBees: For [Operation CuckooBees](https://attack.mitre.org/campaigns/C0012), the threat actors obtained publicly-available JSP code that was used to deploy a webshell onto a compromised server.(Citation: Cybereason OperationCuckooBees May 2022)
- [G1014] LuminousMoth: [LuminousMoth](https://attack.mitre.org/groups/G1014) has obtained an ARP spoofing tool from GitHub.(Citation: Bitdefender LuminousMoth July 2021)
- [G1041] Sea Turtle: [Sea Turtle](https://attack.mitre.org/groups/G1041) has used tools such as Adminer during intrusions.(Citation: Hunt Sea Turtle 2024)
- [C0002] Night Dragon: During [Night Dragon](https://attack.mitre.org/campaigns/C0002), threat actors obtained and used tools such as [gsecdump](https://attack.mitre.org/software/S0008).(Citation: McAfee Night Dragon)
- [G0099] APT-C-36: [APT-C-36](https://attack.mitre.org/groups/G0099) obtained and used a modified variant of [Imminent Monitor](https://attack.mitre.org/software/S0434).(Citation: QiAnXin APT-C-36 Feb2019)
- [G0090] WIRTE: [WIRTE](https://attack.mitre.org/groups/G0090) has obtained and used [Empire](https://attack.mitre.org/software/S0363) for post-exploitation activities.(Citation: Lab52 WIRTE Apr 2019)
- [G1016] FIN13: [FIN13](https://attack.mitre.org/groups/G1016) has utilized publicly available tools such as [Mimikatz](https://attack.mitre.org/software/S0002), [Impacket](https://attack.mitre.org/software/S0357), PWdump7, ProcDump, Nmap, and Incognito V2 for targeting efforts.(Citation: Sygnia Elephant Beetle Jan 2022)
- [G0080] Cobalt Group: [Cobalt Group](https://attack.mitre.org/groups/G0080) has obtained and used a variety of tools including [Mimikatz](https://attack.mitre.org/software/S0002), [PsExec](https://attack.mitre.org/software/S0029), [Cobalt Strike](https://attack.mitre.org/software/S0154), and [SDelete](https://attack.mitre.org/software/S0195).(Citation: PTSecurity Cobalt Dec 2016)
- [C0021] C0021: For [C0021](https://attack.mitre.org/campaigns/C0021), the threat actors used [Cobalt Strike](https://attack.mitre.org/software/S0154) configured with a modified variation of the publicly available Pandora Malleable C2 Profile.(Citation: FireEye APT29 Nov 2018)(Citation: Microsoft Unidentified Dec 2018)
- [G0004] Ke3chang: [Ke3chang](https://attack.mitre.org/groups/G0004) has obtained and used tools such as [Mimikatz](https://attack.mitre.org/software/S0002).(Citation: NCC Group APT15 Alive and Strong)
- [G0027] Threat Group-3390: [Threat Group-3390](https://attack.mitre.org/groups/G0027) has obtained and used tools such as [Impacket](https://attack.mitre.org/software/S0357), [pwdump](https://attack.mitre.org/software/S0006), [Mimikatz](https://attack.mitre.org/software/S0002), [gsecdump](https://attack.mitre.org/software/S0008), [NBTscan](https://attack.mitre.org/software/S0590), and [Windows Credential Editor](https://attack.mitre.org/software/S0005).(Citation: Unit42 Emissary Panda May 2019)(Citation: Dell TG-3390)
- [G0032] Lazarus Group: [Lazarus Group](https://attack.mitre.org/groups/G0032) has obtained a variety of tools for their operations, including [Responder](https://attack.mitre.org/software/S0174) and PuTTy PSCP.(Citation: Kaspersky ThreatNeedle Feb 2021)
- [G0053] FIN5: [FIN5](https://attack.mitre.org/groups/G0053) has obtained and used a customized version of [PsExec](https://attack.mitre.org/software/S0029), as well as use other tools such as [pwdump](https://attack.mitre.org/software/S0006), [SDelete](https://attack.mitre.org/software/S0195), and [Windows Credential Editor](https://attack.mitre.org/software/S0005).(Citation: Mandiant FIN5 GrrCON Oct 2016)
- [C0045] ShadowRay: During [ShadowRay](https://attack.mitre.org/campaigns/C0045), threat actors used tools including the XMRig miner and Interactsh.(Citation: Oligo ShadowRay Campaign MAR 2024)
- [G0076] Thrip: [Thrip](https://attack.mitre.org/groups/G0076) has obtained and used tools such as [Mimikatz](https://attack.mitre.org/software/S0002) and [PsExec](https://attack.mitre.org/software/S0029).(Citation: Symantec Thrip June 2018)
- [G1009] Moses Staff: [Moses Staff](https://attack.mitre.org/groups/G1009) has used the commercial tool DiskCryptor.(Citation: Checkpoint MosesStaff Nov 2021)
- [C0014] Operation Wocao: For [Operation Wocao](https://attack.mitre.org/campaigns/C0014), the threat actors obtained a variety of open source tools, including JexBoss, KeeThief, and [BloodHound](https://attack.mitre.org/software/S0521).(Citation: FoxIT Wocao December 2019)
- [C0004] CostaRicto: During [CostaRicto](https://attack.mitre.org/campaigns/C0004), the threat actors obtained open source tools to use in their operations.(Citation: BlackBerry CostaRicto November 2020)
- [G1005] POLONIUM: [POLONIUM](https://attack.mitre.org/groups/G1005) has obtained and used tools such as AirVPN and plink in their operations.(Citation: Microsoft POLONIUM June 2022)
- [G0011] PittyTiger: [PittyTiger](https://attack.mitre.org/groups/G0011) has obtained and used tools such as [Mimikatz](https://attack.mitre.org/software/S0002) and [gsecdump](https://attack.mitre.org/software/S0008).(Citation: Bizeul 2014)
- [G1001] HEXANE: [HEXANE](https://attack.mitre.org/groups/G1001) has acquired, and sometimes customized, open source tools such as [Mimikatz](https://attack.mitre.org/software/S0002), [Empire](https://attack.mitre.org/software/S0363), VNC remote access software, and DIG.net.(Citation: Kaspersky Lyceum October 2021)(Citation: SecureWorks August 2019)(Citation: Zscaler Lyceum DnsSystem June 2022)
- [C0048] Operation MidnightEclipse: During [Operation MidnightEclipse](https://attack.mitre.org/campaigns/C0048), threat actors used the GO Simple Tunnel (GOST) reverse proxy tool.(Citation: Volexity UPSTYLE 2024)
- [G0107] Whitefly: [Whitefly](https://attack.mitre.org/groups/G0107) has obtained and used tools such as [Mimikatz](https://attack.mitre.org/software/S0002).(Citation: Symantec Whitefly March 2019)
- [G0030] Lotus Blossom: [Lotus Blossom](https://attack.mitre.org/groups/G0030) has used publicly-available tools such as a Python-based cookie stealer for Chrome browsers, [Impacket](https://attack.mitre.org/software/S0357), and the Venom proxy tool.(Citation: Cisco LotusBlossom 2025)
- [G0051] FIN10: [FIN10](https://attack.mitre.org/groups/G0051) has relied on publicly-available software to gain footholds and establish persistence in victim environments.(Citation: FireEye FIN10 June 2017)
- [G1032] INC Ransom: [INC Ransom](https://attack.mitre.org/groups/G1032) has acquired and used several tools including MegaSync, AnyDesk,  [esentutl](https://attack.mitre.org/software/S0404) and [PsExec](https://attack.mitre.org/software/S0029).(Citation: Cybereason INC Ransomware November 2023)(Citation: Huntress INC Ransom Group August 2023)(Citation: SOCRadar INC Ransom January 2024)(Citation: Huntress INC Ransomware May 2024)(Citation: SentinelOne INC Ransomware)
- [G0035] Dragonfly: [Dragonfly](https://attack.mitre.org/groups/G0035) has obtained and used tools such as [Mimikatz](https://attack.mitre.org/software/S0002), [CrackMapExec](https://attack.mitre.org/software/S0488), and [PsExec](https://attack.mitre.org/software/S0029).(Citation: Secureworks IRON LIBERTY July 2019)
- [G0136] IndigoZebra: [IndigoZebra](https://attack.mitre.org/groups/G0136) has acquired open source tools such as [NBTscan](https://attack.mitre.org/software/S0590) and Meterpreter for their operations.(Citation: Checkpoint IndigoZebra July 2021)(Citation: Securelist APT Trends Q2 2017)
- [G0143] Aquatic Panda: [Aquatic Panda](https://attack.mitre.org/groups/G0143) has acquired and used [Cobalt Strike](https://attack.mitre.org/software/S0154) in its operations.(Citation: CrowdStrike AQUATIC PANDA December 2021)
- [G1007] Aoqin Dragon: [Aoqin Dragon](https://attack.mitre.org/groups/G1007) obtained the Heyoka open source exfiltration tool and subsequently modified it for their operations.(Citation: SentinelOne Aoqin Dragon June 2022)
- [G0082] APT38: [APT38](https://attack.mitre.org/groups/G0082) has obtained and used open-source tools such as [Mimikatz](https://attack.mitre.org/software/S0002).(Citation: ESET Lazarus KillDisk April 2018)
- [G1006] Earth Lusca: [Earth Lusca](https://attack.mitre.org/groups/G1006) has acquired and used a variety of open source tools.(Citation: TrendMicro EarthLusca 2022)
- [G0064] APT33: [APT33](https://attack.mitre.org/groups/G0064) has obtained and leveraged publicly-available tools for early intrusion activities.(Citation: FireEye APT33 Guardrail)(Citation: Symantec Elfin Mar 2019)
- [C0022] Operation Dream Job: For [Operation Dream Job](https://attack.mitre.org/campaigns/C0022), [Lazarus Group](https://attack.mitre.org/groups/G0032) obtained tools such as Wake-On-Lan, [Responder](https://attack.mitre.org/software/S0174), ChromePass, and dbxcli.(Citation: ClearSky Lazarus Aug 2020)(Citation: ESET Lazarus Jun 2020)
- [G0137] Ferocious Kitten: [Ferocious Kitten](https://attack.mitre.org/groups/G0137) has obtained open source tools for its operations, including JsonCPP and Psiphon.(Citation: Kaspersky Ferocious Kitten Jun 2021)
- [G0050] APT32: [APT32](https://attack.mitre.org/groups/G0050) has obtained and used tools such as [Mimikatz](https://attack.mitre.org/software/S0002) and [Cobalt Strike](https://attack.mitre.org/software/S0154), and a variety of other open-source tools from GitHub.(Citation: FireEye APT32 May 2017)(Citation: Cybereason Oceanlotus May 2017)
- [C0018] C0018: For [C0018](https://attack.mitre.org/campaigns/C0018), the threat actors acquired a variety of open source tools, including [Mimikatz](https://attack.mitre.org/software/S0002), [Sliver](https://attack.mitre.org/software/S0633), SoftPerfect Network Scanner, AnyDesk, and PDQ Deploy.(Citation: Cisco Talos Avos Jun 2022)(Citation: Costa AvosLocker May 2022)
- [G1033] Star Blizzard: [Star Blizzard](https://attack.mitre.org/groups/G1033) has incorporated the open-source EvilGinx framework into their spearphishing activity.(Citation: CISA Star Blizzard Advisory December 2023)(Citation: StarBlizzard)
- [G0078] Gorgon Group: [Gorgon Group](https://attack.mitre.org/groups/G0078) has obtained and used tools such as [QuasarRAT](https://attack.mitre.org/software/S0262) and [Remcos](https://attack.mitre.org/software/S0332).(Citation: Unit 42 Gorgon Group Aug 2018)
- [G0091] Silence: [Silence](https://attack.mitre.org/groups/G0091) has obtained and modified versions of publicly-available tools like [Empire](https://attack.mitre.org/software/S0363) and [PsExec](https://attack.mitre.org/software/S0029).(Citation: Group IB Silence Aug 2019) (Citation: SecureList Silence Nov 2017)
- [G0047] Gamaredon Group: [Gamaredon Group](https://attack.mitre.org/groups/G0047) has used various legitimate tools, such as `mshta.exe` and [Reg](https://attack.mitre.org/software/S0075), and services during operations.(Citation: unit42_gamaredon_dec2022)
- [G0114] Chimera: [Chimera](https://attack.mitre.org/groups/G0114) has obtained and used tools such as [BloodHound](https://attack.mitre.org/software/S0521), [Cobalt Strike](https://attack.mitre.org/software/S0154), [Mimikatz](https://attack.mitre.org/software/S0002), and [PsExec](https://attack.mitre.org/software/S0029).(Citation: Cycraft Chimera April 2020)(Citation: NCC Group Chimera January 2021)
- [G1013] Metador: [Metador](https://attack.mitre.org/groups/G1013) has used Microsoft's Console Debugger in some of their operations.(Citation: SentinelLabs Metador Sept 2022)
- [G0052] CopyKittens: [CopyKittens](https://attack.mitre.org/groups/G0052) has used Metasploit, [Empire](https://attack.mitre.org/software/S0363), and AirVPN for post-exploitation activities.(Citation: ClearSky and Trend Micro Operation Wilted Tulip July 2017)(Citation: Microsoft POLONIUM June 2022)
- [G0122] Silent Librarian: [Silent Librarian](https://attack.mitre.org/groups/G0122) has obtained free and publicly available tools including SingleFile and HTTrack to copy login pages of targeted organizations.(Citation: Proofpoint TA407 September 2019)(Citation: Secureworks COBALT DICKENS September 2019)
- [C0027] C0027: During [C0027](https://attack.mitre.org/campaigns/C0027), [Scattered Spider](https://attack.mitre.org/groups/G1015) obtained and used multiple tools including the LINpeas privilege escalation utility, aws_consoler, rsocx reverse proxy, Level RMM tool, and RustScan port scanner.(Citation: Crowdstrike TELCO BPO Campaign December 2022)
- [G1040] Play: [Play](https://attack.mitre.org/groups/G1040) has used multiple tools for discovery and defense evasion purposes on compromised hosts.(Citation: CISA Play Ransomware Advisory December 2023)
- [C0010] C0010: For [C0010](https://attack.mitre.org/campaigns/C0010), UNC3890 actors obtained multiple publicly-available tools, including METASPLOIT, UNICORN, and NorthStar C2.(Citation: Mandiant UNC3890 Aug 2022)
- [G1045] Salt Typhoon: [Salt Typhoon](https://attack.mitre.org/groups/G1045) has used publicly available tooling to exploit vulnerabilities.(Citation: Cisco Salt Typhoon FEB 2025)
- [G1017] Volt Typhoon: [Volt Typhoon](https://attack.mitre.org/groups/G1017) has used legitimate network and forensic tools and customized versions of open-source tools for C2.(Citation: Microsoft Volt Typhoon May 2023)(Citation: CISA AA24-038A PRC Critical Infrastructure February 2024)
- [C0052] SPACEHOP Activity: [SPACEHOP Activity](https://attack.mitre.org/campaigns/C0052) leverages a C2 framework sourced from a publicly-available Github repository for administration of relay nodes.(Citation: ORB Mandiant)
- [C0001] Frankenstein: For [Frankenstein](https://attack.mitre.org/campaigns/C0001), the threat actors obtained and used [Empire](https://attack.mitre.org/software/S0363).(Citation: Talos Frankenstein June 2019)
- [G0073] APT19: [APT19](https://attack.mitre.org/groups/G0073) has obtained and used publicly-available tools like [Empire](https://attack.mitre.org/software/S0363).(Citation: NCSC Joint Report Public Tools)(Citation: FireEye APT19)
- [G1044] APT42: [APT42](https://attack.mitre.org/groups/G1044) has used built-in features in the Microsoft 365 environment and publicly available tools to avoid detection.(Citation: Mandiant APT42-untangling)
- [C0015] C0015: For [C0015](https://attack.mitre.org/campaigns/C0015), the threat actors obtained a variety of tools, including [AdFind](https://attack.mitre.org/software/S0552),  AnyDesk, and Process Hacker.(Citation: DFIR Conti Bazar Nov 2021)
- [C0017] C0017: For [C0017](https://attack.mitre.org/campaigns/C0017), [APT41](https://attack.mitre.org/groups/G0096) obtained publicly available tools such as YSoSerial.NET, ConfuserEx, and BadPotato.(Citation: Mandiant APT41)
- [C0007] FunnyDream: For [FunnyDream](https://attack.mitre.org/campaigns/C0007), the threat actors used a modified version of the open source [PcShare](https://attack.mitre.org/software/S1050) remote administration tool.(Citation: Bitdefender FunnyDream Campaign November 2020)
- [C0038] HomeLand Justice: During [HomeLand Justice](https://attack.mitre.org/campaigns/C0038), threat actors used tools including Advanced Port Scanner, [Mimikatz](https://attack.mitre.org/software/S0002), and [Impacket](https://attack.mitre.org/software/S0357).(Citation: CISA Iran Albanian Attacks September 2022)(Citation: Microsoft Albanian Government Attacks September 2022)
- [G0108] Blue Mockingbird: [Blue Mockingbird](https://attack.mitre.org/groups/G0108) has obtained and used tools such as [Mimikatz](https://attack.mitre.org/software/S0002).(Citation: RedCanary Mockingbird May 2020)
- [C0029] Cutting Edge: During [Cutting Edge](https://attack.mitre.org/campaigns/C0029), threat actors leveraged tools including Interactsh to identify vulnerable targets, PySoxy to simultaneously dispatch traffic between multiple endpoints, BusyBox to enable post exploitation activities, and Kubo Injector to inject shared objects into process memory.(Citation: Mandiant Cutting Edge January 2024)(Citation: Mandiant Cutting Edge Part 3 February 2024)
- [G0006] APT1: [APT1](https://attack.mitre.org/groups/G0006) has used various open-source tools for privilege escalation purposes.(Citation: Mandiant APT1)
- [G0008] Carbanak: [Carbanak](https://attack.mitre.org/groups/G0008) has obtained and used open-source tools such as [PsExec](https://attack.mitre.org/software/S0029) and [Mimikatz](https://attack.mitre.org/software/S0002).(Citation: Kaspersky Carbanak)
- [G0079] DarkHydrus: [DarkHydrus](https://attack.mitre.org/groups/G0079) has obtained and used tools such as [Mimikatz](https://attack.mitre.org/software/S0002), [Empire](https://attack.mitre.org/software/S0363), and [Cobalt Strike](https://attack.mitre.org/software/S0154).(Citation: Unit 42 DarkHydrus July 2018)

#### T1588.003 - Obtain Capabilities: Code Signing Certificates

Description:

Adversaries may buy and/or steal code signing certificates that can be used during targeting. Code signing is the process of digitally signing executables and scripts to confirm the software author and guarantee that the code has not been altered or corrupted. Code signing provides a level of authenticity for a program from the developer and a guarantee that the program has not been tampered with.(Citation: Wikipedia Code Signing) Users and/or security tools may trust a signed piece of code more than an unsigned piece of code even if they don't know who issued the certificate or who the author is.

Prior to [Code Signing](https://attack.mitre.org/techniques/T1553/002), adversaries may purchase or steal code signing certificates for use in operations. The purchase of code signing certificates may be done using a front organization or using information stolen from a previously compromised entity that allows the adversary to validate to a certificate provider as that entity. Adversaries may also steal code signing materials directly from a compromised third-party.

Procedures:

- [G0102] Wizard Spider: [Wizard Spider](https://attack.mitre.org/groups/G0102) has obtained code signing certificates signed by DigiCert, GlobalSign, and COMOOD for malware payloads.(Citation: DFIR Ryuk 2 Hour Speed Run November 2020)(Citation: Mandiant FIN12 Oct 2021)
- [G0049] OilRig: [OilRig](https://attack.mitre.org/groups/G0049) has obtained stolen code signing certificates to digitally sign malware.(Citation: ClearSky OilRig Jan 2017)
- [G0098] BlackTech: [BlackTech](https://attack.mitre.org/groups/G0098) has used stolen code-signing certificates for its malicious payloads.(Citation: Symantec Palmerworm Sep 2020)
- [G0061] FIN8: [FIN8](https://attack.mitre.org/groups/G0061) has used an expired open-source X.509 certificate for testing in the OpenSSL repository, to connect to actor-controlled C2 servers.(Citation: Bitdefender Sardonic Aug 2021)
- [S0576] MegaCortex: [MegaCortex](https://attack.mitre.org/software/S0576) has used code signing certificates issued to fake companies to bypass security controls.(Citation: IBM MegaCortex)
- [C0038] HomeLand Justice: During [HomeLand Justice](https://attack.mitre.org/campaigns/C0038), threat actors used tools with legitimate code signing certificates. (Citation: CISA Iran Albanian Attacks September 2022)
- [C0040] APT41 DUST: [APT41 DUST](https://attack.mitre.org/campaigns/C0040) used stolen code signing certificates to sign [DUSTTRAP](https://attack.mitre.org/software/S1159) malware and components.(Citation: Google Cloud APT41 2024)
- [C0022] Operation Dream Job: During [Operation Dream Job](https://attack.mitre.org/campaigns/C0022), [Lazarus Group](https://attack.mitre.org/groups/G0032) used code signing certificates issued by Sectigo RSA for some of its malware and tools.(Citation: ESET Lazarus Jun 2020)
- [G0027] Threat Group-3390: [Threat Group-3390](https://attack.mitre.org/groups/G0027) has obtained stolen valid certificates, including from VMProtect and the Chinese instant messaging application Youdu, for their operations.(Citation: Lunghi Iron Tiger Linux)
- [G0094] Kimsuky: [Kimsuky](https://attack.mitre.org/groups/G0094) has stolen a valid certificate that is used to sign the malware and the dropper.(Citation: S2W Troll Stealer 2024)

#### T1588.004 - Obtain Capabilities: Digital Certificates

Description:

Adversaries may buy and/or steal SSL/TLS certificates that can be used during targeting. SSL/TLS certificates are designed to instill trust. They include information about the key, information about its owner's identity, and the digital signature of an entity that has verified the certificate's contents are correct. If the signature is valid, and the person examining the certificate trusts the signer, then they know they can use that key to communicate with its owner.

Adversaries may purchase or steal SSL/TLS certificates to further their operations, such as encrypting C2 traffic (ex: [Asymmetric Cryptography](https://attack.mitre.org/techniques/T1573/002) with [Web Protocols](https://attack.mitre.org/techniques/T1071/001)) or even enabling [Adversary-in-the-Middle](https://attack.mitre.org/techniques/T1557) if the certificate is trusted or otherwise added to the root of trust (i.e. [Install Root Certificate](https://attack.mitre.org/techniques/T1553/004)). The purchase of digital certificates may be done using a front organization or using information stolen from a previously compromised entity that allows the adversary to validate to a certificate provider as that entity. Adversaries may also steal certificate materials directly from a compromised third-party, including from certificate authorities.(Citation: DiginotarCompromise) Adversaries may register or hijack domains that they will later purchase an SSL/TLS certificate for.

Certificate authorities exist that allow adversaries to acquire SSL/TLS certificates, such as domain validation certificates, for free.(Citation: Let's Encrypt FAQ)

After obtaining a digital certificate, an adversary may then install that certificate (see [Install Digital Certificate](https://attack.mitre.org/techniques/T1608/003)) on infrastructure under their control.

Procedures:

- [G0122] Silent Librarian: [Silent Librarian](https://attack.mitre.org/groups/G0122) has obtained free Let's Encrypt SSL certificates for use on their phishing pages.(Citation: Phish Labs Silent Librarian)(Citation: Secureworks COBALT DICKENS September 2019)
- [C0043] Indian Critical Infrastructure Intrusions: [Indian Critical Infrastructure Intrusions](https://attack.mitre.org/campaigns/C0043) included the use of digital certificates spoofing Microsoft.(Citation: RecordedFuture RedEcho 2022)
- [G0032] Lazarus Group: [Lazarus Group](https://attack.mitre.org/groups/G0032) has obtained SSL certificates for their C2 domains.(Citation: CISA AppleJeus Feb 2021)
- [G1041] Sea Turtle: [Sea Turtle](https://attack.mitre.org/groups/G1041) created new certificates using a technique called the actors performed "certificate impersonation," a technique in which [Sea Turtle](https://attack.mitre.org/groups/G1041) obtained a certificate authority-signed X.509 certificate from another provider for the same domain imitating the one already used by the targeted organization.(Citation: Talos Sea Turtle 2019)(Citation: Talos Sea Turtle 2019_2)
- [C0006] Operation Honeybee: For [Operation Honeybee](https://attack.mitre.org/campaigns/C0006), the threat actors stole a digital signature from Adobe Systems to use with their MaoCheng dropper.(Citation: McAfee Honeybee)
- [C0047] RedDelta Modified PlugX Infection Chain Operations: [Mustang Panda](https://attack.mitre.org/groups/G0129) acquired Cloudflare Origin CA TLS certificates during [RedDelta Modified PlugX Infection Chain Operations](https://attack.mitre.org/campaigns/C0047).(Citation: Recorded Future RedDelta 2025)
- [G1014] LuminousMoth: [LuminousMoth](https://attack.mitre.org/groups/G1014) has used a valid digital certificate for some of their malware.(Citation: Kaspersky LuminousMoth July 2021)
- [G0098] BlackTech: [BlackTech](https://attack.mitre.org/groups/G0098) has used valid, stolen digital certificates for some of their malware and tools.(Citation: ESET PLEAD Malware July 2018)

#### T1588.005 - Obtain Capabilities: Exploits

Description:

Adversaries may buy, steal, or download exploits that can be used during targeting. An exploit takes advantage of a bug or vulnerability in order to cause unintended or unanticipated behavior to occur on computer hardware or software. Rather than developing their own exploits, an adversary may find/modify exploits from online or purchase them from exploit vendors.(Citation: Exploit Database)(Citation: TempertonDarkHotel)(Citation: NationsBuying)

In addition to downloading free exploits from the internet, adversaries may purchase exploits from third-party entities. Third-party entities can include technology companies that specialize in exploit development, criminal marketplaces (including exploit kits), or from individuals.(Citation: PegasusCitizenLab)(Citation: Wired SandCat Oct 2019) In addition to purchasing exploits, adversaries may steal and repurpose exploits from third-party entities (including other adversaries).(Citation: TempertonDarkHotel)

An adversary may monitor exploit provider forums to understand the state of existing, as well as newly discovered, exploits. There is usually a delay between when an exploit is discovered and when it is made public. An adversary may target the systems of those known to conduct exploit research and development in order to gain that knowledge for use during a subsequent operation.

Adversaries may use exploits during various phases of the adversary lifecycle (i.e. [Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190), [Exploitation for Client Execution](https://attack.mitre.org/techniques/T1203), [Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1068), [Exploitation for Defense Evasion](https://attack.mitre.org/techniques/T1211), [Exploitation for Credential Access](https://attack.mitre.org/techniques/T1212), [Exploitation of Remote Services](https://attack.mitre.org/techniques/T1210), and [Application or System Exploitation](https://attack.mitre.org/techniques/T1499/004)).

Procedures:

- [G1003] Ember Bear: [Ember Bear](https://attack.mitre.org/groups/G1003) has obtained exploitation scripts against publicly-disclosed vulnerabilities from public repositories.(Citation: CISA GRU29155 2024)
- [G0094] Kimsuky: [Kimsuky](https://attack.mitre.org/groups/G0094) has obtained exploit code for various CVEs.(Citation: KISA Operation Muzabi)

#### T1588.006 - Obtain Capabilities: Vulnerabilities

Description:

Adversaries may acquire information about vulnerabilities that can be used during targeting. A vulnerability is a weakness in computer hardware or software that can, potentially, be exploited by an adversary to cause unintended or unanticipated behavior to occur. Adversaries may find vulnerability information by searching open databases or gaining access to closed vulnerability databases.(Citation: National Vulnerability Database)

An adversary may monitor vulnerability disclosures/databases to understand the state of existing, as well as newly discovered, vulnerabilities. There is usually a delay between when a vulnerability is discovered and when it is made public. An adversary may target the systems of those known to conduct vulnerability research (including commercial vendors). Knowledge of a vulnerability may cause an adversary to search for an existing exploit (i.e. [Exploits](https://attack.mitre.org/techniques/T1588/005)) or to attempt to develop one themselves (i.e. [Exploits](https://attack.mitre.org/techniques/T1587/004)).

Procedures:

- [G0034] Sandworm Team: In 2017, [Sandworm Team](https://attack.mitre.org/groups/G0034) conducted technical research related to vulnerabilities associated with websites used by the Korean Sport and Olympic Committee, a Korean power company, and a Korean airport.(Citation: US District Court Indictment GRU Unit 74455 October 2020)
- [G1017] Volt Typhoon: [Volt Typhoon](https://attack.mitre.org/groups/G1017) has used publicly available exploit code for initial access.(Citation: CISA AA24-038A PRC Critical Infrastructure February 2024)
- [C0049] Leviathan Australian Intrusions: [Leviathan](https://attack.mitre.org/groups/G0065) weaponized publicly-known vulnerabilities for initial access and other purposes during [Leviathan Australian Intrusions](https://attack.mitre.org/campaigns/C0049).(Citation: CISA Leviathan 2024)

#### T1588.007 - Obtain Capabilities: Artificial Intelligence

Description:

Adversaries may obtain access to generative artificial intelligence tools, such as large language models (LLMs), to aid various techniques during targeting. These tools may be used to inform, bolster, and enable a variety of malicious tasks, including conducting [Reconnaissance](https://attack.mitre.org/tactics/TA0043), creating basic scripts, assisting social engineering, and even developing payloads.(Citation: MSFT-AI) 

For example, by utilizing a publicly available LLM an adversary is essentially outsourcing or automating certain tasks to the tool. Using AI, the adversary may draft and generate content in a variety of written languages to be used in [Phishing](https://attack.mitre.org/techniques/T1566)/[Phishing for Information](https://attack.mitre.org/techniques/T1598) campaigns. The same publicly available tool may further enable vulnerability or other offensive research supporting [Develop Capabilities](https://attack.mitre.org/techniques/T1587). AI tools may also automate technical tasks by generating, refining, or otherwise enhancing (e.g., [Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027)) malicious scripts and payloads.(Citation: OpenAI-CTI) Finally, AI-generated text, images, audio, and video may be used for fraud, [Impersonation](https://attack.mitre.org/techniques/T1656), and other malicious activities.(Citation: Google-Vishing24)(Citation: IC3-AI24)(Citation: WSJ-Vishing-AI24)


### T1608 - Stage Capabilities

Description:

Adversaries may upload, install, or otherwise set up capabilities that can be used during targeting. To support their operations, an adversary may need to take capabilities they developed ([Develop Capabilities](https://attack.mitre.org/techniques/T1587)) or obtained ([Obtain Capabilities](https://attack.mitre.org/techniques/T1588)) and stage them on infrastructure under their control. These capabilities may be staged on infrastructure that was previously purchased/rented by the adversary ([Acquire Infrastructure](https://attack.mitre.org/techniques/T1583)) or was otherwise compromised by them ([Compromise Infrastructure](https://attack.mitre.org/techniques/T1584)). Capabilities may also be staged on web services, such as GitHub or Pastebin, or on Platform-as-a-Service (PaaS) offerings that enable users to easily provision applications.(Citation: Volexity Ocean Lotus November 2020)(Citation: Dragos Heroku Watering Hole)(Citation: Malwarebytes Heroku Skimmers)(Citation: Netskope GCP Redirection)(Citation: Netskope Cloud Phishing)

Staging of capabilities can aid the adversary in a number of initial access and post-compromise behaviors, including (but not limited to):

* Staging web resources necessary to conduct [Drive-by Compromise](https://attack.mitre.org/techniques/T1189) when a user browses to a site.(Citation: FireEye CFR Watering Hole 2012)(Citation: Gallagher 2015)(Citation: ATT ScanBox)
* Staging web resources for a link target to be used with spearphishing.(Citation: Malwarebytes Silent Librarian October 2020)(Citation: Proofpoint TA407 September 2019)
* Uploading malware or tools to a location accessible to a victim network to enable [Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105).(Citation: Volexity Ocean Lotus November 2020)
* Installing a previously acquired SSL/TLS certificate to use to encrypt command and control traffic (ex: [Asymmetric Cryptography](https://attack.mitre.org/techniques/T1573/002) with [Web Protocols](https://attack.mitre.org/techniques/T1071/001)).(Citation: DigiCert Install SSL Cert)

Procedures:

- [G0129] Mustang Panda: [Mustang Panda](https://attack.mitre.org/groups/G0129) has used servers under their control to validate tracking pixels sent to phishing victims.(Citation: Proofpoint TA416 Europe March 2022)

#### T1608.001 - Stage Capabilities: Upload Malware

Description:

Adversaries may upload malware to third-party or adversary controlled infrastructure to make it accessible during targeting. Malicious software can include payloads, droppers, post-compromise tools, backdoors, and a variety of other malicious content. Adversaries may upload malware to support their operations, such as making a payload available to a victim network to enable [Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105) by placing it on an Internet accessible web server.

Malware may be placed on infrastructure that was previously purchased/rented by the adversary ([Acquire Infrastructure](https://attack.mitre.org/techniques/T1583)) or was otherwise compromised by them ([Compromise Infrastructure](https://attack.mitre.org/techniques/T1584)). Malware can also be staged on web services, such as GitHub or Pastebin, or hosted on the InterPlanetary File System (IPFS), where decentralized content storage makes the removal of malicious files difficult.(Citation: Volexity Ocean Lotus November 2020)(Citation: Talos IPFS 2022)

Adversaries may upload backdoored files, such as application binaries, virtual machine images, or container images, to third-party software stores or repositories (ex: GitHub, CNET, AWS Community AMIs, Docker Hub). By chance encounter, victims may directly download/install these backdoored files via [User Execution](https://attack.mitre.org/techniques/T1204). [Masquerading](https://attack.mitre.org/techniques/T1036) may increase the chance of users mistakenly executing these files.

Procedures:

- [G0034] Sandworm Team: [Sandworm Team](https://attack.mitre.org/groups/G0034) staged compromised versions of legitimate software installers in forums to enable initial access to executing user.(Citation: mandiant_apt44_unearthing_sandworm)
- [G1018] TA2541: [TA2541](https://attack.mitre.org/groups/G1018) has uploaded malware to various platforms including Google Drive, Pastetext, Sharetext, and GitHub.(Citation: Proofpoint TA2541 February 2022)(Citation: Cisco Operation Layover September 2021)
- [C0022] Operation Dream Job: For [Operation Dream Job](https://attack.mitre.org/campaigns/C0022), [Lazarus Group](https://attack.mitre.org/groups/G0032) used compromised servers to host malware.(Citation: ClearSky Lazarus Aug 2020)(Citation: ESET Lazarus Jun 2020)(Citation: McAfee Lazarus Jul 2020)(Citation: McAfee Lazarus Nov 2020)
- [C0002] Night Dragon: During [Night Dragon](https://attack.mitre.org/campaigns/C0002), threat actors uploaded commonly available hacker tools to compromised web servers.(Citation: McAfee Night Dragon)
- [G1006] Earth Lusca: [Earth Lusca](https://attack.mitre.org/groups/G1006) has staged malware and malicious files on compromised web servers, GitHub, and Google Drive.(Citation: TrendMicro EarthLusca 2022)
- [G0129] Mustang Panda: [Mustang Panda](https://attack.mitre.org/groups/G0129) has hosted malicious payloads on DropBox including [PlugX](https://attack.mitre.org/software/S0013).(Citation: Proofpoint TA416 Europe March 2022)
- [G1014] LuminousMoth: [LuminousMoth](https://attack.mitre.org/groups/G1014) has hosted malicious payloads on Dropbox.(Citation: Kaspersky LuminousMoth July 2021)
- [C0011] C0011: For [C0011](https://attack.mitre.org/campaigns/C0011), [Transparent Tribe](https://attack.mitre.org/groups/G0134) hosted malicious documents on domains registered by the group.(Citation: Cisco Talos Transparent Tribe Education Campaign July 2022)
- [C0047] RedDelta Modified PlugX Infection Chain Operations: [Mustang Panda](https://attack.mitre.org/groups/G0129) staged malware on adversary-controlled domains and cloud storage instances during [RedDelta Modified PlugX Infection Chain Operations](https://attack.mitre.org/campaigns/C0047).(Citation: Recorded Future RedDelta 2025)
- [G0094] Kimsuky: [Kimsuky](https://attack.mitre.org/groups/G0094) has used compromised and acquired infrastructure to host and deliver malware including Blogspot to host beacons, file exfiltrators, and implants.(Citation: Talos Kimsuky Nov 2021)(Citation: Mandiant APT43 March 2024)(Citation: Mandiant APT43 Full PDF Report)
- [G1020] Mustard Tempest: [Mustard Tempest](https://attack.mitre.org/groups/G1020) has hosted payloads on acquired second-stage servers for periods of either days, weeks, or months.(Citation: SentinelOne SocGholish Infrastructure November 2022)
- [G0049] OilRig: [OilRig](https://attack.mitre.org/groups/G0049) has hosted malware on fake websites designed to target specific audiences.(Citation: ClearSky OilRig Jan 2017)
- [G0139] TeamTNT: [TeamTNT](https://attack.mitre.org/groups/G0139) has uploaded backdoored Docker images to Docker Hub.(Citation: Lacework TeamTNT May 2021)
- [C0005] Operation Spalax: For [Operation Spalax](https://attack.mitre.org/campaigns/C0005), the threat actors staged malware and malicious files in legitimate hosting services such as OneDrive or MediaFire.(Citation: ESET Operation Spalax Jan 2021)
- [G0140] LazyScripter: [LazyScripter](https://attack.mitre.org/groups/G0140) has hosted open-source remote access Trojans used in its operations in GitHub.(Citation: MalwareBytes LazyScripter Feb 2021)
- [G0047] Gamaredon Group: [Gamaredon Group](https://attack.mitre.org/groups/G0047) has registered domains to stage payloads.(Citation: Microsoft Actinium February 2022)(Citation: Unit 42 Gamaredon February 2022)
- [G1033] Star Blizzard: [Star Blizzard](https://attack.mitre.org/groups/G1033) has uploaded malicious payloads to cloud storage sites.(Citation: Google TAG COLDRIVER January 2024)
- [G0027] Threat Group-3390: [Threat Group-3390](https://attack.mitre.org/groups/G0027) has hosted malicious payloads on Dropbox.(Citation: Trend Micro DRBControl February 2020)
- [G1008] SideCopy: [SideCopy](https://attack.mitre.org/groups/G1008) has used compromised domains to host its malicious payloads.(Citation: MalwareBytes SideCopy Dec 2021)
- [C0010] C0010: For [C0010](https://attack.mitre.org/campaigns/C0010), UNC3890 actors staged malware on their infrastructure for direct download onto a compromised system.(Citation: Mandiant UNC3890 Aug 2022)
- [C0013] Operation Sharpshooter: For [Operation Sharpshooter](https://attack.mitre.org/campaigns/C0013), the threat actors staged malicious files on Dropbox and other websites.(Citation: McAfee Sharpshooter December 2018)
- [G0092] TA505: [TA505](https://attack.mitre.org/groups/G0092) has staged malware on actor-controlled domains.(Citation: Korean FSI TA505 2020)
- [G1043] BlackByte: [BlackByte](https://attack.mitre.org/groups/G1043) has staged tools such as [Cobalt Strike](https://attack.mitre.org/software/S0154) at public file sharing and hosting sites.(Citation: Microsoft BlackByte 2023)
- [G1002] BITTER: [BITTER](https://attack.mitre.org/groups/G1002) has registered domains to stage payloads.(Citation: Forcepoint BITTER Pakistan Oct 2016)
- [C0021] C0021: For [C0021](https://attack.mitre.org/campaigns/C0021), the threat actors uploaded malware to websites under their control.(Citation: FireEye APT29 Nov 2018)(Citation: Microsoft Unidentified Dec 2018)
- [G0050] APT32: [APT32](https://attack.mitre.org/groups/G0050) has hosted malicious payloads in Dropbox, Amazon S3, and Google Drive for use during targeting.(Citation: Volexity Ocean Lotus November 2020)
- [G1001] HEXANE: [HEXANE](https://attack.mitre.org/groups/G1001) has staged malware on fraudulent websites set up to impersonate targeted organizations.(Citation: ClearSky Siamesekitten August 2021)
- [G1031] Saint Bear: [Saint Bear](https://attack.mitre.org/groups/G1031) has used the Discord content delivery network for hosting malicious content referenced in links and emails.(Citation: Palo Alto Unit 42 OutSteel SaintBot February 2022 )
- [G1036] Moonstone Sleet: [Moonstone Sleet](https://attack.mitre.org/groups/G1036) staged malicious capabilities online for follow-on download by victims or malware.(Citation: Microsoft Moonstone Sleet 2024)
- [G0046] FIN7: [FIN7](https://attack.mitre.org/groups/G0046) has staged legitimate software, that was trojanized to contain an Atera agent installer, on Amazon S3.(Citation: Mandiant FIN7 Apr 2022)
- [G1011] EXOTIC LILY: [EXOTIC LILY](https://attack.mitre.org/groups/G1011)  has uploaded malicious payloads to file-sharing services including TransferNow, TransferXL, WeTransfer, and OneDrive.(Citation: Google EXOTIC LILY March 2022)
- [G1044] APT42: [APT42](https://attack.mitre.org/groups/G1044) has used its infrastructure for C2 and for staging the VINETHORN payload, which masqueraded as a VPN application.(Citation: Mandiant APT42-charms)

#### T1608.002 - Stage Capabilities: Upload Tool

Description:

Adversaries may upload tools to third-party or adversary controlled infrastructure to make it accessible during targeting. Tools can be open or closed source, free or commercial. Tools can be used for malicious purposes by an adversary, but (unlike malware) were not intended to be used for those purposes (ex: [PsExec](https://attack.mitre.org/software/S0029)). Adversaries may upload tools to support their operations, such as making a tool available to a victim network to enable [Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105) by placing it on an Internet accessible web server.

Tools may be placed on infrastructure that was previously purchased/rented by the adversary ([Acquire Infrastructure](https://attack.mitre.org/techniques/T1583)) or was otherwise compromised by them ([Compromise Infrastructure](https://attack.mitre.org/techniques/T1584)).(Citation: Dell TG-3390) Tools can also be staged on web services, such as an adversary controlled GitHub repo, or on Platform-as-a-Service offerings that enable users to easily provision applications.(Citation: Dragos Heroku Watering Hole)(Citation: Malwarebytes Heroku Skimmers)(Citation: Intezer App Service Phishing)

Adversaries can avoid the need to upload a tool by having compromised victim machines download the tool directly from a third-party hosting location (ex: a non-adversary controlled GitHub repo), including the original hosting site of the tool.

Procedures:

- [C0022] Operation Dream Job: For [Operation Dream Job](https://attack.mitre.org/campaigns/C0022), [Lazarus Group](https://attack.mitre.org/groups/G0032) used multiple servers to host malicious tools.(Citation: ESET Lazarus Jun 2020)
- [C0010] C0010: For [C0010](https://attack.mitre.org/campaigns/C0010), UNC3890 actors staged tools on their infrastructure to download directly onto a compromised system.(Citation: Mandiant UNC3890 Aug 2022)
- [G0027] Threat Group-3390: [Threat Group-3390](https://attack.mitre.org/groups/G0027) has staged tools, including [gsecdump](https://attack.mitre.org/software/S0008) and WCE, on previously compromised websites.(Citation: Dell TG-3390)

#### T1608.003 - Stage Capabilities: Install Digital Certificate

Description:

Adversaries may install SSL/TLS certificates that can be used during targeting. SSL/TLS certificates are files that can be installed on servers to enable secure communications between systems. Digital certificates include information about the key, information about its owner's identity, and the digital signature of an entity that has verified the certificate's contents are correct. If the signature is valid, and the person examining the certificate trusts the signer, then they know they can use that key to communicate securely with its owner. Certificates can be uploaded to a server, then the server can be configured to use the certificate to enable encrypted communication with it.(Citation: DigiCert Install SSL Cert)

Adversaries may install SSL/TLS certificates that can be used to further their operations, such as encrypting C2 traffic (ex: [Asymmetric Cryptography](https://attack.mitre.org/techniques/T1573/002) with [Web Protocols](https://attack.mitre.org/techniques/T1071/001)) or lending credibility to a credential harvesting site. Installation of digital certificates may take place for a number of server types, including web servers and email servers. 

Adversaries can obtain digital certificates (see [Digital Certificates](https://attack.mitre.org/techniques/T1588/004)) or create self-signed certificates (see [Digital Certificates](https://attack.mitre.org/techniques/T1587/003)). Digital certificates can then be installed on adversary controlled infrastructure that may have been acquired ([Acquire Infrastructure](https://attack.mitre.org/techniques/T1583)) or previously compromised ([Compromise Infrastructure](https://attack.mitre.org/techniques/T1584)).

Procedures:

- [G1041] Sea Turtle: [Sea Turtle](https://attack.mitre.org/groups/G1041) captured legitimate SSL certificates from victim organizations and installed these on [Sea Turtle](https://attack.mitre.org/groups/G1041)-controlled infrastructure to enable subsequent adversary-in-the-middle operations.(Citation: Talos Sea Turtle 2019)

#### T1608.004 - Stage Capabilities: Drive-by Target

Description:

Adversaries may prepare an operational environment to infect systems that visit a website over the normal course of browsing. Endpoint systems may be compromised through browsing to adversary controlled sites, as in [Drive-by Compromise](https://attack.mitre.org/techniques/T1189). In such cases, the user's web browser is typically targeted for exploitation (often not requiring any extra user interaction once landing on the site), but adversaries may also set up websites for non-exploitation behavior such as [Application Access Token](https://attack.mitre.org/techniques/T1550/001). Prior to [Drive-by Compromise](https://attack.mitre.org/techniques/T1189), adversaries must stage resources needed to deliver that exploit to users who browse to an adversary controlled site. Drive-by content can be staged on adversary controlled infrastructure that has been acquired ([Acquire Infrastructure](https://attack.mitre.org/techniques/T1583)) or previously compromised ([Compromise Infrastructure](https://attack.mitre.org/techniques/T1584)).

Adversaries may upload or inject malicious web content, such as [JavaScript](https://attack.mitre.org/techniques/T1059/007), into websites.(Citation: FireEye CFR Watering Hole 2012)(Citation: Gallagher 2015) This may be done in a number of ways, including:

* Inserting malicious scripts into web pages or other user controllable web content such as forum posts
* Modifying script files served to websites from publicly writeable cloud storage buckets
* Crafting malicious web advertisements and purchasing ad space on a website through legitimate ad providers (i.e., [Malvertising](https://attack.mitre.org/techniques/T1583/008))

In addition to staging content to exploit a user's web browser, adversaries may also stage scripting content to profile the user's browser (as in [Gather Victim Host Information](https://attack.mitre.org/techniques/T1592)) to ensure it is vulnerable prior to attempting exploitation.(Citation: ATT ScanBox)

Websites compromised by an adversary and used to stage a drive-by may be ones visited by a specific community, such as government, a particular industry, or region, where the goal is to compromise a specific user or set of users based on a shared interest. This kind of targeted campaign is referred to a strategic web compromise or watering hole attack.

Adversaries may purchase domains similar to legitimate domains (ex: homoglyphs, typosquatting, different top-level domain, etc.) during acquisition of infrastructure ([Domains](https://attack.mitre.org/techniques/T1583/001)) to help facilitate [Drive-by Compromise](https://attack.mitre.org/techniques/T1189).

Procedures:

- [G0134] Transparent Tribe: [Transparent Tribe](https://attack.mitre.org/groups/G0134) has set up websites with malicious hyperlinks and iframes to infect targeted victims with [Crimson](https://attack.mitre.org/software/S0115), [njRAT](https://attack.mitre.org/software/S0385), and other malicious tools.(Citation: Proofpoint Operation Transparent Tribe March 2016)(Citation: Unit 42 ProjectM March 2016)(Citation: Talos Transparent Tribe May 2021)
- [G1014] LuminousMoth: [LuminousMoth](https://attack.mitre.org/groups/G1014) has redirected compromised machines to an actor-controlled webpage through HTML injection.(Citation: Bitdefender LuminousMoth July 2021)
- [G0035] Dragonfly: [Dragonfly](https://attack.mitre.org/groups/G0035) has compromised websites to redirect traffic and to host exploit kits.(Citation: Gigamon Berserk Bear October 2021)
- [G1012] CURIUM: [CURIUM](https://attack.mitre.org/groups/G1012) used strategic website compromise to fingerprint then target victims.(Citation: PWC Yellow Liderc 2023)
- [G0050] APT32: [APT32](https://attack.mitre.org/groups/G0050) has stood up websites containing numerous articles and content scraped from the Internet to make them appear legitimate, but some of these pages include malicious JavaScript to profile the potential victim or infect them via a fake software update.(Citation: Volexity Ocean Lotus November 2020)
- [G0046] FIN7: [FIN7](https://attack.mitre.org/groups/G0046) has compromised a digital product website and modified multiple download links to point to trojanized versions of offered digital products.(Citation: Mandiant FIN7 Apr 2022)
- [G0027] Threat Group-3390: [Threat Group-3390](https://attack.mitre.org/groups/G0027) has embedded malicious code into websites to screen a potential victim's IP address and then exploit their browser if they are of interest.(Citation: Gallagher 2015)
- [C0010] C0010: For [C0010](https://attack.mitre.org/campaigns/C0010), the threat actors compromised the login page of a legitimate Israeli shipping company and likely established a watering hole that collected visitor information.(Citation: Mandiant UNC3890 Aug 2022)
- [G1020] Mustard Tempest: [Mustard Tempest](https://attack.mitre.org/groups/G1020) has injected malicious JavaScript into compromised websites to infect victims via drive-by download.(Citation: SocGholish-update)(Citation: SentinelOne SocGholish Infrastructure November 2022)(Citation: Red Canary SocGholish March 2024)(Citation: Secureworks Gold Prelude Profile)

#### T1608.005 - Stage Capabilities: Link Target

Description:

Adversaries may put in place resources that are referenced by a link that can be used during targeting. An adversary may rely upon a user clicking a malicious link in order to divulge information (including credentials) or to gain execution, as in [Malicious Link](https://attack.mitre.org/techniques/T1204/001). Links can be used for spearphishing, such as sending an email accompanied by social engineering text to coax the user to actively click or copy and paste a URL into a browser. Prior to a phish for information (as in [Spearphishing Link](https://attack.mitre.org/techniques/T1598/003)) or a phish to gain initial access to a system (as in [Spearphishing Link](https://attack.mitre.org/techniques/T1566/002)), an adversary must set up the resources for a link target for the spearphishing link. 

Typically, the resources for a link target will be an HTML page that may include some client-side script such as [JavaScript](https://attack.mitre.org/techniques/T1059/007) to decide what content to serve to the user. Adversaries may clone legitimate sites to serve as the link target, this can include cloning of login pages of legitimate web services or organization login pages in an effort to harvest credentials during [Spearphishing Link](https://attack.mitre.org/techniques/T1598/003).(Citation: Malwarebytes Silent Librarian October 2020)(Citation: Proofpoint TA407 September 2019) Adversaries may also [Upload Malware](https://attack.mitre.org/techniques/T1608/001) and have the link target point to malware for download/execution by the user.

Adversaries may purchase domains similar to legitimate domains (ex: homoglyphs, typosquatting, different top-level domain, etc.) during acquisition of infrastructure ([Domains](https://attack.mitre.org/techniques/T1583/001)) to help facilitate [Malicious Link](https://attack.mitre.org/techniques/T1204/001).

Links can be written by adversaries to mask the true destination in order to deceive victims by abusing the URL schema and increasing the effectiveness of phishing.(Citation: Kaspersky-masking)(Citation: mandiant-masking)

Adversaries may also use free or paid accounts on link shortening services and Platform-as-a-Service providers to host link targets while taking advantage of the widely trusted domains of those providers to avoid being blocked while redirecting victims to malicious pages.(Citation: Netskope GCP Redirection)(Citation: Netskope Cloud Phishing)(Citation: Intezer App Service Phishing)(Citation: Cofense-redirect) In addition, adversaries may serve a variety of malicious links through uniquely generated URIs/URLs (including one-time, single use links).(Citation: iOS URL Scheme)(Citation: URI)(Citation: URI Use)(Citation: URI Unique) Finally, adversaries may take advantage of the decentralized nature of the InterPlanetary File System (IPFS) to host link targets that are difficult to remove.(Citation: Talos IPFS 2022)

Procedures:

- [G1014] LuminousMoth: [LuminousMoth](https://attack.mitre.org/groups/G1014) has created a link to a Dropbox file that has been used in their spear-phishing operations.(Citation: Kaspersky LuminousMoth July 2021)
- [G0122] Silent Librarian: [Silent Librarian](https://attack.mitre.org/groups/G0122) has cloned victim organization login pages and staged them for later use in credential harvesting campaigns. [Silent Librarian](https://attack.mitre.org/groups/G0122) has also made use of a variety of URL shorteners for these staged websites.(Citation: Secureworks COBALT DICKENS September 2019)(Citation: Malwarebytes Silent Librarian October 2020)(Citation: Proofpoint TA407 September 2019)

#### T1608.006 - Stage Capabilities: SEO Poisoning

Description:

Adversaries may poison mechanisms that influence search engine optimization (SEO) to further lure staged capabilities towards potential victims. Search engines typically display results to users based on purchased ads as well as the site’s ranking/score/reputation calculated by their web crawlers and algorithms.(Citation: Atlas SEO)(Citation: MalwareBytes SEO)

To help facilitate [Drive-by Compromise](https://attack.mitre.org/techniques/T1189), adversaries may stage content that explicitly manipulates SEO rankings in order to promote sites hosting their malicious payloads (such as [Drive-by Target](https://attack.mitre.org/techniques/T1608/004)) within search engines. Poisoning SEO rankings may involve various tricks, such as stuffing keywords (including in the form of hidden text) into compromised sites. These keywords could be related to the interests/browsing habits of the intended victim(s) as well as more broad, seasonably popular topics (e.g. elections, trending news).(Citation: ZScaler SEO)(Citation: Atlas SEO)

In addition to internet search engines (such as Google), adversaries may also aim to manipulate specific in-site searches for developer platforms (such as GitHub) to deceive users towards [Supply Chain Compromise](https://attack.mitre.org/techniques/T1195) lures. In-site searches will rank search results according to their own algorithms and metrics such as popularity(Citation: Chexmarx-seo) which may be targeted and gamed by malicious actors.(Citation: Checkmarx-oss-seo)

Adversaries may also purchase or plant incoming links to staged capabilities in order to boost the site’s calculated relevance and reputation.(Citation: MalwareBytes SEO)(Citation: DFIR Report Gootloader)

SEO poisoning may also be combined with evasive redirects and other cloaking mechanisms (such as measuring mouse movements or serving content based on browser user agents, user language/localization settings, or HTTP headers) in order to feed SEO inputs while avoiding scrutiny from defenders.(Citation: ZScaler SEO)(Citation: Sophos Gootloader)

Procedures:

- [G1020] Mustard Tempest: [Mustard Tempest](https://attack.mitre.org/groups/G1020) has poisoned search engine results to return fake software updates in order to distribute malware.(Citation: Microsoft Ransomware as a Service)(Citation: SocGholish-update)


### T1650 - Acquire Access

Description:

Adversaries may purchase or otherwise acquire an existing access to a target system or network. A variety of online services and initial access broker networks are available to sell access to previously compromised systems.(Citation: Microsoft Ransomware as a Service)(Citation: CrowdStrike Access Brokers)(Citation: Krebs Access Brokers Fortune 500) In some cases, adversary groups may form partnerships to share compromised systems with each other.(Citation: CISA Karakurt 2022)

Footholds to compromised systems may take a variety of forms, such as access to planted backdoors (e.g., [Web Shell](https://attack.mitre.org/techniques/T1505/003)) or established access via [External Remote Services](https://attack.mitre.org/techniques/T1133). In some cases, access brokers will implant compromised systems with a “load” that can be used to install additional malware for paying customers.(Citation: Microsoft Ransomware as a Service)

By leveraging existing access broker networks rather than developing or obtaining their own initial access capabilities, an adversary can potentially reduce the resources required to gain a foothold on a target network and focus their efforts on later stages of compromise. Adversaries may prioritize acquiring access to systems that have been determined to lack security monitoring or that have high privileges, or systems that belong to organizations in a particular sector.(Citation: Microsoft Ransomware as a Service)(Citation: CrowdStrike Access Brokers)

In some cases, purchasing access to an organization in sectors such as IT contracting, software development, or telecommunications may allow an adversary to compromise additional victims via a [Trusted Relationship](https://attack.mitre.org/techniques/T1199), [Multi-Factor Authentication Interception](https://attack.mitre.org/techniques/T1111), or even [Supply Chain Compromise](https://attack.mitre.org/techniques/T1195).

**Note:** while this technique is distinct from other behaviors such as [Purchase Technical Data](https://attack.mitre.org/techniques/T1597/002) and [Credentials](https://attack.mitre.org/techniques/T1589/001), they may often be used in conjunction (especially where the acquired foothold requires [Valid Accounts](https://attack.mitre.org/techniques/T1078)).

