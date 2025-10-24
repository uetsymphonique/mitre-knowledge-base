### T1589.001 - Gather Victim Identity Information: Credentials

Procedures:

- [G0007] APT28: APT28 has harvested user's login credentials.
- [G0059] Magic Hound: Magic Hound gathered credentials from two victims that they then attempted to validate across 75 different websites. Magic Hound has also collected credentials from over 900 Fortinet VPN servers in the US, Europe, and Israel.
- [G0065] Leviathan: Leviathan has collected compromised credentials to use for targeting efforts.
- [C0024] SolarWinds Compromise: For the SolarWinds Compromise, APT29 conducted credential theft operations to obtain credentials to be used for access to victim environments.
- [G1004] LAPSUS$: LAPSUS$ has gathered user identities and credentials to gain initial access to a victim's organization; the group has also called an organization's help desk to reset a target's credentials.
- [G0114] Chimera: Chimera has collected credentials for the target organization from previous breaches for use in brute force attacks.
- [C0027] C0027: During C0027, Scattered Spider sent phishing messages via SMS to steal credentials.

### T1589.002 - Gather Victim Identity Information: Email Addresses

Procedures:

- [G1031] Saint Bear: Saint Bear gathered victim email information in advance of phishing operations for targeted attacks.
- [G1036] Moonstone Sleet: Moonstone Sleet gathered victim email address information for follow-on phishing activity.
- [G0127] TA551: TA551 has used spoofed company emails that were acquired from email clients on previously infected hosts to target other individuals.
- [G1017] Volt Typhoon: Volt Typhoon has targeted the personal emails of key network and IT staff at victim organizations.
- [C0037] Water Curupira Pikabot Distribution: Water Curupira Pikabot Distribution utilizes thread spoofing of existing email threads in order to execute spear phishing operations.
- [G0032] Lazarus Group: Lazarus Group collected email addresses belonging to various departments of a targeted organization which were used in follow-on phishing campaigns.
- [G0125] HAFNIUM: HAFNIUM has collected e-mail addresses for users they intended to target.
- [G0059] Magic Hound: Magic Hound has identified high-value email accounts in academia, journalism, NGO's, foreign policy, and national security for targeting.
- [G0122] Silent Librarian: Silent Librarian has collected e-mail addresses from targeted organizations from open Internet searches.
- [G0094] Kimsuky: Kimsuky has collected valid email addresses including personal accounts that were subsequently used for spearphishing and other forms of social engineering.
- [S0677] AADInternals: AADInternals can check for the existence of user email addresses using public Microsoft APIs.
- [G1001] HEXANE: HEXANE has targeted executives, human resources staff, and IT personnel for spearphishing.
- [G1004] LAPSUS$: LAPSUS$ has gathered employee email addresses, including personal accounts, for social engineering and initial access efforts.
- [G1011] EXOTIC LILY: EXOTIC LILY has gathered targeted individuals' e-mail addresses through open source research and website contact forms.
- [G0050] APT32: APT32 has collected e-mail addresses for activists and bloggers in order to target them with spyware.

### T1589.003 - Gather Victim Identity Information: Employee Names

Procedures:

- [G0094] Kimsuky: Kimsuky has collected victim employee name information.
- [G0034] Sandworm Team: Sandworm Team's research of potential victim organizations included the identification and collection of employee information.
- [G0122] Silent Librarian: Silent Librarian has collected lists of names for individuals from targeted organizations.


### T1590.001 - Gather Victim Network Information: Domain Properties

Procedures:

- [G0034] Sandworm Team: Sandworm Team conducted technical reconnaissance of the Parliament of Georgia's official internet domain prior to its 2019 attack.
- [S0677] AADInternals: AADInternals can gather information about a tenant’s domains using public Microsoft APIs.

### T1590.002 - Gather Victim Network Information: DNS

Procedures:

- Adversaries may gather information about the victim's DNS that can be used during targeting. DNS information may include a variety of details, including registered name servers as well as records that outline addressing for a target’s subdomains, mail servers, and other hosts. DNS MX, TXT, and SPF records may also reveal the use of third party cloud and SaaS providers, such as Office 365, G Suite, Salesforce, or Zendesk. Adversaries may gather this information in various ways, such as querying or otherwise collecting details via DNS/Passive DNS. DNS information may also be exposed to adversaries via online or other accessible data sets (ex: Search Open Technical Databases). Gathering this information may reveal opportunities for other forms of reconnaissance (ex: Search Open Technical Databases, Search Open Websites/Domains, or Active Scanning), establishing operational resources (ex: Acquire Infrastructure or Compromise Infrastructure), and/or initial access (ex: External Remote Services). Adversaries may also use DNS zone transfer (DNS query type AXFR) to collect all records from a misconfigured DNS server.

### T1590.003 - Gather Victim Network Information: Network Trust Dependencies

Procedures:

- Adversaries may gather information about the victim's network trust dependencies that can be used during targeting. Information about network trusts may include a variety of details, including second or third-party organizations/domains (ex: managed service providers, contractors, etc.) that have connected (and potentially elevated) network access. Adversaries may gather this information in various ways, such as direct elicitation via Phishing for Information. Information about network trusts may also be exposed to adversaries via online or other accessible data sets (ex: Search Open Technical Databases). Gathering this information may reveal opportunities for other forms of reconnaissance (ex: Active Scanning or Search Open Websites/Domains), establishing operational resources (ex: Acquire Infrastructure or Compromise Infrastructure), and/or initial access (ex: Trusted Relationship).

### T1590.004 - Gather Victim Network Information: Network Topology

Procedures:

- [G1045] Salt Typhoon: Salt Typhoon has used configuration files from exploited network devices to help discover upstream and downstream network segments.
- [G1016] FIN13: FIN13 has searched for infrastructure that can provide remote access to an environment for targeting efforts.
- [G1017] Volt Typhoon: Volt Typhoon has conducted extensive reconnaissance of victim networks including identifying network topologies.

### T1590.005 - Gather Victim Network Information: IP Addresses

Procedures:

- [G0138] Andariel: Andariel has limited its watering hole attacks to specific IP address ranges.
- [G0059] Magic Hound: Magic Hound has captured the IP addresses of visitors to their phishing sites.
- [G0125] HAFNIUM: HAFNIUM has obtained IP addresses for publicly-accessible Exchange servers.

### T1590.006 - Gather Victim Network Information: Network Security Appliances

Procedures:

- [G1017] Volt Typhoon: Volt Typhoon has identified target network security measures as part of pre-compromise reconnaissance.


### T1591.001 - Gather Victim Org Information: Determine Physical Locations

Procedures:

- [G0059] Magic Hound: Magic Hound has collected location information from visitors to their phishing sites.

### T1591.002 - Gather Victim Org Information: Business Relationships

Procedures:

- [G0035] Dragonfly: Dragonfly has collected open source information to identify relationships between organizations for targeting purposes.
- [G1004] LAPSUS$: LAPSUS$ has gathered detailed knowledge of an organization's supply chain relationships.
- [G0034] Sandworm Team: In preparation for its attack against the 2018 Winter Olympics, Sandworm Team conducted online research of partner organizations listed on an official PyeongChang Olympics partnership site.

### T1591.003 - Gather Victim Org Information: Identify Business Tempo

Procedures:

- Adversaries may gather information about the victim's business tempo that can be used during targeting. Information about an organization’s business tempo may include a variety of details, including operational hours/days of the week. This information may also reveal times/dates of purchases and shipments of the victim’s hardware and software resources. Adversaries may gather this information in various ways, such as direct elicitation via Phishing for Information. Information about business tempo may also be exposed to adversaries via online or other accessible data sets (ex: Social Media or Search Victim-Owned Websites). Gathering this information may reveal opportunities for other forms of reconnaissance (ex: Phishing for Information or Search Open Websites/Domains), establishing operational resources (ex: Establish Accounts or Compromise Accounts), and/or initial access (ex: Supply Chain Compromise or Trusted Relationship)

### T1591.004 - Gather Victim Org Information: Identify Roles

Procedures:

- [G1017] Volt Typhoon: Volt Typhoon has identified key network and IT staff members pre-compromise at targeted organizations.
- [G1004] LAPSUS$: LAPSUS$ has gathered detailed knowledge of team structures within a target organization.
- [C0022] Operation Dream Job: During Operation Dream Job, Lazarus Group targeted specific individuals within an organization with tailored job vacancy announcements.
- [G1001] HEXANE: HEXANE has identified executives, HR, and IT staff at victim organizations for further targeting.


### T1592.001 - Gather Victim Host Information: Hardware

Procedures:

- Adversaries may gather information about the victim's host hardware that can be used during targeting. Information about hardware infrastructure may include a variety of details such as types and versions on specific hosts, as well as the presence of additional components that might be indicative of added defensive protections (ex: card/biometric readers, dedicated encryption hardware, etc.). Adversaries may gather this information in various ways, such as direct collection actions via Active Scanning (ex: hostnames, server banners, user agent strings) or Phishing for Information. Adversaries may also compromise sites then include malicious content designed to collect host information from visitors. Information about the hardware infrastructure may also be exposed to adversaries via online or other accessible data sets (ex: job postings, network maps, assessment reports, resumes, or purchase invoices). Gathering this information may reveal opportunities for other forms of reconnaissance (ex: Search Open Websites/Domains or Search Open Technical Databases), establishing operational resources (ex: Develop Capabilities or Obtain Capabilities), and/or initial access (ex: Compromise Hardware Supply Chain or Hardware Additions).

### T1592.002 - Gather Victim Host Information: Software

Procedures:

- [G0059] Magic Hound: Magic Hound has captured the user-agent strings from visitors to their phishing sites.
- [G0034] Sandworm Team: Sandworm Team has researched software code to enable supply-chain operations, most notably for the 2017 NotPetya attack. Sandworm Team also collected a list of computers using specific software as part of its targeting efforts.
- [G0138] Andariel: Andariel has inserted a malicious script within compromised websites to collect potential victim information such as browser type, system language, Flash Player version, and other data.

### T1592.003 - Gather Victim Host Information: Firmware

Procedures:

- Adversaries may gather information about the victim's host firmware that can be used during targeting. Information about host firmware may include a variety of details such as type and versions on specific hosts, which may be used to infer more information about hosts in the environment (ex: configuration, purpose, age/patch level, etc.). Adversaries may gather this information in various ways, such as direct elicitation via Phishing for Information. Information about host firmware may only be exposed to adversaries via online or other accessible data sets (ex: job postings, network maps, assessment reports, resumes, or purchase invoices). Gathering this information may reveal opportunities for other forms of reconnaissance (ex: Search Open Websites/Domains or Search Open Technical Databases), establishing operational resources (ex: Develop Capabilities or Obtain Capabilities), and/or initial access (ex: Supply Chain Compromise or Exploit Public-Facing Application).

### T1592.004 - Gather Victim Host Information: Client Configurations

Procedures:

- [G0125] HAFNIUM: HAFNIUM has interacted with Office 365 tenants to gather details regarding target's environments.


### T1593.001 - Search Open Websites/Domains: Social Media

Procedures:

- [G0094] Kimsuky: Kimsuky has used Twitter to monitor potential victims and to prepare targeted phishing e-mails.
- [G1011] EXOTIC LILY: EXOTIC LILY has copied data from social media sites to impersonate targeted individuals.
- [C0022] Operation Dream Job: For Operation Dream Job, Lazarus Group used LinkedIn to identify and target employees within a chosen organization.

### T1593.002 - Search Open Websites/Domains: Search Engines

Procedures:

- [C0040] APT41 DUST: APT41 DUST involved use of search engines to research victim servers.
- [G0094] Kimsuky: Kimsuky has searched for vulnerabilities, tools, and geopolitical trends on Google to target victims.

### T1593.003 - Search Open Websites/Domains: Code Repositories

Procedures:

- [G1004] LAPSUS$: LAPSUS$ has searched public code repositories for exposed credentials.
- [G0125] HAFNIUM: HAFNIUM has discovered leaked corporate credentials on public repositories including GitHub.


### T1594 - Search Victim-Owned Websites

Procedures:

- [G0122] Silent Librarian: Silent Librarian has searched victim's websites to identify the interests and academic areas of targeted individuals and to scrape source code, branding, and organizational contact information for phishing pages.
- [C0029] Cutting Edge: During Cutting Edge, threat actors peformed reconnaissance of victims' internal websites via proxied connections.
- [G0094] Kimsuky: Kimsuky has searched for information on the target company's website.
- [G1017] Volt Typhoon: Volt Typhoon has conducted pre-compromise reconnaissance on victim-owned sites.
- [G1011] EXOTIC LILY: EXOTIC LILY has used contact forms on victim websites to generate phishing e-mails.
- [C0049] Leviathan Australian Intrusions: Leviathan enumerated compromised web application resources to identify additional endpoints and resources linkd to the website for follow-on access during Leviathan Australian Intrusions.
- [G0034] Sandworm Team: Sandworm Team has conducted research against potential victim websites as part of its operational planning.
- [G1038] TA578: TA578 has filled out contact forms on victims' websites to direct them to adversary-controlled URLs.
- [C0040] APT41 DUST: APT41 DUST involved access of external victim websites for target development.


### T1595.001 - Active Scanning: Scanning IP Blocks

Procedures:

- [G1003] Ember Bear: Ember Bear has targeted IP ranges for vulnerability scanning related to government and critical infrastructure organizations.
- [G0139] TeamTNT: TeamTNT has scanned specific lists of target IP addresses.

### T1595.002 - Active Scanning: Vulnerability Scanning

Procedures:

- [G0034] Sandworm Team: Sandworm Team has scanned network infrastructure for vulnerabilities as part of its operational planning.
- [C0029] Cutting Edge: During Cutting Edge, threat actors used the publicly available Interactsh tool to identify Ivanti Connect Secure VPNs vulnerable to CVE-2024-21893.
- [G0123] Volatile Cedar: Volatile Cedar has performed vulnerability scans of the target server.
- [G0065] Leviathan: Leviathan has conducted reconnaissance against target networks of interest looking for vulnerable, end-of-life, or no longer maintainted devices against which to rapidly deploy exploits.
- [G1003] Ember Bear: Ember Bear has used publicly available tools such as MASSCAN and Acunetix for vulnerability scanning of public-facing infrastructure.
- [G0096] APT41: APT41 used the Acunetix SQL injection vulnerability scanner in target reconnaissance operations, as well as the JexBoss tool to identify vulnerabilities in Java applications.
- [G0139] TeamTNT: TeamTNT has scanned for vulnerabilities in IoT devices and other related resources such as the Docker API.
- [G0007] APT28: APT28 has performed large-scale scans in an attempt to find vulnerable servers.
- [G0059] Magic Hound: Magic Hound has conducted widespread scanning to identify public-facing systems vulnerable to CVE-2021-44228 in Log4j and ProxyShell vulnerabilities; CVE-2021-26855, CVE-2021-26857, CVE-2021-26858, and CVE-2021-27065 in on-premises MS Exchange Servers; and CVE-2018-13379 in Fortinet FortiOS SSL VPNs.
- [G0016] APT29: APT29 has conducted widespread scanning of target environments to identify vulnerabilities for exploit.
- [G1035] Winter Vivern: Winter Vivern has used remotely-hosted instances of the Acunetix vulnerability scanner.
- [G0143] Aquatic Panda: Aquatic Panda has used publicly accessible DNS logging services to identify servers vulnerable to Log4j (CVE 2021-44228).
- [G0035] Dragonfly: Dragonfly has scanned targeted systems for vulnerable Citrix and Microsoft Exchange services.
- [G1006] Earth Lusca: Earth Lusca has scanned for vulnerabilities in the public-facing servers of their targets.

### T1595.003 - Active Scanning: Wordlist Scanning

Procedures:

- [G0096] APT41: APT41 leverages various tools and frameworks to brute-force directories on web servers.
- [G0123] Volatile Cedar: Volatile Cedar has used DirBuster and GoBuster to brute force web directories and DNS subdomains.


### T1596.001 - Search Open Technical Databases: DNS/Passive DNS

Procedures:

- Adversaries may search DNS data for information about victims that can be used during targeting. DNS information may include a variety of details, including registered name servers as well as records that outline addressing for a target’s subdomains, mail servers, and other hosts. Adversaries may search DNS data to gather actionable information. Threat actors can query nameservers for a target organization directly, or search through centralized repositories of logged DNS query responses (known as passive DNS). Adversaries may also seek and target DNS misconfigurations/leaks that reveal information about internal networks. Information from these sources may reveal opportunities for other forms of reconnaissance (ex: Search Victim-Owned Websites or Search Open Websites/Domains), establishing operational resources (ex: Acquire Infrastructure or Compromise Infrastructure), and/or initial access (ex: External Remote Services or Trusted Relationship).

### T1596.002 - Search Open Technical Databases: WHOIS

Procedures:

- Adversaries may search public WHOIS data for information about victims that can be used during targeting. WHOIS data is stored by regional Internet registries (RIR) responsible for allocating and assigning Internet resources such as domain names. Anyone can query WHOIS servers for information about a registered domain, such as assigned IP blocks, contact information, and DNS nameservers. Adversaries may search WHOIS data to gather actionable information. Threat actors can use online resources or command-line utilities to pillage through WHOIS data for information about potential victims. Information from these sources may reveal opportunities for other forms of reconnaissance (ex: Active Scanning or Phishing for Information), establishing operational resources (ex: Acquire Infrastructure or Compromise Infrastructure), and/or initial access (ex: External Remote Services or Trusted Relationship).

### T1596.003 - Search Open Technical Databases: Digital Certificates

Procedures:

- Adversaries may search public digital certificate data for information about victims that can be used during targeting. Digital certificates are issued by a certificate authority (CA) in order to cryptographically verify the origin of signed content. These certificates, such as those used for encrypted web traffic (HTTPS SSL/TLS communications), contain information about the registered organization such as name and location. Adversaries may search digital certificate data to gather actionable information. Threat actors can use online resources and lookup tools to harvest information about certificates. Digital certificate data may also be available from artifacts signed by the organization (ex: certificates used from encrypted web traffic are served with content). Information from these sources may reveal opportunities for other forms of reconnaissance (ex: Active Scanning or Phishing for Information), establishing operational resources (ex: Develop Capabilities or Obtain Capabilities), and/or initial access (ex: External Remote Services or Trusted Relationship).

### T1596.004 - Search Open Technical Databases: CDNs

Procedures:

- Adversaries may search content delivery network (CDN) data about victims that can be used during targeting. CDNs allow an organization to host content from a distributed, load balanced array of servers. CDNs may also allow organizations to customize content delivery based on the requestor’s geographical region. Adversaries may search CDN data to gather actionable information. Threat actors can use online resources and lookup tools to harvest information about content servers within a CDN. Adversaries may also seek and target CDN misconfigurations that leak sensitive information not intended to be hosted and/or do not have the same protection mechanisms (ex: login portals) as the content hosted on the organization’s website. Information from these sources may reveal opportunities for other forms of reconnaissance (ex: Active Scanning or Search Open Websites/Domains), establishing operational resources (ex: Acquire Infrastructure or Compromise Infrastructure), and/or initial access (ex: Drive-by Compromise).

### T1596.005 - Search Open Technical Databases: Scan Databases

Procedures:

- [G0096] APT41: APT41 uses the Chinese website fofa.su, similar to the Shodan scanning service, for passive scanning of victims.
- [C0040] APT41 DUST: APT41 DUST used internet scan data for target development.
- [G1017] Volt Typhoon: Volt Typhoon has used FOFA, Shodan, and Censys to search for exposed victim infrastructure.


### T1597.001 - Search Closed Sources: Threat Intel Vendors

Procedures:

- Adversaries may search private data from threat intelligence vendors for information that can be used during targeting. Threat intelligence vendors may offer paid feeds or portals that offer more data than what is publicly reported. Although sensitive details (such as customer names and other identifiers) may be redacted, this information may contain trends regarding breaches such as target industries, attribution claims, and successful TTPs/countermeasures. Adversaries may search in private threat intelligence vendor data to gather actionable information. Threat actors may seek information/indicators gathered about their own campaigns, as well as those conducted by other adversaries that may align with their target industries, capabilities/objectives, or other operational concerns. Information reported by vendors may also reveal opportunities other forms of reconnaissance (ex: Search Open Websites/Domains), establishing operational resources (ex: Develop Capabilities or Obtain Capabilities), and/or initial access (ex: Exploit Public-Facing Application or External Remote Services).

### T1597.002 - Search Closed Sources: Purchase Technical Data

Procedures:

- [G1004] LAPSUS$: LAPSUS$ has purchased credentials and session tokens from criminal underground forums.


### T1598.001 - Phishing for Information: Spearphishing Service

Procedures:

- [C0027] C0027: During C0027, Scattered Spider sent Telegram messages impersonating IT personnel to harvest credentials.

### T1598.002 - Phishing for Information: Spearphishing Attachment

Procedures:

- [G0035] Dragonfly: Dragonfly has used spearphishing with Microsoft Office attachments to enable harvesting of user credentials.
- [G1033] Star Blizzard: Star Blizzard has sent emails to establish rapport with targets eventually sending messages with attachments containing links to credential-stealing sites.
- [G0121] Sidewinder: Sidewinder has sent e-mails with malicious attachments that lead victims to credential harvesting websites.
- [G1008] SideCopy: SideCopy has crafted generic lures for spam campaigns to collect emails and credentials for targeting efforts.

### T1598.003 - Phishing for Information: Spearphishing Link

Procedures:

- [G0121] Sidewinder: Sidewinder has sent e-mails with malicious links to credential harvesting websites.
- [G0129] Mustang Panda: Mustang Panda has delivered web bugs to profile their intended targets.
- [G0034] Sandworm Team: Sandworm Team has crafted spearphishing emails with hyperlinks designed to trick unwitting recipients into revealing their account credentials.
- [G0122] Silent Librarian: Silent Librarian has used links in e-mails to direct victims to credential harvesting websites designed to appear like the targeted organization's login page.
- [S0677] AADInternals: AADInternals can send phishing emails containing malicious links designed to collect users’ credentials.
- [G0128] ZIRCONIUM: ZIRCONIUM has used web beacons in e-mails to track hits to attacker-controlled URL's.
- [G0050] APT32: APT32 has used malicious links to direct users to web pages designed to harvest credentials.
- [G0094] Kimsuky: Kimsuky has used links in e-mail to steal account information including web beacons for target profiling.
- [G0059] Magic Hound: Magic Hound has used SMS and email messages with links designed to steal credentials or track victims.
- [S0649] SMOKEDHAM: SMOKEDHAM has been delivered via malicious links in phishing emails.
- [G0007] APT28: APT28 has conducted credential phishing campaigns with links that redirect to credential harvesting sites.
- [G1033] Star Blizzard: Star Blizzard has sent emails to establish rapport with targets eventually sending messages with links to credential-stealing sites.
- [G1036] Moonstone Sleet: Moonstone Sleet used spearphishing messages containing items such as tracking pixels to determine if users interacted with malicious messages.
- [G1012] CURIUM: CURIUM used malicious links to adversary-controlled resources for credential harvesting.
- [G0035] Dragonfly: Dragonfly has used spearphishing with PDF attachments containing malicious links that redirected to credential harvesting websites.

### T1598.004 - Phishing for Information: Spearphishing Voice

Procedures:

- [C0027] C0027: During C0027, Scattered Spider used phone calls to instruct victims to navigate to credential-harvesting websites.
- [G1004] LAPSUS$: LAPSUS$ has called victims' help desk to convince the support personnel to reset a privileged account’s credentials.
- [G1015] Scattered Spider: During C0027, Scattered Spider used phone calls to instruct victims to navigate to credential-harvesting websites. Scattered Spider has also called employees at target organizations and compelled them to navigate to fake login portals using adversary-in-the-middle toolkits.

