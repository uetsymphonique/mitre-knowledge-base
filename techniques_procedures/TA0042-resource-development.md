### T1583.001 - Acquire Infrastructure: Domains

Description:

Adversaries may acquire domains that can be used during targeting. Domain names are the human readable names used to represent one or more IP addresses. They can be purchased or, in some cases, acquired for free. Adversaries may use acquired domains for a variety of purposes, including for Phishing, Drive-by Compromise, and Command and Control. Adversaries may choose domains that are similar to legitimate domains, including through use of homoglyphs or use of a different top-level domain (TLD). Typosquatting may be used to aid in delivery of payloads via Drive-by Compromise. Adversaries may also use internationalized domain names (IDNs) and different character sets (e.g. Cyrillic, Greek, etc.) to execute "IDN homograph attacks," creating visually similar lookalike domains used to deliver malware to victim machines. Different URIs/URLs may also be dynamically generated to uniquely serve malicious content to victims (including one-time, single use domain names). Adversaries may also acquire and repurpose expired domains, which may be potentially already allowlisted/trusted by defenders based on an existing reputation/history. Domain registrars each maintain a publicly viewable database that displays contact information for every registered domain. Private WHOIS services display alternative information, such as their own company data, rather than the owner of the domain. Adversaries may use such private WHOIS services to obscure information about who owns a purchased domain. Adversaries may further interrupt efforts to track their infrastructure by using varied registration information and purchasing domains with different domain registrars. In addition to legitimately purchasing a domain, an adversary may register a new domain in a compromised environment. For example, in AWS environments, adversaries may leverage the Route53 domain service to register a domain and create hosted zones pointing to resources of the threat actor’s choosing.

Procedures:

- [C0021] C0021: For C0021, the threat actors registered domains for use in C2.
- [G0007] APT28: APT28 registered domains imitating NATO, OSCE security websites, Caucasus information resources, and other organizations.
- [G0092] TA505: TA505 has registered domains to impersonate services such as Dropbox to distribute malware.

### T1583.002 - Acquire Infrastructure: DNS Server

Description:

Adversaries may set up their own Domain Name System (DNS) servers that can be used during targeting. During post-compromise activity, adversaries may utilize DNS traffic for various tasks, including for Command and Control (ex: Application Layer Protocol). Instead of hijacking existing DNS servers, adversaries may opt to configure and run their own DNS servers in support of operations. By running their own DNS servers, adversaries can have more control over how they administer server-side DNS C2 traffic (DNS). With control over a DNS server, adversaries can configure DNS applications to provide conditional responses to malware and, generally, have more flexibility in the structure of the DNS-based C2 channel.

Procedures:

- [G1041] Sea Turtle: Sea Turtle built adversary-in-the-middle DNS servers to impersonate legitimate services that were later used to capture credentials.
- [G0001] Axiom: Axiom has acquired dynamic DNS services for use in the targeting of intended victims.
- [G1001] HEXANE: HEXANE has set up custom DNS servers to send commands to compromised hosts via TXT records.

### T1583.003 - Acquire Infrastructure: Virtual Private Server

Description:

Adversaries may rent Virtual Private Servers (VPSs) that can be used during targeting. There exist a variety of cloud service providers that will sell virtual machines/containers as a service. By utilizing a VPS, adversaries can make it difficult to physically tie back operations to them. The use of cloud infrastructure can also make it easier for adversaries to rapidly provision, modify, and shut down their infrastructure. Acquiring a VPS for use in later stages of the adversary lifecycle, such as Command and Control, can allow adversaries to benefit from the ubiquity and trust associated with higher reputation cloud service providers. Adversaries may also acquire infrastructure from VPS service providers that are known for renting VPSs with minimal registration information, allowing for more anonymous acquisitions of infrastructure.

Procedures:

- [G0047] Gamaredon Group: Gamaredon Group has used VPS hosting providers for infrastructure outside of Russia.
- [G0007] APT28: APT28 hosted phishing domains on free services for brief periods of time during campaigns.
- [C0053] FLORAHOX Activity: FLORAHOX Activity has used acquired Virtual Private Servers as control systems for the ORB network.

### T1583.004 - Acquire Infrastructure: Server

Description:

Adversaries may buy, lease, rent, or obtain physical servers that can be used during targeting. Use of servers allows an adversary to stage, launch, and execute an operation. During post-compromise activity, adversaries may utilize servers for various tasks, such as watering hole operations in Drive-by Compromise, enabling Phishing operations, or facilitating Command and Control. Instead of compromising a third-party Server or renting a Virtual Private Server, adversaries may opt to configure and run their own servers in support of operations. Free trial periods of cloud servers may also be abused. Adversaries may only need a lightweight setup if most of their activities will take place using online infrastructure. Or, they may need to build extensive infrastructure if they want to test, communicate, and control other aspects of their activities on their own systems.

Procedures:

- [C0022] Operation Dream Job: During Operation Dream Job, Lazarus Group acquired servers to host their malicious tools.
- [G0093] GALLIUM: GALLIUM has used Taiwan-based servers that appear to be exclusive to GALLIUM.
- [G0094] Kimsuky: Kimsuky has purchased hosting servers with virtual currency and prepaid cards.

### T1583.005 - Acquire Infrastructure: Botnet

Description:

Adversaries may buy, lease, or rent a network of compromised systems that can be used during targeting. A botnet is a network of compromised systems that can be instructed to perform coordinated tasks. Adversaries may purchase a subscription to use an existing botnet from a booter/stresser service. Internet-facing edge devices and related network appliances that are end-of-life (EOL) and unsupported by their manufacturers are commonly acquired for botnet activities. Adversaries may lease operational relay box (ORB) networks – consisting of virtual private servers (VPS), small office/home office (SOHO) routers, or Internet of Things (IoT) devices – to serve as a botnet. With a botnet at their disposal, adversaries may perform follow-on activity such as large-scale Phishing or Distributed Denial of Service (DDoS). Acquired botnets may also be used to support Command and Control activity, such as Hide Infrastructure through an established Proxy network.

Procedures:

- [G0125] HAFNIUM: HAFNIUM has incorporated leased devices into covert networks to obfuscate communications.
- [G1023] APT5: APT5 has acquired a network of compromised systems – specifically an ORB (operational relay box) network – for follow on activities.
- [G0004] Ke3chang: Ke3chang has utilized an ORB (operational relay box) network for reconnaissance and vulnerability exploitation.

### T1583.006 - Acquire Infrastructure: Web Services

Description:

Adversaries may register for web services that can be used during targeting. A variety of popular websites exist for adversaries to register for a web-based service that can be abused during later stages of the adversary lifecycle, such as during Command and Control (Web Service), Exfiltration Over Web Service, or Phishing. Using common services, such as those offered by Google, GitHub, or Twitter, makes it easier for adversaries to hide in expected noise. By utilizing a web service, adversaries can make it difficult to physically tie back operations to them.

Procedures:

- [G1006] Earth Lusca: Earth Lusca has established GitHub accounts to host their malware.
- [G0125] HAFNIUM: HAFNIUM has acquired web services for use in C2 and exfiltration.
- [G0010] Turla: Turla has created web accounts including Dropbox and GitHub for C2 and document exfiltration.

### T1583.007 - Acquire Infrastructure: Serverless

Description:

Adversaries may purchase and configure serverless cloud infrastructure, such as Cloudflare Workers, AWS Lambda functions, or Google Apps Scripts, that can be used during targeting. By utilizing serverless infrastructure, adversaries can make it more difficult to attribute infrastructure used during operations back to them. Once acquired, the serverless runtime environment can be leveraged to either respond directly to infected machines or to Proxy traffic to an adversary-owned command and control server. As traffic generated by these functions will appear to come from subdomains of common cloud providers, it may be difficult to distinguish from ordinary traffic to these providers - making it easier to Hide Infrastructure.

Procedures:

- [C0040] APT41 DUST: APT41 DUST used infrastructure hosted behind Cloudflare or utilized Cloudflare Workers for command and control.

### T1583.008 - Acquire Infrastructure: Malvertising

Description:

Adversaries may purchase online advertisements that can be abused to distribute malware to victims. Ads can be purchased to plant as well as favorably position artifacts in specific locations online, such as prominently placed within search engine results. These ads may make it more difficult for users to distinguish between actual search results and advertisements. Purchased ads may also target specific audiences using the advertising network’s capabilities, potentially further taking advantage of the trust inherently given to search engines and popular websites. Adversaries may purchase ads and other resources to help distribute artifacts containing malicious code to victims. Purchased ads may attempt to impersonate or spoof well-known brands. For example, these spoofed ads may trick victims into clicking the ad which could then send them to a malicious domain that may be a clone of official websites containing trojanized versions of the advertised software. Adversary’s efforts to create malicious domains and purchase advertisements may also be automated at scale to better resist cleanup efforts. Malvertising may be used to support Drive-by Target and Drive-by Compromise, potentially requiring limited interaction from the user if the ad contains code/exploits that infect the target system's web browser. Adversaries may also employ several techniques to evade detection by the advertising network. For example, adversaries may dynamically route ad clicks to send automated crawler/policy enforcer traffic to benign sites while validating potential targets then sending victims referred from real ad clicks to malicious pages. This infection vector may therefore remain hidden from the ad network as well as any visitor not reaching the malicious sites with a valid identifier from clicking on the advertisement. Other tricks, such as intentional typos to avoid brand reputation monitoring, may also be used to evade automated detection.

Procedures:

- [G1020] Mustard Tempest: Mustard Tempest has posted false advertisements including for software packages and browser updates in order to distribute malware.
- [S1130] Raspberry Robin: Raspberry Robin variants have been delivered via malicious advertising items that, when interacted with, download a malicious archive file containing the initial payload, hosted on services such as Discord.


### T1584.001 - Compromise Infrastructure: Domains

Description:

Adversaries may hijack domains and/or subdomains that can be used during targeting. Domain registration hijacking is the act of changing the registration of a domain name without the permission of the original registrant. Adversaries may gain access to an email account for the person listed as the owner of the domain. The adversary can then claim that they forgot their password in order to make changes to the domain registration. Other possibilities include social engineering a domain registration help desk to gain access to an account, taking advantage of renewal process gaps, or compromising a cloud service that enables managing domains (e.g., AWS Route53). Subdomain hijacking can occur when organizations have DNS entries that point to non-existent or deprovisioned resources. In such cases, an adversary may take control of a subdomain to conduct operations with the benefit of the trust associated with that domain. Adversaries who compromise a domain may also engage in domain shadowing by creating malicious subdomains under their control while keeping any existing DNS records. As service will not be disrupted, the malicious subdomains may go unnoticed for long periods of time.

Procedures:

- [G0059] Magic Hound: Magic Hound has used compromised domains to host links targeted to specific phishing victims.
- [G1008] SideCopy: SideCopy has compromised domains for some of their infrastructure, including for C2 and staging malware.
- [C0024] SolarWinds Compromise: For the SolarWinds Compromise, APT29 compromised domains to use for C2.

### T1584.002 - Compromise Infrastructure: DNS Server

Description:

Adversaries may compromise third-party DNS servers that can be used during targeting. During post-compromise activity, adversaries may utilize DNS traffic for various tasks, including for Command and Control (ex: Application Layer Protocol). Instead of setting up their own DNS servers, adversaries may compromise third-party DNS servers in support of operations. By compromising DNS servers, adversaries can alter DNS records. Such control can allow for redirection of an organization's traffic, facilitating Collection and Credential Access efforts for the adversary. Additionally, adversaries may leverage such control in conjunction with Digital Certificates to redirect traffic to adversary-controlled infrastructure, mimicking normal trusted network communications. Adversaries may also be able to silently create subdomains pointed at malicious servers without tipping off the actual owner of the DNS server.

Procedures:

- [G1041] Sea Turtle: Sea Turtle modified Name Server (NS) items to refer to Sea Turtle-controlled DNS servers to provide responses for all DNS lookups.
- [G1004] LAPSUS$: LAPSUS$ has reconfigured a victim's DNS records to actor-controlled domains and websites.

### T1584.003 - Compromise Infrastructure: Virtual Private Server

Description:

Adversaries may compromise third-party Virtual Private Servers (VPSs) that can be used during targeting. There exist a variety of cloud service providers that will sell virtual machines/containers as a service. Adversaries may compromise VPSs purchased by third-party entities. By compromising a VPS to use as infrastructure, adversaries can make it difficult to physically tie back operations to themselves. Compromising a VPS for use in later stages of the adversary lifecycle, such as Command and Control, can allow adversaries to benefit from the ubiquity and trust associated with higher reputation cloud service providers as well as that added by the compromised third-party.

Procedures:

- [C0048] Operation MidnightEclipse: During Operation MidnightEclipse, threat actors abused Virtual Private Servers to store malicious files.
- [G1017] Volt Typhoon: Volt Typhoon has compromised Virtual Private Servers (VPS) to proxy C2 traffic.
- [G0010] Turla: Turla has used the VPS infrastructure of compromised Iranian threat actors.

### T1584.004 - Compromise Infrastructure: Server

Description:

Adversaries may compromise third-party servers that can be used during targeting. Use of servers allows an adversary to stage, launch, and execute an operation. During post-compromise activity, adversaries may utilize servers for various tasks, including for Command and Control. Instead of purchasing a Server or Virtual Private Server, adversaries may compromise third-party servers in support of operations. Adversaries may also compromise web servers to support watering hole operations, as in Drive-by Compromise, or email servers to support Phishing operations.

Procedures:

- [G0032] Lazarus Group: Lazarus Group has compromised servers to stage malicious tools.
- [G1017] Volt Typhoon: Volt Typhoon has used compromised Paessler Router Traffic Grapher (PRTG) servers from other organizations for C2.
- [G0035] Dragonfly: Dragonfly has compromised legitimate websites to host C2 and malware modules.

### T1584.005 - Compromise Infrastructure: Botnet

Description:

Adversaries may compromise numerous third-party systems to form a botnet that can be used during targeting. A botnet is a network of compromised systems that can be instructed to perform coordinated tasks. Instead of purchasing/renting a botnet from a booter/stresser service, adversaries may build their own botnet by compromising numerous third-party systems. Adversaries may also conduct a takeover of an existing botnet, such as redirecting bots to adversary-controlled C2 servers. With a botnet at their disposal, adversaries may perform follow-on activity such as large-scale Phishing or Distributed Denial of Service (DDoS).

Procedures:

- [G0125] HAFNIUM: HAFNIUM has used compromised devices in covert networks to obfuscate communications.
- [G0001] Axiom: Axiom has used large groups of compromised machines for use as proxy nodes.
- [G0034] Sandworm Team: Sandworm Team has used a large-scale botnet to target Small Office/Home Office (SOHO) network devices.

### T1584.006 - Compromise Infrastructure: Web Services

Description:

Adversaries may compromise access to third-party web services that can be used during targeting. A variety of popular websites exist for legitimate users to register for web-based services, such as GitHub, Twitter, Dropbox, Google, SendGrid, etc. Adversaries may try to take ownership of a legitimate user's access to a web service and use that web service as infrastructure in support of cyber operations. Such web services can be abused during later stages of the adversary lifecycle, such as during Command and Control (Web Service), Exfiltration Over Web Service, or Phishing. Using common services, such as those offered by Google or Twitter, makes it easier for adversaries to hide in expected noise. By utilizing a web service, particularly when access is stolen from legitimate users, adversaries can make it difficult to physically tie back operations to them. Additionally, leveraging compromised web-based email services may allow adversaries to leverage the trust associated with legitimate domains.

Procedures:

- [G0010] Turla: Turla has frequently used compromised WordPress sites for C2 infrastructure.
- [G1006] Earth Lusca: Earth Lusca has compromised Google Drive repositories.
- [S1138] Gootloader: Gootloader can insert malicious scripts to compromise vulnerable content management systems (CMS).

### T1584.007 - Compromise Infrastructure: Serverless

Description:

Adversaries may compromise serverless cloud infrastructure, such as Cloudflare Workers, AWS Lambda functions, or Google Apps Scripts, that can be used during targeting. By utilizing serverless infrastructure, adversaries can make it more difficult to attribute infrastructure used during operations back to them. Once compromised, the serverless runtime environment can be leveraged to either respond directly to infected machines or to Proxy traffic to an adversary-owned command and control server. As traffic generated by these functions will appear to come from subdomains of common cloud providers, it may be difficult to distinguish from ordinary traffic to these providers - making it easier to Hide Infrastructure.

### T1584.008 - Compromise Infrastructure: Network Devices

Description:

Adversaries may compromise third-party network devices that can be used during targeting. Network devices, such as small office/home office (SOHO) routers, may be compromised where the adversary's ultimate goal is not Initial Access to that environment -- instead leveraging these devices to support additional targeting. Once an adversary has control, compromised network devices can be used to launch additional operations, such as hosting payloads for Phishing campaigns (i.e., Link Target) or enabling the required access to execute Content Injection operations. Adversaries may also be able to harvest reusable credentials (i.e., Valid Accounts) from compromised network devices. Adversaries often target Internet-facing edge devices and related network appliances that specifically do not support robust host-based defenses. Compromised network devices may be used to support subsequent Command and Control activity, such as Hide Infrastructure through an established Proxy and/or Botnet network.

Procedures:

- [C0053] FLORAHOX Activity: FLORAHOX Activity has compromised network routers and IoT devices for the ORB network.
- [G1017] Volt Typhoon: Volt Typhoon has compromised small office and home office (SOHO) network edge devices, many of which were located in the same geographic area as the victim, to proxy network traffic.
- [G0007] APT28: APT28 compromised Ubiquiti network devices to act as collection devices for credentials compromised via phishing webpages.


### T1585.001 - Establish Accounts: Social Media Accounts

Description:

Adversaries may create and cultivate social media accounts that can be used during targeting. Adversaries can create social media accounts that can be used to build a persona to further operations. Persona development consists of the development of public information, presence, history and appropriate affiliations. For operations incorporating social engineering, the utilization of a persona on social media may be important. These personas may be fictitious or impersonate real people. The persona may exist on a single social media site or across multiple sites (ex: Facebook, LinkedIn, Twitter, etc.). Establishing a persona on social media may require development of additional documentation to make them seem real. This could include filling out profile information, developing social networks, or incorporating photos. Once a persona has been developed an adversary can use it to create connections to targets of interest. These connections may be direct or may include trying to connect through others. These accounts may be leveraged during other phases of the adversary lifecycle, such as during Initial Access (ex: Spearphishing via Service).

Procedures:

- [G0034] Sandworm Team: Sandworm Team has established social media accounts to disseminate victim internal-only documents and other sensitive data.
- [C0022] Operation Dream Job: For Operation Dream Job, Lazarus Group created fake LinkedIn accounts for their targeting efforts.
- [G1011] EXOTIC LILY: EXOTIC LILY has established social media profiles to mimic employees of targeted companies.

### T1585.002 - Establish Accounts: Email Accounts

Description:

Adversaries may create email accounts that can be used during targeting. Adversaries can use accounts created with email providers to further their operations, such as leveraging them to conduct Phishing for Information or Phishing. Establishing email accounts may also allow adversaries to abuse free services – such as trial periods – to Acquire Infrastructure for follow-on purposes. Adversaries may also take steps to cultivate a persona around the email account, such as through use of Social Media Accounts, to increase the chance of success of follow-on behaviors. Created email accounts can also be used in the acquisition of infrastructure (ex: Domains). To decrease the chance of physically tying back operations to themselves, adversaries may make use of disposable email services.

Procedures:

- [C0006] Operation Honeybee: During Operation Honeybee, attackers created email addresses to register for a free account for a control server used for the implants.
- [G0094] Kimsuky: Kimsuky has created email accounts for phishing operations.
- [G1036] Moonstone Sleet: Moonstone Sleet has created email accounts to interact with victims, including for phishing purposes.

### T1585.003 - Establish Accounts: Cloud Accounts

Description:

Adversaries may create accounts with cloud providers that can be used during targeting. Adversaries can use cloud accounts to further their operations, including leveraging cloud storage services such as Dropbox, MEGA, Microsoft OneDrive, or AWS S3 buckets for Exfiltration to Cloud Storage or to Upload Tools. Cloud accounts can also be used in the acquisition of infrastructure, such as Virtual Private Servers or Serverless infrastructure. Establishing cloud accounts may allow adversaries to develop sophisticated capabilities without managing their own servers. Creating Cloud Accounts may also require adversaries to establish Email Accounts to register with the cloud provider.

Procedures:

- [G1046] Storm-1811: Storm-1811 has created malicious accounts to enable activity via Microsoft Teams, typically spoofing various IT support and helpdesk themes.
- [C0042] Outer Space: During Outer Space, OilRig created M365 email accounts to be used as part of C2.


### T1586.001 - Compromise Accounts: Social Media Accounts

Description:

Adversaries may compromise social media accounts that can be used during targeting. For operations incorporating social engineering, the utilization of an online persona may be important. Rather than creating and cultivating social media profiles (i.e. Social Media Accounts), adversaries may compromise existing social media accounts. Utilizing an existing persona may engender a level of trust in a potential victim if they have a relationship, or knowledge of, the compromised persona. A variety of methods exist for compromising social media accounts, such as gathering credentials via Phishing for Information, purchasing credentials from third-party sites, or by brute forcing credentials (ex: password reuse from breach credential dumps). Prior to compromising social media accounts, adversaries may conduct Reconnaissance to inform decisions about which accounts to compromise to further their operation. Personas may exist on a single site or across multiple sites (ex: Facebook, LinkedIn, Twitter, etc.). Compromised social media accounts may require additional development, this could include filling out or modifying profile information, further developing social networks, or incorporating photos. Adversaries can use a compromised social media profile to create new, or hijack existing, connections to targets of interest. These connections may be direct or may include trying to connect through others. Compromised profiles may be leveraged during other phases of the adversary lifecycle, such as during Initial Access (ex: Spearphishing via Service).

Procedures:

- [G0034] Sandworm Team: Sandworm Team creates credential capture webpages to compromise existing, legitimate social media accounts.
- [G0065] Leviathan: Leviathan has compromised social media accounts to conduct social engineering attacks.

### T1586.002 - Compromise Accounts: Email Accounts

Description:

Adversaries may compromise email accounts that can be used during targeting. Adversaries can use compromised email accounts to further their operations, such as leveraging them to conduct Phishing for Information, Phishing, or large-scale spam email campaigns. Utilizing an existing persona with a compromised email account may engender a level of trust in a potential victim if they have a relationship with, or knowledge of, the compromised persona. Compromised email accounts can also be used in the acquisition of infrastructure (ex: Domains). A variety of methods exist for compromising email accounts, such as gathering credentials via Phishing for Information, purchasing credentials from third-party sites, brute forcing credentials (ex: password reuse from breach credential dumps), or paying employees, suppliers or business partners for access to credentials. Prior to compromising email accounts, adversaries may conduct Reconnaissance to inform decisions about which accounts to compromise to further their operation. Adversaries may target compromising well-known email accounts or domains from which malicious spam or Phishing emails may evade reputation-based email filtering rules. Adversaries can use a compromised email account to hijack existing email threads with targets of interest.

Procedures:

- [G0007] APT28: APT28 has used compromised email accounts to send credential phishing emails.
- [G0059] Magic Hound: Magic Hound has compromised personal email accounts through the use of legitimate credentials and gathered additional victim information.
- [G0049] OilRig: OilRig has compromised email accounts to send phishing emails.

### T1586.003 - Compromise Accounts: Cloud Accounts

Description:

Adversaries may compromise cloud accounts that can be used during targeting. Adversaries can use compromised cloud accounts to further their operations, including leveraging cloud storage services such as Dropbox, Microsoft OneDrive, or AWS S3 buckets for Exfiltration to Cloud Storage or to Upload Tools. Cloud accounts can also be used in the acquisition of infrastructure, such as Virtual Private Servers or Serverless infrastructure. Additionally, cloud-based messaging services such as Twilio, SendGrid, AWS End User Messaging, AWS SNS (Simple Notification Service), or AWS SES (Simple Email Service) may be leveraged for spam or Phishing. Compromising cloud accounts may allow adversaries to develop sophisticated capabilities without managing their own servers. A variety of methods exist for compromising cloud accounts, such as gathering credentials via Phishing for Information, purchasing credentials from third-party sites, conducting Password Spraying attacks, or attempting to Steal Application Access Tokens. Prior to compromising cloud accounts, adversaries may conduct Reconnaissance to inform decisions about which accounts to compromise to further their operation. In some cases, adversaries may target privileged service provider accounts with the intent of leveraging a Trusted Relationship between service providers and their customers.

Procedures:

- [C0040] APT41 DUST: APT41 DUST used compromised Google Workspace accounts for command and control.
- [G0016] APT29: APT29 has used residential proxies, including Azure Virtual Machines, to obfuscate their access to victim environments.


### T1587.001 - Develop Capabilities: Malware

Description:

Adversaries may develop malware and malware components that can be used during targeting. Building malicious software can include the development of payloads, droppers, post-compromise tools, backdoors (including backdoored images), packers, C2 protocols, and the creation of infected removable media. Adversaries may develop malware to support their operations, creating a means for maintaining control of remote machines, evading defenses, and executing post-compromise behaviors. As with legitimate development efforts, different skill sets may be required for developing malware. The skills needed may be located in-house, or may need to be contracted out. Use of a contractor may be considered an extension of that adversary's malware development capabilities, provided the adversary plays a role in shaping requirements and maintains a degree of exclusivity to the malware. Some aspects of malware development, such as C2 protocol development, may require adversaries to obtain additional infrastructure. For example, malware developed that will communicate with Twitter for C2, may require use of Web Services.

Procedures:

- [G0094] Kimsuky: Kimsuky has developed its own unique malware such as MailFetch.py for use in operations.
- [G1016] FIN13: FIN13 has utilized custom malware to maintain persistence in a compromised environment.
- [G1036] Moonstone Sleet: Moonstone Sleet has developed custom malware, including a malware delivery mechanism masquerading as a legitimate game.

### T1587.002 - Develop Capabilities: Code Signing Certificates

Description:

Adversaries may create self-signed code signing certificates that can be used during targeting. Code signing is the process of digitally signing executables and scripts to confirm the software author and guarantee that the code has not been altered or corrupted. Code signing provides a level of authenticity for a program from the developer and a guarantee that the program has not been tampered with. Users and/or security tools may trust a signed piece of code more than an unsigned piece of code even if they don't know who issued the certificate or who the author is. Prior to Code Signing, adversaries may develop self-signed code signing certificates for use in operations.

Procedures:

- [G1034] Daggerfly: Daggerfly created code signing certificates to sign malicious macOS files.
- [G0056] PROMETHIUM: PROMETHIUM has created self-signed certificates to sign malicious installers.
- [G0040] Patchwork: Patchwork has created self-signed certificates from fictitious and spoofed legitimate software companies that were later used to sign malware.

### T1587.003 - Develop Capabilities: Digital Certificates

Description:

Adversaries may create self-signed SSL/TLS certificates that can be used during targeting. SSL/TLS certificates are designed to instill trust. They include information about the key, information about its owner's identity, and the digital signature of an entity that has verified the certificate's contents are correct. If the signature is valid, and the person examining the certificate trusts the signer, then they know they can use that key to communicate with its owner. In the case of self-signing, digital certificates will lack the element of trust associated with the signature of a third-party certificate authority (CA). Adversaries may create self-signed SSL/TLS certificates that can be used to further their operations, such as encrypting C2 traffic (ex: Asymmetric Cryptography with Web Protocols) or even enabling Adversary-in-the-Middle if added to the root of trust (i.e. Install Root Certificate). After creating a digital certificate, an adversary may then install that certificate (see Install Digital Certificate) on infrastructure under their control.

Procedures:

- [G0016] APT29: APT29 has created self-signed digital certificates to enable mutual TLS authentication for malware.
- [C0046] ArcaneDoor: ArcaneDoor included acquiring digital certificates mimicking patterns associated with Cisco ASA appliances for command and control infrastructure.
- [G0056] PROMETHIUM: PROMETHIUM has created self-signed digital certificates for use in HTTPS C2 traffic.

### T1587.004 - Develop Capabilities: Exploits

Description:

Adversaries may develop exploits that can be used during targeting. An exploit takes advantage of a bug or vulnerability in order to cause unintended or unanticipated behavior to occur on computer hardware or software. Rather than finding/modifying exploits from online or purchasing them from exploit vendors, an adversary may develop their own exploits. Adversaries may use information acquired via Vulnerabilities to focus exploit development efforts. As part of the exploit development process, adversaries may uncover exploitable vulnerabilities through methods such as fuzzing and patch analysis. As with legitimate development efforts, different skill sets may be required for developing exploits. The skills needed may be located in-house, or may need to be contracted out. Use of a contractor may be considered an extension of that adversary's exploit development capabilities, provided the adversary plays a role in shaping requirements and maintains an initial degree of exclusivity to the exploit. Adversaries may use exploits during various phases of the adversary lifecycle (i.e. Exploit Public-Facing Application, Exploitation for Client Execution, Exploitation for Privilege Escalation, Exploitation for Defense Evasion, Exploitation for Credential Access, Exploitation of Remote Services, and Application or System Exploitation).

Procedures:

- [G1017] Volt Typhoon: Volt Typhoon has exploited zero-day vulnerabilities for initial access.
- [G0065] Leviathan: Leviathan has rapidly transformed and adapted public exploit proof-of-concept code for new vulnerabilities and utilized them against target networks.


### T1588.001 - Obtain Capabilities: Malware

Description:

Adversaries may buy, steal, or download malware that can be used during targeting. Malicious software can include payloads, droppers, post-compromise tools, backdoors, packers, and C2 protocols. Adversaries may acquire malware to support their operations, obtaining a means for maintaining control of remote machines, evading defenses, and executing post-compromise behaviors. In addition to downloading free malware from the internet, adversaries may purchase these capabilities from third-party entities. Third-party entities can include technology companies that specialize in malware development, criminal marketplaces (including Malware-as-a-Service, or MaaS), or from individuals. In addition to purchasing malware, adversaries may steal and repurpose malware from third-party entities (including other adversaries).

Procedures:

- [G1014] LuminousMoth: LuminousMoth has obtained and used malware such as Cobalt Strike.
- [C0002] Night Dragon: During Night Dragon, threat actors used Trojans from underground hacker websites.
- [C0005] Operation Spalax: For Operation Spalax, the threat actors obtained malware, including Remcos, njRAT, and AsyncRAT.

### T1588.002 - Obtain Capabilities: Tool

Description:

Adversaries may buy, steal, or download software tools that can be used during targeting. Tools can be open or closed source, free or commercial. A tool can be used for malicious purposes by an adversary, but (unlike malware) were not intended to be used for those purposes (ex: PsExec). Tool acquisition can involve the procurement of commercial software licenses, including for red teaming tools such as Cobalt Strike. Commercial software may be obtained through purchase, stealing licenses (or licensed copies of the software), or cracking trial versions. Adversaries may obtain tools to support their operations, including to support execution of post-compromise behaviors. In addition to freely downloading or purchasing software, adversaries may steal software and/or software licenses from third-party entities (including other adversaries).

Procedures:

- [G0105] DarkVishnya: DarkVishnya has obtained and used tools such as Impacket, Winexe, and PsExec.
- [G0010] Turla: Turla has obtained and customized publicly-available tools like Mimikatz.
- [C0032] C0032: During the C0032 campaign, TEMP.Veles obtained and used tools such as Mimikatz and PsExec.

### T1588.003 - Obtain Capabilities: Code Signing Certificates

Description:

Adversaries may buy and/or steal code signing certificates that can be used during targeting. Code signing is the process of digitally signing executables and scripts to confirm the software author and guarantee that the code has not been altered or corrupted. Code signing provides a level of authenticity for a program from the developer and a guarantee that the program has not been tampered with. Users and/or security tools may trust a signed piece of code more than an unsigned piece of code even if they don't know who issued the certificate or who the author is. Prior to Code Signing, adversaries may purchase or steal code signing certificates for use in operations. The purchase of code signing certificates may be done using a front organization or using information stolen from a previously compromised entity that allows the adversary to validate to a certificate provider as that entity. Adversaries may also steal code signing materials directly from a compromised third-party.

Procedures:

- [G0102] Wizard Spider: Wizard Spider has obtained code signing certificates signed by DigiCert, GlobalSign, and COMOOD for malware payloads.
- [G0049] OilRig: OilRig has obtained stolen code signing certificates to digitally sign malware.
- [G0098] BlackTech: BlackTech has used stolen code-signing certificates for its malicious payloads.

### T1588.004 - Obtain Capabilities: Digital Certificates

Description:

Adversaries may buy and/or steal SSL/TLS certificates that can be used during targeting. SSL/TLS certificates are designed to instill trust. They include information about the key, information about its owner's identity, and the digital signature of an entity that has verified the certificate's contents are correct. If the signature is valid, and the person examining the certificate trusts the signer, then they know they can use that key to communicate with its owner. Adversaries may purchase or steal SSL/TLS certificates to further their operations, such as encrypting C2 traffic (ex: Asymmetric Cryptography with Web Protocols) or even enabling Adversary-in-the-Middle if the certificate is trusted or otherwise added to the root of trust (i.e. Install Root Certificate). The purchase of digital certificates may be done using a front organization or using information stolen from a previously compromised entity that allows the adversary to validate to a certificate provider as that entity. Adversaries may also steal certificate materials directly from a compromised third-party, including from certificate authorities. Adversaries may register or hijack domains that they will later purchase an SSL/TLS certificate for. Certificate authorities exist that allow adversaries to acquire SSL/TLS certificates, such as domain validation certificates, for free. After obtaining a digital certificate, an adversary may then install that certificate (see Install Digital Certificate) on infrastructure under their control.

Procedures:

- [G0122] Silent Librarian: Silent Librarian has obtained free Let's Encrypt SSL certificates for use on their phishing pages.
- [C0043] Indian Critical Infrastructure Intrusions: Indian Critical Infrastructure Intrusions included the use of digital certificates spoofing Microsoft.
- [G0032] Lazarus Group: Lazarus Group has obtained SSL certificates for their C2 domains.

### T1588.005 - Obtain Capabilities: Exploits

Description:

Adversaries may buy, steal, or download exploits that can be used during targeting. An exploit takes advantage of a bug or vulnerability in order to cause unintended or unanticipated behavior to occur on computer hardware or software. Rather than developing their own exploits, an adversary may find/modify exploits from online or purchase them from exploit vendors. In addition to downloading free exploits from the internet, adversaries may purchase exploits from third-party entities. Third-party entities can include technology companies that specialize in exploit development, criminal marketplaces (including exploit kits), or from individuals. In addition to purchasing exploits, adversaries may steal and repurpose exploits from third-party entities (including other adversaries). An adversary may monitor exploit provider forums to understand the state of existing, as well as newly discovered, exploits. There is usually a delay between when an exploit is discovered and when it is made public. An adversary may target the systems of those known to conduct exploit research and development in order to gain that knowledge for use during a subsequent operation. Adversaries may use exploits during various phases of the adversary lifecycle (i.e. Exploit Public-Facing Application, Exploitation for Client Execution, Exploitation for Privilege Escalation, Exploitation for Defense Evasion, Exploitation for Credential Access, Exploitation of Remote Services, and Application or System Exploitation).

Procedures:

- [G1003] Ember Bear: Ember Bear has obtained exploitation scripts against publicly-disclosed vulnerabilities from public repositories.
- [G0094] Kimsuky: Kimsuky has obtained exploit code for various CVEs.

### T1588.006 - Obtain Capabilities: Vulnerabilities

Description:

Adversaries may acquire information about vulnerabilities that can be used during targeting. A vulnerability is a weakness in computer hardware or software that can, potentially, be exploited by an adversary to cause unintended or unanticipated behavior to occur. Adversaries may find vulnerability information by searching open databases or gaining access to closed vulnerability databases. An adversary may monitor vulnerability disclosures/databases to understand the state of existing, as well as newly discovered, vulnerabilities. There is usually a delay between when a vulnerability is discovered and when it is made public. An adversary may target the systems of those known to conduct vulnerability research (including commercial vendors). Knowledge of a vulnerability may cause an adversary to search for an existing exploit (i.e. Exploits) or to attempt to develop one themselves (i.e. Exploits).

Procedures:

- [G0034] Sandworm Team: In 2017, Sandworm Team conducted technical research related to vulnerabilities associated with websites used by the Korean Sport and Olympic Committee, a Korean power company, and a Korean airport.
- [G1017] Volt Typhoon: Volt Typhoon has used publicly available exploit code for initial access.
- [C0049] Leviathan Australian Intrusions: Leviathan weaponized publicly-known vulnerabilities for initial access and other purposes during Leviathan Australian Intrusions.

### T1588.007 - Obtain Capabilities: Artificial Intelligence

Description:

Adversaries may obtain access to generative artificial intelligence tools, such as large language models (LLMs), to aid various techniques during targeting. These tools may be used to inform, bolster, and enable a variety of malicious tasks, including conducting Reconnaissance, creating basic scripts, assisting social engineering, and even developing payloads. For example, by utilizing a publicly available LLM an adversary is essentially outsourcing or automating certain tasks to the tool. Using AI, the adversary may draft and generate content in a variety of written languages to be used in Phishing/Phishing for Information campaigns. The same publicly available tool may further enable vulnerability or other offensive research supporting Develop Capabilities. AI tools may also automate technical tasks by generating, refining, or otherwise enhancing (e.g., Obfuscated Files or Information) malicious scripts and payloads. Finally, AI-generated text, images, audio, and video may be used for fraud, Impersonation, and other malicious activities.


### T1608.001 - Stage Capabilities: Upload Malware

Description:

Adversaries may upload malware to third-party or adversary controlled infrastructure to make it accessible during targeting. Malicious software can include payloads, droppers, post-compromise tools, backdoors, and a variety of other malicious content. Adversaries may upload malware to support their operations, such as making a payload available to a victim network to enable Ingress Tool Transfer by placing it on an Internet accessible web server. Malware may be placed on infrastructure that was previously purchased/rented by the adversary (Acquire Infrastructure) or was otherwise compromised by them (Compromise Infrastructure). Malware can also be staged on web services, such as GitHub or Pastebin, or hosted on the InterPlanetary File System (IPFS), where decentralized content storage makes the removal of malicious files difficult. Adversaries may upload backdoored files, such as application binaries, virtual machine images, or container images, to third-party software stores or repositories (ex: GitHub, CNET, AWS Community AMIs, Docker Hub). By chance encounter, victims may directly download/install these backdoored files via User Execution. Masquerading may increase the chance of users mistakenly executing these files.

Procedures:

- [G0034] Sandworm Team: Sandworm Team staged compromised versions of legitimate software installers in forums to enable initial access to executing user.
- [G1018] TA2541: TA2541 has uploaded malware to various platforms including Google Drive, Pastetext, Sharetext, and GitHub.
- [C0022] Operation Dream Job: For Operation Dream Job, Lazarus Group used compromised servers to host malware.

### T1608.002 - Stage Capabilities: Upload Tool

Description:

Adversaries may upload tools to third-party or adversary controlled infrastructure to make it accessible during targeting. Tools can be open or closed source, free or commercial. Tools can be used for malicious purposes by an adversary, but (unlike malware) were not intended to be used for those purposes (ex: PsExec). Adversaries may upload tools to support their operations, such as making a tool available to a victim network to enable Ingress Tool Transfer by placing it on an Internet accessible web server. Tools may be placed on infrastructure that was previously purchased/rented by the adversary (Acquire Infrastructure) or was otherwise compromised by them (Compromise Infrastructure). Tools can also be staged on web services, such as an adversary controlled GitHub repo, or on Platform-as-a-Service offerings that enable users to easily provision applications. Adversaries can avoid the need to upload a tool by having compromised victim machines download the tool directly from a third-party hosting location (ex: a non-adversary controlled GitHub repo), including the original hosting site of the tool.

Procedures:

- [C0022] Operation Dream Job: For Operation Dream Job, Lazarus Group used multiple servers to host malicious tools.
- [C0010] C0010: For C0010, UNC3890 actors staged tools on their infrastructure to download directly onto a compromised system.
- [G0027] Threat Group-3390: Threat Group-3390 has staged tools, including gsecdump and WCE, on previously compromised websites.

### T1608.003 - Stage Capabilities: Install Digital Certificate

Description:

Adversaries may install SSL/TLS certificates that can be used during targeting. SSL/TLS certificates are files that can be installed on servers to enable secure communications between systems. Digital certificates include information about the key, information about its owner's identity, and the digital signature of an entity that has verified the certificate's contents are correct. If the signature is valid, and the person examining the certificate trusts the signer, then they know they can use that key to communicate securely with its owner. Certificates can be uploaded to a server, then the server can be configured to use the certificate to enable encrypted communication with it. Adversaries may install SSL/TLS certificates that can be used to further their operations, such as encrypting C2 traffic (ex: Asymmetric Cryptography with Web Protocols) or lending credibility to a credential harvesting site. Installation of digital certificates may take place for a number of server types, including web servers and email servers. Adversaries can obtain digital certificates (see Digital Certificates) or create self-signed certificates (see Digital Certificates). Digital certificates can then be installed on adversary controlled infrastructure that may have been acquired (Acquire Infrastructure) or previously compromised (Compromise Infrastructure).

Procedures:

- [G1041] Sea Turtle: Sea Turtle captured legitimate SSL certificates from victim organizations and installed these on Sea Turtle-controlled infrastructure to enable subsequent adversary-in-the-middle operations.

### T1608.004 - Stage Capabilities: Drive-by Target

Description:

Adversaries may prepare an operational environment to infect systems that visit a website over the normal course of browsing. Endpoint systems may be compromised through browsing to adversary controlled sites, as in Drive-by Compromise. In such cases, the user's web browser is typically targeted for exploitation (often not requiring any extra user interaction once landing on the site), but adversaries may also set up websites for non-exploitation behavior such as Application Access Token. Prior to Drive-by Compromise, adversaries must stage resources needed to deliver that exploit to users who browse to an adversary controlled site. Drive-by content can be staged on adversary controlled infrastructure that has been acquired (Acquire Infrastructure) or previously compromised (Compromise Infrastructure). Adversaries may upload or inject malicious web content, such as JavaScript, into websites. This may be done in a number of ways, including: * Inserting malicious scripts into web pages or other user controllable web content such as forum posts * Modifying script files served to websites from publicly writeable cloud storage buckets * Crafting malicious web advertisements and purchasing ad space on a website through legitimate ad providers (i.e., Malvertising) In addition to staging content to exploit a user's web browser, adversaries may also stage scripting content to profile the user's browser (as in Gather Victim Host Information) to ensure it is vulnerable prior to attempting exploitation. Websites compromised by an adversary and used to stage a drive-by may be ones visited by a specific community, such as government, a particular industry, or region, where the goal is to compromise a specific user or set of users based on a shared interest. This kind of targeted campaign is referred to a strategic web compromise or watering hole attack. Adversaries may purchase domains similar to legitimate domains (ex: homoglyphs, typosquatting, different top-level domain, etc.) during acquisition of infrastructure (Domains) to help facilitate Drive-by Compromise.

Procedures:

- [G0134] Transparent Tribe: Transparent Tribe has set up websites with malicious hyperlinks and iframes to infect targeted victims with Crimson, njRAT, and other malicious tools.
- [G1014] LuminousMoth: LuminousMoth has redirected compromised machines to an actor-controlled webpage through HTML injection.
- [G0035] Dragonfly: Dragonfly has compromised websites to redirect traffic and to host exploit kits.

### T1608.005 - Stage Capabilities: Link Target

Description:

Adversaries may put in place resources that are referenced by a link that can be used during targeting. An adversary may rely upon a user clicking a malicious link in order to divulge information (including credentials) or to gain execution, as in Malicious Link. Links can be used for spearphishing, such as sending an email accompanied by social engineering text to coax the user to actively click or copy and paste a URL into a browser. Prior to a phish for information (as in Spearphishing Link) or a phish to gain initial access to a system (as in Spearphishing Link), an adversary must set up the resources for a link target for the spearphishing link. Typically, the resources for a link target will be an HTML page that may include some client-side script such as JavaScript to decide what content to serve to the user. Adversaries may clone legitimate sites to serve as the link target, this can include cloning of login pages of legitimate web services or organization login pages in an effort to harvest credentials during Spearphishing Link. Adversaries may also Upload Malware and have the link target point to malware for download/execution by the user. Adversaries may purchase domains similar to legitimate domains (ex: homoglyphs, typosquatting, different top-level domain, etc.) during acquisition of infrastructure (Domains) to help facilitate Malicious Link. Links can be written by adversaries to mask the true destination in order to deceive victims by abusing the URL schema and increasing the effectiveness of phishing. Adversaries may also use free or paid accounts on link shortening services and Platform-as-a-Service providers to host link targets while taking advantage of the widely trusted domains of those providers to avoid being blocked while redirecting victims to malicious pages. In addition, adversaries may serve a variety of malicious links through uniquely generated URIs/URLs (including one-time, single use links). Finally, adversaries may take advantage of the decentralized nature of the InterPlanetary File System (IPFS) to host link targets that are difficult to remove.

Procedures:

- [G1014] LuminousMoth: LuminousMoth has created a link to a Dropbox file that has been used in their spear-phishing operations.
- [G0122] Silent Librarian: Silent Librarian has cloned victim organization login pages and staged them for later use in credential harvesting campaigns. Silent Librarian has also made use of a variety of URL shorteners for these staged websites.

### T1608.006 - Stage Capabilities: SEO Poisoning

Description:

Adversaries may poison mechanisms that influence search engine optimization (SEO) to further lure staged capabilities towards potential victims. Search engines typically display results to users based on purchased ads as well as the site’s ranking/score/reputation calculated by their web crawlers and algorithms. To help facilitate Drive-by Compromise, adversaries may stage content that explicitly manipulates SEO rankings in order to promote sites hosting their malicious payloads (such as Drive-by Target) within search engines. Poisoning SEO rankings may involve various tricks, such as stuffing keywords (including in the form of hidden text) into compromised sites. These keywords could be related to the interests/browsing habits of the intended victim(s) as well as more broad, seasonably popular topics (e.g. elections, trending news). In addition to internet search engines (such as Google), adversaries may also aim to manipulate specific in-site searches for developer platforms (such as GitHub) to deceive users towards Supply Chain Compromise lures. In-site searches will rank search results according to their own algorithms and metrics such as popularity which may be targeted and gamed by malicious actors. Adversaries may also purchase or plant incoming links to staged capabilities in order to boost the site’s calculated relevance and reputation. SEO poisoning may also be combined with evasive redirects and other cloaking mechanisms (such as measuring mouse movements or serving content based on browser user agents, user language/localization settings, or HTTP headers) in order to feed SEO inputs while avoiding scrutiny from defenders.

Procedures:

- [G1020] Mustard Tempest: Mustard Tempest has poisoned search engine results to return fake software updates in order to distribute malware.


### T1650 - Acquire Access

Description:

Adversaries may purchase or otherwise acquire an existing access to a target system or network. A variety of online services and initial access broker networks are available to sell access to previously compromised systems. In some cases, adversary groups may form partnerships to share compromised systems with each other. Footholds to compromised systems may take a variety of forms, such as access to planted backdoors (e.g., Web Shell) or established access via External Remote Services. In some cases, access brokers will implant compromised systems with a “load” that can be used to install additional malware for paying customers. By leveraging existing access broker networks rather than developing or obtaining their own initial access capabilities, an adversary can potentially reduce the resources required to gain a foothold on a target network and focus their efforts on later stages of compromise. Adversaries may prioritize acquiring access to systems that have been determined to lack security monitoring or that have high privileges, or systems that belong to organizations in a particular sector. In some cases, purchasing access to an organization in sectors such as IT contracting, software development, or telecommunications may allow an adversary to compromise additional victims via a Trusted Relationship, Multi-Factor Authentication Interception, or even Supply Chain Compromise. **Note:** while this technique is distinct from other behaviors such as Purchase Technical Data and Credentials, they may often be used in conjunction (especially where the acquired foothold requires Valid Accounts).

