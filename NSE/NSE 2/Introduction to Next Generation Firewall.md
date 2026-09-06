# Introduction to Next Generation Firewall Course - NSE 2

## What is a Next Generation Firewall?

Attack methods are constantly changing and this makes traditional firewalls vulnerable. An NGFW processes traffic and uses rules to determine what traffic to drop. NGFWs can filter traffic by application and perform DPI. Both traditional firewalls and NGFW block traffic but traditional firewalls inspect packet headers before deciding whether to drop the packets - this happens at the network and transport layers. NGFWs inspect traffic across the network transport and application layers. This enables NGFWs to perform deep packet inspection and looks for threats - it can also sandbox potential threats.

NGFWs have application awareness, letting them control traffic based on applications rather than ports. NGFWs can also perform other security features, such as network segmentation, access control, SSL decryption and sandboxing.

NGFWs are improving and are being more and more intertwined with ML algorithms. NGFWs are becoming less of a standalone product and becoming more a part of the secure access service edge (SASE).

## How do Firewall Policies Work?

Firewalls are physical security devices, or software applications that monitor and control incoming and outgoing network traffic. Gatekeeping firewalls are called perimeter firewalls. Firewalls can be used for internal segmentation and this includes micro segmentation.

Firewalls need rules or instructions to determine what actions to take. They describe the traffic to examine, the conditions to meet and what action to take. Firewall policies are lists of rules. Most firewall rules need a source, destination, port, protocol and action.

Firewalls process rules from top to bottom. Generally they follow first-match behaviour and so it stops checking the traffic against subsequent rules. This makes the order of rules very important. Most firewalls have an implicit deny rule at the bottom of its policy. A rule is called a shadow rule if it will never be triggered because of an earlier rule.

A firewall rule must contain match criteria and an action.

## User Authentication with a NGFW

Traditional firewalls use IP addresses to determine whether to allow or block a user. However this is a problem because it only relates devices to requests and not users. NGFWs have shifted towards identity based security to try and mitigate these risks. This allows for better tracking, stronger security and stronger logging.

Authentication is the process of verifying a user's identity. Authorisation determines what the user can access. You can authenticate with:

- **Something you know**

- **Something you have**

- **Something you are** *(inherited biometrics)*

- **Something you do** *(Behavioural biometrics)*

- **Somewhere you are** 

- **Something you do** (behavioural biometrics)

NGFWs map users to their devices to associate traffic with a specific user. What this means is that you can allow users traffic based on their identity and not just their device. A common authentication method used by NGFWs is directory-based authentication. The credentials are stored in LDAP directories or active directory. SSO can also help the firewall recognise user identities.

Captive portal authentication has users log in through a web page before accessing the internet. Certificate based authentication uses digital certificates to grant access in enterprise environments.

A user is a person or account that logs in using credentials. Users are organised into groups with different roles. Roles determine permissions.

## How do NGFWs Block Malware?

Malware is malicious software that is designed to harm a computer system, disrupt its operations or steal data. There are several common types of malware:

- **Viruses**

- **Trojans**

- **Ransomware**

Malware often enters a network through actions that appear harmless. For example through phishing or compromised websites. Malware can also spread through compromised software updates. Malware will often attempt to move from one system to another through lateral movement. It may also try and communicate to an external C2 server.

Traditional firewalls do not have visibility into packet data. This means malware hidden in normal looking traffic can pass through firewalls. NGFWs can perform deep packet inspection and look into the payload data of a packet. They are also context aware and can look for anomalies.

A common method for detecting malware on NGFWs is signature detection. Behaviour-based detection focuses on looking for unusual or harmful behaviour rather than known threat signatures.

Threat intelligence provides NGFWs with up-to-date information about threats. If an NGFW detects malware, it can block traffic, drop packets, terminate sessions, or alert administrators. NGFWs can also send files to a sandbox environment.

NGFWs are powerful but not a complete solution so administrators should also use tools such as EDR solutions. Defence-in-depth is a strategy that relies on using lots of different security solutions at different layers. The idea is that no one tool can block every threat, but the chance of an attack getting through all of them is quite low. 

## Controlling Web Access with Web Filtering

Web filtering helps control or track the websites that people visit. People may want to limit access to social media, prevent network congestion, decrease exposure to external threats, limit liability, prevent inappropriate material, etc. If using a FortiGate firewall, you can filter based on website category. Websites are categorised three times: once for production, once for schools and once for home.

## IPS and Application Control on FortiGate

An IPS is a security tool that monitors traffic in real time and automatically blocks malicious activity. IPS can prevent known attacks through signature based analysis. An IPS complements a firewall by sitting behind it and looking at traffic that has already been approved. Many standards, such as PCI DSS, require an IPS system.

An IPS can take different actions upon traffic matching including:

- *Allow*

- *Monitor*

- *Block*

- *Reset*

- *Quarantine*

## Connecting Multiple Locations Securely

A Virtual Private Network is an encrypted private communication over a public network. Data traveling through a VPN is protected. Organisations will require remote users to use a VPN to connect to their infrastructure. There are two types of VPNs:

- **Remote Access**: Connects users' devices to an organisations network.

- **Site-to-Site**: Connects entire networks.

VPNs provide several benefits including protecting data through encryption, they allow users to securely access organisational resources and they enable organisations to secure connect multiple locations. VPN endpoints authenticate to each other and exchange keys, data sent through the endpoints are then encrypted and decrypted when they arrive. A common technology to create these networks is IPsec which provides authentication, integrity and encryption.

First the endpoint establish trust and create a secure tunnel. They then exchange keys. As data travels through the network, IPsec encrypts the data packets. When the data reaches the destination, the VPN endpoint decrypts the data.

## SD-WAN

Business need to adapt to changing WAN networks. The solution to to migrate to SD-WAN architectures. An SD-WAN is a technology uses software defined networking to improve how WANs connect across different locations. It can provide better performance and make network management easier. SD-WANs can monitor the health and status of WAN connections.

SD-WAN technology is constantly adapting:

-  **Phase 1**: SD-WAN was developed because of the high cost and limited bandwidth of WAN networks. SD-WAN added load balancers and allowed networks make decisions based on applications.

- **Phase 2**: New capabilities were developed driven by the need for enhanced performance in SD-WAN networks. This reduced delays and simplified operations.

- **Phase 3**: Secure SD-WAN is a combination of a firewall and SD-WAN in one device.

## SASE

Work environments have evolved and so has user access requirements. Organisations must provide this access in a scalable way. SASE addresses these needs by combining NETaaS and SECaaS, delivered through the cloud. This allows remote workers take advantage of FWaaS, SWG, CASB and ZTNA. SASE is comprised of SD-WAN and Security Service Edge (SSE). When used properly, SASE allows all workers to experience the same level of security whether they are.
