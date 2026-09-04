# Secure Network

### Secure Perimeter

A secure perimeter is a form of protection involving devices or techniques added at the edge of a managed network. The secure perimeter includes a protected zone and everything inside is considered trusted. Everything outside is  considered untrusted. The secure perimeter can filter traffic at different OSI layers:

- **Data link**: MAC Address filtering.

- **Transport**: Packet filtering. Stateless or stateful. Can also perform NAT filtering.

- **Application**: Proxy filtering through MiTM layer. Can also use application layer gateway to dynamically open ports for the process of communication.

Secure perimeters have some issues in the modern day. This comes from the increase in remote working and BYOD, as well as prevalence of cloud infrastructure. This makes it much harder for modern IT teams to identify what is trusted.

### Zero Trust Principles

The zero trust security model is founded by the following principles:

1. Never trust anything and always verify everything.

2. Implement least privilege

3. Assume the network is always compromised.

Perimeter networks are closed networks usually gated behind a firewall. VPNs can be used to enter a perimeter network remotely. Business transformation is now changing the attack surface and means that less network infrastructure is actually on site.

The never trust principle can be implemented by repeated identification processes (including using MFA) as well as context based clues such as the time and date, geolocation and security posture of the device being used.

The principle of least privilege can be implemented by introducing PAM, defining the protection surface and utilising the Kipling method.

You should always prepare for the worst. Introduce DRPs and business continuity plans. You can also segment the network.

Zero trust access uses role-based access control and endpoint agents to gain greater visibility to the attack surface. Network access control can be used to headless devices and implements zero trust network access (ZTNA) for establishing a secure session automatically.

In the zero trust model, there is a no trust zone. Trust must be proven and everything has the principle of least privilege. In this model, micro-segmentation can prevent the spread of malware through the network.

### Centralised Security Network Management

Centralised security network management refers to the act of gathering data from network devices and putting it into one central location. The objective is to provide a comprehensive view of the networks security. In an expanding network, including more users, devices and cloud environments requires dynamic elastic central security management. A possible solution includes data fabric architecture.

Data fabric uses AI to improve decision making and to automate simple tasks.

Some of the benefits of centralised security network management include:

- **High-level view and broad visibility**

- **Device integration**

- **Reduction in repetitive tasks**

- **Easier capacity planning**

- **Easier maintenance**

- **Easier compliance audits**

### Network Segmentation

Network segmentation divides a network into smaller segments. This makes it easier to protect the network as a whole and respond to incidents. A primary example of this is the DMZ of an organisations network, which lets users on the internet access some of the servers but not the internal network. Using zero trust also allows us to perform micro-segmentation. Traffic to and from the zones is called North-South traffic. Traffic inside the zones is called East-West traffic.

A network can be segmented physically or logically. Physical uses firewalls and switches to make various subnets. Logical segmentation relies on VLANs and generally does not require an organisation to purchase additional hardware. Physical segmentation occurs at the Network layer in the OSI model.

An SD-WAN (software defined wide area network) exists at the application layer and applies an overlay network (include tunnel encrypted paths) onto the underlay network (the physical hardware).

One way to securely access other network segments is to use a jump box. This has additional privileges and limited authorisation as well as additional logging. Another method is a bastion host which provides access to a private network from an external network. it is hardened to secure against attacks.

Network segmentation has many benefits:

- **Easier management**

- **Reduction in network broadcasts**

- **Minimisation of congestion**

- **Limiting attacks to one segment**

- **Greater protection of critical devices**

- **Reduction of scope of attacks**

### Firewalls

It is important to control the flow of traffic over a network. Firewalls are split into different generations:

- **First gen**: stateless firewalls. A packet filter that examine routing information and ports to define which packets are allowed through. A disadvantage to this is that it requires additional configuration to safely manage networks.

- **Second gen**: Stateful firewalls. Aims to offset disadvantages of first gen firewalls. Monitors sessions over time and continuously examines behaviour of traffic to determine what connections to block. Stateful firewalls still cannot block rogue packets if they use a well-established protocol.

- **Third gen**: DPI firewalls. They look into data payloads and understand the application layer protocols and can apply application layer filtering. This allows them to distinguish traffic that might use the same port. These can also include things like VPNs, IDS/IPS and antivirus.

- **Next gen firewalls**: NGFW. Operates with multiple security checkpoints. More detailed than a DPI. NGFWs can send packets to sandbox environments for further testing. They can also control applications, segment networks and use AI to proactively filter traffic.

### Secure Switching and Ports

Switches act at the data link layer. They assign packets to VLANs based on the source MAC address of the packet frame. They use a CAM table to move packets. It allows for faster packet forwarding and fewer collisions. Switches can also set a packet threshold to avoid being overwhelmed with requests.

An attacker can exploit this by flooding the network. They could do this through a MAC flooding attack. A MAC flooding attack aims to fill the CAM table with fake MAC addresses so that over devices cannot be routed to. This results in the data flooding through the whole network which can allow the attacker to receive potentially confidential data. A MAC flooding attack can be avoided by limiting the number of ports assigned to a MAC address, you can also use dynamic CAM fields. 802.1X authentication should be implemented.

The best practices for secure switching and protecting ports are:

- **Protect physical switches locally**

- **Separate switches**

- **Limit the number of MAC addresses per port**

- **Configure sticky or static MAC addresses**

- **Use ACLs to filter unverified addresses**

- **Add port authentication**

- **Implement port mirroring**

### Security Protocols

A protocol is a set of rules and methods used to establish communication between two devices. A security protocol validates and encrypts data between two devices. Protocols are secured by signing and encrypting. For example S/MIME for email. In HTTPS, the security is provided via TLS which encrypts the whole communication.

### Sandbox

A sandbox is a system that confines the actions of an application within a safe virtual environment. Sandboxing was invented to help protect against zero-day attacks. Sandboxing technology can be broadly split into 3 generations:

- **First gen**: Unable to share threat intelligence with other devices. Requires a separate management console.

- **Second gen**: Better at integrating with other devices such as SIEMs.

- **Third gen**: Uses the MITRE ATT&CK security language to help categorise and classify threats.

### Common Network Threats and Prevention

Network threats are unlawful or malicious activities that intend to take advantage of network vulnerabilities. Common threats include:

- **Spoofing**

- **Hijacking**

- **Replay attacks**

- **Transitive attacks**

- **DoS**

  - *Flood attacks*

  - *Ping of death*

  - *Teardrop attacks*

  - *Permanent DoS*

  - *Fork bomb*

DoS attacks can be prevented by implementing firewalls on the network and performing packet anomaly detection. We should also close unnecessary ports and fix known vulnerabilities.

### Operational Technology Security

OT systems are the physical systems that run critical infrastructure. OT systems monitor and control devices and processes. The difference between OT and IT is that IT systems are designed to manage information processing, storing and transmitting. IT security prioritises the CIA triad. OT systems control physical processes and run machines. OT security prioritises reliability, availability and stability.

Historically OT systems were separate from IT systems. This acted as an air-gap protecting against external threats. Nowadays modern OT networks are included in IT networks which expands their attack surface.

The common components of OT are:

- **Industrial control systems (ICS)**

- **Industrial Internet of Things (IIoT)**

- **Huma-machine interfaces**

- **Remote terminal units (RTUs)**

OT environments may face unique threats such as targeted supply chain attacks. OT systems often run on legacy systems that are very old and do not support modern security tools. They are often unable to have downtime as well.

Effective OT security requires structured, layered controls. These protect across all levels of the environment.
