# Glossary

- **Event**: An action occurring within a system or network.

- **Incident**: An event with negative consequences.

- **IT Security Incident**: This varies between companies however HTB defines it as an event with a clear intent to cause harm, performed against a computer system.

- **Incident Handling**: The clearly defined set of procedures for managing and responding to security incidents.

- **Incident Response Team**: A trained workforce whose job is to respond systematically to incidents and decide appropriate actions. The goal of such a team is to minimise disruption to business caused by an incident.

- **Tactic**: A high-level adversary objective during an incident. What does the attacker want to achieve at this stage in the attack?

- **Technique**: A specific method that an adversary uses to achieve a tactic. This is concrete attacker behaviour. Techniques in the MITRE framework are given IDs to help identify them.

- **Sub-technique**: The children of techniques that capture a particular implementation or target. In the MITRE framework, sub-techniques extend the ID of the parent technique.

- **IOC**: An indicator of compromise is a sign that an incident has occurred.

- **SOC**: Security Operations Centre

- **CISO**: Chief information security officer

- **TTPs**: Tactics, Tools and Procedures

- **EDR**: Endpoint detection and response

- **CTI**: Cyber Threat Intelligence

- **SIEM**: Security Information and Event Management

- **SIM**: Security Information Mangement

- **SEM**: Security Event Management

- **KQL**: Kibana Query Language

- **ECS**: Elastic Common Schema

- **ETW**: Event tracing for windows

- **DFIR**: Digital Forensics and Incident Response

- **Adversary**: An unauthorised entity seeking to infiltrate the organisation for a variety of purposes. Examples of adversary groups are cyber criminals, insider threats, hacktivists or state-sponsored operators.

- **APTs**: Advanced persistent threats are associated with highly organised groups that possess extensive resources which enable them to carry out their activities over a prolonged period of time. They generally show a preference for high-value targets including governments, healthcare and defence.

- **Campaign**: A collection of incidents that share similar TTPs are are believed to have similar goals.

- **Artefacts**: Traces of an attackers activity left behind after an incident.

- **Domain**: A group of objects that share the same AD database, such as users or devices.

- **Tree**: one or more grouped domains.

- **Forest**: A group of multiple trees. The highest level of organisation, all domains are included.

- **Organisational Unit (OU)**: An AD container containing user groups, computers and other OUs

- **Trust**: An access between resources to gain permission/access to resources in another domain.

- **Domain Controller (DC)**: The admin of the AD used to to setup the directory. The DC provides authentication and authorisation so it has the highest level of authority and privileges.

- **AD Data Store**: Contains Database files and processes that store and manage directory information. Contains the most critical file within an AD environment `NTDS.DIT`. On a DC this is stored in the `%systemroot%\NTDS`folder.

- **Access Control List (ACL)**: Contains information about different user/group privileges, each one being an Access Control Entry (ACE)

- **LDAP**: A protocol that systems in the network use the communicate with AD. DCs will run LDAP and constantly listen for requests

- **Key Distribution Centre (KDC)**: A kerberos service installed on  DC that generates tickets. Key components are the authentication server (AS) and the ticket-granting server (TGS).

- **Kerberos Ticket**: Tokens that serve as proof of identity issued by the KDC.

- **TGT**: A Kerberos ticket that acts as proof the client submitted valid user information to the KDC

- **TGS**: The kerberos ticket that is generated for each service the client wants to access and is allowed to access with their TGT.

- **KRBTGT User**: The first account created in an AD environment. It is a disabled user and is not intended to be logged in but has the purpose of storing secrets as password hashes. These passwords are always random and not known by anyone.

- **KDC Key**: An encryption key that proves the TGT is valid. AD creates the KDC key from the hashed password of the KRBTGT account.

- **Enterprise Admin**: The highest privilege group in a forest which has rights over all domains.


