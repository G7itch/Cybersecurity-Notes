# Cloud security and Virtualisation

Nowadays servers are no longer single pieces of hardware in an office location. Cloud computing has many advantages to physical hardware in availability, scalability and cost.

### Virtualisation Overview

Virtualisation is the creation of a virtual version of something, such as an OS. Virtualisation uses software to emulate hardware functionality - this means many virtual systems can run on a single physical system. Virtualisation comes with the benefit of cost and energy savings, and providing safe testing environments. Virtualisation also has much better disaster recovery mechanisms.

A hypervisor is software that manages the deployment of virtual machines. Generally hypervisors fall into two types:

- **Type 1**: Bare metal hypervisors. Run directly on computer hardware and can interact directly with the CPU, memory and physical storage.

- **Type 2**: Hosted hypervisor. Installed as a software application and runs over the existing OS.

Hyper-V is the Microsoft product for the deployment of VMs.

### Cloud Overview

The cloud refers to software and services offered by companies that makes their resources available over the internet. A very common cloud service is data storage. Services provided in the cloud are easily accessible.

Most cloud providers also let business arrange high availability and fault tolerance. There are 3 important service categories for cloud computing:

- **IaaS**

- **PaaS**

- **SaaS**

The main difference between the categories is how much control the customer has over the resources. Security in the cloud is shared between the cloud provider and the customer. Most cloud security vulnerabilities come from the user, so customers need to be very careful with their configuration.

### Cloud Security

Having physical computing systems on site historically has come at a large cost to companies. This is compounded with having many unused resources.

Security gets quite complex when dealing with the cloud since you do not have direct access to the hardware. The provider must secure the physical hardware.

### Virtual Machine Risks

We need to use procedures, policies and programs to secure the hypervisor. We also need to secure the physical hardware. Virtualisation aims to increase availability, scalability and elasticity, however it can also increase security risks.

You should:

- *Patch the OS*

- *Use IAM*

- *Install firewalls*

- *Implement network segmentation*

- *Limit connectivity*

- *Remove unnecessary virtual hardware*

- *Implement VM planning*

Data erasure needs to be performed properly including an appropriate secure data destruction process.

VMs can also lead to privilege escalation attacks. MiTM is another risk of VMs.

### Common Cloud Threats

The biggest threats to cloud environments are errors in configuration, setup and deployment. Securing all stages of a cloud deployment is a significant challenge. Some common threats are:

- Authentication and authorisation

- VM creep

- Misconfigured storage

- Data loss

- Connectivity

- Improper logging

- Rights and data ownership

You should use token based authentication like OAuth and SAML. This can help with IAM and simplify administration. The information most at risk in the cloud is the stored data. This data should have its own unique set of authentication rules and policies.

You should regularly audit and trim cloud services to ensure there aren't any unused or old vulnerable containers.

API connections should be encrypted to protect them. API keys also need to be kept private so threat actors cannot authenticate to cloud services.

It can occasionally be difficult to have a comprehensive view of what is going on in a  cloud environment. Collecting log information in a central location is incredibly useful.

### Cloud Hosted Security Services

The increase in cloud services led to cyber platforms to also be hosted in the cloud. Cloud native firewalls, WAFs and email gateways can all live in the cloud. Centralising network security devices saves large costs for small businesses.

Cloud based firewalls can replace local firewalls by allowing connections only through a secure VPN tunnel. SEGs can also be hosted in the cloud and scan all emails before they get sent to the recipient.

Authentication-as-a-service helps organisations arrange their IAM, SSO and MFA platforms in a central location. This can simplify identity management.

A Cloud access security broker (CASB)allows users to authenticate and controls their access the cloud applications. A cloud browser/remote browser isolation (RBI) is a SaaS web browser that runs in the cloud and behaves like a regular, locally installed web browser.

Sandbox environments can also exist in the cloud.

Secure access service edge (SASE) aims to extend networking and security beyond the connection between offices and cloud. SASE aims to let users interact with cloud firewalls, ZTNA and SWG by combining SD-WAN with a security service edge containing SECaas products.

### Securing the Cloud

Cloud networks should be partitioned from the public-facing network using a WAF and a CNF. At this stage we can perform regular network hardening on each partition.

You can also host DLP scanners, AV engines and sandboxes in cloud networks. You should also proxy connections and control access to services.

APIs come in two flavours:

- **REST (Representation state transfer)**: Simple request and response

- **SOAP (Simple object access protocol)**: Uses XML schema to package request as HTTP POST request.

You should protect APIs by using encryption through HTTPS, VPNS or using an API gateway. These gateways can use a schema to find anomalous API traffic.
