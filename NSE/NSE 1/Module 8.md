# Endpoint Security

Traditionally an endpoint has been defined as a device connecting to a network.

### IoT

IoT is the network of physical devices connected to the internet. IoT devices come in many categories such as:

- **Personal devices**

- **Residential locations**

- **Industrial devices**

IoT devices massively greaten the attack service of a network. IoT devices generally do not have the capacity or capability for security tools or management visibility which can make them hard to secure. IoT has exploded the number of endpoints which makes it exponentially harder to secure the entire network. IoT devices also raise the risk of botnets since they generally have little or no encryption and are numerous.

It is recommended to connect IoT devices to an isolated network before registering it to the established network. This way we can whitelist (or in the worst case, block) the device in the established network.

### Endpoint Hardening Techniques

Hardening endpoints is critical to reduce risk on the network. Hardening endpoints can be achieved through different controls:

- **Administrative controls**: Passwords, restrictions and PoLP.

- **Local endpoint protection**: OS hardening, disk security and encryption, data loss prevention (DLP).

- **Endpoint maintenance**: Auto-updates and patching, policy checks and backups.

- **Endpoint monitoring**: Use UDS or EPP.

Firmware and boot processes should also be hardened. This is especially important for IoT devices. It is much easier to compromise a device if you have physical access to it so we should aim to prevent a threat actor getting physical access.

Full disk encryption (FDE) can be used to secure the data on the device. The disk is decrypted at boot time. You can also use a self encrypting drive (SED), that automatically encrypts data as it is written. You should also use DLP software to detect the transfer of sensitive information from a device or send it over the network.

### Endpoint Monitoring

Endpoint protection platforms (EPPs) can:

- Verify versions of software and firmware.

- Scan for malware.

- Enforce DLP.

- Provide visibility into systems.

EDR tools can detect and stop anomalous behaviours. This helps them prevent attacks that may not be detected by traditional antimalware systems. EDR usually uses AI and large amounts of data from previous attacks. EDR tools can talk to each other and allow other endpoints to block the malicious software before it is even run.
