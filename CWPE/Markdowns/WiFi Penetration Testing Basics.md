# Wi-Fi Pen-testing Basics Module

## Introduction

Wi-Fi penetration testing is a critical process employed by cybersecurity professionals to assess the security posture of Wi-Fi networks. The aim of Wi-Fi pentesters is to uncover potential weaknesses and vulnerabilities that could compromise network security.

### Wi-Fi Authentication Types

We need to understand Wi-Fi authentication to have any hope of being able to conduct red (or blue) team work around wifi networks.

```mermaid
flowchart TD;
id1[WiFi Security] --> id2[[WiFi Authentication Types]]
id2 --> id3([WEP])
id2 --> id4([WPA])
id2 --> id5([WPA2])
id2 --> id6([WPA3])

id5 ---> id7([WPA2-PSK/WPA2-Personal])
id5 ---> id8([WPA2-Enterprise])
id6 --> id9([WPA3-SAE/WPA3-Personal])
id6 --> id10([WPA3-Enterprise])


id8 --> id11([EAP-TTLS/PAP])
id8 --> id12([PEAP-MSCHAPv2])
id8 ----> id13([EAP-TLS])
id10 --> id13


id13 --> id14[Certificate-Based authentication, CBA]
```

- WEP (Wired Equivalent Privacy): Original Wifi security protocol, providing basic encryption. Now considered insecure.

- WPA (Wifi Protected Access): Introduced as an interim improvement to WEP, WPA offers better encryption through TKIP (temporal key integrity protocol) but is still considered outdated.

- WPA2: A significant advancement over WPA, now using AES for security. Considered the standard for many years.

- WPA3: The latest standard with enhanced encryption and more robust password authentication

Wifi penetration testers need to be comfortable with the 4 key components of a test:

- Assessing passphrases

- Analysing configurations

- Probing infrastructure

- Testing client devices

## 802.11 Frames


