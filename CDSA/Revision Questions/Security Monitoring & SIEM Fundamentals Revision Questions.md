# Security Monitoring & SIEM Fundamentals Revision Questions

### 1. SIEMs

Define a SIEM and explain how it differs from IDS and IPS technologies.

### 2. SIEM data flow

Include the three main stages and explain the purpose of each.

### 3. SIEM use case development lifecycle

Why is periodic fine-tuning an important stage?

### 4. Components of the Elastic Stack

Describe the role of Elasticsearch, Logstash, Kibana, and Beats.

### 5. Elastic Common Schema

Discuss at least four advantages of using ECS within the Elastic Stack.

### 6. SOC Teams

What are its primary responsibilities?

### 7. SOC Job Roles

Compare the responsibilities of Tier 1, Tier 2, and Tier 3 SOC analysts.

### 8. SOC Evolution

Explain the evolution of SOCs from SOC 1.0 to Cognitive (Next-Generation) SOCs.

### 9. MITRE ATT&CK

How does the MITRE ATT&CK Framework support security operations? Provide at least five examples of its use.

### 10. Alert

Why are alert enrichment and risk assessment important before escalation?

---

### 11. KQL Query Writing

Write a Kibana Query Language (KQL) query to find all failed Windows logon events (Event ID 4625) involving usernames beginning with admin.

### 12. SIEM Investigation

Your SIEM generates multiple alerts for failed logins from a single IP address across several servers. Describe the steps you would take to investigate and determine whether this is a brute-force attack.

### 13. Use Case Development

Your organisation wants to detect PowerShell being used to download malicious files. Outline how you would develop this SIEM use case using the lifecycle described in the module.

### 14. SOC Alert Escalation

You are a Tier 1 SOC analyst investigating an alert indicating malware execution on a domain controller. Explain:

- How you would triage the alert.

- What information you would collect.

- When and why you would escalate it.

### 15. Elastic Stack Data Flow

A Windows endpoint generates a security log that eventually appears on a Kibana dashboard. Describe the journey of this log through the Elastic Stack, identifying the role of each component involved.


