# Introduction to Threat Hunting & Elastic Revision Questions

### 1. Threat Hunting Fundamentals

Explain why threat hunting is considered a proactive cybersecurity practice. In your answer, discuss how it differs from traditional defence-oriented security approaches and describe its primary objectives.

### 2. Threat Hunting Process

You have received a threat intelligence report stating that attackers are exploiting a newly disclosed VPN vulnerability to gain initial access. Design a threat hunting plan by describing:

- Your hypothesis
- The data sources you would collect
- The tools or queries you would use
- How you would validate or reject your hypothesis

### 3. Threat Hunting Team Structure

Describe the roles of a threat hunting team. Select four different roles and explain how each contributes to the success of a threat hunting operation.

### 4. Investigating Suspicious Authentication Activity

An organisation notices the following:

- Multiple failed VPN logins from foreign IP addresses
- A successful login immediately afterwards
- Unusual PowerShell activity on the authenticated host

Outline the steps you would take to investigate whether this represents a real compromise. Explain what evidence you would collect and how you would determine whether the activity is malicious.

### 5. Risk Assessment and Threat Hunting

Explain how risk assessment supports threat hunting. Include at least four ways in which the results of a risk assessment influence hunting priorities and decision-making.

### 6. Writing an Elastic Query

Create an Elastic Query Language (EQL), KQL, or Lucene query that searches for suspicious PowerShell executions launched by `WINWORD.EXE` or `EXCEL.EXE`.

Your query should:

- Detect PowerShell processes
- Check that the parent process is either Microsoft Word or Excel
- Avoid using an example copied directly from the course material

Briefly explain why this behaviour may indicate malicious activity.

### 7. The Diamond Model

Describe the four core components of the Diamond Model of Intrusion Analysis. Explain how the model complements the Cyber Kill Chain rather than replacing it.

### 8. Detecting Lateral Movement

A threat intelligence report indicates that attackers commonly move laterally using PsExec and WinRM.

Describe how you would hunt for evidence of this behaviour in an enterprise environment. Include:

- Relevant log sources
- Useful Windows Event IDs (where appropriate)
- Network indicators
- How you would distinguish legitimate administration from malicious activity

### 9. Cyber Threat Intelligence

Explain the four fundamental principles of effective Cyber Threat Intelligence (CTI). Why is each principle important when supporting security operations?

### 10. IOC Analysis Workflow

You are given the following Indicators of Compromise:

- Two SHA-256 hashes
- Three IP addresses
- One suspicious domain
- One phishing email subject

Describe how you would validate these indicators before deploying them into production security controls. Include any external intelligence sources or internal validation steps you would perform.

### 11. Threat Intelligence vs Threat Hunting

Compare threat intelligence and threat hunting. Explain how their objectives differ, what information each focuses on, and how the two disciplines support one another.

### 12. Hunting for Persistence

An attacker is believed to establish persistence by dropping executables into user startup locations.

Design a threat hunt that identifies this behaviour. Your answer should include:

- Which Windows artifacts you would inspect
- Which Elastic data sources you would query
- What suspicious patterns would increase your confidence that persistence has been established

### 13. Tactical Threat Intelligence

Describe the process of analysing a tactical threat intelligence report. Explain why validation, contextual understanding, and continuous monitoring are essential before acting on reported IOCs.

### 14. Correlating Multiple Indicators

You have the following observations from Elastic:

- A phishing email delivered to a user
- A OneNote attachment downloaded
- A PowerShell process spawned shortly afterwards
- An outbound connection to a known malicious IP

Describe how you would correlate these events to determine whether they represent a successful attack. Explain what additional evidence you would seek before escalating the incident.
