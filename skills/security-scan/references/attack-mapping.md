# ATT&CK mapping

Use this file to tag a finding with the MITRE ATT&CK technique an attacker would use. The tag lets the user's security team connect a finding to their own detections and to public reporting.

Tag the technique the weakness *enables*, not something the scan did. One finding, one primary technique; add a second only when it is clearly a different step.

Technique identifiers change between ATT&CK versions. When updating this file, check them against the current matrix.

## By stage

### Stage 1: Initial reconnaissance

| Technique | Name | The scan checks |
|---|---|---|
| T1595 | Active Scanning | what is reachable from the internet; whether request bursts are logged |
| T1596 | Search Open Technical Databases | what public indexes can know: exposed services, certificates, DNS |
| T1580 | Cloud Infrastructure Discovery | public cloud resources and their exposure |
| T1526 | Cloud Service Discovery | which services answer without authentication |

### Stage 2: Initial compromise

| Technique | Name | The scan checks |
|---|---|---|
| T1078 | Valid Accounts (.004 Cloud Accounts) | exposed and long-lived credentials; authentication strength |
| T1552.001 | Unsecured Credentials: Credentials in Files | secrets in repositories, bundles, state, images, documents |
| T1110.003 | Brute Force: Password Spraying | lockout and throttling; legacy protocols |
| T1190 | Exploit Public-Facing Application | entry flaws in code; patch latency of exposed software |
| T1133 | External Remote Services | VPN and remote access with weak authentication |
| T1199 | Trusted Relationship | vendor and partner access; multi-tenant applications |
| T1195 | Supply Chain Compromise | pipeline and dependency trust |
| T1606.002 | Forge Web Credentials: SAML Tokens | token and assertion verification |

### Stage 3: Foothold

| Technique | Name | The scan checks |
|---|---|---|
| T1087.004 | Account Discovery: Cloud Account | what an identity can list |
| T1069.003 | Permission Groups Discovery: Cloud Groups | effective permissions per identity |
| T1651 | Cloud Administration Command | remote-command features and who can use them |
| T1648 | Serverless Execution | functions and jobs an identity can create or change |
| T1059 | Command and Scripting Interpreter | deployment interfaces that run commands |
| T1505.003 | Server Software Component: Web Shell | database and deployment features that write executable files |

### Stage 4: Privilege escalation

| Technique | Name | The scan checks |
|---|---|---|
| T1098.001 | Account Manipulation: Additional Cloud Credentials | who can add credentials to identities and applications |
| T1098.003 | Account Manipulation: Additional Cloud Roles | who can assign roles, including to themselves |
| T1552.005 | Unsecured Credentials: Cloud Instance Metadata API | metadata service configuration; pass-role and launch rights |
| T1558.003 | Steal or Forge Kerberos Tickets: Kerberoasting | service accounts with weak encryption or old passwords |
| T1003.006 | OS Credential Dumping: DCSync | who holds replication rights |
| T1649 | Steal or Forge Authentication Certificates | certificate templates and enrolment rights |
| T1134.001 | Access Token Manipulation: Token Impersonation/Theft | delegation settings |
| T1606 | Forge Web Credentials | signing-key rotation and storage |
| T1068 | Exploitation for Privilege Escalation | patch level for known escalation flaws |

### Stage 5: Internal reconnaissance

| Technique | Name | The scan checks |
|---|---|---|
| T1087.002 | Account Discovery: Domain Account | directory enumeration by ordinary accounts |
| T1555 | Credentials from Password Stores | who can read vaults and local administrator passwords |
| T1555.006 | Credentials from Password Stores: Cloud Secrets Management Stores | breadth of secret-store read access |
| T1213 | Data from Information Repositories | credentials in wikis, tickets, shared drives |
| T1518.001 | Software Discovery: Security Software Discovery | hosts without endpoint sensor; logging gaps |

### Stage 6: Lateral movement

| Technique | Name | The scan checks |
|---|---|---|
| T1550.002 | Use Alternate Authentication Material: Pass the Hash | credential reuse; shared local administrator passwords |
| T1550.003 | Use Alternate Authentication Material: Pass the Ticket | delegation; ticket lifetime |
| T1021.006 | Remote Services: Windows Remote Management | remote administration between segments |
| T1021.007 | Remote Services: Cloud Services | cloud to on-premises and cross-account bridges |
| T1557.001 | Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning and SMB Relay | signing and channel binding |
| T1199 | Trusted Relationship | cross-tenant and vendor trust |

### Stage 7: Persistence and control

| Technique | Name | The scan checks |
|---|---|---|
| T1136.003 | Create Account: Cloud Account | who can create accounts; alerting on creation |
| T1098 | Account Manipulation | password resets; credential additions |
| T1098.004 | Account Manipulation: SSH Authorized Keys | who can register keys |
| T1578.002 | Modify Cloud Compute Infrastructure: Create Cloud Instance | who can launch instances and allocate public addresses |
| T1505.003 | Server Software Component: Web Shell | unexpected files in web roots |
| T1219 | Remote Access Software | remote-access tools on hosts |
| T1572 | Protocol Tunneling | outbound tunnelling from servers |
| T1090 | Proxy (.003 Multi-hop Proxy) | outbound filtering; proxy logging |
| T1071.001 | Application Layer Protocol: Web Protocols | first contact with new external destinations |

### Stage 8: Mission

| Technique | Name | The scan checks |
|---|---|---|
| T1530 | Data from Cloud Storage | bulk-read rights; data-plane logging |
| T1005 | Data from Local System | database read rights of reachable identities |
| T1114.002 | Email Collection: Remote Email Collection | mailbox access by applications |
| T1074 | Data Staged (.001 Local, .002 Remote) | who can create volumes and copy snapshots |
| T1537 | Transfer Data to Cloud Account | snapshot and image sharing outside the organization |
| T1567 | Exfiltration Over Web Service | outbound paths from data-holding systems |
| T1496 | Resource Hijacking | AI and compute spend exposure |
| T1485 | Data Destruction | who can delete data stores |
| T1490 | Inhibit System Recovery | who can delete or alter backups |

## Tagging a finding

```yaml
attack:
  primary: T1552.001
  name: "Unsecured Credentials: Credentials in Files"
  enables: [T1078.004]
```
