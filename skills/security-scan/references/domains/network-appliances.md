# Domain: Network appliances and infrastructure servers

> **Status: outline.** The checks below are the plan for this playbook. The read-only commands, the evidence format and the detailed criteria for each check are added in build step 3. Until then, use the outline with the stage file and your own knowledge of the platform, and stay inside the rules of engagement.

**Covers:** Firewalls, VPN gateways, routers, hypervisors, backup servers and other management servers.

**Read with:** management APIs and exported configuration, read-only; inventory data

Use this playbook together with the stage file: the stage file says what question to answer, this file says where to look in this technology. Every stage heading below matches a file in `../phases/`.

## Stage 1: Initial reconnaissance

- management interfaces reachable from the internet
- firmware and software versions against known exploited flaws
- VPN portals

## Stage 2: Initial compromise

- default or shared admin credentials, local accounts without strong authentication
- exposed configuration backups

## Stage 3: Foothold

- what appliance administration allows: configuration export, packet capture, credential stores

## Stage 4: Privilege escalation

- routes from read-only to admin
- shared admin accounts
- API tokens with full rights

## Stage 5: Internal reconnaissance

- stored directory bind credentials
- configuration that reveals topology
- log forwarding state

## Stage 6: Lateral movement

- the appliance as a pivot: management network reach, hypervisor over all machines, backup server over all data

## Stage 7: Persistence and control

- who can add VPN users, rules, admin accounts, scheduled scripts
- configuration-change alerts, firmware integrity

## Stage 8: Mission

- backup repositories: read, delete, immutability
- hypervisor snapshots
- VPN as a way out

## Detection sources

- appliance logs forwarded to a central store, configuration-change alerts

## Collector

`scripts/collectors/network_appliances.py` (not implemented yet). Its job is the read-only collection for the checks above, written as redacted JSON under `evidence/<stage>/`.
