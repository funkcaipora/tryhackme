# Stage 7: Persistence and control

**Question:** Where would an attacker hide, and who would notice?

## What an automated attacker does here

It makes sure it can come back, usually by creating things that look ordinary. It adds accounts and gives them admin rights, resets the passwords of real users, adds a credential to an existing application, creates access keys and API tokens, registers SSH keys, launches a small instance with a public address to serve as a way back in. On servers it drops web shells and remote-access tools. To stay in contact it opens tunnels out of the network and routes its traffic through proxies, so commands and data travel over connections that look like normal web traffic. It also plants itself in the tools developers trust: a hook or connector entry in an AI coding assistant's configuration runs its code the next time someone opens the project.

## What to check, from the inside

There are two questions here: what could be created, and what already exists that nobody can explain.

**Who can create persistence**

- who can create users, groups and role assignments
- who can create access keys, tokens and application credentials, and add credentials to existing applications
- who can register SSH keys, launch instances, allocate public addresses, open firewall rules
- who can create functions, scheduled jobs, pipeline secrets, deploy keys, webhooks
- whether organization-level policy blocks any of this for non-admins

**Drift that already exists**

- admin accounts and privileged role assignments nobody recognises, or created recently outside the normal process
- keys and tokens older than the rotation policy, or never used
- application consents and grants nobody reviewed
- instances, addresses and firewall rules with no owner
- files in web roots that are not part of a deployment

If any of this looks like an intrusion in progress and not just drift, stop and tell the user (see the stopping rules in `rules-of-engagement.md`).

**Control channels: could an attacker stay in contact?**

- what servers can reach on the internet: is outbound traffic filtered, or open?
- can servers reach request-capture services, tunnelling services, file-transfer sites and AI provider APIs they have no reason to use?
- is outbound DNS and proxy traffic logged?
- are tunnelling and remote-access tools detected on hosts?

**Developer tooling**

- AI assistant configuration in repositories: hooks, connector definitions, instruction files. Who can change them, are changes reviewed, do they run code on open?
- package and pipeline configuration that runs code from outside the repository

## Facts to record

- one fact per persistence capability: which identities can create what
- one fact per unexplained existing object
- one fact per open control channel: from where, to what
- relations: `can-write` from identities to what they can create

## Detection lens

For each kind of persistence, is its creation alerted?

- new privileged role assignment or admin account
- credential added to an application
- new access key, token or SSH key
- new instance with a public address, new public address, new inbound rule
- new file in a web root
- change to assistant configuration or pipeline definition

And for control: is a server's first connection to a new external destination noticed?

## Typical findings

| Finding | Usual priority |
|---|---|
| Unexplained admin account or privileged credential that looks recent | Stop: possible intrusion |
| Non-admin identities can add credentials to privileged applications | P1 or P0 |
| Creation of admin accounts, keys or application credentials raises no alert | P1 |
| Servers have unrestricted outbound access and outbound traffic is not logged | P1 |
| Assistant configuration in a repository can run code and is not reviewed | P1 |
| Stale high-privilege keys never rotated | P1 |
| Unreviewed application consents | P2, P1 for broad permissions |

## Exit criteria

- persistence capabilities are recorded for every non-admin identity that reached stage 4 or beyond
- existing drift is listed, each item explained or marked unexplained
- outbound reachability is recorded for each production segment

## Stage report

Three parts, as in `reporting.md`.
