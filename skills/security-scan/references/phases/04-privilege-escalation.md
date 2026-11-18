# Stage 4: Privilege escalation

**Question:** How does a foothold become admin?

## What an automated attacker does here

It turns partial access into full control by the shortest route the configuration allows, and it tries several routes at once. In the cloud it launches compute with a more powerful role attached and reads that role's credentials, attaches a policy to itself, adds a credential to an application that has more rights, or gives itself an administrator role outright. In a directory it requests service tickets for accounts with weak passwords and cracks them offline, abuses delegation settings and certificate templates, reads local administrator passwords it is allowed to read, and, once it holds replication rights, copies every password hash in the domain. In applications it sets the field that makes an account an administrator, forges a token with a signing key that was never rotated, or reaches the cloud metadata service through a request-forgery flaw. When one route fails it adapts and tries the next.

## What to check, from the inside

Every route below is visible in configuration. Read it; do not try it.

**Cloud identity**

- identities that can pass a role to a service they can also launch or configure
- identities that can create or update policies, attach them, or change a role's trust
- identities that can create credentials for other identities, or add credentials to applications and service principals
- identities that can assign roles, including to themselves
- role chains: who can assume what, and where a chain ends in admin
- instance metadata reachable without session tokens

**Kubernetes and containers**

- service accounts that can create pods, read secrets, or bind and escalate roles
- workloads running privileged, with host mounts, or in the host's namespaces
- service accounts mapped to cloud identities with more rights than the workload needs

**Directory services**

- service accounts with weak encryption types or old passwords
- accounts that do not require pre-authentication
- who holds replication rights
- certificate templates that let the requester choose the subject, or that low-privilege users may enrol in
- unconstrained and resource-based delegation
- who can read local administrator passwords
- service accounts in highly privileged groups; applications running on domain controllers
- patch level for known escalation flaws in the domain

**Applications**

- privilege fields (`is_admin`, role, tenant) accepted from the client
- token signing keys: age, rotation, where they are stored
- administrative functions without a separate authorization check

**Operating systems and hosts**

- shared local administrator passwords
- credentials cached on servers where low-privilege users can log on

## Facts to record

- one fact per escalation route: from which identity, to which privilege, in how many steps, by which configuration
- relations: `can-assume`, `can-write` (to policy or role), `authenticates-as` after escalation

## Detection lens

- An identity assigning itself a role, or adding a credential to an application: alerted?
- Bursts of service-ticket requests, or replication requests from a host that is not a domain controller: alerted?
- Unusual certificate enrolment for privileged users: alerted?
- Compute launched with a privileged role by an identity that never did so: alerted?

## Typical findings

| Finding | Usual priority |
|---|---|
| Non-admin identity can give itself administrative control in one step | P0 |
| Pass-role plus launch rights lead to an admin role | P1, P0 from an exposed credential |
| Certificate template lets low-privilege users impersonate anyone | P1 or P0 |
| Replication rights held outside the domain controllers | P1 or P0 |
| Privilege field accepted from the client | P1, P0 on an internet-facing application |
| Token signing key never rotated | P1 |
| Service account with weak encryption and an old password in a privileged group | P1 |

## Exit criteria

- every identity that reached this stage has its escalation routes recorded, or a fact that none was found
- each route names the configuration that allows it

## Stage report

Three parts, as in `reporting.md`. In "what could be exploited", give each route as a short chain: identity, configuration, resulting privilege.
