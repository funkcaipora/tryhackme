# Defense layers

Use this file when writing the "what must be fixed" part of a report. Every fix belongs to one of five layers. The order matters: a fix in an earlier layer usually removes whole attack paths, while a fix in a later layer makes them harder or more visible.

Write fixes that someone can act on: the setting, the policy, the line. "Apply least privilege" is not a fix; "remove `secrets:Get*` on `*` from role `ci-deploy` and grant it on the three secrets the pipeline reads" is.

## Layer 1: Control planes

Whoever reaches a management interface controls what is behind it. Keep them off the open internet and behind strong authentication.

| Weakness | Fix |
|---|---|
| Cloud administration, deployment or publishing endpoints reachable from anywhere | Restrict to trusted networks, private connectivity or a dedicated administrative path |
| Hypervisor, backup, VPN, firewall or network-device management exposed | Move to a management network; require an approved jump host or managed device |
| CI/CD servers, registries or the Kubernetes API exposed | Private endpoints; network allowlists; no anonymous access |
| AI gateways, model proxies or application builders exposed | Require authentication; remove default keys; treat as production systems |
| Password-only access to an admin interface | Phishing-resistant strong authentication |
| Basic or publishing authentication enabled but unused | Disable it; restrict deployment credentials |
| Applications that can be modified in place through the deployment interface | Prefer deployment models that mount an immutable package |
| New public addresses appear without review | Governance on public address allocation; architecture review before anything is exposed |
| Internal applications published directly | Put them behind an access proxy that authenticates first |

## Layer 2: Identities and keys

A credential that lives for years will leak eventually. Replace standing secrets with short-lived, workload-bound access.

| Weakness | Fix |
|---|---|
| Long-lived cloud access keys | Roles with temporary credentials |
| Application client secrets | Managed or workload identities |
| Storage account shared keys and long-lived signed URLs | Directory-based authorization with conditions |
| Service-account key files | Workload identity federation |
| Broad personal access tokens in pipelines | Fine-grained tokens, or pipeline identity federation without stored secrets |
| An identity can pass any role to any service | Restrict pass-role to named roles and named services |
| Vendor or multi-tenant applications with broad standing permissions | Least privilege on application permissions and consent grants; review them on a schedule |
| Service identities that may sign in from anywhere | Restrict by network or workload |
| Privileged accounts without strong authentication | Require it; remove legacy protocols that bypass it |
| Standing admin rights | Just-in-time elevation with approval |
| An exposed credential | Rotate it. Removing it from history is not enough: assume it was copied |
| Secrets in code, configuration, infrastructure state, pipelines, images | Move to a secret store with scoped access; scan repositories, images and build artifacts continuously |

## Layer 3: Configuration and paths

Remove the edges that attack paths use.

| Weakness | Fix |
|---|---|
| Internet-facing software behind on fixes | Shorten the time from fix released to fix deployed, first for what is exposed; put a compensating control in front until patched |
| Peripheral and forgotten systems | Inventory every internet-facing application, including partner portals, mobile backends, internal tools and legacy services; retire or own each one |
| Flat networks; exposed tier reaches identity or data directly | Segment application tiers; allow only the flows the design needs |
| Non-production can reach production | Separate networks, accounts and credentials; alert on any crossing |
| Database runtime account can write files, run commands or change server settings | Least-privilege runtime accounts |
| Certificate templates that let the requester choose the subject, or open enrolment | Remove requester-supplied subject where not needed; restrict enrolment rights; require approval for sensitive templates; protect the enrolment web interface |
| Weak service-account encryption and old passwords | Strong encryption types; managed service accounts; rotation |
| Replication rights outside domain controllers | Remove them; alert on replication from other hosts |
| Shared local administrator passwords | Unique, rotated passwords per host; restrict who can read them |
| Applications running on domain controllers or as domain administrators | Move them; run under scoped service accounts |
| Signing and channel binding not required | Require them on file-sharing and directory protocols; reduce legacy authentication |
| Instance metadata reachable without session tokens | Require the token-based metadata service |
| Privileged or host-mounted containers; service accounts that read all secrets | Restrict by policy; scope service accounts to the namespace's needs |
| Backups reachable and deletable with production credentials | Separate credentials; immutability; deletion protection |

## Layer 4: Application protections

Stop legitimate features from being used against the business.

| Weakness | Fix |
|---|---|
| Authorization decided by the client, or missing ownership checks | Server-side authorization on every object and action |
| Privilege fields accepted from requests | Allow-list writable fields; set privilege server-side only |
| Tokens accepted unsigned or unverified | Verify signature, issuer, audience and expiry; rotate signing keys |
| Endpoints that return more than the operation needs | Limit response fields |
| Functions that send messages, create users, move money or change access, with no limits | Rate, recipient and amount limits; alert when volume leaves the normal range |
| Sequential lookups and bulk export without control | Per-identity rate limits; alert on records per session |
| Rate limits only per endpoint or per address | Limit per identity as well |
| Detailed errors for unauthenticated users | Generic errors outside; detail in internal logs |
| Public source maps, configuration files, API descriptions | Remove from production, or require authentication |
| Open self-registration on staff or partner systems | Close it, or verify and approve |
| Flaws reaching production unnoticed | Static and dynamic testing before deployment; review of AI assistant and pipeline configuration changes |

## Layer 5: Detection and response

When prevention fails, see it and stop it at the attacker's speed. `detection-signals.md` lists what to look for.

| Weakness | Fix |
|---|---|
| Audit logging off for an account, region, cluster or tenant | Turn it on everywhere in scope; centralize |
| No data-plane logging on crown jewels | Enable object-read and query logging there first |
| Events logged but never alerted on | Rules for the behavioural signals, written as sequences |
| No baseline of normal automation | Baseline sign-in origins, control-plane velocity, storage reads, east-west traffic, server egress |
| Persistence objects created silently | Alerts on new admin assignments, application credentials, keys, public addresses, inbound rules |
| Servers can reach any external destination | Egress filtering; alert on first contact with a new destination |
| Response depends on a person being awake | Pre-approved automatic containment: revoke key, end sessions, isolate host |
| Logs kept too briefly to investigate | Extend retention for audit and identity logs |
| AI and cloud spend unwatched | Budgets and spend alerts that fire within the hour |
| Nobody knows how long detection and containment take | Measure both; report them |

## Ordering fixes in the remediation plan

1. By priority: P0, P1, P2.
2. Within a priority: choke points first, because one fix there breaks several paths.
3. Between equal fixes: the earlier layer first.

When a real fix will take time, add an interim mitigation from layer 1 or layer 5: restrict who can reach the weakness, or alert on its use.
