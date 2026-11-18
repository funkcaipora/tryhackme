# Stage 2: Initial compromise

**Question:** Where does an attacker get in?

## What an automated attacker does here

Most of the time it does not break in; it logs in. It arrives with credentials that leaked (in a public repository, a package, a container image, a paste, a stolen laptop), or that belong to a vendor the victim trusts. When it has no credential it looks for one: it sprays common passwords against the identity provider at a steady machine rhythm, and it tests account-recovery and sign-up flows. When an exposed system has a known vulnerability, it builds a working exploit from the public fix within hours. Against web applications it tries the whole catalogue of ordinary flaws, quickly and in parallel: missing authentication on an API, authentication bypass, injection, server-side request forgery, access to other users' objects by changing an identifier, anonymous upload, unsigned or unverified tokens, an administrator password left in client-side code, open self-registration, default credentials.

## What to check, from the inside

**Credentials that are already out, or easy to take**

- secrets in repositories, including git history, and in CI/CD variables and logs
- secrets in infrastructure state files, container image layers, build artifacts, notebooks
- secrets in client-side bundles and in configuration served to browsers
- secrets in documents, tickets and chat reachable through the connectors
- credential files and tokens on the workstation

Record type, location, age and fingerprint for each. Never the value.

**Long-lived credentials**

- access keys, client secrets, service-account keys, personal tokens, storage keys, signed URLs with long expiry
- for each: age, last use, what it can do (stage 3 goes deeper), whether a short-lived alternative exists

**Identity provider hygiene**

- strong authentication coverage, especially for administrators and for anyone with production access
- legacy protocols that skip strong authentication
- lockout and throttling: per account, or only per endpoint
- self-service flows: does password reset or sign-up confirm whether an account exists?
- sign-in allowed from anywhere, for service identities that only ever run from known places

**Trust in third parties**

- vendor and partner applications with standing permissions in the tenant, and what those permissions are
- multi-tenant applications and cross-account or cross-tenant roles
- remote-management and support tooling with privileged access

**Entry flaws in the user's own code.** Review, do not test:

- endpoints with no authentication or with authorization decided by the client
- object access by identifier with no ownership check
- fields that grant privilege accepted from request bodies
- token verification that accepts unsigned tokens or skips signature checks
- request handlers that fetch a URL supplied by the user
- file upload without authentication or type control
- open registration on systems meant for staff or partners
- default or hard-coded credentials

**Limits**

- rate limits on login, search and lookup endpoints: per identity, or only per address

## Facts to record

- one fact per exposed credential: type, location, age, fingerprint, the identity it belongs to
- one fact per identity without strong authentication, by privilege level
- one fact per third-party trust, with its permissions
- one fact per entry flaw, with the file and line
- relations: `authenticates-as` from each credential to its identity; `trusts` from the tenant to each vendor application

## Detection lens

- Would many failed sign-ins across many accounts from one source alert someone? From many sources at one rhythm?
- Is a successful sign-in from an unfamiliar network, provider or country flagged, for people and for service identities?
- Does secret scanning run on every push, and does a hit block or only notify?

## Typical findings

| Finding | Usual priority |
|---|---|
| Valid credential in a public or widely readable place, with more than trivial permissions | P0 |
| API endpoint with no authentication exposing data or actions | P0 |
| Administrator without strong authentication | P1, P0 if reachable from the internet with password only |
| Long-lived high-privilege key, not rotated | P1 |
| Vendor application holding broad standing permissions | P1 |
| Object access without ownership check | P1, P0 when it exposes other customers' data |
| Account enumeration through reset or sign-up | P2 |

## Exit criteria

- every credential found is on the blackboard with its identity
- every identity in scope has its authentication strength recorded
- every third-party trust in scope is listed

## Stage report

Three parts, as in `reporting.md`. "What could be exploited" names each credential and entry point as the start of a stage 3 pass.
