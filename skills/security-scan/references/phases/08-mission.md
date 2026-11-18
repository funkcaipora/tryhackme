# Stage 8: Mission

**Question:** What leaves, and how much damage?

## What an automated attacker does here

Now it does what it came for. It queries databases and downloads the results, reads storage in bulk, reads mailboxes, and harvests snapshots and backups by attaching them to machines it controls. It parses what it took to find what is valuable. It stages data on new volumes before moving it, then sends it out over ordinary web connections to services that accept anything. It abuses the application's own features at volume: a notification function becomes a way to mail thousands of people. If the goal is money, it uses the victim's cloud and AI accounts: it enables model access, raises quotas, launches GPU instances and resells the capacity, and the bill arrives within hours. If the goal is extortion, it also looks at what it could delete.

## What to check, from the inside

**Crown jewels: who can read them in bulk**

- for each crown jewel: which identities can read all of it, and which of those are reachable by the paths found so far
- whether bulk reads are possible through the application itself (export functions, unpaginated endpoints, sequential lookups)
- encryption keys: who can use them to decrypt

**Data-plane visibility**

- is data-plane logging on for the stores that matter (object reads, queries)?
- would a volume of reads far above normal raise an alert?

**Ways out**

- outbound paths from the systems that hold or can read crown jewels
- external sharing: public links, cross-account sharing of snapshots and images, replication to other accounts
- staging: who can create large volumes or copy snapshots

**Backups and recovery**

- who can read, share, modify or delete backups and snapshots
- immutability, versioning and deletion protection
- whether backups are reachable with the same credentials as production

**High-impact functions**

- application functions that send mail or notifications, create users, move money or change access: do they have rate, recipient and amount limits?
- is there an alert when one of them runs far outside its normal volume?

**AI and cloud spend**

- who can enable AI models, request quota increases or launch GPU capacity
- AI provider keys: where they are, what they can spend, whether budgets and spend alerts exist
- AI gateways and proxies: authentication, default keys, who can read the provider keys they hold

**Destruction**

- who can delete data stores, logs, backups and the infrastructure itself
- whether deletion needs a second factor or a second person

## Facts to record

- one fact per crown jewel: who can read it in bulk, whether that is logged
- one fact per way out
- one fact per backup set: who can delete or share it
- one fact per high-impact function: its limits
- relations: `can-read` and `can-write` from identities to crown jewels and backups

## Detection lens

- Read volume on a data store far above its baseline: alerted?
- A snapshot shared outside the organization, or a new large volume: alerted?
- Structured data leaving a server to a new external destination: visible?
- A notification function sending to thousands: alerted?
- AI spend or token consumption far above normal: alerted, and how fast?

## Typical findings

| Finding | Usual priority |
|---|---|
| Crown-jewel data readable in bulk by an identity on a P0 or P1 path, with no data-plane logging | P0 or P1 |
| Backups deletable with the same credentials as production | P1 |
| Snapshots or images can be shared outside the organization by non-admins | P1 |
| Notification or user-creation function with no limits | P1 |
| AI provider key with no budget or spend alert | P1 |
| AI gateway with default credentials holding provider keys | P0 when internet-reachable |
| Any production operator can delete data stores without a second control | P1 |

## Exit criteria

- every crown jewel has its bulk-read, exit and destruction exposure recorded
- backup exposure is recorded
- AI and cloud spend exposure is recorded when the scope has any

## Stage report

Three parts, as in `reporting.md`. In "what could be exploited", state impact in the user's terms: which data, how many records when known, what it would cost.
