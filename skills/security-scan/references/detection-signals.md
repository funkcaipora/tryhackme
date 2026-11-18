# Detection signals

Use this file to answer the second question of every check: would it be logged and alerted?

Automated attackers change their names, file names and user agents freely. What they cannot easily change is how they behave, because the behaviour comes from how an agent works: broad first, fast, in bursts, retrying after errors. The signals below are behavioural for that reason. Treat any fixed string (a file prefix, an account name, a user agent) as a lead for a hunt, never as a durable detection.

## How to use a signal during the scan

For each signal relevant to the stage, establish four facts and record them:

1. **Source.** Is the log that would show it turned on for the assets in scope?
2. **Rule.** Is there a detection that looks for the pattern, as a sequence and not as a single event?
3. **Recipient.** Does the alert reach someone, or something, that acts?
4. **Speed.** Is the response fast enough for an attacker measured in minutes? Is any containment automatic?

A missing source is a logging gap. A source with no rule is a detection gap. A rule nobody answers in time is a response gap. Say which.

## The signals

| # | Signal | What it looks like | Where it shows | Stage |
|---|---|---|---|---|
| 1 | Machine cadence | Activity in bursts of seconds separated by pauses; or a steady rhythm near one request per second held for tens of minutes | sign-in logs, load balancer, gateway and firewall logs | 1, 2 |
| 2 | Breadth before depth | Dozens of read-only calls across many services within seconds; dry-run and validation calls across many resource types; "who am I" from a network the identity never used | cloud audit logs | 3 |
| 3 | Test write | An object written and deleted within a second | storage data-plane logs | 3 |
| 4 | Denied burst | Many permission-denied answers for one identity within a minute | cloud audit logs | 3, 4 |
| 5 | Error, fix, success | Several client errors on a path, then a success on the same path with adjusted parameters; files with incrementing names; near-identical script variants appearing in a web root | web access logs, endpoint file telemetry | 2, 3 |
| 6 | Fetch, then use | A source map or API description is fetched, and routes named in it are called minutes later | web access logs | 1, 2 |
| 7 | Baseline probe | A deliberate request for something that cannot exist, right before a run of path guesses | web access logs | 1 |
| 8 | Identity rotation | One address or one connection fingerprint presenting many user agents; a new source address minutes after a block | gateway, proxy and firewall logs | 1, 2 |
| 9 | Identity velocity | One service identity signing in hundreds of times in minutes; many tenants touched, few actions in each | identity sign-in logs | 2, 6 |
| 10 | Secret sweep | Many secrets read across several stores in a short window | secret store audit logs | 5 |
| 11 | Directory sweep | Tens of thousands of directory objects read by one account; bursts of service-ticket requests; replication requested by a host that is not a domain controller | directory and domain controller logs | 4, 5 |
| 12 | Credential replay | One credential used on many hosts within minutes; a hash or ticket used from a host where its owner never logged on | authentication logs | 6 |
| 13 | Persistence objects | New keys, public addresses, small instances, application credentials or admin accounts in quick succession, often with counters in their names | cloud audit logs, identity audit logs | 7 |
| 14 | New outbound destination | A server contacting request-capture services, tunnelling services, file-transfer sites or AI provider APIs for the first time; many different callback URLs on one service | DNS, proxy and flow logs | 7, 8 |
| 15 | Colliding actions | The same request repeated, or parallel workers overwriting each other; a very high event count for one small task | any of the above | all |
| 16 | No breaks | A session that runs for many hours without the pauses a person takes | any of the above | all |
| 17 | Feature at volume | A notification function sending to thousands; sequential record lookups; far more records per session than normal | application logs | 8 |
| 18 | Bulk read | Read volume on a data store far above its baseline; a snapshot shared outward; a large new volume | data-plane logs, cloud audit logs | 8 |
| 19 | Spend anomaly | AI token use or spend far above normal; new model access enabled; quota increases; GPU capacity launched by an identity that never did | billing and usage data, cloud audit logs | 8 |
| 20 | Cleanup | Logs cleared, timestamps altered, staged files deleted | host audit logs | 7 |

## Starting thresholds

Useful as first rules while no baseline exists. Tune them against the environment's normal automation, which overlaps with several of these signals.

| Pattern | Starting threshold |
|---|---|
| Password spray | 20 or more accounts from one source, 90% or more failing, within 15 minutes |
| Denied burst | 10 or more denied calls from one identity within a minute |
| Secret sweep | 5 or more secret reads by one identity within 10 minutes, or 20 or more across 3 or more stores within 15 minutes |
| Command burst | 8 or more command lines on one host within 10 seconds |
| Script variants | 3 or more script files created in a web root within 10 minutes |
| Identity velocity | 200 or more sign-ins by one service identity within 5 minutes |

## Principles to carry into the report

- **Sequences beat events.** Each single action of an automated attacker looks normal. The order, the volume and the origin do not.
- **Baselines are needed.** Legitimate automation produces bursts too. Without knowing what is normal for an identity, the rule either misses or floods.
- **The control plane and the data plane are the usual blind spots.** Endpoint monitoring tends to be mature; management APIs, service identities and storage reads tend to be logged and never alerted on.
- **Detection without response is not a control.** If the attacker finishes before anyone can act, the alert only documents the loss. Favour responses that are decided in advance and can run automatically: revoke the key, end the sessions, isolate the host.
- **Measure two times.** From first suspicious activity to detection, and from detection to containment. Put both in the report whenever the environment can supply them.

## The scan as a drill

The scan itself behaves like signals 2, 4 and 10: bursts of read calls from one identity. The audit timeline in the final report lists when it did so. Comparing that timeline with what monitoring raised is a free detection test.
