# Stopwatch calibration and limits

The Wire stopwatch reports cumulative simulated time from the assumed edge foothold. See [Timing and data volumes in Wire](wire-timing-and-volume.md) for the milestones, historical references, and volume evidence shown in the demo.

## Historical context

CrowdStrike's [2023 Global Threat Report announcement](https://www.crowdstrike.com/en-us/press-releases/2023-crowdstrike-global-threat-report-reveals-sophisticated-adversaries-re-exploiting-patched-vulnerabilities-moving-beyond-ransomware/) reports mean eCrime breakout times of 98 minutes in 2021 and 84 minutes in 2022. Breakout measures movement from a compromised host to another host. It does not measure the time to read a sensitive record, the full duration of an intrusion or individual gang timing distributions.

Anthropic's [AI-orchestrated espionage report](https://www.anthropic.com/news/disrupting-AI-espionage) describes automated orchestration and human intervention. It supplies behavioral context for an agentic profile, not a validated 45–75-minute distribution for enterprise data breach. ARTEX-like is a scenario policy applied to a modern generated estate, not a reconstruction of that campaign.

## Explicit scenario assumptions

| Input | Current rule | Interpretation |
| --- | --- | --- |
| Conventional nominal path duration | Seeded integer draw from 80–270 minutes | Retained illustrative range informed by historical context; not an empirical distribution fitted to those reports. |
| ARTEX-like nominal path duration | Seeded integer draw from 45–75 minutes | Synthetic comparison assumption, not measured ARTEX field performance. |
| Stage allocation | Three independently keyed positive weights, normalized to nominal duration | Synthetic distribution across identity access, internal movement and data access. No fixed 50/35-second finishing burst. |
| Initial ingress action | Zero duration | The clock starts at the assumed initial foothold. Discovery and exploitation before that point are outside this clock. |
| Workers | One conventional, three ARTEX-like | Scenario concurrency setting, independent of the common transition allowance. Both profiles use the same access evaluator. |
| Response in generated estates | Collection 0–30 seconds; decision 15–60 seconds; attempted enforcement 60–1,800 seconds after collection | Independently keyed synthetic deployment assumptions, not measured SOC guarantees. Fixed fixtures without those fields default to 0/15/60 seconds. Decision must occur before enforcement. |
| Sensor coverage and response capability | Each layer in mixed estates has an independent 80% deployment draw; demo/logs estates retain full layer monitoring. Authority and successful enforcement each use a 95% scenario draw. | Synthetic sensitivity inputs, not real-world reliability rates. Both actors and every defense comparison retain the same deployment and capability draws. |
| Evidence | Two monitored hops on a compromised path, or a deployed decoy interaction | Simplified sequence-correlation hypothesis, not a general rule that ordinary cross-boundary traffic is malicious. Benign traffic and false-positive calibration remain future model work. |

Each run exports its action durations, sensor layers, response delays, authority and enforcement assumption in `run.assumptions`. A worker executes one transition at a time; discovered work queues until capacity is available. Action start times cannot precede source access. Consequently the actual stopwatch time to impact can exceed the nominal path-duration draw when other work consumes worker capacity.

Signals, decisions and enforcement share the attack clock. A containment time at or before completion suppresses the pending action's effect; it does not retroactively erase earlier access or reads. Such suppression is reported separately from a new prevented attack attempt. Decoy contact alerts through the same response lifecycle. Confirmed enforcement, failure, unavailable authority and unrelated response scope are distinct engine options.

`simulateWireRun(estate, mode, attacker, options)` accepts `actionDurations`, response/collection/decision delays, `responseAuthority`, `enforcementSucceeds`, `responseScope`, `explorationLimit` and attacker worker settings for controlled fixtures and sensitivity checks. These are developer inputs, not extra implementation controls in the demo UI.

## Remaining calibration boundaries

The current WAF rules are declared coverage assumptions. The ARTEX-like adaptive signature-evasion flag remains a simplifying capability assumption; this release does not establish real product efficacy or agent success rates. The data objective remains a non-decoy Layer 3 read. Dataset sensitivity independent of diagram layer, fallible discovery, complex multi-principal lineage, noise and full investigation policy require additional modeling.

Legacy `evaluateComparisonRun()` fixtures retain explicitly authored teaching traces, including their speed-race examples. The active Wire UI uses `simulateWireRun()` with the causal worker scheduler. Results from one API must not be presented as validation of the other.
