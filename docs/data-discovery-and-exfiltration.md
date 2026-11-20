# Data discovery and exfiltration

Data reads and completed transfers are separate events. A successful protected read adds **DATA FOUND** to the activity feed. Only a completed transfer adds **DATA EXFILTRATED**, with its record count, byte count, method and destination. Egress denial or containment creates **EXFILTRATION BLOCKED** or **EXFILTRATION STOPPED** without erasing the prior read. Encryption remains a separate effect.

## Source review

Reviewed on 20 November 2026. The implementation uses these documented methods, with scenario assumptions for scheduling and volume:

| Profile | Selected transfer method | Evidence |
| --- | --- | --- |
| Malicious ARTEX | HTTP/API bulk extraction to an attacker-controlled workspace | Repository snapshot [6997a466, evidence store](https://github.com/RuoJi6/ARTEX/blob/6997a4661921395072290becc50380db8dacb04e/evidence/store.go), [finding guidance](https://github.com/RuoJi6/ARTEX/blob/6997a4661921395072290becc50380db8dacb04e/agent/finding_recorder.go) and [worker reporting](https://github.com/RuoJi6/ARTEX/blob/6997a4661921395072290becc50380db8dacb04e/agent/worker.go) preserve verified commands, responses and finding evidence. Per user direction, this demo represents a malicious operator using that access to export the full readable dataset. That bulk objective is a scenario choice, not a claim that the repository hardcodes a theft routine. |
| LockBit | Rclone to external cloud storage, T1567.002 | [Joint advisory AA23-165A](https://www.cyber.gov.au/advisory/understanding-ransomware-threat-actors-lockbit) documents Rclone/FreeFileSync and MEGA, as well as StealBit. This implementation selects the cloud route. |
| Conti | Rclone to cloud file sharing, T1567.002 | [ACSC Conti profile](https://www.cyber.gov.au/advisory/2021-010-asds-acsc-ransomware-profile-conti) describes cloud file-sharing transfers using Rclone. The specific subtechnique mapping is analyst-assigned from that procedure. |
| BlackCat | MEGAsync / Rclone, T1567.002 | [Microsoft's June 2022 investigation](https://www.microsoft.com/en-us/security/blog/2022/06/13/the-many-lives-of-blackcat-ransomware/) describes collection followed by those tools. The subtechnique mapping is analyst-assigned. |
| Hive | Rclone to MEGA, T1537 | [Joint advisory AA22-321A](https://www.cisa.gov/sites/default/files/publications/aa22-321a_joint_csa_stopransomware_hive.pdf) describes a likely Rclone/MEGA combination and assigns T1537; that advisory's mapping is retained. |
| REvil | Rclone to external cloud storage, T1567.002 | [Unit 42's 2021 investigation, updated June 2022](https://unit42.paloaltonetworks.com/revil-threat-actors/) records an Rclone transfer. This is a separate affiliate supplement, with an analyst-assigned mapping. The pinned software entry's T1041 example concerns host/malware information and is not treated as proof of bulk document theft. |

Gang additions are attributed separately from the imported Threat Vision technique catalogue. No live tools, network transfers or payloads are executed.

## Preconditions and scheduling

Newly generated estates give non-decoy data-tier assets a dataset label, 100–4,999 records and 1 KiB per record. Each host has explicit, seeded cloud-upload and response-export permissions. Cloud upload is allowed in 80% of those synthetic assignments and response export in 90%; these are scenario variety assumptions, not observed incident rates. The same estate and permissions are used for every actor and defense.

A protected read must succeed before a transfer can be queued. Gang transfers follow the established access ancestry to a host with execution capability, and require that host's cloud-upload permission. ARTEX uses the host through which data was actually read and its response-export permission. Read-only credentials cannot invent another readable dataset, and a read cannot imply successful egress.

Transfers use the existing worker queue, session scope, transition budget and containment lifecycle. All profiles export the full dataset their successful read actually exposes, without enlarging credential scope. Transfer duration is 120 seconds plus one second per 512 KiB for every profile; ARTEX can schedule up to three parallel actions while gangs retain one worker. These durations are authored scheduling choices, not measurements of the referenced tools. Transfer completion is atomic: this version does not estimate partial bytes sent before an interrupted transfer.

Containment at or before completion prevents the transfer; later containment preserves it. A monitored collection host can emit transfer telemetry after completion, with the estate's collection, decision and response delays. Egress blocking is an existing host policy and is not credited to HTTP virtual patching. Custom or older saved estates without explicit dataset/egress metadata retain data-found events but do not silently acquire a transfer capability; generate New Infra to get the new assumptions.

`node scripts/test-data-exfiltration.cjs` checks all six profiles, method provenance, full accessible dataset volume, readable-data/execution/egress prerequisites, replay immutability, containment before/during/after a transfer, and exact ties. Browser checks verify feed ordering and timing for both data milestones and blocked transfers.
