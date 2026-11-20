# Gang technique policy and workforce entry points

Implemented 20 November 2026. Affects product phases 1–3 (estate, findings and attacker policy), with phase 4–6 checks for clock consistency, causal defense results and replay. The current controls, styles and animation presentation are preserved.

## Source and filter

[Threat Vision's analyzeDomain](https://github.com/kaligraeme/mitre-threat-vision-ncs/blob/8f93e855ca7a9427935016c7efae6f7bc96133aa/js/sim-engine.js) traverses active `uses` relationships to techniques, optionally including associated software and attributed campaigns. Its default options enable both. It downloads its ATT&CK knowledge base separately; it does not hardcode these ransomware gangs into a bespoke technique table.

The generated [offline catalogue](../js/gang-techniques.js) applies that walk to the pinned Enterprise ATT&CK **20.1** bundle, recording its SHA-256, selected roots, relationship IDs and evidence references. Ransomware names resolve to software entries rather than invented intrusion-set IDs:

| Spawned gang | Selected ATT&CK roots | Techniques from Threat Vision's walk |
| --- | --- | ---: |
| LockBit | S1199, S1202 (2.0 and 3.0) | 40 |
| Conti | S0575 | 16 |
| BlackCat | S1068 | 21 |
| Hive | No matching entry in this bundle | 0 |
| REvil | S0496 | 35 |

Software entries describe ransomware capabilities and often omit the affiliates' initial access. Separately attributed operator supplements in [the engine](../js/wire-engine.js) come from [CISA LockBit AA23-165A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-165a), [CISA Conti AA21-265A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-265a), [Microsoft's 2022 BlackCat investigation](https://www.microsoft.com/en-us/security/blog/2022/06/13/the-many-lives-of-blackcat-ransomware/), [CISA Hive AA22-321A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-321a), and [FBI's 2021 Hive alert](https://www.ic3.gov/CSA/2021/210825.pdf). BlackCat's initial-access IDs and Hive's lateral RDP ID are analyst mappings of the sources' narrative; event provenance marks them accordingly. They are not claimed to be Threat Vision relationships.

This is a **historical-style operator applied to a modern estate**, not a reconstruction restricted to facts available before 2023. The current ATT&CK catalogue and some retrospective advisories include later reporting. A technique mapping does not prove that an affiliate exploited any particular CVE. The existing nominal clock remains illustrative; neither mapped technique counts nor seeded exposure choices are measured attack rates.

## Runtime behavior

When an existing gang selection spawns, its identity selects the repertoire in `simulateWireRun`. Reachability, product/version, configuration, credentials and permissions are evaluated first. Unsupported actions are recorded as policy exclusions, with no access grant or defense credit. There is no unrestricted conventional fallback. A parent technique filter includes its children, while a subtechnique does not enable its siblings or its parent.

Ordinary use of an acquired, scoped credential after a foothold is labeled `modeled_supporting_access`; reachable decoy interaction is labeled separately. Neither is evidence of an additional historical gang technique. Each selected action carries `attackerEvidence`, and run assumptions record the source snapshot and supplements. Initial account use still needs a documented gang entry method.

Among feasible methods, authored scenario ordering favors remote access for LockBit and BlackCat, and attachment access for Conti, Hive and REvil. These orderings are illustrative choices, not sourced likelihoods. Deterministic estate ordering breaks ties. Overlapping documented techniques can produce overlapping routes; the simulation does not force different routes or successful breaches.

The activity-flow review refined progression: gangs prefer following their first foothold, apply supported persistence, transfer accessible data promptly and defer encryption until collection and exploration checks are exhausted. ARTEX pipelines access, data collection and bulk export over three workers. Additional ingress attempts take five minutes after the initial access result; this is an equal, explicit scenario cost for all actors. Genuine timed failures remain, while redundant capabilities and repertoire exclusions consume no attack time. Source-capability upgrades and newly acquired credentials reopen relevant routes, with attempt prerequisites frozen at their start. See [the five paired reviews](activity-flow-audit.md) and `scripts/test-activity-progression.cjs`.

## Workforce branch in mixed estates

Every new mixed estate includes a Windows email desktop, an internet-facing RDP login, Windows management and file servers, a confidential department share, and two or three department desktop fleets. Each fleet inventories 12–80 synthetic endpoints. These assets use the existing node rendering and icons. Their conditions, stored credentials and allowed routes vary deterministically by seed, independently of attacker identity and without changing the existing appliance RNG sequence. Demo/API and credential-in-logs fixtures keep their existing topology. The earlier exposure thresholds are retained; fleet and integration work does not apply the subsequently proposed lower entry-point percentages.

- **Attachment access (T1566.001):** generated **Windows Desktop · Phishable User** surfaces explicitly assume delivered mail, user opening and permitted execution, without mail-filter blocking. Their presence supplies a usable foothold for a profile with a documented attachment technique. These prerequisites remain enforced for protected or custom estates. Later movement, persistence and encryption still require their own permissions and access. ARTEX's current profile has no user-interaction capability and cannot use this route. No actual email or payload is sent.
- **External RDP (T1133):** requires an explicitly modeled broker-supplied starting credential scoped to that host, enabled remote login, and no unsatisfied MFA. A valid account never bypasses disabled remote login.
- **SMB, WMI and internal RDP (T1021.002, T1047, T1021.001):** require the actual protocol on a permitted directed route, an established source capability, and a target-scoped credential with execution permission. Conti/LockBit can choose SMB; REvil/BlackCat can choose WMI; Hive can choose its reported RDP method.

MFA is evaluated on the accepting protocol. Generated fleets declare `conditions.mfaProtocols` as either `['rdp']` or `[]`; the existing 25% draw selects an RDP gate, not an account-wide restriction. External RDP retains its explicit login/MFA policy. Legacy `mfaEnforced` and credential `mfaRequired` flags apply only to interactive RDP, VPN or HTTP(S) authentication. They do not impose an MFA challenge on SMB/WMI, share reads, or local actions in an already executing session. An explicit protocol list takes precedence over legacy flags. Revocation, expiry, audience, permissions, endpoint scope and enabled remote login remain independent requirements. Windows Hello for Business's device-bound sign-in factors do not imply an MFA gate on every network use of the account ([Microsoft authentication overview](https://learn.microsoft.com/en-us/windows/security/identity-protection/hello-for-business/hello-how-it-works-authentication)).
- **Data access:** requires the file server's established execution and an explicitly stored credential with read permission for the exact department share. Access to a desktop does not imply domain administration or data access.

HTTP virtual patching does not prevent email attachment execution or Windows remote login. SOC visibility and response still come from the same estate-owned telemetry, response authority and timing; a policy exclusion does not count as prevention. No new mail gateway or endpoint prevention control is implied.

A successful phish immediately marks the desktop **PHISH EXECUTED** and creates a high-severity illustrative event ticket, even if no credentials or lateral route are usable. When SOC response is enabled and the desktop layer is monitored, execution also emits endpoint telemetry with the configured collection and response delays. An unmonitored endpoint does not gain a detection signal. A visible phishing event establishes neither lateral access nor encryption.

## Integrated Windows fleets, persistence and encryption

The workforce branch connects to actual generated application and identity assets, rather than remaining a separate four-node chain. Fleets have scoped accounts for their business applications. Seeded management routes from existing Exchange, application, identity, secret-store and API assets can expose Windows management credentials if the attacker establishes the required source execution. Where present, the management server also has an explicit directory-access route. A drawn route alone grants no login or administration privilege.

Additional credentials vary by seed across department user, helpdesk, local administrator, deployment service and domain administrator roles. Their permissions distinguish authentication, read access, execution, local file writes and user startup changes. Credentials may be revoked, expired or protected by unsatisfied MFA. Every credential names its actual source capability, target and audience. The role name alone grants no privilege. Fleet credentials list the exact synthetic endpoint IDs they cover; successful execution records permissions per endpoint. Credentials stored on a fleet also name the endpoint where they can be recovered: execution on another member of that fleet does not expose them. A domain administrator credential is still limited to its declared targets and endpoint scope. A recovered credential can unlock a previously unsuccessful route; the engine retries that route only when relevant credential knowledge changes.

Persistence and encryption are separate scheduled local actions after execution, not consequences of merely drawing a Windows asset or obtaining a read-only credential:

- **Persistence (T1547.001)** models a user registry startup entry. It requires actual execution, an explicit `persist_user` permission and an asset configuration allowing startup changes. The gang repertoire must include the technique; the current pinned catalogue supports it for LockBit. This does not invent registry persistence for every ransomware gang.
- **Encryption (T1486)** requires execution, `write_local_files` permission and modeled writable local files. It affects only the intersection of executed endpoint IDs and their individual write permissions. It does not imply encryption of every device in a fleet or of shares/databases to which the account lacks write access. Encryption does not require persistence to succeed.

Startup installation takes an additional **120 modeled seconds** and local encryption takes **300 modeled seconds**, identical across profiles if those actions are enabled. These are synthetic scheduling assumptions, not measured deployment speed, throughput or historical estimates. Supported persistence is scheduled before further lateral work; encryption follows discovered feasible lateral routes. Ineligible local actions grant nothing. No registry changes, payload deployment or real file encryption occur.

Local actions run through the same worker queue, exploration budget, session scope and containment lifecycle as remote actions. Enabled layer telemetry can emit an endpoint-behavior signal after a successful local action; it does not fabricate another boundary crossing. Containment at or before an action's completion suppresses its effect. Later containment preserves completed persistence and encrypted endpoint counts; containing a session is not evidence that startup artifacts were removed or files restored. ARTEX does not perform persistent installation or ransomware encryption.

The subsequent malicious-ARTEX scenario direction enables bulk data theft after a successful protected read. It still does not enable persistence or encryption for ARTEX. All actors now have separately scheduled, access- and egress-gated exports, described in [data discovery and exfiltration](data-discovery-and-exfiltration.md). Conti, BlackCat and REvil cloud-transfer evidence is an explicitly attributed affiliate supplement, with analyst-assigned subtechnique mapping; it is not attributed to the Threat Vision import.

Events carry the action kind, source evidence and affected endpoint IDs. Run summaries distinguish protected reads, established persistence and encryption. Existing node states, tooltips, SOC tickets and the final HUD show the same effects and the affected subset of each fleet, with no new controls or layout redesign. Older saved estates gain fleet targets only through **New Infra**.

Switching attackers or defense cards preserves the estate and its exposure assumptions. Replay uses the same identity and event history. Use **New Infra** to generate the new workforce nodes when viewing an older saved estate.

## Verification and refresh

`node scripts/test-gang-techniques.cjs` checks distinct mapped routes, user interaction, RDP/MFA, credential permission/revocation/expiry/audience, network reachability, virtual-patch scope, immutable estates and deterministic replay across 720 attacker/defense combinations. The existing model, remediation and browser checks also apply.

`node scripts/test-windows-fleets.cjs` checks endpoint scope, read/execute/write/startup permissions, actual source access, delayed credential discovery, expired/revoked/MFA-protected accounts, route removal, persistence independent of encryption, containment before/between/after local actions and exact completion ties. Generated estates are checked for fleet-size variation, all five credential roles, integration with real application nodes, impact prerequisites and replay. Browser checks verify fleet impact in the existing node states and final result.

To reproduce the catalogue, download the exact bundle URL recorded in the catalogue and run `python scripts/import-gang-techniques.py <bundle>`. The importer rejects a different ATT&CK version. With the referenced Threat Vision source available, `node scripts/verify-threat-vision.cjs <bundle> <sim-engine.js>` independently executes its actual `analyzeDomain` implementation and compares every selected technique against the generated catalogue.
