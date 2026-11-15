# Plan: feasible four-layer attack paths

## Goal and current behavior

Make the synthetic estate show a small number of defensible attack paths through four layers: ingress, access/identity, internal services, and data. Paths can use software vulnerabilities, missing authentication, credential exposure, password spraying, or legitimate privileges. A finding is a scenario assumption, not proof about a real product or estate.

The current uncommitted implementation extracts a seeded engine into `js/wire-engine.js`, separates findings and credentials, and provides mixed-estate and demo-ready presets. It has not yet met the path-feasibility requirements below. A review found that source capabilities are not checked before onward movement; generated CVE requirements copy placeholder asset values; credential permissions and MFA checks differ by action; and canary events bypass action eligibility. A demo-ready path is therefore not necessarily feasible even if all four layers are reached. The previous version used an 80% exposure default and resampled for a baseline breach; those are historical behavior, not a description of the new engine. Preserve the existing WAF, SOAR, canary, SOC ticker, saved infrastructure, and scenario comparisons where they can be represented honestly.

## Truthfulness first: simplify the scope

Start with a few hand-reviewed scenario templates rather than generating many product/CVE combinations whose prerequisites cannot be checked. Keep other assets as contextual, non-exploitable objects until an action template is supported. This document is the target design, not a claim that the implementation already meets it.

For every displayed result distinguish **source-backed fact** (with a specific source and review date), **synthetic deployment assumption** (such as a route, stored token, or selected affected version), and **simulated outcome** (including defense behavior). Never label a synthetic finding or applicability assessment as verified. If an essential fact is unknown, report the step as **not established** and do not grant its capability. This is not proof that a real-world attack is impossible. A lack of a modeled finding does not prove an asset is secure.

## Corrections required before calling paths feasible

1. **Enforce source capabilities.** Each action declares the specific source context needed to use the particular outbound interface. File read alone does not create execution, a proxy, a network foothold, or a session. Model those capabilities only where a justified action supplies them. Regression case: demo seed 0 currently lets an Apache file-read result progress to a customer API; stop that transition unless a separately justified capability exists.
2. **Replace placeholder CVE checks.** Each enabled template records an actual assumed product and version, independently authored affected-version range, entry interface, authentication and other material conditions, plus primary-source advisory and review date. Match the asset against these requirements; copying the asset's fields into the finding is not validation. Represent a read-only exploit as file read, not execution. If conditions cannot be substantiated, disable the CVE action or label it unmodeled. Verify KEV membership against a dated CISA catalog separately from technical applicability; recheck the CVE-2023-32707 flag, which conflicts with `docs/wire_diagram_logic.md`. Do not assert a status until checked.
3. **Use one credential authorization check for all actions.** Require acquisition from an explicitly readable source, validity and non-revocation, intended audience, exact target or explicitly granted group, required permission and MFA/session conditions. Credentials intended for one asset must not authorize siblings through a group match. A read-only credential must not grant execution or a broader session; authenticated CVE actions use the same MFA and scope checks. Expired credentials are unusable.
4. **Check canary access before crediting detection.** A decoy has its own interface, reachable relationship and access requirements. Evaluate an attempt against those requirements first; only an eligible interaction can generate a canary alert. Model the response and its scope explicitly. An inaccessible decoy must not trigger an alert or be credited with containment.
5. **Represent outcomes honestly.** A blocked control does not prove all other paths are contained. A run stopped by a display or exploration budget must say it is incomplete; a no-path result means no path was found under the modeled assumptions. A successful action is a simulated result, not a real exploit or measured likelihood.

Implement and test these corrections before adding product pools, probability tuning, or visual polish. Do not advertise the implementation as prerequisite-checked until the negative cases pass.

## Reference and design boundaries

Reviewed [kaligraeme/mitre-threat-vision-ncs](https://github.com/kaligraeme/mitre-threat-vision-ncs) at `8f93e85` on `main` (fetched 2026-11-15). Its [estate contract](https://github.com/kaligraeme/mitre-threat-vision-ncs/blob/8f93e85/js/cybersim-estate.js) separates estate structure from technique and CVE presentation and validates the shape. Its [playbook](https://github.com/kaligraeme/mitre-threat-vision-ncs/blob/8f93e85/js/cybersim-playbook.js) separates illustrative attacker behavior and example telemetry from actual execution, and gates the SOC view on modeled coverage. Its [README](https://github.com/kaligraeme/mitre-threat-vision-ncs/blob/8f93e85/README.md) distinguishes a CTID technique-to-CVE mapping from an affected asset or a threat group's known exploitation.

The reference project's walk explicitly is not an executed path and does not calculate reachability or probabilities. Borrow its separation of concerns, validation and honest labeling; ARTEX must add its own explicit connectivity, permissions, prerequisites and progression rules. Do not infer asset vulnerability or a real detection from a technique mapping alone.

## Proposed estate and progression model

Separate four concepts, stored as structured data with stable IDs:

1. **Asset:** product and assumed version, function, layer, trust zone, interfaces, authentication, and data or privileges held. An asset can have no finding.
2. **Finding:** an applicable CVE with version/configuration prerequisites; anonymous access; weak authentication; a credential exposed in code or logs; or excessive permission. Multiple findings may coexist. Distinguish verified source facts from synthetic deployment assumptions.
3. **Relationship:** a directed service flow or access route, including source, target, protocol, direction, trust boundary, and why the relationship exists. A flow is not itself permission to exploit or authenticate.
4. **Attacker state and action:** location, execution or account context, acquired credential IDs and scopes, and privileges. Each action states required reachability, access, relevant finding and prerequisites; it yields a specific capability, not automatic control of connected assets. Record the evidence/assumption for each step.

Validate CVE product, version, interface and prerequisites against the relevant vendor advisory and CISA/NVD before adding a scenario. Track whether an entry is actually in KEV; a CVE-to-technique mapping or CISA membership alone does not prove the particular asset is vulnerable. Treat unknown facts as unknown, not as satisfied.

## How many objects and onward moves?

Use counts as **demo-design budgets**, not measured risk or per-exploit probabilities. Count distinct assets and distinct successful transitions, not animation events. A reachable or compromised object can have zero, one, or multiple possible onward actions; an eligible action still needs every prerequisite. A failed action must not grant its output capability. Do not use a universal success rate or imply that a vulnerability automatically escalates to another layer.

For an initial medium-sized illustrative estate, tune by eligible asset count rather than a fixed percentage:

| Layer | Starting design target for exploitable findings | Onward action budget per reached object |
| --- | --- | --- |
| 1: ingress | 1–2 externally reachable entry objects with a usable finding; other objects may be healthy | 0–2 distinct eligible layer-2 targets |
| 2: access and identity | 2–3 objects with relevant findings or usable access relationships | 0–2 distinct eligible layer-3 targets |
| 3: internal services | 2–3 objects with relevant findings or recoverable, scoped credentials | 0–2 distinct eligible layer-4 targets |
| 4: data and secrets | 1–2 accessible data or secret destinations, subject to permissions | 0 onward transitions in the initial four-layer demo; an exposed secret can be modeled as a separate step if explicitly linked |

These are starting targets across a generated estate, not requirements that each layer contains a CVE. A legitimate gateway may simply route to a vulnerable service; a data store may be reached with valid credentials and have no CVE. Each usable transition requires a concrete capability and relationship; zero is appropriate for an isolated or constrained foothold. Where several objects are eligible, initially display **up to two distinct onward targets per reached source** and **up to three successful objects per layer** for readability; these are presentation limits, not security limits. Prefer evaluating a bounded scenario independently of animation and make omitted alternatives inspectable. If a limit restricts exploration, explicitly report an incomplete run instead of treating unexamined paths as blocked. Count each source-target pair once for the display budget, but evaluate distinct actions when their prerequisites or capabilities differ.

For a demo-ready preset, aim for one complete four-layer path and optionally one alternative branch that fails or is stopped. Verify the actual prerequisites instead of forcing each layer to be vulnerable. For the default mixed-estate preset, allow zero complete paths and report that outcome. Do not silently resample until success; if a preset constructs a guaranteed path, label that intentional selection. Report layer-level counts, number of eligible and attempted transitions, and truncation. Calibrate counts against actual generated asset totals and visual density before fixing defaults; test small estates where targets cannot be met.

## Link and action feasibility

Introduce typed relationships and action templates. An action is eligible only when all required facts are present:

- **Reachability:** attacker location can reach the relevant destination interface and port/protocol in the stated direction; distinguish routed traffic from management access and telemetry.
- **Access:** required identity, scope, privilege, session or execution context exists. An identity-provider compromise does not automatically grant administrative rights everywhere.
- **Finding applicability:** the target product and assumed version/configuration fit the CVE, or the specific misconfiguration/credential condition exists. An unauthenticated data store needs no CVE; a patched service may still accept a valid credential.
- **Output:** define exactly what the action yields—such as application execution, an account session, a read-only token or data read. A source compromise does not automatically hand over credentials unless they are present and accessible from that context.
- **Next hop:** confirm that the acquired capability is usable at the next interface and has the necessary permissions. Preserve the reason for both success and failure in the event detail.

Use a reviewed, variant-aware catalog of connection/action templates rather than assuming every product in a family has identical capabilities. An edge can be visible as ordinary service connectivity without being a valid attack transition. Explicitly model exceptions such as direct public data access or a credential permitting a layer skip as separately justified paths; do not insert arbitrary shortcut probabilities. Detect cycles and duplicate transitions; bound exploration independently of UI animation.

Example A: exposed gateway → reachable application interface → application execution under a specified CVE and conditions → read a service credential actually stored in accessible configuration → authenticate to a reachable database with that credential's read scope. Each arrow needs a declared relationship and action; compromise of the gateway alone does not guarantee database access.

Example B: public source repository or readable application logs → a synthetic exposed service token → authenticated access to the specific service and permission granted to the token → data read only if that permission and target relationship permit it. If credentials are absent, expired, revoked, out of scope or inaccessible, the path stops. Do not put real secrets in fixtures.

Example C: a reachable authentication interface permits a modeled password-spray attempt against synthetic accounts. Only the explicitly modeled account can be obtained, and only if its password, rate-limit, lockout and MFA assumptions permit it. A session does not bypass MFA without a separately modeled reason. Detection and containment require applicable telemetry and response; show attempts and outcomes without real credentials or live requests.

## Defenses, presentation, and reproducibility

- Save the estate, findings, relationship facts, credentials, action ordering and random seeds once per infrastructure. Replaying a defense scenario reuses them; controls may change outcomes, not the underlying asset findings. Version saved snapshots and migrate or clearly regenerate incompatible older snapshots.
- Apply WAF rules only to covered protocols and interfaces; show what a rule blocks. Model SOAR as detection plus a specific feasible response, such as disabling an account or revoking a token, not automatic universal prevention. Model the canary as a distinct decoy action and preserve the ticket ticker. Keep all rates explicitly synthetic.
- Show each hop's source, target, finding, technique where correctly mapped, required access, assumed reachability, granted capability and control outcome. Distinguish a modeled finding from a technique-to-CVE mapping and a synthetic ticket from actual telemetry. Summarize why eligible-looking links are unusable.
- Keep the analysis engine independent of rendering and use a validated estate/action contract, following the reference project's separation of data, mappings and presentation.

## Implementation sequence and acceptance checks

Start by freezing the existing broad catalog out of automatic progression unless each enabled action has the required evidence and prerequisites. Build a small, complete scenario first: a reviewed ingress action, an explicitly usable connection, an internal service action, and a scoped credential that grants only a stated data read. Add anonymous access, password spray and credential exposure as separate curated scenarios once each can be explained and tested end to end. If a demo-ready path cannot satisfy these rules, report generation failure; do not invent a capability to guarantee a breach.

Mandatory regression tests, in addition to the checks below:

- File read without network capability cannot produce an onward request; adding a separately justified routing capability permits only its explicitly allowed route. Test the current seed-0 failure.
- A CVE action rejects wrong product, unaffected version, missing configuration, wrong interface and missing required authentication. A copied placeholder version does not satisfy an independently defined affected range. A CVE mapping alone never establishes applicability.
- A token scoped to one instance cannot authenticate to a sibling; read scope cannot grant execution; expired, revoked, wrong-audience and MFA-protected credentials fail on both normal and authenticated-CVE actions. A valid, correctly scoped credential can access a patched target only to the extent of its permissions.
- An inaccessible canary produces no canary alert; an eligible decoy interaction produces only the modeled alert and response. Test lack of route, wrong protocol and absent credential.
- Multiple findings on one asset are independently considered: a failed first finding must not hide a later eligible one. Successful actions with different capabilities must not be collapsed merely because the asset was visited once.
- Verify every enabled CVE's cited advisory and dated KEV status, including the Splunk discrepancy. Check that UI text distinguishes catalog mapping, assumed applicability, and simulated outcome; unknown is not shown as healthy or verified.
- Compare all four modes on the same saved estate and seed. Verify that a display cap or a defense in one branch cannot be reported as proof that unexplored branches are contained. A direct public-data exposure and an interrupted run must be reported accurately.

1. Define a versioned schema and validator for assets, findings, directed relationships, credentials, capabilities, actions and provenance. Inventory existing `LAYER_CONFIG`, `ALLOWED_CONNECTIONS`, exposure logic and controls; map existing behavior before migration.
2. Curate a small set of end-to-end scenario templates with reviewed product/version prerequisites and ATT&CK mappings. Include CVE, unauthenticated access, exposed code/log credentials, password spray, and healthy/no-path cases. Document sources and synthetic assumptions per template.
3. Implement a pure, seeded action evaluator and bounded graph traversal. Evaluate prerequisites and output capabilities before applying defense decisions; do not expose a finding merely because a family is connected. Separate exploration limits from success probabilities.
4. Build mixed-estate and demo-ready generation, with the budgets above and explicit reporting of unmet targets, intentional path construction and truncated exploration. Keep stable scenario replays and provide migration for saved estates.
5. Integrate visuals, understandable hop explanations, controls, canary and SOC tickets. Exercise all four scenarios and narrow displays, and retain the existing dashboard and demo features.
6. Test positive and negative cases: wrong product/version, missing route, wrong protocol/direction, missing privilege, unacquired or wrong-scope credential, revoked token, MFA/rate-limited spray, anonymous read, valid credential on a patched asset, isolated objects, cycles, multiple branches and direct public data access. Test 0/1/2 onward targets, caps and truncation; identical seeds and replay invariance; legacy snapshot handling; interrupted animations; control coverage and ticket accuracy. Keep `node scripts/test-wire-model.cjs` and extend it for the new contract. Browser-check generation, replay, resize and explanations.

Acceptance: every displayed successful hop has a traceable, satisfiable chain of prerequisites and a specific resulting capability; missing prerequisites stop it with a reason. No generic CVE or credential grants arbitrary access. The default can produce a no-path estate, demo-ready paths are labeled, and the four existing defense views compare the same underlying estate. Synthetic findings, rates, coverage and tickets are visibly distinguished from real evidence.
