# Plan: feasible four-layer attack paths

## Goal and current behavior

Make the synthetic estate show a small number of defensible attack paths through four layers: ingress, access/identity, internal services, and data. Paths can use software vulnerabilities, missing authentication, credential exposure, password spraying, or legitimate privileges. A finding is a scenario assumption, not proof about a real product or estate.

Today `wire.html` assigns an exposure to 80% of assets by default, with some per-product exceptions. A mapped CVE, public exposure, and assumed compromised credentials are handled through a shared exposure decision. Most connections are adjacent-layer family allowlists. The baseline generator resamples until a data-reaching path exists, and the run caps successful hits at three per layer. These choices make a useful demo but do not establish real-world exposure rates or whether the next hop's prerequisites are met. Preserve the existing WAF, SOAR, canary, SOC ticker, saved infrastructure, and scenario comparisons while changing the underlying model.

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

These are starting targets across a generated estate, not requirements that each layer contains a CVE. A legitimate gateway may simply route to a vulnerable service; a data store may be reached with valid credentials and have no CVE. Each usable transition requires a concrete capability and relationship; zero is appropriate for an isolated or constrained foothold. Where several objects are eligible, limit the default demonstration to **at most two distinct successful onward targets per reached source** and **at most three successful objects per layer** for readability; treat these as a display/simulation budget, not a security limit. Count each source-target pair once, even with multiple findings. Report when the budget truncates exploration; do not silently present the result as an exhaustive assessment. Keep alternative eligible paths inspectable.

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

1. Define a versioned schema and validator for assets, findings, directed relationships, credentials, capabilities, actions and provenance. Inventory existing `LAYER_CONFIG`, `ALLOWED_CONNECTIONS`, exposure logic and controls; map existing behavior before migration.
2. Curate a small set of end-to-end scenario templates with reviewed product/version prerequisites and ATT&CK mappings. Include CVE, unauthenticated access, exposed code/log credentials, password spray, and healthy/no-path cases. Document sources and synthetic assumptions per template.
3. Implement a pure, seeded action evaluator and bounded graph traversal. Evaluate prerequisites and output capabilities before applying defense decisions; do not expose a finding merely because a family is connected. Separate exploration limits from success probabilities.
4. Build mixed-estate and demo-ready generation, with the budgets above and explicit reporting of unmet targets, intentional path construction and truncated exploration. Keep stable scenario replays and provide migration for saved estates.
5. Integrate visuals, understandable hop explanations, controls, canary and SOC tickets. Exercise all four scenarios and narrow displays, and retain the existing dashboard and demo features.
6. Test positive and negative cases: wrong product/version, missing route, wrong protocol/direction, missing privilege, unacquired or wrong-scope credential, revoked token, MFA/rate-limited spray, anonymous read, valid credential on a patched asset, isolated objects, cycles, multiple branches and direct public data access. Test 0/1/2 onward targets, caps and truncation; identical seeds and replay invariance; legacy snapshot handling; interrupted animations; control coverage and ticket accuracy. Keep `node scripts/test-wire-model.cjs` and extend it for the new contract. Browser-check generation, replay, resize and explanations.

Acceptance: every displayed successful hop has a traceable, satisfiable chain of prerequisites and a specific resulting capability; missing prerequisites stop it with a reason. No generic CVE or credential grants arbitrary access. The default can produce a no-path estate, demo-ready paths are labeled, and the four existing defense views compare the same underlying estate. Synthetic findings, rates, coverage and tickets are visibly distinguished from real evidence.
